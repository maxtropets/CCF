// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/jwt_auth.h"

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/ds/nonstd.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ds/lru.h"
#include "enclave/enclave_time.h"
#include "http/http_jwt.h"

namespace
{
  static const std::string multitenancy_indicator{"{tenantid}"};
  static const std::string microsoft_entra_domain{"login.microsoftonline.com"};

  std::optional<std::string_view> first_non_empty_chunk(
    const std::vector<std::string_view>& chunks)
  {
    for (auto chunk : chunks)
    {
      if (!chunk.empty())
      {
        return chunk;
      }
    }
    return std::nullopt;
  }

}

namespace ccf
{
  bool validate_issuer(
    const std::string& iss,
    const std::optional<std::string>& tid,
    std::string constraint)
  {
    LOG_DEBUG_FMT(
      "Verify token.iss {} and token.tid {} against published key issuer {}",
      iss,
      tid,
      constraint);

    const auto issuer_url = ::http::parse_url_full(constraint);
    if (issuer_url.host != microsoft_entra_domain)
    {
      return iss == constraint &&
        !tid; // tid is a MSFT-specific claim and
              // shoudn't be set for a non-Entra issuer.
    }

    // Specify tenant if working with multi-tenant endpoint.
    const auto pos = constraint.find(multitenancy_indicator);
    if (pos != std::string::npos && tid)
    {
      constraint.replace(pos, multitenancy_indicator.size(), *tid);
    }

    // Step 1. Verify the token issuer against the key issuer.
    if (iss != constraint)
    {
      return false;
    }

    // Step 2. Verify that token.tid is served as a part of token.iss. According
    // to the documentation, we only accept this format:
    //
    // https://domain.com/tenant_id/something_else
    //
    // Here url.path == "/tenant_id/something_else".
    //
    // Check for details here:
    // https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-issuer.

    const auto url = ::http::parse_url_full(iss);
    const auto tenant_id =
      first_non_empty_chunk(ccf::nonstd::split(url.path, "/"));

    return tenant_id && tid && *tid == *tenant_id;
  }

  struct PublicKeysCache
  {
    static constexpr size_t DEFAULT_MAX_KEYS = 10;

    using DER = std::vector<uint8_t>;
    ccf::pal::Mutex keys_lock;
    LRU<DER, ccf::crypto::RSAPublicKeyPtr> keys;

    PublicKeysCache(size_t max_keys = DEFAULT_MAX_KEYS) : keys(max_keys) {}

    ccf::crypto::RSAPublicKeyPtr get_key(const DER& der)
    {
      std::lock_guard<ccf::pal::Mutex> guard(keys_lock);

      auto it = keys.find(der);
      if (it == keys.end())
      {
        it = keys.insert(der, ccf::crypto::make_rsa_public_key(der));
      }

      return it->second;
    }
  };

  JwtAuthnPolicy::JwtAuthnPolicy() :
    keys_cache(std::make_unique<PublicKeysCache>())
  {}

  JwtAuthnPolicy::~JwtAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> JwtAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();

    const auto token_opt =
      ::http::JwtVerifier::extract_token(headers, error_reason);
    if (!token_opt)
    {
      return nullptr;
    }

    auto& token = token_opt.value();
    auto keys = tx.ro<JwtPublicSigningKeys>(
      ccf::Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA);
    const auto key_id = token.header_typed.kid;
    auto token_keys = keys->get(key_id);

    if (!token_keys)
    {
      auto fallback_keys = tx.ro<Tables::Legacy::JwtPublicSigningKeys>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEYS);
      auto fallback_issuers = tx.ro<Tables::Legacy::JwtPublicSigningKeyIssuer>(
        ccf::Tables::Legacy::JWT_PUBLIC_SIGNING_KEY_ISSUER);

      auto fallback_cert = fallback_keys->get(key_id);
      if (fallback_cert)
      {
        // Legacy keys are stored as certs, new approach is raw keys, so
        // conversion is needed to implicitly work futher down the code.
        auto verifier = ccf::crypto::make_unique_verifier(*fallback_cert);
        token_keys = std::vector<OpenIDJWKMetadata>{OpenIDJWKMetadata{
          .public_key = verifier->public_key_der(),
          .issuer = *fallback_issuers->get(key_id),
          .constraint = std::nullopt}};
      }
    }

    if (!token_keys || token_keys->empty())
    {
      error_reason =
        fmt::format("JWT signing key not found for kid {}", key_id);
      return nullptr;
    }

    for (const auto& metadata : *token_keys)
    {
      if (!metadata.public_key.has_value())
      {
        error_reason =
          fmt::format("Missing public key for a given kid: {}", key_id);
        continue;
      }

      const auto pubkey = keys_cache->get_key(metadata.public_key.value());
      // Obsolote PKCS1 padding is chosen for JWT, as explained in details here:
      // https://github.com/microsoft/CCF/issues/6601#issuecomment-2512059875.
      if (!pubkey->verify_pkcs1(
            (uint8_t*)token.signed_content.data(),
            token.signed_content.size(),
            token.signature.data(),
            token.signature.size(),
            ccf::crypto::MDType::SHA256))
      {
        error_reason = "Signature verification failed";
        continue;
      }

      // Check that the Not Before and Expiration Time claims are valid
      const size_t time_now = std::chrono::duration_cast<std::chrono::seconds>(
                                ccf::get_enclave_time())
                                .count();
      if (time_now < token.payload_typed.nbf)
      {
        error_reason = fmt::format(
          "Current time {} is before token's Not Before (nbf) claim {}",
          time_now,
          token.payload_typed.nbf);
      }
      else if (time_now > token.payload_typed.exp)
      {
        error_reason = fmt::format(
          "Current time {} is after token's Expiration Time (exp) claim {}",
          time_now,
          token.payload_typed.exp);
      }
      else if (
        metadata.constraint &&
        !validate_issuer(
          token.payload_typed.iss,
          token.payload_typed.tid,
          *metadata.constraint))
      {
        error_reason = fmt::format(
          "Kid {} failed issuer constraint validation {}",
          key_id,
          *metadata.constraint);
      }
      else
      {
        auto identity = std::make_unique<JwtAuthnIdentity>();
        identity->key_issuer = metadata.issuer;
        identity->header = std::move(token.header);
        identity->payload = std::move(token.payload);
        return identity;
      }
    }

    return nullptr;
  }

  void JwtAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
    ctx->set_response_header(
      http::headers::WWW_AUTHENTICATE,
      "Bearer realm=\"JWT bearer token access\", error=\"invalid_token\"");
  }

  const OpenAPISecuritySchema JwtAuthnPolicy::security_schema = std::make_pair(
    JwtAuthnPolicy::SECURITY_SCHEME_NAME,
    nlohmann::json{
      {"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}});
}
