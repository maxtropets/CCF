// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/verifier.h"
#include "ccf/node/cose_signatures_config.h"
#include "crypto/certs.h"
#include "crypto/openssl/ec_key_pair.h"
#include "service/tables/identity_types.h"

#include <map>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf
{
  struct SigningIdentity
  {
    Identity public_identity;
    IdentityValue private_key;

    ~SigningIdentity()
    {
      OPENSSL_cleanse(private_key.data(), private_key.size());
    }

    bool operator==(const SigningIdentity&) const = default;
  };

  DECLARE_JSON_TYPE(SigningIdentity);
  DECLARE_JSON_REQUIRED_FIELDS(SigningIdentity, public_identity, private_key);

  using SigningIdentityMap = std::map<IdentityType, SigningIdentity>;

  // Random material every node of an epoch holds, from which signing
  // identities are derived. Distributed like the network identity, never
  // written to the ledger, so a new identity type needs no key distribution:
  // every node derives the same key independently.
  struct SigningSeed
  {
    std::vector<uint8_t> value;

    ~SigningSeed()
    {
      OPENSSL_cleanse(value.data(), value.size());
    }

    [[nodiscard]] bool empty() const
    {
      return value.empty();
    }

    bool operator==(const SigningSeed&) const = default;
  };

  DECLARE_JSON_TYPE(SigningSeed);
  DECLARE_JSON_REQUIRED_FIELDS(SigningSeed, value);

  static constexpr size_t SIGNING_SEED_SIZE = 32;

  inline SigningSeed create_signing_seed()
  {
    return {ccf::crypto::get_entropy()->random(SIGNING_SEED_SIZE)};
  }

  // CLASSICAL is the service identity key itself, so it is never derived.
  static constexpr auto EC384_CURVE = ccf::crypto::CurveID::SECP384R1;

  // ML-DSA-65 is not available yet. Until it is, a PQ identity is backed
  // by an EC key pair so that the surrounding lifecycle can be exercised.
  static constexpr auto MOCK_MLDSA65_CURVE = ccf::crypto::CurveID::SECP521R1;

  inline ccf::crypto::CurveID curve_for_identity(IdentityType identity_type)
  {
    switch (identity_type)
    {
      case IdentityType::CLASSICAL:
        return EC384_CURVE;
      case IdentityType::PQ:
        return MOCK_MLDSA65_CURVE;
    }
    throw std::logic_error("Unknown identity type");
  }

  inline SigningIdentity make_signing_identity(
    const std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL>& key_pair)
  {
    return {
      {IdentityKind::X509_SPKI_DER, key_pair->public_key_der()},
      key_pair->private_key_pem().raw()};
  }

  inline SigningIdentity derive_signing_identity(
    const SigningSeed& seed, IdentityType identity_type)
  {
    if (identity_type == IdentityType::CLASSICAL)
    {
      throw std::logic_error(
        "The CLASSICAL signing identity is the service identity and is not "
        "derived");
    }

    return make_signing_identity(ccf::crypto::derive_ec_key_pair(
      curve_for_identity(identity_type),
      seed.value,
      fmt::format(
        "ccf.signing-identity.{}", identity_type_name(identity_type))));
  }

  inline std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> get_signing_key_pair(
    const SigningIdentity& identity)
  {
    return std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(
      ccf::crypto::Pem(identity.private_key));
  }

  inline SigningIdentityMap make_classical_signing_identity_map(
    const std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL>& key_pair)
  {
    SigningIdentityMap identities;
    identities.emplace(
      IdentityType::CLASSICAL, make_signing_identity(key_pair));
    return identities;
  }

  struct NetworkIdentity
  {
    ccf::crypto::Pem priv_key;
    ccf::crypto::Pem cert;

    bool operator==(const NetworkIdentity& other) const = default;

    NetworkIdentity(
      const std::string& subject_name,
      ccf::crypto::CurveID curve_id,
      const std::string& valid_from,
      size_t validity_period_days)
    {
      auto identity_key_pair =
        std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(curve_id);
      priv_key = identity_key_pair->private_key_pem();

      cert = ccf::crypto::create_self_signed_cert(
        identity_key_pair,
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    NetworkIdentity(const NetworkIdentity& other) = default;

    NetworkIdentity() = default;

    virtual ~NetworkIdentity()
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
    }

    ccf::crypto::Pem renew_certificate(
      const std::string& valid_from, size_t validity_period_days)
    {
      return ccf::crypto::create_self_signed_cert(
        get_key_pair(),
        ccf::crypto::get_subject_name(cert),
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    void set_certificate(const ccf::crypto::Pem& new_cert)
    {
      cert = new_cert;
    }

    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> get_key_pair()
    {
      return std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(priv_key);
    }
  };
}
