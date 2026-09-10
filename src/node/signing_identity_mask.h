// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service/tables/identity_types.h"

#include <cstdint>

namespace ccf
{
  // Set of identity types, one bit per IdentityType value.
  using SigningIdentityMask = uint64_t;

  constexpr SigningIdentityMask identity_bit(IdentityType identity_type)
  {
    return SigningIdentityMask{1} << static_cast<uint64_t>(identity_type);
  }

  constexpr bool is_signing_identity_selected(
    SigningIdentityMask mask, IdentityType identity_type)
  {
    return (mask & identity_bit(identity_type)) != 0;
  }

  static constexpr SigningIdentityMask DEFAULT_SIGNING_IDENTITY_MASK =
    identity_bit(IdentityType::CLASSICAL);

  /** Can be optionally implemented by the application to select which service
   * identities are used to sign the ledger. Every selected identity produces
   * its own COSE Sign1 signature in each signature transaction, and is created
   * when the service is created if it does not already exist.
   *
   * The default (weak) implementation selects IdentityType::CLASSICAL only.
   *
   * @return the set of identity types to sign with
   */
  SigningIdentityMask get_signing_identity_mask();
}
