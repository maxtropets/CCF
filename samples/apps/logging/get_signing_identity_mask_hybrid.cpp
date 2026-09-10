// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/signing_identity_mask.h"

namespace ccf
{
  SigningIdentityMask get_signing_identity_mask()
  {
    return identity_bit(IdentityType::CLASSICAL) |
      identity_bit(IdentityType::PQ);
  }
}
