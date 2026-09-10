// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/signing_identity_mask.h"

namespace ccf
{
  SigningIdentityMask __attribute__((weak)) get_signing_identity_mask()
  {
    return DEFAULT_SIGNING_IDENTITY_MASK;
  }
}
