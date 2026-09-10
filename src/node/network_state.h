// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "identity.h"
#include "ledger_secrets.h"
#include "service/network_tables.h"

namespace ccf
{
  struct NetworkState : public NetworkTables
  {
    std::unique_ptr<NetworkIdentity> identity;
    // Seed the non-legacy signing identities are derived from. Every node of
    // an epoch holds it, so any of them can derive and serve any identity.
    SigningSeed signing_seed;
    SigningIdentityMap signing_identities;
    std::shared_ptr<LedgerSecrets> ledger_secrets;

    NetworkState() = default;
  };
}