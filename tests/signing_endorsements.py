# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import copy

import ccf.ledger
import infra.e2e_args
import infra.logging_app as app
import infra.network
import infra.platform_detection
import infra.utils
from infra.runner import ConcurrentRunner
from loguru import logger as LOG

# Signing identity types, as serialised in KV table keys (little-endian uint64)
EC384_KEY = (0).to_bytes(8, byteorder="little")
MLDSA65_KEY = (1).to_bytes(8, byteorder="little")

ENDORSEMENTS_TABLE = "public:ccf.internal.previous_service_identity_endorsement"
SIGNING_IDENTITIES_TABLE = "public:ccf.gov.service.signing_identities"

HYBRID_PACKAGE = "samples/apps/logging/logging_hybrid_signing"


def read_endorsements(node):
    """Collect every endorsement written to the ledger, keyed by identity
    type, in the order they were written."""
    current_ledger_dir, committed_ledger_dirs = node.get_ledger()
    ledger = ccf.ledger.Ledger(
        committed_ledger_dirs + [current_ledger_dir],
        committed_only=False,
        contiguous_suffix=True,
    )

    endorsements = {}
    published_identities = {}
    for chunk in ledger:
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()

            identities = tables.get(SIGNING_IDENTITIES_TABLE)
            if identities is not None:
                published_identities.update(identities)

            written = tables.get(ENDORSEMENTS_TABLE)
            if written is not None:
                for identity_type, value in written.items():
                    endorsements.setdefault(identity_type, []).append(value)

    return endorsements, published_identities


def trust_hybrid_package(network, primary, args):
    host_data, _ = infra.utils.get_host_data_and_security_policy(
        infra.platform_detection.get_platform(),
        HYBRID_PACKAGE,
        binary_dir=args.binary_dir,
    )
    network.consortium.add_host_data(
        primary, infra.platform_detection.get_platform(), host_data
    )


def run_chain_per_identity(args):
    """Each signing identity gets its own endorsement chain, and an identity
    created part-way through an epoch starts its chain there."""
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()

        LOG.info("An CLASSICAL-only service endorses only the CLASSICAL identity")
        endorsements, _ = read_endorsements(primary)
        assert EC384_KEY in endorsements, "CLASSICAL identity was never endorsed"
        assert MLDSA65_KEY not in endorsements, (
            "An identity the service does not have was endorsed: "
            f"{sorted(endorsements)}"
        )
        ec384_endorsements_before = len(endorsements[EC384_KEY])

        LOG.info("Introducing PQ by joining a node which requires it")
        trust_hybrid_package(network, primary, args)
        hybrid_node = network.create_node()
        network.join_node(hybrid_node, HYBRID_PACKAGE, args, from_snapshot=False)
        network.trust_node(hybrid_node, args)

        endorsements, published_identities = read_endorsements(primary)

        # The new identity must self-endorse when it is published, otherwise
        # nothing ties the key it signs with to this epoch.
        assert (
            MLDSA65_KEY in endorsements
        ), "PQ was published without starting an endorsement chain"
        assert MLDSA65_KEY in published_identities

        # Introducing an identity must not disturb the existing chain.
        assert (
            len(endorsements[EC384_KEY]) == ec384_endorsements_before
        ), "Introducing PQ wrote to the CLASSICAL endorsement chain"

        LOG.success("Each identity has its own endorsement chain")


def run_chain_across_recovery(args):
    """Recovering a service continues each identity's chain, so receipts from
    the previous epoch remain verifiable."""
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()
        endorsements, identities_before = read_endorsements(primary)
        chain_before = len(endorsements[EC384_KEY])
        ec384_before = identities_before[EC384_KEY]
        first_endorsement = endorsements[EC384_KEY][0]

        network.txs.issue(network, number_txs=3)

        service_identity_file, _ = network.save_service_identity_to_file()
        snapshots_dir = network.get_committed_snapshots(primary)
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
        network.stop_all_nodes()

        LOG.info("Recovering the service")
        recovery_args = copy.deepcopy(args)
        recovery_args.label += "_recovery"
        recovery_args.previous_service_identity_file = service_identity_file

        with infra.network.network(
            recovery_args.nodes,
            recovery_args.binary_dir,
            recovery_args.debug_nodes,
            existing_network=network,
        ) as recovered_network:
            recovered_network.start_in_recovery(
                recovery_args,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshots_dir,
            )
            recovered_network.recover(recovery_args)

            recovered_primary, _ = recovered_network.find_primary()
            # Commit past the recovery so the endorsement it wrote is durable
            # in the ledger before it is read back.
            recovered_network.txs.issue(recovered_network, number_txs=3)
            recovered_network.wait_for_all_nodes_to_commit(primary=recovered_primary)
            endorsements, identities_after = read_endorsements(recovered_primary)

            # A new epoch must use a fresh key, otherwise the previous
            # service's key would still be live.
            assert (
                identities_after[EC384_KEY] != ec384_before
            ), "Recovery reused the previous epoch's CLASSICAL signing identity"

            # ...and must link it to the previous one, so that receipts signed
            # before the recovery still verify.
            assert (
                len(endorsements[EC384_KEY]) > chain_before
            ), "Recovery did not extend the CLASSICAL endorsement chain"
            assert (
                endorsements[EC384_KEY][-1] != first_endorsement
            ), "The recovery endorsement is identical to the original one"

        LOG.success("Endorsement chain continues across recovery")


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "chain_per_identity",
        run_chain_per_identity,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
    )

    cr.add(
        "chain_across_recovery",
        run_chain_across_recovery,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
    )

    cr.run()
