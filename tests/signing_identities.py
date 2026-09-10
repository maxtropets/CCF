# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.


import ccf.ledger
import ccf.receipt
import ccf.signatures
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

SIGNING_IDENTITIES_TABLE = "public:ccf.gov.service.signing_identities"


def read_signature_identities(node, after_seqno):
    """Collect the set of identity keys present in each signature transaction
    written after after_seqno, and the identities published by the service."""
    current_ledger_dir, committed_ledger_dirs = node.get_ledger()
    ledger = ccf.ledger.Ledger(
        committed_ledger_dirs + [current_ledger_dir],
        committed_only=False,
        contiguous_suffix=True,
    )

    signature_key_sets = []
    published_identities = {}

    for chunk in ledger:
        for tx in chunk:
            public_domain = tx.get_public_domain()
            tables = public_domain.get_tables()

            identities = tables.get(SIGNING_IDENTITIES_TABLE)
            if identities is not None:
                published_identities.update(identities)

            if public_domain.get_seqno() <= after_seqno:
                continue

            signatures = tables.get(ccf.signatures.COSE_SIGNATURE_TX_TABLE_NAME)
            if signatures is not None:
                signature_key_sets.append(set(signatures.keys()))

    return signature_key_sets, published_identities


def last_signed_seqno(node):
    with node.client() as client:
        response = client.get("/node/state")
        assert response.status_code == 200, response
        return response.body.json()["last_signed_seqno"]


def issue_and_flush(network, args, node):
    network.txs.issue(network, number_txs=max(args.sig_tx_interval + 2, 5))
    network.wait_for_all_nodes_to_commit(primary=node)


def check_signing_identities(network, args, expected_keys):
    primary, _ = network.find_primary()
    start_seqno = last_signed_seqno(primary)
    issue_and_flush(network, args, primary)

    signature_key_sets, published_identities = read_signature_identities(
        primary, start_seqno
    )

    assert signature_key_sets, "No COSE signature transaction found in ledger"
    for keys in signature_key_sets:
        assert keys == expected_keys, (
            f"Signature transaction has identity keys {sorted(keys)}, "
            f"expected {sorted(expected_keys)}"
        )

    for key in expected_keys:
        assert key in published_identities, (
            f"Identity {key!r} signs the ledger but was never published in "
            f"{SIGNING_IDENTITIES_TABLE}"
        )

    return signature_key_sets


def verify_ec384_signature_still_parses(network):
    """The CLASSICAL signature keeps the legacy single-row table key, so existing
    tooling must keep working unchanged."""
    primary, _ = network.find_primary()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    ledger = ccf.ledger.Ledger(
        committed_ledger_dirs + [current_ledger_dir],
        committed_only=False,
        contiguous_suffix=True,
    )

    parsed = 0
    for chunk in ledger:
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            signature = ccf.signatures.parse_cose_signature_from_tx(tables)
            if signature is not None:
                parsed += 1

    assert parsed > 0, "Legacy COSE signature parsing found no signatures"
    LOG.info(f"Legacy COSE signature parsing still works ({parsed} signatures)")


def run_default_ec_only(args):
    """A node using the default signing identity mask signs with CLASSICAL only."""
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)

        LOG.info("Default mask: expecting CLASSICAL-only signatures")
        check_signing_identities(network, args, {EC384_KEY})
        verify_ec384_signature_still_parses(network)


def run_hybrid(args):
    """A node selecting CLASSICAL and PQ signs with both, and both identities
    are published by the service."""
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)

        LOG.info("Hybrid mask: expecting CLASSICAL and PQ signatures")
        signature_key_sets = check_signing_identities(
            network, args, {EC384_KEY, MLDSA65_KEY}
        )

        # Existing single-signature tooling selects the CLASSICAL signature, so it
        # must remain usable when a second identity is present.
        verify_ec384_signature_still_parses(network)

        LOG.success(
            f"{len(signature_key_sets)} dual-identity signature transactions "
            "verified"
        )


def run_live_upgrade(args):
    """A node requiring an identity the service lacks causes the primary to
    create it in the join transaction, so a signing identity can be introduced
    without recovering the service."""
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)

        LOG.info("Service starts CLASSICAL-only")
        check_signing_identities(network, args, {EC384_KEY})

        primary, _ = network.find_primary()
        ec_only_nodes = network.get_joined_nodes()

        hybrid_package = "samples/apps/logging/logging_hybrid_signing"
        host_data, _ = infra.utils.get_host_data_and_security_policy(
            infra.platform_detection.get_platform(),
            hybrid_package,
            binary_dir=args.binary_dir,
        )
        network.consortium.add_host_data(
            primary, infra.platform_detection.get_platform(), host_data
        )

        LOG.info("Joining a node which requires the PQ identity")
        hybrid_node = network.create_node()
        network.join_node(hybrid_node, hybrid_package, args, from_snapshot=False)
        network.trust_node(hybrid_node, args)

        # The identity must be published before the joining node can sign with
        # it, and while the EC-only primary is still signing CLASSICAL only.
        _, published_identities = read_signature_identities(primary, 0)
        assert MLDSA65_KEY in published_identities, (
            "PQ identity was not created and published during the join "
            f"transaction, found {sorted(published_identities)}"
        )

        published_mldsa65 = published_identities[MLDSA65_KEY]

        LOG.info("Retiring the EC-only nodes so the new node becomes primary")
        for node in ec_only_nodes:
            network.retire_node(hybrid_node, node)
            node.stop()

        network.wait_for_new_primary_in([hybrid_node], nodes=[hybrid_node])

        LOG.info("Service now signs with both identities, without recovery")
        check_signing_identities(network, args, {EC384_KEY, MLDSA65_KEY})

        # A node which never took part in publishing the identity must still be
        # able to serve it, and must serve the very same key.
        LOG.info("Joining a second node through the new primary")
        second_node = network.create_node()
        network.join_node(second_node, hybrid_package, args, from_snapshot=False)
        network.trust_node(second_node, args)

        _, published_identities = read_signature_identities(hybrid_node, 0)
        assert published_identities[MLDSA65_KEY] == published_mldsa65, (
            "The PQ identity changed across a primary change, so "
            "previously emitted signatures would no longer verify"
        )

        LOG.success("Signing identity introduced by live upgrade")


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "default_ec_only",
        run_default_ec_only,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
        sig_tx_interval=10,
    )

    cr.add(
        "hybrid",
        run_hybrid,
        package="samples/apps/logging/logging_hybrid_signing",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
        sig_tx_interval=10,
    )

    cr.add(
        "live_upgrade",
        run_live_upgrade,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
        sig_tx_interval=10,
    )

    cr.run()
