# Post-Quantum Support

This page defines the target shape for post-quantum support in CCF, not the current state of it.

## Goals

The target design provides post-quantum safety for:

- User-to-node TLS
- Node-to-node communication
- Ledger signatures, receipts, and endorsements trust chain
- Member governance signatures
- User and member certificate authentication

## Identity type disclaimer

Identity references use `identity_type`, not type-agnostic ids.

- `identity_type` is a CCF-specific enum, not the concrete crypto type.
- If needed, two enum values may still point to identities with the same crypto shape.
- Upgrade is per type and code-embedded, like COSE ledger signing mode.
- It is not a runtime config knob.

Previous identity endorsement is per type, so it is clear who endorses whom:

```text
DR:    0         1         2         3

A:     A0 <----- A1 <----- A2
       ^  \
       +---+

B:                         B2 <----- B3
                           ^  \
                           +---+
```

## Switching to multiple identities

Service maintains identity material separately from purpose bindings:

| KV map | Key | Value |
| --- | --- | --- |
| `service.identities` | `identity_type` | `Identity` |
| `service.identity_bindings` | `Purpose` | `identity_type[]` |

| Type | Schema |
| --- | --- |
| `Identity` | `{ kind: Kind, value: bytes }` |
| `Kind` | `"key" \| "cert" \| ...` |
| `Purpose` | `"Signing" \| "UserTLS" \| ...` |

All identities in the `identity_type[]` are used for that purpose. For example:

- For signing, the service signs with every listed identity.
- For TLS, the service offers every listed certificate, and the TLS protocol selects one according to the client's capabilities.

## Node-to-node identity is separate

- N2N is node-scoped, not service-scoped.
- It is not listed in `service.identity_bindings`.

Current node identity state is split across node tables:

| KV map | Key | Value |
| --- | --- | --- |
| `public:ccf.gov.nodes.info` | `node_id` | `NodeInfo` |
| `public:ccf.gov.nodes.endorsed_certificates` | `node_id` | Service-endorsed node cert |

- Current `NodeInfo` already stores the node's quote, encryption public key, status, CSR, and public key.
- The `node_id` is derived from the node public key.

- The N2N migration should be orthogonal: eventually replace the custom N2N channel with a PQ-safe transport, likely TLS.
- The internal node communication identity shape is left opaque for now.

- During a rolling N2N upgrade, new nodes join with the communication identity required by their binary and old nodes retire.
- Since this is internal node communication, there is no need to offer several N2N identities in parallel.

## Introducing and removing identities

- Identity material and purpose bindings are introduced or removed atomically.
- Nodes advertise the service identity types they support when they join.
- Join policy is also expressed in terms of service identity types, with the same two-step shape as the COSE-only ledger upgrade:

| Stage | Join policy | Effect |
| --- | --- | --- |
| Transition | `allowed_identity_types = [EC, PQ]` | New nodes may join with either type while old nodes are being replaced. |
| Cutover | `allowed_identity_types = [PQ]` | New EC-only nodes are rejected. |

- If a joining node advertises an allowed identity type and the service does not have that identity yet, the identity must be created in the same join transaction.
- The identity is then reused for future joiners of the same type, and its private material is shared with trusted nodes the same way service private material is shared today.
- Recovery follows the same rule.
- The first recovery node sets the initial join policy from the identity types embedded in its binary.

## Previous identity endorsements

- Previous identity endorsements are stored separately from identity material and purpose bindings.
- They are keyed by `identity_type`, so each identity has its own continuity chain.

## Attestation

Today, CCF uses AMD SEV-SNP `report_data` as a node-identity binding:

| Field | Current value |
| --- | --- |
| `QuoteInfo.format` | `AMD_SEV_SNP_v1` |
| SNP `report_data` | `SHA256(node_public_key_der)` |

The rest of quote verification is separate: CCF verifies the AMD endorsements, the security policy in `host_data`, the measurement or UVM endorsements, and the TCB version.

With multiple identities, each attested identity needs an explicit binding statement:

| Field | Meaning |
| --- | --- |
| `version` | Binding format version |
| `identity_type` | CCF identity type |
| `purpose` | Purpose or purpose bitmask |
| `kind` | `key`, `cert`, or another identity material kind |
| `algorithm` | Signing or certificate algorithm suite |
| `hash_algorithm` | Hash used for the identity material |
| `identity_hash` | Hash of the canonical identity material |

- The logical attested value is this binding statement.
- For SNP, `report_data` should contain the hash of the canonical binding statement, not the raw identity material.
- This keeps the AMD quote payload fixed-size while letting verifiers distinguish which identity and purpose were attested.