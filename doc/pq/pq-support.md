# Post-Quantum Support

This page defines the target shape for post-quantum support in CCF, not the current state of it.

## Goals

The target design provides post-quantum safety for user-to-node TLS, node-to-node communication, ledger signatures, receipts, endorsements trust chain, member governance signatures, and user and member certificate authentication.

## Identity type disclaimer

Identity references use `identity_type`, not type-agnostic ids.

`identity_type` is a CCF-specific enum, not the concrete crypto type.
It identifies the identity variant, not the purpose.
If needed, two enum values may still point to identities with the same crypto shape.
Upgrade is done via each node configuration and supporting join policies.

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

N2N is node-scoped, not service-scoped.
It is not listed in `service.identity_bindings`.

Current node identity state is split across node tables:

| KV map | Key | Value |
| --- | --- | --- |
| `public:ccf.gov.nodes.info` | `node_id` | `NodeInfo` |
| `public:ccf.gov.nodes.endorsed_certificates` | `node_id` | Service-endorsed node cert |

Current `NodeInfo` already stores the node's quote, encryption public key, status, CSR, and public key.
The `node_id` is derived from the node public key.

The N2N migration should be orthogonal: eventually replace the custom N2N channel with a PQ-safe transport via QUIC.
The internal node communication identity shape is left opaque for now.

During a rolling N2N upgrade, new nodes join with the communication identity required by their config and old nodes retire.
Since this is internal node communication, there is no need to offer several N2N identities in parallel.

## Introducing and removing identities

Identity material and purpose bindings are introduced or removed atomically.
Nodes advertise the service identity types they support when they join, or set them straight avay in the KV on service creation/recovery.
Join policy is also expressed in terms of service identity types, with the same two-step shape as the COSE-only ledger upgrade:

| Stage | Join policy | Effect |
| --- | --- | --- |
| Transition | `allowed_identity_types = [EC, PQ]` | New nodes may join with either type while old nodes are being replaced. |
| Cutover | `allowed_identity_types = [PQ]` | New EC-only nodes are rejected. |

Mixed identity periods are expected during the rolling update window.
This is an intentional design choice, not a temporary inconsistency.

If a joining node advertises an allowed identity type and the service does not have that identity yet, the identity must be created in the same join transaction.
The identity is then reused for future joiners of the same type, and its private material is shared with trusted nodes the same way service private material is shared today.
The first recovery node sets the initial join policy from the identity types in its config.

## Previous identity endorsements

Previous identity endorsements are stored separately from identity material and purpose bindings.
They are keyed by `identity_type`, so each identity has its own continuity chain.

## Attestation

Today, CCF uses AMD SEV-SNP `report_data` as a node-identity binding:

```text
0                                32                               64
+--------------------------------+--------------------------------+
| SHA256(node_public_key_der)    | unused (0-filled)              |
+--------------------------------+--------------------------------+
```

The rest of quote verification is separate: CCF verifies the AMD endorsements, the security policy in `host_data`, the measurement or UVM endorsements, and the TCB version.

With multiple identities, `report_data` should carry both the identity digest and the binding metadata:

```text
0        8          16                                               64
+--------+----------+-----------------------------------------------+
| LAYOUT | RESERVED | DIGEST (zero padded if SHA-256)               |
+--------+----------+-----------------------------------------------+
```

| Field | Meaning |
| --- | --- |
| `LAYOUT` | 6-byte binding metadata: version, `identity_type`, kind, purpose, algorithm suite, hash algorithm |
| `RESERVED` | 10 bytes, must be zero |
| `DIGEST` | 48-byte digest slot: SHA-256 digest followed by 16 zero bytes, or SHA-384 digest |

`LAYOUT` is:

```text
byte:    00 01 02 03 04 05
layout:  V  T  K  P  S  H
```

| Field | Meaning |
| --- | --- |
| V | Binding format version |
| T | CCF `identity_type` |
| K | Identity material kind: key, cert, or another kind |
| P | Purpose or purpose bitmask |
| S | Signing or certificate algorithm suite |
| H | Hash algorithm |

Examples:

For node join, attestation must bind the node identity used to request trust:

```text
identity material: DER bytes of EC service TLS certificate
H = SHA-256
K = cert
T = ec_p384
P = UserTLS
S = ecdsa_p384_sha384

DIGEST = SHA256(ec_service_tls_cert_der)
```

```text
identity material: DER SubjectPublicKeyInfo bytes of PQ signing key
H = SHA-384
K = key
T = mldsa65
P = Signing
S = mldsa65

DIGEST = SHA384(mldsa65_signing_public_key_der)
```

```text
identity material: DER SubjectPublicKeyInfo bytes of node N2N TLS PQ key
H = SHA-384
K = key
T = mldsa65
P = N2N
S = mldsa65

DIGEST = SHA384(node_n2n_tls_mldsa65_public_key_der)
```

SHA-256 leaves 16 digest-slot bytes unused, so they must be zero.
SHA-384 consumes the whole 48-byte digest slot.
SHA-512 is not used because it would consume all 64 bytes of `report_data`.
The layout keeps 16 bytes for binding metadata and reserved space.
The verifier checks the digest and the metadata, so it can tell which identity type and purpose were attested.

## Current platform and standards support

As-is, CCF targets Azure Linux 3 and is pinned to OpenSSL 3.3.

The target standards drafts are [`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) for Composite-ML-DSA X.509 certificates and [`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) for JOSE/COSE composite signatures.
They are related, but they are different registries and API surfaces.

Azure Linux 4 matters as the likely path to consume OpenSSL 3.5+ from the OS.
OpenSSL 3.5 adds ML-KEM, ML-DSA, SLH-DSA, TLS hybrid KEX, and ML-DSA key/sign/verify support in the default and FIPS providers.
OpenSSL 3.5 does not provide stock LAMPS Composite-ML-DSA certificate support in TLS.
Pure ML-DSA certificates are therefore closer to stock OpenSSL 3.5 than Composite-ML-DSA certificates.