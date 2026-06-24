# Post-Quantum Support

This page defines the target shape for post-quantum support in CCF, not the current state of it.

## Goals

The target design provides post-quantum safety for user-to-node TLS, node-to-node communication, ledger signatures, receipts, endorsements trust chain, member governance signatures, and user and member certificate authentication.

## Identity type disclaimer

Identity references use `identity_type`, not type-agnostic IDs.

- `identity_type` is a CCF-specific enum, not the concrete crypto, e.g. `ML-DSA-65` or `EC384`.
- It identifies the identity variant, not the purpose, but if needed, two enum values may still point to identities with the same crypto shape, although there are no use cases for this at the moment. E.g. `ML-DSA-65-1`, `ML-DSA-65-2`.

Reasons for that are:

- It allows a clear previous identity endorsement chain per type, so it is clear who endorses whom.
- It allows a straightforward upgrade story, where each node advertises the `[T1, ..., TN]` identities it requires, making it possible to tell them apart in order to create/share missing ones.
- It allows identifying them in attestation reports.

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

Nit. Users are mapped 1<->cert, so in order to get PQ TLS they'll need to have a PQ cert issued.

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
Since this is internal node communication, there is no need to offer several N2N identities in parallel, and the complete transition design is to be sorted out later.

## Introducing and removing identities

Identity material and purpose bindings are introduced or removed atomically.

* Join - nodes advertise the service identity types they support when they join
* Service create/recovery - the node sets them straight away in the KV, with a corresponding join policy

Join policy is also expressed in terms of service identity types and purposes.
It should distinguish required, allowed, and disallowed combinations.
If both EC and PQ signing are required, EC-only and PQ-only joiners are both rejected.
The concrete policy can be JSON/Rego.
The rollout shape mirrors the [COSE-only ledger upgrade](https://ccf.dev/main/operations/configuration.html#upgrading-to-cose-only-ledger-signatures).

| Stage | Purpose bindings / node config | Join policy | Effect |
| --- | --- | --- | --- |
| Before | `EC -> [TLS, SIGN]` | `required EC -> [TLS, SIGN]` | EC TLS and EC signing. |
| Policy upgrade #1 | `EC -> [TLS, SIGN]` | `required EC -> [TLS, SIGN]; allowed PQ -> [SIGN]` | PQ signing identities may join, but are not mandatory yet. |
| Upgrade | new nodes use `EC -> [TLS, SIGN]; PQ -> [SIGN]` | same as policy upgrade #1 | New nodes keep EC TLS and add PQ signing. |
| Retire old nodes | `EC -> [TLS, SIGN]; PQ -> [SIGN]` | same as policy upgrade #1 | Nodes without PQ signing leave the network. |
| Policy upgrade #2 | `EC -> [TLS, SIGN]; PQ -> [SIGN]` | `required EC -> [TLS, SIGN]; required PQ -> [SIGN]` | New EC-only and PQ-only nodes are rejected. |
| Completed | `EC -> [TLS, SIGN]; PQ -> [SIGN]` | same as policy upgrade #2 | Network signs with both EC and PQ and keeps EC TLS. |

Mixed identity periods are expected during the rolling update window.
This is an intentional design choice, not a temporary inconsistency.

If a joining node advertises an allowed identity type and the service does not have that identity yet, the identity must be created in the same join transaction.
The identity is then reused for future joiners of the same type, and its private material is shared with trusted nodes the same way service private material is shared today.
On recovery, the existing join policy is preserved.
On service creation, the initial join policy is operator-set in the current design; deriving it automatically from the configured service identities is still to be defined.

## Previous identity endorsements

Previous identity endorsements are stored separately from identity material and purpose bindings.
They are keyed by `identity_type`, so each identity has its own continuity chain.
Identities are created on each service create/recovery, the same as the service identity today.

```text
DR:    0         1         2         3

A:     A0 <----- A1 <----- A2
       ^  \
       +---+

B:                         B2 <----- B3
                           ^  \
                           +---+
```

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
0        7          16                                               64
+--------+----------+-----------------------------------------------+
| LAYOUT | RESERVED | DIGEST (zero padded if SHA-256)               |
+--------+----------+-----------------------------------------------+
```

| Field | Meaning |
| --- | --- |
| `LAYOUT` | 7-byte binding metadata: version, attestation type, `identity_type`, kind, purpose, algorithm suite, hash algorithm |
| `RESERVED` | 9 bytes, must be zero |
| `DIGEST` | 48-byte digest slot: SHA-256 digest followed by 16 zero bytes, or SHA-384 digest |

`LAYOUT` is:

```text
byte:    00 01 02 03 04 05 06
layout:  V  A  T  K  P  S  H
```

| Field | Meaning |
| --- | --- |
| V | Binding format version |
| A | Attestation type: service or node |
| T | CCF `identity_type` |
| K | Identity material kind: key, cert, or another kind |
| P | Purpose or purpose bitmask |
| S | Signing or certificate algorithm suite |
| H | Hash algorithm |

Examples:

```text
identity material: DER bytes of EC service TLS certificate
A = service
H = SHA-256
K = cert
T = ec_p384
P = UserTLS
S = ecdsa_p384_sha384

DIGEST = SHA256(ec_service_tls_cert_der)
```

```text
identity material: DER SubjectPublicKeyInfo bytes of PQ signing key
A = service
H = SHA-384
K = key
T = mldsa65
P = Signing
S = mldsa65

DIGEST = SHA384(mldsa65_signing_public_key_der)
```

For node join, attestation must bind the node identity used to request trust:

```text
identity material: DER SubjectPublicKeyInfo bytes of node N2N TLS PQ key
A = node
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

## Members and users

Members and users should mirror the current model.
Users use certificate authentication with PQ-enabled certificates.
Members use certificate authentication where needed, and governance messages are COSE-signed with PQ or composite COSE signatures.
Registering a new PQ-enabled cert creates a new user/member identity, same as any cert rotation today.

## Current platform and standards support

The standards RFCs/drafts possibly targeted by this design are:

* [`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) for Composite-ML-DSA X.509 certificates
* [`draft-reddy-tls-composite-mldsa`](https://datatracker.ietf.org/doc/draft-reddy-tls-composite-mldsa/) for Composite-ML-DSA authentication in TLS 1.3.
* [`draft-ietf-jose-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) for JOSE/COSE composite signatures.
* [`RFC 9881`](https://datatracker.ietf.org/doc/rfc9881/) for pure ML-DSA X.509 certificates.
* [`RFC 9964`](https://datatracker.ietf.org/doc/rfc9964/) for pure ML-DSA JOSE/COSE signatures.
* [`FIPS 204`](https://csrc.nist.gov/pubs/fips/204/final) for the ML-DSA algorithm itself.
* [OpenSSL 3.5 ML-DSA key support](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/) and [OpenSSL 3.5 ML-DSA signature support](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/) for implementation details.

CCF will target Azure Linux 4 and OpenSSL 3.5, so here is the list of what is currently supported and not supported:

- OpenSSL 3.5 supports ML-DSA keys and signatures.
- OpenSSL 3.5 supports ML-KEM, SLH-DSA, and TLS hybrid KEX.
- OpenSSL 3.5 *does not* support LAMPS Composite-ML-DSA certificates or Composite-ML-DSA authentication in TLS.

### Azure Linux 4 confirmation

This was confirmed on Azure Linux 4 with OpenSSL 3.5, without SymCrypt yet.

Confirmed support:

- Pure `ML-DSA-65` X.509 certificates can be generated, DER-parsed, and verified with `X509_verify`.
- `ML-DSA-65` and `SLH-DSA-SHA2-128s` signatures can be generated and verified.
- `ML-KEM-512`, `ML-KEM-768`, and `ML-KEM-1024` encapsulation and decapsulation work.
- TLS 1.3 can negotiate the `X25519MLKEM768` hybrid group with an `ML-DSA-65` server certificate, `mldsa65` CertificateVerify, and client certificate verification.
- Composite ML-DSA X.509/TLS is not supported by this stock OpenSSL build. No provider composite algorithms are exposed, composite keymgmt/signature candidates cannot be fetched, and TLS rejects composite signature algorithm names. Without an `EVP_PKEY` keymgmt and signature provider implementation, X.509 and TLS have no composite primitive to use.

Composite certificates can be encoded, but stock OpenSSL 3.5 cannot use them as normal certificates.
OpenSSL has no Composite-ML-DSA key, signature, X.509, or TLS `SignatureScheme` support.
CCF therefore cannot ask OpenSSL to generate, verify, select, or present a Composite-ML-DSA certificate in TLS.

Composite COSE signatures are technically possible with stock OpenSSL 3.5, but not as one OpenSSL algorithm.
The JOSE/COSE draft reuses the LAMPS composite key and signature encoding, carried as AKP `pub`/`priv` bytes.
CCF can implement the draft combiner and use OpenSSL only for the ML-DSA and classical component signatures.
This is draft-compliant if CCF pins the draft version, labels, prehash, key encodings, and COSE algorithm values.

The component keys must still be a single composite key.
The drafts require fresh component key generation and forbid reusing those keys in other contexts or as standalone keys.
For certificate-backed identities, `x5chain`/`x5c` should refer to a LAMPS composite X.509 certificate.
Stock OpenSSL cannot create that certificate form, so this needs custom tooling or another provider/library.
It is not RFC-standard yet: RFC 9964 only standardizes pure ML-DSA for JOSE/COSE.

### Path forward

Start with a PQ-only extra identity for RFC 9964 ML-DSA COSE signing.
Keep the existing classical identity and signature during migration.
For TLS confidentiality, enable OpenSSL 3.5 ML-KEM hybrid groups, starting with `X25519MLKEM768`.

Leave composite support for later.
Composite TLS depends on composite certificate and TLS signature support that stock OpenSSL does not provide.
For signing, require two COSE signatures for now: one classical and one ML-DSA.
