# security-considerations

This document gathers the security claims, trust assumptions, and
explicit non-properties of the mzprov v0 reference implementation in
standard vocabulary, so a reviewer reading this document does not have
to reconstruct them from the architecture, threat model, and roadmap
documents.

It is normative in the sense that conforming implementations MUST NOT
make stronger claims than this document permits, and SHOULD make the
same claims wherever they are applicable.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## Security goals

mzprov v0 aims to provide:

- **Content integrity** of the signed bytes against unauthorized
  post-signing modification. Any change to the signed `.d` content,
  mzML content, ground-truth DB content, or copied config bytes is
  detected by hash comparison.
- **Origin attribution** of the signed bytes to a specific Ed25519
  public key. The verifier can determine which key id signed a
  sidecar; whether that key id corresponds to a *trusted* signer is a
  separate question handled by the trust layer (`--expected-key-id`,
  `--require-trusted`).
- **Format-disclosure binding**: a sidecar's `type` field commits the
  signed bundle to either the `.d` schema or the mzML schema. The
  verifier dispatches accordingly and refuses cross-format reuse.
- **Tamper-evidence with field-level diagnostics**: a tampered bundle
  does not just fail; the verifier reports which specific hash field
  diverged (`d_content_hash`, `mzml_content_hash`, `ground_truth_hash`,
  `config_hash`, or `content_hash`), with expected and actual digests.
- **Declared-synthetic self-disclosure**: a TimSim, Synthedia, or
  SMITER user who runs the default workflow produces a sidecar that
  identifies the producing tool. Honest simulators self-tag.

## Threat model recap

| Actor | Capability | Defense |
|---|---|---|
| **U** (verifier) | Reads any sidecar a third party sends | Verifies integrity locally; needs separate out-of-band knowledge to grant trust |
| **M** (offline tamperer) | Edits `.d`, mzML, ground-truth DB, config copy, or sidecar bytes after signing | Hash recomputation detects content changes; signature recomputation detects payload edits |
| **M** (key forger) | Generates a fresh keypair and re-signs a forged bundle | Integrity check passes, but `--expected-key-id` and `--require-trusted` reject the unknown signer |
| **M** (label forger) | Mutates `payload.key_id` or `payload.experiment_name` to claim a different identity | The verifier derives `key_id` from `verifying_key` and refuses sidecars where `payload.key_id` disagrees |
| **M** (split-identity) | Supplies `--public-key X.pem` while the sidecar embeds key `Y` | The verifier requires `--public-key` to match the embedded key byte-for-byte |
| **M** (encoding-tag swap on mzML) | Changes the precision cvParam (e.g. `MS:1000519` → `MS:1000522`) on the same payload bytes | The canonical record carries the precision tag (`f64`/`f32`/`i64`/`i32`) and value count, so the swap changes the hash |
| **S** (honest simulator) | Produces mzML/.d that resembles real instrument data | Signs its output; the resulting sidecar identifies the producing tool, supporting downstream policy filters |
| **S** (dishonest simulator) | Re-labels output as "real" by stripping the sidecar | Detected at the policy layer: a dataset claimed as real-instrument with no instrument-rooted attestation must be treated as unverified, regardless of whether a simulator sidecar is present or absent |

What is **not** in scope for the v0 threat model:

- A signer whose host is compromised and the private key file is read
  by an attacker. The attacker becomes indistinguishable from the
  legitimate signer. This is the inherent limit of a software key.
- An instrument operator who fabricates raw data on a real instrument.
  v0 has no instrument-rooted attestation, so it cannot defend against
  this.
- A repository or CA that vouches for the wrong key. There is no
  transparency log in v0.

## Trust assumptions

The v0 security claims depend on the following trust assumptions.
Each one names where it can be violated.

| Assumption | Where it can fail |
|---|---|
| The cryptography library implements Ed25519, BLAKE2b, and SHA-256 correctly | Library bug; backend selection; supply-chain attack |
| The signer's host is not compromised at signing time | Privilege escalation; malicious code in the signer's process |
| The private key file is readable only by the signer | Filesystem permissions misconfiguration; backup leakage |
| The verifier's host has not been substituted between trust pinning and verification | Local compromise; the trusted-keys registry has been edited by another process |
| Collisions in BLAKE2b truncated to 80 bits (the key id derivation) are computationally infeasible to find | True for blake2b-80 in the bounded population we expect; the registry's PEM-bytes comparison provides defense in depth against an unforeseen collision |
| The XML parser does not silently produce a different element tree for inputs that other standards-grade parsers accept | Cross-validated against `pyteomics` for mzML in the test suite |

## Properties NOT provided

The v0 system explicitly does **not** provide:

- **Confidentiality.** Sidecars and the signed bytes are plaintext.
  mzprov is an attestation scheme, not an encryption scheme.
- **Freshness against replay.** A signature over a given artifact is
  valid forever. There is no nonce, no challenge-response, no counter.
  This is deliberate: a non-interactive attestation system needs to
  be re-verifiable at any later time. The downside is that a verifier
  cannot tell whether a sidecar is new or replayed, only that it was
  produced at the asserted timestamp by the signer.
- **Forward secrecy.** Compromise of the signing key compromises
  every prior signature made by that key.
- **Non-repudiation against the signer's host.** Software keys cannot
  prove that the signer actually intended to sign a given artifact,
  only that the signing key was used. A signer who later denies
  having produced an artifact cannot be cryptographically refuted via
  v0 alone.
- **Instrument attestation.** A v0 sidecar does not prove that any
  data came from a real instrument. Vendor / instrument signing is the
  rest of the architecture and is not in this implementation.
- **Hardware-backed key protection.** The signing key is a software
  file. Anyone with read access to it can sign as that key.
- **Revocation.** There is no revocation list, certificate hierarchy,
  or transparency log. A compromised key remains valid for the
  lifetime of every existing sidecar that used it.
- **Trust on first use (TOFU).** Trust grants are explicit. The
  verifier never auto-adds a key to the trusted-keys registry on a
  successful first verification.
- **Conformance with any current standards-body protocol.** The
  sidecar format is project-internal; it does not yet implement
  in-toto, SLSA, PROV-O, or PSI-MS provenance vocabularies. Alignment
  with those is later-phase work.

## Cryptographic primitives

| Primitive | Algorithm | Where used |
|---|---|---|
| Asymmetric signing | Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) | Sidecar `signature` field |
| Content hashing | SHA-256 (FIPS 180-4) | `.d` and mzML canonical content hash, config hash, file streaming hash |
| Key id derivation | BLAKE2b ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)) truncated to 80 bits, base32-encoded lowercase | Local key id file, sidecar `payload.key_id` |
| Encoding | base64 ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) standard alphabet) | `signature` and `verifying_key` fields in the sidecar |

The signed bytes are the canonical JSON serialization of the
sidecar's `payload` object (sorted keys, no whitespace, UTF-8). All
other framing is outside the signature. The canonical record format
for `.d` (SQLite content) and mzML (spectrum content) is documented
in [`canonicalization-d-v0.md`](canonicalization-d-v0.md) and
[`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md).

## Algorithm agility

The `signature` and `verifying_key` fields use the prefix form
`"{algorithm}:{encoding}:{value}"`. Future revisions may carry, e.g.,
`"ed448:base64:..."` or `"ml-dsa-65:base64:..."`. A new signature
scheme is introduced via:

1. A new attestation `type` string.
2. A new value in the `signature` and `verifying_key` algorithm prefix.
3. Continued support for the old type by the verifier indefinitely.

The `canonicalization_version` field bumps independently when the
canonical record format changes. The two version axes are orthogonal:
a `v0` canonicalization with a `v1` signature scheme, and vice versa,
are both representable.

Implementations **MUST** refuse signature algorithms they do not
recognize and **MUST NOT** silently fall through to verifying with
the embedded key under an unknown algorithm string.

## Side-channel and implementation considerations

The v0 reference implementation relies on the constant-time
properties of the underlying `pyca/cryptography` library for Ed25519
signing and verification. No additional side-channel hardening is
done at the application level. A signer running in a shared-tenancy
environment with an adversary capable of cache-timing or speculative-
execution attacks should not be considered safe; no software-rooted
scheme is.

Atomic file writes (write-temp-then-rename, with `fsync` where the
platform supports it) are used for sidecar and registry files so that
a crash mid-write leaves either the previous version or the new
version, never a half-written file.

The mzML canonicalizer uses Python's stdlib
`xml.etree.ElementTree`. It does not perform XML schema validation,
DTD resolution, or external entity expansion, which avoids the most
common XML attack surface (XXE, billion-laughs). Bytes inside
`<binary>` elements are treated as opaque base64 and never
interpreted as XML.

The SQLite canonicalizer refuses to hash a database file when
`-wal`, `-shm`, or `-journal` sidecars are present (raising
`SqliteNotQuiescent`), so the on-disk view it hashes always matches
what other readers would see.

## Replay and freshness

v0 produces deterministic signatures given a fixed canonical input
plus a fixed key. The same artifact, signed twice with the same key,
produces the same signature both times. There is no nonce, no
monotonic counter, and no challenge-response.

The implications:

- **Re-verification works indefinitely.** A consumer can verify a
  sidecar produced years ago without contacting the signer.
- **A captured sidecar can be presented at any later time.** A
  verifier cannot distinguish a freshly-produced sidecar from a
  replayed one. This is acceptable for an attestation system (the
  artifact and its content hash are what matter; *when* the verifier
  received the sidecar is not part of the security claim) but
  consumers who care about delivery freshness must wrap the sidecar
  in a separate transport-layer freshness mechanism.
- **The `payload.timestamp_utc` field is self-asserted.** It is
  signed bytes, so it cannot be edited after signing without
  invalidating the signature, but the signer can lie about when they
  ran. There is no trusted timestamping authority in v0.

## Privacy considerations

A v0 sidecar contains:

- The signer's `key_id` (a one-way hash of the public key bytes; not
  personally identifying on its own)
- The producing tool's `tool_name` / `simulator_name` and version
  string
- The `experiment_name` as supplied by the user
- A wall-clock UTC timestamp
- Content hashes
- The full Ed25519 public key in base64 form

It does not contain file paths, hostnames, usernames, or any data
that the producer did not place in the `experiment_name` or the
config file (which is hashed but only embedded as a copy if
explicitly provided to the signer).

The local trusted-keys registry stores comments the user supplied
via `mzprov keys trust ... --comment "..."`. Users should not put
PII in those comments if the registry is intended to be portable
across machines or users.

A consumer who receives many sidecars from the same signer can
correlate them by `key_id`. This is intentional — origin attribution
is a security goal — but worth noting for users who want
pseudonymous publishing.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the format whose
  integrity this document discusses
- [`signature-scheme.md`](signature-scheme.md) — the Ed25519 signing
  primitive
- [`key-id-derivation.md`](key-id-derivation.md) — the BLAKE2b-80
  derivation and the label-vs-signer consistency check
- [`trust-model.md`](trust-model.md) — the trust layer this document
  refers to
- [`../docs/03-threat-model.md`](../docs/03-threat-model.md) — the
  non-normative companion that introduces actors and attacks
