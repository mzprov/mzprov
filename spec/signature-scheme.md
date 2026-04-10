# signature-scheme

This document specifies the signing primitive, the signature encoding,
and the algorithm-agility envelope used by mzprov v0. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## 1. Signing primitive

The v0 signing primitive is **Ed25519** as defined in
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

A conforming signer:

- MUST use Ed25519 with the standard parameters (the `Ed25519` variant,
  not `Ed25519ph` or `Ed25519ctx`).
- MUST sign the bytes produced by the canonical payload serialization
  defined in [`sidecar-format.md`](sidecar-format.md) §5.
- MUST NOT pre-hash the canonical payload bytes before passing them to
  Ed25519. Ed25519 internally hashes its input; pre-hashing would be
  the `Ed25519ph` variant, which is a different signature scheme and
  produces incompatible signatures.

A conforming verifier:

- MUST reconstruct the canonical payload bytes from the parsed payload
  object, NOT extract them from the on-disk envelope by character
  range.
- MUST verify the signature against `(canonical_payload_bytes,
  signature, verifying_key)` using a conforming Ed25519
  implementation.

## 2. Signature encoding

Signatures and public keys are encoded in the sidecar as
prefix-tagged base64 strings:

```
{algorithm}:{encoding}:{value}
```

In v0:

| Field | Algorithm | Encoding | Value |
|---|---|---|---|
| `signature` | `ed25519` | `base64` | the 64 raw bytes of the Ed25519 signature, base64-encoded with the [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) standard alphabet and `=` padding |
| `verifying_key` | `ed25519` | `base64` | the 32 raw bytes of the Ed25519 public key, base64-encoded with the same alphabet |

Implementations MUST emit the literal lowercase strings `ed25519` and
`base64` for the algorithm and encoding fields.

A verifier MUST refuse a `signature` or `verifying_key` field whose
algorithm prefix is not `ed25519` and MUST NOT silently fall through
to verifying with the embedded key under an unknown algorithm name.
Likewise for an unknown encoding prefix. The reference implementation
raises `MalformedSidecar` from the signature decoder, mapped to the
`SIDECAR_ERROR` exit code.

## 3. Verifying-key encoding

The v0 verifying key on disk is the 32 raw bytes of an Ed25519 public
key (NOT the 32 + 32 bytes of a private key, NOT a SubjectPublicKeyInfo
DER wrapper, NOT a PKCS#8 wrapper). The base64-decoded form is exactly
32 bytes.

A conforming implementation:

- MUST refuse to load a verifying-key string whose decoded length is
  not 32 bytes.
- MUST use the cryptographic library's "raw public key" loader
  (e.g., `Ed25519PublicKey.from_public_bytes` in Python's
  `cryptography` library; `Ed25519/X25519` raw constructors in .NET
  `System.Security.Cryptography` or BouncyCastle).

The signing-key file on disk is a separate concern and is specified
in §5.

## 4. Signing flow

The v0 signing flow is:

1. **Compose the payload object** with the fields specified in
   [`sidecar-format.md`](sidecar-format.md) §3 (for `.d`) or §4 (for
   mzML). The `key_id` field MUST be derived from the verifying key
   per [`key-id-derivation.md`](key-id-derivation.md), NOT chosen by
   the signer.
2. **Serialize the payload to canonical bytes** per
   [`sidecar-format.md`](sidecar-format.md) §5: sorted keys, no
   whitespace, UTF-8.
3. **Sign the canonical bytes** with Ed25519 and the signing key.
4. **Encode the signature** as `ed25519:base64:<...>`.
5. **Encode the verifying key** as `ed25519:base64:<...>`.
6. **Build the envelope** with `type`, `payload`, `signature`,
   `verifying_key`.
7. **Write the envelope to disk atomically** (write to a temp file,
   fsync, then rename).

## 5. Signing key file format

A v0 signing key on disk is stored as PKCS#8 PEM, unencrypted:

- File format: PEM
- Inner format: PKCS#8 (`PrivateKeyInfo`)
- Encryption: none

The accompanying public key file is stored as SubjectPublicKeyInfo PEM.

These on-disk formats are an implementation convention, NOT a wire
format requirement. A conforming implementation MAY use any local key
storage scheme, but the `verifying_key` field that ends up in the
sidecar MUST always be the raw 32 bytes encoded as `ed25519:base64:<...>`.

The reference implementation:

- Generates fresh keys via `cryptography`'s `Ed25519PrivateKey.generate()`.
- Writes the private key with `chmod 0600` on filesystems that
  support it.
- Stores keys at `~/.config/timsim/keys/signing_key.pem`,
  `~/.config/timsim/keys/verifying_key.pem`, and
  `~/.config/timsim/keys/key_id`. The path is preserved as-is for
  backwards compatibility with the original lift; see the FAQ for
  the v1 rename plan.

## 6. Algorithm agility

The `{algorithm}:{encoding}:{value}` envelope is designed to support
future signature schemes without breaking v0 verifiers. New signature
schemes are introduced via:

1. **A new attestation `type` string** in
   [`sidecar-format.md`](sidecar-format.md) §2 (e.g.,
   `mzprov.provenance.v1`).
2. **A new value in the `signature` and `verifying_key` algorithm
   prefix** (e.g., `ed448`, `ml-dsa-65` for ML-DSA).
3. **Continued support for the v0 type by every verifier
   indefinitely**, so that existing v0 sidecars stay verifiable.

The `canonicalization_version` field bumps independently when the
canonical record format changes. The two version axes are orthogonal:
a `v0` canonicalization with a `v1` signature scheme, and vice versa,
are both representable.

Implementations MUST refuse signature algorithms they do not recognize
and MUST NOT silently fall through to verifying with the embedded key
under an unknown algorithm string. This is the most important rule of
the algorithm-agility envelope: an envelope that *advertised*
agility but silently accepted unknown algorithms would be worse than
one that did not have agility at all, because it would let an
attacker use a known-broken scheme by simply renaming it.

## 7. Determinism and replay

Ed25519 signatures over the same canonical payload bytes with the
same key are **deterministic**: signing twice produces the same
signature both times. This is a property of Ed25519, not a feature
mzprov adds.

The implications:

- **Re-verification works indefinitely.** A consumer can verify a
  sidecar produced years ago without contacting the signer.
- **A captured sidecar can be presented at any later time.** A
  verifier cannot distinguish a freshly-produced sidecar from a
  replayed one. This is acceptable for an attestation system (the
  artifact and its content hash are what matter; *when* the verifier
  received the sidecar is not part of the security claim) but
  consumers who care about delivery freshness MUST wrap the sidecar
  in a separate transport-layer freshness mechanism.
- **The `payload.timestamp_utc` field is self-asserted.** It is
  signed bytes, so it cannot be edited after signing without
  invalidating the signature, but the signer can lie about when they
  ran. There is no trusted timestamping authority in v0.

See [`security-considerations.md`](security-considerations.md) §
"Replay and freshness" for the full treatment.

## 8. Test vectors

Conforming implementations MUST verify the signatures on every valid
sidecar vector under
[`../test-vectors/sidecar/valid/`](../test-vectors/sidecar/valid/) and
MUST reject the signature-related invalid vectors under
[`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/),
specifically:

- `*-tampered-payload-experiment-name/` — verifier MUST report
  `SIGNATURE_MISMATCH` (exit code 6) because the canonical bytes of
  the modified payload no longer match the signature.
- `*-unknown-signature-algorithm/` — verifier MUST report
  `SIDECAR_ERROR` (exit code 3) and MUST NOT verify the signature
  under any other algorithm prefix.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the JSON envelope and
  the canonical payload form that gets signed
- [`key-id-derivation.md`](key-id-derivation.md) — how the signer's
  stable key id is derived from the Ed25519 public key
- [`trust-model.md`](trust-model.md) — what the verifier does with
  the signed sidecar after the signature checks pass
