# key-id-derivation

This document specifies how a stable key id is derived from an
Ed25519 public key. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## 1. Purpose

The key id is a short, stable, deterministic string identifier for an
Ed25519 public key. It exists so that:

- Signers can identify themselves in the sidecar `payload.key_id`
  field without embedding the full key.
- Trust pinning (`--expected-key-id`) can refer to a key by its short
  id rather than its full PEM.
- Verifiers can detect a sidecar where `payload.key_id` and the
  embedded `verifying_key` disagree (the **label-vs-signer** check
  in [`trust-model.md`](trust-model.md)).
- The local trusted-keys registry can index by key id.

The key id is derived by a one-way hash, so it is **not** a
substitute for the public key itself. A trust system that compares
only key ids and not the full PEM is vulnerable to a (computationally
infeasible but theoretically possible) collision in the truncated
hash. The reference verifier always compares the embedded
`verifying_key` byte-for-byte against the registered PEM as well as
checking the key id, as defense in depth.

## 2. Inputs and outputs

| | |
|---|---|
| Input | An Ed25519 public key (32 raw bytes) |
| Output | A string key id of the form `timsim-local-<16 base32-lowercase chars>` |

The output is exactly 28 characters: 13 characters of fixed prefix
plus 16 characters of base32-encoded digest.

## 3. Algorithm

The derivation MUST proceed as follows:

```
raw_pubkey = the 32 raw bytes of the Ed25519 public key
digest     = BLAKE2b(raw_pubkey, digest_size=10 bytes)
encoded    = base32(digest)              # 16 characters, RFC 4648 alphabet
encoded    = encoded with trailing '=' padding stripped
encoded    = encoded.lower()             # lowercase
key_id     = "timsim-local-" + encoded
```

Step by step:

1. **Get the raw public key bytes.** The Ed25519 public key MUST be
   serialized as its 32 raw bytes (the format that goes into the
   `verifying_key` field after base64 encoding). Do NOT use a
   SubjectPublicKeyInfo wrapper, a PKCS#8 wrapper, or any other
   container.

2. **Compute BLAKE2b with `digest_size=10`.** [BLAKE2b](https://www.rfc-editor.org/rfc/rfc7693)
   is a hash function that natively supports parameterized digest
   length (unlike SHA-2, which always produces a fixed-length output
   that you would have to truncate). The 10-byte (80-bit) digest
   length is chosen because:
   - 80 bits is enough collision resistance for the scale of keys we
     expect (preimage cost is far higher than collision-finding cost).
   - 10 bytes encodes to exactly 16 base32 characters with no
     padding required after stripping `=`.
   - The reference verifier compares full PEMs as a defense in depth,
     so a collision in the key id alone is not sufficient to forge a
     trust grant.

3. **Encode in base32 with the [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
   alphabet** (`A`–`Z`, `2`–`7`, `=` for padding). 10 bytes encode to
   16 characters plus 0 bytes of `=` padding (because 10 is divisible
   by 5/8 in the right way: 10 × 8 = 80 bits = 16 base32 chars).

4. **Strip trailing `=` characters.** No `=` should appear in v0 key
   ids because 10 bytes always encodes cleanly, but stripping is
   defensive and matches the reference implementation.

5. **Lowercase the result.** The base32 alphabet is uppercase by
   default; v0 key ids are lowercase. Lowercasing is what makes
   the key id terminal-friendly and URL-friendly.

6. **Prefix with `timsim-local-`.** The prefix is the v0 legacy of
   the lift. It is NOT optional in v0; verifiers MUST emit and
   compare the prefix exactly. A v1 rename to `mzprov-local-` is
   recorded in the FAQ as future work.

## 4. Worked example

For a public key with the raw 32 bytes:

```
93 5d 4f c5 d8 38 76 35 2c b1 31 80 7d e6 c3 7f
2c 5b dd 41 9b 6d 90 7f f4 12 23 35 cf 6f 8b 68
```

(this is the test-only key id `timsim-local-umdyuiienlum7prj` used by
the test vectors).

1. `raw_pubkey` is the 32 bytes above
2. `BLAKE2b(raw_pubkey, digest_size=10)` produces 10 specific bytes
3. base32-encoding those 10 bytes produces 16 uppercase characters
4. lowercased and prefixed: `timsim-local-umdyuiienlum7prj`

The test-only keypair under
[`../test-vectors/keys/test-only-keypair-001/`](../test-vectors/keys/test-only-keypair-001/)
includes a `key_id` text file with this exact value, and a
conforming implementation MUST reproduce it byte-for-byte from the
committed `verifying_key.pem`.

## 5. Properties

The derivation has the following properties that conforming
implementations MUST preserve:

1. **Determinism.** Two implementations on different machines, given
   the same raw public key bytes, MUST produce the same key id
   character-for-character.
2. **One-wayness.** Given a key id, an attacker cannot recover the
   public key bytes. (BLAKE2b is preimage-resistant.)
3. **Collision resistance is weak by design.** 80 bits of digest is
   too short for collision resistance against a determined adversary.
   This is acceptable because the verifier always compares the full
   `verifying_key` bytes against any registered PEM as a defense in
   depth (see [`trust-model.md`](trust-model.md) §4).
4. **Fixed length.** Every v0 key id is exactly 28 characters
   (13-char prefix + 16-char digest). This makes column alignment
   in CLI output predictable.

## 6. The label-vs-signer consistency check

This is the most important consequence of the derivation: a verifier
MUST always **derive** the key id from the embedded `verifying_key`
field at verification time, and MUST refuse the sidecar if the derived
key id does not equal `payload.key_id`.

This catches the **label-forger** attack:

> An attacker takes a valid sidecar, modifies `payload.key_id` to
> claim a different identity (e.g., to bypass `--expected-key-id`),
> but does NOT change `verifying_key` (because they cannot — they
> would also have to re-sign with the matching private key).

The attack fails because the verifier derives `key_id` from
`verifying_key` independently and compares against `payload.key_id`.
The reference verifier raises `MalformedSidecar` and maps the
failure to `SIDECAR_ERROR` (exit code 3).

A verifier MUST NOT use `payload.key_id` as anything other than a
self-consistency check. In particular:

- Trust pins (`--expected-key-id`) MUST be compared against the
  derived key id, not against the payload field.
- Trusted-keys registry lookups MUST be keyed by the derived key id,
  not by the payload field.
- Any UI that displays the signer's identity MUST show the derived
  key id, not the payload field.

## 7. Test vectors

The test-only keypair under
[`../test-vectors/keys/test-only-keypair-001/`](../test-vectors/keys/test-only-keypair-001/)
ships:

- `signing_key.pem` — the Ed25519 private key (PKCS#8 PEM, unencrypted)
- `verifying_key.pem` — the Ed25519 public key (SubjectPublicKeyInfo PEM)
- `key_id` — the expected derived key id, ASCII text

A conforming implementation MUST:

1. Load the verifying key from `verifying_key.pem`.
2. Extract its 32 raw bytes.
3. Apply the derivation in §3.
4. Produce a key id that matches the contents of the `key_id` file
   byte-for-byte.

The label-forger invalid vectors
(`*-wrong-key-id-label.json`) under
[`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/)
test the label-vs-signer consistency check from §6. A conforming
verifier MUST reject these with `SIDECAR_ERROR` (exit code 3).

## See also

- [`signature-scheme.md`](signature-scheme.md) — Ed25519 signing and
  the encoding of `signature` and `verifying_key`
- [`trust-model.md`](trust-model.md) — how the trust layer uses the
  derived key id (and the full PEM, as defense in depth)
- [`sidecar-format.md`](sidecar-format.md) — the `payload.key_id`
  field and where it appears in the envelope
