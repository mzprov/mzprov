# trust-model

This document specifies the verifier's behavior, the exit code
contract, the trust pinning options, and the auto-discovery rules for
locating sidecars and source artifacts. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## 1. Two layers: integrity and trust

mzprov verification is layered. The two layers are conceptually
orthogonal and MUST be evaluated separately.

### 1.1 Integrity

> The bytes match what was signed by the key embedded in the sidecar.

Always evaluated. Consists of:

- Sidecar shape validation
- `verifying_key` decoding
- Key id consistency check (`payload.key_id` matches the key id
  derived from `verifying_key` per
  [`key-id-derivation.md`](key-id-derivation.md))
- Source artifact location (the `.d` directory or mzML file)
- Per-component hash recomputation and comparison
- Ed25519 signature verification over the canonical payload bytes

A sidecar that passes all of integrity is **internally consistent**.
This is necessary but not sufficient for trust.

### 1.2 Trust

> The embedded key is who I expected it to be.

Always evaluated, but **defaults to "not requested"** unless the
caller passes one of the trust flags. Consists of:

- `--expected-key-id` matching against the derived key id
- `--require-trusted` checking presence in the local trusted-keys
  registry
- `--public-key` consistency checking against an out-of-band PEM

A verifier with no trust flags reports integrity only. The trust
field on the result is `not_requested`. This is the default and is
appropriate for "I want to know whether this sidecar is internally
consistent" use cases. It is **not** appropriate for "I trust this
data" use cases — those MUST set at least one trust flag.

## 2. Exit code contract

A conforming verifier CLI MUST exit with one of the following codes:

| Code | Symbol | Meaning |
|---|---|---|
| 0 | `EXIT_OK` | Verified. Integrity passed and (if requested) trust passed. |
| 1 | `EXIT_GENERIC` | Generic / unexpected error not covered by another code. |
| 2 | `EXIT_KEY_ERROR` | A key file (signing or verifying) is missing or unreadable. |
| 3 | `EXIT_SIDECAR_ERROR` | The sidecar is missing, malformed, of an unknown version, has an unknown signature algorithm, has a key-id-consistency failure, or references an artifact that does not exist. Also raised when SQLite quiescence is violated. |
| 4 | `EXIT_UNSIGNED` | No sidecar was found. By default this is reported as a warning and exit 4 is only returned if `--strict` is set; without `--strict` the exit is 0 with a warning printed to stderr. |
| 5 | `EXIT_HASH_MISMATCH` | A recomputed content hash does not match the value in the payload. The diagnostic MUST name the field that diverged. |
| 6 | `EXIT_SIGNATURE_MISMATCH` | The signature does not validate against the canonical payload bytes and the verifying key. Distinct from `HASH_MISMATCH`: signature mismatch means the bytes that were signed are not what we now have; hash mismatch means the bytes on disk no longer match the hash that was signed. |
| 7 | `EXIT_KEY_NOT_TRUSTED` | A trust pin (`--expected-key-id` or `--require-trusted`) was set and not satisfied. |

The codes 0–7 are the **stable v0 contract**. Conforming
implementations MUST use exactly these codes for the named conditions.
Implementations MAY define additional codes in the 8–127 range for
implementation-specific failures, but MUST NOT reuse 0–7 for other
meanings.

## 3. Auto-discovery rules

When the verifier is given a path that is not directly a sidecar JSON
file, it MUST locate the sidecar according to the following rules
**in this order**.

### 3.1 Sidecar discovery

Given an input path `p`:

1. **If `p` is a file ending in `.json` whose name contains
   `.provenance`** (e.g. `foo.provenance.json`), `p` IS the sidecar.
   Return it.
2. **If `p` is a file with extension `.mzML` (case-insensitive):**
   - Look for `{p.stem}.provenance.json` in `p.parent`. If it exists,
     return it.
   - Otherwise, glob for `*.provenance.json` in `p.parent`. If
     exactly one match exists, return it. (This handles the case
     where the sidecar was named with a different stem than the
     mzML.)
   - Otherwise, return `None` (verifier reports `UNSIGNED`).
3. **If `p` is a directory:**
   - **If `p.suffix == ".d"`:** the sidecar conventionally lives one
     level up. Glob for `*.provenance.json` in `p.parent`. If any
     match, return the first (lexicographic order).
   - Then, glob for `*.provenance.json` in `p` itself. If any match,
     return the first.
   - Otherwise, return `None`.
4. **Otherwise**, return `None`.

### 3.2 `.d` source location

When verifying a `.d` sidecar, the verifier MUST locate the actual
`.d` directory **independently of any payload field**. Path resolution
that depends on `payload.experiment_name` or any other signed string
is NOT conforming, because that would let an attacker who controls
the payload bytes redirect verification to a phantom path.

The reference rule (`_find_unique_d`):

- Let `search_root` be the directory containing the sidecar.
- Look for any subdirectory of `search_root` whose name ends in `.d`
  AND that contains an `analysis.tdf` file. Each such subdirectory is
  a candidate.
- Look one level deeper: for any subdirectory of `search_root`,
  iterate its children and add any `*.d` directory containing
  `analysis.tdf` to the candidate list. This handles the conventional
  `{save_path}/{exp}/{exp}.d` layout.
- If exactly one candidate was found, return it.
- If zero or more than one candidate was found, raise `MissingArtifact`
  (mapped to `SIDECAR_ERROR`).

The verifier MUST NOT search beyond one level of nesting and MUST NOT
follow symlinks outside `search_root`. The intent is to bind
verification to a specific layout, not to walk an arbitrary
filesystem subtree.

### 3.3 Ground-truth DB location

If `payload.ground_truth_hash` is non-empty, the verifier MUST
recompute the canonical hash of `synthetic_data.db` in the same
directory as the sidecar (i.e., `sidecar.parent / "synthetic_data.db"`).
If that file does not exist, the verifier MUST raise `MissingArtifact`
(mapped to `SIDECAR_ERROR`).

If `payload.ground_truth_hash` is the empty string, the ground-truth
hash check is skipped and the verifier MUST NOT look for a
`synthetic_data.db` file.

### 3.4 Config file location

If `--config` was passed explicitly, the verifier MUST hash that file
and compare. If the explicit config is missing, the verifier MUST
raise `MissingArtifact` (mapped to `SIDECAR_ERROR`).

If `--config` was NOT passed, the verifier MUST look for the
conventional config copy at `{sidecar_stem}.config.toml` in the same
directory as the sidecar (where `sidecar_stem` is the sidecar
filename minus the `.provenance.json` suffix). If found, hash it and
compare.

If no config copy is found at the conventional path, the config_hash
check status MUST be reported as `UNCHECKED` (NOT `OK`, NOT
`MISMATCH`). The verifier MUST NOT fall back to the signed
`payload.config_hash` value as the recomputed value, because that
would make the check tautological (compare hash to itself, always
passes). `UNCHECKED` is a distinct check status that consumers can
filter on; the overall verification result remains successful as
long as the other components verify.

### 3.5 mzML source location

When verifying an mzML sidecar, the verifier MUST locate the actual
mzML file independently of any payload field, in the same way as the
`.d` rules: look for an `*.mzML` file in the sidecar's directory
matching the sidecar's filename stem first, then fall back to a
unique sibling. The exact matching rules are the same as the
`.mzml`-extension branch of §3.1 in reverse.

## 4. Trust pinning options

A v0 verifier MUST support the following three trust pinning options.
Each is independent of the others; a caller MAY combine them.

### 4.1 `--expected-key-id <KEY_ID>`

The verifier:

1. Derives `signer_key_id` from the embedded `verifying_key` per
   [`key-id-derivation.md`](key-id-derivation.md).
2. Compares `signer_key_id` against the supplied `<KEY_ID>` for
   exact (lowercase, prefix-included) match.
3. If they do not match, sets the trust check status to
   `id_mismatch` and the overall result to failed. Exit code is
   `KEY_NOT_TRUSTED` (7).

The comparison MUST be against the **derived** key id, not against
`payload.key_id`. (The label-vs-signer consistency check in
[`key-id-derivation.md`](key-id-derivation.md) §6 has already been
applied at this point, so the two are equal anyway, but the
comparison MUST be against the derived value as a matter of
principle: trust attaches to the cryptographic identity, not to the
attacker-controllable label.)

### 4.2 `--require-trusted`

The verifier:

1. Loads the local trusted-keys registry. By default this is at
   `~/.config/timsim/trusted_keys.json`. Implementations MAY honor
   `XDG_CONFIG_HOME` or an environment variable override.
2. Looks up the **derived** `signer_key_id` in the registry.
3. If absent, sets the trust check status to `not_in_registry` and
   the overall result to failed. Exit code: `KEY_NOT_TRUSTED` (7).
4. If present, compares the registered PEM bytes against the
   embedded `verifying_key` (after decoding). If they do not match
   byte-for-byte, sets the trust check status to
   `registry_pem_mismatch` and the overall result to failed.
   Exit code: `KEY_NOT_TRUSTED` (7).

The PEM byte-for-byte check is **defense in depth** against an
unforeseen 80-bit BLAKE2b collision in the key id. A registered
trusted key MUST match both its key id AND its full PEM.

### 4.3 `--public-key <PEM_PATH>`

The verifier:

1. Loads the public key from `<PEM_PATH>`.
2. Extracts the 32 raw bytes.
3. Compares to the 32 raw bytes of the embedded `verifying_key` from
   the sidecar.
4. If they do not match byte-for-byte, raises `MalformedSidecar`
   with a "split identity" diagnostic. Exit code: `SIDECAR_ERROR`
   (3).

This is a **consistency check** against an out-of-band copy of the
trusted public key, NOT an alternative trust path. The sidecar's
embedded `verifying_key` is what gets used for signature
verification. The override exists so that if a verifier holds a copy
of the public key from a trusted out-of-band channel (e.g.,
delivered by a different protocol, displayed at a conference,
included in a signed email), it can confirm that the embedded key
matches the out-of-band key. If they do not match, the sidecar is
not what the verifier thought it was.

## 5. Verifier check order

The reference verifier executes its checks in the order below. Other
implementations MAY differ in order, but the failure-mode reporting
MUST be consistent: a sidecar that the reference verifier rejects
with `KEY_ID_CONSISTENCY` SHOULD be rejected by other implementations
under the same name, even if their internal order is different.

1. Sidecar exists at the given path
2. Sidecar parses as UTF-8 JSON
3. Top-level shape is valid (the four required fields are present)
4. `type` tag is recognized → dispatch to `.d` or mzML payload parser
5. Payload schema validation (all required payload fields present and
   well-formed)
6. `verifying_key` decodes successfully
7. Key id consistency: `payload.key_id` equals the key id derived
   from `verifying_key`
8. (Optional) `--public-key` matches embedded key
9. Source artifact location (`.d` directory or mzML file)
10. Hash recomputation for each component
11. Composed `content_hash` recomputation
12. Signature decode (`ed25519:base64:...` parses)
13. Signature verification
14. (Optional) `--expected-key-id` match
15. (Optional) `--require-trusted` registry lookup

The reference verifier checks **hashes before signatures** (steps 10
and 11 before steps 12 and 13). This is why a sidecar with a
flipped hex character in `payload.d_content_hash` is reported as
`HASH_MISMATCH` (step 10) rather than as `SIGNATURE_MISMATCH` (step
13), even though the same mutation would also break the signature.

A v0 implementation MAY check signatures first. If it does, the
same input would be reported as `SIGNATURE_MISMATCH`. The test
vectors document this with a note in the `_metadata.description`
field for the affected vector. **Both orderings are conforming**;
this is an underdetermined area of the spec that is recorded as a
known cross-implementation difference and may be tightened in v1.

## 6. Result structure

A conforming verifier MUST be able to report, in addition to the
exit code, the following structured information for any sidecar
(passing or failing):

- Sidecar path
- Parsed payload (or as much of it as parsed before the failure)
- Per-component check results: each named hash field, with status
  (`ok`, `mismatch`, `unchecked`), expected value, actual value, and
  optional human-readable detail
- `signature_ok`: boolean
- `overall_ok`: boolean (this is `signature_ok` AND every check
  status is `ok` AND the trust check is satisfied)
- `trust`: status (`ok`, `not_requested`, `id_mismatch`,
  `not_in_registry`, `registry_pem_mismatch`)

The reference implementation exposes this as a `VerificationResult`
dataclass returned from `verify_sidecar()`. CLI consumers see it as
human-readable text by default and as JSON when `--json` is passed.

## 7. The `--strict` flag

By default, a sidecar that cannot be located (`UNSIGNED`) is
reported as a warning to stderr and the process exits 0. With
`--strict`, `UNSIGNED` becomes a hard failure (exit 4).

The default is permissive because the most common failure mode for
"no sidecar" is "the simulator did not opt in to signing yet" — a
non-error, but a useful warning.

## 8. Test vectors

Conforming implementations MUST verify the per-vector behavior under
[`../test-vectors/sidecar/`](../test-vectors/sidecar/), in particular:

- Every vector under `valid/` MUST exit 0 with no warnings.
- Every vector under `invalid/` MUST exit with the code in
  `_metadata.expected_exit_code`.
- The trust-model vectors (any vector named `*-wrong-key-id-label*`,
  any vector named `*-cross-format-*`) MUST be rejected with the
  named failure.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the JSON envelope and
  payload structure the verifier parses
- [`signature-scheme.md`](signature-scheme.md) — the signing primitive
  and the canonical payload form the verifier reconstructs
- [`key-id-derivation.md`](key-id-derivation.md) — how the verifier
  derives the signer's key id from the embedded `verifying_key`
- [`security-considerations.md`](security-considerations.md) — what
  the trust layer does NOT defend against
