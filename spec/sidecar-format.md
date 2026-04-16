# sidecar-format

This document specifies the on-disk JSON envelope of an mzprov v0
sidecar and the field semantics of its inner payload. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## 1. Envelope structure

A v0 sidecar is a single UTF-8 JSON object with exactly four
top-level fields:

```json
{
  "type":          "<attestation-type-tag>",
  "payload":       { ... payload fields ... },
  "signature":     "ed25519:base64:<...>",
  "verifying_key": "ed25519:base64:<...>"
}
```

A conforming sidecar:

- MUST be a JSON object at its root.
- MUST contain the four fields `type`, `payload`, `signature`,
  `verifying_key`. Implementations MUST reject sidecars missing any of
  these fields with a sidecar-malformed error.
- MAY contain additional top-level fields. Verifiers MUST ignore
  unknown top-level fields. Test vectors use the additional field
  `_metadata` to record their expected outcome; signing tools MUST NOT
  emit `_metadata`.
- MUST encode the JSON as UTF-8 with no byte order mark.
- SHOULD pretty-print the envelope with sorted keys and 2-space
  indentation for human inspection. The pretty-printing of the
  envelope is NOT signed and MAY differ between implementations.

## 2. Attestation types

There are exactly two `type` values in v0:

| type | Payload schema | Subject |
|---|---|---|
| `timsim.provenance.v0` | §3 Payload (`.d`) | a Bruker timsTOF `.d` directory |
| `timsim.provenance.mzml.v0` | §4 Payload (mzML) | an mzML file |

A verifier MUST dispatch on the `type` field to select the payload
parser. A verifier MUST refuse `type` values it does not recognize and
MUST NOT silently fall back to a different parser. The reference
implementation raises `UnknownVersion` and maps the failure to the
`SIDECAR_ERROR` exit code.

The `timsim.` prefix is the v0 legacy of the lift from the
`imspy_simulation.provenance` module. A v1 rename to `mzprov.` is a
candidate change that would require a new attestation type tag and
would coexist indefinitely with v0 (per the algorithm-agility
contract in [`signature-scheme.md`](signature-scheme.md)).

## 3. Payload — `.d` (`type = timsim.provenance.v0`)

The `.d` payload object MUST contain the following fields, in any
order. The signed canonical form (§5) sorts them.

| Field | JSON type | Format | Semantics |
|---|---|---|---|
| `simulator_name` | string | free text | Identifies the producing simulator (e.g., `"TimSim"`) |
| `simulator_version` | string | free text | Version string of the producing simulator |
| `experiment_name` | string | free text | A human-readable label for the dataset (signed; verifier never uses it for path resolution) |
| `config_hash` | string | `sha256:<64 hex>` | SHA-256 of the config bytes that produced the dataset |
| `d_content_hash` | string | `sha256:<64 hex>` | Canonical content hash of the `.d` directory (see [`canonicalization-d-v0.md`](canonicalization-d-v0.md)) |
| `ground_truth_hash` | string | `sha256:<64 hex>` or `""` | Canonical content hash of an optional ground-truth SQLite DB; the empty string indicates no ground truth was signed |
| `content_hash` | string | `sha256:<64 hex>` | The composed content hash from `d_content_hash`, `ground_truth_hash`, `config_hash` (see [`canonicalization-d-v0.md`](canonicalization-d-v0.md) §4) |
| `timestamp_utc` | string | `YYYY-MM-DDTHH:MM:SS.fffZ` | UTC wall-clock timestamp at signing; self-asserted, no trusted time authority |
| `key_id` | string | see [`key-id-derivation.md`](key-id-derivation.md) | The signer's stable key id; verifiers MUST derive this from `verifying_key` and reject mismatches |
| `canonicalization_version` | string | `"v0"` in v0 | Selects the canonicalization algorithm; verifiers MUST refuse unknown values |

A verifier MUST refuse a `.d` payload missing any of these fields. The
reference implementation raises `MalformedSidecar` and maps the failure
to `SIDECAR_ERROR`.

A verifier MUST NOT use `experiment_name` or any other payload field as
a path or directory name when locating the source `.d`. Path resolution
is the verifier's responsibility (per
[`trust-model.md`](trust-model.md) §3) and MUST be independent of any
attacker-controllable signed string.

## 4. Payload — mzML (`type = timsim.provenance.mzml.v0`)

The mzML payload object MUST contain the following fields. It does NOT
have `d_content_hash`, `ground_truth_hash`, or `simulator_name`/
`simulator_version`. The producing tool is named generically
(`tool_name`/`tool_version`) because mzML is emitted by simulators
*and* converters.

| Field | JSON type | Format | Semantics |
|---|---|---|---|
| `tool_name` | string | free text | Producing tool name |
| `tool_version` | string | free text | Producing tool version |
| `experiment_name` | string | free text | Free-form dataset label |
| `config_hash` | string | `sha256:<64 hex>` | SHA-256 of optional config bytes (empty bytes hash if no config) |
| `mzml_content_hash` | string | `sha256:<64 hex>` | Canonical mzML content hash (see [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md)) |
| `content_hash` | string | `sha256:<64 hex>` | The composed content hash from `mzml_content_hash` and `config_hash` |
| `timestamp_utc` | string | `YYYY-MM-DDTHH:MM:SS.fffZ` | UTC wall-clock timestamp at signing |
| `key_id` | string | see [`key-id-derivation.md`](key-id-derivation.md) | Signer's stable key id |
| `canonicalization_version` | string | `"v0"` in v0 | |

The same payload-field-vs-path-resolution rule from §3 applies: a
verifier MUST locate the source mzML independently of any payload
field.

## 5. Canonical signed form

The bytes that get signed are the canonical JSON serialization of the
**inner payload object only**. They are NOT the bytes of the
pretty-printed envelope.

The canonical serialization of the payload MUST be:

- A JSON object containing exactly the payload fields defined in §3
  or §4 (no extras, no `_metadata`)
- With keys sorted in ascending byte (codepoint) order
- With NO whitespace anywhere (no spaces after colons, no spaces after
  commas, no newlines)
- Encoded as UTF-8
- With non-ASCII characters preserved (the equivalent of Python's
  `ensure_ascii=False`)

The reference implementation produces this form via Python's
`json.dumps(asdict(payload), sort_keys=True, separators=(",", ":"),
ensure_ascii=False).encode("utf-8")`. The same output is produced by
[RFC 8785 (JCS — JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785)
applied to the same input object, although v0 does NOT formally
require JCS conformance.

A verifier MUST reconstruct the canonical form from the parsed payload
object before checking the signature. A verifier MUST NOT extract the
canonical bytes from the on-disk envelope by character-range slicing.

## 6. Hash field encoding

Every hash field in the payload uses the form:

```
sha256:<64 lowercase hex characters>
```

Hash fields MUST use lowercase hex. Verifiers MAY accept uppercase as
input but MUST treat it as a malformed sidecar field unless the
reference implementation behavior is matched.

The literal string `""` (empty) is permitted only for `ground_truth_hash`
in the `.d` payload, where it means "no ground truth was signed". Every
other hash field MUST be present and well-formed.

## 7. Signature and verifying key encoding

The `signature` and `verifying_key` fields are strings of the form:

```
{algorithm}:{encoding}:{value}
```

In v0:

- `algorithm` MUST be `ed25519`. Verifiers MUST refuse other values
  with `SIDECAR_ERROR` (the reference implementation raises
  `MalformedSidecar` from the signature decoder).
- `encoding` MUST be `base64` (RFC 4648 standard alphabet, with
  `=` padding).
- `value` is the base64-encoded raw bytes of the Ed25519 signature
  (64 bytes) or public key (32 bytes).

Implementations MUST refuse signature algorithms they do not recognize
and MUST NOT silently fall through to verifying with the embedded key
under an unknown algorithm string. See
[`signature-scheme.md`](signature-scheme.md) for the complete
signature scheme spec including the algorithm-agility envelope rules.

## 8. Sidecar discovery on disk

When a verifier is given a path that is not directly a sidecar JSON
file, it MUST locate the sidecar according to the discovery rules in
[`trust-model.md`](trust-model.md) §3. In summary:

- For a `*.provenance.json` file: that is the sidecar.
- For an mzML file: look for `{stem}.provenance.json` in the same
  directory; if absent, accept any single `*.provenance.json` sibling.
- For a `.d` directory: look for `*.provenance.json` in the parent
  directory.
- For any other directory: look for `*.provenance.json` inside it.

The discovery rules are normative because the verifier exit codes
depend on whether discovery returned a sidecar (`UNSIGNED` if not).

This section describes the **JSON transport** only. The embedded
transport defined in [`embedded-d-v0.md`](embedded-d-v0.md) (and
its mzML counterpart) bypasses these rules: the in-band container
(`analysis.tdf` for `.d`) is the discovery target. A verifier MUST
attempt the embedded transport first and fall back to the rules
above only when the embedded reader returns no provenance. See
[`embedded-d-v0.md`](embedded-d-v0.md) §6 for the full dispatch
order.

## 9. Validation

| Error condition | Reference exit code |
|---|---|
| Sidecar JSON does not parse as UTF-8 JSON | `SIDECAR_ERROR` (3) |
| Sidecar root is not a JSON object | `SIDECAR_ERROR` (3) |
| Required top-level field missing | `SIDECAR_ERROR` (3) |
| `type` is not a recognized attestation type | `SIDECAR_ERROR` (3) |
| `payload` is not an object | `SIDECAR_ERROR` (3) |
| Payload field missing | `SIDECAR_ERROR` (3) |
| `canonicalization_version` is not `"v0"` | `SIDECAR_ERROR` (3) |
| Hash field is not `sha256:<hex>` | `SIDECAR_ERROR` (3) |
| `signature` field algorithm prefix is not `ed25519` | `SIDECAR_ERROR` (3) |
| `verifying_key` field algorithm prefix is not `ed25519` | `SIDECAR_ERROR` (3) |
| `payload.key_id` does not match the key id derived from `verifying_key` | `SIDECAR_ERROR` (3) |
| Source artifact (`.d` or mzML) not found | `SIDECAR_ERROR` (3) (`MissingArtifact`) |
| Recomputed content hash differs from payload field | `HASH_MISMATCH` (5) |
| Signature does not verify against payload canonical bytes + verifying key | `SIGNATURE_MISMATCH` (6) |
| Trust pin (`--expected-key-id` or `--require-trusted`) not satisfied | `KEY_NOT_TRUSTED` (7) |
| No sidecar found at all | `UNSIGNED` (4) |

## 10. Test vectors

Implementations MUST verify every vector under
[`../test-vectors/sidecar/valid/`](../test-vectors/sidecar/valid/) and
MUST reject every vector under
[`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/)
with an exit code that matches the vector's `_metadata.expected_exit_code`.

## See also

- [`signature-scheme.md`](signature-scheme.md) — Ed25519 signing details and the algorithm-agility envelope
- [`key-id-derivation.md`](key-id-derivation.md) — how `payload.key_id` is derived from `verifying_key`
- [`canonicalization-d-v0.md`](canonicalization-d-v0.md) — what `d_content_hash`, `ground_truth_hash`, and `content_hash` are computed over
- [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) — what `mzml_content_hash` and `content_hash` are computed over (mzML side)
- [`trust-model.md`](trust-model.md) — verifier behavior, exit codes, trust pinning
