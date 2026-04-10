# canonicalization-d-v0

This document specifies the v0 canonicalization of a Bruker timsTOF
`.d` directory and the associated SQLite content canonicalization. It
is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

The canonicalization version this document specifies is `v0`. The
sidecar's `payload.canonicalization_version` field MUST equal `"v0"`
for this spec to apply. A future `v1` revision MUST live in a separate
spec document and MUST coexist with v0 indefinitely so that v0 sidecars
remain verifiable.

## 1. Inputs and outputs

The `.d` canonicalization takes one input — a path to a directory —
and produces one output: a 32-byte SHA-256 digest, encoded in the
sidecar as `sha256:<64 lowercase hex chars>`.

A conforming canonicalizer:

- MUST accept any directory whose name ends in `.d` and contains both
  `analysis.tdf` (a SQLite database) and `analysis.tdf_bin` (a binary
  spectrum file).
- MUST refuse to operate on a directory missing either of these files.
  The reference implementation raises `FileNotFoundError`.
- MUST NOT modify the input directory in any way. Implementations
  SHOULD open the SQLite file in read-only, immutable mode (the
  reference implementation uses the SQLite URI
  `file:{path}?mode=ro&immutable=1`) so the operating system never
  creates `-journal`, `-wal`, or `-shm` sidecars during hashing.

## 2. SQLite quiescence guard

Before opening or reading the `analysis.tdf` SQLite file, the
canonicalizer MUST check for the presence of any of the following
files alongside it:

- `analysis.tdf-journal`
- `analysis.tdf-wal`
- `analysis.tdf-shm`

If any of these are present, the canonicalizer MUST refuse to operate
on the database and MUST raise an error that distinguishes
"not-quiescent" from other failures. The reference implementation
raises `SqliteNotQuiescent`, which the verifier maps to the
`SIDECAR_ERROR` exit code.

This check is required because SQLite read-only / immutable mode
deliberately ignores WAL and journal sidecars: hashing the main
database file in their presence would produce a digest of a view that
ordinary readers will never see, which would let a verifier attest
"VERIFIED" against a stale image. Refusing in this state is the only
correct response.

## 3. SQLite content canonicalization (`canonicalize_sqlite`)

The canonical content of a SQLite database is a deterministic byte
stream constructed from its **user tables**, their **columns**, and
their **rows** under a fixed encoding. The hash is the SHA-256 of this
stream. The output is invariant under:

- `VACUUM`
- `REINDEX`
- `PRAGMA user_version` changes
- Different page-size settings
- Different insert orders for the same logical content

It is sensitive to:

- Any difference in row content
- Any added or removed row
- Any added or removed column or table
- Any column type difference

### 3.1 Byte separators

Two ASCII control bytes are used as separators throughout the canonical
form. They are chosen because they cannot legally appear in SQL
identifiers and are not whitespace, so they survive any text-handling
layer that might otherwise normalize them.

| Symbol | Byte | Name | Used between |
|---|---|---|---|
| `US` | `0x1F` | Unit Separator | adjacent fields |
| `RS` | `0x1E` | Record Separator | adjacent rows |

### 3.2 Table enumeration

The canonicalizer MUST enumerate user tables via:

```sql
SELECT name FROM sqlite_master
WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
ORDER BY name;
```

Tables MUST be visited in the order returned (alphabetical by name,
SQLite default collation).

Tables whose names begin with `sqlite_` MUST be excluded. Indexes,
views, and triggers MUST NOT be canonicalized.

### 3.3 Column enumeration

For each table, the canonicalizer MUST enumerate columns via
`PRAGMA table_info("<table>")` and visit them in `cid` (declared)
order. The reference implementation re-sorts by `cid` defensively.

For each column, the canonicalizer captures the column **name** (as
declared) and the column **declared type** (from the `type` column of
`PRAGMA table_info`; the empty string if no type was declared).

### 3.4 Row enumeration

For each non-empty table (a table with zero columns is skipped after
the column block; see §3.6), the canonicalizer MUST select all rows
via:

```sql
SELECT * FROM "<table>" ORDER BY <quoted col 1>, <quoted col 2>, ..., <quoted col N>;
```

where the column list is the columns from §3.3 in `cid` order. SQL
identifiers MUST be quoted by wrapping in double quotes and doubling
any embedded double quotes (`abc"def` → `"abc""def"`).

The `ORDER BY` over **every column** is what makes the canonical form
invariant under insert order, page layout, rowid quirks, and any
storage reordering.

### 3.5 Value canonicalization (`canonicalize_value`)

Each cell value MUST be encoded according to its SQLite storage class
as follows:

| Storage class | Canonical encoding |
|---|---|
| `NULL` | `b"\x00NULL\x00"` (literal bytes) |
| `INTEGER` | the decimal ASCII representation of the integer; e.g. `b"42"` for `42`, `b"-7"` for `-7`. Booleans MUST be treated as integers (`True` → `b"1"`, `False` → `b"0"`) when SQLite returns them, and MUST be handled before the integer case in implementations where `bool` is a subclass of `int`. |
| `REAL` | the IEEE 754 double-precision big-endian byte representation, hex-encoded as 16 lowercase ASCII characters; e.g. `b"4024000000000000"` for `10.0`. NaN MUST be normalized to the canonical bit pattern `0x7FF8000000000000` (its hex form is `b"7ff8000000000000"`). Negative zero is preserved as the IEEE 754 negative-zero bit pattern. |
| `TEXT` | `b"\x00len" + ascii(N) + b"\x00" + utf8` where `utf8` is the value's bytes after **NFC** Unicode normalization, and `N` is the byte length of `utf8`. |
| `BLOB` | `b"\x00blob" + ascii(N) + b"\x00" + lowercase_hex` where `lowercase_hex` is the lowercase hex representation of the blob bytes and `N` is the blob's byte length. |

A canonicalizer that encounters any other value type MUST raise an
error. SQLite has no other storage classes; any other Python type
indicates a programming error in the implementation.

### 3.6 The canonical record stream

For each table, the canonicalizer MUST emit, in order:

1. **A table header record:**
   ```
   US + b"table" + US + utf8(table_name) + US
   ```
2. **One column header record per column** (in `cid` order):
   ```
   US + b"col" + US + utf8(col_name) + US + utf8(col_type) + US
   ```
3. **One row record per row** (in the ORDER BY order from §3.4):
   ```
   US + b"row" + US + canonical_value(c1) + US + canonical_value(c2) + US + ... + canonical_value(cN) + US + RS
   ```

Tables with zero columns MUST emit the table header and the (empty)
column block, then move to the next table without selecting rows. (A
table with zero columns is a malformed schema, but the canonicalizer
MUST be deterministic about it.)

The complete record stream is fed to a SHA-256 hasher. The output of
`canonicalize_sqlite` is the 32-byte hasher digest.

## 4. `.d` directory composition (`canonicalize_d`)

The canonical content hash of a `.d` directory is composed from two
components:

| Component | How it is hashed |
|---|---|
| `analysis.tdf_bin` | streaming SHA-256 of the file bytes (no canonicalization) |
| `analysis.tdf` | `canonicalize_sqlite()` per §3 |

The composition is:

```
canonicalize_d(d_path)
  = sha256( bin_hash || tdf_hash )
```

where `||` is byte concatenation, `bin_hash` is the 32-byte streaming
digest of `analysis.tdf_bin`, and `tdf_hash` is the 32-byte
`canonicalize_sqlite` digest of `analysis.tdf`.

The output is 32 raw bytes; the sidecar encodes it as
`sha256:<64 lowercase hex>`.

## 5. Composed content hash (`compose_content_hash`)

The single `content_hash` that lives in `payload.content_hash` and
that is bound by the signature is composed from:

- `d_hash` (the output of §4)
- `ground_truth_hash` (the output of §3 applied to an optional
  `synthetic_data.db`, or `None`)
- `config_hash` (SHA-256 of the raw config bytes; see §6)

The composition is:

```
domain     = b"timsim.v0\x1f"
US         = b"\x1f"
gt_marker  = ground_truth_hash if present else b"none"

content_hash = sha256(
    domain
    || d_hash
    || US
    || gt_marker
    || US
    || config_hash
)
```

Notes:

- The literal `b"none"` is the marker for "no ground truth was signed".
  Implementations MUST NOT use any other marker. Using a marker rather
  than omitting the field ensures `None` and an all-zero ground-truth
  hash do not collide.
- The `domain` prefix `b"timsim.v0\x1f"` is the v0 legacy of the lift
  and is part of the byte stream. It MUST be emitted exactly as
  specified, with the trailing `US` byte. A future v1 will use a
  different domain prefix to prevent cross-version collisions.
- All three input hashes MUST be 32 bytes. Implementations SHOULD
  validate this length on input and raise rather than truncating or
  padding.

## 6. Config hash (`canonicalize_bytes`)

The config hash is simply:

```
config_hash = sha256(config_bytes)
```

where `config_bytes` is the literal byte content of the config TOML
file as it appeared on disk at signing time. **The config bytes are
NOT re-serialized, NOT normalized, and NOT canonicalized in any other
way.** The intent is to bind the attestation to the *exact bytes* the
user wrote.

If the signing call was passed no config (the mzML signing path
allows this), the config bytes MUST be the empty byte string `b""`.

## 7. Test vectors

Conforming implementations MUST:

- Reproduce the canonical hash of every fixture under
  [`../test-vectors/canonicalization/d/`](../test-vectors/canonicalization/d/)
  byte-identically.
- Verify every paired `.d` vector under
  [`../test-vectors/sidecar/valid/`](../test-vectors/sidecar/valid/)
  with `type = timsim.provenance.v0`.
- Reject every paired `.d` vector under
  [`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/)
  with `type = timsim.provenance.v0` with an exit code matching
  `_metadata.expected_exit_code`.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the JSON envelope and
  payload field semantics
- [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) — the
  parallel spec for mzML
- [`security-considerations.md`](security-considerations.md) — what
  the canonical-form encoding choices defend against
