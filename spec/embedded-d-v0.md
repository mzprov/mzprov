# embedded-d-v0

This document specifies the v0 in-band embedding of an mzprov sidecar
envelope inside a Bruker timsTOF `.d` directory. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## 1. Two equivalent storage modes

mzprov v0 supports two equivalent storage modes for a `.d` sidecar:

- **Sidecar JSON.** A `*.provenance.json` file alongside the `.d`
  directory, located by the discovery rules in
  [`sidecar-format.md`](sidecar-format.md) §8. This is the universal
  fallback and is the only mode supported for opaque single-blob
  vendor formats (e.g., Waters `.raw`, Thermo `.raw` without vendor
  cooperation).
- **Embedded.** A single row in a reserved SQLite table named
  `mzprov_provenance` inside `analysis.tdf`, defined by this
  document. Embedded mode keeps the artifact a single self-describing
  bundle, which simplifies hand-off and upload to repositories such
  as PRIDE.

**The signed envelope is byte-identical between the two modes.** The
canonical signed form defined in [`sidecar-format.md`](sidecar-format.md)
§5 is computed over the same payload object regardless of transport.
Only the bytes around the envelope (file vs. table row) differ.

A `.d` MAY have a sidecar JSON, an embedded row, or both. See §6 for
verifier dispatch when both are present.

## 2. Schema

When mzprov writes embedded provenance to `analysis.tdf`, it MUST
create the following table if it does not already exist:

```sql
CREATE TABLE IF NOT EXISTS mzprov_provenance (
    sidecar_json TEXT NOT NULL
);
```

A conforming `.d`:

- MUST contain at most one row in `mzprov_provenance`. A signer that
  finds an existing row MUST `DELETE FROM mzprov_provenance` before
  inserting the new row, atomically within the same transaction.
- MUST store, in the single column `sidecar_json`, the **complete
  sidecar envelope** as a UTF-8 JSON string, conforming to
  [`sidecar-format.md`](sidecar-format.md) §1. The string is the
  envelope object, not the inner payload object — a verifier must
  see `type`, `payload`, `signature`, and `verifying_key`.

Multi-signer embedded provenance (more than one row, keyed by
`key_id`) is explicitly out of scope for v0; see
[`v1-draft/README.md`](v1-draft/README.md) "Repository countersignature
attestations" for the expected v1 evolution.

## 3. Exclusion from the canonical hash

The reserved table name `mzprov_provenance` is excluded from the `.d`
canonical content hash by
[`canonicalization-d-v0.md`](canonicalization-d-v0.md) §3.2. This is
what makes embed-after-hash well-defined:

1. The signer computes `canonicalize_d(d)` *with* the exclusion in
   effect — this yields the same bytes whether or not the table is
   currently present.
2. The signer signs the composed content hash and produces the
   sidecar envelope.
3. The signer inserts the envelope into `mzprov_provenance` (creating
   the table if needed). The exclusion rule guarantees the
   recomputed hash after insertion is unchanged.
4. A verifier reads the row, recomputes the canonical hash with the
   row excluded, and verifies the signature.

Conforming implementations MUST NOT special-case the exclusion to
"only if the table contains a row" or "only if it was present at
hash time." The exclusion is unconditional.

## 4. Signer protocol

A conforming embedded signer MUST:

1. **Pre-check quiescence.** Before opening `analysis.tdf` for write,
   check that no SQLite sidecar files (`-journal`, `-wal`, `-shm`)
   exist alongside it. If any are present, refuse with the same
   not-quiescent error used at hash time
   ([`canonicalization-d-v0.md`](canonicalization-d-v0.md) §2). The
   reference implementation reuses `_assert_sqlite_quiescent`.
2. **Open in DELETE journal mode.** The signer MUST set
   `PRAGMA journal_mode=DELETE` for the write connection (or use a
   connection that is known not to leave WAL/SHM files behind on
   close). The reference implementation issues `PRAGMA
   journal_mode=DELETE` immediately after opening and verifies the
   pragma return value.
3. **Compute the canonical hash** of the `.d` per
   [`canonicalization-d-v0.md`](canonicalization-d-v0.md) §4 and
   compose the content hash per §5 of that document.
4. **Build the sidecar envelope** per
   [`sidecar-format.md`](sidecar-format.md) §1, including signing the
   canonical form per §5 of that document.
5. **Write the row in a single transaction:**
   ```sql
   BEGIN IMMEDIATE;
   CREATE TABLE IF NOT EXISTS mzprov_provenance (sidecar_json TEXT NOT NULL);
   DELETE FROM mzprov_provenance;
   INSERT INTO mzprov_provenance (sidecar_json) VALUES (?);
   COMMIT;
   ```
6. **Close cleanly.** The signer MUST close the connection. After
   close, the signer MUST re-check that no `-journal`, `-wal`, or
   `-shm` sidecar files exist next to `analysis.tdf`. If any do, the
   signer MUST raise an error and SHOULD attempt to surface a
   recovery hint (typically: another process is holding the database
   open, or the database was previously WAL-mode and a checkpoint is
   needed). The reference implementation raises `SqliteNotQuiescent`
   from the same code path used at hash time.

The post-write quiescence check is required because the verifier's
quiescence guard
([`canonicalization-d-v0.md`](canonicalization-d-v0.md) §2) will
refuse to operate in their presence — a signer that left them behind
would produce a `.d` that no verifier can read.

## 5. Reader protocol

A conforming reader (used both by the verifier and by any tool that
wants to extract embedded provenance):

1. MUST check for `analysis.tdf` quiescence per
   [`canonicalization-d-v0.md`](canonicalization-d-v0.md) §2 before
   opening.
2. MUST open `analysis.tdf` read-only with the same URI used at hash
   time (`file:{path}?mode=ro&immutable=1`).
3. MUST check whether the `mzprov_provenance` table exists via:
   ```sql
   SELECT name FROM sqlite_master
   WHERE type = 'table' AND name = 'mzprov_provenance';
   ```
   If absent, the reader MUST return "no embedded provenance" (the
   reference implementation returns `None`).
4. If present, the reader MUST select the single row:
   ```sql
   SELECT sidecar_json FROM mzprov_provenance;
   ```
   - If zero rows: return "no embedded provenance".
   - If exactly one row: return the `sidecar_json` string.
   - If more than one row: refuse with a malformed-embed error. The
     reference implementation maps this to `SIDECAR_ERROR`.

The returned `sidecar_json` string is then parsed and validated by
the standard envelope rules in
[`sidecar-format.md`](sidecar-format.md) §§1, 9.

## 6. Verifier dispatch

When the verifier is given a path that resolves to a `.d` directory
(either directly, or via the experiment-directory descent in §6.1),
it MUST follow this order:

1. Run the §5 reader protocol on `analysis.tdf`.
2. If the reader returns a non-null `sidecar_json`, that is the
   sidecar; proceed with verification using it.
3. If the reader returns null (no `mzprov_provenance` table or zero
   rows), fall back to the JSON sidecar discovery rules in
   [`sidecar-format.md`](sidecar-format.md) §8.
4. If both produce nothing, the `.d` is `UNSIGNED` (exit code 4).

### 6.1 Experiment-directory descent

When the verifier is given a directory path that is NOT itself a
`.d`, it MUST attempt to locate a unique `.d` inside it (at depth 0
or 1, matching the conventional `{save_path}/{exp}/{exp}.d` layout)
and, if exactly one is found, apply the dispatch in §6 to that
`.d` *before* falling back to JSON sidecar discovery on the
original directory. Without this descent, an experiment directory
that contains an embedded-only `.d` (no sibling
`*.provenance.json`) would be misreported as `UNSIGNED`.

If two or more `.d` directories are found, the descent does not
resolve and the verifier falls through to JSON sidecar discovery on
the original directory (which has its own "unique sibling"
disambiguation).

### 6.2 Error propagation: no silent fallback

If the §5 reader (or the §1 quiescence check that precedes it) raises
an error — for example because `analysis.tdf` has a `-journal`,
`-wal`, or `-shm` sidecar present, or the embedded table is malformed
(more than one row, non-UTF-8 value, etc.) — the verifier MUST
surface that error and MUST NOT silently fall back to the JSON
sidecar transport. Embedded provenance is authoritative once it is
present (or once the embedded probe proves the transport is broken):
quietly accepting a sibling `*.provenance.json` in that state would
let a malformed or stale embed be masked by a co-located JSON
attestation that the user did not intend to be load-bearing.

The reference implementations map this to `SIDECAR_ERROR` (exit
code 3). Conforming verifiers MUST refuse equivalent behavior
("try embedded, swallow on error, return JSON success") even when
the resulting JSON sidecar would itself verify cleanly.

### 6.3 Defense-in-depth comparison (optional)

A verifier MAY, as a defense-in-depth check, compare the embedded
row against any sidecar JSON file also discovered by §8 and refuse
on divergence. This is OPTIONAL in v0 and is expected to become
RECOMMENDED in a later revision.

The verifier MUST NOT prefer the JSON sidecar over the embedded row
when both are present — embedded is in-band and authoritative.

## 7. Discovery interaction with sidecar-format §8

[`sidecar-format.md`](sidecar-format.md) §8 defines on-disk discovery
for the sidecar JSON path. That section is unchanged by this
document; it remains the rule for the JSON transport. The embedded
transport bypasses §8 entirely: the `analysis.tdf` SQLite file is
the discovery target.

When this document and §8 are read together, the effective rule for
a `.d` directory is:

1. Try the §5 reader on `analysis.tdf` (this document).
2. If null, apply §8 of `sidecar-format.md` to the parent directory.
3. If both null, return `UNSIGNED`.

## 8. Validation

| Error condition | Reference exit code |
|---|---|
| `analysis.tdf` not quiescent at read time | `SIDECAR_ERROR` (3) |
| `mzprov_provenance` table contains more than one row | `SIDECAR_ERROR` (3) |
| `sidecar_json` value is not valid UTF-8 | `SIDECAR_ERROR` (3) |
| `sidecar_json` value does not parse as a v0 envelope (per [`sidecar-format.md`](sidecar-format.md) §9) | `SIDECAR_ERROR` (3) |
| Signer leaves a `-wal`, `-shm`, or `-journal` file alongside `analysis.tdf` | signer-side error; not assigned a verifier exit code because the verifier's quiescence guard catches the resulting state as `SIDECAR_ERROR` (3) at next read |

## 9. Test vectors

Conforming implementations MUST:

- Reproduce the canonical hash of every paired fixture under
  [`../test-vectors/canonicalization/d/`](../test-vectors/canonicalization/d/)
  with the `mzprov_provenance` table both present and absent — the
  two MUST yield byte-identical digests (exclusion correctness).
- Verify every paired `.d` vector under
  [`../test-vectors/sidecar/valid/embedded-d/`](../test-vectors/sidecar/valid/embedded-d/)
  via the embedded reader path.
- Reject every paired `.d` vector under
  [`../test-vectors/sidecar/invalid/embedded-d/`](../test-vectors/sidecar/invalid/embedded-d/)
  with the exit code in `_metadata.expected_exit_code`.

## See also

- [`canonicalization-d-v0.md`](canonicalization-d-v0.md) — §3.2 defines
  the table-name exclusion that makes this embedding safe
- [`sidecar-format.md`](sidecar-format.md) — the envelope schema, §8
  the JSON transport's on-disk discovery
- [`embedded-mzml-v0.md`](embedded-mzml-v0.md) — the parallel
  embedding spec for mzML (slot choice pending HUPO-PSI / Richard
  ratification)
- [`trust-model.md`](trust-model.md) — exit code semantics
