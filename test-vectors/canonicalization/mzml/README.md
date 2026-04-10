# canonicalization/mzml/ — mzML canonical-hash fixtures

Each `NNN-name.mzML` file ships with `NNN-name.canonical-hash.txt`
containing the expected canonical hash, as `sha256:hex\n`. A
conforming implementation MUST run its mzML canonicalizer on the
input and produce a hash byte-identical to the expected value.

## Fixtures

| Fixture | Source bytes | Expected hash | Invariance proven |
|---|---|---|---|
| `001-indented.mzML` | indented, multi-line | (see file) | baseline |
| `002-compact.mzML` | no whitespace, single line | **same as 001** | whitespace invariance |

Implementations that fail to produce identical hashes for 001 and
002 are not whitespace-invariant and do not conform to v0.
