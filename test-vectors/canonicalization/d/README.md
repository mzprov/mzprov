# canonicalization/d/ — Bruker .d canonical-hash fixtures

Each `NNN-name.d/` directory ships with `NNN-name.canonical-hash.txt`
containing the expected canonical hash, as `sha256:hex\n`. A
conforming implementation MUST run its `.d` canonicalizer on the
input and produce a hash byte-identical to the expected value.

## Fixtures

| Fixture | Description | Invariance proven |
|---|---|---|
| `001-minimal.d/` | minimal Bruker-shaped .d (analysis.tdf + analysis.tdf_bin) | baseline |

Additional invariance fixtures (page-size, VACUUM, REINDEX,
PRAGMA user_version) will land here as the spec is written down.
