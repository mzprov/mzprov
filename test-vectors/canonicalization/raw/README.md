# canonicalization/raw/ — Thermo .raw canonical-hash fixtures

Each `NNN-name.raw` file ships with `NNN-name.canonical-hash.txt`
containing the expected canonical hash, as `sha256:hex\n`. A
conforming implementation MUST run its `.raw` canonicalizer on the
input and produce a hash byte-identical to the expected value.

Unlike the mzML path, the `.raw` canonicalization is an **opaque
whole-file SHA-256** with a domain prefix (per
`spec/canonicalization-raw-v0.md`): there is no structural
normalization, so the hash is sensitive to every byte. The fixture
below is a small deterministic dummy `.raw` (NOT a real Thermo
container) whose only contract is byte-stability.

## Fixtures

| Fixture | Description | Property |
|---|---|---|
| `001-minimal.raw` | small deterministic opaque byte fixture | baseline opaque whole-file hash |
