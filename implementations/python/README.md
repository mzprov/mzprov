# mzprov

Cryptographic provenance for mass spectrometry data.

`mzprov` signs mass spectrometry data files with an Ed25519 attestation and
verifies them later. A signature binds the file's content to the tool that
produced it, its configuration and a signing key, so any change made after
signing is detected. This package is the Python reference implementation of
the [mzprov specification](https://github.com/mzprov/mzprov/tree/main/spec).

Supported formats:

| Format | How it is hashed | Where the attestation lives |
|---|---|---|
| Bruker `.d` | canonical SQLite content plus binary | JSON sidecar, or embedded in `analysis.tdf` |
| mzML | canonical spectrum content, all binary arrays | JSON sidecar, or embedded in the file |
| Thermo and Waters `.raw` | opaque whole-file digest | JSON sidecar |
| SCIEX `.wiff` | the whole `.wiff` / `.wiff.scan` bundle | JSON sidecar |

mzprov guarantees provenance, not truth. A valid signature says these bytes
have not changed since this key signed them. It does not say the data came
from an instrument, or that the experiment was sound.

## Install

```bash
pip install mzprov
```

Python 3.11 to 3.13. The only runtime dependency is `cryptography`.

## Use

```bash
# Sign a Bruker .d. --config binds the run to its configuration bytes.
mzprov sign run.d --experiment-name run-001 --config run.toml \
    --tool-name timsTOF --tool-version 1.0

# Sign an mzML produced by any tool (--config is optional here).
mzprov sign run.mzML --experiment-name run-001 \
    --tool-name msconvert --tool-version 3.0.24

# Verify. The sidecar or embedded record is discovered from the data path.
mzprov verify run.d
mzprov verify run.mzML

# Verify and require a known signer.
mzprov verify run.d --expected-key-id <key-id>
mzprov verify run.d --require-trusted
```

The first `sign` generates a signing key at
`~/.config/timsim/keys/signing_key.pem` and prints its key id. Manage keys
and the trusted-keys registry with `mzprov keys show|export|trust|list|untrust`.

Exit codes are fixed by the specification: `0` verified, `1` generic error,
`2` key error, `3` sidecar or artifact error, `4` unsigned (with `--strict`),
`5` hash mismatch, `6` signature mismatch, `7` signer not trusted. Add
`--json` to `verify` for a machine-readable result.

### Python API

```python
from mzprov import sign_mzml_output, verify_sidecar

sidecar = sign_mzml_output(
    mzml_path="run.mzML",
    config_path=None,
    experiment_name="run-001",
    tool_name="msconvert",
    tool_version="3.0.24",
)
result = verify_sidecar(sidecar)
assert result.overall_ok
```

### Provenance chains (prototype)

`mzprov.chain` signs derivations: each output records the artifacts it was
made from, and `verify_chain` walks the lineage back to a trusted root, for
example raw acquisition to mzML to search result. Chains are Python-only and
a v1 draft; they are not yet part of the frozen v0 specification. A verified
chain shows the provenance claims are intact, not that each transform was
correct.

## Links

- Specification and design documents: <https://github.com/mzprov/mzprov>
- Test vectors shared by the Python, Rust and C# implementations:
  <https://github.com/mzprov/mzprov/tree/main/test-vectors>
- Changelog: <https://github.com/mzprov/mzprov/blob/main/CHANGELOG.md>

## License

Apache-2.0. The specification and documentation are CC-BY-4.0 and the test
vectors CC0; see the repository's
[LICENSE](https://github.com/mzprov/mzprov/blob/main/LICENSE).
