# implementations/python/ — Python reference implementation

This is the **reference implementation** of mzprov in Python. It is the
implementation against which the test vectors under
[`../../test-vectors/`](../../test-vectors/) are first generated, and it
is the implementation that the TimSim simulator uses internally via a
thin wrapper.

## Status

The implementation is being lifted from the `imspy_simulation.provenance`
module in the rustims project (branch `feature/sign-simulation`). Until
the lift is complete, the canonical source remains
`packages/imspy-simulation/src/imspy_simulation/provenance/` in that
branch.

After the lift, `imspy_simulation.provenance` becomes a thin re-export
shim around `mzprov`, and this directory is the canonical source. See
`MIGRATION_PLAN.md` in the rustims branch for the migration plan.

## Planned package metadata

| | |
|---|---|
| PyPI name | `mzprov` |
| Module name | `mzprov` |
| Python | >=3.11, <3.14 |
| Runtime dependencies | `cryptography` (Ed25519, BLAKE2b, SHA-256) |
| Optional dependencies | `pyteomics` (cross-validation against an independent mzML parser, test only) |

## Planned CLI surface

The CLI is named `mzprov` and dispatches by subcommand:

```
mzprov sign     <file>           sign a .d directory or an mzML file
mzprov verify   <file>           verify a sidecar (auto-discovers)
mzprov keys     show|export|trust|list|untrust
```

See the top-level [`../../README.md`](../../README.md) for usage examples.

## Licensing

The Python reference implementation is licensed under Apache 2.0. See
[`../../LICENSE-APACHE`](../../LICENSE-APACHE).
