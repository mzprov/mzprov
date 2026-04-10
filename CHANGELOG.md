# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning policy: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
applies to the Python reference implementation. The specification version
(`v0`, `v1`, ...) and the canonicalization version
(`canonicalization_version` in the sidecar) evolve independently — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Unreleased

### Added

- Initial repository skeleton.
- Three-license split: CC-BY-4.0 for `docs/` and `spec/`, Apache-2.0 for
  `implementations/python/`, CC0 1.0 for `test-vectors/`.
- Top-level `README.md`, `CONTRIBUTING.md`, and `LICENSE` umbrella document.
- Stub `README.md` in each subdirectory describing its scope and status.

### Notes

- The Python reference implementation is being lifted from
  `imspy_simulation.provenance` in the rustims project (branch
  `feature/sign-simulation`). The `v0` sidecar format, canonicalization
  algorithms, and verifier behavior are frozen at the state shipping in
  TimSim as of 2026-04-10.
- The full migration plan lives in the rustims branch as `MIGRATION_PLAN.md`.
