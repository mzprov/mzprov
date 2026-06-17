# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning policy: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
applies to the Python reference implementation. The specification version
(`v0`, `v1`, ...) and the canonicalization version
(`canonicalization_version` in the sidecar) evolve independently — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Unreleased

### Added

- Cross-implementation conformance CI (`.github/workflows/conformance.yml`):
  runs the Python unit suite plus a language-agnostic black-box harness
  (`test-vectors/_harness/run_conformance.py`) over `test-vectors/` on every
  push and PR to `main`. A `conformance` gate job requires every
  implementation job to pass, turning the test vectors from a documented
  contract into an enforced merge gate (issue #1).
- Independent C# implementation (`implementations/csharp/`) of `verify` (all
  three transports) and `canonicalize` (`.d`/mzML/`.raw`), passing every v0
  vector under the shared conformance harness. Shares no code with the
  Python reference; both target the same spec and vectors.
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
- One v0 vector was corrected during conformance bring-up:
  `d-tampered-payload-d-content-hash` declared `expected_exit_code: 5`
  (HASH_MISMATCH) but a payload-field tamper invalidates the signature, and
  the reference verifier checks the signature before per-field hashes, so the
  authoritative result is `6` (SIGNATURE_MISMATCH) — consistent with the
  sibling `d-tampered-payload-experiment-name` vector.
