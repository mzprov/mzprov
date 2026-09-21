# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning policy: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
applies to the Python reference implementation. The specification version
(`v0`, `v1`, ...) and the canonicalization version
(`canonicalization_version` in the sidecar) evolve independently — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Unreleased

### Added

- `mzprov chain sign` and `mzprov chain verify`: the command line for
  provenance chains, which were available only as Python functions.
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
- C# signing: `mzprov sign` (`.d`/mzML/`.raw`, JSON sidecar or `--embed`) and
  `mzprov keys generate`. Ed25519 keys are byte-format-compatible with the
  Python reference's key files (interoperable both directions).
- Cross-implementation round-trip harness
  (`test-vectors/_harness/run_roundtrip.py`) and a `roundtrip` CI job: a
  differential test proving an attestation produced by one implementation is
  accepted by another (both directions, all transports). Added to the
  `conformance` merge gate.
- Initial repository skeleton.
- Three-license split: CC-BY-4.0 for `docs/` and `spec/`, Apache-2.0 for
  `implementations/python/`, CC0 1.0 for `test-vectors/`.
- Top-level `README.md`, `CONTRIBUTING.md`, and `LICENSE` umbrella document.
- Stub `README.md` in each subdirectory describing its scope and status.

### Fixed

- Chain verification reports a malformed sidecar or graph as `3`, as v0
  does, instead of `4`, which v0 reserves for an unsigned file. Chain-only
  outcomes keep `8` (broken link) and `9` (missing provenance).
- `mzprov sign --tool-name` is now recorded for a `.d`. It was ignored and the
  payload always said `TimSim`, so a genuine acquisition was attested as
  simulator output. `sign_simulation_output` gains a `simulator_name`
  argument, defaulting to `"TimSim"`.
- When an embedded `.d` record references a missing ground-truth DB, `verify`
  still exits `3` (spec/trust-model.md 3.3) but the error now names the
  embedded record, its signer, experiment and key, instead of only a path.
- An `--experiment-name` containing a path separator no longer creates a
  directory for the sidecar. It is rejected unless `--sidecar` names the file.
- The real-data tests read their inputs from `MZPROV_*` environment variables
  instead of paths on one machine.

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
