# Contributing to mzprov

This document explains how to propose changes, where they land, and how a
proposal becomes part of the normative specification.

## What is governed

Three things move at independent rates and need separate change processes:

1. **The specification version** (`v0`, `v1`, ...). Frozen except via the
   `v1-draft/` path described below.
2. **The canonicalization version** (`canonicalization_version` in the
   sidecar). Bumps independently of the spec version when the canonical
   record format for `.d` or mzML changes in a way that affects hashes.
3. **The Python reference implementation version** (semver). Bumps freely;
   bug fixes and clarifications that do not change the spec ship as patch
   releases.

## What is frozen at v0

The following are not changing in v0. Proposals that conflict with them
belong in [`spec/v1-draft/`](spec/v1-draft/), not in [`spec/`](spec/).

- The sidecar JSON envelope (field names, ordering, signature format)
- The Ed25519 signature scheme
- The BLAKE2b-80 + base32-lowercase key id derivation
- The `.d` canonicalization algorithm
- The mzML canonicalization algorithm (v0 scope: spectrum content, all
  binary arrays, no chromatograms, no run-level metadata, no numpress)
- The verifier exit codes `0`–`7`
- The trust model (`--expected-key-id`, `--require-trusted`, `--public-key`)

## How to propose a new feature

1. **Open an issue** describing the motivation, the threat-model implication,
   and the proposed scope.
2. **Write a draft** as a new file under `spec/v1-draft/`. The draft uses
   RFC 2119 keywords and is structured the same way as the v0 spec
   documents. Drafts MAY contradict v0 — the draft directory is the place
   for that.
3. **Add test vectors** under `test-vectors/v1-draft/` (a parallel tree)
   covering the valid and invalid cases the draft introduces.
4. **Implement** the draft in at least one of the implementations, behind a
   feature flag if necessary.
5. **Discuss.** Drafts stay in `v1-draft/` until there is consensus among
   the active implementations and approval by a maintainer.
6. **Graduate.** When a draft graduates, it moves into `spec/` (replacing
   or extending the relevant v0 document), the test vectors move into
   `test-vectors/`, and the spec version bumps.

## How to fix a bug in v0

A bug in v0 is a discrepancy between the specification, the test vectors,
and the reference implementation. The first step is to determine which is
authoritative for the property in question:

- **Test vectors are the contract.** A change to a vector is a behavior
  change and requires explicit acknowledgement.
- **The spec is the human-readable contract.** If the spec is silent or
  ambiguous, that is itself a bug, and the fix is to clarify the spec and
  add a vector.
- **The implementation may be wrong.** If the implementation disagrees with
  the spec and the vectors, the implementation gets a patch release.

A bug fix that requires changing the canonical hash for any input is **not
a v0 bug fix**. It is a v1 change, even if the v0 implementation is
"wrong" in some interpretive sense. v0 hashes are an immutable commitment
to existing sidecars in the wild.

## Governance

`main` is currently merged solo by the project lead. This will change as
the project grows and as new implementations land. The intent is not
centralized control; the intent is that v0 is small enough to keep in one
head while it is being written down, and that decisions are reversible
until the spec graduates from `v1-draft/`.

Decisions are documented in commit messages and in `docs/` files. There is
no separate steering committee in v0.

## Maintainer note: the .d/mzML symmetry

The Bruker `.d` and mzML attestation paths are designed as **parallel**
attestation types. The `.d` path carries more special-case logic
(directory of multiple files, embedded SQLite, ground-truth DB, SQLite
quiescence checks) but the trust model, the discovery rules, and the
error-to-exit-code mapping are intended to be **symmetric** across both.

Any PR that touches discovery, trust, error mapping, or any other
behavior with both a `.d` and an mzML implementation MUST consider both
paths together. Specifically:

- If you change `find_sidecar_for()`, check both the `.d` directory
  branch and the `.mzML` file branch.
- If you change a MUST/SHOULD claim in
  [`spec/trust-model.md`](spec/trust-model.md) or
  [`spec/sidecar-format.md`](spec/sidecar-format.md), check whether
  it applies symmetrically to both attestation types.
- If you add a new exit code or change how an exception maps to an
  exit code, check that the mapping is the same on both paths.
- If you tighten or loosen a check on one path, ask whether the
  other path needs the same change.

The asymmetry between the two paths is **justified** (they are
genuinely different file formats) but it is a maintenance liability:
inconsistencies are easy to introduce and easy to miss in review. The
first-wins discovery bugs caught in the 2026-04 review passes were
exactly this class of mistake — fixes were applied to one branch
first, and the other branches had to be flagged in follow-up review
passes. See [`docs/faq.md`](docs/faq.md) ("Why does discovery refuse
to guess on ambiguity?") for the underlying design principle this
checklist is meant to protect.
