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
