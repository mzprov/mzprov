# docs/ — non-normative documentation

This directory contains the **why** of mzprov: problem statement, threat
model, design rationale, related work, FAQ.

It is non-normative. Implementations are not bound by the prose here, only
by the [`spec/`](../spec/) documents and the
[`test-vectors/`](../test-vectors/). If `docs/` and `spec/` ever disagree,
`spec/` wins.

## Index

| File | Topic |
|---|---|
| [`01-problem.md`](01-problem.md) | What problem mzprov solves and for whom; current limitations of mzML and vendor RAW; one-line summary |
| [`02-architecture.md`](02-architecture.md) | The chain-of-custody architecture (V → D → R → U), the parallel deployment tracks, and what partial deployment enables |
| [`03-threat-model.md`](03-threat-model.md) | Actors, capabilities, the v0 attack-vs-defense table, what is NOT in scope, and what is NOT guaranteed |
| [`04-canonicalization.md`](04-canonicalization.md) | The canonical hashing problem, the prototype-first requirement, and the full-content vs sampling-based attestation discussion |
| [`05-roadmap.md`](05-roadmap.md) | The five-phase plan from simulator self-signing to instrument attestation, plus the technical / operational / social / security risks |
| [`06-related-work.md`](06-related-work.md) | mzML `dataProcessing`, PROV-O, SLSA, in-toto, Sigstore, Rekor, ProteomeXchange — what mzprov builds on and what it does not reinvent |
| [`faq.md`](faq.md) | The mzML SHA-1 misread; full hash vs sampling; why not blockchain; why not a shared Rust core; test-only key rationale; sidecar pretty-printing; the legacy `timsim/` prefix |

## Reading order

A new reader should start at `01-problem.md` and read through to
`06-related-work.md` in order. The FAQ is for specific recurring
questions and does not need to be read top-to-bottom.

A reviewer who only has 10 minutes should read `01-problem.md` (the
problem statement), the bottom of `03-threat-model.md` (the "what is
NOT guaranteed" section), and the top of `05-roadmap.md` (current
state).

A contributor who wants to propose a new feature should also read
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`../spec/v1-draft/README.md`](../spec/v1-draft/README.md).

## Licensing

All files in this directory are CC-BY-4.0. See [`../LICENSE-CC-BY`](../LICENSE-CC-BY).
