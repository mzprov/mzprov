# 05 — Roadmap

Phase 0 ships immediately as a working reference implementation.
Phase 0.5 ships in parallel. Phases 1 through 4 proceed in sequence.
A community engagement track runs continuously alongside all phases.

This document also lists the **risks** that each phase has to
navigate, so the plan is read with eyes open.

---

## Where we are today

This repository contains a Phase 0 reference implementation: a
working, validated, cross-implementation-ready signing and
verification system for simulator/converter `.d` and mzML output. It
is **not** the full vendor-anchored chain of custody yet; it is the
simulator/converter-side proof that the approach can work in concrete
code.

The scope is deliberately narrow: one tool family (the `mzprov`
Python reference implementation, lifted from the TimSim provenance
hook), and one primary device/output path (Bruker-shaped timsTOF
`.d` data, with an added mzML signing path for non-Bruker
simulator/converter output). This proves feasibility; it does not
yet prove generality across instruments, vendors, converters,
repositories, or independent implementations.

For a current status snapshot, see the top-level
[`../README.md`](../README.md).

---

## Community track — starts day one

Formal HUPO-PSI standardization (Phase 4) cannot be the first PSI
conversation. Informal engagement must run continuously:

- Initial *"here is what we are planning"* conversations with PSI
  members, ideally at ASMS or a similar venue, before any formal
  proposal.
- Keep PSI informed at each phase so standardization becomes
  ratification rather than retrofit.
- Touchpoints at each delivered artifact (Phase 0 signed simulator
  output, Phase 0.5 pilot repository, Phase 1 canonical hasher).

---

## Phase 0 — Simulator self-signing (shipping)

- Define the minimal attestation format:
  `{simulator_name, version, config_hash, output_hash, timestamp}`.
  Five fields, deliberately boring.
- Implement signed output as the reference. **Done** in `mzprov`
  via the `imspy_simulation.provenance` lift.
- Publish a minimal verification tool. **Done** as
  `mzprov verify` and the legacy `timsim-verify` alias.
- Propose the format to Synthedia, SMITER, and other simulator
  authors. The barrier to entry must be low enough to implement in an
  afternoon.

The cross-implementation contract is the test vectors under
[`../test-vectors/`](../test-vectors/). A second implementation in any
language conforms iff it accepts every valid vector and rejects every
invalid vector with the named failure mode.

## Phase 0.5 — Repository ingestion signing

Pilot ingestion-side signing with one repository. Bind submissions
to uploader identity and affiliation. Ship verification tooling for
downstream consumers.

**PRIDE is the eventual destination but may not be the fastest
pilot** — it is large, well-established infrastructure with slow
governance. MassIVE or jPOSTrepo may be more tractable first
partners, both because of scale and because direct contact with the
right people is easier. Choice of pilot should follow the available
relationships.

## Phase 1 — Canonical hashing prototype

- Working canonical-content hasher that survives an `msconvert`
  round-trip. **In progress** — the v0 mzML canonicalizer covers
  spectrum content; run-level metadata is candidate v1 work.
- Converter-level proof-of-concept signer as a dry run for the
  instrument signer.
- Initial proposal for key management (per-instrument keys,
  vendor-operated CA).

This phase produces the artifact that makes vendor conversations
concrete.

## Phase 2 — Vendor engagement

Approach vendors with working reference implementations from
Phases 0 and 1 in hand.

- Lead with **regulatory motivation** (21 CFR Part 11, IVDR), not
  scientific trust. This is the lever that moves commercial vendors.
- Propose minimal, incremental instrumentation: hash and sign,
  nothing more.
- Start with one vendor rather than all four.

## Phase 3 — Ecosystem integration

- Converter support (ProteoWizard, vendor converters).
- Signed-transformation attestations for legitimate reprocessing.
- Verification integrated into common analysis pipelines.

## Phase 4 — Formal standardization

- Extensions through HUPO-PSI.
- Alignment with PROV-O and SLSA / in-toto vocabularies.
- Journal and repository adoption as a submission requirement.

---

## Risks

The plan navigates real risks. They are recorded here so future
contributors can see what we are watching.

### Technical

- **Canonical hashing specification** ([`04-canonicalization.md`](04-canonicalization.md)).
  Defining a canonical content form that two independent implementations
  produce identical hashes for is the central technical risk. Mitigated
  by RFC 2119 normative specs, cross-implementation test vectors, and
  cross-validation of the v0 mzML canonicalizer against `pyteomics`.
- **Floating-point determinism across platforms.** Mitigated by hashing
  raw IEEE 754 byte sequences with their precision tag, never their
  decimal renderings.
- **Performance overhead on large acquisitions.** timsTOF files reach
  tens of GB. The v0 reference implementation has been measured at
  signing speeds dominated by I/O, not by canonicalization CPU. Risk
  recorded; not currently load-bearing.
- **Verification tooling must be trivial to use** or adoption fails.
  v0 ships a `mzprov verify <path>` CLI that auto-discovers sidecars
  and dispatches by format type.

### Operational

- **Key management at instrument and vendor scale.**
- **Revocation, rotation, long-term verifiability of archived data.**
- **Legitimate reprocessing without breaking chains.** Phase 3 work.

### Social

- **Vendor adoption is the single largest risk.** Coordination across
  Bruker, Thermo, SCIEX, and Waters has a mixed historical record.
  Mitigated by shipping Phase 0 and Phase 1 first so the conversation
  with vendors starts from working code, not from a proposal.
- HUPO-PSI standardization is slow by design — informal engagement
  must start early (community track above).
- Researchers may resist friction at acquisition or submission.
  Mitigated by making the default behavior in `mzprov` to sign on
  output with no required user action.

### Security

- **Signature reuse attacks** if lineage is not cryptographically
  enforced. Defended by binding signatures to specific content hashes.
- **Rogue or compromised instrument keys.** Need for revocation and
  transparency logs. Out of scope for v0; Phase 2 + 3 work.
- **Physical-access attacks on instrument signing.** Phase 4 / hardware
  attestation work.
- **Partial chains overtrusted as full guarantees.** This is a
  documentation and policy risk: if a downstream consumer treats a
  Phase 0 simulator signature as evidence of real-instrument origin,
  the system has failed even though the cryptography is fine.
  Mitigated by [`03-threat-model.md`](03-threat-model.md), the
  "what is NOT guaranteed" section in
  [`../spec/security-considerations.md`](../spec/security-considerations.md),
  and the explicit `type` tag on every sidecar.

---

## See also

- [`02-architecture.md`](02-architecture.md) — what each phase
  contributes to the cryptographic chain of custody
- [`../README.md`](../README.md) — current status snapshot
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to land changes,
  the `v1-draft/` convention for proposed features
