# 04 — Canonicalization

Canonicalization is the technical problem at the heart of mzprov. It is
also where the project either succeeds or quietly fails: a
canonicalizer that is wrong-but-deterministic ships untrustworthy
attestations forever, and a canonicalizer that is right-but-
non-deterministic produces hashes that diverge across implementations
and breaks interop.

This document explains the problem, the design choices, and one
specific design decision (full content hashing vs. sampling-based
attestation) that has come up in early review and is worth
documenting.

---

## Why hashing the file bytes is wrong

Hashing raw file bytes is brittle: RAW files contain volatile metadata
(timestamps, read-order artifacts, cache state). The canonical form
must be over *content* — ordered spectra and declared metadata fields —
not the container.

There are two related but different canonicalization problems:

1. **Open derived formats such as mzML.** The canonicalizer can be
   public and format-level: parse mzML, extract spectrum content and
   selected per-spectrum metadata, normalize representation, and hash
   that content form. This is what the v0 reference implementation
   does — see [`../spec/canonicalization-mzml-v0.md`](../spec/canonicalization-mzml-v0.md)
   for the normative spec.

2. **Vendor RAW formats.** The canonicalizer is likely a family of
   algorithms, not one function. It may depend on vendor, instrument
   model, acquisition mode, RAW format version, firmware/software
   version, and the vendor's internal definition of acquisition
   content. For some vendors, the practical route may be that the
   instrument software signs a vendor-produced canonical digest rather
   than exposing enough proprietary internals for an external
   canonicalizer.

The RAW-side pseudocode should therefore be read as:

```
H_raw = hash(canonicalize_raw_vendor_vN(
  raw_bytes_or_container,
  vendor,
  instrument_model,
  acquisition_mode,
  raw_format_version
))
```

not as a single universal `canonicalize(RAW)` routine.

---

## Prototype-first requirement

Before any vendor conversation, the project ships a working
canonical-content hasher that:

- Operates on extracted mzML content, not container bytes
- Produces a stable hash across a lossless `msconvert` round-trip
- Runs independently of vendor cooperation

A working demo makes every downstream conversation — with vendors,
repositories, and PSI — concrete rather than aspirational. The
[Bruker `.d` canonicalizer](../spec/canonicalization-d-v0.md) and the
[mzML canonicalizer](../spec/canonicalization-mzml-v0.md) under
`spec/` are the artifacts that satisfy this requirement.

---

## Open questions the v0 prototype answers (or doesn't)

| Question | v0 answer |
|---|---|
| What is in scope? | Spectra: yes, fully. Acquisition log: not in v0. Cache/temp state: never. Run-level metadata (`instrumentConfiguration`, `dataProcessing`, `softwareList`, `sourceFile`): not in v0; candidate for v1. |
| How are floating-point m/z and intensity values canonicalized? | Per-array bytes are hashed via SHA-256 along with the **precision tag** (`f64`/`f32`/`i64`/`i32`) and the value count. An encoding-tag swap that re-interprets the same bytes under a different precision changes the canonical hash. |
| Can a canonical form be defined without exposing proprietary format internals? | For mzML and SQLite-shaped Bruker `.d`: yes, and v0 demonstrates it. For other vendor RAW: open. Commitments over extracted content may satisfy vendors who resist canonicalization of the file itself. |
| Which RAW fields are semantic acquisition content versus volatile storage state for each vendor and acquisition mode? | Open. v0 only covers Bruker timsTOF `.d` (which is SQLite-shaped). |
| Does the vendor sign a canonical digest it computes internally, or does the community define an external extractor? | Open. Both approaches remain viable for v1. |
| How are canonicalization versions negotiated and preserved so old signatures remain verifiable after the canonical form evolves? | The sidecar carries an explicit `canonicalization_version` field; verifiers must reject sidecars with versions they do not understand, never silently accept. v0 freezes `"v0"`; v1 will be a new value the v0 verifier refuses. |

---

## Full content hashing vs sampling-based attestation

This subsection records a design discussion that has come up in early
peer review and is worth preserving so it does not have to be re-run.

### The proposal

A reasonable alternative to hashing 100% of spectrum content is to
**sample**: pick *n* spectra at random, embed their bytes (or
content hashes) in the signed payload, and let the verifier
re-extract and compare. The advantage is that the signed payload
stays small even for huge files, and the verifier does not need to
agree with the producer on a canonicalization spec — it only needs to
agree on which n spectra were sampled and what the sampled bytes
are.

### Why v0 hashes everything instead

mzprov v0 hashes **100% of spectrum content** via the canonicalizer
in [`canonicalization-mzml-v0.md`](../spec/canonicalization-mzml-v0.md).
Every `binaryDataArray` (m/z, intensity, ion mobility, charge, …) is
hashed with its precision tag and value count. There is no `n`;
coverage is total.

The reasons:

1. **Coverage.** Tamper detection probability with sampling is
   `1 − (1−p)^n` where `p` is the fraction of spectra an attacker
   modifies. Full hashing is `1` for any non-zero edit to in-scope
   content. The asymmetry is large for small `n` and small `p`.
2. **Size is not the constraint we think it is.** The signed payload
   in v0 is a fixed-size hash, not the content itself. Whether the
   underlying file is 1 GB or 50 GB, the payload stays at one
   sha256 per major component. Full hashing already gives sampling's
   size benefit, for free.
3. **No statistical argument needed.** Sampling-based attestation
   forces the spec to commit to a sampling rate, a sampling
   algorithm, a seed source, and a verifier check that the sampled
   indices are correct. Full hashing has none of those moving parts.

### Where the sampling idea is still useful (defense in depth)

The sampling proposal has a real pocket of value that is *not* about
replacing the full hash: it is about **defense in depth against a
canonicalizer bug**.

If the canonicalizer in some implementation has a subtle determinism
flaw (a Unicode normalization edge case, a sort-key inconsistency, a
locale-dependent float format), the full content hash silently
diverges from the producer's hash. The error mode is "verifier
rejects honest data" — annoying, but not a forgery.

A sidecar extension that *also* embeds a small randomly-sampled set
of canonical spectrum bytes alongside the full-content hash would let
a verifier sanity-check against the original bytes without trusting
the canonicalizer. If the full hash diverges but the sampled bytes
match, the diagnosis is "the canonicalizer disagrees, the content is
the same."

This is a reasonable v1 candidate and is recorded in
[`../spec/v1-draft/`](../spec/v1-draft/) as a future feature.

### Pre-empting the misread

The argument **"sampling is better than full hashing because it covers
a portion of the file with bounded message size"** is incorrect on
both halves:

- Full hashing already covers 100% of content.
- The signed payload size is constant in either approach because both
  embed hashes, not bytes. Sampling only saves space if the proposal
  is to embed actual bytes — which v0 does not do for either
  approach.

If a future contributor proposes sampling as a *replacement* for full
hashing, the right response is to point at this section and the
[full-content vs sampling FAQ entry](faq.md#why-do-we-hash-the-whole-spectrum-content-instead-of-sampling).

---

## Other technical challenges

### Key management and root of trust

The single largest operational question for the long-term vendor
chain.

- **Per-instrument keys** (better revocation, requires vendor PKI)
  vs **vendor master keys** (simpler, single point of compromise).
- **Where does the private key live?** Ideally an HSM on the
  instrument; realistically, vendor-signed firmware holding a
  software key is an acceptable first step.
- **Revocation and rotation.** Compromised keys must be rejectable
  going forward while previously-signed data remains verifiable.
- **Certificate transparency.** Public logs of issued instrument
  certificates let the community detect rogue issuance.

None of this is in scope for v0, which uses a single
software-rooted Ed25519 key per signer with no certificate hierarchy.

### Legitimate transformations

Recalibration, centroiding, noise filtering, format conversion,
re-peak-picking — these are normal operations. Naive file-level
hashing breaks on the first step.

Two compatible solutions:

1. **Signed-semantics transformations.** Each step publishes a signed
   attestation `{input_hash, tool, version, parameters, output_hash}`.
   The chain grows.
2. **Canonical invariant representation.** Sign a content form that
   survives lossless transforms. Lossy transforms break the
   invariant, as they should.

A production system needs both. v0 implements (2) for the
single-step "produce a sidecar at the moment of writing" case. The
multi-step transformation chain is v1+ work.

### Hardware attestation

A TPM-like root of trust on the instrument upgrades the guarantee
from *"signed by a key we believe was on an instrument"* to *"signed
by a key attested to be executing on instrument firmware version X
at time Y."* Not v0, but the design must leave room for it. The
algorithm-agility envelope in
[`../spec/signature-scheme.md`](../spec/signature-scheme.md) leaves
that room.

---

## See also

- [`../spec/canonicalization-d-v0.md`](../spec/canonicalization-d-v0.md) — normative spec for `.d` canonical hashing
- [`../spec/canonicalization-mzml-v0.md`](../spec/canonicalization-mzml-v0.md) — normative spec for mzML canonical hashing
- [`../test-vectors/canonicalization/`](../test-vectors/canonicalization/) — fixtures that prove invariance properties (whitespace-equivalence, page-size, etc.)
- [`faq.md`](faq.md) — FAQ entries on the SHA-1 misread, sampling vs hashing, and related questions
