# spec/v1-draft/ — proposed features awaiting graduation

This directory holds proposed features that are not yet part of the
normative mzprov specification. Drafts MAY contradict v0 — that is the
point of the draft directory.

A draft graduates into the normative spec when **all** of the following
are true:

1. The draft is written as a complete spec document in RFC 2119 style.
2. There are test vectors under `test-vectors/v1-draft/` covering the
   valid and invalid cases it introduces.
3. The feature is implemented in at least one of the active
   implementations, behind a feature flag if it is not yet stable.
4. There is consensus among the maintainers of the active implementations.
5. A maintainer approves the graduation.

When a draft graduates, the file moves into [`../`](../) (replacing or
extending the relevant v0 document), the test vectors move into
`../../test-vectors/`, and the specification version bumps.

See [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) for the full proposal
process.

## Current drafts

*(none yet)*

## Candidate drafts mentioned in design discussions

The following ideas have come up in design conversations and would be the
most natural first inhabitants of this directory. None of them are
committed to graduate; this list exists so that the discussion is not
lost.

- **Sampled-spectra defense in depth.** A sidecar extension that embeds a
  random sample of canonical spectrum bytes alongside the full-content
  hash, so a verifier can sanity-check against the original bytes without
  trusting the canonicalizer. Originally proposed by R as a primary
  mechanism; reframed as a v1 defense-in-depth layer. See
  [`../../docs/04-canonicalization.md`](../../docs/04-canonicalization.md)
  once it lands.
- **mzML run-level metadata signing.** Extending the v0 mzML
  canonicalization scope to cover `instrumentConfiguration`,
  `dataProcessing`, `softwareList`, and `sourceFile`.
- **Numpress decoding support.** v0 raises `ProvenanceError` on
  numpress-compressed binary arrays rather than producing a misleading
  hash. v1 could decode and canonicalize them.
- **Vendor RAW canonicalization.** The hard problem from
  [`../../docs/04-canonicalization.md`](../../docs/04-canonicalization.md).
  Likely a per-vendor family of algorithms rather than a single function.
- **Repository countersignature attestations.** A second sidecar layer
  signed by a repository at ingestion time, binding the dataset to
  uploader identity, affiliation, submission timestamp, and embargo state.
