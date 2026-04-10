# 06 — Related work

mzprov is not built in a vacuum. Several adjacent projects and
specifications either solve a structurally similar problem (in
software supply chain or in W3C provenance) or are the natural
integration points in mass spectrometry. This document records what
mzprov **builds on**, what it **does not reinvent**, and what each
contributes.

The principle is: **build on existing work; do not reinvent.** Where
mzprov diverges from established vocabularies, it is because the
mass-spectrometry context has properties (binary spectrum content,
file-format diversity, vendor proprietary formats) that the existing
work does not address. Where the existing work fits, mzprov adopts it.

---

## mzML `dataProcessing` and `softwareList`

[mzML](https://www.psidev.info/mzML) is the open mass spectrometry
data format defined by HUPO-PSI. Two slots in the mzML schema record
informational provenance:

- `<dataProcessing>` — a record of the processing steps applied to
  the data.
- `<softwareList>` — the software involved in producing the file.

These are **informational, not signed**. There is no cryptographic
binding between the listed transformations and the actual content.
mzprov **extends** these slots — does not replace them. A future v1
extension may sign the contents of `<dataProcessing>` and
`<softwareList>` as part of the canonical record (this is recorded in
[`../spec/v1-draft/README.md`](../spec/v1-draft/README.md) as a
candidate). v0 leaves them out of the canonical hash and treats them
as untrusted commentary.

The mzML `<fileChecksum>` element is *not* equivalent to a
provenance signature — it is a self-checksum (SHA-1, computed by the
same software that wrote the file) and is trivially recomputable
after tampering. See [`faq.md`](faq.md#what-about-the-sha-1-checksum-in-mzml)
for the long form.

---

## W3C PROV-O

[PROV-O](https://www.w3.org/TR/prov-o/) is the W3C provenance
ontology. It defines a mature vocabulary for provenance graphs:
`Entity`, `Activity`, `Agent`, and the relations between them.

PROV-O is the right framework for talking about the long-term
chain-of-custody graph in
[`02-architecture.md`](02-architecture.md). v0 does not yet emit
PROV-O serializations of its sidecars, but the field set in the v0
sidecar payload maps cleanly: the producing tool is an `Activity`,
the configuration and signing key are `Agents`, and the input and
output artifacts are `Entities`. A future export adapter to PROV-O
serialization is candidate v1 work.

---

## SLSA and in-toto

[SLSA](https://slsa.dev/) (Supply-chain Levels for Software
Artifacts) and [in-toto](https://in-toto.io/) are software supply
chain attestation frameworks that solved structurally similar
problems: build provenance, layered attestations, transformation
chains. **The vocabulary ports cleanly:**

| in-toto / SLSA term | mzprov equivalent |
|---|---|
| **Attestation** | What an mzprov sidecar is |
| **Envelope** | The outer JSON wrapping (type tag + payload + signature + verifying key) |
| **Predicate** | The mzprov payload schema (`Payload` for `.d`, `MzmlPayload` for mzML) |
| **Statement** | The full sidecar bound to a specific artifact |
| **Subject** | The `.d` directory or mzML file the sidecar attests about |
| **Builder** | The producing simulator/converter, named in `simulator_name` / `tool_name` |

mzprov v0 does not yet implement an in-toto-compliant envelope (DSSE),
but the conceptual model is the same and a future v1 may adopt the
[DSSE envelope format](https://github.com/secure-systems-lab/dsse) for
serialization compatibility. The choice was deferred for v0 to keep
the on-disk format inspectable as plain JSON without DSSE base64
wrapping.

---

## Sigstore and Rekor

[Sigstore](https://www.sigstore.dev/) is a public-good infrastructure
for signing software artifacts, with the
[Rekor](https://docs.sigstore.dev/logging/overview/) transparency log
as its tamper-evident append-only storage layer.

Sigstore is the **workable model** for MS signature logging at scale.
mzprov does not (and should not) build its own transparency log; if
and when the long-term chain of custody needs one, Sigstore-style
public logs are the design to copy. The mzprov v0 design leaves room
for this: the sidecar format is independent of the trust layer, and a
future addition could record sidecar hashes in a public Rekor-like
log without changing the sidecar bytes.

Sigstore also informs how mzprov should handle multiple independent
implementations: Sigstore has cosign (Go), sigstore-python (Python),
sigstore-java (Java), sigstore-rs (Rust), and they explicitly do
**not** share a core library — they share a *spec* and a *conformance
test suite*. mzprov adopts the same model. See
[`faq.md`](faq.md#why-not-implement-the-core-in-rust-and-bind-from-python-and-c)
for the long form.

---

## ProteomeXchange and PRIDE

[ProteomeXchange](http://www.proteomexchange.org/) is the consortium
that runs the public mass spectrometry data repositories
([PRIDE](https://www.ebi.ac.uk/pride/), [MassIVE](https://massive.ucsd.edu/),
[jPOSTrepo](https://repository.jpostdb.org/), etc.).

ProteomeXchange and its repositories are the **integration point**
for the repository track of the deployment plan
([`05-roadmap.md`](05-roadmap.md), Phase 0.5). When a repository
ingests a dataset, it is in a position to add a countersignature
binding the dataset to the uploader's identity, affiliation, and
submission timestamp.

mzprov is not asking ProteomeXchange to adopt anything in v0. v0 is
about producing a sidecar that *travels with* the data through
existing submission flows. Phase 0.5 is the conversation about
repositories actually validating and countersigning at ingestion.

---

## What mzprov adds that none of the above provides

The combination of:

- A **canonical content form** for binary mass spectrometry data
  (Bruker `.d` SQLite + binary, mzML spectrum content with
  binary-array role labels and precision tags) that survives lossless
  transformations and detects encoding-tag-swap attacks
- A **signed sidecar** that binds an MS-specific artifact to a key
- A **conformance test vector suite** that lets independent
  implementations in any language verify they agree
- A **deployment strategy** that ships value via simulator
  self-signing without waiting for vendor adoption

is what mzprov contributes. The cryptographic primitives, the
attestation envelope vocabulary, the transparency log model, and the
repository integration story are all **borrowed** from the projects
listed above.

---

## See also

- [`../spec/security-considerations.md`](../spec/security-considerations.md) — the cryptographic primitives mzprov uses (and does not invent)
- [`02-architecture.md`](02-architecture.md) — where each related work fits in the long-term plan
- [`faq.md`](faq.md) — FAQ entries on why specific alternatives (blockchain, shared Rust core, mzML SHA-1) are not used
