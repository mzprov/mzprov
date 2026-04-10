# 02 — Architecture

The mzprov architecture has two complementary parts: a long-term
**chain of custody** that anchors trust in the instrument, and a
**deployment strategy** that ships value incrementally without waiting
for any single anchor to be adopted.

## Actors used in this document

The chain-of-custody diagram and the deployment-tracks table below
refer to actors by single-letter shortcodes. The full definitions live
in [`03-threat-model.md`](03-threat-model.md#actors); the short
version, just for the symbols this file uses:

| Symbol | Actor |
|---|---|
| **V** | Vendor / Instrument — produces RAW data; potential root of trust |
| **D** | Developer / Converter — transforms RAW → mzML; responsible for lineage |
| **R** | Repository — hosts datasets (PRIDE, MassIVE, jPOSTrepo); potential secondary trust anchor |
| **U** | User / Analyst — consumes data; needs to assess trustworthiness |
| **S** | Simulator — generates synthetic datasets indistinguishable from real acquisitions |

The **M** actor (malicious actor) does not appear in this file; the
threat model that uses it is in
[`03-threat-model.md`](03-threat-model.md).

---

## The cryptographic chain of custody

The long-term architecture anchors trust at the instrument:

```
V (signs RAW)
  → D (links + signs transformation)
    → R (countersigns at ingestion)
      → U (verifies full chain)
```

Three anchors — instrument, converter, repository — each contribute a
distinct guarantee. The system must deploy incrementally: partial
adoption must deliver partial value.

### Step 1 — Vendor establishes root of trust (RAW)

At acquisition:

```
canonicalizer = vendor_canonicalizer(
  vendor,
  instrument_model,
  acquisition_mode,
  raw_format_version,
  canonicalization_version
)
H_raw = hash(canonicalizer(RAW))
Sig_V = sign_vendor(H_raw, instrument_id, timestamp, canonicalization_version)
```

Embedded in RAW metadata: canonical hash, vendor signature, instrument
ID, timestamp, certificate chain.

**Guarantees.** RAW originates from a real instrument running
vendor-signed firmware. RAW content integrity is verifiable.

*Critical design question: what is canonicalized?* There is probably no
universal `canonicalize(RAW)` function. RAW canonicalization is expected
to be vendor-, instrument-, acquisition-mode-, and version-specific.
See [`04-canonicalization.md`](04-canonicalization.md).

### Step 2 — Converter establishes lineage (RAW → mzML)

```
mzML provenance block:
  upstream:
    H_raw, Sig_V
    instrument_id, timestamp
  transformation:
    tool       = "ProteoWizard msconvert 3.0.24"
    parameters = {...}
    H_mzML     = hash(canonicalize_mzML_vN(mzML))
  Sig_D = sign_converter(upstream || transformation || H_mzML)
```

**Guarantees.** mzML is linked to a specific RAW. Transformation
tool, version, and parameters are attributable. Re-processing extends
the chain without breaking earlier links.

### Step 3 — Repository anchors ingestion

At deposition:

```
Sig_R = sign_repository(
  H_mzML,
  uploader_identity,
  affiliation,
  submission_timestamp,
  embargo_state
)
```

**Guarantees.** Dataset is bound to submitter and affiliation.
Submission time is attested by a trusted third party. Works
independently of vendor adoption.

### Step 4 — Simulator self-signing

Simulators sign their own output with a clearly-identified simulator
key. The attestation format is deliberately minimal:

```
Sig_S = sign_simulator({
  simulator_name,
  version,
  config_hash,
  output_hash,
  timestamp
})
```

Five fields, nothing more. Low-friction adoption is the point — peer
simulators (Synthedia, SMITER, and others) should be able to implement
this in an afternoon.

**Guarantees.** Honest simulators self-disclose. Repositories and
journals can filter declared-synthetic data. Absence of a known
simulator mark on a *claimed-real* dataset becomes weak-but-useful
evidence.

No vendor coordination required. Ships today.

---

## Deployment strategy: parallel tracks

The vendor-anchored chain is the correct endgame but load-bearing on
vendor adoption — historically the slowest step in MS standardization.
The plan ships value without waiting for V.

Four tracks run in parallel:

| Track | Anchor | Requires | Timeline |
|-------|--------|----------|----------|
| Simulator self-signing | S | Simulator authors | Immediate |
| Repository ingestion | R | One repository adopts | Near-term |
| Community engagement | HUPO-PSI | Informal conversations | Continuous from day one |
| Instrument attestation | V | Vendor firmware + key management | Long-term |

Shipping tracks 1 and 2 first builds a working reference implementation
and community familiarity with verification tooling. Track 3 keeps the
standards community in the loop throughout, so formal standardization
becomes ratification rather than retrofit. Track 4 presents vendors
with a concrete precedent: *here is Step 1; we already did it for
ourselves.*

---

## What partial deployment enables

Partial adoption is not a degenerate state. Each track delivers
specific properties on its own:

| Property | Track 1 (S) | Track 2 (R) | Track 4 (V) |
|----------|:----:|:----:|:----:|
| Declared-synthetic detection | yes | — | — |
| Submitter attribution | — | yes | — |
| Submission timestamping | — | yes | — |
| RAW authenticity | — | — | yes |
| RAW integrity | — | — | yes |
| mzML lineage | — | — | yes (with D) |
| Tamper detection | — | — | yes |

Partial deployment delivers partial value. No track is blocked on
another. The mzprov v0 reference implementation lives entirely in
Track 1.

---

## See also

- [`05-roadmap.md`](05-roadmap.md) — the phased plan from v0 to vendor
  adoption
- [`04-canonicalization.md`](04-canonicalization.md) — the canonical
  hashing problem at the heart of every step in the chain
- [`03-threat-model.md`](03-threat-model.md) — what each step in the
  chain defends against, and against whom
