# 03 — Threat model

This document names the actors, the attacks they can attempt, and what
mzprov does and does not defend against. It is non-normative — the
binding security claims live in
[`../spec/security-considerations.md`](../spec/security-considerations.md).

---

## Actors

| Actor | Role |
|---|---|
| **V — Vendor / Instrument** | Produces RAW data. Potential root of trust. |
| **D — Developer / Converter** | Transforms RAW → mzML. Responsible for lineage. |
| **U — User / Analyst** | Consumes data; needs to assess trustworthiness. |
| **S — Simulator** | Generates synthetic datasets indistinguishable from real acquisitions. |
| **M — Malicious actor** | Modifies, fabricates, or misrepresents data. |
| **R — Repository** | Hosts datasets (PRIDE, MassIVE, jPOSTrepo). Potential secondary trust anchor. |

---

## What attackers can do

### Simulator (S) — used dishonestly

Produces realistic synthetic data. Exports valid mzML. Used honestly
(benchmarks, method development) or dishonestly (passed off as real).

The mzprov design treats honest and dishonest simulator usage as the
same problem: the only difference is the label the producer attaches to
the output. The defense is not to detect synthetic data by inspection
(that arms race is already lost) but to make honest disclosure
self-evident and dishonest re-labeling forensically detectable.

### Malicious actor (M)

| Attack | What M tries |
|---|---|
| Content tampering | Alter spectra, intensities, or metadata in a signed file |
| Signal injection / removal | Add or remove peaks (e.g., fabricate a target analyte) |
| Metadata theft | Copy metadata from real datasets to dress up tampered or simulated data |
| Signature reuse | Reuse legitimate signatures without valid linkage to their payload |
| Physical access | Operate with hands-on access to instrument software |

### Specific Phase 0 attack scenarios

These are the attacks the v0 reference implementation actively
defends against. The defenses are tested by the test vectors under
[`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/).

| Actor | Capability | Defense |
|---|---|---|
| **U** (verifier) | Reads any sidecar a third party sends | Verifies integrity locally; needs separate out-of-band knowledge to grant trust |
| **M** (offline tamperer) | Edits `.d`, mzML, ground-truth DB, config copy, or sidecar bytes after signing | Hash recomputation detects content changes; signature recomputation detects payload edits |
| **M** (key forger) | Generates a fresh keypair and re-signs a forged bundle | Integrity check passes, but `--expected-key-id` and `--require-trusted` reject the unknown signer |
| **M** (label forger) | Mutates `payload.key_id` or `payload.experiment_name` to claim a different identity | The verifier derives `key_id` from `verifying_key` and refuses sidecars where `payload.key_id` disagrees |
| **M** (split-identity) | Supplies `--public-key X.pem` while the sidecar embeds key `Y` | The verifier requires `--public-key` to match the embedded key byte-for-byte |
| **M** (encoding-tag swap on mzML) | Changes the precision cvParam (e.g. `MS:1000519` → `MS:1000522`) on the same payload bytes | The canonical record carries the precision tag (`f64`/`f32`/`i64`/`i32`) and value count, so the swap changes the hash |
| **S** (honest simulator) | Produces mzML/.d that resembles real instrument data | Signs its output; the resulting sidecar identifies the producing tool, supporting downstream policy filters |
| **S** (dishonest simulator) | Re-labels output as "real" by stripping the sidecar | Detected at the policy layer: a dataset claimed as real-instrument with no instrument-rooted attestation must be treated as unverified, regardless of whether a simulator sidecar is present or absent |

---

## What is NOT in scope for v0

The Phase 0 system explicitly does **not** provide the following. These
are listed here so the boundaries are clear; the normative version of
this list lives in
[`../spec/security-considerations.md`](../spec/security-considerations.md).

- **Confidentiality.** Sidecars and the signed bytes are plaintext. mzprov is an attestation scheme, not an encryption scheme.
- **Freshness against replay.** A signature over a given artifact is valid forever. There is no nonce, no challenge-response, no counter. Re-verification works indefinitely as a feature; freshness must be wrapped at the transport layer.
- **Forward secrecy.** Compromise of the signing key compromises every prior signature made by that key.
- **Non-repudiation against the signer's host.** Software keys cannot prove that the signer actually intended to sign a given artifact, only that the signing key was used.
- **Instrument attestation.** A v0 sidecar does not prove that any data came from a real instrument. Vendor / instrument signing is the rest of the architecture and is not in this implementation.
- **Hardware-backed key protection.** The signing key is a software file. Anyone with read access to it can sign as that key.
- **Revocation.** No revocation list, no certificate hierarchy, no transparency log. A compromised key remains valid for the lifetime of every existing sidecar that used it.
- **Trust on first use (TOFU).** Trust grants are explicit. The verifier never auto-adds a key to the trusted-keys registry on a successful first verification.

---

## What is NOT guaranteed about the science

mzprov guarantees *bytes*, not *truth*. It does not prove:

- Scientific correctness of the data (calibration, sample handling)
- Absence of experimental artifacts
- Faithfulness of conversion unless the converter is signed and verified
- Honest experimental design (biased samples, p-hacking, pre-specified vs. post-hoc analysis)
- That the person holding the signing key acted honestly

**Key principle:**

> mzprov guarantees provenance, not truth. Trust in the *data* is
> necessary but not sufficient for trust in the *science*.

A simulator signature is **not** a "real data" certificate. It is a
disclosure mark plus tamper-evidence for simulated/software-produced
data. The long-term vendor/repository chain
([`02-architecture.md`](02-architecture.md)) is what would make the
inverse claim possible.

---

## See also

- [`../spec/security-considerations.md`](../spec/security-considerations.md) — the normative security claims, trust assumptions, primitives, and properties NOT provided
- [`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/) — concrete vectors for each attack the verifier defends against
- [`02-architecture.md`](02-architecture.md) — how the long-term chain
  closes the gaps that v0 leaves open
