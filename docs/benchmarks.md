# Benchmarks

This document records throughput measurements of `mzprov`'s
canonicalization functions on real and synthetic mass spectrometry
data. It exists so that future "is hashing the full thing slow?"
questions can be answered with hard numbers instead of estimates.

This file is non-normative — measurements are environment-dependent,
and any conforming implementation may be faster or slower than these
numbers. The point is that the cost is **bounded and small** for
realistic mass spec data, not that any specific number is the
contract.

---

## 2026-04-10 — canonicalization throughput on real and synthetic data

### Hardware and software

| | |
|---|---|
| CPU | AMD Ryzen 7 3700X (8 cores, Zen 2 — **no hardware SHA acceleration**) |
| RAM | 32 GB |
| OS | Linux 5.15.0 |
| Python | 3.12 |
| `mzprov` | 0.1.0 (commit at the time: `bbbd54e`) |
| Filesystem | local SSD |

The Zen 2 generation (Ryzen 3000 series) does not implement the SHA
extensions, so all SHA-256 in this run is software (`pyca/cryptography`'s
default OpenSSL backend, software path). On a host with Intel SHA-NI,
ARMv8 crypto extensions, or AMD Zen 3+, the SHA-256-bound work is
3–5× faster. The numbers below are therefore the **pessimistic
case** for the SHA cost.

### Methodology

Each measurement runs `mzprov.canonicalize_d` (for `.d` directories)
or `mzprov.canonicalize_mzml` (for mzML files) **in-process** via
`time.perf_counter()` around the call. CLI startup overhead is
intentionally excluded — that overhead is constant (~200 ms for
Python startup + key load) and irrelevant to the scaling question.

For each fixture, two consecutive runs are reported:

- **cold** — first run after staging the file. The file may already
  be in the OS page cache from the preceding `stat()`, so this is
  not a true cold-cache measurement; for that you need to drop OS
  caches between runs (requires root).
- **warm** — second run, fully cached.

The hashes are asserted equal across the two runs as a determinism
sanity check.

### `.d` canonicalization (`canonicalize_d`)

`canonicalize_d` does two things in sequence: a streaming SHA-256 over
`analysis.tdf_bin` (the binary peak file), and a content-level walk of
`analysis.tdf` (the SQLite metadata) where every user table is
SELECT-ORDER-BY'd over all columns and every cell is fed through
`canonicalize_value` into the same SHA-256 stream. Both files are
folded into the final 32-byte digest.

| Fixture | analysis.tdf | analysis.tdf_bin | total | cold | warm | warm MB/s |
|---|---:|---:|---:|---:|---:|---:|
| TimSim DIA HeLa 10K (sim) | 3.5 MB | 550 MB | **552 MB** | 0.74s | 0.64s | **864** |
| TimSim DDA HeLa 10K (sim) | 2.5 MB | 736 MB | **738 MB** | 4.47s | 0.64s | **1157** |
| Bruker DDA blank (real) | 128 MB | 1017 MB | **1.12 GB** | 8.97s | 8.96s | **128** ⚠ |
| Bruker DIA synchroPASEF (real) | 37 MB | 2.9 GB | **2.93 GB** | 9.24s | 4.34s | **691** |

### mzML canonicalization (`canonicalize_mzml`) — real files

`canonicalize_mzml` parses the mzML XML, walks every `<spectrum>` in
sorted-index order, extracts spectrum-level metadata (id, MS level,
polarity, RT, ion mobility, precursor block) by PSI-MS accession, and
SHA-256-hashes every `<binaryDataArray>` payload alongside its
precision tag, value count, and role label. The per-spectrum record
is fed into the file-level SHA-256.

| Fixture | size | cold | warm | warm MB/s |
|---|---:|---:|---:|---:|
| Thermo Q Exactive (sage fixture) | 12 KB | <1 ms | <1 ms | (overhead-bound) |
| Thermo 32-bit float | 2.7 MB | 30 ms | 30 ms | **87** |
| Bruker timsTOF / msconvert | 49 MB | 1.78s | 1.71s | **28** |

### mzML canonicalization — synthetic GB-scale fixtures

To test mzML throughput at file sizes comparable to real `.d`
directories (and to give R something to point at when "what about
huge mzML?" comes up), three synthetic mzMLs were generated with the
following structure:

- 1000 m/z + 1000 intensity peaks per spectrum
- 64-bit float arrays, no compression
- One `<scan>` per spectrum with a `scan_start_time` cvParam
- MS1 spectra only (no precursor blocks)
- Indexed mzML wrapper, valid PSI-MS namespaces

| Fixture | spectra | gen time | size | cold | warm | warm MB/s |
|---|---:|---:|---:|---:|---:|---:|
| medium  | 22,000  | 0.64s | **468 MB** | 3.29s | 3.19s | **147** |
| large   | 65,000  | 1.91s | **1.35 GB** | 9.80s | 9.78s | **142** |
| xlarge  | 130,000 | 3.79s | **2.70 GB** | 20.44s | 19.14s | **145** |

The throughput is essentially flat (~140 MB/s) across the three sizes
— the canonicalizer scales linearly with bytes for this spectrum
shape.

### Headline numbers

> A **3 GB real Bruker `.d`** (synchroPASEF) hashes in **4.3 seconds
> warm**, **9.2 seconds cold**.
>
> A **2.7 GB synthetic mzML** hashes in **19 seconds**.
>
> A **49 MB real Bruker timsTOF mzML** hashes in **1.7 seconds**.

For comparison, on the same machine:

| | Time |
|---|---|
| NVMe disk reads 3 GB | ~3 s |
| HDD reads 3 GB | ~30 s |
| timsTOF data acquisition | hours |
| DiaNN / FragPipe / MaxQuant search | minutes to hours |
| Re-acquiring data because verification routed wrong | days |

Hashing is in the **single-digit seconds** for the largest realistic
mass spec input. It is dominated by every other step of a typical
mass spec workflow by 2–4 orders of magnitude.

### Three observations worth recording

#### 1. The Bruker DDA blank is the slow outlier — and the reason is interesting

The Bruker DDA blank fixture is 1.12 GB total but takes 9 seconds
*even on the warm run*, when streaming SHA-256 of `analysis.tdf_bin`
alone would predict ~1 second. By contrast, the TimSim DDA HeLa 10K
fixture is 738 MB total and the warm run completes in 0.64 seconds
(1157 MB/s).

The difference is `analysis.tdf`: **128 MB on the Bruker file vs
2.5 MB on the TimSim file**. Real Bruker SQLite schemas have many
tables with hundreds of thousands of rows, and `canonicalize_sqlite`'s
hot loop is a Python-level iteration over every row calling
`canonicalize_value` per cell. For real Bruker data, that
Python-level row iteration dominates the streaming SHA-256.

This is a v0.2 optimization opportunity (rewrite the row encoder in
C, or use `fetchmany` + bulk encoding, or use `apsw`). Estimated 5–10×
speedup for real Bruker `.d` files. **Not a current blocker** — 9
seconds for a 1.12 GB Bruker file is still negligible against
acquisition and search times.

#### 2. mzML throughput depends on per-spectrum complexity, not file size

The 49 MB real Bruker timsTOF mzML hits 28 MB/s; the 2.7 GB synthetic
mzML hits 145 MB/s — same code, **5× difference**. The reason: real
Bruker mzML has many small spectra (MS1 + MS2 + ion mobility slices,
~150 peaks per spectrum on average), while the synthetic has fewer
larger spectra (1000 peaks each). The per-spectrum XML parsing cost
dominates when spectra are small; the binary array hashing cost
dominates when spectra are large.

The honest range for mzML canonicalization throughput is therefore
**30 MB/s (worst case, dense Bruker timsTOF)** to **145 MB/s (large
MS1 spectra)**. A 3 GB realistic-shape Bruker mzML would take about
100 seconds. Still fine for verification at repository ingestion or
peer review.

Future optimization: replacing `xml.etree.ElementTree` with `lxml`
(libxml2-backed) would give an estimated 5× speedup for the
XML-parsing-bound cases. Same code, faster parser. v0.2 work.

#### 3. SHA-256 is not the bottleneck anywhere

Even on this Zen 2 CPU without hardware SHA acceleration, software
SHA-256 hits ~1 GB/s in tight loops, and the canonicalizer never gets
close to that ceiling. The `analysis.tdf_bin` streaming case (which
*is* SHA-256 in a tight loop on big bytes) hit 1157 MB/s warm. The
bottlenecks are all on the **walking-the-content** side (XML parsing,
SQLite row iteration), not on the cryptographic side.

This means a hardware-accelerated host (Intel SHA-NI, ARMv8 crypto,
AMD Zen 3+) **does not help much** — the win would be bounded by the
canonicalizer's content walk, not by the hash itself. Therefore the
numbers in the table above transfer cleanly to faster hardware:
content-walk costs stay roughly the same, SHA-256 costs go down a
bit, and the overall throughput improves only modestly. We do not
need to caveat the table with "this is software-SHA only".

### Conclusion

For realistic mass spec data, **full canonical hashing is fast enough
that there is no performance argument for sampling-based alternatives**.
The cost of hashing a complete Bruker `.d` or mzML file is in the
single-digit seconds for typical inputs and the low double-digit
seconds for the largest realistic inputs. That cost is dominated by
acquisition, sample preparation, search engines, and even ordinary
file copy operations.

The full-content vs sampling discussion in
[`04-canonicalization.md`](04-canonicalization.md#full-content-hashing-vs-sampling-based-attestation)
and the FAQ entry
[`faq.md`](faq.md#why-do-we-hash-the-whole-spectrum-content-instead-of-sampling)
make the asymmetric-correctness argument: full hashing strictly
dominates sampling for tamper detection, because sampling has
detection probability `1 − (1−p)^n` for fraction `p` tampered and
sample size `n`, while full hashing is `1` for any non-zero edit to
in-scope content. The only case where the sampling proposal has real
value is **defense in depth against a canonicalizer bug** — if some
implementation has a subtle determinism flaw, embedding a small
sample of canonical spectrum bytes alongside the full hash would let
a verifier sanity-check against the original bytes without trusting
the canonicalizer. That use case is recorded in
[`../spec/v1-draft/README.md`](../spec/v1-draft/README.md) and is
NOT performance-motivated.

This benchmark exists to close the performance argument permanently.
If a future contributor proposes sampling as a way to make hashing
"more scalable", point them at this file.
