# mzprov

**Cryptographic provenance for mass spectrometry data.**

`mzprov` is a format and protocol for signing mass spectrometry data files
(Bruker `.d`, mzML) with verifiable, tamper-evident provenance metadata. It
produces a portable JSON sidecar that any conforming implementation in any
language can verify.

The current scope is **simulator and converter self-disclosure**: a TimSim,
Synthedia, SMITER, or msconvert run produces a sidecar that identifies the
producing tool, binds the output to a specific configuration and a specific
signing key, and detects post-signing tampering at the level of individual
spectra. The longer-term scope is a chain of custody from instrument to
repository to consumer.

This repository contains:

- A non-normative explanation of **why** ([`docs/`](docs/))
- A normative **specification** of the format and verifier behavior ([`spec/`](spec/))
- Language-agnostic **test vectors** that any conforming implementation runs
  to prove interop ([`test-vectors/`](test-vectors/))
- A Python **reference implementation** ([`implementations/python/`](implementations/python/))
- A C# implementation in development ([`implementations/csharp/`](implementations/csharp/))

## Status

This is **v0**. The sidecar format, the canonicalization algorithms, the
signing primitive (Ed25519), and the verifier exit codes are frozen at the
state shipping in TimSim today. New features land as drafts under
[`spec/v1-draft/`](spec/v1-draft/) and only graduate into the normative spec
when there is at least one implementation, test vectors, and approval — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

| Component | Status |
|---|---|
| Sidecar envelope (JSON, Ed25519, embedded verifying key, key id) | v0 frozen |
| `.d` canonicalization (Bruker timsTOF SQLite content + binary) | v0 frozen |
| mzML canonicalization (spectrum content, all binary arrays) | v0 frozen |
| Trust model (`--expected-key-id`, `--require-trusted`, `--public-key`) | v0 frozen |
| Verifier exit codes (`0`–`7`) | v0 frozen |
| Python reference implementation | being lifted from `imspy_simulation.provenance` |
| C# implementation | in development |
| Cross-implementation conformance test vectors | in development |
| Vendor RAW canonicalization | out of scope for v0 |
| Repository countersignature | out of scope for v0 |
| Hardware-backed key protection | out of scope for v0 |

## What this repository does NOT claim

`mzprov` is an attestation scheme, not a certificate of scientific truth. It
guarantees provenance (these bytes were signed by this key at this time),
not correctness (the experiment was well designed and executed). See
[`spec/security-considerations.md`](spec/security-considerations.md) once it
lands for the full list of properties not provided.

In particular, in v0:

- A simulator signature is **not** evidence that data is real instrument data.
  It is evidence that the data was produced by software and signed by a
  specific software key. This is intentional — see [`docs/01-problem.md`](docs/01-problem.md).
- There is no vendor PKI, no repository countersignature, no transparency log,
  no revocation, and no hardware-rooted key. Those are future work.

## Quick start

> The Python reference implementation is currently being lifted from
> `imspy_simulation.provenance` and will land in
> [`implementations/python/`](implementations/python/) shortly. Once installed
> via `pip install mzprov`, the planned CLI is:

```bash
# Sign a Bruker .d directory
mzprov sign /data/run.d --config /data/run.toml --experiment-name run-001

# Sign an mzML file from any converter or simulator
mzprov sign /data/run.mzML --tool-name msconvert --tool-version 3.0.24

# Verify
mzprov verify /data/run.d
mzprov verify /data/run.mzML
mzprov verify /data/run.provenance.json

# Verify with trust pinning
mzprov verify /data/run.d --expected-key-id mzprov-local-...
mzprov verify /data/run.d --require-trusted
mzprov verify /data/run.d --public-key /etc/known_signer.pem

# Manage keys
mzprov keys show
mzprov keys export --to my_public_key.pem
mzprov keys trust /data/in/their_run.provenance.json --comment "lab X"
mzprov keys list
mzprov keys untrust mzprov-local-...
```

For TimSim users: `imspy_simulation.provenance` continues to work and becomes
a thin wrapper around `mzprov`. Existing `timsim-verify` and `timsim-keys`
invocations are preserved.

## Repository layout

```
mzprov/
├── README.md                         this file
├── CHANGELOG.md
├── CONTRIBUTING.md                   how to propose changes; the v1-draft convention
├── LICENSE                           explains the three-license split below
├── LICENSE-APACHE                    Apache 2.0 (covers implementations/python/)
├── LICENSE-CC-BY                     CC-BY 4.0 (covers docs/ and spec/)
├── LICENSE-CC0                       CC0 1.0 (covers test-vectors/)
│
├── docs/                             non-normative: problem, threat model, design
│   ├── 01-problem.md
│   ├── 02-architecture.md
│   ├── 03-threat-model.md
│   ├── 04-canonicalization.md
│   ├── 05-roadmap.md
│   ├── 06-related-work.md
│   └── faq.md
│
├── spec/                             normative: RFC 2119 keywords
│   ├── sidecar-format.md
│   ├── canonicalization-d-v0.md
│   ├── canonicalization-mzml-v0.md
│   ├── signature-scheme.md
│   ├── key-id-derivation.md
│   ├── trust-model.md
│   ├── security-considerations.md
│   └── v1-draft/                     proposed features awaiting graduation
│
├── test-vectors/                     interop contract — language-agnostic
│   ├── sidecar/{valid,invalid}/
│   ├── canonicalization/{mzml,d}/
│   └── keys/
│
└── implementations/
    ├── python/                       reference implementation
    └── csharp/                       independent implementation
```

## License

This repository uses three licenses, by directory:

| Path | License | Why |
|---|---|---|
| `docs/`, `spec/` | CC-BY-4.0 | specifications must be quotable in papers and other specifications without legal friction |
| `implementations/python/` | Apache-2.0 | the patent grant matters for security-adjacent code |
| `test-vectors/` | CC0 1.0 | test fixtures should have zero attribution burden so any implementation in any language can ship them |

See [`LICENSE`](LICENSE) for the full breakdown.

## Citation

Citation information will appear here once the accompanying paper is
published. Until then, cite the repository and the commit hash.
