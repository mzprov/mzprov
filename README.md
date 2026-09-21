# mzprov

**Cryptographic provenance for mass spectrometry data.**

`mzprov` is a format and protocol for signing mass spectrometry data files with
verifiable, tamper-evident provenance metadata. It produces a portable JSON
sidecar that any conforming implementation in any language can verify.

Coverage today: Bruker `.d` and mzML by content canonicalization, Thermo and
Waters `.raw` by an opaque whole-file digest, and SCIEX `.wiff` as a whole
bundle, since its spectra live in a sibling `.wiff.scan` and hashing the anchor
alone would attest almost nothing.

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
- An independent Rust implementation — signer + verifier ([`implementations/rust/`](implementations/rust/))
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
| Python reference implementation | shipping on PyPI as `mzprov` |
| Rust implementation | signer and verifier; not yet in the conformance CI |
| C# implementation | in development, passes every conformance vector |
| Cross-implementation conformance test vectors | 21 vectors, enforced in CI for Python and C# |
| `.raw` canonicalization (opaque whole-file, sidecar-only) | v0 frozen, `spec/canonicalization-raw-v0.md` |
| `.wiff` bundle canonicalization (member names folded into the digest) | shipping in the Python implementation; spec text pending |
| Provenance chains (signed derivation lineage, `mzprov chain sign` / `verify`) | Python prototype, v1 draft |
| Repository countersignature | out of scope for v0 |
| Hardware-backed key protection | out of scope for v0 |

## Two layers: integrity and identity

`mzprov` is a **two-layer system**. The layers are evaluated separately
and answer different questions:

- **Integrity** — *Do the bytes match what was signed?* Always
  evaluated. The canonical content hash plus the Ed25519 signature
  over the payload tell the verifier whether anything has been
  modified since signing. Spec:
  [`spec/canonicalization-d-v0.md`](spec/canonicalization-d-v0.md),
  [`spec/canonicalization-mzml-v0.md`](spec/canonicalization-mzml-v0.md),
  [`spec/signature-scheme.md`](spec/signature-scheme.md).
- **Identity** — *Who signed those bytes?* Opt-in via trust flags.
  The stable key id derived from the embedded verifying key, the
  local trusted-keys registry, and three trust pinning options
  (`--expected-key-id`, `--require-trusted`, `--public-key`) tell
  the verifier whether the signer is who you expected. Spec:
  [`spec/key-id-derivation.md`](spec/key-id-derivation.md),
  [`spec/trust-model.md`](spec/trust-model.md).

A passing integrity check means *"these bytes have not been modified
since they were signed by the key embedded in the sidecar"*. It does
NOT mean *"the signer is trustworthy to me"* — that is the identity
layer's job. Without a trust flag, `mzprov verify` reports integrity
only and the trust-check status is `not_requested`. With one or more
trust flags, both layers must pass for the verifier to exit `0`.

This separation is the same one [Sigstore](https://www.sigstore.dev/),
[in-toto](https://in-toto.io/), and [SLSA](https://slsa.dev/) use,
and it is what lets the trust layer evolve independently of the
cryptographic primitive. The verifier's check order and the
label-vs-signer consistency defense (which prevents an attacker from
relabeling `payload.key_id` to claim a different identity) are
specified in [`spec/trust-model.md`](spec/trust-model.md) §1 and §5.

## Embedded records survive sidecar removal

Because a `.d` carries its attestation inside `analysis.tdf`, deleting the
external sidecar does not strip provenance. The embedded record survives, and
its absence in a genuine acquisition makes its presence meaningful. When the
embedded record references an artifact that is missing, `verify` still exits
`3` as the specification requires, and the error names the embedded record:
who signed it, for which experiment, with which key.

## What this repository does NOT claim

`mzprov` is an attestation scheme, not a certificate of scientific truth. It
guarantees provenance (these bytes were signed by this key at this time),
not correctness (the experiment was well designed and executed). See
[`spec/security-considerations.md`](spec/security-considerations.md) for
a list of additional properties not provided.

In particular, in v0:

- A simulator signature is **not** evidence that data is real instrument data.
  It is evidence that the data was produced by software and signed by a
  specific software key. This is intentional — see [`docs/01-problem.md`](docs/01-problem.md).
- There is no vendor PKI, no repository countersignature, no transparency log,
  no revocation, and no hardware-rooted key. Those are future work.
- There is **no encryption**. `mzprov` is an attestation scheme: every
  sidecar and every signed byte is plaintext, and confidentiality is
  not a goal. This is the same property [in-toto](https://in-toto.io/),
  [SLSA](https://slsa.dev/), [Sigstore](https://www.sigstore.dev/),
  and every other attestation system has. If you need confidentiality,
  use a transport-layer encryption mechanism (HTTPS, age, GPG, …) on
  top of the signed bytes — `mzprov` and that mechanism are
  orthogonal.

## Quick start

### Install

```bash
pip install mzprov
```

To work on the implementation itself, install from a clone instead:

```bash
git clone https://github.com/mzprov/mzprov.git
cd mzprov
pip install -e implementations/python
```

This installs the unified `mzprov` console script and three flat
aliases (`mzprov-sign`, `mzprov-verify`, `mzprov-keys`). Python ≥3.11
required. The only runtime dependency is `cryptography` (Ed25519,
BLAKE2b, SHA-256).

### Confirm your install with a known-good test vector

mzprov ships ready-to-verify vectors under
[`test-vectors/`](test-vectors/). The fastest way to confirm your
install is wired correctly is to verify the minimal valid `.d` vector
— no need to bring your own data:

```bash
mzprov verify test-vectors/sidecar/valid/d-v0-minimal/   # from a clone
```

Expected output:

```
TimSim provenance verification
  experiment:        d-v0-minimal
  producer:          TimSim mzprov-test-vectors/0.1.0
  signed at:         2026-04-10T07:07:22.467Z
  key id:            timsim-local-umdyuiienlum7prj
  canonicalization:  v0

   d_content_hash  OK         (sha256:2926eb20eb6cbe5d4...)
   config_hash     OK         (sha256:dad70a13f2ba7a10c...)
   content_hash    OK         (sha256:3cd20d9c8b3a20d53...)
   signature       OK         (ed25519)

VERIFIED
```

Exit code 0 means success. To see the verifier *reject* a tampered
bundle (and confirm tamper detection works):

```bash
mzprov verify test-vectors/sidecar/invalid/d-hash-mismatch-tdf-bin-tampered/
echo "exit=$?"   # should print: exit=5
```

The full exit-code contract (`0` verified, `3` sidecar error, `4`
unsigned, `5` hash mismatch, `6` signature mismatch, `7` trust
failure) is documented in [`spec/trust-model.md`](spec/trust-model.md).

### Sign your own data

```bash
# Sign a Bruker .d directory. --config is REQUIRED for .d signing
# (the .d signing path binds the experiment to its config bytes).
mzprov sign /data/run.d \
    --experiment-name run-001 \
    --config /data/run.toml \
    --tool-version 1.0.0

# Sign an mzML file from any tool. --config is OPTIONAL for mzML.
mzprov sign /data/run.mzML \
    --experiment-name run-001 \
    --tool-name msconvert \
    --tool-version 3.0.24 \
    --config /data/run.toml
```

The first time you sign, `mzprov` auto-generates a software signing
key at `~/.config/timsim/keys/signing_key.pem` and prints its key id.
The `timsim/` path is intentionally preserved from the lift from
`imspy_simulation.provenance`; a v1 rename to `~/.config/mzprov/`
(with a one-time migration helper) is recorded as deferred work in
[`docs/faq.md`](docs/faq.md). For the same reason, derived key ids
are prefixed with `timsim-local-`.

### Verify

```bash
mzprov verify /data/run.d
mzprov verify /data/run.mzML
mzprov verify /data/run.provenance.json
```

The verifier auto-discovers the sidecar from any of these paths.
Multi-bundle directories are handled safely: discovery requires a
unique sidecar match and refuses to guess on ambiguity (see
[`spec/trust-model.md`](spec/trust-model.md) §3.1).

### Verify with trust pinning

```bash
# Pin to a specific expected signer's key id
mzprov verify /data/run.d --expected-key-id timsim-local-yourkey

# Require the signer to be in the local trusted-keys registry
mzprov verify /data/run.d --require-trusted

# Cross-check the embedded verifying key against an out-of-band PEM
mzprov verify /data/run.d --public-key /etc/known_signer.pem
```

The three options are independent and can be combined.

### Manage keys and trust grants

```bash
# Show the local signing key id and where it lives
mzprov keys show

# Export the local public key (to share with collaborators)
mzprov keys export --to my_public_key.pem

# Trust a specific signer's key (from a sidecar JSON or from a PEM)
mzprov keys trust /data/in/their_run.provenance.json --comment "lab X"
mzprov keys trust /etc/collaborator_pub.pem --comment "lab Y"

# List trusted keys
mzprov keys list

# Revoke trust
mzprov keys untrust timsim-local-yourkey
```

The `--comment` flag is required on `mzprov keys trust` so that trust
grants are deliberate and auditable rather than absent-minded.

### TimSim integration

For TimSim users: `imspy_simulation.provenance` continues to work
unchanged and is now a thin wrapper around `mzprov`. The legacy
`timsim-verify` and `timsim-keys` console scripts are preserved and
dispatch to `mzprov.cli:main` and `mzprov.keys_cli:main` respectively.

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
    ├── rust/                         independent Rust verifier
    └── csharp/                       independent implementation
```

## License

This repository uses three licenses, by directory:

| Path | License | Why |
|---|---|---|
| `docs/`, `spec/` | CC-BY-4.0 | specifications must be quotable in papers and other specifications without legal friction |
| `implementations/python/`, `implementations/rust/` | Apache-2.0 | the patent grant matters for security-adjacent code |
| `test-vectors/` | CC0 1.0 | test fixtures should have zero attribution burden so any implementation in any language can ship them |

See [`LICENSE`](LICENSE) for the full breakdown.

## Citation

Citation information will appear here once the accompanying paper is
published. Until then, cite the repository and the commit hash.
