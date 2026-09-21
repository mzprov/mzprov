# FAQ

This document collects questions that have come up in early review and
the durable parts of the answers. The aim is so that the same
conversation does not have to be re-run with every new reviewer.

If you encounter a question not covered here that takes more than a
few sentences to answer, please open an issue or a PR adding it.

---

## What about the SHA-1 checksum in mzML? Doesn't that already solve tampering?

Short answer: **no.**

The mzML standard defines an optional `<fileChecksum>` element that
holds a SHA-1 of the file (up to the start of the `<fileChecksum>`
element itself). This is a useful integrity check against transmission
corruption — bit rot, truncated downloads, accidentally-modified
files. It is **not** a defense against an attacker, for several
reasons:

1. **It is unsigned.** Anyone with write access to the file can
   recompute the SHA-1 after editing and write the new value back. The
   checksum is computed by the same software that wrote the file. A
   tampered file with a "valid" updated `<fileChecksum>` is
   indistinguishable from an honest file.
2. **It is not bound to any identity.** There is no way to ask "who
   computed this checksum?" The checksum field carries no signer.
3. **SHA-1 is broken for collision resistance.** Since 2017
   ([SHAttered](https://shattered.io/)), generating SHA-1 collisions
   is feasible for an adversary with modest resources. SHA-1 has been
   deprecated for security purposes by NIST and removed from most
   modern security protocols.
4. **It only covers the file bytes**, not a canonical content form.
   Reformatting the XML (different whitespace, attribute order,
   indented vs non-indented) changes the SHA-1 even though the
   semantic content is identical. So `<fileChecksum>` cannot survive
   even legitimate lossless transformations.

mzprov's `mzml_content_hash` is:

- A SHA-256 (collision-resistant)
- Over a canonical *content* form (whitespace-invariant,
  attribute-order-invariant, binary-array-order-invariant)
- Wrapped in an Ed25519 signature with an embedded verifying key
- Bound to a specific signer via the key id derived from that key

These are the cryptographic properties the mzML SHA-1 was never
designed to provide. The two are not substitutes for each other:
`<fileChecksum>` is a transmission-integrity checksum; the mzprov
sidecar is a cryptographic provenance attestation.

---

## Why do we hash the whole spectrum content instead of sampling?

This question comes up because there is a reasonable-sounding
intuition that **sampling** — embedding hashes of *n* randomly-chosen
spectra in the signed payload — would keep the payload smaller for
huge files while still catching most tampering.

The intuition is wrong on both halves:

1. **Full hashing already covers 100% of content.** Tamper detection
   probability with sampling is `1 − (1−p)^n` for fraction `p`
   tampered and sample size `n`. Full hashing is `1` for any
   non-zero edit to in-scope content. Full hashing strictly
   dominates sampling unless the threat model only cares about
   "lots of tampering" and is willing to miss subtle single-spectrum
   forgeries.
2. **Payload size is not the constraint sampling assumes.** mzprov
   v0 signs a fixed-size hash, not the actual content bytes.
   Whether the underlying file is 1 GB or 50 GB, the signed payload
   is one SHA-256 per major component. Full hashing already gives
   sampling's size benefit, for free.

In other words: full content hashing is what you would do if you
were free to choose, and sampling is what you would do if you were
constrained to embed actual bytes in the payload (which v0 is not).

There is **one** legitimate use of the sampling idea, and it has
been recorded as a v1 candidate: **defense in depth against a
canonicalizer bug.** If the canonicalizer in some implementation has
a subtle determinism flaw (Unicode normalization, sort-key
inconsistency, locale-dependent float format), the full content
hash silently diverges and the verifier rejects honest data. A
sidecar extension that *also* embeds a small randomly-sampled set
of canonical spectrum bytes alongside the full hash would let a
verifier sanity-check against the original bytes without trusting
the canonicalizer.

That extension would be additive, not a replacement for full
hashing. See [`04-canonicalization.md`](04-canonicalization.md#full-content-hashing-vs-sampling-based-attestation)
for the longer treatment and [`../spec/v1-draft/README.md`](../spec/v1-draft/README.md)
for the candidate-feature record.

---

## Why not blockchain?

Two reasons.

1. **No incentive structure to maintain ledgers.** A blockchain-based
   provenance system would need a network of nodes willing to
   maintain a public ledger of mass spectrometry signatures. There
   is no money to be earned from this. Without proof-of-work or
   proof-of-stake economics, the ledger has no enforcement against
   rewriting.
2. **Sigstore's model is the right one.** The
   ([Sigstore](https://www.sigstore.dev/)) project has already
   solved the same problem (public, append-only, tamper-evident
   logs of software signatures) using
   [Rekor](https://docs.sigstore.dev/logging/overview/) — a
   purpose-built transparency log without proof-of-work theatre. If
   and when mzprov needs a public log of signature events, the
   right design is a Rekor-style transparency log, not a blockchain.

The blockchain question is recorded here because it does come up.
The short version of the answer is: **a transparency log is the
right primitive; "blockchain" implies an unnecessary set of
properties (decentralized consensus, smart contracts, tokens) that
solve no problem we have.**

---

## Why not implement the core in Rust and bind from Python and C#?

This question is reasonable because (a) rustims already has a
Python+Rust+PyO3 workflow, so the technology fit is good, and (b)
shared core libraries are a common pattern for cross-language
projects.

The short answer is: **a shared Rust core would weaken the spec's
strongest property — cross-implementation diversity — without
solving a problem we currently have.** The longer reasoning:

### Cross-implementation diversity is itself a security argument

The point of factoring out a spec was so that **multiple independent
implementations** could prove the spec is implementable in
isolation. If we then say "the canonicalizer is a shared Rust
library and Python+C# are wrappers," the C# code stops being a
second implementation and becomes a second wrapper around the same
code. The conformance test vectors stop being a cross-implementation
contract and become a wrapper-correctness contract — a much weaker
claim. A bug in the shared Rust core ships to every user; a bug in
one of N independent implementations affects only that
implementation's users.

### Sigstore is the precedent

[Sigstore](https://www.sigstore.dev/) has cosign (Go),
sigstore-python (Python), sigstore-java (Java), and sigstore-rs
(Rust), and they explicitly do **not** share a core library. They
share a *spec* and a *conformance test suite*. The same is true for
[in-toto](https://in-toto.io/) and [SLSA](https://slsa.dev/). The
cross-implementation diversity is part of the security argument, not
an accident of history.

### The performance argument is weak today

mzprov signing is millisecond-scale. Verification is sub-second
even for the full test suite. There is no current performance
bottleneck that would justify the maintenance cost of an FFI layer.

### The distribution cost is real

A shared Rust core means building wheels per Python platform
(manylinux, macOS x86, macOS ARM, Windows), shipping a NuGet package
with native binaries for .NET runtimes (including Linux musl,
Windows-on-ARM), and tracking ABI compatibility across releases.
The pure-Python and pure-.NET alternatives have none of those
problems.

### The spec is stronger when it must be written for non-Rust readers

Writing a normative spec in RFC 2119 terms forces precision that a
Rust reference implementation can hide ("the canonical form is
whatever the Rust code does"). The spec serves the cross-language
audience, and that audience benefits from at least one non-Rust
reference implementation existing.

### A hybrid is possible if evidence demands it

If at some point the spec turns out to be hard to keep in sync
across two implementations, the right move is **not** to delete
either implementation but to ship a `mzprov-core` Rust crate with a
**tiny FFI surface** — only the two `canonicalize_*` functions —
and let each language wrapper *opt in*. Each language can still
ship a pure-native canonicalizer for those who prefer it. This
preserves the cross-implementation diversity argument as long as at
least one language has a native canonicalizer.

This is recorded so that the decision is documented and reversible.
The trigger conditions for revisiting are: (a) performance becomes
a real bottleneck, (b) the canonicalizers in two implementations
diverge in subtle ways that are hard to debug from spec text alone,
(c) a third language wants to join and reimplementing the
canonicalizer becomes prohibitive, (d) a contributor explicitly
prefers wrapping a Rust core to maintaining native code.

---

## Why is the test-only signing key committed in plaintext?

So that test vectors are byte-stable and reproducible across
machines. The test-only key under
[`../test-vectors/keys/test-only-keypair-001/`](../test-vectors/keys/test-only-keypair-001/)
is committed in plaintext intentionally and is marked as such in
the directory README. Conforming implementations SHOULD reject this
key id (and any future test-only key ids) when they appear in
production verification contexts. The reasoning:

- Test fixtures must be the same on every developer's machine and
  in CI, so the same key must be loaded by every conformance run.
- Generating a fresh key per run would change every test vector
  byte every regeneration, defeating the byte-stability that makes
  the vectors a fixed contract.
- The key is openly published, so it has zero cryptographic value
  for signing real data. Any signature produced with it should be
  treated as a test artifact, never a trust anchor.

The trade-off is documented in
[`../test-vectors/keys/README.md`](../test-vectors/keys/README.md).

---

## Why is the sidecar JSON pretty-printed but the signed payload compact?

The signature is over `Payload.to_canonical_json()`, which is
**sorted keys, no whitespace, UTF-8** — the same canonical form
[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) describes.
This is the only form that has to be byte-stable across
implementations.

The on-disk envelope (`Sidecar.to_json_bytes()`) is *also* sorted
keys but **indented with two spaces**, so a human can read the
sidecar with `cat`/`less` without piping through `jq`. The
indentation is for human inspection only; the verifier reconstructs
the canonical payload form from the parsed `payload` object before
checking the signature, never from the raw envelope bytes.

This means a sidecar with `_metadata` injected at the top level
(as the test vectors do) still verifies cleanly: the inner payload
is unchanged.

---

## Where does the timsim/ prefix in key ids and config paths come from?

It is the legacy of the lift. mzprov was extracted from the
`imspy_simulation.provenance` module in the rustims project, which
used the prefix `timsim-local-` for key ids and stored config under
`~/.config/timsim/`.

Since 0.1.2 new keys and registries live under `~/.config/mzprov/`. A
key or registry found only at the old `~/.config/timsim/` location is
used where it is, never copied, so an upgrade does not create a second
signing identity.

The `timsim-local-` key-id prefix and the `timsim.*` type tags stay:
they are inside signed payloads and derived key ids, so changing them
would break every existing sidecar. Renaming them is v1 work and needs
verifiers to accept both forms.

---

## Why does discovery refuse to guess on ambiguity?

When the verifier or trust layer is given a path that could resolve
to more than one sidecar — multiple `.d` bundles in a shared parent
directory, multiple `*.provenance.json` siblings of an mzML, or
multiple sidecars in an experiment directory — it MUST return
`None` (verify) or fail loudly (trust). It MUST NOT silently pick
the first match lexicographically. This is a stated design
principle, not a temporary limitation.

The reasoning is asymmetric:

- **Cost of being too strict:** the user gets a clear error and
  learns to specify the file explicitly. Annoying.
- **Cost of being too convenient:** the verifier silently routes to
  the wrong artifact and reports `VERIFIED` for a sidecar that does
  not correspond to the data the user thought they were verifying.
  This is a security bug.

The first failure mode is recoverable. The second is not.

Conforming implementations MUST follow the same rule. Any future
proposal to make discovery "more convenient" by guessing — picking
the first sidecar lexicographically, picking the most recently
modified, picking based on filename similarity, falling back to a
search up the directory tree — should be rejected. The right
answer is always "ask the caller to disambiguate by passing the
explicit sidecar JSON path".

This principle was crystallized after a multi-pass code review of
the lifted Python implementation found four independent first-wins
discovery bugs (`verify.py`'s `.d` branch, mzML branch, generic
directory branch, and `keys_cli.py`'s trust-by-directory branch),
all of which had passed the test suite because the suite only
exercised the single-bundle happy path. The lesson is durable:
never reintroduce the convenience path. The corresponding
regression tests under
[`../implementations/python/tests/test_sign_verify.py`](../implementations/python/tests/test_sign_verify.py)
and
[`../implementations/python/tests/test_trust.py`](../implementations/python/tests/test_trust.py)
exist precisely to catch any reintroduction.
