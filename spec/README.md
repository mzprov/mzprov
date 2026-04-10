# spec/ — normative specification

This directory is the **normative** specification of the mzprov format and
verifier behavior. A conforming implementation MUST satisfy every claim in
this directory and MUST pass every test vector under
[`../test-vectors/`](../test-vectors/).

Documents in this directory use the keywords MUST, MUST NOT, SHOULD,
SHOULD NOT, MAY, REQUIRED, RECOMMENDED, and OPTIONAL as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

If the prose in [`../docs/`](../docs/) and a claim in this directory ever
disagree, this directory wins.

## Index

| File | Scope |
|---|---|
| [`sidecar-format.md`](sidecar-format.md) | JSON envelope, payload field semantics for both `.d` and mzML attestation types, hash and signature encoding rules, exit-code mapping |
| [`canonicalization-d-v0.md`](canonicalization-d-v0.md) | Bruker timsTOF `.d` canonicalization: SQLite content walk, value encoding, `.d` directory composition, `compose_content_hash` |
| [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) | mzML canonicalization: spectrum enumeration, per-spectrum record format, binary array role labels and precision tags, `compose_mzml_content_hash` |
| [`signature-scheme.md`](signature-scheme.md) | Ed25519 signing, the `{algorithm}:{encoding}:{value}` envelope, algorithm agility, replay/freshness implications |
| [`key-id-derivation.md`](key-id-derivation.md) | BLAKE2b-80 → base32-lowercase → `timsim-local-` prefix; the label-vs-signer consistency check |
| [`trust-model.md`](trust-model.md) | Verifier behavior, exit codes `0`–`7`, sidecar discovery, source-artifact location, `--expected-key-id`, `--require-trusted`, `--public-key`, the verifier check order |
| [`security-considerations.md`](security-considerations.md) | Security goals, threat model recap, trust assumptions, properties NOT provided, primitives, side-channel notes, replay/freshness, privacy |
| [`v1-draft/`](v1-draft/) | Proposed features awaiting graduation — see [`v1-draft/README.md`](v1-draft/README.md) |

## Versioning

The specification version (`v0`) is independent from:

- The canonicalization version (`canonicalization_version` in the sidecar),
  which bumps when the canonical record format changes
- The signature algorithm (`signature` field prefix, currently
  `ed25519:base64:...`), which can evolve independently via the
  algorithm-agility envelope defined in [`signature-scheme.md`](signature-scheme.md)

A `v0` canonicalization with a future `v1` signature scheme, and vice
versa, are both representable.

## Licensing

All files in this directory are CC-BY-4.0. See [`../LICENSE-CC-BY`](../LICENSE-CC-BY).
