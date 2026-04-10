# test-vectors/ — the interop contract

This directory is the **interop contract** for mzprov. A conforming
implementation in any language MUST verify every vector under `valid/`
and MUST reject every vector under `invalid/` with the named rejection
reason.

This is the only mechanism by which two independent implementations can
mechanically verify they agree.

## Layout

```
test-vectors/
├── README.md                         this file
├── sidecar/
│   ├── valid/                        sidecars that MUST verify
│   │   ├── d-v0-minimal.json
│   │   ├── mzml-v0-minimal.json
│   │   └── ...
│   └── invalid/                      sidecars that MUST be rejected
│       ├── tampered-content-hash.json     reason: HASH_MISMATCH
│       ├── tampered-payload.json          reason: SIGNATURE_MISMATCH
│       ├── wrong-key-id-label.json        reason: KEY_ID_CONSISTENCY
│       ├── unknown-signature-algo.json    reason: UNKNOWN_ALGORITHM
│       ├── cross-format-reuse.json        reason: WRONG_SIDECAR_TYPE
│       ├── encoding-tag-swap.json         reason: HASH_MISMATCH
│       └── ...
├── canonicalization/
│   ├── mzml/
│   │   ├── 001-input.mzML
│   │   ├── 001-canonical-hash.txt    expected sha256
│   │   ├── 002-whitespace-variant.mzML    different bytes, same hash as 001
│   │   ├── 002-canonical-hash.txt
│   │   └── ...
│   └── d/
│       └── ...
└── keys/
    └── test-only-keypair-001.{pem,id}     CLEARLY MARKED — never used to sign real data
```

## How to consume from any language

A conforming implementation runs its own conformance harness against this
directory. The harness MUST:

1. For each file under `sidecar/valid/`, parse the sidecar and verify it.
   The verifier MUST return success.
2. For each file under `sidecar/invalid/`, parse the sidecar and attempt
   verification. The verifier MUST return failure with the rejection
   reason declared in the file's `_metadata.expected_failure` field.
3. For each input/expected-hash pair under `canonicalization/`, run the
   canonicalizer on the input and check that the output hash matches the
   expected value byte-for-byte.

The Python reference implementation's conformance harness lives at
`implementations/python/tests/conformance/`. The C# implementation's
harness will live at `implementations/csharp/tests/conformance/`. They run
against the same vectors.

## Vector format

Each invalid vector carries an `_metadata` object with at least:

```json
{
  "_metadata": {
    "expected_failure": "HASH_MISMATCH",
    "spec_section": "spec/sidecar-format.md#hash-validation",
    "description": "human-readable explanation of what was tampered"
  }
}
```

The `_metadata` object MUST be ignored by signing tools (it is added by
the test suite, not by `mzprov sign`) but MUST be honored by the
conformance harness.

## Test-only keys

The keys under `keys/` are **test-only**. They are committed in plaintext
to this repository specifically so that conformance tests are
reproducible. They MUST NOT be used to sign real data. They MUST NOT be
added to any production trust registry. The corresponding key ids are
listed in `keys/README.md` (once it lands) so that production tooling can
refuse them outright.

## Status

| Category | Status |
|---|---|
| Sidecar valid vectors | being generated from the lifted Python implementation |
| Sidecar invalid vectors | being generated from the lifted Python implementation |
| mzML canonicalization vectors | being generated from the lifted Python implementation |
| `.d` canonicalization vectors | being generated from the lifted Python implementation |
| Test-only keys | not yet committed |

## Licensing

All files in this directory are CC0 1.0. See [`../LICENSE-CC0`](../LICENSE-CC0).

This is intentional: test fixtures should have zero attribution burden so
any implementation in any language can ship them as part of its own test
suite.
