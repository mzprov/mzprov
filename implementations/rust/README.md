# implementations/rust/ — Rust implementation

An independent Rust implementation of the mzprov v0 verifier. It shares
no code with the Python reference; both implementations target the
normative specification in [`../../spec/`](../../spec/) and pass the
same test vectors in [`../../test-vectors/`](../../test-vectors/).

This port exists for consumers working in Rust — notably tooling around
emerging mass-spec file-format standards — so they can verify mzprov
sidecars without a Python toolchain.

## Status

Full signer + verifier. Passes every vector under
[`../../test-vectors/sidecar/`](../../test-vectors/sidecar/) with the
exit code declared in each vector's `_metadata.expected_exit_code`.
Matches the canonical hashes in
[`../../test-vectors/canonicalization/`](../../test-vectors/canonicalization/)
byte-for-byte, derives the test-vector key id from `verifying_key.pem`
character-for-character, and a sidecar produced by `mzprov sign` (Rust)
verifies under both the Rust and Python verifiers.

| Feature | State |
|---|---|
| `.d` canonicalization | implemented |
| mzML canonicalization (non-numpress) | implemented |
| Sidecar envelope parse + canonical payload | implemented |
| BLAKE2b-80 key-id derivation | implemented |
| Ed25519 signature verify + sign | implemented |
| Key generation (`mzprov keys generate`) | implemented |
| Signer (`mzprov sign` for `.d` and mzML) | implemented |
| Verifier (`mzprov verify`) | implemented |
| Trust pinning (`--expected-key-id`, `--require-trusted`) | implemented |
| Trusted-keys registry (`keys trust` / `keys untrust` / `keys list`) | implemented |
| numpress mzML arrays | not yet (spec leaves this to v1) |

## Build and test

```sh
cargo build
cargo test         # runs the conformance harness + round-trip tests

# Verify a sidecar
cargo run -- verify ../../test-vectors/sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json

# Generate a keypair and sign a fresh file
cargo run -- keys generate --out /tmp/keys
cargo run -- sign /tmp/sample.mzML \
    --experiment-name demo \
    --tool-name my-tool --tool-version 0.1 \
    --key /tmp/keys/signing_key.pem

# Trust-pin verification (ad-hoc)
cargo run -- verify /tmp/sample.provenance.json \
    --expected-key-id "$(cat /tmp/keys/key_id)"

# Populate the trusted-keys registry and require membership
cargo run -- keys trust /tmp/keys/verifying_key.pem --comment "my lab"
cargo run -- verify /tmp/sample.provenance.json --require-trusted
```

Exit codes follow [`../../spec/trust-model.md`](../../spec/trust-model.md)
and match the Python reference: 0 OK, 2 key error, 3 sidecar error,
4 unsigned, 5 hash mismatch, 6 signature mismatch, 7 trust not satisfied.

## Layout

```
Cargo.toml
src/
  lib.rs
  errors.rs             ProvenanceError taxonomy
  exit_codes.rs         numeric exit codes from spec/trust-model.md
  keys.rs               BLAKE2b-80 key id, PEM I/O, sign/verify, keygen
  envelope.rs           sidecar parse + canonical payload bytes
  canonicalize_d.rs     Bruker .d canonical content hash
  canonicalize_mzml.rs  mzML canonical content hash
  sign.rs               build payload, sign, write envelope atomically
  trust.rs              trusted-keys registry + TrustedKey helpers
  verify.rs             verifier, discovery rules, trust-model exit map
  bin/mzprov.rs         CLI (verify, sign, keys generate|trust|untrust|list)
tests/
  conformance.rs        runs against ../../test-vectors/
```

## Why two implementations matter

The point of a second implementation is to surface specification
ambiguities. If Rust and Python both pass every vector but disagree on
a real-world input, the spec or the vectors are incomplete. File an
issue and we will add a vector.

## Licensing

Apache-2.0, matching the Python reference.
