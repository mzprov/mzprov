# implementations/csharp/ — C# implementation

This directory will hold an **independent** C# implementation of mzprov.

## Independence

This implementation is intentionally independent of the Python reference
implementation. The two implementations target the same normative
specification ([`../../spec/`](../../spec/)) and the same interop contract
([`../../test-vectors/`](../../test-vectors/)). They share no code.

The point of an independent second implementation is to surface
ambiguities in the specification: if the C# implementation and the Python
implementation both pass every test vector but produce different results
on a real-world input, the spec or the test vectors are incomplete.

## Status

Not yet started. The implementation goal is to pass every test vector
under [`../../test-vectors/`](../../test-vectors/) under the same
conformance harness contract documented in
[`../../test-vectors/README.md`](../../test-vectors/README.md).

## Suggested platform notes

For implementers picking up this work:

- **.NET 6 or later** has Ed25519 in `System.Security.Cryptography` (via
  the `Ed25519` algorithm). Earlier .NET versions can use BouncyCastle.
- **SHA-256** is in `System.Security.Cryptography`. **BLAKE2b** is
  available in BouncyCastle if not in the standard library.
- **JSON canonicalization for the signed payload** is sorted keys, no
  whitespace, UTF-8 — see `spec/sidecar-format.md` once it lands. This is
  the same canonicalization [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
  describes.

## Licensing

The C# implementation will declare its own license inside this directory
when it lands. The expected license is Apache 2.0 to match the Python
reference implementation, but this is the C# implementer's call.
