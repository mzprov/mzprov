# implementations/csharp/ — C# implementation

An **independent** C# implementation of mzprov verification and
canonicalization, targeting .NET 8.

## Independence

This implementation is intentionally independent of the Python reference
implementation. The two target the same normative specification
([`../../spec/`](../../spec/)) and the same interop contract
([`../../test-vectors/`](../../test-vectors/)). They share no code.

The point of an independent second implementation is to surface
ambiguities in the specification: if the C# implementation and the Python
implementation both pass every test vector but produce different results
on a real-world input, the spec or the test vectors are incomplete.

## Scope (v0)

A complete signer + verifier:

- **`sign`** — sign a `.d` directory, an mzML file, or a Thermo `.raw`
  file. Writes a JSON sidecar (`*.provenance.json` + a config copy), or
  embeds the envelope in-band with `--embed` (the `.d`
  `mzprov_provenance` SQLite row or the mzML `mzprov:provenance`
  userParam; `.raw` is sidecar-only). Attestations it produces are
  accepted by the Python reference and vice versa (see Round-trip below).
- **`keys generate`** — create an Ed25519 keypair, written as
  `signing_key.pem` (PKCS#8), `verifying_key.pem` (SPKI), and `key_id`,
  byte-format-compatible with the Python reference's key files (keys are
  interoperable in both directions).
- **`verify`** — all three transports (JSON sidecar, embedded-`.d` SQLite
  table, embedded-mzML userParam). Performs key-id consistency,
  cross-format, unknown-algorithm, per-field hash, and Ed25519 signature
  checks, and maps the outcome to the frozen `0`–`7` verifier exit codes.
- **`canonicalize`** — byte-identical canonical hashing for `.d`
  (analysis.tdf SQLite + analysis.tdf_bin), mzML (spectrum content), and
  Thermo `.raw` (opaque whole-file).

**Not implemented:** the trusted-keys registry / trust-pinning flags
(`--expected-key-id`, `--require-trusted`) — out of scope for v0 interop.

### Known differences from the Python reference

- For a `.d`, the reference's `sign_simulation_output` hardcodes the payload
  `simulator_name` to `"TimSim"` (its only `.d` producer). A general signer
  must not misattribute provenance, so the C# `sign` records the actual
  `--tool-name` instead. The field is free-form and never read by a verifier,
  so this does not affect interop — round-trip passes in both directions.

## Layout

```
implementations/csharp/
├── Mzprov/
│   ├── Mzprov.csproj        net8.0 console app (AssemblyName: mzprov)
│   ├── Program.cs           subcommand dispatch
│   ├── SignCli.cs           `sign` CLI
│   ├── KeysCli.cs           `keys generate` CLI
│   ├── VerifyCli.cs         `verify` + exit-code mapping
│   ├── CanonicalizeCli.cs   `canonicalize` driver
│   ├── Sign.cs              hash + sign + write (3 formats, sidecar/embed)
│   ├── Verify.cs            discovery + 3-transport verification + checks
│   ├── Envelope.cs          sidecar JSON parse + canonical payload JSON + writer
│   ├── Canonicalize.cs      .raw + .d (SQLite) canonicalization
│   ├── CanonicalizeMzml.cs  mzML canonicalization
│   ├── Embed.cs             embedded-transport readers (.d table / mzML userParam)
│   ├── EmbedWrite.cs        embedded-transport writers
│   ├── Keys.cs              key-id derivation, Ed25519 sign/verify, PEM I/O
│   ├── Paths.cs             config-copy path conventions (shared sign/verify)
│   ├── Errors.cs            typed errors
│   └── ExitCodes.cs         the frozen 0–7 exit codes
├── LICENSE                  Apache 2.0
└── README.md
```

## Dependencies

- [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)
  — Ed25519 verification and the BLAKE2b-80 key-id digest.
- [Microsoft.Data.Sqlite](https://www.nuget.org/packages/Microsoft.Data.Sqlite)
  — reading `analysis.tdf` for the `.d` canonical SQL dump (row ordering
  comes from SQLite itself, so it matches the reference exactly).

## Build and run

```sh
dotnet build implementations/csharp/Mzprov/Mzprov.csproj --configuration Release

DLL=implementations/csharp/Mzprov/bin/Release/net8.0/mzprov.dll
dotnet $DLL keys generate --key-dir ~/.mzprov-keys
dotnet $DLL sign path/to/file.mzML --experiment-name demo --key ~/.mzprov-keys
dotnet $DLL sign path/to/sample.d  --experiment-name demo --key ~/.mzprov-keys --config run.toml --embed
dotnet $DLL verify path/to/experiment           # exit code 0..7
dotnet $DLL canonicalize mzml path/to/file.mzML # prints sha256:<hex>
```

## Conformance

The one binary serves both halves of the conformance harness
([`../../test-vectors/_harness/run_conformance.py`](../../test-vectors/_harness/run_conformance.py))
via subcommands:

```sh
DLL=implementations/csharp/Mzprov/bin/Release/net8.0/mzprov.dll
python test-vectors/_harness/run_conformance.py \
  --verify-cmd "dotnet $DLL verify" \
  --canonicalize-cmd "dotnet $DLL canonicalize"
```

This is exactly what the `csharp` job in
[`.github/workflows/conformance.yml`](../../.github/workflows/conformance.yml)
runs on every push and PR; the `conformance` gate requires it.

## Round-trip (cross-implementation interop)

Beyond verifying the committed corpus, the `roundtrip` CI job proves that
attestations **produced** by one implementation are **accepted** by another
(a differential test), driven by
[`../../test-vectors/_harness/run_roundtrip.py`](../../test-vectors/_harness/run_roundtrip.py):

```sh
DLL=implementations/csharp/Mzprov/bin/Release/net8.0/mzprov.dll
dotnet $DLL keys generate --key-dir /tmp/cs-keys
# C# signs every format -> Python verifies
python test-vectors/_harness/run_roundtrip.py \
  --signer-cmd "dotnet $DLL sign" --verifier-cmd "mzprov verify" --key /tmp/cs-keys
```

Ed25519 keys generated by either implementation load in the other, so the
same signer key is usable across both.

## Licensing

Apache 2.0 (see [`LICENSE`](LICENSE)), matching the Python reference
implementation.
