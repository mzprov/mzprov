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

This is the **conformance-sufficient** surface — everything the
cross-implementation conformance harness exercises:

- **`verify`** — all three transports: the JSON sidecar
  (`*.provenance.json`), the embedded-`.d` `mzprov_provenance` SQLite
  table, and the embedded-mzML `mzprov:provenance` userParam. Performs
  key-id consistency, cross-format, unknown-algorithm, per-field hash,
  and Ed25519 signature checks, and maps the outcome to the frozen
  `0`–`7` verifier exit codes.
- **`canonicalize`** — byte-identical canonical hashing for `.d`
  (analysis.tdf SQLite + analysis.tdf_bin), mzML (spectrum content), and
  Thermo `.raw` (opaque whole-file).

**Not yet implemented:** `sign`, key generation, and writing the embedded
transports (no test vector exercises signing). These are a clean
follow-up; verification + canonicalization are what the interop contract
requires.

## Layout

```
implementations/csharp/
├── Mzprov/
│   ├── Mzprov.csproj        net8.0 console app (AssemblyName: mzprov)
│   ├── Program.cs           subcommand dispatch
│   ├── VerifyCli.cs         `verify` + exit-code mapping
│   ├── CanonicalizeCli.cs   `canonicalize` driver
│   ├── Verify.cs            discovery + 3-transport verification + checks
│   ├── Envelope.cs          sidecar JSON parse + canonical signed-payload JSON
│   ├── Canonicalize.cs      .raw + .d (SQLite) canonicalization
│   ├── CanonicalizeMzml.cs  mzML canonicalization
│   ├── Embed.cs             embedded-transport readers (.d table / mzML userParam)
│   ├── Keys.cs              key-id derivation + Ed25519 verify
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

## Licensing

Apache 2.0 (see [`LICENSE`](LICENSE)), matching the Python reference
implementation.
