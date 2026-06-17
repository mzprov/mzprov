namespace Mzprov;

// Verifier exit codes. Frozen at v0 (see spec/trust-model.md and
// CONTRIBUTING.md "What is frozen at v0"). These values ARE the
// cross-implementation contract the conformance harness keys on.
internal static class ExitCodes
{
    public const int Ok = 0;
    public const int Generic = 1;
    public const int KeyError = 2;
    public const int SidecarError = 3;
    public const int Unsigned = 4;
    public const int HashMismatch = 5;
    public const int SignatureMismatch = 6;
    public const int KeyNotTrusted = 7;
}
