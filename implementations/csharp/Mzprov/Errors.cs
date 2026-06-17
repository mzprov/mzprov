using System;

namespace Mzprov;

// Typed errors mirroring the reference implementation's mzprov.errors.
// Each maps to a stable verifier exit code in VerifyCli. Structural
// problems (missing/malformed sidecar, unknown version, missing artifact)
// are raised; hash/signature mismatches are NOT exceptions — they are
// reported as fields on VerificationResult so the CLI can pick the most
// specific exit code.
internal class ProvenanceException : Exception
{
    public ProvenanceException(string message) : base(message) { }
}

// A signing/verifying key was requested but not found on disk.
internal sealed class KeyNotFoundException : ProvenanceException
{
    public KeyNotFoundException(string message) : base(message) { }
}

// A key file exists but cannot be parsed / is the wrong algorithm.
internal sealed class MalformedKeyException : ProvenanceException
{
    public MalformedKeyException(string message) : base(message) { }
}

// The sidecar JSON is malformed, missing required fields, has the wrong
// shape, or carries an undecodable signature/key field.
internal sealed class MalformedSidecarException : ProvenanceException
{
    public MalformedSidecarException(string message) : base(message) { }
}

// The sidecar declares a type / canonicalization_version we do not handle.
internal sealed class UnknownVersionException : ProvenanceException
{
    public UnknownVersionException(string message) : base(message) { }
}

// A .d directory was found but no provenance accompanies it.
internal sealed class UnsignedException : ProvenanceException
{
    public UnsignedException(string message) : base(message) { }
}

// The sidecar references an artifact (.d, .mzML, .raw) that is not on disk.
internal sealed class MissingArtifactException : ProvenanceException
{
    public MissingArtifactException(string message) : base(message) { }
}

// A SQLite file we are about to hash has -wal/-shm/-journal sidecars
// present, so the bytes the immutable reader sees may differ from what
// ordinary readers see. Refusing is the only safe option.
internal sealed class SqliteNotQuiescentException : ProvenanceException
{
    public SqliteNotQuiescentException(string message) : base(message) { }
}
