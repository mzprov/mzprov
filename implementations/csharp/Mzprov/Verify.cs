using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Mzprov;

internal enum Transport { SidecarJson, EmbeddedD, EmbeddedMzml }

internal readonly struct Discovery
{
    public Transport Transport { get; }
    public string Path { get; }
    public Discovery(Transport transport, string path) { Transport = transport; Path = path; }
}

internal enum CheckStatus { Ok, Mismatch, Unchecked }

internal sealed class VerificationResult
{
    public bool SignatureOk;
    public List<CheckStatus> Checks = new();
    public bool OverallOk;
}

// Pure verifier: discovers provenance, recomputes canonical hashes, checks
// the Ed25519 signature, and reports per-field statuses. Structural problems
// throw; hash/signature mismatches are recorded on the result. Mirrors
// mzprov.verify (trust pinning is out of scope for the conformance build —
// no vector exercises --expected-key-id/--require-trusted, so trust is
// always satisfied).
internal static class Verify
{
    private const string ConfigEmptyHashHex = ""; // computed lazily below

    // ----- discovery (find_provenance_for) -----

    public static Discovery? FindProvenanceFor(string path)
    {
        string? d = ProbeEmbeddedD(path);
        if (d != null) return new Discovery(Transport.EmbeddedD, d);

        string? m = ProbeEmbeddedMzml(path);
        if (m != null) return new Discovery(Transport.EmbeddedMzml, m);

        string? j = FindSidecarFor(path);
        if (j != null) return new Discovery(Transport.SidecarJson, j);

        return null;
    }

    private static string? ProbeEmbeddedD(string path)
    {
        string? candidate;
        if (Directory.Exists(path) && BaseName(path).EndsWith(".d", StringComparison.Ordinal)
            && File.Exists(System.IO.Path.Combine(path, "analysis.tdf")))
        {
            candidate = path;
        }
        else if (Directory.Exists(path))
        {
            candidate = FindUniqueD(path);
        }
        else
        {
            return null;
        }
        if (candidate is null) return null;
        return Embed.HasEmbeddedD(candidate) ? candidate : null;
    }

    private static string? ProbeEmbeddedMzml(string path)
    {
        string? candidate;
        if (File.Exists(path) && HasMzmlSuffix(path))
        {
            candidate = path;
        }
        else if (Directory.Exists(path))
        {
            candidate = FindUniqueMzml(path);
        }
        else
        {
            return null;
        }
        if (candidate is null) return null;
        return Embed.HasEmbeddedMzml(candidate) ? candidate : null;
    }

    private static string? FindSidecarFor(string path)
    {
        if (File.Exists(path))
        {
            string fname = BaseName(path);
            if (fname.EndsWith(".json", StringComparison.Ordinal) && fname.Contains(".provenance"))
            {
                return path;
            }
            if (HasMzmlSuffix(path))
            {
                string stem = StripSuffixCaseInsensitive(fname, ".mzml");
                string candidate = System.IO.Path.Combine(DirName(path), stem + ".provenance.json");
                if (File.Exists(candidate)) return candidate;
                return UniqueProvenance(DirName(path));
            }
            return null;
        }

        if (Directory.Exists(path))
        {
            string name = BaseName(path);
            if (name.EndsWith(".d", StringComparison.Ordinal))
            {
                string stem = name.Substring(0, name.Length - 2);
                string candidate = System.IO.Path.Combine(DirName(path), stem + ".provenance.json");
                if (File.Exists(candidate)) return candidate;
                return UniqueProvenance(DirName(path));
            }
            return UniqueProvenance(path);
        }

        return null;
    }

    private static string? UniqueProvenance(string dir)
    {
        var hits = SafeEnumerateFiles(dir).Where(f => f.EndsWith(".provenance.json", StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal).ToList();
        return hits.Count == 1 ? hits[0] : null;
    }

    private static string? FindUniqueD(string searchRoot)
    {
        var candidates = new List<string>();
        foreach (string child in SafeEnumerateDirectories(searchRoot))
        {
            if (BaseName(child).EndsWith(".d", StringComparison.Ordinal)
                && File.Exists(System.IO.Path.Combine(child, "analysis.tdf")))
            {
                candidates.Add(child);
                continue;
            }
            foreach (string grandchild in SafeEnumerateDirectories(child))
            {
                if (BaseName(grandchild).EndsWith(".d", StringComparison.Ordinal)
                    && File.Exists(System.IO.Path.Combine(grandchild, "analysis.tdf")))
                {
                    candidates.Add(grandchild);
                }
            }
        }
        return candidates.Count == 1 ? candidates[0] : null;
    }

    private static string? FindUniqueMzml(string searchRoot)
    {
        var candidates = SafeEnumerateFiles(searchRoot).Where(HasMzmlSuffix).ToList();
        return candidates.Count == 1 ? candidates[0] : null;
    }

    // ----- entry points -----

    public static VerificationResult VerifySidecarJson(string sidecarPath)
    {
        if (!File.Exists(sidecarPath))
        {
            throw new MalformedSidecarException($"sidecar file does not exist: {sidecarPath}");
        }
        var sidecar = Sidecar.Parse(File.ReadAllBytes(sidecarPath));
        byte[] pub = ValidateSignerIdentity(sidecar);

        switch (sidecar.Kind)
        {
            case PayloadKind.D:
                {
                    string saveDir = DirName(sidecarPath);
                    string? dPath = FindUniqueD(saveDir);
                    if (dPath is null)
                    {
                        throw new MissingArtifactException(
                            $"could not find a unique .d directory near {saveDir}");
                    }
                    return VerifyDPayload(sidecar, pub, dPath,
                        System.IO.Path.Combine(saveDir, "synthetic_data.db"),
                        SidecarConfigPath(sidecarPath));
                }
            case PayloadKind.Mzml:
                {
                    string? mzmlPath = FindMzmlForSidecar(sidecarPath);
                    if (mzmlPath is null)
                    {
                        throw new MissingArtifactException(
                            $"could not find an .mzML file for sidecar {BaseName(sidecarPath)}");
                    }
                    return VerifyMzmlPayload(sidecar, pub, mzmlPath, SidecarConfigPath(sidecarPath));
                }
            default:
                {
                    string? rawPath = FindRawForSidecar(sidecarPath);
                    if (rawPath is null)
                    {
                        throw new MissingArtifactException(
                            $"could not find the .raw file for sidecar {BaseName(sidecarPath)}");
                    }
                    return VerifyRawPayload(sidecar, pub, rawPath, SidecarConfigPath(sidecarPath));
                }
        }
    }

    public static VerificationResult VerifyEmbeddedD(string dPath)
    {
        if (!Directory.Exists(dPath))
        {
            throw new MissingArtifactException($".d directory does not exist: {dPath}");
        }
        byte[]? envelope = Embed.ReadEmbeddedD(dPath);
        if (envelope is null)
        {
            throw new UnsignedException($"no embedded provenance found in {dPath}/analysis.tdf");
        }
        var sidecar = Sidecar.Parse(envelope);
        if (sidecar.Kind != PayloadKind.D)
        {
            throw new MalformedSidecarException(
                $"embedded provenance in {dPath} is not a .d attestation");
        }
        byte[] pub = ValidateSignerIdentity(sidecar);
        return VerifyDPayload(sidecar, pub, dPath,
            System.IO.Path.Combine(DirName(dPath), "synthetic_data.db"),
            EmbeddedDConfigPath(dPath));
    }

    public static VerificationResult VerifyEmbeddedMzml(string mzmlPath)
    {
        if (!File.Exists(mzmlPath))
        {
            throw new MissingArtifactException($"mzml file does not exist: {mzmlPath}");
        }
        byte[]? envelope = Embed.ReadEmbeddedMzml(mzmlPath);
        if (envelope is null)
        {
            throw new UnsignedException($"no embedded provenance found in {mzmlPath}");
        }
        var sidecar = Sidecar.Parse(envelope);
        if (sidecar.Kind != PayloadKind.Mzml)
        {
            throw new MalformedSidecarException(
                $"embedded provenance in {mzmlPath} is not an mzML attestation");
        }
        byte[] pub = ValidateSignerIdentity(sidecar);
        return VerifyMzmlPayload(sidecar, pub, mzmlPath, EmbeddedMzmlConfigPath(mzmlPath));
    }

    // ----- per-format payload verification -----

    private static VerificationResult VerifyDPayload(Sidecar sidecar, byte[] pub, string dPath,
        string groundTruthPath, string conventionalConfigPath)
    {
        byte[] dHash = Canonicalize.CanonicalizeD(dPath);

        byte[]? groundTruthHash = null;
        string gtField = sidecar.Field("ground_truth_hash");
        if (gtField.Length > 0)
        {
            if (!File.Exists(groundTruthPath))
            {
                throw new MissingArtifactException(
                    $"sidecar references a ground-truth DB but none was found at {groundTruthPath}");
            }
            groundTruthHash = Canonicalize.CanonicalizeSqlite(groundTruthPath);
        }

        var checks = new List<CheckStatus>();
        checks.Add(HashCheck(sidecar.Field("d_content_hash"), dHash));
        if (gtField.Length > 0)
        {
            checks.Add(groundTruthHash != null ? HashCheck(gtField, groundTruthHash) : CheckStatus.Mismatch);
        }

        // .d config resolution has NO sha256("") fallback (matches the reference).
        byte[]? configHash = ResolveConfig(conventionalConfigPath, sidecar.Field("config_hash"),
            allowEmptyFallback: false, out CheckStatus configStatus);
        checks.Add(configStatus);

        if (configHash is null)
        {
            checks.Add(CheckStatus.Unchecked);
        }
        else
        {
            byte[] composed = Canonicalize.ComposeContentHash(dHash, groundTruthHash, configHash);
            checks.Add(HashCheck(sidecar.Field("content_hash"), composed));
        }

        return Finish(sidecar, pub, checks);
    }

    private static VerificationResult VerifyMzmlPayload(Sidecar sidecar, byte[] pub, string mzmlPath,
        string conventionalConfigPath)
    {
        byte[] mzmlHash = CanonicalizeMzml.Run(mzmlPath);

        var checks = new List<CheckStatus>();
        checks.Add(HashCheck(sidecar.Field("mzml_content_hash"), mzmlHash));

        byte[]? configHash = ResolveConfig(conventionalConfigPath, sidecar.Field("config_hash"),
            allowEmptyFallback: true, out CheckStatus configStatus);
        checks.Add(configStatus);

        if (configHash is null)
        {
            checks.Add(CheckStatus.Unchecked);
        }
        else
        {
            byte[] composed = CanonicalizeMzml.ComposeMzmlContentHash(mzmlHash, configHash);
            checks.Add(HashCheck(sidecar.Field("content_hash"), composed));
        }

        return Finish(sidecar, pub, checks);
    }

    private static VerificationResult VerifyRawPayload(Sidecar sidecar, byte[] pub, string rawPath,
        string conventionalConfigPath)
    {
        byte[] rawHash = Canonicalize.CanonicalizeRaw(rawPath);

        var checks = new List<CheckStatus>();
        checks.Add(HashCheck(sidecar.Field("raw_content_hash"), rawHash));

        byte[]? configHash = ResolveConfig(conventionalConfigPath, sidecar.Field("config_hash"),
            allowEmptyFallback: true, out CheckStatus configStatus);
        checks.Add(configStatus);

        if (configHash is null)
        {
            checks.Add(CheckStatus.Unchecked);
        }
        else
        {
            byte[] composed = Canonicalize.ComposeRawContentHash(rawHash, configHash);
            checks.Add(HashCheck(sidecar.Field("content_hash"), composed));
        }

        return Finish(sidecar, pub, checks);
    }

    // Resolve the config file and return its hash (or null if unchecked).
    // Never falls back to the signed value. The empty fallback recomputes
    // sha256(b"") — a fixed constant, not a payload value — and is used by
    // the mzML/.raw paths only.
    private static byte[]? ResolveConfig(string conventionalConfigPath, string signedConfigHash,
        bool allowEmptyFallback, out CheckStatus status)
    {
        if (File.Exists(conventionalConfigPath))
        {
            byte[] h = Canonicalize.CanonicalizeBytes(File.ReadAllBytes(conventionalConfigPath));
            status = signedConfigHash == Hex(h) ? CheckStatus.Ok : CheckStatus.Mismatch;
            return h;
        }
        if (allowEmptyFallback)
        {
            byte[] empty = Canonicalize.CanonicalizeBytes(Array.Empty<byte>());
            if (signedConfigHash == Hex(empty))
            {
                status = CheckStatus.Ok;
                return empty;
            }
        }
        status = CheckStatus.Unchecked;
        return null;
    }

    private static VerificationResult Finish(Sidecar sidecar, byte[] pub, List<CheckStatus> checks)
    {
        // Decode-failure on the signature surfaces as MalformedSidecar (exit 3),
        // matching the reference (e.g. an unknown signature algorithm prefix).
        byte[] signature = Keys.SignatureFromB64(sidecar.Signature);
        byte[] signed = sidecar.CanonicalPayloadJson();
        bool sigOk = Keys.Verify(pub, signature, signed);

        bool overall = sigOk && checks.All(c => c == CheckStatus.Ok);
        return new VerificationResult { SignatureOk = sigOk, Checks = checks, OverallOk = overall };
    }

    private static byte[] ValidateSignerIdentity(Sidecar sidecar)
    {
        byte[] pub = Keys.PublicKeyFromB64(sidecar.VerifyingKey);
        string derivedId = Keys.DeriveKeyId(pub);
        if (sidecar.Field("key_id") != derivedId)
        {
            throw new MalformedSidecarException(
                $"sidecar payload.key_id ('{sidecar.Field("key_id")}') does not match the key id " +
                $"derived from sidecar.verifying_key ('{derivedId}').");
        }
        return pub;
    }

    private static CheckStatus HashCheck(string expected, byte[] actual) =>
        expected == Hex(actual) ? CheckStatus.Ok : CheckStatus.Mismatch;

    private static string Hex(byte[] b) => "sha256:" + Canonicalize.ToHexLower(b);

    // ----- path conventions -----

    private static string SidecarConfigPath(string sidecarPath)
    {
        string name = BaseName(sidecarPath);
        string stem = name.EndsWith(".provenance.json", StringComparison.Ordinal)
            ? name.Substring(0, name.Length - ".provenance.json".Length)
            : System.IO.Path.GetFileNameWithoutExtension(name);
        return System.IO.Path.Combine(DirName(sidecarPath), stem + ".config.toml");
    }

    private static string EmbeddedDConfigPath(string dPath)
    {
        string name = BaseName(dPath);
        string stem = name.EndsWith(".d", StringComparison.Ordinal) ? name.Substring(0, name.Length - 2) : name;
        return System.IO.Path.Combine(DirName(dPath), stem + ".config.toml");
    }

    private static string EmbeddedMzmlConfigPath(string mzmlPath) =>
        System.IO.Path.Combine(DirName(mzmlPath),
            System.IO.Path.GetFileNameWithoutExtension(BaseName(mzmlPath)) + ".config.toml");

    private static string? FindMzmlForSidecar(string sidecarPath)
    {
        string name = BaseName(sidecarPath);
        string stem = name.EndsWith(".provenance.json", StringComparison.Ordinal)
            ? name.Substring(0, name.Length - ".provenance.json".Length)
            : System.IO.Path.GetFileNameWithoutExtension(name);
        string parent = DirName(sidecarPath);
        foreach (string suffix in new[] { ".mzML", ".mzml" })
        {
            string candidate = System.IO.Path.Combine(parent, stem + suffix);
            if (File.Exists(candidate)) return candidate;
        }
        return FindUniqueMzml(parent);
    }

    private static string? FindRawForSidecar(string sidecarPath)
    {
        string name = BaseName(sidecarPath);
        string stem = name.EndsWith(".provenance.json", StringComparison.Ordinal)
            ? name.Substring(0, name.Length - ".provenance.json".Length)
            : System.IO.Path.GetFileNameWithoutExtension(name);
        string parent = DirName(sidecarPath);
        var found = new List<string>();
        foreach (string suffix in new[] { ".raw", ".RAW" })
        {
            string candidate = System.IO.Path.Combine(parent, stem + suffix);
            if (File.Exists(candidate) && !found.Any(p => string.Equals(
                    System.IO.Path.GetFullPath(p), System.IO.Path.GetFullPath(candidate), StringComparison.Ordinal)))
            {
                found.Add(candidate);
            }
        }
        if (found.Count > 1)
        {
            throw new MalformedSidecarException(
                $"ambiguous .raw pairing for sidecar {sidecarPath}: both {stem}.raw and {stem}.RAW exist");
        }
        return found.Count == 1 ? found[0] : null;
    }

    // ----- small fs helpers -----

    private static bool HasMzmlSuffix(string path) =>
        BaseName(path).EndsWith(".mzml", StringComparison.OrdinalIgnoreCase);

    private static string BaseName(string path) =>
        System.IO.Path.GetFileName(path.TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar));

    private static string DirName(string path) =>
        System.IO.Path.GetDirectoryName(path.TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar)) ?? ".";

    private static string StripSuffixCaseInsensitive(string s, string suffix) =>
        s.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ? s.Substring(0, s.Length - suffix.Length) : s;

    private static IEnumerable<string> SafeEnumerateFiles(string dir)
    {
        try { return Directory.EnumerateFiles(dir); }
        catch (Exception) { return Enumerable.Empty<string>(); }
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string dir)
    {
        try { return Directory.EnumerateDirectories(dir); }
        catch (Exception) { return Enumerable.Empty<string>(); }
    }
}
