using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Mzprov;

// Hash + sign + write a provenance attestation for a .d, mzML, or .raw.
// Mirrors mzprov.sign. The bytes that get signed are the canonical JSON of
// the payload (Envelope.CanonicalJson); the on-disk/embedded envelope
// formatting is not part of the signature.
internal static class Sign
{
    public static string SignD(string dPath, string? groundTruthPath, string configPath,
        string experimentName, string toolName, string toolVersion,
        string? sidecarPathOverride, SigningKeyPair key, bool embed)
    {
        if (!Directory.Exists(dPath)) throw new MissingArtifactException($".d directory does not exist: {dPath}");
        if (!File.Exists(configPath)) throw new MissingArtifactException($"config file does not exist: {configPath}");
        if (groundTruthPath != null && !File.Exists(groundTruthPath))
            throw new MissingArtifactException($"ground-truth database does not exist: {groundTruthPath}");

        string sidecarPath;
        string configCopyPath;
        if (embed)
        {
            sidecarPath = dPath;
            configCopyPath = Paths.EmbeddedDConfigPath(dPath);
        }
        else
        {
            sidecarPath = sidecarPathOverride
                ?? Path.Combine(Paths.DirName(dPath), experimentName + ".provenance.json");
            configCopyPath = Paths.SidecarConfigPath(sidecarPath);
        }

        byte[] dHash = Canonicalize.CanonicalizeD(dPath);
        byte[] configBytes = File.ReadAllBytes(configPath);
        byte[] configHash = Canonicalize.CanonicalizeBytes(configBytes);
        byte[]? groundTruthHash = groundTruthPath != null
            ? Canonicalize.CanonicalizeSqlite(groundTruthPath)
            : null;

        WriteConfigCopy(configCopyPath, configBytes);

        byte[] contentHash = Canonicalize.ComposeContentHash(dHash, groundTruthHash, configHash);

        var payload = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["simulator_name"] = toolName,
            ["simulator_version"] = toolVersion,
            ["experiment_name"] = experimentName,
            ["config_hash"] = Hex(configHash),
            ["d_content_hash"] = Hex(dHash),
            ["ground_truth_hash"] = groundTruthHash != null ? Hex(groundTruthHash) : "",
            ["content_hash"] = Hex(contentHash),
            ["timestamp_utc"] = UtcNowIso(),
            ["key_id"] = key.KeyId,
            ["canonicalization_version"] = "v0",
        };

        byte[] envelope = BuildEnvelope(Sidecar.TypeD, payload, key);
        if (embed)
        {
            EmbedWrite.WriteEmbeddedD(dPath, envelope);
            return dPath;
        }
        WriteAtomic(sidecarPath, envelope);
        return sidecarPath;
    }

    public static string SignMzml(string mzmlPath, string? configPath, string experimentName,
        string toolName, string toolVersion, string? sidecarPathOverride, SigningKeyPair key, bool embed)
    {
        if (!File.Exists(mzmlPath)) throw new MissingArtifactException($"mzml file does not exist: {mzmlPath}");
        byte[] configBytes = ReadOptionalConfig(configPath);

        string sidecarPath;
        string configCopyPath;
        if (embed)
        {
            sidecarPath = mzmlPath;
            configCopyPath = Paths.EmbeddedMzmlConfigPath(mzmlPath);
        }
        else
        {
            sidecarPath = sidecarPathOverride
                ?? Path.Combine(Paths.DirName(mzmlPath),
                    Path.GetFileNameWithoutExtension(Paths.BaseName(mzmlPath)) + ".provenance.json");
            configCopyPath = Paths.SidecarConfigPath(sidecarPath);
        }

        byte[] mzmlHash = CanonicalizeMzml.Run(mzmlPath);
        byte[] configHash = Canonicalize.CanonicalizeBytes(configBytes);
        if (configPath != null) WriteConfigCopy(configCopyPath, configBytes);

        byte[] contentHash = CanonicalizeMzml.ComposeMzmlContentHash(mzmlHash, configHash);

        var payload = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tool_name"] = toolName,
            ["tool_version"] = toolVersion,
            ["experiment_name"] = experimentName,
            ["config_hash"] = Hex(configHash),
            ["mzml_content_hash"] = Hex(mzmlHash),
            ["content_hash"] = Hex(contentHash),
            ["timestamp_utc"] = UtcNowIso(),
            ["key_id"] = key.KeyId,
            ["canonicalization_version"] = "v0",
        };

        byte[] envelope = BuildEnvelope(Sidecar.TypeMzml, payload, key);
        if (embed)
        {
            EmbedWrite.WriteEmbeddedMzml(mzmlPath, envelope);
            return mzmlPath;
        }
        WriteAtomic(sidecarPath, envelope);
        return sidecarPath;
    }

    public static string SignRaw(string rawPath, string? configPath, string experimentName,
        string toolName, string toolVersion, string? sidecarPathOverride, SigningKeyPair key)
    {
        if (!File.Exists(rawPath)) throw new MissingArtifactException($"raw file does not exist: {rawPath}");
        byte[] configBytes = ReadOptionalConfig(configPath);

        string sidecarPath = sidecarPathOverride
            ?? Path.Combine(Paths.DirName(rawPath),
                Path.GetFileNameWithoutExtension(Paths.BaseName(rawPath)) + ".provenance.json");
        string configCopyPath = Paths.SidecarConfigPath(sidecarPath);

        byte[] rawHash = Canonicalize.CanonicalizeRaw(rawPath);
        byte[] configHash = Canonicalize.CanonicalizeBytes(configBytes);
        if (configPath != null) WriteConfigCopy(configCopyPath, configBytes);

        byte[] contentHash = Canonicalize.ComposeRawContentHash(rawHash, configHash);

        var payload = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tool_name"] = toolName,
            ["tool_version"] = toolVersion,
            ["experiment_name"] = experimentName,
            ["config_hash"] = Hex(configHash),
            ["raw_content_hash"] = Hex(rawHash),
            ["content_hash"] = Hex(contentHash),
            ["timestamp_utc"] = UtcNowIso(),
            ["key_id"] = key.KeyId,
            ["canonicalization_version"] = "v0",
        };

        byte[] envelope = BuildEnvelope(Sidecar.TypeRaw, payload, key);
        WriteAtomic(sidecarPath, envelope);
        return sidecarPath;
    }

    // ----- helpers -----

    private static byte[] BuildEnvelope(string type, IReadOnlyDictionary<string, string> payload, SigningKeyPair key)
    {
        byte[] signed = Sidecar.CanonicalJson(payload);
        byte[] signature = Keys.Sign(key.Private, signed);
        return Sidecar.WriteSidecarJson(type, payload,
            Keys.SignatureToB64(signature), Keys.PublicKeyToB64(key.PublicRaw));
    }

    private static byte[] ReadOptionalConfig(string? configPath)
    {
        if (configPath is null) return Array.Empty<byte>();
        if (!File.Exists(configPath)) throw new MissingArtifactException($"config file does not exist: {configPath}");
        return File.ReadAllBytes(configPath);
    }

    private static void WriteConfigCopy(string configCopyPath, byte[] configBytes)
    {
        Directory.CreateDirectory(Paths.DirName(configCopyPath));
        File.WriteAllBytes(configCopyPath, configBytes);
    }

    private static void WriteAtomic(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Paths.DirName(path));
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }

    private static string Hex(byte[] b) => "sha256:" + Canonicalize.ToHexLower(b);

    private static string UtcNowIso() =>
        DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture) + "Z";
}
