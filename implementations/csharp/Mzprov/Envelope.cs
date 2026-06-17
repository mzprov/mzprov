using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Mzprov;

internal enum PayloadKind { D, Mzml, Raw }

// The sidecar envelope: type tag + payload + signature + verifying key.
// The bytes that get signed are the canonical JSON of the payload's
// required fields (sorted keys, no whitespace, UTF-8, non-ASCII preserved),
// reproducing the reference Payload.to_canonical_json exactly.
internal sealed class Sidecar
{
    public const string TypeD = "timsim.provenance.v0";
    public const string TypeMzml = "timsim.provenance.mzml.v0";
    public const string TypeRaw = "timsim.provenance.raw.v0";

    private static readonly string[] RequiredD =
    {
        "simulator_name", "simulator_version", "experiment_name", "config_hash",
        "d_content_hash", "ground_truth_hash", "content_hash", "timestamp_utc",
        "key_id", "canonicalization_version",
    };

    private static readonly string[] RequiredMzml =
    {
        "tool_name", "tool_version", "experiment_name", "config_hash",
        "mzml_content_hash", "content_hash", "timestamp_utc", "key_id",
        "canonicalization_version",
    };

    private static readonly string[] RequiredRaw =
    {
        "tool_name", "tool_version", "experiment_name", "config_hash",
        "raw_content_hash", "content_hash", "timestamp_utc", "key_id",
        "canonicalization_version",
    };

    public PayloadKind Kind { get; }
    public string Type { get; }
    public string Signature { get; }
    public string VerifyingKey { get; }

    // Exactly the required payload fields, in JSON-string form.
    private readonly IReadOnlyDictionary<string, string> _payload;

    private Sidecar(PayloadKind kind, string type, IReadOnlyDictionary<string, string> payload,
        string signature, string verifyingKey)
    {
        Kind = kind;
        Type = type;
        _payload = payload;
        Signature = signature;
        VerifyingKey = verifyingKey;
    }

    public string Field(string name) => _payload[name];

    public string ContentHashField => Kind switch
    {
        PayloadKind.D => _payload["d_content_hash"],
        PayloadKind.Mzml => _payload["mzml_content_hash"],
        PayloadKind.Raw => _payload["raw_content_hash"],
        _ => throw new InvalidOperationException(),
    };

    // Canonical JSON of the payload — the bytes that were signed.
    public byte[] CanonicalPayloadJson()
    {
        var keys = new List<string>(_payload.Keys);
        keys.Sort(StringComparer.Ordinal);
        var sb = new StringBuilder();
        sb.Append('{');
        for (int i = 0; i < keys.Count; i++)
        {
            if (i > 0) sb.Append(',');
            AppendJsonString(sb, keys[i]);
            sb.Append(':');
            AppendJsonString(sb, _payload[keys[i]]);
        }
        sb.Append('}');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // JSON string escaping matching Python json.dumps(ensure_ascii=False):
    // escape " \ and control chars; keep all other (incl. non-ASCII) as-is.
    private static void AppendJsonString(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (char c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u");
                        sb.Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    // Parse and dispatch by the envelope's `type` tag.
    public static Sidecar Parse(byte[] data)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(data);
        }
        catch (JsonException e)
        {
            throw new MalformedSidecarException($"sidecar is not valid UTF-8 JSON: {e.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new MalformedSidecarException("sidecar root must be a JSON object");
            }

            string? type = root.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String
                ? typeEl.GetString()
                : null;

            (PayloadKind kind, string[] required) = type switch
            {
                TypeD => (PayloadKind.D, RequiredD),
                TypeMzml => (PayloadKind.Mzml, RequiredMzml),
                TypeRaw => (PayloadKind.Raw, RequiredRaw),
                _ => throw new UnknownVersionException(
                    $"sidecar type '{type ?? "<null>"}' is not supported"),
            };

            if (!root.TryGetProperty("payload", out var payloadEl) ||
                payloadEl.ValueKind != JsonValueKind.Object)
            {
                throw new MalformedSidecarException("sidecar.payload must be an object");
            }

            var payload = new Dictionary<string, string>(StringComparer.Ordinal);
            var missing = new List<string>();
            foreach (string key in required)
            {
                if (payloadEl.TryGetProperty(key, out var v))
                {
                    payload[key] = JsonValueToString(v);
                }
                else
                {
                    missing.Add(key);
                }
            }
            if (missing.Count > 0)
            {
                missing.Sort(StringComparer.Ordinal);
                throw new MalformedSidecarException(
                    $"sidecar payload is missing required fields: [{string.Join(", ", missing)}]");
            }

            if (payload["canonicalization_version"] != "v0")
            {
                throw new UnknownVersionException(
                    $"sidecar canonicalization_version '{payload["canonicalization_version"]}' is not supported");
            }

            string? signature = root.TryGetProperty("signature", out var sigEl) && sigEl.ValueKind == JsonValueKind.String
                ? sigEl.GetString()
                : null;
            string? verifyingKey = root.TryGetProperty("verifying_key", out var vkEl) && vkEl.ValueKind == JsonValueKind.String
                ? vkEl.GetString()
                : null;
            if (signature is null || verifyingKey is null)
            {
                throw new MalformedSidecarException(
                    "sidecar.signature and sidecar.verifying_key must be strings");
            }

            return new Sidecar(kind, type!, payload, signature, verifyingKey);
        }
    }

    // The required payload fields are JSON strings in every valid sidecar.
    // Reproduce the value as the signer wrote it; a non-string required
    // field is a malformed payload.
    private static string JsonValueToString(JsonElement v)
    {
        if (v.ValueKind != JsonValueKind.String)
        {
            throw new MalformedSidecarException(
                $"sidecar payload field has non-string value (kind={v.ValueKind})");
        }
        return v.GetString()!;
    }
}
