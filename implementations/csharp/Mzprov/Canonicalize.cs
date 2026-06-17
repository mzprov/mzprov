using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Mzprov;

// Canonical content hashing for Thermo .raw (opaque whole-file) and
// Bruker .d (analysis.tdf_bin streaming hash composed with the canonical
// SQL dump of analysis.tdf). Byte-for-byte compatible with
// spec/canonicalization-{raw,d}-v0.md and the Python reference.
internal static class Canonicalize
{
    private static readonly byte[] US = { 0x1F }; // Unit Separator
    private static readonly byte[] RS = { 0x1E }; // Record Separator

    private const string EmbeddedProvenanceTable = "mzprov_provenance";
    private static readonly string[] SqliteSidecarSuffixes = { "-journal", "-wal", "-shm" };

    // A single canonical NaN bit pattern (big-endian 0x7ff8000000000000).
    private static readonly byte[] CanonicalNanBytes =
        { 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    private static readonly byte[] RawCanonicalPrefix =
        Encoding.ASCII.GetBytes("TIMSIM-RAW-CANONICAL-v0\x1f");
    private static readonly byte[] RawContentDomain =
        Encoding.ASCII.GetBytes("timsim.raw.v0\x1f");
    private static readonly byte[] DContentDomain =
        Encoding.ASCII.GetBytes("timsim.v0\x1f");

    // ----- .raw -----

    public static byte[] CanonicalizeRaw(string rawPath)
    {
        if (!File.Exists(rawPath))
        {
            throw new FileNotFoundException($"raw file not found: {rawPath}");
        }
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(rawPath);
        var prefixBlock = new byte[RawCanonicalPrefix.Length];
        Array.Copy(RawCanonicalPrefix, prefixBlock, RawCanonicalPrefix.Length);
        sha.TransformBlock(prefixBlock, 0, prefixBlock.Length, null, 0);
        var buffer = new byte[1 << 20];
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.TransformBlock(buffer, 0, read, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    public static byte[] ComposeRawContentHash(byte[] rawHash, byte[] configHash)
    {
        Require32(rawHash, nameof(rawHash));
        Require32(configHash, nameof(configHash));
        using var ms = new MemoryStream();
        ms.Write(RawContentDomain, 0, RawContentDomain.Length);
        ms.Write(rawHash, 0, rawHash.Length);
        ms.Write(US, 0, US.Length);
        ms.Write(configHash, 0, configHash.Length);
        return SHA256.HashData(ms.ToArray());
    }

    // ----- .d -----

    public static byte[] CanonicalizeD(string dPath)
    {
        if (!Directory.Exists(dPath))
        {
            throw new FileNotFoundException($".d path is not a directory: {dPath}");
        }
        string tdf = Path.Combine(dPath, "analysis.tdf");
        string tdfBin = Path.Combine(dPath, "analysis.tdf_bin");
        if (!File.Exists(tdf))
        {
            throw new FileNotFoundException($"missing analysis.tdf in {dPath}");
        }
        if (!File.Exists(tdfBin))
        {
            throw new FileNotFoundException($"missing analysis.tdf_bin in {dPath}");
        }
        byte[] binHash = HashFileStreaming(tdfBin);
        byte[] tdfHash = CanonicalizeSqlite(tdf);
        var combined = new byte[binHash.Length + tdfHash.Length];
        Array.Copy(binHash, 0, combined, 0, binHash.Length);
        Array.Copy(tdfHash, 0, combined, binHash.Length, tdfHash.Length);
        return SHA256.HashData(combined);
    }

    public static byte[] ComposeContentHash(byte[] dHash, byte[]? groundTruthHash, byte[] configHash)
    {
        Require32(dHash, nameof(dHash));
        Require32(configHash, nameof(configHash));
        byte[] gtMarker;
        if (groundTruthHash is null)
        {
            gtMarker = Encoding.ASCII.GetBytes("none");
        }
        else
        {
            Require32(groundTruthHash, nameof(groundTruthHash));
            gtMarker = groundTruthHash;
        }
        using var ms = new MemoryStream();
        ms.Write(DContentDomain, 0, DContentDomain.Length);
        ms.Write(dHash, 0, dHash.Length);
        ms.Write(US, 0, US.Length);
        ms.Write(gtMarker, 0, gtMarker.Length);
        ms.Write(US, 0, US.Length);
        ms.Write(configHash, 0, configHash.Length);
        return SHA256.HashData(ms.ToArray());
    }

    public static byte[] CanonicalizeBytes(byte[] data) => SHA256.HashData(data);

    // ----- SQLite canonical dump -----

    public static byte[] CanonicalizeSqlite(string dbPath)
    {
        AssertSqliteQuiescent(dbPath);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        // immutable=1 + read-only, matching the reference: never mutate the
        // file we are hashing, and skip locking / WAL.
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadOnly,
        };
        using var conn = new SqliteConnection(builder.ToString());
        conn.Open();

        foreach (string table in ListUserTables(conn))
        {
            var cols = TableColumns(conn, table);
            sha.AppendData(Concat(US, Ascii("table"), US, Utf8(table), US));
            foreach (var (colName, colType) in cols)
            {
                sha.AppendData(Concat(US, Ascii("col"), US, Utf8(colName), US, Utf8(colType), US));
            }
            if (cols.Count == 0)
            {
                continue;
            }

            var orderBy = new StringBuilder();
            for (int i = 0; i < cols.Count; i++)
            {
                if (i > 0) orderBy.Append(", ");
                orderBy.Append(QuoteIdent(cols[i].Name));
            }

            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT * FROM {QuoteIdent(table)} ORDER BY {orderBy};";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var row = new List<byte[]> { Concat(US, Ascii("row")) };
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    row.Add(Concat(US, CanonicalizeValue(reader.GetValue(i))));
                }
                row.Add(Concat(US, RS));
                sha.AppendData(Concat(row.ToArray()));
            }
        }
        return sha.GetHashAndReset();
    }

    // Render a single SQLite cell value to its canonical byte form.
    private static byte[] CanonicalizeValue(object value)
    {
        switch (value)
        {
            case null:
            case DBNull:
                return Concat(new byte[] { 0x00 }, Ascii("NULL"), new byte[] { 0x00 });
            case long l:
                return Ascii(l.ToString(CultureInfo.InvariantCulture));
            case int i:
                return Ascii(i.ToString(CultureInfo.InvariantCulture));
            case double d:
                {
                    byte[] be = double.IsNaN(d) ? CanonicalNanBytes : DoubleBigEndian(d);
                    return Ascii(ToHexLower(be));
                }
            case string s:
                {
                    byte[] norm = Encoding.UTF8.GetBytes(s.Normalize(NormalizationForm.FormC));
                    return Concat(new byte[] { 0x00 }, Ascii("len" + norm.Length.ToString(CultureInfo.InvariantCulture)),
                        new byte[] { 0x00 }, norm);
                }
            case byte[] b:
                return Concat(new byte[] { 0x00 }, Ascii("blob" + b.Length.ToString(CultureInfo.InvariantCulture)),
                    new byte[] { 0x00 }, Ascii(ToHexLower(b)));
            default:
                throw new InvalidOperationException(
                    $"canonicalize_value: unsupported type {value.GetType().Name}");
        }
    }

    private static List<string> ListUserTables(SqliteConnection conn)
    {
        var tables = new List<string>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT name FROM sqlite_master " +
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != $excl " +
            "ORDER BY name;";
        cmd.Parameters.AddWithValue("$excl", EmbeddedProvenanceTable);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            tables.Add(reader.GetString(0));
        }
        return tables;
    }

    private static List<(string Name, string Type)> TableColumns(SqliteConnection conn, string table)
    {
        // (cid, name, type, ...) — PRAGMA returns rows in cid order already.
        var cols = new List<(int Cid, string Name, string Type)>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({QuoteIdent(table)});";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            int cid = reader.GetInt32(0);
            string name = reader.GetString(1);
            string type = reader.IsDBNull(2) ? "" : reader.GetString(2);
            cols.Add((cid, name, type));
        }
        cols.Sort((a, b) => a.Cid.CompareTo(b.Cid));
        var result = new List<(string, string)>();
        foreach (var c in cols)
        {
            result.Add((c.Name, c.Type));
        }
        return result;
    }

    private static void AssertSqliteQuiescent(string dbPath)
    {
        var found = new List<string>();
        foreach (string suffix in SqliteSidecarSuffixes)
        {
            string candidate = dbPath + suffix;
            if (File.Exists(candidate))
            {
                found.Add(Path.GetFileName(candidate));
            }
        }
        if (found.Count > 0)
        {
            throw new SqliteNotQuiescentException(
                $"refusing to hash {dbPath}: SQLite sidecar files present " +
                $"({string.Join(", ", found)}).");
        }
    }

    private static byte[] HashFileStreaming(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return sha.ComputeHash(fs);
    }

    // ----- helpers -----

    private static string QuoteIdent(string ident) => "\"" + ident.Replace("\"", "\"\"") + "\"";

    private static byte[] DoubleBigEndian(double value)
    {
        byte[] le = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(le);
        }
        return le;
    }

    // Strict base64 decode matching Python base64.b64decode(validate=True):
    // .NET's Convert.FromBase64String silently ignores embedded whitespace,
    // so reject any whitespace first. Non-alphabet chars and bad padding are
    // rejected by Convert.FromBase64String itself (FormatException).
    public static byte[] DecodeBase64Strict(string text)
    {
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                throw new FormatException("base64 contains whitespace");
            }
        }
        return Convert.FromBase64String(text);
    }

    public static string ToHexLower(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (var p in parts) total += p.Length;
        var result = new byte[total];
        int offset = 0;
        foreach (var p in parts)
        {
            Array.Copy(p, 0, result, offset, p.Length);
            offset += p.Length;
        }
        return result;
    }

    private static void Require32(byte[] b, string name)
    {
        if (b is null || b.Length != 32)
        {
            throw new ArgumentException($"{name} must be 32 bytes");
        }
    }
}
