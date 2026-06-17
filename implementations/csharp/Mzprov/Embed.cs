using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Data.Sqlite;

namespace Mzprov;

// Readers for the two in-band embedded transports:
//   - .d:   the `mzprov_provenance` SQLite table inside analysis.tdf
//   - mzML: the `mzprov:provenance` userParam in fileDescription/fileContent
// Each exposes a cheap Has* probe (used by discovery) and a Read* that
// returns the envelope bytes. Mirrors mzprov.embed_d / mzprov.embed_mzml.
internal static class Embed
{
    private const string EmbeddedProvenanceTable = "mzprov_provenance";
    private static readonly string[] SqliteSidecarSuffixes = { "-journal", "-wal", "-shm" };

    private static readonly XNamespace Ns = "http://psi.hupo.org/ms/mzml";
    private const string EmbeddedUserParamName = "mzprov:provenance";

    // ----- .d (SQLite) -----

    public static bool HasEmbeddedD(string dPath)
    {
        string tdf = TdfPath(dPath);
        AssertQuiescent(tdf);
        using var conn = OpenReadOnly(tdf);
        if (!TableExists(conn, EmbeddedProvenanceTable))
        {
            return false;
        }
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT 1 FROM \"{EmbeddedProvenanceTable}\" LIMIT 1;";
        using var reader = cmd.ExecuteReader();
        return reader.Read();
    }

    public static byte[]? ReadEmbeddedD(string dPath)
    {
        string tdf = TdfPath(dPath);
        AssertQuiescent(tdf);
        using var conn = OpenReadOnly(tdf);
        if (!TableExists(conn, EmbeddedProvenanceTable))
        {
            return null;
        }
        var rows = new List<string>();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = $"SELECT sidecar_json FROM \"{EmbeddedProvenanceTable}\";";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                if (reader.IsDBNull(0))
                {
                    throw new MalformedSidecarException(
                        $"{EmbeddedProvenanceTable}.sidecar_json is not TEXT");
                }
                rows.Add(reader.GetString(0));
            }
        }
        if (rows.Count == 0)
        {
            return null;
        }
        if (rows.Count > 1)
        {
            throw new MalformedSidecarException(
                $"{EmbeddedProvenanceTable} contains {rows.Count} rows; v0 mandates at most one");
        }
        return System.Text.Encoding.UTF8.GetBytes(rows[0]);
    }

    private static string TdfPath(string dPath)
    {
        if (!Directory.Exists(dPath))
        {
            throw new MissingArtifactException($".d directory does not exist: {dPath}");
        }
        string tdf = Path.Combine(dPath, "analysis.tdf");
        if (!File.Exists(tdf))
        {
            throw new MissingArtifactException($"missing analysis.tdf in {dPath}");
        }
        return tdf;
    }

    private static SqliteConnection OpenReadOnly(string dbPath)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadOnly,
        };
        var conn = new SqliteConnection(builder.ToString());
        conn.Open();
        return conn;
    }

    private static bool TableExists(SqliteConnection conn, string table)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = $n;";
        cmd.Parameters.AddWithValue("$n", table);
        using var reader = cmd.ExecuteReader();
        return reader.Read();
    }

    private static void AssertQuiescent(string dbPath)
    {
        var found = new List<string>();
        foreach (string suffix in SqliteSidecarSuffixes)
        {
            if (File.Exists(dbPath + suffix))
            {
                found.Add(Path.GetFileName(dbPath + suffix));
            }
        }
        if (found.Count > 0)
        {
            throw new SqliteNotQuiescentException(
                $"refusing to read {dbPath}: SQLite sidecar files present ({string.Join(", ", found)}).");
        }
    }

    // ----- mzML (userParam) -----

    public static bool HasEmbeddedMzml(string mzmlPath)
    {
        var fileContent = FileContent(ReadInner(mzmlPath));
        if (fileContent is null)
        {
            return false;
        }
        foreach (var up in fileContent.Elements(Ns + "userParam"))
        {
            if (up.Attribute("name")?.Value == EmbeddedUserParamName)
            {
                return true;
            }
        }
        return false;
    }

    public static byte[]? ReadEmbeddedMzml(string mzmlPath)
    {
        var fileContent = FileContent(ReadInner(mzmlPath));
        if (fileContent is null)
        {
            return null;
        }
        var found = new List<string>();
        foreach (var up in fileContent.Elements(Ns + "userParam"))
        {
            if (up.Attribute("name")?.Value == EmbeddedUserParamName)
            {
                found.Add(up.Attribute("value")?.Value ?? "");
            }
        }
        if (found.Count == 0)
        {
            return null;
        }
        if (found.Count > 1)
        {
            throw new MalformedSidecarException(
                $"mzml fileContent contains {found.Count} userParams with name='{EmbeddedUserParamName}'; v0 mandates at most one");
        }
        try
        {
            return Convert.FromBase64String(found[0]);
        }
        catch (FormatException e)
        {
            throw new MalformedSidecarException(
                $"mzprov:provenance userParam value is not valid base64: {e.Message}");
        }
    }

    private static XElement ReadInner(string mzmlPath)
    {
        if (!File.Exists(mzmlPath))
        {
            throw new MissingArtifactException($"mzml file does not exist: {mzmlPath}");
        }
        XDocument doc;
        try
        {
            using var reader = XmlReader.Create(mzmlPath, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
            doc = XDocument.Load(reader);
        }
        catch (XmlException e)
        {
            throw new MalformedSidecarException($"mzml is not parseable as XML: {e.Message}");
        }
        var root = doc.Root!;
        if (root.Name == Ns + "mzML")
        {
            return root;
        }
        if (root.Name == Ns + "indexedmzML")
        {
            var inner = root.Element(Ns + "mzML");
            if (inner is null)
            {
                throw new MalformedSidecarException("indexedmzML wrapper has no inner <mzML> element");
            }
            return inner;
        }
        throw new MalformedSidecarException($"expected <mzML> or <indexedmzML> root, got {root.Name.LocalName}");
    }

    private static XElement? FileContent(XElement innerMzml)
    {
        var fileDesc = innerMzml.Element(Ns + "fileDescription");
        return fileDesc?.Element(Ns + "fileContent");
    }
}
