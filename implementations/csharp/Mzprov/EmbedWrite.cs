using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Data.Sqlite;

namespace Mzprov;

// Writers for the two in-band embedded transports, mirroring
// mzprov.embed_d / mzprov.embed_mzml. The .d table and the mzML userParam
// both live in regions the canonicalizer excludes, so embedding after
// hashing leaves the canonical hash unchanged.
internal static class EmbedWrite
{
    private const string EmbeddedProvenanceTable = "mzprov_provenance";
    private static readonly string[] SqliteSidecarSuffixes = { "-journal", "-wal", "-shm" };

    private static readonly XNamespace Ns = "http://psi.hupo.org/ms/mzml";
    private const string EmbeddedUserParamName = "mzprov:provenance";

    // ----- .d (SQLite mzprov_provenance row) -----

    public static void WriteEmbeddedD(string dPath, byte[] sidecarBytes)
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
        AssertQuiescent(tdf);

        string sidecarText = Encoding.UTF8.GetString(sidecarBytes);

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = tdf,
            Mode = SqliteOpenMode.ReadWrite,
        };
        using (var conn = new SqliteConnection(builder.ToString()))
        {
            conn.Open();

            // journal_mode=DELETE avoids leaving -wal/-shm behind, which the
            // verifier's quiescence guard would reject.
            using (var pragma = conn.CreateCommand())
            {
                pragma.CommandText = "PRAGMA journal_mode=DELETE;";
                var mode = pragma.ExecuteScalar() as string;
                if (mode is null || !mode.Equals("delete", StringComparison.OrdinalIgnoreCase))
                {
                    throw new SqliteNotQuiescentException(
                        $"could not set journal_mode=DELETE on {tdf} (got '{mode}')");
                }
            }

            using var tx = conn.BeginTransaction();
            using (var create = conn.CreateCommand())
            {
                create.Transaction = tx;
                create.CommandText =
                    $"CREATE TABLE IF NOT EXISTS \"{EmbeddedProvenanceTable}\" (sidecar_json TEXT NOT NULL);";
                create.ExecuteNonQuery();
            }
            using (var del = conn.CreateCommand())
            {
                del.Transaction = tx;
                del.CommandText = $"DELETE FROM \"{EmbeddedProvenanceTable}\";";
                del.ExecuteNonQuery();
            }
            using (var ins = conn.CreateCommand())
            {
                ins.Transaction = tx;
                ins.CommandText =
                    $"INSERT INTO \"{EmbeddedProvenanceTable}\" (sidecar_json) VALUES ($j);";
                ins.Parameters.AddWithValue("$j", sidecarText);
                ins.ExecuteNonQuery();
            }
            tx.Commit();
        }
        SqliteConnection.ClearAllPools(); // release the file handle before the quiescence re-check
        AssertQuiescent(tdf);
    }

    // ----- mzML (mzprov:provenance userParam) -----

    public static void WriteEmbeddedMzml(string mzmlPath, byte[] sidecarBytes)
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
        XElement inner;
        if (root.Name == Ns + "mzML")
        {
            inner = root;
        }
        else if (root.Name == Ns + "indexedmzML")
        {
            inner = root.Element(Ns + "mzML")
                ?? throw new MalformedSidecarException("indexedmzML wrapper has no inner <mzML> element");
        }
        else
        {
            throw new MalformedSidecarException($"expected <mzML> or <indexedmzML> root, got {root.Name.LocalName}");
        }

        var fileDesc = inner.Element(Ns + "fileDescription")
            ?? throw new MalformedSidecarException("mzml has no <fileDescription> element; cannot embed");
        var fileContent = fileDesc.Element(Ns + "fileContent");
        if (fileContent is null)
        {
            fileContent = new XElement(Ns + "fileContent");
            fileDesc.AddFirst(fileContent);
        }

        // Single-row equivalent: drop any existing mzprov:provenance userParam.
        foreach (var up in new List<XElement>(fileContent.Elements(Ns + "userParam")))
        {
            if (up.Attribute("name")?.Value == EmbeddedUserParamName)
            {
                up.Remove();
            }
        }

        string encoded = Convert.ToBase64String(sidecarBytes);
        fileContent.Add(new XElement(Ns + "userParam",
            new XAttribute("name", EmbeddedUserParamName),
            new XAttribute("type", "xsd:string"),
            new XAttribute("value", encoded)));

        // Output the inner <mzML> (drop the indexedmzML wrapper per spec §4);
        // the clone has no parent so it can be a document root.
        var outDoc = new XDocument(new XDeclaration("1.0", "utf-8", null), new XElement(inner));

        string tmp = mzmlPath + ".tmp";
        var settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false };
        using (var writer = XmlWriter.Create(tmp, settings))
        {
            outDoc.Save(writer);
        }
        File.Move(tmp, mzmlPath, overwrite: true);
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
                $"refusing to embed into {dbPath}: SQLite sidecar files present ({string.Join(", ", found)}).");
        }
    }
}
