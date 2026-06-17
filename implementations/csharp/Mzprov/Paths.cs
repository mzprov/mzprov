using System;
using System.IO;

namespace Mzprov;

// Config-copy path conventions shared between signing and verification.
// Both sides MUST derive the config path from the on-disk artifact/sidecar
// location alone (never from a payload field). Mirrors mzprov.paths.
internal static class Paths
{
    public static string SidecarConfigPath(string sidecarPath)
    {
        string name = BaseName(sidecarPath);
        string stem = name.EndsWith(".provenance.json", StringComparison.Ordinal)
            ? name.Substring(0, name.Length - ".provenance.json".Length)
            : Path.GetFileNameWithoutExtension(name);
        return Path.Combine(DirName(sidecarPath), stem + ".config.toml");
    }

    public static string EmbeddedDConfigPath(string dPath)
    {
        string name = BaseName(dPath);
        string stem = name.EndsWith(".d", StringComparison.Ordinal) ? name.Substring(0, name.Length - 2) : name;
        return Path.Combine(DirName(dPath), stem + ".config.toml");
    }

    public static string EmbeddedMzmlConfigPath(string mzmlPath) =>
        Path.Combine(DirName(mzmlPath), Path.GetFileNameWithoutExtension(BaseName(mzmlPath)) + ".config.toml");

    public static string BaseName(string path) =>
        Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    public static string DirName(string path) =>
        Path.GetDirectoryName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) ?? ".";
}
