using System;

namespace Mzprov;

// `mzprov canonicalize {mzml|d|raw} <path>` — the canonicalize-driver the
// conformance harness invokes. Prints "sha256:<hex>" on stdout and exits 0
// on success; prints an error to stderr and exits non-zero otherwise.
internal static class CanonicalizeCli
{
    public static int Run(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("usage: mzprov canonicalize {mzml|d|raw} <input-path>");
            return 2;
        }

        string fmt = args[0];
        string path = args[1];
        try
        {
            byte[] digest = fmt switch
            {
                "mzml" => CanonicalizeMzml.Run(path),
                "d" => Canonicalize.CanonicalizeD(path),
                "raw" => Canonicalize.CanonicalizeRaw(path),
                _ => throw new ArgumentException($"unknown format: {fmt} (expected one of: d, mzml, raw)"),
            };
            Console.Out.WriteLine("sha256:" + Canonicalize.ToHexLower(digest));
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"mzprov canonicalize: {e.Message}");
            return 1;
        }
    }
}
