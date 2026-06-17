using System;

namespace Mzprov;

// Entry point + subcommand dispatch for the C# implementation.
//
//   mzprov verify <path>                 -> exit code 0..7 (the cross-impl contract)
//   mzprov canonicalize {mzml|d|raw} <p> -> prints "sha256:<hex>" on stdout, exit 0
//
// The two subcommands are exactly what test-vectors/_harness/run_conformance.py
// drives (via --verify-cmd / --canonicalize-cmd). See the csharp job in
// .github/workflows/conformance.yml.
internal static class Program
{
    private const string Usage =
        "usage: mzprov <subcommand> [args...]\n\n" +
        "subcommands:\n" +
        "  sign <path> ...               sign a .d dir, .mzML, or .raw with an Ed25519 attestation\n" +
        "  verify <path>                 verify a sidecar (.d dir, .mzML, .raw, or sidecar JSON)\n" +
        "  keys generate ...             generate an Ed25519 signing keypair\n" +
        "  canonicalize {mzml|d|raw} <p> print the canonical hash of an artifact as sha256:<hex>\n";

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.Write(Usage);
            return 2;
        }

        string sub = args[0];
        string[] rest = new string[args.Length - 1];
        Array.Copy(args, 1, rest, 0, rest.Length);

        switch (sub)
        {
            case "-h":
            case "--help":
            case "help":
                Console.Out.Write(Usage);
                return 0;
            case "sign":
                return SignCli.Run(rest);
            case "verify":
                return VerifyCli.Run(rest);
            case "keys":
                return KeysCli.Run(rest);
            case "canonicalize":
                return CanonicalizeCli.Run(rest);
            default:
                Console.Error.Write($"mzprov: unknown subcommand: {sub}\n\n");
                Console.Error.Write(Usage);
                return 2;
        }
    }
}
