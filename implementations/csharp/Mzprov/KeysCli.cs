using System;
using System.IO;

namespace Mzprov;

// `mzprov keys generate [--key-dir DIR]` — create an Ed25519 keypair and
// write signing_key.pem (PKCS#8), verifying_key.pem (SPKI), and key_id,
// in a format interoperable with the Python reference's key files.
internal static class KeysCli
{
    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] != "generate")
        {
            Console.Error.WriteLine("usage: mzprov keys generate [--key-dir DIR]");
            return ExitCodes.Generic;
        }

        string? keyDir = null;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--key-dir" && i + 1 < args.Length)
            {
                keyDir = args[++i];
            }
            else
            {
                Console.Error.WriteLine($"mzprov keys generate: unexpected argument {args[i]}");
                return ExitCodes.Generic;
            }
        }
        keyDir ??= DefaultKeyDir();

        try
        {
            var pair = Keys.GenerateKeyPair();
            Keys.WriteKeyPair(pair, keyDir);
            Console.WriteLine($"generated key {pair.KeyId} in {keyDir}");
            return ExitCodes.Ok;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"mzprov keys generate: {e.Message}");
            return ExitCodes.Generic;
        }
    }

    private static string DefaultKeyDir()
    {
        string baseDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(baseDir, "mzprov", "keys");
    }
}
