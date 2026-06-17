using System;
using System.Collections.Generic;
using System.IO;

namespace Mzprov;

// `mzprov sign <path> ...` — signs a .d directory, an mzML file, or a .raw
// file with an Ed25519 attestation. Mirrors mzprov.sign_cli (and adds .raw,
// which the reference exposes as a library function). Exit codes:
//   0 ok | 1 generic/bad-args | 2 key error | 3 sidecar/artifact error
internal static class SignCli
{
    public static int Run(string[] args)
    {
        string? path = null;
        string? experiment = null, config = null, groundTruth = null;
        string toolName = "mzprov", toolVersion = "unknown";
        string? keyArg = null, sidecar = null;
        bool embed = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "--experiment-name": experiment = Next(args, ref i, a); break;
                case "--config": config = Next(args, ref i, a); break;
                case "--ground-truth": groundTruth = Next(args, ref i, a); break;
                case "--tool-name": toolName = Next(args, ref i, a); break;
                case "--tool-version": toolVersion = Next(args, ref i, a); break;
                case "--key":
                case "--private-key": keyArg = Next(args, ref i, a); break;
                case "--sidecar": sidecar = Next(args, ref i, a); break;
                case "--embed": embed = true; break;
                default:
                    if (a.StartsWith("-", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine($"mzprov sign: unknown option {a}");
                        return ExitCodes.Generic;
                    }
                    if (path != null)
                    {
                        Console.Error.WriteLine("mzprov sign: more than one input path given");
                        return ExitCodes.Generic;
                    }
                    path = a;
                    break;
            }
        }

        if (path is null) { Console.Error.WriteLine("usage: mzprov sign <path> --experiment-name NAME [...]"); return ExitCodes.Generic; }
        if (experiment is null) { Console.Error.WriteLine("mzprov sign: --experiment-name is required"); return ExitCodes.Generic; }
        if (embed && sidecar != null) { Console.Error.WriteLine("mzprov sign: --embed and --sidecar are mutually exclusive"); return ExitCodes.Generic; }

        string fmt = DetectFormat(path);
        if (fmt == "")
        {
            Console.Error.WriteLine($"mzprov sign: {path} is not a .d directory, an mzML file, or a .raw file");
            return ExitCodes.SidecarError;
        }
        if (embed && fmt == "raw") { Console.Error.WriteLine("mzprov sign: --embed is not supported for .raw (sidecar-only)"); return ExitCodes.Generic; }
        if (fmt == "d" && config is null) { Console.Error.WriteLine("mzprov sign: --config is required when signing a .d directory"); return ExitCodes.Generic; }

        SigningKeyPair key;
        try
        {
            key = keyArg != null ? Keys.ResolveKeyPair(keyArg) : Keys.LoadOrCreate(DefaultKeyDir());
        }
        catch (Exception e) when (e is KeyNotFoundException or MalformedKeyException)
        {
            Console.Error.WriteLine($"mzprov sign: key error: {e.Message}");
            return ExitCodes.KeyError;
        }

        try
        {
            string result = fmt switch
            {
                "d" => Sign.SignD(path, groundTruth, config!, experiment, toolName, toolVersion, sidecar, key, embed),
                "mzml" => Sign.SignMzml(path, config, experiment, toolName, toolVersion, sidecar, key, embed),
                _ => Sign.SignRaw(path, config, experiment, toolName, toolVersion, sidecar, key),
            };
            Console.WriteLine($"signed: {result}");
            return ExitCodes.Ok;
        }
        catch (Exception e) when (e is KeyNotFoundException or MalformedKeyException)
        {
            Console.Error.WriteLine($"mzprov sign: key error: {e.Message}");
            return ExitCodes.KeyError;
        }
        catch (Exception e) when (e is MissingArtifactException or SqliteNotQuiescentException
            or MalformedSidecarException or FileNotFoundException or ProvenanceException)
        {
            Console.Error.WriteLine($"mzprov sign: {e.Message}");
            return ExitCodes.SidecarError;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"mzprov sign: unexpected error: {e.GetType().Name}: {e.Message}");
            return ExitCodes.Generic;
        }
    }

    private static string DetectFormat(string path)
    {
        if (Directory.Exists(path) && Paths.BaseName(path).EndsWith(".d", StringComparison.Ordinal)) return "d";
        if (File.Exists(path) && Paths.BaseName(path).EndsWith(".mzml", StringComparison.OrdinalIgnoreCase)) return "mzml";
        if (File.Exists(path) && Paths.BaseName(path).EndsWith(".raw", StringComparison.OrdinalIgnoreCase)) return "raw";
        return "";
    }

    // Matches the reference default (~/.config/timsim/keys) so that signing
    // without --key uses the SAME local identity across both implementations.
    private static string DefaultKeyDir() => DefaultKeyDirShared();

    internal static string DefaultKeyDirShared()
    {
        string baseDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(baseDir, "timsim", "keys");
    }

    private static string Next(string[] args, ref int i, string opt)
    {
        if (i + 1 >= args.Length) throw new ArgumentException($"option {opt} requires a value");
        return args[++i];
    }
}
