using System;
using System.Linq;

namespace Mzprov;

// `mzprov verify <path>` — discovers provenance, verifies, and maps the
// outcome to the frozen 0..7 exit codes. Mirrors mzprov.cli.main. Trust
// pinning flags are out of scope for the conformance build.
internal static class VerifyCli
{
    public static int Run(string[] args)
    {
        // Accept the first non-flag argument as the target path.
        string? path = args.FirstOrDefault(a => !a.StartsWith("-", StringComparison.Ordinal));
        if (path is null)
        {
            Console.Error.WriteLine("usage: mzprov verify <path>");
            return 2;
        }

        Discovery? discovery;
        try
        {
            discovery = Verify.FindProvenanceFor(path);
        }
        catch (SqliteNotQuiescentException e)
        {
            Console.Error.WriteLine($"mzprov verify: artifact error: {e.Message}");
            return ExitCodes.SidecarError;
        }
        catch (Exception e) when (e is MalformedSidecarException or MissingArtifactException)
        {
            Console.Error.WriteLine($"mzprov verify: discovery error: {e.Message}");
            return ExitCodes.SidecarError;
        }

        if (discovery is null)
        {
            // Non-strict: unsigned input is informational, not a failure.
            Console.WriteLine($"mzprov verify: no provenance found near {path}. This file or directory is unsigned.");
            Console.WriteLine("UNSIGNED");
            return ExitCodes.Ok;
        }

        VerificationResult result;
        try
        {
            result = discovery.Value.Transport switch
            {
                Transport.EmbeddedD => Verify.VerifyEmbeddedD(discovery.Value.Path),
                Transport.EmbeddedMzml => Verify.VerifyEmbeddedMzml(discovery.Value.Path),
                _ => Verify.VerifySidecarJson(discovery.Value.Path),
            };
        }
        catch (Exception e) when (e is KeyNotFoundException or MalformedKeyException)
        {
            Console.Error.WriteLine($"mzprov verify: key error: {e.Message}");
            return ExitCodes.KeyError;
        }
        catch (SqliteNotQuiescentException e)
        {
            Console.Error.WriteLine($"mzprov verify: artifact error: {e.Message}");
            return ExitCodes.SidecarError;
        }
        catch (Exception e) when (e is MalformedSidecarException or UnknownVersionException or MissingArtifactException)
        {
            Console.Error.WriteLine($"mzprov verify: sidecar error: {e.Message}");
            return ExitCodes.SidecarError;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"mzprov verify: unexpected error: {e.GetType().Name}: {e.Message}");
            return ExitCodes.Generic;
        }

        if (result.OverallOk)
        {
            Console.WriteLine("VERIFIED");
            return ExitCodes.Ok;
        }

        Console.WriteLine("FAILED");
        return ExitForFailure(result);
    }

    // Most-specific exit code for a failed verification (matches _exit_for_failure):
    // signature mismatch (6) > hash mismatch / unchecked (5) > generic (1).
    private static int ExitForFailure(VerificationResult result)
    {
        if (!result.SignatureOk) return ExitCodes.SignatureMismatch;
        if (result.Checks.Any(c => c == CheckStatus.Mismatch)) return ExitCodes.HashMismatch;
        if (result.Checks.Any(c => c == CheckStatus.Unchecked)) return ExitCodes.HashMismatch;
        return ExitCodes.Generic;
    }
}
