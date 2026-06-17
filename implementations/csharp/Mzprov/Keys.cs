using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Mzprov;

// Ed25519 key handling + stable key-id derivation.
//
// key_id = "timsim-local-" + base32(blake2b(raw_pubkey, digest=10 bytes)).rstrip('=').lower()
// (see spec/key-id-derivation.md). The verifying_key / signature wire
// form is "ed25519:base64:<...>".
internal static class Keys
{
    private const string KeyIdPrefix = "timsim-local-";
    private const string Ed25519Prefix = "ed25519:base64:";
    private const int Blake2bDigestBytes = 10; // 80 bits -> 16 base32 chars

    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 4648

    // Derive the stable key id from the 32 raw bytes of an Ed25519 public key.
    public static string DeriveKeyId(byte[] rawPublicKey)
    {
        var digest = new Blake2bDigest(Blake2bDigestBytes * 8); // size in bits
        digest.BlockUpdate(rawPublicKey, 0, rawPublicKey.Length);
        var outBytes = new byte[Blake2bDigestBytes];
        digest.DoFinal(outBytes, 0);
        string encoded = Base32Encode(outBytes).TrimEnd('=').ToLowerInvariant();
        return KeyIdPrefix + encoded;
    }

    // RFC 4648 base32 (with '=' padding; caller strips it).
    private static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                sb.Append(Base32Alphabet[index]);
            }
        }
        if (bitsLeft > 0)
        {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.Append(Base32Alphabet[index]);
        }
        while (sb.Length % 8 != 0)
        {
            sb.Append('=');
        }
        return sb.ToString();
    }

    // Decode an "ed25519:base64:<32 raw bytes>" verifying key to its raw bytes.
    // Throws MalformedSidecarException on a wrong prefix or undecodable body,
    // mirroring how the reference verifier surfaces a non-ed25519 key.
    public static byte[] PublicKeyFromB64(string encoded)
    {
        if (!encoded.StartsWith(Ed25519Prefix, StringComparison.Ordinal))
        {
            throw new MalformedSidecarException(
                $"unrecognized verifying key format: {Truncate(encoded)}...");
        }
        byte[] raw = DecodeBase64(encoded.Substring(Ed25519Prefix.Length),
            "verifying_key");
        if (raw.Length != Ed25519.PublicKeySize)
        {
            throw new MalformedSidecarException(
                $"ed25519 public key must be {Ed25519.PublicKeySize} bytes, got {raw.Length}");
        }
        return raw;
    }

    // Decode an "ed25519:base64:<sig>" signature to its raw bytes.
    public static byte[] SignatureFromB64(string encoded)
    {
        if (!encoded.StartsWith(Ed25519Prefix, StringComparison.Ordinal))
        {
            throw new MalformedSidecarException(
                $"unrecognized signature format: {Truncate(encoded)}...");
        }
        return DecodeBase64(encoded.Substring(Ed25519Prefix.Length), "signature");
    }

    // Verify a raw Ed25519 signature over message with the raw public key.
    // Returns false on any failure (bad length, invalid signature) — never throws.
    public static bool Verify(byte[] rawPublicKey, byte[] signature, byte[] message)
    {
        if (rawPublicKey.Length != Ed25519.PublicKeySize ||
            signature.Length != Ed25519.SignatureSize)
        {
            return false;
        }
        try
        {
            return Ed25519.Verify(signature, 0, rawPublicKey, 0, message, 0, message.Length);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static byte[] DecodeBase64(string body, string field)
    {
        try
        {
            return Convert.FromBase64String(body);
        }
        catch (FormatException e)
        {
            throw new MalformedSidecarException(
                $"sidecar {field} field is not decodable: {e.Message}");
        }
    }

    private static string Truncate(string s) => s.Length <= 20 ? s : s.Substring(0, 20);
}
