using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Mzprov;

// An Ed25519 keypair plus its derived stable key id, used for signing.
internal sealed class SigningKeyPair
{
    public Ed25519PrivateKeyParameters Private { get; }
    public Ed25519PublicKeyParameters Public { get; }
    public byte[] PublicRaw { get; }
    public string KeyId { get; }

    public SigningKeyPair(Ed25519PrivateKeyParameters priv)
    {
        Private = priv;
        Public = priv.GeneratePublicKey();
        PublicRaw = Public.GetEncoded();
        KeyId = Keys.DeriveKeyId(PublicRaw);
    }
}

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

    // ----- signing-side -----

    private const string PrivateKeyFilename = "signing_key.pem";
    private const string PublicKeyFilename = "verifying_key.pem";
    private const string KeyIdFilename = "key_id";

    public static SigningKeyPair GenerateKeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        return new SigningKeyPair((Ed25519PrivateKeyParameters)pair.Private);
    }

    // Load a PKCS#8 Ed25519 private key from a PEM file (BEGIN PRIVATE KEY).
    public static SigningKeyPair LoadPrivateKeyPem(string path)
    {
        if (!File.Exists(path))
        {
            throw new KeyNotFoundException($"private key not found: {path}");
        }
        byte[] der;
        try
        {
            der = DecodePem(File.ReadAllText(path), "PRIVATE KEY");
        }
        catch (Exception e)
        {
            throw new MalformedKeyException($"private key at {path} could not be parsed: {e.Message}");
        }
        try
        {
            var key = PrivateKeyFactory.CreateKey(der);
            if (key is not Ed25519PrivateKeyParameters priv)
            {
                throw new MalformedKeyException($"key at {path} is not an Ed25519 private key");
            }
            return new SigningKeyPair(priv);
        }
        catch (MalformedKeyException) { throw; }
        catch (Exception e)
        {
            throw new MalformedKeyException($"private key at {path} could not be parsed: {e.Message}");
        }
    }

    // Resolve a signing keypair the way the reference _resolve_keypair does:
    // a PEM file is loaded; a directory is load-or-create (signing_key.pem).
    public static SigningKeyPair ResolveKeyPair(string keyPath)
    {
        if (Directory.Exists(keyPath))
        {
            return LoadOrCreate(keyPath);
        }
        return LoadPrivateKeyPem(keyPath);
    }

    public static SigningKeyPair LoadOrCreate(string keyDir)
    {
        string sk = Path.Combine(keyDir, PrivateKeyFilename);
        if (File.Exists(sk))
        {
            return LoadPrivateKeyPem(sk);
        }
        var pair = GenerateKeyPair();
        WriteKeyPair(pair, keyDir);
        return pair;
    }

    // Fixed DER prefixes for the *minimal* Ed25519 PKCS#8 v1 private key (48
    // bytes total) and SubjectPublicKeyInfo (44 bytes). We build these by hand
    // rather than via BouncyCastle's factories, whose Ed25519 PKCS#8 output
    // (v2, with an embedded public key) the Python `cryptography` loader
    // rejects. This minimal form is byte-identical to what the reference
    // writes, so keys are interoperable in both directions.
    private static readonly byte[] Ed25519Pkcs8Prefix =
        { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
    private static readonly byte[] Ed25519SpkiPrefix =
        { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };

    // Write signing_key.pem (PKCS#8), verifying_key.pem (SPKI), and key_id,
    // byte-format-compatible with the Python reference's key files.
    public static void WriteKeyPair(SigningKeyPair pair, string keyDir)
    {
        Directory.CreateDirectory(keyDir);
        byte[] privDer = Concat(Ed25519Pkcs8Prefix, pair.Private.GetEncoded()); // 16 + 32
        byte[] pubDer = Concat(Ed25519SpkiPrefix, pair.PublicRaw);              // 12 + 32
        string skPath = Path.Combine(keyDir, PrivateKeyFilename);
        File.WriteAllText(skPath, EncodePem(privDer, "PRIVATE KEY"));
        // Restrict the private key to owner read/write, matching the reference's
        // chmod 0600. Tolerate platforms where this is not meaningful.
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(skPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception) { /* best-effort, as the reference does */ }
        File.WriteAllText(Path.Combine(keyDir, PublicKeyFilename), EncodePem(pubDer, "PUBLIC KEY"));
        File.WriteAllText(Path.Combine(keyDir, KeyIdFilename), pair.KeyId + "\n");
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Array.Copy(a, 0, r, 0, a.Length);
        Array.Copy(b, 0, r, a.Length, b.Length);
        return r;
    }

    public static byte[] Sign(Ed25519PrivateKeyParameters priv, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, priv);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    public static string PublicKeyToB64(byte[] rawPublicKey) =>
        Ed25519Prefix + Convert.ToBase64String(rawPublicKey);

    public static string SignatureToB64(byte[] signature) =>
        Ed25519Prefix + Convert.ToBase64String(signature);

    // ----- minimal PEM codec (BEGIN/END <label> + base64 in 64-col lines) -----

    private static string EncodePem(byte[] der, string label)
    {
        string b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }
        sb.Append("-----END ").Append(label).Append("-----\n");
        return sb.ToString();
    }

    private static byte[] DecodePem(string pem, string label)
    {
        string begin = "-----BEGIN " + label + "-----";
        string end = "-----END " + label + "-----";
        int b = pem.IndexOf(begin, StringComparison.Ordinal);
        int e = pem.IndexOf(end, StringComparison.Ordinal);
        if (b < 0 || e < 0 || e < b)
        {
            throw new FormatException($"PEM block '{label}' not found");
        }
        string body = pem.Substring(b + begin.Length, e - (b + begin.Length));
        var cleaned = new StringBuilder();
        foreach (char c in body)
        {
            if (!char.IsWhiteSpace(c)) cleaned.Append(c);
        }
        return Convert.FromBase64String(cleaned.ToString());
    }
}
