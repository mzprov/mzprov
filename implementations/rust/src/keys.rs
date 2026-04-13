//! Ed25519 key loading and key-id derivation.
//!
//! See `spec/key-id-derivation.md`: BLAKE2b-80 over the 32 raw public-key
//! bytes, base32 (RFC 4648) with `=` stripped, lowercased, prefixed with
//! `timsim-local-`. Exactly 28 characters.

use base64::Engine;
use blake2::digest::consts::U10;
use blake2::{Blake2b, Digest};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::Path;

use crate::errors::{ProvenanceError, Result};

const KEY_ID_PREFIX: &str = "timsim-local-";
const SPKI_HEADER_LEN: usize = 12;
const ED25519_RAW_PUBKEY_LEN: usize = 32;

/// Derive the stable key id from an Ed25519 public key.
pub fn derive_key_id(public_key: &VerifyingKey) -> String {
    let mut hasher = Blake2b::<U10>::new();
    hasher.update(public_key.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(KEY_ID_PREFIX.len() + 16);
    out.push_str(KEY_ID_PREFIX);
    out.push_str(&BASE32_NOPAD.encode(&digest).to_ascii_lowercase());
    out
}

/// Load a SubjectPublicKeyInfo-wrapped Ed25519 PEM file from disk.
pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ProvenanceError::KeyNotFound(format!("public key not found: {}", path.display()))
        }
        _ => ProvenanceError::Io(e),
    })?;
    let pem = pem::parse(&bytes)
        .map_err(|e| ProvenanceError::MalformedKey(format!("not a PEM file: {e}")))?;
    if pem.tag() != "PUBLIC KEY" {
        return Err(ProvenanceError::MalformedKey(format!(
            "expected 'PUBLIC KEY' PEM armor, got {:?}",
            pem.tag()
        )));
    }
    verifying_key_from_spki(pem.contents())
}

/// Extract an Ed25519 verifying key from DER SubjectPublicKeyInfo bytes.
///
/// The Ed25519 SPKI has a fixed 12-byte header followed by the raw 32-byte
/// public key — see RFC 8410 §4. We accept any SPKI whose body is exactly
/// 44 bytes and whose tail is the raw public key.
pub fn verifying_key_from_spki(der: &[u8]) -> Result<VerifyingKey> {
    if der.len() != SPKI_HEADER_LEN + ED25519_RAW_PUBKEY_LEN {
        return Err(ProvenanceError::MalformedKey(format!(
            "unexpected Ed25519 SPKI length: {}",
            der.len()
        )));
    }
    let raw: [u8; 32] = der[SPKI_HEADER_LEN..].try_into().unwrap();
    VerifyingKey::from_bytes(&raw)
        .map_err(|e| ProvenanceError::MalformedKey(format!("invalid Ed25519 public key: {e}")))
}

/// Decode an `ed25519:base64:...` verifying key string to a `VerifyingKey`.
pub fn public_key_from_b64(encoded: &str) -> Result<VerifyingKey> {
    let raw = decode_algorithm_envelope(encoded, "verifying_key")?;
    let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        ProvenanceError::MalformedSidecar(format!(
            "verifying_key is not 32 bytes (got {})",
            raw.len()
        ))
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| ProvenanceError::MalformedSidecar(format!("invalid Ed25519 public key: {e}")))
}

/// Decode an `ed25519:base64:...` signature string to a raw 64-byte `Signature`.
pub fn signature_from_b64(encoded: &str) -> Result<Signature> {
    let raw = decode_algorithm_envelope(encoded, "signature")?;
    let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
        ProvenanceError::MalformedSidecar(format!(
            "signature is not 64 bytes (got {})",
            raw.len()
        ))
    })?;
    Ok(Signature::from_bytes(&arr))
}

/// Split an `{algorithm}:{encoding}:{value}` envelope and decode the value.
///
/// In v0 the only accepted algorithm/encoding pair is `ed25519:base64:`.
/// Any other prefix is an `UnknownAlgorithm` error, which the verifier maps
/// to `SIDECAR_ERROR` (exit 3). See `spec/sidecar-format.md` §7.
fn decode_algorithm_envelope(encoded: &str, field: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = encoded.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "{field} is not in algorithm:encoding:value form"
        )));
    }
    if parts[0] != "ed25519" {
        return Err(ProvenanceError::UnknownAlgorithm(format!(
            "{field} algorithm {:?} is not supported (v0 requires ed25519)",
            parts[0]
        )));
    }
    if parts[1] != "base64" {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "{field} encoding {:?} is not supported (v0 requires base64)",
            parts[1]
        )));
    }
    base64::engine::general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|e| ProvenanceError::MalformedSidecar(format!("{field} base64 decode: {e}")))
}

/// Byte-for-byte equality of two Ed25519 public keys (raw 32 bytes).
pub fn pubkeys_equal(a: &VerifyingKey, b: &VerifyingKey) -> bool {
    a.as_bytes() == b.as_bytes()
}

/// Verify a raw Ed25519 signature over `message` with `public_key`.
pub fn verify_signature(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}

/// Load an Ed25519 signing key from a PKCS#8 PEM file (unencrypted).
pub fn load_private_key(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ProvenanceError::KeyNotFound(format!("private key not found: {}", path.display()))
        }
        _ => ProvenanceError::Io(e),
    })?;
    SigningKey::from_pkcs8_pem(&bytes).map_err(|e| {
        ProvenanceError::MalformedKey(format!("not an Ed25519 PKCS#8 PEM: {e}"))
    })
}

/// Encode a verifying key as a SubjectPublicKeyInfo PEM string (LF newlines).
pub fn public_key_to_pem(public_key: &VerifyingKey) -> Result<String> {
    public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ProvenanceError::MalformedKey(format!("encode SPKI PEM: {e}")))
}

/// Decode a SubjectPublicKeyInfo PEM string into an `Ed25519` verifying key.
pub fn public_key_from_pem(text: &str) -> Result<VerifyingKey> {
    let pem_obj = pem::parse(text)
        .map_err(|e| ProvenanceError::MalformedKey(format!("not a PEM string: {e}")))?;
    if pem_obj.tag() != "PUBLIC KEY" {
        return Err(ProvenanceError::MalformedKey(format!(
            "expected 'PUBLIC KEY' PEM armor, got {:?}",
            pem_obj.tag()
        )));
    }
    verifying_key_from_spki(pem_obj.contents())
}

/// Encode a verifying key as the `ed25519:base64:...` envelope used in sidecars.
pub fn public_key_to_b64(public_key: &VerifyingKey) -> String {
    format!(
        "ed25519:base64:{}",
        base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes())
    )
}

/// Encode a raw signature as the `ed25519:base64:...` envelope.
pub fn signature_to_b64(signature: &Signature) -> String {
    format!(
        "ed25519:base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    )
}

/// Sign `message` with `signing_key`, producing a raw 64-byte Ed25519 signature.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// A freshly generated keypair and its derived stable key id.
pub struct GeneratedKey {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub key_id: String,
}

/// Generate a fresh Ed25519 keypair using the operating system CSPRNG.
pub fn generate_keypair() -> Result<GeneratedKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| {
        ProvenanceError::MalformedKey(format!("OS CSPRNG failed: {e}"))
    })?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let key_id = derive_key_id(&verifying_key);
    Ok(GeneratedKey {
        signing_key,
        verifying_key,
        key_id,
    })
}

/// Write a keypair to `key_dir` as `signing_key.pem` (PKCS#8),
/// `verifying_key.pem` (SPKI), and `key_id` (plain text). Creates
/// `key_dir` if it does not exist. On Unix, the private-key file is
/// written with mode 0600.
pub fn write_keypair(gen: &GeneratedKey, key_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(key_dir)?;

    let signing_pem = gen
        .signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| ProvenanceError::MalformedKey(format!("encode PKCS#8: {e}")))?;
    let verifying_pem = gen
        .verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ProvenanceError::MalformedKey(format!("encode SPKI: {e}")))?;

    let sk_path = key_dir.join("signing_key.pem");
    let pk_path = key_dir.join("verifying_key.pem");
    let id_path = key_dir.join("key_id");

    std::fs::write(&sk_path, signing_pem.as_bytes())?;
    set_private_mode_0600(&sk_path);
    std::fs::write(&pk_path, verifying_pem.as_bytes())?;
    std::fs::write(&id_path, format!("{}\n", gen.key_id))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_mode_0600(_path: &Path) {}
