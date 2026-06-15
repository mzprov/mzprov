//! Opaque content hashing for Thermo `.raw` vendor files (v0, frozen).
//!
//! Independent port of `canonicalize_raw.py`. Unlike the mzML path
//! ([`crate::canonicalize_mzml`]), which extracts spectrum *content* and
//! hashes it in a serialization-invariant way, a Thermo `.raw` file is an
//! **undocumented proprietary binary**. There is no published structure to
//! canonicalize against and no safe place to inject an embedded envelope.
//! The v0 `.raw` canonicalization is therefore an **opaque whole-file
//! SHA-256**:
//!
//! - It hashes the *exact bytes on disk*, in order, with no structural
//!   normalization whatsoever.
//! - It is consequently sensitive to **any** byte change: a single flipped
//!   bit, a re-serialization by any tool, a different vendor-library version
//!   that rewrites the container — all change the hash. This is
//!   **intentional and strict**: without a documented format we cannot tell
//!   a benign re-encoding from a malicious edit, so every byte is treated as
//!   load-bearing.
//! - Because there is no safe injection point in the vendor binary, the
//!   `.raw` attestation is **sidecar-only**. There is no embed transport
//!   (contrast [`crate::embed_d`] / [`crate::embed_mzml`]).
//!
//! This module is **frozen** at v0. Any future revision that changes what
//! bytes are hashed (e.g. a parser that learns the container format and
//! excludes a reserved provenance slot, the way the mzML path excludes
//! `mzprov:provenance`) MUST live in a `canonicalize_raw_v1.rs` and bump the
//! `canonicalization_version` field. See `spec/canonicalization-raw-v0.md`.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::errors::{ProvenanceError, Result};

const US: u8 = 0x1f;

/// Domain prefix for the composed `.raw` content hash. Distinct from the
/// `.d` domain prefix in `canonicalize_d` and the mzML domain prefix in
/// `canonicalize_mzml` so the three cannot collide.
const RAW_CONTENT_DOMAIN: &[u8] = b"timsim.raw.v0\x1f";

/// Streaming chunk size for the file hasher (1 MiB), matching the Python
/// reference so the hash uses constant memory regardless of file size.
const HASH_CHUNK: usize = 1 << 20;

/// Return the sha256 of the opaque whole-file content of a `.raw`.
///
/// The hash is a domain-prefixed streaming SHA-256 over the entire file
/// byte stream, read in 1 MiB chunks. There is **no** structural
/// normalization: any re-serialization of the file changes the hash. See
/// the module docstring for why that strictness is intentional.
///
/// Returns 32 raw bytes (use [`crate::envelope::encode_hash_field`] for the
/// conventional `sha256:<hex>` string form).
///
/// Returns [`ProvenanceError::MissingArtifact`] if `path` is not an
/// existing regular file (mirrors the Python `FileNotFoundError`).
pub fn canonicalize_raw(path: &Path) -> Result<[u8; 32]> {
    if !path.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "raw file not found: {}",
            path.display()
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"TIMSIM-RAW-CANONICAL-v0\x1f");

    let mut file = File::open(path)?;
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Compose the `.raw` content hash:
/// `sha256(RAW_CONTENT_DOMAIN || raw_hash || US || config_hash)`.
///
/// The version-tagged domain prefix protects against cross-protocol
/// confusion with the `.d` [`crate::canonicalize_d::compose_content_hash`]
/// and the mzML [`crate::canonicalize_mzml::compose_mzml_content_hash`].
/// Both input hashes are 32 bytes.
pub fn compose_raw_content_hash(raw_hash: &[u8; 32], config_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RAW_CONTENT_DOMAIN);
    h.update(raw_hash);
    h.update([US]);
    h.update(config_hash);
    h.finalize().into()
}
