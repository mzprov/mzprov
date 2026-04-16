//! Path conventions shared between the signer and the verifier.
//!
//! Mirrors `implementations/python/src/mzprov/paths.py`. Both sides
//! MUST derive these paths from the on-disk artifact (or sidecar)
//! location alone — never from a payload field — because payload
//! fields are attacker-controllable and a tampered field could
//! otherwise redirect the verifier to a phantom file. Centralizing
//! the conventions here keeps that property in one place.

use std::path::{Path, PathBuf};

/// Conventional config-copy path for the JSON sidecar transport.
///
/// For `foo.provenance.json` returns `foo.config.toml` in the same
/// directory.
pub fn sidecar_config_path(sidecar_path: &Path) -> PathBuf {
    let name = sidecar_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let stem = name.strip_suffix(".provenance.json").unwrap_or_else(|| {
        sidecar_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    });
    let parent = sidecar_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}.config.toml"))
}

/// Conventional config-copy path for the embedded-d transport.
///
/// For `…/sample.d` returns `…/sample.config.toml`.
pub fn embedded_d_config_path(d_path: &Path) -> PathBuf {
    let name = d_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let stem = name.strip_suffix(".d").unwrap_or(name);
    let parent = d_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}.config.toml"))
}

/// Conventional config-copy path for the embedded-mzml transport.
///
/// For `…/sample.mzML` returns `…/sample.config.toml`.
pub fn embedded_mzml_config_path(mzml_path: &Path) -> PathBuf {
    let stem = mzml_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let parent = mzml_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}.config.toml"))
}
