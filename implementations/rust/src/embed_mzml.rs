//! In-band embedding of an mzprov sidecar inside an mzML file.
//!
//! Mirrors the Python `mzprov.embed_mzml` module. See
//! `spec/embedded-mzml-v0.md` for the normative protocol. The slot is
//! a `userParam` with name `mzprov:provenance` inside
//! `<fileDescription>/<fileContent>`; the value is the base64 of the
//! v0 envelope JSON.
//!
//! The slot is canonically excluded by virtue of living in
//! `<fileDescription>`, which the mzML canonicalizer never enters
//! (see `spec/canonicalization-mzml-v0.md` §1, §2). Embed-after-hash
//! is therefore well-defined without any change to the
//! canonicalization algorithm.
//!
//! This implementation uses [`mzdata`] for read and write. mzdata
//! produces a fresh, valid `<indexedmzML>` wrapper (re-index mode
//! per `spec/embedded-mzml-v0.md` §4) — not the strip-on-embed mode
//! the Python reference uses. Both are conformant.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use mzdata::io::mzml::{MzMLReader, MzMLWriter};
use mzdata::params::Param;
use mzdata::prelude::*;

use crate::errors::{ProvenanceError, Result};

/// Reserved userParam name for the embedded transport. See
/// `spec/embedded-mzml-v0.md` §2. Tools other than mzprov MUST NOT
/// use this name.
pub const EMBEDDED_USERPARAM_NAME: &str = "mzprov:provenance";

fn missing_artifact(p: &Path) -> ProvenanceError {
    ProvenanceError::MissingArtifact(format!("mzml file does not exist: {}", p.display()))
}

fn mzml_err(msg: impl AsRef<str>) -> ProvenanceError {
    ProvenanceError::MalformedSidecar(format!("mzml: {}", msg.as_ref()))
}

/// Insert (or replace) the embedded sidecar userParam in an mzML file.
///
/// Implements the signer protocol from `spec/embedded-mzml-v0.md` §5.
/// Output is a valid `<indexedmzML>` document with a fresh, correct
/// byte-offset index — re-index mode per spec §4.
pub fn write_embedded_provenance(mzml_path: &Path, sidecar_bytes: &[u8]) -> Result<()> {
    if !mzml_path.is_file() {
        return Err(missing_artifact(mzml_path));
    }
    // Validate UTF-8 of the sidecar up front for a clear error.
    let _ = std::str::from_utf8(sidecar_bytes).map_err(|e| {
        ProvenanceError::MalformedSidecar(format!("sidecar bytes are not valid UTF-8: {e}"))
    })?;
    let encoded = B64.encode(sidecar_bytes);

    let mut tmp_os = mzml_path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    {
        let mut reader = MzMLReader::open_path(mzml_path)
            .map_err(|e| mzml_err(format!("open for read: {e}")))?;

        // Single-row equivalent: drop any pre-existing reserved param,
        // then insert ours.
        let fd = reader.file_description_mut();
        fd.params_mut().retain(|p| p.name != EMBEDDED_USERPARAM_NAME);

        let mut up = Param::new();
        up.name = EMBEDDED_USERPARAM_NAME.into();
        up.value = encoded.into();
        // Param with no accession / cv_ref is rendered as userParam by
        // mzdata's writer (matches the schema choice in the Python
        // reference).
        fd.add_param(up);

        let out_file = fs::File::create(&tmp_path)?;
        let mut writer = MzMLWriter::new(out_file);
        writer
            .copy_metadata_from(&reader);
        for spec in reader.iter() {
            writer
                .write(&spec)
                .map_err(|e| mzml_err(format!("write spectrum: {e}")))?;
        }
        writer
            .close()
            .map_err(|e| mzml_err(format!("close writer: {e}")))?;
    }

    fs::rename(&tmp_path, mzml_path)?;
    Ok(())
}

/// Return the embedded sidecar bytes, or `None` if the userParam is
/// absent. Implements the reader protocol from
/// `spec/embedded-mzml-v0.md` §6.
pub fn read_embedded_provenance(mzml_path: &Path) -> Result<Option<Vec<u8>>> {
    if !mzml_path.is_file() {
        return Err(missing_artifact(mzml_path));
    }
    let reader = MzMLReader::open_path(mzml_path)
        .map_err(|e| mzml_err(format!("open for read: {e}")))?;
    let fd = reader.file_description();

    let matches: Vec<&Param> = fd
        .params()
        .iter()
        .filter(|p| p.name == EMBEDDED_USERPARAM_NAME)
        .collect();

    match matches.len() {
        0 => Ok(None),
        1 => {
            let value = matches[0].value.to_string();
            B64.decode(value.as_str()).map(Some).map_err(|e| {
                ProvenanceError::MalformedSidecar(format!(
                    "mzprov:provenance userParam value is not valid base64: {e}"
                ))
            })
        }
        n => Err(ProvenanceError::MalformedSidecar(format!(
            "mzml fileDescription contains {n} params with name={EMBEDDED_USERPARAM_NAME:?}; \
             v0 mandates at most one"
        ))),
    }
}

/// Cheap existence check.
pub fn has_embedded_provenance(mzml_path: &Path) -> Result<bool> {
    Ok(read_embedded_provenance(mzml_path)?.is_some())
}
