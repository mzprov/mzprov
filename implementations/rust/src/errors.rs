//! Typed errors. Mirrors the error taxonomy of the Python reference so the
//! CLI can map failures to the exit codes in `spec/trust-model.md`.

use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ProvenanceError {
    KeyNotFound(String),
    MalformedKey(String),
    MalformedSidecar(String),
    UnknownVersion(String),
    UnknownAlgorithm(String),
    MissingArtifact(String),
    SqliteNotQuiescent {
        db: PathBuf,
        sidecars: Vec<PathBuf>,
    },
    Canonicalization(String),
    Io(io::Error),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound(m) => write!(f, "key not found: {m}"),
            Self::MalformedKey(m) => write!(f, "malformed key: {m}"),
            Self::MalformedSidecar(m) => write!(f, "malformed sidecar: {m}"),
            Self::UnknownVersion(m) => write!(f, "unknown version: {m}"),
            Self::UnknownAlgorithm(m) => write!(f, "unknown signature algorithm: {m}"),
            Self::MissingArtifact(m) => write!(f, "missing artifact: {m}"),
            Self::SqliteNotQuiescent { db, sidecars } => {
                let names: Vec<_> = sidecars
                    .iter()
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .collect();
                write!(
                    f,
                    "refusing to hash {}: SQLite sidecar files present ({})",
                    db.display(),
                    names.join(", ")
                )
            }
            Self::Canonicalization(m) => write!(f, "canonicalization error: {m}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

impl From<io::Error> for ProvenanceError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ProvenanceError>;
