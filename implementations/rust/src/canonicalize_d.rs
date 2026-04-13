//! Canonical content hashing for a Bruker `.d` directory.
//!
//! Frozen v0 algorithm — byte output is fixed forever. See
//! `spec/canonicalization-d-v0.md` and the Python reference at
//! `implementations/python/src/mzprov/canonicalize.py`. This module is an
//! independent port; the two converge at the test-vector hashes.

use rusqlite::types::Value as SqliteValue;
use rusqlite::OpenFlags;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

use crate::errors::{ProvenanceError, Result};

const US: u8 = 0x1f;
const RS: u8 = 0x1e;
/// Domain-tagged prefix for the composed content hash.
const CONTENT_DOMAIN: &[u8] = b"timsim.v0\x1f";
/// Canonical NaN bit pattern (IEEE 754 quiet NaN, big-endian).
const CANONICAL_NAN: [u8; 8] = [0x7f, 0xf8, 0, 0, 0, 0, 0, 0];
const SQLITE_SIDECAR_SUFFIXES: &[&str] = &["-journal", "-wal", "-shm"];
const BIN_CHUNK: usize = 1 << 20;

/// Render a single SQLite cell to its canonical byte form.
pub fn canonicalize_value(v: &SqliteValue) -> Vec<u8> {
    match v {
        SqliteValue::Null => b"\x00NULL\x00".to_vec(),
        SqliteValue::Integer(i) => i.to_string().into_bytes(),
        SqliteValue::Real(f) => {
            let bytes = if f.is_nan() {
                CANONICAL_NAN
            } else {
                f.to_be_bytes()
            };
            hex::encode(bytes).into_bytes()
        }
        SqliteValue::Text(s) => {
            let normalized: String = s.nfc().collect();
            let body = normalized.as_bytes();
            let mut out = Vec::with_capacity(body.len() + 8);
            out.extend_from_slice(b"\x00len");
            out.extend_from_slice(body.len().to_string().as_bytes());
            out.push(0);
            out.extend_from_slice(body);
            out
        }
        SqliteValue::Blob(b) => {
            let mut out = Vec::with_capacity(b.len() * 2 + 8);
            out.extend_from_slice(b"\x00blob");
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(0);
            out.extend_from_slice(hex::encode(b).as_bytes());
            out
        }
    }
}

fn quote_ident(ident: &str) -> String {
    let mut s = String::with_capacity(ident.len() + 2);
    s.push('"');
    for c in ident.chars() {
        if c == '"' {
            s.push('"');
            s.push('"');
        } else {
            s.push(c);
        }
    }
    s.push('"');
    s
}

fn assert_quiescent(db_path: &Path) -> Result<()> {
    let mut found = Vec::new();
    let file_name = db_path.file_name().ok_or_else(|| {
        ProvenanceError::Canonicalization(format!(
            "sqlite db path has no filename: {}",
            db_path.display()
        ))
    })?;
    let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        let mut candidate = PathBuf::from(parent);
        let mut name = file_name.to_os_string();
        name.push(suffix);
        candidate.push(name);
        if candidate.exists() {
            found.push(candidate);
        }
    }
    if !found.is_empty() {
        return Err(ProvenanceError::SqliteNotQuiescent {
            db: db_path.to_path_buf(),
            sidecars: found,
        });
    }
    Ok(())
}

/// SHA-256 of the canonical SQL dump of a SQLite file.
pub fn canonicalize_sqlite(db_path: &Path) -> Result<[u8; 32]> {
    assert_quiescent(db_path)?;
    let uri = format!("file:{}?mode=ro&immutable=1", db_path.display());
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let conn = rusqlite::Connection::open_with_flags(uri, flags)
        .map_err(|e| ProvenanceError::Canonicalization(format!("open sqlite: {e}")))?;

    let mut hasher = Sha256::new();

    // List user tables, alphabetical.
    let mut tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
                 ORDER BY name;",
            )
            .map_err(|e| ProvenanceError::Canonicalization(format!("list tables: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| ProvenanceError::Canonicalization(format!("list tables: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ProvenanceError::Canonicalization(format!("list tables: {e}")))?
    };
    tables.sort();

    for table in tables {
        // (cid, name, declared_type) per table_info PRAGMA. Python sorts
        // by cid explicitly — rusqlite returns in cid order but we sort
        // defensively to match.
        let cols: Vec<(i64, String, String)> = {
            let pragma = format!("PRAGMA table_info({});", quote_ident(&table));
            let mut stmt = conn.prepare(&pragma).map_err(|e| {
                ProvenanceError::Canonicalization(format!("pragma table_info: {e}"))
            })?;
            let rows = stmt
                .query_map([], |row| {
                    let cid: i64 = row.get(0)?;
                    let name: String = row.get(1)?;
                    let declared: Option<String> = row.get(2)?;
                    Ok((cid, name, declared.unwrap_or_default()))
                })
                .map_err(|e| {
                    ProvenanceError::Canonicalization(format!("pragma table_info: {e}"))
                })?;
            let mut v = rows
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| {
                    ProvenanceError::Canonicalization(format!("pragma table_info: {e}"))
                })?;
            v.sort_by_key(|r| r.0);
            v
        };

        // Table header record.
        hasher.update([US]);
        hasher.update(b"table");
        hasher.update([US]);
        hasher.update(table.as_bytes());
        hasher.update([US]);

        for (_cid, name, declared) in &cols {
            hasher.update([US]);
            hasher.update(b"col");
            hasher.update([US]);
            hasher.update(name.as_bytes());
            hasher.update([US]);
            hasher.update(declared.as_bytes());
            hasher.update([US]);
        }

        if cols.is_empty() {
            continue;
        }

        let order_by: Vec<String> = cols.iter().map(|c| quote_ident(&c.1)).collect();
        let select_sql = format!(
            "SELECT * FROM {} ORDER BY {};",
            quote_ident(&table),
            order_by.join(", ")
        );

        let mut stmt = conn.prepare(&select_sql).map_err(|e| {
            ProvenanceError::Canonicalization(format!("select {table}: {e}"))
        })?;
        let col_count = stmt.column_count();
        let mut rows = stmt
            .query([])
            .map_err(|e| ProvenanceError::Canonicalization(format!("query {table}: {e}")))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ProvenanceError::Canonicalization(format!("row {table}: {e}")))?
        {
            hasher.update([US]);
            hasher.update(b"row");
            for idx in 0..col_count {
                let raw: SqliteValue = row
                    .get::<_, SqliteValue>(idx)
                    .map_err(|e| ProvenanceError::Canonicalization(format!("cell: {e}")))?;
                hasher.update([US]);
                hasher.update(canonicalize_value(&raw));
            }
            hasher.update([US, RS]);
        }
    }

    let digest = hasher.finalize();
    Ok(digest.into())
}

fn hash_file_streaming(path: &Path) -> Result<[u8; 32]> {
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(BIN_CHUNK, f);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BIN_CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Canonical content hash of a Bruker `.d` directory.
pub fn canonicalize_d(d_path: &Path) -> Result<[u8; 32]> {
    if !d_path.is_dir() {
        return Err(ProvenanceError::MissingArtifact(format!(
            ".d path is not a directory: {}",
            d_path.display()
        )));
    }
    let tdf = d_path.join("analysis.tdf");
    let tdf_bin = d_path.join("analysis.tdf_bin");
    if !tdf.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "missing analysis.tdf in {}",
            d_path.display()
        )));
    }
    if !tdf_bin.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "missing analysis.tdf_bin in {}",
            d_path.display()
        )));
    }
    let bin_hash = hash_file_streaming(&tdf_bin)?;
    let tdf_hash = canonicalize_sqlite(&tdf)?;
    let mut hasher = Sha256::new();
    hasher.update(bin_hash);
    hasher.update(tdf_hash);
    Ok(hasher.finalize().into())
}

/// SHA-256 of an arbitrary byte slice (e.g. a config file).
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Compose the per-component hashes into the signed content hash. Layout:
/// `sha256(CONTENT_DOMAIN || d_hash || US || gt_marker || US || config_hash)`.
pub fn compose_content_hash(
    d_hash: &[u8; 32],
    ground_truth_hash: Option<&[u8; 32]>,
    config_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTENT_DOMAIN);
    h.update(d_hash);
    h.update([US]);
    match ground_truth_hash {
        Some(gt) => h.update(gt),
        None => h.update(b"none"),
    }
    h.update([US]);
    h.update(config_hash);
    h.finalize().into()
}
