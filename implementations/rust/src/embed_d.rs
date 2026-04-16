//! In-band embedding of an mzprov sidecar inside a Bruker `.d` directory.
//!
//! Mirrors the Python `mzprov.embed_d` module. See `spec/embedded-d-v0.md`
//! for the normative protocol. The reserved table name is excluded from
//! the canonical hash by `canonicalize_d`, which is what makes
//! embed-after-hash well-defined.

use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

use crate::canonicalize_d::{assert_sqlite_quiescent, EMBEDDED_PROVENANCE_TABLE};
use crate::errors::{ProvenanceError, Result};

fn tdf_path(d_path: &Path) -> Result<PathBuf> {
    if !d_path.is_dir() {
        return Err(ProvenanceError::MissingArtifact(format!(
            ".d directory does not exist: {}",
            d_path.display()
        )));
    }
    let tdf = d_path.join("analysis.tdf");
    if !tdf.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "missing analysis.tdf in {}",
            d_path.display()
        )));
    }
    Ok(tdf)
}

/// Insert (or replace) the embedded sidecar row in `analysis.tdf`.
///
/// Implements the signer protocol from `spec/embedded-d-v0.md` §4:
/// quiescence pre-check, force `journal_mode=DELETE`, single-row
/// transactional INSERT OR REPLACE, clean close, post-write
/// quiescence re-check.
pub fn write_embedded_provenance(d_path: &Path, sidecar_bytes: &[u8]) -> Result<()> {
    let tdf = tdf_path(d_path)?;
    assert_sqlite_quiescent(&tdf)?;

    // Validate UTF-8 up front so we fail with a clear error rather than
    // a generic SQLite encoding error downstream. The TEXT column
    // requires UTF-8.
    let sidecar_text = std::str::from_utf8(sidecar_bytes).map_err(|e| {
        ProvenanceError::MalformedSidecar(format!("sidecar bytes are not valid UTF-8: {e}"))
    })?;

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(&tdf, flags).map_err(|e| {
        ProvenanceError::Canonicalization(format!("open sqlite for write: {e}"))
    })?;

    // Force DELETE journal mode so the write txn does not leave WAL/SHM
    // files behind that the verifier's quiescence guard would reject.
    let mode: String = conn
        .query_row("PRAGMA journal_mode=DELETE;", [], |r| r.get(0))
        .map_err(|e| ProvenanceError::Canonicalization(format!("pragma journal_mode: {e}")))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(ProvenanceError::SqliteNotQuiescent {
            db: tdf.clone(),
            sidecars: vec![],
        });
    }

    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{}\" (sidecar_json TEXT NOT NULL);",
        EMBEDDED_PROVENANCE_TABLE
    );
    let delete_sql = format!("DELETE FROM \"{}\";", EMBEDDED_PROVENANCE_TABLE);
    let insert_sql = format!(
        "INSERT INTO \"{}\" (sidecar_json) VALUES (?1);",
        EMBEDDED_PROVENANCE_TABLE
    );

    let txn_result: Result<()> = (|| {
        conn.execute("BEGIN IMMEDIATE;", [])
            .map_err(|e| ProvenanceError::Canonicalization(format!("begin: {e}")))?;
        conn.execute(&create_sql, [])
            .map_err(|e| ProvenanceError::Canonicalization(format!("create: {e}")))?;
        conn.execute(&delete_sql, [])
            .map_err(|e| ProvenanceError::Canonicalization(format!("delete: {e}")))?;
        conn.execute(&insert_sql, [sidecar_text])
            .map_err(|e| ProvenanceError::Canonicalization(format!("insert: {e}")))?;
        conn.execute("COMMIT;", [])
            .map_err(|e| ProvenanceError::Canonicalization(format!("commit: {e}")))?;
        Ok(())
    })();

    if let Err(e) = txn_result {
        let _ = conn.execute("ROLLBACK;", []);
        drop(conn);
        return Err(e);
    }

    drop(conn);
    assert_sqlite_quiescent(&tdf)?;
    Ok(())
}

/// Return the embedded sidecar bytes, or `None` if no row exists.
///
/// Implements the reader protocol from `spec/embedded-d-v0.md` §5.
/// Returns `Ok(None)` when the `mzprov_provenance` table is absent or
/// empty; returns `Err(MalformedSidecar)` when the table contains more
/// than one row.
pub fn read_embedded_provenance(d_path: &Path) -> Result<Option<Vec<u8>>> {
    let tdf = tdf_path(d_path)?;
    assert_sqlite_quiescent(&tdf)?;

    let uri = format!("file:{}?mode=ro&immutable=1", tdf.display());
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(uri, flags)
        .map_err(|e| ProvenanceError::Canonicalization(format!("open sqlite: {e}")))?;

    // Check the table exists before selecting from it, so a missing
    // table is "no embedded provenance" rather than a SQL error.
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1;",
            [EMBEDDED_PROVENANCE_TABLE],
            |row| row.get(0),
        )
        .ok();
    if exists.is_none() {
        return Ok(None);
    }

    let select_sql = format!(
        "SELECT sidecar_json FROM \"{}\";",
        EMBEDDED_PROVENANCE_TABLE
    );
    let mut stmt = conn
        .prepare(&select_sql)
        .map_err(|e| ProvenanceError::Canonicalization(format!("prepare select: {e}")))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| ProvenanceError::Canonicalization(format!("query: {e}")))?;

    let mut found: Vec<String> = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| ProvenanceError::Canonicalization(format!("row: {e}")))?
    {
        let value: String = row
            .get(0)
            .map_err(|e| ProvenanceError::Canonicalization(format!("cell: {e}")))?;
        found.push(value);
    }

    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found.into_iter().next().unwrap().into_bytes())),
        n => Err(ProvenanceError::MalformedSidecar(format!(
            "{} contains {} rows; v0 mandates at most one",
            EMBEDDED_PROVENANCE_TABLE, n
        ))),
    }
}

/// Cheap existence check — does the .d carry an embedded row?
pub fn has_embedded_provenance(d_path: &Path) -> Result<bool> {
    Ok(read_embedded_provenance(d_path)?.is_some())
}
