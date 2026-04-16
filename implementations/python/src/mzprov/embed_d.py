"""In-band embedding of an mzprov sidecar inside a Bruker .d directory.

This is the writer/reader for the ``mzprov_provenance`` SQLite table
defined by ``spec/embedded-d-v0.md``. The transport is in-band; the
envelope bytes are byte-identical to what would be written to the
``*.provenance.json`` sidecar.

The exclusion rule that makes embed-after-hash safe lives in
``canonicalize.py`` (see ``EMBEDDED_PROVENANCE_TABLE``). This module
relies on that exclusion: once the row is written, recomputing the
canonical hash yields the same digest, because the table is filtered
out of the canonical record stream.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Union

from mzprov.canonicalize import (
    EMBEDDED_PROVENANCE_TABLE,
    _assert_sqlite_quiescent,
)
from mzprov.errors import (
    MalformedSidecar,
    MissingArtifact,
    SqliteNotQuiescent,
)

PathLike = Union[str, Path]


def _tdf_path(d_path: Path) -> Path:
    """Return the path to ``analysis.tdf`` for a .d directory, validating existence."""
    if not d_path.is_dir():
        raise MissingArtifact(f".d directory does not exist: {d_path}")
    tdf = d_path / "analysis.tdf"
    if not tdf.is_file():
        raise MissingArtifact(f"missing analysis.tdf in {d_path}")
    return tdf


def write_embedded_provenance(d_path: PathLike, sidecar_bytes: bytes) -> None:
    """Insert (or replace) the embedded sidecar row in ``analysis.tdf``.

    Implements the signer protocol from ``spec/embedded-d-v0.md`` §4:

      1. Pre-check quiescence (no -journal/-wal/-shm sidecars).
      2. Open the SQLite file, force ``journal_mode=DELETE`` so the write
         transaction does not leave WAL/SHM files behind.
      3. CREATE TABLE IF NOT EXISTS, DELETE existing row, INSERT new row,
         COMMIT — all in one transaction.
      4. Close cleanly.
      5. Re-check quiescence; raise ``SqliteNotQuiescent`` if any sidecar
         file lingers (which would prevent the verifier from reading it).

    Parameters
    ----------
    d_path
        The .d directory.
    sidecar_bytes
        The complete sidecar envelope as bytes (as produced by
        ``Sidecar.to_json_bytes()``). Stored as-is in the
        ``sidecar_json`` column. Must be valid UTF-8.
    """
    d_path = Path(d_path)
    tdf = _tdf_path(d_path)

    # Pre-check: refuse if the .tdf is not quiescent. Same guard the
    # canonicalizer uses; reusing it means the signer fails with the
    # same diagnostic the verifier would.
    _assert_sqlite_quiescent(tdf)

    # Decoding to UTF-8 here gives us a fast-fail with a clear message
    # rather than letting SQLite surface a generic encoding error
    # downstream. The TEXT column requires UTF-8.
    try:
        sidecar_text = sidecar_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedSidecar(
            f"sidecar bytes are not valid UTF-8: {e}"
        ) from e

    # Open read-write. We deliberately do NOT use the immutable URI here
    # (that's the read path). isolation_level=None lets us drive the
    # transaction explicitly with BEGIN/COMMIT.
    conn = sqlite3.connect(str(tdf), isolation_level=None)
    try:
        # journal_mode=DELETE keeps the rollback-journal in-place during
        # the write but deletes it on COMMIT. Crucially this avoids WAL
        # mode, which would leave -wal and -shm files alongside the
        # database that the verifier's quiescence guard would reject.
        cur = conn.execute("PRAGMA journal_mode=DELETE;")
        mode = cur.fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            # If the database was previously in WAL mode, switching to
            # DELETE here may require a checkpoint. We surface a clear
            # error rather than silently producing an embedded row that
            # the verifier cannot read.
            raise SqliteNotQuiescent(
                tdf,
                [
                    p
                    for suffix in ("-wal", "-shm")
                    for p in [tdf.with_name(tdf.name + suffix)]
                    if p.exists()
                ],
            )

        conn.execute("BEGIN IMMEDIATE;")
        try:
            conn.execute(
                f'CREATE TABLE IF NOT EXISTS "{EMBEDDED_PROVENANCE_TABLE}" '
                f"(sidecar_json TEXT NOT NULL);"
            )
            conn.execute(f'DELETE FROM "{EMBEDDED_PROVENANCE_TABLE}";')
            conn.execute(
                f'INSERT INTO "{EMBEDDED_PROVENANCE_TABLE}" (sidecar_json) VALUES (?);',
                (sidecar_text,),
            )
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
    finally:
        conn.close()

    # Post-check: the writer must leave the file quiescent. If any
    # -journal/-wal/-shm sidecar exists at this point, the verifier's
    # quiescence guard would refuse the file and the embedded
    # provenance would be unreadable. Surface this as a hard error.
    _assert_sqlite_quiescent(tdf)


def read_embedded_provenance(d_path: PathLike) -> bytes | None:
    """Return the embedded sidecar bytes, or None if no embedded row exists.

    Implements the reader protocol from ``spec/embedded-d-v0.md`` §5.
    Always opens read-only with the same URI used at hash time so we
    never mutate the .d. Returns ``None`` (not an error) when the
    ``mzprov_provenance`` table is absent or empty — the caller (the
    verifier) treats that as "fall back to JSON sidecar discovery."

    Raises ``MalformedSidecar`` if the table contains more than one row.
    Raises ``SqliteNotQuiescent`` if any -journal/-wal/-shm sidecar
    exists alongside ``analysis.tdf``.
    """
    d_path = Path(d_path)
    tdf = _tdf_path(d_path)

    _assert_sqlite_quiescent(tdf)

    uri = f"file:{tdf}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = ?;",
            (EMBEDDED_PROVENANCE_TABLE,),
        )
        if cur.fetchone() is None:
            return None

        cur = conn.execute(
            f'SELECT sidecar_json FROM "{EMBEDDED_PROVENANCE_TABLE}";'
        )
        rows = cur.fetchall()
        if not rows:
            return None
        if len(rows) > 1:
            raise MalformedSidecar(
                f"{EMBEDDED_PROVENANCE_TABLE} contains {len(rows)} rows; "
                f"v0 mandates at most one"
            )
        sidecar_text = rows[0][0]
        if not isinstance(sidecar_text, str):
            raise MalformedSidecar(
                f"{EMBEDDED_PROVENANCE_TABLE}.sidecar_json is not TEXT "
                f"(got {type(sidecar_text).__name__})"
            )
        return sidecar_text.encode("utf-8")
    finally:
        conn.close()


def has_embedded_provenance(d_path: PathLike) -> bool:
    """Cheap existence check — does the .d carry an embedded row?

    Equivalent to ``read_embedded_provenance(d_path) is not None`` but
    avoids loading the row body. Useful for the verifier's dispatch
    decision when it just needs to know which transport to use.
    """
    d_path = Path(d_path)
    tdf = _tdf_path(d_path)
    _assert_sqlite_quiescent(tdf)

    uri = f"file:{tdf}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = ?;",
            (EMBEDDED_PROVENANCE_TABLE,),
        )
        if cur.fetchone() is None:
            return False
        cur = conn.execute(
            f'SELECT 1 FROM "{EMBEDDED_PROVENANCE_TABLE}" LIMIT 1;'
        )
        return cur.fetchone() is not None
    finally:
        conn.close()
