"""Tests for the embedded-d-v0 transport.

Covers:
  - Round-trip embed/read in isolation (pure embed_d module).
  - Exclusion correctness: hash(d) == hash(d_after_insert).
  - End-to-end sign --embed + verify-via-CLI.
  - Verifier dispatch: prefer embedded over JSON sidecar when both exist.
  - Verifier fall-back to JSON sidecar when no embedded row exists.
  - Tamper detection on the embedded envelope.
  - Quiescence guard refuses to read a .d with a lingering -wal/-journal.
  - Replace-on-resign semantics (single-row invariant).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from mzprov import canonicalize_d
from mzprov.cli import (
    EXIT_HASH_MISMATCH,
    EXIT_OK,
    EXIT_SIDECAR_ERROR,
    main as verify_main,
)
from mzprov.embed_d import (
    has_embedded_provenance,
    read_embedded_provenance,
    write_embedded_provenance,
)
from mzprov.errors import (
    MalformedSidecar,
    SqliteNotQuiescent,
)
from mzprov.sign import sign_simulation_output
from mzprov.verify import (
    find_provenance_for,
    verify_embedded_d,
    verify_sidecar,
)


# ---------------------------------------------------------------------------
# embed_d module — round-trip and exclusion correctness
# ---------------------------------------------------------------------------


def test_embed_d_round_trip(minimal_d):
    """write_embedded_provenance then read_embedded_provenance returns the same bytes."""
    envelope = b'{"type": "timsim.provenance.v0", "payload": {"k": 1}, "signature": "x", "verifying_key": "y"}'
    write_embedded_provenance(minimal_d, envelope)
    got = read_embedded_provenance(minimal_d)
    assert got == envelope


def test_embed_d_exclusion_correctness(minimal_d):
    """hash(d) before embedding must equal hash(d) after embedding.

    This is the load-bearing property that makes embed-after-hash safe:
    the canonical hash filters the mzprov_provenance table out of the
    record stream, so inserting it does not perturb the digest.
    """
    h_before = canonicalize_d(minimal_d)
    write_embedded_provenance(
        minimal_d,
        b'{"type": "timsim.provenance.v0", "payload": {}, "signature": "x", "verifying_key": "y"}',
    )
    h_after = canonicalize_d(minimal_d)
    assert h_before == h_after


def test_embed_d_replace_keeps_single_row(minimal_d):
    """Re-signing must leave at most one row. v0 schema invariant."""
    write_embedded_provenance(minimal_d, b'{"v": 1}')
    write_embedded_provenance(minimal_d, b'{"v": 2}')
    got = read_embedded_provenance(minimal_d)
    assert got == b'{"v": 2}'

    # Direct DB query to confirm row count.
    with sqlite3.connect(str(minimal_d / "analysis.tdf")) as conn:
        (count,) = conn.execute("SELECT COUNT(*) FROM mzprov_provenance;").fetchone()
    assert count == 1


def test_embed_d_post_write_no_sqlite_sidecars(minimal_d):
    """After the writer closes, no -wal/-shm/-journal files lingers.

    The verifier's quiescence guard would refuse the .d if these were
    present. The signer's post-write check enforces this; this test
    asserts the observable filesystem state directly.
    """
    write_embedded_provenance(minimal_d, b'{"v": 1}')
    tdf = minimal_d / "analysis.tdf"
    for suffix in ("-wal", "-shm", "-journal"):
        assert not tdf.with_name(tdf.name + suffix).exists(), (
            f"writer left {suffix} sidecar — verifier will refuse"
        )


def test_read_returns_none_when_no_table(minimal_d):
    """A pristine .d with no mzprov_provenance table reads as None."""
    assert read_embedded_provenance(minimal_d) is None
    assert has_embedded_provenance(minimal_d) is False


def test_read_refuses_multiple_rows(minimal_d):
    """If somehow >1 row exists, the reader raises MalformedSidecar."""
    write_embedded_provenance(minimal_d, b'{"v": 1}')
    # Bypass the writer's single-row enforcement by inserting directly.
    with sqlite3.connect(str(minimal_d / "analysis.tdf")) as conn:
        conn.execute(
            "INSERT INTO mzprov_provenance (sidecar_json) VALUES (?);",
            ('{"v": 2}',),
        )
        conn.commit()

    with pytest.raises(MalformedSidecar):
        read_embedded_provenance(minimal_d)


def test_quiescence_guard_refuses_read_with_journal(minimal_d):
    """A .d with a -journal file present must refuse at read time."""
    write_embedded_provenance(minimal_d, b'{"v": 1}')
    tdf = minimal_d / "analysis.tdf"
    journal = tdf.with_name(tdf.name + "-journal")
    journal.write_bytes(b"")
    try:
        with pytest.raises(SqliteNotQuiescent):
            read_embedded_provenance(minimal_d)
    finally:
        journal.unlink()


# ---------------------------------------------------------------------------
# End-to-end sign + verify with --embed
# ---------------------------------------------------------------------------


def test_sign_embed_then_verify(minimal_d, minimal_config_bytes, tmp_path):
    """sign_simulation_output(embed=True) → verify_embedded_d → VERIFIED."""
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    result_path = sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="embed_smoke",
        simulator_version="0.1",
        embed=True,
    )
    # In embed mode we return the .d itself, not a sidecar JSON path.
    assert result_path == minimal_d

    # No JSON sidecar should have been written.
    sidecar_jsons = list(minimal_d.parent.glob("*.provenance.json"))
    assert sidecar_jsons == []

    result = verify_embedded_d(minimal_d)
    assert result.overall_ok is True
    assert result.transport == "embedded-d"
    assert result.signature_ok is True


def test_verify_embedded_via_cli(minimal_d, minimal_config_bytes, tmp_path, capsys):
    """`mzprov verify <d_path>` discovers the embedded row and verifies."""
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="embed_cli",
        simulator_version="0.1",
        embed=True,
    )

    rc = verify_main([str(minimal_d)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "VERIFIED" in out


def test_sign_embed_rejects_sidecar_path(minimal_d, minimal_config_bytes, tmp_path):
    """embed=True + sidecar_path is a usage error; refuse loudly."""
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)
    with pytest.raises(ValueError):
        sign_simulation_output(
            d_path=minimal_d,
            ground_truth_path=None,
            config_path=config_path,
            experiment_name="oops",
            simulator_version="0.1",
            sidecar_path=tmp_path / "out.provenance.json",
            embed=True,
        )


# ---------------------------------------------------------------------------
# Discovery / dispatch
# ---------------------------------------------------------------------------


def test_find_provenance_prefers_embedded_when_both_exist(
    minimal_d, minimal_config_bytes, tmp_path
):
    """When a .d has both an embedded row and a sibling JSON sidecar,
    discovery returns the embedded transport (in-band is authoritative).
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    # Sign once to produce the JSON sidecar...
    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="dual",
        simulator_version="0.1",
    )
    assert (minimal_d.parent / "dual.provenance.json").is_file()

    # ...then sign again with --embed so both transports exist.
    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="dual",
        simulator_version="0.1",
        embed=True,
    )

    discovery = find_provenance_for(minimal_d)
    assert discovery is not None
    transport, _ = discovery
    assert transport == "embedded-d"


def test_find_provenance_falls_back_to_json(
    minimal_d, minimal_config_bytes, tmp_path
):
    """When no embedded row exists, discovery returns the JSON sidecar."""
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="json_only",
        simulator_version="0.1",
    )

    discovery = find_provenance_for(minimal_d)
    assert discovery is not None
    transport, path = discovery
    assert transport == "sidecar-json"
    assert path == minimal_d.parent / "json_only.provenance.json"


def test_find_provenance_returns_none_when_unsigned(minimal_d):
    assert find_provenance_for(minimal_d) is None


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_d_after_embed_caught_as_hash_mismatch(
    minimal_d, minimal_config_bytes, tmp_path, capsys
):
    """Modifying a non-provenance row in the .d after embedding must
    surface as a HASH_MISMATCH at verify time.
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="tamper",
        simulator_version="0.1",
        embed=True,
    )

    # Tamper with a Frames row.
    with sqlite3.connect(str(minimal_d / "analysis.tdf")) as conn:
        conn.execute("UPDATE Frames SET Time = 999.0 WHERE Id = 1;")
        conn.commit()

    rc = verify_main([str(minimal_d)])
    assert rc == EXIT_HASH_MISMATCH


def test_not_quiescent_d_with_sibling_json_does_not_silently_verify(
    minimal_d, minimal_config_bytes, tmp_path, capsys
):
    """Regression: a .d with a stale -wal sidecar AND a sibling JSON
    sidecar must NOT silently verify against the JSON. Per
    spec/embedded-d-v0.md §6.2, embedded discovery errors MUST
    propagate; quietly accepting the JSON would mask a broken embed.
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    # Sign in JSON-sidecar mode so a sibling .provenance.json exists.
    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="quiet_check",
        simulator_version="0.1",
    )
    sidecar_json = minimal_d.parent / "quiet_check.provenance.json"
    assert sidecar_json.is_file(), "JSON sidecar prerequisite"

    # Plant a stale -wal next to analysis.tdf.
    wal = (minimal_d / "analysis.tdf").with_name("analysis.tdf-wal")
    wal.write_bytes(b"")
    try:
        rc = verify_main([str(minimal_d)])
        assert rc == EXIT_SIDECAR_ERROR, (
            f"expected SIDECAR_ERROR (3) for not-quiescent .d, got {rc}; "
            "the verifier silently fell back to the JSON sidecar"
        )
    finally:
        wal.unlink()


def test_embedded_only_experiment_dir_is_discovered(
    minimal_d, minimal_config_bytes, tmp_path, capsys
):
    """Regression: an experiment directory containing an embedded-only
    .d (no sibling .provenance.json) must be discovered and verified
    when the user passes the experiment dir, not the .d. Per
    spec/embedded-d-v0.md §6.1 the verifier descends into a unique .d
    for the embedded probe before falling back to JSON discovery.
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="embed_only",
        simulator_version="0.1",
        embed=True,
    )
    # The .d's parent is the experiment directory in this test layout.
    experiment_dir = minimal_d.parent
    assert list(experiment_dir.glob("*.provenance.json")) == [], (
        "test invariant: no JSON sidecar should exist"
    )

    rc = verify_main([str(experiment_dir)])
    assert rc == EXIT_OK, f"expected VERIFIED, got exit {rc}"
    out = capsys.readouterr().out
    assert "VERIFIED" in out


def test_experiment_dir_with_both_transports_prefers_embedded(
    minimal_d, minimal_config_bytes, tmp_path
):
    """When both an embedded .d and a sibling JSON sidecar exist in an
    experiment directory, discovery must prefer embedded (per
    spec/embedded-d-v0.md §6 — embedded is in-band and authoritative).
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="dual2",
        simulator_version="0.1",
    )
    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="dual2",
        simulator_version="0.1",
        embed=True,
    )

    discovery = find_provenance_for(minimal_d.parent)
    assert discovery is not None
    transport, resolved = discovery
    assert transport == "embedded-d"
    assert resolved == minimal_d


def test_tamper_embedded_envelope_caught(
    minimal_d, minimal_config_bytes, tmp_path
):
    """Editing the embedded envelope JSON itself breaks signature
    verification (or trips the key_id consistency check) — never
    silently passes.
    """
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(minimal_config_bytes)

    sign_simulation_output(
        d_path=minimal_d,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name="env_tamper",
        simulator_version="0.1",
        embed=True,
    )

    raw = read_embedded_provenance(minimal_d)
    assert raw is not None
    envelope = json.loads(raw.decode("utf-8"))
    envelope["payload"]["experiment_name"] = "MUTATED"
    write_embedded_provenance(
        minimal_d, json.dumps(envelope, sort_keys=True).encode("utf-8")
    )

    # Either signature or key_id-consistency catches this. We don't
    # care which — just that verification does not pass.
    try:
        result = verify_embedded_d(minimal_d)
        assert result.overall_ok is False
    except MalformedSidecar:
        pass  # key_id consistency check tripped — also a valid catch
