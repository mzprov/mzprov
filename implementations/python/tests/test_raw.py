"""Tests for the Thermo ``.raw`` canonicalization, signing, and verification path.

A Thermo ``.raw`` is an undocumented proprietary binary: it cannot be
structurally canonicalized and has no safe embed injection point. Its
attestation is therefore an OPAQUE whole-file SHA-256 and is
sidecar-only (no embed transport). These tests exercise:

  - the opaque canonicalization (whole-file hash, domain prefix,
    sensitivity to any byte change, FileNotFoundError on a missing file)
  - the composed content hash and its distinct domain prefix
  - a sign + verify round trip
  - tamper detection: flipping one byte of the .raw must mismatch
    ``raw_content_hash`` and ``content_hash`` while the signature stays
    valid (the signature is over the payload, not the artifact)
  - the sidecar-only invariant: a ``.provenance.json`` is written and no
    embed is performed
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mzprov import (
    canonicalize_raw,
    sign_raw_output,
    verify_sidecar,
)
from mzprov.canonicalize_raw import compose_raw_content_hash
from mzprov.envelope import (
    ATTESTATION_TYPE_RAW,
    RawSidecar,
    parse_sidecar,
)
from mzprov.errors import MissingArtifact
from mzprov.keys import generate_keypair, write_keypair


def _make_dummy_raw(directory: Path, name: str = "sample") -> Path:
    """Write a small dummy .raw file. Its bytes are arbitrary — the whole
    point of the opaque hash is that no internal structure is assumed."""
    directory.mkdir(parents=True, exist_ok=True)
    raw_path = directory / f"{name}.raw"
    # A plausible-looking header magic plus some payload bytes; nothing
    # about this needs to be a real Thermo container.
    raw_path.write_bytes(b"\x01\xA1RAWxFILE" + bytes(range(256)) * 4)
    return raw_path


def _write_temp_key(tmp_path: Path) -> Path:
    key_dir = tmp_path / "keys"
    write_keypair(generate_keypair(), key_dir)
    return key_dir / "signing_key.pem"


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def test_canonicalize_raw_idempotent(tmp_path):
    p = _make_dummy_raw(tmp_path)
    assert canonicalize_raw(p) == canonicalize_raw(p)


def test_canonicalize_raw_is_domain_prefixed_whole_file(tmp_path):
    """The hash is exactly the domain-prefixed SHA-256 of the file bytes."""
    p = _make_dummy_raw(tmp_path)
    expected = hashlib.sha256(b"TIMSIM-RAW-CANONICAL-v0\x1f" + p.read_bytes()).digest()
    assert canonicalize_raw(p) == expected
    assert len(canonicalize_raw(p)) == 32


def test_canonicalize_raw_sensitive_to_any_byte(tmp_path):
    """Flipping a single byte changes the opaque hash."""
    p = _make_dummy_raw(tmp_path)
    h_before = canonicalize_raw(p)
    data = bytearray(p.read_bytes())
    data[10] ^= 0x01
    p.write_bytes(bytes(data))
    assert canonicalize_raw(p) != h_before


def test_canonicalize_raw_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        canonicalize_raw(tmp_path / "does-not-exist.raw")


def test_compose_raw_content_hash_distinct_domain(tmp_path):
    """The composed hash uses the timsim.raw.v0 domain prefix."""
    raw_hash = b"\x11" * 32
    config_hash = b"\x22" * 32
    expected = hashlib.sha256(
        b"timsim.raw.v0\x1f" + raw_hash + b"\x1f" + config_hash
    ).digest()
    assert compose_raw_content_hash(raw_hash=raw_hash, config_hash=config_hash) == expected


def test_compose_raw_content_hash_validates_lengths():
    with pytest.raises(ValueError):
        compose_raw_content_hash(raw_hash=b"\x00" * 31, config_hash=b"\x00" * 32)
    with pytest.raises(ValueError):
        compose_raw_content_hash(raw_hash=b"\x00" * 32, config_hash=b"\x00" * 16)


# ---------------------------------------------------------------------------
# Sign + verify round trip
# ---------------------------------------------------------------------------


def test_sign_raw_writes_sidecar_only_no_embed(tmp_path):
    """sign_raw_output writes a {stem}.provenance.json and leaves the .raw bytes untouched."""
    raw_path = _make_dummy_raw(tmp_path)
    raw_before = raw_path.read_bytes()
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "raw_smoke"\n')
    key_path = _write_temp_key(tmp_path)

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=config_path,
        experiment_name="raw_smoke",
        tool_version="test",
        private_key_path=key_path,
    )

    # The default sidecar is {stem}.provenance.json next to the .raw.
    assert sidecar_path == raw_path.with_name(raw_path.stem + ".provenance.json")
    assert sidecar_path.is_file()
    # Sidecar-only: the .raw bytes are not modified (no embed).
    assert raw_path.read_bytes() == raw_before

    parsed = parse_sidecar(sidecar_path.read_bytes())
    assert isinstance(parsed, RawSidecar)
    assert parsed.type == ATTESTATION_TYPE_RAW


def test_sign_then_verify_raw_round_trip(tmp_path):
    raw_path = _make_dummy_raw(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "raw_smoke"\n')
    key_path = _write_temp_key(tmp_path)

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=config_path,
        experiment_name="raw_smoke",
        tool_version="test",
        private_key_path=key_path,
    )

    result = verify_sidecar(sidecar_path)
    assert result.overall_ok
    assert result.signature_ok
    assert all(c.ok for c in result.checks)
    names = {c.name for c in result.checks}
    assert names == {"raw_content_hash", "config_hash", "content_hash"}


def test_sign_raw_no_config_round_trip(tmp_path):
    """config_path=None signs sha256(b"") and verifies without a config copy."""
    raw_path = _make_dummy_raw(tmp_path)
    key_path = _write_temp_key(tmp_path)

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=None,
        experiment_name="raw_smoke",
        private_key_path=key_path,
    )
    # No config copy is written next to the sidecar.
    assert not (tmp_path / f"{raw_path.stem}.config.toml").exists()

    result = verify_sidecar(sidecar_path)
    assert result.overall_ok
    assert result.signature_ok


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_raw_byte_flips_content_checks_signature_still_ok(tmp_path):
    raw_path = _make_dummy_raw(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "raw_smoke"\n')
    key_path = _write_temp_key(tmp_path)

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=config_path,
        experiment_name="raw_smoke",
        private_key_path=key_path,
    )
    assert verify_sidecar(sidecar_path).overall_ok

    # Flip one byte of the .raw artifact.
    data = bytearray(raw_path.read_bytes())
    data[5] ^= 0xFF
    raw_path.write_bytes(bytes(data))

    result = verify_sidecar(sidecar_path)
    assert not result.overall_ok
    # Signature is over the payload, not the artifact, so it stays valid.
    assert result.signature_ok

    checks = {c.name: c for c in result.checks}
    assert checks["raw_content_hash"].status == "mismatch"
    assert checks["content_hash"].status == "mismatch"
    # The config was untouched, so its check still passes.
    assert checks["config_hash"].status == "ok"


def test_verify_raw_missing_artifact_raises(tmp_path):
    raw_path = _make_dummy_raw(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b"x = 1\n")
    key_path = _write_temp_key(tmp_path)

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=config_path,
        experiment_name="raw_smoke",
        private_key_path=key_path,
    )
    raw_path.unlink()
    with pytest.raises(MissingArtifact):
        verify_sidecar(sidecar_path)
