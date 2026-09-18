"""Tests for the SCIEX ``.wiff`` bundle canonicalization, signing, and verification path.

A SCIEX acquisition is an undocumented proprietary binary AND a *bundle*: the ``.wiff``
(OLE2 method + scan directory), the sibling ``.wiff.scan`` (packed spectra), usually a
``.wiff2``, and sometimes a ``.timeseries.data``. Like a Thermo ``.raw`` it cannot be
structurally canonicalized and has no safe embed injection point, so its attestation is an
OPAQUE whole-BUNDLE SHA-256 and is sidecar-only. Unlike ``.raw``, the hash must cover every
bundle member (the spectra live in ``.wiff.scan`` — hashing the ``.wiff`` alone attests
nothing about the data). These tests exercise:

  - the opaque bundle canonicalization (covers every member, binds basename AND bytes,
    order-independent, sensitive to any byte change / member add / member rename)
  - the composed content hash and its distinct domain prefix
  - a sign + verify round trip (with and without a config)
  - the config-copy exclusion regression: the ``{stem}.config.toml`` copy the signer writes
    must NOT be folded into the bundle hash, else verify recomputes a different member set
    than sign saw and always mismatches
  - tamper detection: flipping one byte of ANY bundle member must mismatch
    ``wiff_content_hash`` and ``content_hash`` while the signature stays valid
  - the sidecar-only invariant: a ``.provenance.json`` is written and no embed is performed
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mzprov import (
    sign_wiff_output,
    verify_sidecar,
)
from mzprov.canonicalize_wiff import (
    canonicalize_wiff,
    compose_wiff_content_hash,
    wiff_bundle_members,
)
from mzprov.envelope import (
    ATTESTATION_TYPE_WIFF,
    WiffSidecar,
    parse_sidecar,
)
from mzprov.errors import MissingArtifact
from mzprov.keys import generate_keypair, write_keypair


BASE = "sample"


def _make_dummy_wiff(directory: Path, name: str = BASE) -> Path:
    """Write a small dummy ``.wiff`` bundle: ``.wiff`` + ``.wiff.scan`` + ``.wiff2`` +
    ``.timeseries.data``. The bytes are arbitrary — the opaque hash assumes no structure."""
    directory.mkdir(parents=True, exist_ok=True)
    wiff = directory / f"{name}.wiff"
    wiff.write_bytes(b"\x01\xA1WIFFxOLE" + bytes(range(256)) * 2)
    (directory / f"{name}.wiff.scan").write_bytes(b"SCAN" + bytes(range(256)) * 8)
    (directory / f"{name}.wiff2").write_bytes(b"WIFF2" + bytes(range(128)) * 3)
    (directory / f"{name}.timeseries.data").write_bytes(b"TS" + bytes(range(64)))
    return wiff


def _write_temp_key(tmp_path: Path) -> Path:
    key_dir = tmp_path / "keys"
    write_keypair(generate_keypair(), key_dir)
    return key_dir / "signing_key.pem"


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def test_canonicalize_wiff_idempotent(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    assert canonicalize_wiff(wiff) == canonicalize_wiff(wiff)


def test_bundle_members_cover_every_sibling(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    names = {m.name for m in wiff_bundle_members(wiff)}
    assert names == {
        f"{BASE}.wiff",
        f"{BASE}.wiff.scan",
        f"{BASE}.wiff2",
        f"{BASE}.timeseries.data",
    }


def test_canonicalize_wiff_covers_scan_member(tmp_path):
    """Editing the .wiff.scan (spectra) member must change the bundle hash — the whole point
    of a bundle hash vs a single-file hash."""
    wiff = _make_dummy_wiff(tmp_path)
    h0 = canonicalize_wiff(wiff)
    scan = tmp_path / f"{BASE}.wiff.scan"
    b = bytearray(scan.read_bytes())
    b[len(b) // 2] ^= 0xFF
    scan.write_bytes(b)
    assert canonicalize_wiff(wiff) != h0


def test_canonicalize_wiff_detects_added_member(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    h0 = canonicalize_wiff(wiff)
    (tmp_path / f"{BASE}.rogue.data").write_bytes(b"injected")
    assert canonicalize_wiff(wiff) != h0


def test_canonicalize_wiff_detects_renamed_member(tmp_path):
    """Renaming a member (same bytes, different name) must change the hash — the hash binds
    each member's basename, not just its content."""
    wiff = _make_dummy_wiff(tmp_path)
    h0 = canonicalize_wiff(wiff)
    (tmp_path / f"{BASE}.wiff2").rename(tmp_path / f"{BASE}.wiff2renamed")
    assert canonicalize_wiff(wiff) != h0


def test_canonicalize_wiff_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        canonicalize_wiff(tmp_path / "nope.wiff")


def test_compose_wiff_content_hash_distinct_domain(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    wiff_hash = canonicalize_wiff(wiff)
    config_hash = hashlib.sha256(b"cfg").digest()
    composed = compose_wiff_content_hash(wiff_hash=wiff_hash, config_hash=config_hash)
    # Must NOT be a naive concat-hash and must differ from the raw wiff hash.
    assert composed != wiff_hash
    assert composed != hashlib.sha256(wiff_hash + config_hash).digest()


def test_compose_wiff_content_hash_validates_lengths():
    with pytest.raises(ValueError):
        compose_wiff_content_hash(wiff_hash=b"short", config_hash=bytes(32))
    with pytest.raises(ValueError):
        compose_wiff_content_hash(wiff_hash=bytes(32), config_hash=b"short")


# ---------------------------------------------------------------------------
# Sign + verify
# ---------------------------------------------------------------------------

def test_sign_wiff_writes_sidecar_only_no_embed(tmp_path):
    """sign_wiff_output writes a {stem}.provenance.json and leaves every bundle member's
    bytes untouched."""
    wiff = _make_dummy_wiff(tmp_path)
    before = {m.name: m.read_bytes() for m in wiff_bundle_members(wiff)}
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "wiff_smoke"\n')
    key = _write_temp_key(tmp_path)

    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=config_path,
        experiment_name="wiff_smoke",
        private_key_path=key,
    )
    assert sidecar_path.name == f"{BASE}.provenance.json"
    assert sidecar_path.is_file()
    # No member was mutated by signing.
    after = {m.name: m.read_bytes() for m in wiff_bundle_members(wiff)}
    assert after == before

    parsed = parse_sidecar(sidecar_path.read_bytes())
    assert isinstance(parsed, WiffSidecar)
    assert parsed.type == ATTESTATION_TYPE_WIFF


def test_sign_then_verify_wiff_round_trip(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "wiff_smoke"\n')
    key = _write_temp_key(tmp_path)

    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=config_path,
        experiment_name="wiff_smoke",
        private_key_path=key,
    )
    result = verify_sidecar(sidecar_path)
    assert result.overall_ok
    assert result.signature_ok
    assert all(c.status == "ok" for c in result.checks)


def test_config_copy_is_not_folded_into_bundle_hash(tmp_path):
    """Regression: the signer writes a ``{stem}.config.toml`` copy beside the bundle, which
    shares the bundle stem prefix. It is an attestation OUTPUT, not a signed INPUT, and must
    be excluded from the bundle hash — else verify recomputes a member set that includes the
    config copy (absent when sign hashed) and always mismatches."""
    wiff = _make_dummy_wiff(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "wiff_cfg"\n')
    key = _write_temp_key(tmp_path)

    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=config_path,
        experiment_name="wiff_cfg",
        private_key_path=key,
    )
    # The config copy exists beside the bundle and shares the stem...
    config_copy = tmp_path / f"{BASE}.config.toml"
    assert config_copy.is_file()
    # ...but it is NOT a bundle member.
    assert config_copy.name not in {m.name for m in wiff_bundle_members(wiff)}
    # ...and verify passes despite the copy sitting in the directory.
    assert verify_sidecar(sidecar_path).overall_ok


def test_sign_wiff_no_config_round_trip(tmp_path):
    """config_path=None signs sha256(b"") and verifies without a config copy."""
    wiff = _make_dummy_wiff(tmp_path)
    key = _write_temp_key(tmp_path)
    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=None,
        experiment_name="wiff_noconfig",
        private_key_path=key,
    )
    result = verify_sidecar(sidecar_path)
    assert result.overall_ok
    # No config copy was written.
    assert not (tmp_path / f"{BASE}.config.toml").exists()


@pytest.mark.parametrize("member", [f"{BASE}.wiff", f"{BASE}.wiff.scan", f"{BASE}.wiff2"])
def test_tamper_any_member_flips_content_checks_signature_still_ok(tmp_path, member):
    """Flipping one byte of ANY bundle member mismatches wiff_content_hash + content_hash,
    while the signature stays valid (it is over the payload, not the artifact)."""
    wiff = _make_dummy_wiff(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nname = "wiff_smoke"\n')
    key = _write_temp_key(tmp_path)

    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=config_path,
        experiment_name="wiff_smoke",
        private_key_path=key,
    )
    assert verify_sidecar(sidecar_path).overall_ok

    target = tmp_path / member
    b = bytearray(target.read_bytes())
    b[0] ^= 0xFF
    target.write_bytes(b)

    result = verify_sidecar(sidecar_path)
    assert not result.overall_ok
    assert result.signature_ok  # payload signature is intact
    statuses = {c.name: c.status for c in result.checks}
    assert statuses["wiff_content_hash"] == "mismatch"
    assert statuses["content_hash"] == "mismatch"


def test_verify_wiff_missing_artifact_raises(tmp_path):
    wiff = _make_dummy_wiff(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b"x = 1\n")
    key = _write_temp_key(tmp_path)

    sidecar_path = sign_wiff_output(
        wiff_path=wiff,
        config_path=config_path,
        experiment_name="wiff_gone",
        private_key_path=key,
    )
    # Remove the .wiff anchor: the artifact the sidecar attests is gone.
    wiff.unlink()
    with pytest.raises(MissingArtifact):
        verify_sidecar(sidecar_path)
