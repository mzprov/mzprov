"""``mzprov chain sign`` / ``mzprov chain verify`` through the unified CLI.

The chain logic itself is covered in test_chain.py; this checks the command
surface: argument handling, sidecar placement, and the exit codes.
"""
import json

from cryptography.hazmat.primitives import serialization

from mzprov.chain import (
    EXIT_BAD_SIG,
    EXIT_BROKEN_LINK,
    EXIT_INTEGRITY,
    EXIT_MALFORMED,
    EXIT_MISSING_PROV,
    EXIT_OK,
    EXIT_TRUST,
)
from mzprov.keys import load_or_create_keypair
from mzprov.main import main as mzprov
from mzprov.trust import TrustedKey, TrustedKeyRegistry


def _trust(tmp_path, keydir):
    kp = load_or_create_keypair(keydir)
    pem = kp.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    registry = tmp_path / "trusted.json"
    reg = TrustedKeyRegistry.load(registry)
    reg.add(TrustedKey(
        key_id=kp.key_id, public_key_pem=pem,
        comment="lab", added_at="2026-09-21T00:00:00Z",
    ))
    reg.save()
    return registry


def _build(tmp_path):
    keydir = tmp_path / "keys"
    load_or_create_keypair(keydir)
    raw = tmp_path / "run.raw"
    raw.write_bytes(b"genuine acquisition bytes")
    mzml = tmp_path / "run.mzML"
    mzml.write_bytes(b"<mzML>peak-picked from run.raw</mzML>")
    assert mzprov([
        "chain", "sign", str(raw), "--experiment-name", "acq001",
        "--tool-name", "Instrument", "--key", str(keydir),
    ]) == EXIT_OK
    assert mzprov([
        "chain", "sign", str(mzml), "--experiment-name", "acq001",
        "--tool-name", "msconvert",
        "--input", f"source_raw={raw}.chain.json", "--key", str(keydir),
    ]) == EXIT_OK
    return keydir, raw, mzml


def test_sign_then_verify_by_artifact_path(tmp_path, capsys):
    keydir, _, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    rc = mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(registry)])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "VERIFIED" in out
    assert out.count("signature OK") == 2


def test_verify_json(tmp_path, capsys):
    keydir, _, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    capsys.readouterr()
    rc = mzprov([
        "chain", "verify", f"{mzml}.chain.json",
        "--trusted-keys", str(registry), "--json",
    ])
    blob = json.loads(capsys.readouterr().out)
    assert rc == blob["exit_code"] == EXIT_OK
    assert [n["is_root"] for n in blob["nodes"]] == [False, True]


def test_untrusted_root_is_7(tmp_path):
    _, _, mzml = _build(tmp_path)
    empty = tmp_path / "none.json"
    assert mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(empty)]) == EXIT_TRUST


def test_tampered_parent_artifact_is_5(tmp_path):
    keydir, raw, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    raw.write_bytes(b"altered acquisition bytes")
    assert mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(registry)]) == EXIT_INTEGRITY


def test_forged_signature_is_6(tmp_path):
    keydir, _, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    sidecar = tmp_path / "run.mzML.chain.json"
    blob = json.loads(sidecar.read_text())
    blob["payload"]["tool_name"] = "someone-else"
    sidecar.write_text(json.dumps(blob))
    assert mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(registry)]) == EXIT_BAD_SIG


def test_missing_parent_sidecar_is_9(tmp_path):
    keydir, raw, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    (tmp_path / "run.raw.chain.json").unlink()
    assert mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(registry)]) == EXIT_MISSING_PROV


def test_malformed_sidecar_is_3(tmp_path):
    keydir, _, mzml = _build(tmp_path)
    registry = _trust(tmp_path, keydir)
    (tmp_path / "run.mzML.chain.json").write_text("not json")
    assert mzprov(["chain", "verify", str(mzml), "--trusted-keys", str(registry)]) == EXIT_MALFORMED


def test_codes_do_not_collide_with_v0(tmp_path):
    # 3-7 keep their v0 meanings; 8 and 9 are chain-only.
    assert (EXIT_MALFORMED, EXIT_INTEGRITY, EXIT_BAD_SIG, EXIT_TRUST) == (3, 5, 6, 7)
    assert (EXIT_BROKEN_LINK, EXIT_MISSING_PROV) == (8, 9)


def test_sign_rejects_malformed_input_spec(tmp_path, capsys):
    raw = tmp_path / "run.raw"
    raw.write_bytes(b"x")
    try:
        mzprov(["chain", "sign", str(raw), "--experiment-name", "e", "--input", "no-equals"])
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("argparse should reject ROLE=PATH without '='")


def test_sign_missing_parent_sidecar_is_3(tmp_path):
    mzml = tmp_path / "run.mzML"
    mzml.write_bytes(b"x")
    rc = mzprov([
        "chain", "sign", str(mzml), "--experiment-name", "e",
        "--input", f"source_raw={tmp_path / 'absent.chain.json'}",
        "--key", str(tmp_path / "keys"),
    ])
    assert rc == 3
