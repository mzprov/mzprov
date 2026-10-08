"""Tests for the ``mzprov-mcp`` server (mzprov.mcp_server).

The tool functions are called directly; one test goes through the MCP
server's own ``call_tool`` to check registration and serialization.
Skipped when the ``mcp`` extra is not installed.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mzprov import sign_simulation_output  # noqa: E402
from mzprov.cli import main as verify_cli_main  # noqa: E402
from mzprov.keys import generate_keypair, write_keypair  # noqa: E402
from mzprov.mcp_server import (  # noqa: E402
    build_server,
    find_provenance,
    list_trusted_keys,
    show_signing_key,
    sign,
    verify,
)
from mzprov.trust import TrustedKeyRegistry, trusted_key_from_public_key  # noqa: E402

from mzprov._fixtures import make_minimal_mzml  # noqa: E402

from .conftest import (  # noqa: E402
    make_minimal_d,
    make_minimal_ground_truth,
    tamper_sql_value,
)


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    """Point ~/.config at a temp dir so no test touches the real key or registry."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


def _signed_bundle(tmp_path: Path):
    d_path = make_minimal_d(tmp_path, name="bundle")
    ground_truth = make_minimal_ground_truth(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b'[experiment]\nexperiment_name = "bundle"\n')
    key_dir = tmp_path / "keys"
    keypair = generate_keypair()
    write_keypair(keypair, key_dir)
    sidecar_path = sign_simulation_output(
        d_path=d_path,
        ground_truth_path=ground_truth,
        config_path=config_path,
        experiment_name="bundle",
        simulator_version="test",
        private_key_path=key_dir / "signing_key.pem",
    )
    return d_path, sidecar_path, keypair


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_matches_cli_json(tmp_path, capsys):
    d_path, _, _ = _signed_bundle(tmp_path)

    result = verify(str(d_path))
    assert result["status"] == "verified"
    assert result["overall_ok"] is True
    assert result["exit_code"] == 0

    assert verify_cli_main([str(d_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(
        json.dumps(result, sort_keys=True)
    )


def test_verify_detects_tamper(tmp_path):
    d_path, _, _ = _signed_bundle(tmp_path)
    tamper_sql_value(
        d_path / "analysis.tdf",
        table="GlobalMetadata",
        set_column="Value",
        set_value="FAKE",
        where_column="Key",
        where_value="InstrumentName",
    )

    result = verify(str(d_path))
    assert result["status"] == "failed"
    assert result["overall_ok"] is False
    assert result["exit_code"] == 5


def test_verify_expected_key_id_mismatch(tmp_path):
    d_path, _, _ = _signed_bundle(tmp_path)

    result = verify(str(d_path), expected_key_id="timsim-local-aaaaaaaaaaaaaaaa")
    assert result["status"] == "failed"
    assert result["trust"]["status"] == "id_mismatch"
    assert result["exit_code"] == 7


def test_verify_unsigned(tmp_path):
    d_path = make_minimal_d(tmp_path, name="lonely")

    assert verify(str(d_path))["status"] == "unsigned"
    assert verify(str(d_path))["exit_code"] == 0
    assert verify(str(d_path), strict=True)["exit_code"] == 4


def test_verify_malformed_sidecar_is_error_not_exception(tmp_path):
    _, sidecar_path, _ = _signed_bundle(tmp_path)
    sidecar_path.write_text("{not json")

    result = verify(str(sidecar_path))
    assert result["status"] == "error"
    assert result["exit_code"] == 3
    assert result["error"]["type"] == "MalformedSidecar"


@pytest.mark.parametrize("strict", [False, True])
def test_verify_unsigned_matches_cli_json(tmp_path, capsys, strict):
    d_path = make_minimal_d(tmp_path, name="lonely")
    flags = ["--strict"] if strict else []

    result = verify(str(d_path), strict=strict)
    verify_cli_main([str(d_path), "--json", *flags])
    assert json.loads(capsys.readouterr().out) == result


def test_verify_corrupt_tdf_stays_in_schema(tmp_path):
    d_path = make_minimal_d(tmp_path, name="corrupt")
    (d_path / "analysis.tdf").write_bytes(b"this is not a sqlite database" * 10)

    result = verify(str(d_path))
    assert result["schema"] == "timsim.verify-result.v0"
    assert result["status"] == "error"
    assert result["exit_code"] == 1
    assert result["error"]["type"] == "DatabaseError"


def test_verify_relative_path(tmp_path, monkeypatch):
    _signed_bundle(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert verify("bundle.d")["status"] == "verified"


def test_verify_embedded_d_and_mzml(tmp_path):
    # Separate directories: a .d and an mzML with one stem in one directory
    # would share the {stem}.config.toml copy.
    (tmp_path / "d").mkdir()
    (tmp_path / "m").mkdir()
    d_path = make_minimal_d(tmp_path / "d", name="emb")
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b"[x]\n")
    mzml = make_minimal_mzml(tmp_path / "m", name="emb")

    sign(str(d_path), experiment_name="emb", config=str(config_path), embed=True)
    sign(str(mzml), experiment_name="emb", embed=True)

    assert verify(str(d_path))["status"] == "verified"
    assert verify(str(mzml))["status"] == "verified"
    assert find_provenance(str(d_path))["transport"] == "embedded-d"
    assert find_provenance(str(mzml))["transport"] == "embedded-mzml"


# ---------------------------------------------------------------------------
# find_provenance
# ---------------------------------------------------------------------------


def test_find_provenance_returns_unverified_payload(tmp_path):
    d_path, sidecar_path, keypair = _signed_bundle(tmp_path)

    found = find_provenance(str(d_path))
    assert found["found"] is True
    assert found["verified"] is False
    assert found["transport"] == "sidecar-json"
    assert found["location"] == str(sidecar_path)
    assert found["payload"]["experiment_name"] == "bundle"
    assert found["payload"]["key_id"] == keypair.key_id


def test_find_provenance_unsigned(tmp_path):
    d_path = make_minimal_d(tmp_path, name="lonely")
    assert find_provenance(str(d_path))["found"] is False


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


def test_show_signing_key_never_creates_a_key(tmp_path):
    shown = show_signing_key()
    assert shown["exists"] is False
    assert not (tmp_path / "xdg" / "mzprov" / "keys" / "signing_key.pem").exists()


def test_show_signing_key_reports_existing_key(tmp_path):
    keypair = generate_keypair()
    write_keypair(keypair, tmp_path / "keys")

    shown = show_signing_key(str(tmp_path / "keys"))
    assert shown["exists"] is True
    assert shown["key_id"] == keypair.key_id
    assert shown["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE" not in json.dumps(shown)


def test_list_trusted_keys(tmp_path):
    registry_path = tmp_path / "trusted.json"
    assert list_trusted_keys(str(registry_path))["keys"] == []

    keypair = generate_keypair()
    registry = TrustedKeyRegistry.load(registry_path)
    registry.add(trusted_key_from_public_key(keypair.public_key, comment="lab key"))
    registry.save()

    listed = list_trusted_keys(str(registry_path))
    assert [k["key_id"] for k in listed["keys"]] == [keypair.key_id]
    assert listed["keys"][0]["comment"] == "lab key"


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def test_sign_then_verify(tmp_path):
    d_path = make_minimal_d(tmp_path, name="fresh")
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b"[x]\n")

    signed = sign(str(d_path), experiment_name="fresh", config=str(config_path))
    assert signed["format"] == "d"
    assert Path(signed["signed"]).exists()
    assert signed["key_id"] == show_signing_key()["key_id"]
    assert verify(str(d_path), expected_key_id=signed["key_id"])["overall_ok"] is True


def test_sign_reports_signer_from_envelope(tmp_path, monkeypatch):
    """key_id comes from what was written, not from reloading the key."""
    import mzprov.keys

    # mzprov.sign bound its own reference at import, so this trips only on
    # a fresh reload of the key after signing.
    monkeypatch.setattr(
        mzprov.keys, "load_or_create_keypair",
        lambda *a, **k: pytest.fail("sign must not reload the key"),
    )
    mzml = make_minimal_mzml(tmp_path, name="who")
    for embed in (False, True):
        signed = sign(str(mzml), experiment_name="who", embed=embed)
        assert signed["key_id"] == show_signing_key()["key_id"]


@pytest.mark.parametrize("kind", ["d", "mzml"])
def test_sign_with_custom_sidecar_name(tmp_path, kind):
    """A non-default sidecar name: sign reads the written file directly, and
    a name verifiers would not recognize is refused."""
    if kind == "d":
        artifact = make_minimal_d(tmp_path, name="custom")
        config = tmp_path / "config.toml"
        config.write_bytes(b"[x]\n")
        extra = {"config": str(config)}
    else:
        artifact = make_minimal_mzml(tmp_path, name="custom")
        extra = {}
    with pytest.raises(ValueError, match=r"\.provenance\.json"):
        sign(str(artifact), experiment_name="custom",
             sidecar=str(tmp_path / "attestation.json"), **extra)

    target = tmp_path / "attestation.provenance.json"
    signed = sign(str(artifact), experiment_name="custom",
                  sidecar=str(target), **extra)
    assert signed["signed"] == str(target)
    assert signed["key_id"] == show_signing_key()["key_id"]
    assert verify(str(target))["status"] == "verified"


def test_sign_d_requires_config(tmp_path):
    d_path = make_minimal_d(tmp_path, name="fresh")
    with pytest.raises(ValueError, match="config is required"):
        sign(str(d_path), experiment_name="fresh")


def test_sign_rejects_unsignable_input(tmp_path):
    other = tmp_path / "notes.txt"
    other.write_text("hi")
    with pytest.raises(ValueError, match="not signable"):
        sign(str(other), experiment_name="x")


# ---------------------------------------------------------------------------
# server assembly
# ---------------------------------------------------------------------------


def _tool_names(server) -> set:
    return {t.name for t in asyncio.run(server.list_tools())}


def test_sign_tool_is_opt_in():
    read_only = {"verify", "find_provenance", "show_signing_key", "list_trusted_keys"}
    assert _tool_names(build_server()) == read_only
    assert _tool_names(build_server(allow_sign=True)) == read_only | {"sign"}


def test_trust_management_is_not_exposed():
    names = _tool_names(build_server(allow_sign=True))
    assert not {"trust", "untrust", "trust_key", "untrust_key"} & names


def test_annotations_are_honest():
    tools = {t.name: t for t in asyncio.run(build_server(allow_sign=True).list_tools())}
    assert tools["sign"].annotations.read_only_hint is False
    assert tools["sign"].annotations.destructive_hint is True
    for name in ("verify", "find_provenance", "show_signing_key", "list_trusted_keys"):
        assert tools[name].annotations.read_only_hint is True


def test_sign_rejected_without_allow_sign(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="nope")
    before = sorted(p.name for p in tmp_path.iterdir())
    try:
        result = asyncio.run(build_server().call_tool(
            "sign", {"path": str(mzml), "experiment_name": "nope"}
        ))
    except Exception:  # noqa: BLE001 - an exception is also a rejection
        pass
    else:
        assert result.is_error is True
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_read_only_tools_leave_filesystem_unchanged(tmp_path):
    root = tmp_path / ("odd#dir" if sys.platform == "win32" else "odd#dir?x=1")
    root.mkdir()
    d_path, sidecar_path, keypair = _signed_bundle(root)

    def snapshot():
        return sorted(
            (str(p.relative_to(tmp_path)), p.stat().st_size, p.stat().st_mtime_ns)
            for p in tmp_path.rglob("*")
        )

    before = snapshot()
    verify(str(d_path), require_trusted=True)
    find_provenance(str(d_path))
    show_signing_key()
    show_signing_key(str(root / "keys"))
    list_trusted_keys()
    assert snapshot() == before


def test_verify_through_server(tmp_path):
    d_path, _, _ = _signed_bundle(tmp_path)
    result = asyncio.run(build_server().call_tool("verify", {"path": str(d_path)}))
    assert result.is_error is False
    assert json.loads(result.content[0].text)["status"] == "verified"
