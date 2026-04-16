"""Tests for the embedded-mzml-v0 transport.

Mirrors test_embed_d.py for mzML. Covers:
  - Round-trip embed/read in isolation.
  - Exclusion correctness: hash before == hash after embed.
  - End-to-end sign(--embed) + verify_embedded_mzml.
  - Verifier dispatch: prefer embedded over JSON sidecar.
  - Verifier fall-back to JSON sidecar when no embedded slot.
  - Tamper detection (data: corrupt a spectrum's binary array;
    envelope: mutate the userParam value).
  - Single-row invariant on re-sign.
  - Embedded-only experiment-dir descent.
  - Strip indexedmzML wrapper on embed (the v1 behavior).
"""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from mzprov import canonicalize_mzml
from mzprov._fixtures import make_minimal_mzml
from mzprov.cli import (
    EXIT_HASH_MISMATCH,
    EXIT_OK,
    EXIT_SIDECAR_ERROR,
    main as verify_main,
)
from mzprov.embed_mzml import (
    EMBEDDED_USERPARAM_NAME,
    has_embedded_provenance,
    read_embedded_provenance,
    write_embedded_provenance,
)
from mzprov.errors import MalformedSidecar, Unsigned
from mzprov.sign import sign_mzml_output
from mzprov.verify import (
    find_provenance_for,
    verify_embedded_mzml,
)

NS = "{http://psi.hupo.org/ms/mzml}"


# ---------------------------------------------------------------------------
# embed_mzml module — round-trip and exclusion correctness
# ---------------------------------------------------------------------------


def test_embed_mzml_round_trip(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="round-trip")
    envelope = b'{"type": "timsim.provenance.mzml.v0", "payload": {}, "signature": "x", "verifying_key": "y"}'
    write_embedded_provenance(mzml, envelope)
    assert read_embedded_provenance(mzml) == envelope


def test_embed_mzml_exclusion_correctness(tmp_path):
    """hash(mzml) before embed must equal hash(mzml) after embed.

    fileDescription is out of scope for the canonical hash per
    spec/canonicalization-mzml-v0.md §2, so inserting our userParam
    must not perturb the digest.
    """
    mzml = make_minimal_mzml(tmp_path, name="excl")
    h_before = canonicalize_mzml(mzml)
    write_embedded_provenance(
        mzml,
        b'{"type": "timsim.provenance.mzml.v0", "payload": {}, "signature": "x", "verifying_key": "y"}',
    )
    h_after = canonicalize_mzml(mzml)
    assert h_before == h_after


def test_embed_mzml_strips_indexed_wrapper(tmp_path):
    """The signer protocol §5 step 6: output must be plain <mzML>, not <indexedmzML>."""
    mzml = make_minimal_mzml(tmp_path, name="indexed", indented=True)
    # Confirm the fixture starts indexed.
    text = mzml.read_text()
    assert "<indexedmzML" in text, "test invariant: fixture should be indexed-wrapped"

    write_embedded_provenance(mzml, b"{}")

    text = mzml.read_text()
    assert "<indexedmzML" not in text, "embedded write must strip the indexedmzML wrapper"


def test_embed_mzml_replace_keeps_single_param(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="replace")
    write_embedded_provenance(mzml, b'{"v": 1}')
    write_embedded_provenance(mzml, b'{"v": 2}')

    assert read_embedded_provenance(mzml) == b'{"v": 2}'

    # Direct XML inspection: only one mzprov:provenance userParam.
    tree = ET.parse(mzml)
    root = tree.getroot()
    fc = root.find(f"{NS}fileDescription/{NS}fileContent")
    matches = [
        up for up in fc.findall(f"{NS}userParam")
        if up.get("name") == EMBEDDED_USERPARAM_NAME
    ]
    assert len(matches) == 1


def test_read_returns_none_when_no_userparam(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="bare")
    assert read_embedded_provenance(mzml) is None
    assert has_embedded_provenance(mzml) is False


def test_read_refuses_multiple_userparams(tmp_path):
    """If somehow more than one mzprov:provenance userParam exists,
    the reader raises MalformedSidecar (per spec §6, validation table).
    """
    mzml = make_minimal_mzml(tmp_path, name="dup")
    write_embedded_provenance(mzml, b'{"v": 1}')

    # Hand-craft a duplicate.
    ET.register_namespace("", "http://psi.hupo.org/ms/mzml")
    tree = ET.parse(mzml)
    root = tree.getroot()
    fc = root.find(f"{NS}fileDescription/{NS}fileContent")
    dup = ET.SubElement(fc, f"{NS}userParam")
    dup.set("name", EMBEDDED_USERPARAM_NAME)
    dup.set(
        "value",
        base64.standard_b64encode(b'{"v": 2}').decode("ascii"),
    )
    tree.write(mzml, encoding="utf-8", xml_declaration=True)

    with pytest.raises(MalformedSidecar):
        read_embedded_provenance(mzml)


def test_read_refuses_invalid_base64(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="bad-b64")
    write_embedded_provenance(mzml, b"{}")
    # Mangle the base64 with chars outside the alphabet.
    ET.register_namespace("", "http://psi.hupo.org/ms/mzml")
    tree = ET.parse(mzml)
    root = tree.getroot()
    fc = root.find(f"{NS}fileDescription/{NS}fileContent")
    for up in fc.findall(f"{NS}userParam"):
        if up.get("name") == EMBEDDED_USERPARAM_NAME:
            up.set("value", "***not base64***")
    tree.write(mzml, encoding="utf-8", xml_declaration=True)

    with pytest.raises(MalformedSidecar):
        read_embedded_provenance(mzml)


# ---------------------------------------------------------------------------
# End-to-end sign + verify with --embed
# ---------------------------------------------------------------------------


def test_sign_embed_then_verify(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="e2e")
    result_path = sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="e2e-embed",
        tool_name="mzprov-test",
        tool_version="0.1",
        embed=True,
    )
    assert result_path == mzml, "embed mode returns the mzml path"

    # No JSON sidecar should have been written.
    assert list(tmp_path.glob("*.provenance.json")) == []

    result = verify_embedded_mzml(mzml)
    assert result.overall_ok is True
    assert result.transport == "embedded-mzml"
    assert result.signature_ok is True


def test_verify_embedded_mzml_via_cli(tmp_path, capsys):
    """`mzprov verify <mzml>` discovers the embedded slot and verifies."""
    mzml = make_minimal_mzml(tmp_path, name="cli-mzml")
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="cli-embed",
        tool_name="mzprov-test",
        tool_version="0.1",
        embed=True,
    )
    rc = verify_main([str(mzml)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "VERIFIED" in out


def test_sign_embed_rejects_sidecar_path(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="oops")
    with pytest.raises(ValueError):
        sign_mzml_output(
            mzml_path=mzml,
            config_path=None,
            experiment_name="oops",
            tool_name="x",
            tool_version="0.1",
            sidecar_path=tmp_path / "out.provenance.json",
            embed=True,
        )


def test_verify_embedded_mzml_unsigned_when_no_userparam(tmp_path):
    """Calling verify_embedded_mzml on a bare mzml raises Unsigned."""
    mzml = make_minimal_mzml(tmp_path, name="bare2")
    with pytest.raises(Unsigned):
        verify_embedded_mzml(mzml)


# ---------------------------------------------------------------------------
# Discovery / dispatch
# ---------------------------------------------------------------------------


def test_find_provenance_prefers_embedded_when_both_exist(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="dual")
    # First sign in JSON-sidecar mode...
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="dual",
        tool_name="x",
        tool_version="0.1",
    )
    json_sidecar = tmp_path / "dual.provenance.json"
    assert json_sidecar.is_file()

    # ...then sign with --embed so both transports exist.
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="dual",
        tool_name="x",
        tool_version="0.1",
        embed=True,
    )

    discovery = find_provenance_for(mzml)
    assert discovery is not None
    transport, _ = discovery
    assert transport == "embedded-mzml"


def test_find_provenance_falls_back_to_json(tmp_path):
    mzml = make_minimal_mzml(tmp_path, name="json_only")
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="json_only",
        tool_name="x",
        tool_version="0.1",
    )
    discovery = find_provenance_for(mzml)
    assert discovery is not None
    transport, path = discovery
    assert transport == "sidecar-json"
    assert path == tmp_path / "json_only.provenance.json"


def test_embedded_mzml_experiment_dir_descent(tmp_path, capsys):
    """An experiment dir containing an embedded-only mzml is discovered."""
    exp = tmp_path / "experiment"
    exp.mkdir()
    mzml = make_minimal_mzml(exp, name="sample")
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="dir-embed",
        tool_name="x",
        tool_version="0.1",
        embed=True,
    )
    rc = verify_main([str(exp)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "VERIFIED" in out


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_mzml_data_after_embed_caught_as_hash_mismatch(tmp_path):
    """Modifying a spectrum binary after embedding must surface as HASH_MISMATCH."""
    mzml = make_minimal_mzml(tmp_path, name="tamper-data")
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="tamper-data",
        tool_name="x",
        tool_version="0.1",
        embed=True,
    )

    # Corrupt one of the <binary> elements.
    text = mzml.read_text()
    # Find the first <binary>...</binary> and flip a base64 character.
    idx = text.find("<binary>")
    end = text.find("</binary>", idx)
    assert idx > 0 and end > idx
    payload = text[idx + len("<binary>"):end]
    # Swap the first character to its alphabet neighbor.
    swapped = ("B" if payload[0] == "A" else "A") + payload[1:]
    text = text[:idx + len("<binary>")] + swapped + text[end:]
    mzml.write_text(text)

    rc = verify_main([str(mzml)])
    assert rc == EXIT_HASH_MISMATCH, f"expected HASH_MISMATCH (5), got {rc}"


def test_tamper_embedded_envelope_caught(tmp_path):
    """Mutating the envelope JSON inside the userParam fails verification."""
    mzml = make_minimal_mzml(tmp_path, name="tamper-env")
    sign_mzml_output(
        mzml_path=mzml,
        config_path=None,
        experiment_name="tamper-env",
        tool_name="x",
        tool_version="0.1",
        embed=True,
    )

    raw = read_embedded_provenance(mzml)
    assert raw is not None
    envelope = json.loads(raw.decode("utf-8"))
    envelope["payload"]["experiment_name"] = "MUTATED"
    write_embedded_provenance(
        mzml, json.dumps(envelope, sort_keys=True).encode("utf-8")
    )

    # Either signature mismatch (overall_ok=False) or key_id consistency
    # (MalformedSidecar) catches this. Both are valid; what's NOT valid
    # is silent VERIFIED.
    try:
        result = verify_embedded_mzml(mzml)
        assert result.overall_ok is False
    except MalformedSidecar:
        pass
