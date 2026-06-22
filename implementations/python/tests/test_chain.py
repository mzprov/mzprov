"""Provenance chain (v1) — RAW -> mzML lineage. Prototype, Python-only.

Proves the canonical example: a genuine RAW is signed as an acquisition root; an mzML is peak-picked
from it and signed referencing the RAW; a verifier walks mzML -> RAW back to the trusted lab key.
Then the failure modes: tamper the mzML, tamper the RAW, untrust the root, break the link, lose the
parent provenance.
"""
from cryptography.hazmat.primitives import serialization

from mzprov.keys import load_or_create_keypair
from mzprov.trust import TrustedKey, TrustedKeyRegistry
from mzprov.chain import (
    InputRef,
    sha256_hex,
    sign_derivation,
    make_input_ref,
    verify_chain,
    EXIT_OK,
    EXIT_MALFORMED,
    EXIT_INTEGRITY,
    EXIT_TRUST,
    EXIT_BROKEN_LINK,
    EXIT_MISSING_PROV,
)

RAW_BYTES = b"PROFILE-MS1+MS2 genuine acquisition bytes ........ (stand-in for a real .raw)"
MZML_BYTES = b"<mzML><run>centroided spectra peak-picked from run.raw</run></mzML>"


def _trust(kp) -> TrustedKey:
    pem = kp.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return TrustedKey(key_id=kp.key_id, public_key_pem=pem, comment="lab", added_at="2026-06-22T00:00:00Z")


def _lab_setup(tmp_path):
    keydir = tmp_path / "labkeys"
    lab = load_or_create_keypair(keydir)
    reg = TrustedKeyRegistry.load(tmp_path / "trusted.json")
    reg.add(_trust(lab))
    return keydir, reg


def _build_raw_then_mzml(tmp_path, keydir):
    raw = tmp_path / "run.raw"
    raw.write_bytes(RAW_BYTES)
    raw_sc = sign_derivation(
        artifact_path=raw, inputs=[], experiment_name="acq001",
        tool_name="Instrument", tool_version="1.0", private_key_path=keydir,
    )
    mzml = tmp_path / "run.mzML"
    mzml.write_bytes(MZML_BYTES)
    mzml_sc = sign_derivation(
        artifact_path=mzml, inputs=[make_input_ref("source_raw", raw_sc)],
        experiment_name="acq001", tool_name="MSConvert", tool_version="3.0.25296",
        private_key_path=keydir,
    )
    return raw, raw_sc, mzml, mzml_sc


def test_raw_to_mzml_chain_verifies(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    _, _, _, mzml_sc = _build_raw_then_mzml(tmp_path, keydir)

    res = verify_chain(mzml_sc, reg)
    assert res.ok, res.detail
    assert res.code == EXIT_OK
    # walked two nodes: the mzML leaf and the RAW root
    assert len(res.nodes) == 2
    roots = [n for n in res.nodes if n.is_root]
    assert len(roots) == 1 and roots[0].trusted
    assert all(n.signature_ok for n in res.nodes)


def test_tamper_mzml_breaks_integrity(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    _, _, mzml, mzml_sc = _build_raw_then_mzml(tmp_path, keydir)
    mzml.write_bytes(MZML_BYTES + b"  <!-- injected ENO1 fragment -->")
    res = verify_chain(mzml_sc, reg)
    assert res.code == EXIT_INTEGRITY


def test_tamper_raw_breaks_at_root(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    raw, _, _, mzml_sc = _build_raw_then_mzml(tmp_path, keydir)
    raw.write_bytes(RAW_BYTES + b"  tampered")
    res = verify_chain(mzml_sc, reg)
    # the root's artifact no longer matches its signed hash
    assert res.code == EXIT_INTEGRITY


def test_untrusted_root_fails(tmp_path):
    keydir, _ = _lab_setup(tmp_path)
    _, _, _, mzml_sc = _build_raw_then_mzml(tmp_path, keydir)
    empty = TrustedKeyRegistry.load(tmp_path / "empty.json")
    res = verify_chain(mzml_sc, empty)
    assert res.code == EXIT_TRUST


def test_broken_link_when_edge_hash_lies(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    raw, raw_sc, mzml, _ = _build_raw_then_mzml(tmp_path, keydir)
    # forge an edge that points at the real RAW sidecar but claims a different content hash
    good = make_input_ref("source_raw", raw_sc)
    forged = InputRef(role="source_raw", content_hash="sha256:" + "0" * 64,
                      parent_key_id=good.parent_key_id, parent_sidecar_hash=good.parent_sidecar_hash)
    mzml_sc = sign_derivation(
        artifact_path=mzml, inputs=[forged], experiment_name="acq001",
        tool_name="MSConvert", tool_version="3.0", private_key_path=keydir,
    )
    res = verify_chain(mzml_sc, reg)
    assert res.code == EXIT_BROKEN_LINK


def test_missing_parent_provenance(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    raw, raw_sc, mzml, mzml_sc = _build_raw_then_mzml(tmp_path, keydir)
    raw_sc.unlink()  # lose the RAW's provenance record
    res = verify_chain(mzml_sc, reg)
    assert res.code == EXIT_MISSING_PROV


def test_shared_ancestor_dag_verifies(tmp_path):
    # codex review repro: two edges reaching the SAME parent must NOT be flagged as a cycle.
    keydir, reg = _lab_setup(tmp_path)
    raw = tmp_path / "run.raw"
    raw.write_bytes(RAW_BYTES)
    raw_sc = sign_derivation(artifact_path=raw, inputs=[], experiment_name="acq001",
                             tool_name="Instrument", tool_version="1.0", private_key_path=keydir)
    out = tmp_path / "run.mzML"
    out.write_bytes(MZML_BYTES)
    refs = [make_input_ref("primary", raw_sc), make_input_ref("calibration", raw_sc)]
    out_sc = sign_derivation(artifact_path=out, inputs=refs, experiment_name="acq001",
                             tool_name="MSConvert", tool_version="3.0", private_key_path=keydir)
    res = verify_chain(out_sc, reg)
    assert res.ok, res.detail
    assert res.code == EXIT_OK


def test_malformed_parent_returns_malformed_not_crash(tmp_path):
    keydir, reg = _lab_setup(tmp_path)
    bad = tmp_path / "bad.chain.json"
    bad.write_bytes(b"{ this is not valid chain json")
    mzml = tmp_path / "run.mzML"
    mzml.write_bytes(MZML_BYTES)
    edge = InputRef(role="source_raw", content_hash="sha256:" + "0" * 64,
                    parent_key_id="whoever", parent_sidecar_hash=sha256_hex(bad.read_bytes()))
    mzml_sc = sign_derivation(artifact_path=mzml, inputs=[edge], experiment_name="acq001",
                              tool_name="MSConvert", tool_version="3.0", private_key_path=keydir)
    res = verify_chain(mzml_sc, reg)
    assert res.code == EXIT_MALFORMED  # structured result, not an exception
