#!/usr/bin/env python3
"""mzprov test vector generator.

Consumes the mzprov Python reference implementation as a library and
produces the v0 test vectors under ``test-vectors/``. Self-validating:
every produced vector is verified against the reference implementation,
and the actual exit code / failure type is recorded in the vector's
``_metadata`` block. A regression in the generator can never produce a
vector whose ``_metadata`` lies about its expected behavior.

Idempotent: re-running regenerates everything under ``test-vectors/``
EXCEPT for the test-only signing key under ``test-vectors/keys/``, which
is committed once and reused so that committed vectors stay byte-stable
across regenerations.

Layout:

    test-vectors/
    ├── keys/
    │   └── test-only-keypair-001/      committed once, never regenerated
    ├── sidecar/
    │   ├── valid/
    │   │   ├── d-v0-minimal/           paired (sidecar + source .d + config)
    │   │   └── mzml-v0-minimal/        paired (sidecar + source .mzml + config)
    │   └── invalid/
    │       └── <name>/                  paired; sidecar is mutated post-signing
    ├── canonicalization/
    │   ├── d/
    │   └── mzml/
    └── _generators/
        └── generate.py                  this file

Every vector under ``invalid/`` is its own SUBDIRECTORY containing the
mutated sidecar plus the source files the verifier needs to reach the
failure mode. Standalone single-file vectors are NOT used because the
verifier locates the source artifact independently of the sidecar
payload (so a tampered sidecar in a directory of unrelated files would
either crash on MissingArtifact or — worse — verify against the wrong
source file by accident).

Usage (from any working directory):

    python test-vectors/_generators/generate.py

Requires mzprov to be importable. The simplest setup is:

    pip install -e implementations/python
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from mzprov import (
    MalformedSidecar,
    ProvenanceError,
    UnknownVersion,
    canonicalize_d,
    canonicalize_mzml,
    canonicalize_raw,
    sign_mzml_output,
    sign_raw_output,
    sign_simulation_output,
    verify_sidecar,
)
from mzprov._fixtures import (
    make_minimal_d,
    make_minimal_mzml,
    tamper_byte,
)
from mzprov.envelope import (
    ATTESTATION_TYPE,
    ATTESTATION_TYPE_MZML,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


REPO_ROOT = Path(__file__).resolve().parents[2]  # mzprov/
VECTORS_ROOT = REPO_ROOT / "test-vectors"
KEYS_DIR = VECTORS_ROOT / "keys"
TEST_KEY_DIR = KEYS_DIR / "test-only-keypair-001"
SIDECAR_DIR = VECTORS_ROOT / "sidecar"
VALID_DIR = SIDECAR_DIR / "valid"
INVALID_DIR = SIDECAR_DIR / "invalid"
CANON_DIR = VECTORS_ROOT / "canonicalization"
CANON_D_DIR = CANON_DIR / "d"
CANON_MZML_DIR = CANON_DIR / "mzml"
CANON_RAW_DIR = CANON_DIR / "raw"


# Deterministic dummy ``.raw`` bytes. A Thermo ``.raw`` is canonicalized as
# an opaque whole-file SHA-256, so the only requirement for a stable vector
# is that the bytes are fixed across regenerations. These bytes are NOT a
# real Thermo container — they only need to exercise the streaming opaque
# hash and be byte-stable. The header mimics the Thermo magic just enough to
# be recognisable; everything after is arbitrary fixed filler.
_DUMMY_RAW_BYTES = (
    b"\x01\xa1F\x00i\x00n\x00n\x00i\x00g\x00a\x00n\x00"  # pseudo "Finnigan" magic
    + bytes(range(256)) * 8
    + b"mzprov-test-vectors/raw-v0-opaque-fixture\x00"
)


def make_minimal_raw(tmp_path: Path, *, name: str = "001-minimal") -> Path:
    """Write a small deterministic dummy ``.raw`` file and return its path.

    The bytes are fixed (see ``_DUMMY_RAW_BYTES``) so the opaque whole-file
    canonical hash is byte-stable across regenerations.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw_path = tmp_path / f"{name}.raw"
    raw_path.write_bytes(_DUMMY_RAW_BYTES)
    return raw_path


# Reference exit codes used in _metadata. These are the values mzprov-verify
# returns for each failure mode and they are part of the v0 spec contract.
EXIT_OK = 0
EXIT_SIDECAR_ERROR = 3
EXIT_HASH_MISMATCH = 5
EXIT_SIGNATURE_MISMATCH = 6


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def _purge(path: Path) -> None:
    if path.is_file() or path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _read_sidecar(path: Path) -> dict:
    return json.loads(path.read_bytes().decode("utf-8"))


def _write_sidecar(blob: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps(blob, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )


def _attach_metadata(
    blob: dict,
    *,
    expected_result: str,
    expected_exit_code: int,
    expected_failure: str | None,
    spec_section: str,
    description: str,
) -> dict:
    blob["_metadata"] = {
        "expected_result": expected_result,
        "expected_exit_code": expected_exit_code,
        "expected_failure": expected_failure,
        "spec_section": spec_section,
        "description": description,
    }
    return blob


# ---------------------------------------------------------------------------
# Self-validation: run mzprov against each vector and require the expected outcome
# ---------------------------------------------------------------------------


def _expect_verify_ok(sidecar_path: Path) -> None:
    result = verify_sidecar(sidecar_path)
    if not result.overall_ok:
        raise RuntimeError(
            f"valid vector did not verify cleanly: {sidecar_path}\n"
            f"  signature_ok: {result.signature_ok}\n"
            f"  checks: {[(c.field, c.status) for c in result.checks]}\n"
            f"  trust: {result.trust.status}"
        )


def _expect_verify_raises(sidecar_path: Path, *, exc_type: type) -> None:
    try:
        result = verify_sidecar(sidecar_path)
    except exc_type:
        return
    except ProvenanceError as e:
        raise RuntimeError(
            f"vector {sidecar_path} raised {type(e).__name__} ({e}) but the "
            f"generator expected {exc_type.__name__}"
        )
    raise RuntimeError(
        f"vector {sidecar_path} verified successfully but the generator "
        f"expected {exc_type.__name__}; result.overall_ok={result.overall_ok}"
    )


def _expect_verify_returns_failure(sidecar_path: Path, *, failing_field: str) -> None:
    """Verifier MUST return overall_ok=False with the named failure mode.

    ``failing_field`` names where the failure must surface:
        - "signature"            -> result.signature_ok must be False
        - "d_content_hash" etc.  -> the corresponding FieldCheck entry in
                                    result.checks must have status != "ok"

    This is what distinguishes one failure mode from another and is what
    the generator records into _metadata.
    """
    result = verify_sidecar(sidecar_path)
    if result.overall_ok:
        raise RuntimeError(
            f"vector {sidecar_path} verified successfully but the generator "
            f"expected overall_ok=False (failing_field={failing_field!r})"
        )

    if failing_field == "signature":
        if result.signature_ok:
            raise RuntimeError(
                f"vector {sidecar_path} did fail overall, but signature_ok "
                f"is True. Expected SIGNATURE_MISMATCH."
            )
        return

    statuses = {c.name: c.status for c in result.checks}
    if statuses.get(failing_field, "ok") == "ok":
        raise RuntimeError(
            f"vector {sidecar_path} did fail overall, but field "
            f"{failing_field!r} was reported as ok. Per-field statuses: "
            f"{statuses}"
        )


# ---------------------------------------------------------------------------
# Test-only key management
# ---------------------------------------------------------------------------


def ensure_test_key() -> Path:
    """Ensure the test-only keypair exists at TEST_KEY_DIR.

    First run: generates a fresh Ed25519 keypair via the standard mzprov
    key writer. Subsequent runs: reuses the same key. This is what keeps
    committed vectors byte-stable across regenerations.
    """
    TEST_KEY_DIR.mkdir(parents=True, exist_ok=True)
    signing_key_pem = TEST_KEY_DIR / "signing_key.pem"
    if not signing_key_pem.is_file():
        from mzprov.keys import generate_keypair, write_keypair

        keypair = generate_keypair()
        write_keypair(keypair, TEST_KEY_DIR)
        print(f"  [keys] generated fresh test keypair at {TEST_KEY_DIR}")
    else:
        print(f"  [keys] reusing existing test keypair at {TEST_KEY_DIR}")
    return TEST_KEY_DIR


def write_keys_readme() -> None:
    readme = KEYS_DIR / "README.md"
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    readme.write_text(
        "# test-vectors/keys/ — test-only signing keys\n"
        "\n"
        "**WARNING.** Every key in this directory is committed in plaintext\n"
        "to the public mzprov repository on purpose. They exist so that\n"
        "the cross-implementation test vectors are reproducible.\n"
        "\n"
        "These keys MUST NOT be used to sign real data. They MUST NOT be\n"
        "added to any production trusted-keys registry. They MUST NOT\n"
        "appear in any sidecar that ships outside the `test-vectors/`\n"
        "tree.\n"
        "\n"
        "Conforming implementations SHOULD reject these key ids when they\n"
        "appear in production verification contexts. The known test-only\n"
        "key ids will be enumerated in `spec/key-id-derivation.md` once\n"
        "that document lands.\n"
    )


# ---------------------------------------------------------------------------
# Paired vector builders
# ---------------------------------------------------------------------------


def _build_d_paired_subdir(parent: Path, name: str) -> tuple[Path, Path]:
    """Create a subdirectory under ``parent`` containing a freshly-signed .d.

    Returns ``(subdirectory, sidecar_path)``. The subdirectory contains:
        ``{name}.d/``                   the source .d directory
        ``{name}.config.toml``          the config copy
        ``{name}.provenance.json``      the freshly-written sidecar (valid)

    Caller may then mutate the sidecar bytes for invalid-vector cases.
    """
    out_dir = parent / name
    _purge(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    d_path = make_minimal_d(out_dir, name=name)
    config_path = out_dir / f"{name}.config.toml"
    config_path.write_bytes(
        b"[experiment]\n"
        b'name = "' + name.encode("ascii") + b'"\n'
        b'description = "mzprov v0 test vector: ' + name.encode("ascii") + b'"\n'
    )

    sidecar_path = sign_simulation_output(
        d_path=d_path,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name=name,
        simulator_version="mzprov-test-vectors/0.1.0",
        sidecar_path=out_dir / f"{name}.provenance.json",
        private_key_path=TEST_KEY_DIR,
    )
    return out_dir, sidecar_path


def _build_mzml_paired_subdir(parent: Path, name: str) -> tuple[Path, Path]:
    out_dir = parent / name
    _purge(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    mzml_path = make_minimal_mzml(out_dir, name=name)
    config_path = out_dir / f"{name}.config.toml"
    config_path.write_bytes(
        b"[experiment]\n"
        b'name = "' + name.encode("ascii") + b'"\n'
        b'description = "mzprov v0 test vector: ' + name.encode("ascii") + b'"\n'
    )

    sidecar_path = sign_mzml_output(
        mzml_path=mzml_path,
        config_path=config_path,
        experiment_name=name,
        tool_name="mzprov-test-vectors",
        tool_version="0.1.0",
        sidecar_path=out_dir / f"{name}.provenance.json",
        private_key_path=TEST_KEY_DIR,
    )
    return out_dir, sidecar_path


def _build_raw_paired_subdir(parent: Path, name: str) -> tuple[Path, Path]:
    out_dir = parent / name
    _purge(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_path = make_minimal_raw(out_dir, name=name)
    config_path = out_dir / f"{name}.config.toml"
    config_path.write_bytes(
        b"[experiment]\n"
        b'name = "' + name.encode("ascii") + b'"\n'
        b'description = "mzprov v0 test vector: ' + name.encode("ascii") + b'"\n'
    )

    sidecar_path = sign_raw_output(
        raw_path=raw_path,
        config_path=config_path,
        experiment_name=name,
        tool_name="mzprov-test-vectors",
        tool_version="0.1.0",
        sidecar_path=out_dir / f"{name}.provenance.json",
        private_key_path=TEST_KEY_DIR,
    )
    return out_dir, sidecar_path


# ---------------------------------------------------------------------------
# Valid vectors
# ---------------------------------------------------------------------------


def generate_d_paired_valid() -> None:
    out_dir, sidecar_path = _build_d_paired_subdir(VALID_DIR, "d-v0-minimal")
    blob = _read_sidecar(sidecar_path)
    _attach_metadata(
        blob,
        expected_result="VERIFY",
        expected_exit_code=EXIT_OK,
        expected_failure=None,
        spec_section="spec/sidecar-format.md",
        description=(
            "Minimal valid .d sidecar paired with its source .d directory and "
            "config copy, produced by the Python reference implementation. "
            "Verifier MUST report VERIFIED."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_ok(sidecar_path)
    print(f"  [valid:OK] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_embedded_valid() -> None:
    """Build a .d whose sidecar envelope is embedded inside analysis.tdf.

    The vector consists of the .d directory alone — there is no
    sibling .provenance.json. Conforming implementations MUST verify
    via the embedded-reader path defined in `spec/embedded-d-v0.md` §5.
    Metadata describing the expected outcome is written to a
    `_metadata.json` file alongside the .d (rather than embedded in the
    sidecar JSON, which is itself inside the SQLite file).
    """
    name = "d-v0-embedded-minimal"
    out_dir = VALID_DIR / name
    _purge(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    d_path = make_minimal_d(out_dir, name=name)
    config_path = out_dir / f"{name}.config.toml"
    config_path.write_bytes(
        b"[experiment]\n"
        b'name = "' + name.encode("ascii") + b'"\n'
        b'description = "mzprov v0 test vector: ' + name.encode("ascii") + b'"\n'
    )

    sign_simulation_output(
        d_path=d_path,
        ground_truth_path=None,
        config_path=config_path,
        experiment_name=name,
        simulator_version="mzprov-test-vectors/0.1.0",
        private_key_path=TEST_KEY_DIR,
        embed=True,
    )

    metadata = {
        "expected_result": "VERIFY",
        "expected_exit_code": EXIT_OK,
        "expected_failure": None,
        "spec_section": "spec/embedded-d-v0.md",
        "transport": "embedded-d",
        "description": (
            "Minimal valid .d with the sidecar envelope embedded in "
            "analysis.tdf as a row in the mzprov_provenance table. "
            "There is no sibling *.provenance.json. Verifier MUST "
            "discover the embedded transport, verify, and report "
            "VERIFIED. The .d's content hash MUST be invariant to the "
            "presence of the mzprov_provenance row (the table is "
            "excluded from canonicalization per spec/canonicalization-"
            "d-v0.md §3.2)."
        ),
    }
    (out_dir / "_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True)
    )

    # Self-validate via the embedded-verify entry point.
    from mzprov.verify import verify_embedded_d
    result = verify_embedded_d(d_path, config_path_override=config_path)
    if not result.overall_ok:
        raise RuntimeError(
            f"embedded vector did not verify cleanly: {d_path}\n"
            f"  signature_ok: {result.signature_ok}\n"
            f"  checks: {[(c.name, c.status) for c in result.checks]}"
        )
    if result.transport != "embedded-d":
        raise RuntimeError(
            f"embedded vector verified but transport was "
            f"{result.transport!r}; expected 'embedded-d'"
        )
    print(f"  [valid:OK] {out_dir.relative_to(VECTORS_ROOT)}/  (embedded)")


def generate_mzml_embedded_valid() -> None:
    """Build an mzML whose sidecar envelope is embedded as a userParam.

    The vector is a single .mzML file containing the
    `mzprov:provenance` userParam in fileDescription/fileContent
    (per spec/embedded-mzml-v0.md §2). Metadata for the conformance
    harness lives in a sibling _metadata.json because the envelope
    is inside the mzML, not in a separate sidecar JSON.
    """
    name = "mzml-v0-embedded-minimal"
    out_dir = VALID_DIR / name
    _purge(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    mzml_path = make_minimal_mzml(out_dir, name=name)
    config_path = out_dir / f"{name}.config.toml"
    config_path.write_bytes(
        b"[experiment]\n"
        b'name = "' + name.encode("ascii") + b'"\n'
        b'description = "mzprov v0 test vector: ' + name.encode("ascii") + b'"\n'
    )

    sign_mzml_output(
        mzml_path=mzml_path,
        config_path=config_path,
        experiment_name=name,
        tool_name="mzprov-test-vectors",
        tool_version="0.1.0",
        private_key_path=TEST_KEY_DIR,
        embed=True,
    )

    metadata = {
        "expected_result": "VERIFY",
        "expected_exit_code": EXIT_OK,
        "expected_failure": None,
        "spec_section": "spec/embedded-mzml-v0.md",
        "transport": "embedded-mzml",
        "description": (
            "Minimal valid mzML with the sidecar envelope embedded as a "
            "userParam (name='mzprov:provenance') inside fileDescription/"
            "fileContent. There is no sibling *.provenance.json. The "
            "indexedmzML wrapper is stripped on embed (spec §4); the "
            "output is plain mzML. Verifier MUST discover the embedded "
            "transport, verify, and report VERIFIED. The mzML's content "
            "hash MUST be invariant to the presence of the userParam "
            "(slot is canonically excluded by virtue of living in "
            "fileDescription per canonicalization-mzml-v0.md §1, §2)."
        ),
    }
    (out_dir / "_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True)
    )

    # Self-validate via the embedded-verify entry point.
    from mzprov.verify import verify_embedded_mzml
    result = verify_embedded_mzml(mzml_path, config_path_override=config_path)
    if not result.overall_ok:
        raise RuntimeError(
            f"embedded mzml vector did not verify cleanly: {mzml_path}\n"
            f"  signature_ok: {result.signature_ok}\n"
            f"  checks: {[(c.name, c.status) for c in result.checks]}"
        )
    if result.transport != "embedded-mzml":
        raise RuntimeError(
            f"embedded mzml vector verified but transport was "
            f"{result.transport!r}; expected 'embedded-mzml'"
        )
    print(f"  [valid:OK] {out_dir.relative_to(VECTORS_ROOT)}/  (embedded mzml)")


def generate_mzml_paired_valid() -> None:
    out_dir, sidecar_path = _build_mzml_paired_subdir(VALID_DIR, "mzml-v0-minimal")
    blob = _read_sidecar(sidecar_path)
    _attach_metadata(
        blob,
        expected_result="VERIFY",
        expected_exit_code=EXIT_OK,
        expected_failure=None,
        spec_section="spec/sidecar-format.md",
        description=(
            "Minimal valid mzML sidecar paired with its source mzML file and "
            "config copy, produced by the Python reference implementation. "
            "Verifier MUST report VERIFIED."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_ok(sidecar_path)
    print(f"  [valid:OK] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_raw_paired_valid() -> None:
    out_dir, sidecar_path = _build_raw_paired_subdir(VALID_DIR, "raw-v0-minimal")
    blob = _read_sidecar(sidecar_path)
    _attach_metadata(
        blob,
        expected_result="VERIFY",
        expected_exit_code=EXIT_OK,
        expected_failure=None,
        spec_section="spec/canonicalization-raw-v0.md",
        description=(
            "Minimal valid Thermo .raw sidecar paired with its source .raw "
            "file (an opaque deterministic fixture) and config copy, "
            "produced by the Python reference implementation. The .raw is "
            "hashed as an opaque whole-file SHA-256 and the attestation is "
            "sidecar-only (no embed transport). Verifier MUST report VERIFIED."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_ok(sidecar_path)
    print(f"  [valid:OK] {out_dir.relative_to(VECTORS_ROOT)}/")


# ---------------------------------------------------------------------------
# Invalid vectors — .d
# ---------------------------------------------------------------------------


def generate_d_hash_mismatch_tdf_bin() -> None:
    """Sign a .d, then byte-flip analysis.tdf_bin POST-SIGNING."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-hash-mismatch-tdf-bin-tampered"
    )
    bin_path = out_dir / "d-hash-mismatch-tdf-bin-tampered.d" / "analysis.tdf_bin"
    tamper_byte(bin_path, 100)

    blob = _read_sidecar(sidecar_path)
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_HASH_MISMATCH,
        expected_failure="HASH_MISMATCH",
        spec_section="spec/canonicalization-d-v0.md",
        description=(
            "A valid .d sidecar paired with a .d whose analysis.tdf_bin has "
            "been byte-flipped at offset 100 AFTER signing. The signature "
            "still verifies (the payload is unchanged) but the recomputed "
            "d_content_hash MUST diverge from payload.d_content_hash, and "
            "the verifier MUST report HASH_MISMATCH on the d_content_hash field."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_returns_failure(sidecar_path, failing_field="d_content_hash")
    print(f"  [invalid:HASH_MISMATCH] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_tampered_payload_experiment_name() -> None:
    """Mutate payload.experiment_name post-signing. Must fail SIGNATURE_MISMATCH."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-tampered-payload-experiment-name"
    )
    blob = _read_sidecar(sidecar_path)
    blob["payload"]["experiment_name"] = "TAMPERED"
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIGNATURE_MISMATCH,
        expected_failure="SIGNATURE_MISMATCH",
        spec_section="spec/signature-scheme.md",
        description=(
            "A valid .d sidecar paired with its (untampered) source .d, "
            "but the sidecar's payload.experiment_name has been rewritten "
            "to 'TAMPERED' after signing. Hash recomputation succeeds. "
            "Signature verification MUST fail because re-canonicalizing "
            "the modified payload produces different bytes than what "
            "was signed. Verifier MUST report SIGNATURE_MISMATCH."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_returns_failure(sidecar_path, failing_field="signature")
    print(f"  [invalid:SIGNATURE_MISMATCH] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_tampered_payload_d_content_hash() -> None:
    """Flip the last hex char of payload.d_content_hash."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-tampered-payload-d-content-hash"
    )
    blob = _read_sidecar(sidecar_path)
    h = blob["payload"]["d_content_hash"]
    blob["payload"]["d_content_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_HASH_MISMATCH,
        expected_failure="HASH_MISMATCH",
        spec_section="spec/sidecar-format.md",
        description=(
            "A valid .d sidecar paired with its (untampered) source .d, "
            "but the sidecar's payload.d_content_hash has had its last "
            "hex character flipped after signing. The recomputed hash "
            "from disk does not match the field; verifier reports "
            "HASH_MISMATCH on d_content_hash. (NOTE: this is one possible "
            "diagnosis; the same mutation also breaks the signature, so "
            "implementations MAY surface this as SIGNATURE_MISMATCH if "
            "they verify the signature before recomputing hashes. The "
            "v0 reference verifier checks hashes first.)"
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_returns_failure(sidecar_path, failing_field="d_content_hash")
    print(f"  [invalid:HASH_MISMATCH] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_wrong_key_id_label() -> None:
    """Relabel payload.key_id without changing verifying_key."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-wrong-key-id-label"
    )
    blob = _read_sidecar(sidecar_path)
    blob["payload"]["key_id"] = "timsim-local-aaaaaaaaaaaaaaaa"
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="KEY_ID_CONSISTENCY",
        spec_section="spec/key-id-derivation.md",
        description=(
            "A valid .d sidecar paired with its (untampered) source .d, "
            "but the sidecar's payload.key_id has been relabeled to a "
            "different (still well-formed) value. The verifying_key "
            "embedded in the sidecar is unchanged. The verifier MUST "
            "derive the key id from verifying_key (NOT from "
            "payload.key_id) and refuse the sidecar because the label "
            "and the actual signer disagree. The reference verifier "
            "raises MalformedSidecar at this check, mapped to "
            "SIDECAR_ERROR (3)."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:KEY_ID_CONSISTENCY] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_unknown_signature_algorithm() -> None:
    """Replace the ed25519: prefix with a fictional algorithm name."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-unknown-signature-algorithm"
    )
    blob = _read_sidecar(sidecar_path)
    sig = blob["signature"]
    assert sig.startswith("ed25519:base64:"), f"unexpected signature prefix: {sig[:30]}"
    blob["signature"] = "xed25519:base64:" + sig[len("ed25519:base64:"):]
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="UNKNOWN_SIGNATURE_ALGORITHM",
        spec_section="spec/signature-scheme.md",
        description=(
            "A valid .d sidecar paired with its (untampered) source .d, "
            "but the sidecar's signature algorithm prefix has been "
            "changed from 'ed25519:' to 'xed25519:' (a fictional "
            "algorithm name). The verifier MUST refuse signatures with "
            "an unknown algorithm prefix and MUST NOT silently fall "
            "through to verifying with the embedded key under an "
            "unknown algorithm name. The reference verifier raises "
            "MalformedSidecar from the signature decoder, mapped to "
            "SIDECAR_ERROR (3)."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:UNKNOWN_SIGNATURE_ALGORITHM] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_d_cross_format_typed_as_mzml() -> None:
    """Change the type tag from .d to mzml. Payload schema mismatch."""
    out_dir, sidecar_path = _build_d_paired_subdir(
        INVALID_DIR, "d-cross-format-typed-as-mzml"
    )
    blob = _read_sidecar(sidecar_path)
    blob["type"] = ATTESTATION_TYPE_MZML
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="CROSS_FORMAT_REUSE",
        spec_section="spec/sidecar-format.md",
        description=(
            "A valid .d sidecar paired with its (untampered) source .d, "
            f"but the sidecar's type tag has been changed from "
            f"{ATTESTATION_TYPE!r} to {ATTESTATION_TYPE_MZML!r}. The "
            "payload schema still has the .d shape (d_content_hash, "
            "ground_truth_hash) so the mzml parser MUST reject it for "
            "missing required mzml fields (mzml_content_hash). The "
            "reference verifier raises MalformedSidecar via the mzml "
            "payload validator, mapped to SIDECAR_ERROR (3)."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:CROSS_FORMAT_REUSE] {out_dir.relative_to(VECTORS_ROOT)}/")


# ---------------------------------------------------------------------------
# Invalid vectors — mzML
# ---------------------------------------------------------------------------


def generate_mzml_hash_mismatch() -> None:
    """Sign an mzML, then mutate a hashed cvParam value POST-SIGNING.

    Changes the MS1 scan start time from "0.5" to "0.7". The canonical
    record includes the scan start time (rt), so this changes the
    canonical hash without breaking any XML or base64 parsing — which
    is what we need to test the HASH_MISMATCH path (as opposed to the
    SIDECAR_ERROR path that fires when the file is structurally broken).
    """
    out_dir, sidecar_path = _build_mzml_paired_subdir(
        INVALID_DIR, "mzml-hash-mismatch-scan-start-time"
    )
    mzml_path = out_dir / "mzml-hash-mismatch-scan-start-time.mzML"
    contents = mzml_path.read_text(encoding="utf-8")
    old = 'name="scan start time" value="0.5"'
    new = 'name="scan start time" value="0.7"'
    if old not in contents:
        raise RuntimeError(
            f"could not find {old!r} in {mzml_path}; the fixture changed shape"
        )
    contents = contents.replace(old, new, 1)
    mzml_path.write_text(contents, encoding="utf-8")

    blob = _read_sidecar(sidecar_path)
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_HASH_MISMATCH,
        expected_failure="HASH_MISMATCH",
        spec_section="spec/canonicalization-mzml-v0.md",
        description=(
            "A valid mzML sidecar paired with an mzML whose MS1 spectrum "
            "scan start time cvParam has been changed from 0.5 to 0.7 "
            "AFTER signing. The mzml_content_hash includes the canonical "
            "rt field, so the recomputed hash MUST diverge from "
            "payload.mzml_content_hash and the verifier MUST report "
            "HASH_MISMATCH on mzml_content_hash. The XML and base64 "
            "remain structurally valid; only a hashed semantic value "
            "changed."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_returns_failure(sidecar_path, failing_field="mzml_content_hash")
    print(f"  [invalid:HASH_MISMATCH] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_mzml_tampered_payload_experiment_name() -> None:
    out_dir, sidecar_path = _build_mzml_paired_subdir(
        INVALID_DIR, "mzml-tampered-payload-experiment-name"
    )
    blob = _read_sidecar(sidecar_path)
    blob["payload"]["experiment_name"] = "TAMPERED"
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIGNATURE_MISMATCH,
        expected_failure="SIGNATURE_MISMATCH",
        spec_section="spec/signature-scheme.md",
        description=(
            "A valid mzML sidecar paired with its (untampered) source "
            "mzML, but the sidecar's payload.experiment_name has been "
            "rewritten to 'TAMPERED' after signing. Hash recomputation "
            "succeeds; signature verification MUST fail with "
            "SIGNATURE_MISMATCH."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_returns_failure(sidecar_path, failing_field="signature")
    print(f"  [invalid:SIGNATURE_MISMATCH] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_mzml_wrong_key_id_label() -> None:
    out_dir, sidecar_path = _build_mzml_paired_subdir(
        INVALID_DIR, "mzml-wrong-key-id-label"
    )
    blob = _read_sidecar(sidecar_path)
    blob["payload"]["key_id"] = "timsim-local-aaaaaaaaaaaaaaaa"
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="KEY_ID_CONSISTENCY",
        spec_section="spec/key-id-derivation.md",
        description=(
            "A valid mzML sidecar paired with its (untampered) source "
            "mzML, but the sidecar's payload.key_id has been relabeled. "
            "Verifier MUST refuse via key-id-consistency check."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:KEY_ID_CONSISTENCY] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_mzml_unknown_signature_algorithm() -> None:
    out_dir, sidecar_path = _build_mzml_paired_subdir(
        INVALID_DIR, "mzml-unknown-signature-algorithm"
    )
    blob = _read_sidecar(sidecar_path)
    sig = blob["signature"]
    assert sig.startswith("ed25519:base64:"), f"unexpected signature prefix: {sig[:30]}"
    blob["signature"] = "xed25519:base64:" + sig[len("ed25519:base64:"):]
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="UNKNOWN_SIGNATURE_ALGORITHM",
        spec_section="spec/signature-scheme.md",
        description=(
            "A valid mzML sidecar paired with its (untampered) source "
            "mzML, but the sidecar's signature algorithm prefix has "
            "been changed from 'ed25519:' to 'xed25519:'. Verifier MUST "
            "refuse."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:UNKNOWN_SIGNATURE_ALGORITHM] {out_dir.relative_to(VECTORS_ROOT)}/")


def generate_mzml_cross_format_typed_as_d() -> None:
    out_dir, sidecar_path = _build_mzml_paired_subdir(
        INVALID_DIR, "mzml-cross-format-typed-as-d"
    )
    blob = _read_sidecar(sidecar_path)
    blob["type"] = ATTESTATION_TYPE
    _attach_metadata(
        blob,
        expected_result="REJECT",
        expected_exit_code=EXIT_SIDECAR_ERROR,
        expected_failure="CROSS_FORMAT_REUSE",
        spec_section="spec/sidecar-format.md",
        description=(
            "A valid mzML sidecar paired with its (untampered) source "
            f"mzML, but the sidecar's type tag has been changed from "
            f"{ATTESTATION_TYPE_MZML!r} to {ATTESTATION_TYPE!r}. The "
            "payload schema still has the mzml shape so the .d parser "
            "MUST reject it for missing required .d fields "
            "(d_content_hash, ground_truth_hash)."
        ),
    )
    _write_sidecar(blob, sidecar_path)
    _expect_verify_raises(sidecar_path, exc_type=MalformedSidecar)
    print(f"  [invalid:CROSS_FORMAT_REUSE] {out_dir.relative_to(VECTORS_ROOT)}/")


# ---------------------------------------------------------------------------
# Canonicalization fixtures: input file + expected hash
# ---------------------------------------------------------------------------


def generate_canonicalization_d() -> None:
    _purge(CANON_D_DIR)
    CANON_D_DIR.mkdir(parents=True, exist_ok=True)

    d_path = make_minimal_d(CANON_D_DIR, name="001-minimal")
    canonical_hash = canonicalize_d(d_path)
    (CANON_D_DIR / "001-minimal.canonical-hash.txt").write_text(
        "sha256:" + canonical_hash.hex() + "\n"
    )
    print(f"  [canon:d] 001-minimal -> sha256:{canonical_hash.hex()[:16]}...")

    # Exclusion-correctness fixture for spec/embedded-d-v0.md §3.
    # We build a fresh .d, hash it, INSERT a mzprov_provenance row by
    # hand (bypassing the signer so the row is deterministic test
    # bytes), then re-hash. The two hashes MUST be byte-identical:
    # this is what makes the embed-after-hash protocol well-defined.
    from mzprov.embed_d import write_embedded_provenance

    excl_path = make_minimal_d(CANON_D_DIR, name="002-with-mzprov-provenance")
    pre_hash = canonicalize_d(excl_path)
    # Use a fixed envelope so the stored TEXT cell is byte-stable across
    # regenerations of this fixture.
    write_embedded_provenance(
        excl_path,
        b'{"_test_only_envelope": "mzprov-test-vectors/exclusion-correctness"}',
    )
    post_hash = canonicalize_d(excl_path)
    if pre_hash != post_hash:
        raise RuntimeError(
            "EXCLUSION CORRECTNESS FAILURE: hash before and after embedding "
            f"the mzprov_provenance row differ:\n"
            f"  pre:  sha256:{pre_hash.hex()}\n"
            f"  post: sha256:{post_hash.hex()}"
        )
    if pre_hash != canonical_hash:
        raise RuntimeError(
            "002-with-mzprov-provenance does not match 001-minimal's hash; "
            "the exclusion fixture must be a clone of the baseline"
        )
    (CANON_D_DIR / "002-with-mzprov-provenance.canonical-hash.txt").write_text(
        "sha256:" + post_hash.hex() + "\n"
    )
    print(
        f"  [canon:d] 002-with-mzprov-provenance -> sha256:"
        f"{post_hash.hex()[:16]}... (== 001-minimal)"
    )

    (CANON_D_DIR / "README.md").write_text(
        "# canonicalization/d/ — Bruker .d canonical-hash fixtures\n"
        "\n"
        "Each `NNN-name.d/` directory ships with `NNN-name.canonical-hash.txt`\n"
        "containing the expected canonical hash, as `sha256:hex\\n`. A\n"
        "conforming implementation MUST run its `.d` canonicalizer on the\n"
        "input and produce a hash byte-identical to the expected value.\n"
        "\n"
        "## Fixtures\n"
        "\n"
        "| Fixture | Description | Invariance proven |\n"
        "|---|---|---|\n"
        "| `001-minimal.d/` | minimal Bruker-shaped .d (analysis.tdf + analysis.tdf_bin) | baseline |\n"
        "| `002-with-mzprov-provenance.d/` | identical content to 001 plus a populated `mzprov_provenance` SQLite table | exclusion-rule correctness (per `spec/embedded-d-v0.md` §3); MUST hash identically to 001-minimal |\n"
        "\n"
        "Additional invariance fixtures (page-size, VACUUM, REINDEX,\n"
        "PRAGMA user_version) will land here as the spec is written down.\n"
    )


def generate_canonicalization_mzml() -> None:
    _purge(CANON_MZML_DIR)
    CANON_MZML_DIR.mkdir(parents=True, exist_ok=True)

    indented_path = make_minimal_mzml(CANON_MZML_DIR, name="001-indented", indented=True)
    indented_hash = canonicalize_mzml(indented_path)
    (CANON_MZML_DIR / "001-indented.canonical-hash.txt").write_text(
        "sha256:" + indented_hash.hex() + "\n"
    )
    print(f"  [canon:mzml] 001-indented -> sha256:{indented_hash.hex()[:16]}...")

    compact_path = make_minimal_mzml(CANON_MZML_DIR, name="002-compact", indented=False)
    compact_hash = canonicalize_mzml(compact_path)
    (CANON_MZML_DIR / "002-compact.canonical-hash.txt").write_text(
        "sha256:" + compact_hash.hex() + "\n"
    )
    print(f"  [canon:mzml] 002-compact -> sha256:{compact_hash.hex()[:16]}...")

    if indented_hash != compact_hash:
        raise RuntimeError(
            "INVARIANCE FAILURE: indented and compact mzML produced different "
            f"canonical hashes:\n"
            f"  001-indented: sha256:{indented_hash.hex()}\n"
            f"  002-compact:  sha256:{compact_hash.hex()}"
        )

    if indented_path.read_bytes() == compact_path.read_bytes():
        raise RuntimeError(
            "001-indented.mzML and 002-compact.mzML have identical bytes; "
            "the invariance test would be vacuous"
        )

    print(f"  [canon:mzml] invariance OK: 001 and 002 hash identically")

    (CANON_MZML_DIR / "README.md").write_text(
        "# canonicalization/mzml/ — mzML canonical-hash fixtures\n"
        "\n"
        "Each `NNN-name.mzML` file ships with `NNN-name.canonical-hash.txt`\n"
        "containing the expected canonical hash, as `sha256:hex\\n`. A\n"
        "conforming implementation MUST run its mzML canonicalizer on the\n"
        "input and produce a hash byte-identical to the expected value.\n"
        "\n"
        "## Fixtures\n"
        "\n"
        "| Fixture | Source bytes | Expected hash | Invariance proven |\n"
        "|---|---|---|---|\n"
        "| `001-indented.mzML` | indented, multi-line | (see file) | baseline |\n"
        "| `002-compact.mzML` | no whitespace, single line | **same as 001** | whitespace invariance |\n"
        "\n"
        "Implementations that fail to produce identical hashes for 001 and\n"
        "002 are not whitespace-invariant and do not conform to v0.\n"
    )


def generate_canonicalization_raw() -> None:
    _purge(CANON_RAW_DIR)
    CANON_RAW_DIR.mkdir(parents=True, exist_ok=True)

    raw_path = make_minimal_raw(CANON_RAW_DIR, name="001-minimal")
    canonical_hash = canonicalize_raw(raw_path)
    (CANON_RAW_DIR / "001-minimal.canonical-hash.txt").write_text(
        "sha256:" + canonical_hash.hex() + "\n"
    )
    print(f"  [canon:raw] 001-minimal -> sha256:{canonical_hash.hex()[:16]}...")

    (CANON_RAW_DIR / "README.md").write_text(
        "# canonicalization/raw/ — Thermo .raw canonical-hash fixtures\n"
        "\n"
        "Each `NNN-name.raw` file ships with `NNN-name.canonical-hash.txt`\n"
        "containing the expected canonical hash, as `sha256:hex\\n`. A\n"
        "conforming implementation MUST run its `.raw` canonicalizer on the\n"
        "input and produce a hash byte-identical to the expected value.\n"
        "\n"
        "Unlike the mzML path, the `.raw` canonicalization is an **opaque\n"
        "whole-file SHA-256** with a domain prefix (per\n"
        "`spec/canonicalization-raw-v0.md`): there is no structural\n"
        "normalization, so the hash is sensitive to every byte. The fixture\n"
        "below is a small deterministic dummy `.raw` (NOT a real Thermo\n"
        "container) whose only contract is byte-stability.\n"
        "\n"
        "## Fixtures\n"
        "\n"
        "| Fixture | Description | Property |\n"
        "|---|---|---|\n"
        "| `001-minimal.raw` | small deterministic opaque byte fixture | baseline opaque whole-file hash |\n"
    )


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"mzprov test vector generator")
    print(f"  repo root:    {REPO_ROOT}")
    print(f"  vectors root: {VECTORS_ROOT}")
    print()

    print("=== wiping regenerable subtrees ===")
    _purge(VALID_DIR)
    _purge(INVALID_DIR)
    _purge(CANON_DIR)
    VALID_DIR.mkdir(parents=True, exist_ok=True)
    INVALID_DIR.mkdir(parents=True, exist_ok=True)
    CANON_DIR.mkdir(parents=True, exist_ok=True)

    print()
    print("=== test-only key ===")
    ensure_test_key()
    write_keys_readme()

    print()
    print("=== valid sidecar vectors ===")
    generate_d_paired_valid()
    generate_d_embedded_valid()
    generate_mzml_paired_valid()
    generate_mzml_embedded_valid()
    generate_raw_paired_valid()

    print()
    print("=== invalid .d vectors ===")
    generate_d_hash_mismatch_tdf_bin()
    generate_d_tampered_payload_experiment_name()
    generate_d_tampered_payload_d_content_hash()
    generate_d_wrong_key_id_label()
    generate_d_unknown_signature_algorithm()
    generate_d_cross_format_typed_as_mzml()

    print()
    print("=== invalid mzML vectors ===")
    generate_mzml_hash_mismatch()
    generate_mzml_tampered_payload_experiment_name()
    generate_mzml_wrong_key_id_label()
    generate_mzml_unknown_signature_algorithm()
    generate_mzml_cross_format_typed_as_d()

    print()
    print("=== canonicalization fixtures ===")
    generate_canonicalization_d()
    generate_canonicalization_mzml()
    generate_canonicalization_raw()

    print()
    print("=== done ===")
    print("All vectors validated against the Python reference implementation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
