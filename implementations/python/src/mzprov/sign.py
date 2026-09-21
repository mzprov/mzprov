"""Sign a TimSim simulation output: produce a sidecar attestation file.

This is the high-level entry point that the simulator's JOB 11 hook calls
after ``assemble_frames`` returns. It composes the canonical hashes,
builds the payload, signs it with Ed25519, and writes the sidecar JSON
atomically (temp file + rename) so a partial sidecar is never visible.
"""

from __future__ import annotations

import datetime as _dt
import os
import shutil
from pathlib import Path
from typing import Union

from mzprov.canonicalize import (
    CANONICALIZATION_VERSION,
    canonicalize_bytes,
    canonicalize_d,
    canonicalize_sqlite,
    compose_content_hash,
)
from mzprov.canonicalize_mzml import (
    canonicalize_mzml,
    compose_mzml_content_hash,
)
from mzprov.canonicalize_raw import (
    canonicalize_raw,
    compose_raw_content_hash,
)
from mzprov.canonicalize_wiff import (
    canonicalize_wiff,
    compose_wiff_content_hash,
)
from mzprov.envelope import (
    ATTESTATION_TYPE,
    ATTESTATION_TYPE_MZML,
    ATTESTATION_TYPE_RAW,
    ATTESTATION_TYPE_WIFF,
    MzmlPayload,
    MzmlSidecar,
    Payload,
    RawPayload,
    RawSidecar,
    Sidecar,
    WiffPayload,
    WiffSidecar,
)
from mzprov.errors import MissingArtifact, ProvenanceError
from mzprov.paths import (
    embedded_d_config_path,
    embedded_mzml_config_path,
    sidecar_config_path,
)
from mzprov.keys import (
    KeyPair,
    load_or_create_keypair,
    load_private_key,
    public_key_to_b64,
    signature_to_b64,
)

PathLike = Union[str, Path]


def _hex(b: bytes) -> str:
    return "sha256:" + b.hex()


def _utc_now_iso() -> str:
    return (
        _dt.datetime.now(tz=_dt.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )


def _resolve_keypair(private_key_path: PathLike | None) -> KeyPair:
    """Resolve the keypair to use for signing.

    If a path is given we load it (and re-derive its public key + key id).
    Otherwise we fall back to the default ``~/.config/timsim/keys`` location,
    creating one on first use.
    """
    if private_key_path is None:
        return load_or_create_keypair()

    private_key_path = Path(private_key_path)
    if private_key_path.is_dir():
        # User passed the key directory, not the .pem file. Treat it as such.
        return load_or_create_keypair(private_key_path)

    # Specific .pem file. We do not auto-create at an arbitrary path; if it
    # is missing, the load function raises KeyNotFoundError.
    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    from mzprov.keys import derive_key_id  # local to avoid cycle
    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        key_id=derive_key_id(public_key),
    )


def sign_simulation_output(
    *,
    d_path: PathLike,
    ground_truth_path: PathLike | None,
    config_path: PathLike,
    experiment_name: str,
    simulator_version: str,
    sidecar_path: PathLike | None = None,
    private_key_path: PathLike | None = None,
    embed: bool = False,
    simulator_name: str = "TimSim",
) -> Path:
    """Hash, sign, and write a provenance sidecar for a TimSim output.

    Parameters
    ----------
    d_path
        The Bruker ``.d`` directory produced by TimSim.
    ground_truth_path
        Path to ``synthetic_data.db`` (may be None if not used).
    config_path
        Path to the user's TOML config file. We re-read it to capture
        the exact bytes the user wrote.
    experiment_name
        The TimSim experiment name (used as a payload field).
    simulator_version
        The TimSim version string (e.g. "0.4.1").
    sidecar_path
        Where to write the sidecar JSON. Defaults to a sibling of the
        ``.d`` named ``{experiment_name}.provenance.json``.
    private_key_path
        Override path to an Ed25519 private key (or its containing
        directory). If None, the default ``~/.config/timsim/keys/``
        location is used (and a key is generated there on first use).
    embed
        If True, the sidecar envelope is written into the .d's
        ``analysis.tdf`` SQLite as a row in the ``mzprov_provenance``
        table (see ``spec/embedded-d-v0.md``) and no JSON sidecar file
        is produced. Returns the .d path in this mode. The exclusion
        rule in ``canonicalize.canonicalize_d`` makes embed-after-hash
        well-defined: the hash computed on the .d before embedding
        equals the hash computed after.
        If False (default), the JSON sidecar transport is used.
    simulator_name
        The producing tool recorded in the payload. Defaults to
        "TimSim"; set it when signing a ``.d`` that TimSim did not make,
        such as a genuine acquisition.

    Returns
    -------
    Path
        The path to the written sidecar JSON file in the default mode,
        or the .d directory path when ``embed=True``.
    """
    d_path = Path(d_path)
    config_path = Path(config_path)
    if not d_path.is_dir():
        raise MissingArtifact(f".d directory does not exist: {d_path}")
    if not config_path.is_file():
        raise MissingArtifact(f"config file does not exist: {config_path}")

    if ground_truth_path is not None:
        ground_truth_path = Path(ground_truth_path)
        if not ground_truth_path.is_file():
            raise MissingArtifact(
                f"ground-truth database does not exist: {ground_truth_path}"
            )

    # The journal/-wal/-shm quiescence check is centralized inside
    # canonicalize_sqlite (see canonicalize._assert_sqlite_quiescent).
    # Any of those sidecars present will surface as SqliteNotQuiescent,
    # which is a ProvenanceError subclass, so the simulator hook's
    # existing required=true handler catches it without special-casing.

    if embed:
        # The envelope lives inside analysis.tdf; sidecar_path is unused
        # in this mode. Refuse a caller-supplied sidecar_path rather
        # than silently ignoring it — it almost certainly indicates a
        # mistake.
        if sidecar_path is not None:
            raise ValueError(
                "sidecar_path is not meaningful when embed=True; "
                "the envelope is stored inside analysis.tdf"
            )
        config_copy_path = embedded_d_config_path(d_path)
    else:
        if sidecar_path is None:
            # The name becomes a filename here; a separator in it would
            # silently place the sidecar in a subdirectory.
            if (
                "/" in experiment_name
                or "\\" in experiment_name
                or experiment_name in ("", ".", "..")
            ):
                raise ValueError(
                    f"experiment_name {experiment_name!r} cannot name a "
                    f"sidecar file; pass sidecar_path explicitly"
                )
            sidecar_path = d_path.parent / f"{experiment_name}.provenance.json"
        else:
            sidecar_path = Path(sidecar_path)
        config_copy_path = sidecar_config_path(sidecar_path)

    # 1. Compute component hashes from disk.
    d_hash = canonicalize_d(d_path)
    config_bytes = config_path.read_bytes()
    config_hash = canonicalize_bytes(config_bytes)
    ground_truth_hash: bytes | None = None
    if ground_truth_path is not None:
        ground_truth_hash = canonicalize_sqlite(ground_truth_path)

    # 1a. Copy the config bytes alongside the artifact so the verifier
    # has something to recompute the signed config_hash against. Without
    # this the config part of the attestation is unverifiable. The copy
    # location is derived from the sidecar/.d path, never from the
    # signed payload, so a tampered ``experiment_name`` cannot redirect
    # the verifier's lookup.
    config_copy_path.parent.mkdir(parents=True, exist_ok=True)
    config_copy_path.write_bytes(config_bytes)

    # 2. Compose the single content hash.
    content_hash = compose_content_hash(
        d_hash=d_hash,
        ground_truth_hash=ground_truth_hash,
        config_hash=config_hash,
    )

    # 3. Resolve a keypair (load or create on first use).
    keypair = _resolve_keypair(private_key_path)

    # 4. Build the payload.
    payload = Payload(
        simulator_name=str(simulator_name),
        simulator_version=str(simulator_version),
        experiment_name=str(experiment_name),
        config_hash=_hex(config_hash),
        d_content_hash=_hex(d_hash),
        ground_truth_hash=_hex(ground_truth_hash) if ground_truth_hash else "",
        content_hash=_hex(content_hash),
        timestamp_utc=_utc_now_iso(),
        key_id=keypair.key_id,
        canonicalization_version=CANONICALIZATION_VERSION,
    )

    # 5. Sign the deterministic JSON serialization of the payload.
    signed_bytes = payload.to_canonical_json()
    signature = keypair.private_key.sign(signed_bytes)

    sidecar = Sidecar(
        payload=payload,
        signature=signature_to_b64(signature),
        verifying_key=public_key_to_b64(keypair.public_key),
        type=ATTESTATION_TYPE,
    )

    # 6. Write the envelope to its transport.
    envelope_bytes = sidecar.to_json_bytes()
    if embed:
        # Local import to avoid a hard dependency on embed_d for the
        # JSON transport path.
        from mzprov.embed_d import write_embedded_provenance
        write_embedded_provenance(d_path, envelope_bytes)
        return d_path
    write_sidecar_atomic(envelope_bytes, sidecar_path)
    return sidecar_path


def write_sidecar_atomic(sidecar_bytes: bytes, sidecar_path: Path) -> None:
    """Write the sidecar bytes to ``sidecar_path`` atomically.

    Implementation: write to ``{sidecar_path}.tmp``, fsync, then rename.
    Guarantees that a reader either sees the old sidecar (if any) or
    the new one — never a half-written file.
    """
    sidecar_path = Path(sidecar_path)
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = sidecar_path.with_suffix(sidecar_path.suffix + ".tmp")
    with open(tmp_path, "wb") as f:
        f.write(sidecar_bytes)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            # Some filesystems do not support fsync; tolerate the failure.
            pass
    os.replace(tmp_path, sidecar_path)


# ---------------------------------------------------------------------------
# mzML signing
# ---------------------------------------------------------------------------


def sign_mzml_output(
    *,
    mzml_path: PathLike,
    config_path: PathLike | None,
    experiment_name: str,
    tool_name: str = "TimSim",
    tool_version: str = "unknown",
    sidecar_path: PathLike | None = None,
    private_key_path: PathLike | None = None,
    embed: bool = False,
) -> Path:
    """Hash, sign, and write a provenance sidecar for an mzML file.

    Use this for any tool that emits mzML — TimSim's own simulator
    does not (it writes Bruker .d), so this entry point is for
    external simulators (Synthedia, SMITER, etc.) and converters
    (msconvert outputs, custom pipelines).

    Parameters
    ----------
    mzml_path
        The mzML file to sign.
    config_path
        Optional path to the tool's config file. If None, the
        ``config_hash`` is computed over an empty byte string and the
        sidecar carries it as such (still distinct from "no config
        field present at all" — both forms are deterministic).
    experiment_name
        The experiment / dataset name (free-form string).
    tool_name, tool_version
        The producing tool's identity, recorded in the payload.
    sidecar_path
        Where to write the sidecar JSON. Defaults to a sibling of the
        mzml file named ``{mzml_stem}.provenance.json``.
    private_key_path
        Override path to an Ed25519 private key. If None, the default
        location ``~/.config/timsim/keys/signing_key.pem`` is used (and
        a key is generated there on first use).

    Returns
    -------
    Path
        The path to the written sidecar.
    """
    mzml_path = Path(mzml_path)
    if not mzml_path.is_file():
        raise MissingArtifact(f"mzml file does not exist: {mzml_path}")

    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise MissingArtifact(f"config file does not exist: {config_path}")
        config_bytes = config_path.read_bytes()
    else:
        config_bytes = b""

    if embed:
        if sidecar_path is not None:
            raise ValueError(
                "sidecar_path is not meaningful when embed=True; "
                "the envelope is stored inside the mzML's fileContent"
            )
        sidecar_path = mzml_path  # the "result path" returned to the caller
        config_copy_target = embedded_mzml_config_path(mzml_path)
    else:
        if sidecar_path is None:
            sidecar_path = mzml_path.with_name(mzml_path.stem + ".provenance.json")
        else:
            sidecar_path = Path(sidecar_path)
        config_copy_target = sidecar_config_path(sidecar_path)

    # 1. Compute component hashes from disk.
    mzml_hash = canonicalize_mzml(mzml_path)
    config_hash = canonicalize_bytes(config_bytes)

    # 1a. Copy the config bytes (if any) into the experiment directory
    # so the verifier has something to check the signed config_hash
    # against. Same convention as the .d signing path: the copy is
    # anchored on the artifact's name (or the sidecar's stem in the
    # JSON-transport case), never on a payload field.
    if config_path is not None:
        config_copy_target.parent.mkdir(parents=True, exist_ok=True)
        config_copy_target.write_bytes(config_bytes)

    # 2. Compose the single content hash.
    content_hash = compose_mzml_content_hash(
        mzml_hash=mzml_hash,
        config_hash=config_hash,
    )

    # 3. Resolve a keypair (load or create on first use).
    keypair = _resolve_keypair(private_key_path)

    # 4. Build the payload.
    payload = MzmlPayload(
        tool_name=str(tool_name),
        tool_version=str(tool_version),
        experiment_name=str(experiment_name),
        config_hash=_hex(config_hash),
        mzml_content_hash=_hex(mzml_hash),
        content_hash=_hex(content_hash),
        timestamp_utc=_utc_now_iso(),
        key_id=keypair.key_id,
        canonicalization_version="v0",
    )

    # 5. Sign the deterministic JSON serialization of the payload.
    signed_bytes = payload.to_canonical_json()
    signature = keypair.private_key.sign(signed_bytes)

    sidecar = MzmlSidecar(
        payload=payload,
        signature=signature_to_b64(signature),
        verifying_key=public_key_to_b64(keypair.public_key),
        type=ATTESTATION_TYPE_MZML,
    )

    # 6. Write the envelope to its transport.
    envelope_bytes = sidecar.to_json_bytes()
    if embed:
        from mzprov.embed_mzml import write_embedded_provenance
        write_embedded_provenance(mzml_path, envelope_bytes)
        return mzml_path
    write_sidecar_atomic(envelope_bytes, sidecar_path)
    return sidecar_path


# ---------------------------------------------------------------------------
# Thermo .raw signing
# ---------------------------------------------------------------------------


def sign_raw_output(
    *,
    raw_path: PathLike,
    config_path: PathLike | None,
    experiment_name: str,
    tool_name: str = "TimSim",
    tool_version: str = "unknown",
    sidecar_path: PathLike | None = None,
    private_key_path: PathLike | None = None,
) -> Path:
    """Hash, sign, and write a provenance sidecar for a Thermo ``.raw`` file.

    A Thermo ``.raw`` is an undocumented proprietary binary. It cannot be
    structurally canonicalized and has no safe injection point for an
    embedded envelope, so its attestation is an **opaque whole-file
    hash** and is **sidecar-only** — there is deliberately no ``embed``
    parameter (contrast ``sign_simulation_output`` / ``sign_mzml_output``).

    Parameters
    ----------
    raw_path
        The Thermo ``.raw`` file to sign.
    config_path
        Optional path to the producing tool's config file. If None, the
        ``config_hash`` is computed over an empty byte string and the
        sidecar carries it as such (still distinct from "no config field
        present at all" — both forms are deterministic).
    experiment_name
        The experiment / dataset name (free-form string).
    tool_name, tool_version
        The producing tool's identity, recorded in the payload.
    sidecar_path
        Where to write the sidecar JSON. Defaults to a sibling of the
        ``.raw`` file named ``{raw_stem}.provenance.json``.
    private_key_path
        Override path to an Ed25519 private key. If None, the default
        location ``~/.config/timsim/keys/signing_key.pem`` is used (and a
        key is generated there on first use).

    Returns
    -------
    Path
        The path to the written sidecar.
    """
    raw_path = Path(raw_path)
    if not raw_path.is_file():
        raise MissingArtifact(f"raw file does not exist: {raw_path}")

    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise MissingArtifact(f"config file does not exist: {config_path}")
        config_bytes = config_path.read_bytes()
    else:
        config_bytes = b""

    if sidecar_path is None:
        sidecar_path = raw_path.with_name(raw_path.stem + ".provenance.json")
    else:
        sidecar_path = Path(sidecar_path)
        # The .raw artifact is located at verify time by stripping ".provenance.json"
        # from the sidecar name and looking for "{stem}.raw" in the SIDECAR's directory
        # (verify._find_raw_for_sidecar) — the pairing is by stem + directory, NOT by a
        # signed basename. A custom sidecar_path that doesn't pair back to raw_path would
        # attest one file but verify a different (or absent) one, so require the pairing.
        name = sidecar_path.name
        if not name.endswith(".provenance.json"):
            raise ValueError(
                f"sidecar_path must end with '.provenance.json' (got {name!r}); the "
                "verifier derives the .raw name from that suffix"
            )
        derived_stem = name[: -len(".provenance.json")]
        if (
            derived_stem != raw_path.stem
            or sidecar_path.parent.resolve() != raw_path.parent.resolve()
        ):
            raise ValueError(
                f"sidecar_path {sidecar_path} does not pair with raw_path {raw_path}: a "
                f".raw sidecar must be named '{raw_path.stem}.provenance.json' beside the "
                ".raw file (the verifier finds the artifact by the sidecar's stem + dir)"
            )
    config_copy_target = sidecar_config_path(sidecar_path)

    # 1. Compute component hashes from disk.
    raw_hash = canonicalize_raw(raw_path)
    config_hash = canonicalize_bytes(config_bytes)

    # 1a. Copy the config bytes (if any) alongside the sidecar so the
    # verifier has something to check the signed config_hash against.
    # Same convention as the .d / mzML signing paths: the copy is
    # anchored on the sidecar's stem, never on a payload field.
    if config_path is not None:
        config_copy_target.parent.mkdir(parents=True, exist_ok=True)
        config_copy_target.write_bytes(config_bytes)

    # 2. Compose the single content hash.
    content_hash = compose_raw_content_hash(
        raw_hash=raw_hash,
        config_hash=config_hash,
    )

    # 3. Resolve a keypair (load or create on first use).
    keypair = _resolve_keypair(private_key_path)

    # 4. Build the payload.
    payload = RawPayload(
        tool_name=str(tool_name),
        tool_version=str(tool_version),
        experiment_name=str(experiment_name),
        config_hash=_hex(config_hash),
        raw_content_hash=_hex(raw_hash),
        content_hash=_hex(content_hash),
        timestamp_utc=_utc_now_iso(),
        key_id=keypair.key_id,
        canonicalization_version="v0",
    )

    # 5. Sign the deterministic JSON serialization of the payload.
    signed_bytes = payload.to_canonical_json()
    signature = keypair.private_key.sign(signed_bytes)

    sidecar = RawSidecar(
        payload=payload,
        signature=signature_to_b64(signature),
        verifying_key=public_key_to_b64(keypair.public_key),
        type=ATTESTATION_TYPE_RAW,
    )

    # 6. Write the envelope to its sidecar transport (no embed for .raw).
    envelope_bytes = sidecar.to_json_bytes()
    write_sidecar_atomic(envelope_bytes, sidecar_path)
    return sidecar_path


def sign_wiff_output(
    *,
    wiff_path: PathLike,
    config_path: PathLike | None,
    experiment_name: str,
    tool_name: str = "TimSim",
    tool_version: str = "unknown",
    sidecar_path: PathLike | None = None,
    private_key_path: PathLike | None = None,
) -> Path:
    """Hash, sign, and write a provenance sidecar for a SCIEX ``.wiff`` BUNDLE.

    A SCIEX ``.wiff`` is an opaque proprietary binary and — unlike a Thermo ``.raw`` —
    a *bundle* (``.wiff`` + ``.wiff.scan`` + ``.wiff2`` + …). Its attestation is an opaque
    whole-BUNDLE hash (``canonicalize_wiff``) and is **sidecar-only** (no embed transport),
    mirroring ``sign_raw_output``. The sidecar is written beside the ``.wiff`` as
    ``{wiff_stem}.provenance.json`` (the verifier finds the bundle by that stem + dir).
    """
    wiff_path = Path(wiff_path)
    if not wiff_path.is_file():
        raise MissingArtifact(f"wiff file does not exist: {wiff_path}")

    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise MissingArtifact(f"config file does not exist: {config_path}")
        config_bytes = config_path.read_bytes()
    else:
        config_bytes = b""

    stem = wiff_path.name[: -len(".wiff")]  # strip the .wiff suffix (Path.stem is unsafe here)
    if sidecar_path is None:
        sidecar_path = wiff_path.with_name(stem + ".provenance.json")
    else:
        sidecar_path = Path(sidecar_path)
        name = sidecar_path.name
        if not name.endswith(".provenance.json"):
            raise ValueError(
                f"sidecar_path must end with '.provenance.json' (got {name!r})"
            )
        derived = name[: -len(".provenance.json")]
        if derived != stem or sidecar_path.parent.resolve() != wiff_path.parent.resolve():
            raise ValueError(
                f"sidecar_path {sidecar_path} does not pair with wiff_path {wiff_path}: a "
                f".wiff sidecar must be named '{stem}.provenance.json' beside the .wiff file"
            )
    config_copy_target = sidecar_config_path(sidecar_path)

    # 1. Component hashes: the whole bundle + the config.
    wiff_hash = canonicalize_wiff(wiff_path)
    config_hash = canonicalize_bytes(config_bytes)
    if config_path is not None:
        config_copy_target.parent.mkdir(parents=True, exist_ok=True)
        config_copy_target.write_bytes(config_bytes)

    # 2. Compose the single content hash.
    content_hash = compose_wiff_content_hash(wiff_hash=wiff_hash, config_hash=config_hash)

    # 3-4. Keypair + payload.
    keypair = _resolve_keypair(private_key_path)
    payload = WiffPayload(
        tool_name=str(tool_name),
        tool_version=str(tool_version),
        experiment_name=str(experiment_name),
        config_hash=_hex(config_hash),
        wiff_content_hash=_hex(wiff_hash),
        content_hash=_hex(content_hash),
        timestamp_utc=_utc_now_iso(),
        key_id=keypair.key_id,
        canonicalization_version="v0",
    )

    # 5. Sign the canonical payload.
    signed_bytes = payload.to_canonical_json()
    signature = keypair.private_key.sign(signed_bytes)
    sidecar = WiffSidecar(
        payload=payload,
        signature=signature_to_b64(signature),
        verifying_key=public_key_to_b64(keypair.public_key),
        type=ATTESTATION_TYPE_WIFF,
    )

    # 6. Write the sidecar (no embed for .wiff).
    write_sidecar_atomic(sidecar.to_json_bytes(), sidecar_path)
    return sidecar_path
