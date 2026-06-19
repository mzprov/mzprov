"""Verify a TimSim provenance sidecar against the artifacts it describes.

The verifier is pure: it takes a sidecar path, reads the referenced
artifacts, recomputes canonical hashes, and validates the Ed25519
signature. It returns a structured ``VerificationResult`` rather than
raising on every kind of failure — the CLI maps failures to exit codes.

The only exceptions raised are *structural* problems (sidecar missing,
malformed, unknown version, missing referenced artifact). Hash mismatches
and signature mismatches are reported as fields on the result object so
the CLI can render a useful diagnostic listing every check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from enum import Enum
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature

from mzprov.canonicalize import (
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
from mzprov.envelope import (
    ATTESTATION_TYPE,
    ATTESTATION_TYPE_MZML,
    ATTESTATION_TYPE_RAW,
    MzmlPayload,
    MzmlSidecar,
    Payload,
    RawPayload,
    RawSidecar,
    Sidecar,
    parse_sidecar,
)
from mzprov.errors import (
    KeyNotFoundError,
    MalformedSidecar,
    MissingArtifact,
    ProvenanceError,
    Unsigned,
)
from mzprov.keys import (
    derive_key_id,
    load_public_key,
    public_key_from_b64,
    signature_from_b64,
)
from mzprov.paths import (
    embedded_d_config_path,
    embedded_mzml_config_path,
    sidecar_config_path,
)

PathLike = Union[str, Path]

# Possible statuses for an individual FieldCheck. UNCHECKED means we
# could not recompute this hash (e.g. the artifact is missing) — it is
# DELIBERATELY treated as not-ok by overall_ok so that "we couldn't
# verify it" never gets reported as VERIFIED.
STATUS_OK = "ok"
STATUS_MISMATCH = "mismatch"
STATUS_UNCHECKED = "unchecked"


class Transport(str, Enum):
    """Which transport was used to load (or discover) a sidecar envelope.

    Inherits from ``str`` so existing ``transport == "embedded-d"``
    callers keep working — the enum members compare equal to their
    string values.
    """

    SIDECAR_JSON = "sidecar-json"
    EMBEDDED_D = "embedded-d"
    EMBEDDED_MZML = "embedded-mzml"


class Discovery(NamedTuple):
    """Result of ``find_provenance_for``.

    ``transport`` says which path resolved; ``path`` is the file or
    directory the verifier should hand to the matching verify entry
    point. As a NamedTuple this destructures the same way the prior
    ``(str, Path)`` tuple did, so existing callers (``transport, path
    = discovery``) keep working.
    """

    transport: Transport
    path: Path


@dataclass
class FieldCheck:
    """The verification status of a single hash field in the sidecar."""

    name: str
    expected: str  # the hex digest from the sidecar (e.g. "sha256:abc...")
    actual: str  # the hex digest we recomputed (empty if not checked)
    status: str  # one of STATUS_OK / STATUS_MISMATCH / STATUS_UNCHECKED
    detail: str = ""  # optional human-readable explanation (e.g. "no config file found")

    @property
    def ok(self) -> bool:
        """True iff the hash was computed AND matched the signed value."""
        return self.status == STATUS_OK

    def __str__(self) -> str:
        label = {
            STATUS_OK: "OK",
            STATUS_MISMATCH: "MISMATCH",
            STATUS_UNCHECKED: "UNCHECKED",
        }.get(self.status, self.status.upper())
        return f"{self.name:<18} {label}   ({self.expected[:24]}...)"


@dataclass
class TrustCheck:
    """Trust-pinning result. Layered ON TOP of the integrity check.

    Trust is conceptually orthogonal to integrity:

      - Integrity (signature_ok + per-field hash checks): "the bytes match
        what was signed by the key embedded in the sidecar". Always
        evaluated.
      - Trust (this struct): "the embedded key is who I expected it to
        be". Only evaluated if the user passed --expected-key-id or
        --require-trusted; otherwise reported as ``not_requested``.

    A bundle that fails integrity but passes trust is still a failure.
    A bundle that passes integrity but fails trust is also a failure.
    Both must be true for overall_ok.

    Status values:
      - "not_requested": no trust check was requested by the caller.
      - "ok":             the embedded key matched the user's expectation.
      - "id_mismatch":    --expected-key-id was given but the sidecar's
                          key_id is different.
      - "not_in_registry": --require-trusted was given but the sidecar's
                           signing key is not in the trusted-keys registry.
      - "registry_pem_mismatch": --require-trusted was given, the
                                 sidecar's key_id IS in the registry, but
                                 the registered PEM differs from the
                                 sidecar's embedded key. This catches
                                 forgeries that reuse a trusted key_id
                                 but ship different bytes.
    """

    status: str = "not_requested"
    detail: str = ""
    expected_key_id: str = ""
    actual_key_id: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "not_requested")

    @property
    def was_requested(self) -> bool:
        return self.status != "not_requested"


@dataclass
class VerificationResult:
    """The full result of verifying a sidecar.

    ``sidecar_path`` is the on-disk path for the JSON transport. For
    embedded provenance (the envelope lives inside ``analysis.tdf``)
    the field carries the .d directory path instead — there is no
    separate sidecar file. ``transport`` says which mode was used.
    """

    sidecar_path: Path
    payload: Payload
    checks: list = field(default_factory=list)
    signature_ok: bool = False
    overall_ok: bool = False
    trust: TrustCheck = field(default_factory=TrustCheck)
    transport: str = "sidecar-json"  # "sidecar-json" or "embedded-d"


def _hex(b: bytes) -> str:
    return "sha256:" + b.hex()


def _decode_hash(field_value: str) -> bytes:
    """Decode a ``"sha256:hex..."`` string to raw bytes. Returns empty bytes if not present."""
    if not field_value:
        return b""
    if not field_value.startswith("sha256:"):
        raise MalformedSidecar(f"hash field is not sha256-prefixed: {field_value!r}")
    try:
        return bytes.fromhex(field_value[len("sha256:"):])
    except ValueError as e:
        raise MalformedSidecar(f"hash field is not valid hex: {field_value!r}") from e


def find_sidecar_for(path: PathLike) -> Path | None:
    """Given a path to a sidecar, an experiment dir, a .d, an .mzML, or a .raw, return the sidecar path.

    Discovery rules:
        - If ``path`` is itself a sidecar JSON file, return it.
        - If ``path`` is an ``.mzML`` file, look for
          ``{stem}.provenance.json`` in the same directory first; if
          absent, fall back to a UNIQUE ``*.provenance.json`` sibling.
          If neither resolves unambiguously, return ``None``.
        - If ``path`` is a ``.raw`` file (Thermo/Waters; opaque,
          sidecar-only, see ``spec/canonicalization-raw-v0.md``), resolve
          identically to the ``.mzML`` case: ``{stem}.provenance.json``
          first, then a UNIQUE ``*.provenance.json`` sibling.
        - If ``path`` is a ``.d`` directory, the sidecar conventionally
          lives one level up with a stem-based pairing. Look for
          ``{stem}.provenance.json`` in ``path.parent`` (where ``stem``
          is the ``.d`` name without the ``.d`` suffix). If absent,
          fall back to a UNIQUE ``*.provenance.json`` sibling in the
          parent. If neither resolves unambiguously, return ``None``.
        - If ``path`` is any other directory, look for
          ``*.provenance.json`` inside it.
        - Otherwise return None.

    This function discovers JSON sidecars only. When verifying a .d
    that may carry an embedded sidecar (see ``spec/embedded-d-v0.md``),
    callers should use ``find_provenance_for`` instead, which prefers
    the embedded transport over the JSON fallback.

    The "unique sibling" rule is what defends against the multi-bundle
    case where several signed datasets share a parent directory.
    Without it, ``find_sidecar_for(b.d)`` could silently return
    ``a.provenance.json`` from a sibling bundle just because ``a``
    sorts first; with it, the verifier returns ``None`` and forces
    the caller to disambiguate.
    """
    path = Path(path)

    if path.is_file() and path.suffix == ".json" and ".provenance" in path.name:
        return path

    if path.is_file() and path.suffix.lower() == ".mzml":
        candidate = path.with_name(path.stem + ".provenance.json")
        if candidate.is_file():
            return candidate
        # Fall back to a UNIQUE sibling. Multiple matches are
        # ambiguous, not best-effort: returning the first
        # lexicographically would silently pick a sidecar from a
        # different bundle that happens to share the parent directory.
        siblings = sorted(path.parent.glob("*.provenance.json"))
        if len(siblings) == 1:
            return siblings[0]
        return None

    if path.is_file() and path.suffix.lower() == ".raw":
        # Thermo/Waters .raw: opaque, sidecar-only (spec/canonicalization-raw-v0.md).
        # Resolve like the .mzML case — {stem}.provenance.json, then a UNIQUE sibling.
        candidate = path.with_name(path.stem + ".provenance.json")
        if candidate.is_file():
            return candidate
        siblings = sorted(path.parent.glob("*.provenance.json"))
        if len(siblings) == 1:
            return siblings[0]
        return None

    if path.is_dir():
        # If this directory itself looks like a .d, the sidecar lives
        # one level up with a stem-based pairing. The bug-before-fix
        # was that this branch ignored ``path.name`` entirely and just
        # returned the first sibling sidecar lexicographically, which
        # silently picked the wrong sidecar in multi-bundle layouts.
        if path.suffix == ".d":
            stem = path.name[: -len(".d")]
            candidate = path.parent / f"{stem}.provenance.json"
            if candidate.is_file():
                return candidate
            # Fall back to a UNIQUE sibling sidecar in the parent.
            parent_hits = sorted(path.parent.glob("*.provenance.json"))
            if len(parent_hits) == 1:
                return parent_hits[0]
            return None

        # Generic directory: require a UNIQUE *.provenance.json inside.
        # Multiple matches are ambiguous, not best-effort. Returning the
        # first lexicographically would silently verify the wrong bundle
        # in directories that contain several signed datasets.
        hits = sorted(path.glob("*.provenance.json"))
        if len(hits) == 1:
            return hits[0]
        return None

    return None


def _probe_embedded_d(path: Path) -> Path | None:
    """If ``path`` resolves to an embedded-d ``.d``, return its path.

    Resolves either ``path`` itself (when it is the ``.d``) or a
    unique ``.d`` inside ``path`` (the experiment-directory descent
    from ``spec/embedded-d-v0.md`` §6.1). Returns ``None`` when
    nothing resolves OR when the resolved ``.d`` carries no embedded
    row.

    Errors from the embedded probe (``SqliteNotQuiescent``,
    ``MalformedSidecar`` from a multi-row embed, etc.) propagate per
    spec §6.2 — this function deliberately does NOT mask them.
    """
    if path.is_dir() and path.suffix == ".d" and (path / "analysis.tdf").is_file():
        candidate = path
    elif path.is_dir():
        candidate = _find_unique_d(path)
    else:
        return None
    if candidate is None:
        return None

    from mzprov.embed_d import has_embedded_provenance as _has

    return candidate if _has(candidate) else None


def _probe_embedded_mzml(path: Path) -> Path | None:
    """If ``path`` resolves to an embedded-mzml file, return its path.

    Symmetric to ``_probe_embedded_d``: handles a direct ``.mzML``
    path or a unique ``.mzML`` inside an experiment directory.
    Errors propagate per ``spec/embedded-mzml-v0.md`` §7.2.
    """
    if path.is_file() and path.suffix.lower() == ".mzml":
        candidate = path
    elif path.is_dir():
        candidate = _find_unique_mzml(path)
    else:
        return None
    if candidate is None:
        return None

    from mzprov.embed_mzml import has_embedded_provenance as _has

    return candidate if _has(candidate) else None


def find_provenance_for(path: PathLike) -> Discovery | None:
    """Discover provenance for a path, preferring embedded over JSON sidecar.

    Returns a :class:`Discovery` (a ``(transport, path)`` NamedTuple)
    naming the resolved transport, or ``None`` when nothing resolved
    (caller should report ``UNSIGNED``).

    Probe order — embedded first because it is in-band and
    authoritative when both forms are present (per
    ``spec/embedded-d-v0.md`` §6 and ``spec/embedded-mzml-v0.md`` §7):

      1. embedded-d (``.d`` direct OR descent into experiment dir)
      2. embedded-mzml (``.mzML`` direct OR descent into experiment dir)
      3. JSON sidecar discovery via :func:`find_sidecar_for`

    Errors raised by either embedded probe propagate; quietly falling
    back to a sibling JSON sidecar would defeat the "embedded is
    authoritative" guarantee (spec §6.2 / §7.2).
    """
    path = Path(path)

    if (d := _probe_embedded_d(path)) is not None:
        return Discovery(Transport.EMBEDDED_D, d)
    if (m := _probe_embedded_mzml(path)) is not None:
        return Discovery(Transport.EMBEDDED_MZML, m)

    json_sidecar = find_sidecar_for(path)
    if json_sidecar is not None:
        return Discovery(Transport.SIDECAR_JSON, json_sidecar)
    return None


def _find_unique_d(search_root: Path) -> Path | None:
    """Find a unique ``.d`` directory in ``search_root`` or one level deep.

    A ``.d`` is recognized as a directory with ``.d`` suffix that contains
    ``analysis.tdf``. We search the immediate children of ``search_root``
    and one level deeper (to handle the conventional
    ``{save_path}/{exp}/{exp}.d`` layout).

    Path resolution is intentionally INDEPENDENT of the sidecar payload so
    that a tampered ``experiment_name`` field cannot redirect verification
    to a non-existent file. The integrity of the path resolution is what
    lets us treat signature mismatch as a clean diagnostic.

    Returns None if zero or multiple candidates are found.
    """
    candidates: list[Path] = []
    try:
        children = list(search_root.iterdir())
    except OSError:
        return None

    for child in children:
        if not child.is_dir():
            continue
        if child.suffix == ".d" and (child / "analysis.tdf").is_file():
            candidates.append(child)
            continue
        # Look one level deeper for the {exp}/{exp}.d pattern.
        try:
            for grandchild in child.iterdir():
                if (
                    grandchild.is_dir()
                    and grandchild.suffix == ".d"
                    and (grandchild / "analysis.tdf").is_file()
                ):
                    candidates.append(grandchild)
        except OSError:
            continue

    if len(candidates) == 1:
        return candidates[0]
    return None


# The config-copy path conventions live in ``mzprov.paths`` so the
# signer and verifier derive them from a single source. ``_config_path_for_sidecar``
# is kept as an alias so existing callers below continue to read
# unchanged.
_config_path_for_sidecar = sidecar_config_path


def _validate_signer_identity(
    sidecar,
    *,
    public_key_override: PathLike | None,
):
    """Decode the embedded verifying_key, derive its key id, enforce
    consistency with payload.key_id, and (if given) verify the
    --public-key override matches byte-for-byte.

    Returns ``(derived_signer_pubkey, derived_signer_key_id)``.
    Raises ``MalformedSidecar`` for any structural inconsistency
    that means the sidecar's claimed signer is not the actual signer.
    Raises ``KeyNotFoundError`` if ``--public-key`` points at a
    missing file (propagated unchanged from ``load_public_key``).

    This prelude runs identically for every verify path (sidecar
    JSON, embedded-d, embedded-mzml). Centralizing it here means a
    policy change applies to all transports atomically; the previous
    per-path copies were a drift hazard.
    """
    try:
        derived_signer_pubkey = public_key_from_b64(sidecar.verifying_key)
    except (ValueError, TypeError) as e:
        raise MalformedSidecar(
            f"sidecar verifying_key field is not decodable: {e}"
        ) from e
    derived_signer_key_id = derive_key_id(derived_signer_pubkey)

    if sidecar.payload.key_id != derived_signer_key_id:
        raise MalformedSidecar(
            f"sidecar payload.key_id ({sidecar.payload.key_id!r}) does not match "
            f"the key id derived from sidecar.verifying_key "
            f"({derived_signer_key_id!r}). The label and the actual signer "
            f"disagree. This is consistent with a tampered or forged sidecar."
        )

    if public_key_override is not None:
        from cryptography.hazmat.primitives import serialization

        try:
            override_pubkey = load_public_key(public_key_override)
        except KeyNotFoundError:
            raise  # propagate the explicit not-found

        embedded_raw = derived_signer_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        override_raw = override_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if embedded_raw != override_raw:
            raise MalformedSidecar(
                f"--public-key override does not match the verifying_key "
                f"embedded in the sidecar. The override is a consistency "
                f"check against an out-of-band copy of the trusted public "
                f"key; if it does not match the embedded key, the sidecar "
                f"is not what you thought it was."
            )

    return derived_signer_pubkey, derived_signer_key_id


def verify_sidecar(
    sidecar_path: PathLike,
    *,
    public_key_override: PathLike | None = None,
    config_path_override: PathLike | None = None,
    expected_key_id: str | None = None,
    require_trusted: bool = False,
    trusted_registry_path: PathLike | None = None,
) -> VerificationResult:
    """Verify a sidecar by recomputing all referenced hashes and checking the signature.

    Parameters
    ----------
    sidecar_path
        Path to the ``*.provenance.json`` sidecar file.
    public_key_override
        Optional path to a PEM verifying key. If given, this key is used
        instead of the one embedded in the sidecar.
    config_path_override
        Optional path to the TOML config file to hash. If given, this
        path is hashed and compared to ``payload.config_hash``. If not
        given, we look for the conventional ``{stem}.config.toml`` next
        to the sidecar. If neither resolves to a real file, the
        ``config_hash`` check is reported as UNCHECKED — we **never**
        fall back to the signed value, because that would make the
        check tautological.
    expected_key_id
        Optional ad-hoc trust pin. If given, the verifier requires the
        signing key id to equal this value. Mismatch sets the trust
        check status to ``id_mismatch`` and overall_ok to False.
    require_trusted
        If True, the signing key must be present in the trusted-keys
        registry AND its embedded PEM must equal the registered PEM.
        Mismatch sets the trust check status to ``not_in_registry`` or
        ``registry_pem_mismatch`` and overall_ok to False.
    trusted_registry_path
        Optional override for the trusted-keys registry path. Default:
        ``~/.config/timsim/trusted_keys.json``.

    Raises
    ------
    MalformedSidecar
        Sidecar file does not exist, is unreadable, or has the wrong shape.
    UnknownVersion
        Sidecar has a ``type`` or ``canonicalization_version`` we cannot handle.
    MissingArtifact
        Sidecar references a ``.d`` or ``synthetic_data.db`` that does not exist.
    SqliteNotQuiescent
        A SQLite file we need to hash has -wal/-shm/-journal sidecars present.

    Hash mismatches, signature mismatches, and trust mismatches do NOT
    raise; they appear on the returned ``VerificationResult``.
    """
    sidecar_path = Path(sidecar_path)
    if not sidecar_path.is_file():
        raise MalformedSidecar(f"sidecar file does not exist: {sidecar_path}")

    # Dispatch on the sidecar's attestation type. mzml sidecars take a
    # completely different verification path because the artifact is a
    # single file, not a directory, and the payload schema is different.
    parsed = parse_sidecar(sidecar_path.read_bytes())
    if isinstance(parsed, MzmlSidecar):
        return _verify_mzml_sidecar(
            sidecar_path,
            parsed,
            public_key_override=public_key_override,
            config_path_override=config_path_override,
            expected_key_id=expected_key_id,
            require_trusted=require_trusted,
            trusted_registry_path=trusted_registry_path,
        )
    if isinstance(parsed, RawSidecar):
        return _verify_raw_sidecar(
            sidecar_path,
            parsed,
            public_key_override=public_key_override,
            config_path_override=config_path_override,
            expected_key_id=expected_key_id,
            require_trusted=require_trusted,
            trusted_registry_path=trusted_registry_path,
        )

    sidecar = parsed
    payload = sidecar.payload

    derived_signer_pubkey, derived_signer_key_id = _validate_signer_identity(
        sidecar, public_key_override=public_key_override
    )

    # Locate the .d INDEPENDENTLY of the payload, so a tampered
    # experiment_name field cannot redirect verification to a phantom
    # path. We accept either the conventional {save_path}/{exp}/{exp}.d
    # layout or the sibling {save_path}/{exp}.d layout — _find_unique_d
    # handles both.
    save_path = sidecar_path.parent
    d_path = _find_unique_d(save_path)
    if d_path is None:
        raise MissingArtifact(
            f"could not find a unique .d directory near {save_path}"
        )

    return _verify_d_payload(
        sidecar=sidecar,
        sidecar_path=sidecar_path,
        d_path=d_path,
        ground_truth_path=save_path / "synthetic_data.db",
        conventional_config_path=_config_path_for_sidecar(sidecar_path),
        config_path_override=config_path_override,
        derived_signer_pubkey=derived_signer_pubkey,
        derived_signer_key_id=derived_signer_key_id,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
        transport="sidecar-json",
    )


def _verify_d_payload(
    *,
    sidecar: Sidecar,
    sidecar_path: Path,
    d_path: Path,
    ground_truth_path: Path,
    conventional_config_path: Path,
    config_path_override: PathLike | None,
    derived_signer_pubkey,
    derived_signer_key_id: str,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
    transport: str,
) -> VerificationResult:
    """Run integrity + trust checks for an already-parsed .d sidecar.

    Shared between the JSON-sidecar path (``verify_sidecar``) and the
    embedded path (``verify_embedded_d``). The two paths differ only
    in how the sidecar bytes are obtained and how the .d / config
    paths are derived; the field-by-field verification logic is
    identical from here onward.
    """
    payload = sidecar.payload

    # Recompute the .d hash.
    d_hash = canonicalize_d(d_path)

    # Recompute the ground-truth hash if the payload claims one.
    ground_truth_hash: bytes | None = None
    if payload.ground_truth_hash:
        if not ground_truth_path.is_file():
            raise MissingArtifact(
                f"sidecar references a ground-truth DB but none was found at "
                f"{ground_truth_path}"
            )
        ground_truth_hash = canonicalize_sqlite(ground_truth_path)

    # Resolve the config file: explicit override wins, otherwise look
    # for the conventional copy next to the sidecar. We never fall back
    # to the payload's signed value — that would make the check
    # tautological (compare hash to itself => always passes).
    config_hash: bytes | None = None
    config_check_status = STATUS_UNCHECKED
    config_check_actual = ""
    config_check_detail = ""

    if config_path_override is not None:
        config_resolved = Path(config_path_override)
        if not config_resolved.is_file():
            raise MissingArtifact(
                f"--config override points at a missing file: {config_resolved}"
            )
        config_hash = canonicalize_bytes(config_resolved.read_bytes())
        config_check_actual = _hex(config_hash)
        config_check_status = (
            STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
        )
    else:
        if conventional_config_path.is_file():
            config_hash = canonicalize_bytes(conventional_config_path.read_bytes())
            config_check_actual = _hex(config_hash)
            config_check_status = (
                STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
            )
        else:
            config_check_detail = (
                f"no config file found at {conventional_config_path} "
                f"(pass --config to override)"
            )

    checks: list[FieldCheck] = []

    expected_d = payload.d_content_hash
    actual_d = _hex(d_hash)
    checks.append(
        FieldCheck(
            name="d_content_hash",
            expected=expected_d,
            actual=actual_d,
            status=STATUS_OK if expected_d == actual_d else STATUS_MISMATCH,
        )
    )

    if payload.ground_truth_hash:
        expected_g = payload.ground_truth_hash
        actual_g = _hex(ground_truth_hash) if ground_truth_hash is not None else ""
        checks.append(
            FieldCheck(
                name="ground_truth_hash",
                expected=expected_g,
                actual=actual_g,
                status=STATUS_OK if expected_g == actual_g else STATUS_MISMATCH,
            )
        )

    checks.append(
        FieldCheck(
            name="config_hash",
            expected=payload.config_hash,
            actual=config_check_actual,
            status=config_check_status,
            detail=config_check_detail,
        )
    )

    # Recompute the composed content hash. If we could not hash the
    # config from disk, we mark the composed check UNCHECKED rather than
    # use the signed value — same reasoning as above. The .d and ground
    # truth components have already been recomputed independently, so
    # any tampering on those is caught by their own per-field checks.
    if config_hash is None:
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual="",
                status=STATUS_UNCHECKED,
                detail="cannot recompose content_hash without the config file",
            )
        )
    else:
        composed = compose_content_hash(
            d_hash=d_hash,
            ground_truth_hash=ground_truth_hash,
            config_hash=config_hash,
        )
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual=_hex(composed),
                status=(
                    STATUS_OK if payload.content_hash == _hex(composed) else STATUS_MISMATCH
                ),
            )
        )

    # Verify the signature against the canonical payload bytes. The
    # verifying_key was already decoded at the top (derived_signer_pubkey).
    # If --public-key was supplied, we already enforced byte-for-byte
    # equality above, so the override and the embedded key are the same
    # key — there is no need to special-case it here. Decode errors on
    # the signature field surface as MalformedSidecar.
    public_key = derived_signer_pubkey
    try:
        signature_bytes = signature_from_b64(sidecar.signature)
    except (ValueError, MalformedSidecar) as e:
        raise MalformedSidecar(
            f"sidecar signature field is not decodable: {e}"
        ) from e

    signed_bytes = payload.to_canonical_json()

    try:
        public_key.verify(signature_bytes, signed_bytes)
        signature_ok = True
    except InvalidSignature:
        signature_ok = False
    except Exception:
        signature_ok = False

    # Trust check (layered ON TOP of integrity). The actual signer
    # identity comes from the verifying_key, NOT from payload.key_id —
    # we already enforced consistency above, but the trust evaluator
    # treats the derived id as the canonical identity to be defensive.
    trust = _evaluate_trust(
        actual_key_id=derived_signer_key_id,
        actual_pubkey=derived_signer_pubkey,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
    )

    overall_ok = (
        signature_ok
        and all(c.status == STATUS_OK for c in checks)
        and trust.ok
    )

    return VerificationResult(
        sidecar_path=sidecar_path,
        payload=payload,
        checks=checks,
        signature_ok=signature_ok,
        overall_ok=overall_ok,
        trust=trust,
        transport=transport,
    )


def verify_embedded_d(
    d_path: PathLike,
    *,
    public_key_override: PathLike | None = None,
    config_path_override: PathLike | None = None,
    expected_key_id: str | None = None,
    require_trusted: bool = False,
    trusted_registry_path: PathLike | None = None,
) -> VerificationResult:
    """Verify a .d whose sidecar envelope is embedded inside ``analysis.tdf``.

    Reads the envelope from the ``mzprov_provenance`` table (see
    ``spec/embedded-d-v0.md``), then runs the same integrity + trust
    checks as ``verify_sidecar``. Raises ``Unsigned`` if the .d
    contains no embedded provenance — the caller (typically the CLI's
    discovery layer) is expected to have already preferred this path
    over the JSON sidecar fallback when an embedded row exists.
    """
    from mzprov.embed_d import read_embedded_provenance

    d_path = Path(d_path)
    if not d_path.is_dir():
        raise MissingArtifact(f".d directory does not exist: {d_path}")

    envelope_bytes = read_embedded_provenance(d_path)
    if envelope_bytes is None:
        raise Unsigned(
            f"no embedded provenance found in {d_path}/analysis.tdf "
            f"(no mzprov_provenance table or no rows)"
        )

    parsed = parse_sidecar(envelope_bytes)
    if isinstance(parsed, MzmlSidecar):
        raise MalformedSidecar(
            f"embedded provenance in {d_path} is an mzML attestation; "
            f"expected a .d attestation"
        )
    sidecar = parsed
    derived_signer_pubkey, derived_signer_key_id = _validate_signer_identity(
        sidecar, public_key_override=public_key_override
    )

    # The artifact path is the .d we already have — no _find_unique_d
    # search. The conventional config copy is the embedded-d path
    # convention shared with the signer (mzprov.paths).
    conventional_config_path = embedded_d_config_path(d_path)

    return _verify_d_payload(
        sidecar=sidecar,
        sidecar_path=d_path,
        d_path=d_path,
        ground_truth_path=d_path.parent / "synthetic_data.db",
        conventional_config_path=conventional_config_path,
        config_path_override=config_path_override,
        derived_signer_pubkey=derived_signer_pubkey,
        derived_signer_key_id=derived_signer_key_id,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
        transport="embedded-d",
    )


def _evaluate_trust(
    *,
    actual_key_id: str,
    actual_pubkey,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
) -> TrustCheck:
    """Run the optional trust pinning checks. Returns a TrustCheck struct.

    ``actual_key_id`` MUST be derived from the embedded verifying_key by
    the caller (verify_sidecar enforces this). Never accept payload.key_id
    here — it is attacker-controllable and using it would let a forger
    bypass --expected-key-id by lying in the signed payload.

    Both ``expected_key_id`` and ``require_trusted`` are evaluated.
    """
    # No trust pinning requested → always "ok" but flagged as not_requested
    # so the CLI can render it as "(not pinned)" rather than "trusted".
    if expected_key_id is None and not require_trusted:
        return TrustCheck(
            status="not_requested",
            actual_key_id=actual_key_id,
        )

    # Ad-hoc pin via --expected-key-id.
    if expected_key_id is not None:
        if expected_key_id != actual_key_id:
            return TrustCheck(
                status="id_mismatch",
                detail=(
                    f"sidecar was signed by {actual_key_id!r} but caller "
                    f"expected {expected_key_id!r}"
                ),
                expected_key_id=expected_key_id,
                actual_key_id=actual_key_id,
            )

    # Registry-based trust check via --require-trusted.
    if require_trusted:
        # Local import to avoid a circular dep at module load time.
        from mzprov.trust import TrustedKeyRegistry

        try:
            registry = TrustedKeyRegistry.load(trusted_registry_path)
        except MalformedSidecar as e:
            return TrustCheck(
                status="not_in_registry",
                detail=f"trusted-keys registry is malformed: {e}",
                actual_key_id=actual_key_id,
            )

        entry = registry.find(actual_key_id)
        if entry is None:
            return TrustCheck(
                status="not_in_registry",
                detail=(
                    f"key {actual_key_id!r} is not in the trusted-keys "
                    f"registry at {registry.path}. Add it with "
                    f"'timsim-keys trust ...' if you trust this signer."
                ),
                actual_key_id=actual_key_id,
            )

        # Defense in depth: even if the key id matches, compare the raw
        # PEM bytes of the registered key to the actual signer's public
        # key. This catches the (cryptographically improbable) case of
        # an 80-bit key_id collision and is also defense against any
        # unforeseen path where two distinct keys could share an id.
        try:
            registered_pubkey = entry.load_public_key()
        except (ValueError, ProvenanceError) as e:
            return TrustCheck(
                status="registry_pem_mismatch",
                detail=f"could not compare sidecar key to registered key: {e}",
                actual_key_id=actual_key_id,
            )

        from cryptography.hazmat.primitives import serialization

        actual_raw = actual_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        registered_raw = registered_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if actual_raw != registered_raw:
            return TrustCheck(
                status="registry_pem_mismatch",
                detail=(
                    f"sidecar's signing key id {actual_key_id!r} matches a "
                    f"registry entry, but the public key bytes differ. "
                    f"This is consistent with a key_id collision or forgery."
                ),
                actual_key_id=actual_key_id,
            )

    # All requested trust checks passed.
    return TrustCheck(
        status="ok",
        expected_key_id=expected_key_id or "",
        actual_key_id=actual_key_id,
    )


# ---------------------------------------------------------------------------
# mzML verification path
# ---------------------------------------------------------------------------


def _find_unique_mzml(search_root: Path) -> Path | None:
    """Find a unique .mzML file in ``search_root`` (case-insensitive suffix).

    Returns None if zero or multiple are found. Path resolution is
    INDEPENDENT of the sidecar payload so a tampered ``experiment_name``
    field cannot redirect verification to a phantom file.
    """
    candidates: list[Path] = []
    try:
        children = list(search_root.iterdir())
    except OSError:
        return None
    for child in children:
        if child.is_file() and child.suffix.lower() == ".mzml":
            candidates.append(child)
    if len(candidates) == 1:
        return candidates[0]
    return None


def _find_mzml_for_sidecar(sidecar_path: Path) -> Path | None:
    """Find the mzml that this sidecar attests.

    First tries the conventional pairing (a sidecar at
    ``foo.provenance.json`` looks for ``foo.mzML`` in the same
    directory, case-insensitive on the suffix). If that does not
    resolve, falls back to ``_find_unique_mzml`` for legacy bundles
    that did not use the convention. Both lookups are independent of
    the sidecar payload.

    The conventional-pairing-first behavior matters when several
    bundles share the same directory: ``sample_a.provenance.json``
    must find ``sample_a.mzML`` even when ``sample_b.mzML`` is also
    present. The previous uniqueness-only logic incorrectly failed
    in that layout.
    """
    name = sidecar_path.name
    if name.endswith(".provenance.json"):
        stem = name[: -len(".provenance.json")]
    else:
        stem = sidecar_path.stem

    parent = sidecar_path.parent
    # Try the canonical .mzML extension and the lower-case variant.
    # We do not try every casing because most filesystems are
    # case-sensitive and the sign-side convention is exact.
    for suffix in (".mzML", ".mzml"):
        candidate = parent / (stem + suffix)
        if candidate.is_file():
            return candidate

    # Fallback for legacy / non-conventional layouts.
    return _find_unique_mzml(parent)


def _verify_mzml_sidecar(
    sidecar_path: Path,
    sidecar: MzmlSidecar,
    *,
    public_key_override: PathLike | None,
    config_path_override: PathLike | None,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
) -> VerificationResult:
    """Verify an mzML sidecar by recomputing the canonical hash and signature.

    Same defense layering as the .d path:
      - Derive the actual signer key id from sidecar.verifying_key.
      - Enforce payload.key_id consistency.
      - --public-key is a byte-for-byte consistency check.
      - Trust pinning (--expected-key-id, --require-trusted) layers on top.
      - The mzml file is discovered independently of the payload.
    """
    derived_signer_pubkey, derived_signer_key_id = _validate_signer_identity(
        sidecar, public_key_override=public_key_override
    )

    # Discover the .mzML file independently of the payload. Try the
    # conventional {sidecar_stem}.mzML pairing first so co-located
    # bundles in the same directory verify cleanly; fall back to
    # uniqueness only when the convention does not resolve.
    mzml_path = _find_mzml_for_sidecar(sidecar_path)
    if mzml_path is None:
        raise MissingArtifact(
            f"could not find an .mzML file for sidecar {sidecar_path.name} "
            f"(looked for {sidecar_path.parent / (sidecar_path.name.replace('.provenance.json', '.mzML'))} "
            f"and any unique sibling .mzML)"
        )

    # Conventional config copy for the JSON transport — shared
    # convention from mzprov.paths. Anchored on the sidecar's name,
    # never on a payload field.
    conventional_config_path = sidecar_config_path(sidecar_path)

    return _verify_mzml_payload(
        sidecar=sidecar,
        sidecar_path=sidecar_path,
        mzml_path=mzml_path,
        conventional_config_path=conventional_config_path,
        config_path_override=config_path_override,
        derived_signer_pubkey=derived_signer_pubkey,
        derived_signer_key_id=derived_signer_key_id,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
        transport="sidecar-json",
    )


def _verify_mzml_payload(
    *,
    sidecar: MzmlSidecar,
    sidecar_path: Path,
    mzml_path: Path,
    conventional_config_path: Path,
    config_path_override: PathLike | None,
    derived_signer_pubkey,
    derived_signer_key_id: str,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
    transport: str,
) -> VerificationResult:
    """Run integrity + trust checks for an already-parsed mzML sidecar.

    Shared between the JSON-sidecar path and the embedded-mzml path
    (mirror of ``_verify_d_payload``). The two paths differ only in
    how the sidecar bytes are obtained and how the mzml / config
    paths are derived; the field-by-field verification is identical
    from here onward.
    """
    payload = sidecar.payload

    # Recompute the mzml content hash.
    mzml_hash = canonicalize_mzml(mzml_path)

    # Resolve the config file: explicit override wins, otherwise look
    # for the conventional copy next to the sidecar. Same convention
    # as the .d path: never fall back to the payload's signed value.
    config_hash: bytes | None = None
    config_check_status = STATUS_UNCHECKED
    config_check_actual = ""
    config_check_detail = ""

    if config_path_override is not None:
        config_resolved = Path(config_path_override)
        if not config_resolved.is_file():
            raise MissingArtifact(
                f"--config override points at a missing file: {config_resolved}"
            )
        config_hash = canonicalize_bytes(config_resolved.read_bytes())
        config_check_actual = _hex(config_hash)
        config_check_status = (
            STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
        )
    else:
        if conventional_config_path.is_file():
            config_hash = canonicalize_bytes(conventional_config_path.read_bytes())
            config_check_actual = _hex(config_hash)
            config_check_status = (
                STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
            )
        elif payload.config_hash == _hex(canonicalize_bytes(b"")):
            # The signer used config_path=None, so the signed config_hash
            # is sha256(b""). We can recompute that without a file and
            # compare; this is NOT tautological because b"" is a fixed
            # constant, not a value pulled from the payload.
            config_hash = canonicalize_bytes(b"")
            config_check_actual = _hex(config_hash)
            config_check_status = STATUS_OK
        else:
            config_check_detail = (
                f"no config file found at {conventional_config_path} "
                f"(pass --config to override)"
            )

    checks: list[FieldCheck] = []

    expected_m = payload.mzml_content_hash
    actual_m = _hex(mzml_hash)
    checks.append(
        FieldCheck(
            name="mzml_content_hash",
            expected=expected_m,
            actual=actual_m,
            status=STATUS_OK if expected_m == actual_m else STATUS_MISMATCH,
        )
    )

    checks.append(
        FieldCheck(
            name="config_hash",
            expected=payload.config_hash,
            actual=config_check_actual,
            status=config_check_status,
            detail=config_check_detail,
        )
    )

    if config_hash is None:
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual="",
                status=STATUS_UNCHECKED,
                detail="cannot recompose content_hash without the config file",
            )
        )
    else:
        composed = compose_mzml_content_hash(
            mzml_hash=mzml_hash,
            config_hash=config_hash,
        )
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual=_hex(composed),
                status=(
                    STATUS_OK if payload.content_hash == _hex(composed) else STATUS_MISMATCH
                ),
            )
        )

    # Verify signature against the canonical payload bytes.
    public_key = derived_signer_pubkey
    try:
        signature_bytes = signature_from_b64(sidecar.signature)
    except (ValueError, MalformedSidecar) as e:
        raise MalformedSidecar(
            f"sidecar signature field is not decodable: {e}"
        ) from e

    signed_bytes = payload.to_canonical_json()

    try:
        public_key.verify(signature_bytes, signed_bytes)
        signature_ok = True
    except InvalidSignature:
        signature_ok = False
    except Exception:
        signature_ok = False

    trust = _evaluate_trust(
        actual_key_id=derived_signer_key_id,
        actual_pubkey=derived_signer_pubkey,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
    )

    overall_ok = (
        signature_ok
        and all(c.status == STATUS_OK for c in checks)
        and trust.ok
    )

    return VerificationResult(
        sidecar_path=sidecar_path,
        payload=payload,
        checks=checks,
        signature_ok=signature_ok,
        overall_ok=overall_ok,
        trust=trust,
        transport=transport,
    )


def verify_embedded_mzml(
    mzml_path: PathLike,
    *,
    public_key_override: PathLike | None = None,
    config_path_override: PathLike | None = None,
    expected_key_id: str | None = None,
    require_trusted: bool = False,
    trusted_registry_path: PathLike | None = None,
) -> VerificationResult:
    """Verify an mzML whose sidecar envelope is embedded as a userParam.

    Reads the envelope from the ``mzprov:provenance`` userParam in
    ``<fileDescription>/<fileContent>`` (see
    ``spec/embedded-mzml-v0.md`` §6), then runs the same integrity +
    trust checks as ``verify_sidecar``. Raises ``Unsigned`` if the
    mzML carries no embedded slot — the caller (typically the CLI's
    discovery layer) is expected to have already preferred this path
    over the JSON sidecar fallback when an embedded slot exists.
    """
    from mzprov.embed_mzml import read_embedded_provenance

    mzml_path = Path(mzml_path)
    if not mzml_path.is_file():
        raise MissingArtifact(f"mzml file does not exist: {mzml_path}")

    envelope_bytes = read_embedded_provenance(mzml_path)
    if envelope_bytes is None:
        raise Unsigned(
            f"no embedded provenance found in {mzml_path} "
            f"(no mzprov:provenance userParam in fileContent)"
        )

    parsed = parse_sidecar(envelope_bytes)
    if not isinstance(parsed, MzmlSidecar):
        raise MalformedSidecar(
            f"embedded provenance in {mzml_path} is not an mzML "
            f"attestation (got type={parsed.type!r})"
        )
    sidecar = parsed

    derived_signer_pubkey, derived_signer_key_id = _validate_signer_identity(
        sidecar, public_key_override=public_key_override
    )

    # Conventional config copy for embedded mzml — shared convention
    # from mzprov.paths.
    conventional_config_path = embedded_mzml_config_path(mzml_path)

    return _verify_mzml_payload(
        sidecar=sidecar,
        sidecar_path=mzml_path,
        mzml_path=mzml_path,
        conventional_config_path=conventional_config_path,
        config_path_override=config_path_override,
        derived_signer_pubkey=derived_signer_pubkey,
        derived_signer_key_id=derived_signer_key_id,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
        transport="embedded-mzml",
    )


# ---------------------------------------------------------------------------
# Thermo .raw verification path
# ---------------------------------------------------------------------------


def _find_raw_for_sidecar(sidecar_path: Path) -> Path | None:
    """Find the ``.raw`` that this sidecar attests.

    Unlike the mzML path, ``.raw`` discovery is **exact** and independent
    of the payload: a sidecar at ``{name}.provenance.json`` attests the
    file ``{name}.raw`` in the same directory. There is no
    unique-sibling fallback — the ``.raw`` attestation is sidecar-only
    and the pairing is always by stem. Returns ``None`` if the exact
    file does not exist.
    """
    name = sidecar_path.name
    if name.endswith(".provenance.json"):
        stem = name[: -len(".provenance.json")]
    else:
        stem = sidecar_path.stem

    parent = sidecar_path.parent
    # Accept ``{stem}.raw``, tolerating ``{stem}.RAW`` on case-sensitive filesystems
    # that store an upper-case extension. If BOTH exist as DISTINCT files the pairing is
    # ambiguous — refuse rather than silently pick one (dedup by resolved path so a
    # case-insensitive filesystem, where the two names are one file, is not ambiguous).
    found: list[Path] = []
    for suffix in (".raw", ".RAW"):
        candidate = parent / (stem + suffix)
        if candidate.is_file():
            key = candidate.resolve()
            if not any(p.resolve() == key for p in found):
                found.append(candidate)
    if len(found) > 1:
        raise MalformedSidecar(
            f"ambiguous .raw pairing for sidecar {sidecar_path}: both {stem}.raw and "
            f"{stem}.RAW exist"
        )
    return found[0] if found else None


def _verify_raw_sidecar(
    sidecar_path: Path,
    sidecar: RawSidecar,
    *,
    public_key_override: PathLike | None,
    config_path_override: PathLike | None,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
) -> VerificationResult:
    """Verify a ``.raw`` sidecar by recomputing the opaque hash and signature.

    Same defense layering as the .d / mzML paths:
      - Derive the actual signer key id from sidecar.verifying_key.
      - Enforce payload.key_id consistency.
      - --public-key is a byte-for-byte consistency check.
      - Trust pinning (--expected-key-id, --require-trusted) layers on top.
      - The .raw file is discovered independently of the payload, by the
        exact ``{sidecar_stem}.raw`` pairing.

    There is no embedded transport for ``.raw``, so this is the only
    entry point into the raw verification path.
    """
    derived_signer_pubkey, derived_signer_key_id = _validate_signer_identity(
        sidecar, public_key_override=public_key_override
    )

    # Discover the .raw file independently of the payload, by the exact
    # {sidecar_stem}.raw pairing. If that file is missing this is a
    # structural error: the artifact the sidecar attests is gone.
    raw_path = _find_raw_for_sidecar(sidecar_path)
    if raw_path is None:
        name = sidecar_path.name
        if name.endswith(".provenance.json"):
            stem = name[: -len(".provenance.json")]
        else:
            stem = sidecar_path.stem
        raise MissingArtifact(
            f"could not find the .raw file for sidecar {sidecar_path.name} "
            f"(looked for {sidecar_path.parent / (stem + '.raw')})"
        )

    # Conventional config copy for the JSON transport — shared
    # convention from mzprov.paths. Anchored on the sidecar's name,
    # never on a payload field.
    conventional_config_path = sidecar_config_path(sidecar_path)

    return _verify_raw_payload(
        sidecar=sidecar,
        sidecar_path=sidecar_path,
        raw_path=raw_path,
        conventional_config_path=conventional_config_path,
        config_path_override=config_path_override,
        derived_signer_pubkey=derived_signer_pubkey,
        derived_signer_key_id=derived_signer_key_id,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
        transport="sidecar-json",
    )


def _verify_raw_payload(
    *,
    sidecar: RawSidecar,
    sidecar_path: Path,
    raw_path: Path,
    conventional_config_path: Path,
    config_path_override: PathLike | None,
    derived_signer_pubkey,
    derived_signer_key_id: str,
    expected_key_id: str | None,
    require_trusted: bool,
    trusted_registry_path: PathLike | None,
    transport: str,
) -> VerificationResult:
    """Run integrity + trust checks for an already-parsed ``.raw`` sidecar.

    Mirror of ``_verify_mzml_payload`` with the opaque whole-file hash in
    place of the content hash. There is no embedded transport for
    ``.raw``, so ``transport`` is always ``"sidecar-json"``; the
    parameter is kept for symmetry with the other payload verifiers.
    """
    payload = sidecar.payload

    # Recompute the opaque whole-file raw hash.
    raw_hash = canonicalize_raw(raw_path)

    # Resolve the config file: explicit override wins, otherwise look
    # for the conventional copy next to the sidecar. Same convention as
    # the .d / mzML paths: never fall back to the payload's signed value.
    config_hash: bytes | None = None
    config_check_status = STATUS_UNCHECKED
    config_check_actual = ""
    config_check_detail = ""

    if config_path_override is not None:
        config_resolved = Path(config_path_override)
        if not config_resolved.is_file():
            raise MissingArtifact(
                f"--config override points at a missing file: {config_resolved}"
            )
        config_hash = canonicalize_bytes(config_resolved.read_bytes())
        config_check_actual = _hex(config_hash)
        config_check_status = (
            STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
        )
    else:
        if conventional_config_path.is_file():
            config_hash = canonicalize_bytes(conventional_config_path.read_bytes())
            config_check_actual = _hex(config_hash)
            config_check_status = (
                STATUS_OK if payload.config_hash == config_check_actual else STATUS_MISMATCH
            )
        elif payload.config_hash == _hex(canonicalize_bytes(b"")):
            # The signer used config_path=None, so the signed config_hash
            # is sha256(b""). We can recompute that without a file and
            # compare; this is NOT tautological because b"" is a fixed
            # constant, not a value pulled from the payload.
            config_hash = canonicalize_bytes(b"")
            config_check_actual = _hex(config_hash)
            config_check_status = STATUS_OK
        else:
            config_check_detail = (
                f"no config file found at {conventional_config_path} "
                f"(pass --config to override)"
            )

    checks: list[FieldCheck] = []

    expected_r = payload.raw_content_hash
    actual_r = _hex(raw_hash)
    checks.append(
        FieldCheck(
            name="raw_content_hash",
            expected=expected_r,
            actual=actual_r,
            status=STATUS_OK if expected_r == actual_r else STATUS_MISMATCH,
        )
    )

    checks.append(
        FieldCheck(
            name="config_hash",
            expected=payload.config_hash,
            actual=config_check_actual,
            status=config_check_status,
            detail=config_check_detail,
        )
    )

    if config_hash is None:
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual="",
                status=STATUS_UNCHECKED,
                detail="cannot recompose content_hash without the config file",
            )
        )
    else:
        composed = compose_raw_content_hash(
            raw_hash=raw_hash,
            config_hash=config_hash,
        )
        checks.append(
            FieldCheck(
                name="content_hash",
                expected=payload.content_hash,
                actual=_hex(composed),
                status=(
                    STATUS_OK if payload.content_hash == _hex(composed) else STATUS_MISMATCH
                ),
            )
        )

    # Verify signature against the canonical payload bytes.
    public_key = derived_signer_pubkey
    try:
        signature_bytes = signature_from_b64(sidecar.signature)
    except (ValueError, MalformedSidecar) as e:
        raise MalformedSidecar(
            f"sidecar signature field is not decodable: {e}"
        ) from e

    signed_bytes = payload.to_canonical_json()

    try:
        public_key.verify(signature_bytes, signed_bytes)
        signature_ok = True
    except InvalidSignature:
        signature_ok = False
    except Exception:
        signature_ok = False

    trust = _evaluate_trust(
        actual_key_id=derived_signer_key_id,
        actual_pubkey=derived_signer_pubkey,
        expected_key_id=expected_key_id,
        require_trusted=require_trusted,
        trusted_registry_path=trusted_registry_path,
    )

    overall_ok = (
        signature_ok
        and all(c.status == STATUS_OK for c in checks)
        and trust.ok
    )

    return VerificationResult(
        sidecar_path=sidecar_path,
        payload=payload,
        checks=checks,
        signature_ok=signature_ok,
        overall_ok=overall_ok,
        trust=trust,
        transport=transport,
    )
