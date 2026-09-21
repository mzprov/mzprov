"""mzprov provenance chains (v1) — a signed lineage DAG over derived artifacts.

PROTOTYPE, Python-only. Adds the one thing v0 island sidecars lack: a *signed* reference to the
INPUT artifacts an output was derived from, so a verifier can walk RAW -> peak-pick -> mzML -> ...
back to a trusted acquisition root.

Scope (per design doc + codex review): a chain proves the **integrity of provenance claims** and
lineage, NOT the truth/honesty of a transform. This is the *attested* tier only — no deterministic
re-run yet. "Chain verified" must never be read as "analysis valid".

Security properties implemented (codex hardening):
- the signed digest is the deterministic-JSON of the whole payload, so version + type + inputs are
  all inside the signed bytes (no delimiter folding, no downgrade/strip);
- each edge binds BOTH the parent's artifact content hash AND the parent sidecar's own hash
  (closes splicing); the parent sidecar is resolved *by* that hash (content-addressed);
- trust resolves by the registry, and key_id must equal derive_key_id(verifying_key) (no label
  spoofing); roots use an explicit empty inputs list and must be trusted;
- acyclicity (visited set by sidecar hash) + max depth.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from mzprov.errors import MalformedSidecar
from mzprov.keys import (
    derive_key_id,
    public_key_from_b64,
    public_key_to_b64,
    signature_from_b64,
    signature_to_b64,
)
from mzprov.sign import _resolve_keypair
from mzprov.trust import TrustedKeyRegistry

PathLike = Union[str, Path]

ATTESTATION_TYPE_CHAIN = "mzprov.provenance.chain.v1"
CANON_VERSION = "v1"
CHAIN_SUFFIX = ".chain.json"
MAX_DEPTH = 64

# Exit-code taxonomy (codex precedence: malformed > bad-sig > integrity > broken-link >
# missing-prov > trust). 0 and 3-7 mean what they mean for v0 sidecars; 8 and 9 exist only for
# chains.
EXIT_OK = 0
EXIT_MALFORMED = 3
EXIT_INTEGRITY = 5
EXIT_BAD_SIG = 6
EXIT_TRUST = 7
EXIT_BROKEN_LINK = 8
EXIT_MISSING_PROV = 9


def sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def hash_artifact(path: PathLike) -> str:
    """Whole-file content hash. (A production impl would dispatch to the per-format
    canonicalizer — canonicalize_raw / canonicalize_mzml — here we keep it format-agnostic.)"""
    return sha256_hex(Path(path).read_bytes())


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class InputRef:
    """One edge: a reference to an input artifact + the provenance record about it."""

    role: str
    content_hash: str          # the input artifact's content hash (binds the input bytes)
    parent_key_id: str         # signer of the input's sidecar ("" if unsigned)
    parent_sidecar_hash: str   # sha256 of the parent sidecar bytes ("" if unsigned)

    def _sort_key(self):
        return (self.role, self.content_hash, self.parent_key_id, self.parent_sidecar_hash)

    def to_dict(self) -> dict:
        return {
            "content_hash": self.content_hash,
            "parent_key_id": self.parent_key_id,
            "parent_sidecar_hash": self.parent_sidecar_hash,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InputRef":
        req = {"role", "content_hash", "parent_key_id", "parent_sidecar_hash"}
        if req - d.keys():
            raise MalformedSidecar(f"InputRef missing fields: {sorted(req - d.keys())}")
        return cls(d["role"], d["content_hash"], d["parent_key_id"], d["parent_sidecar_hash"])


@dataclass(frozen=True)
class ChainPayload:
    artifact_content_hash: str
    config_hash: str
    tool_name: str
    tool_version: str
    experiment_name: str
    timestamp_utc: str
    key_id: str
    inputs: tuple  # tuple[InputRef, ...]; empty == root
    canonicalization_version: str = CANON_VERSION
    type: str = ATTESTATION_TYPE_CHAIN

    def to_canonical_json(self) -> bytes:
        """Deterministic UTF-8 JSON of the whole payload — the bytes that get signed. The inputs
        list is sorted by the full tuple (sort_keys alone can't order a list); exact duplicates are
        rejected."""
        srt = sorted(self.inputs, key=lambda i: i._sort_key())
        for a, b in zip(srt, srt[1:]):
            if a == b:
                raise MalformedSidecar("duplicate InputRef in chain payload")
        d = {
            "artifact_content_hash": self.artifact_content_hash,
            "canonicalization_version": self.canonicalization_version,
            "config_hash": self.config_hash,
            "experiment_name": self.experiment_name,
            "inputs": [i.to_dict() for i in srt],
            "key_id": self.key_id,
            "timestamp_utc": self.timestamp_utc,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "type": self.type,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> "ChainPayload":
        req = {
            "artifact_content_hash", "config_hash", "tool_name", "tool_version",
            "experiment_name", "timestamp_utc", "key_id", "inputs",
            "canonicalization_version", "type",
        }
        if req - d.keys():
            raise MalformedSidecar(f"chain payload missing fields: {sorted(req - d.keys())}")
        if d["type"] != ATTESTATION_TYPE_CHAIN:
            raise MalformedSidecar(f"not a chain payload type: {d['type']!r}")
        if d["canonicalization_version"] != CANON_VERSION:  # fail closed on unknown/newer
            raise MalformedSidecar(f"unsupported chain version {d['canonicalization_version']!r}")
        return cls(
            artifact_content_hash=d["artifact_content_hash"], config_hash=d["config_hash"],
            tool_name=d["tool_name"], tool_version=d["tool_version"],
            experiment_name=d["experiment_name"], timestamp_utc=d["timestamp_utc"],
            key_id=d["key_id"], inputs=tuple(InputRef.from_dict(x) for x in d["inputs"]),
            canonicalization_version=d["canonicalization_version"], type=d["type"],
        )


@dataclass(frozen=True)
class ChainSidecar:
    payload: ChainPayload
    signature: str
    verifying_key: str
    type: str = ATTESTATION_TYPE_CHAIN

    def to_json_bytes(self) -> bytes:
        obj = {
            "payload": json.loads(self.payload.to_canonical_json()),
            "signature": self.signature,
            "type": self.type,
            "verifying_key": self.verifying_key,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "ChainSidecar":
        try:
            obj = json.loads(data)
        except Exception as e:  # noqa: BLE001
            raise MalformedSidecar(f"chain sidecar is not JSON: {e}") from e
        for k in ("payload", "signature", "verifying_key", "type"):
            if k not in obj:
                raise MalformedSidecar(f"chain sidecar missing {k!r}")
        return cls(
            payload=ChainPayload.from_dict(obj["payload"]),
            signature=obj["signature"], verifying_key=obj["verifying_key"], type=obj["type"],
        )


# --------------------------------------------------------------------------- signing


def make_input_ref(role: str, parent_sidecar_path: PathLike) -> InputRef:
    """Build an edge from a parent chain sidecar: binds the parent's artifact hash AND the exact
    parent sidecar (by its own hash), so the edge can't be re-pointed at a different record."""
    p = Path(parent_sidecar_path)
    sc_bytes = p.read_bytes()
    sc = ChainSidecar.from_json_bytes(sc_bytes)
    return InputRef(
        role=role,
        content_hash=sc.payload.artifact_content_hash,
        parent_key_id=sc.payload.key_id,
        parent_sidecar_hash=sha256_hex(sc_bytes),
    )


def sign_derivation(
    *,
    artifact_path: PathLike,
    inputs,
    experiment_name: str,
    tool_name: str = "unknown",
    tool_version: str = "unknown",
    config_path: PathLike | None = None,
    sidecar_path: PathLike | None = None,
    private_key_path: PathLike | None = None,
) -> Path:
    """Sign an artifact as a node in the chain. `inputs` is a list of InputRef (empty == root)."""
    artifact_path = Path(artifact_path)
    config_bytes = Path(config_path).read_bytes() if config_path else b""
    keypair = _resolve_keypair(private_key_path)
    payload = ChainPayload(
        artifact_content_hash=hash_artifact(artifact_path),
        config_hash=sha256_hex(config_bytes),
        tool_name=str(tool_name), tool_version=str(tool_version),
        experiment_name=str(experiment_name), timestamp_utc=_utc_now_iso(),
        key_id=keypair.key_id, inputs=tuple(inputs),
    )
    signature = keypair.private_key.sign(payload.to_canonical_json())
    sidecar = ChainSidecar(
        payload=payload, signature=signature_to_b64(signature),
        verifying_key=public_key_to_b64(keypair.public_key),
    )
    if sidecar_path is None:
        sidecar_path = artifact_path.with_name(artifact_path.name + CHAIN_SUFFIX)
    Path(sidecar_path).write_bytes(sidecar.to_json_bytes())
    return Path(sidecar_path)


# --------------------------------------------------------------------------- verify


@dataclass
class NodeResult:
    sidecar_path: str
    key_id: str
    signature_ok: bool
    artifact_ok: Optional[bool]  # None == artifact not present locally (UNCHECKED)
    trusted: bool
    is_root: bool


@dataclass
class ChainResult:
    code: int
    status: str
    nodes: list
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.code == EXIT_OK


def _resolve_parent(search_dir: Path, parent_sidecar_hash: str) -> Optional[Path]:
    """Content-addressed lookup: find the sidecar whose bytes hash to the referenced value."""
    for p in sorted(search_dir.glob(f"*{CHAIN_SUFFIX}")):
        try:
            if sha256_hex(p.read_bytes()) == parent_sidecar_hash:
                return p
        except OSError:
            continue
    return None


def verify_chain(
    sidecar_path: PathLike,
    registry: TrustedKeyRegistry | None = None,
    *,
    require_trusted_chain: bool = False,
    _verified: set | None = None,
    _inprogress: set | None = None,
    _depth: int = 0,
    _nodes: list | None = None,
) -> ChainResult:
    """Walk the DAG from `sidecar_path` to a trusted root. Default policy: root-trust + full
    cryptographic chain integrity; intermediates are tamper-evident but need not be trusted unless
    `require_trusted_chain`."""
    sidecar_path = Path(sidecar_path)
    registry = registry if registry is not None else TrustedKeyRegistry.load()
    _verified = _verified if _verified is not None else set()
    _inprogress = _inprogress if _inprogress is not None else set()
    _nodes = _nodes if _nodes is not None else []
    if _depth > MAX_DEPTH:
        return ChainResult(EXIT_MALFORMED, "max depth exceeded", _nodes)
    try:
        data = sidecar_path.read_bytes()
        sc = ChainSidecar.from_json_bytes(data)
    except (OSError, MalformedSidecar) as e:
        return ChainResult(EXIT_MALFORMED, f"malformed/unreadable: {e}", _nodes)
    sc_hash = sha256_hex(data)
    if sc_hash in _verified:
        # shared ancestor reached via another edge — already fully verified, not a cycle
        return ChainResult(EXIT_OK, "verified (shared ancestor)", _nodes)
    if sc_hash in _inprogress:
        return ChainResult(EXIT_MALFORMED, "cycle detected", _nodes)
    _inprogress.add(sc_hash)
    p = sc.payload

    # 1. signature
    try:
        pub = public_key_from_b64(sc.verifying_key)
        pub.verify(signature_from_b64(sc.signature), p.to_canonical_json())
        sig_ok = True
    except Exception:  # noqa: BLE001
        sig_ok = False
    is_root = len(p.inputs) == 0
    if not sig_ok:
        _nodes.append(NodeResult(str(sidecar_path), p.key_id, False, None, False, is_root))
        return ChainResult(EXIT_BAD_SIG, "signature invalid", _nodes)
    # key_id must be the real fingerprint of the verifying key (no label spoofing)
    if p.key_id != derive_key_id(pub):
        return ChainResult(EXIT_MALFORMED, "key_id does not match verifying_key", _nodes)

    # 2. artifact integrity (sidecar is <artifact>.chain.json)
    artifact_ok: Optional[bool] = None
    if sidecar_path.name.endswith(CHAIN_SUFFIX):
        art = sidecar_path.with_name(sidecar_path.name[: -len(CHAIN_SUFFIX)])
        if art.is_file():
            artifact_ok = hash_artifact(art) == p.artifact_content_hash

    trusted = p.key_id in registry
    _nodes.append(NodeResult(str(sidecar_path), p.key_id, True, artifact_ok, trusted, is_root))
    if artifact_ok is False:
        return ChainResult(EXIT_INTEGRITY, "artifact content hash mismatch", _nodes)

    # 3. walk inputs (each edge: resolve parent by its hash, bind content + key_id, recurse)
    for ref in p.inputs:
        if not ref.parent_sidecar_hash:
            return ChainResult(EXIT_MISSING_PROV, f"unsigned input '{ref.role}'", _nodes)
        parent = _resolve_parent(sidecar_path.parent, ref.parent_sidecar_hash)
        if parent is None:
            return ChainResult(EXIT_MISSING_PROV, f"parent sidecar not found for '{ref.role}'", _nodes)
        try:
            psc = ChainSidecar.from_json_bytes(parent.read_bytes())
        except (OSError, MalformedSidecar) as e:
            return ChainResult(EXIT_MALFORMED, f"parent sidecar malformed for '{ref.role}': {e}", _nodes)
        if psc.payload.artifact_content_hash != ref.content_hash:
            return ChainResult(EXIT_BROKEN_LINK, f"input '{ref.role}': content_hash != parent artifact", _nodes)
        if psc.payload.key_id != ref.parent_key_id:
            return ChainResult(EXIT_BROKEN_LINK, f"input '{ref.role}': parent key_id mismatch", _nodes)
        sub = verify_chain(parent, registry, require_trusted_chain=require_trusted_chain,
                           _verified=_verified, _inprogress=_inprogress, _depth=_depth + 1, _nodes=_nodes)
        if sub.code != EXIT_OK:
            return sub

    # 4. trust policy
    if is_root and not trusted:
        return ChainResult(EXIT_TRUST, f"root signer not trusted: {p.key_id}", _nodes)
    if require_trusted_chain and not trusted:
        return ChainResult(EXIT_TRUST, f"intermediate signer not trusted: {p.key_id}", _nodes)

    _inprogress.discard(sc_hash)
    _verified.add(sc_hash)  # memoize: a fully-verified node is a valid shared ancestor, not a cycle
    return ChainResult(EXIT_OK, "verified", _nodes)
