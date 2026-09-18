"""Canonicalization for SCIEX ``.wiff`` outputs — an opaque, sidecar-only bundle hash.

A SCIEX acquisition is a **bundle**, not a single file: the ``.wiff`` (OLE2 method +
scan directory), the sibling ``.wiff.scan`` (the packed spectra), and usually a
``.wiff2`` (plus other same-stem siblings, e.g. ``.timeseries.data``). Like a Thermo
``.raw`` it is an undocumented proprietary binary with no safe injection point, so its
attestation is an **opaque whole-content hash** over the *entire bundle* and is
**sidecar-only**. Unlike ``.raw``, the hash must cover every bundle member — the spectra
live in ``.wiff.scan``, so hashing the ``.wiff`` alone would attest nothing about the data.

The bundle hash binds each member's basename AND bytes, so adding/removing a member or
renaming one is detected, not just editing content.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

CANONICALIZATION_VERSION = "v0"

# Domain prefix for the composed .wiff content hash. Distinct from the .d / mzML / .raw
# domain prefixes so the attestations cannot collide across formats.
_WIFF_CONTENT_DOMAIN = b"timsim.wiff.v0\x1f"

US = b"\x1f"  # Unit Separator
_HASH_CHUNK = 1 << 20  # 1 MiB streaming


def wiff_bundle_members(wiff_path: PathLike) -> list[Path]:
    """Return the sorted list of files in a ``.wiff`` bundle.

    The bundle is every regular file in the ``.wiff``'s directory whose name begins with
    the ``.wiff`` stem (the basename with the trailing ``.wiff`` removed) — i.e.
    ``X.wiff``, ``X.wiff.scan``, ``X.wiff2``, ``X.timeseries.data``, … — EXCLUDING any
    attestation *output* that shares the stem: the ``.provenance.json`` sidecar and the
    ``.config.toml`` config copy the signer writes beside it (see ``mzprov.paths``). Those
    are produced BY signing, not inputs TO it; including them would make the hash depend on
    its own outputs (verify would recompute a different member set than sign saw and always
    mismatch). Deterministically sorted by name so the hash is order-independent.
    """
    wiff_path = Path(wiff_path)
    name = wiff_path.name
    if not name.lower().endswith(".wiff"):
        raise ValueError(f"not a .wiff path: {wiff_path}")
    stem = name[: -len(".wiff")]
    members = []
    for f in wiff_path.parent.iterdir():
        if not f.is_file() or not f.name.startswith(stem):
            continue
        # Never fold in our own attestation outputs: the sidecar JSON or the config copy.
        # Both are written BY the signer beside the bundle and share the stem prefix.
        if f.name.endswith(".provenance.json") or ".provenance." in f.name:
            continue
        if f.name.endswith(".config.toml"):
            continue
        members.append(f)
    return sorted(members, key=lambda p: p.name)


def canonicalize_wiff(wiff_path: PathLike) -> bytes:
    """Return the SHA-256 of the opaque whole-content of a ``.wiff`` bundle.

    A domain-prefixed streaming SHA-256 over each bundle member in name order: for each
    member it folds in ``US || basename || US || <streamed file bytes>``. No structural
    normalization — any re-serialization of any member changes the hash. 32 raw bytes.

    Raises
    ------
    FileNotFoundError
        If ``wiff_path`` is not an existing regular file (or has no bundle members).
    """
    wiff_path = Path(wiff_path)
    if not wiff_path.is_file():
        raise FileNotFoundError(f"wiff file not found: {wiff_path}")
    members = wiff_bundle_members(wiff_path)
    if not members:
        raise FileNotFoundError(f"no .wiff bundle members found for {wiff_path}")

    h = hashlib.sha256()
    h.update(b"TIMSIM-WIFF-CANONICAL-v0\x1f")
    for member in members:
        h.update(US)
        h.update(member.name.encode("utf-8"))
        h.update(US)
        with open(member, "rb") as f:
            while True:
                chunk = f.read(_HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    return h.digest()


def compose_wiff_content_hash(*, wiff_hash: bytes, config_hash: bytes) -> bytes:
    """Compose the per-component hashes into the single content hash that gets signed.

    Layout: ``sha256(_WIFF_CONTENT_DOMAIN || wiff_hash || US || config_hash)`` — the
    version-tagged domain prefix protects against cross-protocol confusion with the
    ``.d`` / mzML / ``.raw`` compose functions.
    """
    if not isinstance(wiff_hash, (bytes, bytearray)) or len(wiff_hash) != 32:
        raise ValueError("wiff_hash must be 32 bytes")
    if not isinstance(config_hash, (bytes, bytearray)) or len(config_hash) != 32:
        raise ValueError("config_hash must be 32 bytes")
    h = hashlib.sha256()
    h.update(_WIFF_CONTENT_DOMAIN)
    h.update(bytes(wiff_hash))
    h.update(US)
    h.update(bytes(config_hash))
    return h.digest()
