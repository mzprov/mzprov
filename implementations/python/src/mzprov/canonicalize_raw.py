"""Opaque content hashing for Thermo ``.raw`` vendor files.

This is the v0 implementation for the ``.raw`` side of provenance.
Unlike the mzML path (``canonicalize_mzml.py``), which extracts the
spectrum *content* and hashes it in a serialization-invariant way, a
Thermo ``.raw`` file is an **undocumented proprietary binary**. There
is no published structure to canonicalize against and no safe place to
inject an embedded envelope. The v0 ``.raw`` canonicalization is
therefore an **opaque whole-file SHA-256**:

  - It hashes the *exact bytes on disk*, in order, with no structural
    normalization whatsoever.
  - It is consequently sensitive to **any** byte change: a single
    flipped bit, a re-serialization by any tool, a different vendor
    library version that rewrites the container — all change the hash.
    This is **intentional and strict**: without a documented format we
    cannot tell a benign re-encoding from a malicious edit, so we treat
    every byte as load-bearing.
  - Because there is no safe injection point in the vendor binary, the
    ``.raw`` attestation is **sidecar-only**. There is no embed
    transport (contrast ``embed_d.py`` / ``embed_mzml.py``).

VERSIONING DISCIPLINE
=====================

This file is the **v0** implementation. It is **frozen**: see the same
note in ``canonicalize.py`` and ``canonicalize_mzml.py``. Any future
revision that changes what bytes are hashed (e.g. a parser that learns
the container format and excludes a reserved provenance slot, the way
the mzML path excludes ``mzprov:provenance``) lives in
``canonicalize_raw_v1.py`` and bumps the ``canonicalization_version``
field in ``envelope.RawPayload``.

The byte separator ``\\x1f`` (Unit Separator) is the same as the other
canonicalization paths so all canonicalization output across the
package shares one wire format.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

CANONICALIZATION_VERSION = "v0"

# Domain prefix for the composed .raw content hash. Distinct from the
# .d domain prefix in canonicalize.py and the mzML domain prefix in
# canonicalize_mzml.py so the three cannot collide.
_RAW_CONTENT_DOMAIN = b"timsim.raw.v0\x1f"

# Byte separator (same as canonicalize.py / canonicalize_mzml.py for
# cross-format consistency).
US = b"\x1f"  # Unit Separator

# Streaming chunk size for the file hasher.
_HASH_CHUNK = 1 << 20  # 1 MiB


def canonicalize_raw(raw_path: PathLike) -> bytes:
    """Return the SHA-256 of the opaque whole-file content of a ``.raw``.

    The hash is a domain-prefixed streaming SHA-256 over the entire file
    byte stream, read in 1 MiB chunks. There is **no** structural
    normalization: any re-serialization of the file changes the hash.
    See the module docstring for why that strictness is intentional.

    The hash is 32 raw bytes (use ``.hex()`` for the conventional string
    form).

    Raises
    ------
    FileNotFoundError
        If ``raw_path`` is not an existing regular file.
    """
    raw_path = Path(raw_path)
    if not raw_path.is_file():
        raise FileNotFoundError(f"raw file not found: {raw_path}")

    h = hashlib.sha256()
    h.update(b"TIMSIM-RAW-CANONICAL-v0\x1f")
    with open(raw_path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def compose_raw_content_hash(
    *,
    raw_hash: bytes,
    config_hash: bytes,
) -> bytes:
    """Compose the per-component hashes into the single content hash that gets signed.

    Layout: ``sha256(_RAW_CONTENT_DOMAIN || raw_hash || US || config_hash)``.

    The version-tagged domain prefix protects against cross-protocol
    confusion with the ``.d`` ``compose_content_hash`` and the mzML
    ``compose_mzml_content_hash``.
    """
    if not isinstance(raw_hash, (bytes, bytearray)) or len(raw_hash) != 32:
        raise ValueError("raw_hash must be 32 bytes")
    if not isinstance(config_hash, (bytes, bytearray)) or len(config_hash) != 32:
        raise ValueError("config_hash must be 32 bytes")
    h = hashlib.sha256()
    h.update(_RAW_CONTENT_DOMAIN)
    h.update(bytes(raw_hash))
    h.update(US)
    h.update(bytes(config_hash))
    return h.digest()
