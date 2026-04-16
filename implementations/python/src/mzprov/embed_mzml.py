"""In-band embedding of an mzprov sidecar inside an mzML file.

Mirrors :mod:`mzprov.embed_d`. See ``spec/embedded-mzml-v0.md`` for the
normative protocol. The slot is a ``userParam`` with name
``mzprov:provenance`` inside ``<fileDescription>/<fileContent>``; the
value is the base64 of the v0 envelope JSON.

The slot is canonically excluded by virtue of living in
``<fileDescription>``, which the mzML canonicalizer never enters
(see ``spec/canonicalization-mzml-v0.md`` §1, §2). Embed-after-hash
is therefore well-defined without any change to the canonicalization
algorithm.
"""

from __future__ import annotations

import base64
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Union

from mzprov.errors import MalformedSidecar, MissingArtifact

PathLike = Union[str, Path]

MZML_NS = "http://psi.hupo.org/ms/mzml"
INDEXED_MZML_TAG = f"{{{MZML_NS}}}indexedmzML"
MZML_TAG = f"{{{MZML_NS}}}mzML"
FILE_DESCRIPTION_TAG = f"{{{MZML_NS}}}fileDescription"
FILE_CONTENT_TAG = f"{{{MZML_NS}}}fileContent"
USER_PARAM_TAG = f"{{{MZML_NS}}}userParam"

#: Reserved userParam name for the embedded transport. See
#: ``spec/embedded-mzml-v0.md`` §2. Tools other than mzprov MUST NOT
#: use this name.
EMBEDDED_USERPARAM_NAME = "mzprov:provenance"


def _read_root(mzml_path: Path) -> ET.Element:
    if not mzml_path.is_file():
        raise MissingArtifact(f"mzml file does not exist: {mzml_path}")
    try:
        tree = ET.parse(mzml_path)
    except ET.ParseError as e:
        raise MalformedSidecar(f"mzml is not parseable as XML: {e}") from e
    return tree.getroot()


def _inner_mzml(root: ET.Element) -> ET.Element:
    """Return the inner ``<mzML>`` element, unwrapping ``<indexedmzML>`` if present."""
    if root.tag == MZML_TAG:
        return root
    if root.tag == INDEXED_MZML_TAG:
        inner = root.find(MZML_TAG)
        if inner is None:
            raise MalformedSidecar(
                "indexedmzML wrapper has no inner <mzML> element"
            )
        return inner
    raise MalformedSidecar(
        f"expected <mzML> or <indexedmzML> root, got {root.tag!r}"
    )


def _file_content(inner_mzml: ET.Element, *, create_if_missing: bool) -> ET.Element | None:
    """Return the ``<fileContent>`` element under ``<fileDescription>``.

    If ``create_if_missing=True``, creates ``<fileContent>`` (but not
    ``<fileDescription>`` — that's required by the mzML schema and its
    absence is a malformed input).
    """
    file_desc = inner_mzml.find(FILE_DESCRIPTION_TAG)
    if file_desc is None:
        if create_if_missing:
            raise MalformedSidecar(
                "mzml has no <fileDescription> element; cannot embed"
            )
        return None
    file_content = file_desc.find(FILE_CONTENT_TAG)
    if file_content is None:
        if create_if_missing:
            file_content = ET.SubElement(file_desc, FILE_CONTENT_TAG)
        else:
            return None
    return file_content


def write_embedded_provenance(mzml_path: PathLike, sidecar_bytes: bytes) -> None:
    """Insert (or replace) the embedded sidecar userParam in an mzML file.

    Implements the signer protocol from ``spec/embedded-mzml-v0.md`` §5.
    Strips any ``<indexedmzML>`` wrapper on write — output is plain
    mzML. Re-index downstream (e.g. with msconvert) if a byte-offset
    index is needed.

    Parameters
    ----------
    mzml_path
        The mzML file to embed into. Overwritten atomically.
    sidecar_bytes
        The complete sidecar envelope as bytes (as produced by
        ``Sidecar.to_json_bytes()``). Stored as the base64 of these
        bytes in the userParam's ``value`` attribute.
    """
    mzml_path = Path(mzml_path)
    root = _read_root(mzml_path)
    inner = _inner_mzml(root)

    # Validate UTF-8 up front for a clear error rather than letting
    # base64 mask a producer bug.
    try:
        sidecar_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedSidecar(
            f"sidecar bytes are not valid UTF-8: {e}"
        ) from e

    file_content = _file_content(inner, create_if_missing=True)
    assert file_content is not None  # create_if_missing=True

    # Single-row equivalent: drop any existing mzprov:provenance userParam.
    for up in list(file_content.findall(USER_PARAM_TAG)):
        if up.get("name") == EMBEDDED_USERPARAM_NAME:
            file_content.remove(up)

    encoded = base64.standard_b64encode(sidecar_bytes).decode("ascii")
    new_up = ET.SubElement(file_content, USER_PARAM_TAG)
    new_up.set("name", EMBEDDED_USERPARAM_NAME)
    new_up.set("type", "xsd:string")
    new_up.set("value", encoded)

    # Register the PSI-MS namespace as the default so the output
    # uses xmlns="..." rather than ElementTree's auto-generated ns0:
    # prefixes. This must be set before the serialize call.
    ET.register_namespace("", MZML_NS)

    # The output root is always the inner <mzML>; the indexedmzML
    # wrapper is dropped on write because its byte-offset index would
    # be stale after our insertion (spec §4).
    new_tree = ET.ElementTree(inner)

    tmp_path = mzml_path.with_suffix(mzml_path.suffix + ".tmp")
    # Encoding is utf-8; xml_declaration=True to emit <?xml version="1.0" ...?>.
    new_tree.write(tmp_path, encoding="utf-8", xml_declaration=True)
    os.replace(tmp_path, mzml_path)


def read_embedded_provenance(mzml_path: PathLike) -> bytes | None:
    """Return the embedded sidecar bytes, or None if no embedded slot exists.

    Implements the reader protocol from ``spec/embedded-mzml-v0.md`` §6.
    Returns ``None`` (not an error) when the userParam is absent —
    callers (the verifier) treat that as "fall back to JSON sidecar
    discovery".

    Raises ``MalformedSidecar`` if the slot contains more than one
    userParam, or if the value is not valid base64.
    """
    mzml_path = Path(mzml_path)
    root = _read_root(mzml_path)
    inner = _inner_mzml(root)

    file_content = _file_content(inner, create_if_missing=False)
    if file_content is None:
        return None

    found: list[str] = []
    for up in file_content.findall(USER_PARAM_TAG):
        if up.get("name") == EMBEDDED_USERPARAM_NAME:
            found.append(up.get("value", ""))

    if not found:
        return None
    if len(found) > 1:
        raise MalformedSidecar(
            f"mzml fileContent contains {len(found)} userParams with "
            f"name={EMBEDDED_USERPARAM_NAME!r}; v0 mandates at most one"
        )

    # base64.b64decode supports validate=; standard_b64decode does not.
    # Strict validation rejects whitespace and unexpected chars.
    try:
        return base64.b64decode(found[0], validate=True)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise MalformedSidecar(
            f"mzprov:provenance userParam value is not valid base64: {e}"
        ) from e


def has_embedded_provenance(mzml_path: PathLike) -> bool:
    """Cheap existence check — does the mzml carry an embedded userParam?

    Equivalent to ``read_embedded_provenance(mzml_path) is not None``
    but stops at the first hit and avoids decoding the value body.
    """
    mzml_path = Path(mzml_path)
    root = _read_root(mzml_path)
    inner = _inner_mzml(root)
    file_content = _file_content(inner, create_if_missing=False)
    if file_content is None:
        return False
    for up in file_content.findall(USER_PARAM_TAG):
        if up.get("name") == EMBEDDED_USERPARAM_NAME:
            return True
    return False
