"""Path conventions shared between the signer and the verifier.

The signer copies the user's config bytes to a conventional location;
the verifier reads from the same location to recompute the signed
``config_hash``. Both sides MUST derive the path from the on-disk
artifact (or sidecar) location alone — never from a payload field
like ``experiment_name`` — because payload fields are
attacker-controllable and a tampered field could otherwise redirect
the verifier to a phantom file. Centralizing the conventions here
keeps that property in one place.

Three conventions:

- **JSON sidecar transport.** The config copy sits at
  ``{sidecar-stem}.config.toml`` next to the sidecar, where the
  sidecar stem is the sidecar's basename minus ``.provenance.json``.
- **Embedded .d transport.** The config copy sits at
  ``{d-stem}.config.toml`` next to the .d, where the .d stem is the
  directory name minus the ``.d`` suffix.
- **Embedded mzML transport.** The config copy sits at
  ``{mzml-stem}.config.toml`` next to the mzml file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


def sidecar_config_path(sidecar_path: PathLike) -> Path:
    """Conventional config-copy path for the JSON sidecar transport.

    For ``foo.provenance.json`` returns ``foo.config.toml`` in the
    same directory. The sidecar suffix ``.provenance.json`` is
    stripped explicitly so a sidecar like ``a.b.provenance.json``
    yields ``a.b.config.toml``, not ``a.config.toml``.
    """
    sidecar_path = Path(sidecar_path)
    name = sidecar_path.name
    if name.endswith(".provenance.json"):
        stem = name[: -len(".provenance.json")]
    else:
        stem = sidecar_path.stem
    return sidecar_path.parent / f"{stem}.config.toml"


def embedded_d_config_path(d_path: PathLike) -> Path:
    """Conventional config-copy path for the embedded-d transport.

    For ``…/sample.d`` returns ``…/sample.config.toml``. The ``.d``
    suffix is stripped explicitly; if the directory does not end in
    ``.d`` the full directory name is used as the stem.
    """
    d_path = Path(d_path)
    name = d_path.name
    if name.endswith(".d"):
        stem = name[: -len(".d")]
    else:
        stem = name
    return d_path.parent / f"{stem}.config.toml"


def embedded_mzml_config_path(mzml_path: PathLike) -> Path:
    """Conventional config-copy path for the embedded-mzml transport.

    For ``…/sample.mzML`` returns ``…/sample.config.toml``.
    """
    mzml_path = Path(mzml_path)
    return mzml_path.with_name(mzml_path.stem + ".config.toml")
