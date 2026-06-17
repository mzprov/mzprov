#!/usr/bin/env python3
"""Reference *canonicalize driver* for the Python implementation.

The conformance harness (``run_conformance.py``) is implementation-agnostic:
it shells out to a canonicalize command to obtain a canonical hash for each
fixture. This script is that command for the Python reference implementation.

Usage:
    canonicalize_mzprov.py {mzml|d|raw} <input-path>

On success it prints exactly one line to stdout::

    sha256:<hex>

and exits 0. Any other exit code is treated by the harness as a failure.

Other implementations supply their own equivalent (e.g. a C# console app)
and point the harness at it via ``--canonicalize-cmd``; the harness never
imports ``mzprov`` directly, so the contract here — argv shape and the
``sha256:<hex>`` stdout line — is the only thing a new implementation must
match.
"""
from __future__ import annotations

import sys

import mzprov


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            "usage: canonicalize_mzprov.py {mzml|d|raw} <input-path>\n"
        )
        return 2

    fmt, path = argv
    dispatch = {
        "mzml": mzprov.canonicalize_mzml,
        "d": mzprov.canonicalize_d,
        "raw": mzprov.canonicalize_raw,
    }
    fn = dispatch.get(fmt)
    if fn is None:
        sys.stderr.write(
            f"canonicalize_mzprov.py: unknown format {fmt!r} "
            f"(expected one of: {', '.join(sorted(dispatch))})\n"
        )
        return 2

    digest = fn(path)  # 32 raw SHA-256 bytes
    sys.stdout.write("sha256:" + digest.hex() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
