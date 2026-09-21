"""mzprov unified CLI dispatcher.

Routes:

    mzprov sign   <args...>    -> mzprov.sign_cli:main
    mzprov verify <args...>    -> mzprov.cli:main
    mzprov keys   <args...>    -> mzprov.keys_cli:main
    mzprov chain  <args...>    -> mzprov.chain_cli:main

The unified CLI is a thin dispatcher: each subcommand is implemented as a
standalone module with its own ``main()`` function, and is also available
as a direct flat console script (``mzprov-sign``, ``mzprov-verify``,
``mzprov-keys``) for users who prefer the flat command surface.

The legacy TimSim entry points (``timsim-verify``, ``timsim-keys``)
continue to work via the ``imspy_simulation.provenance`` shim, which
re-exports this package; see the rustims project for that side of the
migration.
"""
from __future__ import annotations

import sys


_USAGE = """\
usage: mzprov <subcommand> [args...]

subcommands:
  sign         sign a .d directory or an mzML file with an Ed25519 attestation
  verify       verify a sidecar (.d directory, mzML file, or sidecar JSON)
  keys         manage signing keys and the trusted-keys registry
  chain        sign and verify provenance chains (v1 prototype)

global flags:
  -h, --help     show this message
  -V, --version  show the mzprov package version

run 'mzprov <subcommand> --help' for subcommand help.
"""


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``mzprov`` console script."""
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        sys.stderr.write(_USAGE)
        return 2

    sub = argv[0]
    rest = argv[1:]

    if sub in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0

    if sub in ("-V", "--version", "version"):
        try:
            from importlib.metadata import version

            print(f"mzprov {version('mzprov')}")
        except Exception:
            print("mzprov (version unknown)")
        return 0

    if sub == "verify":
        from mzprov.cli import main as _verify_main

        sys.argv = ["mzprov verify", *rest]
        return _verify_main() or 0

    if sub == "keys":
        from mzprov.keys_cli import main as _keys_main

        sys.argv = ["mzprov keys", *rest]
        return _keys_main() or 0

    if sub == "chain":
        from mzprov.chain_cli import main as _chain_main

        return _chain_main(rest)

    if sub == "sign":
        from mzprov.sign_cli import main as _sign_main

        sys.argv = ["mzprov sign", *rest]
        return _sign_main() or 0

    sys.stderr.write(f"mzprov: unknown subcommand: {sub}\n\n")
    sys.stderr.write(_USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
