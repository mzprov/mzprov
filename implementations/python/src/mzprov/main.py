"""mzprov unified CLI dispatcher.

Routes:

    mzprov verify <args...>    -> mzprov.cli:main
    mzprov keys <args...>      -> mzprov.keys_cli:main
    mzprov sign <args...>      -> not yet wired as a CLI in v0 of the lift;
                                  use the Python API:
                                      mzprov.sign_simulation_output(...)
                                      mzprov.sign_mzml_output(...)

The unified CLI is a thin dispatcher: each subcommand is implemented as a
standalone module with its own ``main()`` function, and is also available as
a direct script (``mzprov-verify``, ``mzprov-keys``) for users who prefer
the flat command surface.

The legacy TimSim entry points (``timsim-verify``, ``timsim-keys``) continue
to work via the ``imspy_simulation.provenance`` shim, which re-exports this
package; see the rustims project for that side of the migration.
"""
from __future__ import annotations

import sys


_USAGE = """\
usage: mzprov <subcommand> [args...]

subcommands:
  verify       verify a sidecar (.d directory, mzML file, or sidecar JSON)
  keys         manage signing keys and the trusted-keys registry
  sign         sign a .d or mzML file
                 (not yet wired as a CLI in v0; use the Python API:
                  mzprov.sign_simulation_output, mzprov.sign_mzml_output)

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

    if sub == "sign":
        sys.stderr.write(
            "mzprov sign: not yet wired as a CLI in v0 of the lift.\n"
            "Use the Python API:\n"
            "  from mzprov import sign_simulation_output, sign_mzml_output\n"
        )
        return 2

    sys.stderr.write(f"mzprov: unknown subcommand: {sub}\n\n")
    sys.stderr.write(_USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
