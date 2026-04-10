"""``mzprov sign`` command-line interface.

Signs a Bruker timsTOF ``.d`` directory or an mzML file with an Ed25519
provenance attestation. Wraps :func:`mzprov.sign.sign_simulation_output`
(for ``.d``) and :func:`mzprov.sign.sign_mzml_output` (for mzML).

The CLI is dispatched both as the unified ``mzprov sign`` subcommand
(via :mod:`mzprov.main`) and as a flat ``mzprov-sign`` console script
(declared in pyproject.toml). Both entry points call :func:`main`.

Exit codes:

    0  EXIT_OK             — sidecar written
    1  EXIT_GENERIC        — invalid arguments / unexpected error
    2  EXIT_KEY_ERROR      — signing key missing or unreadable
    3  EXIT_SIDECAR_ERROR  — input artifact missing, wrong type, or
                              SQLite quiescence violation
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mzprov.errors import (
    KeyNotFoundError,
    MalformedKey,
    MissingArtifact,
    ProvenanceError,
    SqliteNotQuiescent,
)
from mzprov.sign import sign_mzml_output, sign_simulation_output

EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_KEY_ERROR = 2
EXIT_SIDECAR_ERROR = 3


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mzprov sign",
        description=(
            "Sign a Bruker .d directory or an mzML file with an Ed25519 "
            "provenance attestation. The resulting sidecar is written next "
            "to the input as {stem}.provenance.json, with an optional copy "
            "of the config file at {stem}.config.toml."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a .d directory or an mzML file to sign.",
    )
    parser.add_argument(
        "--experiment-name",
        required=True,
        help=(
            "Free-form label for the dataset; recorded in the signed "
            "payload as experiment_name."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a config file whose bytes are hashed and bound to "
            "the signature. The file is also copied next to the sidecar "
            "as {stem}.config.toml so the verifier can recompute the hash. "
            "REQUIRED for .d signing; OPTIONAL for mzML (defaults to an "
            "empty-bytes config_hash if omitted)."
        ),
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=None,
        help=(
            "Optional path to a synthetic_data.db ground-truth SQLite "
            "file. Only meaningful when signing a .d; ignored otherwise."
        ),
    )
    parser.add_argument(
        "--tool-name",
        default="mzprov",
        help=(
            "Producing-tool name (defaults to 'mzprov'). Recorded as "
            "simulator_name in .d payloads and tool_name in mzML payloads."
        ),
    )
    parser.add_argument(
        "--tool-version",
        default="unknown",
        help=(
            "Producing-tool version. Recorded as simulator_version in .d "
            "payloads and tool_version in mzML payloads."
        ),
    )
    parser.add_argument(
        "--key", "--private-key",
        type=Path,
        default=None,
        dest="private_key",
        help=(
            "Override path to an Ed25519 private key (or a directory "
            "containing one). Defaults to the user's local signing key "
            "at ~/.config/timsim/keys/signing_key.pem (auto-generated on "
            "first use)."
        ),
    )
    parser.add_argument(
        "--sidecar",
        type=Path,
        default=None,
        help=(
            "Override the sidecar output path. Defaults to "
            "{stem}.provenance.json in the same directory as the input."
        ),
    )
    return parser


def _detect_format(path: Path) -> str:
    """Return ``'d'`` for a Bruker .d directory, ``'mzml'`` for an mzML
    file, or ``''`` (empty string) if the input is neither."""
    if path.is_dir() and path.suffix == ".d":
        return "d"
    if path.is_file() and path.suffix.lower() == ".mzml":
        return "mzml"
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(
            f"mzprov sign: input does not exist: {args.path}",
            file=sys.stderr,
        )
        return EXIT_SIDECAR_ERROR

    fmt = _detect_format(args.path)
    if not fmt:
        print(
            f"mzprov sign: {args.path} is neither a .d directory nor an "
            f"mzML file. .d directories must have the .d suffix and "
            f"contain analysis.tdf; mzML files must have the .mzML "
            f"extension (case-insensitive).",
            file=sys.stderr,
        )
        return EXIT_SIDECAR_ERROR

    try:
        if fmt == "d":
            if args.config is None:
                print(
                    "mzprov sign: --config is required when signing a "
                    ".d directory (the .d signing path binds the "
                    "experiment to its config bytes)",
                    file=sys.stderr,
                )
                return EXIT_GENERIC
            sidecar_path = sign_simulation_output(
                d_path=args.path,
                ground_truth_path=args.ground_truth,
                config_path=args.config,
                experiment_name=args.experiment_name,
                simulator_version=args.tool_version,
                sidecar_path=args.sidecar,
                private_key_path=args.private_key,
            )
        else:  # fmt == "mzml"
            sidecar_path = sign_mzml_output(
                mzml_path=args.path,
                config_path=args.config,
                experiment_name=args.experiment_name,
                tool_name=args.tool_name,
                tool_version=args.tool_version,
                sidecar_path=args.sidecar,
                private_key_path=args.private_key,
            )
    except (KeyNotFoundError, MalformedKey) as e:
        print(f"mzprov sign: key error: {e}", file=sys.stderr)
        return EXIT_KEY_ERROR
    except (MissingArtifact, SqliteNotQuiescent) as e:
        print(f"mzprov sign: {e}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR
    except ProvenanceError as e:
        print(f"mzprov sign: provenance error: {e}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR
    except Exception as e:  # noqa: BLE001
        print(
            f"mzprov sign: unexpected error: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return EXIT_GENERIC

    print(f"signed: {sidecar_path}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
