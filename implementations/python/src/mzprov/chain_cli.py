"""``mzprov chain`` — sign and verify provenance chains (v1 prototype).

    mzprov chain sign   <artifact> --experiment-name N [--input ROLE=PARENT.chain.json ...]
    mzprov chain verify <artifact | artifact.chain.json> [--trusted-keys PATH]

A chain sidecar sits next to its artifact as ``<artifact>.chain.json``. A node
with no ``--input`` is a root; verification walks every input back to a root,
which must be in the trusted-keys registry. Parent sidecars are found by hash
in the same directory as the child.

Exit codes for ``chain verify``:

    0  verified
    3  malformed sidecar or graph (unreadable, cyclic, too deep, key id mismatch)
    5  an artifact no longer matches its signed content hash
    6  a signature does not verify
    7  the root (or, with --require-trusted-chain, any) signer is not trusted
    8  broken link: an input does not match the parent it points to
    9  missing provenance: an input is unsigned or its parent sidecar is absent

A verified chain shows the provenance claims are intact, not that any
transform was correct.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mzprov.chain import CHAIN_SUFFIX, make_input_ref, sign_derivation, verify_chain
from mzprov.errors import KeyNotFoundError, MalformedKey, MalformedSidecar
from mzprov.trust import TrustedKeyRegistry

EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_KEY_ERROR = 2
EXIT_SIDECAR_ERROR = 3

_USAGE = """\
usage: mzprov chain <sign|verify> [args...]

  sign     sign an artifact as a chain node, referencing its inputs
  verify   walk an artifact's chain back to a trusted root

run 'mzprov chain <sign|verify> --help' for details.
"""


def _parse_input(value: str) -> tuple[str, Path]:
    role, sep, path = value.partition("=")
    if not sep or not role or not path:
        raise argparse.ArgumentTypeError(
            f"expected ROLE=PARENT{CHAIN_SUFFIX}, got {value!r}"
        )
    return role, Path(path)


def _sign(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mzprov chain sign",
        description=(
            "Sign an artifact as a node in a provenance chain. With no --input "
            "the node is a root, such as a raw acquisition."
        ),
    )
    parser.add_argument("artifact", type=Path, help="the file to sign")
    parser.add_argument("--experiment-name", required=True)
    parser.add_argument(
        "--input",
        dest="inputs",
        action="append",
        default=[],
        type=_parse_input,
        metavar=f"ROLE=PARENT{CHAIN_SUFFIX}",
        help=(
            "an input this artifact was derived from, given as a role and the "
            "input's chain sidecar (repeatable)"
        ),
    )
    parser.add_argument("--tool-name", default="unknown")
    parser.add_argument("--tool-version", default="unknown")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument(
        "--sidecar",
        type=Path,
        default=None,
        help=f"where to write the sidecar (default: <artifact>{CHAIN_SUFFIX})",
    )
    parser.add_argument(
        "--key", "--private-key",
        type=Path,
        default=None,
        dest="private_key",
        help="Ed25519 private key or its directory (default: the local signing key)",
    )
    args = parser.parse_args(argv)

    if not args.artifact.is_file():
        print(f"mzprov chain sign: not a file: {args.artifact}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR
    if args.config is not None and not args.config.is_file():
        print(f"mzprov chain sign: config not found: {args.config}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR
    try:
        refs = [make_input_ref(role, parent) for role, parent in args.inputs]
        sidecar = sign_derivation(
            artifact_path=args.artifact,
            inputs=refs,
            experiment_name=args.experiment_name,
            tool_name=args.tool_name,
            tool_version=args.tool_version,
            config_path=args.config,
            sidecar_path=args.sidecar,
            private_key_path=args.private_key,
        )
    except (KeyNotFoundError, MalformedKey) as e:
        print(f"mzprov chain sign: key error: {e}", file=sys.stderr)
        return EXIT_KEY_ERROR
    except (OSError, MalformedSidecar) as e:
        print(f"mzprov chain sign: input error: {e}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR

    print(f"signed: {sidecar}")
    return EXIT_OK


def _verify(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="mzprov chain verify",
        description=(
            "Verify an artifact's chain: every signature, every artifact present "
            "locally, every link, back to a trusted root."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help=f"the artifact, or its {CHAIN_SUFFIX} sidecar",
    )
    parser.add_argument(
        "--trusted-keys",
        type=Path,
        default=None,
        help="trusted-keys registry (default: the local registry, see 'mzprov keys')",
    )
    parser.add_argument(
        "--require-trusted-chain",
        action="store_true",
        help="require every signer in the chain to be trusted, not just the root",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    path = args.path
    if not path.name.endswith(CHAIN_SUFFIX):
        path = path.with_name(path.name + CHAIN_SUFFIX)

    try:
        registry = TrustedKeyRegistry.load(args.trusted_keys)
    except MalformedSidecar as e:
        print(f"mzprov chain verify: {e}", file=sys.stderr)
        return EXIT_SIDECAR_ERROR
    result = verify_chain(
        path, registry, require_trusted_chain=args.require_trusted_chain
    )

    if args.json:
        print(json.dumps(
            {
                "schema": "mzprov.chain-verify-result.v1",
                "exit_code": result.code,
                "status": result.status,
                "nodes": [
                    {
                        "sidecar": n.sidecar_path,
                        "key_id": n.key_id,
                        "is_root": n.is_root,
                        "signature_ok": n.signature_ok,
                        "artifact_ok": n.artifact_ok,
                        "trusted": n.trusted,
                    }
                    for n in result.nodes
                ],
            },
            indent=2,
            sort_keys=True,
        ))
        return result.code

    print("mzprov chain verification")
    for n in result.nodes:
        artifact = {True: "OK", False: "MISMATCH", None: "not present"}[n.artifact_ok]
        print(
            f"  {'root' if n.is_root else 'node'}  {n.sidecar_path}\n"
            f"        key {n.key_id}{' (trusted)' if n.trusted else ''}, "
            f"signature {'OK' if n.signature_ok else 'INVALID'}, artifact {artifact}"
        )
    print()
    print("VERIFIED" if result.ok else f"FAILED: {result.status}")
    return result.code


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        (sys.stdout if argv else sys.stderr).write(_USAGE)
        return 0 if argv else 2
    sub, rest = argv[0], argv[1:]
    if sub == "sign":
        return _sign(rest)
    if sub == "verify":
        return _verify(rest)
    sys.stderr.write(f"mzprov chain: unknown subcommand: {sub}\n\n{_USAGE}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
