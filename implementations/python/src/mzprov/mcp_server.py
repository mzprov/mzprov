"""``mzprov-mcp``: a Model Context Protocol server for mzprov.

Exposes mzprov to MCP clients (Claude Code, Claude Desktop, and other
agent hosts) over stdio. Every tool is a thin wrapper around the same
library calls the CLIs make, and ``verify`` returns the exact
``timsim.verify-result.v0`` object that ``mzprov verify --json`` prints.

Tools:

    verify              Recompute hashes and check the signature and trust.
    find_provenance     Locate the attestation for a path and return its
                        payload, without verifying anything.
    show_signing_key    The local signing key id and public key. Never
                        creates a key.
    list_trusted_keys   The entries of the trusted-keys registry.
    sign                Only with ``--allow-sign``: sign a .d, mzML or .raw.

Signing is off by default because a signature asserts the key holder's
identity: an agent that can call ``sign`` can attest to any file the server
can read. Adding or removing trusted keys is not exposed at all, since
``mzprov keys trust`` requires a human to state why a key is trusted.

Requires the ``mcp`` extra (Python 3.10+): ``pip install 'mzprov[mcp]'``.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

from mzprov.cli import (
    EXIT_GENERIC,
    EXIT_KEY_ERROR,
    EXIT_OK,
    EXIT_SIDECAR_ERROR,
    EXIT_UNSIGNED,
    _error_to_json_dict,
    _exit_for_failure,
    _result_to_json_dict,
)
from mzprov.envelope import parse_sidecar
from mzprov.errors import (
    KeyNotFoundError,
    MalformedKey,
    MalformedSidecar,
    MissingArtifact,
    SqliteNotQuiescent,
    UnknownVersion,
)
from mzprov.verify import (
    Transport,
    find_provenance_for,
    verify_embedded_d,
    verify_embedded_mzml,
    verify_sidecar,
)

_INSTRUCTIONS = """\
mzprov checks Ed25519 provenance attestations on mass spectrometry data
(Bruker .d directories, mzML, Thermo/Waters .raw, SCIEX .wiff). Use
`verify` to check a file; `overall_ok` is the verdict. A valid signature
proves integrity only. It proves who signed only when `expected_key_id` is
pinned or `require_trusted` is set and the trust status is "ok". Use
`find_provenance` to read who signed what, and when, without hashing the data.
Paths are resolved on the machine running this server."""


# ---------------------------------------------------------------------------
# Tool implementations (plain functions, so tests can call them directly)
# ---------------------------------------------------------------------------


def verify(
    path: str,
    strict: bool = False,
    public_key: str | None = None,
    config: str | None = None,
    expected_key_id: str | None = None,
    require_trusted: bool = False,
) -> dict:
    """Verify the provenance of a .d directory, mzML, .raw or .wiff file,
    a sidecar JSON, or an experiment directory.

    Recomputes the canonical content hashes and checks the Ed25519
    signature. Large .d directories can take minutes. Returns the same
    JSON object as `mzprov verify --json`: `status` is "verified",
    "failed", "unsigned" or "error", `overall_ok` is the verdict, and
    `checks` lists each hash comparison.

    Args:
        path: File, directory or sidecar to verify.
        strict: Report an unsigned input as a failure rather than informational.
        public_key: PEM verifying key to use instead of the embedded one.
        config: Config file to hash instead of the copy next to the sidecar.
        expected_key_id: Fail unless the signing key has this id.
        require_trusted: Fail unless the signing key is in the trusted-keys registry.
    """
    try:
        discovery = find_provenance_for(path)
    except Exception as e:  # noqa: BLE001 - reported to the client, not raised
        # The CLI lets errors other than these three escape discovery; here
        # every failure stays inside the verify-result schema.
        known = (SqliteNotQuiescent, MalformedSidecar, MissingArtifact)
        return _error_to_json_dict(
            status="error",
            exit_code=EXIT_SIDECAR_ERROR if isinstance(e, known) else EXIT_GENERIC,
            error_type=type(e).__name__, error_message=str(e),
        )

    if discovery is None:
        # Same wording as ``mzprov verify``, which formats the path as a Path.
        return _error_to_json_dict(
            status="unsigned",
            exit_code=EXIT_UNSIGNED if strict else EXIT_OK,
            error_type="Unsigned",
            error_message=(
                f"mzprov verify: no provenance sidecar found near {Path(path)}. "
                f"This file or directory is unsigned."
            ),
        )

    transport, sidecar_path = discovery
    verify_fn = {
        Transport.EMBEDDED_D: verify_embedded_d,
        Transport.EMBEDDED_MZML: verify_embedded_mzml,
    }.get(transport, verify_sidecar)
    try:
        result = verify_fn(
            sidecar_path,
            public_key_override=public_key,
            config_path_override=config,
            expected_key_id=expected_key_id,
            require_trusted=require_trusted,
        )
    except Exception as e:  # noqa: BLE001 - reported to the client, not raised
        if isinstance(e, (KeyNotFoundError, MalformedKey)):
            exit_code = EXIT_KEY_ERROR
        elif isinstance(
            e, (SqliteNotQuiescent, MalformedSidecar, UnknownVersion, MissingArtifact)
        ):
            exit_code = EXIT_SIDECAR_ERROR
        else:
            exit_code = EXIT_GENERIC
        return _error_to_json_dict(
            status="error", exit_code=exit_code,
            error_type=type(e).__name__, error_message=str(e),
            sidecar_path=sidecar_path,
        )

    if result.overall_ok:
        return _result_to_json_dict(result, status="verified", exit_code=EXIT_OK)
    return _result_to_json_dict(
        result, status="failed", exit_code=_exit_for_failure(result)
    )


def _read_envelope(transport: Transport, location) -> bytes:
    """Return the raw envelope bytes stored at ``location``."""
    if transport is Transport.EMBEDDED_D:
        from mzprov.embed_d import read_embedded_provenance
        return read_embedded_provenance(location)
    if transport is Transport.EMBEDDED_MZML:
        from mzprov.embed_mzml import read_embedded_provenance
        return read_embedded_provenance(location)
    return Path(location).read_bytes()


def find_provenance(path: str) -> dict:
    """Locate the provenance attestation for a path and return its signed
    payload WITHOUT verifying it.

    Fast: reads only the envelope, never hashes the data. The payload says
    what was signed, by which key, when, and with which tool, but nothing
    in it is trustworthy until `verify` succeeds.

    Args:
        path: File, directory or sidecar to look up.
    """

    discovery = find_provenance_for(path)
    if discovery is None:
        return {"found": False, "transport": None, "location": None,
                "verified": False, "type": None, "payload": None}

    transport, location = discovery
    sidecar = parse_sidecar(_read_envelope(transport, location))
    return {
        "found": True,
        "transport": transport.value,
        "location": str(location),
        "verified": False,
        "type": sidecar.type,
        "payload": asdict(sidecar.payload),
    }


def show_signing_key(key_dir: str | None = None) -> dict:
    """Show the local signing key's id and public key PEM.

    Unlike `mzprov keys show`, this never generates a key: if none exists
    it reports `exists: false`. The private key is never returned.

    Args:
        key_dir: Key directory to read instead of ~/.config/mzprov/keys/.
    """
    from cryptography.hazmat.primitives import serialization

    from mzprov.keys import default_key_dir, derive_key_id, load_private_key

    directory = Path(key_dir) if key_dir is not None else default_key_dir()
    private_path = directory / "signing_key.pem"
    if not private_path.exists():
        return {"exists": False, "key_dir": str(directory),
                "key_id": None, "public_key_pem": None}

    public_key = load_private_key(private_path).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "exists": True,
        "key_dir": str(directory),
        "key_id": derive_key_id(public_key),
        "public_key_pem": pem.decode("ascii"),
    }


def list_trusted_keys(registry: str | None = None) -> dict:
    """List the keys in the trusted-keys registry that `verify` consults
    when `require_trusted` is set.

    Args:
        registry: Registry file to read instead of ~/.config/mzprov/trusted_keys.json.
    """
    from mzprov.trust import TrustedKeyRegistry

    loaded = TrustedKeyRegistry.load(registry)
    return {
        "registry": str(loaded.path),
        "keys": [entry.to_dict() for entry in loaded],
    }


def sign(
    path: str,
    experiment_name: str,
    config: str | None = None,
    ground_truth: str | None = None,
    tool_name: str = "mzprov",
    tool_version: str = "unknown",
    embed: bool = False,
    sidecar: str | None = None,
) -> dict:
    """Sign a Bruker .d directory, an mzML file or a .raw file with the
    local Ed25519 key, exactly as `mzprov sign` does.

    Writes {stem}.provenance.json next to the input (or embeds the envelope
    with `embed`), replacing any existing attestation. Generates the local
    key on first use.

    Args:
        path: The .d directory, .mzML or .raw file to sign.
        experiment_name: Label recorded in the signed payload.
        config: Config file whose bytes are bound to the signature (required for .d).
        ground_truth: synthetic_data.db to bind as well (.d only).
        tool_name: Producing tool recorded in the payload.
        tool_version: Producing tool version recorded in the payload.
        embed: Store the envelope inside the .d or mzML instead of a sidecar (not .raw).
        sidecar: Sidecar output path instead of {stem}.provenance.json.
    """
    from mzprov.sign import sign_mzml_output, sign_raw_output, sign_simulation_output
    from mzprov.sign_cli import _detect_format

    artifact = Path(path)
    if not artifact.exists():
        raise ValueError(f"input does not exist: {artifact}")
    fmt = _detect_format(artifact)
    if not fmt:
        raise ValueError(
            f"{artifact} is not signable: expected a .d directory, an .mzML "
            f"file or a .raw file"
        )
    if embed and sidecar is not None:
        raise ValueError("embed and sidecar are mutually exclusive")
    if fmt == "raw" and embed:
        raise ValueError(".raw attestation is sidecar-only; embed is not supported")

    common = dict(
        config_path=config,
        experiment_name=experiment_name,
        sidecar_path=sidecar,
        private_key_path=None,
    )
    if fmt == "d":
        if config is None:
            raise ValueError("config is required when signing a .d directory")
        written = sign_simulation_output(
            d_path=artifact, ground_truth_path=ground_truth,
            simulator_name=tool_name, simulator_version=tool_version,
            embed=embed, **common,
        )
    elif fmt == "mzml":
        written = sign_mzml_output(
            mzml_path=artifact, tool_name=tool_name, tool_version=tool_version,
            embed=embed, **common,
        )
    else:
        written = sign_raw_output(
            raw_path=artifact, tool_name=tool_name, tool_version=tool_version,
            **common,
        )
    # Report the signer from the envelope just written, not by reloading the
    # key, which could have been replaced in the meantime. Read the written
    # location directly: discovery would miss a custom sidecar name.
    if not embed:
        transport = Transport.SIDECAR_JSON
    elif fmt == "d":
        transport = Transport.EMBEDDED_D
    else:
        transport = Transport.EMBEDDED_MZML
    signer = parse_sidecar(_read_envelope(transport, written)).payload.key_id
    return {
        "signed": str(written),
        "format": fmt,
        "embedded": embed,
        "key_id": signer,
    }


# ---------------------------------------------------------------------------
# Server assembly and entry point
# ---------------------------------------------------------------------------


def build_server(*, allow_sign: bool = False):
    """Return an ``MCPServer`` with the mzprov tools registered.

    ``sign`` is registered only when ``allow_sign`` is true.
    """
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError as e:
        raise ImportError(
            "mzprov-mcp needs the MCP SDK (Python 3.10+): "
            "pip install 'mzprov[mcp]'"
        ) from e

    try:
        from importlib.metadata import version
        server_version = version("mzprov")
    except Exception:  # noqa: BLE001
        server_version = ""

    server = MCPServer(
        name="mzprov", version=server_version, instructions=_INSTRUCTIONS
    )
    read_only = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    server.add_tool(verify, annotations=read_only)
    server.add_tool(find_provenance, annotations=read_only)
    server.add_tool(show_signing_key, annotations=read_only)
    server.add_tool(list_trusted_keys, annotations=read_only)
    if allow_sign:
        server.add_tool(
            sign,
            annotations=ToolAnnotations(
                # Overwrites existing sidecars, config copies and embedded
                # records, and `sidecar` can name any writable file.
                readOnlyHint=False, destructiveHint=True, openWorldHint=False
            ),
        )
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mzprov-mcp",
        description=(
            "Serve mzprov verification (and, with --allow-sign, signing) "
            "to MCP clients over stdio."
        ),
    )
    parser.add_argument(
        "--allow-sign",
        action="store_true",
        help=(
            "Also expose the sign tool, which signs with your local key. "
            "Off by default: a signature asserts your identity."
        ),
    )
    args = parser.parse_args(argv)
    try:
        server = build_server(allow_sign=args.allow_sign)
    except ImportError as e:
        print(f"mzprov-mcp: {e}", file=sys.stderr)
        return 1
    server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
