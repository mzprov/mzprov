#!/usr/bin/env python3
"""Language-agnostic conformance harness for the mzprov test vectors.

This script is the *executable* definition of "what it means to pass the
mzprov conformance suite". It is intentionally implementation-agnostic: it
drives a **verify command** and a **canonicalize command** supplied on the
command line, so the same harness validates the Python reference
implementation, the (forthcoming) C# implementation, and any future
implementation in any language.

It performs the three checks mandated by ``test-vectors/README.md``:

  1. ``sidecar/valid/``    — every vector MUST verify (exit code 0).
  2. ``sidecar/invalid/``  — every vector MUST be rejected with the exit
                             code declared in its ``_metadata.expected_exit_code``.
  3. ``canonicalization/`` — every input MUST canonicalize to the committed
                             expected hash, byte-for-byte.

The verifier *exit code* is the cross-implementation signal: the exit codes
0-7 are frozen at v0 (see ``CONTRIBUTING.md`` — "What is frozen at v0"), so
two implementations agree iff they return the same exit code on every
vector. Failure-reason strings are human diagnostics and are NOT part of the
machine contract, so this harness keys on exit codes only.

Usage::

    run_conformance.py [--vectors DIR]
                       [--verify-cmd CMD]
                       [--canonicalize-cmd CMD]
                       [-q]

``CMD`` strings are split with ``shlex``; the harness appends the target
path (and, for canonicalization, the format token) as trailing arguments.
The defaults drive the Python reference implementation:

    --verify-cmd        "mzprov verify"
    --canonicalize-cmd  "python <this-dir>/canonicalize_mzprov.py"

A new implementation runs the SAME harness with its own two commands, e.g.::

    run_conformance.py \\
        --verify-cmd "dotnet implementations/csharp/.../mzprov.dll verify" \\
        --canonicalize-cmd "dotnet implementations/csharp/.../canon.dll"

The harness exits 0 iff every vector passes, and 1 otherwise. It always
prints a full per-vector report before the summary so a failure localizes
itself without re-running.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Locations. The harness lives at test-vectors/_harness/, so the vectors root
# is its parent directory by default.
# ---------------------------------------------------------------------------
HARNESS_DIR = Path(__file__).resolve().parent
DEFAULT_VECTORS = HARNESS_DIR.parent
DEFAULT_VERIFY_CMD = "mzprov verify"
DEFAULT_CANON_CMD = f"{shlex.quote(sys.executable)} {shlex.quote(str(HARNESS_DIR / 'canonicalize_mzprov.py'))}"

# Canonicalization fixtures live under canonicalization/<format>/ and the
# input artifact for each <stem>.canonical-hash.txt carries this suffix.
CANON_INPUT_SUFFIX = {"mzml": ".mzML", "d": ".d", "raw": ".raw"}
HASH_SUFFIX = ".canonical-hash.txt"


class Result:
    """One vector's outcome. ``ok`` drives the process exit code."""

    __slots__ = ("section", "name", "ok", "detail")

    def __init__(self, section: str, name: str, ok: bool, detail: str) -> None:
        self.section = section
        self.name = name
        self.ok = ok
        self.detail = detail


def _read_expected_exit_code(vector_dir: Path) -> int | None:
    """Return the declared ``expected_exit_code`` for a vector directory.

    Two transports carry the metadata differently:

      * sidecar vectors carry an ``_metadata`` object inside their
        ``*.provenance.json`` — this is authoritative, since it lives in the
        signed artifact's actual sidecar;
      * embedded vectors have no sibling ``*.provenance.json`` and instead
        ship a standalone ``_metadata.json``.

    The provenance sidecar therefore wins when present, and the standalone
    file is only a fallback for the embedded transport. A vector that
    declares an exit code in *both* places is ambiguous — rather than guess
    which one is authoritative, raise ``ValueError`` so the caller records a
    clear failure (the project's refuse-ambiguity rule applies to vector
    authoring too).

    Returns ``None`` if no metadata declares an exit code (a vector authoring
    error the harness surfaces as a failure rather than guessing).
    """
    provenance_code = None
    for prov in sorted(vector_dir.glob("*.provenance.json")):
        obj = json.loads(prov.read_text())
        meta = obj.get("_metadata")
        if isinstance(meta, dict) and "expected_exit_code" in meta:
            provenance_code = meta["expected_exit_code"]
            break

    standalone_code = None
    standalone = vector_dir / "_metadata.json"
    if standalone.is_file():
        meta = json.loads(standalone.read_text())
        if "expected_exit_code" in meta:
            standalone_code = meta["expected_exit_code"]

    if provenance_code is not None and standalone_code is not None:
        raise ValueError(
            "vector declares expected_exit_code in both a *.provenance.json "
            "_metadata block and a standalone _metadata.json; refusing to "
            "guess which is authoritative"
        )
    if provenance_code is not None:
        return provenance_code
    return standalone_code


def _run_verify(verify_cmd: list[str], target: Path) -> int:
    """Invoke the verify command on ``target`` and return its exit code.

    Raises ``RuntimeError`` (not ``OSError``) if the command cannot be
    launched at all — e.g. ``--verify-cmd`` names a missing executable —
    so callers can record a clean failed Result instead of crashing with a
    traceback that swallows the per-vector report.
    """
    try:
        proc = subprocess.run(
            [*verify_cmd, str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise RuntimeError(
            f"could not run verify command {' '.join(verify_cmd)!r}: {exc}"
        ) from exc
    return proc.returncode


def check_sidecar_valid(vectors: Path, verify_cmd: list[str]) -> list[Result]:
    results: list[Result] = []
    root = vectors / "sidecar" / "valid"
    for vector_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        try:
            code = _run_verify(verify_cmd, vector_dir)
        except RuntimeError as exc:
            results.append(Result("sidecar/valid", vector_dir.name, False, str(exc)))
            continue
        ok = code == 0
        results.append(
            Result(
                "sidecar/valid",
                vector_dir.name,
                ok,
                f"exit {code} (want 0)" if not ok else "verified (exit 0)",
            )
        )
    return results


def check_sidecar_invalid(vectors: Path, verify_cmd: list[str]) -> list[Result]:
    results: list[Result] = []
    root = vectors / "sidecar" / "invalid"
    for vector_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        try:
            want = _read_expected_exit_code(vector_dir)
        except ValueError as exc:
            results.append(Result("sidecar/invalid", vector_dir.name, False, str(exc)))
            continue
        if want is None:
            results.append(
                Result(
                    "sidecar/invalid",
                    vector_dir.name,
                    False,
                    "no _metadata.expected_exit_code found",
                )
            )
            continue
        try:
            code = _run_verify(verify_cmd, vector_dir)
        except RuntimeError as exc:
            results.append(Result("sidecar/invalid", vector_dir.name, False, str(exc)))
            continue
        ok = code == want
        results.append(
            Result(
                "sidecar/invalid",
                vector_dir.name,
                ok,
                f"exit {code} (want {want})",
            )
        )
    return results


def _run_canonicalize(canon_cmd: list[str], fmt: str, target: Path) -> str:
    """Invoke the canonicalize command and return its ``sha256:<hex>`` line.

    Raises ``RuntimeError`` on both a nonzero exit and a launch failure
    (missing executable) so the caller can record a failed Result.
    """
    try:
        proc = subprocess.run(
            [*canon_cmd, fmt, str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(
            f"could not run canonicalize command {' '.join(canon_cmd)!r}: {exc}"
        ) from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"canonicalize command exited {proc.returncode}: "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    return proc.stdout.strip()


def _canon_input_artifacts(fmt_dir: Path, fmt: str):
    """Yield the input artifacts in ``fmt_dir`` for canonicalization format ``fmt``.

    For ``d`` these are ``*.d`` *directories*; for ``mzml``/``raw`` they are
    ``*.mzML``/``*.raw`` *files*. Non-artifacts (README.md, the hash files
    themselves) are ignored.
    """
    suffix = CANON_INPUT_SUFFIX[fmt]
    for child in fmt_dir.iterdir():
        if not child.name.endswith(suffix):
            continue
        if fmt == "d":
            if child.is_dir():
                yield child
        elif child.is_file():
            yield child


def check_canonicalization(vectors: Path, canon_cmd: list[str]) -> list[Result]:
    """Check every canonicalization fixture, and guard against silent coverage loss.

    A conformance run must not go green just because fixtures disappeared, so
    this also fails if a required v0 format directory is missing or empty, and
    cross-checks both directions: every ``*.canonical-hash.txt`` must have an
    input artifact, and every input artifact must have an expected hash.
    """
    results: list[Result] = []
    root = vectors / "canonicalization"
    for fmt in sorted(CANON_INPUT_SUFFIX):
        suffix = CANON_INPUT_SUFFIX[fmt]
        fmt_dir = root / fmt
        if not fmt_dir.is_dir():
            results.append(
                Result(
                    "canonicalization",
                    fmt,
                    False,
                    f"required format directory canonicalization/{fmt}/ is missing",
                )
            )
            continue

        hash_files = sorted(fmt_dir.glob(f"*{HASH_SUFFIX}"))
        if not hash_files:
            results.append(
                Result(
                    "canonicalization",
                    fmt,
                    False,
                    f"canonicalization/{fmt}/ has no *{HASH_SUFFIX} fixtures",
                )
            )
            continue

        # Forward: every expected hash has an input that canonicalizes to it.
        hashed_stems: set[str] = set()
        for hash_file in hash_files:
            stem = hash_file.name[: -len(HASH_SUFFIX)]
            hashed_stems.add(stem)
            target = fmt_dir / (stem + suffix)
            name = f"{fmt}/{stem}"
            if not target.exists():
                results.append(
                    Result(
                        "canonicalization",
                        name,
                        False,
                        f"input artifact not found: {target.name}",
                    )
                )
                continue
            want = hash_file.read_text().strip()
            try:
                got = _run_canonicalize(canon_cmd, fmt, target)
            except RuntimeError as exc:
                results.append(
                    Result("canonicalization", name, False, str(exc))
                )
                continue
            ok = got == want
            results.append(
                Result(
                    "canonicalization",
                    name,
                    ok,
                    "hash matches" if ok else f"got {got} (want {want})",
                )
            )

        # Reverse: every input artifact must have a committed expected hash,
        # so an untested fixture cannot slip in alongside the contract.
        for artifact in sorted(_canon_input_artifacts(fmt_dir, fmt)):
            stem = artifact.name[: -len(suffix)]
            if stem not in hashed_stems:
                results.append(
                    Result(
                        "canonicalization",
                        f"{fmt}/{stem}",
                        False,
                        f"input artifact {artifact.name} has no {stem}{HASH_SUFFIX}",
                    )
                )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_conformance.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--vectors",
        type=Path,
        default=DEFAULT_VECTORS,
        help="Path to the test-vectors/ directory (default: the harness's parent).",
    )
    parser.add_argument(
        "--verify-cmd",
        default=DEFAULT_VERIFY_CMD,
        help=f"Verify command; target path is appended (default: {DEFAULT_VERIFY_CMD!r}).",
    )
    parser.add_argument(
        "--canonicalize-cmd",
        default=DEFAULT_CANON_CMD,
        help="Canonicalize command; format token + input path are appended "
        "(default: the bundled Python driver).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only print failures and the final summary.",
    )
    args = parser.parse_args(argv)

    vectors = args.vectors.resolve()
    verify_cmd = shlex.split(args.verify_cmd)
    canon_cmd = shlex.split(args.canonicalize_cmd)

    if not (vectors / "sidecar").is_dir():
        sys.stderr.write(
            f"run_conformance.py: {vectors} does not look like a vectors "
            f"directory (no sidecar/ subdir).\n"
        )
        return 2

    print(f"mzprov conformance harness")
    print(f"  vectors:          {vectors}")
    print(f"  verify-cmd:       {' '.join(verify_cmd)} <target>")
    print(f"  canonicalize-cmd: {' '.join(canon_cmd)} <format> <input>")
    print()

    results: list[Result] = []
    results += check_sidecar_valid(vectors, verify_cmd)
    results += check_sidecar_invalid(vectors, verify_cmd)
    results += check_canonicalization(vectors, canon_cmd)

    current_section = None
    for r in results:
        if r.section != current_section:
            current_section = r.section
            print(f"[{current_section}]")
        if r.ok and args.quiet:
            continue
        mark = "PASS" if r.ok else "FAIL"
        print(f"  {mark}  {r.name:<46} {r.detail}")

    failures = [r for r in results if not r.ok]
    print()
    print(
        f"{len(results) - len(failures)}/{len(results)} vectors passed"
        + (f", {len(failures)} FAILED" if failures else "")
    )
    if failures:
        print("\nFailures:")
        for r in failures:
            print(f"  - {r.section}/{r.name}: {r.detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
