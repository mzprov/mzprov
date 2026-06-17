#!/usr/bin/env python3
"""Cross-implementation round-trip harness for mzprov.

The conformance harness (`run_conformance.py`) proves each implementation
verifies a fixed corpus of committed vectors. This harness proves the
stronger interop property: an attestation **produced** by one implementation
is **accepted** by another. It signs fresh copies of the canonicalization
fixtures with a *signer* command and verifies them with a *verifier* command;
point the two at different implementations to get a differential test.

Usage::

    run_roundtrip.py --signer-cmd "<impl-a> sign" \\
                     --verifier-cmd "<impl-b> verify" \\
                     --key <dir-or-pem> \\
                     [--cases d,d-embed,mzml,mzml-embed,raw] \\
                     [--label "A->B"]

For each case it: copies the source artifact into a fresh temp dir, writes a
config file, runs the signer (asserting exit 0), then runs the verifier on
the temp directory (asserting exit 0). Exits 0 iff every case round-trips.

`--cases` selects which formats to run, because not every signer CLI supports
every format (e.g. the Python reference's `sign` CLI has no `.raw`).
"""
from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent
VECTORS = HARNESS_DIR.parent / "canonicalization"

# case -> (source artifact, copied-name, is_directory, embed)
CASES = {
    "d":          (VECTORS / "d" / "001-minimal.d",        "sample.d",    True,  False),
    "d-embed":    (VECTORS / "d" / "001-minimal.d",        "sample.d",    True,  True),
    "mzml":       (VECTORS / "mzml" / "001-indented.mzML",  "sample.mzML", False, False),
    "mzml-embed": (VECTORS / "mzml" / "001-indented.mzML",  "sample.mzML", False, True),
    "raw":        (VECTORS / "raw" / "001-minimal.raw",     "sample.raw",  False, False),
}


def run_case(name: str, signer: list[str], verifier: list[str], key: str) -> tuple[bool, str]:
    src, copied, is_dir, embed = CASES[name]
    work = Path(tempfile.mkdtemp(prefix=f"rt-{name}-"))
    try:
        dest = work / copied
        if is_dir:
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)

        cfg = work / "rt.config.toml"
        cfg.write_text("roundtrip = true\n")

        sign_cmd = [*signer, str(dest), "--experiment-name", "rt",
                    "--key", key, "--config", str(cfg)]
        if embed:
            sign_cmd.append("--embed")
        s = subprocess.run(sign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if s.returncode != 0:
            return False, f"sign exit {s.returncode}: {s.stderr.strip() or s.stdout.strip()}"

        # Verify by handing the verifier the whole work directory; discovery
        # resolves the artifact + sidecar (or the embedded transport).
        v = subprocess.run([*verifier, str(work)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if v.returncode != 0:
            return False, f"verify exit {v.returncode}: {v.stderr.strip() or v.stdout.strip()}"
        return True, "signed + verified"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--signer-cmd", required=True)
    parser.add_argument("--verifier-cmd", required=True)
    parser.add_argument("--key", required=True, help="Signing key (directory or PEM file).")
    parser.add_argument("--cases", default=",".join(CASES),
                        help="Comma-separated subset of: " + ", ".join(CASES))
    parser.add_argument("--label", default="roundtrip")
    args = parser.parse_args(argv)

    signer = shlex.split(args.signer_cmd)
    verifier = shlex.split(args.verifier_cmd)
    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    unknown = [c for c in cases if c not in CASES]
    if unknown:
        sys.stderr.write(f"unknown case(s): {unknown}\n")
        return 2

    print(f"round-trip [{args.label}]: {' '.join(signer)} <art>  ->  {' '.join(verifier)} <dir>")
    failures = []
    for name in cases:
        ok, detail = run_case(name, signer, verifier, args.key)
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<11} {detail}")
        if not ok:
            failures.append(name)

    print()
    print(f"{len(cases) - len(failures)}/{len(cases)} cases round-tripped"
          + (f", {len(failures)} FAILED" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
