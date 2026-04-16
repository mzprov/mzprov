"""End-to-end demo: signing a Bruker .d via both transports.

Runs the same lifecycle for two transports of the v0 attestation:

  1. Sidecar JSON  — a `*.provenance.json` file alongside the .d.
  2. Embedded     — the envelope stored inside `analysis.tdf`'s
                    `mzprov_provenance` table (spec/embedded-d-v0.md).

For each transport the script:
  - builds a fresh synthetic .d in its own experiment directory,
  - signs it,
  - shows the resulting layout and verifies it,
  - tampers with the .d's data and shows the failure surface,
  - tampers with the sidecar / embedded envelope itself and shows
    the failure surface.

Usage:
    python examples/demo_d_transports.py
    python examples/demo_d_transports.py --keep   # don't clean up the workdir

Requires `mzprov` to be importable. The script invokes the CLI as
`python -m mzprov.main ...` so it works whether or not the `mzprov`
console script is on PATH.
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

# We use the in-tree fixture builder so the demo is reproducible
# without a real simulator. The .d it produces is small but
# representative (multiple tables, multiple value types, deterministic
# binary blob).
from mzprov._fixtures import make_minimal_d


CLI = [sys.executable, "-m", "mzprov.main"]


# ---------------------------------------------------------------------------
# Output helpers — make the script readable when its stdout becomes the demo.
# ---------------------------------------------------------------------------


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def step(title: str) -> None:
    print()
    print(f"--- {title}")


def shell(*args: str) -> int:
    """Run a CLI command, echo it the way a user would type it, print output.

    Returns the process exit code so callers can assert on it.
    """
    pretty = "mzprov " + " ".join(_quote(a) for a in args)
    print(f"$ {pretty}")
    proc = subprocess.run(CLI + list(args), capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.stderr:
        # stderr is shown separately so the failure paths are obvious.
        for line in proc.stderr.rstrip().splitlines():
            print(f"  [stderr] {line}")
    print(f"  (exit {proc.returncode})")
    return proc.returncode


def _quote(s: str) -> str:
    return f'"{s}"' if " " in s else s


def show_tree(root: Path, label: str) -> None:
    print(f"{label}")
    rel_root = root.name
    print(f"  {rel_root}/")
    for entry in sorted(root.rglob("*")):
        rel = entry.relative_to(root)
        depth = len(rel.parts)
        indent = "  " * (depth + 1)
        suffix = "/" if entry.is_dir() else ""
        print(f"{indent}{rel.parts[-1]}{suffix}")


# ---------------------------------------------------------------------------
# Workdir builders — each transport gets its own clean experiment dir.
# ---------------------------------------------------------------------------


def build_experiment(parent: Path, name: str) -> Path:
    """Build a synthetic experiment directory at ``parent/name``.

    Layout:
        {name}/
            sample.d/
                analysis.tdf
                analysis.tdf_bin
            sample.config.toml      (the user's config bytes)
    """
    exp = parent / name
    exp.mkdir(parents=True, exist_ok=True)
    make_minimal_d(exp, name="sample")
    (exp / "sample.config.toml").write_bytes(
        b"[experiment]\n"
        b'name = "demo-d-transports"\n'
        b'description = "synthetic .d for the mzprov v0 transport demo"\n'
    )
    return exp


# ---------------------------------------------------------------------------
# The two transport demos.
# ---------------------------------------------------------------------------


def demo_sidecar_json(workdir: Path, key_path: Path) -> None:
    section("TRANSPORT A — sidecar JSON")
    print(
        "The sidecar lives in a *.provenance.json file next to the .d.\n"
        "This is the universal v0 transport — works for any artifact,\n"
        "including formats we cannot embed into (Thermo .raw, Waters)."
    )

    exp = build_experiment(workdir, "experiment-json")
    show_tree(exp, "\nbefore signing:")

    step("sign with default JSON transport")
    rc = shell(
        "sign",
        str(exp / "sample.d"),
        "--config",
        str(exp / "sample.config.toml"),
        "--experiment-name",
        "demo-json",
        "--key",
        str(key_path),
    )
    assert rc == 0, "JSON sign should succeed"
    show_tree(exp, "\nafter signing (note new files at the experiment-dir level):")

    step("verify the experiment directory")
    rc = shell("verify", str(exp))
    assert rc == 0, "JSON verify should succeed"

    step("tamper: edit a row in the .d's analysis.tdf, then re-verify")
    print(
        "  $ sqlite3 sample.d/analysis.tdf "
        '"UPDATE Frames SET Time = 999.0 WHERE Id = 1;"'
    )
    with sqlite3.connect(str(exp / "sample.d" / "analysis.tdf")) as conn:
        conn.execute("UPDATE Frames SET Time = 999.0 WHERE Id = 1;")
        conn.commit()
    rc = shell("verify", str(exp))
    assert rc == 5, f"data tamper should be HASH_MISMATCH (5), got {rc}"
    print("  -> exit 5 (HASH_MISMATCH) — d_content_hash diverged from the signed value.")

    step("tamper: edit the sidecar JSON itself, then re-verify")
    sidecar_path = exp / "demo-json.provenance.json"
    text = sidecar_path.read_text()
    # Mutate the experiment_name in the signed payload — an attacker
    # who wants to relabel the dataset.
    mutated = text.replace('"demo-json"', '"MUTATED-LABEL"', 1)
    assert mutated != text, "expected to find experiment_name in sidecar"
    sidecar_path.write_text(mutated)
    print(f'  $ sed -i "s/demo-json/MUTATED-LABEL/" {sidecar_path.name}')
    rc = shell("verify", str(exp))
    # 6 = SIGNATURE_MISMATCH (signed bytes no longer match) is the
    # normal outcome here. The verifier may also catch the change as
    # KEY_ID_CONSISTENCY (3) if the mutation crosses that field, but
    # for an experiment_name flip we expect 6.
    assert rc != 0, "sidecar tamper must not silently verify"
    print(f"  -> exit {rc} — the signature no longer matches the canonical payload bytes.")


def demo_embedded(workdir: Path, key_path: Path) -> None:
    section("TRANSPORT B — embedded (in-band, inside analysis.tdf)")
    print(
        "The same v0 envelope is stored as a row in a reserved\n"
        "`mzprov_provenance` table inside `analysis.tdf`. The .d's\n"
        "canonical content hash is unchanged — the table is excluded\n"
        "from canonicalization (spec/canonicalization-d-v0.md §3.2)."
    )

    exp = build_experiment(workdir, "experiment-embed")
    show_tree(exp, "\nbefore signing:")

    step("sign with --embed")
    rc = shell(
        "sign",
        str(exp / "sample.d"),
        "--config",
        str(exp / "sample.config.toml"),
        "--experiment-name",
        "demo-embed",
        "--key",
        str(key_path),
        "--embed",
    )
    assert rc == 0, "embed sign should succeed"
    show_tree(exp, "\nafter signing (no new files — the envelope is inside analysis.tdf):")

    step("inspect: pull the embedded envelope back out with sqlite3")
    print('  $ sqlite3 sample.d/analysis.tdf "SELECT sidecar_json FROM mzprov_provenance"')
    with sqlite3.connect(str(exp / "sample.d" / "analysis.tdf")) as conn:
        (raw,) = conn.execute(
            "SELECT sidecar_json FROM mzprov_provenance LIMIT 1;"
        ).fetchone()
    # Trim for display.
    snippet = raw if len(raw) <= 240 else raw[:240] + "...(truncated)"
    print("  ->")
    for line in snippet.splitlines():
        print(f"    {line}")
    print("  (the full envelope is the v0 sidecar JSON — same schema as Transport A)")

    step("verify the experiment directory (auto-detects embedded transport)")
    rc = shell("verify", str(exp))
    assert rc == 0, "embedded verify should succeed"

    step("tamper: edit a row in the .d's analysis.tdf, then re-verify")
    print(
        "  $ sqlite3 sample.d/analysis.tdf "
        '"UPDATE Frames SET Time = 999.0 WHERE Id = 1;"'
    )
    with sqlite3.connect(str(exp / "sample.d" / "analysis.tdf")) as conn:
        conn.execute("UPDATE Frames SET Time = 999.0 WHERE Id = 1;")
        conn.commit()
    rc = shell("verify", str(exp))
    assert rc == 5, f"data tamper should be HASH_MISMATCH (5), got {rc}"
    print("  -> exit 5 (HASH_MISMATCH) — same detection as Transport A.")

    step("tamper: edit the embedded envelope's payload, then re-verify")
    print(
        '  $ sqlite3 sample.d/analysis.tdf '
        '"UPDATE mzprov_provenance SET sidecar_json = '
        "REPLACE(sidecar_json, 'demo-embed', 'MUTATED-LABEL')\""
    )
    with sqlite3.connect(str(exp / "sample.d" / "analysis.tdf")) as conn:
        conn.execute(
            "UPDATE mzprov_provenance "
            "SET sidecar_json = REPLACE(sidecar_json, 'demo-embed', 'MUTATED-LABEL');"
        )
        conn.commit()
    rc = shell("verify", str(exp))
    assert rc != 0, "embedded tamper must not silently verify"
    print(f"  -> exit {rc} — the signature/identity check on the in-band envelope catches it.")


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="don't delete the workdir at the end (handy for poking around)",
    )
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="mzprov-demo-"))
    print(f"workdir: {workdir}")

    # Use a fresh per-demo signing key. We point `--key` at an EMPTY
    # directory; on first sign, mzprov auto-creates the keypair there.
    # The directory itself must exist (the CLI's resolver requires
    # is_dir() to recognize the path as a key directory rather than a
    # missing .pem file). We do NOT use the committed test-vector key
    # — this demo should look like first contact with the tool.
    keys_dir = workdir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    print(f"signing key directory (auto-created on first sign): {keys_dir}")

    try:
        demo_sidecar_json(workdir, keys_dir)
        demo_embedded(workdir, keys_dir)

        # Surface the demo key id once we know it (after the first sign).
        key_id_file = keys_dir / "key_id"
        if key_id_file.is_file():
            print()
            print(f"demo signer key_id: {key_id_file.read_text().strip()}")

        section("SIDE-BY-SIDE — what gets shipped")
        print(
            "  Transport A (sidecar JSON):\n"
            "    * the .d directory          (the data)\n"
            "    * sample.config.toml         (the original config)\n"
            "    * demo-json.provenance.json  (the attestation)\n"
            "    * demo-json.config.toml      (config copy for the verifier)\n"
            "    -> 4 files; recipient must keep them together.\n"
            "\n"
            "  Transport B (embedded):\n"
            "    * the .d directory           (data + attestation, in-band)\n"
            "    * sample.config.toml         (the original config)\n"
            "    * demo-embed.config.toml     (config copy for the verifier)\n"
            "    -> 3 files; the .d is self-describing — no separate sidecar to lose.\n"
            "\n"
            "Both paths give an attacker the same surface and the same exit\n"
            "codes when they tamper. The choice is operational: how does the\n"
            "data get from producer to verifier?"
        )

        return 0
    finally:
        if args.keep:
            print()
            print(f"workdir kept at: {workdir}")
        else:
            shutil.rmtree(workdir)


if __name__ == "__main__":
    raise SystemExit(main())
