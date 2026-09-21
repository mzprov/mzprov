# Demo: Bruker `.d` provenance — sidecar JSON vs. embedded

This walkthrough shows the same v0 attestation against the same `.d`
in **two transport modes**, then breaks each one to prove the
attestation actually catches tampering. It's meant to be readable
end-to-end in 5 minutes — not exhaustive — and to give a concrete
answer to two questions that come up immediately:

1. *What does each transport look like for a user?*
2. *What happens when someone modifies the data after it was signed?*

The data here is a small synthetic Bruker `.d` (a couple of frames,
hand-crafted SQLite tables) so the demo is reproducible without an
instrument. The signing key is generated fresh on first sign — it
has no production status; treat it as a one-shot demo identity.

## Reproduce locally

```sh
# from the repo root, with mzprov installed (e.g. `pip install -e implementations/python`)
python examples/demo_d_transports.py

# or, without installing:
PYTHONPATH=implementations/python/src python examples/demo_d_transports.py
```

Pass `--keep` if you want the workdir left in `/tmp` afterwards so
you can poke at the files yourself.

The sections below are the script's annotated output. Exit codes are
real — the assertions in the script fail loudly if any of them
diverge from the spec.

---

## Setup

The script builds two parallel experiment directories under a temp
workdir, each with its own copy of the same synthetic `.d`:

```
experiment-json/
  sample.d/
    analysis.tdf
    analysis.tdf_bin
  sample.config.toml          # the user's config

experiment-embed/
  sample.d/
    analysis.tdf
    analysis.tdf_bin
  sample.config.toml
```

Both `sample.config.toml` files are byte-identical. Both `sample.d`
directories canonicalize to the same hash. The only thing that
differs between the two experiments is which transport their
attestation will use.

The first call to `mzprov sign` auto-creates a fresh Ed25519 keypair
in the directory passed via `--key`:

```
Generated new TimSim signing key at /tmp/mzprov-demo-…/keys/signing_key.pem.
Key id: timsim-local-…  This is a SOFTWARE key — see SIGNING.md §9
for the limitations of the Phase 0 prototype.
```

That key id is what verifies subsequent signatures.

---

## Transport A — sidecar JSON

The sidecar lives in a `*.provenance.json` file next to the `.d`.
This is the universal v0 transport — it works for any artifact,
including formats we cannot embed into (Thermo `.raw`, Waters, etc.).

### Sign

```sh
$ mzprov sign experiment-json/sample.d \
    --config experiment-json/sample.config.toml \
    --experiment-name demo-json \
    --key experiment-json/../keys
signed: experiment-json/demo-json.provenance.json
(exit 0)
```

Resulting layout:

```
experiment-json/
  sample.d/
    analysis.tdf                   # unchanged
    analysis.tdf_bin               # unchanged
  sample.config.toml               # the original config
  demo-json.provenance.json        # the attestation
  demo-json.config.toml            # config copy the verifier checks against
```

Two new files appear at the experiment-dir level. The `.d/` directory
itself is untouched.

### Verify

```sh
$ mzprov verify experiment-json
mzprov provenance verification
  experiment:        demo-json
  producer:          TimSim unknown
  signed at:         …
  key id:            timsim-local-…
  canonicalization:  v0

   d_content_hash  OK         (sha256:2926eb20…)
   config_hash     OK         (sha256:0381012d…)
   content_hash    OK         (sha256:78611e7b…)
   signature       OK         (ed25519)

VERIFIED
(exit 0)
```

### Tamper: modify the data, then re-verify

A row update in `analysis.tdf` simulates an attacker (or a
well-meaning post-hoc edit) changing the data after signing:

```sh
$ sqlite3 experiment-json/sample.d/analysis.tdf \
    "UPDATE Frames SET Time = 999.0 WHERE Id = 1;"

$ mzprov verify experiment-json
mzprov provenance verification
  experiment:        demo-json
  …

 * d_content_hash  MISMATCH   (sha256:2926eb20…)
     expected:  sha256:2926eb20eb6cbe5d448bd8348dd56375891130eec777313adb33d3e8ed021cab
     actual:    sha256:b8fb007a6a4fa698bc9781223bea9548acbd7108dd0c5416c7f7c01817c01375
   config_hash     OK         (sha256:0381012d…)
 * content_hash    MISMATCH   (sha256:78611e7b…)
   signature       OK         (ed25519)

FAILED
(exit 5)
```

Exit **5 = HASH_MISMATCH**: the recomputed `d_content_hash` no longer
matches the value that was signed. The signature itself is still OK
because the sidecar wasn't touched — the canonical payload bytes are
unchanged. The mismatch surfaces in the per-field check.

### Tamper: modify the sidecar itself, then re-verify

What if the attacker also rewrites the sidecar to claim a different
experiment name?

```sh
$ sed -i "s/demo-json/MUTATED-LABEL/" experiment-json/demo-json.provenance.json

$ mzprov verify experiment-json
…
 * d_content_hash  MISMATCH   (sha256:2926eb20…)
   config_hash     OK         (sha256:0381012d…)
 * content_hash    MISMATCH   (sha256:78611e7b…)
 * signature       MISMATCH   (ed25519)

FAILED
(exit 6)
```

Exit **6 = SIGNATURE_MISMATCH**: the canonical bytes of the payload
have changed (because we mutated `experiment_name`), so the
Ed25519 signature no longer validates. Forging a coherent sidecar
would require the signer's private key — which is the whole point.

---

## Transport B — embedded (in-band, inside `analysis.tdf`)

The same v0 envelope is stored as a single row in a reserved
`mzprov_provenance` table inside `analysis.tdf`. The `.d`'s canonical
content hash is unchanged — the table is excluded from
canonicalization (`spec/canonicalization-d-v0.md` §3.2).

### Sign

```sh
$ mzprov sign experiment-embed/sample.d \
    --config experiment-embed/sample.config.toml \
    --experiment-name demo-embed \
    --key experiment-embed/../keys \
    --embed
signed: experiment-embed/sample.d
(exit 0)
```

Resulting layout — note no new files at the experiment-dir level:

```
experiment-embed/
  sample.d/
    analysis.tdf                   # now contains a mzprov_provenance row
    analysis.tdf_bin               # unchanged
  sample.config.toml               # the original config (and, by virtue of
                                   #   the convention below, also the
                                   #   verifier's config copy)
```

The `.d/` directory now contains its own attestation in-band.

> **About the embedded config copy.** The verifier expects the config
> bytes at `{d-stem}.config.toml` next to the `.d` (here:
> `sample.config.toml`). In this demo the user's input config is
> already at that path, so the sign step rewrites the same file with
> the same bytes and no extra file appears. If the user had named
> their input config something else (e.g. `mysetup.toml`), embedded
> signing would create `sample.config.toml` as a separate copy.
> Either way the verifier reads from the conventional path —
> never from a payload field — so a tampered `experiment_name` can't
> redirect it.

### Inspect: pull the embedded envelope back out

```sh
$ sqlite3 experiment-embed/sample.d/analysis.tdf \
    "SELECT sidecar_json FROM mzprov_provenance"
{
  "payload": {
    "canonicalization_version": "v0",
    "config_hash": "sha256:0381012d…",
    "content_hash": "sha256:78611e7b…",
    "d_content_hash": "sha256:2926eb20…",
    …
  },
  "signature": "ed25519:base64:…",
  "verifying_key": "ed25519:base64:…",
  "type": "timsim.provenance.v0"
}
```

Same envelope schema as Transport A — `sidecar-format.md` is
authoritative for both. Only the storage differs.

### Verify

```sh
$ mzprov verify experiment-embed
mzprov provenance verification
  experiment:        demo-embed
  …
   d_content_hash  OK         (sha256:2926eb20…)
   config_hash     OK         (sha256:0381012d…)
   content_hash    OK         (sha256:78611e7b…)
   signature       OK         (ed25519)

VERIFIED
(exit 0)
```

`mzprov verify` was given the experiment directory (not the `.d`
directly). The discovery layer descends into the unique `.d` inside,
detects the `mzprov_provenance` row, and dispatches to the embedded
verify path automatically (see `spec/embedded-d-v0.md` §6.1).

### Tamper: modify the data, then re-verify

```sh
$ sqlite3 experiment-embed/sample.d/analysis.tdf \
    "UPDATE Frames SET Time = 999.0 WHERE Id = 1;"

$ mzprov verify experiment-embed
…
 * d_content_hash  MISMATCH   (sha256:2926eb20…)
   config_hash     OK         (sha256:0381012d…)
 * content_hash    MISMATCH   (sha256:78611e7b…)
   signature       OK         (ed25519)

FAILED
(exit 5)
```

Same `HASH_MISMATCH` outcome as Transport A. The exclusion rule means
the row doesn't perturb the canonical hash, but **everything else**
in `analysis.tdf` does — the Frames row update is caught.

### Tamper: modify the embedded envelope itself

```sh
$ sqlite3 experiment-embed/sample.d/analysis.tdf \
    "UPDATE mzprov_provenance \
       SET sidecar_json = REPLACE(sidecar_json, 'demo-embed', 'MUTATED-LABEL')"

$ mzprov verify experiment-embed
…
 * d_content_hash  MISMATCH   (sha256:2926eb20…)
   config_hash     OK         (sha256:0381012d…)
 * content_hash    MISMATCH   (sha256:78611e7b…)
 * signature       MISMATCH   (ed25519)

FAILED
(exit 6)
```

Same `SIGNATURE_MISMATCH` outcome as Transport A. The envelope being
in-band rather than alongside the file makes no difference to the
crypto — it's the same canonical payload bytes signed by the same
key, and any mutation invalidates the signature.

---

## Side-by-side: what gets shipped

| | Transport A (sidecar JSON) | Transport B (embedded) |
|---|---|---|
| Files to hand off | `sample.d/`, `sample.config.toml`, `demo-json.provenance.json`, `demo-json.config.toml` | `sample.d/`, `sample.config.toml` |
| Config-copy convention | `{sidecar-stem}.config.toml` — distinct from the user's input config | `{d-stem}.config.toml` — coincides with the user's input config in this demo (would be a separate file if the user named their config differently) |
| Single self-describing artifact? | No — sidecar can be lost or separated in transit | Yes — the `.d` carries its own attestation |
| Works for opaque single-blob formats (Thermo `.raw`, Waters) | Yes | No — requires an editable container |
| Affected by signing? | Untouched `.d` + new sidecar files | `.d/analysis.tdf` gains one row in `mzprov_provenance` |
| Tamper detection | `HASH_MISMATCH` / `SIGNATURE_MISMATCH` | `HASH_MISMATCH` / `SIGNATURE_MISMATCH` |

Both paths give an attacker the same surface and the same exit codes
when they tamper. The choice between them is operational — how does
the data get from producer to verifier? — not cryptographic.

For PRIDE-style upload of a Bruker dataset, the embedded transport
removes a class of "I forgot the sidecar" failure modes. For
formats where the artifact bytes are off-limits to us (vendor `.raw`,
custom binary blobs), the JSON sidecar is the only option and stays
first-class for that reason.

---

## See also

- `spec/canonicalization-d-v0.md` — what bytes are in scope for the `.d` content hash
- `spec/embedded-d-v0.md` — the embedded transport (schema, signer/reader protocols, verifier dispatch)
- `spec/sidecar-format.md` — the v0 envelope shared by both transports
- `examples/demo_d_transports.py` — the script that produced this walkthrough
