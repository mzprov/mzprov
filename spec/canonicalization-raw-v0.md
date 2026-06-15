# canonicalization-raw-v0

This document specifies the v0 canonicalization of a Thermo ``.raw``
vendor file. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

The canonicalization version this document specifies is `v0`. The
sidecar's `payload.canonicalization_version` field MUST equal `"v0"`
for this spec to apply.

## 1. What v0 hashes

A Thermo ``.raw`` file is an **undocumented proprietary binary**.
There is no published structure to canonicalize against, so v0 does
**not** extract content the way the mzML path
([`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md)) does.
Instead, v0 computes an **opaque whole-file SHA-256** over the exact
bytes of the file on disk, in order, with no structural normalization
whatsoever.

The canonical hash is therefore sensitive to **any** byte change:

- A single flipped bit anywhere in the file.
- Any re-serialization by any tool or vendor-library version that
  rewrites the container, even if it preserves the logical scan data.
- Any added, removed, reordered, or rewritten byte.

This strictness is **intentional**. Without a documented format the
implementation cannot distinguish a benign re-encoding from a
malicious edit, so every byte is treated as load-bearing. A consumer
that re-exports a ``.raw`` through any tool MUST re-sign the result.

## 2. Sidecar-only — no embed transport

The ``.raw`` attestation is **sidecar-only**. There is no embedded
transport (contrast [`embedded-d-v0.md`](embedded-d-v0.md) and
[`embedded-mzml-v0.md`](embedded-mzml-v0.md)). The vendor binary has
**no safe injection point**: there is no documented, structurally
inert slot into which an envelope could be written without (a) risking
corruption of the file as read by vendor software and (b) changing the
very bytes the opaque hash covers, which would make embed-after-hash
ill-defined.

The envelope therefore always lives in a separate
``{stem}.provenance.json`` file next to the ``{stem}.raw`` it attests.

## 3. Whole-file canonicalization (`canonicalize_raw`)

The full canonicalization is:

```
h = sha256()
h.update(b"TIMSIM-RAW-CANONICAL-v0\x1f")

for chunk in read_file_in_1MiB_chunks(raw_path):
    h.update(chunk)

return h.digest()
```

The leading domain prefix `b"TIMSIM-RAW-CANONICAL-v0\x1f"` is
mandatory. The file is read in 1 MiB chunks so the hash uses constant
memory regardless of file size.

If `raw_path` is not an existing regular file, the implementation MUST
raise `FileNotFoundError`.

The output is 32 raw bytes, encoded in the sidecar as
`sha256:<64 lowercase hex>`.

## 4. Composed raw content hash (`compose_raw_content_hash`)

The single `content_hash` that lives in `payload.content_hash` is
composed from:

- `raw_hash` (the output of §3)
- `config_hash` (SHA-256 of the raw config bytes, or `sha256(b"")` if
  no config was provided)

The composition is:

```
domain = b"timsim.raw.v0\x1f"
US     = b"\x1f"

content_hash = sha256(
    domain
    || raw_hash
    || US
    || config_hash
)
```

Notes:

- The domain prefix `b"timsim.raw.v0\x1f"` is distinct from the `.d`
  domain prefix (`b"timsim.v0\x1f"`) and the mzML domain prefix
  (`b"timsim.mzml.v0\x1f"`) so that an attacker cannot cross-substitute
  a `.d` or mzML content hash for a `.raw` content hash or vice versa.
- Both input hashes MUST be 32 bytes.

## 5. Versioning

This spec is **frozen** at `v0`. Any future revision that changes what
bytes are hashed — for instance, a parser that learns the container
format well enough to exclude a reserved provenance slot, the way the
mzML path excludes the `mzprov:provenance` `userParam` — MUST live in a
`canonicalization-raw-v1.md` document and bump the
`canonicalization_version` field in `envelope.RawPayload`.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the JSON envelope and
  payload field semantics
- [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) — the
  content-extracting parallel spec for mzML
- [`canonicalization-d-v0.md`](canonicalization-d-v0.md) — the
  parallel spec for `.d`
