# embedded-mzml-v0

This document specifies the v0 in-band embedding of an mzprov sidecar
envelope inside an mzML file. It is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

> **Status.** The slot defined in §2 (a `userParam` inside
> `<fileDescription>/<fileContent>` with name `mzprov:provenance`) is a
> proposed v0 mechanism. It is the natural mzML escape hatch — schema-
> legal everywhere mzML is read, requires no HUPO-PSI controlled-
> vocabulary term, and lives in a part of the document that is already
> outside the canonical hash. The slot choice is open for ratification
> by the wider mzML community before this document graduates from
> draft.

## 1. Two equivalent storage modes

mzprov v0 supports two equivalent storage modes for an mzML sidecar:

- **Sidecar JSON.** A `*.provenance.json` file alongside the mzML,
  located by the discovery rules in
  [`sidecar-format.md`](sidecar-format.md) §8. Universal v0 transport
  and the only mode supported for opaque single-blob vendor formats
  (Thermo `.raw`, Waters).
- **Embedded.** A `userParam` inside the mzML's
  `<fileDescription>/<fileContent>` element, defined by this
  document. Embedded mode keeps the artifact a single self-describing
  file, mirroring the embedded-`.d` story in
  [`embedded-d-v0.md`](embedded-d-v0.md).

The signed envelope is byte-identical between the two modes. The
canonical signed form defined in
[`sidecar-format.md`](sidecar-format.md) §5 is computed over the
same payload object regardless of transport. Only the bytes around
the envelope differ.

## 2. The reserved userParam slot

When mzprov writes embedded provenance to an mzML file, it MUST add
exactly one `<userParam>` element with all of the following
attributes:

| Attribute | Value | Notes |
|---|---|---|
| `name` | `mzprov:provenance` | Reserved name for this slot. |
| `value` | base64 (RFC 4648 standard alphabet, with `=` padding) of the complete sidecar envelope as defined in [`sidecar-format.md`](sidecar-format.md) §1, encoded as UTF-8 JSON | The envelope is the v0 sidecar object — `type`, `payload`, `signature`, `verifying_key`. Base64 sidesteps XML attribute escaping and keeps the value self-delimiting. |
| `type` | `xsd:string` | Optional but RECOMMENDED for schema-strict readers. |

The `<userParam>` MUST be a direct child of `<fileContent>`, which
MUST be a direct child of `<fileDescription>`, which MUST be a direct
child of the inner `<mzML>` element:

```xml
<mzML xmlns="http://psi.hupo.org/ms/mzml" ...>
  <fileDescription>
    <fileContent>
      <cvParam cvRef="MS" accession="MS:1000579" name="MS1 spectrum"/>
      <userParam name="mzprov:provenance" type="xsd:string"
                 value="<base64 of envelope JSON>"/>
    </fileContent>
    ...
  </fileDescription>
  ...
</mzML>
```

This is a schema-legal location for `userParam` per the mzML 1.1
schema. Conforming readers that ignore unrecognized userParams
(the standard expectation) treat the embedded envelope as a no-op.

A conforming mzML MUST contain at most one `userParam` with
`name="mzprov:provenance"` in `<fileContent>`. A signer that finds
an existing one MUST remove it before inserting the new one. A
reader that finds more than one MUST refuse with a malformed-embed
error (the reference implementations map this to `SIDECAR_ERROR`).

The reserved name `mzprov:provenance` is registered for this purpose
and MUST NOT be used by any other tool.

## 3. Why no canonicalization amendment is required

[`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) §2 lists
`<fileDescription>` (other than what cvParams expose on individual
spectra) as out of scope for the canonical hash. The canonicalizer
walks `<spectrum>` subtrees only; nothing in `<fileDescription>` is
read into the hash stream.

This means the embedded slot defined in §2 is **already excluded** by
virtue of where it lives. The exclusion is unconditional: a canonical
hash computed before the userParam is inserted equals the canonical
hash computed after. No new exclusion clause is needed.

A conforming canonicalizer SHOULD also explicitly skip
`mzprov:provenance` userParams as a defense-in-depth check against
a future spec that loosens the §2 exclusion. The reference
implementations skip it implicitly (by never iterating
`<fileDescription>` descendants) rather than by name.

## 4. Indexed mzML wrapper

Real-world mzML is often wrapped in `<indexedmzML>`, which carries
a trailing `<indexList>`/`<indexListOffset>`/`<fileChecksum>`
pointing at byte offsets in the file. Inserting a userParam into
`<fileContent>` shifts those offsets and invalidates both the index
and the checksum.

A conforming embedded signer MUST do **one** of the following:

- **Strip mode.** Produce the inner `<mzML>` as the document root.
  The `<indexedmzML>` wrapper, if present in the input, is dropped
  on write. The output is a plain mzML file; tools that need a
  byte-offset index can re-index downstream (`msconvert`,
  `pyteomics.mzml`).
- **Re-index mode.** Produce a fresh, valid `<indexedmzML>` wrapper
  with a recomputed `<indexList>`, `<indexListOffset>`, and
  `<fileChecksum>` matching the new byte layout. The output is a
  valid indexed mzML.

A signer MUST NOT leave a stale `<indexedmzML>` wrapper in place
(i.e., one whose `<indexList>` byte offsets disagree with the
post-embed file layout). Stale wrappers can mislead downstream
random-access readers.

The canonical hash is unaffected by either mode (the wrapper is out
of scope per
[`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) §1, §2),
so an indexed input and either form of embedded output verify
against the same signature.

The reference implementations make different choices on this axis:
the Python implementation strips the wrapper (uses stdlib
`xml.etree.ElementTree`); the Rust implementation re-indexes (uses
`mzdata`'s `MzMLWriter`, which emits a fresh indexed wrapper). Both
are conformant. Verifiers MUST accept both forms.

## 5. Signer protocol

A conforming embedded signer MUST:

1. **Compute the canonical hash** of the input mzML per
   [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) §8
   and compose the content hash per §9 of that document.
2. **Build the sidecar envelope** per
   [`sidecar-format.md`](sidecar-format.md) §1 and sign it per §5
   of that document.
3. **Locate the inner mzML.** If the input root is
   `{http://psi.hupo.org/ms/mzml}indexedmzML`, find the inner
   `{http://psi.hupo.org/ms/mzml}mzML` child; that becomes the new
   document root. If the input root is already
   `{http://psi.hupo.org/ms/mzml}mzML`, use it directly.
4. **Locate or create `<fileDescription>/<fileContent>`.** The
   `<fileDescription>` element is required by mzML; if absent, the
   input is malformed and the signer MUST refuse. The
   `<fileContent>` element MUST be created if missing (this can
   happen only with very minimal mzML test fixtures; real-world
   files always have it).
5. **Remove any pre-existing `mzprov:provenance` userParam** from
   `<fileContent>`, then insert a new one with the attributes from
   §2.
6. **Serialize the inner `<mzML>` as the document root** (no
   `<indexedmzML>` wrapper, no `<indexList>`, no `<indexListOffset>`,
   no `<fileChecksum>`). The PSI-MS namespace
   `http://psi.hupo.org/ms/mzml` MUST be the default XML namespace of
   the output.
7. **Write atomically** (temp file + rename) so a partial output is
   never visible.

## 6. Reader protocol

A conforming reader (used by the verifier and any tool extracting the
embedded envelope):

1. **Parse the mzML.** Tolerate both an `<indexedmzML>` wrapper and a
   bare `<mzML>` root.
2. **Locate the inner `<mzML>`** and then its
   `<fileDescription>/<fileContent>` child. If either is absent,
   return "no embedded provenance" (the reference implementations
   return `None`).
3. **Find the `userParam` with `name="mzprov:provenance"`** as a
   direct child of `<fileContent>`. If absent, return "no embedded
   provenance". If more than one exists, refuse with a malformed-
   embed error.
4. **Base64-decode the `value` attribute.** Decoding errors are
   `MalformedSidecar`. The result is the envelope bytes; parse and
   validate per [`sidecar-format.md`](sidecar-format.md) §§1, 9.

## 7. Verifier dispatch

When the verifier is given a path that resolves to an mzML file
(directly, or via experiment-directory descent), it MUST follow this
order:

1. Run the §6 reader protocol on the mzML.
2. If the reader returns a non-null envelope, that is the sidecar;
   proceed with verification using it.
3. Otherwise, fall back to the JSON sidecar discovery rules in
   [`sidecar-format.md`](sidecar-format.md) §8.
4. If both produce nothing, the mzML is `UNSIGNED` (exit code 4).

### 7.1 Experiment-directory descent

When the verifier is given a directory that is NOT itself a sidecar
or an mzML file, it MUST attempt to locate a unique mzML inside it
(at depth 0 or 1) and apply the dispatch in §7 to that mzML *before*
falling back to JSON sidecar discovery on the original directory.
The rationale and resolution rules mirror
[`embedded-d-v0.md`](embedded-d-v0.md) §6.1.

### 7.2 Error propagation: no silent fallback

If the §6 reader raises an error — for example because the
`mzprov:provenance` slot contains more than one userParam, or its
`value` is not valid base64, or the inner mzML element is malformed
— the verifier MUST surface that error and MUST NOT silently fall
back to the JSON sidecar transport. Embedded provenance is
authoritative once present (or once the embedded probe proves the
transport is broken). The reference implementations map this to
`SIDECAR_ERROR` (exit code 3). Rationale mirrors
[`embedded-d-v0.md`](embedded-d-v0.md) §6.2.

### 7.3 Defense-in-depth comparison (optional)

A verifier MAY, as a defense-in-depth check, compare the embedded
envelope against any sidecar JSON file also discovered by §8 and
refuse on divergence. This is OPTIONAL in v0 and is expected to
become RECOMMENDED in a later revision.

The verifier MUST NOT prefer the JSON sidecar over the embedded
userParam when both are present — embedded is in-band and
authoritative.

## 8. Validation

| Error condition | Reference exit code |
|---|---|
| Input is not parseable as XML | `SIDECAR_ERROR` (3) |
| Root element is neither `mzML` nor `indexedmzML` | `SIDECAR_ERROR` (3) |
| Inner `mzML` has no `<fileDescription>` | `SIDECAR_ERROR` (3) (signer side) |
| `<fileContent>` contains more than one `mzprov:provenance` userParam | `SIDECAR_ERROR` (3) |
| `value` attribute is not valid base64 | `SIDECAR_ERROR` (3) |
| Decoded value does not parse as a v0 envelope (per [`sidecar-format.md`](sidecar-format.md) §9) | `SIDECAR_ERROR` (3) |

## 9. Test vectors

Conforming implementations MUST:

- Reproduce the canonical hash of any embedded fixture under
  [`../test-vectors/canonicalization/mzml/`](../test-vectors/canonicalization/mzml/)
  with the `mzprov:provenance` userParam both present and absent —
  the two MUST yield byte-identical digests (exclusion correctness).
- Verify every paired mzML vector under
  [`../test-vectors/sidecar/valid/embedded-mzml/`](../test-vectors/sidecar/valid/embedded-mzml/)
  via the embedded reader path.

## See also

- [`canonicalization-mzml-v0.md`](canonicalization-mzml-v0.md) — §1 and §2
  are what make this slot canonically excluded
- [`sidecar-format.md`](sidecar-format.md) — the envelope schema
- [`embedded-d-v0.md`](embedded-d-v0.md) — the parallel embedding spec
  for `.d`; verifier dispatch (§6) is mirrored here
- [`trust-model.md`](trust-model.md) — exit code semantics
