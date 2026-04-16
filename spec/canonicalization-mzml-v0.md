# canonicalization-mzml-v0

This document specifies the v0 canonicalization of an mzML file. It
is normative.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, REQUIRED,
RECOMMENDED, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

The canonicalization version this document specifies is `v0`. The
sidecar's `payload.canonicalization_version` field MUST equal `"v0"`
for this spec to apply.

## 1. What v0 hashes

The v0 mzML canonicalization operates on **spectrum content**: the
spectra and the per-spectrum metadata that data consumers actually
read. The canonical hash is invariant under:

- Whitespace and indentation changes
- Attribute reordering within an XML element
- `cvParam` ordering within a spectrum (cvParams are extracted by
  accession, not by document order)
- Presence or absence of the optional `<indexedmzML>` wrapper
- Run-level metadata (instrument configuration strings,
  `<dataProcessing>` history, `<sourceFile>` listings)

It is sensitive to:

- Any change to a spectrum's binary array bytes (m/z, intensity, ion
  mobility, charge, time, pressure, wavelength, …)
- Any added, removed, or reindexed spectrum
- Any change to spectrum-level metadata that v0 hashes (id, MS level,
  RT, polarity, precursor target/charge/window, ion mobility)
- Any change to a binary array's **precision tag** (`f64`/`f32`/
  `i64`/`i32`) or its **value count**, even if the underlying bytes
  are identical

## 2. What v0 does NOT hash

The following are intentionally out of scope for v0. Implementations
MUST NOT include them in the canonical form (doing so would diverge
from the reference implementation and break interop):

- The `<indexedmzML>` wrapper itself, including its index list and
  embedded checksums
- The mzML root element's attributes (`version`, `xsi:schemaLocation`,
  `xmlns`)
- The `<cvList>`, `<fileDescription>` (other than what cvParams expose
  on individual spectra), `<referenceableParamGroupList>`,
  `<sampleList>`, `<softwareList>`, `<scanSettingsList>`,
  `<instrumentConfigurationList>`, and `<dataProcessingList>` elements
- `<sourceFile>` references and any of their content
- `<run>` element attributes
- The `<chromatogramList>` element and any of its content

These exclusions are deliberate and recorded as candidate v1 work in
[`v1-draft/`](v1-draft/).

The `<fileDescription>` exclusion above is what makes the embedded
mzML transport defined in [`embedded-mzml-v0.md`](embedded-mzml-v0.md)
canonically free: a `userParam` with the reserved name
`mzprov:provenance` inside `<fileDescription>/<fileContent>` is
covered by the §2 exclusion and does not perturb the canonical hash.
A future revision that brings any subset of `<fileDescription>` into
the canonical hash MUST keep the reserved `mzprov:provenance` slot
explicitly excluded so embed-after-hash stays well-defined.

## 3. What v0 explicitly refuses

Implementations MUST refuse mzML files with any of the following
features by raising a sidecar / provenance error rather than
producing a hash:

- **Numpress compression** on any binary array. The PSI-MS accessions
  for numpress are `MS:1002312` (linear), `MS:1002313` (PIC), and
  `MS:1002314` (SLOF). Numpress is lossy, complex to specify across
  implementations, and out of scope for v0. The reference
  implementation raises `ProvenanceError`.
- A `<binaryDataArray>` with no inner `<binary>` element. Reference:
  `MalformedSidecar`.
- A `<binaryDataArray>` whose base64 content cannot be decoded.
  Reference: `MalformedSidecar`.
- A `<binaryDataArray>` whose base64 content can be decoded but
  whose zlib payload (when zlib compression is declared) cannot be
  decompressed. Reference: `MalformedSidecar`.
- A `<binaryDataArray>` with no `cvParam` identifying its array role.
  Reference: `MalformedSidecar`.
- A `<spectrum>` with a missing or non-integer `index` attribute.
  Reference: `MalformedSidecar`.

## 4. XML namespaces

mzML uses the namespace `http://psi.hupo.org/ms/mzml`. Implementations
MUST use namespace-aware XML parsing and locate elements by qualified
name (e.g., `{http://psi.hupo.org/ms/mzml}spectrum`). Local-name-only
matching is not conforming because mzML files in the wild may include
other namespaces alongside the PSI-MS namespace.

## 5. PSI-MS controlled-vocabulary accessions

The canonical form refers to spectrum metadata by PSI-MS controlled-
vocabulary accession, not by `name` attribute. Accessions are stable
across CV releases; names are localized and shortened.

The accessions used by v0:

| Symbol | Accession | Meaning |
|---|---|---|
| `ms_level` | `MS:1000511` | MS level (1, 2, …) |
| `scan_start_time` | `MS:1000016` | scan start time |
| `positive_scan` | `MS:1000130` | positive scan polarity |
| `negative_scan` | `MS:1000129` | negative scan polarity |
| `selected_ion_mz` | `MS:1000744` | selected ion m/z (precursor) |
| `charge_state` | `MS:1000041` | precursor charge state |
| `iso_target` | `MS:1000827` | isolation window target m/z |
| `iso_lower_off` | `MS:1000828` | isolation window lower offset |
| `iso_upper_off` | `MS:1000829` | isolation window upper offset |
| `binary_f64` | `MS:1000523` | 64-bit float encoding |
| `binary_f32` | `MS:1000521` | 32-bit float encoding |
| `binary_i64` | `MS:1000522` | 64-bit integer encoding |
| `binary_i32` | `MS:1000519` | 32-bit integer encoding |
| `no_compression` | `MS:1000576` | no compression |
| `zlib_compression` | `MS:1000574` | zlib compression |
| `numpress_linear` | `MS:1002312` | numpress linear (REFUSED) |
| `numpress_pic` | `MS:1002313` | numpress PIC (REFUSED) |
| `numpress_slof` | `MS:1002314` | numpress SLOF (REFUSED) |
| `ion_mobility` | `MS:1002476` | ion mobility drift time (scalar cvParam) |
| `ion_mobility_alt` | `MS:1003006` | inverse reduced ion mobility (scalar cvParam) |

### 5.1 Known binary-array role accessions

The canonical form labels each `<binaryDataArray>` with the accession
of a `cvParam` that identifies its content (not its encoding). The
following accessions are recognized as **content** accessions in v0:

```
MS:1000514  m/z array
MS:1000515  intensity array
MS:1000516  charge array
MS:1000517  signal-to-noise array
MS:1000595  time array
MS:1000617  wavelength array
MS:1000786  non-standard data array
MS:1000820  flow rate array
MS:1000821  pressure array
MS:1000822  temperature array
MS:1002476  mean ion mobility array (drift time)
MS:1002477  mean ion mobility array (other forms)
MS:1002478  mean charge array
MS:1003006  mean inverse reduced ion mobility array
MS:1003007  raw ion mobility array
MS:1003008  raw inverse reduced ion mobility array
MS:1003153  noise array
```

The following accessions are recognized as **encoding** accessions
(meta about HOW an array is stored, not WHAT it contains) and are
explicitly excluded from role-label selection:

```
MS:1000519  32-bit integer
MS:1000521  32-bit float
MS:1000522  64-bit integer
MS:1000523  64-bit float
MS:1000574  zlib compression
MS:1000576  no compression
MS:1002312  numpress linear
MS:1002313  numpress PIC
MS:1002314  numpress SLOF
```

## 6. Spectrum enumeration

The canonicalizer MUST enumerate every `<spectrum>` element under the
mzML root, regardless of how deeply nested they are within `<run>`
and `<spectrumList>` elements. Each spectrum MUST have an integer
`index` attribute (mzML requires this).

Spectra MUST be sorted by integer `index` in ascending order before
hashing. The sort is what makes the canonical form invariant under
any document-order rearrangement a converter or pretty-printer might
apply. Two spectra with the same `index` are a malformed mzml; the
canonicalizer MUST NOT raise but SHOULD allow the duplicate to surface
naturally as identical bytes (which still produces a stable hash, just
one that does not distinguish them).

## 7. Per-spectrum canonical record

For each spectrum (in sorted index order), the canonicalizer MUST
extract the following fields and emit them in the fixed order shown
below. Each field is emitted as the byte sequence:

```
US + key + US + value + US
```

where `US = 0x1F`. Empty values are emitted as a zero-length value
between the two `US` bytes — they MUST NOT be omitted, because the
fixed slot order is what guarantees that two spectra disagreeing on
whether a field exists produce different bytes.

After all field records, the spectrum record ends with `RS = 0x1E`.

### 7.1 Header fields

| Slot | Key | Value encoding | Source |
|---|---|---|---|
| 1 | `spec_index` | ASCII decimal of the integer parsed from the `index` attribute | `<spectrum index="...">` |
| 2 | `spec_id` | UTF-8 of the `id` attribute (empty string if absent) | `<spectrum id="...">` |
| 3 | `ms_level` | ASCII of the `value` attribute on the cvParam with accession `MS:1000511`; empty if absent | direct child cvParam |
| 4 | `polarity` | `b"+"` if `MS:1000130` present, `b"-"` if `MS:1000129` present, `b"?"` if neither | direct child cvParam |
| 5 | `rt_sec` | IEEE 754 double-precision big-endian hex (16 chars) of the scan start time normalized to seconds; empty if absent or unparseable | see §7.2 |
| 6 | `mobility` | IEEE 754 hex of the ion-mobility scalar; empty if absent | see §7.3 |

### 7.2 Scan start time (`rt_sec`)

The canonicalizer MUST locate the first `<scan>` element under the
spectrum's first `<scanList>`, then iterate that `<scan>` element's
direct child `cvParam` elements, looking for accession `MS:1000016`.

If found, the canonicalizer MUST parse the `value` attribute as a
float. The unit is taken from the `unitAccession` attribute on the
same `cvParam`:

- `UO:0000010` (or any other) — value is in **seconds**, used as-is
- `UO:0000031` — value is in **minutes**, MUST be multiplied by `60.0`
  to normalize to seconds

The normalized seconds value is encoded as IEEE 754 big-endian hex
(16 lowercase hex characters). If the `value` attribute is missing or
unparseable, `rt_sec` is the empty string.

### 7.3 Ion mobility (`mobility`)

The canonicalizer MUST search the entire spectrum subtree (using a
recursive iteration over all `cvParam` descendants) for cvParam
accessions `MS:1002476` (drift time) or `MS:1003006` (inverse reduced
ion mobility), in that order. The first one found provides the value;
the rest are ignored.

The value is parsed as a float and encoded as IEEE 754 big-endian hex.
If neither accession is found or the value is unparseable, `mobility`
is the empty string.

### 7.4 Precursor block

After the header fields, the canonicalizer MUST emit five fixed-slot
precursor fields, in this order:

| Slot | Key | Source cvParam |
|---|---|---|
| 7 | `prec_target` | `MS:1000827` on the precursor's `<isolationWindow>` |
| 8 | `prec_lower` | `MS:1000828` on the precursor's `<isolationWindow>` |
| 9 | `prec_upper` | `MS:1000829` on the precursor's `<isolationWindow>` |
| 10 | `prec_selected` | `MS:1000744` on the precursor's `<selectedIonList>/<selectedIon>` |
| 11 | `prec_charge` | `MS:1000041` on the precursor's `<selectedIonList>/<selectedIon>` |

Float-typed slots (`prec_target`, `prec_lower`, `prec_upper`,
`prec_selected`) are encoded as IEEE 754 big-endian hex (16 chars) or
the empty string if absent / unparseable.

The `prec_charge` slot is encoded as ASCII decimal (e.g. `b"2"`) or
the empty string if absent. **The charge slot MUST NOT use the IEEE
754 hex encoding** because it is a small integer.

If the spectrum has no `<precursorList>` at all, all five precursor
slots are emitted with the empty value.

### 7.5 Binary array block

After the precursor block, the canonicalizer MUST count and emit
every `<binaryDataArray>` in the spectrum's `<binaryDataArrayList>`,
in role-label-sorted order.

For each `<binaryDataArray>`:

1. **Determine the role label** by examining direct child cvParams:
   - **Pass 1:** if any cvParam has an accession in the known
     content-accession set (§5.1), use that accession as the role
     label.
   - **Pass 2:** if no Pass 1 match, find any cvParam whose accession
     is NOT in the known encoding-accession set (§5.1), and use
     `unknown:<accession>` as the role label.
   - **Pass 3:** if neither pass yields a label, raise
     `MalformedSidecar`. This is the only failure mode for an
     untagged array.

2. **Determine the precision tag.** Inspect cvParams in this order:
   `f64` (`MS:1000523`), `f32` (`MS:1000521`), `i64` (`MS:1000522`),
   `i32` (`MS:1000519`). The first match wins. If none match, the tag
   is `??` (two literal question marks).

3. **Decode the binary payload** by:
   - Refusing if any numpress accession is present (see §3).
   - Locating the inner `<binary>` element. Raise `MalformedSidecar`
     if absent.
   - Stripping leading and trailing whitespace from the inner text.
   - Base64-decoding with strict validation. Raise `MalformedSidecar`
     if decoding fails.
   - If `MS:1000574` (zlib compression) is present, zlib-decompressing
     the result. Raise `MalformedSidecar` if decompression fails.
   - If neither `MS:1000574` nor `MS:1000576` is present, treat as
     uncompressed.
   - The result is the **payload**: the raw bytes of the array values.

4. **Determine the value count** as `len(payload) / width`, where
   width is 8 for `f64`/`i64`, 4 for `f32`/`i32`, and 0 for `??`. If
   width is 0, the value count is 0.

5. **Hash the payload** with SHA-256 and take the lowercase hex
   digest as ASCII bytes.

The canonicalizer MUST collect tuples `(role_label, precision_tag,
value_count, payload_hex_digest)` for every binary array in the
spectrum, then **sort by role_label** before emitting them. This sort
is what makes the canonical form invariant under `<binaryDataArray>`
document order.

After the precursor block, the canonicalizer emits:

| Slot | Key | Value encoding |
|---|---|---|
| 12 | `array_count` | ASCII decimal of the number of arrays |
| 13… | for each array, in role-sorted order: | |
|     | `array_role` | ASCII of the role label |
|     | `array_precision` | the precision tag (`f64`/`f32`/`i64`/`i32`/`??`) |
|     | `array_value_count` | ASCII decimal of the value count |
|     | `array_hash` | the SHA-256 hex digest of the payload, as ASCII |

The `array_count` slot up front guards against truncation: an attacker
who removes one array's records from the byte stream would also have
to fix the `array_count`, which is itself in the hash stream.

### 7.6 Record terminator

The full per-spectrum byte sequence ends with `RS = 0x1E`. This is
what separates one spectrum's record from the next in the streaming
hash.

## 8. Top-level canonicalization (`canonicalize_mzml`)

The full canonicalization is:

```
h = sha256()
h.update(b"TIMSIM-MZML-CANONICAL-v0\x1f")

count = 0
for spectrum in spectra_sorted_by_index(root):
    h.update(spectrum_record(spectrum))
    count += 1

h.update(b"\x1fspectrum_count\x1f" + ascii(count) + b"\x1f")
return h.digest()
```

The leading domain prefix `b"TIMSIM-MZML-CANONICAL-v0\x1f"` and the
trailing `spectrum_count` block are mandatory. The trailing count
ensures that an attacker cannot truncate the spectrum stream
unnoticed: the trailing count is itself in the hash, so any
disagreement between the recorded count and the number of spectrum
records hashes to a different value.

The output is 32 raw bytes, encoded in the sidecar as
`sha256:<64 lowercase hex>`.

## 9. Composed mzML content hash (`compose_mzml_content_hash`)

The single `content_hash` that lives in `payload.content_hash` is
composed from:

- `mzml_hash` (the output of §8)
- `config_hash` (SHA-256 of the raw config bytes, or `sha256(b"")` if
  no config was provided)

The composition is:

```
domain = b"timsim.mzml.v0\x1f"
US     = b"\x1f"

content_hash = sha256(
    domain
    || mzml_hash
    || US
    || config_hash
)
```

Notes:

- The domain prefix `b"timsim.mzml.v0\x1f"` is distinct from the `.d`
  domain prefix (`b"timsim.v0\x1f"`) so that an attacker cannot
  cross-substitute a `.d` content hash for an mzml content hash or
  vice versa.
- Both input hashes MUST be 32 bytes.

## 10. Test vectors

Conforming implementations MUST:

- Reproduce the canonical hash of every mzML fixture under
  [`../test-vectors/canonicalization/mzml/`](../test-vectors/canonicalization/mzml/)
  byte-identically.
- Verify every paired mzML vector under
  [`../test-vectors/sidecar/valid/`](../test-vectors/sidecar/valid/)
  with `type = timsim.provenance.mzml.v0`.
- Reject every paired mzML vector under
  [`../test-vectors/sidecar/invalid/`](../test-vectors/sidecar/invalid/)
  with `type = timsim.provenance.mzml.v0` with an exit code matching
  `_metadata.expected_exit_code`.

In particular, an implementation that produces different canonical
hashes for the indented and compact fixtures
(`001-indented.mzML` and `002-compact.mzML`) is **not** whitespace-
invariant and does not conform to v0.

## See also

- [`sidecar-format.md`](sidecar-format.md) — the JSON envelope and
  payload field semantics, including the mzML payload schema
- [`canonicalization-d-v0.md`](canonicalization-d-v0.md) — the
  parallel spec for `.d`
- [`security-considerations.md`](security-considerations.md) — the
  rationale for the precision tag in §7.5 (the encoding-tag-swap
  defense)
