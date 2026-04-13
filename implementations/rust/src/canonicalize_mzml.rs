//! Canonical content hashing for mzML files (v0, frozen).
//!
//! Independent port of `canonicalize_mzml.py`. Hashes spectra only; every
//! `binaryDataArray` contributes a labeled (role, precision, count,
//! sha256-hex) record, so tampering with e.g. an ion-mobility array
//! changes the hash. See `spec/canonicalization-mzml-v0.md`.

use base64::Engine;
use flate2::read::ZlibDecoder;
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use crate::errors::{ProvenanceError, Result};

const US: u8 = 0x1f;
const RS: u8 = 0x1e;
const MZML_NS: &str = "http://psi.hupo.org/ms/mzml";
const MZML_CONTENT_DOMAIN: &[u8] = b"timsim.mzml.v0\x1f";

// PSI-MS accessions we resolve by number.
const ACC_MS_LEVEL: &str = "MS:1000511";
const ACC_SCAN_START_TIME: &str = "MS:1000016";
const ACC_POSITIVE: &str = "MS:1000130";
const ACC_NEGATIVE: &str = "MS:1000129";
const ACC_SELECTED_ION_MZ: &str = "MS:1000744";
const ACC_CHARGE_STATE: &str = "MS:1000041";
const ACC_ISO_TARGET: &str = "MS:1000827";
const ACC_ISO_LOWER: &str = "MS:1000828";
const ACC_ISO_UPPER: &str = "MS:1000829";
const ACC_F64: &str = "MS:1000523";
const ACC_F32: &str = "MS:1000521";
const ACC_I64: &str = "MS:1000522";
const ACC_I32: &str = "MS:1000519";
const ACC_NO_COMPRESSION: &str = "MS:1000576";
const ACC_ZLIB: &str = "MS:1000574";
const ACC_NUMPRESS_LINEAR: &str = "MS:1002312";
const ACC_NUMPRESS_PIC: &str = "MS:1002313";
const ACC_NUMPRESS_SLOF: &str = "MS:1002314";
const ACC_ION_MOBILITY: &str = "MS:1002476";
const ACC_ION_MOBILITY_ALT: &str = "MS:1003006";
const UNIT_MINUTE: &str = "UO:0000031";

const KNOWN_ARRAY_ROLE_ACCS: &[&str] = &[
    "MS:1000514", "MS:1000515", "MS:1000516", "MS:1000517", "MS:1000595",
    "MS:1000617", "MS:1000786", "MS:1000820", "MS:1000821", "MS:1000822",
    "MS:1002476", "MS:1002477", "MS:1002478", "MS:1003006", "MS:1003007",
    "MS:1003008", "MS:1003153",
];

const KNOWN_ENCODING_ACCS: &[&str] = &[
    "MS:1000519", "MS:1000521", "MS:1000522", "MS:1000523",
    "MS:1000574", "MS:1000576",
    "MS:1002312", "MS:1002313", "MS:1002314",
];

fn is_ms_elem(node: &Node, local: &str) -> bool {
    node.is_element() && node.tag_name().name() == local && node.tag_name().namespace() == Some(MZML_NS)
}

fn child_elem<'a, 'input>(parent: &Node<'a, 'input>, local: &str) -> Option<Node<'a, 'input>> {
    parent.children().find(|c| is_ms_elem(c, local))
}

fn children_elem<'a, 'input: 'a>(
    parent: &Node<'a, 'input>,
    local: &'a str,
) -> impl Iterator<Item = Node<'a, 'input>> + 'a {
    parent.children().filter(move |c| is_ms_elem(c, local))
}

fn cv_value<'a>(parent: &Node<'a, '_>, accession: &str) -> Option<&'a str> {
    for cv in children_elem(parent, "cvParam") {
        if cv.attribute("accession") == Some(accession) {
            return cv.attribute("value");
        }
    }
    None
}

fn cv_present(parent: &Node, accession: &str) -> bool {
    children_elem(parent, "cvParam").any(|cv| cv.attribute("accession") == Some(accession))
}

fn cv_value_recursive<'a>(root: &Node<'a, '_>, accession: &str) -> Option<&'a str> {
    for d in root.descendants() {
        if is_ms_elem(&d, "cvParam") && d.attribute("accession") == Some(accession) {
            return d.attribute("value");
        }
    }
    None
}

fn ieee754_hex(v: f64) -> String {
    hex::encode(v.to_be_bytes())
}

fn extract_polarity(spectrum: &Node) -> u8 {
    if cv_present(spectrum, ACC_POSITIVE) {
        return b'+';
    }
    if cv_present(spectrum, ACC_NEGATIVE) {
        return b'-';
    }
    b'?'
}

fn extract_rt_seconds(spectrum: &Node) -> Option<f64> {
    let scan_list = child_elem(spectrum, "scanList")?;
    let scan = child_elem(&scan_list, "scan")?;
    for cv in children_elem(&scan, "cvParam") {
        if cv.attribute("accession") == Some(ACC_SCAN_START_TIME) {
            let v = cv.attribute("value")?.parse::<f64>().ok()?;
            let is_minute = cv.attribute("unitAccession") == Some(UNIT_MINUTE);
            return Some(if is_minute { v * 60.0 } else { v });
        }
    }
    None
}

fn extract_ion_mobility(spectrum: &Node) -> Option<f64> {
    for acc in [ACC_ION_MOBILITY, ACC_ION_MOBILITY_ALT] {
        if let Some(v) = cv_value_recursive(spectrum, acc) {
            if let Ok(f) = v.parse::<f64>() {
                return Some(f);
            }
        }
    }
    None
}

#[derive(Default)]
struct PrecursorFields {
    target: Option<f64>,
    lower: Option<f64>,
    upper: Option<f64>,
    selected_mz: Option<f64>,
    charge: Option<i64>,
}

fn extract_precursor(spectrum: &Node) -> Option<PrecursorFields> {
    let plist = child_elem(spectrum, "precursorList")?;
    let precursor = child_elem(&plist, "precursor")?;

    let mut out = PrecursorFields::default();
    let mut any = false;

    if let Some(iso) = child_elem(&precursor, "isolationWindow") {
        for (slot, acc) in [
            ("target", ACC_ISO_TARGET),
            ("lower", ACC_ISO_LOWER),
            ("upper", ACC_ISO_UPPER),
        ] {
            if let Some(v) = cv_value(&iso, acc) {
                if let Ok(f) = v.parse::<f64>() {
                    any = true;
                    match slot {
                        "target" => out.target = Some(f),
                        "lower" => out.lower = Some(f),
                        "upper" => out.upper = Some(f),
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    if let Some(sil) = child_elem(&precursor, "selectedIonList") {
        if let Some(sion) = child_elem(&sil, "selectedIon") {
            if let Some(v) = cv_value(&sion, ACC_SELECTED_ION_MZ) {
                if let Ok(f) = v.parse::<f64>() {
                    any = true;
                    out.selected_mz = Some(f);
                }
            }
            if let Some(v) = cv_value(&sion, ACC_CHARGE_STATE) {
                if let Ok(i) = v.parse::<i64>() {
                    any = true;
                    out.charge = Some(i);
                }
            }
        }
    }

    if any {
        Some(out)
    } else {
        None
    }
}

fn decode_binary(bda: &Node) -> Result<Vec<u8>> {
    for acc in [ACC_NUMPRESS_LINEAR, ACC_NUMPRESS_PIC, ACC_NUMPRESS_SLOF] {
        if cv_present(bda, acc) {
            return Err(ProvenanceError::Canonicalization(format!(
                "mzml binaryDataArray uses numpress ({acc}); not supported in v0"
            )));
        }
    }
    let binary_el = child_elem(bda, "binary").ok_or_else(|| {
        ProvenanceError::MalformedSidecar(
            "mzml binaryDataArray is missing the inner <binary> element".into(),
        )
    })?;
    let text = binary_el.text().unwrap_or("").trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| {
            ProvenanceError::MalformedSidecar(format!("undecodable base64 in binary: {e}"))
        })?;
    if cv_present(bda, ACC_ZLIB) {
        let mut d = ZlibDecoder::new(&raw[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out).map_err(|e| {
            ProvenanceError::MalformedSidecar(format!("undecompressable zlib: {e}"))
        })?;
        return Ok(out);
    }
    // Explicit no-compression or missing cvParam — treat as raw bytes.
    let _ = ACC_NO_COMPRESSION;
    Ok(raw)
}

fn precision_tag(bda: &Node) -> (&'static [u8], usize) {
    if cv_present(bda, ACC_F64) {
        return (b"f64", 8);
    }
    if cv_present(bda, ACC_F32) {
        return (b"f32", 4);
    }
    if cv_present(bda, ACC_I64) {
        return (b"i64", 8);
    }
    if cv_present(bda, ACC_I32) {
        return (b"i32", 4);
    }
    (b"??", 0)
}

fn array_role_label(bda: &Node) -> Result<String> {
    for cv in children_elem(bda, "cvParam") {
        if let Some(acc) = cv.attribute("accession") {
            if KNOWN_ARRAY_ROLE_ACCS.contains(&acc) {
                return Ok(acc.to_owned());
            }
        }
    }
    for cv in children_elem(bda, "cvParam") {
        if let Some(acc) = cv.attribute("accession") {
            if !acc.is_empty() && !KNOWN_ENCODING_ACCS.contains(&acc) {
                return Ok(format!("unknown:{acc}"));
            }
        }
    }
    Err(ProvenanceError::MalformedSidecar(
        "binaryDataArray has no cvParam identifying its array role".into(),
    ))
}

fn emit(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.push(US);
    out.extend_from_slice(key);
    out.push(US);
    out.extend_from_slice(value);
    out.push(US);
}

fn spectrum_record(spectrum: &Node) -> Result<Vec<u8>> {
    let spec_id = spectrum.attribute("id").unwrap_or("");
    let index_str = spectrum.attribute("index").unwrap_or("");
    let index: i64 = index_str.parse().map_err(|_| {
        ProvenanceError::MalformedSidecar(format!(
            "mzml spectrum {spec_id:?} has missing or non-integer index"
        ))
    })?;

    let ms_level = cv_value(spectrum, ACC_MS_LEVEL).unwrap_or("");
    let polarity = extract_polarity(spectrum);
    let rt = extract_rt_seconds(spectrum);
    let mob = extract_ion_mobility(spectrum);
    let precursor = extract_precursor(spectrum);

    // Collect every binary array; sort by role label.
    let mut arrays: Vec<(String, &'static [u8], usize, String)> = Vec::new();
    if let Some(bdal) = child_elem(spectrum, "binaryDataArrayList") {
        for bda in children_elem(&bdal, "binaryDataArray") {
            let role = array_role_label(&bda)?;
            let payload = decode_binary(&bda)?;
            let (tag, width) = precision_tag(&bda);
            let count = if width != 0 { payload.len() / width } else { 0 };
            let mut h = Sha256::new();
            h.update(&payload);
            let digest = hex::encode(h.finalize());
            arrays.push((role, tag, count, digest));
        }
    }
    arrays.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rec = Vec::with_capacity(512);

    emit(&mut rec, b"spec_index", index.to_string().as_bytes());
    emit(&mut rec, b"spec_id", spec_id.as_bytes());
    emit(&mut rec, b"ms_level", ms_level.as_bytes());
    emit(&mut rec, b"polarity", &[polarity]);
    emit(
        &mut rec,
        b"rt_sec",
        rt.map(ieee754_hex).as_deref().unwrap_or("").as_bytes(),
    );
    emit(
        &mut rec,
        b"mobility",
        mob.map(ieee754_hex).as_deref().unwrap_or("").as_bytes(),
    );

    match &precursor {
        None => {
            emit(&mut rec, b"prec_target", b"");
            emit(&mut rec, b"prec_lower", b"");
            emit(&mut rec, b"prec_upper", b"");
            emit(&mut rec, b"prec_selected", b"");
            emit(&mut rec, b"prec_charge", b"");
        }
        Some(p) => {
            emit(
                &mut rec,
                b"prec_target",
                p.target.map(ieee754_hex).as_deref().unwrap_or("").as_bytes(),
            );
            emit(
                &mut rec,
                b"prec_lower",
                p.lower.map(ieee754_hex).as_deref().unwrap_or("").as_bytes(),
            );
            emit(
                &mut rec,
                b"prec_upper",
                p.upper.map(ieee754_hex).as_deref().unwrap_or("").as_bytes(),
            );
            emit(
                &mut rec,
                b"prec_selected",
                p.selected_mz
                    .map(ieee754_hex)
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
            );
            emit(
                &mut rec,
                b"prec_charge",
                p.charge
                    .map(|c| c.to_string())
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
            );
        }
    }

    emit(
        &mut rec,
        b"array_count",
        arrays.len().to_string().as_bytes(),
    );
    for (role, prec, count, digest) in &arrays {
        emit(&mut rec, b"array_role", role.as_bytes());
        emit(&mut rec, b"array_precision", prec);
        emit(&mut rec, b"array_value_count", count.to_string().as_bytes());
        emit(&mut rec, b"array_hash", digest.as_bytes());
    }

    rec.push(RS);
    Ok(rec)
}

/// Return the sha256 of the canonical content form of an mzML file.
pub fn canonicalize_mzml(path: &Path) -> Result<[u8; 32]> {
    if !path.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "mzml file not found: {}",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(path)?;
    let doc = Document::parse(&text).map_err(|e| {
        ProvenanceError::MalformedSidecar(format!("mzml file is not valid XML: {e}"))
    })?;
    let root = doc.root_element();

    let mut indexed: Vec<(i64, Node)> = Vec::new();
    for d in root.descendants() {
        if is_ms_elem(&d, "spectrum") {
            let idx: i64 = d
                .attribute("index")
                .ok_or_else(|| {
                    ProvenanceError::MalformedSidecar(
                        "mzml spectrum has missing index attribute".into(),
                    )
                })?
                .parse()
                .map_err(|_| {
                    ProvenanceError::MalformedSidecar(
                        "mzml spectrum has non-integer index attribute".into(),
                    )
                })?;
            indexed.push((idx, d));
        }
    }
    indexed.sort_by_key(|(i, _)| *i);

    let mut hasher = Sha256::new();
    hasher.update(b"TIMSIM-MZML-CANONICAL-v0\x1f");
    for (_, spectrum) in &indexed {
        hasher.update(&spectrum_record(spectrum)?);
    }
    hasher.update(b"\x1fspectrum_count\x1f");
    hasher.update(indexed.len().to_string().as_bytes());
    hasher.update([US]);
    Ok(hasher.finalize().into())
}

/// Compose the mzML content hash: `sha256(MZML_DOMAIN || mzml || US || config)`.
pub fn compose_mzml_content_hash(mzml_hash: &[u8; 32], config_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MZML_CONTENT_DOMAIN);
    h.update(mzml_hash);
    h.update([US]);
    h.update(config_hash);
    h.finalize().into()
}
