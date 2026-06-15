//! Signing: build a payload, sign its canonical bytes with Ed25519, and
//! write the sidecar envelope. Mirrors `implementations/python/src/mzprov/sign.py`.
//!
//! The envelope pretty-printing is SHOULD per `spec/sidecar-format.md` §1
//! and explicitly not part of the signed bytes.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde_json::{Map, Value};

use crate::canonicalize_d::{canonicalize_d, canonicalize_sqlite, compose_content_hash, sha256_bytes};
use crate::canonicalize_mzml::{canonicalize_mzml, compose_mzml_content_hash};
use crate::canonicalize_raw::{canonicalize_raw, compose_raw_content_hash};
use crate::paths::{
    embedded_d_config_path, embedded_mzml_config_path, sidecar_config_path,
};
use crate::envelope::{
    encode_hash_field, AttestationType, ATTESTATION_TYPE_D, ATTESTATION_TYPE_MZML,
    ATTESTATION_TYPE_RAW, SUPPORTED_CANONICALIZATION,
};
use crate::errors::{ProvenanceError, Result};
use crate::keys::{derive_key_id, public_key_to_b64, sign_message, signature_to_b64};

/// Sign a Bruker `.d` directory. Writes the sidecar next to the source
/// (`{experiment_name}.provenance.json` by default in the .d's parent)
/// and copies the config bytes to `{stem}.config.toml`. Returns the
/// sidecar path.
///
/// When `embed=true`, the sidecar envelope is written into
/// `analysis.tdf` as a row in `mzprov_provenance` (see
/// `spec/embedded-d-v0.md`); no JSON sidecar file is produced and the
/// returned path is the .d itself. The exclusion rule in
/// `canonicalize_d` ensures the .d's content hash does not change as
/// a result. `sidecar_path` MUST be `None` when `embed=true`.
#[allow(clippy::too_many_arguments)]
pub fn sign_d(
    d_path: &Path,
    ground_truth_path: Option<&Path>,
    config_path: &Path,
    experiment_name: &str,
    simulator_name: &str,
    simulator_version: &str,
    sidecar_path: Option<&Path>,
    signing_key: &SigningKey,
    embed: bool,
) -> Result<PathBuf> {
    if !d_path.is_dir() {
        return Err(ProvenanceError::MissingArtifact(format!(
            ".d directory does not exist: {}",
            d_path.display()
        )));
    }
    if !config_path.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "config file does not exist: {}",
            config_path.display()
        )));
    }
    if let Some(gt) = ground_truth_path {
        if !gt.is_file() {
            return Err(ProvenanceError::MissingArtifact(format!(
                "ground-truth database does not exist: {}",
                gt.display()
            )));
        }
    }
    if embed && sidecar_path.is_some() {
        return Err(ProvenanceError::MissingArtifact(
            "sidecar_path is not meaningful when embed=true; \
             the envelope is stored inside analysis.tdf"
                .into(),
        ));
    }

    let (sidecar, config_copy_target): (PathBuf, PathBuf) = if embed {
        // Embedded mode: there is no sidecar file. The config copy is
        // the conventional embedded-d location.
        (d_path.to_path_buf(), embedded_d_config_path(d_path))
    } else {
        let default_sidecar = d_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{experiment_name}.provenance.json"));
        let chosen = sidecar_path.map(Path::to_path_buf).unwrap_or(default_sidecar);
        let cfg = sidecar_config_path(&chosen);
        (chosen, cfg)
    };

    let d_hash = canonicalize_d(d_path)?;
    let config_bytes = fs::read(config_path)?;
    let config_hash = sha256_bytes(&config_bytes);
    let ground_truth_hash = match ground_truth_path {
        Some(gt) => Some(canonicalize_sqlite(gt)?),
        None => None,
    };

    copy_config_to(&config_copy_target, &config_bytes)?;

    let content_hash = compose_content_hash(&d_hash, ground_truth_hash.as_ref(), &config_hash);

    let verifying = signing_key.verifying_key();
    let key_id = derive_key_id(&verifying);

    let mut payload: Map<String, Value> = Map::new();
    payload.insert("simulator_name".into(), Value::String(simulator_name.into()));
    payload.insert("simulator_version".into(), Value::String(simulator_version.into()));
    payload.insert("experiment_name".into(), Value::String(experiment_name.into()));
    payload.insert("config_hash".into(), Value::String(encode_hash_field(&config_hash)));
    payload.insert("d_content_hash".into(), Value::String(encode_hash_field(&d_hash)));
    payload.insert(
        "ground_truth_hash".into(),
        Value::String(ground_truth_hash.map(|h| encode_hash_field(&h)).unwrap_or_default()),
    );
    payload.insert("content_hash".into(), Value::String(encode_hash_field(&content_hash)));
    payload.insert("timestamp_utc".into(), Value::String(utc_now_iso()));
    payload.insert("key_id".into(), Value::String(key_id));
    payload.insert(
        "canonicalization_version".into(),
        Value::String(SUPPORTED_CANONICALIZATION.into()),
    );

    let envelope_bytes = build_envelope_bytes(
        AttestationType::D,
        &payload,
        signing_key,
        &verifying,
    );
    if embed {
        crate::embed_d::write_embedded_provenance(d_path, &envelope_bytes)?;
        Ok(d_path.to_path_buf())
    } else {
        write_atomic(&sidecar, &envelope_bytes)?;
        Ok(sidecar)
    }
}

/// Sign an mzML file. `config_path` is optional; when absent, the signed
/// `config_hash` is sha256 of the empty byte string.
///
/// When `embed=true`, the sidecar envelope is written into the mzML
/// itself as a `userParam` named `mzprov:provenance` inside
/// `<fileDescription>/<fileContent>` (see `spec/embedded-mzml-v0.md`).
/// No JSON sidecar file is produced; the returned path is the mzML
/// itself. The output is a valid `<indexedmzML>` document with a fresh
/// byte-offset index (re-index mode per spec §4). `sidecar_path` MUST
/// be `None` when `embed=true`.
#[allow(clippy::too_many_arguments)]
pub fn sign_mzml(
    mzml_path: &Path,
    config_path: Option<&Path>,
    experiment_name: &str,
    tool_name: &str,
    tool_version: &str,
    sidecar_path: Option<&Path>,
    signing_key: &SigningKey,
    embed: bool,
) -> Result<PathBuf> {
    if !mzml_path.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "mzml file does not exist: {}",
            mzml_path.display()
        )));
    }
    let config_bytes: Vec<u8> = match config_path {
        Some(p) => {
            if !p.is_file() {
                return Err(ProvenanceError::MissingArtifact(format!(
                    "config file does not exist: {}",
                    p.display()
                )));
            }
            fs::read(p)?
        }
        None => Vec::new(),
    };

    if embed && sidecar_path.is_some() {
        return Err(ProvenanceError::MissingArtifact(
            "sidecar_path is not meaningful when embed=true; \
             the envelope is stored inside the mzML's fileContent"
                .into(),
        ));
    }

    let (sidecar, config_copy_target): (PathBuf, PathBuf) = if embed {
        // Embedded mode: the "result path" is the mzml itself; the
        // config copy is the conventional embedded-mzml location.
        (mzml_path.to_path_buf(), embedded_mzml_config_path(mzml_path))
    } else {
        let default_sidecar = {
            let stem = mzml_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("sidecar");
            mzml_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!("{stem}.provenance.json"))
        };
        let chosen = sidecar_path.map(Path::to_path_buf).unwrap_or(default_sidecar);
        let cfg = sidecar_config_path(&chosen);
        (chosen, cfg)
    };

    let mzml_hash = canonicalize_mzml(mzml_path)?;
    let config_hash = sha256_bytes(&config_bytes);

    if config_path.is_some() {
        copy_config_to(&config_copy_target, &config_bytes)?;
    }

    let content_hash = compose_mzml_content_hash(&mzml_hash, &config_hash);

    let verifying = signing_key.verifying_key();
    let key_id = derive_key_id(&verifying);

    let mut payload: Map<String, Value> = Map::new();
    payload.insert("tool_name".into(), Value::String(tool_name.into()));
    payload.insert("tool_version".into(), Value::String(tool_version.into()));
    payload.insert("experiment_name".into(), Value::String(experiment_name.into()));
    payload.insert("config_hash".into(), Value::String(encode_hash_field(&config_hash)));
    payload.insert("mzml_content_hash".into(), Value::String(encode_hash_field(&mzml_hash)));
    payload.insert("content_hash".into(), Value::String(encode_hash_field(&content_hash)));
    payload.insert("timestamp_utc".into(), Value::String(utc_now_iso()));
    payload.insert("key_id".into(), Value::String(key_id));
    payload.insert(
        "canonicalization_version".into(),
        Value::String(SUPPORTED_CANONICALIZATION.into()),
    );

    let envelope_bytes = build_envelope_bytes(
        AttestationType::Mzml,
        &payload,
        signing_key,
        &verifying,
    );
    if embed {
        crate::embed_mzml::write_embedded_provenance(mzml_path, &envelope_bytes)?;
        Ok(mzml_path.to_path_buf())
    } else {
        write_atomic(&sidecar, &envelope_bytes)?;
        Ok(sidecar)
    }
}

/// Sign a Thermo `.raw` file. `config_path` is optional; when absent, the
/// signed `config_hash` is sha256 of the empty byte string.
///
/// A Thermo `.raw` is an undocumented proprietary binary. It cannot be
/// structurally canonicalized and has no safe injection point for an
/// embedded envelope, so its attestation is an **opaque whole-file hash**
/// and is **sidecar-only** — there is deliberately no `embed` parameter
/// (contrast [`sign_d`] / [`sign_mzml`]).
///
/// The sidecar defaults to `{stem}.provenance.json` beside the `.raw`. A
/// custom `sidecar_path` MUST end with `.provenance.json` and pair back to
/// the `.raw` (same stem, same directory): the verifier locates the
/// artifact by stripping `.provenance.json` from the sidecar name and
/// looking for `{stem}.raw` in the sidecar's directory, NEVER by a signed
/// basename, so a sidecar that does not pair would attest one file but
/// verify a different (or absent) one. This mirrors the guard in the Python
/// `sign_raw_output`.
#[allow(clippy::too_many_arguments)]
pub fn sign_raw(
    raw_path: &Path,
    config_path: Option<&Path>,
    experiment_name: &str,
    tool_name: &str,
    tool_version: &str,
    sidecar_path: Option<&Path>,
    signing_key: &SigningKey,
) -> Result<PathBuf> {
    if !raw_path.is_file() {
        return Err(ProvenanceError::MissingArtifact(format!(
            "raw file does not exist: {}",
            raw_path.display()
        )));
    }
    let config_bytes: Vec<u8> = match config_path {
        Some(p) => {
            if !p.is_file() {
                return Err(ProvenanceError::MissingArtifact(format!(
                    "config file does not exist: {}",
                    p.display()
                )));
            }
            fs::read(p)?
        }
        None => Vec::new(),
    };

    let raw_stem = raw_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sidecar");

    let sidecar: PathBuf = match sidecar_path {
        None => raw_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{raw_stem}.provenance.json")),
        Some(chosen) => {
            // The .raw artifact is located at verify time by stripping
            // ".provenance.json" from the sidecar name and looking for
            // "{stem}.raw" in the SIDECAR's directory — the pairing is by
            // stem + directory, NOT by a signed basename. Reject a custom
            // sidecar path that wouldn't pair back to raw_path.
            let name = chosen
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let derived_stem = name.strip_suffix(".provenance.json").ok_or_else(|| {
                ProvenanceError::MissingArtifact(format!(
                    "sidecar_path must end with '.provenance.json' (got {name:?}); the \
                     verifier derives the .raw name from that suffix"
                ))
            })?;
            let same_dir = match (chosen.parent(), raw_path.parent()) {
                (Some(a), Some(b)) => {
                    a.canonicalize().ok() == b.canonicalize().ok()
                        || a == b
                }
                _ => false,
            };
            if derived_stem != raw_stem || !same_dir {
                return Err(ProvenanceError::MissingArtifact(format!(
                    "sidecar_path {} does not pair with raw_path {}: a .raw sidecar must be \
                     named '{raw_stem}.provenance.json' beside the .raw file (the verifier \
                     finds the artifact by the sidecar's stem + dir)",
                    chosen.display(),
                    raw_path.display()
                )));
            }
            chosen.to_path_buf()
        }
    };
    let config_copy_target = sidecar_config_path(&sidecar);

    let raw_hash = canonicalize_raw(raw_path)?;
    let config_hash = sha256_bytes(&config_bytes);

    if config_path.is_some() {
        copy_config_to(&config_copy_target, &config_bytes)?;
    }

    let content_hash = compose_raw_content_hash(&raw_hash, &config_hash);

    let verifying = signing_key.verifying_key();
    let key_id = derive_key_id(&verifying);

    let mut payload: Map<String, Value> = Map::new();
    payload.insert("tool_name".into(), Value::String(tool_name.into()));
    payload.insert("tool_version".into(), Value::String(tool_version.into()));
    payload.insert("experiment_name".into(), Value::String(experiment_name.into()));
    payload.insert("config_hash".into(), Value::String(encode_hash_field(&config_hash)));
    payload.insert("raw_content_hash".into(), Value::String(encode_hash_field(&raw_hash)));
    payload.insert("content_hash".into(), Value::String(encode_hash_field(&content_hash)));
    payload.insert("timestamp_utc".into(), Value::String(utc_now_iso()));
    payload.insert("key_id".into(), Value::String(key_id));
    payload.insert(
        "canonicalization_version".into(),
        Value::String(SUPPORTED_CANONICALIZATION.into()),
    );

    let envelope_bytes = build_envelope_bytes(
        AttestationType::Raw,
        &payload,
        signing_key,
        &verifying,
    );
    write_atomic(&sidecar, &envelope_bytes)?;
    Ok(sidecar)
}

fn copy_config_to(target: &Path, config_bytes: &[u8]) -> Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    fs::write(target, config_bytes)?;
    Ok(())
}

/// Build the pretty-printed envelope bytes (the JSON representation of
/// the v0 sidecar). Used by both transports — JSON file and embedded
/// row carry the *same* envelope; only the storage differs.
fn build_envelope_bytes(
    type_tag: AttestationType,
    payload: &Map<String, Value>,
    signing_key: &SigningKey,
    verifying: &ed25519_dalek::VerifyingKey,
) -> Vec<u8> {
    let signed_bytes = serde_json::to_vec(&Value::Object(payload.clone()))
        .expect("Map<String, Value> must serialize");
    let sig = sign_message(signing_key, &signed_bytes);

    let type_str = match type_tag {
        AttestationType::D => ATTESTATION_TYPE_D,
        AttestationType::Mzml => ATTESTATION_TYPE_MZML,
        AttestationType::Raw => ATTESTATION_TYPE_RAW,
    };

    let mut envelope: Map<String, Value> = Map::new();
    envelope.insert("type".into(), Value::String(type_str.into()));
    envelope.insert("payload".into(), Value::Object(payload.clone()));
    envelope.insert("signature".into(), Value::String(signature_to_b64(&sig)));
    envelope.insert(
        "verifying_key".into(),
        Value::String(public_key_to_b64(verifying)),
    );

    serde_json::to_vec_pretty(&Value::Object(envelope))
        .expect("envelope must serialize")
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        // fsync is best-effort; some filesystems in CI don't support it.
        let _ = f.sync_all();
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub(crate) fn utc_now_iso() -> String {
    // "YYYY-MM-DDTHH:MM:SS.fffZ" — matches the Python reference exactly.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_secs(total_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Convert a POSIX timestamp (seconds since 1970-01-01 UTC) to a civil
/// date/time tuple. Uses the Howard Hinnant algorithm from
/// <https://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_secs(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    let h = time_of_day / 3600;
    let mi = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    (y, mo, d, h, mi, s)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m, d)
}
