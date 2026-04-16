//! Verifier. Pure function: given a sidecar path, returns a result that the
//! CLI maps to exit codes. Structural problems raise errors; hash and
//! signature mismatches surface as fields so the diagnostic can name the
//! failing check.
//!
//! Path resolution for the source artifact (.d / mzML) is independent of
//! the payload (per `spec/trust-model.md` §3): a tampered `experiment_name`
//! cannot redirect verification.

use std::path::{Path, PathBuf};

use crate::canonicalize_d::{
    canonicalize_d, canonicalize_sqlite, compose_content_hash, sha256_bytes,
};
use crate::canonicalize_mzml::{canonicalize_mzml, compose_mzml_content_hash};
use crate::envelope::{
    decode_hash_field, encode_hash_field, AttestationType, Sidecar,
};
use crate::errors::{ProvenanceError, Result};
use crate::keys::{
    derive_key_id, pubkeys_equal, public_key_from_b64, signature_from_b64, verify_signature,
};
use crate::trust::TrustedKeyRegistry;
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Mismatch,
    Unchecked,
}

#[derive(Debug, Clone)]
pub struct FieldCheck {
    pub name: String,
    pub expected: String,
    pub actual: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// No trust pin was requested.
    NotRequested,
    /// All requested pins were satisfied.
    Ok,
    /// `--expected-key-id` was given but the signer's derived key id differs.
    IdMismatch,
    /// `--require-trusted` was given but the signer is not in the registry.
    NotInRegistry,
    /// `--require-trusted` was given, the key_id is in the registry, but the
    /// registered PEM differs from the embedded verifying_key — catches both
    /// an 80-bit key_id collision and a forgery that reuses a trusted id.
    RegistryPemMismatch,
}

#[derive(Debug, Clone)]
pub struct TrustCheck {
    pub status: TrustStatus,
    pub detail: String,
    pub expected_key_id: String,
    pub actual_key_id: String,
}

impl TrustCheck {
    pub fn ok(&self) -> bool {
        matches!(self.status, TrustStatus::Ok | TrustStatus::NotRequested)
    }
    pub fn was_requested(&self) -> bool {
        !matches!(self.status, TrustStatus::NotRequested)
    }
}

/// Options controlling the optional trust-pinning layer of verification.
#[derive(Debug, Clone, Default)]
pub struct TrustOptions {
    /// Require the signer's derived key id to equal this string.
    pub expected_key_id: Option<String>,
    /// Require the signing key to be present in the trusted-keys registry
    /// AND match byte-for-byte.
    pub require_trusted: bool,
    /// Override the default `~/.config/timsim/trusted_keys.json` path.
    pub trusted_registry_path: Option<PathBuf>,
}

/// Which transport was used to load the sidecar envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Sidecar JSON file on disk.
    SidecarJson,
    /// In-band row in `analysis.tdf`'s `mzprov_provenance` table.
    EmbeddedD,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub sidecar_path: PathBuf,
    pub type_tag: AttestationType,
    pub signature_ok: bool,
    pub overall_ok: bool,
    pub checks: Vec<FieldCheck>,
    pub derived_key_id: String,
    pub trust: TrustCheck,
    pub transport: Transport,
}

impl VerificationResult {
    pub fn any_mismatch(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Mismatch)
    }
}

fn find_unique<F: Fn(&Path) -> bool>(root: &Path, accept: F) -> Option<PathBuf> {
    let mut hits: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if accept(&p) {
            hits.push(p);
        }
    }
    if hits.len() == 1 {
        Some(hits.remove(0))
    } else {
        None
    }
}

fn find_unique_d(root: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) == Some("d")
                && p.join("analysis.tdf").is_file()
            {
                candidates.push(p);
                continue;
            }
            if let Ok(grand) = std::fs::read_dir(&p) {
                for g in grand.flatten() {
                    let gp = g.path();
                    if gp.is_dir()
                        && gp.extension().and_then(|s| s.to_str()) == Some("d")
                        && gp.join("analysis.tdf").is_file()
                    {
                        candidates.push(gp);
                    }
                }
            }
        }
    }
    if candidates.len() == 1 {
        Some(candidates.remove(0))
    } else {
        None
    }
}

fn find_mzml_for_sidecar(sidecar_path: &Path) -> Option<PathBuf> {
    let name = sidecar_path.file_name()?.to_str()?;
    let stem = name
        .strip_suffix(".provenance.json")
        .unwrap_or_else(|| sidecar_path.file_stem().and_then(|s| s.to_str()).unwrap_or(""));
    let parent = sidecar_path.parent()?;
    for suffix in [".mzML", ".mzml"] {
        let candidate = parent.join(format!("{stem}{suffix}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    find_unique(parent, |p| {
        p.is_file()
            && p.extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("mzml"))
                .unwrap_or(false)
    })
}

fn config_path_for_sidecar(sidecar_path: &Path) -> Option<PathBuf> {
    let name = sidecar_path.file_name()?.to_str()?;
    let stem = name
        .strip_suffix(".provenance.json")
        .unwrap_or_else(|| sidecar_path.file_stem().and_then(|s| s.to_str()).unwrap_or(""));
    Some(sidecar_path.parent()?.join(format!("{stem}.config.toml")))
}

/// Verify a sidecar without any trust pinning.
pub fn verify_sidecar(sidecar_path: &Path) -> Result<VerificationResult> {
    verify_sidecar_with(sidecar_path, &TrustOptions::default())
}

/// Verify a sidecar. Returns an error for structural problems (missing
/// sidecar, malformed JSON, unknown type, missing artifact). Hash,
/// signature, and trust mismatches surface as fields on the result.
pub fn verify_sidecar_with(
    sidecar_path: &Path,
    trust_opts: &TrustOptions,
) -> Result<VerificationResult> {
    if !sidecar_path.is_file() {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "sidecar file does not exist: {}",
            sidecar_path.display()
        )));
    }
    let data = std::fs::read(sidecar_path)?;
    let sidecar = Sidecar::from_json_bytes(&data)?;

    // Derive the actual signer identity from verifying_key, not payload.key_id.
    let pubkey = public_key_from_b64(&sidecar.verifying_key)?;
    let derived_key_id = derive_key_id(&pubkey);
    let payload_key_id = sidecar.payload_str("key_id")?;
    if payload_key_id != derived_key_id {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "sidecar payload.key_id ({payload_key_id:?}) does not match the key id \
             derived from sidecar.verifying_key ({derived_key_id:?}); this is \
             consistent with a tampered or forged sidecar"
        )));
    }

    // Decode the signature early so an unknown-algorithm envelope in the
    // signature field surfaces as `UnknownAlgorithm` (exit 3).
    let signature = signature_from_b64(&sidecar.signature)?;

    let signed_bytes = sidecar.canonical_payload();
    let signature_ok = verify_signature(&pubkey, &signed_bytes, &signature);

    let mut checks: Vec<FieldCheck> = Vec::new();

    match sidecar.type_tag {
        AttestationType::D => {
            verify_d(sidecar_path, &sidecar, &mut checks)?;
        }
        AttestationType::Mzml => {
            verify_mzml(sidecar_path, &sidecar, &mut checks)?;
        }
    }

    let all_fields_ok = checks.iter().all(|c| c.status == CheckStatus::Ok);

    let trust = evaluate_trust(&derived_key_id, &pubkey, trust_opts);

    let overall_ok = signature_ok && all_fields_ok && trust.ok();

    Ok(VerificationResult {
        sidecar_path: sidecar_path.to_path_buf(),
        type_tag: sidecar.type_tag,
        signature_ok,
        overall_ok,
        checks,
        derived_key_id,
        trust,
        transport: Transport::SidecarJson,
    })
}

/// Verify a `.d` whose sidecar envelope is embedded inside `analysis.tdf`.
///
/// Reads the envelope from the `mzprov_provenance` table per
/// `spec/embedded-d-v0.md` §5, then runs the same integrity + trust
/// checks as [`verify_sidecar_with`]. Returns
/// [`ProvenanceError::MissingArtifact`] if the .d carries no embedded
/// row — the caller (typically the discovery layer) is expected to
/// fall back to JSON sidecar discovery in that case.
pub fn verify_embedded_d(
    d_path: &Path,
    trust_opts: &TrustOptions,
) -> Result<VerificationResult> {
    if !d_path.is_dir() {
        return Err(ProvenanceError::MissingArtifact(format!(
            ".d directory does not exist: {}",
            d_path.display()
        )));
    }

    let envelope = crate::embed_d::read_embedded_provenance(d_path)?.ok_or_else(|| {
        ProvenanceError::MissingArtifact(format!(
            "no embedded provenance found in {}/analysis.tdf",
            d_path.display()
        ))
    })?;

    let sidecar = Sidecar::from_json_bytes(&envelope)?;
    if sidecar.type_tag != AttestationType::D {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "embedded provenance in {} is an mzML attestation; expected a .d attestation",
            d_path.display()
        )));
    }

    let pubkey = public_key_from_b64(&sidecar.verifying_key)?;
    let derived_key_id = derive_key_id(&pubkey);
    let payload_key_id = sidecar.payload_str("key_id")?;
    if payload_key_id != derived_key_id {
        return Err(ProvenanceError::MalformedSidecar(format!(
            "sidecar payload.key_id ({payload_key_id:?}) does not match the key id \
             derived from sidecar.verifying_key ({derived_key_id:?})"
        )));
    }

    let signature = signature_from_b64(&sidecar.signature)?;
    let signed_bytes = sidecar.canonical_payload();
    let signature_ok = verify_signature(&pubkey, &signed_bytes, &signature);

    let mut checks: Vec<FieldCheck> = Vec::new();
    verify_d_against(d_path, &sidecar, &mut checks)?;

    let all_fields_ok = checks.iter().all(|c| c.status == CheckStatus::Ok);
    let trust = evaluate_trust(&derived_key_id, &pubkey, trust_opts);
    let overall_ok = signature_ok && all_fields_ok && trust.ok();

    Ok(VerificationResult {
        sidecar_path: d_path.to_path_buf(),
        type_tag: AttestationType::D,
        signature_ok,
        overall_ok,
        checks,
        derived_key_id,
        trust,
        transport: Transport::EmbeddedD,
    })
}

fn evaluate_trust(
    actual_key_id: &str,
    actual_pubkey: &VerifyingKey,
    opts: &TrustOptions,
) -> TrustCheck {
    if opts.expected_key_id.is_none() && !opts.require_trusted {
        return TrustCheck {
            status: TrustStatus::NotRequested,
            detail: String::new(),
            expected_key_id: String::new(),
            actual_key_id: actual_key_id.to_owned(),
        };
    }

    if let Some(expected) = &opts.expected_key_id {
        if expected != actual_key_id {
            return TrustCheck {
                status: TrustStatus::IdMismatch,
                detail: format!(
                    "sidecar was signed by {actual_key_id:?} but caller expected {expected:?}"
                ),
                expected_key_id: expected.clone(),
                actual_key_id: actual_key_id.to_owned(),
            };
        }
    }

    if opts.require_trusted {
        let registry = match TrustedKeyRegistry::load(opts.trusted_registry_path.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                return TrustCheck {
                    status: TrustStatus::NotInRegistry,
                    detail: format!("trusted-keys registry is malformed: {e}"),
                    expected_key_id: opts.expected_key_id.clone().unwrap_or_default(),
                    actual_key_id: actual_key_id.to_owned(),
                };
            }
        };
        let entry = match registry.find(actual_key_id) {
            Some(e) => e,
            None => {
                return TrustCheck {
                    status: TrustStatus::NotInRegistry,
                    detail: format!(
                        "key {actual_key_id:?} is not in the trusted-keys registry at {}. \
                         Add it with 'mzprov keys trust ...' if you trust this signer.",
                        registry.path.display()
                    ),
                    expected_key_id: opts.expected_key_id.clone().unwrap_or_default(),
                    actual_key_id: actual_key_id.to_owned(),
                };
            }
        };
        let registered = match entry.load_public_key() {
            Ok(k) => k,
            Err(e) => {
                return TrustCheck {
                    status: TrustStatus::RegistryPemMismatch,
                    detail: format!("could not load registered PEM: {e}"),
                    expected_key_id: opts.expected_key_id.clone().unwrap_or_default(),
                    actual_key_id: actual_key_id.to_owned(),
                };
            }
        };
        if !pubkeys_equal(actual_pubkey, &registered) {
            return TrustCheck {
                status: TrustStatus::RegistryPemMismatch,
                detail: format!(
                    "sidecar's key id {actual_key_id:?} is trusted but its public key bytes \
                     differ from the registered PEM; consistent with a key_id collision or forgery"
                ),
                expected_key_id: opts.expected_key_id.clone().unwrap_or_default(),
                actual_key_id: actual_key_id.to_owned(),
            };
        }
    }

    TrustCheck {
        status: TrustStatus::Ok,
        detail: String::new(),
        expected_key_id: opts.expected_key_id.clone().unwrap_or_default(),
        actual_key_id: actual_key_id.to_owned(),
    }
}

fn push_check(
    out: &mut Vec<FieldCheck>,
    name: &str,
    expected: &str,
    actual: &str,
    status: CheckStatus,
    detail: &str,
) {
    out.push(FieldCheck {
        name: name.into(),
        expected: expected.into(),
        actual: actual.into(),
        status,
        detail: detail.into(),
    });
}

fn verify_d(sidecar_path: &Path, sidecar: &Sidecar, checks: &mut Vec<FieldCheck>) -> Result<()> {
    let parent = sidecar_path.parent().unwrap_or_else(|| Path::new("."));
    let d_path = find_unique_d(parent).ok_or_else(|| {
        ProvenanceError::MissingArtifact(format!(
            "could not find a unique .d directory near {}",
            parent.display()
        ))
    })?;
    verify_d_payload(
        sidecar,
        &d_path,
        config_path_for_sidecar(sidecar_path),
        parent.join("synthetic_data.db"),
        checks,
    )
}

/// Verify the .d half of a parsed sidecar against an already-known
/// `.d` directory. Used by the embedded-d verification path.
fn verify_d_against(d_path: &Path, sidecar: &Sidecar, checks: &mut Vec<FieldCheck>) -> Result<()> {
    let d_name = d_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("data");
    let stem = d_name.strip_suffix(".d").unwrap_or(d_name).to_owned();
    let parent = d_path.parent().unwrap_or_else(|| Path::new("."));
    verify_d_payload(
        sidecar,
        d_path,
        Some(parent.join(format!("{stem}.config.toml"))),
        parent.join("synthetic_data.db"),
        checks,
    )
}

/// Shared per-field verification body. Both transports (JSON sidecar
/// and embedded-d) reduce to this once the artifact and config paths
/// are known.
fn verify_d_payload(
    sidecar: &Sidecar,
    d_path: &Path,
    config_path: Option<PathBuf>,
    ground_truth_path: PathBuf,
    checks: &mut Vec<FieldCheck>,
) -> Result<()> {
    let d_hash = canonicalize_d(d_path)?;

    let expected_d = sidecar.payload_str("d_content_hash")?.to_owned();
    let actual_d = encode_hash_field(&d_hash);
    let status = if expected_d == actual_d {
        CheckStatus::Ok
    } else {
        CheckStatus::Mismatch
    };
    push_check(checks, "d_content_hash", &expected_d, &actual_d, status, "");

    let gt_field = sidecar.payload_str("ground_truth_hash")?.to_owned();
    let mut gt_hash: Option<[u8; 32]> = None;
    if !gt_field.is_empty() {
        if !ground_truth_path.is_file() {
            return Err(ProvenanceError::MissingArtifact(format!(
                "sidecar references ground-truth DB but none at {}",
                ground_truth_path.display()
            )));
        }
        let h = canonicalize_sqlite(&ground_truth_path)?;
        let actual_g = encode_hash_field(&h);
        let status = if gt_field == actual_g {
            CheckStatus::Ok
        } else {
            CheckStatus::Mismatch
        };
        push_check(checks, "ground_truth_hash", &gt_field, &actual_g, status, "");
        gt_hash = Some(h);
    }

    let expected_cfg = sidecar.payload_str("config_hash")?.to_owned();
    let (cfg_hash_opt, cfg_actual, cfg_status, cfg_detail) =
        resolve_config_hash_at(config_path.as_deref(), &expected_cfg);
    push_check(
        checks,
        "config_hash",
        &expected_cfg,
        &cfg_actual,
        cfg_status,
        &cfg_detail,
    );

    let expected_content = sidecar.payload_str("content_hash")?.to_owned();
    match cfg_hash_opt {
        Some(cfg) => {
            let composed = compose_content_hash(&d_hash, gt_hash.as_ref(), &cfg);
            let actual = encode_hash_field(&composed);
            let status = if expected_content == actual {
                CheckStatus::Ok
            } else {
                CheckStatus::Mismatch
            };
            push_check(checks, "content_hash", &expected_content, &actual, status, "");
        }
        None => {
            push_check(
                checks,
                "content_hash",
                &expected_content,
                "",
                CheckStatus::Unchecked,
                "cannot recompose content_hash without the config file",
            );
        }
    }

    Ok(())
}

fn verify_mzml(
    sidecar_path: &Path,
    sidecar: &Sidecar,
    checks: &mut Vec<FieldCheck>,
) -> Result<()> {
    let mzml_path = find_mzml_for_sidecar(sidecar_path).ok_or_else(|| {
        ProvenanceError::MissingArtifact(format!(
            "could not find an .mzML file for sidecar {}",
            sidecar_path.display()
        ))
    })?;
    let mzml_hash = canonicalize_mzml(&mzml_path)?;

    let expected_m = sidecar.payload_str("mzml_content_hash")?.to_owned();
    let actual_m = encode_hash_field(&mzml_hash);
    let status = if expected_m == actual_m {
        CheckStatus::Ok
    } else {
        CheckStatus::Mismatch
    };
    push_check(
        checks,
        "mzml_content_hash",
        &expected_m,
        &actual_m,
        status,
        "",
    );

    let expected_cfg = sidecar.payload_str("config_hash")?.to_owned();
    let (cfg_hash_opt, cfg_actual, cfg_status, cfg_detail) =
        resolve_config_hash(sidecar_path, &expected_cfg);
    push_check(
        checks,
        "config_hash",
        &expected_cfg,
        &cfg_actual,
        cfg_status,
        &cfg_detail,
    );

    let expected_content = sidecar.payload_str("content_hash")?.to_owned();
    match cfg_hash_opt {
        Some(cfg) => {
            let composed = compose_mzml_content_hash(&mzml_hash, &cfg);
            let actual = encode_hash_field(&composed);
            let status = if expected_content == actual {
                CheckStatus::Ok
            } else {
                CheckStatus::Mismatch
            };
            push_check(checks, "content_hash", &expected_content, &actual, status, "");
        }
        None => {
            push_check(
                checks,
                "content_hash",
                &expected_content,
                "",
                CheckStatus::Unchecked,
                "cannot recompose content_hash without the config file",
            );
        }
    }

    // Validate the expected config_hash is well-formed sha256 so a bad
    // field surfaces as SIDECAR_ERROR even when the file is absent.
    let _ = decode_hash_field(&expected_cfg)?;
    Ok(())
}

fn resolve_config_hash(
    sidecar_path: &Path,
    expected_cfg: &str,
) -> (Option<[u8; 32]>, String, CheckStatus, String) {
    resolve_config_hash_at(config_path_for_sidecar(sidecar_path).as_deref(), expected_cfg)
}

fn resolve_config_hash_at(
    cfg_path: Option<&Path>,
    expected_cfg: &str,
) -> (Option<[u8; 32]>, String, CheckStatus, String) {
    if let Some(cfg_path) = cfg_path {
        if cfg_path.is_file() {
            match std::fs::read(cfg_path) {
                Ok(bytes) => {
                    let hash = sha256_bytes(&bytes);
                    let actual = encode_hash_field(&hash);
                    let status = if expected_cfg == actual {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Mismatch
                    };
                    return (Some(hash), actual, status, String::new());
                }
                Err(e) => {
                    return (
                        None,
                        String::new(),
                        CheckStatus::Unchecked,
                        format!("config file unreadable: {e}"),
                    );
                }
            }
        }
    }
    // mzML-side special case: if signer used config_path=None, the signed
    // hash is sha256(b""); we can recompute that without a file.
    let empty_actual = encode_hash_field(&sha256_bytes(b""));
    if expected_cfg == empty_actual {
        return (
            Some(sha256_bytes(b"")),
            empty_actual,
            CheckStatus::Ok,
            String::new(),
        );
    }
    (
        None,
        String::new(),
        CheckStatus::Unchecked,
        "no config file found next to sidecar".into(),
    )
}

/// Discovery result. Mirrors the Python `find_provenance_for`.
#[derive(Debug, Clone)]
pub enum Discovery {
    /// Provenance is embedded in `.d`/analysis.tdf as an `mzprov_provenance` row.
    EmbeddedD(PathBuf),
    /// Provenance is a JSON sidecar at the given path.
    SidecarJson(PathBuf),
}

/// Locate provenance for a path, preferring embedded over JSON sidecar.
///
/// For `.d` directories, the embedded transport is checked first
/// (`spec/embedded-d-v0.md` §6 — embedded is in-band and authoritative
/// when both forms are present). For everything else this falls
/// through to [`find_sidecar_for`].
pub fn find_provenance_for(path: &Path) -> Option<Discovery> {
    if path.is_dir()
        && path.extension().and_then(|s| s.to_str()) == Some("d")
        && path.join("analysis.tdf").is_file()
    {
        match crate::embed_d::has_embedded_provenance(path) {
            Ok(true) => return Some(Discovery::EmbeddedD(path.to_path_buf())),
            // Quiescence guard or similar — treat as "no embedded
            // provenance" for discovery; the verifier surfaces the
            // same error if the user invokes the embedded path.
            Ok(false) | Err(_) => {}
        }
    }
    find_sidecar_for(path).map(Discovery::SidecarJson)
}

/// Discovery rule for a sidecar given a path to any of: the sidecar itself,
/// a `.d` directory, an mzML file, or an experiment directory. Mirrors
/// `spec/sidecar-format.md` §8.
///
/// This function discovers JSON sidecars only. For full transport-aware
/// discovery (embedded preferred over JSON for `.d`), use
/// [`find_provenance_for`].
pub fn find_sidecar_for(path: &Path) -> Option<PathBuf> {
    if path.is_file()
        && path.extension().and_then(|s| s.to_str()) == Some("json")
        && path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.contains(".provenance"))
            .unwrap_or(false)
    {
        return Some(path.to_path_buf());
    }
    if path.is_file()
        && path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("mzml"))
            .unwrap_or(false)
    {
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            let parent = path.parent()?;
            let candidate = parent.join(format!("{stem}.provenance.json"));
            if candidate.is_file() {
                return Some(candidate);
            }
            return find_unique(parent, |p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| n.ends_with(".provenance.json"))
                        .unwrap_or(false)
            });
        }
    }
    if path.is_dir() {
        if path.extension().and_then(|s| s.to_str()) == Some("d") {
            let stem_os = path.file_stem()?;
            let stem = stem_os.to_str()?;
            let parent = path.parent()?;
            let candidate = parent.join(format!("{stem}.provenance.json"));
            if candidate.is_file() {
                return Some(candidate);
            }
            return find_unique(parent, |p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| n.ends_with(".provenance.json"))
                        .unwrap_or(false)
            });
        }
        return find_unique(path, |p| {
            p.is_file()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| n.ends_with(".provenance.json"))
                    .unwrap_or(false)
        });
    }
    None
}
