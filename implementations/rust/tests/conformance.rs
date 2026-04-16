//! Conformance harness — runs against `../../../test-vectors/`.
//!
//! The vectors are the interop contract: every `valid/` sidecar MUST verify,
//! every `invalid/` sidecar MUST be rejected with the declared exit code,
//! and every canonicalization input MUST hash to the declared value.

use std::path::{Path, PathBuf};

use mzprov::canonicalize_d::canonicalize_d;
use mzprov::canonicalize_mzml::canonicalize_mzml;
use mzprov::envelope::encode_hash_field;
use mzprov::errors::ProvenanceError;
use mzprov::exit_codes::{
    EXIT_GENERIC, EXIT_HASH_MISMATCH, EXIT_KEY_ERROR, EXIT_KEY_NOT_TRUSTED, EXIT_OK,
    EXIT_SIDECAR_ERROR, EXIT_SIGNATURE_MISMATCH,
};
use mzprov::keys::{
    derive_key_id, generate_keypair, load_private_key, load_public_key, write_keypair,
};
use mzprov::sign::{sign_d, sign_mzml};
use mzprov::trust::{TrustedKey, TrustedKeyRegistry};
use mzprov::verify::{
    verify_sidecar, verify_sidecar_with, CheckStatus, TrustOptions, TrustStatus,
};

fn vectors_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../test-vectors").canonicalize().unwrap()
}

fn map_to_exit(result: Result<mzprov::verify::VerificationResult, ProvenanceError>) -> i32 {
    match result {
        Ok(r) => {
            if r.overall_ok {
                EXIT_OK
            } else if !r.trust.ok() {
                EXIT_KEY_NOT_TRUSTED
            } else if r.any_mismatch() {
                EXIT_HASH_MISMATCH
            } else if !r.signature_ok {
                EXIT_SIGNATURE_MISMATCH
            } else {
                EXIT_GENERIC
            }
        }
        Err(e) => match e {
            ProvenanceError::KeyNotFound(_) | ProvenanceError::MalformedKey(_) => EXIT_KEY_ERROR,
            ProvenanceError::MalformedSidecar(_)
            | ProvenanceError::UnknownVersion(_)
            | ProvenanceError::UnknownAlgorithm(_)
            | ProvenanceError::MissingArtifact(_)
            | ProvenanceError::SqliteNotQuiescent { .. }
            | ProvenanceError::Canonicalization(_) => EXIT_SIDECAR_ERROR,
            ProvenanceError::Io(_) => EXIT_GENERIC,
        },
    }
}

fn expected_exit_code(sidecar_path: &Path) -> i32 {
    let text = std::fs::read_to_string(sidecar_path).expect("read sidecar");
    let v: serde_json::Value = serde_json::from_str(&text).expect("parse sidecar");
    v.get("_metadata")
        .and_then(|m| m.get("expected_exit_code"))
        .and_then(|e| e.as_i64())
        .expect("vector missing _metadata.expected_exit_code") as i32
}

/// One vector subdirectory under `sidecar/valid/` or `sidecar/invalid/`.
/// Embedded vectors have no JSON sidecar; their `_metadata` lives in
/// a sibling `_metadata.json` file because the envelope is inside the
/// artifact (`.d` SQLite or mzML userParam).
enum VectorEntry {
    Json {
        sidecar: PathBuf,
    },
    EmbeddedD {
        d_path: PathBuf,
        metadata: serde_json::Value,
    },
    EmbeddedMzml {
        mzml_path: PathBuf,
        metadata: serde_json::Value,
    },
}

fn classify_vector(dir: &Path) -> VectorEntry {
    let name = dir.file_name().unwrap().to_string_lossy().to_string();
    let sidecar = dir.join(format!("{name}.provenance.json"));
    if sidecar.is_file() {
        return VectorEntry::Json { sidecar };
    }
    let metadata_path = dir.join("_metadata.json");
    let d_path = dir.join(format!("{name}.d"));
    if d_path.is_dir() && metadata_path.is_file() {
        let txt = std::fs::read_to_string(&metadata_path).expect("read embedded metadata");
        let metadata: serde_json::Value =
            serde_json::from_str(&txt).expect("parse embedded metadata");
        return VectorEntry::EmbeddedD { d_path, metadata };
    }
    let mzml_path = dir.join(format!("{name}.mzML"));
    if mzml_path.is_file() && metadata_path.is_file() {
        let txt = std::fs::read_to_string(&metadata_path).expect("read embedded metadata");
        let metadata: serde_json::Value =
            serde_json::from_str(&txt).expect("parse embedded metadata");
        return VectorEntry::EmbeddedMzml { mzml_path, metadata };
    }
    panic!(
        "vector {} has none of: JSON sidecar, embedded .d + _metadata.json, embedded mzml + _metadata.json",
        dir.display()
    );
}

fn for_each_vector(subdir: &str, mut f: impl FnMut(&VectorEntry)) {
    let root = vectors_root().join("sidecar").join(subdir);
    for entry in std::fs::read_dir(&root).expect("read sidecar dir").flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        f(&classify_vector(&dir));
    }
}

#[test]
fn valid_vectors_verify_with_exit_zero() {
    for_each_vector("valid", |vector| match vector {
        VectorEntry::Json { sidecar } => {
            let expected = expected_exit_code(sidecar);
            let got = map_to_exit(verify_sidecar(sidecar));
            assert_eq!(
                got,
                expected,
                "vector {}: expected {expected}, got {got}",
                sidecar.display()
            );

            let r = verify_sidecar(sidecar).expect("valid vector must verify");
            assert!(r.overall_ok, "valid vector must verify: {}", sidecar.display());
            assert!(r.signature_ok);
            assert!(r.checks.iter().all(|c| c.status == CheckStatus::Ok));
        }
        VectorEntry::EmbeddedD { d_path, metadata } => {
            let expected = metadata
                .get("expected_exit_code")
                .and_then(|e| e.as_i64())
                .expect("metadata missing expected_exit_code") as i32;
            let r = mzprov::verify::verify_embedded_d(d_path, &TrustOptions::default())
                .expect("embedded vector must read");
            let got = if r.overall_ok { 0 } else { 1 };
            assert_eq!(
                got,
                expected,
                "embedded vector {}: expected {expected}, got {got}",
                d_path.display()
            );
            assert!(r.overall_ok, "embedded vector must verify: {}", d_path.display());
            assert!(r.signature_ok);
            assert!(r.checks.iter().all(|c| c.status == CheckStatus::Ok));
            assert!(matches!(r.transport, mzprov::verify::Transport::EmbeddedD));
        }
        VectorEntry::EmbeddedMzml { mzml_path, metadata } => {
            let expected = metadata
                .get("expected_exit_code")
                .and_then(|e| e.as_i64())
                .expect("metadata missing expected_exit_code") as i32;
            let r = mzprov::verify::verify_embedded_mzml(mzml_path, &TrustOptions::default())
                .expect("embedded mzml vector must read");
            let got = if r.overall_ok { 0 } else { 1 };
            assert_eq!(
                got,
                expected,
                "embedded mzml vector {}: expected {expected}, got {got}",
                mzml_path.display()
            );
            assert!(r.overall_ok, "embedded mzml vector must verify: {}", mzml_path.display());
            assert!(r.signature_ok);
            assert!(r.checks.iter().all(|c| c.status == CheckStatus::Ok));
            assert!(matches!(r.transport, mzprov::verify::Transport::EmbeddedMzml));
        }
    });
}

#[test]
fn invalid_vectors_reject_with_declared_exit_code() {
    for_each_vector("invalid", |vector| match vector {
        VectorEntry::Json { sidecar } => {
            let expected = expected_exit_code(sidecar);
            let got = map_to_exit(verify_sidecar(sidecar));
            assert_eq!(
                got,
                expected,
                "vector {}: expected exit {expected}, got {got}",
                sidecar.display()
            );
        }
        VectorEntry::EmbeddedD { d_path, metadata } => {
            let expected = metadata
                .get("expected_exit_code")
                .and_then(|e| e.as_i64())
                .expect("metadata missing expected_exit_code") as i32;
            let r = mzprov::verify::verify_embedded_d(d_path, &TrustOptions::default());
            let got = match r {
                Ok(res) if res.overall_ok => 0,
                Ok(_) => 5,
                Err(e) => map_to_exit(Err(e)),
            };
            assert_eq!(
                got,
                expected,
                "embedded vector {}: expected exit {expected}, got {got}",
                d_path.display()
            );
        }
        VectorEntry::EmbeddedMzml { mzml_path, metadata } => {
            let expected = metadata
                .get("expected_exit_code")
                .and_then(|e| e.as_i64())
                .expect("metadata missing expected_exit_code") as i32;
            let r = mzprov::verify::verify_embedded_mzml(mzml_path, &TrustOptions::default());
            let got = match r {
                Ok(res) if res.overall_ok => 0,
                Ok(_) => 5,
                Err(e) => map_to_exit(Err(e)),
            };
            assert_eq!(
                got,
                expected,
                "embedded mzml vector {}: expected exit {expected}, got {got}",
                mzml_path.display()
            );
        }
    });
}

#[test]
fn key_id_derivation_matches_test_vector() {
    let keys_dir = vectors_root().join("keys/test-only-keypair-001");
    let pem_path = keys_dir.join("verifying_key.pem");
    let expected = std::fs::read_to_string(keys_dir.join("key_id"))
        .expect("read key_id")
        .trim()
        .to_owned();
    let vk = load_public_key(&pem_path).expect("load verifying key");
    let got = derive_key_id(&vk);
    assert_eq!(got, expected);
}

#[test]
fn canonical_d_hash_matches_vector() {
    let root = vectors_root().join("canonicalization/d");
    let d_dir = root.join("001-minimal.d");
    let expected = std::fs::read_to_string(root.join("001-minimal.canonical-hash.txt"))
        .expect("read expected")
        .trim()
        .to_owned();
    let digest = canonicalize_d(&d_dir).expect("canonicalize_d");
    assert_eq!(encode_hash_field(&digest), expected);
}

/// Exclusion-correctness fixture from spec/embedded-d-v0.md §3:
/// 002-with-mzprov-provenance.d contains a populated mzprov_provenance
/// table and MUST hash byte-identically to 001-minimal.d (which does
/// not). A canonicalizer that fails this is not exclusion-correct.
#[test]
fn canonical_d_hash_excludes_mzprov_provenance_table() {
    let root = vectors_root().join("canonicalization/d");
    let baseline = root.join("001-minimal.d");
    let with_table = root.join("002-with-mzprov-provenance.d");

    let h_baseline = canonicalize_d(&baseline).expect("canonicalize baseline");
    let h_with_table = canonicalize_d(&with_table).expect("canonicalize with-table");

    assert_eq!(
        h_baseline, h_with_table,
        "002-with-mzprov-provenance must hash identically to 001-minimal; \
         the mzprov_provenance table must be excluded from canonicalization"
    );

    let expected = std::fs::read_to_string(root.join("002-with-mzprov-provenance.canonical-hash.txt"))
        .expect("read expected")
        .trim()
        .to_owned();
    assert_eq!(encode_hash_field(&h_with_table), expected);
}

#[test]
fn round_trip_sign_then_verify_d() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/d/001-minimal.d");
    let dst = tmp.join("sample.d");
    copy_dir(&src, &dst);
    let config_path = tmp.join("sample.config.toml");
    std::fs::write(&config_path, b"name = \"round-trip\"\n").unwrap();

    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    let sidecar = sign_d(
        &dst,
        None,
        &config_path,
        "round-trip",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        false,
    )
    .unwrap();

    let r = verify_sidecar(&sidecar).expect("verify after sign");
    assert!(r.overall_ok, "round-trip sidecar must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
}

#[test]
fn round_trip_sign_embedded_then_verify_d() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/d/001-minimal.d");
    let dst = tmp.join("sample.d");
    copy_dir(&src, &dst);
    let config_path = tmp.join("sample.config.toml");
    std::fs::write(&config_path, b"name = \"round-trip-embedded\"\n").unwrap();

    let pre_hash = canonicalize_d(&dst).expect("hash before sign");

    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    let result_path = sign_d(
        &dst,
        None,
        &config_path,
        "round-trip-embedded",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        true,
    )
    .unwrap();
    assert_eq!(result_path, dst, "embed mode returns the .d path itself");

    // Exclusion correctness on the live .d.
    let post_hash = canonicalize_d(&dst).expect("hash after sign");
    assert_eq!(pre_hash, post_hash, "embed must not perturb the canonical hash");

    let r = mzprov::verify::verify_embedded_d(&dst, &TrustOptions::default())
        .expect("verify embedded after sign");
    assert!(r.overall_ok, "round-trip embedded must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
    assert!(matches!(r.transport, mzprov::verify::Transport::EmbeddedD));
}

#[test]
fn round_trip_sign_then_verify_mzml() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/mzml/001-indented.mzML");
    let dst = tmp.join("sample.mzML");
    std::fs::copy(&src, &dst).unwrap();

    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    let sidecar = sign_mzml(
        &dst,
        None,
        "round-trip",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        false,
    )
    .unwrap();

    let r = verify_sidecar(&sidecar).expect("verify after sign");
    assert!(r.overall_ok, "round-trip mzml sidecar must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
}

/// Round-trip embed-then-verify for mzML using the mzdata-backed
/// writer. Asserts exclusion correctness on the live file too: the
/// canonical hash MUST be unchanged across the write.
#[test]
fn round_trip_sign_embedded_then_verify_mzml() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/mzml/001-indented.mzML");
    let dst = tmp.join("sample.mzML");
    std::fs::copy(&src, &dst).unwrap();

    let pre_hash = canonicalize_mzml(&dst).expect("hash before sign");

    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    let result_path = sign_mzml(
        &dst,
        None,
        "round-trip-embedded",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        true,
    )
    .unwrap();
    assert_eq!(result_path, dst, "embed mode returns the mzml path itself");

    // Exclusion correctness on the live file.
    let post_hash = canonicalize_mzml(&dst).expect("hash after sign");
    assert_eq!(
        pre_hash, post_hash,
        "embed must not perturb the canonical hash"
    );

    let r = mzprov::verify::verify_embedded_mzml(&dst, &TrustOptions::default())
        .expect("verify embedded after sign");
    assert!(r.overall_ok, "round-trip embedded mzml must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
    assert!(matches!(r.transport, mzprov::verify::Transport::EmbeddedMzml));
}

#[test]
fn expected_key_id_matches() {
    let sidecar = vectors_root().join("sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json");
    let opts = TrustOptions {
        expected_key_id: Some("timsim-local-umdyuiienlum7prj".into()),
        ..TrustOptions::default()
    };
    let r = verify_sidecar_with(&sidecar, &opts).unwrap();
    assert!(r.overall_ok);
    assert_eq!(r.trust.status, TrustStatus::Ok);
}

#[test]
fn expected_key_id_mismatch_fails_with_exit_seven() {
    let sidecar = vectors_root().join("sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json");
    let opts = TrustOptions {
        expected_key_id: Some("timsim-local-wrongkeyid12345".into()),
        ..TrustOptions::default()
    };
    let r = verify_sidecar_with(&sidecar, &opts).unwrap();
    assert!(!r.overall_ok);
    assert_eq!(r.trust.status, TrustStatus::IdMismatch);
    assert_eq!(map_to_exit(Ok(r)), EXIT_KEY_NOT_TRUSTED);
}

#[test]
fn require_trusted_rejects_empty_registry() {
    let tmp = tempdir();
    let registry = tmp.join("trusted_keys.json");
    let sidecar = vectors_root().join("sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json");
    let opts = TrustOptions {
        require_trusted: true,
        trusted_registry_path: Some(registry),
        ..TrustOptions::default()
    };
    let r = verify_sidecar_with(&sidecar, &opts).unwrap();
    assert!(!r.overall_ok);
    assert_eq!(r.trust.status, TrustStatus::NotInRegistry);
    assert_eq!(map_to_exit(Ok(r)), EXIT_KEY_NOT_TRUSTED);
}

#[test]
fn require_trusted_accepts_registered_key() {
    let tmp = tempdir();
    let registry_path = tmp.join("trusted_keys.json");

    // Seed the registry with the test-only key.
    let pem = std::fs::read_to_string(
        vectors_root().join("keys/test-only-keypair-001/verifying_key.pem"),
    )
    .unwrap();
    let mut reg = TrustedKeyRegistry {
        path: registry_path.clone(),
        keys: Vec::new(),
    };
    let vk = mzprov::keys::public_key_from_pem(&pem).unwrap();
    reg.add(TrustedKey::from_public_key(&vk, "test seed", Some("2026-04-13T00:00:00.000Z"))
        .unwrap())
        .unwrap();
    reg.save().unwrap();

    let sidecar = vectors_root().join("sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json");
    let opts = TrustOptions {
        require_trusted: true,
        trusted_registry_path: Some(registry_path),
        ..TrustOptions::default()
    };
    let r = verify_sidecar_with(&sidecar, &opts).unwrap();
    assert!(r.overall_ok);
    assert_eq!(r.trust.status, TrustStatus::Ok);
}

#[test]
fn require_trusted_detects_pem_mismatch_under_same_key_id() {
    // Craft a registry entry whose key_id matches the signer's derived id
    // but whose stored PEM is a different key. Since key_id is a 80-bit
    // digest, this is the "collision-or-forgery" defense path: the check
    // compares raw PEMs byte-for-byte, not just the ids.
    let tmp = tempdir();
    let registry_path = tmp.join("trusted_keys.json");

    let other_kp = mzprov::keys::generate_keypair().unwrap();
    let other_pem = mzprov::keys::public_key_to_pem(&other_kp.verifying_key).unwrap();

    // Key id of the actual signer of the valid vector.
    let signer_key_id = "timsim-local-umdyuiienlum7prj".to_string();
    let spoofed = TrustedKey {
        key_id: signer_key_id,
        public_key_pem: other_pem,
        comment: "spoofed".into(),
        added_at: "2026-04-13T00:00:00.000Z".into(),
    };
    let reg = TrustedKeyRegistry {
        path: registry_path.clone(),
        keys: vec![spoofed],
    };
    reg.save().unwrap();

    let sidecar = vectors_root().join("sidecar/valid/d-v0-minimal/d-v0-minimal.provenance.json");
    let opts = TrustOptions {
        require_trusted: true,
        trusted_registry_path: Some(registry_path),
        ..TrustOptions::default()
    };
    let r = verify_sidecar_with(&sidecar, &opts).unwrap();
    assert!(!r.overall_ok);
    assert_eq!(r.trust.status, TrustStatus::RegistryPemMismatch);
    assert_eq!(map_to_exit(Ok(r)), EXIT_KEY_NOT_TRUSTED);
}

#[test]
fn registry_add_remove_round_trip() {
    let tmp = tempdir();
    let registry_path = tmp.join("trusted_keys.json");
    let kp = mzprov::keys::generate_keypair().unwrap();
    let entry =
        TrustedKey::from_public_key(&kp.verifying_key, "demo", Some("2026-04-13T00:00:00.000Z"))
            .unwrap();

    let mut reg = TrustedKeyRegistry {
        path: registry_path.clone(),
        keys: Vec::new(),
    };
    reg.add(entry.clone()).unwrap();
    // Idempotent: adding the same PEM under the same key_id is a no-op.
    reg.add(entry.clone()).unwrap();
    assert_eq!(reg.keys.len(), 1);
    reg.save().unwrap();

    let reloaded = TrustedKeyRegistry::load(Some(&registry_path)).unwrap();
    assert_eq!(reloaded.keys.len(), 1);
    assert_eq!(reloaded.keys[0].key_id, kp.key_id);

    let mut reg2 = reloaded;
    assert!(reg2.remove(&kp.key_id));
    assert!(!reg2.remove(&kp.key_id));
    assert!(reg2.keys.is_empty());
}

fn tempdir() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "mzprov-rust-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let p = entry.path();
        let target = dst.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_dir(&p, &target);
        } else {
            std::fs::copy(&p, &target).unwrap();
        }
    }
}

#[test]
fn canonical_mzml_hashes_match_vectors() {
    let root = vectors_root().join("canonicalization/mzml");
    for stem in ["001-indented", "002-compact"] {
        let mzml = root.join(format!("{stem}.mzML"));
        let expected = std::fs::read_to_string(root.join(format!("{stem}.canonical-hash.txt")))
            .expect("read expected")
            .trim()
            .to_owned();
        let digest = canonicalize_mzml(&mzml).expect("canonicalize_mzml");
        assert_eq!(
            encode_hash_field(&digest),
            expected,
            "mzml vector {stem} mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// Discovery-layer regressions (spec/embedded-d-v0.md §6.1, §6.2)
// ---------------------------------------------------------------------------

/// Regression: a .d with a stale `-wal` sidecar AND a sibling JSON
/// sidecar must NOT silently verify against the JSON. The embedded
/// probe must propagate the quiescence error (per §6.2); quietly
/// accepting the JSON would mask a broken embed.
#[test]
fn not_quiescent_d_with_sibling_json_does_not_silently_verify() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    // Build a .d in JSON-sidecar mode so a sibling .provenance.json exists.
    let src = vectors_root().join("canonicalization/d/001-minimal.d");
    let dst = tmp.join("quiet.d");
    copy_dir(&src, &dst);
    let config_path = tmp.join("quiet.config.toml");
    std::fs::write(&config_path, b"name = \"quiet\"\n").unwrap();
    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    let _sidecar = sign_d(
        &dst,
        None,
        &config_path,
        "quiet",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        false,
    )
    .unwrap();
    assert!(tmp.join("quiet.provenance.json").is_file(), "JSON sidecar prerequisite");

    // Plant a stale -wal sidecar next to analysis.tdf.
    let wal = dst.join("analysis.tdf-wal");
    std::fs::write(&wal, b"").unwrap();

    let result = mzprov::verify::find_provenance_for(&dst);
    match result {
        Err(mzprov::errors::ProvenanceError::SqliteNotQuiescent { .. }) => {}
        other => panic!(
            "expected SqliteNotQuiescent from discovery (no silent JSON fallback); got {other:?}"
        ),
    }
}

/// Regression: an experiment directory containing an embedded-only
/// .d (no sibling JSON sidecar) must be discovered when the user
/// passes the experiment dir, not the .d. Without the §6.1 descent,
/// this would be misreported as unsigned.
#[test]
fn embedded_only_experiment_dir_is_discovered() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/d/001-minimal.d");
    let exp_dir = tmp.join("experiment");
    std::fs::create_dir_all(&exp_dir).unwrap();
    let d_path = exp_dir.join("sample.d");
    copy_dir(&src, &d_path);

    let config_path = exp_dir.join("sample.config.toml");
    std::fs::write(&config_path, b"name = \"embed-only\"\n").unwrap();
    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();
    sign_d(
        &d_path,
        None,
        &config_path,
        "embed-only",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        true,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_dir(&exp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".provenance.json"))
                .unwrap_or(false))
            .count(),
        0,
        "test invariant: no JSON sidecar should exist"
    );

    // Discovery on the EXPERIMENT DIRECTORY (not the .d) must descend
    // into the unique .d and find the embedded transport.
    let discovery = mzprov::verify::find_provenance_for(&exp_dir)
        .expect("discovery did not error")
        .expect("discovery returned None for an embedded-only experiment dir");
    match discovery {
        mzprov::verify::Discovery::EmbeddedD(d) => {
            assert_eq!(d, d_path, "embedded discovery resolved the wrong .d");
        }
        other => panic!("expected EmbeddedD, got {other:?}"),
    }

    // And the embedded verifier must verify it.
    let r = mzprov::verify::verify_embedded_d(&d_path, &TrustOptions::default()).unwrap();
    assert!(r.overall_ok, "embedded-only experiment dir must verify");
}

/// Regression: when an experiment directory contains BOTH an
/// embedded .d and a sibling JSON sidecar, discovery must prefer
/// embedded (per spec/embedded-d-v0.md §6 — embedded is in-band and
/// authoritative).
#[test]
fn experiment_dir_with_both_transports_prefers_embedded() {
    let tmp = tempdir();
    let keypair = generate_keypair().unwrap();
    write_keypair(&keypair, &tmp.join("keys")).unwrap();

    let src = vectors_root().join("canonicalization/d/001-minimal.d");
    let exp_dir = tmp.join("dual");
    std::fs::create_dir_all(&exp_dir).unwrap();
    let d_path = exp_dir.join("dual.d");
    copy_dir(&src, &d_path);

    let config_path = exp_dir.join("dual.config.toml");
    std::fs::write(&config_path, b"name = \"dual\"\n").unwrap();
    let signing_key = load_private_key(&tmp.join("keys/signing_key.pem")).unwrap();

    // Sign once in JSON mode and once with --embed.
    sign_d(
        &d_path,
        None,
        &config_path,
        "dual",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        false,
    )
    .unwrap();
    sign_d(
        &d_path,
        None,
        &config_path,
        "dual",
        "mzprov-rust-test",
        "0.0.1",
        None,
        &signing_key,
        true,
    )
    .unwrap();

    let discovery = mzprov::verify::find_provenance_for(&exp_dir)
        .expect("discovery did not error")
        .expect("discovery returned None");
    assert!(
        matches!(discovery, mzprov::verify::Discovery::EmbeddedD(_)),
        "embedded must win over JSON when both are present"
    );
}
