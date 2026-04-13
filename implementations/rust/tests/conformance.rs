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
    EXIT_GENERIC, EXIT_HASH_MISMATCH, EXIT_KEY_ERROR, EXIT_OK, EXIT_SIDECAR_ERROR,
    EXIT_SIGNATURE_MISMATCH,
};
use mzprov::keys::{
    derive_key_id, generate_keypair, load_private_key, load_public_key, write_keypair,
};
use mzprov::sign::{sign_d, sign_mzml};
use mzprov::verify::{verify_sidecar, CheckStatus};

fn vectors_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../test-vectors").canonicalize().unwrap()
}

fn map_to_exit(result: Result<mzprov::verify::VerificationResult, ProvenanceError>) -> i32 {
    match result {
        Ok(r) => {
            if r.overall_ok {
                EXIT_OK
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

fn for_each_sidecar(subdir: &str, mut f: impl FnMut(&Path)) {
    let root = vectors_root().join("sidecar").join(subdir);
    for entry in std::fs::read_dir(&root).expect("read sidecar dir").flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let sidecar = dir.join(format!("{name}.provenance.json"));
        assert!(sidecar.is_file(), "missing sidecar: {}", sidecar.display());
        f(&sidecar);
    }
}

#[test]
fn valid_vectors_verify_with_exit_zero() {
    for_each_sidecar("valid", |sidecar| {
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
    });
}

#[test]
fn invalid_vectors_reject_with_declared_exit_code() {
    for_each_sidecar("invalid", |sidecar| {
        let expected = expected_exit_code(sidecar);
        let got = map_to_exit(verify_sidecar(sidecar));
        assert_eq!(
            got,
            expected,
            "vector {}: expected exit {expected}, got {got}",
            sidecar.display()
        );
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
    )
    .unwrap();

    let r = verify_sidecar(&sidecar).expect("verify after sign");
    assert!(r.overall_ok, "round-trip sidecar must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
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
    )
    .unwrap();

    let r = verify_sidecar(&sidecar).expect("verify after sign");
    assert!(r.overall_ok, "round-trip mzml sidecar must verify");
    assert!(r.signature_ok);
    assert_eq!(r.derived_key_id, keypair.key_id);
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
