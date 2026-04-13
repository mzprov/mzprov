//! Independent Rust implementation of mzprov v0.
//!
//! This crate targets the normative specification in `../../spec/` and is
//! validated against the shared test vectors in `../../test-vectors/`. It
//! shares no code with the Python reference implementation; both pass the
//! same conformance harness.
//!
//! Scope:
//!
//! - Ed25519 key loading (public + private PKCS#8 PEM), key-id derivation
//! - Sidecar envelope parsing + canonical payload bytes
//! - `.d` and mzML content canonicalization
//! - Signer (`mzprov sign`) and verifier (`mzprov verify`) with exit codes
//!   matching `spec/trust-model.md`

pub mod canonicalize_d;
pub mod canonicalize_mzml;
pub mod envelope;
pub mod errors;
pub mod exit_codes;
pub mod keys;
pub mod sign;
pub mod trust;
pub mod verify;

pub use errors::ProvenanceError;
