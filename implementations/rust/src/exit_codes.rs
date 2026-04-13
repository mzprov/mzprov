//! Verifier exit codes. Values come from `spec/trust-model.md`.

pub const EXIT_OK: i32 = 0;
pub const EXIT_GENERIC: i32 = 1;
pub const EXIT_KEY_ERROR: i32 = 2;
pub const EXIT_SIDECAR_ERROR: i32 = 3;
pub const EXIT_UNSIGNED: i32 = 4;
pub const EXIT_HASH_MISMATCH: i32 = 5;
pub const EXIT_SIGNATURE_MISMATCH: i32 = 6;
pub const EXIT_KEY_NOT_TRUSTED: i32 = 7;
