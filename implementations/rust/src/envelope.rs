//! Sidecar envelope parsing + canonical payload serialization.
//!
//! The wire bytes that get signed are the canonical JSON serialization of
//! the inner `payload` object only: sorted keys, no whitespace, UTF-8,
//! non-ASCII preserved. See `spec/sidecar-format.md` §5.
//!
//! serde_json's `Map` is backed by `BTreeMap` (the default, without the
//! `preserve_order` feature), so serializing a `Value::Object` already
//! produces sorted keys. Its default compact formatter emits `,`/`:`
//! separators with no whitespace. Non-ASCII is emitted as raw UTF-8,
//! matching Python's `json.dumps(..., ensure_ascii=False)`.

use serde_json::{Map, Value};

use crate::errors::{ProvenanceError, Result};

pub const ATTESTATION_TYPE_D: &str = "timsim.provenance.v0";
pub const ATTESTATION_TYPE_MZML: &str = "timsim.provenance.mzml.v0";
pub const ATTESTATION_TYPE_RAW: &str = "timsim.provenance.raw.v0";
pub const SUPPORTED_CANONICALIZATION: &str = "v0";

const D_REQUIRED: &[&str] = &[
    "simulator_name",
    "simulator_version",
    "experiment_name",
    "config_hash",
    "d_content_hash",
    "ground_truth_hash",
    "content_hash",
    "timestamp_utc",
    "key_id",
    "canonicalization_version",
];

const MZML_REQUIRED: &[&str] = &[
    "tool_name",
    "tool_version",
    "experiment_name",
    "config_hash",
    "mzml_content_hash",
    "content_hash",
    "timestamp_utc",
    "key_id",
    "canonicalization_version",
];

const RAW_REQUIRED: &[&str] = &[
    "tool_name",
    "tool_version",
    "experiment_name",
    "config_hash",
    "raw_content_hash",
    "content_hash",
    "timestamp_utc",
    "key_id",
    "canonicalization_version",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationType {
    D,
    Mzml,
    Raw,
}

#[derive(Debug, Clone)]
pub struct Sidecar {
    pub type_tag: AttestationType,
    /// The payload as parsed — already a `BTreeMap`-backed object, so
    /// re-serializing it produces canonical bytes.
    pub payload: Map<String, Value>,
    pub signature: String,
    pub verifying_key: String,
}

impl Sidecar {
    /// Parse a sidecar from JSON bytes, validating envelope shape and
    /// dispatching on the `type` tag.
    pub fn from_json_bytes(data: &[u8]) -> Result<Self> {
        let blob: Value = serde_json::from_slice(data).map_err(|e| {
            ProvenanceError::MalformedSidecar(format!("sidecar is not valid UTF-8 JSON: {e}"))
        })?;
        let obj = blob
            .as_object()
            .ok_or_else(|| ProvenanceError::MalformedSidecar("sidecar root must be a JSON object".into()))?;

        let type_tag = match obj.get("type").and_then(Value::as_str) {
            Some(ATTESTATION_TYPE_D) => AttestationType::D,
            Some(ATTESTATION_TYPE_MZML) => AttestationType::Mzml,
            Some(ATTESTATION_TYPE_RAW) => AttestationType::Raw,
            Some(other) => {
                return Err(ProvenanceError::UnknownVersion(format!(
                    "sidecar type {other:?} is not a recognized attestation type"
                )))
            }
            None => {
                return Err(ProvenanceError::MalformedSidecar(
                    "sidecar is missing required top-level field 'type'".into(),
                ))
            }
        };

        let payload_value = obj.get("payload").ok_or_else(|| {
            ProvenanceError::MalformedSidecar("sidecar is missing required top-level field 'payload'".into())
        })?;
        let payload = payload_value
            .as_object()
            .ok_or_else(|| ProvenanceError::MalformedSidecar("sidecar.payload must be an object".into()))?
            .clone();

        let signature = obj
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProvenanceError::MalformedSidecar(
                    "sidecar.signature must be a string".into(),
                )
            })?
            .to_owned();
        let verifying_key = obj
            .get("verifying_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProvenanceError::MalformedSidecar(
                    "sidecar.verifying_key must be a string".into(),
                )
            })?
            .to_owned();

        let required: &[&str] = match type_tag {
            AttestationType::D => D_REQUIRED,
            AttestationType::Mzml => MZML_REQUIRED,
            AttestationType::Raw => RAW_REQUIRED,
        };
        for field in required {
            if !payload.contains_key(*field) {
                return Err(ProvenanceError::MalformedSidecar(format!(
                    "sidecar payload is missing required field {field:?}"
                )));
            }
        }

        let canon_v = payload
            .get("canonicalization_version")
            .and_then(Value::as_str)
            .unwrap_or("");
        if canon_v != SUPPORTED_CANONICALIZATION {
            return Err(ProvenanceError::UnknownVersion(format!(
                "sidecar canonicalization_version {canon_v:?} is not supported"
            )));
        }

        Ok(Self {
            type_tag,
            payload,
            signature,
            verifying_key,
        })
    }

    /// Serialize the payload to canonical JSON bytes. These are the bytes
    /// that get signed.
    pub fn canonical_payload(&self) -> Vec<u8> {
        // `Map` is a `BTreeMap` (no `preserve_order` feature), so default
        // serialization is sorted keys with compact `,`/`:` separators.
        serde_json::to_vec(&Value::Object(self.payload.clone()))
            .expect("serializing a valid Map<String, Value> cannot fail")
    }

    /// Get a required string field from the payload.
    pub fn payload_str(&self, field: &str) -> Result<&str> {
        self.payload
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProvenanceError::MalformedSidecar(format!(
                    "payload field {field:?} is missing or not a string"
                ))
            })
    }
}

/// Decode an `sha256:<hex>` field to 32 raw bytes. An empty string is
/// permitted for `ground_truth_hash` and returns `None`.
pub fn decode_hash_field(value: &str) -> Result<Option<[u8; 32]>> {
    if value.is_empty() {
        return Ok(None);
    }
    let rest = value.strip_prefix("sha256:").ok_or_else(|| {
        ProvenanceError::MalformedSidecar(format!("hash field is not sha256-prefixed: {value:?}"))
    })?;
    let raw = hex::decode(rest)
        .map_err(|e| ProvenanceError::MalformedSidecar(format!("hash field is not valid hex: {e}")))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| ProvenanceError::MalformedSidecar("hash field is not 32 bytes".into()))?;
    Ok(Some(arr))
}

pub fn encode_hash_field(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}
