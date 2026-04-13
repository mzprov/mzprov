//! Trusted-keys registry — identity layer on top of the internally-consistent
//! signature check. Two independent mechanisms (see `spec/trust-model.md`):
//!
//! 1. Ad-hoc pinning via `--expected-key-id ID` (no registry).
//! 2. `--require-trusted` against `~/.config/timsim/trusted_keys.json`.
//!
//! The registry is never populated implicitly — no TOFU. The user must run
//! `mzprov keys trust ...` to grant trust explicitly.

use ed25519_dalek::VerifyingKey;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

use crate::envelope::Sidecar;
use crate::errors::{ProvenanceError, Result};
use crate::keys::{derive_key_id, load_public_key, public_key_from_pem, public_key_to_pem};
use crate::sign::{utc_now_iso, write_atomic};

pub const REGISTRY_SCHEMA: &str = "timsim.trusted_keys/v0";
const REGISTRY_FILENAME: &str = "trusted_keys.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key_pem: String,
    pub comment: String,
    pub added_at: String,
}

impl TrustedKey {
    pub fn from_public_key(
        public_key: &VerifyingKey,
        comment: &str,
        added_at: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            key_id: derive_key_id(public_key),
            public_key_pem: public_key_to_pem(public_key)?,
            comment: comment.to_owned(),
            added_at: added_at.map(str::to_owned).unwrap_or_else(utc_now_iso),
        })
    }

    /// Parse the stored PEM back into an Ed25519 verifying key.
    pub fn load_public_key(&self) -> Result<VerifyingKey> {
        public_key_from_pem(&self.public_key_pem)
    }

    fn to_value(&self) -> Value {
        let mut m: Map<String, Value> = Map::new();
        m.insert("added_at".into(), Value::String(self.added_at.clone()));
        m.insert("comment".into(), Value::String(self.comment.clone()));
        m.insert("key_id".into(), Value::String(self.key_id.clone()));
        m.insert(
            "public_key_pem".into(),
            Value::String(self.public_key_pem.clone()),
        );
        Value::Object(m)
    }

    fn from_value(v: &Value) -> Result<Self> {
        let obj = v.as_object().ok_or_else(|| {
            ProvenanceError::MalformedSidecar("trusted-key entry is not an object".into())
        })?;
        let get_str = |k: &str| -> Result<String> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    ProvenanceError::MalformedSidecar(format!(
                        "trusted-key entry is missing field {k:?}"
                    ))
                })
        };
        Ok(Self {
            key_id: get_str("key_id")?,
            public_key_pem: get_str("public_key_pem")?,
            comment: get_str("comment")?,
            added_at: get_str("added_at")?,
        })
    }
}

pub fn default_registry_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("timsim").join(REGISTRY_FILENAME)
}

#[derive(Debug, Clone)]
pub struct TrustedKeyRegistry {
    pub path: PathBuf,
    pub keys: Vec<TrustedKey>,
}

impl TrustedKeyRegistry {
    /// Load from `path` (or the default). A missing file is a fresh empty
    /// registry — not an error.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let registry_path = path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_registry_path);
        if !registry_path.exists() {
            return Ok(Self {
                path: registry_path,
                keys: Vec::new(),
            });
        }
        let bytes = std::fs::read(&registry_path)?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| {
            ProvenanceError::MalformedSidecar(format!(
                "trusted-keys registry at {} is not valid JSON: {e}",
                registry_path.display()
            ))
        })?;
        let obj = v.as_object().ok_or_else(|| {
            ProvenanceError::MalformedSidecar(format!(
                "trusted-keys registry at {} root must be an object",
                registry_path.display()
            ))
        })?;
        let schema = obj.get("schema").and_then(Value::as_str).unwrap_or("");
        if schema != REGISTRY_SCHEMA {
            return Err(ProvenanceError::MalformedSidecar(format!(
                "trusted-keys registry schema {schema:?} is not supported \
                 (supported: {REGISTRY_SCHEMA:?})"
            )));
        }
        let keys_blob = obj.get("keys").cloned().unwrap_or(Value::Array(Vec::new()));
        let arr = keys_blob.as_array().ok_or_else(|| {
            ProvenanceError::MalformedSidecar(
                "trusted-keys registry 'keys' field must be a list".into(),
            )
        })?;
        let keys = arr
            .iter()
            .map(TrustedKey::from_value)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            path: registry_path,
            keys,
        })
    }

    /// Persist atomically. Matches the Python reference byte format (sorted
    /// keys, 2-space indent, trailing LF-less body).
    pub fn save(&self) -> Result<()> {
        let mut root: Map<String, Value> = Map::new();
        root.insert("schema".into(), Value::String(REGISTRY_SCHEMA.into()));
        root.insert(
            "keys".into(),
            Value::Array(self.keys.iter().map(TrustedKey::to_value).collect()),
        );
        let serialized = serde_json::to_vec_pretty(&Value::Object(root))
            .expect("registry must serialize");
        write_atomic(&self.path, &serialized)
    }

    /// Add a key. Idempotent if the same PEM is already stored under the
    /// same `key_id`; errors if a *different* PEM is stored under it.
    pub fn add(&mut self, key: TrustedKey) -> Result<()> {
        for existing in &self.keys {
            if existing.key_id == key.key_id {
                if existing.public_key_pem == key.public_key_pem {
                    return Ok(());
                }
                return Err(ProvenanceError::MalformedKey(format!(
                    "refusing to add: a different public key is already trusted \
                     under key_id {:?}. Untrust it first if this is intentional.",
                    key.key_id
                )));
            }
        }
        self.keys.push(key);
        Ok(())
    }

    pub fn remove(&mut self, key_id: &str) -> bool {
        if let Some(pos) = self.keys.iter().position(|k| k.key_id == key_id) {
            self.keys.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn find(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

/// Build a `TrustedKey` from a public-key PEM file on disk.
pub fn trusted_key_from_pem_file(path: &Path, comment: &str) -> Result<TrustedKey> {
    let vk = load_public_key(path)?;
    TrustedKey::from_public_key(&vk, comment, None)
}

/// Build a `TrustedKey` from the `verifying_key` field of an existing
/// sidecar. Useful for the "trust the signer of this bundle going forward"
/// workflow — the caller is asserting out-of-band confidence in the source.
pub fn trusted_key_from_sidecar_file(sidecar_path: &Path, comment: &str) -> Result<TrustedKey> {
    if !sidecar_path.is_file() {
        return Err(ProvenanceError::KeyNotFound(format!(
            "sidecar file not found: {}",
            sidecar_path.display()
        )));
    }
    let data = std::fs::read(sidecar_path)?;
    let sidecar = Sidecar::from_json_bytes(&data)?;
    let vk = crate::keys::public_key_from_b64(&sidecar.verifying_key)?;
    TrustedKey::from_public_key(&vk, comment, None)
}
