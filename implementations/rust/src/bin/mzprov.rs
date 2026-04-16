//! `mzprov` CLI: verify, sign, and generate keys.
//!
//! Exit codes follow `spec/trust-model.md`: 0 OK, 1 generic, 2 key error,
//! 3 sidecar error, 4 unsigned, 5 hash mismatch, 6 signature mismatch,
//! 7 key not trusted.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mzprov::envelope::AttestationType;
use mzprov::errors::ProvenanceError;
use mzprov::exit_codes::{
    EXIT_GENERIC, EXIT_HASH_MISMATCH, EXIT_KEY_ERROR, EXIT_KEY_NOT_TRUSTED, EXIT_OK,
    EXIT_SIDECAR_ERROR, EXIT_SIGNATURE_MISMATCH, EXIT_UNSIGNED,
};
use mzprov::keys::{generate_keypair, load_private_key, write_keypair};
use mzprov::sign::{sign_d, sign_mzml};
use mzprov::trust::{
    trusted_key_from_pem_file, trusted_key_from_sidecar_file, TrustedKeyRegistry,
};
use mzprov::verify::{
    verify_sidecar_with, CheckStatus, TrustOptions, TrustStatus,
};

#[derive(Parser, Debug)]
#[command(name = "mzprov", version, about = "mzprov v0 (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Verify a provenance sidecar (or a `.d` / mzML / experiment dir).
    Verify {
        /// Path to a sidecar, a .d directory, an mzML file, or a directory
        /// containing one of those.
        path: PathBuf,
        /// Treat "unsigned" (no sidecar found) as a failure.
        #[arg(long)]
        strict: bool,
        /// Require the signing key id to equal this string.
        #[arg(long)]
        expected_key_id: Option<String>,
        /// Require the signing key to be in the trusted-keys registry.
        #[arg(long)]
        require_trusted: bool,
        /// Override the trusted-keys registry path.
        #[arg(long)]
        trust_registry: Option<PathBuf>,
    },
    /// Sign a `.d` directory or an mzML file.
    Sign {
        /// Input: a `.d` directory or an `.mzML` file.
        path: PathBuf,
        /// Free-form label recorded in the signed payload.
        #[arg(long)]
        experiment_name: String,
        /// Config file whose bytes are bound to the signature. REQUIRED
        /// for `.d`; OPTIONAL for mzML (defaults to sha256(b"")).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional ground-truth SQLite DB (`.d` only).
        #[arg(long)]
        ground_truth: Option<PathBuf>,
        /// Producing-tool name (simulator_name for .d, tool_name for mzML).
        #[arg(long, default_value = "mzprov")]
        tool_name: String,
        /// Producing-tool version.
        #[arg(long, default_value = "unknown")]
        tool_version: String,
        /// Path to an Ed25519 PKCS#8 PEM private key.
        #[arg(long)]
        key: PathBuf,
        /// Override the sidecar output path. Mutually exclusive with --embed.
        #[arg(long)]
        sidecar: Option<PathBuf>,
        /// Embed the sidecar envelope inside the artifact instead of
        /// writing a JSON file. For .d, the envelope is stored in
        /// analysis.tdf as a row in the mzprov_provenance table (see
        /// spec/embedded-d-v0.md). The .d's content hash is unchanged
        /// — the table is excluded from canonicalization.
        #[arg(long)]
        embed: bool,
    },
    /// Key management.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCmd {
    /// Generate a fresh Ed25519 keypair. Writes `signing_key.pem`,
    /// `verifying_key.pem`, and `key_id` to the target directory.
    Generate {
        /// Directory to write the keypair into. Created if missing.
        #[arg(long, default_value = "./keys")]
        out: PathBuf,
        /// Refuse to overwrite an existing signing_key.pem.
        #[arg(long)]
        no_overwrite: bool,
    },
    /// Add a key to the trusted-keys registry.
    Trust {
        /// Path to a PEM public key OR an existing `.provenance.json` sidecar.
        source: PathBuf,
        /// Free-form note recorded with the entry.
        #[arg(long, default_value = "")]
        comment: String,
        /// Override the trusted-keys registry path.
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Remove a key from the trusted-keys registry.
    Untrust {
        /// The key id to remove (e.g. `timsim-local-...`).
        key_id: String,
        /// Override the trusted-keys registry path.
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// List keys in the trusted-keys registry.
    List {
        /// Override the trusted-keys registry path.
        #[arg(long)]
        registry: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Verify {
            path,
            strict,
            expected_key_id,
            require_trusted,
            trust_registry,
        } => run_verify(
            &path,
            strict,
            TrustOptions {
                expected_key_id,
                require_trusted,
                trusted_registry_path: trust_registry,
            },
        ),
        Cmd::Sign {
            path,
            experiment_name,
            config,
            ground_truth,
            tool_name,
            tool_version,
            key,
            sidecar,
            embed,
        } => run_sign(
            &path,
            &experiment_name,
            config.as_deref(),
            ground_truth.as_deref(),
            &tool_name,
            &tool_version,
            &key,
            sidecar.as_deref(),
            embed,
        ),
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::Generate { out, no_overwrite } => run_keys_generate(&out, no_overwrite),
            KeysCmd::Trust {
                source,
                comment,
                registry,
            } => run_keys_trust(&source, &comment, registry.as_deref()),
            KeysCmd::Untrust { key_id, registry } => {
                run_keys_untrust(&key_id, registry.as_deref())
            }
            KeysCmd::List { registry } => run_keys_list(registry.as_deref()),
        },
    };
    std::process::exit(code);
}

fn run_verify(path: &std::path::Path, _strict: bool, trust_opts: TrustOptions) -> i32 {
    // Discovery itself can fail with structural errors (e.g.
    // SqliteNotQuiescent on a .tdf with a stale -wal). Per
    // spec/embedded-d-v0.md §6.2 these MUST propagate as
    // SIDECAR_ERROR — silently falling back to a sibling JSON
    // sidecar would mask a broken embed.
    let discovery = match mzprov::verify::find_provenance_for(path) {
        Ok(d) => d,
        Err(e) => return provenance_error_to_exit(&e),
    };
    let verify_result = match discovery {
        Some(mzprov::verify::Discovery::EmbeddedD(d)) => {
            mzprov::verify::verify_embedded_d(&d, &trust_opts)
        }
        Some(mzprov::verify::Discovery::EmbeddedMzml(m)) => {
            mzprov::verify::verify_embedded_mzml(&m, &trust_opts)
        }
        Some(mzprov::verify::Discovery::SidecarJson(p)) => {
            verify_sidecar_with(&p, &trust_opts)
        }
        None => {
            eprintln!("mzprov verify: no sidecar found for {}", path.display());
            return EXIT_UNSIGNED;
        }
    };

    match verify_result {
        Ok(result) => {
            let type_str = match result.type_tag {
                AttestationType::D => "d",
                AttestationType::Mzml => "mzml",
            };
            println!(
                "sidecar:    {}\ntype:       {}\nkey_id:     {}",
                result.sidecar_path.display(),
                type_str,
                result.derived_key_id
            );
            for c in &result.checks {
                let label = match c.status {
                    CheckStatus::Ok => "OK",
                    CheckStatus::Mismatch => "MISMATCH",
                    CheckStatus::Unchecked => "UNCHECKED",
                };
                println!("  {:<18} {}", c.name, label);
                if !c.detail.is_empty() {
                    println!("    ({})", c.detail);
                }
            }
            println!(
                "signature:  {}",
                if result.signature_ok { "OK" } else { "MISMATCH" }
            );
            if result.trust.was_requested() {
                let label = match result.trust.status {
                    TrustStatus::Ok => "TRUSTED",
                    TrustStatus::IdMismatch => "KEY_ID_MISMATCH",
                    TrustStatus::NotInRegistry => "NOT_IN_REGISTRY",
                    TrustStatus::RegistryPemMismatch => "REGISTRY_PEM_MISMATCH",
                    TrustStatus::NotRequested => unreachable!(),
                };
                println!("trust:      {}", label);
                if !result.trust.detail.is_empty() {
                    println!("    ({})", result.trust.detail);
                }
            }

            if result.overall_ok {
                println!("result:     VERIFIED");
                return EXIT_OK;
            }
            if !result.trust.ok() {
                println!("result:     TRUST NOT SATISFIED");
                return EXIT_KEY_NOT_TRUSTED;
            }
            if result.any_mismatch() {
                println!("result:     HASH MISMATCH");
                return EXIT_HASH_MISMATCH;
            }
            if !result.signature_ok {
                println!("result:     SIGNATURE MISMATCH");
                return EXIT_SIGNATURE_MISMATCH;
            }
            println!("result:     FAILED");
            EXIT_GENERIC
        }
        Err(e) => provenance_error_to_exit(&e),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_sign(
    path: &std::path::Path,
    experiment_name: &str,
    config: Option<&std::path::Path>,
    ground_truth: Option<&std::path::Path>,
    tool_name: &str,
    tool_version: &str,
    key_path: &std::path::Path,
    sidecar_override: Option<&std::path::Path>,
    embed: bool,
) -> i32 {
    if embed && sidecar_override.is_some() {
        eprintln!("mzprov sign: --embed and --sidecar are mutually exclusive");
        return EXIT_GENERIC;
    }
    let signing_key = match load_private_key(key_path) {
        Ok(k) => k,
        Err(e) => return provenance_error_to_exit(&e),
    };

    let is_d = path.is_dir() && path.extension().and_then(|s| s.to_str()) == Some("d");
    let is_mzml = path.is_file()
        && path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("mzml"))
            .unwrap_or(false);

    let result = if is_d {
        let config_path = match config {
            Some(c) => c,
            None => {
                eprintln!(
                    "mzprov sign: --config is required when signing a .d directory"
                );
                return EXIT_GENERIC;
            }
        };
        sign_d(
            path,
            ground_truth,
            config_path,
            experiment_name,
            tool_name,
            tool_version,
            sidecar_override,
            &signing_key,
            embed,
        )
    } else if is_mzml {
        sign_mzml(
            path,
            config,
            experiment_name,
            tool_name,
            tool_version,
            sidecar_override,
            &signing_key,
            embed,
        )
    } else {
        eprintln!(
            "mzprov sign: {} is neither a .d directory nor an mzML file",
            path.display()
        );
        return EXIT_SIDECAR_ERROR;
    };

    match result {
        Ok(sidecar_path) => {
            println!("signed: {}", sidecar_path.display());
            EXIT_OK
        }
        Err(e) => provenance_error_to_exit(&e),
    }
}

fn run_keys_generate(out: &std::path::Path, no_overwrite: bool) -> i32 {
    if no_overwrite && out.join("signing_key.pem").exists() {
        eprintln!(
            "mzprov keys generate: refusing to overwrite existing signing key at {}",
            out.join("signing_key.pem").display()
        );
        return EXIT_GENERIC;
    }
    let gen = match generate_keypair() {
        Ok(g) => g,
        Err(e) => return provenance_error_to_exit(&e),
    };
    if let Err(e) = write_keypair(&gen, out) {
        return provenance_error_to_exit(&e);
    }
    println!("key_id:       {}", gen.key_id);
    println!("signing_key:  {}", out.join("signing_key.pem").display());
    println!("verifying_key: {}", out.join("verifying_key.pem").display());
    EXIT_OK
}

fn run_keys_trust(source: &std::path::Path, comment: &str, registry: Option<&std::path::Path>) -> i32 {
    let key = if source.is_file()
        && source
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.ends_with(".provenance.json"))
            .unwrap_or(false)
    {
        match trusted_key_from_sidecar_file(source, comment) {
            Ok(k) => k,
            Err(e) => return provenance_error_to_exit(&e),
        }
    } else {
        match trusted_key_from_pem_file(source, comment) {
            Ok(k) => k,
            Err(e) => return provenance_error_to_exit(&e),
        }
    };

    let mut reg = match TrustedKeyRegistry::load(registry) {
        Ok(r) => r,
        Err(e) => return provenance_error_to_exit(&e),
    };
    if let Err(e) = reg.add(key.clone()) {
        return provenance_error_to_exit(&e);
    }
    if let Err(e) = reg.save() {
        return provenance_error_to_exit(&e);
    }
    println!("trusted:  {}", key.key_id);
    println!("registry: {}", reg.path.display());
    EXIT_OK
}

fn run_keys_untrust(key_id: &str, registry: Option<&std::path::Path>) -> i32 {
    let mut reg = match TrustedKeyRegistry::load(registry) {
        Ok(r) => r,
        Err(e) => return provenance_error_to_exit(&e),
    };
    if !reg.remove(key_id) {
        eprintln!("mzprov keys untrust: no such key_id in registry: {key_id}");
        return EXIT_GENERIC;
    }
    if let Err(e) = reg.save() {
        return provenance_error_to_exit(&e);
    }
    println!("untrusted: {}", key_id);
    EXIT_OK
}

fn run_keys_list(registry: Option<&std::path::Path>) -> i32 {
    let reg = match TrustedKeyRegistry::load(registry) {
        Ok(r) => r,
        Err(e) => return provenance_error_to_exit(&e),
    };
    if reg.keys.is_empty() {
        println!("(no trusted keys in {})", reg.path.display());
        return EXIT_OK;
    }
    println!("registry: {}", reg.path.display());
    for k in &reg.keys {
        println!("  {}  {}  {}", k.key_id, k.added_at, k.comment);
    }
    EXIT_OK
}

fn provenance_error_to_exit(e: &ProvenanceError) -> i32 {
    eprintln!("mzprov: {e}");
    match e {
        ProvenanceError::KeyNotFound(_) | ProvenanceError::MalformedKey(_) => EXIT_KEY_ERROR,
        ProvenanceError::MalformedSidecar(_)
        | ProvenanceError::UnknownVersion(_)
        | ProvenanceError::UnknownAlgorithm(_)
        | ProvenanceError::MissingArtifact(_)
        | ProvenanceError::SqliteNotQuiescent { .. }
        | ProvenanceError::Canonicalization(_) => EXIT_SIDECAR_ERROR,
        ProvenanceError::Io(_) => EXIT_GENERIC,
    }
}
