use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::random;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::config::{Config, KeySource};
use crate::state::{ResolvedPaths, ensure_private_directory};

type HmacSha512 = Hmac<Sha512>;
const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_LANES: u32 = 2;
const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub nonce_b64: String,
    pub ciphertext: Vec<u8>,
}

pub struct KeyMaterial {
    path_hash_key: Zeroizing<[u8; 64]>,
    manifest_key: Zeroizing<[u8; 32]>,
    content_key: Zeroizing<[u8; 32]>,
}

impl KeyMaterial {
    pub fn load(config: &Config, paths: &ResolvedPaths) -> Result<Self> {
        paths.ensure_dirs()?;
        let secret = load_secret(&config.key_source)?;
        let salt = load_or_create_salt(paths)?;
        let mut master = Zeroizing::new([0u8; 32]);
        key_derivation_hasher()?
            .hash_password_into(secret.as_ref(), &salt, master.as_mut())
            .map_err(|error| anyhow!("derive master key: {error}"))?;

        let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
        let mut path_hash_key = [0u8; 64];
        let mut manifest_key = [0u8; 32];
        let mut content_key = [0u8; 32];
        hkdf.expand(b"storecold/path-hash", &mut path_hash_key)
            .map_err(|error| anyhow!("derive path hash key: {error}"))?;
        hkdf.expand(b"storecold/manifest", &mut manifest_key)
            .map_err(|error| anyhow!("derive manifest key: {error}"))?;
        hkdf.expand(b"storecold/content", &mut content_key)
            .map_err(|error| anyhow!("derive content key: {error}"))?;

        Ok(Self {
            path_hash_key: Zeroizing::new(path_hash_key),
            manifest_key: Zeroizing::new(manifest_key),
            content_key: Zeroizing::new(content_key),
        })
    }

    pub fn path_hash(&self, host_id: &str, path: &str) -> Result<String> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&self.path_hash_key[..])
            .context("construct hmac")?;
        mac.update(host_id.as_bytes());
        mac.update(&[0]);
        mac.update(path.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    pub fn encrypt_manifest(&self, plaintext: &[u8]) -> Result<EncryptedBlob> {
        encrypt_with_key(&self.manifest_key, plaintext)
    }

    pub fn encrypt_content(&self, plaintext: Vec<u8>) -> Result<EncryptedBlob> {
        encrypt_with_key_in_place(&self.content_key, plaintext)
    }
}

fn key_derivation_hasher() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|error| anyhow!("configure argon2 parameters: {error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn encrypt_with_key(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = random::<[u8; 24]>();
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .context("encrypt payload")?;

    Ok(EncryptedBlob {
        nonce_b64: BASE64.encode(nonce),
        ciphertext,
    })
}

fn encrypt_with_key_in_place(
    key_bytes: &[u8; 32],
    mut plaintext: Vec<u8>,
) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = random::<[u8; 24]>();
    cipher
        .encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut plaintext)
        .context("encrypt payload in place")?;

    Ok(EncryptedBlob {
        nonce_b64: BASE64.encode(nonce),
        ciphertext: plaintext,
    })
}

fn load_secret(key_source: &KeySource) -> Result<Zeroizing<Vec<u8>>> {
    match key_source {
        KeySource::Passphrase { env_var } => {
            let value = std::env::var(env_var)
                .with_context(|| format!("environment variable {} is not set", env_var))?;
            if value.is_empty() {
                bail!("environment variable {} must not be empty", env_var);
            }
            Ok(Zeroizing::new(value.into_bytes()))
        }
        KeySource::KeyFile { path } => {
            let bytes =
                fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
            if bytes.is_empty() {
                bail!("key file {} must not be empty", path.display());
            }
            Ok(Zeroizing::new(bytes))
        }
    }
}

fn load_or_create_salt(paths: &ResolvedPaths) -> Result<Vec<u8>> {
    if paths.salt_path.exists() {
        fs::set_permissions(&paths.salt_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", paths.salt_path.display()))?;
        return fs::read(&paths.salt_path)
            .with_context(|| format!("read salt {}", paths.salt_path.display()));
    }

    let salt = random::<[u8; 16]>().to_vec();
    write_new_private_file(&paths.salt_path, &salt)
        .with_context(|| format!("write salt {}", paths.salt_path.display()))?;
    Ok(salt)
}

fn write_new_private_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_directory(parent)?;
    }

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            std::io::Write::write_all(&mut file, contents)
                .with_context(|| format!("write {}", path.display()))?;
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
            let existing =
                fs::read(path).with_context(|| format!("read existing {}", path.display()))?;
            if existing.is_empty() {
                bail!("existing file {} is empty", path.display());
            }
            return Ok(());
        }
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{Config, KeySource, PolicyConfig, Repository, UploadConfig};

    #[test]
    fn path_hash_is_stable() {
        let temp = tempdir().expect("temp dir");
        let key_path = temp.path().join("key.txt");
        fs::write(&key_path, b"secret").expect("write key file");
        let paths = ResolvedPaths {
            config_path: temp.path().join("config.yaml"),
            state_dir: temp.path().join("state"),
            spool_dir: temp.path().join("state/spool"),
            salt_path: temp.path().join("state/master_key.salt"),
            database_path: temp.path().join("state/catalog.db"),
        };

        let config = Config {
            version: 1,
            host_id: "host".to_string(),
            state_dir: None,
            key_source: KeySource::KeyFile { path: key_path },
            repositories: vec![Repository {
                name: "r".to_string(),
                backend: crate::config::Backend::S3 {
                    data_bucket: "a".to_string(),
                    data_prefix: "b".to_string(),
                    region: "us-west-2".to_string(),
                    storage_class: "STANDARD".to_string(),
                    index_bucket: "c".to_string(),
                    index_prefix: "d".to_string(),
                    index_storage_class: "STANDARD".to_string(),
                    endpoint: None,
                },
            }],
            paths: vec![],
            upload: UploadConfig {
                batch_target_mib: 64,
                batch_max_delay_sec: 10,
                max_concurrent_uploads: 1,
                max_upload_mib_per_sec: 5,
                max_puts_per_minute: 30,
                max_local_spool_gib: 1,
            },
            policy: PolicyConfig {
                rescan_interval: "1h".to_string(),
                on_content_change: "warn_and_keep_both".to_string(),
                follow_symlinks: false,
                one_file_system: true,
                retain_deleted_versions_days: 1,
            },
        };

        let keys = KeyMaterial::load(&config, &paths).expect("keys");
        let first = keys
            .path_hash("host", "/srv/archive/file.txt")
            .expect("hash");
        let second = keys
            .path_hash("host", "/srv/archive/file.txt")
            .expect("hash");
        assert_eq!(first, second);
        assert_eq!(keys.path_hash_key.len(), 64);

        let salt_mode = fs::metadata(&paths.salt_path)
            .expect("salt metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(salt_mode, 0o600);
    }

    #[test]
    fn key_derivation_uses_explicit_harder_parameters() {
        let hasher = key_derivation_hasher().expect("argon2 configuration");
        let params = hasher.params();

        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
        assert_eq!(params.t_cost(), ARGON2_ITERATIONS);
        assert_eq!(params.p_cost(), ARGON2_LANES);
        assert_eq!(params.output_len(), Some(MASTER_KEY_LEN));
    }
}
