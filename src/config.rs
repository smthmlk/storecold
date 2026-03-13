use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use humantime::parse_duration;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub host_id: String,
    pub state_dir: Option<PathBuf>,
    pub key_source: KeySource,
    pub repositories: Vec<Repository>,
    pub paths: Vec<PathSpec>,
    pub upload: UploadConfig,
    pub policy: PolicyConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if config_permissions_too_open(path)? {
            let mode = fs::metadata(path)
                .with_context(|| format!("inspect config {}", path.display()))?
                .permissions()
                .mode()
                & 0o777;
            warn!(
                path = %path.display(),
                mode = format_args!("{mode:o}"),
                "config file is group/world-readable; restrict it to mode 0600"
            );
        }
        let contents =
            fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
        let config: Self =
            serde_yaml::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported config version {}", self.version);
        }

        if self.host_id.trim().is_empty() {
            bail!("host_id must not be empty");
        }

        if self.repositories.is_empty() {
            bail!("at least one repository must be configured");
        }

        if self.paths.is_empty() {
            bail!("at least one path must be configured");
        }

        let mut repo_names = HashSet::new();
        for repository in &self.repositories {
            if !repo_names.insert(repository.name.as_str()) {
                bail!("duplicate repository name {}", repository.name);
            }
        }

        for path in &self.paths {
            if !path.path.is_absolute() {
                bail!("configured path {} must be absolute", path.path.display());
            }

            if !repo_names.contains(path.repository.as_str()) {
                bail!(
                    "path {} references unknown repository {}",
                    path.path.display(),
                    path.repository
                );
            }
        }

        self.upload.validate()?;
        self.policy.validate()?;
        Ok(())
    }

    pub fn repository(&self, name: &str) -> Result<&Repository> {
        self.repositories
            .iter()
            .find(|repo| repo.name == name)
            .with_context(|| format!("unknown repository {}", name))
    }
}

fn config_permissions_too_open(path: &Path) -> Result<bool> {
    let mode = fs::metadata(path)
        .with_context(|| format!("inspect config {}", path.display()))?
        .permissions()
        .mode();
    Ok(mode & 0o077 != 0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    #[serde(flatten)]
    pub backend: Backend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Backend {
    S3 {
        data_bucket: String,
        data_prefix: String,
        region: String,
        storage_class: String,
        index_bucket: String,
        index_prefix: String,
        index_storage_class: String,
        #[serde(default)]
        endpoint: Option<String>,
    },
    AzureBlob {
        account: String,
        auth: AzureAuth,
        data_container: String,
        data_prefix: String,
        access_tier: String,
        index_container: String,
        index_prefix: String,
        index_access_tier: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AzureAuth {
    AccessKeyEnv {
        env_var: String,
    },
    ConnectionStringEnv {
        env_var: String,
    },
    DeveloperTools,
    ManagedIdentity {
        #[serde(default)]
        client_id_env_var: Option<String>,
    },
    ClientSecretEnv {
        tenant_id_env_var: String,
        client_id_env_var: String,
        client_secret_env_var: String,
    },
    SasUrlEnv {
        env_var: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeySource {
    Passphrase { env_var: String },
    KeyFile { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSpec {
    pub path: PathBuf,
    pub repository: String,
    #[serde(default)]
    pub excludes: Vec<String>,
}

impl PathSpec {
    #[cfg(test)]
    pub fn new(path: impl Into<PathBuf>, repository: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            repository: repository.into(),
            excludes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadConfig {
    pub batch_target_mib: u32,
    pub batch_max_delay_sec: u32,
    pub max_concurrent_uploads: usize,
    pub max_upload_mib_per_sec: u32,
    pub max_puts_per_minute: u32,
    pub max_local_spool_gib: u32,
}

impl UploadConfig {
    pub fn validate(&self) -> Result<()> {
        if self.batch_target_mib == 0 {
            bail!("upload.batch_target_mib must be greater than zero");
        }
        if self.max_concurrent_uploads == 0 {
            bail!("upload.max_concurrent_uploads must be greater than zero");
        }
        Ok(())
    }

    pub fn batch_target_bytes(&self) -> u64 {
        self.batch_target_mib as u64 * 1024 * 1024
    }

    pub fn rate_limit_bytes_per_sec(&self) -> u64 {
        self.max_upload_mib_per_sec as u64 * 1024 * 1024
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub rescan_interval: String,
    pub on_content_change: String,
    pub follow_symlinks: bool,
    pub one_file_system: bool,
    pub retain_deleted_versions_days: u32,
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<()> {
        if self.on_content_change != "warn_and_keep_both" {
            bail!("policy.on_content_change must be warn_and_keep_both");
        }

        self.rescan_interval_duration()?;
        Ok(())
    }

    pub fn rescan_interval_duration(&self) -> Result<Duration> {
        parse_duration(&self.rescan_interval)
            .with_context(|| format!("invalid rescan interval {}", self.rescan_interval))
    }
}

pub fn sample_config(host_id: String) -> Config {
    Config {
        version: 1,
        host_id,
        state_dir: None,
        key_source: KeySource::Passphrase {
            env_var: "STORECOLD_PASSPHRASE".to_string(),
        },
        repositories: vec![
            Repository {
                name: "cold-s3".to_string(),
                backend: Backend::S3 {
                    data_bucket: "replace-me-data".to_string(),
                    data_prefix: "data/".to_string(),
                    region: "us-west-2".to_string(),
                    storage_class: "DEEP_ARCHIVE".to_string(),
                    index_bucket: "replace-me-index".to_string(),
                    index_prefix: "index/".to_string(),
                    index_storage_class: "STANDARD".to_string(),
                    endpoint: None,
                },
            },
            Repository {
                name: "cold-azure".to_string(),
                backend: Backend::AzureBlob {
                    account: "replace-me".to_string(),
                    auth: AzureAuth::DeveloperTools,
                    data_container: "backup-data".to_string(),
                    data_prefix: "data/".to_string(),
                    access_tier: "Archive".to_string(),
                    index_container: "backup-index".to_string(),
                    index_prefix: "index/".to_string(),
                    index_access_tier: "Hot".to_string(),
                },
            },
        ],
        paths: vec![PathSpec {
            path: PathBuf::from("/srv/archive"),
            repository: "cold-s3".to_string(),
            excludes: vec!["**/.cache/**".to_string(), "**/*.tmp".to_string()],
        }],
        upload: UploadConfig {
            batch_target_mib: 64,
            batch_max_delay_sec: 120,
            max_concurrent_uploads: 2,
            max_upload_mib_per_sec: 5,
            max_puts_per_minute: 30,
            max_local_spool_gib: 20,
        },
        policy: PolicyConfig {
            rescan_interval: "6h".to_string(),
            on_content_change: "warn_and_keep_both".to_string(),
            follow_symlinks: false,
            one_file_system: true,
            retain_deleted_versions_days: 365,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn sample_config_is_valid() {
        sample_config("pi4-office".to_string())
            .validate()
            .expect("sample config validates");
    }

    #[test]
    fn unknown_repository_is_rejected() {
        let mut config = sample_config("pi4-office".to_string());
        config.paths[0].repository = "missing".to_string();

        let error = config.validate().expect_err("config should fail");
        assert!(error.to_string().contains("unknown repository"));
    }

    #[test]
    fn config_permission_check_detects_world_readable_files() {
        let dir = tempdir().expect("temp dir");
        let config_path = dir.path().join("storecold.yaml");
        fs::write(&config_path, "version: 1\n").expect("write config");
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).expect("chmod config");

        assert!(config_permissions_too_open(&config_path).expect("permission check"));
    }
}
