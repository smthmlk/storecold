use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};
use crate::config::{Config, PathSpec, sample_config};
use crate::crypto::KeyMaterial;
use crate::daemon;
use crate::provider::ProviderPool;
use crate::reconcile::{SyncSummary, sync_roots};
use crate::state::{
    Catalog, ResolvedPaths, SharedCatalog, shared_catalog, with_catalog, write_private_file,
};

pub async fn run() -> Result<()> {
    install_tracing();

    let cli = Cli::parse();
    let overrides = PathOverrides::from_cli(&cli);
    match cli.command {
        Command::Init { force } => init_command(force, &overrides),
        Command::Status => status_command(&overrides),
        Command::Sync { path } => sync_command(path.as_deref(), &overrides).await,
        Command::Daemon => daemon_command(&overrides).await,
    }
}

#[derive(Debug, Clone, Default)]
struct PathOverrides {
    config_path: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

impl PathOverrides {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            config_path: cli.config.clone(),
            state_dir: cli.state_dir.clone(),
        }
    }
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn init_command(force: bool, overrides: &PathOverrides) -> Result<()> {
    let paths = ResolvedPaths::discover(
        overrides.config_path.as_deref(),
        overrides.state_dir.as_deref(),
    )?;
    if paths.config_path.exists() && !force {
        bail!(
            "config already exists at {} (use --force to overwrite)",
            paths.config_path.display()
        );
    }

    paths.ensure_dirs()?;
    let config = starter_config(default_host_id()?, overrides.state_dir.as_deref());
    let rendered = serde_yaml::to_string(&config).context("serialize sample config")?;
    write_private_file(&paths.config_path, rendered.as_bytes())?;
    let _ = Catalog::open(&paths)?;

    println!("Initialized storecold");
    println!("config: {}", paths.config_path.display());
    println!("state: {}", paths.state_dir.display());
    println!(
        "passphrase env: {}",
        match config.key_source {
            crate::config::KeySource::Passphrase { ref env_var } => env_var,
            crate::config::KeySource::KeyFile { .. } => "<key-file>",
        }
    );
    Ok(())
}

fn status_command(overrides: &PathOverrides) -> Result<()> {
    let bootstrap_paths = ResolvedPaths::discover(
        overrides.config_path.as_deref(),
        overrides.state_dir.as_deref(),
    )?;
    println!("config: {}", bootstrap_paths.config_path.display());
    println!("config_exists: {}", bootstrap_paths.config_path.exists());

    if !bootstrap_paths.config_path.exists() {
        println!("state: {}", bootstrap_paths.state_dir.display());
        println!("database: {}", bootstrap_paths.database_path.display());
        println!("hint: run `storecold init` to create a starter config");
        return Ok(());
    }

    let config = Config::load(&bootstrap_paths.config_path)?;
    let paths = runtime_paths(&bootstrap_paths.config_path, &config, overrides)?;
    let catalog = Catalog::open(&paths)?;
    println!("state: {}", paths.state_dir.display());
    println!("database: {}", paths.database_path.display());
    println!("host_id: {}", config.host_id);
    println!("repositories: {}", config.repositories.len());
    println!("paths: {}", config.paths.len());
    println!("observed_files: {}", catalog.total_observed_files()?);
    Ok(())
}

async fn sync_command(path_filter: Option<&str>, overrides: &PathOverrides) -> Result<()> {
    let runtime = load_runtime(overrides).await?;
    let roots = select_roots(&runtime.config.paths, path_filter)?;
    let summaries = runtime.sync_selected(&roots).await?;
    print_summaries(&summaries);
    Ok(())
}

async fn daemon_command(overrides: &PathOverrides) -> Result<()> {
    let runtime = load_runtime(overrides).await?;
    daemon::run(runtime).await
}

pub struct Runtime {
    pub paths: ResolvedPaths,
    pub config: Config,
    pub catalog: SharedCatalog,
    pub keys: KeyMaterial,
    pub providers: ProviderPool,
    pub sync_gate: tokio::sync::Mutex<()>,
}

impl Runtime {
    pub async fn sync_selected(&self, roots: &[&PathSpec]) -> Result<Vec<SyncSummary>> {
        let _sync_guard = self.sync_gate.lock().await;
        sync_roots(
            &self.config,
            &self.catalog,
            &self.keys,
            &self.providers,
            roots,
        )
        .await
    }

    pub fn total_observed_files(&self) -> Result<u64> {
        with_catalog(&self.catalog, Catalog::total_observed_files)
    }
}

async fn load_runtime(overrides: &PathOverrides) -> Result<Runtime> {
    let bootstrap_paths = ResolvedPaths::discover(
        overrides.config_path.as_deref(),
        overrides.state_dir.as_deref(),
    )?;
    let config = Config::load(&bootstrap_paths.config_path)?;
    let paths = runtime_paths(&bootstrap_paths.config_path, &config, overrides)?;
    let catalog = Catalog::open(&paths)?;
    let keys = KeyMaterial::load(&config, &paths)?;
    let providers = ProviderPool::from_config(&config).await?;
    Ok(Runtime {
        paths,
        config,
        catalog: shared_catalog(catalog),
        keys,
        providers,
        sync_gate: tokio::sync::Mutex::new(()),
    })
}

fn default_host_id() -> Result<String> {
    Ok(hostname::get()
        .context("read hostname")?
        .to_string_lossy()
        .into_owned())
}

fn starter_config(host_id: String, state_dir_override: Option<&Path>) -> Config {
    let mut config = sample_config(host_id);
    if let Some(state_dir) = state_dir_override {
        config.state_dir = Some(state_dir.to_path_buf());
    }
    config
}

fn runtime_paths(
    config_path: &Path,
    config: &Config,
    overrides: &PathOverrides,
) -> Result<ResolvedPaths> {
    ResolvedPaths::discover(
        Some(config_path),
        overrides
            .state_dir
            .as_deref()
            .or(config.state_dir.as_deref()),
    )
}

fn select_roots<'a>(roots: &'a [PathSpec], path_filter: Option<&str>) -> Result<Vec<&'a PathSpec>> {
    if let Some(filter) = path_filter {
        let requested = Path::new(filter);
        let selected: Vec<_> = roots.iter().filter(|root| root.path == requested).collect();
        if selected.is_empty() {
            bail!("configured path {} was not found", requested.display());
        }
        return Ok(selected);
    }
    Ok(roots.iter().collect())
}

fn print_summaries(summaries: &[SyncSummary]) {
    for summary in summaries {
        println!("root: {}", summary.root.display());
        println!("  files_scanned: {}", summary.files_scanned);
        println!("  changed_files: {}", summary.changed_files);
        println!("  deleted_files: {}", summary.deleted_files);
        println!("  uploaded_files: {}", summary.uploaded_files);
        println!("  reused_files: {}", summary.reused_files);
        println!("  bytes_uploaded: {}", summary.bytes_uploaded);
        println!("  errors: {}", summary.errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_roots_returns_requested_path() {
        let roots = vec![
            PathSpec::new("/tmp/one", "repo-a"),
            PathSpec::new("/tmp/two", "repo-b"),
        ];

        let selected = select_roots(&roots, Some("/tmp/two")).expect("selection succeeds");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, Path::new("/tmp/two"));
    }

    #[test]
    fn starter_config_persists_explicit_state_dir() {
        let config = starter_config(
            "pi4-office".to_string(),
            Some(Path::new("/var/lib/storecold")),
        );

        assert_eq!(config.state_dir, Some(PathBuf::from("/var/lib/storecold")));
    }
}
