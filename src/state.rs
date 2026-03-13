use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use dirs::home_dir;
use rusqlite::{Connection, OptionalExtension, params};

const EXPECTED_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub spool_dir: PathBuf,
    pub salt_path: PathBuf,
    pub database_path: PathBuf,
}

impl ResolvedPaths {
    pub fn discover(
        config_path_override: Option<&Path>,
        state_dir_override: Option<&Path>,
    ) -> Result<Self> {
        let home = home_dir().context("resolve home directory")?;
        let config_path = config_path_override
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.join(".storecold.yaml"));
        let state_dir = state_dir_override
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.join(".local/state/storecold"));
        let spool_dir = state_dir.join("spool");
        let salt_path = state_dir.join("master_key.salt");
        let database_path = state_dir.join("catalog.db");

        Ok(Self {
            config_path,
            state_dir,
            spool_dir,
            salt_path,
            database_path,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        ensure_private_directory(&self.state_dir)
            .with_context(|| format!("create state directory {}", self.state_dir.display()))?;
        ensure_private_directory(&self.spool_dir)
            .with_context(|| format!("create spool directory {}", self.spool_dir.display()))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ObservedFile {
    pub path: String,
    pub path_hash: String,
    pub repository: String,
    pub dev: i64,
    pub inode: i64,
    pub size: i64,
    pub mtime_ns: i64,
    pub current_sha512: Option<String>,
    pub deleted: bool,
    pub last_seen_at: String,
}

#[derive(Debug, Clone)]
pub struct VersionRecord {
    pub version_id: String,
    pub path_hash: String,
    pub path: String,
    pub repository: String,
    pub sha512: Option<String>,
    pub created_at: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ContentRef {
    pub repository: String,
    pub sha512: String,
    pub object_key: String,
    pub ciphertext_offset: i64,
    pub cipher_len: i64,
    pub plain_len: i64,
    pub nonce_b64: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct SyncRunRecord {
    pub root_path: String,
    pub files_scanned: u64,
    pub changed_files: u64,
    pub deleted_files: u64,
    pub uploaded_files: u64,
    pub reused_files: u64,
    pub bytes_uploaded: u64,
    pub errors: u64,
}

pub struct Catalog {
    connection: Connection,
}

pub type SharedCatalog = Arc<Mutex<Catalog>>;

pub fn shared_catalog(catalog: Catalog) -> SharedCatalog {
    Arc::new(Mutex::new(catalog))
}

pub fn with_catalog<T>(
    catalog: &SharedCatalog,
    operation: impl FnOnce(&Catalog) -> Result<T>,
) -> Result<T> {
    let guard = catalog
        .lock()
        .map_err(|_| anyhow!("catalog mutex poisoned"))?;
    operation(&guard)
}

impl Catalog {
    pub fn open(paths: &ResolvedPaths) -> Result<Self> {
        paths.ensure_dirs()?;
        ensure_private_file(&paths.database_path)
            .with_context(|| format!("prepare database {}", paths.database_path.display()))?;
        let connection = Connection::open(&paths.database_path)
            .with_context(|| format!("open database {}", paths.database_path.display()))?;
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observed_files (
                path TEXT PRIMARY KEY,
                path_hash TEXT NOT NULL,
                repository TEXT NOT NULL,
                dev INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                current_sha512 TEXT,
                deleted INTEGER NOT NULL DEFAULT 0,
                last_seen_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS observed_files_path_hash_idx
                ON observed_files(path_hash);
            CREATE INDEX IF NOT EXISTS observed_files_root_idx
                ON observed_files(repository, path);

            CREATE TABLE IF NOT EXISTS versions (
                version_id TEXT PRIMARY KEY,
                path_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                repository TEXT NOT NULL,
                sha512 TEXT,
                created_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS versions_path_hash_idx
                ON versions(path_hash, created_at);

            CREATE TABLE IF NOT EXISTS content_refs (
                repository TEXT NOT NULL,
                sha512 TEXT NOT NULL,
                object_key TEXT NOT NULL,
                entry_offset INTEGER NOT NULL,
                cipher_len INTEGER NOT NULL,
                plain_len INTEGER NOT NULL,
                nonce_b64 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (repository, sha512)
            );

            CREATE TABLE IF NOT EXISTS sync_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_path TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                changed_files INTEGER NOT NULL,
                deleted_files INTEGER NOT NULL,
                uploaded_files INTEGER NOT NULL,
                reused_files INTEGER NOT NULL,
                bytes_uploaded INTEGER NOT NULL,
                errors INTEGER NOT NULL,
                synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            ",
        )?;
        ensure_schema_version(&connection)?;

        Ok(Self { connection })
    }

    pub fn observed_file(&self, path: &str) -> Result<Option<ObservedFile>> {
        self.connection
            .query_row(
                "
                SELECT path, path_hash, repository, dev, inode, size, mtime_ns, current_sha512, deleted, last_seen_at
                FROM observed_files
                WHERE path = ?1
                ",
                [path],
                row_to_observed_file,
            )
            .optional()
            .context("query observed file")
    }

    pub fn upsert_observed_file(&self, file: &ObservedFile) -> Result<()> {
        self.connection.execute(
            "
            INSERT INTO observed_files (
                path, path_hash, repository, dev, inode, size, mtime_ns, current_sha512, deleted, last_seen_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(path) DO UPDATE SET
                path_hash = excluded.path_hash,
                repository = excluded.repository,
                dev = excluded.dev,
                inode = excluded.inode,
                size = excluded.size,
                mtime_ns = excluded.mtime_ns,
                current_sha512 = excluded.current_sha512,
                deleted = excluded.deleted,
                last_seen_at = excluded.last_seen_at
            ",
            params![
                file.path,
                file.path_hash,
                file.repository,
                file.dev,
                file.inode,
                file.size,
                file.mtime_ns,
                file.current_sha512,
                if file.deleted { 1 } else { 0 },
                file.last_seen_at,
            ],
        )?;
        Ok(())
    }

    pub fn active_paths_under_root(
        &self,
        repository: &str,
        root: &Path,
    ) -> Result<Vec<ObservedFile>> {
        let root_text = root.display().to_string();
        let prefix = format!("{root_text}/%");
        let mut statement = self.connection.prepare(
            "
            SELECT path, path_hash, repository, dev, inode, size, mtime_ns, current_sha512, deleted, last_seen_at
            FROM observed_files
            WHERE repository = ?1 AND deleted = 0 AND (path = ?2 OR path LIKE ?3)
            ",
        )?;

        let rows = statement
            .query_map(params![repository, root_text, prefix], row_to_observed_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn insert_version(&self, version: &VersionRecord) -> Result<()> {
        self.connection.execute(
            "
            INSERT INTO versions (version_id, path_hash, path, repository, sha512, created_at, reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                version.version_id,
                version.path_hash,
                version.path,
                version.repository,
                version.sha512,
                version.created_at,
                version.reason,
            ],
        )?;
        Ok(())
    }

    pub fn versions_for_path_hash(&self, path_hash: &str) -> Result<Vec<VersionRecord>> {
        let mut statement = self.connection.prepare(
            "
            SELECT version_id, path_hash, path, repository, sha512, created_at, reason
            FROM versions
            WHERE path_hash = ?1
            ORDER BY created_at ASC, version_id ASC
            ",
        )?;
        let rows = statement
            .query_map([path_hash], |row| {
                Ok(VersionRecord {
                    version_id: row.get(0)?,
                    path_hash: row.get(1)?,
                    path: row.get(2)?,
                    repository: row.get(3)?,
                    sha512: row.get(4)?,
                    created_at: row.get(5)?,
                    reason: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn latest_observed_by_path_hash(&self, path_hash: &str) -> Result<Option<ObservedFile>> {
        self.connection
            .query_row(
                "
                SELECT path, path_hash, repository, dev, inode, size, mtime_ns, current_sha512, deleted, last_seen_at
                FROM observed_files
                WHERE path_hash = ?1
                LIMIT 1
                ",
                [path_hash],
                row_to_observed_file,
            )
            .optional()
            .context("query path state")
    }

    pub fn content_ref(&self, repository: &str, sha512: &str) -> Result<Option<ContentRef>> {
        self.connection
            .query_row(
                "
                SELECT repository, sha512, object_key, entry_offset, cipher_len, plain_len, nonce_b64, created_at
                FROM content_refs
                WHERE repository = ?1 AND sha512 = ?2
                ",
                params![repository, sha512],
                |row| {
                    Ok(ContentRef {
                        repository: row.get(0)?,
                        sha512: row.get(1)?,
                        object_key: row.get(2)?,
                        ciphertext_offset: row.get(3)?,
                        cipher_len: row.get(4)?,
                        plain_len: row.get(5)?,
                        nonce_b64: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .context("query content ref")
    }

    pub fn save_content_ref(&self, content_ref: &ContentRef) -> Result<()> {
        self.connection.execute(
            "
            INSERT OR REPLACE INTO content_refs (
                repository, sha512, object_key, entry_offset, cipher_len, plain_len, nonce_b64, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ",
            params![
                content_ref.repository,
                content_ref.sha512,
                content_ref.object_key,
                content_ref.ciphertext_offset,
                content_ref.cipher_len,
                content_ref.plain_len,
                content_ref.nonce_b64,
                content_ref.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn record_sync_run(&self, record: &SyncRunRecord) -> Result<()> {
        self.connection.execute(
            "
            INSERT INTO sync_runs (
                root_path, files_scanned, changed_files, deleted_files, uploaded_files, reused_files, bytes_uploaded, errors
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ",
            params![
                record.root_path,
                record.files_scanned,
                record.changed_files,
                record.deleted_files,
                record.uploaded_files,
                record.reused_files,
                record.bytes_uploaded,
                record.errors,
            ],
        )?;
        Ok(())
    }

    pub fn total_observed_files(&self) -> Result<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM observed_files WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count).context("observed file count cannot be negative")
    }
}

fn ensure_schema_version(connection: &Connection) -> Result<()> {
    let version = connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .context("query schema version")?;

    match version {
        Some(value) => {
            let parsed = value
                .parse::<i64>()
                .with_context(|| format!("parse schema version {}", value))?;
            if parsed != EXPECTED_SCHEMA_VERSION {
                return Err(anyhow!(
                    "unsupported schema version {}; expected {}",
                    parsed,
                    EXPECTED_SCHEMA_VERSION
                ));
            }
        }
        None => {
            connection
                .execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
                    [EXPECTED_SCHEMA_VERSION.to_string()],
                )
                .context("initialize schema version")?;
        }
    }

    Ok(())
}

fn row_to_observed_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservedFile> {
    Ok(ObservedFile {
        path: row.get(0)?,
        path_hash: row.get(1)?,
        repository: row.get(2)?,
        dev: row.get(3)?,
        inode: row.get(4)?,
        size: row.get(5)?,
        mtime_ns: row.get(6)?,
        current_sha512: row.get(7)?,
        deleted: row.get::<_, i64>(8)? != 0,
        last_seen_at: row.get(9)?,
    })
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create directory {}", path.display()));
        }
    }

    fs::set_permissions(path, Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))?;
    Ok(())
}

pub(crate) fn ensure_private_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_directory(parent)?;
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;

    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_directory(parent)?;
    }

    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, contents))
        .with_context(|| format!("write {}", path.display()))?;

    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn catalog_persists_content_refs() {
        let dir = tempdir().expect("temp dir");
        let paths = ResolvedPaths {
            config_path: dir.path().join("config.yaml"),
            state_dir: dir.path().join("state"),
            spool_dir: dir.path().join("state/spool"),
            salt_path: dir.path().join("state/master_key.salt"),
            database_path: dir.path().join("state/catalog.db"),
        };

        let catalog = Catalog::open(&paths).expect("open catalog");
        let content_ref = ContentRef {
            repository: "cold-s3".to_string(),
            sha512: "abc".to_string(),
            object_key: "data/packs/one.pack".to_string(),
            ciphertext_offset: 12,
            cipher_len: 34,
            plain_len: 30,
            nonce_b64: "nonce".to_string(),
            created_at: "2026-03-12T19:00:00Z".to_string(),
        };

        catalog.save_content_ref(&content_ref).expect("save");
        let loaded = catalog
            .content_ref("cold-s3", "abc")
            .expect("load")
            .expect("present");

        assert_eq!(loaded.object_key, "data/packs/one.pack");
        assert_eq!(loaded.cipher_len, 34);
    }

    #[test]
    fn ensure_dirs_uses_private_permissions() {
        let dir = tempdir().expect("temp dir");
        let paths = ResolvedPaths {
            config_path: dir.path().join("config.yaml"),
            state_dir: dir.path().join("state"),
            spool_dir: dir.path().join("state/spool"),
            salt_path: dir.path().join("state/master_key.salt"),
            database_path: dir.path().join("state/catalog.db"),
        };

        paths.ensure_dirs().expect("create dirs");

        let state_mode = fs::metadata(&paths.state_dir)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777;
        let spool_mode = fs::metadata(&paths.spool_dir)
            .expect("spool metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(state_mode, 0o700);
        assert_eq!(spool_mode, 0o700);
    }

    #[test]
    fn catalog_rejects_unknown_schema_version() {
        let dir = tempdir().expect("temp dir");
        let paths = ResolvedPaths {
            config_path: dir.path().join("config.yaml"),
            state_dir: dir.path().join("state"),
            spool_dir: dir.path().join("state/spool"),
            salt_path: dir.path().join("state/master_key.salt"),
            database_path: dir.path().join("state/catalog.db"),
        };

        let catalog = Catalog::open(&paths).expect("open catalog");
        drop(catalog);

        let connection = Connection::open(&paths.database_path).expect("reopen database");
        connection
            .execute(
                "UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'",
                [],
            )
            .expect("update schema version");
        drop(connection);

        let error = Catalog::open(&paths)
            .err()
            .expect("schema mismatch should fail");
        assert!(error.to_string().contains("unsupported schema version"));
    }

    #[test]
    fn catalog_database_uses_private_permissions() {
        let dir = tempdir().expect("temp dir");
        let paths = ResolvedPaths {
            config_path: dir.path().join("config.yaml"),
            state_dir: dir.path().join("state"),
            spool_dir: dir.path().join("state/spool"),
            salt_path: dir.path().join("state/master_key.salt"),
            database_path: dir.path().join("state/catalog.db"),
        };

        let _catalog = Catalog::open(&paths).expect("open catalog");

        let db_mode = fs::metadata(&paths.database_path)
            .expect("db metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(db_mode, 0o600);
    }

    #[test]
    fn discover_honors_explicit_config_and_state_paths() {
        let paths = ResolvedPaths::discover(
            Some(Path::new("/etc/storecold/config.yaml")),
            Some(Path::new("/var/lib/storecold")),
        )
        .expect("resolve paths");

        assert_eq!(paths.config_path, Path::new("/etc/storecold/config.yaml"));
        assert_eq!(paths.state_dir, Path::new("/var/lib/storecold"));
        assert_eq!(paths.spool_dir, Path::new("/var/lib/storecold/spool"));
        assert_eq!(
            paths.database_path,
            Path::new("/var/lib/storecold/catalog.db")
        );
    }
}
