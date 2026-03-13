use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use sha2::{Digest, Sha512};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::config::{Config, PathSpec};
use crate::crypto::KeyMaterial;
use crate::manifest::{CatalogEntry, ContentManifest, PathManifest, PathManifestVersion};
use crate::provider::ProviderPool;
use crate::state::{
    ContentRef, ObservedFile, SharedCatalog, SyncRunRecord, VersionRecord, with_catalog,
};

const PACK_MAGIC: &[u8] = b"STRCLDP1";
const MAX_UPLOAD_ATTEMPTS: u32 = 3;
const RETRY_BASE_DELAY_MS: u64 = 500;

#[derive(Debug, Clone, Default)]
pub struct SyncSummary {
    pub root: PathBuf,
    pub files_scanned: u64,
    pub changed_files: u64,
    pub deleted_files: u64,
    pub uploaded_files: u64,
    pub reused_files: u64,
    pub bytes_uploaded: u64,
    pub errors: u64,
}

pub async fn sync_roots(
    config: &Config,
    catalog: &SharedCatalog,
    keys: &KeyMaterial,
    providers: &ProviderPool,
    roots: &[&PathSpec],
) -> Result<Vec<SyncSummary>> {
    let mut summaries = Vec::with_capacity(roots.len());
    let mut pending_uploads: HashMap<(String, String), PendingContentUpload> = HashMap::new();
    let mut changed_path_hashes = HashSet::new();

    for root in roots {
        let summary_index = summaries.len();
        let summary = reconcile_root(
            config,
            catalog,
            keys,
            root,
            &mut pending_uploads,
            &mut changed_path_hashes,
            summary_index,
        )?;
        summaries.push(summary);
    }

    let uploaded_content =
        upload_pending_contents(config, keys, providers, pending_uploads, &mut summaries).await?;

    with_catalog(catalog, |catalog| {
        for uploaded in &uploaded_content {
            catalog.save_content_ref(&uploaded.content_ref)?;
            for commit in &uploaded.commits {
                catalog.insert_version(&commit.version)?;
                catalog.upsert_observed_file(&commit.observed)?;
                changed_path_hashes.insert(commit.version.path_hash.clone());
            }
        }
        Ok(())
    })?;

    publish_index_updates(
        config,
        catalog,
        keys,
        providers,
        &changed_path_hashes,
        &uploaded_content,
    )
    .await?;

    with_catalog(catalog, |catalog| {
        for summary in &summaries {
            catalog.record_sync_run(&SyncRunRecord {
                root_path: summary.root.display().to_string(),
                files_scanned: summary.files_scanned,
                changed_files: summary.changed_files,
                deleted_files: summary.deleted_files,
                uploaded_files: summary.uploaded_files,
                reused_files: summary.reused_files,
                bytes_uploaded: summary.bytes_uploaded,
                errors: summary.errors,
            })?;
        }
        Ok(())
    })?;

    Ok(summaries)
}

fn reconcile_root(
    config: &Config,
    catalog: &SharedCatalog,
    keys: &KeyMaterial,
    root: &PathSpec,
    pending_uploads: &mut HashMap<(String, String), PendingContentUpload>,
    changed_path_hashes: &mut HashSet<String>,
    summary_index: usize,
) -> Result<SyncSummary> {
    let excludes = compile_excludes(&root.excludes)?;
    let mut summary = SyncSummary {
        root: root.path.clone(),
        ..SyncSummary::default()
    };
    let mut seen_paths = HashSet::new();

    for entry in WalkDir::new(&root.path)
        .follow_links(config.policy.follow_symlinks)
        .same_file_system(config.policy.one_file_system)
        .into_iter()
        .filter_entry(|entry| !is_excluded(&excludes, &root.path, entry.path()))
    {
        match entry {
            Ok(entry) => {
                if !entry.file_type().is_file() {
                    continue;
                }

                summary.files_scanned += 1;
                let path = entry.path().to_path_buf();
                let path_text = path.display().to_string();
                seen_paths.insert(path_text.clone());

                let metadata = match entry.metadata() {
                    Ok(value) => value,
                    Err(error) => {
                        summary.errors += 1;
                        warn!(path = %path.display(), error = %error, "unable to read file metadata");
                        continue;
                    }
                };

                let last_seen_at = now_rfc3339()?;
                let path_hash = keys.path_hash(&config.host_id, &path_text)?;
                let mtime_ns = match compose_unix_timestamp_ns(
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        summary.errors += 1;
                        warn!(path = %path.display(), error = %error, "unable to compose file mtime");
                        continue;
                    }
                };
                let observed = ObservedFile {
                    path: path_text.clone(),
                    path_hash: path_hash.clone(),
                    repository: root.repository.clone(),
                    dev: metadata.dev() as i64,
                    inode: metadata.ino() as i64,
                    size: metadata.len() as i64,
                    mtime_ns,
                    current_sha512: None,
                    deleted: false,
                    last_seen_at,
                };

                let existing = with_catalog(catalog, |catalog| catalog.observed_file(&path_text))?;
                if let Some(current) = &existing {
                    if !current.deleted
                        && current.size == observed.size
                        && current.mtime_ns == observed.mtime_ns
                        && current.current_sha512.is_some()
                    {
                        let mut refreshed = observed.clone();
                        refreshed.current_sha512 = current.current_sha512.clone();
                        with_catalog(catalog, |catalog| catalog.upsert_observed_file(&refreshed))?;
                        continue;
                    }
                }

                let sha512 = match sha512_file(&path) {
                    Ok(value) => value,
                    Err(error) => {
                        summary.errors += 1;
                        warn!(path = %path.display(), error = %error, "unable to hash file");
                        continue;
                    }
                };

                if existing
                    .as_ref()
                    .and_then(|item| item.current_sha512.as_ref())
                    .is_some_and(|value| value == &sha512)
                {
                    let mut refreshed = observed.clone();
                    refreshed.current_sha512 = Some(sha512);
                    with_catalog(catalog, |catalog| catalog.upsert_observed_file(&refreshed))?;
                    continue;
                }

                if let Some(previous) = existing
                    .as_ref()
                    .and_then(|item| item.current_sha512.as_ref())
                {
                    warn!(
                        path = %path.display(),
                        previous_sha512 = %previous,
                        current_sha512 = %sha512,
                        "file content changed; possible corruption or legitimate modification"
                    );
                }

                let version = VersionRecord {
                    version_id: Uuid::new_v4().to_string(),
                    path_hash: path_hash.clone(),
                    path: path_text.clone(),
                    repository: root.repository.clone(),
                    sha512: Some(sha512.clone()),
                    created_at: now_rfc3339()?,
                    reason: if existing.is_some() {
                        "modified".to_string()
                    } else {
                        "new".to_string()
                    },
                };

                let mut updated_observed = observed.clone();
                updated_observed.current_sha512 = Some(sha512.clone());

                summary.changed_files += 1;
                changed_path_hashes.insert(path_hash);

                if with_catalog(catalog, |catalog| catalog.content_ref(&root.repository, &sha512))?
                    .is_some()
                {
                    with_catalog(catalog, |catalog| {
                        catalog.insert_version(&version)?;
                        catalog.upsert_observed_file(&updated_observed)?;
                        Ok(())
                    })?;
                    summary.reused_files += 1;
                    continue;
                }

                let key = (root.repository.clone(), sha512.clone());
                pending_uploads
                    .entry(key)
                    .and_modify(|pending| {
                        pending.commits.push(QueuedCommit {
                            observed: updated_observed.clone(),
                            version: version.clone(),
                            summary_index,
                        });
                    })
                    .or_insert_with(|| PendingContentUpload {
                        repository: root.repository.clone(),
                        sha512,
                        file_path: path.clone(),
                        commits: vec![QueuedCommit {
                            observed: updated_observed,
                            version,
                            summary_index,
                        }],
                    });
            }
            Err(error) => {
                summary.errors += 1;
                warn!(error = %error, "walkdir error");
            }
        }
    }

    let active_paths =
        with_catalog(catalog, |catalog| catalog.active_paths_under_root(&root.repository, &root.path))?;
    for missing in active_paths {
        if seen_paths.contains(&missing.path) {
            continue;
        }

        let tombstone = VersionRecord {
            version_id: Uuid::new_v4().to_string(),
            path_hash: missing.path_hash.clone(),
            path: missing.path.clone(),
            repository: missing.repository.clone(),
            sha512: None,
            created_at: now_rfc3339()?,
            reason: "deleted".to_string(),
        };

        let mut deleted = missing.clone();
        deleted.deleted = true;
        deleted.last_seen_at = now_rfc3339()?;

        with_catalog(catalog, |catalog| {
            catalog.insert_version(&tombstone)?;
            catalog.upsert_observed_file(&deleted)?;
            Ok(())
        })?;
        changed_path_hashes.insert(tombstone.path_hash.clone());
        summary.changed_files += 1;
        summary.deleted_files += 1;
    }

    Ok(summary)
}

async fn upload_pending_contents(
    config: &Config,
    keys: &KeyMaterial,
    providers: &ProviderPool,
    pending_uploads: HashMap<(String, String), PendingContentUpload>,
    summaries: &mut [SyncSummary],
) -> Result<Vec<UploadedContent>> {
    if pending_uploads.is_empty() {
        return Ok(Vec::new());
    }

    let mut pending_by_repo: HashMap<String, Vec<PendingContentUpload>> = HashMap::new();
    for (_, pending) in pending_uploads {
        pending_by_repo
            .entry(pending.repository.clone())
            .or_default()
            .push(pending);
    }

    let mut plans = Vec::new();
    for (repository, mut pending) in pending_by_repo {
        pending.sort_by(|left, right| left.sha512.cmp(&right.sha512));
        plans.extend(build_pack_plans(
            config,
            keys,
            &repository,
            pending,
            summaries,
        )?);
    }

    let limiter = tokio::sync::Mutex::new(UploadThrottle::new(
        config.upload.rate_limit_bytes_per_sec(),
        config.upload.max_puts_per_minute,
    ));

    let upload_results = stream::iter(plans.into_iter().map(|plan| async {
        let wait = {
            let mut limiter = limiter.lock().await;
            limiter.reserve(plan.bytes.len() as u64)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }

        let PackUploadPlan {
            repository,
            object_key,
            bytes,
            records,
        } = plan;
        match put_data_with_retry(providers, &repository, &object_key, bytes).await {
            Ok(()) => UploadPackOutcome::Uploaded(UploadedPack {
                repository,
                object_key,
                records,
            }),
            Err(error) => UploadPackOutcome::Failed(FailedPack {
                repository,
                object_key,
                records,
                error,
            }),
        }
    }))
    .buffer_unordered(config.upload.max_concurrent_uploads)
    .collect::<Vec<_>>()
    .await;

    let mut uploaded = Vec::new();
    let mut failed_packs = 0u64;
    for result in upload_results {
        match result {
            UploadPackOutcome::Uploaded(plan) => {
                for record in plan.records {
                    for commit in &record.commits {
                        summaries[commit.summary_index].uploaded_files += 1;
                        summaries[commit.summary_index].bytes_uploaded += record.plain_len as u64;
                    }
                    uploaded.push(UploadedContent {
                        content_ref: ContentRef {
                            repository: plan.repository.clone(),
                            sha512: record.sha512,
                            object_key: plan.object_key.clone(),
                            ciphertext_offset: record.ciphertext_offset,
                            cipher_len: record.cipher_len,
                            plain_len: record.plain_len,
                            nonce_b64: record.nonce_b64,
                            created_at: record.created_at,
                        },
                        commits: record.commits,
                    });
                }
            }
            UploadPackOutcome::Failed(failure) => {
                failed_packs += 1;
                record_pack_errors(&failure.records, summaries);
                warn!(
                    repository = %failure.repository,
                    object_key = %failure.object_key,
                    error = %failure.error,
                    "pack upload failed; changes will be retried on the next sync"
                );
            }
        }
    }

    if failed_packs > 0 {
        warn!(
            failed_packs,
            "some pack uploads failed after retries; successful uploads were still committed"
        );
    }

    Ok(uploaded)
}

async fn publish_index_updates(
    config: &Config,
    catalog: &SharedCatalog,
    keys: &KeyMaterial,
    providers: &ProviderPool,
    changed_path_hashes: &HashSet<String>,
    uploaded_content: &[UploadedContent],
) -> Result<()> {
    for item in uploaded_content {
        let manifest = ContentManifest {
            repository: item.content_ref.repository.clone(),
            sha512: item.content_ref.sha512.clone(),
            object_key: item.content_ref.object_key.clone(),
            ciphertext_offset: item.content_ref.ciphertext_offset,
            cipher_len: item.content_ref.cipher_len,
            plain_len: item.content_ref.plain_len,
            nonce_b64: item.content_ref.nonce_b64.clone(),
            created_at: item.content_ref.created_at.clone(),
        };
        let encrypted = encrypt_json(keys, &manifest)?;
        let object_key = format!("content/{}.bin", item.content_ref.sha512);
        put_index_with_retry(
            providers,
            &item.content_ref.repository,
            &object_key,
            Bytes::from(encrypted),
        )
        .await?;
    }

    for path_hash in changed_path_hashes {
        let (versions, latest_state) = with_catalog(catalog, |catalog| {
            Ok((
                catalog.versions_for_path_hash(path_hash)?,
                catalog.latest_observed_by_path_hash(path_hash)?,
            ))
        })?;
        if versions.is_empty() {
            continue;
        }

        let latest = versions
            .last()
            .cloned()
            .ok_or_else(|| anyhow!("missing latest version for {}", path_hash))?;
        let repository = latest.repository.clone();
        let path = latest_state
            .as_ref()
            .map(|state| state.path.clone())
            .unwrap_or_else(|| latest.path.clone());
        let deleted = latest_state.as_ref().is_some_and(|state| state.deleted);

        let manifest = PathManifest {
            path_hash: path_hash.clone(),
            path,
            repository: repository.clone(),
            deleted,
            updated_at: latest.created_at.clone(),
            versions: versions
                .into_iter()
                .map(|version| PathManifestVersion {
                    version_id: version.version_id,
                    sha512: version.sha512,
                    created_at: version.created_at,
                    reason: version.reason,
                })
                .collect(),
        };

        if let Some(current_sha512) = current_catalog_sha512(&manifest.versions) {
            let catalog_entry = CatalogEntry {
                path_hash: path_hash.clone(),
                current_sha512,
            };
            put_index_with_retry(
                providers,
                &repository,
                &format!("catalog/{}.json", path_hash),
                Bytes::from(serde_json::to_vec(&catalog_entry)?),
            )
            .await?;
        } else {
            warn!(
                path_hash = %path_hash,
                "skipping catalog entry for path without uploaded content history"
            );
        }
        put_index_with_retry(
            providers,
            &repository,
            &format!("manifests/{}.bin", path_hash),
            Bytes::from(encrypt_json(keys, &manifest)?),
        )
        .await?;
    }

    info!(
        changed_paths = changed_path_hashes.len(),
        uploaded_content = uploaded_content.len(),
        "published hot index updates"
    );
    let _ = config;
    Ok(())
}

fn encrypt_json<T: Serialize>(keys: &KeyMaterial, value: &T) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(value).context("serialize manifest")?;
    let encrypted = keys.encrypt_manifest(&plaintext)?;
    serde_json::to_vec(&EncryptedEnvelope {
        nonce_b64: encrypted.nonce_b64,
        ciphertext_b64: BASE64.encode(encrypted.ciphertext),
    })
    .context("serialize encrypted envelope")
}

fn build_pack_plans(
    config: &Config,
    keys: &KeyMaterial,
    repository: &str,
    pending: Vec<PendingContentUpload>,
    summaries: &mut [SyncSummary],
) -> Result<Vec<PackUploadPlan>> {
    let mut plans = Vec::new();
    let target_bytes = config.upload.batch_target_bytes();
    let mut bytes = PACK_MAGIC.to_vec();
    let mut records = Vec::new();
    let mut current_size = bytes.len() as u64;

    for item in pending {
        let payload = match std::fs::read(&item.file_path) {
            Ok(payload) => payload,
            Err(error) => {
                record_commit_errors(&item.commits, summaries);
                warn!(
                    path = %item.file_path.display(),
                    error = %error,
                    "unable to read file for upload; skipping this revision"
                );
                continue;
            }
        };
        let actual_sha512 = sha512_bytes(&payload);
        if actual_sha512 != item.sha512 {
            record_commit_errors(&item.commits, summaries);
            warn!(
                path = %item.file_path.display(),
                expected_sha512 = %item.sha512,
                actual_sha512 = %actual_sha512,
                "file changed between hashing and upload; skipping this revision"
            );
            continue;
        }

        let plain_len = payload.len() as u64;
        let encrypted = keys.encrypt_content(payload)?;
        let header = PackEntryHeader {
            sha512: item.sha512.clone(),
            plain_len,
            cipher_len: encrypted.ciphertext.len() as u64,
            nonce_b64: encrypted.nonce_b64.clone(),
        };
        let header_bytes = serde_json::to_vec(&header).context("serialize pack header")?;
        let entry_size = 8u64 + header_bytes.len() as u64 + encrypted.ciphertext.len() as u64;

        if current_size > PACK_MAGIC.len() as u64 && current_size + entry_size > target_bytes {
            plans.push(PackUploadPlan::new(repository.to_string(), bytes, records));
            bytes = PACK_MAGIC.to_vec();
            records = Vec::new();
            current_size = bytes.len() as u64;
        }

        let ciphertext_offset = current_size as i64 + 8 + header_bytes.len() as i64;
        bytes.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&encrypted.ciphertext);
        current_size += entry_size;

        records.push(PackRecord {
            sha512: item.sha512,
            ciphertext_offset,
            cipher_len: encrypted.ciphertext.len() as i64,
            plain_len: plain_len as i64,
            nonce_b64: encrypted.nonce_b64,
            created_at: now_rfc3339()?,
            commits: item.commits,
        });
    }

    if !records.is_empty() {
        plans.push(PackUploadPlan::new(repository.to_string(), bytes, records));
    }

    Ok(plans)
}

fn compile_excludes(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("invalid glob {}", pattern))?);
    }
    builder.build().context("build exclude set")
}

fn is_excluded(excludes: &GlobSet, root: &Path, candidate: &Path) -> bool {
    if excludes.is_empty() {
        return false;
    }

    candidate
        .strip_prefix(root)
        .ok()
        .is_some_and(|relative| excludes.is_match(relative))
}

fn now_rfc3339() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")
}

fn compose_unix_timestamp_ns(seconds: i64, nanoseconds: i64) -> Result<i64> {
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanoseconds))
        .ok_or_else(|| {
            anyhow!(
                "mtime overflow for seconds={} nanoseconds={}",
                seconds,
                nanoseconds
            )
        })
}

fn sha512_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buffer = [0u8; 1024 * 1024];
    let mut hasher = Sha512::new();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha512_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn current_catalog_sha512(versions: &[PathManifestVersion]) -> Option<String> {
    versions
        .iter()
        .rev()
        .find_map(|version| version.sha512.clone())
}

fn record_commit_errors(commits: &[QueuedCommit], summaries: &mut [SyncSummary]) {
    for commit in commits {
        if let Some(summary) = summaries.get_mut(commit.summary_index) {
            summary.errors += 1;
        }
    }
}

fn record_pack_errors(records: &[PackRecord], summaries: &mut [SyncSummary]) {
    for record in records {
        record_commit_errors(&record.commits, summaries);
    }
}

async fn put_data_with_retry(
    providers: &ProviderPool,
    repository: &str,
    object_key: &str,
    body: Bytes,
) -> Result<()> {
    for attempt in 1..=MAX_UPLOAD_ATTEMPTS {
        match providers.put_data(repository, object_key, body.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if attempt < MAX_UPLOAD_ATTEMPTS => {
                let delay = Duration::from_millis(RETRY_BASE_DELAY_MS * (1 << (attempt - 1)));
                warn!(
                    attempt,
                    repository,
                    object_key,
                    error = %error,
                    retry_in_ms = delay.as_millis(),
                    "data upload failed; retrying"
                );
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("upload attempts should always return or retry")
}

async fn put_index_with_retry(
    providers: &ProviderPool,
    repository: &str,
    object_key: &str,
    body: Bytes,
) -> Result<()> {
    for attempt in 1..=MAX_UPLOAD_ATTEMPTS {
        match providers.put_index(repository, object_key, body.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if attempt < MAX_UPLOAD_ATTEMPTS => {
                let delay = Duration::from_millis(RETRY_BASE_DELAY_MS * (1 << (attempt - 1)));
                warn!(
                    attempt,
                    repository,
                    object_key,
                    error = %error,
                    retry_in_ms = delay.as_millis(),
                    "index upload failed; retrying"
                );
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("upload attempts should always return or retry")
}

struct PendingContentUpload {
    repository: String,
    sha512: String,
    file_path: PathBuf,
    commits: Vec<QueuedCommit>,
}

#[derive(Clone)]
struct QueuedCommit {
    observed: ObservedFile,
    version: VersionRecord,
    summary_index: usize,
}

struct UploadedContent {
    content_ref: ContentRef,
    commits: Vec<QueuedCommit>,
}

struct UploadedPack {
    repository: String,
    object_key: String,
    records: Vec<PackRecord>,
}

enum UploadPackOutcome {
    Uploaded(UploadedPack),
    Failed(FailedPack),
}

struct FailedPack {
    repository: String,
    object_key: String,
    records: Vec<PackRecord>,
    error: anyhow::Error,
}

#[derive(Serialize)]
struct PackEntryHeader {
    sha512: String,
    plain_len: u64,
    cipher_len: u64,
    nonce_b64: String,
}

struct PackUploadPlan {
    repository: String,
    object_key: String,
    bytes: Bytes,
    records: Vec<PackRecord>,
}

impl PackUploadPlan {
    fn new(repository: String, bytes: Vec<u8>, records: Vec<PackRecord>) -> Self {
        Self {
            repository,
            object_key: format!("packs/{}.pack", Uuid::new_v4()),
            bytes: Bytes::from(bytes),
            records,
        }
    }
}

struct PackRecord {
    sha512: String,
    ciphertext_offset: i64,
    cipher_len: i64,
    plain_len: i64,
    nonce_b64: String,
    created_at: String,
    commits: Vec<QueuedCommit>,
}

struct UploadThrottle {
    bytes_per_sec: u64,
    put_gap: Duration,
    next_byte_slot: Instant,
    next_put_slot: Instant,
}

#[derive(Serialize)]
struct EncryptedEnvelope {
    nonce_b64: String,
    ciphertext_b64: String,
}

impl UploadThrottle {
    fn new(bytes_per_sec: u64, max_puts_per_minute: u32) -> Self {
        let now = Instant::now();
        let put_gap = if max_puts_per_minute == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(60.0 / f64::from(max_puts_per_minute))
        };
        Self {
            bytes_per_sec,
            put_gap,
            next_byte_slot: now,
            next_put_slot: now,
        }
    }

    fn reserve(&mut self, bytes: u64) -> Duration {
        let now = Instant::now();
        let scheduled = self.next_byte_slot.max(self.next_put_slot);
        let wait = scheduled.saturating_duration_since(now);
        let start = now + wait;

        self.next_put_slot = start + self.put_gap;
        self.next_byte_slot = if self.bytes_per_sec == 0 {
            start
        } else {
            start + Duration::from_secs_f64(bytes as f64 / self.bytes_per_sec as f64)
        };

        wait
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn sha512_matches_known_value() {
        assert_eq!(
            sha512_bytes(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn excludes_match_relative_paths() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("**/*.tmp").expect("glob"));
        let excludes = builder.build().expect("build");
        let root = tempdir().expect("temp dir");
        let candidate = root.path().join("child/file.tmp");
        assert!(is_excluded(&excludes, root.path(), &candidate));
    }

    #[test]
    fn compose_unix_timestamp_ns_handles_negative_seconds() {
        let value = compose_unix_timestamp_ns(-1, 500_000_000).expect("timestamp composes");
        assert_eq!(value, -500_000_000);
    }

    #[test]
    fn compose_unix_timestamp_ns_rejects_overflow() {
        let error = compose_unix_timestamp_ns(i64::MAX, 1).expect_err("overflow should fail");
        assert!(error.to_string().contains("mtime overflow"));
    }

    #[test]
    fn current_catalog_sha512_ignores_deletion_only_histories() {
        let versions = vec![PathManifestVersion {
            version_id: "v1".to_string(),
            sha512: None,
            created_at: "2026-03-12T00:00:00Z".to_string(),
            reason: "deleted".to_string(),
        }];

        assert_eq!(current_catalog_sha512(&versions), None);
    }
}
