use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::StorageClass;
use azure_core::{
    credentials::{Secret, TokenCredential},
    http::{RequestContent, Url},
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId,
};
use azure_storage_blob::{
    BlobServiceClient,
    models::{AccessTier, BlobClientUploadOptions},
};
use bytes::Bytes;

use crate::config::{AzureAuth, Backend, Config};

pub struct ProviderPool {
    backends: HashMap<String, Arc<dyn ObjectBackend>>,
}

impl ProviderPool {
    pub async fn from_config(config: &Config) -> Result<Self> {
        let mut backends = HashMap::new();
        for repository in &config.repositories {
            let client: Arc<dyn ObjectBackend> = match &repository.backend {
                Backend::S3 {
                    data_bucket,
                    data_prefix,
                    region,
                    storage_class,
                    index_bucket,
                    index_prefix,
                    index_storage_class,
                    endpoint,
                } => Arc::new(
                    S3RepositoryClient::new(
                        region,
                        endpoint.as_deref(),
                        data_bucket,
                        data_prefix,
                        storage_class,
                        index_bucket,
                        index_prefix,
                        index_storage_class,
                    )
                    .await?,
                ),
                Backend::AzureBlob {
                    account,
                    auth,
                    data_container,
                    data_prefix,
                    access_tier,
                    index_container,
                    index_prefix,
                    index_access_tier,
                } => Arc::new(AzureRepositoryClient::new(
                    account,
                    auth,
                    data_container,
                    data_prefix,
                    access_tier,
                    index_container,
                    index_prefix,
                    index_access_tier,
                )?),
            };

            backends.insert(repository.name.clone(), client);
        }

        Ok(Self { backends })
    }

    #[cfg(test)]
    pub(crate) fn from_backends(backends: HashMap<String, Arc<dyn ObjectBackend>>) -> Self {
        Self { backends }
    }

    pub async fn put_data(&self, repository: &str, object_key: &str, body: Bytes) -> Result<()> {
        self.backend(repository)?.put_data(object_key, body).await
    }

    pub async fn put_index(&self, repository: &str, object_key: &str, body: Bytes) -> Result<()> {
        self.backend(repository)?.put_index(object_key, body).await
    }

    fn backend(&self, repository: &str) -> Result<&dyn ObjectBackend> {
        self.backends
            .get(repository)
            .map(Arc::as_ref)
            .with_context(|| format!("repository backend not found for {}", repository))
    }
}

#[async_trait]
pub(crate) trait ObjectBackend: Send + Sync {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()>;
    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()>;
}

#[async_trait]
pub(crate) trait S3ObjectClient: Send + Sync {
    async fn put_object(
        &self,
        bucket: &str,
        object_key: &str,
        storage_class: &str,
        body: Bytes,
    ) -> Result<()>;
}

struct AwsS3ObjectClient {
    client: S3Client,
}

#[async_trait]
impl S3ObjectClient for AwsS3ObjectClient {
    async fn put_object(
        &self,
        bucket: &str,
        object_key: &str,
        storage_class: &str,
        body: Bytes,
    ) -> Result<()> {
        self.client
            .put_object()
            .bucket(bucket)
            .key(object_key)
            .storage_class(StorageClass::from(storage_class))
            .body(ByteStream::from(body))
            .send()
            .await
            .with_context(|| format!("upload s3 object {}", object_key))?;
        Ok(())
    }
}

#[async_trait]
pub(crate) trait AzureBlobClient: Send + Sync {
    async fn upload_blob(
        &self,
        container: &str,
        object_key: &str,
        tier: AccessTier,
        body: Bytes,
    ) -> Result<()>;
}

struct AzureSdkBlobClient {
    service: BlobServiceClient,
}

#[async_trait]
impl AzureBlobClient for AzureSdkBlobClient {
    async fn upload_blob(
        &self,
        container: &str,
        object_key: &str,
        tier: AccessTier,
        body: Bytes,
    ) -> Result<()> {
        let blob = self.service.blob_client(container, object_key);
        let options = BlobClientUploadOptions {
            tier: Some(tier),
            ..Default::default()
        };

        blob.upload(RequestContent::from(body.to_vec()), Some(options))
            .await
            .with_context(|| format!("upload azure blob {}", object_key))?;
        Ok(())
    }
}

pub(crate) struct S3RepositoryClient {
    client: Arc<dyn S3ObjectClient>,
    data_bucket: String,
    data_prefix: String,
    data_storage_class: String,
    index_bucket: String,
    index_prefix: String,
    index_storage_class: String,
}

impl S3RepositoryClient {
    async fn new(
        region: &str,
        endpoint: Option<&str>,
        data_bucket: &str,
        data_prefix: &str,
        data_storage_class: &str,
        index_bucket: &str,
        index_prefix: &str,
        index_storage_class: &str,
    ) -> Result<Self> {
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint_url(endpoint);
        }

        Ok(Self::from_client(
            Arc::new(AwsS3ObjectClient {
                client: S3Client::from_conf(builder.build()),
            }),
            data_bucket,
            data_prefix,
            data_storage_class,
            index_bucket,
            index_prefix,
            index_storage_class,
        ))
    }

    fn from_client(
        client: Arc<dyn S3ObjectClient>,
        data_bucket: &str,
        data_prefix: &str,
        data_storage_class: &str,
        index_bucket: &str,
        index_prefix: &str,
        index_storage_class: &str,
    ) -> Self {
        Self {
            client,
            data_bucket: data_bucket.to_string(),
            data_prefix: data_prefix.to_string(),
            data_storage_class: data_storage_class.to_string(),
            index_bucket: index_bucket.to_string(),
            index_prefix: index_prefix.to_string(),
            index_storage_class: index_storage_class.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_client(
        client: Arc<dyn S3ObjectClient>,
        data_bucket: &str,
        data_prefix: &str,
        data_storage_class: &str,
        index_bucket: &str,
        index_prefix: &str,
        index_storage_class: &str,
    ) -> Self {
        Self::from_client(
            client,
            data_bucket,
            data_prefix,
            data_storage_class,
            index_bucket,
            index_prefix,
            index_storage_class,
        )
    }

    fn prefixed_key(prefix: &str, key: &str) -> String {
        join_object_key(prefix, key)
    }
}

#[async_trait]
impl ObjectBackend for S3RepositoryClient {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object(
                &self.data_bucket,
                &Self::prefixed_key(&self.data_prefix, object_key),
                &self.data_storage_class,
                body,
            )
            .await
            .with_context(|| format!("upload s3 data object {}", object_key))?;
        Ok(())
    }

    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object(
                &self.index_bucket,
                &Self::prefixed_key(&self.index_prefix, object_key),
                &self.index_storage_class,
                body,
            )
            .await
            .with_context(|| format!("upload s3 index object {}", object_key))?;
        Ok(())
    }
}

pub(crate) struct AzureRepositoryClient {
    client: Arc<dyn AzureBlobClient>,
    data_container: String,
    data_prefix: String,
    data_access_tier: AccessTier,
    index_container: String,
    index_prefix: String,
    index_access_tier: AccessTier,
}

impl AzureRepositoryClient {
    fn new(
        account: &str,
        auth: &AzureAuth,
        data_container: &str,
        data_prefix: &str,
        data_access_tier: &str,
        index_container: &str,
        index_prefix: &str,
        index_access_tier: &str,
    ) -> Result<Self> {
        let (endpoint, credential) = azure_blob_service_endpoint(account, auth)?;
        let service = BlobServiceClient::new(&endpoint, credential, None)
            .context("build azure blob service client")?;

        Ok(Self::from_client(
            Arc::new(AzureSdkBlobClient { service }),
            data_container,
            data_prefix,
            data_access_tier,
            index_container,
            index_prefix,
            index_access_tier,
        )?)
    }

    fn from_client(
        client: Arc<dyn AzureBlobClient>,
        data_container: &str,
        data_prefix: &str,
        data_access_tier: &str,
        index_container: &str,
        index_prefix: &str,
        index_access_tier: &str,
    ) -> Result<Self> {
        Ok(Self {
            client,
            data_container: data_container.to_string(),
            data_prefix: data_prefix.to_string(),
            data_access_tier: parse_access_tier(data_access_tier)?,
            index_container: index_container.to_string(),
            index_prefix: index_prefix.to_string(),
            index_access_tier: parse_access_tier(index_access_tier)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_client(
        client: Arc<dyn AzureBlobClient>,
        data_container: &str,
        data_prefix: &str,
        data_access_tier: &str,
        index_container: &str,
        index_prefix: &str,
        index_access_tier: &str,
    ) -> Result<Self> {
        Self::from_client(
            client,
            data_container,
            data_prefix,
            data_access_tier,
            index_container,
            index_prefix,
            index_access_tier,
        )
    }

    fn prefixed_key(prefix: &str, key: &str) -> String {
        join_object_key(prefix, key)
    }
}

fn join_object_key(prefix: &str, key: &str) -> String {
    let normalized_prefix = prefix.trim_matches('/');
    let normalized_key = key.trim_start_matches('/');

    match (normalized_prefix.is_empty(), normalized_key.is_empty()) {
        (true, true) => String::new(),
        (true, false) => normalized_key.to_string(),
        (false, true) => normalized_prefix.to_string(),
        (false, false) => format!("{normalized_prefix}/{normalized_key}"),
    }
}

#[async_trait]
impl ObjectBackend for AzureRepositoryClient {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .upload_blob(
                &self.data_container,
                &Self::prefixed_key(&self.data_prefix, object_key),
                self.data_access_tier.clone(),
                body,
            )
            .await
            .with_context(|| format!("upload azure data blob {}", object_key))?;
        Ok(())
    }

    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .upload_blob(
                &self.index_container,
                &Self::prefixed_key(&self.index_prefix, object_key),
                self.index_access_tier.clone(),
                body,
            )
            .await
            .with_context(|| format!("upload azure index blob {}", object_key))?;
        Ok(())
    }
}

fn parse_access_tier(value: &str) -> Result<AccessTier> {
    match value.to_ascii_lowercase().as_str() {
        "hot" => Ok(AccessTier::Hot),
        "cold" => Ok(AccessTier::Cold),
        "cool" => Ok(AccessTier::Cool),
        "archive" => Ok(AccessTier::Archive),
        _ => bail!("unsupported azure access tier {}", value),
    }
}

fn azure_blob_service_endpoint(
    account: &str,
    auth: &AzureAuth,
) -> Result<(String, Option<Arc<dyn TokenCredential>>)> {
    match auth {
        AzureAuth::AccessKeyEnv { .. } => bail!(
            "azure access-key authentication is not supported by the official azure_storage_blob crate; use developer_tools, managed_identity, client_secret_env, or sas_url_env"
        ),
        AzureAuth::ConnectionStringEnv { .. } => bail!(
            "azure connection-string authentication is not supported by the official azure_storage_blob crate; use developer_tools, managed_identity, client_secret_env, or sas_url_env"
        ),
        AzureAuth::DeveloperTools => {
            let credential: Arc<dyn TokenCredential> = DeveloperToolsCredential::new(None)?;
            Ok((azure_blob_endpoint(account), Some(credential)))
        }
        AzureAuth::ManagedIdentity { client_id_env_var } => {
            let user_assigned_id = client_id_env_var
                .as_ref()
                .map(|env_var| {
                    std::env::var(env_var)
                        .with_context(|| format!("environment variable {} is not set", env_var))
                        .map(UserAssignedId::ClientId)
                })
                .transpose()?;
            let options = ManagedIdentityCredentialOptions {
                user_assigned_id,
                ..Default::default()
            };
            let credential: Arc<dyn TokenCredential> =
                ManagedIdentityCredential::new(Some(options))?;
            Ok((azure_blob_endpoint(account), Some(credential)))
        }
        AzureAuth::ClientSecretEnv {
            tenant_id_env_var,
            client_id_env_var,
            client_secret_env_var,
        } => {
            let tenant_id = std::env::var(tenant_id_env_var).with_context(|| {
                format!("environment variable {} is not set", tenant_id_env_var)
            })?;
            let client_id = std::env::var(client_id_env_var).with_context(|| {
                format!("environment variable {} is not set", client_id_env_var)
            })?;
            let client_secret = std::env::var(client_secret_env_var).with_context(|| {
                format!("environment variable {} is not set", client_secret_env_var)
            })?;
            let credential: Arc<dyn TokenCredential> = ClientSecretCredential::new(
                &tenant_id,
                client_id,
                Secret::new(client_secret),
                None,
            )?;
            Ok((azure_blob_endpoint(account), Some(credential)))
        }
        AzureAuth::SasUrlEnv { env_var } => {
            let endpoint = std::env::var(env_var)
                .with_context(|| format!("environment variable {} is not set", env_var))?;
            validate_azure_service_url(&endpoint)?;
            Ok((endpoint, None))
        }
    }
}

fn azure_blob_endpoint(account: &str) -> String {
    format!("https://{account}.blob.core.windows.net/")
}

fn validate_azure_service_url(endpoint: &str) -> Result<()> {
    let url =
        Url::parse(endpoint).with_context(|| format!("parse azure service URL {endpoint}"))?;
    if !matches!(url.path(), "" | "/") {
        bail!(
            "azure sas_url_env must point at the storage account root (for example https://account.blob.core.windows.net/?sv=...), got {}",
            url
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct S3Call {
        bucket: String,
        object_key: String,
        storage_class: String,
        body: Vec<u8>,
    }

    struct RecordingS3Client {
        calls: Mutex<Vec<S3Call>>,
    }

    impl RecordingS3Client {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn take_calls(&self) -> Vec<S3Call> {
            self.calls.lock().expect("recording mutex").clone()
        }
    }

    #[async_trait]
    impl S3ObjectClient for RecordingS3Client {
        async fn put_object(
            &self,
            bucket: &str,
            object_key: &str,
            storage_class: &str,
            body: Bytes,
        ) -> Result<()> {
            self.calls.lock().expect("recording mutex").push(S3Call {
                bucket: bucket.to_string(),
                object_key: object_key.to_string(),
                storage_class: storage_class.to_string(),
                body: body.to_vec(),
            });
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct AzureCall {
        container: String,
        object_key: String,
        tier: AccessTier,
        body: Vec<u8>,
    }

    struct RecordingAzureClient {
        calls: Mutex<Vec<AzureCall>>,
    }

    impl RecordingAzureClient {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn take_calls(&self) -> Vec<AzureCall> {
            self.calls.lock().expect("recording mutex").clone()
        }
    }

    #[async_trait]
    impl AzureBlobClient for RecordingAzureClient {
        async fn upload_blob(
            &self,
            container: &str,
            object_key: &str,
            tier: AccessTier,
            body: Bytes,
        ) -> Result<()> {
            self.calls.lock().expect("recording mutex").push(AzureCall {
                container: container.to_string(),
                object_key: object_key.to_string(),
                tier,
                body: body.to_vec(),
            });
            Ok(())
        }
    }

    struct RecordingBackend {
        calls: Mutex<Vec<(String, String, Vec<u8>)>>,
    }

    impl RecordingBackend {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn take_calls(&self) -> Vec<(String, String, Vec<u8>)> {
            self.calls.lock().expect("recording mutex").clone()
        }
    }

    #[async_trait]
    impl ObjectBackend for RecordingBackend {
        async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()> {
            self.calls.lock().expect("recording mutex").push((
                "data".to_string(),
                object_key.to_string(),
                body.to_vec(),
            ));
            Ok(())
        }

        async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
            self.calls.lock().expect("recording mutex").push((
                "index".to_string(),
                object_key.to_string(),
                body.to_vec(),
            ));
            Ok(())
        }
    }

    #[test]
    fn join_object_key_normalizes_slashes() {
        assert_eq!(join_object_key("data", "packs/a.pack"), "data/packs/a.pack");
        assert_eq!(
            join_object_key("data/", "packs/a.pack"),
            "data/packs/a.pack"
        );
        assert_eq!(
            join_object_key("/data/", "/packs/a.pack"),
            "data/packs/a.pack"
        );
        assert_eq!(join_object_key("", "/packs/a.pack"), "packs/a.pack");
    }

    #[tokio::test]
    async fn s3_repository_client_routes_data_uploads_through_injected_client() {
        let client = Arc::new(RecordingS3Client::new());
        let repository = S3RepositoryClient::with_client(
            client.clone(),
            "data-bucket",
            "data/",
            "DEEP_ARCHIVE",
            "index-bucket",
            "index/",
            "STANDARD",
        );

        repository
            .put_data("packs/root.pack", Bytes::from_static(b"ciphertext"))
            .await
            .expect("upload succeeds");

        assert_eq!(
            client.take_calls(),
            vec![S3Call {
                bucket: "data-bucket".to_string(),
                object_key: "data/packs/root.pack".to_string(),
                storage_class: "DEEP_ARCHIVE".to_string(),
                body: b"ciphertext".to_vec(),
            }]
        );
    }

    #[tokio::test]
    async fn s3_repository_client_routes_index_uploads_through_injected_client() {
        let client = Arc::new(RecordingS3Client::new());
        let repository = S3RepositoryClient::with_client(
            client.clone(),
            "data-bucket",
            "data/",
            "DEEP_ARCHIVE",
            "index-bucket",
            "index/",
            "STANDARD",
        );

        repository
            .put_index("/catalog.json", Bytes::from_static(b"index"))
            .await
            .expect("upload succeeds");

        assert_eq!(
            client.take_calls(),
            vec![S3Call {
                bucket: "index-bucket".to_string(),
                object_key: "index/catalog.json".to_string(),
                storage_class: "STANDARD".to_string(),
                body: b"index".to_vec(),
            }]
        );
    }

    #[tokio::test]
    async fn azure_repository_client_routes_data_uploads_through_injected_client() {
        let client = Arc::new(RecordingAzureClient::new());
        let repository = AzureRepositoryClient::with_client(
            client.clone(),
            "backup-data",
            "data/",
            "Archive",
            "backup-index",
            "index/",
            "Hot",
        )
        .expect("repository client builds");

        repository
            .put_data("packs/root.pack", Bytes::from_static(b"ciphertext"))
            .await
            .expect("upload succeeds");

        let calls = client.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].container, "backup-data");
        assert_eq!(calls[0].object_key, "data/packs/root.pack");
        assert_eq!(calls[0].tier, AccessTier::Archive);
        assert_eq!(calls[0].body, b"ciphertext".to_vec());
    }

    #[tokio::test]
    async fn azure_repository_client_routes_index_uploads_through_injected_client() {
        let client = Arc::new(RecordingAzureClient::new());
        let repository = AzureRepositoryClient::with_client(
            client.clone(),
            "backup-data",
            "data/",
            "Archive",
            "backup-index",
            "index/",
            "Hot",
        )
        .expect("repository client builds");

        repository
            .put_index("/catalog.json", Bytes::from_static(b"index"))
            .await
            .expect("upload succeeds");

        let calls = client.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].container, "backup-index");
        assert_eq!(calls[0].object_key, "index/catalog.json");
        assert_eq!(calls[0].tier, AccessTier::Hot);
        assert_eq!(calls[0].body, b"index".to_vec());
    }

    #[tokio::test]
    async fn provider_pool_accepts_injected_backends_for_unit_tests() {
        let backend = Arc::new(RecordingBackend::new());
        let pool = ProviderPool::from_backends(HashMap::from([(
            "cold-store".to_string(),
            backend.clone() as Arc<dyn ObjectBackend>,
        )]));

        pool.put_data(
            "cold-store",
            "packs/root.pack",
            Bytes::from_static(b"ciphertext"),
        )
        .await
        .expect("data upload succeeds");
        pool.put_index("cold-store", "catalog.json", Bytes::from_static(b"index"))
            .await
            .expect("index upload succeeds");

        assert_eq!(
            backend.take_calls(),
            vec![
                (
                    "data".to_string(),
                    "packs/root.pack".to_string(),
                    b"ciphertext".to_vec(),
                ),
                (
                    "index".to_string(),
                    "catalog.json".to_string(),
                    b"index".to_vec(),
                ),
            ]
        );
    }
}
