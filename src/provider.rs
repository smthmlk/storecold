use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::StorageClass;
use azure_storage::{ConnectionString, StorageCredentials};
use azure_storage_blobs::prelude::{AccessTier, BlobServiceClient};
use bytes::Bytes;

use crate::config::{AzureAuth, Backend, Config};

pub struct ProviderPool {
    backends: HashMap<String, RepositoryClient>,
}

impl ProviderPool {
    pub async fn from_config(config: &Config) -> Result<Self> {
        let mut backends = HashMap::new();
        for repository in &config.repositories {
            let client = match &repository.backend {
                Backend::S3 {
                    data_bucket,
                    data_prefix,
                    region,
                    storage_class,
                    index_bucket,
                    index_prefix,
                    index_storage_class,
                    endpoint,
                } => RepositoryClient::S3(
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
                } => RepositoryClient::Azure(AzureRepositoryClient::new(
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

    pub async fn put_data(&self, repository: &str, object_key: &str, body: Bytes) -> Result<()> {
        self.backend(repository)?
            .put_data(object_key, body)
            .await
    }

    pub async fn put_index(&self, repository: &str, object_key: &str, body: Bytes) -> Result<()> {
        self.backend(repository)?
            .put_index(object_key, body)
            .await
    }

    fn backend(&self, repository: &str) -> Result<&RepositoryClient> {
        self.backends
            .get(repository)
            .with_context(|| format!("repository backend not found for {}", repository))
    }
}

enum RepositoryClient {
    S3(S3RepositoryClient),
    Azure(AzureRepositoryClient),
}

#[async_trait]
trait ObjectBackend {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()>;
    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()>;
}

#[async_trait]
impl ObjectBackend for RepositoryClient {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()> {
        match self {
            RepositoryClient::S3(client) => client.put_data(object_key, body).await,
            RepositoryClient::Azure(client) => client.put_data(object_key, body).await,
        }
    }

    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
        match self {
            RepositoryClient::S3(client) => client.put_index(object_key, body).await,
            RepositoryClient::Azure(client) => client.put_index(object_key, body).await,
        }
    }
}

struct S3RepositoryClient {
    client: S3Client,
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

        Ok(Self {
            client: S3Client::from_conf(builder.build()),
            data_bucket: data_bucket.to_string(),
            data_prefix: data_prefix.to_string(),
            data_storage_class: data_storage_class.to_string(),
            index_bucket: index_bucket.to_string(),
            index_prefix: index_prefix.to_string(),
            index_storage_class: index_storage_class.to_string(),
        })
    }

    fn prefixed_key(prefix: &str, key: &str) -> String {
        join_object_key(prefix, key)
    }
}

#[async_trait]
impl ObjectBackend for S3RepositoryClient {
    async fn put_data(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.data_bucket)
            .key(Self::prefixed_key(&self.data_prefix, object_key))
            .storage_class(StorageClass::from(self.data_storage_class.as_str()))
            .body(ByteStream::from(body))
            .send()
            .await
            .with_context(|| format!("upload s3 data object {}", object_key))?;
        Ok(())
    }

    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.index_bucket)
            .key(Self::prefixed_key(&self.index_prefix, object_key))
            .storage_class(StorageClass::from(self.index_storage_class.as_str()))
            .body(ByteStream::from(body))
            .send()
            .await
            .with_context(|| format!("upload s3 index object {}", object_key))?;
        Ok(())
    }
}

struct AzureRepositoryClient {
    service: BlobServiceClient,
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
        let service = match auth {
            AzureAuth::AccessKeyEnv { env_var } => {
                let key = std::env::var(env_var)
                    .with_context(|| format!("environment variable {} is not set", env_var))?;
                let credentials = StorageCredentials::access_key(account.to_string(), key);
                BlobServiceClient::new(account.to_string(), credentials)
            }
            AzureAuth::ConnectionStringEnv { env_var } => {
                let value = std::env::var(env_var)
                    .with_context(|| format!("environment variable {} is not set", env_var))?;
                let connection_string =
                    ConnectionString::new(&value).context("parse connection string")?;
                let account_name = connection_string
                    .account_name
                    .clone()
                    .context("connection string missing account name")?;
                let credentials = connection_string.storage_credentials()?;
                BlobServiceClient::new(account_name, credentials)
            }
        };

        Ok(Self {
            service,
            data_container: data_container.to_string(),
            data_prefix: data_prefix.to_string(),
            data_access_tier: parse_access_tier(data_access_tier)?,
            index_container: index_container.to_string(),
            index_prefix: index_prefix.to_string(),
            index_access_tier: parse_access_tier(index_access_tier)?,
        })
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
        let blob = self
            .service
            .container_client(&self.data_container)
            .blob_client(Self::prefixed_key(&self.data_prefix, object_key));

        blob.put_block_blob(body)
            .access_tier(self.data_access_tier.clone())
            .await
            .with_context(|| format!("upload azure data blob {}", object_key))?;
        Ok(())
    }

    async fn put_index(&self, object_key: &str, body: Bytes) -> Result<()> {
        let blob = self
            .service
            .container_client(&self.index_container)
            .blob_client(Self::prefixed_key(&self.index_prefix, object_key));

        blob.put_block_blob(body)
            .access_tier(self.index_access_tier.clone())
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

#[cfg(test)]
mod tests {
    use super::join_object_key;

    #[test]
    fn join_object_key_normalizes_slashes() {
        assert_eq!(join_object_key("data", "packs/a.pack"), "data/packs/a.pack");
        assert_eq!(join_object_key("data/", "packs/a.pack"), "data/packs/a.pack");
        assert_eq!(join_object_key("/data/", "/packs/a.pack"), "data/packs/a.pack");
        assert_eq!(join_object_key("", "/packs/a.pack"), "packs/a.pack");
    }
}
