use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub path_hash: String,
    pub current_sha512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathManifest {
    pub path_hash: String,
    pub path: String,
    pub repository: String,
    pub deleted: bool,
    pub updated_at: String,
    pub versions: Vec<PathManifestVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathManifestVersion {
    pub version_id: String,
    pub sha512: Option<String>,
    pub created_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentManifest {
    pub repository: String,
    pub sha512: String,
    pub object_key: String,
    #[serde(rename = "ciphertext_offset", alias = "entry_offset")]
    pub ciphertext_offset: i64,
    pub cipher_len: i64,
    pub plain_len: i64,
    pub nonce_b64: String,
    pub created_at: String,
}
