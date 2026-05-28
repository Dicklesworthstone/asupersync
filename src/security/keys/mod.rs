//! Durable identity key storage for ATP peers.
//!
//! The store persists NKey user seeds with a small canonical JSON record. All
//! creation and rotation APIs take caller-provided entropy and timestamps so ATP
//! daemon code can keep randomness and clocks capability-explicit.

use nkeys::{KeyPair, KeyPairType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const KEY_STORE_SCHEMA_VERSION: u32 = 1;
const FINGERPRINT_DOMAIN: &[u8] = b"ATP-IDENTITY-KEY-FINGERPRINT-V1\0";
const MIN_SEED_DISTINCT_BYTES: usize = 8;
const MIN_SEED_HAMMING_WEIGHT: u32 = 8;
const MAX_SEED_HAMMING_WEIGHT: u32 = 248;

/// Stable fingerprint for a public identity key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyFingerprint([u8; 32]);

impl KeyFingerprint {
    /// Derive the canonical fingerprint from public key material.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, KeyStoreError> {
        if public_key.is_empty() {
            return Err(KeyStoreError::InvalidPublicKey(
                "public key material is empty".to_string(),
            ));
        }
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(KeyStoreError::InvalidPublicKey(
                "public key material is all zero".to_string(),
            ));
        }
        Ok(Self::from_public_key_unchecked(public_key))
    }

    fn from_public_key_unchecked(public_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update((public_key.len() as u64).to_be_bytes());
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }

    /// Decode a hex-encoded fingerprint.
    pub fn from_hex(encoded: &str) -> Result<Self, KeyStoreError> {
        let bytes = hex::decode(encoded).map_err(|err| {
            KeyStoreError::InvalidFingerprint(format!("fingerprint is not valid hex: {err}"))
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            KeyStoreError::InvalidFingerprint(format!(
                "fingerprint has {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        Ok(Self(bytes))
    }

    /// Return the canonical fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return the full lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Return a short diagnostic prefix.
    #[must_use]
    pub fn redacted(self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyFingerprint")
            .field(&self.redacted())
            .finish()
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Public view of an identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentityKey {
    /// Monotonic key generation.
    pub generation: u64,
    /// Public NKey value.
    pub public_key: String,
    /// Canonical public-key fingerprint.
    pub fingerprint: KeyFingerprint,
    /// Whether this generation has been revoked.
    pub revoked: bool,
}

/// Platform-specific key-file hardening strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStorePlatform {
    /// Unix-like hosts use owner-only `0600` key files.
    UnixOwnerOnly,
    /// Windows hosts require ACL hardening by the daemon installer.
    WindowsAclRequired,
    /// Other targets persist records with best-effort process ownership.
    BestEffort,
}

impl KeyStorePlatform {
    /// Return the strategy for the current compilation target.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(unix) {
            Self::UnixOwnerOnly
        } else if cfg!(windows) {
            Self::WindowsAclRequired
        } else {
            Self::BestEffort
        }
    }
}

/// Filesystem-backed ATP identity key store.
#[derive(Debug, Clone)]
pub struct IdentityKeyStore {
    path: PathBuf,
    record: KeyStoreRecord,
}

impl IdentityKeyStore {
    /// Create a new store with an initial active key.
    pub fn create(
        path: impl AsRef<Path>,
        seed_material: [u8; 32],
        created_at_micros: u64,
    ) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        if path.try_exists().map_err(|source| KeyStoreError::Io {
            path: path.clone(),
            source,
        })? {
            return Err(KeyStoreError::StoreAlreadyExists(path));
        }

        let record = KeyStoreRecord {
            schema_version: KEY_STORE_SCHEMA_VERSION,
            active_generation: 1,
            next_generation: 2,
            keys: vec![persisted_key(seed_material, 1, created_at_micros)?],
        };
        persist_record(&path, &record)?;
        Ok(Self { path, record })
    }

    /// Load an existing key store from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let text = fs::read_to_string(&path).map_err(|source| KeyStoreError::Io {
            path: path.clone(),
            source,
        })?;
        let record: KeyStoreRecord =
            serde_json::from_str(&text).map_err(|source| KeyStoreError::Json {
                path: path.clone(),
                source,
            })?;
        validate_record(&record)?;
        Ok(Self { path, record })
    }

    /// Return the backing store path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the platform hardening strategy used by this store.
    #[must_use]
    pub fn platform(&self) -> KeyStorePlatform {
        KeyStorePlatform::current()
    }

    /// Return the active generation number.
    #[must_use]
    pub const fn active_generation(&self) -> u64 {
        self.record.active_generation
    }

    /// Export the active public identity key.
    pub fn export_public(&self) -> Result<PublicIdentityKey, KeyStoreError> {
        let active = self.active_key_record()?;
        active.public_view()
    }

    /// Export every public key generation in deterministic order.
    pub fn export_public_history(&self) -> Result<Vec<PublicIdentityKey>, KeyStoreError> {
        self.record
            .keys
            .iter()
            .map(PersistedIdentityKey::public_view)
            .collect()
    }

    /// Return the active NKey key pair for signing.
    pub fn active_key_pair(&self) -> Result<KeyPair, KeyStoreError> {
        self.key_pair_for(self.active_key_record()?)
    }

    /// Rotate to a new active key generation.
    pub fn rotate(
        &mut self,
        seed_material: [u8; 32],
        created_at_micros: u64,
    ) -> Result<PublicIdentityKey, KeyStoreError> {
        let generation = self.record.next_generation;
        let key = persisted_key(seed_material, generation, created_at_micros)?;
        let fingerprint = KeyFingerprint::from_hex(&key.fingerprint)?;
        if self
            .record
            .keys
            .iter()
            .any(|existing| existing.fingerprint == key.fingerprint)
        {
            return Err(KeyStoreError::DuplicateFingerprint(fingerprint));
        }

        self.record.active_generation = generation;
        self.record.next_generation = generation
            .checked_add(1)
            .ok_or(KeyStoreError::GenerationOverflow)?;
        self.record.keys.push(key);
        validate_record(&self.record)?;
        persist_record(&self.path, &self.record)?;
        self.export_public()
    }

    /// Revoke a non-active key by fingerprint.
    pub fn revoke(
        &mut self,
        fingerprint: KeyFingerprint,
        revoked_at_micros: u64,
    ) -> Result<PublicIdentityKey, KeyStoreError> {
        let mut revoked = None;
        for key in &mut self.record.keys {
            if key.fingerprint == fingerprint.to_hex() {
                if key.generation == self.record.active_generation {
                    return Err(KeyStoreError::CannotRevokeActiveKey(fingerprint));
                }
                key.revoked = true;
                key.revoked_at_micros = Some(revoked_at_micros);
                revoked = Some(key.public_view()?);
                break;
            }
        }

        let revoked = revoked.ok_or(KeyStoreError::UnknownFingerprint(fingerprint))?;
        validate_record(&self.record)?;
        persist_record(&self.path, &self.record)?;
        Ok(revoked)
    }

    fn active_key_record(&self) -> Result<&PersistedIdentityKey, KeyStoreError> {
        let active = self
            .record
            .keys
            .iter()
            .find(|key| key.generation == self.record.active_generation)
            .ok_or(KeyStoreError::NoActiveKey)?;
        if active.revoked {
            return Err(KeyStoreError::ActiveKeyRevoked);
        }
        Ok(active)
    }

    fn key_pair_for(&self, key: &PersistedIdentityKey) -> Result<KeyPair, KeyStoreError> {
        let key_pair = KeyPair::from_seed(&key.seed).map_err(|err| {
            KeyStoreError::InvalidSeed(format!(
                "generation {} seed could not be decoded: {err}",
                key.generation
            ))
        })?;
        if key_pair.key_pair_type() != KeyPairType::User {
            return Err(KeyStoreError::InvalidSeed(format!(
                "generation {} is {:?}, expected User",
                key.generation,
                key_pair.key_pair_type()
            )));
        }
        if key_pair.public_key() != key.public_key {
            return Err(KeyStoreError::PublicKeyMismatch {
                generation: key.generation,
            });
        }
        Ok(key_pair)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyStoreRecord {
    schema_version: u32,
    active_generation: u64,
    next_generation: u64,
    keys: Vec<PersistedIdentityKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedIdentityKey {
    generation: u64,
    public_key: String,
    seed: String,
    fingerprint: String,
    created_at_micros: u64,
    revoked: bool,
    revoked_at_micros: Option<u64>,
}

impl PersistedIdentityKey {
    fn public_view(&self) -> Result<PublicIdentityKey, KeyStoreError> {
        Ok(PublicIdentityKey {
            generation: self.generation,
            public_key: self.public_key.clone(),
            fingerprint: KeyFingerprint::from_hex(&self.fingerprint)?,
            revoked: self.revoked,
        })
    }
}

/// Durable key-store failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// Filesystem operation failed.
    #[error("key store I/O failed for {}: {source}", path.display())]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing or serialization failed.
    #[error("key store JSON failed for {}: {source}", path.display())]
    Json {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Store creation would overwrite an existing record.
    #[error("key store already exists: {}", .0.display())]
    StoreAlreadyExists(PathBuf),
    /// Store path has no valid file name.
    #[error("invalid key store path: {}", .0.display())]
    InvalidStorePath(PathBuf),
    /// Persistent schema version is unsupported.
    #[error("unsupported key store schema version: {0}")]
    UnsupportedSchema(u32),
    /// Store contains no key generations.
    #[error("key store contains no key generations")]
    EmptyStore,
    /// Store has no usable active key.
    #[error("key store has no active key")]
    NoActiveKey,
    /// Active key was marked revoked.
    #[error("active key generation is revoked")]
    ActiveKeyRevoked,
    /// Active key cannot be revoked before rotation.
    #[error("cannot revoke active key {0}")]
    CannotRevokeActiveKey(KeyFingerprint),
    /// Requested fingerprint is not present.
    #[error("unknown key fingerprint: {0}")]
    UnknownFingerprint(KeyFingerprint),
    /// Rotation would reuse an existing key.
    #[error("duplicate key fingerprint: {0}")]
    DuplicateFingerprint(KeyFingerprint),
    /// Generation counter overflowed.
    #[error("key generation overflow")]
    GenerationOverflow,
    /// Caller-provided seed material was weak.
    #[error("weak identity seed: {0}")]
    WeakSeed(&'static str),
    /// Encoded seed was invalid.
    #[error("invalid identity seed: {0}")]
    InvalidSeed(String),
    /// Public key material was invalid.
    #[error("invalid public identity key: {0}")]
    InvalidPublicKey(String),
    /// Fingerprint encoding was invalid.
    #[error("invalid key fingerprint: {0}")]
    InvalidFingerprint(String),
    /// Stored public key did not match the stored seed.
    #[error("stored public key does not match seed for generation {generation}")]
    PublicKeyMismatch {
        /// Generation that failed validation.
        generation: u64,
    },
    /// Stored fingerprint did not match the public key.
    #[error("stored fingerprint does not match public key for generation {generation}")]
    FingerprintMismatch {
        /// Generation that failed validation.
        generation: u64,
    },
    /// Store has duplicate generations or fingerprints.
    #[error("duplicate key-store field: {0}")]
    DuplicateRecordField(&'static str),
}

fn persisted_key(
    seed_material: [u8; 32],
    generation: u64,
    created_at_micros: u64,
) -> Result<PersistedIdentityKey, KeyStoreError> {
    validate_seed_material(&seed_material)?;
    let key_pair = KeyPair::new_from_raw(KeyPairType::User, seed_material)
        .map_err(|err| KeyStoreError::InvalidSeed(err.to_string()))?;
    let seed = key_pair
        .seed()
        .map_err(|err| KeyStoreError::InvalidSeed(err.to_string()))?;
    let public_key = key_pair.public_key();
    validate_public_key(&public_key, generation)?;
    let fingerprint = KeyFingerprint::from_public_key(public_key.as_bytes())?.to_hex();

    Ok(PersistedIdentityKey {
        generation,
        public_key,
        seed,
        fingerprint,
        created_at_micros,
        revoked: false,
        revoked_at_micros: None,
    })
}

fn validate_seed_material(seed: &[u8; 32]) -> Result<(), KeyStoreError> {
    if seed.iter().all(|byte| *byte == 0) {
        return Err(KeyStoreError::WeakSeed("all-zero seed"));
    }

    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &byte in seed {
        let idx = byte as usize;
        if !seen[idx] {
            seen[idx] = true;
            distinct += 1;
        }
    }
    if distinct < MIN_SEED_DISTINCT_BYTES {
        return Err(KeyStoreError::WeakSeed("insufficient byte diversity"));
    }

    let hamming_weight: u32 = seed.iter().map(|byte| byte.count_ones()).sum();
    if !(MIN_SEED_HAMMING_WEIGHT..=MAX_SEED_HAMMING_WEIGHT).contains(&hamming_weight) {
        return Err(KeyStoreError::WeakSeed("extreme hamming weight"));
    }

    Ok(())
}

fn validate_record(record: &KeyStoreRecord) -> Result<(), KeyStoreError> {
    if record.schema_version != KEY_STORE_SCHEMA_VERSION {
        return Err(KeyStoreError::UnsupportedSchema(record.schema_version));
    }
    if record.keys.is_empty() {
        return Err(KeyStoreError::EmptyStore);
    }
    if record.next_generation <= record.active_generation {
        return Err(KeyStoreError::GenerationOverflow);
    }

    let mut generations = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut has_active = false;
    for key in &record.keys {
        if !generations.insert(key.generation) {
            return Err(KeyStoreError::DuplicateRecordField("generation"));
        }
        if !fingerprints.insert(key.fingerprint.clone()) {
            return Err(KeyStoreError::DuplicateRecordField("fingerprint"));
        }
        validate_public_key(&key.public_key, key.generation)?;
        let fingerprint = KeyFingerprint::from_public_key(key.public_key.as_bytes())?;
        if key.fingerprint != fingerprint.to_hex() {
            return Err(KeyStoreError::FingerprintMismatch {
                generation: key.generation,
            });
        }
        if key.generation == record.active_generation {
            has_active = true;
            if key.revoked {
                return Err(KeyStoreError::ActiveKeyRevoked);
            }
        }
        let key_pair = KeyPair::from_seed(&key.seed).map_err(|err| {
            KeyStoreError::InvalidSeed(format!(
                "generation {} seed could not be decoded: {err}",
                key.generation
            ))
        })?;
        if key_pair.key_pair_type() != KeyPairType::User {
            return Err(KeyStoreError::InvalidSeed(format!(
                "generation {} is {:?}, expected User",
                key.generation,
                key_pair.key_pair_type()
            )));
        }
        if key_pair.public_key() != key.public_key {
            return Err(KeyStoreError::PublicKeyMismatch {
                generation: key.generation,
            });
        }
    }

    if has_active {
        Ok(())
    } else {
        Err(KeyStoreError::NoActiveKey)
    }
}

fn validate_public_key(public_key: &str, generation: u64) -> Result<(), KeyStoreError> {
    KeyPair::from_public_key(public_key).map_err(|err| {
        KeyStoreError::InvalidPublicKey(format!(
            "generation {generation} public key could not be decoded: {err}"
        ))
    })?;
    KeyFingerprint::from_public_key(public_key.as_bytes())?;
    Ok(())
}

fn persist_record(path: &Path, record: &KeyStoreRecord) -> Result<(), KeyStoreError> {
    let parent = path.parent();
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|source| KeyStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let tmp_path = pending_path(path)?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|source| KeyStoreError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    write_key_file(&tmp_path, &bytes)?;
    fs::rename(&tmp_path, path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    harden_key_file(path)?;
    sync_parent_dir(parent);
    Ok(())
}

fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(b"\n").map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    harden_key_file(path)
}

fn pending_path(path: &Path) -> Result<PathBuf, KeyStoreError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| KeyStoreError::InvalidStorePath(path.to_path_buf()))?;
    let mut pending_name = file_name.to_os_string();
    pending_name.push(".pending");
    Ok(path.with_file_name(pending_name))
}

fn harden_key_file(path: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| KeyStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parent_dir(parent: Option<&Path>) {
    if let Some(parent) = parent {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn strong_seed(tag: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::security::keys::tests");
        hasher.update([tag]);
        hasher.finalize().into()
    }

    #[test]
    fn create_load_and_export_public_identity_key() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let store = IdentityKeyStore::create(&path, strong_seed(1), 100).expect("create store");
        let exported = store.export_public().expect("export public");

        assert_eq!(exported.generation, 1);
        assert!(!exported.revoked);
        assert_eq!(
            exported.fingerprint,
            KeyFingerprint::from_public_key(exported.public_key.as_bytes()).expect("fingerprint")
        );

        let loaded = IdentityKeyStore::load(&path).expect("load store");
        assert_eq!(loaded.export_public().unwrap(), exported);
        assert_eq!(loaded.platform(), KeyStorePlatform::current());
    }

    #[test]
    fn rotate_then_revoke_retired_generation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let mut store = IdentityKeyStore::create(&path, strong_seed(2), 100).expect("create store");
        let old = store.export_public().expect("old public");
        let new = store.rotate(strong_seed(3), 200).expect("rotate");

        assert_eq!(new.generation, 2);
        assert_ne!(old.fingerprint, new.fingerprint);
        assert_eq!(store.active_generation(), 2);

        let revoked = store.revoke(old.fingerprint, 300).expect("revoke old");
        assert!(revoked.revoked);
        assert_eq!(
            store.revoke(new.fingerprint, 400).unwrap_err().to_string(),
            format!("cannot revoke active key {}", new.fingerprint)
        );

        let loaded = IdentityKeyStore::load(&path).expect("load rotated store");
        let history = loaded.export_public_history().expect("history");
        assert_eq!(history.len(), 2);
        assert!(history[0].revoked);
        assert!(!history[1].revoked);
    }

    #[test]
    fn rejects_weak_seed_and_bad_public_key_material() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        assert!(matches!(
            IdentityKeyStore::create(&path, [0; 32], 100),
            Err(KeyStoreError::WeakSeed("all-zero seed"))
        ));
        assert!(matches!(
            KeyFingerprint::from_public_key(&[]),
            Err(KeyStoreError::InvalidPublicKey(_))
        ));
    }
}
