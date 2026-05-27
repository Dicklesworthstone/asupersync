//! ATP seeding system for sharing verified content.
//!
//! Enables atpd to seed authorized manifests and provides verified chunks/objects
//! to other peers. Implements grant-based authorization, manifest verification,
//! and bandwidth/quota management for seeding operations.

use crate::atp::cache::{AtpCache, CacheError, CacheKey};
use crate::atp::identity::IdentityError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Seeding configuration for atpd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedingConfig {
    /// Whether seeding is enabled.
    pub enabled: bool,
    /// Maximum bandwidth for seeding (bytes per second).
    pub max_bandwidth_bytes_per_second: Option<u64>,
    /// Maximum storage quota for seeded content (bytes).
    pub max_storage_bytes: Option<u64>,
    /// Maximum number of concurrent seeding connections.
    pub max_concurrent_connections: Option<u32>,
    /// Authorized manifests that can be seeded.
    pub authorized_manifests: HashSet<String>,
    /// Seeding priority levels.
    pub priority_levels: Vec<SeedingPriority>,
    /// Whether to require explicit grants for seeding.
    pub require_explicit_grants: bool,
    /// Root directory for seeded content.
    pub seed_root: PathBuf,
}

impl Default for SeedingConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for security
            max_bandwidth_bytes_per_second: Some(10 * 1024 * 1024), // 10 MB/s
            max_storage_bytes: Some(1_073_741_824), // 1 GiB
            max_concurrent_connections: Some(10),
            authorized_manifests: HashSet::new(),
            priority_levels: vec![
                SeedingPriority::high(),
                SeedingPriority::normal(),
                SeedingPriority::low(),
            ],
            require_explicit_grants: true, // Secure by default
            seed_root: PathBuf::from("./seeds"),
        }
    }
}

/// Seeding priority configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedingPriority {
    /// Priority level name.
    pub name: String,
    /// Priority value (higher = more priority).
    pub priority: u32,
    /// Bandwidth allocation ratio (0.0 to 1.0).
    pub bandwidth_ratio: f64,
    /// Whether this priority level gets dedicated storage quota.
    pub dedicated_storage: bool,
}

impl SeedingPriority {
    /// Create a high priority configuration.
    #[must_use]
    pub fn high() -> Self {
        Self {
            name: "high".to_string(),
            priority: 100,
            bandwidth_ratio: 0.5, // 50% of bandwidth
            dedicated_storage: true,
        }
    }

    /// Create a normal priority configuration.
    #[must_use]
    pub fn normal() -> Self {
        Self {
            name: "normal".to_string(),
            priority: 50,
            bandwidth_ratio: 0.3, // 30% of bandwidth
            dedicated_storage: false,
        }
    }

    /// Create a low priority configuration.
    #[must_use]
    pub fn low() -> Self {
        Self {
            name: "low".to_string(),
            priority: 10,
            bandwidth_ratio: 0.2, // 20% of bandwidth
            dedicated_storage: false,
        }
    }
}

/// Manifest authorization for seeding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAuthorization {
    /// Manifest hash that is authorized.
    pub manifest_hash: String,
    /// Grant scope that authorizes seeding.
    pub grant_scope: String,
    /// When this authorization was created.
    pub created_at: SystemTime,
    /// When this authorization expires.
    pub expires_at: Option<SystemTime>,
    /// Priority level for this manifest.
    pub priority: String,
    /// Whether this manifest is actively being seeded.
    pub active: bool,
}

impl ManifestAuthorization {
    /// Create a new manifest authorization.
    #[must_use]
    pub fn new(manifest_hash: String, grant_scope: String, priority: String) -> Self {
        Self {
            manifest_hash,
            grant_scope,
            created_at: SystemTime::now(),
            expires_at: None,
            priority,
            active: true,
        }
    }

    /// Check if this authorization is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.active && self.expires_at.is_none_or(|exp| exp > SystemTime::now())
    }
}

/// ATP seeding service.
#[derive(Debug)]
pub struct AtpSeedingService {
    /// Seeding configuration.
    config: SeedingConfig,
    /// Cache for seeded content.
    cache: AtpCache,
    /// Authorized manifests for seeding.
    authorizations: HashMap<String, ManifestAuthorization>,
    /// Active seeding sessions.
    active_sessions: HashMap<String, SeedingSession>,
    /// Seeding metrics.
    metrics: SeedingMetrics,
}

impl AtpSeedingService {
    /// Create a new seeding service.
    pub fn new(config: SeedingConfig, cache: AtpCache) -> Self {
        Self {
            config,
            cache,
            authorizations: HashMap::new(),
            active_sessions: HashMap::new(),
            metrics: SeedingMetrics::default(),
        }
    }

    /// Add authorization to seed a manifest.
    pub fn authorize_manifest(
        &mut self,
        manifest_hash: String,
        grant_scope: String,
        priority: String,
    ) -> Result<(), SeedingError> {
        if !self.config.enabled {
            return Err(SeedingError::SeedingDisabled);
        }

        // Validate priority
        if !self
            .config
            .priority_levels
            .iter()
            .any(|p| p.name == priority)
        {
            return Err(SeedingError::InvalidPriority(priority));
        }

        let authorization =
            ManifestAuthorization::new(manifest_hash.clone(), grant_scope, priority);

        self.authorizations
            .insert(manifest_hash.clone(), authorization);
        self.config.authorized_manifests.insert(manifest_hash);

        Ok(())
    }

    /// Remove authorization for a manifest.
    pub fn revoke_manifest(&mut self, manifest_hash: &str) -> Result<(), SeedingError> {
        self.authorizations.remove(manifest_hash);
        self.config.authorized_manifests.remove(manifest_hash);

        // Stop any active sessions for this manifest
        self.active_sessions
            .retain(|_, session| session.manifest_hash != manifest_hash);

        Ok(())
    }

    /// Check if a manifest is authorized for seeding.
    #[must_use]
    pub fn is_authorized(&self, manifest_hash: &str) -> bool {
        if let Some(auth) = self.authorizations.get(manifest_hash) {
            auth.is_valid()
        } else {
            false
        }
    }

    /// Get seeded content if available and authorized.
    pub fn get_seeded_content(
        &mut self,
        manifest_hash: &str,
        content_hash: &str,
        requester_grants: &[String],
    ) -> Result<Option<Vec<u8>>, SeedingError> {
        // Check if manifest is authorized
        let auth = self
            .authorizations
            .get(manifest_hash)
            .ok_or_else(|| SeedingError::UnauthorizedManifest(manifest_hash.to_string()))?;

        if !auth.is_valid() {
            return Err(SeedingError::ExpiredAuthorization(
                manifest_hash.to_string(),
            ));
        }

        // Always check if requester has appropriate grants
        // Security: Grant verification cannot be bypassed, even when explicit grants are disabled
        if !requester_grants.contains(&auth.grant_scope) {
            // For explicitly public content, allow access without specific grants
            if auth.grant_scope != "public" && auth.grant_scope != "public-read" {
                return Err(SeedingError::InsufficientGrants(auth.grant_scope.clone()));
            }
        }

        // Try to get content from cache
        let cache_key = CacheKey::new(
            manifest_hash.to_string(),
            content_hash.to_string(),
            Some(auth.grant_scope.clone()),
        );

        match self.cache.get(&cache_key) {
            Ok(Some(content)) => {
                // Update seeding metrics
                self.metrics.chunks_served += 1;
                self.metrics.bytes_served += content.len() as u64;

                Ok(Some(content))
            }
            Ok(None) => Ok(None),
            Err(cache_error) => Err(SeedingError::CacheError(cache_error)),
        }
    }

    /// Add content to the seeding cache.
    pub fn add_seeded_content(
        &mut self,
        manifest_hash: &str,
        content_hash: &str,
        content: &[u8],
    ) -> Result<(), SeedingError> {
        // Check if manifest is authorized
        let auth = self
            .authorizations
            .get(manifest_hash)
            .ok_or_else(|| SeedingError::UnauthorizedManifest(manifest_hash.to_string()))?;

        if !auth.is_valid() {
            return Err(SeedingError::ExpiredAuthorization(
                manifest_hash.to_string(),
            ));
        }

        // Create cache key with grant scope
        let cache_key = CacheKey::new(
            manifest_hash.to_string(),
            content_hash.to_string(),
            Some(auth.grant_scope.clone()),
        );

        // Store in cache
        self.cache
            .put(cache_key, content)
            .map_err(SeedingError::CacheError)?;

        // Update metrics
        self.metrics.chunks_stored += 1;
        self.metrics.bytes_stored += content.len() as u64;

        Ok(())
    }

    /// Start a seeding session for a peer.
    pub fn start_session(
        &mut self,
        peer_id: String,
        manifest_hash: String,
        requester_grants: Vec<String>,
    ) -> Result<String, SeedingError> {
        if !self.config.enabled {
            return Err(SeedingError::SeedingDisabled);
        }

        // Check concurrent connection limit
        if let Some(max_conn) = self.config.max_concurrent_connections {
            if self.active_sessions.len() >= max_conn as usize {
                return Err(SeedingError::TooManyConnections);
            }
        }

        // Check authorization
        let auth = self
            .authorizations
            .get(&manifest_hash)
            .ok_or_else(|| SeedingError::UnauthorizedManifest(manifest_hash.clone()))?;

        if !auth.is_valid() {
            return Err(SeedingError::ExpiredAuthorization(manifest_hash));
        }

        // Always check grants - security cannot be bypassed via configuration
        if !requester_grants.contains(&auth.grant_scope) {
            // For explicitly public content, allow access without specific grants
            if auth.grant_scope != "public" && auth.grant_scope != "public-read" {
                return Err(SeedingError::InsufficientGrants(auth.grant_scope.clone()));
            }
        }

        // Create session
        let session_id = format!(
            "seed_{}_{}",
            peer_id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let session = SeedingSession {
            session_id: session_id.clone(),
            peer_id,
            manifest_hash,
            started_at: SystemTime::now(),
            bytes_sent: 0,
            chunks_sent: 0,
            priority: auth.priority.clone(),
        };

        self.active_sessions.insert(session_id.clone(), session);
        self.metrics.sessions_started += 1;

        Ok(session_id)
    }

    /// End a seeding session.
    pub fn end_session(&mut self, session_id: &str) -> Result<(), SeedingError> {
        if let Some(session) = self.active_sessions.remove(session_id) {
            // Update metrics
            self.metrics.sessions_completed += 1;
            self.metrics.total_session_duration +=
                session.started_at.elapsed().unwrap_or(Duration::ZERO);
        }

        Ok(())
    }

    /// Get current seeding metrics.
    #[must_use]
    pub const fn metrics(&self) -> &SeedingMetrics {
        &self.metrics
    }

    /// Get list of authorized manifests.
    #[must_use]
    pub fn authorized_manifests(&self) -> Vec<String> {
        self.authorizations.keys().cloned().collect()
    }
}

/// Active seeding session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedingSession {
    /// Unique session identifier.
    pub session_id: String,
    /// Peer receiving seeded content.
    pub peer_id: String,
    /// Manifest being seeded.
    pub manifest_hash: String,
    /// When the session started.
    pub started_at: SystemTime,
    /// Bytes sent in this session.
    pub bytes_sent: u64,
    /// Chunks sent in this session.
    pub chunks_sent: u64,
    /// Priority level for this session.
    pub priority: String,
}

/// Seeding metrics and statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SeedingMetrics {
    /// Number of chunks served.
    pub chunks_served: u64,
    /// Number of bytes served.
    pub bytes_served: u64,
    /// Number of chunks stored for seeding.
    pub chunks_stored: u64,
    /// Number of bytes stored for seeding.
    pub bytes_stored: u64,
    /// Number of seeding sessions started.
    pub sessions_started: u64,
    /// Number of seeding sessions completed.
    pub sessions_completed: u64,
    /// Total duration of all completed sessions.
    pub total_session_duration: Duration,
    /// Number of authorization failures.
    pub authorization_failures: u64,
}

/// Seeding operation errors.
#[derive(Debug, thiserror::Error)]
pub enum SeedingError {
    #[error("Seeding is disabled")]
    SeedingDisabled,

    #[error("Unauthorized manifest: {0}")]
    UnauthorizedManifest(String),

    #[error("Expired authorization for manifest: {0}")]
    ExpiredAuthorization(String),

    #[error("Insufficient grants: {0}")]
    InsufficientGrants(String),

    #[error("Invalid priority: {0}")]
    InvalidPriority(String),

    #[error("Too many concurrent connections")]
    TooManyConnections,

    #[error("Cache error: {0}")]
    CacheError(#[from] CacheError),

    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::cache::{AtpCache, CacheConfig};

    #[test]
    fn seeding_config_defaults() {
        let config = SeedingConfig::default();
        assert!(!config.enabled); // Should be disabled by default
        assert!(config.require_explicit_grants); // Should require grants by default
        assert_eq!(config.priority_levels.len(), 3);
    }

    #[test]
    fn seeding_priority_configurations() {
        let high = SeedingPriority::high();
        let normal = SeedingPriority::normal();
        let low = SeedingPriority::low();

        assert!(high.priority > normal.priority);
        assert!(normal.priority > low.priority);
        assert!(high.bandwidth_ratio > normal.bandwidth_ratio);
        assert!(normal.bandwidth_ratio > low.bandwidth_ratio);
    }

    #[test]
    fn manifest_authorization_validity() {
        let mut auth = ManifestAuthorization::new(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );

        assert!(auth.is_valid());

        // Set expiration in the past
        auth.expires_at = Some(SystemTime::UNIX_EPOCH);
        assert!(!auth.is_valid());

        // Deactivate
        auth.expires_at = None;
        auth.active = false;
        assert!(!auth.is_valid());
    }

    #[test]
    fn seeding_service_authorization() {
        let config = SeedingConfig {
            enabled: true,
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Should not be authorized initially
        assert!(!service.is_authorized("manifest123"));

        // Authorize manifest
        let result = service.authorize_manifest(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );
        assert!(result.is_ok());

        // Should now be authorized
        assert!(service.is_authorized("manifest123"));

        // Revoke authorization
        let result = service.revoke_manifest("manifest123");
        assert!(result.is_ok());
        assert!(!service.is_authorized("manifest123"));
    }

    #[test]
    fn seeding_service_disabled_by_default() {
        let config = SeedingConfig::default(); // Disabled by default
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Should fail when seeding is disabled
        let result = service.authorize_manifest(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );
        assert!(matches!(result, Err(SeedingError::SeedingDisabled)));
    }

    #[test]
    fn seeding_session_management() {
        let config = SeedingConfig {
            enabled: true,
            max_concurrent_connections: Some(2),
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Authorize a manifest first
        service
            .authorize_manifest(
                "manifest123".to_string(),
                "scope456".to_string(),
                "high".to_string(),
            )
            .unwrap();

        // Start session
        let session_id = service
            .start_session(
                "peer1".to_string(),
                "manifest123".to_string(),
                vec!["scope456".to_string()],
            )
            .unwrap();

        assert!(service.active_sessions.contains_key(&session_id));
        assert_eq!(service.metrics().sessions_started, 1);

        // End session
        service.end_session(&session_id).unwrap();
        assert!(!service.active_sessions.contains_key(&session_id));
        assert_eq!(service.metrics().sessions_completed, 1);
    }

    #[test]
    fn grant_verification_cannot_be_bypassed() {
        let config = SeedingConfig {
            enabled: true,
            require_explicit_grants: false, // Even when disabled, security should still work
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Authorize a manifest with private scope
        service
            .authorize_manifest(
                "manifest123".to_string(),
                "private-scope".to_string(),
                "high".to_string(),
            )
            .unwrap();

        // Try to access without proper grants - should be denied
        let result =
            service.get_seeded_content("manifest123", "content456", &["wrong-scope".to_string()]);
        assert!(matches!(result, Err(SeedingError::InsufficientGrants(_))));

        // Try to start session without proper grants - should be denied
        let result = service.start_session(
            "peer1".to_string(),
            "manifest123".to_string(),
            vec!["wrong-scope".to_string()],
        );
        assert!(matches!(result, Err(SeedingError::InsufficientGrants(_))));

        // Public content should still be accessible
        service
            .authorize_manifest(
                "public-manifest".to_string(),
                "public".to_string(),
                "high".to_string(),
            )
            .unwrap();

        let result =
            service.get_seeded_content("public-manifest", "content789", &["any-scope".to_string()]);
        // Should not fail due to grants (will fail due to missing cache content)
        assert!(matches!(
            result,
            Ok(None) | Err(SeedingError::CacheError(_))
        ));
    }
}
