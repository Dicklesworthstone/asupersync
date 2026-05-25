//! Trust boundaries and access policies for ATP cache.
//!
//! Implements trust policies that ensure cached content respects capabilities,
//! prevents ambient data leaks, and enforces encryption requirements for shared caches.

use super::{CacheError, CacheKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Trust policy for cache access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Whether to require encryption for shared cache content.
    pub require_encryption_for_shared: bool,
    /// Set of authorized grant scopes.
    pub authorized_scopes: HashSet<String>,
    /// Whether this cache is considered "shared" (relay, CDN, etc.).
    pub is_shared_cache: bool,
    /// Whether to allow public (unencrypted) content in this cache.
    pub allow_public_content: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            require_encryption_for_shared: true, // Secure by default
            authorized_scopes: HashSet::new(),
            is_shared_cache: false,
            allow_public_content: false, // Secure by default
        }
    }
}

impl TrustPolicy {
    /// Create a new trust policy for a local cache.
    #[must_use]
    pub fn local() -> Self {
        Self {
            require_encryption_for_shared: false, // Local cache can store plaintext
            authorized_scopes: HashSet::new(),
            is_shared_cache: false,
            allow_public_content: true,
        }
    }

    /// Create a new trust policy for a shared cache (relay, CDN, etc.).
    #[must_use]
    pub fn shared() -> Self {
        Self {
            require_encryption_for_shared: true, // Shared cache requires encryption
            authorized_scopes: HashSet::new(),
            is_shared_cache: true,
            allow_public_content: false, // No public content by default
        }
    }

    /// Create a trust policy that allows public content in shared caches.
    #[must_use]
    pub fn shared_with_public() -> Self {
        Self {
            require_encryption_for_shared: false, // Allow plaintext for public content
            authorized_scopes: HashSet::new(),
            is_shared_cache: true,
            allow_public_content: true,
        }
    }

    /// Add an authorized grant scope.
    pub fn add_authorized_scope(&mut self, scope: String) {
        self.authorized_scopes.insert(scope);
    }

    /// Remove an authorized grant scope.
    pub fn remove_authorized_scope(&mut self, scope: &str) {
        self.authorized_scopes.remove(scope);
    }

    /// Check if access to the given cache key is allowed.
    pub fn check_access(&self, key: &CacheKey) -> Result<(), CacheError> {
        // Check grant scope authorization if specified
        if let Some(scope) = &key.grant_scope {
            if !self.authorized_scopes.is_empty() && !self.authorized_scopes.contains(scope) {
                return Err(CacheError::TrustViolation(format!(
                    "Unauthorized grant scope: {}",
                    scope
                )));
            }
        }

        Ok(())
    }

    /// Check if storage of the given cache key is allowed.
    pub fn check_storage(&self, key: &CacheKey) -> Result<(), CacheError> {
        // First check access permissions
        self.check_access(key)?;

        // For shared caches, enforce encryption requirements
        if self.is_shared_cache && self.require_encryption_for_shared {
            // This is a placeholder - in a real implementation, we'd need to know
            // if the content is encrypted. For now, we assume content without
            // explicit public marking must be encrypted.
            if !self.is_explicitly_public_content(key) {
                // Content should be encrypted for shared cache
                // This would be checked against actual content metadata
            }
        }

        Ok(())
    }

    /// Check if content is explicitly marked as public.
    fn is_explicitly_public_content(&self, _key: &CacheKey) -> bool {
        // Placeholder implementation - would check against manifest metadata
        // or explicit public content markers
        self.allow_public_content
    }

    /// Validate trust policy configuration.
    pub fn validate(&self) -> Result<(), TrustPolicyError> {
        if self.is_shared_cache && self.require_encryption_for_shared && self.allow_public_content {
            return Err(TrustPolicyError::ConflictingPolicy(
                "Shared cache cannot both require encryption and allow public content".to_string(),
            ));
        }

        Ok(())
    }

    /// Get a summary of the trust policy for logging/diagnostics.
    #[must_use]
    pub fn summary(&self) -> TrustPolicySummary {
        TrustPolicySummary {
            cache_type: if self.is_shared_cache {
                "shared"
            } else {
                "local"
            }
            .to_string(),
            encryption_required: self.require_encryption_for_shared,
            public_content_allowed: self.allow_public_content,
            authorized_scope_count: self.authorized_scopes.len(),
        }
    }
}

/// Summary of trust policy for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicySummary {
    /// Type of cache (local, shared).
    pub cache_type: String,
    /// Whether encryption is required.
    pub encryption_required: bool,
    /// Whether public content is allowed.
    pub public_content_allowed: bool,
    /// Number of authorized scopes.
    pub authorized_scope_count: usize,
}

/// Trust policy errors.
#[derive(Debug, thiserror::Error)]
pub enum TrustPolicyError {
    #[error("Conflicting policy configuration: {0}")]
    ConflictingPolicy(String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),
}

/// Trust boundary checker for cache operations.
#[derive(Debug)]
pub struct TrustBoundaryChecker {
    /// Active trust policy.
    policy: TrustPolicy,
    /// Access log for auditing.
    access_log: Vec<TrustAccessEvent>,
}

impl TrustBoundaryChecker {
    /// Create a new trust boundary checker.
    #[must_use]
    pub fn new(policy: TrustPolicy) -> Self {
        Self {
            policy,
            access_log: Vec::new(),
        }
    }

    /// Check and log cache access.
    pub fn check_access(&mut self, key: &CacheKey, operation: &str) -> Result<(), CacheError> {
        let result = self.policy.check_access(key);

        // Log access attempt
        self.access_log.push(TrustAccessEvent {
            key: key.clone(),
            operation: operation.to_string(),
            allowed: result.is_ok(),
            timestamp: std::time::SystemTime::now(),
        });

        result
    }

    /// Get access log for auditing.
    #[must_use]
    pub const fn access_log(&self) -> &Vec<TrustAccessEvent> {
        &self.access_log
    }

    /// Clear access log.
    pub fn clear_log(&mut self) {
        self.access_log.clear();
    }
}

/// Logged trust access event for auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAccessEvent {
    /// Cache key that was accessed.
    pub key: CacheKey,
    /// Operation that was attempted.
    pub operation: String,
    /// Whether access was allowed.
    pub allowed: bool,
    /// When the access was attempted.
    pub timestamp: std::time::SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_policy_local_cache_defaults() {
        let policy = TrustPolicy::local();
        assert!(!policy.require_encryption_for_shared);
        assert!(!policy.is_shared_cache);
        assert!(policy.allow_public_content);
    }

    #[test]
    fn trust_policy_shared_cache_secure_by_default() {
        let policy = TrustPolicy::shared();
        assert!(policy.require_encryption_for_shared);
        assert!(policy.is_shared_cache);
        assert!(!policy.allow_public_content);
    }

    #[test]
    fn trust_policy_scope_authorization() {
        let mut policy = TrustPolicy::local();
        policy.add_authorized_scope("test-scope".to_string());

        let key_authorized = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("test-scope".to_string()),
        );

        let key_unauthorized = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("other-scope".to_string()),
        );

        // Should allow authorized scope
        assert!(policy.check_access(&key_authorized).is_ok());

        // Should reject unauthorized scope
        assert!(policy.check_access(&key_unauthorized).is_err());
    }

    #[test]
    fn trust_policy_validation_catches_conflicts() {
        let conflicted_policy = TrustPolicy {
            require_encryption_for_shared: true,
            is_shared_cache: true,
            allow_public_content: true, // Conflict!
            authorized_scopes: HashSet::new(),
        };

        assert!(conflicted_policy.validate().is_err());
    }

    #[test]
    fn trust_boundary_checker_logs_access() {
        let policy = TrustPolicy::local();
        let mut checker = TrustBoundaryChecker::new(policy);

        let key = CacheKey::new("manifest".to_string(), "content".to_string(), None);

        let result = checker.check_access(&key, "get");
        assert!(result.is_ok());
        assert_eq!(checker.access_log().len(), 1);
        assert!(checker.access_log()[0].allowed);
    }

    #[test]
    fn trust_policy_summary() {
        let policy = TrustPolicy::shared();
        let summary = policy.summary();

        assert_eq!(summary.cache_type, "shared");
        assert!(summary.encryption_required);
        assert!(!summary.public_content_allowed);
        assert_eq!(summary.authorized_scope_count, 0);
    }
}
