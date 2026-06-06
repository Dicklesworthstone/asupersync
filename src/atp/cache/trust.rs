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
            // Security: When no scopes are authorized, only allow explicit public access
            if self.authorized_scopes.is_empty() {
                if scope != "public" && scope != "public-read" {
                    return Err(CacheError::TrustViolation(format!(
                        "No authorized scopes configured, only public content allowed. Requested scope: {}",
                        scope
                    )));
                }
            } else if !self.authorized_scopes.contains(scope) {
                return Err(CacheError::TrustViolation(format!(
                    "Unauthorized grant scope: {}",
                    scope
                )));
            }
        }

        Ok(())
    }

    /// Check if storage of the given cache key is allowed.
    pub fn check_storage(&self, key: &CacheKey, content_encrypted: bool) -> Result<(), CacheError> {
        // First check access permissions
        self.check_access(key)?;

        // For shared caches, enforce encryption requirements
        if self.is_shared_cache && self.require_encryption_for_shared {
            if key.grant_scope.is_none() {
                return Err(CacheError::TrustViolation(
                    "Shared cache storage requires an explicit grant scope".to_string(),
                ));
            }

            // Non-public content MUST be encrypted when stored in shared caches
            if !self.is_explicitly_public_content(key) && !content_encrypted {
                // Security: Reject storage of potentially unencrypted content in shared cache
                // Public content can be stored unencrypted, but private content must be encrypted
                // This prevents sensitive data leaks in shared cache environments
                return Err(CacheError::TrustViolation(format!(
                    "Private content requires encryption for shared cache. Grant scope: {:?}",
                    key.grant_scope
                )));
            }
        }

        Ok(())
    }

    /// Check if content is explicitly marked as public.
    fn is_explicitly_public_content(&self, key: &CacheKey) -> bool {
        // Only allow public content if the policy permits it
        if !self.allow_public_content {
            return false;
        }

        // Check if the grant scope explicitly indicates public content
        match &key.grant_scope {
            Some(scope) => {
                // Public content must have explicit "public" scope
                scope == "public" || scope == "public-read"
            }
            None => {
                // Content without scope is NOT considered explicitly public
                // This prevents privilege escalation via missing scope
                false
            }
        }
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
    /// Maximum number of access log entries to retain.
    max_log_entries: usize,
}

impl TrustBoundaryChecker {
    /// Default maximum number of access log entries.
    const DEFAULT_MAX_LOG_ENTRIES: usize = 1000;

    /// Create a new trust boundary checker with default log size limit.
    #[must_use]
    pub fn new(policy: TrustPolicy) -> Self {
        Self::with_max_log_entries(policy, Self::DEFAULT_MAX_LOG_ENTRIES)
    }

    /// Create a new trust boundary checker with custom log size limit.
    #[must_use]
    pub fn with_max_log_entries(policy: TrustPolicy, max_log_entries: usize) -> Self {
        Self {
            policy,
            access_log: Vec::new(),
            max_log_entries: max_log_entries.max(1), // Ensure at least 1 entry
        }
    }

    /// Check and log cache access.
    pub fn check_access(&mut self, key: &CacheKey, operation: &str) -> Result<(), CacheError> {
        let result = self.policy.check_access(key);

        // Log access attempt with bounded memory growth
        let event = TrustAccessEvent {
            key: key.clone(),
            operation: operation.to_string(),
            allowed: result.is_ok(),
            timestamp: std::time::SystemTime::now(),
        };

        // Ensure we don't exceed max_log_entries (FIFO eviction)
        if self.access_log.len() >= self.max_log_entries {
            // Remove oldest entry (front of Vec) to make room
            self.access_log.remove(0);
        }

        self.access_log.push(event);

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

    /// Get the maximum number of log entries allowed.
    #[must_use]
    pub const fn max_log_entries(&self) -> usize {
        self.max_log_entries
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

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
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
        assert_eq!(
            checker.max_log_entries(),
            TrustBoundaryChecker::DEFAULT_MAX_LOG_ENTRIES
        );
    }

    #[test]
    fn trust_boundary_checker_bounded_logging() {
        let policy = TrustPolicy::local();
        let mut checker = TrustBoundaryChecker::with_max_log_entries(policy, 3);

        let key1 = CacheKey::new("manifest1".to_string(), "content1".to_string(), None);
        let key2 = CacheKey::new("manifest2".to_string(), "content2".to_string(), None);
        let key3 = CacheKey::new("manifest3".to_string(), "content3".to_string(), None);
        let key4 = CacheKey::new("manifest4".to_string(), "content4".to_string(), None);

        // Add 3 entries (within limit)
        checker.check_access(&key1, "get").unwrap();
        checker.check_access(&key2, "put").unwrap();
        checker.check_access(&key3, "delete").unwrap();
        assert_eq!(checker.access_log().len(), 3);
        assert_eq!(checker.max_log_entries(), 3);

        // Verify the entries are in order
        assert_eq!(checker.access_log()[0].key.content_hash, "content1");
        assert_eq!(checker.access_log()[1].key.content_hash, "content2");
        assert_eq!(checker.access_log()[2].key.content_hash, "content3");

        // Add 4th entry - should evict oldest (FIFO)
        checker.check_access(&key4, "verify").unwrap();
        assert_eq!(checker.access_log().len(), 3); // Still capped at 3

        // First entry should be evicted, remaining entries shifted
        assert_eq!(checker.access_log()[0].key.content_hash, "content2");
        assert_eq!(checker.access_log()[1].key.content_hash, "content3");
        assert_eq!(checker.access_log()[2].key.content_hash, "content4");
    }

    #[test]
    fn trust_boundary_checker_custom_max_entries() {
        let policy = TrustPolicy::local();
        let mut checker = TrustBoundaryChecker::with_max_log_entries(policy, 100);

        assert_eq!(checker.max_log_entries(), 100);

        // Test minimum constraint (at least 1 entry)
        let policy2 = TrustPolicy::local();
        let checker2 = TrustBoundaryChecker::with_max_log_entries(policy2, 0);
        assert_eq!(checker2.max_log_entries(), 1);
    }

    #[test]
    fn trust_boundary_checker_clear_log_preserves_limit() {
        let policy = TrustPolicy::local();
        let mut checker = TrustBoundaryChecker::with_max_log_entries(policy, 5);

        let key = CacheKey::new("manifest".to_string(), "content".to_string(), None);

        // Add some entries
        for i in 0..3 {
            checker
                .check_access(&key, &format!("operation{}", i))
                .unwrap();
        }
        assert_eq!(checker.access_log().len(), 3);

        // Clear log
        checker.clear_log();
        assert_eq!(checker.access_log().len(), 0);
        assert_eq!(checker.max_log_entries(), 5); // Limit preserved

        // Add more entries - should respect original limit
        for i in 0..7 {
            checker
                .check_access(&key, &format!("operation{}", i))
                .unwrap();
        }
        assert_eq!(checker.access_log().len(), 5); // Capped at limit
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

    #[test]
    fn empty_authorized_scopes_security() {
        // Test trust policy with empty authorized scopes (default state)
        let policy = TrustPolicy::default(); // Has empty authorized_scopes

        // Public content should be allowed
        let public_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("public".to_string()),
        );
        assert!(policy.check_access(&public_key).is_ok());

        let public_read_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("public-read".to_string()),
        );
        assert!(policy.check_access(&public_read_key).is_ok());

        // Private scopes should be rejected when no scopes are authorized
        let private_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("private-scope".to_string()),
        );
        let result = policy.check_access(&private_key);
        assert!(result.is_err());
        assert!(matches!(result, Err(CacheError::TrustViolation(_))));

        // Content with no scope should be allowed (no scope check)
        let no_scope_key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert!(policy.check_access(&no_scope_key).is_ok());

        // When scopes ARE configured, they should be enforced
        let mut policy_with_scopes = TrustPolicy::default();
        policy_with_scopes.add_authorized_scope("allowed-scope".to_string());

        let allowed_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("allowed-scope".to_string()),
        );
        assert!(policy_with_scopes.check_access(&allowed_key).is_ok());

        let unauthorized_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("unauthorized-scope".to_string()),
        );
        let result = policy_with_scopes.check_access(&unauthorized_key);
        assert!(result.is_err());
        assert!(matches!(result, Err(CacheError::TrustViolation(_))));
    }

    #[test]
    fn shared_cache_encryption_validation() {
        // Test shared cache with encryption requirements
        let policy = TrustPolicy {
            is_shared_cache: true,
            require_encryption_for_shared: true,
            allow_public_content: true,
            ..TrustPolicy::default()
        };

        // Public content should be allowed (can be unencrypted)
        let public_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("public".to_string()),
        );
        assert!(policy.check_storage(&public_key, false).is_ok());

        // Private content should be rejected (requires encryption)
        let private_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("private".to_string()),
        );
        let result = policy.check_storage(&private_key, false);
        assert!(result.is_err());
        assert!(matches!(result, Err(CacheError::TrustViolation(_))));

        // Content with no scope should be rejected (requires encryption)
        let no_scope_key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        let result = policy.check_storage(&no_scope_key, false);
        assert!(result.is_err());
        assert!(matches!(result, Err(CacheError::TrustViolation(_))));
        let result = policy.check_storage(&no_scope_key, true);
        assert!(result.is_err());
        assert!(matches!(result, Err(CacheError::TrustViolation(_))));

        let mut scoped_policy = TrustPolicy {
            is_shared_cache: true,
            require_encryption_for_shared: true,
            allow_public_content: false,
            ..TrustPolicy::default()
        };
        scoped_policy.add_authorized_scope("private-encrypted".to_string());
        let encrypted_private_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("private-encrypted".to_string()),
        );
        assert!(
            scoped_policy
                .check_storage(&encrypted_private_key, true)
                .is_ok()
        );
        assert!(
            scoped_policy
                .check_storage(&encrypted_private_key, false)
                .is_err()
        );

        // Local cache should allow any content (no shared cache restrictions)
        let local_policy = TrustPolicy::local();
        assert!(local_policy.check_storage(&private_key, false).is_ok());
        assert!(local_policy.check_storage(&no_scope_key, false).is_ok());
    }

    #[test]
    fn is_explicitly_public_content_checks_cache_key() {
        let mut policy = TrustPolicy::shared();
        policy.allow_public_content = true;

        // Content with "public" scope should be considered public
        let public_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("public".to_string()),
        );
        assert!(policy.is_explicitly_public_content(&public_key));

        // Content with "public-read" scope should be considered public
        let public_read_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("public-read".to_string()),
        );
        assert!(policy.is_explicitly_public_content(&public_read_key));

        // Content with private scope should NOT be considered public
        let private_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("private".to_string()),
        );
        assert!(!policy.is_explicitly_public_content(&private_key));

        // Content with no scope should NOT be considered public
        let no_scope_key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert!(!policy.is_explicitly_public_content(&no_scope_key));

        // When global policy disallows public content, nothing should be public
        policy.allow_public_content = false;
        assert!(!policy.is_explicitly_public_content(&public_key));
    }
}
