//! Resource scope definitions for ATP capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

// Placeholder types - replace with actual implementations when available
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    #[must_use]
    pub fn test(id: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&id.to_le_bytes());
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpPath(pub String);

impl AtpPath {
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        if s.is_empty() {
            Err("path cannot be empty")
        } else {
            Ok(Self(s.to_string()))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_inbox_path(&self) -> bool {
        self.0.starts_with("/inbox") || self.0.contains("inbox")
    }

    #[must_use]
    pub fn starts_with_team(&self, team: &str) -> bool {
        self.0.starts_with(&format!("/team/{team}")) || self.0.contains(team)
    }
}

/// Resource scope that a capability can cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceScope {
    /// Any resource (admin capability)
    Any,
    /// Specific object by ID
    Object(ObjectId),
    /// Path pattern (with wildcards)
    Path(PathScope),
    /// Inbox/mailbox access
    Inbox,
    /// Team/group resource access
    Team(String),
    /// Relay forwarding scope
    Relay {
        /// Allowed destination patterns
        destinations: HashSet<String>,
    },
    /// Cache/seeding scope
    Cache {
        /// Object types allowed to cache
        object_types: HashSet<String>,
        /// Size limits
        max_size_bytes: Option<u64>,
    },
}

impl ResourceScope {
    /// Check if this scope covers a specific object.
    #[must_use]
    pub fn covers_object(&self, object_id: &ObjectId) -> bool {
        match self {
            Self::Any => true,
            Self::Object(id) => id == object_id,
            Self::Path(_) => false, // Objects are not paths
            Self::Inbox | Self::Team(_) | Self::Relay { .. } | Self::Cache { .. } => false,
        }
    }

    /// Check if this scope covers a specific path.
    #[must_use]
    pub fn covers_path(&self, path: &AtpPath) -> bool {
        match self {
            Self::Any => true,
            Self::Object(_) => false, // Objects are not paths
            Self::Path(scope) => scope.matches(path),
            Self::Inbox => path.is_inbox_path(),
            Self::Team(team) => path.starts_with_team(team),
            Self::Relay { .. } | Self::Cache { .. } => false,
        }
    }

    /// Check if this scope covers relay operations to a destination.
    #[must_use]
    pub fn covers_relay(&self, destination: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Relay { destinations } => destinations
                .iter()
                .any(|pattern| glob_match(pattern, destination)),
            _ => false,
        }
    }

    /// Check if this scope covers cache operations.
    #[must_use]
    pub fn covers_cache(&self, object_type: &str, size_bytes: u64) -> bool {
        match self {
            Self::Any => true,
            Self::Cache {
                object_types,
                max_size_bytes,
            } => {
                let type_allowed = object_types.is_empty() || object_types.contains(object_type);
                let size_allowed = max_size_bytes.map_or(true, |max| size_bytes <= max);
                type_allowed && size_allowed
            }
            _ => false,
        }
    }

    /// Get a digest of this scope for policy derivation.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        match self {
            Self::Any => hasher.update(b"any"),
            Self::Object(id) => {
                hasher.update(b"object");
                hasher.update(id.as_bytes());
            }
            Self::Path(scope) => {
                hasher.update(b"path");
                hasher.update(&scope.digest());
            }
            Self::Inbox => hasher.update(b"inbox"),
            Self::Team(team) => {
                hasher.update(b"team");
                hasher.update(team.as_bytes());
            }
            Self::Relay { destinations } => {
                hasher.update(b"relay");
                let mut sorted_destinations: Vec<_> = destinations.iter().collect();
                sorted_destinations.sort();
                for dest in sorted_destinations {
                    hasher.update(dest.as_bytes());
                }
            }
            Self::Cache {
                object_types,
                max_size_bytes,
            } => {
                hasher.update(b"cache");
                let mut sorted_types: Vec<_> = object_types.iter().collect();
                sorted_types.sort();
                for obj_type in sorted_types {
                    hasher.update(obj_type.as_bytes());
                }
                if let Some(max_size) = max_size_bytes {
                    hasher.update(&max_size.to_le_bytes());
                }
            }
        }

        hasher.finalize().into()
    }
}

/// Path-based resource scope with pattern matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathScope {
    /// Path pattern (may include wildcards)
    pub pattern: String,
    /// Whether to allow subdirectories
    pub recursive: bool,
    /// Excluded paths (even if pattern matches)
    pub exclusions: HashSet<String>,
}

impl PathScope {
    /// Create a new path scope.
    #[must_use]
    pub fn new(pattern: String, recursive: bool) -> Self {
        Self {
            pattern,
            recursive,
            exclusions: HashSet::new(),
        }
    }

    /// Create a path scope with exclusions.
    #[must_use]
    pub fn with_exclusions(pattern: String, recursive: bool, exclusions: HashSet<String>) -> Self {
        Self {
            pattern,
            recursive,
            exclusions,
        }
    }

    /// Check if this scope matches a given path.
    #[must_use]
    pub fn matches(&self, path: &AtpPath) -> bool {
        let path_str = path.as_str();

        // Check exclusions first
        if self.exclusions.iter().any(|exc| glob_match(exc, path_str)) {
            return false;
        }

        // Check pattern match
        if glob_match(&self.pattern, path_str) {
            return true;
        }

        // If recursive, check if path is under pattern
        if self.recursive {
            let pattern_path = Path::new(&self.pattern);
            let check_path = Path::new(path_str);
            check_path.starts_with(pattern_path)
        } else {
            false
        }
    }

    /// Get a digest of this path scope.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.pattern.as_bytes());
        hasher.update(&[u8::from(self.recursive)]);

        let mut sorted_exclusions: Vec<_> = self.exclusions.iter().collect();
        sorted_exclusions.sort();
        for exclusion in sorted_exclusions {
            hasher.update(exclusion.as_bytes());
        }

        hasher.finalize().into()
    }
}

/// Additional constraints on capability scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScopeConstraints {
    /// Maximum transfer size per operation
    pub max_transfer_size: Option<u64>,
    /// Maximum bandwidth (bytes/sec)
    pub max_bandwidth: Option<u64>,
    /// Required security level
    pub min_security_level: Option<String>,
    /// IP address restrictions
    pub allowed_ips: Option<HashSet<String>>,
    /// Time-of-day restrictions
    pub allowed_hours: Option<(u8, u8)>, // (start_hour, end_hour) in UTC
}

impl ScopeConstraints {
    /// Check if transfer size constraint is satisfied.
    #[must_use]
    pub fn check_transfer_size(&self, size: u64) -> bool {
        self.max_transfer_size.map_or(true, |max| size <= max)
    }

    /// Check if bandwidth constraint is satisfied.
    #[must_use]
    pub fn check_bandwidth(&self, bytes_per_sec: u64) -> bool {
        self.max_bandwidth.map_or(true, |max| bytes_per_sec <= max)
    }

    /// Check if IP address is allowed.
    #[must_use]
    pub fn check_ip_allowed(&self, ip: &str) -> bool {
        match &self.allowed_ips {
            Some(ips) => ips.contains(ip) || ips.iter().any(|pattern| glob_match(pattern, ip)),
            None => true,
        }
    }

    /// Check if current time is within allowed hours.
    #[must_use]
    pub fn check_time_allowed(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        match self.allowed_hours {
            Some((start, end)) => {
                let now = SystemTime::now();
                let secs_since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let hour = ((secs_since_epoch / 3600) % 24) as u8;

                if start <= end {
                    hour >= start && hour < end
                } else {
                    // Wrap around midnight
                    hour >= start || hour < end
                }
            }
            None => true,
        }
    }

    /// Get a digest of these constraints.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        if let Some(max_size) = self.max_transfer_size {
            hasher.update(&max_size.to_le_bytes());
        }
        if let Some(max_bw) = self.max_bandwidth {
            hasher.update(&max_bw.to_le_bytes());
        }
        if let Some(ref level) = self.min_security_level {
            hasher.update(level.as_bytes());
        }
        if let Some(ref ips) = self.allowed_ips {
            let mut sorted_ips: Vec<_> = ips.iter().collect();
            sorted_ips.sort();
            for ip in sorted_ips {
                hasher.update(ip.as_bytes());
            }
        }
        if let Some((start, end)) = self.allowed_hours {
            hasher.update(&[start, end]);
        }

        hasher.finalize().into()
    }
}

/// Simple glob pattern matching for paths and IPs.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple implementation - for production would use proper glob library
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            text.starts_with(parts[0]) && text.ends_with(parts[1])
        } else {
            // More complex patterns - simplified for now
            pattern == "*" || pattern == text
        }
    } else {
        pattern == text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_scope_object_coverage() {
        let object_id = ObjectId::test(1);
        let scope = ResourceScope::Object(object_id.clone());

        assert!(scope.covers_object(&object_id));
        assert!(!scope.covers_object(&ObjectId::test(2)));
    }

    #[test]
    fn path_scope_pattern_matching() {
        let scope = PathScope::new("/data/**".to_string(), true);
        let path1 = AtpPath::from_str("/data/file.txt").expect("path");
        let path2 = AtpPath::from_str("/data/subdir/file.txt").expect("path");
        let path3 = AtpPath::from_str("/other/file.txt").expect("path");

        assert!(scope.matches(&path1));
        assert!(scope.matches(&path2));
        assert!(!scope.matches(&path3));
    }

    #[test]
    fn path_scope_exclusions() {
        let mut exclusions = HashSet::new();
        exclusions.insert("/data/secret/**".to_string());

        let scope = PathScope::with_exclusions("/data/**".to_string(), true, exclusions);
        let allowed = AtpPath::from_str("/data/public/file.txt").expect("path");
        let excluded = AtpPath::from_str("/data/secret/private.txt").expect("path");

        assert!(scope.matches(&allowed));
        assert!(!scope.matches(&excluded));
    }

    #[test]
    fn scope_constraints_validation() {
        let constraints = ScopeConstraints {
            max_transfer_size: Some(1024),
            max_bandwidth: Some(1000),
            allowed_hours: Some((9, 17)), // 9 AM to 5 PM UTC
            ..Default::default()
        };

        assert!(constraints.check_transfer_size(512));
        assert!(!constraints.check_transfer_size(2048));

        assert!(constraints.check_bandwidth(500));
        assert!(!constraints.check_bandwidth(2000));
    }

    #[test]
    fn resource_scope_digest_stability() {
        let scope1 = ResourceScope::Object(ObjectId::test(1));
        let scope2 = ResourceScope::Object(ObjectId::test(1));
        let scope3 = ResourceScope::Object(ObjectId::test(2));

        assert_eq!(scope1.digest(), scope2.digest());
        assert_ne!(scope1.digest(), scope3.digest());
    }
}
