//! Resource scope definitions for ATP capabilities.

pub use crate::atp::object::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Normalized ATP resource path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpPath(pub String);

impl AtpPath {
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        if s.is_empty() || !s.starts_with('/') {
            return Err("path must be absolute and non-empty");
        }

        if s.contains('\\') {
            return Err("path must use forward slashes");
        }

        if s.len() > 1 && s.ends_with('/') {
            return Err("path must be normalized");
        }

        if s == "/" {
            return Ok(Self(s.to_string()));
        }

        for component in s.split('/').skip(1) {
            if component.is_empty() || component == "." || component == ".." {
                return Err("path must be normalized");
            }
        }

        Ok(Self(s.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_inbox_path(&self) -> bool {
        self.0 == "/inbox" || self.0.starts_with("/inbox/")
    }

    #[must_use]
    pub fn starts_with_team(&self, team: &str) -> bool {
        if team.is_empty() || team.contains('/') {
            return false;
        }

        let prefix = format!("/team/{team}");
        self.0 == prefix
            || self
                .0
                .strip_prefix(&prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
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
                let size_allowed = max_size_bytes.is_none_or(|max| size_bytes <= max);
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
        update_digest_tag(&mut hasher, b"asupersync.atp.ResourceScope.v2");

        match self {
            Self::Any => update_digest_tag(&mut hasher, b"variant.Any"),
            Self::Object(id) => {
                update_digest_tag(&mut hasher, b"variant.Object");
                update_digest_bytes(&mut hasher, b"object.hash", id.hash_bytes());
            }
            Self::Path(scope) => {
                update_digest_tag(&mut hasher, b"variant.Path");
                update_digest_bytes(&mut hasher, b"path.digest", &scope.digest());
            }
            Self::Inbox => update_digest_tag(&mut hasher, b"variant.Inbox"),
            Self::Team(team) => {
                update_digest_tag(&mut hasher, b"variant.Team");
                update_digest_bytes(&mut hasher, b"team", team.as_bytes());
            }
            Self::Relay { destinations } => {
                update_digest_tag(&mut hasher, b"variant.Relay");
                let mut sorted_destinations: Vec<_> = destinations.iter().collect();
                sorted_destinations.sort();
                update_digest_len(&mut hasher, b"destinations.len", sorted_destinations.len());
                for dest in sorted_destinations {
                    update_digest_bytes(&mut hasher, b"destination", dest.as_bytes());
                }
            }
            Self::Cache {
                object_types,
                max_size_bytes,
            } => {
                update_digest_tag(&mut hasher, b"variant.Cache");
                let mut sorted_types: Vec<_> = object_types.iter().collect();
                sorted_types.sort();
                update_digest_len(&mut hasher, b"object_types.len", sorted_types.len());
                for obj_type in sorted_types {
                    update_digest_bytes(&mut hasher, b"object_type", obj_type.as_bytes());
                }
                update_digest_option_u64(&mut hasher, b"max_size_bytes", *max_size_bytes);
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
        if self
            .exclusions
            .iter()
            .any(|exc| path_pattern_match(exc, path_str))
        {
            return false;
        }

        // Check pattern match
        if path_pattern_match(&self.pattern, path_str) {
            return true;
        }

        // If recursive, check if path is under a literal pattern. Wildcard
        // patterns are handled by path_pattern_match above.
        self.recursive
            && !contains_path_wildcard(&self.pattern)
            && path_is_same_or_descendant(&self.pattern, path_str)
    }

    /// Get a digest of this path scope.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        update_digest_tag(&mut hasher, b"asupersync.atp.PathScope.v2");
        update_digest_bytes(&mut hasher, b"pattern", self.pattern.as_bytes());
        update_digest_bool(&mut hasher, b"recursive", self.recursive);

        let mut sorted_exclusions: Vec<_> = self.exclusions.iter().collect();
        sorted_exclusions.sort();
        update_digest_len(&mut hasher, b"exclusions.len", sorted_exclusions.len());
        for exclusion in sorted_exclusions {
            update_digest_bytes(&mut hasher, b"exclusion", exclusion.as_bytes());
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
        self.max_transfer_size.is_none_or(|max| size <= max)
    }

    /// Check if bandwidth constraint is satisfied.
    #[must_use]
    pub fn check_bandwidth(&self, bytes_per_sec: u64) -> bool {
        self.max_bandwidth.is_none_or(|max| bytes_per_sec <= max)
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
                if start >= 24 || end > 24 {
                    return false;
                }

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

        update_digest_tag(&mut hasher, b"asupersync.atp.ScopeConstraints.v2");
        update_digest_option_u64(&mut hasher, b"max_transfer_size", self.max_transfer_size);
        update_digest_option_u64(&mut hasher, b"max_bandwidth", self.max_bandwidth);
        update_digest_option_bytes(
            &mut hasher,
            b"min_security_level",
            self.min_security_level.as_deref().map(str::as_bytes),
        );
        match &self.allowed_ips {
            Some(ips) => {
                update_digest_tag(&mut hasher, b"allowed_ips.some");
                let mut sorted_ips: Vec<_> = ips.iter().collect();
                sorted_ips.sort();
                update_digest_len(&mut hasher, b"allowed_ips.len", sorted_ips.len());
                for ip in sorted_ips {
                    update_digest_bytes(&mut hasher, b"allowed_ip", ip.as_bytes());
                }
            }
            None => update_digest_tag(&mut hasher, b"allowed_ips.none"),
        }
        match self.allowed_hours {
            Some((start, end)) => {
                update_digest_tag(&mut hasher, b"allowed_hours.some");
                let allowed_hours: [u8; 2] = (start, end).into();
                update_digest_bytes(&mut hasher, b"allowed_hours", &allowed_hours);
            }
            None => update_digest_tag(&mut hasher, b"allowed_hours.none"),
        }

        hasher.finalize().into()
    }
}

pub(crate) fn update_digest_tag(hasher: &mut impl sha2::Digest, tag: &[u8]) {
    update_digest_len_raw(hasher, tag.len());
    hasher.update(tag);
}

pub(crate) fn update_digest_bytes(hasher: &mut impl sha2::Digest, tag: &[u8], value: &[u8]) {
    update_digest_tag(hasher, tag);
    update_digest_len_raw(hasher, value.len());
    hasher.update(value);
}

pub(crate) fn update_digest_option_bytes(
    hasher: &mut impl sha2::Digest,
    tag: &[u8],
    value: Option<&[u8]>,
) {
    match value {
        Some(bytes) => {
            update_digest_tag(hasher, tag);
            update_digest_tag(hasher, b"some");
            update_digest_len_raw(hasher, bytes.len());
            hasher.update(bytes);
        }
        None => {
            update_digest_tag(hasher, tag);
            update_digest_tag(hasher, b"none");
        }
    }
}

pub(crate) fn update_digest_u64(hasher: &mut impl sha2::Digest, tag: &[u8], value: u64) {
    update_digest_bytes(hasher, tag, &value.to_le_bytes());
}

pub(crate) fn update_digest_option_u64(
    hasher: &mut impl sha2::Digest,
    tag: &[u8],
    value: Option<u64>,
) {
    match value {
        Some(value) => {
            update_digest_tag(hasher, tag);
            update_digest_tag(hasher, b"some");
            hasher.update(value.to_le_bytes());
        }
        None => {
            update_digest_tag(hasher, tag);
            update_digest_tag(hasher, b"none");
        }
    }
}

pub(crate) fn update_digest_bool(hasher: &mut impl sha2::Digest, tag: &[u8], value: bool) {
    update_digest_bytes(hasher, tag, &[u8::from(value)]);
}

pub(crate) fn update_digest_len(hasher: &mut impl sha2::Digest, tag: &[u8], len: usize) {
    update_digest_u64(hasher, tag, usize_to_u64_len(len));
}

fn update_digest_len_raw(hasher: &mut impl sha2::Digest, len: usize) {
    hasher.update(usize_to_u64_len(len).to_le_bytes());
}

fn usize_to_u64_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pattern_index, mut text_index) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_text_index = 0usize;

    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == text[text_index])
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            while pattern_index + 1 < pattern.len() && pattern[pattern_index + 1] == b'*' {
                pattern_index += 1;
            }
            star = Some(pattern_index);
            pattern_index += 1;
            star_text_index = text_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_text_index += 1;
            text_index = star_text_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

fn path_pattern_match(pattern: &str, path: &str) -> bool {
    let pattern = pattern.as_bytes();
    let path = path.as_bytes();
    let (mut pattern_index, mut path_index) = (0usize, 0usize);
    let mut star: Option<(usize, usize, bool)> = None;

    while path_index < path.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == path[path_index]
                || (pattern[pattern_index] == b'?' && path[path_index] != b'/'))
        {
            pattern_index += 1;
            path_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            let star_start = pattern_index;
            while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
                pattern_index += 1;
            }
            star = Some((pattern_index, path_index, pattern_index - star_start > 1));
        } else if let Some((next_pattern_index, next_path_index, recursive)) =
            advance_path_star(path, star)
        {
            pattern_index = next_pattern_index;
            path_index = next_path_index;
            star = Some((next_pattern_index, next_path_index, recursive));
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

fn advance_path_star(
    path: &[u8],
    star: Option<(usize, usize, bool)>,
) -> Option<(usize, usize, bool)> {
    let (next_pattern_index, path_index, recursive) = star?;
    if path_index >= path.len() || (!recursive && path[path_index] == b'/') {
        return None;
    }

    Some((next_pattern_index, path_index + 1, recursive))
}

fn contains_path_wildcard(pattern: &str) -> bool {
    pattern
        .as_bytes()
        .iter()
        .any(|byte| *byte == b'*' || *byte == b'?')
}

fn path_is_same_or_descendant(base: &str, path: &str) -> bool {
    if base == "/" {
        return path.starts_with('/');
    }

    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;

    fn string_set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn test_object_id(id: u32) -> ObjectId {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&id.to_le_bytes());
        ObjectId::content(ContentId::new(bytes))
    }

    #[test]
    fn resource_scope_object_coverage() {
        let object_id = test_object_id(1);
        let scope = ResourceScope::Object(object_id.clone());

        assert!(scope.covers_object(&object_id));
        assert!(!scope.covers_object(&test_object_id(2)));
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
    fn atp_path_rejects_non_normalized_logical_paths() {
        assert!(AtpPath::from_str("/").is_ok());
        assert!(AtpPath::from_str("/inbox/message").is_ok());

        for path in [
            "",
            "relative/path",
            "/data/./file",
            "/data/../file",
            "/data//file",
            "/data/file/",
            "/data\\file",
        ] {
            assert!(AtpPath::from_str(path).is_err(), "{path} should reject");
        }
    }

    #[test]
    fn path_scope_recursive_literal_respects_segment_boundaries() {
        let scope = PathScope::new("/data".to_string(), true);
        let root = AtpPath::from_str("/data").expect("path");
        let child = AtpPath::from_str("/data/file.txt").expect("path");
        let sibling_prefix = AtpPath::from_str("/database/file.txt").expect("path");

        assert!(scope.matches(&root));
        assert!(scope.matches(&child));
        assert!(!scope.matches(&sibling_prefix));
    }

    #[test]
    fn path_scope_single_star_does_not_cross_segments() {
        let scope = PathScope::new("/team/*/inbox/**".to_string(), false);
        let allowed = AtpPath::from_str("/team/alpha/inbox/a/b").expect("path");
        let too_deep = AtpPath::from_str("/team/alpha/beta/inbox/a").expect("path");

        assert!(scope.matches(&allowed));
        assert!(!scope.matches(&too_deep));
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
        let scope1 = ResourceScope::Object(test_object_id(1));
        let scope2 = ResourceScope::Object(test_object_id(1));
        let scope3 = ResourceScope::Object(test_object_id(2));

        assert_eq!(scope1.digest(), scope2.digest());
        assert_ne!(scope1.digest(), scope3.digest());
    }

    #[test]
    fn resource_scope_digest_frames_variable_length_sets() {
        let relay1 = ResourceScope::Relay {
            destinations: string_set(&["ab", "c"]),
        };
        let relay2 = ResourceScope::Relay {
            destinations: string_set(&["a", "bc"]),
        };

        assert_ne!(relay1.digest(), relay2.digest());

        let cache1 = ResourceScope::Cache {
            object_types: string_set(&["ab", "c"]),
            max_size_bytes: None,
        };
        let cache2 = ResourceScope::Cache {
            object_types: string_set(&["a", "bc"]),
            max_size_bytes: None,
        };

        assert_ne!(cache1.digest(), cache2.digest());
    }

    #[test]
    fn path_scope_digest_frames_exclusions() {
        let scope1 =
            PathScope::with_exclusions("/data/**".to_string(), true, string_set(&["/ab", "/c"]));
        let scope2 =
            PathScope::with_exclusions("/data/**".to_string(), true, string_set(&["/a", "/bc"]));

        assert_ne!(scope1.digest(), scope2.digest());
    }

    #[test]
    fn scope_constraints_digest_frames_options_and_fields() {
        let no_ip_constraint = ScopeConstraints::default();
        let deny_all_ips = ScopeConstraints {
            allowed_ips: Some(HashSet::new()),
            ..Default::default()
        };
        assert_ne!(no_ip_constraint.digest(), deny_all_ips.digest());

        let transfer = ScopeConstraints {
            max_transfer_size: Some(1),
            ..Default::default()
        };
        let bandwidth = ScopeConstraints {
            max_bandwidth: Some(1),
            ..Default::default()
        };
        assert_ne!(transfer.digest(), bandwidth.digest());
    }

    #[test]
    fn scope_constraints_invalid_allowed_hours_fail_closed() {
        let constraints = ScopeConstraints {
            allowed_hours: Some((24, 24)),
            ..Default::default()
        };

        assert!(!constraints.check_time_allowed());
    }

    #[test]
    fn glob_match_handles_multiple_wildcards_and_question_marks() {
        assert!(glob_match("/team/*/inbox/**", "/team/alpha/inbox/a/b"));
        assert!(glob_match("10.0.?.*", "10.0.1.42"));
        assert!(!glob_match("/team/*/inbox/**", "/team/alpha/outbox/a"));
    }
}
