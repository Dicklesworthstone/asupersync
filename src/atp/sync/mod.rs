//! Directory sync semantics for ATP object graphs.
//!
//! The model in this module is deliberately declarative. It builds manifests,
//! classifies differences, and emits dry-run-safe decisions plus proof records;
//! it does not mutate the local filesystem.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Stable schema for directory sync proof summaries.
pub const DIRECTORY_SYNC_PROOF_SCHEMA: &str = "asupersync.atp.directory-sync.proof.v1";

/// Stable schema for one directory sync log entry.
pub const DIRECTORY_SYNC_LOG_SCHEMA: &str = "asupersync.atp.directory-sync.log.v1";

/// Stable schema for directory early-usability reports.
pub const DIRECTORY_EARLY_USABILITY_SCHEMA: &str = "asupersync.atp.directory-early-usability.v1";

const TREE_ROOT_DOMAIN: &[u8] = b"asupersync.atp.directory-sync.tree-root.v1\0";

/// Platform path normalization rules used while building a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathNormalizationRules {
    /// Whether path comparison is case-sensitive.
    pub case_sensitive: bool,
    /// Whether backslashes are normalized to `/`.
    pub normalize_backslashes: bool,
    /// Whether Unicode normalization was applied before manifesting.
    pub unicode_normalized: bool,
    /// Whether absolute paths are rejected.
    pub reject_absolute_paths: bool,
}

impl Default for PathNormalizationRules {
    fn default() -> Self {
        Self {
            case_sensitive: true,
            normalize_backslashes: true,
            unicode_normalized: false,
            reject_absolute_paths: true,
        }
    }
}

/// Canonical relative path inside a directory manifest.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct DirectoryPath(String);

impl DirectoryPath {
    /// Normalize and validate a manifest-relative path.
    ///
    /// # Errors
    ///
    /// Returns [`DirectorySyncError`] when the path is empty, absolute,
    /// contains NUL bytes, traverses via `..`, or normalizes to the root.
    pub fn normalize(raw: &str, rules: PathNormalizationRules) -> Result<Self, DirectorySyncError> {
        if raw.is_empty() {
            return Err(DirectorySyncError::EmptyPath);
        }
        if raw.as_bytes().contains(&0) {
            return Err(DirectorySyncError::InvalidPath {
                path: raw.to_string(),
                reason: "nul byte",
            });
        }

        let normalized_separators = if rules.normalize_backslashes {
            raw.replace('\\', "/")
        } else {
            raw.to_string()
        };
        if rules.reject_absolute_paths
            && (normalized_separators.starts_with('/')
                || normalized_separators
                    .as_bytes()
                    .get(1)
                    .is_some_and(|byte| *byte == b':'))
        {
            return Err(DirectorySyncError::AbsolutePath(raw.to_string()));
        }

        let mut parts = Vec::new();
        for part in normalized_separators.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    return Err(DirectorySyncError::ParentTraversal(raw.to_string()));
                }
                clean => parts.push(clean),
            }
        }

        if parts.is_empty() {
            return Err(DirectorySyncError::RootPath);
        }

        Ok(Self(parts.join("/")))
    }

    /// Borrow the canonical relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the path key used for case-conflict detection.
    #[must_use]
    pub fn case_key(&self, rules: PathNormalizationRules) -> String {
        if rules.case_sensitive {
            self.0.clone()
        } else {
            self.0.to_lowercase()
        }
    }
}

impl fmt::Display for DirectoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Object kind represented by one directory manifest entry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DirectoryEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard-link reference when the source platform can expose one.
    HardLink,
    /// Sparse file with recorded sparse metadata.
    SparseFile,
}

impl DirectoryEntryKind {
    /// Stable kind code for logs and proof summaries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::HardLink => "hard_link",
            Self::SparseFile => "sparse_file",
        }
    }
}

/// Metadata caveat attached to an entry when platform semantics are lossy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MetadataCaveat {
    /// Unix mode bits are platform-specific.
    UnixPermissions,
    /// Windows attributes are platform-specific.
    WindowsAttributes,
    /// Timestamp precision or clock semantics are lossy.
    TimestampResolution,
    /// Symlink preservation depends on destination policy and platform support.
    SymlinkSupport,
    /// Hard links are not portable across all destinations.
    HardLinkSupport,
    /// Sparse extents are advisory metadata.
    SparseMetadata,
    /// Case-insensitive destinations may collapse distinct paths.
    CaseSensitivity,
    /// Path normalization changed the source spelling.
    PathNormalization,
}

impl MetadataCaveat {
    /// Stable caveat code for logs and proof summaries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnixPermissions => "unix_permissions",
            Self::WindowsAttributes => "windows_attributes",
            Self::TimestampResolution => "timestamp_resolution",
            Self::SymlinkSupport => "symlink_support",
            Self::HardLinkSupport => "hard_link_support",
            Self::SparseMetadata => "sparse_metadata",
            Self::CaseSensitivity => "case_sensitivity",
            Self::PathNormalization => "path_normalization",
        }
    }
}

/// Portable metadata recorded for one directory entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct DirectoryEntryMetadata {
    /// Content length for file-like entries.
    pub size_bytes: Option<u64>,
    /// Unix mode bits when policy records them.
    pub unix_mode: Option<u32>,
    /// Windows attribute bitset when policy records it.
    pub windows_attributes: Option<u32>,
    /// Modified time as Unix epoch microseconds when policy records it.
    pub modified_epoch_micros: Option<i64>,
    /// Symlink target as manifest-relative text when applicable.
    pub symlink_target: Option<String>,
    /// Stable hard-link group when applicable.
    pub hard_link_group: Option<String>,
    /// Sparse extent digest or summary when applicable.
    pub sparse_summary: Option<String>,
    /// Stable identity used to detect renames.
    pub stable_identity: Option<String>,
}

impl DirectoryEntryMetadata {
    /// Build metadata containing only a stable identity.
    #[must_use]
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            stable_identity: Some(identity.into()),
            ..Self::default()
        }
    }
}

/// One entry in a directory manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryManifestEntry {
    /// Canonical relative path.
    pub path: DirectoryPath,
    /// Entry kind.
    pub kind: DirectoryEntryKind,
    /// Optional content id or digest for file-like entries.
    pub content_id: Option<String>,
    /// Portable and platform-specific metadata.
    pub metadata: DirectoryEntryMetadata,
    /// Platform caveats attached to the metadata.
    pub caveats: BTreeSet<MetadataCaveat>,
}

impl DirectoryManifestEntry {
    /// Build one manifest entry.
    #[must_use]
    pub fn new(
        path: DirectoryPath,
        kind: DirectoryEntryKind,
        content_id: Option<String>,
        metadata: DirectoryEntryMetadata,
    ) -> Self {
        let mut caveats = BTreeSet::new();
        if metadata.unix_mode.is_some() {
            caveats.insert(MetadataCaveat::UnixPermissions);
        }
        if metadata.windows_attributes.is_some() {
            caveats.insert(MetadataCaveat::WindowsAttributes);
        }
        if metadata.modified_epoch_micros.is_some() {
            caveats.insert(MetadataCaveat::TimestampResolution);
        }
        if kind == DirectoryEntryKind::Symlink || metadata.symlink_target.is_some() {
            caveats.insert(MetadataCaveat::SymlinkSupport);
        }
        if kind == DirectoryEntryKind::HardLink || metadata.hard_link_group.is_some() {
            caveats.insert(MetadataCaveat::HardLinkSupport);
        }
        if kind == DirectoryEntryKind::SparseFile || metadata.sparse_summary.is_some() {
            caveats.insert(MetadataCaveat::SparseMetadata);
        }
        Self {
            path,
            kind,
            content_id,
            metadata,
            caveats,
        }
    }

    /// Return true when kind, content, and metadata match.
    #[must_use]
    pub fn semantically_matches(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.content_id == other.content_id
            && self.metadata == other.metadata
            && self.caveats == other.caveats
    }

    fn stable_identity(&self) -> Option<&str> {
        self.metadata
            .stable_identity
            .as_deref()
            .or(self.content_id.as_deref())
    }
}

/// Directory manifest with deterministic path ordering.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryManifest {
    /// Manifest entries keyed by canonical relative path.
    pub entries: BTreeMap<DirectoryPath, DirectoryManifestEntry>,
    /// Path normalization rules used to build this manifest.
    pub path_rules: PathNormalizationRules,
}

impl DirectoryManifest {
    /// Create an empty manifest.
    #[must_use]
    pub fn new(path_rules: PathNormalizationRules) -> Self {
        Self {
            entries: BTreeMap::new(),
            path_rules,
        }
    }

    /// Insert one manifest entry.
    ///
    /// # Errors
    ///
    /// Returns [`DirectorySyncError::DuplicatePath`] when the canonical path
    /// already exists.
    pub fn insert(&mut self, entry: DirectoryManifestEntry) -> Result<(), DirectorySyncError> {
        if self.entries.contains_key(&entry.path) {
            return Err(DirectorySyncError::DuplicatePath(entry.path));
        }
        self.entries.insert(entry.path.clone(), entry);
        Ok(())
    }

    /// Return case-insensitive collisions according to this manifest's rules.
    #[must_use]
    pub fn case_conflicts(&self) -> Vec<Vec<DirectoryPath>> {
        let mut groups: BTreeMap<String, Vec<DirectoryPath>> = BTreeMap::new();
        for path in self.entries.keys() {
            groups
                .entry(path.case_key(PathNormalizationRules {
                    case_sensitive: false,
                    ..self.path_rules
                }))
                .or_default()
                .push(path.clone());
        }
        groups
            .into_values()
            .filter(|paths| paths.len() > 1)
            .collect()
    }

    /// Compute a deterministic root over paths, entry kinds, content ids, and metadata.
    #[must_use]
    pub fn tree_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TREE_ROOT_DOMAIN);
        hasher.update([u8::from(self.path_rules.case_sensitive)]);
        for (path, entry) in &self.entries {
            hasher.update(path.as_str().as_bytes());
            hasher.update([0]);
            hasher.update(entry.kind.code().as_bytes());
            hasher.update([0]);
            if let Some(content_id) = &entry.content_id {
                hasher.update(content_id.as_bytes());
            }
            hasher.update([0]);
            hash_metadata(&mut hasher, &entry.metadata);
            for caveat in &entry.caveats {
                hasher.update(caveat.code().as_bytes());
                hasher.update([0]);
            }
        }
        hasher.finalize().into()
    }

    /// Build an early-usability report for verified directory metadata and small files.
    #[must_use]
    pub fn early_usability_report(
        &self,
        verified_content_ids: &BTreeSet<String>,
        policy: DirectoryEarlyUsabilityPolicy,
        final_commit_state: DirectoryFinalCommitState,
        replay_pointer: impl Into<String>,
    ) -> DirectoryEarlyUsabilityReport {
        let mut metadata_paths = Vec::new();
        let mut small_file_paths = Vec::new();
        let mut withheld_content_paths = Vec::new();
        let metadata_visible = policy.expose_metadata_before_final
            || final_commit_state == DirectoryFinalCommitState::Committed;

        let entries = self
            .entries
            .values()
            .map(|entry| {
                let exposure = early_entry_exposure(
                    entry,
                    verified_content_ids,
                    policy,
                    final_commit_state,
                    metadata_visible,
                );

                if exposure.metadata_visible {
                    metadata_paths.push(exposure.path.clone());
                }
                if exposure.content_visible {
                    small_file_paths.push(exposure.path.clone());
                } else if entry.content_id.is_some() {
                    withheld_content_paths.push(exposure.path.clone());
                }

                exposure
            })
            .collect::<Vec<_>>();

        let mut safety_caveats = Vec::new();
        if final_commit_state == DirectoryFinalCommitState::Pending {
            safety_caveats.push(
                "final directory commit not complete; expose early entries separately".into(),
            );
        }
        if !metadata_visible && !self.entries.is_empty() {
            safety_caveats
                .push("metadata exposure is disabled until final directory commit".into());
        }
        if !withheld_content_paths.is_empty() {
            safety_caveats.push(
                "some file content is withheld until verification or final commit policy allows it"
                    .into(),
            );
        }

        let usability_state = if final_commit_state == DirectoryFinalCommitState::Committed {
            DirectoryEarlyUsabilityState::FinalCommitted
        } else if !small_file_paths.is_empty() {
            DirectoryEarlyUsabilityState::SmallFilesAvailable
        } else if !metadata_paths.is_empty() {
            DirectoryEarlyUsabilityState::MetadataAvailable
        } else {
            DirectoryEarlyUsabilityState::NoEntries
        };

        DirectoryEarlyUsabilityReport {
            schema_version: DIRECTORY_EARLY_USABILITY_SCHEMA.to_string(),
            usability_state,
            final_commit_state,
            manifest_tree_root: hex::encode(self.tree_root()),
            replay_pointer: replay_pointer.into(),
            metadata_paths,
            small_file_paths,
            withheld_content_paths,
            entries,
            safety_caveats,
        }
    }
}

/// High-level directory operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectorySyncMode {
    /// Copy source entries into an empty or unrelated destination without deletes.
    SendOnly,
    /// Sync source changes while preserving unrelated destination entries.
    Sync,
    /// Make destination match source when destructive delete policy allows it.
    Mirror,
    /// Watch-mode semantics: report changes without implicit destructive action.
    Watch,
    /// Restore source state, quarantining conflicts by default.
    Restore,
}

/// Policy for entries present at destination but not in source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeletePolicy {
    /// Never plan a local delete.
    Never,
    /// Emit a tombstone/skip record but do not delete bytes.
    TombstoneOnly,
    /// Plan delete only when explicit destructive authorization is present.
    MirrorWhenExplicit,
}

/// Policy for conflicting destination entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConflictPolicy {
    /// Keep destination content and report a conflict.
    PreserveLocal,
    /// Move the destination entry into quarantine when explicitly authorized.
    Quarantine,
    /// Overwrite only when explicit destructive authorization is present.
    OverwriteWhenExplicit,
}

/// Policy for symlink entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SymlinkPolicy {
    /// Skip symlinks and record the reason.
    Skip,
    /// Preserve symlinks only when symlink authorization is explicit.
    PreserveAsLinkWhenExplicit,
    /// Materialize the symlink target only when explicitly authorized.
    MaterializeTargetWhenExplicit,
}

/// Policy for permission metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PermissionPolicy {
    /// Record permissions in manifests but do not change destination permissions.
    RecordOnly,
    /// Preserve read-only metadata without mode changes.
    PreserveReadonly,
    /// Apply mode changes only with explicit authorization.
    PreserveModeWhenExplicit,
}

/// Policy for rename detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RenamePolicy {
    /// Detect renames by stable identity or content id.
    DetectByStableIdentity,
    /// Treat moved entries as delete plus create.
    TreatAsDeleteCreate,
}

/// Explicit authorization gates for destructive or sensitive actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestructiveAuthorization {
    /// Whether deletes may execute.
    pub allow_delete: bool,
    /// Whether overwrites may execute.
    pub allow_overwrite: bool,
    /// Whether permission changes may execute.
    pub allow_permission_change: bool,
    /// Whether symlinks may be created or materialized.
    pub allow_symlink_materialization: bool,
    /// Whether decisions are dry-run only.
    pub dry_run: bool,
}

impl Default for DestructiveAuthorization {
    fn default() -> Self {
        Self {
            allow_delete: false,
            allow_overwrite: false,
            allow_permission_change: false,
            allow_symlink_materialization: false,
            dry_run: true,
        }
    }
}

impl DestructiveAuthorization {
    /// Authorization that permits mirror deletes but still exposes dry-run visibility.
    #[must_use]
    pub const fn explicit_mirror_apply() -> Self {
        Self {
            allow_delete: true,
            allow_overwrite: true,
            allow_permission_change: true,
            allow_symlink_materialization: true,
            dry_run: false,
        }
    }
}

/// Complete policy for planning a directory sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySyncPolicy {
    /// High-level sync mode.
    pub mode: DirectorySyncMode,
    /// Delete behavior.
    pub delete_policy: DeletePolicy,
    /// Conflict behavior.
    pub conflict_policy: ConflictPolicy,
    /// Symlink behavior.
    pub symlink_policy: SymlinkPolicy,
    /// Permission behavior.
    pub permission_policy: PermissionPolicy,
    /// Rename behavior.
    pub rename_policy: RenamePolicy,
    /// Explicit authorization gates.
    pub authorization: DestructiveAuthorization,
}

impl Default for DirectorySyncPolicy {
    fn default() -> Self {
        Self {
            mode: DirectorySyncMode::Sync,
            delete_policy: DeletePolicy::Never,
            conflict_policy: ConflictPolicy::PreserveLocal,
            symlink_policy: SymlinkPolicy::Skip,
            permission_policy: PermissionPolicy::RecordOnly,
            rename_policy: RenamePolicy::DetectByStableIdentity,
            authorization: DestructiveAuthorization::default(),
        }
    }
}

impl DirectorySyncPolicy {
    /// Conservative send-only policy.
    #[must_use]
    pub const fn send_only() -> Self {
        Self {
            mode: DirectorySyncMode::SendOnly,
            delete_policy: DeletePolicy::Never,
            conflict_policy: ConflictPolicy::PreserveLocal,
            symlink_policy: SymlinkPolicy::Skip,
            permission_policy: PermissionPolicy::RecordOnly,
            rename_policy: RenamePolicy::DetectByStableIdentity,
            authorization: DestructiveAuthorization {
                allow_delete: false,
                allow_overwrite: false,
                allow_permission_change: false,
                allow_symlink_materialization: false,
                dry_run: true,
            },
        }
    }

    /// Explicit mirror policy for dry-run or apply previews.
    #[must_use]
    pub const fn mirror_with_authorization(authorization: DestructiveAuthorization) -> Self {
        Self {
            mode: DirectorySyncMode::Mirror,
            delete_policy: DeletePolicy::MirrorWhenExplicit,
            conflict_policy: ConflictPolicy::OverwriteWhenExplicit,
            symlink_policy: SymlinkPolicy::PreserveAsLinkWhenExplicit,
            permission_policy: PermissionPolicy::PreserveModeWhenExplicit,
            rename_policy: RenamePolicy::DetectByStableIdentity,
            authorization,
        }
    }
}

/// Planned operation kind for one path.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DirectorySyncAction {
    /// Create a missing destination entry.
    Create,
    /// Update an existing destination entry.
    Update,
    /// Delete a destination entry absent from the source.
    Delete,
    /// Rename an existing destination entry to the source path.
    Rename,
    /// Preserve an existing destination entry.
    Preserve,
    /// Report an unresolved conflict.
    Conflict,
    /// Skip an unsupported or policy-denied entry.
    Skip,
    /// Quarantine a conflicting destination entry.
    Quarantine,
    /// Restore source metadata/content.
    Restore,
    /// Apply a permission-only change.
    PermissionChange,
    /// Create or materialize a symlink.
    SymlinkMaterialize,
}

impl DirectorySyncAction {
    /// Stable action code for logs and proof summaries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Rename => "rename",
            Self::Preserve => "preserve",
            Self::Conflict => "conflict",
            Self::Skip => "skip",
            Self::Quarantine => "quarantine",
            Self::Restore => "restore",
            Self::PermissionChange => "permission_change",
            Self::SymlinkMaterialize => "symlink_materialize",
        }
    }

    /// Whether the action can destroy or change existing destination state.
    #[must_use]
    pub const fn requires_explicit_authorization(self) -> bool {
        matches!(
            self,
            Self::Delete
                | Self::Update
                | Self::Quarantine
                | Self::Restore
                | Self::PermissionChange
                | Self::SymlinkMaterialize
        )
    }
}

/// One dry-run-visible decision for a path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySyncDecision {
    /// Destination/source path affected by the decision.
    pub path: DirectoryPath,
    /// Optional original path for rename decisions.
    pub from_path: Option<DirectoryPath>,
    /// Operation kind.
    pub action: DirectorySyncAction,
    /// Whether all required explicit authorization gates are present.
    pub authorized: bool,
    /// Whether the action would execute under current dry-run settings.
    pub would_apply: bool,
    /// Whether this decision is visible in dry-run/proof output.
    pub dry_run_visible: bool,
    /// Stable reason code.
    pub reason: String,
    /// Metadata caveats attached to the source/destination entry.
    pub caveats: BTreeSet<MetadataCaveat>,
}

impl DirectorySyncDecision {
    fn new(
        path: DirectoryPath,
        from_path: Option<DirectoryPath>,
        action: DirectorySyncAction,
        authorized: bool,
        dry_run: bool,
        reason: impl Into<String>,
        caveats: BTreeSet<MetadataCaveat>,
    ) -> Self {
        Self {
            path,
            from_path,
            action,
            authorized,
            would_apply: authorized && !dry_run,
            dry_run_visible: true,
            reason: reason.into(),
            caveats,
        }
    }
}

/// Structured log record for one directory sync decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySyncLogEntry {
    /// Stable log schema.
    pub schema_version: String,
    /// Path affected by this decision.
    pub path: String,
    /// Optional original path for renames.
    pub from_path: Option<String>,
    /// Operation code.
    pub action: String,
    /// Whether the action is authorized.
    pub authorized: bool,
    /// Whether the action would apply now.
    pub would_apply: bool,
    /// Stable reason code.
    pub reason: String,
    /// Caveat codes.
    pub caveats: Vec<String>,
}

/// Proof summary emitted by directory sync planning.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySyncProofSummary {
    /// Stable proof schema.
    pub schema_version: String,
    /// Sync mode used for the plan.
    pub mode: DirectorySyncMode,
    /// Policy tuple recorded for replay.
    pub metadata_policy: String,
    /// Whether every destructive decision is explicitly authorized.
    pub destructive_actions_authorized: bool,
    /// Paths skipped by policy.
    pub skipped_paths: Vec<String>,
    /// Conflict decisions recorded by path.
    pub conflict_decisions: Vec<String>,
    /// Destination tree root after applying executable decisions in the model.
    pub final_tree_root: String,
    /// Deterministic replay pointer for journal/proof bundles.
    pub replay_pointer: String,
}

/// Full directory sync plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectorySyncPlan {
    /// Decisions in deterministic path/action order.
    pub decisions: Vec<DirectorySyncDecision>,
    /// Structured logs.
    pub logs: Vec<DirectorySyncLogEntry>,
    /// Proof summary for replay and audit bundles.
    pub proof: DirectorySyncProofSummary,
}

/// Final commit state reported separately from directory early usability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectoryFinalCommitState {
    /// The directory manifest is still being assembled or verified.
    Pending,
    /// The final directory manifest has committed.
    Committed,
}

/// Usable-early state for a directory transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectoryEarlyUsabilityState {
    /// No entries are visible under the current policy.
    NoEntries,
    /// Verified metadata can be surfaced, but no file content is visible yet.
    MetadataAvailable,
    /// One or more verified small files can be surfaced before final commit.
    SmallFilesAvailable,
    /// The directory has reached final committed state.
    FinalCommitted,
}

/// Policy for surfacing directory entries before final commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryEarlyUsabilityPolicy {
    /// Largest regular file that may be exposed early when its content is verified.
    pub max_small_file_bytes: u64,
    /// Whether metadata may be exposed before final commit.
    pub expose_metadata_before_final: bool,
}

impl Default for DirectoryEarlyUsabilityPolicy {
    fn default() -> Self {
        Self {
            max_small_file_bytes: 1024 * 1024,
            expose_metadata_before_final: true,
        }
    }
}

impl DirectoryEarlyUsabilityPolicy {
    /// Build a policy that exposes verified files up to `max_small_file_bytes`.
    #[must_use]
    pub const fn small_files_up_to(max_small_file_bytes: u64) -> Self {
        Self {
            max_small_file_bytes,
            expose_metadata_before_final: true,
        }
    }
}

/// Per-entry early exposure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectoryEarlyEntryState {
    /// Only metadata is visible.
    MetadataOnly,
    /// Verified small-file content is visible.
    SmallFileContent,
    /// Metadata and content are withheld under the current policy.
    Withheld,
}

/// Early exposure decision for one directory entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryEarlyEntryExposure {
    /// Canonical manifest path.
    pub path: String,
    /// Entry kind.
    pub kind: DirectoryEntryKind,
    /// Whether metadata can be surfaced.
    pub metadata_visible: bool,
    /// Whether file content can be surfaced.
    pub content_visible: bool,
    /// Entry content identifier, if any.
    pub content_id: Option<String>,
    /// Entry size in bytes, if known.
    pub size_bytes: Option<u64>,
    /// Early exposure state.
    pub state: DirectoryEarlyEntryState,
    /// Stable reason for the decision.
    pub reason: String,
    /// Caveat codes callers must surface with this entry.
    pub caveats: Vec<String>,
}

/// Directory early-usability report for SDK/CLI/proof artifacts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryEarlyUsabilityReport {
    /// Stable report schema.
    pub schema_version: String,
    /// Current usable-early state.
    pub usability_state: DirectoryEarlyUsabilityState,
    /// Final commit state reported independently from early usability.
    pub final_commit_state: DirectoryFinalCommitState,
    /// Manifest tree root for replay and proof artifacts.
    pub manifest_tree_root: String,
    /// Deterministic replay pointer.
    pub replay_pointer: String,
    /// Paths whose metadata is visible.
    pub metadata_paths: Vec<String>,
    /// Paths whose verified small-file content is visible.
    pub small_file_paths: Vec<String>,
    /// Content-bearing paths withheld under the current policy.
    pub withheld_content_paths: Vec<String>,
    /// Per-entry exposure decisions.
    pub entries: Vec<DirectoryEarlyEntryExposure>,
    /// Safety caveats callers must show before early consumption.
    pub safety_caveats: Vec<String>,
}

fn early_entry_exposure(
    entry: &DirectoryManifestEntry,
    verified_content_ids: &BTreeSet<String>,
    policy: DirectoryEarlyUsabilityPolicy,
    final_commit_state: DirectoryFinalCommitState,
    metadata_visible: bool,
) -> DirectoryEarlyEntryExposure {
    let content_verified = entry
        .content_id
        .as_ref()
        .is_some_and(|content_id| verified_content_ids.contains(content_id))
        || final_commit_state == DirectoryFinalCommitState::Committed;
    let size = entry.metadata.size_bytes;
    let is_regular_file = entry.kind == DirectoryEntryKind::File;
    let is_small_file = size.is_some_and(|size| size <= policy.max_small_file_bytes);
    let content_visible = metadata_visible && is_regular_file && content_verified && is_small_file;

    let (state, reason) = if content_visible {
        (
            DirectoryEarlyEntryState::SmallFileContent,
            "verified_small_file",
        )
    } else if !metadata_visible {
        (
            DirectoryEarlyEntryState::Withheld,
            "metadata_withheld_until_final_commit",
        )
    } else if entry.content_id.is_none() {
        (
            DirectoryEarlyEntryState::MetadataOnly,
            "metadata_only_no_content_id",
        )
    } else if !is_regular_file {
        (
            DirectoryEarlyEntryState::MetadataOnly,
            "metadata_only_unsupported_content_kind",
        )
    } else if size.is_none() {
        (
            DirectoryEarlyEntryState::MetadataOnly,
            "metadata_only_unknown_size",
        )
    } else if !content_verified {
        (
            DirectoryEarlyEntryState::MetadataOnly,
            "metadata_only_content_not_verified",
        )
    } else {
        (
            DirectoryEarlyEntryState::MetadataOnly,
            "metadata_only_file_exceeds_small_file_policy",
        )
    };

    DirectoryEarlyEntryExposure {
        path: entry.path.to_string(),
        kind: entry.kind,
        metadata_visible,
        content_visible,
        content_id: entry.content_id.clone(),
        size_bytes: entry.metadata.size_bytes,
        state,
        reason: reason.to_string(),
        caveats: entry
            .caveats
            .iter()
            .map(|caveat| caveat.code().to_string())
            .collect(),
    }
}

/// Directory sync model errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectorySyncError {
    /// Path was empty.
    #[error("directory path is empty")]
    EmptyPath,
    /// Path normalized to the manifest root.
    #[error("directory path normalizes to root")]
    RootPath,
    /// Absolute path was rejected.
    #[error("absolute path rejected: {0}")]
    AbsolutePath(String),
    /// Parent traversal was rejected.
    #[error("parent traversal rejected: {0}")]
    ParentTraversal(String),
    /// Path was invalid for the given rules.
    #[error("invalid path {path}: {reason}")]
    InvalidPath {
        /// Raw path.
        path: String,
        /// Stable reason.
        reason: &'static str,
    },
    /// Duplicate canonical path.
    #[error("duplicate manifest path: {0}")]
    DuplicatePath(DirectoryPath),
}

/// Plan a directory sync without mutating the filesystem.
#[must_use]
pub fn plan_directory_sync(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    policy: DirectorySyncPolicy,
) -> DirectorySyncPlan {
    let mut decisions = Vec::new();
    let mut renamed_from_paths = BTreeSet::new();
    let destination_by_identity = identity_index(destination);
    let source_paths = source.entries.keys().cloned().collect::<BTreeSet<_>>();

    append_case_conflict_decisions(source, destination, policy, &mut decisions);
    append_identity_conflict_decisions(source, destination, policy, &mut decisions);

    for (path, source_entry) in &source.entries {
        if source_entry.kind == DirectoryEntryKind::Symlink {
            append_symlink_decision(
                source_entry,
                destination.entries.get(path),
                policy,
                &mut decisions,
            );
            continue;
        }

        match destination.entries.get(path) {
            Some(destination_entry) if source_entry.semantically_matches(destination_entry) => {
                decisions.push(decision(
                    path.clone(),
                    None,
                    DirectorySyncAction::Preserve,
                    policy,
                    "already_matches",
                    source_entry.caveats.clone(),
                ));
            }
            Some(destination_entry) => {
                append_existing_path_decision(
                    source_entry,
                    destination_entry,
                    policy,
                    &mut decisions,
                );
            }
            None => {
                if let Some(from_path) = detect_rename(
                    source_entry,
                    &destination_by_identity,
                    &source_paths,
                    policy,
                ) {
                    renamed_from_paths.insert(from_path.clone());
                    decisions.push(decision(
                        path.clone(),
                        Some(from_path),
                        DirectorySyncAction::Rename,
                        policy,
                        "stable_identity_rename",
                        source_entry.caveats.clone(),
                    ));
                } else {
                    decisions.push(decision(
                        path.clone(),
                        None,
                        create_or_restore_action(policy),
                        policy,
                        "missing_destination_entry",
                        source_entry.caveats.clone(),
                    ));
                }
            }
        }
    }

    for (path, destination_entry) in &destination.entries {
        if source.entries.contains_key(path) || renamed_from_paths.contains(path) {
            continue;
        }
        decisions.push(delete_or_preserve_decision(path, destination_entry, policy));
    }

    decisions.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.action.cmp(&right.action))
            .then(left.from_path.cmp(&right.from_path))
    });
    let logs = decisions.iter().map(log_entry).collect::<Vec<_>>();
    let proof = proof_summary(source, destination, policy, &decisions);

    DirectorySyncPlan {
        decisions,
        logs,
        proof,
    }
}

fn append_case_conflict_decisions(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    policy: DirectorySyncPolicy,
    decisions: &mut Vec<DirectorySyncDecision>,
) {
    for group in source
        .case_conflicts()
        .into_iter()
        .chain(destination.case_conflicts())
    {
        for path in group {
            decisions.push(decision(
                path,
                None,
                DirectorySyncAction::Conflict,
                policy,
                "case_conflict",
                BTreeSet::from([MetadataCaveat::CaseSensitivity]),
            ));
        }
    }
}

fn append_identity_conflict_decisions(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    policy: DirectorySyncPolicy,
    decisions: &mut Vec<DirectorySyncDecision>,
) {
    let mut conflicted_paths = identity_conflicts(source);
    conflicted_paths.extend(identity_conflicts(destination));

    for path in conflicted_paths {
        decisions.push(decision(
            path,
            None,
            DirectorySyncAction::Conflict,
            policy,
            "stable_identity_conflict",
            BTreeSet::new(),
        ));
    }
}

fn append_symlink_decision(
    source_entry: &DirectoryManifestEntry,
    destination_entry: Option<&DirectoryManifestEntry>,
    policy: DirectorySyncPolicy,
    decisions: &mut Vec<DirectorySyncDecision>,
) {
    let action = match policy.symlink_policy {
        SymlinkPolicy::Skip => DirectorySyncAction::Skip,
        SymlinkPolicy::PreserveAsLinkWhenExplicit
        | SymlinkPolicy::MaterializeTargetWhenExplicit => DirectorySyncAction::SymlinkMaterialize,
    };
    let reason = if destination_entry.is_some_and(|entry| entry.semantically_matches(source_entry))
    {
        "symlink_already_matches"
    } else if action == DirectorySyncAction::Skip {
        "symlink_policy_skip"
    } else {
        "symlink_requires_explicit_policy"
    };
    decisions.push(decision(
        source_entry.path.clone(),
        None,
        action,
        policy,
        reason,
        source_entry.caveats.clone(),
    ));
}

fn append_existing_path_decision(
    source_entry: &DirectoryManifestEntry,
    destination_entry: &DirectoryManifestEntry,
    policy: DirectorySyncPolicy,
    decisions: &mut Vec<DirectorySyncDecision>,
) {
    if permissions_differ(source_entry, destination_entry)
        && content_and_kind_match(source_entry, destination_entry)
    {
        decisions.push(decision(
            source_entry.path.clone(),
            None,
            DirectorySyncAction::PermissionChange,
            policy,
            "metadata_permission_delta",
            source_entry.caveats.clone(),
        ));
        return;
    }

    let action = match policy.conflict_policy {
        ConflictPolicy::PreserveLocal => DirectorySyncAction::Conflict,
        ConflictPolicy::Quarantine => DirectorySyncAction::Quarantine,
        ConflictPolicy::OverwriteWhenExplicit => match policy.mode {
            DirectorySyncMode::Restore => DirectorySyncAction::Restore,
            _ => DirectorySyncAction::Update,
        },
    };
    decisions.push(decision(
        source_entry.path.clone(),
        None,
        action,
        policy,
        "destination_differs",
        source_entry.caveats.clone(),
    ));
}

fn delete_or_preserve_decision(
    path: &DirectoryPath,
    destination_entry: &DirectoryManifestEntry,
    policy: DirectorySyncPolicy,
) -> DirectorySyncDecision {
    let (action, reason) = match (policy.mode, policy.delete_policy) {
        (DirectorySyncMode::Mirror, DeletePolicy::MirrorWhenExplicit) => {
            (DirectorySyncAction::Delete, "mirror_delete")
        }
        (_, DeletePolicy::TombstoneOnly) => (DirectorySyncAction::Skip, "tombstone_only_delete"),
        _ => (DirectorySyncAction::Preserve, "delete_not_allowed"),
    };
    decision(
        path.clone(),
        None,
        action,
        policy,
        reason,
        destination_entry.caveats.clone(),
    )
}

fn decision(
    path: DirectoryPath,
    from_path: Option<DirectoryPath>,
    action: DirectorySyncAction,
    policy: DirectorySyncPolicy,
    reason: impl Into<String>,
    caveats: BTreeSet<MetadataCaveat>,
) -> DirectorySyncDecision {
    DirectorySyncDecision::new(
        path,
        from_path,
        action,
        action_authorized(action, policy),
        policy.authorization.dry_run,
        reason,
        caveats,
    )
}

fn action_authorized(action: DirectorySyncAction, policy: DirectorySyncPolicy) -> bool {
    match action {
        DirectorySyncAction::Delete => {
            policy.delete_policy == DeletePolicy::MirrorWhenExplicit
                && policy.authorization.allow_delete
        }
        DirectorySyncAction::Update | DirectorySyncAction::Restore => {
            policy.conflict_policy == ConflictPolicy::OverwriteWhenExplicit
                && policy.authorization.allow_overwrite
        }
        DirectorySyncAction::Quarantine => {
            policy.conflict_policy == ConflictPolicy::Quarantine
                && policy.authorization.allow_overwrite
        }
        DirectorySyncAction::PermissionChange => {
            policy.permission_policy == PermissionPolicy::PreserveModeWhenExplicit
                && policy.authorization.allow_permission_change
        }
        DirectorySyncAction::SymlinkMaterialize => {
            policy.symlink_policy != SymlinkPolicy::Skip
                && policy.authorization.allow_symlink_materialization
        }
        DirectorySyncAction::Create
        | DirectorySyncAction::Rename
        | DirectorySyncAction::Preserve
        | DirectorySyncAction::Conflict
        | DirectorySyncAction::Skip => true,
    }
}

fn create_or_restore_action(policy: DirectorySyncPolicy) -> DirectorySyncAction {
    match policy.mode {
        DirectorySyncMode::Restore => DirectorySyncAction::Restore,
        _ => DirectorySyncAction::Create,
    }
}

fn identity_index(manifest: &DirectoryManifest) -> BTreeMap<String, DirectoryPath> {
    identity_groups(manifest)
        .into_iter()
        .filter_map(|(identity, paths)| {
            if paths.len() == 1 {
                paths.into_iter().next().map(|path| (identity, path))
            } else {
                None
            }
        })
        .collect()
}

fn identity_conflicts(manifest: &DirectoryManifest) -> BTreeSet<DirectoryPath> {
    identity_groups(manifest)
        .into_values()
        .filter(|paths| paths.len() > 1)
        .flatten()
        .collect()
}

fn identity_groups(manifest: &DirectoryManifest) -> BTreeMap<String, Vec<DirectoryPath>> {
    let mut groups = BTreeMap::new();
    for (path, entry) in &manifest.entries {
        if let Some(identity) = entry.stable_identity() {
            groups
                .entry(identity.to_string())
                .or_insert_with(Vec::new)
                .push(path.clone());
        }
    }
    groups
}

fn detect_rename(
    source_entry: &DirectoryManifestEntry,
    destination_by_identity: &BTreeMap<String, DirectoryPath>,
    source_paths: &BTreeSet<DirectoryPath>,
    policy: DirectorySyncPolicy,
) -> Option<DirectoryPath> {
    if policy.rename_policy != RenamePolicy::DetectByStableIdentity {
        return None;
    }
    let identity = source_entry.stable_identity()?;
    let destination_path = destination_by_identity.get(identity)?;
    (!source_paths.contains(destination_path)).then(|| destination_path.clone())
}

fn permissions_differ(
    source_entry: &DirectoryManifestEntry,
    destination_entry: &DirectoryManifestEntry,
) -> bool {
    source_entry.metadata.unix_mode != destination_entry.metadata.unix_mode
        || source_entry.metadata.windows_attributes != destination_entry.metadata.windows_attributes
}

fn content_and_kind_match(
    source_entry: &DirectoryManifestEntry,
    destination_entry: &DirectoryManifestEntry,
) -> bool {
    source_entry.kind == destination_entry.kind
        && source_entry.content_id == destination_entry.content_id
}

fn log_entry(decision: &DirectorySyncDecision) -> DirectorySyncLogEntry {
    DirectorySyncLogEntry {
        schema_version: DIRECTORY_SYNC_LOG_SCHEMA.to_string(),
        path: decision.path.to_string(),
        from_path: decision.from_path.as_ref().map(ToString::to_string),
        action: decision.action.code().to_string(),
        authorized: decision.authorized,
        would_apply: decision.would_apply,
        reason: decision.reason.clone(),
        caveats: decision
            .caveats
            .iter()
            .map(|caveat| caveat.code().to_string())
            .collect(),
    }
}

fn proof_summary(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    policy: DirectorySyncPolicy,
    decisions: &[DirectorySyncDecision],
) -> DirectorySyncProofSummary {
    let destructive_actions_authorized = decisions
        .iter()
        .filter(|decision| decision.action.requires_explicit_authorization())
        .all(|decision| decision.authorized && decision.dry_run_visible);
    let skipped_paths = decisions
        .iter()
        .filter(|decision| decision.action == DirectorySyncAction::Skip)
        .map(|decision| decision.path.to_string())
        .collect();
    let conflict_decisions = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.action,
                DirectorySyncAction::Conflict | DirectorySyncAction::Quarantine
            )
        })
        .map(|decision| format!("{}:{}", decision.path, decision.reason))
        .collect();

    DirectorySyncProofSummary {
        schema_version: DIRECTORY_SYNC_PROOF_SCHEMA.to_string(),
        mode: policy.mode,
        metadata_policy: metadata_policy_code(policy),
        destructive_actions_authorized,
        skipped_paths,
        conflict_decisions,
        final_tree_root: hex::encode(projected_tree_root(source, destination, decisions)),
        replay_pointer: replay_pointer(source, destination, decisions),
    }
}

fn metadata_policy_code(policy: DirectorySyncPolicy) -> String {
    format!(
        "delete={:?};conflict={:?};symlink={:?};permission={:?};rename={:?};dry_run={}",
        policy.delete_policy,
        policy.conflict_policy,
        policy.symlink_policy,
        policy.permission_policy,
        policy.rename_policy,
        policy.authorization.dry_run
    )
}

fn projected_tree_root(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    decisions: &[DirectorySyncDecision],
) -> [u8; 32] {
    let mut projected = destination.clone();
    for decision in decisions {
        if !decision.would_apply {
            continue;
        }
        match decision.action {
            DirectorySyncAction::Create
            | DirectorySyncAction::Update
            | DirectorySyncAction::Restore
            | DirectorySyncAction::SymlinkMaterialize => {
                if let Some(entry) = source.entries.get(&decision.path) {
                    projected
                        .entries
                        .insert(decision.path.clone(), entry.clone());
                }
            }
            DirectorySyncAction::Delete | DirectorySyncAction::Quarantine => {
                projected.entries.remove(&decision.path);
            }
            DirectorySyncAction::Rename => {
                if let Some(from_path) = &decision.from_path {
                    projected.entries.remove(from_path);
                }
                if let Some(entry) = source.entries.get(&decision.path) {
                    projected
                        .entries
                        .insert(decision.path.clone(), entry.clone());
                }
            }
            DirectorySyncAction::PermissionChange => {
                if let Some(entry) = source.entries.get(&decision.path) {
                    projected
                        .entries
                        .insert(decision.path.clone(), entry.clone());
                }
            }
            DirectorySyncAction::Preserve
            | DirectorySyncAction::Conflict
            | DirectorySyncAction::Skip => {}
        }
    }
    projected.tree_root()
}

fn replay_pointer(
    source: &DirectoryManifest,
    destination: &DirectoryManifest,
    decisions: &[DirectorySyncDecision],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.directory-sync.replay.v1\0");
    hasher.update(source.tree_root());
    hasher.update(destination.tree_root());
    for decision in decisions {
        hasher.update(decision.path.as_str().as_bytes());
        hasher.update(decision.action.code().as_bytes());
        hasher.update([
            u8::from(decision.authorized),
            u8::from(decision.would_apply),
        ]);
    }
    format!("directory-sync:{}", hex::encode(hasher.finalize()))
}

fn hash_metadata(hasher: &mut Sha256, metadata: &DirectoryEntryMetadata) {
    hash_opt_u64(hasher, metadata.size_bytes);
    hash_opt_u32(hasher, metadata.unix_mode);
    hash_opt_u32(hasher, metadata.windows_attributes);
    hash_opt_i64(hasher, metadata.modified_epoch_micros);
    hash_opt_str(hasher, metadata.symlink_target.as_deref());
    hash_opt_str(hasher, metadata.hard_link_group.as_deref());
    hash_opt_str(hasher, metadata.sparse_summary.as_deref());
    hash_opt_str(hasher, metadata.stable_identity.as_deref());
}

fn hash_opt_u64(hasher: &mut Sha256, value: Option<u64>) {
    if let Some(value) = value {
        hasher.update(value.to_be_bytes());
    }
    hasher.update([0]);
}

fn hash_opt_u32(hasher: &mut Sha256, value: Option<u32>) {
    if let Some(value) = value {
        hasher.update(value.to_be_bytes());
    }
    hasher.update([0]);
}

fn hash_opt_i64(hasher: &mut Sha256, value: Option<i64>) {
    if let Some(value) = value {
        hasher.update(value.to_be_bytes());
    }
    hasher.update([0]);
}

fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    if let Some(value) = value {
        hasher.update(value.as_bytes());
    }
    hasher.update([0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(raw: &str) -> DirectoryPath {
        DirectoryPath::normalize(raw, PathNormalizationRules::default()).expect("path")
    }

    fn file(raw: &str, content_id: &str) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            DirectoryEntryMetadata::with_identity(content_id),
        )
    }

    fn sized_file(raw: &str, content_id: &str, size_bytes: u64) -> DirectoryManifestEntry {
        let mut metadata = DirectoryEntryMetadata::with_identity(content_id);
        metadata.size_bytes = Some(size_bytes);
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            metadata,
        )
    }

    fn manifest(entries: Vec<DirectoryManifestEntry>) -> DirectoryManifest {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        for entry in entries {
            manifest.insert(entry).expect("insert");
        }
        manifest
    }

    #[test]
    fn path_normalization_rejects_unsafe_paths() {
        assert_eq!(path("a//./b\\c").as_str(), "a/b/c");
        assert!(matches!(
            DirectoryPath::normalize("../secret", PathNormalizationRules::default()),
            Err(DirectorySyncError::ParentTraversal(_))
        ));
        assert!(matches!(
            DirectoryPath::normalize("/tmp/file", PathNormalizationRules::default()),
            Err(DirectorySyncError::AbsolutePath(_))
        ));
    }

    #[test]
    fn case_conflicts_are_classified() {
        let source = manifest(vec![file("Readme.md", "a"), file("README.md", "b")]);
        let plan = plan_directory_sync(
            &source,
            &DirectoryManifest::new(PathNormalizationRules::default()),
            DirectorySyncPolicy::default(),
        );

        assert!(
            plan.decisions
                .iter()
                .any(|decision| decision.reason == "case_conflict")
        );
        assert!(
            plan.proof
                .conflict_decisions
                .iter()
                .any(|item| item.contains("case_conflict"))
        );
    }

    #[test]
    fn rename_detection_uses_stable_identity() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![file("old/name.txt", "same")]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        let rename = plan
            .decisions
            .iter()
            .find(|decision| decision.action == DirectorySyncAction::Rename)
            .expect("rename");
        assert_eq!(
            rename.from_path.as_ref().map(DirectoryPath::as_str),
            Some("old/name.txt")
        );
    }

    #[test]
    fn rename_detection_does_not_plan_old_path_delete() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![file("old/name.txt", "same")]);
        let plan = plan_directory_sync(
            &source,
            &destination,
            DirectorySyncPolicy::mirror_with_authorization(
                DestructiveAuthorization::explicit_mirror_apply(),
            ),
        );

        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Rename);
        assert_eq!(plan.decisions[0].path.as_str(), "new/name.txt");
        assert_eq!(
            plan.decisions[0]
                .from_path
                .as_ref()
                .map(DirectoryPath::as_str),
            Some("old/name.txt")
        );
    }

    #[test]
    fn duplicate_stable_identity_blocks_rename_candidate() {
        let source = manifest(vec![file("new/name.txt", "same")]);
        let destination = manifest(vec![
            file("old/one.txt", "same"),
            file("old/two.txt", "same"),
        ]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        assert!(
            !plan
                .decisions
                .iter()
                .any(|decision| decision.action == DirectorySyncAction::Rename)
        );
        assert_eq!(
            plan.decisions
                .iter()
                .filter(|decision| decision.reason == "stable_identity_conflict")
                .count(),
            2
        );
    }

    #[test]
    fn symlink_policy_skips_by_default() {
        let mut metadata = DirectoryEntryMetadata::default();
        metadata.symlink_target = Some("target.txt".to_string());
        let source = manifest(vec![DirectoryManifestEntry::new(
            path("link.txt"),
            DirectoryEntryKind::Symlink,
            None,
            metadata,
        )]);
        let plan = plan_directory_sync(
            &source,
            &DirectoryManifest::new(PathNormalizationRules::default()),
            DirectorySyncPolicy::default(),
        );

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Skip);
        assert_eq!(plan.proof.skipped_paths, vec!["link.txt"]);
    }

    #[test]
    fn permission_changes_require_explicit_policy() {
        let mut source_entry = file("run.sh", "script");
        source_entry.metadata.unix_mode = Some(0o755);
        let mut destination_entry = file("run.sh", "script");
        destination_entry.metadata.unix_mode = Some(0o644);
        let source = manifest(vec![source_entry]);
        let destination = manifest(vec![destination_entry]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::default());

        assert_eq!(
            plan.decisions[0].action,
            DirectorySyncAction::PermissionChange
        );
        assert!(!plan.decisions[0].authorized);
        assert!(!plan.decisions[0].would_apply);
    }

    #[test]
    fn mirror_delete_needs_authorization_and_respects_dry_run() {
        let source = DirectoryManifest::new(PathNormalizationRules::default());
        let destination = manifest(vec![file("stale.txt", "old")]);
        let policy = DirectorySyncPolicy::mirror_with_authorization(DestructiveAuthorization {
            allow_delete: true,
            dry_run: true,
            ..DestructiveAuthorization::default()
        });
        let plan = plan_directory_sync(&source, &destination, policy);

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Delete);
        assert!(plan.decisions[0].authorized);
        assert!(!plan.decisions[0].would_apply);
        assert!(plan.decisions[0].dry_run_visible);
    }

    #[test]
    fn metadata_round_trip_preserves_caveats() {
        let mut metadata = DirectoryEntryMetadata::with_identity("id");
        metadata.unix_mode = Some(0o600);
        metadata.modified_epoch_micros = Some(1_234);
        metadata.sparse_summary = Some("holes=2".to_string());
        let entry = DirectoryManifestEntry::new(
            path("sparse.img"),
            DirectoryEntryKind::SparseFile,
            Some("cid".to_string()),
            metadata,
        );

        assert!(entry.caveats.contains(&MetadataCaveat::UnixPermissions));
        assert!(entry.caveats.contains(&MetadataCaveat::TimestampResolution));
        assert!(entry.caveats.contains(&MetadataCaveat::SparseMetadata));
        assert_eq!(
            serde_json::from_str::<DirectoryManifestEntry>(
                &serde_json::to_string(&entry).expect("serialize")
            )
            .expect("deserialize"),
            entry
        );
    }

    #[test]
    fn conflict_classification_preserves_local_by_default() {
        let source = manifest(vec![file("same.txt", "new")]);
        let destination = manifest(vec![file("same.txt", "old")]);
        let plan = plan_directory_sync(&source, &destination, DirectorySyncPolicy::send_only());

        assert_eq!(plan.decisions[0].action, DirectorySyncAction::Conflict);
        assert_eq!(plan.decisions[0].reason, "destination_differs");
        assert!(!plan.decisions[0].would_apply);
        assert_eq!(
            plan.proof.conflict_decisions,
            vec!["same.txt:destination_differs"]
        );
    }

    #[test]
    fn directory_early_report_surfaces_metadata_and_verified_small_files() {
        let directory = DirectoryManifestEntry::new(
            path("docs"),
            DirectoryEntryKind::Directory,
            None,
            DirectoryEntryMetadata::default(),
        );
        let source = manifest(vec![
            directory,
            sized_file("docs/README.md", "small-cid", 512),
            sized_file("model.bin", "large-cid", 2 * 1024 * 1024),
        ]);
        let verified_content_ids =
            BTreeSet::from(["small-cid".to_string(), "large-cid".to_string()]);

        let report = source.early_usability_report(
            &verified_content_ids,
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            DirectoryFinalCommitState::Pending,
            "directory-replay:small-files",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::SmallFilesAvailable
        );
        assert_eq!(
            report.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert_eq!(report.replay_pointer, "directory-replay:small-files");
        assert_eq!(
            report.metadata_paths,
            vec!["docs", "docs/README.md", "model.bin"]
        );
        assert_eq!(report.small_file_paths, vec!["docs/README.md"]);
        assert_eq!(report.withheld_content_paths, vec!["model.bin"]);
        assert_eq!(report.manifest_tree_root, hex::encode(source.tree_root()));
        assert!(report.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));

        let large = report
            .entries
            .iter()
            .find(|entry| entry.path == "model.bin")
            .expect("large entry");
        assert_eq!(
            large.state,
            DirectoryEarlyEntryState::MetadataOnly,
            "large verified files must not become small-file early content"
        );
        assert_eq!(large.reason, "metadata_only_file_exceeds_small_file_policy");
    }

    #[test]
    fn directory_early_report_withholds_unverified_small_file_content() {
        let source = manifest(vec![sized_file("config.json", "config-cid", 128)]);
        let report = source.early_usability_report(
            &BTreeSet::new(),
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            DirectoryFinalCommitState::Pending,
            "directory-replay:unverified",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::MetadataAvailable
        );
        assert_eq!(report.metadata_paths, vec!["config.json"]);
        assert!(report.small_file_paths.is_empty());
        assert_eq!(report.withheld_content_paths, vec!["config.json"]);
        assert_eq!(
            report.entries[0].reason,
            "metadata_only_content_not_verified"
        );
        assert!(!report.entries[0].content_visible);
    }

    #[test]
    fn directory_early_report_keeps_final_commit_state_separate() {
        let source = manifest(vec![sized_file("done.txt", "done-cid", 32)]);
        let policy = DirectoryEarlyUsabilityPolicy {
            expose_metadata_before_final: false,
            ..DirectoryEarlyUsabilityPolicy::small_files_up_to(1024)
        };

        let pending = source.early_usability_report(
            &BTreeSet::from(["done-cid".to_string()]),
            policy,
            DirectoryFinalCommitState::Pending,
            "directory-replay:pending",
        );
        assert_eq!(
            pending.usability_state,
            DirectoryEarlyUsabilityState::NoEntries
        );
        assert!(pending.metadata_paths.is_empty());
        assert!(pending.small_file_paths.is_empty());
        assert_eq!(
            pending.entries[0].reason,
            "metadata_withheld_until_final_commit"
        );

        let committed = source.early_usability_report(
            &BTreeSet::from(["done-cid".to_string()]),
            policy,
            DirectoryFinalCommitState::Committed,
            "directory-replay:committed",
        );
        assert_eq!(
            committed.usability_state,
            DirectoryEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(
            committed.final_commit_state,
            DirectoryFinalCommitState::Committed
        );
        assert_eq!(committed.metadata_paths, vec!["done.txt"]);
        assert_eq!(committed.small_file_paths, vec!["done.txt"]);
        assert!(!committed.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));
    }

    #[test]
    fn explicit_apply_changes_projected_tree_root() {
        let source = manifest(vec![file("same.txt", "new")]);
        let destination = manifest(vec![file("same.txt", "old")]);
        let policy = DirectorySyncPolicy::mirror_with_authorization(
            DestructiveAuthorization::explicit_mirror_apply(),
        );
        let plan = plan_directory_sync(&source, &destination, policy);

        assert!(plan.decisions[0].would_apply);
        assert_eq!(plan.proof.final_tree_root, hex::encode(source.tree_root()));
        assert!(plan.proof.replay_pointer.starts_with("directory-sync:"));
    }
}
