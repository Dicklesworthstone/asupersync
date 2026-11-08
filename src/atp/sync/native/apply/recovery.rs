//! Explicit, confined restoration of retained native synchronization originals.

use super::{
    DestructiveAuthorization, DirectoryEntryKind, DirectoryManifestEntry, DirectoryPath,
    NativeDirectoryActionReceipt, NativeDirectoryActionState, NativeDirectoryError,
    NativeDirectoryLimits, NativeDirectorySnapshot, NativeDirectorySyncReport, NativeRoot,
    Stamp, changed, checkpoint, directory_flags,
    disjoint_roots, guarded_parent, io_error, metadata_stamp, open_guarded_file, os_error,
    record_deletion, record_destination, refused, revalidate_complete, scan_root, stat_at,
    validate_overwrite_metadata, verify_empty_directory,
};
use crate::atp::sync::{BidirectionalSyncAction, PathNormalizationRules};
use crate::cx::Cx;
use nix::fcntl::{RenameFlags, openat, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{getegid, geteuid};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Serializable association between one original action and its retained inode.
///
/// This is untrusted diagnostic input, not a claim that bytes are authentic or an
/// authorization to restore them. Keep every action in its original position:
/// the index determines the only permitted `previous-<index>` quarantine name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct NativeDirectoryRecoverySourceAction {
    /// Original canonical manifest-relative destination.
    pub path: DirectoryPath,
    /// Original direction, used to select the explicitly supplied root.
    pub action: BidirectionalSyncAction,
    /// Last observed action boundary, serialized in snake_case.
    #[serde(with = "source_action_state")]
    pub state: NativeDirectoryActionState,
    /// Retained original name, if the earlier action quarantined anything.
    pub quarantine_path: Option<PathBuf>,
}

impl NativeDirectoryRecoverySourceAction {
    /// Construct association data; preparation validates it before filesystem use.
    #[must_use]
    pub fn new(
        path: DirectoryPath,
        action: BidirectionalSyncAction,
        state: NativeDirectoryActionState,
        quarantine_path: Option<PathBuf>,
    ) -> Self {
        Self { path, action, state, quarantine_path }
    }
}

impl From<&NativeDirectoryActionReceipt> for NativeDirectoryRecoverySourceAction {
    fn from(receipt: &NativeDirectoryActionReceipt) -> Self {
        Self::new(
            receipt.path.clone(), receipt.action, receipt.state, receipt.quarantine_path.clone(),
        )
    }
}

/// Persistable association data for freshly prepared native recovery.
///
/// It contains no native errors, verified-baseline claim, or cached filesystem
/// authority. Deserialization alone grants nothing. Preparation validates every
/// association, confines the exact job directory, and hashes the actual current
/// originals and destinations before returning an opaque recovery plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct NativeDirectoryRecoverySource {
    /// Earlier execution identity naming the retained recovery job.
    pub plan_id: String,
    /// Whether the earlier operation was only a dry run; such input is refused.
    pub dry_run: bool,
    /// Exact retained job directory from the earlier report.
    pub staging_directory: Option<PathBuf>,
    /// All original actions, including ones without quarantine, in original order.
    pub actions: Vec<NativeDirectoryRecoverySourceAction>,
}

impl NativeDirectoryRecoverySource {
    /// Construct untrusted association data for later validation and fresh scanning.
    #[must_use]
    pub fn new(
        plan_id: impl Into<String>,
        dry_run: bool,
        staging_directory: Option<PathBuf>,
        actions: Vec<NativeDirectoryRecoverySourceAction>,
    ) -> Self {
        Self { plan_id: plan_id.into(), dry_run, staging_directory, actions }
    }

    /// Decode and validate association JSON within an explicit byte bound.
    ///
    /// `max_bytes` must be in `1..=64 MiB`; it is checked before deserialization.
    /// Native entry/depth bounds and all canonical association checks also apply.
    /// This performs no filesystem access and establishes no content authenticity.
    ///
    /// # Errors
    /// Refuses an invalid bound, oversized/invalid JSON, or invalid associations.
    pub fn from_json_slice(
        bytes: &[u8],
        max_bytes: usize,
        limits: NativeDirectoryLimits,
    ) -> Result<Self, NativeDirectoryError> {
        limits.validate()?;
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(refused(Path::new(""), "recovery source byte bound requires 1..=64 MiB"));
        }
        if bytes.len() > max_bytes {
            return Err(NativeDirectoryError::Limit {
                path: PathBuf::new(), limit: "max_recovery_source_bytes",
            });
        }
        let source: Self = serde_json::from_slice(bytes)
            .map_err(|_| refused(Path::new(""), "invalid recovery source JSON"))?;
        source_inputs(&source, limits)?;
        Ok(source)
    }
}

impl From<&NativeDirectorySyncReport> for NativeDirectoryRecoverySource {
    fn from(report: &NativeDirectorySyncReport) -> Self {
        Self::new(
            report.plan_id.clone(), report.dry_run, report.staging_directory.clone(),
            report.actions.iter().map(NativeDirectoryRecoverySourceAction::from).collect(),
        )
    }
}

mod source_action_state {
    use super::NativeDirectoryActionState;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        state: &NativeDirectoryActionState,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match state {
            NativeDirectoryActionState::NotStarted => "not_started",
            NativeDirectoryActionState::Unchanged => "unchanged",
            NativeDirectoryActionState::Staged => "staged",
            NativeDirectoryActionState::Quarantined => "quarantined",
            NativeDirectoryActionState::Published => "published",
        })
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<NativeDirectoryActionState, D::Error> {
        let state = String::deserialize(deserializer)?;
        match state.as_str() {
            "not_started" => Ok(NativeDirectoryActionState::NotStarted),
            "unchanged" => Ok(NativeDirectoryActionState::Unchanged),
            "staged" => Ok(NativeDirectoryActionState::Staged),
            "quarantined" => Ok(NativeDirectoryActionState::Quarantined),
            "published" => Ok(NativeDirectoryActionState::Published),
            _ => Err(serde::de::Error::unknown_variant(&state, &[
                "not_started", "unchanged", "staged", "quarantined", "published",
            ])),
        }
    }
}

/// Captured contents proposed for restoration at one actual destination.
///
/// The earlier sync report supplies only an association, never filesystem
/// authority or proof of the original contents. Review these freshly captured
/// inventories before applying: quarantine may have changed since that report.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NativeDirectoryRecoveryEntry {
    /// Canonical path relative to the selected destination root.
    pub path: DirectoryPath,
    /// Explicitly supplied, descriptor-confined destination root.
    pub destination_root: PathBuf,
    /// Actual quarantine entry, including its current content identity.
    /// Its path is relative to the prepared recovery directory.
    pub quarantined: DirectoryManifestEntry,
    /// Actual current destination; a file here requires overwrite authorization.
    pub current: Option<DirectoryManifestEntry>,
}

/// Last completed rename boundary for one restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeDirectoryRecoveryState {
    /// No effect was attempted for this entry.
    NotStarted,
    /// The quarantine inode moved into an absent destination.
    Restored,
    /// The original and current file exchanged names atomically.
    Exchanged,
}

/// Actual restoration effects, including an exchange whose later sync failed.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDirectoryRecoveryReceipt {
    /// Canonical path relative to the destination root.
    pub path: DirectoryPath,
    /// Root receiving the quarantined inode.
    pub destination_root: PathBuf,
    /// Name containing the original before restoration. After `Exchanged`,
    /// this instead retains the displaced current file; after `Restored`, it
    /// is absent. No recovery artifact is removed automatically.
    pub quarantine_path: PathBuf,
    /// Last completed rename boundary.
    pub state: NativeDirectoryRecoveryState,
    /// Inode data and both directory entries completed their required syncs.
    pub durable: bool,
}

/// Restoration outcome that preserves partial effects without claiming rollback.
///
/// This restores the selected quarantined originals only. Newly copied entries
/// from the original synchronization remain. It does not establish a common
/// synchronization baseline or roll back the entire earlier transaction.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDirectoryRecoveryReport {
    /// Earlier synchronization identity, used only to locate its recovery job.
    pub source_plan_id: String,
    /// Whether application was read-only.
    pub dry_run: bool,
    /// Every restoration and final captured-tree revalidation completed.
    pub complete: bool,
    /// Parent-first restoration receipts, including unstarted entries.
    pub actions: Vec<NativeDirectoryRecoveryReceipt>,
    /// First refusal, cancellation, or I/O failure.
    pub failure: Option<NativeDirectoryError>,
}

/// Opaque, single-use restoration prepared from real confined inventories.
#[derive(Debug)]
pub struct PreparedNativeDirectoryRecovery {
    source_plan_id: String,
    review_id: String,
    local: NativeDirectorySnapshot,
    remote: NativeDirectorySnapshot,
    quarantine: NativeDirectorySnapshot,
    entries: Vec<NativeDirectoryRecoveryEntry>,
    limits: NativeDirectoryLimits,
}

impl PreparedNativeDirectoryRecovery {
    /// Actual quarantined contents and current destinations in application order.
    #[must_use]
    pub fn preview(&self) -> &[NativeDirectoryRecoveryEntry] { &self.entries }

    /// Retained recovery job directory; arbitrary receipt paths are never followed.
    #[must_use]
    pub fn recovery_directory(&self) -> &Path { &self.quarantine.root.path }

    /// Identity supplied by the earlier synchronization report.
    #[must_use]
    pub fn source_plan_id(&self) -> &str { &self.source_plan_id }

    /// Stable identity of these freshly captured restoration effects.
    ///
    /// Binds the source plan, selected associations, all three canonical roots,
    /// their filesystem identities, and captured contents and object guards.
    /// A caller can compare this with a previously reviewed identity before
    /// authorizing application. Re-preparing unchanged trees is stable; changed
    /// originals, destinations, identities, or associations produce another ID.
    /// This is a local review binding, not authentication of an earlier report.
    #[must_use]
    pub fn review_id(&self) -> &str { &self.review_id }

    /// Restore the exact captured originals through owned blocking work.
    ///
    /// Absent destinations use `RENAME_NOREPLACE`. Existing regular files require
    /// BOTH `allow_overwrite` and `allow_permission_change`: `RENAME_EXCHANGE`
    /// atomically restores the captured quarantine inode and retains the displaced
    /// current inode at that same quarantine name. Restoring a directory over an
    /// existing entry or changing entry kinds is refused. A dry run makes no
    /// changes and requires no destructive authorization.
    ///
    /// The caller must exclusively own both roots and the recovery directory
    /// throughout prepare/apply. All inventories are rehashed before the first
    /// effect, and each inode and ancestor is checked again at its effect boundary.
    /// Restored directories precede their descendants. Once a rename starts, its
    /// directory syncs and receipt retire without a cancellation checkpoint.
    /// Cancellation between actions preserves prior effects in the report.
    ///
    /// No bytes are copied, no names are unlinked, and no new journal is created.
    /// This is an explicit recovery operation, not a crash-replay protocol or a
    /// complete transaction rollback. Public reports are diagnostic data and are
    /// never accepted as application authority without fresh preparation.
    ///
    /// # Errors
    /// An outer error means runtime dispatch/retirement failed. Work that ran
    /// returns its actual partial report with `failure` populated.
    pub async fn apply(
        self,
        cx: &Cx,
        authorization: DestructiveAuthorization,
    ) -> Result<NativeDirectoryRecoveryReport, NativeDirectoryError> {
        cx.scoped_fs().run_io(move |worker| {
            Ok(restore_owned(&worker, self, authorization))
        }).await.map_err(NativeDirectoryError::Runtime)
    }
}

/// Prepare restoration of originals retained by native sync or mirror application.
///
/// Supply the original local/remote roots explicitly. The public report is
/// untrusted association data: its plan ID, job directory, action directions,
/// canonical relative paths, states and exact `previous-<index>` names are
/// validated before scanning. Reported arbitrary filesystem paths are never
/// opened. Preparation captures current quarantine contents and destination
/// contents for review; the old report contains no authenticated original digest.
///
/// Both roots and the private recovery job must be disjoint directories on one
/// filesystem. This Linux/glibc profile accepts ordinary singly linked files and
/// empty quarantined directories. Special modes, different ownership, visible
/// extended metadata, symlinks and type replacements are refused. Missing parents
/// must themselves be recoverable directories in this plan. Limits apply to each
/// scanned tree, projected destination tree and the selected restoration set.
///
/// # Errors
/// Refuses malformed reports, unsupported metadata or entries, overlap,
/// exceeded limits, absent recovery data, unstable inventories and cancellation.
pub async fn prepare_native_directory_recovery(
    cx: &Cx,
    report: &NativeDirectorySyncReport,
    local_root: impl Into<PathBuf>,
    remote_root: impl Into<PathBuf>,
    limits: NativeDirectoryLimits,
) -> Result<PreparedNativeDirectoryRecovery, NativeDirectoryError> {
    limits.validate()?;
    let (job, inputs) = recovery_inputs(
        &report.plan_id, report.dry_run, report.staging_directory.as_deref(),
        report.actions.iter().map(|receipt| RecoveryAssociation {
            path: &receipt.path, action: receipt.action, state: receipt.state,
            quarantine_path: receipt.quarantine_path.as_deref(),
        }), limits,
    )?;
    prepare_recovery(
        cx, report.plan_id.clone(), job, inputs, local_root.into(), remote_root.into(), limits,
    ).await
}

/// Prepare recovery from a persisted, untrusted association source.
///
/// This uses exactly the same canonical path/direction/state checks and fresh
/// descriptor-confined inventories as [`prepare_native_directory_recovery`].
/// Caller-provided roots remain explicit; input supplies no content authority.
/// Use the returned preview and [`PreparedNativeDirectoryRecovery::review_id`]
/// before granting application authority. Bound external JSON before decoding,
/// for example with [`NativeDirectoryRecoverySource::from_json_slice`].
///
/// # Errors
/// Refuses malformed or oversized associations, unsupported or changed trees,
/// absent originals, unavailable capabilities, and cancellation.
pub async fn prepare_native_directory_recovery_from_source(
    cx: &Cx,
    source: &NativeDirectoryRecoverySource,
    local_root: impl Into<PathBuf>,
    remote_root: impl Into<PathBuf>,
    limits: NativeDirectoryLimits,
) -> Result<PreparedNativeDirectoryRecovery, NativeDirectoryError> {
    limits.validate()?;
    let (job, inputs) = source_inputs(source, limits)?;
    prepare_recovery(
        cx, source.plan_id.clone(), job, inputs, local_root.into(), remote_root.into(), limits,
    ).await
}

async fn prepare_recovery(
    cx: &Cx,
    source_plan_id: String,
    job: PathBuf,
    inputs: Vec<RecoveryInput>,
    local_path: PathBuf,
    remote_path: PathBuf,
    limits: NativeDirectoryLimits,
) -> Result<PreparedNativeDirectoryRecovery, NativeDirectoryError> {
    cx.scoped_fs().run_io(move |worker| {
        Ok((|| {
            checkpoint(&worker)?;
            let local = NativeRoot::open(&local_path)?;
            let remote = NativeRoot::open(&remote_path)?;
            let quarantine = NativeRoot::open(&job)?;
            disjoint_roots(&local, &remote)?;
            disjoint_roots(&quarantine, &local)?;
            disjoint_roots(&quarantine, &remote)?;
            if local.identity.device != remote.identity.device
                || local.identity.device != quarantine.identity.device
            {
                return Err(refused(&job, "recovery requires roots on one filesystem"));
            }
            let stamp = metadata_stamp(&quarantine.file, &job)?;
            if stamp.uid != geteuid().as_raw() || stamp.gid != getegid().as_raw()
                || stamp.mode & 0o7777 != 0o700
            {
                return Err(refused(&job, "recovery job requires private owned directory mode 0700"));
            }
            validate_overwrite_metadata(&quarantine.file, stamp, &job)?;
            let local = scan_root(&worker, local, limits)?;
            let remote = scan_root(&worker, remote, limits)?;
            let quarantine = scan_root(&worker, quarantine, limits)?;
            super::super::disjoint_inventories(&local, &remote)?;
            super::super::disjoint_inventories(&quarantine, &local)?;
            super::super::disjoint_inventories(&quarantine, &remote)?;
            let mut entries = Vec::with_capacity(inputs.len());
            for input in inputs {
                checkpoint(&worker)?;
                let destination = if input.local { &local } else { &remote };
                let original = quarantine.manifest.entries.get(&input.source)
                    .ok_or_else(|| changed(&job.join(input.source.as_str())))?.clone();
                let current = destination.manifest.entries.get(&input.path).cloned();
                if current.as_ref().is_some_and(|entry| {
                    entry.kind != DirectoryEntryKind::File || original.kind != DirectoryEntryKind::File
                }) {
                    return Err(refused(&destination.root.path.join(input.path.as_str()),
                        "recovery may replace only an existing regular file with a regular file"));
                }
                checked_entry(&worker, &quarantine, &input.source, limits)?;
                if current.is_some() {
                    checked_entry(&worker, destination, &input.path, limits)?;
                }
                entries.push(NativeDirectoryRecoveryEntry {
                    path: input.path, destination_root: destination.root.path.clone(),
                    quarantined: original, current,
                });
            }
            entries.sort_by(|a, b| {
                (&a.destination_root, &a.path).cmp(&(&b.destination_root, &b.path))
            });
            let mut prepared = PreparedNativeDirectoryRecovery {
                source_plan_id, review_id: String::new(), local, remote, quarantine, entries, limits,
            };
            validate_projection(&prepared)?;
            // Earlier roots can change while later roots or entries are hashed.
            for snapshot in [&prepared.local, &prepared.remote, &prepared.quarantine] {
                snapshot.root.revalidate()?;
                super::super::revalidate_stamps(&worker, snapshot)?;
            }
            prepared.review_id = recovery_review_id(&worker, &prepared)?;
            Ok(prepared)
        })())
    }).await.map_err(NativeDirectoryError::Runtime)?
}

struct RecoveryInput { local: bool, path: DirectoryPath, source: DirectoryPath }

struct RecoveryAssociation<'a> {
    path: &'a DirectoryPath,
    action: BidirectionalSyncAction,
    state: NativeDirectoryActionState,
    quarantine_path: Option<&'a Path>,
}

fn source_inputs(
    source: &NativeDirectoryRecoverySource,
    limits: NativeDirectoryLimits,
) -> Result<(PathBuf, Vec<RecoveryInput>), NativeDirectoryError> {
    recovery_inputs(
        &source.plan_id, source.dry_run, source.staging_directory.as_deref(),
        source.actions.iter().map(|receipt| RecoveryAssociation {
            path: &receipt.path, action: receipt.action, state: receipt.state,
            quarantine_path: receipt.quarantine_path.as_deref(),
        }), limits,
    )
}

fn recovery_inputs<'a>(
    plan_id: &str,
    dry_run: bool,
    staging_directory: Option<&Path>,
    actions: impl ExactSizeIterator<Item = RecoveryAssociation<'a>>,
    limits: NativeDirectoryLimits,
) -> Result<(PathBuf, Vec<RecoveryInput>), NativeDirectoryError> {
    let diagnostic = Path::new("");
    if dry_run || plan_id.len() != 64
        || !plan_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || actions.len() > limits.max_entries.saturating_mul(2)
    {
        return Err(refused(diagnostic, "invalid or oversized native recovery report"));
    }
    let job = staging_directory
        .ok_or_else(|| refused(diagnostic, "report has no recovery directory"))?;
    let expected_job = format!("asupersync-sync-{plan_id}");
    if !job.is_absolute() || job.file_name() != Some(std::ffi::OsStr::new(&expected_job)) {
        return Err(refused(job, "recovery directory does not match the source plan"));
    }
    let mut inputs = Vec::new();
    let mut targets = BTreeSet::new();
    for (index, receipt) in actions.enumerate() {
        let Some(path) = receipt.quarantine_path else {
            if receipt.state == NativeDirectoryActionState::Quarantined {
                return Err(refused(job, "quarantined receipt has no recovery name"));
            }
            continue;
        };
        let source_name = format!("previous-{index:08x}");
        if path.as_os_str() != job.join(&source_name).as_os_str()
            || !matches!(receipt.state,
                NativeDirectoryActionState::Quarantined | NativeDirectoryActionState::Published)
        {
            return Err(refused(job, "receipt has a noncanonical recovery name or state"));
        }
        let local = match receipt.action {
            BidirectionalSyncAction::CopyRemoteToLocal | BidirectionalSyncAction::DeleteLocal => true,
            BidirectionalSyncAction::CopyLocalToRemote | BidirectionalSyncAction::DeleteRemote => false,
            _ => return Err(refused(job, "receipt action cannot identify a recovery destination")),
        };
        if matches!(receipt.action, BidirectionalSyncAction::DeleteLocal | BidirectionalSyncAction::DeleteRemote)
            && receipt.state != NativeDirectoryActionState::Quarantined
        {
            return Err(refused(job, "deletion receipt has an impossible publication state"));
        }
        let normalized = DirectoryPath::normalize(receipt.path.as_str(), PathNormalizationRules::default())
            .map_err(NativeDirectoryError::Manifest)?;
        if &normalized != receipt.path || receipt.path.as_str().contains('\\')
            || receipt.path.as_str().split('/').count() > limits.max_depth
            || !targets.insert((local, receipt.path.clone()))
            || inputs.len() >= limits.max_entries
        {
            return Err(refused(job, "invalid, repeated or excessive recovery destination"));
        }
        inputs.push(RecoveryInput {
            local, path: normalized,
            source: DirectoryPath::normalize(&source_name, PathNormalizationRules::default())
                .map_err(NativeDirectoryError::Manifest)?,
        });
    }
    if inputs.is_empty() { return Err(refused(job, "report has no quarantined originals")); }
    Ok((job.to_path_buf(), inputs))
}

fn recovery_review_id(
    cx: &Cx,
    prepared: &PreparedNativeDirectoryRecovery,
) -> Result<String, NativeDirectoryError> {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.native-directory-recovery-review.v1\0");
    hash_review_field(&mut hash, prepared.source_plan_id.as_bytes());
    for snapshot in [&prepared.local, &prepared.remote, &prepared.quarantine] {
        checkpoint(cx)?;
        hash_review_field(&mut hash, snapshot.root.path.as_os_str().as_encoded_bytes());
        hash_review_stamp(&mut hash, snapshot.root_stamp);
        hash.update(snapshot.manifest.tree_root());
        hash.update((snapshot.guards.len() as u64).to_be_bytes());
        for (path, stamp) in &snapshot.guards {
            checkpoint(cx)?;
            hash_review_field(&mut hash, path.as_str().as_bytes());
            hash_review_stamp(&mut hash, *stamp);
        }
    }
    hash.update((prepared.entries.len() as u64).to_be_bytes());
    for entry in &prepared.entries {
        checkpoint(cx)?;
        hash_review_field(&mut hash, entry.destination_root.as_os_str().as_encoded_bytes());
        hash_review_field(&mut hash, entry.path.as_str().as_bytes());
        hash_review_field(&mut hash, entry.quarantined.path.as_str().as_bytes());
        hash.update([u8::from(entry.current.is_some())]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn hash_review_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hash_review_stamp(hash: &mut Sha256, stamp: Stamp) {
    for value in [stamp.identity.device, stamp.identity.inode, stamp.links, stamp.size] {
        hash.update(value.to_be_bytes());
    }
    for value in [stamp.mode, stamp.uid, stamp.gid] {
        hash.update(value.to_be_bytes());
    }
    for value in [stamp.modified.0, stamp.modified.1, stamp.changed.0, stamp.changed.1] {
        hash.update(value.to_be_bytes());
    }
}

fn validate_projection(prepared: &PreparedNativeDirectoryRecovery) -> Result<(), NativeDirectoryError> {
    for destination in [&prepared.local, &prepared.remote] {
        let mut projected = destination.manifest.clone();
        for entry in prepared.entries.iter().filter(|entry| entry.destination_root == destination.root.path) {
            let mut restored = entry.quarantined.clone();
            restored.path = entry.path.clone();
            projected.entries.insert(entry.path.clone(), restored);
        }
        // Also checks absent ancestors and the complete projected resource bounds.
        super::super::validate_profile(&projected, prepared.limits)?;
    }
    let mut projected = prepared.quarantine.manifest.clone();
    for entry in &prepared.entries {
        if let Some(current) = &entry.current {
            let mut retained = current.clone();
            retained.path = entry.quarantined.path.clone();
            projected.entries.insert(retained.path.clone(), retained);
        } else {
            projected.entries.remove(&entry.quarantined.path);
        }
    }
    super::super::validate_profile(&projected, prepared.limits)?;
    Ok(())
}

/// Open, hash and bind one ordinary file or empty directory to its captured stamp.
fn checked_entry(
    cx: &Cx,
    snapshot: &NativeDirectorySnapshot,
    path: &DirectoryPath,
    limits: NativeDirectoryLimits,
) -> Result<(File, Stamp), NativeDirectoryError> {
    let display = snapshot.root.path.join(path.as_str());
    let expected = snapshot.guards.get(path).copied().ok_or_else(|| changed(&display))?;
    let (parent, name) = guarded_parent(snapshot, path)?;
    let file = if expected.kind(&display)? == DirectoryEntryKind::File {
        let file = open_guarded_file(&parent, name, &display, expected)?;
        let digest = super::super::hash_file(cx, &file, expected, &display, limits)?;
        if snapshot.manifest.entries.get(path).and_then(|entry| entry.content_id.as_deref()) != Some(digest.as_str()) {
            return Err(changed(&display));
        }
        file
    } else {
        let file = File::from(openat(&parent, name, directory_flags(), Mode::empty())
            .map_err(|error| os_error(&display, error))?);
        if stat_at(&parent, name, &display)? != Some(expected)
            || metadata_stamp(&file, &display)? != expected
        {
            return Err(changed(&display));
        }
        verify_empty_directory(cx, &file, &display)?;
        file
    };
    validate_overwrite_metadata(&file, expected, &display)?;
    Ok((file, expected))
}

fn restore_owned(
    cx: &Cx,
    mut prepared: PreparedNativeDirectoryRecovery,
    authorization: DestructiveAuthorization,
) -> NativeDirectoryRecoveryReport {
    let mut report = NativeDirectoryRecoveryReport {
        source_plan_id: prepared.source_plan_id.clone(), dry_run: authorization.dry_run,
        complete: false, failure: None,
        actions: prepared.entries.iter().map(|entry| NativeDirectoryRecoveryReceipt {
            path: entry.path.clone(), destination_root: entry.destination_root.clone(),
            quarantine_path: prepared.quarantine.root.path.join(entry.quarantined.path.as_str()),
            state: NativeDirectoryRecoveryState::NotStarted, durable: false,
        }).collect(),
    };
    let result = (|| {
        checkpoint(cx)?;
        if !authorization.dry_run && prepared.entries.iter().any(|entry| entry.current.is_some())
            && (!authorization.allow_overwrite || !authorization.allow_permission_change)
        {
            return Err(refused(&prepared.quarantine.root.path,
                "recovery exchange requires overwrite and permission-change authorization"));
        }
        for snapshot in [&prepared.local, &prepared.remote, &prepared.quarantine] {
            revalidate_complete(cx, snapshot, prepared.limits)?;
        }
        // Metadata is also preflighted for the whole set, before any rename.
        for entry in &prepared.entries {
            checked_entry(cx, &prepared.quarantine, &entry.quarantined.path, prepared.limits)?;
            if entry.current.is_some() {
                let destination = if entry.destination_root == prepared.local.root.path {
                    &prepared.local
                } else { &prepared.remote };
                checked_entry(cx, destination, &entry.path, prepared.limits)?;
            }
        }
        if authorization.dry_run { return Ok(()); }
        for (entry, receipt) in prepared.entries.iter().zip(&mut report.actions) {
            checkpoint(cx)?;
            let destination = if entry.destination_root == prepared.local.root.path {
                &mut prepared.local
            } else { &mut prepared.remote };
            restore_entry(cx, &mut prepared.quarantine, destination, entry, prepared.limits, receipt)?;
        }
        for snapshot in [&prepared.local, &prepared.remote, &prepared.quarantine] {
            revalidate_complete(cx, snapshot, prepared.limits)?;
        }
        report.complete = true;
        Ok(())
    })();
    if let Err(error) = result { report.failure = Some(error); }
    report
}

fn restore_entry(
    cx: &Cx,
    quarantine: &mut NativeDirectorySnapshot,
    destination: &mut NativeDirectorySnapshot,
    entry: &NativeDirectoryRecoveryEntry,
    limits: NativeDirectoryLimits,
    receipt: &mut NativeDirectoryRecoveryReceipt,
) -> Result<(), NativeDirectoryError> {
    let source_path = &entry.quarantined.path;
    let source_display = quarantine.root.path.join(source_path.as_str());
    let display = destination.root.path.join(entry.path.as_str());
    let (original, original_stamp) = checked_entry(cx, quarantine, source_path, limits)?;
    let current = if entry.current.is_some() {
        Some(checked_entry(cx, destination, &entry.path, limits)?)
    } else { None };
    original.sync_all().map_err(|source| io_error(&source_display, source))?;
    if let Some((file, _)) = &current {
        file.sync_all().map_err(|source| io_error(&display, source))?;
    }
    // Re-open checked parents after potentially long hashing and inode syncing.
    let (source_parent, source_name) = guarded_parent(quarantine, source_path)?;
    let (target_parent, target_name) = guarded_parent(destination, &entry.path)?;
    if stat_at(&source_parent, source_name, &source_display)? != Some(original_stamp)
        || metadata_stamp(&original, &source_display)? != original_stamp
        || stat_at(&target_parent, target_name, &display)? != current.as_ref().map(|(_, stamp)| *stamp)
    {
        return Err(changed(&display));
    }
    if let Some((file, stamp)) = &current {
        if metadata_stamp(file, &display)? != *stamp { return Err(changed(&display)); }
    }
    if entry.quarantined.kind == DirectoryEntryKind::Directory {
        verify_empty_directory(cx, &original, &source_display)?;
    }
    checkpoint(cx)?;
    let flags = if current.is_some() { RenameFlags::RENAME_EXCHANGE } else { RenameFlags::RENAME_NOREPLACE };
    renameat2(&source_parent, source_name, &target_parent, target_name, flags)
        .map_err(|error| os_error(&display, error))?;
    receipt.state = if current.is_some() {
        NativeDirectoryRecoveryState::Exchanged
    } else { NativeDirectoryRecoveryState::Restored };
    // No cancellation checkpoint between the effect, identity checks and syncs.
    if stat_at(&target_parent, target_name, &display)?.is_none_or(|stamp| stamp.identity != original_stamp.identity)
        || stat_at(&source_parent, source_name, &source_display)?.map(|stamp| stamp.identity)
            != current.as_ref().map(|(_, stamp)| stamp.identity)
    {
        return Err(changed(&display));
    }
    source_parent.sync_all().map_err(|source| io_error(&source_display, source))?;
    target_parent.sync_all().map_err(|source| io_error(&display, source))?;
    receipt.durable = true;
    let mut restored = entry.quarantined.clone();
    restored.path = entry.path.clone();
    destination.total_bytes = destination.total_bytes
        .checked_sub(entry.current.as_ref().and_then(|entry| entry.metadata.size_bytes).unwrap_or(0))
        .and_then(|total| total.checked_add(restored.metadata.size_bytes.unwrap_or(0)))
        .ok_or_else(|| changed(&display))?;
    record_destination(destination, &restored, &target_parent, &original)?;
    if let (Some((current_file, _)), Some(current_entry)) = (current, &entry.current) {
        let mut retained = current_entry.clone();
        retained.path = source_path.clone();
        quarantine.total_bytes = quarantine.total_bytes
            .checked_sub(entry.quarantined.metadata.size_bytes.unwrap_or(0))
            .and_then(|total| total.checked_add(retained.metadata.size_bytes.unwrap_or(0)))
            .ok_or_else(|| changed(&source_display))?;
        record_destination(quarantine, &retained, &source_parent, &current_file)?;
    } else {
        record_deletion(quarantine, source_path, &source_parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
