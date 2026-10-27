//! Application of an opaque native reconciliation with retained recovery data.

use super::{
    DirectoryEntryKind, DirectoryManifest, DirectoryManifestEntry, DirectoryPath,
    NativeDirectoryError, NativeDirectoryLimits, NativeDirectorySnapshot,
    NativeRoot, PreparedNativeDirectorySync, Stamp, changed, checkpoint,
    directory_flags, disjoint_roots, file_flags, io_error, metadata_stamp,
    open_parent, os_error, refused, revalidate_stamps, scan_root, stat_at,
    validate_profile,
};
use crate::atp::sync::{
    BidirectionalSyncAction, BidirectionalSyncDecision, DestructiveAuthorization,
};
use crate::cx::Cx;
use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{getegid, geteuid};
use sha2::{Digest, Sha256};
use std::fs::{File, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use xattr::FileExt;

/// Last actual filesystem boundary reached by an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeDirectoryActionState {
    /// No effect was attempted for this action.
    NotStarted,
    /// Both retained observations already agreed.
    Unchanged,
    /// A staging file exists, possibly with only partial contents.
    Staged,
    /// The previous destination was moved to the reported quarantine path.
    Quarantined,
    /// The new file or directory was published at its destination.
    Published,
}

/// Actual outcome for one reviewed action, including partial publication.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDirectoryActionReceipt {
    /// Manifest-relative path.
    pub path: DirectoryPath,
    /// Original reviewed action.
    pub action: BidirectionalSyncAction,
    /// Last completed effect boundary.
    pub state: NativeDirectoryActionState,
    /// Bytes whose writes to staging completed successfully.
    pub bytes_written: u64,
    /// Retained staging file, if it has not been moved into its destination.
    pub staged_path: Option<PathBuf>,
    /// Retained original destination inode after an authorized overwrite.
    pub quarantine_path: Option<PathBuf>,
    /// Required file and directory syncs completed after publication.
    pub durable: bool,
}

/// An application result that never erases already completed effects.
///
/// A failure may follow successful actions, a staged partial file, a quarantined
/// original, or a published file whose directory sync failed. Inspect receipts
/// and retained paths before recovery. No automatic cleanup or rollback removes
/// data. A common baseline is returned only after both final trees were hashed
/// and found equal to the complete reviewed projection.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDirectorySyncReport {
    /// Identity of the single-use prepared plan.
    pub plan_id: String,
    /// Requested dry-run mode; dry runs never create staging artifacts.
    pub dry_run: bool,
    /// All actions completed and final convergence was verified.
    pub complete: bool,
    /// One receipt per reviewed decision in deterministic path order.
    pub actions: Vec<NativeDirectoryActionReceipt>,
    /// Retained private staging directory, including any recovery data.
    pub staging_directory: Option<PathBuf>,
    /// Verified common inventory; the caller decides how to persist it.
    pub verified_baseline: Option<DirectoryManifest>,
    /// First refusal, cancellation, or actual I/O failure.
    pub failure: Option<NativeDirectoryError>,
}

impl PreparedNativeDirectorySync {
    /// Apply this exact reviewed plan through owned blocking work.
    ///
    /// This initial Linux/glibc profile creates directories and copies ordinary
    /// files in either direction. It never deletes entries or changes entry
    /// kinds. Every conflict, unsupported action, missing authorization, and
    /// stale initial observation refuses the entire plan before staging.
    ///
    /// Overwrite requires BOTH allow_overwrite and allow_permission_change,
    /// with dry_run false. Ordinary destination mode/uid/gid are preserved;
    /// setid/sticky modes, different ownership, and visible extended attributes
    /// are refused. An empty xattr listing cannot prove absence of hidden
    /// platform metadata, so explicit permission-change authorization is still
    /// required. The original inode remains in quarantine for recovery.
    ///
    /// The existing staging root must be outside both synchronization roots,
    /// on their shared filesystem, owned by the effective user, and not group
    /// or world writable. Private artifacts are retained on every exit. New
    /// files use mode 0600 and new directories 0700; source metadata is not
    /// preserved by this content-only profile.
    ///
    /// Publication uses renameat2(RENAME_NOREPLACE). A concurrent destination
    /// creation is never silently overwritten. The two-rename overwrite can
    /// stop after quarantine; receipts distinguish that state from publication.
    /// Once publication begins, cancellation drains that operation before
    /// returning its real result. No cross-tree atomicity is claimed.
    ///
    /// # Errors
    ///
    /// The outer error means runtime dispatch/retirement failed. An operation
    /// that ran returns its actual partial report, with failure populated.
    pub async fn apply(
        self,
        cx: &Cx,
        authorization: DestructiveAuthorization,
        staging_root: impl Into<PathBuf>,
    ) -> Result<NativeDirectorySyncReport, NativeDirectoryError> {
        let staging_root = staging_root.into();
        cx.scoped_fs()
            .run_io(move |worker| {
                Ok(apply_owned(&worker, self, authorization, &staging_root))
            })
            .await
            .map_err(NativeDirectoryError::Runtime)
    }
}

fn apply_owned(
    cx: &Cx,
    mut prepared: PreparedNativeDirectorySync,
    authorization: DestructiveAuthorization,
    staging_path: &Path,
) -> NativeDirectorySyncReport {
    let mut report = NativeDirectorySyncReport {
        plan_id: prepared.plan_id.clone(),
        dry_run: authorization.dry_run,
        complete: false,
        actions: prepared.preview.decisions.iter().map(|decision| {
            NativeDirectoryActionReceipt {
                path: decision.path.clone(),
                action: decision.action,
                state: NativeDirectoryActionState::NotStarted,
                bytes_written: 0,
                staged_path: None,
                quarantine_path: None,
                durable: false,
            }
        }).collect(),
        staging_directory: None,
        verified_baseline: None,
        failure: None,
    };
    let result = (|| {
        checkpoint(cx)?;
        prepared.limits.validate()?;
        let expected = preflight_actions(&prepared, authorization)?;
        revalidate_complete(cx, &prepared.local, prepared.limits)?;
        revalidate_complete(cx, &prepared.remote, prepared.limits)?;
        revalidate_stamps(cx, &prepared.local)?;
        revalidate_stamps(cx, &prepared.remote)?;
        prepared.local.root.revalidate()?;
        prepared.remote.root.revalidate()?;
        preflight_overwrites(cx, &prepared)?;
        if authorization.dry_run {
            return Ok(());
        }
        if prepared.preview.is_noop() {
            for receipt in &mut report.actions {
                receipt.state = NativeDirectoryActionState::Unchanged;
                receipt.durable = true;
            }
            report.verified_baseline = Some(expected);
            report.complete = true;
            return Ok(());
        }

        let staging_root = preflight_staging(&prepared, staging_path)?;
        checkpoint(cx)?;
        let directory_name = format!("asupersync-sync-{}", prepared.plan_id);
        let job_path = staging_root.path.join(&directory_name);
        mkdirat(&staging_root.file, directory_name.as_str(), Mode::S_IRWXU)
            .map_err(|error| os_error(&job_path, error))?;
        report.staging_directory = Some(job_path.clone());
        let staging = File::from(
            openat(
                &staging_root.file, directory_name.as_str(), directory_flags(), Mode::empty(),
            ).map_err(|error| os_error(&job_path, error))?,
        );
        let job_stamp = metadata_stamp(&staging, &job_path)?;
        if job_stamp.uid != geteuid().as_raw()
            || job_stamp.gid != getegid().as_raw()
            || job_stamp.mode & 0o7777 != 0o700
        {
            return Err(refused(&job_path, "staging directory ownership or permissions differ"));
        }
        staging_root.file.sync_all().map_err(|source| io_error(&staging_root.path, source))?;

        for (index, decision) in prepared.preview.decisions.iter().enumerate() {
            checkpoint(cx)?;
            staging_root.revalidate()?;
            let current_job = stat_at(&staging_root.file, directory_name.as_str(), &job_path)?
                .ok_or_else(|| changed(&job_path))?;
            if current_job.identity != job_stamp.identity {
                return Err(changed(&job_path));
            }
            let receipt = &mut report.actions[index];
            match decision.action {
                BidirectionalSyncAction::Keep => {
                    receipt.state = NativeDirectoryActionState::Unchanged;
                    receipt.durable = true;
                }
                BidirectionalSyncAction::CopyLocalToRemote => apply_copy(
                    cx, &prepared.local, &mut prepared.remote, decision,
                    &staging, &job_path, index, prepared.limits, receipt,
                )?,
                BidirectionalSyncAction::CopyRemoteToLocal => apply_copy(
                    cx, &prepared.remote, &mut prepared.local, decision,
                    &staging, &job_path, index, prepared.limits, receipt,
                )?,
                _ => return Err(refused(
                    Path::new(decision.path.as_str()), "unsupported action escaped preflight",
                )),
            }
        }

        // Both real trees, not the preview alone, establish a common baseline.
        let local = scan_again(cx, &prepared.local.root, prepared.limits)?;
        let remote = scan_again(cx, &prepared.remote.root, prepared.limits)?;
        if local.manifest != expected || remote.manifest != expected {
            return Err(refused(
                &prepared.local.root.path, "final inventories do not match the reviewed projection",
            ));
        }
        revalidate_stamps(cx, &local)?;
        revalidate_stamps(cx, &remote)?;
        local.root.revalidate()?;
        remote.root.revalidate()?;
        report.verified_baseline = Some(expected);
        report.complete = true;
        Ok(())
    })();
    if let Err(error) = result {
        report.failure = Some(error);
    }
    report
}

fn preflight_actions(
    prepared: &PreparedNativeDirectorySync,
    authorization: DestructiveAuthorization,
) -> Result<DirectoryManifest, NativeDirectoryError> {
    for decision in &prepared.preview.decisions {
        let path = Path::new(decision.path.as_str());
        let (source, destination) = match decision.action {
            BidirectionalSyncAction::Keep => continue,
            BidirectionalSyncAction::CopyLocalToRemote => (&decision.local, &decision.remote),
            BidirectionalSyncAction::CopyRemoteToLocal => (&decision.remote, &decision.local),
            BidirectionalSyncAction::Conflict { .. } => {
                return Err(refused(path, "unresolved conflict blocks the entire native plan"));
            }
            BidirectionalSyncAction::DeleteLocal | BidirectionalSyncAction::DeleteRemote => {
                return Err(refused(path, "native directory deletion is not supported"));
            }
        };
        let source = source.as_ref().ok_or_else(|| refused(path, "copy source is absent"))?;
        match (source.kind, destination.as_ref().map(|entry| entry.kind)) {
            (DirectoryEntryKind::File | DirectoryEntryKind::Directory, None) => {}
            (DirectoryEntryKind::File, Some(DirectoryEntryKind::File)) => {
                if !authorization.dry_run
                    && (!authorization.allow_overwrite || !authorization.allow_permission_change)
                {
                    return Err(refused(
                        path, "overwrite requires explicit overwrite and permission-change authorization",
                    ));
                }
            }
            _ => return Err(refused(path, "entry kind replacement is not supported")),
        }
    }
    let expected = prepared.preview.merged_manifest()
        .ok_or_else(|| refused(Path::new(""), "plan has no complete merged projection"))?;
    // The union can exceed a bound even when each input root fits individually.
    validate_profile(&expected, prepared.limits)?;
    Ok(expected)
}

fn preflight_overwrites(
    cx: &Cx,
    prepared: &PreparedNativeDirectorySync,
) -> Result<(), NativeDirectoryError> {
    for decision in &prepared.preview.decisions {
        let destination = match decision.action {
            BidirectionalSyncAction::CopyLocalToRemote if decision.remote.is_some() => &prepared.remote,
            BidirectionalSyncAction::CopyRemoteToLocal if decision.local.is_some() => &prepared.local,
            _ => continue,
        };
        checkpoint(cx)?;
        let (parent, name) = guarded_parent(destination, &decision.path)?;
        let display = destination.root.path.join(decision.path.as_str());
        let expected = destination.guards.get(&decision.path)
            .copied().ok_or_else(|| changed(&display))?;
        let file = open_guarded_file(&parent, name, &display, expected)?;
        validate_overwrite_metadata(&file, expected, &display)?;
    }
    Ok(())
}

fn validate_overwrite_metadata(
    file: &File,
    expected: Stamp,
    path: &Path,
) -> Result<(), NativeDirectoryError> {
    if expected.mode & 0o7000 != 0
        || expected.uid != geteuid().as_raw()
        || expected.gid != getegid().as_raw()
    {
        return Err(refused(path, "overwrite cannot preserve special modes or different ownership"));
    }
    if file.list_xattr().map_err(|source| io_error(path, source))?.next().is_some() {
        return Err(refused(path, "overwrite cannot preserve visible extended metadata"));
    }
    if metadata_stamp(file, path)? != expected {
        return Err(changed(path));
    }
    Ok(())
}

fn preflight_staging(
    prepared: &PreparedNativeDirectorySync,
    path: &Path,
) -> Result<NativeRoot, NativeDirectoryError> {
    let staging = NativeRoot::open(path)?;
    disjoint_roots(&staging, &prepared.local.root)?;
    disjoint_roots(&staging, &prepared.remote.root)?;
    if staging.identity.device != prepared.local.root.identity.device
        || staging.identity.device != prepared.remote.root.identity.device
        || prepared.local.guards.values().chain(prepared.remote.guards.values())
            .any(|stamp| stamp.identity == staging.identity)
    {
        return Err(refused(path, "staging must be external on the same filesystem as both roots"));
    }
    let stamp = metadata_stamp(&staging.file, path)?;
    if stamp.uid != geteuid().as_raw() || stamp.mode & 0o7022 != 0 {
        return Err(refused(path, "staging root requires user ownership and private write access"));
    }
    if staging.file.list_xattr().map_err(|source| io_error(path, source))?.next().is_some() {
        return Err(refused(path, "staging root has unsupported extended metadata"));
    }
    Ok(staging)
}

fn scan_again(
    cx: &Cx,
    root: &NativeRoot,
    limits: NativeDirectoryLimits,
) -> Result<NativeDirectorySnapshot, NativeDirectoryError> {
    root.revalidate()?;
    scan_root(cx, NativeRoot {
        path: root.path.clone(),
        file: root.file.try_clone().map_err(|source| io_error(&root.path, source))?,
        identity: root.identity,
    }, limits)
}

fn revalidate_complete(
    cx: &Cx,
    expected: &NativeDirectorySnapshot,
    limits: NativeDirectoryLimits,
) -> Result<(), NativeDirectoryError> {
    let actual = scan_again(cx, &expected.root, limits)?;
    if actual.manifest != expected.manifest
        || actual.guards != expected.guards
        || actual.root_stamp != expected.root_stamp
    {
        return Err(changed(&expected.root.path));
    }
    Ok(())
}

fn guarded_parent<'a>(
    snapshot: &NativeDirectorySnapshot,
    path: &'a DirectoryPath,
) -> Result<(File, &'a str), NativeDirectoryError> {
    snapshot.root.revalidate()?;
    if metadata_stamp(&snapshot.root.file, &snapshot.root.path)? != snapshot.root_stamp {
        return Err(changed(&snapshot.root.path));
    }
    let (parent, name) = open_parent(&snapshot.root, path)?;
    for (index, _) in path.as_str().match_indices('/') {
        let ancestor = DirectoryPath::normalize(
            &path.as_str()[..index], snapshot.manifest.path_rules,
        ).map_err(NativeDirectoryError::Manifest)?;
        let (above, name) = open_parent(&snapshot.root, &ancestor)?;
        let display = snapshot.root.path.join(ancestor.as_str());
        if stat_at(&above, name, &display)? != snapshot.guards.get(&ancestor).copied() {
            return Err(changed(&display));
        }
    }
    // Bind the returned parent descriptor to the final checked ancestor.
    let expected_parent = match path.as_str().rsplit_once('/') {
        Some((prefix, _)) => {
            let prefix = DirectoryPath::normalize(prefix, snapshot.manifest.path_rules)
                .map_err(NativeDirectoryError::Manifest)?;
            snapshot.guards.get(&prefix).copied()
                .ok_or_else(|| changed(&snapshot.root.path.join(prefix.as_str())))?
        }
        None => snapshot.root_stamp,
    };
    if metadata_stamp(&parent, &snapshot.root.path)? != expected_parent {
        return Err(changed(&snapshot.root.path.join(path.as_str())));
    }
    Ok((parent, name))
}

fn open_guarded_file(
    parent: &File,
    name: &str,
    path: &Path,
    expected: Stamp,
) -> Result<File, NativeDirectoryError> {
    if expected.kind(path)? != DirectoryEntryKind::File
        || stat_at(parent, name, path)? != Some(expected)
    {
        return Err(changed(path));
    }
    let file = File::from(
        openat(parent, name, file_flags(), Mode::empty()).map_err(|error| os_error(path, error))?,
    );
    if metadata_stamp(&file, path)? != expected {
        return Err(changed(path));
    }
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
fn apply_copy(
    cx: &Cx,
    source: &NativeDirectorySnapshot,
    destination: &mut NativeDirectorySnapshot,
    decision: &BidirectionalSyncDecision,
    staging: &File,
    staging_path: &Path,
    index: usize,
    limits: NativeDirectoryLimits,
    receipt: &mut NativeDirectoryActionReceipt,
) -> Result<(), NativeDirectoryError> {
    let path = &decision.path;
    let source_path = source.root.path.join(path.as_str());
    let destination_path = destination.root.path.join(path.as_str());
    let entry = source.manifest.entries.get(path).ok_or_else(|| changed(&source_path))?;
    let source_stamp = source.guards.get(path).copied().ok_or_else(|| changed(&source_path))?;
    let (source_parent, source_name) = guarded_parent(source, path)?;
    if stat_at(&source_parent, source_name, &source_path)? != Some(source_stamp) {
        return Err(changed(&source_path));
    }
    let (destination_parent, destination_name) = guarded_parent(destination, path)?;
    let previous = destination.guards.get(path).copied();
    if stat_at(&destination_parent, destination_name, &destination_path)? != previous {
        return Err(changed(&destination_path));
    }

    if entry.kind == DirectoryEntryKind::Directory {
        checkpoint(cx)?;
        mkdirat(&destination_parent, destination_name, Mode::S_IRWXU)
            .map_err(|error| os_error(&destination_path, error))?;
        receipt.state = NativeDirectoryActionState::Published;
        let created = File::from(
            openat(&destination_parent, destination_name, directory_flags(), Mode::empty())
                .map_err(|error| os_error(&destination_path, error))?,
        );
        created.sync_all().map_err(|source| io_error(&destination_path, source))?;
        destination_parent.sync_all().map_err(|source| io_error(&destination_path, source))?;
        receipt.durable = true;
        return record_destination(destination, entry, &destination_parent, &created);
    }

    let mut source_file = open_guarded_file(
        &source_parent, source_name, &source_path, source_stamp,
    )?;
    let staging_name = format!("new-{index:08x}");
    let staged_path = staging_path.join(&staging_name);
    let mut staged = File::from(
        openat(
            staging, staging_name.as_str(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ).map_err(|error| os_error(&staged_path, error))?,
    );
    receipt.state = NativeDirectoryActionState::Staged;
    receipt.staged_path = Some(staged_path.clone());
    let digest = copy_bytes(
        cx, &mut source_file, &mut staged, source_stamp, &source_path, &staged_path,
        limits, &mut receipt.bytes_written,
    )?;
    if Some(digest.as_str()) != entry.content_id.as_deref() {
        return Err(changed(&source_path));
    }
    let mode = previous.map_or(0o600, |stamp| stamp.mode & 0o777);
    staged.set_permissions(Permissions::from_mode(mode))
        .map_err(|source| io_error(&staged_path, source))?;
    let mut staged_stamp = metadata_stamp(&staged, &staged_path)?;
    if staged_stamp.uid != geteuid().as_raw()
        || staged_stamp.gid != getegid().as_raw()
        || staged_stamp.mode & 0o7777 != mode
    {
        return Err(refused(&staged_path, "staged file ownership or permissions differ"));
    }
    staged.sync_all().map_err(|source| io_error(&staged_path, source))?;
    staged_stamp = metadata_stamp(&staged, &staged_path)?;

    // Revalidate after potentially long copying and immediately before effects.
    let (source_parent, source_name) = guarded_parent(source, path)?;
    if stat_at(&source_parent, source_name, &source_path)? != Some(source_stamp)
        || metadata_stamp(&source_file, &source_path)? != source_stamp
    {
        return Err(changed(&source_path));
    }
    let (destination_parent, destination_name) = guarded_parent(destination, path)?;
    if stat_at(&destination_parent, destination_name, &destination_path)? != previous {
        return Err(changed(&destination_path));
    }
    if let Some(previous) = previous {
        let previous_file = open_guarded_file(
            &destination_parent, destination_name, &destination_path, previous,
        )?;
        validate_overwrite_metadata(&previous_file, previous, &destination_path)?;
        let previous_entry = destination.manifest.entries.get(path)
            .ok_or_else(|| changed(&destination_path))?;
        let digest = super::hash_file(cx, &previous_file, previous, &destination_path, limits)?;
        if Some(digest.as_str()) != previous_entry.content_id.as_deref() {
            return Err(changed(&destination_path));
        }
        // The original bytes must be recoverable before its name is moved.
        previous_file.sync_all().map_err(|source| io_error(&destination_path, source))?;
    }

    // Hashing the old destination can itself be long. Bind both paths again.
    let (source_parent, source_name) = guarded_parent(source, path)?;
    if stat_at(&source_parent, source_name, &source_path)? != Some(source_stamp)
        || metadata_stamp(&source_file, &source_path)? != source_stamp
    {
        return Err(changed(&source_path));
    }
    let (destination_parent, destination_name) = guarded_parent(destination, path)?;
    if stat_at(&destination_parent, destination_name, &destination_path)? != previous {
        return Err(changed(&destination_path));
    }
    verify_staged(staging, staging_path, &staged, &staging_name, staged_stamp)?;
    checkpoint(cx)?;
    // No cancellation boundary inside quarantine + publish + directory sync.
    if let Some(previous) = previous {
        quarantine_previous(
            &destination_parent, destination_name, &destination_path, previous,
            staging, staging_path, index, receipt,
        )?;
    }
    publish_staged(
        staging, staging_path, &staged, &staging_name, staged_stamp,
        &destination_parent, destination_name, &destination_path, receipt,
    )?;
    record_destination(destination, entry, &destination_parent, &staged)
}

fn verify_staged(
    staging: &File,
    staging_path: &Path,
    staged: &File,
    name: &str,
    expected: Stamp,
) -> Result<(), NativeDirectoryError> {
    let named_directory = NativeRoot::open(staging_path)?;
    if named_directory.identity != metadata_stamp(staging, staging_path)?.identity {
        return Err(changed(staging_path));
    }
    let path = staging_path.join(name);
    if stat_at(staging, name, &path)? != Some(expected)
        || metadata_stamp(staged, &path)? != expected
    {
        return Err(changed(&path));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn quarantine_previous(
    destination_parent: &File,
    destination_name: &str,
    destination_path: &Path,
    previous: Stamp,
    staging: &File,
    staging_path: &Path,
    index: usize,
    receipt: &mut NativeDirectoryActionReceipt,
) -> Result<(), NativeDirectoryError> {
    let name = format!("previous-{index:08x}");
    let path = staging_path.join(&name);
    renameat2(
        destination_parent, destination_name, staging, name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    ).map_err(|error| os_error(destination_path, error))?;
    receipt.state = NativeDirectoryActionState::Quarantined;
    receipt.quarantine_path = Some(path.clone());
    if stat_at(staging, name.as_str(), &path)?
        .is_none_or(|stamp| stamp.identity != previous.identity)
    {
        return Err(changed(&path));
    }
    // Keep a durable recovery name even when later publication is refused.
    staging.sync_all().map_err(|source| io_error(staging_path, source))?;
    destination_parent.sync_all().map_err(|source| io_error(destination_path, source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_staged(
    staging: &File,
    staging_path: &Path,
    staged: &File,
    staging_name: &str,
    staged_stamp: Stamp,
    destination_parent: &File,
    destination_name: &str,
    destination_path: &Path,
    receipt: &mut NativeDirectoryActionReceipt,
) -> Result<(), NativeDirectoryError> {
    verify_staged(staging, staging_path, staged, staging_name, staged_stamp)?;
    renameat2(
        staging, staging_name, destination_parent, destination_name,
        RenameFlags::RENAME_NOREPLACE,
    ).map_err(|error| os_error(destination_path, error))?;
    receipt.state = NativeDirectoryActionState::Published;
    receipt.staged_path = None;
    destination_parent.sync_all().map_err(|source| io_error(destination_path, source))?;
    staging.sync_all().map_err(|source| io_error(staging_path, source))?;
    receipt.durable = true;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn copy_bytes(
    cx: &Cx,
    source: &mut File,
    destination: &mut File,
    expected: Stamp,
    source_path: &Path,
    destination_path: &Path,
    limits: NativeDirectoryLimits,
    written: &mut u64,
) -> Result<String, NativeDirectoryError> {
    let mut buffer = vec![0; limits.buffer_bytes];
    let mut digest = Sha256::new();
    let mut read_total = 0_u64;
    loop {
        checkpoint(cx)?;
        let count = source.read(&mut buffer).map_err(|source| io_error(source_path, source))?;
        if count == 0 {
            break;
        }
        read_total = read_total.checked_add(count as u64)
            .filter(|total| *total <= expected.size && *total <= limits.max_file_bytes)
            .ok_or_else(|| changed(source_path))?;
        let mut offset = 0;
        while offset < count {
            checkpoint(cx)?;
            let count_written = destination.write(&buffer[offset..count])
                .map_err(|source| io_error(destination_path, source))?;
            if count_written == 0 {
                return Err(io_error(destination_path, std::io::Error::new(
                    std::io::ErrorKind::WriteZero, "staging write made no progress",
                )));
            }
            offset += count_written;
            *written += count_written as u64;
        }
        digest.update(&buffer[..count]);
    }
    if read_total != expected.size || metadata_stamp(source, source_path)? != expected {
        return Err(changed(source_path));
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn record_destination(
    destination: &mut NativeDirectorySnapshot,
    entry: &DirectoryManifestEntry,
    parent: &File,
    published: &File,
) -> Result<(), NativeDirectoryError> {
    let path = &entry.path;
    let display = destination.root.path.join(path.as_str());
    let published_stamp = metadata_stamp(published, &display)?;
    destination.guards.insert(path.clone(), published_stamp);
    destination.manifest.entries.insert(path.clone(), entry.clone());
    if let Some((prefix, _)) = path.as_str().rsplit_once('/') {
        let prefix = DirectoryPath::normalize(prefix, destination.manifest.path_rules)
            .map_err(NativeDirectoryError::Manifest)?;
        destination.guards.insert(prefix, metadata_stamp(parent, &display)?);
    } else {
        destination.root_stamp = metadata_stamp(parent, &destination.root.path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
