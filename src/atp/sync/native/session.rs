//! Durable root-bound reconciliation history over the existing native engine.

use super::{
    BidirectionalSyncPlan, DirectoryManifest, NativeDirectoryError, NativeDirectoryLimits,
    NativeDirectorySnapshot, NativeDirectorySyncReport, NativePlanBaseline, PreparedNativeDirectorySync,
    Stamp, apply, checkpoint, prepare_native_directory_owned, refused,
};
use crate::atp::sync::DestructiveAuthorization;
use crate::cx::Cx;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod state;
mod watch;
pub use watch::{NativeDirectoryWatch, NativeDirectoryWatchConfig, NativeDirectoryWatchError};
#[cfg(test)]
mod tests;

/// Last observed boundary of a common-baseline publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeDirectoryStatePublication {
    /// The previously published snapshot was not replaced.
    Unchanged,
    /// Writing the inactive slot began; it may contain incomplete bytes.
    Staging {
        /// Proposed generation, not a durable common-baseline claim.
        generation: u64,
    },
    /// The complete snapshot became current, but directory durability is unconfirmed.
    Published {
        /// Generation visible at the publication boundary.
        generation: u64,
    },
    /// Both the complete snapshot and containing directory were synced.
    Durable {
        /// New durably published generation.
        generation: u64,
    },
}

/// Actual tree effects and their separate persistent-history outcome.
///
/// `sync.complete` alone does not mean that the new baseline was persisted.
/// Inspect `publication` and `persistence_failure`. Failed tree application
/// preserves the previous baseline and all native recovery receipts. A failed
/// publication fences the session until it is dropped and reopened.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDirectorySessionReport {
    /// Unmodified result from the existing native application engine.
    pub sync: NativeDirectorySyncReport,
    /// Last generation whose durable publication this caller observed.
    pub baseline_generation: u64,
    /// Actual state-file boundary, separate from tree application.
    pub publication: NativeDirectoryStatePublication,
    /// Failure to persist the verified common inventory, if application succeeded.
    pub persistence_failure: Option<NativeDirectoryError>,
}

/// An exclusively leased, restartable native directory reconciliation session.
///
/// This Linux/glibc content-only profile binds history to the exact canonical
/// paths and device/inode identities of both roots and the private state
/// directory. A session holds an operating-system advisory writer lock. Every
/// started scoped blocking job retains that lease even if its awaiting future
/// is dropped. Callers must still exclusively own the synchronization roots;
/// advisory locks do not constrain an unrelated process with write authority.
///
/// State consists of two bounded canonical snapshots and a lock file. A new
/// snapshot is synced in the inactive slot, atomically exchanged with current,
/// then the directory is synced. The displaced complete snapshot is retained.
/// Failed or abandoned publication requires reopen; reopen reads only current,
/// never guesses whether an inactive snapshot should be promoted. The checksum
/// detects corruption, not malicious rewriting by someone who owns the state.
/// There is no whole-tree transaction, crash rollback, or automatic quarantine
/// cleanup. Native recovery data remains available in the reported staging job.
#[derive(Debug)]
pub struct NativeDirectorySyncSession {
    lease: Arc<state::Lease>,
    baseline: DirectoryManifest,
    generation: u64,
    current: Stamp,
    limits: NativeDirectoryLimits,
    max_state_bytes: usize,
    fenced: bool,
}

impl NativeDirectorySyncSession {
    /// Create new history in an existing empty private directory.
    ///
    /// Generation zero has **no prior common history**. Its empty comparison
    /// baseline gives conservative creation/conflict semantics; existing roots
    /// are not declared synchronized by creating a session. The first successful
    /// reviewed application establishes generation one, including an authorized
    /// no-op application of two already equal roots.
    ///
    /// State must be outside both roots, mode 0700, and owned by the effective
    /// user/group. `max_state_bytes` is a per-slot bound in 1..=64 MiB; even the
    /// empty record must fit. Both root inventories are validated under `limits`
    /// before creating state. Nothing existing is replaced or removed. If initial
    /// publication fails, inspect the retained directory and use explicit reopen
    /// if it has a valid current snapshot; create never silently resets history.
    ///
    /// # Errors
    /// Refuses existing state, overlap/aliasing, unsupported filesystem objects,
    /// exceeded bounds, unavailable capabilities, cancellation, and I/O failure.
    pub async fn create(
        cx: &Cx,
        local_root: impl Into<PathBuf>,
        remote_root: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        limits: NativeDirectoryLimits,
        max_state_bytes: usize,
    ) -> Result<Self, NativeDirectoryError> {
        Self::open(cx, local_root.into(), remote_root.into(), state_directory.into(), limits,
            max_state_bytes, true).await
    }

    /// Reopen exact existing history; missing or invalid state is never reset.
    ///
    /// Roots must have the original canonical paths and device/inode identities.
    /// The private fixed slots must remain singly linked regular files. The byte
    /// limit is checked before reads or allocation, and canonical entries, order,
    /// digest, counts, root bindings and native profile limits are all validated.
    /// The inactive slot may contain an interrupted write and is never loaded as
    /// history. Opening also checks current root inventories for state aliases,
    /// then syncs the validated current slot and directory to resolve a prior
    /// publication whose durability was not observed.
    ///
    /// # Errors
    /// Refuses another active writer, mismatched/replaced roots, malformed or
    /// oversized state, unsupported inventories, cancellation, and I/O failure.
    pub async fn reopen(
        cx: &Cx,
        local_root: impl Into<PathBuf>,
        remote_root: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        limits: NativeDirectoryLimits,
        max_state_bytes: usize,
    ) -> Result<Self, NativeDirectoryError> {
        Self::open(cx, local_root.into(), remote_root.into(), state_directory.into(), limits,
            max_state_bytes, false).await
    }

    async fn open(
        cx: &Cx,
        local: PathBuf,
        remote: PathBuf,
        directory: PathBuf,
        limits: NativeDirectoryLimits,
        max_state_bytes: usize,
        create: bool,
    ) -> Result<Self, NativeDirectoryError> {
        limits.validate()?;
        state::validate_bound(max_state_bytes)?;
        let opened = cx.scoped_fs().run_io(move |worker| {
            Ok(state::open(&worker, &local, &remote, &directory, limits, max_state_bytes, create))
        }).await.map_err(NativeDirectoryError::Runtime)??;
        Ok(Self {
            lease: opened.lease,
            baseline: opened.baseline,
            generation: opened.generation,
            current: opened.current,
            limits,
            max_state_bytes,
            fenced: false,
        })
    }

    /// Last durably observed generation; zero means no prior common history.
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }

    /// Last durably observed common inventory, absent before first application.
    ///
    /// When fenced, the current slot may already contain a newer generation.
    /// Reopen to resolve that outcome before making another plan.
    #[must_use]
    pub fn baseline(&self) -> Option<&DirectoryManifest> {
        (self.generation != 0).then_some(&self.baseline)
    }

    /// Private directory containing the two state slots and writer lease.
    #[must_use]
    pub fn state_directory(&self) -> &Path { &self.lease.directory.path }

    /// Whether an abandoned job or persistence failure requires drop and reopen.
    #[must_use]
    pub const fn is_fenced(&self) -> bool { self.fenced }

    /// Scan both actual roots and review their changes against persisted history.
    ///
    /// The returned value borrows this session exclusively and owns the existing
    /// opaque native plan. Conflicts are visible in `preview`; no authorization
    /// or mutation is implied. Fresh context entropy separates retained staging
    /// jobs even when the same content changes recur after a restart.
    ///
    /// # Errors
    /// Refuses a fenced handle, changed state/root bindings, unavailable entropy,
    /// unsupported or unstable inventories, cancellation, and I/O failure.
    pub async fn prepare(
        &mut self,
        cx: &Cx,
    ) -> Result<PreparedNativeDirectorySessionSync<'_>, NativeDirectoryError> {
        self.require_ready()?;
        let prepared = self.prepare_owned(cx).await?;
        Ok(PreparedNativeDirectorySessionSync { session: self, prepared })
    }

    // Callers check require_ready before entering. The watch surface then
    // fences its session while this read-only job is in flight, so abandoning
    // a scan cannot start another worker before the retained lease retires.
    async fn prepare_owned(
        &self,
        cx: &Cx,
    ) -> Result<PreparedNativeDirectorySync, NativeDirectoryError> {
        checkpoint(cx)?;
        if !cx.capabilities().entropy {
            return Err(refused(self.state_directory(), "session preparation requires context entropy"));
        }
        let mut nonce = [0_u8; 16];
        cx.random_bytes(&mut nonce);
        let lease = Arc::clone(&self.lease);
        let baseline = self.baseline.clone();
        let generation = self.generation;
        let current = self.current;
        let limits = self.limits;
        let max_state_bytes = self.max_state_bytes;
        let prepared = cx.scoped_fs().run_io(move |worker| {
            Ok((|| {
                lease.validate_current(&worker, current, max_state_bytes)?;
                let mut prepared = prepare_native_directory_owned(
                    &worker, NativePlanBaseline::Common(baseline), &lease.local.path,
                    &lease.remote.path, limits,
                )?;
                lease.check_prepared(&worker, &prepared, max_state_bytes)?;
                let mut hash = Sha256::new();
                hash.update(b"asupersync.native-directory-session-plan.v1\0");
                hash.update(prepared.plan_id.as_bytes());
                hash.update(generation.to_be_bytes());
                hash.update(lease.directory.identity.device.to_be_bytes());
                hash.update(lease.directory.identity.inode.to_be_bytes());
                hash.update(nonce);
                prepared.plan_id = hex::encode(hash.finalize());
                Ok(prepared)
            })())
        }).await.map_err(NativeDirectoryError::Runtime)??;
        Ok(prepared)
    }

    fn require_ready(&self) -> Result<(), NativeDirectoryError> {
        if self.fenced {
            return Err(refused(self.state_directory(), "session outcome is unresolved; drop and reopen"));
        }
        Ok(())
    }
}

/// A single reviewed reconciliation borrowing its durable session exclusively.
#[derive(Debug)]
pub struct PreparedNativeDirectorySessionSync<'a> {
    session: &'a mut NativeDirectorySyncSession,
    prepared: PreparedNativeDirectorySync,
}

impl PreparedNativeDirectorySessionSync<'_> {
    /// Existing deterministic three-way decisions, including unresolved conflicts.
    #[must_use]
    pub fn preview(&self) -> &BidirectionalSyncPlan { self.prepared.preview() }

    /// Identity unique to this review and its retained recovery staging job.
    #[must_use]
    pub fn plan_id(&self) -> &str { self.prepared.plan_id() }

    /// Captured local inventory.
    #[must_use]
    pub fn local(&self) -> &NativeDirectorySnapshot { self.prepared.local() }

    /// Captured remote inventory.
    #[must_use]
    pub fn remote(&self) -> &NativeDirectorySnapshot { self.prepared.remote() }

    /// Apply reviewed changes and durably advance history only after convergence.
    ///
    /// Uses the existing quarantined-deletion engine, its explicit authorization
    /// gates, full stale-plan checks, and actual partial receipts. Staging must
    /// also be outside this session's state directory. Its existing directory
    /// metadata is walked under the session's entry/depth bounds to detect aliases;
    /// retained staging contents are not hashed. Generation overflow and
    /// an oversized projected snapshot refuse before tree effects. Dry runs and
    /// failed applications leave common history unchanged.
    ///
    /// The lease, application and publication belong to one scoped blocking job.
    /// Dropping the future does not release the writer lock while that job runs;
    /// it leaves the handle fenced. Cancellation during scanning/copying or
    /// inactive-state writing stops at existing bounded checkpoints. Once state
    /// exchange starts, that exchange and its directory sync retire together.
    /// A persistence failure retains the actual sync report and fences the handle.
    ///
    /// # Errors
    /// Preflight errors have no tree effects. An outer runtime error can lose the
    /// observation of a started job; the handle stays fenced until reopened. A
    /// completed job returns tree and persistence failures in their separate
    /// report fields, including all already completed native effects.
    pub async fn apply(
        self,
        cx: &Cx,
        authorization: DestructiveAuthorization,
        staging_root: impl Into<PathBuf>,
    ) -> Result<NativeDirectorySessionReport, NativeDirectoryError> {
        self.apply_with_directory_sync(cx, authorization, staging_root.into(), std::fs::File::sync_all).await
    }

    // Production always syncs the real directory. Native tests can observe or
    // fail this final boundary after a real exchange, without changing engines.
    async fn apply_with_directory_sync<F>(
        self,
        cx: &Cx,
        authorization: DestructiveAuthorization,
        staging: PathBuf,
        sync_directory: F,
    ) -> Result<NativeDirectorySessionReport, NativeDirectoryError>
    where
        F: FnOnce(&std::fs::File) -> std::io::Result<()> + Send + 'static,
    {
        let Self { session, prepared } = self;
        session.require_ready()?;
        let next_generation = session.generation.checked_add(1).ok_or_else(|| {
            refused(session.state_directory(), "session generation is exhausted")
        })?;
        let lease = Arc::clone(&session.lease);
        let current = session.current;
        let limits = session.limits;
        let max_state_bytes = session.max_state_bytes;
        session.fenced = true;
        let result = cx.scoped_fs().run_io(move |worker| {
            Ok((|| {
                lease.validate_current(&worker, current, max_state_bytes)?;
                lease.check_prepared(&worker, &prepared, max_state_bytes)?;
                lease.check_staging(&worker, &staging, limits)?;
                if !authorization.dry_run {
                    if let Some(projected) = prepared.preview.merged_manifest() {
                        state::encoded_size(&worker, &projected, max_state_bytes)?;
                    }
                }
                let sync = apply::apply_owned(&worker, prepared, authorization, &staging, true);
                let mut publication = NativeDirectoryStatePublication::Unchanged;
                let mut persistence_failure = None;
                let mut updated = None;
                if sync.complete && !sync.dry_run {
                    if let Some(baseline) = &sync.verified_baseline {
                        match state::publish_with_directory_sync(
                            &worker, &lease, Some(current), next_generation, baseline, limits,
                            max_state_bytes, &mut publication, sync_directory,
                        ) {
                            Ok(stamp) => updated = Some((baseline.clone(), stamp)),
                            Err(error) => persistence_failure = Some(error),
                        }
                    } else {
                        persistence_failure = Some(refused(
                            &lease.directory.path, "completed application has no verified baseline",
                        ));
                    }
                }
                Ok((sync, publication, persistence_failure, updated))
            })())
        }).await.map_err(NativeDirectoryError::Runtime)?;
        let (sync, publication, persistence_failure, updated) = match result {
            Ok(result) => result,
            Err(error) => {
                session.fenced = false;
                return Err(error);
            }
        };
        if let Some((baseline, current)) = updated {
            session.baseline = baseline;
            session.current = current;
            session.generation = next_generation;
        }
        session.fenced = persistence_failure.is_some();
        Ok(NativeDirectorySessionReport {
            sync,
            baseline_generation: session.generation,
            publication,
            persistence_failure,
        })
    }
}
