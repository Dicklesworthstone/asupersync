//! Native restart, state-publication and lease-lifetime regressions.
//!
//! Fixtures and displaced contents are retained; tests never unlink recovery data.

use super::*;
use crate::atp::sync::BidirectionalSyncAction;
use crate::runtime::RuntimeBuilder;
use crate::sync::atomic::{AtomicU64, Ordering};
use crate::types::CancelKind;
use std::fs::{self, File, Permissions, TryLockError};
use std::future::{Future, poll_fn};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

const STATE_LIMIT: usize = 1024 * 1024;
const WATCHDOG: Duration = Duration::from_secs(45);

struct Roots {
    base: PathBuf,
    local: PathBuf,
    remote: PathBuf,
    state: PathBuf,
    staging: PathBuf,
}

impl Roots {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let base = loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                "asupersync-native-session-{label}-{}-{sequence}", std::process::id(),
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create retained session fixture: {error}"),
            }
        };
        let roots = Self {
            local: base.join("local"), remote: base.join("remote"),
            state: base.join("state"), staging: base.join("staging"), base,
        };
        for directory in [&roots.local, &roots.remote, &roots.state, &roots.staging] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
        }
        roots
    }

    fn current(&self) -> PathBuf { self.state.join("current.state") }

    async fn create(&self, cx: &Cx) -> NativeDirectorySyncSession {
        NativeDirectorySyncSession::create(cx, &self.local, &self.remote, &self.state,
            NativeDirectoryLimits::default(), STATE_LIMIT).await.unwrap()
    }

    async fn reopen(&self, cx: &Cx) -> NativeDirectorySyncSession {
        NativeDirectorySyncSession::reopen(cx, &self.local, &self.remote, &self.state,
            NativeDirectoryLimits::default(), STATE_LIMIT).await.unwrap()
    }
}

fn native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        crate::time::timeout(cx.now(), WATCHDOG, test(cx)).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(WATCHDOG), "leased blocking workers must retire");
}

fn authorized() -> DestructiveAuthorization {
    DestructiveAuthorization {
        dry_run: false, allow_delete: true, allow_overwrite: true,
        allow_permission_change: true, ..DestructiveAuthorization::default()
    }
}

fn action(plan: &PreparedNativeDirectorySessionSync<'_>, path: &str) -> BidirectionalSyncAction {
    plan.preview().decisions.iter().find(|item| item.path.as_str() == path).unwrap().action
}

fn durable(report: &NativeDirectorySessionReport, generation: u64) {
    assert!(report.sync.complete, "{:?}", report.sync.failure);
    assert!(report.sync.failure.is_none());
    assert!(report.persistence_failure.is_none(), "{:?}", report.persistence_failure);
    assert_eq!(report.baseline_generation, generation);
    assert_eq!(report.publication, NativeDirectoryStatePublication::Durable { generation });
}

#[test]
fn native_session_restart_preserves_bidirectional_edit_and_subtree_deletion_history() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let roots = Roots::new("restart");
            fs::write(roots.local.join("a"), b"version one").unwrap();
            fs::create_dir_all(roots.local.join("old/deep")).unwrap();
            fs::write(roots.local.join("old/deep/payload"), b"retired subtree").unwrap();
            fs::write(roots.remote.join("remote-note"), b"remote original").unwrap();
            let mut session = roots.create(&cx).await;
            assert_eq!(session.generation(), 0);
            assert!(session.baseline().is_none(), "creation does not assert a common inventory");
            let initial = session.prepare(&cx).await.unwrap();
            assert_eq!(action(&initial, "a"), BidirectionalSyncAction::CopyLocalToRemote);
            assert_eq!(action(&initial, "remote-note"), BidirectionalSyncAction::CopyRemoteToLocal);
            let report = initial.apply(&cx, authorized(), &roots.staging).await.unwrap();
            durable(&report, 1);
            let first_baseline = session.baseline().unwrap().clone();
            drop(session);

            let mut session = roots.reopen(&cx).await;
            assert_eq!(session.generation(), 1);
            assert_eq!(session.baseline(), Some(&first_baseline));
            fs::write(roots.local.join("a"), b"version two").unwrap();
            fs::rename(roots.remote.join("remote-note"), roots.base.join("retired-remote-note")).unwrap();
            let next = session.prepare(&cx).await.unwrap();
            assert_eq!(action(&next, "a"), BidirectionalSyncAction::CopyLocalToRemote);
            assert_eq!(action(&next, "remote-note"), BidirectionalSyncAction::DeleteLocal);
            let report = next.apply(&cx, authorized(), &roots.staging).await.unwrap();
            durable(&report, 2);
            assert_eq!(fs::read(roots.remote.join("a")).unwrap(), b"version two");
            assert!(!roots.local.join("remote-note").exists());
            let retired_note = report.sync.actions.iter().find(|item| item.path.as_str() == "remote-note")
                .unwrap().quarantine_path.as_ref().unwrap();
            assert_eq!(fs::read(retired_note).unwrap(), b"remote original");
            drop(session);

            let mut session = roots.reopen(&cx).await;
            fs::rename(roots.local.join("old"), roots.base.join("retired-local-subtree")).unwrap();
            fs::write(roots.remote.join("a"), b"remote version three").unwrap();
            let next = session.prepare(&cx).await.unwrap();
            assert_eq!(action(&next, "a"), BidirectionalSyncAction::CopyRemoteToLocal);
            for path in ["old", "old/deep", "old/deep/payload"] {
                assert_eq!(action(&next, path), BidirectionalSyncAction::DeleteRemote);
            }
            let report = next.apply(&cx, authorized(), &roots.staging).await.unwrap();
            durable(&report, 3);
            assert!(!roots.remote.join("old").exists());
            assert_eq!(fs::read(roots.local.join("a")).unwrap(), b"remote version three");
            assert!(report.sync.actions.iter().filter(|item| item.path.as_str().starts_with("old"))
                .all(|item| item.durable && item.quarantine_path.as_ref().unwrap().exists()));
            assert_eq!(fs::read_dir(&roots.state).unwrap().count(), 3, "only two snapshots and a lock");
            let first = session.prepare(&cx).await.unwrap();
            assert!(first.preview().is_noop());
            let first_id = first.plan_id().to_owned();
            drop(first);
            let second = session.prepare(&cx).await.unwrap();
            assert_ne!(second.plan_id(), first_id, "repeated reviews have separate recovery jobs");
            drop(second);
            drop(session);
            assert_eq!(roots.reopen(&cx).await.generation(), 3);
        });
    }
}

#[test]
fn native_session_refuses_second_writer_swapped_roots_and_replaced_root_inode() {
    native(2, |cx| async move {
        let roots = Roots::new("binding");
        let session = roots.create(&cx).await;
        let current = fs::read(roots.current()).unwrap();
        let limits = NativeDirectoryLimits::default();
        let second = NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
            limits, STATE_LIMIT).await;
        assert!(matches!(second, Err(NativeDirectoryError::Refused { reason, .. })
            if reason.contains("writer lease")));
        assert!(NativeDirectorySyncSession::create(&cx, &roots.local, &roots.remote, &roots.state,
            limits, STATE_LIMIT).await.is_err());
        drop(session);
        assert!(NativeDirectorySyncSession::reopen(&cx, &roots.remote, &roots.local, &roots.state,
            limits, STATE_LIMIT).await.is_err());
        let original_inode = fs::metadata(&roots.local).unwrap().ino();
        fs::rename(&roots.local, roots.base.join("retained-original-root")).unwrap();
        fs::create_dir(&roots.local).unwrap();
        assert_ne!(fs::metadata(&roots.local).unwrap().ino(), original_inode);
        assert!(NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
            limits, STATE_LIMIT).await.is_err());
        assert_eq!(fs::read(roots.current()).unwrap(), current);
    });
}

#[test]
fn native_session_missing_or_corrupt_current_never_promotes_inactive_history() {
    native(1, |cx| async move {
        for corrupt in [false, true] {
            let roots = Roots::new(if corrupt { "corrupt" } else { "missing" });
            let mut session = roots.create(&cx).await;
            fs::write(roots.local.join("payload"), b"common content").unwrap();
            let report = session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.unwrap();
            durable(&report, 1);
            drop(session);
            let previous = fs::read(roots.state.join("next.state")).unwrap();
            assert!(!previous.is_empty());
            if corrupt {
                let mut bytes = fs::read(roots.current()).unwrap();
                *bytes.last_mut().unwrap() ^= 0x80;
                fs::write(roots.current(), bytes).unwrap();
            } else {
                fs::rename(roots.current(), roots.base.join("retained-current.state")).unwrap();
            }
            assert!(NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
                NativeDirectoryLimits::default(), STATE_LIMIT).await.is_err());
            assert_eq!(fs::read(roots.state.join("next.state")).unwrap(), previous);
        }
        let roots = Roots::new("partial-inactive");
        let mut session = roots.create(&cx).await;
        let report = session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.unwrap();
        durable(&report, 1);
        let current = fs::read(roots.current()).unwrap();
        drop(session);
        fs::write(roots.state.join("next.state"), b"interrupted next snapshot").unwrap();
        let session = roots.reopen(&cx).await;
        assert_eq!(session.generation(), 1);
        assert_eq!(fs::read(roots.current()).unwrap(), current);
    });
}

#[test]
fn native_session_bounds_refuse_oversized_decode_and_projected_state_before_tree_effects() {
    native(1, |cx| async move {
        let roots = Roots::new("projected-bound");
        let session = roots.create(&cx).await;
        let current = fs::read(roots.current()).unwrap();
        drop(session);
        let mut session = NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
            NativeDirectoryLimits::default(), current.len()).await.unwrap();
        fs::write(roots.local.join("new"), b"would exceed empty-state bound").unwrap();
        let error = session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.unwrap_err();
        assert!(matches!(error, NativeDirectoryError::Limit { limit: "max_state_bytes", .. }));
        assert_eq!(session.generation(), 0);
        assert!(!session.is_fenced(), "observed effect-free refusal remains usable");
        assert!(session.baseline().is_none());
        assert!(!roots.remote.join("new").exists());
        assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0);
        assert_eq!(fs::read(roots.current()).unwrap(), current);
        drop(session);
        let file = fs::OpenOptions::new().write(true).open(roots.current()).unwrap();
        file.set_len((STATE_LIMIT + 1) as u64).unwrap();
        assert!(matches!(NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
            NativeDirectoryLimits::default(), STATE_LIMIT).await,
            Err(NativeDirectoryError::Limit { limit: "max_state_bytes", .. })));

        let roots = Roots::new("entry-bound");
        let mut session = roots.create(&cx).await;
        for name in ["a", "b"] { fs::write(roots.local.join(name), name).unwrap(); }
        durable(&session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.unwrap(), 1);
        drop(session);
        for (side, directory) in [("local", &roots.local), ("remote", &roots.remote)] {
            for name in ["a", "b"] {
                fs::rename(directory.join(name), roots.base.join(format!("retained-{side}-{name}"))).unwrap();
            }
        }
        // Both current trees fit one entry; only the persisted two-entry record
        // exceeds it, exercising the decoder's pre-allocation count admission.
        assert!(matches!(NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
            NativeDirectoryLimits { max_entries: 1, ..NativeDirectoryLimits::default() }, STATE_LIMIT).await,
            Err(NativeDirectoryError::Limit { limit: "max_entries", .. })));
    });
}

#[test]
fn native_session_state_slots_reject_links_symlinks_and_overlap() {
    native(1, |cx| async move {
        for symbolic in [false, true] {
            let roots = Roots::new(if symbolic { "symlink" } else { "hardlink" });
            drop(roots.create(&cx).await);
            let retained = roots.base.join("retained-state");
            if symbolic {
                fs::rename(roots.current(), &retained).unwrap();
                symlink(&retained, roots.current()).unwrap();
            } else {
                fs::hard_link(roots.current(), &retained).unwrap();
            }
            assert!(NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
                NativeDirectoryLimits::default(), STATE_LIMIT).await.is_err());
            assert!(!fs::read(retained).unwrap().is_empty());
        }
        let roots = Roots::new("overlap");
        let nested = roots.local.join("state");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, Permissions::from_mode(0o700)).unwrap();
        assert!(NativeDirectorySyncSession::create(&cx, &roots.local, &roots.remote, &nested,
            NativeDirectoryLimits::default(), STATE_LIMIT).await.is_err());
        assert_eq!(fs::read_dir(&nested).unwrap().count(), 0);
        let mut session = roots.create(&cx).await;
        let before = fs::read(roots.current()).unwrap();
        assert!(session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.state).await.is_err());
        assert_eq!(fs::read(roots.current()).unwrap(), before);
    });
}

#[test]
fn native_session_dry_run_conflict_stale_plan_and_generation_exhaustion_preserve_history() {
    native(2, |cx| async move {
        let roots = Roots::new("preflight");
        let mut session = roots.create(&cx).await;
        fs::write(roots.local.join("a"), b"first").unwrap();
        let original = fs::read(roots.current()).unwrap();
        let dry = session.prepare(&cx).await.unwrap().apply(&cx, DestructiveAuthorization::default(), &roots.staging).await.unwrap();
        assert!(dry.sync.dry_run && !dry.sync.complete);
        assert_eq!(dry.publication, NativeDirectoryStatePublication::Unchanged);
        assert!(session.baseline().is_none());
        assert!(!roots.remote.join("a").exists());
        assert_eq!(fs::read(roots.current()).unwrap(), original);
        fs::write(roots.remote.join("a"), b"independent creation").unwrap();
        let conflict = session.prepare(&cx).await.unwrap();
        assert!(conflict.preview().has_conflicts());
        let report = conflict.apply(&cx, authorized(), &roots.staging).await.unwrap();
        assert!(report.sync.failure.is_some());
        assert_eq!(report.publication, NativeDirectoryStatePublication::Unchanged);
        assert_eq!(session.generation(), 0);
        assert_eq!(fs::read(roots.current()).unwrap(), original);
        fs::write(roots.remote.join("a"), b"first").unwrap();
        durable(&session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.unwrap(), 1);
        let common = fs::read(roots.current()).unwrap();
        fs::write(roots.local.join("a"), b"second").unwrap();
        let stale = session.prepare(&cx).await.unwrap();
        fs::write(roots.local.join("a"), b"third after review").unwrap();
        let report = stale.apply(&cx, authorized(), &roots.staging).await.unwrap();
        assert!(!report.sync.complete && report.sync.failure.is_some());
        assert_eq!(report.publication, NativeDirectoryStatePublication::Unchanged);
        assert_eq!(session.generation(), 1);
        assert!(!session.is_fenced());
        assert_eq!(fs::read(roots.current()).unwrap(), common);
        assert_eq!(fs::read(roots.remote.join("a")).unwrap(), b"first");
        session.generation = u64::MAX;
        assert!(session.prepare(&cx).await.unwrap().apply(&cx, authorized(), &roots.staging).await.is_err());
        assert_eq!(fs::read(roots.current()).unwrap(), common);
        assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0, "all earlier effects were dry-run/refused/no-op");
    });
}

#[test]
fn native_session_failed_directory_sync_reports_real_publication_and_retains_previous_slot() {
    native(1, |cx| async move {
        let roots = Roots::new("uncertain-durability");
        let mut session = roots.create(&cx).await;
        let previous = fs::read(roots.current()).unwrap();
        fs::write(roots.local.join("payload"), b"actually applied").unwrap();
        let report = session.prepare(&cx).await.unwrap().apply_with_directory_sync(
            &cx, authorized(), roots.staging.clone(), |_| Err(io::Error::other("injected directory sync failure")),
        ).await.unwrap();
        assert!(report.sync.complete, "tree effects really completed");
        assert!(report.sync.verified_baseline.is_some());
        assert!(report.persistence_failure.is_some());
        assert_eq!(report.publication, NativeDirectoryStatePublication::Published { generation: 1 });
        assert_eq!(report.baseline_generation, 0);
        assert!(session.is_fenced());
        assert!(session.baseline().is_none());
        assert!(session.prepare(&cx).await.is_err());
        assert_eq!(fs::read(roots.remote.join("payload")).unwrap(), b"actually applied");
        assert_eq!(fs::read(roots.state.join("next.state")).unwrap(), previous);
        assert_ne!(fs::read(roots.current()).unwrap(), previous);
        drop(session);
        let reopened = roots.reopen(&cx).await;
        assert_eq!(reopened.generation(), 1, "reopen validates the complete visible current slot");
        assert!(reopened.baseline().unwrap().entries.keys().any(|path| path.as_str() == "payload"));
    });
}

#[test]
fn native_session_abandoned_publication_keeps_writer_lease_until_worker_retirement() {
    native(2, |cx| async move {
        let roots = Roots::new("abandoned");
        let mut session = roots.create(&cx).await;
        fs::write(roots.local.join("payload"), b"committed by owned worker").unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let prepared = session.prepare(&cx).await.unwrap();
        let mut applying = Box::pin(prepared.apply_with_directory_sync(
            &cx, authorized(), roots.staging.clone(), move |directory| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(20)).expect("release final sync gate");
                directory.sync_all()
            },
        ));
        poll_fn(|task| {
            assert!(applying.as_mut().poll(task).is_pending(), "publication remains gated");
            if entered_rx.try_recv().is_ok() { Poll::Ready(()) }
            else { task.waker().wake_by_ref(); Poll::Pending }
        }).await;
        drop(applying);
        assert!(session.is_fenced());
        assert_eq!(session.generation(), 0, "the awaiting caller did not observe durability");
        drop(session);
        let competing = File::options().read(true).write(true).open(roots.state.join("lock")).unwrap();
        assert!(matches!(competing.try_lock(), Err(TryLockError::WouldBlock)), "started worker still owns lease");
        drop(competing);
        release_tx.send(()).unwrap();
        let reopened = loop {
            match NativeDirectorySyncSession::reopen(&cx, &roots.local, &roots.remote, &roots.state,
                NativeDirectoryLimits::default(), STATE_LIMIT).await {
                Ok(session) => break session,
                Err(NativeDirectoryError::Refused { reason, .. }) if reason.contains("writer lease") => {
                    crate::runtime::yield_now().await;
                }
                Err(error) => panic!("reopen after owned retirement: {error}"),
            }
        };
        assert_eq!(reopened.generation(), 1);
        assert_eq!(fs::read(roots.remote.join("payload")).unwrap(), b"committed by owned worker");
    });
}

#[test]
fn native_session_cancellation_before_dispatch_and_after_exchange_respects_history_boundaries() {
    native(2, |cx| async move {
        let roots = Roots::new("cancel");
        fs::write(roots.local.join("payload"), b"actual session copy").unwrap();
        let mut session = roots.create(&cx).await;
        let original = fs::read(roots.current()).unwrap();
        let prepared = session.prepare(&cx).await.unwrap();
        // A derived context retains the real runtime gateway and task ownership,
        // while its cancellation does not poison the test's reopening context.
        let cancelled = cx.derive_cancel_scope();
        cancelled.cancel_with(CancelKind::User, Some("before session apply dispatch"));
        let error = prepared.apply(&cancelled, authorized(), &roots.staging).await.unwrap_err();
        assert!(matches!(error, NativeDirectoryError::Runtime(crate::fs::scoped::ScopedFsError::Checkpoint(_))));
        assert_eq!(session.generation(), 0);
        assert!(session.baseline().is_none());
        assert_eq!(fs::read(roots.current()).unwrap(), original);
        assert!(!roots.remote.join("payload").exists());
        assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0);
        drop(session);

        let mut session = roots.reopen(&cx).await;
        let caller = cx.derive_cancel_scope();
        let cancelling_owner = caller.clone();
        let report = session.prepare(&cx).await.unwrap().apply_with_directory_sync(
            &caller, authorized(), roots.staging.clone(), move |directory| {
                // This seam is entered only after actual tree application and
                // state exchange. The commit section must retire its real sync.
                cancelling_owner.cancel_with(CancelKind::User, Some("after real state exchange"));
                directory.sync_all()
            },
        ).await.unwrap();
        durable(&report, 1);
        assert!(caller.is_cancel_requested());
        assert!(!cx.is_cancel_requested());
        assert!(!session.is_fenced());
        assert_eq!(fs::read(roots.remote.join("payload")).unwrap(), b"actual session copy");
        assert_eq!(fs::read(roots.state.join("next.state")).unwrap(), original);
        drop(session);
        assert_eq!(roots.reopen(&cx).await.generation(), 1);
    });
}
