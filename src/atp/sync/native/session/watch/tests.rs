//! Real local trees, explicit review grants, and native watch retirement.
//! Fixtures and quarantined originals are retained rather than unlinked.

use super::{NativeDirectoryWatch, NativeDirectoryWatchConfig, NativeDirectoryWatchError};
use crate::atp::sync::native::{
    NativeDirectoryLimits, NativeDirectorySessionReport, NativeDirectoryStatePublication,
    NativeDirectorySyncSession, PreparedNativeDirectorySync,
};
use crate::atp::sync::{BidirectionalSyncAction, DestructiveAuthorization};
use crate::cx::Cx;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::CancelKind;
use std::fs::{self, Permissions};
use std::future::{Future, poll_fn};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

const STATE_LIMIT: usize = 1024 * 1024;
const WATCHDOG: Duration = Duration::from_secs(30);

struct Roots {
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
            let path = parent.join(format!(
                "asupersync-native-watch-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create retained watch fixture: {error}"),
            }
        };
        let roots = Self {
            local: base.join("local"),
            remote: base.join("remote"),
            state: base.join("state"),
            staging: base.join("staging"),
        };
        for path in [&roots.local, &roots.remote, &roots.state, &roots.staging] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
        }
        roots
    }

    async fn create(&self, cx: &Cx) -> NativeDirectorySyncSession {
        NativeDirectorySyncSession::create(
            cx,
            &self.local,
            &self.remote,
            &self.state,
            NativeDirectoryLimits::default(),
            STATE_LIMIT,
        )
        .await
        .unwrap()
    }

    async fn reopen(&self, cx: &Cx) -> NativeDirectorySyncSession {
        NativeDirectorySyncSession::reopen(
            cx,
            &self.local,
            &self.remote,
            &self.state,
            NativeDirectoryLimits::default(),
            STATE_LIMIT,
        )
        .await
        .unwrap()
    }
}

fn config(observations: u32) -> NativeDirectoryWatchConfig {
    NativeDirectoryWatchConfig {
        poll_interval: Duration::from_millis(1),
        settle_observations: observations,
    }
}

fn grants() -> DestructiveAuthorization {
    DestructiveAuthorization {
        dry_run: false,
        allow_delete: true,
        allow_overwrite: true,
        allow_permission_change: true,
        ..DestructiveAuthorization::default()
    }
}

fn native<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    let runtime = builder.blocking_threads(0, 2).build().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let cx = Cx::current().expect("native watch owner");
            crate::time::timeout(cx.now(), WATCHDOG, scenario(cx))
                .await
                .expect("native watch watchdog");
        });
    }));
    let drain = runtime.shutdown_drained(WATCHDOG);
    let stopped = runtime.shutdown_timeout(WATCHDOG);
    assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
    assert_eq!(drain.live_tasks, 0, "{drain:?}");
    assert_eq!(drain.live_regions, 0, "{drain:?}");
    assert_eq!(drain.pending_spawns, 0, "{drain:?}");
    assert_eq!(drain.pending_obligations, 0, "{drain:?}");
    assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
    assert!(!drain.has_pending_obligation_posts, "{drain:?}");
    assert!(stopped, "native watch workers must retire");
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn action(plan: &PreparedNativeDirectorySync, path: &str) -> BidirectionalSyncAction {
    plan.preview()
        .decisions
        .iter()
        .find(|decision| decision.path.as_str() == path)
        .unwrap()
        .action
}

fn durable(report: &NativeDirectorySessionReport, generation: u64) {
    assert!(report.sync.complete, "{:?}", report.sync.failure);
    assert!(!report.sync.dry_run);
    assert!(report.sync.failure.is_none());
    assert!(report.persistence_failure.is_none());
    assert_eq!(report.baseline_generation, generation);
    assert_eq!(
        report.publication,
        NativeDirectoryStatePublication::Durable { generation }
    );
}

async fn observe_real_inventory(watch: &mut NativeDirectoryWatch, cx: &Cx) -> bool {
    let prepared = watch.session.prepare_owned(cx).await.unwrap();
    watch.observe(prepared)
}

#[test]
fn native_watch_applies_exact_review_and_preserves_durable_bidirectional_history() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let roots = Roots::new("review-and-restart");
            fs::write(roots.local.join("payload"), b"local original").unwrap();
            let mut watch = roots.create(&cx).await.into_watch(config(1)).unwrap();
            let plan = watch.next_review(&cx).await.unwrap();
            assert_eq!(
                action(plan, "payload"),
                BidirectionalSyncAction::CopyLocalToRemote
            );
            let first = plan.plan_id().to_owned();
            assert!(
                !roots.remote.join("payload").exists(),
                "observation has no tree effects"
            );
            assert_eq!(watch.next_review(&cx).await.unwrap().plan_id(), first);
            assert!(matches!(
                watch.decline_pending("unreviewed-plan"),
                Err(NativeDirectoryWatchError::ReviewMismatch)
            ));
            assert!(matches!(
                watch
                    .apply_pending(&cx, "unreviewed-plan", grants(), &roots.staging)
                    .await,
                Err(NativeDirectoryWatchError::ReviewMismatch)
            ));
            assert_eq!(watch.pending_review().unwrap().plan_id(), first);
            assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0);
            let report = watch
                .apply_pending(&cx, &first, grants(), &roots.staging)
                .await
                .unwrap();
            durable(&report, 1);
            assert_eq!(
                fs::read(roots.remote.join("payload")).unwrap(),
                b"local original"
            );
            assert!(!watch.is_stopped());
            assert!(watch.pending_review().is_none());
            assert!(
                !observe_real_inventory(&mut watch, &cx).await,
                "durable convergence must not create another no-op review"
            );
            drop(watch);

            let mut watch = roots.reopen(&cx).await.into_watch(config(1)).unwrap();
            assert_eq!(watch.generation(), 1);
            fs::write(roots.remote.join("payload"), b"remote edit after restart").unwrap();
            let plan = watch.next_review(&cx).await.unwrap();
            assert_eq!(
                action(plan, "payload"),
                BidirectionalSyncAction::CopyRemoteToLocal
            );
            let next = plan.plan_id().to_owned();
            assert_ne!(first, next);
            let report = watch
                .apply_pending(&cx, &next, grants(), &roots.staging)
                .await
                .unwrap();
            durable(&report, 2);
            let original = report
                .sync
                .actions
                .iter()
                .find(|entry| entry.path.as_str() == "payload")
                .unwrap()
                .quarantine_path
                .as_ref()
                .unwrap();
            assert_eq!(fs::read(original).unwrap(), b"local original");
            assert_eq!(
                fs::read(roots.local.join("payload")).unwrap(),
                b"remote edit after restart"
            );
            drop(watch);
            assert_eq!(roots.reopen(&cx).await.generation(), 2);
        });
    }
}

#[test]
fn native_watch_coalesces_changed_inventories_and_declines_without_reoffering() {
    native(1, |cx| async move {
        let roots = Roots::new("coalescing");
        let mut watch = roots.create(&cx).await.into_watch(config(2)).unwrap();
        fs::write(roots.local.join("payload"), b"first transient content").unwrap();
        assert!(!observe_real_inventory(&mut watch, &cx).await);
        fs::write(roots.local.join("payload"), b"second stable content").unwrap();
        assert!(
            !observe_real_inventory(&mut watch, &cx).await,
            "a changed scan resets the consecutive stability count"
        );
        assert!(observe_real_inventory(&mut watch, &cx).await);
        let first = watch.pending_review().unwrap().plan_id().to_owned();
        assert!(!roots.remote.join("payload").exists());
        watch.decline_pending(&first).unwrap();
        assert!(!observe_real_inventory(&mut watch, &cx).await);
        assert!(
            !observe_real_inventory(&mut watch, &cx).await,
            "fresh execution nonces must not reoffer declined content"
        );
        fs::write(roots.local.join("payload"), b"final approved content").unwrap();
        assert!(!observe_real_inventory(&mut watch, &cx).await);
        assert!(observe_real_inventory(&mut watch, &cx).await);
        let final_id = watch.pending_review().unwrap().plan_id().to_owned();
        assert_ne!(first, final_id);
        let report = watch
            .apply_pending(&cx, &final_id, grants(), &roots.staging)
            .await
            .unwrap();
        durable(&report, 1);
        assert_eq!(
            fs::read(roots.remote.join("payload")).unwrap(),
            b"final approved content"
        );
        assert!(!observe_real_inventory(&mut watch, &cx).await);
        assert!(!observe_real_inventory(&mut watch, &cx).await);
        assert_eq!(
            fs::read_dir(&roots.staging).unwrap().count(),
            1,
            "only the single authorized application retains a staging job"
        );
    });
}

#[test]
fn native_watch_dry_run_preserves_history_and_failed_grants_stop_without_retry() {
    native(2, |cx| async move {
        let roots = Roots::new("dry-and-refused");
        fs::write(roots.local.join("payload"), b"common").unwrap();
        let mut watch = roots.create(&cx).await.into_watch(config(1)).unwrap();
        let before = fs::read(roots.state.join("current.state")).unwrap();
        let id = watch.next_review(&cx).await.unwrap().plan_id().to_owned();
        let dry = watch
            .apply_pending(
                &cx,
                &id,
                DestructiveAuthorization::default(),
                &roots.staging,
            )
            .await
            .unwrap();
        assert!(dry.sync.dry_run && !dry.sync.complete);
        assert!(dry.sync.failure.is_none());
        assert_eq!(dry.publication, NativeDirectoryStatePublication::Unchanged);
        assert!(!watch.is_stopped());
        assert_eq!(watch.generation(), 0);
        assert_eq!(fs::read(roots.state.join("current.state")).unwrap(), before);
        assert!(!roots.remote.join("payload").exists());
        fs::write(roots.local.join("payload"), b"changed after dry run").unwrap();
        let id = watch.next_review(&cx).await.unwrap().plan_id().to_owned();
        durable(
            &watch
                .apply_pending(&cx, &id, grants(), &roots.staging)
                .await
                .unwrap(),
            1,
        );
        let common = fs::read(roots.state.join("current.state")).unwrap();
        fs::write(roots.local.join("payload"), b"replacement needs permission").unwrap();
        let id = watch.next_review(&cx).await.unwrap().plan_id().to_owned();
        let denied = DestructiveAuthorization {
            dry_run: false,
            ..DestructiveAuthorization::default()
        };
        let report = watch
            .apply_pending(&cx, &id, denied, &roots.staging)
            .await
            .unwrap();
        assert!(!report.sync.complete && report.sync.failure.is_some());
        assert!(watch.is_stopped());
        assert!(matches!(
            watch.next_review(&cx).await,
            Err(NativeDirectoryWatchError::Stopped)
        ));
        assert_eq!(
            fs::read(roots.remote.join("payload")).unwrap(),
            b"changed after dry run"
        );
        assert_eq!(fs::read(roots.state.join("current.state")).unwrap(), common);
        assert_eq!(watch.generation(), 1);
    });
}

#[test]
fn native_watch_stale_review_reports_failure_without_replanning_around_it() {
    native(1, |cx| async move {
        let roots = Roots::new("stale");
        fs::write(roots.local.join("payload"), b"reviewed").unwrap();
        let mut watch = roots.create(&cx).await.into_watch(config(1)).unwrap();
        let id = watch.next_review(&cx).await.unwrap().plan_id().to_owned();
        fs::write(roots.local.join("payload"), b"unreviewed change").unwrap();
        let report = watch
            .apply_pending(&cx, &id, grants(), &roots.staging)
            .await
            .unwrap();
        assert_eq!(report.sync.plan_id, id);
        assert!(!report.sync.complete && report.sync.failure.is_some());
        assert!(watch.is_stopped());
        assert!(!roots.remote.join("payload").exists());
        assert_eq!(watch.generation(), 0);
        assert!(matches!(
            watch.next_review(&cx).await,
            Err(NativeDirectoryWatchError::Stopped)
        ));
        assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0);
    });
}

#[test]
fn native_watch_cancelled_or_dropped_idle_wait_retires_timer_without_fencing_session() {
    native(1, |cx| async move {
        for cancel in [false, true] {
            let roots = Roots::new(if cancel { "idle-cancel" } else { "idle-drop" });
            let mut watch = roots
                .create(&cx)
                .await
                .into_watch(NativeDirectoryWatchConfig {
                    poll_interval: Duration::from_secs(3600),
                    settle_observations: 1,
                })
                .unwrap();
            let id = watch.next_review(&cx).await.unwrap().plan_id().to_owned();
            watch.decline_pending(&id).unwrap();
            let owner = cx.derive_cancel_scope();
            let timer = owner.timer_driver().unwrap();
            let before = timer.pending_count();
            let mut waiting = Box::pin(watch.next_review(&owner));
            poll_fn(|task| {
                assert!(waiting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                timer.pending_count(),
                before + 1,
                "the watch is parked on its owner timer"
            );
            if cancel {
                owner.cancel_with(CancelKind::User, Some("stop idle directory watch"));
                assert!(waiting.as_mut().await.is_err());
            }
            drop(waiting);
            assert_eq!(
                timer.pending_count(),
                before,
                "the watch must release its timer registration"
            );
            assert!(!watch.is_stopped());
            let mut session = watch.into_session();
            assert!(!session.is_fenced());
            assert!(session.prepare(&cx).await.unwrap().preview().is_noop());
        }
    });
}

#[test]
fn native_watch_abandoned_scan_cannot_be_reentered_or_laundered_into_session() {
    native(1, |cx| async move {
        let roots = Roots::new("scan-drop");
        let mut watch = roots.create(&cx).await.into_watch(config(1)).unwrap();
        let mut scanning = Box::pin(watch.next_review(&cx));
        poll_fn(|task| {
            assert!(
                scanning.as_mut().poll(task).is_pending(),
                "a current-thread scoped scan must await owned worker admission"
            );
            Poll::Ready(())
        })
        .await;
        drop(scanning);
        assert!(watch.is_stopped());
        assert!(watch.next_review(&cx).await.is_err());
        let mut session = watch.into_session();
        assert!(session.is_fenced());
        assert!(
            session.prepare(&cx).await.is_err(),
            "ownership conversion must preserve the fence"
        );
        assert_eq!(session.generation(), 0);
        assert_eq!(fs::read_dir(&roots.staging).unwrap().count(), 0);
    });
}

#[test]
fn native_watch_rejects_invalid_configuration_and_missing_timer_before_observation() {
    native(1, |cx| async move {
        for invalid in [
            NativeDirectoryWatchConfig {
                poll_interval: Duration::ZERO,
                settle_observations: 1,
            },
            config(0),
            config(1025),
        ] {
            let roots = Roots::new("invalid-config");
            assert!(matches!(
                roots.create(&cx).await.into_watch(invalid),
                Err(NativeDirectoryWatchError::InvalidConfig)
            ));
            assert_eq!(roots.reopen(&cx).await.generation(), 0);
        }
        let roots = Roots::new("timer-horizon");
        let too_long = cx
            .timer_driver()
            .unwrap()
            .max_timer_duration()
            .checked_add(Duration::from_secs(1))
            .expect("finite native timer horizon");
        let mut watch = roots
            .create(&cx)
            .await
            .into_watch(NativeDirectoryWatchConfig {
                poll_interval: too_long,
                settle_observations: 1,
            })
            .unwrap();
        assert!(matches!(
            watch.next_review(&cx).await,
            Err(NativeDirectoryWatchError::InvalidConfig)
        ));
        assert!(!watch.is_stopped());
        assert!(watch.pending_review().is_none());
        let mut session = watch.into_session();
        assert!(!session.is_fenced());
        assert!(session.prepare(&cx).await.unwrap().preview().is_noop());
        drop(session);
        let roots = Roots::new("timer-authority");
        let mut watch = roots.create(&cx).await.into_watch(config(1)).unwrap();
        let detached = Cx::for_testing();
        assert!(matches!(
            watch.next_review(&detached).await,
            Err(NativeDirectoryWatchError::Timer(_))
        ));
        assert!(!watch.is_stopped());
        assert!(watch.pending_review().is_none());
        assert!(watch.next_review(&cx).await.unwrap().preview().is_noop());
    });
}
