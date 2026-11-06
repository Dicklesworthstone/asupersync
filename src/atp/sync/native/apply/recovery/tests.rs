use super::*;
use crate::atp::sync::native::{
    prepare_native_directory_mirror, prepare_native_directory_sync, scan_native_directory,
};
use crate::runtime::RuntimeBuilder;
use crate::sync::atomic::{AtomicU64, Ordering};
use std::fs::{self, Permissions};
use std::future::Future;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

fn native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) }.build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(45), test(cx)).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(30)));
}

// Keep all fixtures and recovery artifacts: tests never erase retained data.
fn roots(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let base = loop {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "asupersync-native-recovery-{label}-{}-{sequence}", std::process::id(),
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create recovery fixture: {error}"),
        }
    };
    let local = base.join("local");
    let remote = base.join("remote");
    let staging = base.join("staging");
    for path in [&local, &remote, &staging] { fs::create_dir(path).unwrap(); }
    fs::set_permissions(&staging, Permissions::from_mode(0o700)).unwrap();
    (local, remote, staging)
}

fn authorized() -> DestructiveAuthorization {
    DestructiveAuthorization {
        dry_run: false, allow_delete: true, allow_overwrite: true,
        allow_permission_change: true, ..DestructiveAuthorization::default()
    }
}

async fn mirror(
    cx: &Cx, local: &Path, remote: &Path, staging: &Path, limits: NativeDirectoryLimits,
) -> NativeDirectorySyncReport {
    let report = prepare_native_directory_mirror(cx, local, remote, limits).await.unwrap()
        .apply_with_quarantined_deletions(cx, authorized(), staging).await.unwrap();
    assert!(report.complete, "{:?}", report.failure);
    report
}

fn unstarted(report: &NativeDirectoryRecoveryReport) {
    assert!(!report.complete);
    assert!(report.actions.iter().all(|entry| {
        entry.state == NativeDirectoryRecoveryState::NotStarted && !entry.durable
    }));
}

#[test]
fn native_recovery_restores_deleted_subtree_inodes_and_retains_newly_copied_entries() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let (local, remote, staging) = roots("subtree");
            fs::create_dir_all(remote.join("old/deep")).unwrap();
            fs::create_dir(remote.join("empty")).unwrap();
            fs::write(remote.join("old/deep/payload"), b"original subtree bytes").unwrap();
            fs::write(local.join("new"), b"newly copied entry must remain").unwrap();
            let paths = ["empty", "old", "old/deep", "old/deep/payload"];
            let inodes: Vec<_> = paths.iter().map(|path| fs::metadata(remote.join(path)).unwrap().ino()).collect();
            let limits = NativeDirectoryLimits { buffer_bytes: 7, ..NativeDirectoryLimits::default() };
            let report = mirror(&cx, &local, &remote, &staging, limits).await;
            assert!(!remote.join("old").exists());
            let recovery = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits)
                .await.unwrap();
            assert_eq!(recovery.preview().len(), paths.len());
            assert!(recovery.preview().iter().all(|entry| entry.current.is_none()));
            let restored = recovery.apply(&cx, DestructiveAuthorization {
                dry_run: false, ..DestructiveAuthorization::default()
            }).await.unwrap();
            assert!(restored.complete, "{:?}", restored.failure);
            assert!(restored.actions.iter().all(|entry| {
                entry.state == NativeDirectoryRecoveryState::Restored && entry.durable
                    && !entry.quarantine_path.exists()
            }));
            for (path, inode) in paths.iter().zip(inodes) {
                assert_eq!(fs::metadata(remote.join(path)).unwrap().ino(), inode);
            }
            assert_eq!(fs::read(remote.join("old/deep/payload")).unwrap(), b"original subtree bytes");
            assert_eq!(fs::read(remote.join("new")).unwrap(), b"newly copied entry must remain");
            assert!(!local.join("old").exists(), "recovery must not manufacture a common baseline");
        });
    }
}

#[test]
fn native_recovery_exchange_requires_consent_and_retains_the_current_inode() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("exchange");
        fs::write(local.join("file"), b"new contents").unwrap();
        fs::write(remote.join("file"), b"old contents").unwrap();
        let old_inode = fs::metadata(remote.join("file")).unwrap().ino();
        let limits = NativeDirectoryLimits::default();
        let report = mirror(&cx, &local, &remote, &staging, limits).await;
        let current_inode = fs::metadata(remote.join("file")).unwrap().ino();
        let retained = report.actions[0].quarantine_path.as_ref().unwrap();
        for authorization in [
            DestructiveAuthorization::default(),
            DestructiveAuthorization { dry_run: false, ..DestructiveAuthorization::default() },
            DestructiveAuthorization { dry_run: false, allow_overwrite: true, ..DestructiveAuthorization::default() },
        ] {
            let prepared = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.unwrap();
            assert_ne!(prepared.preview()[0].quarantined.content_id,
                prepared.preview()[0].current.as_ref().unwrap().content_id);
            let result = prepared.apply(&cx, authorization).await.unwrap();
            unstarted(&result);
            assert_eq!(result.failure.is_none(), authorization.dry_run);
            assert_eq!(fs::metadata(remote.join("file")).unwrap().ino(), current_inode);
            assert_eq!(fs::metadata(retained).unwrap().ino(), old_inode);
        }
        let restored = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits)
            .await.unwrap().apply(&cx, authorized()).await.unwrap();
        assert!(restored.complete, "{:?}", restored.failure);
        assert_eq!(restored.actions[0].state, NativeDirectoryRecoveryState::Exchanged);
        assert!(restored.actions[0].durable);
        assert_eq!(fs::read(remote.join("file")).unwrap(), b"old contents");
        assert_eq!(fs::metadata(remote.join("file")).unwrap().ino(), old_inode);
        assert_eq!(fs::read(retained).unwrap(), b"new contents");
        assert_eq!(fs::metadata(retained).unwrap().ino(), current_inode);
        assert_eq!(fs::read(local.join("file")).unwrap(), b"new contents");
        assert_eq!(fs::read_dir(staging).unwrap().count(), 1, "recovery creates no second job");
    });
}

#[test]
fn native_recovery_routes_bidirectional_originals_to_their_own_roots() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("directions");
        for root in [&local, &remote] {
            fs::write(root.join("left"), b"left original").unwrap();
            fs::write(root.join("right"), b"right original").unwrap();
        }
        let left_inode = fs::metadata(local.join("left")).unwrap().ino();
        let right_inode = fs::metadata(remote.join("right")).unwrap().ino();
        let limits = NativeDirectoryLimits::default();
        let baseline = scan_native_directory(&cx, &local, limits).await.unwrap().manifest().clone();
        fs::rename(remote.join("left"), staging.join("observed-left-deletion")).unwrap();
        fs::rename(local.join("right"), staging.join("observed-right-deletion")).unwrap();
        let report = prepare_native_directory_sync(&cx, baseline, &local, &remote, limits)
            .await.unwrap().apply_with_quarantined_deletions(&cx, authorized(), &staging).await.unwrap();
        assert!(report.complete, "{:?}", report.failure);
        assert!(report.actions.iter().any(|entry| entry.action == BidirectionalSyncAction::DeleteLocal));
        assert!(report.actions.iter().any(|entry| entry.action == BidirectionalSyncAction::DeleteRemote));
        let recovery = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits)
            .await.unwrap().apply(&cx, authorized()).await.unwrap();
        assert!(recovery.complete, "{:?}", recovery.failure);
        assert_eq!(fs::metadata(local.join("left")).unwrap().ino(), left_inode);
        assert_eq!(fs::metadata(remote.join("right")).unwrap().ino(), right_inode);
        assert!(!local.join("right").exists());
        assert!(!remote.join("left").exists());
    });
}

#[test]
fn native_recovery_rejects_forged_paths_states_and_actions_without_effects() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("forged");
        fs::write(remote.join("file"), b"original").unwrap();
        let limits = NativeDirectoryLimits::default();
        let mut report = mirror(&cx, &local, &remote, &staging, limits).await;
        let original_name = report.actions[0].quarantine_path.clone();
        let outside = staging.join("unrelated");
        fs::write(&outside, b"never follow a reported arbitrary path").unwrap();
        report.actions[0].quarantine_path = Some(outside.clone());
        assert!(prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.is_err());
        report.actions[0].quarantine_path = original_name.clone();
        report.actions[0].state = NativeDirectoryActionState::Published;
        assert!(prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.is_err());
        report.actions[0].state = NativeDirectoryActionState::Quarantined;
        report.actions[0].action = BidirectionalSyncAction::Keep;
        assert!(prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.is_err());
        report.actions[0].action = BidirectionalSyncAction::DeleteRemote;
        let original_path = report.actions[0].path.clone();
        report.actions[0].path = serde_json::from_str("\"../escape\"").unwrap();
        assert!(prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.is_err());
        report.actions[0].path = original_path;
        report.plan_id = "A".repeat(64);
        assert!(prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.is_err());
        assert!(!remote.join("file").exists());
        assert_eq!(fs::read(original_name.unwrap()).unwrap(), b"original");
        assert_eq!(fs::read(outside).unwrap(), b"never follow a reported arbitrary path");
    });
}

#[test]
fn native_recovery_refuses_stale_quarantine_and_new_destination_before_any_rename() {
    for change_quarantine in [false, true] {
        native(2, move |cx| async move {
            let (local, remote, staging) = roots("stale");
            fs::write(remote.join("a"), b"first original").unwrap();
            fs::write(remote.join("z"), b"second original").unwrap();
            let limits = NativeDirectoryLimits::default();
            let report = mirror(&cx, &local, &remote, &staging, limits).await;
            let retained = report.actions[1].quarantine_path.as_ref().unwrap();
            let prepared = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits)
                .await.unwrap();
            let changed = if change_quarantine { retained.clone() } else { remote.join("z") };
            fs::write(&changed, b"concurrent replacement").unwrap();
            let result = prepared.apply(&cx, authorized()).await.unwrap();
            unstarted(&result);
            assert!(matches!(result.failure, Some(NativeDirectoryError::Changed { .. })));
            assert!(!remote.join("a").exists());
            assert_eq!(fs::read(changed).unwrap(), b"concurrent replacement");
            assert!(report.actions[0].quarantine_path.as_ref().unwrap().exists());
        });
    }
}

#[test]
fn native_recovery_checks_projected_bytes_and_refuses_directory_replacement() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("limits");
        fs::write(remote.join("old"), b"123456").unwrap();
        let report = mirror(&cx, &local, &remote, &staging, NativeDirectoryLimits::default()).await;
        fs::write(remote.join("new"), b"123456").unwrap();
        let limits = NativeDirectoryLimits { max_total_bytes: 8, ..NativeDirectoryLimits::default() };
        assert!(matches!(
            prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await,
            Err(NativeDirectoryError::Limit { limit: "max_total_bytes", .. })
        ));
        assert!(!remote.join("old").exists());
        fs::create_dir(remote.join("old")).unwrap();
        assert!(matches!(
            prepare_native_directory_recovery(&cx, &report, &local, &remote, NativeDirectoryLimits::default()).await,
            Err(NativeDirectoryError::Refused { .. })
        ));
        assert!(remote.join("old").is_dir());
        assert_eq!(fs::read(report.actions[0].quarantine_path.as_ref().unwrap()).unwrap(), b"123456");
    });
}

#[test]
fn native_recovery_preflights_exchange_quarantine_growth_and_refuses_symlink_sources() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("quarantine-bounds");
        for path in ["a", "b"] {
            fs::write(local.join(path), b"123456").unwrap();
            fs::write(remote.join(path), b"12").unwrap();
        }
        let report = mirror(&cx, &local, &remote, &staging, NativeDirectoryLimits::default()).await;
        fs::write(report.staging_directory.as_ref().unwrap().join("staged-partial"), b"12345678").unwrap();
        let limits = NativeDirectoryLimits { max_total_bytes: 12, ..NativeDirectoryLimits::default() };
        assert!(matches!(
            prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await,
            Err(NativeDirectoryError::Limit { limit: "max_total_bytes", .. })
        ));
        assert_eq!(fs::read(remote.join("a")).unwrap(), b"123456");
        let retained = report.actions[0].quarantine_path.as_ref().unwrap();
        let outside = staging.join("retained-outside-job");
        fs::rename(retained, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, retained).unwrap();
        assert!(prepare_native_directory_recovery(
            &cx, &report, &local, &remote, NativeDirectoryLimits::default(),
        ).await.is_err());
        assert_eq!(fs::read(outside).unwrap(), b"12");
        assert_eq!(fs::read(remote.join("a")).unwrap(), b"123456");
    });
}

#[test]
fn native_recovery_cancellation_drains_the_started_restore_and_retains_the_rest() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("cancel");
        fs::write(remote.join("a"), b"first original").unwrap();
        fs::write(remote.join("z"), vec![0x5a_u8; 2 * 1024 * 1024]).unwrap();
        let limits = NativeDirectoryLimits { buffer_bytes: 64, ..NativeDirectoryLimits::default() };
        let report = mirror(&cx, &local, &remote, &staging, limits).await;
        let prepared = prepare_native_directory_recovery(&cx, &report, &local, &remote, limits).await.unwrap();
        let first_destination = remote.join("a");
        let owner = cx.clone();
        let barrier = Arc::new(Barrier::new(2));
        let thread_barrier = Arc::clone(&barrier);
        let observer = std::thread::spawn(move || {
            thread_barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if first_destination.exists() {
                    owner.cancel_with(crate::types::CancelKind::User, Some("cancel after first real restoration"));
                    return true;
                }
                std::thread::yield_now();
            }
            false
        });
        barrier.wait();
        let result = prepared.apply(&cx, authorized()).await.unwrap();
        assert!(observer.join().unwrap(), "observer must see the first actual rename");
        assert!(!result.complete);
        assert!(result.failure.is_some());
        assert_eq!(result.actions[0].state, NativeDirectoryRecoveryState::Restored);
        assert!(result.actions[0].durable, "started rename and both directory syncs must retire");
        assert_eq!(result.actions[1].state, NativeDirectoryRecoveryState::NotStarted);
        assert_eq!(fs::read(remote.join("a")).unwrap(), b"first original");
        assert!(!remote.join("z").exists());
        assert!(result.actions[1].quarantine_path.exists());
    });
}
