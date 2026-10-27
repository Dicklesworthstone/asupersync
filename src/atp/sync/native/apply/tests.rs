use super::*;
use super::super::{prepare_native_directory_sync, scan_native_directory};
use crate::atp::sync::PathNormalizationRules;
use crate::runtime::RuntimeBuilder;
use std::fs;
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

fn native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }.build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(15), test(cx)).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(15)));
}

// Fixtures are intentionally retained. No cleanup or deletion is performed.
fn roots(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let base = loop {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "asupersync-native-apply-{label}-{}-{sequence}", std::process::id(),
        ));
        match fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create native fixture: {error}"),
        }
    };
    let local = base.join("local");
    let remote = base.join("remote");
    let staging = base.join("staging");
    for path in [&local, &remote, &staging] {
        fs::create_dir(path).unwrap();
    }
    fs::set_permissions(&staging, Permissions::from_mode(0o700)).unwrap();
    (local, remote, staging)
}

fn empty() -> DirectoryManifest {
    DirectoryManifest::new(PathNormalizationRules::default())
}

fn create_authorization() -> DestructiveAuthorization {
    DestructiveAuthorization { dry_run: false, ..DestructiveAuthorization::default() }
}

fn overwrite_authorization() -> DestructiveAuthorization {
    DestructiveAuthorization {
        allow_overwrite: true,
        allow_permission_change: true,
        ..create_authorization()
    }
}

fn untouched(report: &NativeDirectorySyncReport, staging: &Path) {
    assert!(!report.complete);
    assert!(report.verified_baseline.is_none());
    assert!(report.staging_directory.is_none());
    assert!(report.actions.iter().all(|receipt| {
        receipt.state == NativeDirectoryActionState::NotStarted
    }));
    assert_eq!(fs::read_dir(staging).unwrap().count(), 0);
}

#[test]
fn native_apply_copies_nested_trees_both_ways_and_returns_verified_baseline() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let (local, remote, staging) = roots("bidirectional");
            fs::create_dir_all(local.join("left/deep")).unwrap();
            fs::create_dir(local.join("empty")).unwrap();
            fs::create_dir(remote.join("right")).unwrap();
            let payload: Vec<_> = (0_u8..=255).cycle().take(1025).collect();
            fs::write(local.join("left/deep/payload"), &payload).unwrap();
            fs::write(remote.join("right/reply"), b"from remote").unwrap();
            let limits = NativeDirectoryLimits { buffer_bytes: 7, ..NativeDirectoryLimits::default() };
            let prepared = prepare_native_directory_sync(
                &cx, empty(), local.clone(), remote.clone(), limits,
            ).await.unwrap();
            assert!(!prepared.preview().has_conflicts());
            let report = prepared.apply(&cx, create_authorization(), staging.clone()).await.unwrap();
            assert!(report.complete, "{:?}", report.failure);
            assert!(report.failure.is_none());
            assert!(report.actions.iter().all(|receipt| {
                receipt.state == NativeDirectoryActionState::Published && receipt.durable
            }));
            assert_eq!(fs::read(remote.join("left/deep/payload")).unwrap(), payload);
            assert_eq!(fs::read(local.join("right/reply")).unwrap(), b"from remote");
            assert!(remote.join("empty").is_dir());
            let baseline = report.verified_baseline.unwrap();
            let actual_local = scan_native_directory(&cx, local.clone(), limits).await.unwrap();
            let actual_remote = scan_native_directory(&cx, remote.clone(), limits).await.unwrap();
            assert_eq!(actual_local.manifest(), &baseline);
            assert_eq!(actual_remote.manifest(), &baseline);
            let prepared = prepare_native_directory_sync(
                &cx, baseline, local, remote, limits,
            ).await.unwrap();
            assert!(prepared.preview().is_noop());
            let report = prepared.apply(&cx, create_authorization(), staging).await.unwrap();
            assert!(report.complete);
            assert!(report.staging_directory.is_none());
            assert!(report.actions.iter().all(|receipt| {
                receipt.state == NativeDirectoryActionState::Unchanged
            }));
        });
    }
}

#[test]
fn native_apply_dry_run_keeps_roots_and_staging_untouched() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("dry-run");
        fs::write(local.join("file"), b"only local").unwrap();
        let prepared = prepare_native_directory_sync(
            &cx, empty(), local, remote.clone(), NativeDirectoryLimits::default(),
        ).await.unwrap();
        let report = prepared.apply(
            &cx, DestructiveAuthorization::default(), staging.clone(),
        ).await.unwrap();
        assert!(report.dry_run);
        assert!(report.failure.is_none());
        untouched(&report, &staging);
        assert!(!remote.join("file").exists());
    });
}

#[test]
fn native_apply_overwrite_needs_both_authorizations_and_retains_original_inode() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("overwrite");
        fs::write(local.join("file"), b"original").unwrap();
        fs::write(remote.join("file"), b"original").unwrap();
        fs::set_permissions(remote.join("file"), Permissions::from_mode(0o640)).unwrap();
        let limits = NativeDirectoryLimits { buffer_bytes: 3, ..NativeDirectoryLimits::default() };
        let baseline = scan_native_directory(&cx, local.clone(), limits)
            .await.unwrap().manifest().clone();
        let original = fs::metadata(remote.join("file")).unwrap();
        fs::write(local.join("file"), b"updated file contents").unwrap();
        for (allow_overwrite, allow_permission_change) in [(false, false), (true, false), (false, true)] {
            let prepared = prepare_native_directory_sync(
                &cx, baseline.clone(), local.clone(), remote.clone(), limits,
            ).await.unwrap();
            let report = prepared.apply(&cx, DestructiveAuthorization {
                allow_overwrite, allow_permission_change, ..create_authorization()
            }, staging.clone()).await.unwrap();
            assert!(matches!(report.failure, Some(NativeDirectoryError::Refused { .. })));
            untouched(&report, &staging);
            assert_eq!(fs::read(remote.join("file")).unwrap(), b"original");
            assert_eq!(fs::metadata(remote.join("file")).unwrap().mode() & 0o777, 0o640);
        }
        let prepared = prepare_native_directory_sync(
            &cx, baseline, local, remote.clone(), limits,
        ).await.unwrap();
        let report = prepared.apply(&cx, overwrite_authorization(), staging).await.unwrap();
        assert!(report.complete, "{:?}", report.failure);
        let receipt = &report.actions[0];
        assert_eq!(receipt.state, NativeDirectoryActionState::Published);
        assert_eq!(receipt.bytes_written, 21);
        assert!(receipt.durable);
        assert!(receipt.staged_path.is_none());
        let backup = receipt.quarantine_path.as_ref().unwrap();
        assert_eq!(fs::read(backup).unwrap(), b"original");
        let backup_metadata = fs::metadata(backup).unwrap();
        assert_eq!(backup_metadata.ino(), original.ino());
        assert_eq!(backup_metadata.mode() & 0o777, 0o640);
        let published = fs::metadata(remote.join("file")).unwrap();
        assert_eq!(published.mode() & 0o777, 0o640);
        assert_eq!(published.uid(), original.uid());
        assert_eq!(published.gid(), original.gid());
        assert_eq!(fs::read(remote.join("file")).unwrap(), b"updated file contents");
    });
}

#[test]
fn native_apply_stale_source_or_destination_refuses_before_effects() {
    for change_source in [true, false] {
        native(2, move |cx| async move {
            let (local, remote, staging) = roots("stale");
            fs::write(local.join("file"), b"before").unwrap();
            let prepared = prepare_native_directory_sync(
                &cx, empty(), local.clone(), remote.clone(), NativeDirectoryLimits::default(),
            ).await.unwrap();
            if change_source {
                fs::write(local.join("file"), b"after!").unwrap();
            } else {
                fs::write(remote.join("file"), b"concurrent destination").unwrap();
            }
            let report = prepared.apply(
                &cx, overwrite_authorization(), staging.clone(),
            ).await.unwrap();
            assert!(matches!(report.failure, Some(NativeDirectoryError::Changed { .. })));
            untouched(&report, &staging);
            if change_source {
                assert!(!remote.join("file").exists());
            } else {
                assert_eq!(fs::read(remote.join("file")).unwrap(), b"concurrent destination");
            }
        });
    }
}

#[test]
fn native_apply_conflict_blocks_an_earlier_independent_copy() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("conflict");
        fs::write(local.join("a-copy"), b"would be copied").unwrap();
        fs::write(local.join("z-conflict"), b"left").unwrap();
        fs::write(remote.join("z-conflict"), b"right").unwrap();
        let prepared = prepare_native_directory_sync(
            &cx, empty(), local, remote.clone(), NativeDirectoryLimits::default(),
        ).await.unwrap();
        assert!(prepared.preview().has_conflicts());
        let report = prepared.apply(
            &cx, overwrite_authorization(), staging.clone(),
        ).await.unwrap();
        untouched(&report, &staging);
        assert!(matches!(report.failure, Some(NativeDirectoryError::Refused { .. })));
        assert!(!remote.join("a-copy").exists());
        assert_eq!(fs::read(remote.join("z-conflict")).unwrap(), b"right");
    });
}

#[test]
fn native_apply_deletion_and_kind_change_refuse_even_with_broad_authorization() {
    for kind_change in [false, true] {
        native(2, move |cx| async move {
            let (local, remote, staging) = roots("unsupported");
            fs::write(local.join("z-existing"), b"keep original").unwrap();
            fs::write(remote.join("z-existing"), b"keep original").unwrap();
            let limits = NativeDirectoryLimits::default();
            let baseline = scan_native_directory(&cx, local.clone(), limits)
                .await.unwrap().manifest().clone();
            // Model a missing entry by retaining it elsewhere, never deleting.
            if kind_change {
                fs::rename(local.join("z-existing"), staging.join("retained-local")).unwrap();
                fs::create_dir(local.join("z-existing")).unwrap();
            } else {
                fs::rename(remote.join("z-existing"), staging.join("retained-remote")).unwrap();
            }
            fs::write(local.join("a-copy"), b"independent new file").unwrap();
            let prepared = prepare_native_directory_sync(
                &cx, baseline, local.clone(), remote.clone(), limits,
            ).await.unwrap();
            let report = prepared.apply(
                &cx, DestructiveAuthorization::explicit_mirror_apply(), staging.clone(),
            ).await.unwrap();
            assert!(!report.complete);
            assert!(report.staging_directory.is_none());
            assert!(report.verified_baseline.is_none());
            assert!(report.actions.iter().all(|receipt| {
                receipt.state == NativeDirectoryActionState::NotStarted
            }));
            assert!(matches!(report.failure, Some(NativeDirectoryError::Refused { .. })));
            assert!(!remote.join("a-copy").exists());
            if kind_change {
                assert_eq!(fs::read(remote.join("z-existing")).unwrap(), b"keep original");
                assert!(local.join("z-existing").is_dir());
            } else {
                assert_eq!(fs::read(local.join("z-existing")).unwrap(), b"keep original");
                assert!(!remote.join("z-existing").exists());
            }
        });
    }
}

#[test]
fn native_apply_checks_projected_union_limits_before_creating_staging() {
    native(1, |cx| async move {
        let (local, remote, staging) = roots("projected-limit");
        fs::write(local.join("left"), b"1234").unwrap();
        fs::write(remote.join("right"), b"5678").unwrap();
        let limits = NativeDirectoryLimits {
            max_total_bytes: 4, ..NativeDirectoryLimits::default()
        };
        let prepared = prepare_native_directory_sync(
            &cx, empty(), local.clone(), remote.clone(), limits,
        ).await.unwrap();
        let report = prepared.apply(&cx, create_authorization(), staging.clone()).await.unwrap();
        assert!(matches!(
            report.failure, Some(NativeDirectoryError::Limit { limit: "max_total_bytes", .. })
        ));
        untouched(&report, &staging);
        assert!(!local.join("right").exists());
        assert!(!remote.join("left").exists());
    });
}

#[test]
fn native_apply_rejects_special_permission_overwrite_before_any_copy() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("special-mode");
        fs::write(local.join("z-existing"), b"old").unwrap();
        fs::write(remote.join("z-existing"), b"old").unwrap();
        let limits = NativeDirectoryLimits::default();
        let baseline = scan_native_directory(&cx, local.clone(), limits)
            .await.unwrap().manifest().clone();
        fs::set_permissions(remote.join("z-existing"), Permissions::from_mode(0o1640)).unwrap();
        fs::write(local.join("z-existing"), b"replacement").unwrap();
        fs::write(local.join("a-copy"), b"earlier decision").unwrap();
        let prepared = prepare_native_directory_sync(
            &cx, baseline, local, remote.clone(), limits,
        ).await.unwrap();
        let report = prepared.apply(
            &cx, overwrite_authorization(), staging.clone(),
        ).await.unwrap();
        assert!(matches!(report.failure, Some(NativeDirectoryError::Refused { .. })));
        untouched(&report, &staging);
        assert!(!remote.join("a-copy").exists());
        assert_eq!(fs::read(remote.join("z-existing")).unwrap(), b"old");
        assert_eq!(fs::metadata(remote.join("z-existing")).unwrap().mode() & 0o7777, 0o1640);
    });
}

fn staged_receipt(path: &str, staged_path: &Path) -> NativeDirectoryActionReceipt {
    NativeDirectoryActionReceipt {
        path: DirectoryPath::normalize(path, PathNormalizationRules::default()).unwrap(),
        action: BidirectionalSyncAction::CopyLocalToRemote,
        state: NativeDirectoryActionState::Staged,
        bytes_written: 3,
        staged_path: Some(staged_path.to_owned()),
        quarantine_path: None,
        durable: false,
    }
}

#[test]
fn native_publication_refusal_after_quarantine_retains_both_versions_and_concurrent_file() {
    let (_local, remote, staging_path) = roots("publication-race");
    let destination_path = remote.join("file");
    let staged_path = staging_path.join("new-00000000");
    fs::write(&destination_path, b"old").unwrap();
    fs::write(&staged_path, b"new").unwrap();
    let destination = NativeRoot::open(&remote).unwrap();
    let staging = NativeRoot::open(&staging_path).unwrap();
    let staged = File::open(&staged_path).unwrap();
    let staged_stamp = metadata_stamp(&staged, &staged_path).unwrap();
    let previous = stat_at(&destination.file, "file", &destination_path).unwrap().unwrap();
    let mut receipt = staged_receipt("file", &staged_path);
    verify_staged(
        &staging.file, &staging_path, &staged, "new-00000000", staged_stamp,
    ).unwrap();
    quarantine_previous(
        &destination.file, "file", &destination_path, previous,
        &staging.file, &staging_path, 0, &mut receipt,
    ).unwrap();
    // Real intervening creation at the destination, between the same two
    // publication phases used by apply. NOREPLACE must preserve it.
    fs::write(&destination_path, b"concurrent").unwrap();
    let error = publish_staged(
        &staging.file, &staging_path, &staged, "new-00000000", staged_stamp,
        &destination.file, "file", &destination_path, &mut receipt,
    ).unwrap_err();
    assert!(matches!(error, NativeDirectoryError::Io { source, .. }
        if source.kind() == std::io::ErrorKind::AlreadyExists));
    assert_eq!(receipt.state, NativeDirectoryActionState::Quarantined);
    assert!(!receipt.durable);
    assert_eq!(receipt.staged_path.as_ref(), Some(&staged_path));
    let backup = receipt.quarantine_path.as_ref().unwrap();
    assert_eq!(fs::read(backup).unwrap(), b"old");
    assert_eq!(fs::metadata(backup).unwrap().ino(), previous.identity.inode);
    assert_eq!(fs::read(staged_path).unwrap(), b"new");
    assert_eq!(fs::read(destination_path).unwrap(), b"concurrent");
}

#[test]
fn native_publication_rejects_a_substituted_staging_name() {
    let (_local, remote, staging_path) = roots("staging-substitution");
    let staged_path = staging_path.join("new-00000000");
    let retained_path = staging_path.join("retained-original");
    fs::write(&staged_path, b"verified").unwrap();
    let staging = NativeRoot::open(&staging_path).unwrap();
    let destination = NativeRoot::open(&remote).unwrap();
    let staged = File::open(&staged_path).unwrap();
    let expected = metadata_stamp(&staged, &staged_path).unwrap();
    fs::rename(&staged_path, &retained_path).unwrap();
    fs::write(&staged_path, b"substituted").unwrap();
    let mut receipt = staged_receipt("file", &staged_path);
    let result = publish_staged(
        &staging.file, &staging_path, &staged, "new-00000000", expected,
        &destination.file, "file", &remote.join("file"), &mut receipt,
    );
    assert!(matches!(result, Err(NativeDirectoryError::Changed { .. })));
    assert_eq!(receipt.state, NativeDirectoryActionState::Staged);
    assert!(!remote.join("file").exists());
    assert_eq!(fs::read(retained_path).unwrap(), b"verified");
    assert_eq!(fs::read(staged_path).unwrap(), b"substituted");
}

#[test]
fn native_apply_cancellation_after_actual_staging_progress_returns_drained_partial_receipt() {
    native(2, |cx| async move {
        let (local, remote, staging) = roots("cancel-copy");
        let payload = vec![0x5a; 1024 * 1024];
        fs::write(local.join("file"), &payload).unwrap();
        let limits = NativeDirectoryLimits {
            buffer_bytes: 1, ..NativeDirectoryLimits::default()
        };
        let prepared = prepare_native_directory_sync(
            &cx, empty(), local, remote.clone(), limits,
        ).await.unwrap();
        let staged_path = staging.join(format!("asupersync-sync-{}", prepared.plan_id()))
            .join("new-00000000");
        let owner = cx.clone();
        let ready = Arc::new(Barrier::new(2));
        let observer_ready = Arc::clone(&ready);
        let observer_path = staged_path.clone();
        let observer = std::thread::spawn(move || {
            observer_ready.wait();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(metadata) = fs::metadata(&observer_path) {
                    if metadata.len() > 0 {
                        let observed_bytes = metadata.len();
                        owner.cancel_with(
                            crate::types::CancelKind::User,
                            Some("cancel during native directory copy"),
                        );
                        return observed_bytes;
                    }
                }
                assert!(Instant::now() < deadline, "no actual staging progress observed");
                std::thread::yield_now();
            }
        });
        ready.wait();
        let report = prepared.apply(&cx, create_authorization(), staging).await.unwrap();
        let observed_bytes = observer.join().unwrap();
        assert!(observed_bytes > 0 && observed_bytes < payload.len() as u64);
        assert!(!report.complete);
        assert!(report.verified_baseline.is_none());
        assert!(matches!(report.failure, Some(NativeDirectoryError::Checkpoint(_))));
        let receipt = &report.actions[0];
        assert_eq!(receipt.state, NativeDirectoryActionState::Staged);
        assert!(receipt.bytes_written > 0 && receipt.bytes_written < payload.len() as u64);
        assert_eq!(receipt.staged_path.as_ref(), Some(&staged_path));
        assert_eq!(fs::metadata(staged_path).unwrap().len(), receipt.bytes_written);
        assert!(!receipt.durable);
        assert!(receipt.quarantine_path.is_none());
        assert!(!remote.join("file").exists());
    });
}
