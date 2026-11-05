//! Real-filesystem inventory and preparation regressions.
//!
//! Every fixture uses a newly created directory and is retained deliberately:
//! neither successful nor failing tests delete files or directories.

use super::*;
use crate::atp::sync::{BidirectionalSyncAction, DestructiveAuthorization};
use crate::runtime::RuntimeBuilder;
use crate::types::CancelKind;
use std::ffi::OsString;
use std::future::Future;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use crate::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(15);

fn fixture(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..1024 {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "asupersync-native-directory-{label}-{}-{sequence}",
            std::process::id(),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
    panic!("retained fixture namespace exhausted");
}

fn native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .expect("native directory runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("native runtime context");
        crate::time::timeout(cx.now(), WATCHDOG, test(cx))
            .await
            .expect("native directory test watchdog");
    });
    assert!(runtime.shutdown_timeout(WATCHDOG), "owned blocking work drains");
}

fn empty() -> DirectoryManifest {
    DirectoryManifest::new(PathNormalizationRules::default())
}

fn decision<'a>(plan: &'a PreparedNativeDirectorySync, path: &str) -> &'a BidirectionalSyncAction {
    &plan.preview().decisions.iter().find(|item| item.path.as_str() == path)
        .expect("expected path decision").action
}

fn mirror_roots(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = fixture(label);
    let source = base.join("source");
    let destination = base.join("destination");
    let staging = base.join("staging");
    for root in [&source, &destination, &staging] {
        std::fs::create_dir(root).unwrap();
    }
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    (source, destination, staging)
}

fn mirror_authorization() -> DestructiveAuthorization {
    DestructiveAuthorization {
        dry_run: false,
        allow_delete: true,
        allow_overwrite: true,
        allow_permission_change: true,
        ..DestructiveAuthorization::default()
    }
}

#[test]
fn native_mirror_prepare_is_directional_deterministic_and_read_only() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let (source, destination, staging) = mirror_roots("mirror-plan");
            std::fs::create_dir(source.join("nested")).unwrap();
            std::fs::write(source.join("nested/new"), b"source-only").unwrap();
            std::fs::write(source.join("shared"), b"authoritative-source").unwrap();
            std::fs::write(destination.join("shared"), b"independent-destination-edit").unwrap();
            std::fs::write(destination.join("extra"), b"destination-only").unwrap();
            let limits = NativeDirectoryLimits::default();
            let first = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            let second = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            assert_eq!(first.preview(), second.preview());
            assert_eq!(first.plan_id(), second.plan_id());
            assert_eq!(first.local().root(), source.as_path());
            assert_eq!(first.remote().root(), destination.as_path());
            assert!(!first.preview().has_conflicts());
            assert!(first.preview().has_destructive_actions());
            for path in ["nested", "nested/new", "shared"] {
                assert_eq!(*decision(&first, path), BidirectionalSyncAction::CopyLocalToRemote);
            }
            assert_eq!(*decision(&first, "extra"), BidirectionalSyncAction::DeleteRemote);
            assert!(first.preview().decisions.iter().all(|item| matches!(
                item.action,
                BidirectionalSyncAction::Keep
                    | BidirectionalSyncAction::CopyLocalToRemote
                    | BidirectionalSyncAction::DeleteRemote
            )));
            // Equal actions from a three-way comparison still have a distinct
            // review identity: mirror and last-common-baseline intent differ.
            let sync = prepare_native_directory_sync(
                &cx, first.remote().manifest().clone(), &source, &destination, limits,
            ).await.unwrap();
            assert_eq!(first.preview(), sync.preview());
            assert_ne!(first.plan_id(), sync.plan_id());
            assert_eq!(std::fs::read(source.join("shared")).unwrap(), b"authoritative-source");
            assert_eq!(std::fs::read(destination.join("shared")).unwrap(), b"independent-destination-edit");
            assert_eq!(std::fs::read(destination.join("extra")).unwrap(), b"destination-only");
            assert!(!source.join("extra").exists());
            assert!(!destination.join("nested").exists());
            assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
        });
    }
}

#[test]
fn native_mirror_apply_converges_without_changing_source_and_retains_recovery_inodes() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let (source, destination, staging) = mirror_roots("mirror-apply");
            std::fs::create_dir_all(source.join("new/deep")).unwrap();
            std::fs::create_dir(source.join("empty")).unwrap();
            std::fs::create_dir_all(destination.join("obsolete/deep")).unwrap();
            let payload: Vec<_> = (0_u8..=255).cycle().take(2051).collect();
            std::fs::write(source.join("new/deep/payload"), &payload).unwrap();
            std::fs::write(source.join("shared"), b"new-source-version").unwrap();
            std::fs::write(destination.join("shared"), b"retained-old-version").unwrap();
            std::fs::write(destination.join("obsolete/deep/value"), b"retained-extra").unwrap();
            let old_shared = std::fs::metadata(destination.join("shared")).unwrap().ino();
            let old_extra = std::fs::metadata(destination.join("obsolete/deep/value")).unwrap().ino();
            let limits = NativeDirectoryLimits { buffer_bytes: 7, ..NativeDirectoryLimits::default() };
            let before = scan_native_directory(&cx, &source, limits).await.unwrap();
            let prepared = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            let reviewed_id = prepared.plan_id().to_owned();
            let report = prepared.apply_with_quarantined_deletions(
                &cx, mirror_authorization(), &staging,
            ).await.unwrap();
            assert!(report.complete, "{:?}", report.failure);
            assert!(report.failure.is_none());
            assert_eq!(report.plan_id, reviewed_id);
            assert_eq!(report.verified_baseline.as_ref(), Some(before.manifest()));
            assert_eq!(std::fs::read(destination.join("new/deep/payload")).unwrap(), payload);
            assert_eq!(std::fs::read(destination.join("shared")).unwrap(), b"new-source-version");
            assert!(destination.join("empty").is_dir());
            assert!(!destination.join("obsolete").exists());
            for (path, inode, bytes) in [
                ("shared", old_shared, b"retained-old-version".as_slice()),
                ("obsolete/deep/value", old_extra, b"retained-extra".as_slice()),
            ] {
                let receipt = report.actions.iter().find(|item| item.path.as_str() == path).unwrap();
                assert!(receipt.durable);
                let quarantined = receipt.quarantine_path.as_ref().unwrap();
                assert_eq!(std::fs::metadata(quarantined).unwrap().ino(), inode);
                assert_eq!(std::fs::read(quarantined).unwrap(), bytes);
            }
            for path in ["obsolete", "obsolete/deep", "obsolete/deep/value"] {
                let receipt = report.actions.iter().find(|item| item.path.as_str() == path).unwrap();
                assert_eq!(receipt.action, BidirectionalSyncAction::DeleteRemote);
                assert_eq!(receipt.state, NativeDirectoryActionState::Quarantined);
                assert!(receipt.durable);
            }
            let after = scan_native_directory(&cx, &source, limits).await.unwrap();
            assert_eq!(after.manifest(), before.manifest());
            assert_eq!(after.guards, before.guards, "mirror must not mutate source objects");
            assert_eq!(after.root_stamp, before.root_stamp);
            let destination_after = scan_native_directory(&cx, &destination, limits).await.unwrap();
            assert_eq!(after.manifest(), destination_after.manifest());
            let next = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            assert!(next.preview().is_noop());
            let repeated = next.apply_with_quarantined_deletions(
                &cx, mirror_authorization(), staging,
            ).await.unwrap();
            assert!(repeated.complete);
            assert!(repeated.staging_directory.is_none());
        });
    }
}

#[test]
fn native_mirror_authority_and_stale_observations_refuse_before_effects() {
    native(2, |cx| async move {
        let (source, destination, staging) = mirror_roots("mirror-refusal");
        std::fs::write(source.join("shared"), b"source").unwrap();
        std::fs::write(destination.join("shared"), b"destination").unwrap();
        std::fs::write(destination.join("extra"), b"retained").unwrap();
        let limits = NativeDirectoryLimits::default();
        for authorization in [
            DestructiveAuthorization { allow_delete: false, ..mirror_authorization() },
            DestructiveAuthorization { allow_overwrite: false, ..mirror_authorization() },
            DestructiveAuthorization { allow_permission_change: false, ..mirror_authorization() },
        ] {
            let prepared = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            let report = prepared.apply_with_quarantined_deletions(&cx, authorization, &staging)
                .await.unwrap();
            assert!(!report.complete);
            assert!(report.failure.is_some());
            assert!(report.staging_directory.is_none());
            assert!(report.verified_baseline.is_none());
            assert!(report.actions.iter().all(|item| item.state == NativeDirectoryActionState::NotStarted));
            assert_eq!(std::fs::read(destination.join("shared")).unwrap(), b"destination");
            assert_eq!(std::fs::read(destination.join("extra")).unwrap(), b"retained");
        }
        let prepared = prepare_native_directory_mirror(&cx, &source, &destination, limits)
            .await.unwrap();
        let dry_run = prepared.apply_with_quarantined_deletions(
            &cx, DestructiveAuthorization::default(), &staging,
        ).await.unwrap();
        assert!(dry_run.dry_run);
        assert!(!dry_run.complete);
        assert!(dry_run.failure.is_none());
        assert!(dry_run.staging_directory.is_none());
        assert!(dry_run.actions.iter().all(|item| item.state == NativeDirectoryActionState::NotStarted));

        for changed_root in [&source, &destination] {
            let prepared = prepare_native_directory_mirror(&cx, &source, &destination, limits)
                .await.unwrap();
            std::fs::write(changed_root.join("shared"), b"changed after review").unwrap();
            let report = prepared.apply_with_quarantined_deletions(
                &cx, mirror_authorization(), &staging,
            ).await.unwrap();
            assert!(!report.complete);
            assert!(matches!(report.failure, Some(NativeDirectoryError::Changed { .. })));
            assert!(report.staging_directory.is_none());
            assert!(report.actions.iter().all(|item| item.state == NativeDirectoryActionState::NotStarted));
            assert_eq!(std::fs::read(destination.join("extra")).unwrap(), b"retained");
        }
        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
    });
}

#[test]
fn native_mirror_keeps_native_confinement_limits_and_type_change_refusal() {
    native(1, |cx| async move {
        let (source, destination, staging) = mirror_roots("mirror-profile");
        std::fs::write(source.join("value"), b"bounded source").unwrap();
        let limits = NativeDirectoryLimits::default();
        assert!(matches!(
            prepare_native_directory_mirror(&cx, &source, &source, limits).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));
        assert!(matches!(
            prepare_native_directory_mirror(
                &cx, &source, &destination,
                NativeDirectoryLimits { max_file_bytes: 1, ..limits },
            ).await,
            Err(NativeDirectoryError::Limit { limit: "max_file_bytes", .. }),
        ));
        // An incompatible entry kind stays reviewable, but application must
        // not treat its child tree as permission to replace a directory.
        std::fs::create_dir(destination.join("value")).unwrap();
        std::fs::write(destination.join("value/child"), b"must remain").unwrap();
        let prepared = prepare_native_directory_mirror(&cx, &source, &destination, limits)
            .await.unwrap();
        let report = prepared.apply_with_quarantined_deletions(
            &cx, mirror_authorization(), &staging,
        ).await.unwrap();
        assert!(!report.complete);
        assert!(report.failure.is_some());
        assert!(report.staging_directory.is_none());
        assert_eq!(std::fs::read(destination.join("value/child")).unwrap(), b"must remain");
        let outside = fixture("mirror-outside");
        std::fs::write(outside.join("secret"), b"outside").unwrap();
        symlink(outside.join("secret"), destination.join("link")).unwrap();
        assert!(prepare_native_directory_mirror(&cx, &source, &destination, limits).await.is_err());
        assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"outside");
        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
    });
}

#[test]
fn native_inventory_converges_across_inodes_and_keeps_explicit_ancestors() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let base = fixture("content");
            let left = base.join("left");
            let right = base.join("right");
            for root in [&left, &right] {
                std::fs::create_dir_all(root.join("nested/deeper")).unwrap();
                std::fs::write(root.join("nested/deeper/value"), b"abc").unwrap();
                std::fs::write(root.join("empty"), []).unwrap();
            }
            assert_ne!(
                std::fs::metadata(left.join("nested/deeper/value")).unwrap().ino(),
                std::fs::metadata(right.join("nested/deeper/value")).unwrap().ino(),
            );
            let local = scan_native_directory(&cx, &left, NativeDirectoryLimits::default())
                .await.unwrap();
            let remote = scan_native_directory(&cx, &right, NativeDirectoryLimits::default())
                .await.unwrap();
            assert_eq!(local.manifest(), remote.manifest());
            assert_eq!(local.total_bytes(), 3);
            let paths: Vec<_> = local.manifest().entries.keys().map(DirectoryPath::as_str).collect();
            assert_eq!(paths, ["empty", "nested", "nested/deeper", "nested/deeper/value"]);
            let value = local.manifest().entries.values()
                .find(|entry| entry.path.as_str() == "nested/deeper/value").unwrap();
            assert_eq!(
                value.content_id.as_deref(),
                Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            );
            assert_eq!(value.metadata.size_bytes, Some(3));
            assert_eq!(value.metadata.stable_identity, None);
            assert_eq!(value.metadata.unix_mode, None);
            let prepared = prepare_native_directory_sync(
                &cx, local.manifest().clone(), &left, &right, NativeDirectoryLimits::default(),
            ).await.unwrap();
            assert!(prepared.preview().is_noop());
            assert_eq!(prepared.plan_id().len(), 64);
            assert_eq!(std::fs::read(left.join("nested/deeper/value")).unwrap(), b"abc");
        });
    }
}

#[test]
fn native_prepare_plans_both_directions_from_actual_trees_without_publication() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let base = fixture("directions");
            let left = base.join("left");
            let right = base.join("right");
            for root in [&left, &right] {
                std::fs::create_dir(root).unwrap();
                std::fs::write(root.join("shared"), b"baseline").unwrap();
            }
            let baseline = scan_native_directory(&cx, &left, NativeDirectoryLimits::default())
                .await.unwrap().manifest().clone();
            std::fs::write(left.join("shared"), b"local-edit").unwrap();
            std::fs::write(right.join("remote-only"), b"remote-created").unwrap();
            let prepared = prepare_native_directory_sync(
                &cx, baseline, &left, &right, NativeDirectoryLimits::default(),
            ).await.unwrap();
            assert!(!prepared.preview().has_conflicts());
            assert!(matches!(decision(&prepared, "shared"), BidirectionalSyncAction::CopyLocalToRemote));
            assert!(matches!(decision(&prepared, "remote-only"), BidirectionalSyncAction::CopyRemoteToLocal));
            assert!(prepared.preview().has_destructive_actions());
            assert_eq!(std::fs::read(right.join("shared")).unwrap(), b"baseline");
            assert!(!left.join("remote-only").exists());
        });
    }
}

#[test]
fn native_prepare_preserves_concurrent_edit_conflicts() {
    native(2, |cx| async move {
        let base = fixture("conflict");
        let left = base.join("left");
        let right = base.join("right");
        for root in [&left, &right] {
            std::fs::create_dir(root).unwrap();
            std::fs::write(root.join("value"), b"baseline").unwrap();
        }
        let baseline = scan_native_directory(&cx, &left, NativeDirectoryLimits::default())
            .await.unwrap().manifest().clone();
        std::fs::write(left.join("value"), b"left-change").unwrap();
        std::fs::write(right.join("value"), b"right-change").unwrap();
        let prepared = prepare_native_directory_sync(
            &cx, baseline, &left, &right, NativeDirectoryLimits::default(),
        ).await.unwrap();
        assert!(prepared.preview().has_conflicts());
        assert!(matches!(decision(&prepared, "value"), BidirectionalSyncAction::Conflict { .. }));
        assert_eq!(std::fs::read(left.join("value")).unwrap(), b"left-change");
        assert_eq!(std::fs::read(right.join("value")).unwrap(), b"right-change");
    });
}

#[test]
fn native_inventory_refuses_symlinks_hardlinks_and_unrepresentable_names() {
    native(2, |cx| async move {
        let outside = fixture("outside");
        let victim = outside.join("victim");
        std::fs::write(&victim, b"outside remains unchanged").unwrap();

        let symbolic = fixture("symlink");
        symlink(&victim, symbolic.join("link")).unwrap();
        assert!(matches!(
            scan_native_directory(&cx, &symbolic, NativeDirectoryLimits::default()).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));
        let root_alias = outside.join("root-alias");
        symlink(&symbolic, &root_alias).unwrap();
        assert!(scan_native_directory(&cx, root_alias, NativeDirectoryLimits::default()).await.is_err());

        let hardlinked = fixture("hardlink");
        std::fs::write(hardlinked.join("a"), b"linked").unwrap();
        std::fs::hard_link(hardlinked.join("a"), hardlinked.join("b")).unwrap();
        assert!(matches!(
            scan_native_directory(&cx, hardlinked, NativeDirectoryLimits::default()).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));

        let invalid = fixture("nonutf8");
        std::fs::write(invalid.join(OsString::from_vec(b"bad\xff".to_vec())), b"bytes").unwrap();
        assert!(matches!(
            scan_native_directory(&cx, invalid, NativeDirectoryLimits::default()).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));

        let aliased = fixture("backslash");
        std::fs::write(aliased.join(r"bad\name"), b"bytes").unwrap();
        assert!(matches!(
            scan_native_directory(&cx, aliased, NativeDirectoryLimits::default()).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));
        assert_eq!(std::fs::read(victim).unwrap(), b"outside remains unchanged");
    });
}

#[test]
fn native_inventory_enforces_file_total_entry_and_depth_bounds() {
    native(1, |cx| async move {
        let root = fixture("limits");
        std::fs::write(root.join("a"), b"1234").unwrap();
        std::fs::write(root.join("b"), b"5678").unwrap();
        for (limits, expected) in [
            (NativeDirectoryLimits { max_file_bytes: 3, ..NativeDirectoryLimits::default() }, "max_file_bytes"),
            (NativeDirectoryLimits { max_total_bytes: 7, ..NativeDirectoryLimits::default() }, "max_total_bytes"),
            (NativeDirectoryLimits { max_entries: 1, ..NativeDirectoryLimits::default() }, "max_entries"),
        ] {
            match scan_native_directory(&cx, &root, limits).await {
                Err(NativeDirectoryError::Limit { limit, .. }) => assert_eq!(limit, expected),
                other => panic!("expected {expected} refusal, received {other:?}"),
            }
        }
        let nested = fixture("depth");
        std::fs::create_dir(nested.join("parent")).unwrap();
        std::fs::write(nested.join("parent/child"), b"x").unwrap();
        assert!(matches!(
            scan_native_directory(
                &cx, nested, NativeDirectoryLimits { max_depth: 1, ..NativeDirectoryLimits::default() },
            ).await,
            Err(NativeDirectoryError::Limit { limit: "max_depth", .. }),
        ));
        assert!(matches!(
            scan_native_directory(
                &cx, &root, NativeDirectoryLimits { buffer_bytes: 0, ..NativeDirectoryLimits::default() },
            ).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"1234");
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"5678");
    });
}

#[test]
fn native_prepare_refuses_metadata_it_cannot_preserve_and_overlapping_roots() {
    native(2, |cx| async move {
        let base = fixture("profile");
        let left = base.join("left");
        let right = base.join("right");
        std::fs::create_dir(&left).unwrap();
        std::fs::create_dir(&right).unwrap();
        std::fs::write(left.join("value"), b"abc").unwrap();
        let mut baseline = scan_native_directory(&cx, &left, NativeDirectoryLimits::default())
            .await.unwrap().manifest().clone();
        baseline.entries.values_mut().next().unwrap().metadata.unix_mode = Some(0o755);
        assert!(matches!(
            prepare_native_directory_sync(
                &cx, baseline, &left, &right, NativeDirectoryLimits::default(),
            ).await,
            Err(NativeDirectoryError::Refused { .. }),
        ));
        for other in [&left, &base] {
            assert!(matches!(
                prepare_native_directory_sync(
                    &cx, empty(), &left, other, NativeDirectoryLimits::default(),
                ).await,
                Err(NativeDirectoryError::Refused { .. }),
            ));
        }
        assert_eq!(std::fs::read(left.join("value")).unwrap(), b"abc");
        assert_eq!(std::fs::read_dir(&right).unwrap().count(), 0);
    });
}

#[test]
fn native_inventory_guards_detect_changed_file_and_replaced_root() {
    native(2, |cx| async move {
        let base = fixture("stale");
        let root = base.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("value"), b"old").unwrap();
        let captured = scan_native_directory(&cx, &root, NativeDirectoryLimits::default())
            .await.unwrap();
        std::fs::write(root.join("value"), b"changed-size").unwrap();
        assert!(matches!(revalidate_stamps(&cx, &captured), Err(NativeDirectoryError::Changed { .. })));
        let original = base.join("retained-original");
        std::fs::rename(&root, &original).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(matches!(captured.root.revalidate(), Err(NativeDirectoryError::Changed { .. })));
        assert_eq!(std::fs::read(original.join("value")).unwrap(), b"changed-size");
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    });
}

#[test]
fn native_inventory_refuses_missing_authority_runtime_and_predispatch_cancellation() {
    let root = PathBuf::from("/asupersync-native-directory-deliberately-not-opened");
    let no_runtime = Cx::for_testing();
    assert!(matches!(
        futures_lite::future::block_on(scan_native_directory(
            &no_runtime, &root, NativeDirectoryLimits::default(),
        )),
        Err(NativeDirectoryError::Runtime(ScopedFsError::Admission(_))),
    ));
    let restricted = {
        let _guard = Cx::for_testing().restrict::<crate::cx::NoCaps>().set_current_restricted();
        Cx::current().unwrap()
    };
    assert!(matches!(
        futures_lite::future::block_on(scan_native_directory(
            &restricted, &root, NativeDirectoryLimits::default(),
        )),
        Err(NativeDirectoryError::Runtime(ScopedFsError::CapabilityDenied)),
    ));
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(CancelKind::User, Some("before directory dispatch"));
    assert!(matches!(
        futures_lite::future::block_on(scan_native_directory(
            &cancelled, &root, NativeDirectoryLimits::default(),
        )),
        Err(NativeDirectoryError::Runtime(ScopedFsError::Checkpoint(_))),
    ));
}
