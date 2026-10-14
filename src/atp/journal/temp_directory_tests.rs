//! Owned staging creation must not alter or clean up pre-existing objects.

use super::*;
use std::io::{self, Write};

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
fn set_mode(path: &Path, permissions: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(permissions)).unwrap();
}

#[test]
fn collisions_are_never_tracked_or_deleted_and_do_not_consume_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let mut manager = TempPathManager::with_config(directory.path(), TempManagementConfig {
        max_active_temps: 1,
        auto_create_quarantine: false,
        ..TempManagementConfig::default()
    });
    let mut collisions = Vec::new();
    let mut attempts = 0;
    let (owned, mut file) = manager.create_temp_file_with("collision", |path| {
        attempts += 1;
        if attempts <= 2 {
            fs::write(path, b"pre-existing sentinel").unwrap();
            collisions.push(path.to_path_buf());
        }
        TempPathManager::open_new_file(path, Some(0o600))
    }).unwrap();
    assert_eq!(attempts, 3);
    file.write_all(b"owned payload").unwrap();
    drop(file);
    assert_eq!(manager.get_stats().active_count, 1);
    assert_eq!(fs::read(&owned).unwrap(), b"owned payload");
    for path in &collisions {
        assert!(manager.get_temp_info(path).is_none());
    }
    // Exercise actual stale cleanup with an explicit old record, not a sleep.
    manager.active_temps.get_mut(&owned).unwrap().created_at = UNIX_EPOCH;
    assert_eq!(manager.cleanup_stale_files().unwrap(), vec![owned]);
    for path in collisions {
        assert_eq!(fs::read(path).unwrap(), b"pre-existing sentinel");
    }
    assert_eq!(manager.get_stats().active_count, 0);
    let (_, file) = manager.create_temp_file("next owner").unwrap();
    drop(file);
}

#[test]
fn exhaustion_limits_and_open_errors_leave_no_false_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let mut manager = TempPathManager::with_config(directory.path(), TempManagementConfig {
        max_active_temps: 1,
        auto_create_quarantine: false,
        ..TempManagementConfig::default()
    });
    let mut collisions = Vec::new();
    let result = manager.create_temp_file_with("exhaust", |path| {
        fs::write(path, b"foreign").unwrap();
        collisions.push(path.to_path_buf());
        TempPathManager::open_new_file(path, Some(0o600))
    });
    assert!(matches!(result, Err(TempFileCreationError::Open(error))
        if error.kind() == io::ErrorKind::AlreadyExists));
    assert_eq!(collisions.len(), 8);
    assert_eq!(manager.get_stats().active_count, 0);
    assert!(manager.cleanup_stale_files().unwrap().is_empty());
    for path in collisions { assert_eq!(fs::read(path).unwrap(), b"foreign"); }
    let result = manager.create_temp_file_with("denied", |_| {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected denial"))
    });
    assert!(matches!(result, Err(TempFileCreationError::Open(error))
        if error.kind() == io::ErrorKind::PermissionDenied));
    assert_eq!(manager.get_stats().active_count, 0);
    manager.config.max_active_temps = 0;
    let result = manager.create_temp_file_with("capacity", |_| panic!("opener ran without capacity"));
    assert!(matches!(result, Err(TempFileCreationError::Path(TempManagementError::TooManyTempFiles))));
}

#[cfg(unix)]
#[test]
fn existing_and_dangling_symlink_collisions_never_open_their_targets() {
    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("victim");
    let missing = directory.path().join("must-not-be-created");
    fs::write(&victim, b"keep victim").unwrap();
    let mut manager = TempPathManager::new(directory.path());
    let mut links = Vec::new();
    let (owned, mut file) = manager.create_temp_file_with("links", |path| {
        match links.len() {
            0 => { std::os::unix::fs::symlink(&victim, path).unwrap(); links.push(path.to_path_buf()); }
            1 => { std::os::unix::fs::symlink(&missing, path).unwrap(); links.push(path.to_path_buf()); }
            _ => {}
        }
        TempPathManager::open_new_file(path, Some(0o600))
    }).unwrap();
    file.write_all(b"new owner").unwrap();
    drop(file);
    assert_eq!(fs::read(victim).unwrap(), b"keep victim");
    assert!(!missing.exists());
    assert_eq!(links.len(), 2);
    for link in links {
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(manager.get_temp_info(&link).is_none());
    }
    assert_eq!(fs::read(owned).unwrap(), b"new owner");
    assert_eq!(manager.get_stats().active_count, 1);
}

#[cfg(unix)]
#[test]
fn staging_is_private_at_creation_without_chmoding_the_destination() {
    let directory = tempfile::tempdir().unwrap();
    set_mode(directory.path(), 0o755);
    let mut manager = TempPathManager::new(directory.path());
    let (path, mut file) = manager.create_temp_file("private").unwrap();
    assert_eq!(mode(directory.path()), 0o755);
    assert_eq!(mode(&path) & 0o177, 0, "no execute, group, or other permissions before payload");
    file.write_all(b"private bytes").unwrap();
    assert_eq!(mode(&path) & 0o177, 0);
    assert_eq!(mode(&directory.path().join(".quarantine")) & 0o077, 0);
}

#[cfg(unix)]
#[test]
fn existing_modes_and_ancestors_survive_all_creation_configurations() {
    for requested in [Some(0o700), Some(0o750), None] {
        let directory = tempfile::tempdir().unwrap();
        set_mode(directory.path(), 0o751);
        let quarantine = directory.path().join(".quarantine");
        fs::create_dir(&quarantine).unwrap();
        set_mode(&quarantine, 0o755);
        let manager = TempPathManager::with_config(directory.path(), TempManagementConfig {
            temp_dir_permissions: requested,
            ..TempManagementConfig::default()
        });
        manager.ensure_directories().unwrap();
        assert_eq!(mode(directory.path()), 0o751);
        assert_eq!(mode(&quarantine), 0o755);
        let parent = directory.path().join("new-parent");
        let base = parent.join("new-base");
        let nested = TempPathManager::new(&base);
        nested.ensure_directories().unwrap();
        assert_eq!(mode(directory.path()), 0o751);
        for path in [&parent, &base, &base.join(".quarantine")] {
            assert_eq!(mode(path) & 0o077, 0, "new directories use creation mode");
        }
    }
}

#[cfg(unix)]
#[test]
fn pre_existing_directory_links_do_not_authorize_target_permission_changes() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    let quarantine_target = directory.path().join("quarantine-target");
    fs::create_dir(&target).unwrap();
    fs::create_dir(&quarantine_target).unwrap();
    set_mode(&target, 0o751);
    set_mode(&quarantine_target, 0o750);
    let base = directory.path().join("alias");
    std::os::unix::fs::symlink(&target, &base).unwrap();
    std::os::unix::fs::symlink(&quarantine_target, target.join(".quarantine")).unwrap();
    let manager = TempPathManager::new(&base);
    manager.ensure_directories().unwrap();
    assert_eq!(mode(&target), 0o751);
    assert_eq!(mode(&quarantine_target), 0o750);
    // Existing path-following semantics remain; this is not a sandbox claim.
    assert!(fs::symlink_metadata(base).unwrap().file_type().is_symlink());
}

#[test]
fn non_directory_paths_fail_without_changing_the_existing_object() {
    let directory = tempfile::tempdir().unwrap();
    let base_file = directory.path().join("base-file");
    fs::write(&base_file, b"not a directory").unwrap();
    #[cfg(unix)]
    set_mode(&base_file, 0o640);
    let manager = TempPathManager::new(&base_file);
    assert!(matches!(manager.ensure_directories(), Err(TempManagementError::DirectoryCreation(_))));
    assert_eq!(fs::read(&base_file).unwrap(), b"not a directory");
    #[cfg(unix)]
    assert_eq!(mode(&base_file), 0o640);
    let base = directory.path().join("base");
    fs::create_dir(&base).unwrap();
    let quarantine_file = base.join(".quarantine");
    fs::write(&quarantine_file, b"not quarantine").unwrap();
    let manager = TempPathManager::new(&base);
    assert!(matches!(manager.ensure_directories(), Err(TempManagementError::QuarantineDirectoryCreation(_))));
    assert_eq!(fs::read(quarantine_file).unwrap(), b"not quarantine");
}

#[cfg(unix)]
#[test]
fn concurrent_managers_do_not_reconfigure_shared_directories() {
    let directory = tempfile::tempdir().unwrap();
    let quarantine = directory.path().join(".quarantine");
    fs::create_dir(&quarantine).unwrap();
    set_mode(directory.path(), 0o771);
    set_mode(&quarantine, 0o711);
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut workers = Vec::new();
    for i in 0..8 {
        let path = directory.path().to_path_buf();
        let start = std::sync::Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            let manager = TempPathManager::with_config(path, TempManagementConfig {
                temp_dir_permissions: Some(if i % 2 == 0 { 0o700 } else { 0o750 }),
                ..TempManagementConfig::default()
            });
            manager.ensure_directories().unwrap();
        }));
    }
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(mode(directory.path()), 0o771);
    assert_eq!(mode(&quarantine), 0o711);
}

#[cfg(unix)]
#[test]
fn scoped_receive_to_publication_preserves_destination_access_and_private_files() {
    use crate::atp::journal::sparse_writer::ScopedSparseWriter;
    use crate::atp::journal::{ScopedReceiveOptions, SparseWriterConfig};
    use crate::atp::manifest::Manifest;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::cx::Cx;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::sync::Arc;
    use std::time::Duration;

    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        set_mode(directory.path(), 0o755);
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let object = Object::file(b"private payload".to_vec());
            let id = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
            let destination = directory.path().join("file");
            let writer = ScopedSparseWriter::new(&cx, id, destination.clone(), SparseWriterConfig {
                enable_preallocation: false,
                ..SparseWriterConfig::default()
            }).await.unwrap().unwrap();
            assert_eq!(mode(directory.path()), 0o755);
            let mut session = writer.receive_exact(
                &cx, b"private payload".as_slice(), manifest,
                ScopedReceiveOptions { max_bytes: 64, max_chunks: 16, chunk_size: 4 },
            ).unwrap();
            assert_eq!(session.wait().await.unwrap().unwrap(), destination);
            assert_eq!(fs::read(&destination).unwrap(), b"private payload");
            assert_eq!(mode(&destination) & 0o177, 0);
            assert_eq!(mode(directory.path()), 0o755);
        });
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
    }
}
