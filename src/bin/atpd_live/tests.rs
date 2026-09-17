//! Focused configuration and conservative admission regressions.

use super::{settings, storage};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn directory() -> PathBuf {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn inbox(directory: PathBuf, bytes: u64, entries: u64) -> settings::InboxConfig {
    settings::InboxConfig {
        certificate_sha256: "ab".repeat(32),
        directory,
        max_retained_bytes: bytes,
        max_retained_entries: entries,
    }
}

#[test]
fn certificate_selectors_require_full_digests_and_normalize_case() {
    let lower = "ab".repeat(32);
    assert_eq!(
        settings::selector(&lower).unwrap(),
        settings::selector(&lower.to_uppercase()).unwrap()
    );
    for value in [
        "".to_owned(),
        "0".repeat(63),
        "0".repeat(65),
        "gg".repeat(32),
        "é".repeat(32),
    ] {
        assert!(settings::selector(&value).is_err());
    }
    assert_eq!(
        settings::hex(settings::selector(&lower).unwrap().as_bytes()),
        lower
    );
}

#[test]
fn live_configuration_refuses_unknown_fields_and_unbounded_runtime_limits() {
    let path = directory().join("settings.json");
    std::fs::write(
        &path,
        br#"{"schema_version":1,"unexpected_secret":"must-not-echo"}"#,
    )
    .unwrap();
    let error = settings::load::<settings::ServeConfig>(&path)
        .err()
        .unwrap();
    assert!(!error.to_string().contains("must-not-echo"));
    for (version, workers, epoch, bytes, timeout) in [
        (2, 1, 8, 10, 5),
        (1, 0, 8, 10, 5),
        (1, 33, 8, 10, 5),
        (1, 1, 0, 10, 5),
        (1, 1, 65537, 10, 5),
        (1, 1, 8, u64::MAX, 5),
        (1, 1, 8, 10, 0),
    ] {
        assert!(settings::profile(version, workers, epoch, bytes, timeout).is_err());
    }
    assert!(settings::profile(1, 1, 65536, 0, 1).is_ok());
}

#[test]
fn credential_open_rejects_public_keys_and_symlinks_without_changing_files() {
    let directory = directory();
    let file = directory.join("private.pem");
    std::fs::write(&file, b"sensitive-test-material").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        settings::open_regular(&file, true).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let alias = directory.join("alias.pem");
    std::os::unix::fs::symlink(&file, &alias).unwrap();
    assert!(settings::open_regular(&alias, false).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"sensitive-test-material");
}

#[test]
fn retention_reserves_aliases_and_never_refunds_an_admitted_attempt() {
    let config = inbox(directory(), 20, 5);
    let id = settings::selector(&config.certificate_sha256).unwrap();
    let inboxes = storage::load(&[config]).unwrap();
    let retained = &inboxes[&id];
    retained.reserve(5).unwrap();
    retained.reserve(5).unwrap();
    assert_eq!(
        retained.reserve(0).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(
        retained.reserve(1).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
}

#[test]
fn restart_scans_all_retained_aliases_and_excludes_a_second_owner() {
    let directory = directory();
    let original = directory.join("partial");
    std::fs::write(&original, b"1234").unwrap();
    std::fs::hard_link(&original, directory.join("published")).unwrap();
    let config = inbox(directory, 12, 5);
    let id = settings::selector(&config.certificate_sha256).unwrap();
    let first = storage::load(std::slice::from_ref(&config)).unwrap();
    assert_eq!(
        storage::load(std::slice::from_ref(&config))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        first[&id].reserve(3).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    first[&id].reserve(2).unwrap();
    drop(first);
    let restarted = storage::load(&[config]).unwrap();
    restarted[&id].reserve(2).unwrap();
    assert_eq!(std::fs::read(original).unwrap(), b"1234");
}

#[test]
fn inbox_scan_refuses_symlinks_and_duplicate_authority() {
    let directory = directory();
    let file = directory.join("source");
    std::fs::write(&file, b"retained").unwrap();
    std::os::unix::fs::symlink(&file, directory.join("alias")).unwrap();
    assert!(storage::load(&[inbox(directory, 100, 10)]).is_err());
    let config = inbox(self::directory(), 100, 10);
    assert!(storage::load(&[config.clone(), config]).is_err());
}
