use super::*;
use tempfile::TempDir;

#[test]
fn test_capability_validation() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();

    let controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        std::env::current_exe().unwrap(),
        config_path,
    )
    .unwrap();

    // Status capability should work
    assert!(
        controller
            .require_capability(DaemonControlCapability::Status)
            .is_ok()
    );

    // Start capability should fail
    assert!(
        controller
            .require_capability(DaemonControlCapability::Start)
            .is_err()
    );
}

#[test]
fn test_daemon_controller_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();

    let controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![
            DaemonControlCapability::Status,
            DaemonControlCapability::Start,
        ],
        std::env::current_exe().unwrap(),
        config_path,
    );

    assert!(controller.is_ok());
}

#[test]
fn test_invalid_daemon_path() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();

    let controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        PathBuf::from("/nonexistent/daemon"),
        config_path,
    );

    assert!(controller.is_err());
}

#[test]
fn windows_executable_extension_matching_uses_pathext_semantics() {
    assert!(path_has_windows_executable_extension(
        Path::new("atpd.ExE"),
        Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
    ));
    assert!(path_has_windows_executable_extension(
        Path::new("atpd.cmd"),
        Some(std::ffi::OsStr::new("EXE;CMD"))
    ));
    assert!(!path_has_windows_executable_extension(
        Path::new("atpd.sh"),
        Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
    ));
    assert!(!path_has_windows_executable_extension(
        Path::new("atpd"),
        Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
    ));
}

#[test]
fn test_atp_daemon_controller_factory() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();

    let controller = create_atp_daemon_controller(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        temp_dir.path(),
    );

    assert!(controller.is_ok());
}

#[test]
fn unlimited_budget_allows_status_without_mutating_a_stale_pid_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let mut controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        std::env::current_exe().unwrap(),
        config_path,
    )
    .unwrap();
    let pid_contents = u32::MAX.to_string();
    std::fs::write(&controller.pid_file, &pid_contents).unwrap();

    let status = controller.status(&Cx::for_testing()).unwrap();

    assert_eq!(status.pid, None);
    assert_eq!(
        std::fs::read_to_string(&controller.pid_file).unwrap(),
        pid_contents,
        "status must not remove the daemon's PID claim"
    );
}

#[test]
fn exhausted_cost_budget_still_denies_control() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let mut controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        std::env::current_exe().unwrap(),
        config_path,
    )
    .unwrap();
    let cx = Cx::for_testing_with_budget(crate::types::Budget::INFINITE.with_cost_quota(0));

    assert!(controller.status(&cx).is_err());
}

#[test]
fn relative_configuration_is_resolved_before_changing_child_directory() {
    let current_dir = std::env::current_dir().unwrap();
    let temp_dir = TempDir::new_in(&current_dir).unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let relative_config = config_path
        .strip_prefix(&current_dir)
        .unwrap()
        .to_path_buf();
    let controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Start],
        std::env::current_exe().unwrap(),
        relative_config,
    )
    .unwrap();

    assert_eq!(controller.config_path, config_path.canonicalize().unwrap());
    assert!(controller.daemon_path.is_absolute());
    assert!(controller.pid_file.is_absolute());
}

#[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
#[test]
fn failed_start_reaps_the_child_without_publishing_a_pid_claim() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let mut controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Start],
        // Rust's test harness rejects atpd's --config option before running
        // any tests, giving a portable real-process startup failure.
        std::env::current_exe().unwrap(),
        config_path,
    )
    .unwrap();

    let result = controller.start(&Cx::for_testing()).unwrap();

    assert!(matches!(
        result,
        DaemonControlResult::Failed {
            operation: DaemonControlCapability::Start,
            current_state: DaemonState::Failed,
            ..
        }
    ));
    assert!(controller.child.is_none(), "failed child must be reaped");
    assert!(!controller.pid_file.exists());
}

#[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
#[test]
fn cancelled_start_never_spawns_the_daemon() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let mut controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Start],
        std::env::current_exe().unwrap(),
        config_path,
    )
    .unwrap();
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    assert!(controller.start(&cx).is_err());
    assert!(controller.child.is_none());
    assert!(!controller.pid_file.exists());
}
