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

#[cfg(target_os = "linux")]
#[test]
fn status_loads_metadata_for_a_process_missing_from_the_initial_snapshot() {
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

    // A newly spawned daemon is absent from the controller's construction
    // snapshot. An empty snapshot reproduces that state without spawning a
    // second test harness or changing this process's working directory.
    controller.system = System::new().unwrap();
    let pid = std::process::id();
    std::fs::write(&controller.pid_file, pid.to_string()).unwrap();
    let expected_dir = std::env::current_dir().unwrap().canonicalize().unwrap();
    let info = controller.status_strict(&Cx::for_testing()).unwrap();

    assert_eq!(info.pid, Some(pid));
    assert_eq!(info.working_dir, expected_dir);
    assert!(
        !info.command.is_empty(),
        "status must load the command line"
    );
    let process = controller.system.process(Pid::from_u32(pid)).unwrap();
    assert_eq!(
        process.cwd(),
        Some(expected_dir.as_path()),
        "the directory must be observed, not the caller's fallback"
    );
    assert!(
        process.user_id().is_some(),
        "status must load the process user"
    );
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

#[test]
fn strict_status_preserves_pid_claim_errors_while_legacy_status_stays_compatible() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let mut controller = create_atp_daemon_controller_with_executable(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        temp_dir.path(),
        &std::env::current_exe().unwrap(),
    )
    .unwrap();
    let cx = Cx::for_testing();

    assert_eq!(controller.status_strict(&cx).unwrap().pid, None);
    for invalid in ["not a pid\n", "0\n", "1\n", "4294967296\n"] {
        std::fs::write(&controller.pid_file, invalid).unwrap();
        assert!(
            controller.status_strict(&cx).is_err(),
            "strict status must reject an inconclusive PID claim: {invalid:?}"
        );
        assert_eq!(controller.status(&cx).unwrap().pid, None);
        assert_eq!(
            std::fs::read_to_string(&controller.pid_file).unwrap(),
            invalid
        );
    }

    // A directory at the claim path is a deterministic read error, even when
    // tests run with privileges that would bypass ordinary file permissions.
    controller.pid_file = temp_dir.path().join("pid-directory");
    std::fs::create_dir(&controller.pid_file).unwrap();
    assert!(controller.status_strict(&cx).is_err());
    assert_eq!(controller.status(&cx).unwrap().pid, None);
    assert!(controller.pid_file.is_dir());
}

#[test]
fn strict_stop_needs_only_stop_capability_and_rejects_inconclusive_discovery() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    let mut controller = create_atp_daemon_controller(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Stop],
        temp_dir.path(),
    )
    .unwrap();
    let cx = Cx::for_testing();

    assert!(controller.status_strict(&cx).is_err());
    assert!(matches!(
        controller.stop_strict(&cx).unwrap(),
        DaemonControlResult::Success {
            previous_state: DaemonState::Stopped,
            new_state: DaemonState::Stopped,
            ..
        }
    ));

    std::fs::write(&controller.pid_file, "not a pid").unwrap();
    assert!(controller.stop_strict(&cx).is_err());
    assert_eq!(
        std::fs::read_to_string(&controller.pid_file).unwrap(),
        "not a pid"
    );
    assert!(matches!(
        controller.stop(&cx).unwrap(),
        DaemonControlResult::Success {
            previous_state: DaemonState::Stopped,
            new_state: DaemonState::Stopped,
            ..
        }
    ));

    cx.set_cancel_requested(true);
    assert!(controller.stop_strict(&cx).is_err());
}

#[cfg(unix)]
#[test]
fn pid_claim_rejects_values_outside_the_native_process_id_range() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    let controller = create_atp_daemon_controller(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::ForceKill],
        temp_dir.path(),
    )
    .unwrap();

    std::fs::write(&controller.pid_file, u32::MAX.to_string()).unwrap();
    assert!(controller.read_pid_file().is_err());
}

#[test]
fn an_executable_basename_is_not_external_process_identity() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "# test config").unwrap();
    let current_exe = std::env::current_exe().unwrap();
    let lookalike_path = temp_dir.path().join(current_exe.file_name().unwrap());
    std::fs::write(&lookalike_path, "not the running executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lookalike_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut controller = SecureDaemonController::new(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        lookalike_path,
        config_path,
    )
    .unwrap();
    std::fs::write(&controller.pid_file, std::process::id().to_string()).unwrap();

    let process = controller
        .system
        .process(Pid::from_u32(std::process::id()))
        .expect("the current process must be visible");
    assert!(!controller.is_our_daemon_process(process));
    assert_eq!(
        controller.status_strict(&Cx::for_testing()).unwrap().pid,
        None,
        "a known different executable is not the configured daemon"
    );
}

#[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
#[test]
fn restart_capability_authorizes_the_combined_action_without_standalone_grants() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    let mut controller = create_atp_daemon_controller_with_executable(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Restart],
        temp_dir.path(),
        // The harness rejects --config, proving restart reached the actual
        // spawn path without requiring Start or Stop capabilities.
        &std::env::current_exe().unwrap(),
    )
    .unwrap();
    let cx = Cx::for_testing();
    assert!(controller.start(&cx).is_err());
    assert!(controller.stop(&cx).is_err());

    let result = controller.restart(&cx).unwrap();
    assert!(matches!(
        result,
        DaemonControlResult::Failed {
            operation: DaemonControlCapability::Start,
            current_state: DaemonState::Failed,
            ..
        }
    ));
    assert!(
        controller.child.is_none(),
        "failed restart must reap its child"
    );
    assert!(!controller.pid_file.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_configuration_preserves_the_callers_pid_directory_and_working_directory() {
    let temp_dir = TempDir::new().unwrap();
    let caller_dir = temp_dir.path().join("instance");
    let shared_dir = temp_dir.path().join("shared-config");
    std::fs::create_dir(&caller_dir).unwrap();
    std::fs::create_dir(&shared_dir).unwrap();
    let target_config = shared_dir.join("daemon.toml");
    std::fs::write(&target_config, "# shared config").unwrap();
    std::os::unix::fs::symlink(&target_config, caller_dir.join("config.toml")).unwrap();
    let mut controller = create_atp_daemon_controller(
        RegionId::new_for_test(1, 0),
        vec![DaemonControlCapability::Status],
        &caller_dir,
    )
    .unwrap();

    let caller_dir = caller_dir.canonicalize().unwrap();
    assert_eq!(
        controller.config_path,
        target_config.canonicalize().unwrap()
    );
    assert_eq!(controller.config_dir, caller_dir);
    assert_eq!(controller.pid_file, caller_dir.join("daemon.pid"));
    assert_eq!(
        controller.status(&Cx::for_testing()).unwrap().working_dir,
        caller_dir
    );
}
