use super::*;
use tempfile::TempDir;

#[test]
fn test_upgrade_controller_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path();

    // Create a minimal config file.
    std::fs::write(config_dir.join("config.toml"), "# test config").unwrap();

    let result = create_upgrade_daemon_controller(RegionId::new_for_test(1, 0), config_dir);

    assert!(result.is_ok());
}

#[test]
fn explicit_upgrade_controller_validates_the_selected_executable() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    let region = RegionId::new_for_test(1, 0);

    let missing = temp_dir.path().join("missing-atpd");
    assert!(
        create_upgrade_daemon_controller_with_executable(region, temp_dir.path(), &missing)
            .is_err()
    );
    assert!(
        create_upgrade_daemon_controller_with_executable(
            region,
            temp_dir.path(),
            &std::env::current_exe().unwrap(),
        )
        .is_ok()
    );
    assert!(!temp_dir.path().join("daemon.pid").exists());
}

#[test]
fn explicit_upgrade_controller_requires_configuration_before_starting() {
    let temp_dir = TempDir::new().unwrap();
    assert!(
        UpgradeDaemonController::new_for_upgrade_with_executable(
            RegionId::new_for_test(1, 0),
            temp_dir.path(),
            &std::env::current_exe().unwrap(),
        )
        .is_err()
    );
    assert!(!temp_dir.path().join("daemon.pid").exists());
}

#[test]
fn strict_upgrade_status_preserves_authorization_failures() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    let mut controller = UpgradeDaemonController::new_for_upgrade_with_executable(
        RegionId::new_for_test(1, 0),
        temp_dir.path(),
        &std::env::current_exe().unwrap(),
    )
    .unwrap();
    let denied = Cx::for_testing_with_budget(crate::types::Budget::INFINITE.with_cost_quota(0));

    assert!(
        futures_lite::future::block_on(controller.try_is_daemon_running(&denied)).is_err(),
        "an unauthorized query must not certify daemon absence"
    );
    assert!(
        !futures_lite::future::block_on(controller.is_daemon_running(&denied)).unwrap(),
        "the established query retains its compatibility behavior"
    );
    assert!(
        !futures_lite::future::block_on(controller.try_is_daemon_running(&Cx::for_testing()))
            .unwrap()
    );
}

#[test]
fn strict_upgrade_status_rejects_corrupt_pid_claims() {
    for claim in ["not-a-process-id", "0", "1"] {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
        std::fs::write(temp_dir.path().join("daemon.pid"), claim).unwrap();
        let mut controller = UpgradeDaemonController::new_for_upgrade_with_executable(
            RegionId::new_for_test(1, 0),
            temp_dir.path(),
            &std::env::current_exe().unwrap(),
        )
        .unwrap();
        let cx = Cx::for_testing();

        assert!(
            futures_lite::future::block_on(controller.try_is_daemon_running(&cx)).is_err(),
            "a corrupt PID claim must not certify daemon absence: {claim:?}"
        );
        assert!(
            futures_lite::future::block_on(controller.try_stop_daemon_if_running(&cx)).is_err(),
            "a corrupt PID claim must stop the upgrade: {claim:?}"
        );
        assert!(
            !futures_lite::future::block_on(controller.is_daemon_running(&cx)).unwrap(),
            "legacy status behavior remains unchanged"
        );
        assert!(
            !futures_lite::future::block_on(controller.stop_daemon_if_running(&cx)).unwrap(),
            "legacy stop discovery behavior remains unchanged"
        );
    }
}

#[test]
fn strict_upgrade_status_preserves_pid_claim_read_failures() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("config.toml"), "# test config").unwrap();
    std::fs::create_dir(temp_dir.path().join("daemon.pid")).unwrap();
    let mut controller = UpgradeDaemonController::new_for_upgrade_with_executable(
        RegionId::new_for_test(1, 0),
        temp_dir.path(),
        &std::env::current_exe().unwrap(),
    )
    .unwrap();

    assert!(
        futures_lite::future::block_on(controller.try_is_daemon_running(&Cx::for_testing()))
            .is_err(),
        "an unreadable PID claim must not certify daemon absence"
    );
    assert!(
        futures_lite::future::block_on(controller.try_stop_daemon_if_running(&Cx::for_testing()))
            .is_err(),
        "an unreadable PID claim must stop the upgrade"
    );
}
