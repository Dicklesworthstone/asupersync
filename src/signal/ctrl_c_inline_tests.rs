    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn ctrl_c_not_available() {
        init_test("ctrl_c_not_available");
        let available = is_available();
        #[cfg(any(unix, windows))]
        crate::assert_with_log!(available, "available", true, available);
        #[cfg(not(any(unix, windows)))]
        crate::assert_with_log!(!available, "not available", false, available);
        crate::test_complete!("ctrl_c_not_available");
    }

    #[test]
    fn ctrl_c_error_display() {
        init_test("ctrl_c_error_display");
        let err = CtrlCError::unavailable();
        let msg = format!("{err}");
        let contains = msg.contains("unavailable");
        crate::assert_with_log!(contains, "contains unavailable", true, contains);
        crate::test_complete!("ctrl_c_error_display");
    }

    /// is_available() used to register a SIGINT handler that is never
    /// removed, so a program that only probed availability could no longer
    /// be stopped with Ctrl+C. Checked in a fresh child test process (other
    /// tests here register SIGINT for real) through the kernel's own record
    /// of caught signals, which does not depend on how the test runner's
    /// SIGINT disposition was inherited.
    #[cfg(target_os = "linux")]
    #[test]
    fn is_available_does_not_install_a_sigint_handler() {
        const CHILD_ENV: &str = "ASUPERSYNC_CTRL_C_PROBE_CHILD";
        const TEST_NAME: &str =
            "signal::ctrl_c::tests::is_available_does_not_install_a_sigint_handler";
        fn sigint_caught() -> bool {
            let status = std::fs::read_to_string("/proc/self/status").expect("read status");
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
                .expect("SigCgt line");
            // SIGINT is signal 2, bit 1 of the mask.
            mask & (1 << 1) != 0
        }

        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(!sigint_caught(), "a fresh process starts without one");
            assert!(is_available());
            assert!(
                !sigint_caught(),
                "is_available() must not install a SIGINT handler"
            );
            return;
        }
        init_test("is_available_does_not_install_a_sigint_handler");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child test binary");
        assert!(
            output.status.success(),
            "child probe failed: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        // The child must actually have run the test, not filtered it out.
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("1 passed"),
            "child did not run the probe: {stdout}"
        );
        crate::test_complete!("is_available_does_not_install_a_sigint_handler");
    }
