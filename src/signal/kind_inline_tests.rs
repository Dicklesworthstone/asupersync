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
    fn signal_kind_constructors() {
        init_test("signal_kind_constructors");
        crate::assert_with_log!(
            SignalKind::interrupt() == SignalKind::Interrupt,
            "interrupt",
            SignalKind::Interrupt,
            SignalKind::interrupt()
        );
        crate::assert_with_log!(
            SignalKind::terminate() == SignalKind::Terminate,
            "terminate",
            SignalKind::Terminate,
            SignalKind::terminate()
        );
        crate::assert_with_log!(
            SignalKind::hangup() == SignalKind::Hangup,
            "hangup",
            SignalKind::Hangup,
            SignalKind::hangup()
        );
        crate::assert_with_log!(
            SignalKind::quit() == SignalKind::Quit,
            "quit",
            SignalKind::Quit,
            SignalKind::quit()
        );
        crate::assert_with_log!(
            SignalKind::user_defined1() == SignalKind::User1,
            "user1",
            SignalKind::User1,
            SignalKind::user_defined1()
        );
        crate::assert_with_log!(
            SignalKind::user_defined2() == SignalKind::User2,
            "user2",
            SignalKind::User2,
            SignalKind::user_defined2()
        );
        crate::assert_with_log!(
            SignalKind::child() == SignalKind::Child,
            "child",
            SignalKind::Child,
            SignalKind::child()
        );
        crate::assert_with_log!(
            SignalKind::window_change() == SignalKind::WindowChange,
            "window_change",
            SignalKind::WindowChange,
            SignalKind::window_change()
        );
        crate::test_complete!("signal_kind_constructors");
    }

    #[test]
    fn signal_kind_names() {
        init_test("signal_kind_names");
        let interrupt = SignalKind::Interrupt.name();
        crate::assert_with_log!(interrupt == "SIGINT", "interrupt", "SIGINT", interrupt);
        let terminate = SignalKind::Terminate.name();
        crate::assert_with_log!(terminate == "SIGTERM", "terminate", "SIGTERM", terminate);
        let hangup = SignalKind::Hangup.name();
        crate::assert_with_log!(hangup == "SIGHUP", "hangup", "SIGHUP", hangup);
        crate::test_complete!("signal_kind_names");
    }

    #[test]
    fn signal_kind_display() {
        init_test("signal_kind_display");
        let interrupt = format!("{}", SignalKind::Interrupt);
        crate::assert_with_log!(interrupt == "SIGINT", "interrupt", "SIGINT", interrupt);
        let terminate = format!("{}", SignalKind::Terminate);
        crate::assert_with_log!(terminate == "SIGTERM", "terminate", "SIGTERM", terminate);
        crate::test_complete!("signal_kind_display");
    }

    #[test]
    fn signal_kind_all_variants_name_and_display_match() {
        init_test("signal_kind_all_variants_name_and_display_match");
        let cases = [
            (SignalKind::interrupt(), "SIGINT"),
            (SignalKind::terminate(), "SIGTERM"),
            (SignalKind::hangup(), "SIGHUP"),
            (SignalKind::quit(), "SIGQUIT"),
            (SignalKind::user_defined1(), "SIGUSR1"),
            (SignalKind::user_defined2(), "SIGUSR2"),
            (SignalKind::child(), "SIGCHLD"),
            (SignalKind::window_change(), "SIGWINCH"),
            (SignalKind::pipe(), "SIGPIPE"),
            (SignalKind::alarm(), "SIGALRM"),
        ];

        for (kind, expected_name) in cases {
            let name = kind.name();
            crate::assert_with_log!(
                name == expected_name,
                "name matches expected signal spelling",
                expected_name,
                name
            );

            let display_name = kind.to_string();
            crate::assert_with_log!(
                display_name == expected_name,
                "display delegates to name",
                expected_name,
                display_name
            );
        }

        crate::test_complete!("signal_kind_all_variants_name_and_display_match");
    }

    #[cfg(unix)]
    #[test]
    fn signal_kind_raw_values() {
        init_test("signal_kind_raw_values");
        let interrupt = SignalKind::Interrupt.as_raw_value();
        crate::assert_with_log!(
            interrupt == libc::SIGINT,
            "interrupt",
            libc::SIGINT,
            interrupt
        );
        let terminate = SignalKind::Terminate.as_raw_value();
        crate::assert_with_log!(
            terminate == libc::SIGTERM,
            "terminate",
            libc::SIGTERM,
            terminate
        );
        let hangup = SignalKind::Hangup.as_raw_value();
        crate::assert_with_log!(hangup == libc::SIGHUP, "hangup", libc::SIGHUP, hangup);
        let user1 = SignalKind::User1.as_raw_value();
        crate::assert_with_log!(user1 == libc::SIGUSR1, "user1", libc::SIGUSR1, user1);
        let user2 = SignalKind::User2.as_raw_value();
        crate::assert_with_log!(user2 == libc::SIGUSR2, "user2", libc::SIGUSR2, user2);
        let child = SignalKind::Child.as_raw_value();
        crate::assert_with_log!(child == libc::SIGCHLD, "child", libc::SIGCHLD, child);
        let winch = SignalKind::WindowChange.as_raw_value();
        crate::assert_with_log!(winch == libc::SIGWINCH, "winch", libc::SIGWINCH, winch);
        let pipe = SignalKind::Pipe.as_raw_value();
        crate::assert_with_log!(pipe == libc::SIGPIPE, "pipe", libc::SIGPIPE, pipe);
        let alarm = SignalKind::Alarm.as_raw_value();
        crate::assert_with_log!(alarm == libc::SIGALRM, "alarm", libc::SIGALRM, alarm);
        crate::test_complete!("signal_kind_raw_values");
    }

    #[cfg(windows)]
    #[test]
    fn signal_kind_raw_values_windows_subset() {
        init_test("signal_kind_raw_values_windows_subset");
        let interrupt = SignalKind::Interrupt.as_raw_value();
        crate::assert_with_log!(
            interrupt == Some(libc::SIGINT),
            "interrupt",
            Some(libc::SIGINT),
            interrupt
        );
        let terminate = SignalKind::Terminate.as_raw_value();
        crate::assert_with_log!(
            terminate == Some(libc::SIGTERM),
            "terminate",
            Some(libc::SIGTERM),
            terminate
        );
        let quit = SignalKind::Quit.as_raw_value();
        crate::assert_with_log!(
            quit == Some(signal_hook::consts::SIGBREAK),
            "quit",
            Some(signal_hook::consts::SIGBREAK),
            quit
        );
        let user1 = SignalKind::User1.as_raw_value();
        crate::assert_with_log!(user1.is_none(), "user1 unsupported", true, user1.is_none());
        crate::test_complete!("signal_kind_raw_values_windows_subset");
    }

    // =========================================================================
    // Wave 51 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn signal_kind_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let s = SignalKind::Interrupt;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Interrupt"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        let mut set = HashSet::new();
        set.insert(s);
        assert!(set.contains(&SignalKind::Interrupt));
        assert!(!set.contains(&SignalKind::Terminate));
    }
