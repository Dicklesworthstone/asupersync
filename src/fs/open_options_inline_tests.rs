    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn open_options_builder() {
        init_test("open_options_builder");
        let opts = OpenOptions::new().read(true).write(true).create(true);

        crate::assert_with_log!(opts.read, "read", true, opts.read);
        crate::assert_with_log!(opts.write, "write", true, opts.write);
        crate::assert_with_log!(opts.create, "create", true, opts.create);
        crate::assert_with_log!(!opts.append, "append false", false, opts.append);
        crate::assert_with_log!(!opts.truncate, "truncate false", false, opts.truncate);
        crate::assert_with_log!(!opts.create_new, "create_new false", false, opts.create_new);
        crate::test_complete!("open_options_builder");
    }

    #[test]
    fn open_options_default() {
        init_test("open_options_default");
        let opts = OpenOptions::default();
        crate::assert_with_log!(!opts.read, "read false", false, opts.read);
        crate::assert_with_log!(!opts.write, "write false", false, opts.write);
        crate::assert_with_log!(!opts.append, "append false", false, opts.append);
        crate::assert_with_log!(!opts.truncate, "truncate false", false, opts.truncate);
        crate::assert_with_log!(!opts.create, "create false", false, opts.create);
        crate::assert_with_log!(!opts.create_new, "create_new false", false, opts.create_new);
        crate::test_complete!("open_options_default");
    }

    #[test]
    fn to_std_options_roundtrip() {
        init_test("to_std_options_roundtrip");
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");

        // Create a file using our options
        let opts = OpenOptions::new().write(true).create(true);
        let std_opts = opts.to_std_options();

        // Should succeed
        let file = std_opts.open(&path);
        crate::assert_with_log!(file.is_ok(), "open ok", true, file.is_ok());
        crate::test_complete!("to_std_options_roundtrip");
    }

    #[cfg(unix)]
    #[test]
    fn mode_option_unix() {
        init_test("mode_option_unix");
        let opts = OpenOptions::new().write(true).create(true).mode(0o600);

        crate::assert_with_log!(opts.mode == Some(0o600), "mode", Some(0o600), opts.mode);
        crate::test_complete!("mode_option_unix");
    }

    #[cfg(unix)]
    #[test]
    fn custom_flags_option_unix() {
        init_test("custom_flags_option_unix");
        let opts = OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(libc::O_CLOEXEC);

        crate::assert_with_log!(
            opts.custom_flags == Some(libc::O_CLOEXEC),
            "custom_flags",
            Some(libc::O_CLOEXEC),
            opts.custom_flags
        );
        crate::test_complete!("custom_flags_option_unix");
    }

    #[test]
    fn open_options_debug_clone_default() {
        let opts = OpenOptions::new();
        let cloned = opts.clone();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("OpenOptions"));
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
        let default_opts = OpenOptions::default();
        let dbg3 = format!("{default_opts:?}");
        assert_eq!(dbg, dbg3);
    }
