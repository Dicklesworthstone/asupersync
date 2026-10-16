    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn validate_named_pipe_path_rejects_non_pipe_namespace() {
        let err = validate_named_pipe_path(Path::new(r"C:\tmp\not-a-pipe")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn validate_named_pipe_path_rejects_empty_pipe_name() {
        let err = validate_named_pipe_path(Path::new(r"\\.\pipe\")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn validate_named_pipe_path_accepts_valid_prefix_and_name() {
        let valid = validate_named_pipe_path(Path::new(r"\\.\pipe\asupersync-test"));
        assert!(valid.is_ok());
    }

    #[test]
    fn options_reject_read_and_write_both_disabled() {
        let err = NamedPipeClientOptions::new()
            .read(false)
            .write(false)
            .open(Path::new(r"\\.\pipe\asupersync-test"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
