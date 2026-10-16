    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::process;
    use std::time::UNIX_EPOCH;

    fn level_table() -> String {
        [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ]
        .into_iter()
        .map(|level| format!("{level}|{}|{}", level.as_char(), level.as_str_lower()))
        .collect::<Vec<_>>()
        .join("\n")
    }

    fn structured_filter_snapshot() -> (String, u32, u128) {
        let timestamp_nanos = crate::observability::replayable_system_time()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let pid = process::id();
        let records = [
            (LogLevel::Trace, "trace-path"),
            (LogLevel::Debug, "debug-path"),
            (LogLevel::Info, "info-path"),
            (LogLevel::Warn, "warn-path"),
            (LogLevel::Error, "error-path"),
        ];

        let rendered = [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ]
        .into_iter()
        .map(|threshold| {
            let rendered = records
                .iter()
                .filter(|(level, _)| level.is_enabled_at(threshold))
                .map(|(level, message)| {
                    format!(
                        "{{\"pid\":{pid},\"threshold\":\"{threshold}\",\"timestamp\":\"ts-{timestamp_nanos}\",\"level\":\"{level}\",\"message\":\"{message}\"}}",
                        threshold = threshold.as_str_lower(),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("[threshold={}]\n{rendered}", threshold.as_str_lower())
        })
        .collect::<Vec<_>>()
        .join("\n\n");

        (rendered, pid, timestamp_nanos)
    }

    fn scrub_structured_filter_snapshot(rendered: &str, pid: u32, timestamp_nanos: u128) -> String {
        rendered
            .replace(&format!("\"pid\":{pid}"), "\"pid\":[PID]")
            .replace(
                &format!("\"timestamp\":\"ts-{timestamp_nanos}\""),
                "\"timestamp\":\"[TIMESTAMP]\"",
            )
    }

    #[test]
    fn test_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_level_enabled_at_threshold() {
        let threshold = LogLevel::Info;
        assert!(LogLevel::Error.is_enabled_at(threshold));
        assert!(LogLevel::Warn.is_enabled_at(threshold));
        assert!(LogLevel::Info.is_enabled_at(threshold));
        assert!(!LogLevel::Debug.is_enabled_at(threshold));
        assert!(!LogLevel::Trace.is_enabled_at(threshold));
    }

    #[test]
    fn test_level_from_str() {
        assert_eq!(LogLevel::from_str("info"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("INFO"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("Warn"), Ok(LogLevel::Warn));
        assert!(LogLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_level_display() {
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
    }

    #[test]
    fn test_as_char() {
        assert_eq!(LogLevel::Trace.as_char(), 'T');
        assert_eq!(LogLevel::Error.as_char(), 'E');
    }

    // =========================================================================
    // Wave 52 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn log_level_debug_clone_copy_hash_default() {
        use std::collections::HashSet;
        let l = LogLevel::Warn;
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Warn"), "{dbg}");
        let copied = l;
        let cloned = l;
        assert_eq!(copied, cloned);
        let def = LogLevel::default();
        assert_eq!(def, LogLevel::Info);
        let mut set = HashSet::new();
        set.insert(l);
        assert!(set.contains(&LogLevel::Warn));
    }

    #[test]
    fn log_level_table_snapshot() {
        insta::assert_snapshot!("log_level_table", level_table());
    }

    #[test]
    fn log_level_structured_filter_snapshot_scrubs_timestamp_and_pid() {
        let (rendered, pid, timestamp_nanos) = structured_filter_snapshot();
        insta::assert_snapshot!(
            "log_level_structured_filter_scrubbed",
            scrub_structured_filter_snapshot(&rendered, pid, timestamp_nanos)
        );
    }
