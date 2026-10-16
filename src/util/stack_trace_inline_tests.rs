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
    fn test_capture_stack_trace() {
        let trace = capture_stack_trace();

        // Should not be empty
        assert!(!trace.is_empty());

        // When stack traces are enabled, should contain "Stack trace:"
        // When disabled, should contain "disabled"
        #[cfg(feature = "lab-stack-traces")]
        assert!(trace.contains("Stack trace:"));

        #[cfg(not(feature = "lab-stack-traces"))]
        assert!(trace.contains("disabled"));
    }

    #[test]
    fn test_stack_trace_wrapper() {
        let trace = StackTrace::capture();

        // Should not be empty
        assert!(!trace.as_str().is_empty());

        // Display trait should work
        let displayed = format!("{}", trace);
        assert_eq!(displayed, trace.as_str());

        // Compact should work
        let compact = trace.compact();
        assert!(!compact.is_empty());

        // Frame count should be reasonable
        let frame_count = trace.frame_count();
        assert!(frame_count > 0);
    }

    #[test]
    fn test_stack_trace_from_deep_call() {
        fn level_1() -> StackTrace {
            level_2()
        }

        fn level_2() -> StackTrace {
            level_3()
        }

        fn level_3() -> StackTrace {
            StackTrace::capture()
        }

        let trace = level_1();

        // Should contain function names (when feature enabled)
        #[cfg(feature = "lab-stack-traces")]
        {
            let trace_str = trace.as_str();
            assert!(
                trace_str.contains("level_1")
                    || trace_str.contains("level_2")
                    || trace_str.contains("level_3")
            );
            assert!(trace.frame_count() > 1);
        }

        #[cfg(not(feature = "lab-stack-traces"))]
        assert_eq!(trace.frame_count(), 1);
    }

    #[test]
    fn test_compact_formatting() {
        // Create a trace with many lines to test compacting
        let long_trace = StackTrace {
            trace: (0..10)
                .map(|i| format!("  {}: function_{}", i, i))
                .collect::<Vec<_>>()
                .join("\n"),
        };

        let compact = long_trace.compact();

        // Should contain ellipsis for truncated traces
        if long_trace.frame_count() > 5 {
            assert!(compact.contains("... ("));
            assert!(compact.contains("more frames)"));
        }
    }

    #[test]
    fn test_filter_frames() {
        let trace = StackTrace {
            trace: "Stack trace:\n  0: my_function\n  1: std::panic\n  2: other_function\n  3: std::thread".to_string(),
        };

        let filtered = trace.filter_frames("std::");
        assert!(filtered.as_str().contains("std::panic"));
        assert!(filtered.as_str().contains("std::thread"));
        assert!(!filtered.as_str().contains("my_function"));
        assert!(!filtered.as_str().contains("other_function"));
    }

    #[test]
    fn test_feature_flag_behavior() {
        let trace = capture_stack_trace();

        #[cfg(feature = "lab-stack-traces")]
        {
            // With feature enabled, should get real stack trace
            assert!(trace.starts_with("Stack trace:"));
            assert!(trace.lines().count() > 1);
        }

        #[cfg(not(feature = "lab-stack-traces"))]
        {
            // With feature disabled, should get the diagnostic string.
            assert_eq!(
                trace,
                "Stack trace capture disabled (enable 'lab-stack-traces' feature)"
            );
        }
    }

    #[test]
    fn test_repeated_capture_preserves_contract() {
        for _ in 0..10 {
            let trace = capture_stack_trace();

            assert!(!trace.is_empty());

            #[cfg(feature = "lab-stack-traces")]
            assert!(trace.starts_with("Stack trace:"));

            #[cfg(not(feature = "lab-stack-traces"))]
            assert_eq!(
                trace,
                "Stack trace capture disabled (enable 'lab-stack-traces' feature)"
            );
        }
    }

    #[test]
    fn test_string_conversion() {
        let trace = StackTrace::capture();
        let as_string: String = trace.clone().into();
        assert_eq!(as_string, trace.as_str());
    }

    #[test]
    fn test_debug_formatting() {
        let trace = StackTrace::capture();
        let debug_str = format!("{:?}", trace);
        assert!(debug_str.contains("StackTrace"));
        assert!(debug_str.contains("trace:"));
    }
