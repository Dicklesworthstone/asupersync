//! Feature matrix tests for stack trace functionality.
//!
//! This file contains tests that verify behavior with different feature flag
//! combinations to ensure stack traces work correctly both when enabled
//! and disabled.

use asupersync::util::stack_trace::{StackTrace, capture_stack_trace};

#[cfg(test)]
mod feature_matrix_tests {
    use super::*;

    #[test]
    fn test_feature_flag_matrix() {
        // This test verifies behavior under different feature flag states
        // The actual behavior depends on which features are enabled at compile time

        let trace = capture_stack_trace();

        // Verify basic contract is always satisfied
        assert!(!trace.is_empty(), "Stack trace should never be empty");

        // Test StackTrace wrapper works regardless of feature state
        let wrapped = StackTrace::capture();
        assert!(!wrapped.as_str().is_empty());
        assert!(wrapped.frame_count() > 0);

        // Test all formatting methods work
        let compact = wrapped.compact();
        assert!(!compact.is_empty());

        let as_string: String = wrapped.clone().into();
        assert_eq!(as_string, wrapped.as_str());

        let displayed = format!("{}", wrapped);
        assert_eq!(displayed, wrapped.as_str());
    }

    #[test]
    fn test_consistency_across_calls() {
        // Multiple calls should have consistent behavior
        let traces: Vec<String> = (0..5).map(|_| capture_stack_trace()).collect();

        // All traces should have the same "type" of content
        let first_is_enabled = traces[0].starts_with("Stack trace:");
        for trace in &traces {
            let is_enabled = trace.starts_with("Stack trace:");
            assert_eq!(
                is_enabled, first_is_enabled,
                "Stack trace enabled/disabled state should be consistent across calls"
            );
        }

        // All traces should be non-empty
        for trace in &traces {
            assert!(!trace.is_empty());
        }
    }

    #[test]
    fn test_error_resistance() {
        // Test that stack trace capture doesn't panic or fail unexpectedly
        // even in edge cases

        // Should work from different contexts
        let trace1 = capture_from_closure();
        let trace2 = capture_from_method();
        let trace3 = StackTrace::capture();

        assert!(!trace1.is_empty());
        assert!(!trace2.is_empty());
        assert!(!trace3.as_str().is_empty());

        // All should have consistent behavior
        let all_start_with_header = [&trace1, &trace2, trace3.as_str()]
            .iter()
            .all(|t| t.starts_with("Stack trace:"));

        let all_are_disabled = [&trace1, &trace2, trace3.as_str()]
            .iter()
            .all(|t| t.contains("disabled"));

        // Should be either all enabled or all disabled
        assert!(
            all_start_with_header || all_are_disabled,
            "Stack trace state should be consistent across different capture contexts"
        );
    }

    fn capture_from_closure() -> String {
        let closure = || capture_stack_trace();
        closure()
    }

    fn capture_from_method() -> String {
        static_capture_method()
    }

    fn static_capture_method() -> String {
        capture_stack_trace()
    }
}

#[cfg(test)]
mod build_verification_tests {
    use super::*;

    #[test]
    fn test_feature_enabled_build() {
        // This test verifies expected behavior when lab-stack-traces is enabled
        // Note: This will only pass when the feature is actually enabled

        #[cfg(feature = "lab-stack-traces")]
        {
            let trace = capture_stack_trace();
            assert!(
                trace.starts_with("Stack trace:"),
                "With lab-stack-traces enabled, should get real stack trace"
            );
            assert!(
                trace.lines().count() > 1,
                "Real stack trace should have multiple lines"
            );

            let wrapped = StackTrace::capture();
            assert!(
                wrapped.frame_count() > 1,
                "Real stack trace should have multiple frames"
            );
        }

        #[cfg(not(feature = "lab-stack-traces"))]
        {
            // This branch runs when feature is disabled
            let trace = capture_stack_trace();
            assert_eq!(
                trace, "Stack trace capture disabled (enable 'lab-stack-traces' feature)",
                "With lab-stack-traces disabled, should get disabled message"
            );

            let wrapped = StackTrace::capture();
            assert_eq!(
                wrapped.frame_count(),
                1,
                "Disabled stack trace should report 1 frame (the disabled message)"
            );
        }
    }

    #[test]
    fn test_optional_dependencies_available() {
        // Verify that when the feature is enabled, the dependencies are available
        // This is a compile-time check mainly

        #[cfg(feature = "lab-stack-traces")]
        {
            // The fact that this compiles means backtrace and rustc-demangle are available
            let bt = backtrace::Backtrace::new();
            assert!(
                !bt.frames().is_empty(),
                "captured backtrace should include the current stack"
            );

            let mangled = "_ZN4test4funcE";
            let _ = rustc_demangle::try_demangle(mangled); // Should not panic
        }
    }

    #[test]
    fn test_disabled_capture_contract_is_stable() {
        #[cfg(not(feature = "lab-stack-traces"))]
        {
            let traces: Vec<String> = (0..10).map(|_| capture_stack_trace()).collect();

            assert!(
                traces.iter().all(|trace| trace
                    == "Stack trace capture disabled (enable 'lab-stack-traces' feature)")
            );
        }
    }

    #[test]
    fn test_enabled_capture_contract_is_stable() {
        #[cfg(feature = "lab-stack-traces")]
        {
            let traces: Vec<String> = (0..3).map(|_| capture_stack_trace()).collect();

            assert!(traces.iter().all(|trace| trace.starts_with("Stack trace:")));
            assert!(traces.iter().all(|trace| trace.lines().count() > 1));
        }
    }
}
