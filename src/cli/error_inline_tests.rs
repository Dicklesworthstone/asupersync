    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::{CliError, ExitCode, errors};
    use serde_json::{Value, json};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn scrub_stack_trace(value: &mut Value) -> u64 {
        let Some(context) = value.get_mut("context").and_then(Value::as_object_mut) else {
            return 0;
        };
        let Some(stack_trace) = context.get_mut("stack_trace") else {
            return 0;
        };
        let Some(stack_trace) = stack_trace.as_str() else {
            return 0;
        };
        let frame_count = stack_trace.lines().count() as u64;
        *context
            .get_mut("stack_trace")
            .expect("stack trace key still exists") =
            Value::String(format!("[STACK_TRACE:{} frames]", frame_count));
        frame_count
    }

    fn scrubbed_error_snapshot(error: &CliError) -> Value {
        let human = error.human_format(false);
        let human_line_count = human.lines().count() as u64;
        let suggestion = error.suggestion.clone();
        let docs_url = error.docs_url.clone();
        let mut machine = serde_json::to_value(error).expect("CliError should serialize");
        let stack_trace_line_count = scrub_stack_trace(&mut machine);

        json!({
            "type": error.error_type,
            "title": error.title,
            "exit_code": error.exit_code,
            "suggestion": suggestion,
            "docs_url": docs_url,
            "human_line_count": human_line_count,
            "human": human,
            "stack_trace_line_count": stack_trace_line_count,
            "machine": machine,
        })
    }

    #[test]
    fn error_serializes_to_json() {
        init_test("error_serializes_to_json");
        let error = CliError::new("test_error", "Test Error")
            .detail("Something went wrong")
            .suggestion("Try again")
            .context("file", "test.rs")
            .exit_code(1);

        let json = serde_json::to_string(&error).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        crate::assert_with_log!(
            parsed["type"] == "test_error",
            "type",
            "test_error",
            parsed["type"].clone()
        );
        crate::assert_with_log!(
            parsed["title"] == "Test Error",
            "title",
            "Test Error",
            parsed["title"].clone()
        );
        crate::assert_with_log!(
            parsed["detail"] == "Something went wrong",
            "detail",
            "Something went wrong",
            parsed["detail"].clone()
        );
        crate::assert_with_log!(
            parsed["suggestion"] == "Try again",
            "suggestion",
            "Try again",
            parsed["suggestion"].clone()
        );
        crate::assert_with_log!(
            parsed["context"]["file"] == "test.rs",
            "context file",
            "test.rs",
            parsed["context"]["file"].clone()
        );
        crate::assert_with_log!(
            parsed["exit_code"] == 1,
            "exit_code",
            1,
            parsed["exit_code"].clone()
        );
        crate::test_complete!("error_serializes_to_json");
    }

    #[test]
    fn error_human_format_includes_all_parts() {
        init_test("error_human_format_includes_all_parts");
        let error = CliError::new("test_error", "Test Error")
            .detail("Details here")
            .suggestion("Try this");

        let human = error.human_format(false);

        let has_title = human.contains("Error: Test Error");
        crate::assert_with_log!(has_title, "title", true, has_title);
        let has_details = human.contains("Details here");
        crate::assert_with_log!(has_details, "details", true, has_details);
        let has_suggestion = human.contains("Suggestion: Try this");
        crate::assert_with_log!(has_suggestion, "suggestion", true, has_suggestion);
        crate::test_complete!("error_human_format_includes_all_parts");
    }

    #[test]
    fn error_human_format_no_ansi_when_disabled() {
        init_test("error_human_format_no_ansi_when_disabled");
        let error = CliError::new("test", "Test");
        let human = error.human_format(false);

        let has_ansi = human.contains("\x1b[");
        crate::assert_with_log!(!has_ansi, "no ansi", false, has_ansi);
        crate::test_complete!("error_human_format_no_ansi_when_disabled");
    }

    #[test]
    fn error_human_format_has_ansi_when_enabled() {
        init_test("error_human_format_has_ansi_when_enabled");
        let error = CliError::new("test", "Test");
        let human = error.human_format(true);

        let has_ansi = human.contains("\x1b[");
        crate::assert_with_log!(has_ansi, "has ansi", true, has_ansi);
        crate::test_complete!("error_human_format_has_ansi_when_enabled");
    }

    #[test]
    fn error_implements_display() {
        init_test("error_implements_display");
        let error = CliError::new("test_type", "Test Title");
        let display = format!("{error}");

        let has_type = display.contains("test_type");
        crate::assert_with_log!(has_type, "type", true, has_type);
        let has_title = display.contains("Test Title");
        crate::assert_with_log!(has_title, "title", true, has_title);
        crate::test_complete!("error_implements_display");
    }

    #[test]
    fn standard_errors_have_correct_exit_codes() {
        init_test("standard_errors_have_correct_exit_codes");
        let invalid = errors::invalid_argument("foo", "bad").exit_code;
        crate::assert_with_log!(
            invalid == ExitCode::USER_ERROR,
            "invalid_argument",
            ExitCode::USER_ERROR,
            invalid
        );
        let not_found = errors::file_not_found("/path").exit_code;
        crate::assert_with_log!(
            not_found == ExitCode::USER_ERROR,
            "file_not_found",
            ExitCode::USER_ERROR,
            not_found
        );
        let permission = errors::permission_denied("/path").exit_code;
        crate::assert_with_log!(
            permission == ExitCode::USER_ERROR,
            "permission_denied",
            ExitCode::USER_ERROR,
            permission
        );
        let cancelled = errors::cancelled().exit_code;
        crate::assert_with_log!(
            cancelled == ExitCode::CANCELLED,
            "cancelled",
            ExitCode::CANCELLED,
            cancelled
        );
        let internal = errors::internal("bug").exit_code;
        crate::assert_with_log!(
            internal == ExitCode::INTERNAL_ERROR,
            "internal",
            ExitCode::INTERNAL_ERROR,
            internal
        );
        let test_failure = errors::test_failure("test", "reason").exit_code;
        crate::assert_with_log!(
            test_failure == ExitCode::TEST_FAILURE,
            "test_failure",
            ExitCode::TEST_FAILURE,
            test_failure
        );
        let oracle = errors::oracle_violation("oracle", "details").exit_code;
        crate::assert_with_log!(
            oracle == ExitCode::ORACLE_VIOLATION,
            "oracle_violation",
            ExitCode::ORACLE_VIOLATION,
            oracle
        );
        crate::test_complete!("standard_errors_have_correct_exit_codes");
    }

    #[test]
    fn error_context_accepts_various_types() {
        init_test("error_context_accepts_various_types");
        let error = CliError::new("test", "Test")
            .context("string", "value")
            .context("number", 42)
            .context("bool", true)
            .context("array", vec![1, 2, 3]);

        let len = error.context.len();
        crate::assert_with_log!(len == 4, "context len", 4, len);
        crate::assert_with_log!(
            error.context["string"] == "value",
            "string",
            "value",
            error.context["string"].clone()
        );
        crate::assert_with_log!(
            error.context["number"] == 42,
            "number",
            42,
            error.context["number"].clone()
        );
        crate::assert_with_log!(
            error.context["bool"] == true,
            "bool",
            true,
            error.context["bool"].clone()
        );
        crate::test_complete!("error_context_accepts_various_types");
    }

    #[test]
    fn error_deserializes_from_json() {
        init_test("error_deserializes_from_json");
        let json = r#"{"type":"test","title":"Test","exit_code":1}"#;
        let error: CliError = serde_json::from_str(json).unwrap();

        crate::assert_with_log!(error.error_type == "test", "type", "test", error.error_type);
        crate::assert_with_log!(error.title == "Test", "title", "Test", error.title);
        crate::assert_with_log!(error.exit_code == 1, "exit_code", 1, error.exit_code);
        crate::test_complete!("error_deserializes_from_json");
    }

    #[test]
    fn exit_code_builder_sanitizes_invalid_values() {
        init_test("exit_code_builder_sanitizes_invalid_values");
        let reserved = CliError::new("test", "Test").exit_code(130);
        crate::assert_with_log!(
            reserved.exit_code == ExitCode::INTERNAL_ERROR,
            "130 sanitized",
            ExitCode::INTERNAL_ERROR,
            reserved.exit_code
        );
        let negative = CliError::new("test", "Test").exit_code(-5);
        crate::assert_with_log!(
            negative.exit_code == ExitCode::INTERNAL_ERROR,
            "-5 sanitized",
            ExitCode::INTERNAL_ERROR,
            negative.exit_code
        );
        crate::test_complete!("exit_code_builder_sanitizes_invalid_values");
    }

    #[test]
    fn structured_error_diagnostics_scrubbed_snapshot() {
        init_test("structured_error_diagnostics_scrubbed_snapshot");

        let user_error = errors::invalid_argument("profile", "expected one of: dev, staging, prod")
            .suggestion("Pass --profile with a supported value")
            .docs("https://docs.asupersync.dev/cli#profile");

        let system_error = errors::internal(
            "Scheduler certificate writer panicked while flushing diagnostics",
        )
        .context("component", "runtime::scheduler")
        .context("panic_id", "panic-000042")
        .context(
            "stack_trace",
            "src/runtime/scheduler/three_lane.rs:412\nsrc/runtime/worker.rs:91\nsrc/cli/main.rs:14",
        );

        let panic_recovery = CliError::new("panic_recovery", "Recovered from panic")
            .detail("The CLI captured a panic, preserved the evidence bundle, and returned a safe fallback response.")
            .suggestion("Inspect the evidence bundle and rerun with --replay-seed 424242 to reproduce the failure deterministically.")
            .docs("https://docs.asupersync.dev/cli#panic-recovery")
            .context("recovery_mode", "deterministic-replay")
            .context("evidence_bundle", "artifacts/replay/panic-000042.json")
            .context(
                "stack_trace",
                "src/cli/main.rs:88\nsrc/cli/run.rs:144\nsrc/runtime/scheduler/three_lane.rs:3110\nsrc/runtime/task.rs:287",
            )
            .exit_code(ExitCode::INTERNAL_ERROR);

        insta::assert_json_snapshot!(
            "structured_error_diagnostics_scrubbed",
            json!({
                "user_error": scrubbed_error_snapshot(&user_error),
                "system_error": scrubbed_error_snapshot(&system_error),
                "panic_recovery": scrubbed_error_snapshot(&panic_recovery),
            })
        );
    }
