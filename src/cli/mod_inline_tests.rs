    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde::Serialize;
    use std::io::Cursor;

    #[derive(Serialize)]
    struct TestData {
        value: i32,
    }

    impl Outputtable for TestData {
        fn human_format(&self) -> String {
            format!("Value: {}", self.value)
        }
    }

    struct TestCmd;

    impl Completable for TestCmd {
        fn command_name(&self) -> &'static str {
            "test"
        }

        fn subcommands(&self) -> Vec<CompletionItem> {
            vec![CompletionItem::new("run")]
        }

        fn global_options(&self) -> Vec<CompletionItem> {
            vec![CompletionItem::new("--help")]
        }

        fn subcommand_options(&self, subcommand: &str) -> Vec<CompletionItem> {
            if subcommand == "run" {
                vec![CompletionItem::new("--dry-run")]
            } else {
                vec![]
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn prelude_exports_work() {
        init_test("prelude_exports_work");
        // Verify prelude exports compile
        let _ = ExitCode::SUCCESS;
        let _ = OutputFormat::Human;
        let _ = ColorChoice::Auto;
        crate::test_complete!("prelude_exports_work");
    }

    #[test]
    fn error_integration() {
        init_test("error_integration");
        // Test that error module integrates with exit codes
        let error = errors::invalid_argument("test", "invalid");
        crate::assert_with_log!(
            error.exit_code == ExitCode::USER_ERROR,
            "exit_code",
            ExitCode::USER_ERROR,
            error.exit_code
        );
        crate::test_complete!("error_integration");
    }

    #[test]
    fn output_integration() {
        init_test("output_integration");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);
        let data = TestData { value: 42 };
        output.write(&data).unwrap();
        crate::test_complete!("output_integration");
    }

    #[test]
    fn signal_integration() {
        init_test("signal_integration");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        let cancelled = token.is_cancelled();
        crate::assert_with_log!(!cancelled, "token not cancelled", false, cancelled);
        let _ = handler.record_signal();
        let cancelled = token.is_cancelled();
        crate::assert_with_log!(cancelled, "token cancelled", true, cancelled);
        crate::test_complete!("signal_integration");
    }

    #[test]
    fn completion_integration() {
        init_test("completion_integration");
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCmd, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let contains = output.contains("test");
        crate::assert_with_log!(contains, "contains test", true, contains);
        let has_subcommand_option = output.contains("--dry-run");
        crate::assert_with_log!(
            has_subcommand_option,
            "contains subcommand option",
            true,
            has_subcommand_option
        );
        crate::test_complete!("completion_integration");
    }
