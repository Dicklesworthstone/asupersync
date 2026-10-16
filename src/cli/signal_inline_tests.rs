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
    fn signal_names() {
        init_test("signal_names");
        let interrupt = Signal::Interrupt.name();
        crate::assert_with_log!(interrupt == "SIGINT", "SIGINT", "SIGINT", interrupt);
        let terminate = Signal::Terminate.name();
        crate::assert_with_log!(terminate == "SIGTERM", "SIGTERM", "SIGTERM", terminate);
        let hangup = Signal::Hangup.name();
        crate::assert_with_log!(hangup == "SIGHUP", "SIGHUP", "SIGHUP", hangup);
        crate::test_complete!("signal_names");
    }

    #[test]
    fn signal_numbers() {
        init_test("signal_numbers");
        let interrupt = Signal::Interrupt.number();
        crate::assert_with_log!(interrupt == 2, "SIGINT number", 2, interrupt);
        let terminate = Signal::Terminate.number();
        crate::assert_with_log!(terminate == 15, "SIGTERM number", 15, terminate);
        let hangup = Signal::Hangup.number();
        crate::assert_with_log!(hangup == 1, "SIGHUP number", 1, hangup);
        crate::test_complete!("signal_numbers");
    }

    #[test]
    fn signal_handler_initial_state() {
        init_test("signal_handler_initial_state");
        let handler = SignalHandler::new();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(!cancelled, "not cancelled", false, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 0, "signal_count", 0, count);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(!force_quit, "no force quit", false, force_quit);
        crate::test_complete!("signal_handler_initial_state");
    }

    #[test]
    fn signal_handler_records_signals() {
        init_test("signal_handler_records_signals");
        let handler = SignalHandler::new();

        let first = handler.record_signal();
        crate::assert_with_log!(!first, "first record", false, first);
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 1, "signal_count", 1, count);

        let second = handler.record_signal();
        crate::assert_with_log!(!second, "second record", false, second);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 2, "signal_count", 2, count);

        // Third signal triggers force quit (default threshold is 3)
        let third = handler.record_signal();
        crate::assert_with_log!(third, "third triggers force quit", true, third);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(force_quit, "force quit", true, force_quit);
        crate::test_complete!("signal_handler_records_signals");
    }

    #[test]
    fn signal_handler_custom_threshold() {
        init_test("signal_handler_custom_threshold");
        let handler = SignalHandler::new().with_force_quit_threshold(2);

        let first = handler.record_signal();
        crate::assert_with_log!(!first, "first record", false, first);
        let second = handler.record_signal(); // Second signal triggers force quit
        crate::assert_with_log!(second, "second triggers force quit", true, second);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(force_quit, "force quit", true, force_quit);
        crate::test_complete!("signal_handler_custom_threshold");
    }

    #[test]
    fn signal_handler_reset() {
        init_test("signal_handler_reset");
        let handler = SignalHandler::new();

        let _ = handler.record_signal();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);

        handler.reset();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(!cancelled, "not cancelled", false, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 0, "signal_count", 0, count);
        crate::test_complete!("signal_handler_reset");
    }

    #[test]
    fn cancellation_token_shares_state() {
        init_test("cancellation_token_shares_state");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        let cancelled = token.is_cancelled();
        crate::assert_with_log!(!cancelled, "token not cancelled", false, cancelled);

        let _ = handler.record_signal();
        let cancelled = token.is_cancelled();
        crate::assert_with_log!(cancelled, "token cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_shares_state");
    }

    #[test]
    fn cancellation_token_can_cancel() {
        init_test("cancellation_token_can_cancel");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        token.cancel();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "handler cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_can_cancel");
    }

    #[test]
    fn cancellation_token_cloneable() {
        init_test("cancellation_token_cloneable");
        let handler = SignalHandler::new();
        let token1 = handler.cancellation_token();
        let token2 = token1.clone();

        token1.cancel();
        let cancelled = token2.is_cancelled();
        crate::assert_with_log!(cancelled, "token2 cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_cloneable");
    }

    #[test]
    fn global_signal_state() {
        init_test("global_signal_state");
        reset_global_signal_state();

        let received = signal_received();
        crate::assert_with_log!(!received, "no signal", false, received);
        let count = global_signal_count();
        crate::assert_with_log!(count == 0, "count 0", 0, count);

        let count = record_global_signal();
        crate::assert_with_log!(count == 1, "record count", 1, count);
        let received = signal_received();
        crate::assert_with_log!(received, "signal received", true, received);
        let count = global_signal_count();
        crate::assert_with_log!(count == 1, "count 1", 1, count);

        reset_global_signal_state();
        let received = signal_received();
        crate::assert_with_log!(!received, "reset cleared", false, received);
        crate::test_complete!("global_signal_state");
    }
