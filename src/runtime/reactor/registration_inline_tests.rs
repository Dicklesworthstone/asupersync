    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Test reactor atomics are assertion counters/flags and publish no side data.
    const TEST_REACTOR_ORDERING: Ordering = Ordering::Relaxed;

    /// Test reactor for testing Registration RAII behavior.
    struct TestReactor {
        deregistered: AtomicBool,
        deregister_count: AtomicUsize,
        last_token: Mutex<Option<Token>>,
        last_interest: Mutex<Option<Interest>>,
    }

    impl TestReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregistered: AtomicBool::new(false),
                deregister_count: AtomicUsize::new(0),
                last_token: Mutex::new(None),
                last_interest: Mutex::new(None),
            })
        }

        fn was_deregistered(&self) -> bool {
            self.deregistered.load(TEST_REACTOR_ORDERING)
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(TEST_REACTOR_ORDERING)
        }
    }

    impl ReactorHandle for TestReactor {
        fn deregister_by_token(&self, token: Token) -> io::Result<()> {
            self.deregistered.store(true, TEST_REACTOR_ORDERING);
            self.deregister_count.fetch_add(1, TEST_REACTOR_ORDERING);
            *self.last_token.lock() = Some(token);
            Ok(())
        }

        fn modify_interest(&self, token: Token, interest: Interest) -> io::Result<()> {
            *self.last_token.lock() = Some(token);
            *self.last_interest.lock() = Some(interest);
            Ok(())
        }
    }

    struct FlakyReactor {
        deregister_count: AtomicUsize,
    }

    impl FlakyReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(TEST_REACTOR_ORDERING)
        }
    }

    impl ReactorHandle for FlakyReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            let call = self.deregister_count.fetch_add(1, TEST_REACTOR_ORDERING);
            if call == 0 {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    struct AlwaysFailReactor {
        deregister_count: AtomicUsize,
    }

    impl AlwaysFailReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(TEST_REACTOR_ORDERING)
        }
    }

    impl ReactorHandle for AlwaysFailReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            self.deregister_count.fetch_add(1, TEST_REACTOR_ORDERING);
            Err(io::Error::other("persistent failure"))
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    struct ThirdTryReactor {
        deregistered: AtomicBool,
        deregister_count: AtomicUsize,
    }

    impl ThirdTryReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregistered: AtomicBool::new(false),
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn was_deregistered(&self) -> bool {
            self.deregistered.load(TEST_REACTOR_ORDERING)
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(TEST_REACTOR_ORDERING)
        }
    }

    impl ReactorHandle for ThirdTryReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            let call = self.deregister_count.fetch_add(1, TEST_REACTOR_ORDERING);
            if call < 2 {
                Err(io::Error::other("injected failure"))
            } else {
                self.deregistered.store(true, TEST_REACTOR_ORDERING);
                Ok(())
            }
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    struct PanickingReactor {
        deregister_count: AtomicUsize,
    }

    impl PanickingReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deregister_count: AtomicUsize::new(0),
            })
        }

        fn deregister_count(&self) -> usize {
            self.deregister_count.load(TEST_REACTOR_ORDERING)
        }
    }

    impl ReactorHandle for PanickingReactor {
        fn deregister_by_token(&self, _token: Token) -> io::Result<()> {
            self.deregister_count.fetch_add(1, TEST_REACTOR_ORDERING);
            unreachable!("injected deregister panic")
        }

        fn modify_interest(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Ok(())
        }
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn drop_deregisters() {
        init_test("drop_deregisters");
        let reactor = TestReactor::new();
        let token = Token::new(42);

        {
            let _reg = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
            let was = reactor.was_deregistered();
            crate::assert_with_log!(!was, "not deregistered in scope", false, was);
        }

        let was = reactor.was_deregistered();
        crate::assert_with_log!(was, "deregistered on drop", true, was);
        let last_token = *reactor.last_token.lock();
        crate::assert_with_log!(
            last_token == Some(token),
            "last token recorded",
            Some(token),
            last_token
        );
        crate::test_complete!("drop_deregisters");
    }

    #[test]
    fn set_interest_updates_reactor() {
        init_test("set_interest_updates_reactor");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        crate::assert_with_log!(
            reg.interest() == Interest::READABLE,
            "initial interest",
            Interest::READABLE,
            reg.interest()
        );

        reg.set_interest(Interest::WRITABLE).unwrap();

        crate::assert_with_log!(
            reg.interest() == Interest::WRITABLE,
            "interest updated",
            Interest::WRITABLE,
            reg.interest()
        );
        let last_interest = *reactor.last_interest.lock();
        crate::assert_with_log!(
            last_interest == Some(Interest::WRITABLE),
            "reactor saw interest update",
            Some(Interest::WRITABLE),
            last_interest
        );
        crate::test_complete!("set_interest_updates_reactor");
    }

    #[test]
    fn handles_reactor_dropped() {
        init_test("handles_reactor_dropped");
        let token = Token::new(1);

        let reg = {
            let reactor = TestReactor::new();
            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
            // reactor is dropped here
        };

        // Registration should not panic when reactor is gone
        let active = reg.is_active();
        crate::assert_with_log!(!active, "inactive after reactor drop", false, active);

        // set_interest should fail gracefully
        let result = reg.set_interest(Interest::WRITABLE);
        crate::assert_with_log!(result.is_err(), "set_interest fails", true, result.is_err());

        // drop should not panic
        drop(reg);
        crate::test_complete!("handles_reactor_dropped");
    }

    #[test]
    fn is_active() {
        init_test("is_active");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let active = reg.is_active();
        crate::assert_with_log!(active, "active before drop", true, active);

        drop(reactor);

        let active_after = reg.is_active();
        crate::assert_with_log!(!active_after, "inactive after drop", false, active_after);
        crate::test_complete!("is_active");
    }

    #[test]
    fn explicit_deregister() {
        init_test("explicit_deregister");
        let reactor = TestReactor::new();
        let token = Token::new(1);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(result.is_ok(), "deregister ok", true, result.is_ok());
        let was = reactor.was_deregistered();
        crate::assert_with_log!(was, "reactor deregistered", true, was);
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 1, "deregister count", 1usize, count);
        // Note: reg is consumed, so drop won't run again
        crate::test_complete!("explicit_deregister");
    }

    #[test]
    fn explicit_deregister_when_reactor_gone() {
        init_test("explicit_deregister_when_reactor_gone");
        let token = Token::new(1);

        let reg = {
            let reactor = TestReactor::new();
            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
        };

        // Should succeed even though reactor is gone
        let result = reg.deregister();
        crate::assert_with_log!(result.is_ok(), "deregister ok", true, result.is_ok());
        crate::test_complete!("explicit_deregister_when_reactor_gone");
    }

    #[test]
    fn explicit_deregister_transient_error_recovers_and_returns_ok() {
        init_test("explicit_deregister_transient_error_recovers_and_returns_ok");
        let reactor = FlakyReactor::new();
        let token = Token::new(7);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_ok(),
            "deregister succeeds after retry",
            true,
            result.is_ok()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 2, "best-effort cleanup attempted", 2usize, count);
        crate::test_complete!("explicit_deregister_transient_error_recovers_and_returns_ok");
    }

    #[test]
    fn explicit_deregister_persistent_error_returns_err_after_retry() {
        init_test("explicit_deregister_persistent_error_returns_err_after_retry");
        let reactor = AlwaysFailReactor::new();
        let token = Token::new(8);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_err(),
            "persistent failures surface an error",
            true,
            result.is_err()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(
            count == 4,
            "explicit error path leaves Drop armed for final cleanup pass",
            4usize,
            count
        );
        crate::test_complete!("explicit_deregister_persistent_error_returns_err_after_retry");
    }

    #[test]
    fn explicit_deregister_error_still_allows_drop_cleanup_success() {
        init_test("explicit_deregister_error_still_allows_drop_cleanup_success");
        let reactor = ThirdTryReactor::new();
        let token = Token::new(14);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_err(),
            "explicit deregister still reports the persistent two-attempt failure",
            true,
            result.is_err()
        );
        let was = reactor.was_deregistered();
        crate::assert_with_log!(
            was,
            "drop cleanup gets a final successful deregister attempt",
            true,
            was
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(
            count == 3,
            "two explicit attempts plus one drop cleanup attempt",
            3usize,
            count
        );
        crate::test_complete!("explicit_deregister_error_still_allows_drop_cleanup_success");
    }

    #[test]
    fn drop_retries_after_transient_deregister_error() {
        init_test("drop_retries_after_transient_deregister_error");
        let reactor = FlakyReactor::new();
        let token = Token::new(11);

        {
            let _reg = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
        }

        let count = reactor.deregister_count();
        crate::assert_with_log!(
            count == 2,
            "drop retries deregister once after transient error",
            2usize,
            count
        );
        crate::test_complete!("drop_retries_after_transient_deregister_error");
    }

    #[test]
    fn drop_swallows_panicking_reactor_deregister() {
        init_test("drop_swallows_panicking_reactor_deregister");
        let reactor = PanickingReactor::new();
        let token = Token::new(12);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(reg)));
        crate::assert_with_log!(
            dropped.is_ok(),
            "drop must not panic even if deregister panics",
            true,
            dropped.is_ok()
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 1, "single deregister attempt", 1usize, count);
        crate::test_complete!("drop_swallows_panicking_reactor_deregister");
    }

    #[test]
    fn explicit_deregister_panicking_reactor_returns_error() {
        init_test("explicit_deregister_panicking_reactor_returns_error");
        let reactor = PanickingReactor::new();
        let token = Token::new(13);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = reg.deregister();
        crate::assert_with_log!(
            result.is_err(),
            "explicit deregister surfaces panic as error",
            true,
            result.is_err()
        );
        let kind = result
            .as_ref()
            .err()
            .map_or(io::ErrorKind::Other, io::Error::kind);
        crate::assert_with_log!(
            kind == io::ErrorKind::Other,
            "panic maps to io::ErrorKind::Other",
            io::ErrorKind::Other,
            kind
        );
        let count = reactor.deregister_count();
        crate::assert_with_log!(
            count == 2,
            "drop retries cleanup once after explicit panic-path error",
            2usize,
            count
        );
        crate::test_complete!("explicit_deregister_panicking_reactor_returns_error");
    }

    #[test]
    fn token_accessor() {
        init_test("token_accessor");
        let reactor = TestReactor::new();
        let token = Token::new(999);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        crate::assert_with_log!(reg.token() == token, "token accessor", token, reg.token());
        crate::test_complete!("token_accessor");
    }

    #[test]
    fn debug_impl() {
        init_test("debug_impl");
        let reactor = TestReactor::new();
        let token = Token::new(42);

        let reg = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let debug_text = format!("{reg:?}");
        crate::assert_with_log!(
            debug_text.contains("Registration"),
            "debug includes type",
            true,
            debug_text.contains("Registration")
        );
        crate::assert_with_log!(
            debug_text.contains("42"),
            "debug includes token",
            true,
            debug_text.contains("42")
        );
        crate::test_complete!("debug_impl");
    }

    #[test]
    fn multiple_registrations() {
        init_test("multiple_registrations");
        let reactor = TestReactor::new();

        {
            let _reg1 = Registration::new(
                Token::new(1),
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
            let _reg2 = Registration::new(
                Token::new(2),
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::WRITABLE,
            );

            let count = reactor.deregister_count();
            crate::assert_with_log!(count == 0, "no deregisters yet", 0usize, count);
        }

        // Both should have been deregistered
        let count = reactor.deregister_count();
        crate::assert_with_log!(count == 2, "two deregisters", 2usize, count);
        crate::test_complete!("multiple_registrations");
    }
