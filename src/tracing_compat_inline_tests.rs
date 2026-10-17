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
    #[cfg(feature = "proc-macros")]
    use futures_lite::future::block_on;

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[cfg(feature = "proc-macros")]
    #[super::instrument]
    fn instrumented_sync_add(task_id: u32, label: &str) -> usize {
        usize::try_from(task_id).expect("task_id fits usize") + label.len()
    }

    #[cfg(feature = "proc-macros")]
    struct InstrumentedWorker;

    #[cfg(feature = "proc-macros")]
    impl InstrumentedWorker {
        #[super::instrument(level = "debug", skip(self))]
        fn tick(&self, value: usize) -> usize {
            value + 1
        }
    }

    #[cfg(feature = "proc-macros")]
    #[super::instrument(name = "instrumented_async_len", level = "trace", skip(secret))]
    async fn instrumented_async_len(secret: String, visible: usize) -> usize {
        visible + secret.len()
    }

    #[test]
    fn test_noop_macros_compile() {
        init_test("test_noop_macros_compile");
        // These should all compile and do nothing
        trace!("trace message");
        debug!("debug message");
        info!("info message");
        warn!("warn message");
        error!("error message");

        trace!(field = "value", "trace with field");
        debug!(count = 42, "debug with field");
        info!(name = "test", "info with field");
        crate::test_complete!("test_noop_macros_compile");
    }

    #[test]
    fn test_noop_span_compile() {
        init_test("test_noop_span_compile");
        let span = span!(Level::INFO, "test_span");
        let _guard = span.enter();

        let span2 = info_span!("info_span");
        let _entered = span2.entered();

        let span3 = debug_span!("debug_span", task_id = 42);
        span3.record("field", "value");
        crate::test_complete!("test_noop_span_compile");
    }

    #[test]
    fn test_noop_level_constants() {
        init_test("test_noop_level_constants");
        // Verify that Level constants are accessible — tested further in
        // `level_equality_and_ordering`.
        crate::test_complete!("test_noop_level_constants");
    }

    #[test]
    fn test_noop_span_methods() {
        init_test("test_noop_span_methods");
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span = NoopSpan;
            let disabled = span.is_disabled();
            crate::assert_with_log!(disabled, "noop span should be disabled", true, disabled);

            let current = NoopSpan::current();
            let none = NoopSpan::none();
            let _ = current.or_current();
            none.follows_from(&span);
        }
        crate::test_complete!("test_noop_span_methods");
    }

    #[test]
    fn noop_guard_debug() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let guard = NoopGuard;
            let dbg = format!("{guard:?}");
            assert!(dbg.contains("NoopGuard"), "{dbg}");
        }
    }

    #[test]
    fn noop_span_debug_clone_copy() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span = NoopSpan;
            let dbg = format!("{span:?}");
            assert!(dbg.contains("NoopSpan"), "{dbg}");

            let copied = span;
            let cloned = span;
            assert!(copied.is_disabled());
            assert!(cloned.is_disabled());
        }
    }

    #[test]
    fn level_equality_and_ordering() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            // All noop levels are the same unit struct
            assert_eq!(Level::TRACE, Level::DEBUG);
            assert_eq!(Level::INFO, Level::WARN);
            assert_eq!(Level::WARN, Level::ERROR);

            // Ordering is consistent
            assert!(Level::TRACE <= Level::ERROR);

            // Debug
            let dbg = format!("{:?}", Level::INFO);
            assert!(dbg.contains("Level"), "{dbg}");

            // Clone/Copy
            let l = Level::INFO;
            let copied = l;
            let cloned = l;
            assert_eq!(copied, cloned);
        }
    }

    #[test]
    fn span_type_alias_works() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span: Span = NoopSpan::current();
            let _guard = span.enter();
        }
    }

    #[test]
    fn all_span_macros_compile() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let _ = trace_span!("t");
            let _ = debug_span!("d");
            let _ = info_span!("i");
            let _ = warn_span!("w");
            let _ = error_span!("e");
        }
    }

    #[test]
    fn instrument_trait_noop() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let fut = async { 42 };
            let instrumented = fut.instrument(NoopSpan);
            // Can also use in_current_span
            drop(async { 1 }.in_current_span());
            drop(instrumented);
        }
    }

    #[cfg(feature = "proc-macros")]
    #[test]
    fn instrument_attribute_wraps_sync_functions() {
        init_test("instrument_attribute_wraps_sync_functions");
        let value = instrumented_sync_add(7, "abc");
        crate::assert_with_log!(value == 10, "sync result", 10usize, value);
        crate::test_complete!("instrument_attribute_wraps_sync_functions");
    }

    #[cfg(feature = "proc-macros")]
    #[test]
    fn instrument_attribute_wraps_methods() {
        init_test("instrument_attribute_wraps_methods");
        let worker = InstrumentedWorker;
        let value = worker.tick(9);
        crate::assert_with_log!(value == 10, "method result", 10usize, value);
        crate::test_complete!("instrument_attribute_wraps_methods");
    }

    #[cfg(feature = "proc-macros")]
    #[test]
    fn instrument_attribute_wraps_async_functions() {
        init_test("instrument_attribute_wraps_async_functions");
        let value = block_on(instrumented_async_len("secret".to_string(), 4));
        crate::assert_with_log!(value == 10, "async result", 10usize, value);
        crate::test_complete!("instrument_attribute_wraps_async_functions");
    }
