    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn scrub_outcome_serde(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(message) = scrubbed.pointer_mut("/cancelled/Cancelled/message") {
            *message = Value::String("[MESSAGE]".to_string());
        }

        scrubbed
    }

    fn scrub_outcome_json_ids(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(origin_region) = scrubbed.pointer_mut("/Cancelled/origin_region") {
            *origin_region = json!("[REGION_ID]");
        }

        if let Some(origin_task) = scrubbed.pointer_mut("/Cancelled/origin_task") {
            *origin_task = json!("[TASK_ID]");
        }

        scrubbed
    }

    // =========================================================================
    // `?` on Outcome (nightly-outcome-try on a compiler that accepts it)
    // =========================================================================

    #[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
    fn add_one(input: Outcome<i32, &'static str>) -> Outcome<i32, &'static str> {
        let value = input?;
        Outcome::Ok(value + 1)
    }

    #[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
    fn from_result(input: Result<i32, &'static str>) -> Outcome<i32, &'static str> {
        let value = input?;
        Outcome::Ok(value + 1)
    }

    #[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
    #[test]
    fn question_mark_continues_on_ok_and_propagates_every_other_variant_unchanged() {
        assert!(matches!(add_one(Outcome::Ok(1)), Outcome::Ok(2)));
        assert!(matches!(add_one(Outcome::Err("e")), Outcome::Err("e")));
        let reason = CancelReason::user("stop");
        match add_one(Outcome::Cancelled(reason.clone())) {
            Outcome::Cancelled(propagated) => assert_eq!(propagated, reason),
            other => panic!("cancellation must propagate unchanged, got {other:?}"),
        }
        match add_one(Outcome::Panicked(PanicPayload::new("boom"))) {
            Outcome::Panicked(payload) => assert_eq!(payload.message(), "boom"),
            other => panic!("a panic must propagate unchanged, got {other:?}"),
        }
        assert!(matches!(from_result(Ok(1)), Outcome::Ok(2)));
        assert!(matches!(from_result(Err("e")), Outcome::Err("e")));
    }

    // =========================================================================
    // Severity Ordering Tests
    // =========================================================================

    #[test]
    fn severity_ordering() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(ok.severity() < err.severity());
        assert!(err.severity() < cancelled.severity());
        assert!(cancelled.severity() < panicked.severity());
    }

    #[test]
    fn severity_values() {
        let ok: Outcome<(), ()> = Outcome::Ok(());
        let err: Outcome<(), ()> = Outcome::Err(());
        let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<(), ()> = Outcome::Panicked(PanicPayload::new("test"));

        assert_eq!(ok.severity(), Severity::Ok);
        assert_eq!(err.severity(), Severity::Err);
        assert_eq!(cancelled.severity(), Severity::Cancelled);
        assert_eq!(panicked.severity(), Severity::Panicked);
    }

    // =========================================================================
    // Predicate Tests (is_ok, is_err, is_cancelled, is_panicked, is_terminal)
    // =========================================================================

    #[test]
    fn is_ok_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        assert!(ok.is_ok());
        assert!(!err.is_ok());
    }

    #[test]
    fn is_err_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        assert!(!ok.is_err());
        assert!(err.is_err());
    }

    #[test]
    fn is_cancelled_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());

        assert!(!ok.is_cancelled());
        assert!(cancelled.is_cancelled());
    }

    #[test]
    fn is_panicked_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));

        assert!(!ok.is_panicked());
        assert!(panicked.is_panicked());
    }

    #[test]
    fn is_terminal_always_true() {
        // All Outcome variants are terminal states
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(ok.is_terminal());
        assert!(err.is_terminal());
        assert!(cancelled.is_terminal());
        assert!(panicked.is_terminal());
    }

    // =========================================================================
    // Join Operation Tests (Lattice Laws)
    // =========================================================================

    #[test]
    fn join_takes_worse() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        let joined = join_outcomes(ok, err);
        assert!(joined.is_err());
    }

    #[test]
    fn join_ok_with_ok_returns_first() {
        let a: Outcome<i32, &str> = Outcome::Ok(1);
        let b: Outcome<i32, &str> = Outcome::Ok(2);

        // When equal severity, first argument wins
        let result = join_outcomes(a, b);
        assert!(matches!(result, Outcome::Ok(1)));
    }

    #[test]
    fn join_err_with_cancelled_returns_cancelled() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());

        let result = join_outcomes(err, cancelled);
        assert!(result.is_cancelled());
    }

    #[test]
    fn join_panicked_dominates_all() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(join_outcomes(ok, panicked.clone()).is_panicked());
        assert!(join_outcomes(err, panicked.clone()).is_panicked());
        assert!(join_outcomes(cancelled, panicked).is_panicked());
    }

    #[test]
    fn join_cancelled_strengthens_to_worst_reason() {
        let user: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let shutdown: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());

        let left_first = user.clone().join(shutdown.clone());
        let right_first = shutdown.join(user);

        match left_first {
            Outcome::Cancelled(reason) => assert!(reason.is_shutdown()),
            other => panic!("expected cancelled outcome, got {other:?}"),
        }

        match right_first {
            Outcome::Cancelled(reason) => assert!(reason.is_shutdown()),
            other => panic!("expected cancelled outcome, got {other:?}"),
        }
    }

    #[test]
    fn join_outcomes_cancelled_strengthens_to_worst_reason() {
        let user: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("soft"));
        let shutdown: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());

        let joined = join_outcomes(user, shutdown);

        match joined {
            Outcome::Cancelled(reason) => assert!(reason.is_shutdown()),
            other => panic!("expected cancelled outcome, got {other:?}"),
        }
    }

    #[test]
    fn join_cancelled_equal_severity_is_left_biased() {
        use crate::types::CancelKind;
        let left: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("z-left"));
        let right: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::user("a-right"));

        let joined = left.join(right);

        match joined {
            Outcome::Cancelled(reason) => {
                assert!(reason.is_kind(CancelKind::User));
                assert_eq!(reason.message(), Some("z-left"));
            }
            other => panic!("expected cancelled outcome, got {other:?}"),
        }
    }

    #[test]
    fn join_cancelled_equal_rank_kinds_is_left_biased() {
        use crate::types::CancelKind;
        let left: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let right: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::deadline());

        let joined = left.join(right);

        match joined {
            Outcome::Cancelled(reason) => assert!(reason.is_kind(CancelKind::Timeout)),
            other => panic!("expected cancelled outcome, got {other:?}"),
        }
    }

    // =========================================================================
    // Map Operations Tests
    // =========================================================================

    #[test]
    fn map_transforms_ok_value() {
        let ok: Outcome<i32, &str> = Outcome::Ok(21);
        let mapped = ok.map(|x| x * 2);
        assert!(matches!(mapped, Outcome::Ok(42)));
    }

    #[test]
    fn map_preserves_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let mapped = err.map(|x| x * 2);
        assert!(matches!(mapped, Outcome::Err("error")));
    }

    #[test]
    fn map_preserves_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let mapped = cancelled.map(|x| x * 2);
        assert!(mapped.is_cancelled());
    }

    #[test]
    fn map_preserves_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let mapped = panicked.map(|x| x * 2);
        assert!(mapped.is_panicked());
    }

    #[test]
    fn map_err_transforms_err_value() {
        let err: Outcome<i32, &str> = Outcome::Err("short");
        let mapped = err.map_err(str::len);
        assert!(matches!(mapped, Outcome::Err(5)));
    }

    #[test]
    fn map_err_preserves_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let mapped = ok.map_err(str::len);
        assert!(matches!(mapped, Outcome::Ok(42)));
    }

    // =========================================================================
    // Unwrap Operations Tests
    // =========================================================================

    #[test]
    fn unwrap_returns_value_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        assert_eq!(ok.unwrap(), 42);
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on an `Err` value")]
    fn unwrap_panics_on_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let _ = err.unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on a `Cancelled` value")]
    fn unwrap_panics_on_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let _ = cancelled.unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on a `Panicked` value")]
    fn unwrap_panics_on_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let _ = panicked.unwrap();
    }

    #[test]
    fn unwrap_or_returns_value_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        assert_eq!(ok.unwrap_or(0), 42);
    }

    #[test]
    fn unwrap_or_returns_default_on_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        assert_eq!(err.unwrap_or(0), 0);
    }

    #[test]
    fn unwrap_or_returns_default_on_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        assert_eq!(cancelled.unwrap_or(99), 99);
    }

    #[test]
    fn unwrap_or_else_computes_default_lazily() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let mut called = false;
        let result = err.unwrap_or_else(|| {
            called = true;
            42
        });
        assert!(called);
        assert_eq!(result, 42);
    }

    #[test]
    fn unwrap_or_else_doesnt_call_closure_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let result = ok.unwrap_or_else(|| panic!("should not be called"));
        assert_eq!(result, 42);
    }

    #[test]
    fn ok_or_else_collapses_non_ok_variants_to_fallback() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));

        assert_eq!(cancelled.ok_or_else(|| "fallback"), Err("fallback"));
        assert_eq!(panicked.ok_or_else(|| "fallback"), Err("fallback"));
    }

    #[test]
    fn ok_or_else_doesnt_call_closure_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let result = ok.ok_or_else(|| panic!("should not be called"));
        assert_eq!(result, Ok(42));
    }

    // =========================================================================
    // into_result Conversion Tests
    // =========================================================================

    #[test]
    fn into_result_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let result = ok.into_result();
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn into_result_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let result = err.into_result();
        assert!(matches!(result, Err(OutcomeError::Err("error"))));
    }

    #[test]
    fn into_result_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let result = cancelled.into_result();
        assert!(matches!(result, Err(OutcomeError::Cancelled(_))));
    }

    #[test]
    fn into_result_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let result = panicked.into_result();
        assert!(matches!(result, Err(OutcomeError::Panicked(_))));
    }

    // =========================================================================
    // From<Result> Conversion Tests
    // =========================================================================

    #[test]
    fn from_result_ok() {
        let result: Result<i32, &str> = Ok(42);
        let outcome: Outcome<i32, &str> = Outcome::from(result);
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    #[test]
    fn from_result_err() {
        let result: Result<i32, &str> = Err("error");
        let outcome: Outcome<i32, &str> = Outcome::from(result);
        assert!(matches!(outcome, Outcome::Err("error")));
    }

    // =========================================================================
    // Display Implementations Tests
    // =========================================================================

    #[test]
    fn panic_payload_display() {
        let payload = PanicPayload::new("something went wrong");
        let display = format!("{payload}");
        assert_eq!(display, "panic: something went wrong");
    }

    #[test]
    fn panic_payload_message() {
        let payload = PanicPayload::new("test message");
        assert_eq!(payload.message(), "test message");
    }

    #[test]
    fn outcome_error_display_err() {
        let error: OutcomeError<&str> = OutcomeError::Err("application error");
        let display = format!("{error}");
        assert_eq!(display, "application error");
    }

    #[test]
    fn outcome_error_display_cancelled() {
        let error: OutcomeError<&str> = OutcomeError::Cancelled(CancelReason::default());
        let display = format!("{error}");
        assert!(display.contains("cancelled"));
    }

    #[test]
    fn outcome_error_display_cancelled_uses_human_readable_reason() {
        let error: OutcomeError<&str> =
            OutcomeError::Cancelled(CancelReason::timeout().with_message("budget elapsed"));
        let display = format!("{error}");
        assert_eq!(display, "cancelled: timeout: budget elapsed");
        assert!(!display.contains("CancelReason"));
    }

    #[test]
    fn outcome_error_display_panicked() {
        let error: OutcomeError<&str> = OutcomeError::Panicked(PanicPayload::new("oops"));
        let display = format!("{error}");
        assert!(display.contains("panic"));
        assert!(display.contains("oops"));
    }

    #[test]
    fn severity_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let a = Severity::Cancelled;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Cancelled"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&Severity::Ok));
    }

    #[test]
    fn panic_payload_debug_clone_eq() {
        let a = PanicPayload::new("boom");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, PanicPayload::new("other"));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("PanicPayload"));
    }

    #[test]
    fn outcome_serde_snapshot_scrubbed() {
        insta::assert_json_snapshot!(
            "outcome_serde_scrubbed",
            scrub_outcome_serde(json!({
                "ok": Outcome::<u8, &str>::ok(7),
                "err": Outcome::<u8, &str>::err("denied"),
                "cancelled": Outcome::<u8, &str>::cancelled(CancelReason::user("req-9f4c36b1")),
                "panicked": OutcomeError::<&str>::Panicked(PanicPayload::new("boom")),
            }))
        );
    }

    #[test]
    fn outcome_json_snapshot_scrubs_ids_only() {
        let cancelled: Outcome<(), ()> = Outcome::cancelled(
            CancelReason::linked_exit()
                .with_region(crate::types::RegionId::new_for_test(42, 7))
                .with_task(crate::types::TaskId::new_for_test(9, 3))
                .with_timestamp(crate::types::Time::from_nanos(55))
                .with_message("upstream closed"),
        );

        insta::assert_json_snapshot!(
            "outcome_json_scrubbed_ids",
            scrub_outcome_json_ids(serde_json::to_value(cancelled).expect("serialize outcome"))
        );
    }
