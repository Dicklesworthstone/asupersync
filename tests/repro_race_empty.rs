//! Tests for race combinator with empty input.
//!
//! Verifies that `race([])` behaves as "never" (pending forever).

mod common;
use common::*;

use asupersync::cx::Cx;
use asupersync::time::timeout;
use asupersync::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[test]
fn test_race_empty_is_never() {
    init_test_logging();
    test_phase!("test_race_empty_is_never");

    run_test(|| async {
        let cx = Cx::for_testing();

        // An empty race should be "never" (pending forever).
        let futures: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];

        // Wrap in timeout to verify it hangs
        let race_fut = Box::pin(cx.race(futures));
        let result = timeout(Time::ZERO, Duration::from_millis(50), race_fut).await;

        assert!(
            result.is_err(),
            "race([]) should hang (timeout), but it returned {:?}",
            result
        );
    });

    test_complete!("test_race_empty_is_never");
}

#[test]
fn test_race_identity_law_violation() {
    init_test_logging();
    test_phase!("test_race_identity_law_violation");

    run_test(|| async {
        let cx = Cx::for_testing();

        // Law: race(a, never) ≃ a
        // If race([]) is never, then race(async { 42 }, race([])) should be 42.

        // f1 finishes quickly with 42
        let f1 = Box::pin(async { 42 }) as Pin<Box<dyn Future<Output = i32> + Send>>;

        // f2 contains race([]) which should hang forever
        let cx_clone = cx.clone();
        let f2 = Box::pin(async move {
            // race([]) should hang
            let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
            cx_clone.race(empty).await.unwrap_or(-1)
        }) as Pin<Box<dyn Future<Output = i32> + Send>>;

        // Use timeout to ensure the whole test doesn't hang if we broke something else
        let race_fut = Box::pin(cx.race(vec![f1, f2]));
        let combined = timeout(Time::ZERO, Duration::from_millis(100), race_fut).await;

        assert!(combined.is_ok(), "Outer race timed out");
        let inner_res = combined.unwrap();

        // f1 should win with 42. f2 (race([])) should hang.
        assert_eq!(
            inner_res.unwrap(),
            42,
            "race(a, race([])) should behave like a"
        );
    });

    test_complete!("test_race_identity_law_violation");
}
