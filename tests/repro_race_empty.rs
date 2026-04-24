#![allow(clippy::all)]
//! Tests for empty race inputs.
//!
//! Empty races should remain pending unless the surrounding context is already
//! cancelled. That preserves `race([])` as the never future while still allowing
//! cancellation to unblock callers.

mod common;

use asupersync::cx::Cx;
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::time::timeout;
use asupersync::types::{CancelKind, Time};
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[test]
fn test_race_empty_is_never() {
    init_test_logging();
    test_phase!("test_race_empty_is_never");

    run_test(|| async {
        let cx: Cx = Cx::for_testing();

        // An empty race should be "never" (pending forever).
        let futures: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];

        // Wrap in timeout to verify it hangs.
        let race_fut = Box::pin(cx.race(futures));
        let result = timeout(Time::ZERO, Duration::from_millis(50), race_fut).await;

        assert!(
            result.is_err(),
            "race([]) should hang (timeout), but it returned {result:?}"
        );
    });

    test_complete!("test_race_empty_is_never");
}

#[test]
fn test_race_identity_law_violation() {
    init_test_logging();
    test_phase!("test_race_identity_law_violation");

    run_test(|| async {
        let cx: Cx = Cx::for_testing();

        // Law: race(a, never) ~= a.
        // If race([]) is never, then race(async { 42 }, race([])) should be 42.

        let f1 = Box::pin(async { 42 }) as Pin<Box<dyn Future<Output = i32> + Send>>;

        let cx_clone = cx.clone();
        let f2 = Box::pin(async move {
            let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
            cx_clone.race(empty).await.unwrap_or(-1)
        }) as Pin<Box<dyn Future<Output = i32> + Send>>;

        let race_fut = Box::pin(cx.race(vec![f1, f2]));
        let combined = timeout(Time::ZERO, Duration::from_millis(100), race_fut).await;

        assert!(combined.is_ok(), "Outer race timed out");
        let inner_res = combined.unwrap();

        assert_eq!(
            inner_res.unwrap(),
            42,
            "race(a, race([])) should behave like a"
        );
    });

    test_complete!("test_race_identity_law_violation");
}

#[test]
fn test_race_all_empty_cancels() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);

        let res: asupersync::Outcome<Result<(i32, usize), JoinError>, asupersync::error::Error> =
            asupersync::proc_macros::scope!(cx, {
                cx.trace("testing race_all empty");
                let res: Result<(i32, usize), JoinError> = scope.race_all(&cx, vec![]).await;
                asupersync::Outcome::Ok(res)
            });

        let inner_res = match res {
            asupersync::Outcome::Ok(result) => result,
            other => panic!("expected Ok outcome, got {other:?}"),
        };

        assert!(matches!(inner_res, Err(JoinError::Cancelled(_))));
    });
}
