#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::channel::mpsc::SendError;
use asupersync::cx::Cx;
use common::*;
use futures_lite::future::block_on;

#[test]
fn repro_mpsc_cancel_returns_disconnected() {
    init_test_logging();
    test_phase!("repro_mpsc_cancel_returns_disconnected");
    test_section!("setup");
    let (tx, _rx) = mpsc::channel::<i32>(1);
    let cx: Cx = Cx::for_testing();

    // Fill channel
    block_on(async {
        tx.send(&cx, 1).await.unwrap();
    });

    // Request cancellation on the context
    cx.set_cancel_requested(true);

    // Try to reserve (which would block since channel is full)
    // It should observe cancellation immediately before blocking
    let result = block_on(async { tx.reserve(&cx).await });

    test_section!("verify");
    tracing::debug!(result = ?result, "reserve result");
    match result {
        Err(SendError::Cancelled(())) => {
            // Success: cancellation is now correctly reported
        }
        Err(SendError::Disconnected(())) => {
            panic!("Got Disconnected, expected Cancelled - bug persists");
        }
        Err(e) => {
            panic!("Unexpected error type: {e:?}");
        }
        Ok(_) => panic!("Should have failed due to cancellation"),
    }
    test_complete!("repro_mpsc_cancel_returns_disconnected");
}
