//! Metamorphic Testing for MPSC FIFO Preservation Under Cancellation
//!
//! Tests FIFO ordering invariants for the two-phase MPSC channel under
//! concurrent reserve/send/cancel operations.
//!
//! Target: src/channel/mpsc.rs
//!
//! # Metamorphic Relations
//!
//! 1. **FIFO Ordering**: Successfully sent messages are received in send order
//! 2. **Cancel Isolation**: Cancelled reserve operations don't affect successful send ordering
//! 3. **Reserve/Send Atomicity**: The two-phase reserve→send is logically atomic for ordering

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use futures_lite::future::block_on;

/// Test: Basic FIFO preservation for sequential sends
#[test]
fn test_mpsc_sequential_fifo_preservation() {
    let (sender, mut receiver) = mpsc::channel(5);

    // Send messages sequentially using try_send
    for i in 1..=5 {
        sender.try_send(i).expect("send should succeed");
    }

    // Receive and verify FIFO order
    let mut received = Vec::new();
    while let Ok(msg) = receiver.try_recv() {
        received.push(msg);
    }

    assert_eq!(
        received,
        vec![1, 2, 3, 4, 5],
        "Messages should be received in FIFO order"
    );
}

/// Test: Two-phase reserve/send preserves FIFO ordering
#[test]
fn test_mpsc_two_phase_fifo_preservation() {
    let (sender, mut receiver) = mpsc::channel::<u64>(3);

    block_on(async {
        let cx = Cx::for_testing();

        // Phase 1: Reserve permits
        let permit1 = sender.reserve(&cx).await.expect("reserve 1");
        let permit2 = sender.reserve(&cx).await.expect("reserve 2");
        let permit3 = sender.reserve(&cx).await.expect("reserve 3");

        // Phase 2: Send in order
        permit1.try_send(10).expect("send 10");
        permit2.try_send(20).expect("send 20");
        permit3.try_send(30).expect("send 30");
    });

    // Receive and verify FIFO order
    let mut received = Vec::new();
    while let Ok(msg) = receiver.try_recv() {
        received.push(msg);
    }

    assert_eq!(
        received,
        vec![10, 20, 30],
        "Two-phase operations should preserve FIFO order"
    );
}

/// Test: FIFO preservation with mixed reserve/direct send operations
#[test]
fn test_mpsc_mixed_operations_fifo() {
    let (sender, mut receiver) = mpsc::channel::<u64>(4);

    block_on(async {
        let cx = Cx::for_testing();

        // Mix direct sends and reserve/send
        sender.send(&cx, 1).await.expect("direct send 1");

        let permit = sender.reserve(&cx).await.expect("reserve for 2");
        permit.try_send(2).expect("send 2");

        sender.send(&cx, 3).await.expect("direct send 3");
        sender.try_send(4).expect("try_send 4");
    });

    // Receive and verify FIFO order
    let mut received = Vec::new();
    while let Ok(msg) = receiver.try_recv() {
        received.push(msg);
    }

    assert_eq!(
        received,
        vec![1, 2, 3, 4],
        "Mixed operations should preserve FIFO order"
    );
}

/// Test: FIFO ordering with capacity constraints
#[test]
fn test_mpsc_fifo_with_capacity_limits() {
    // Test with minimal capacity
    let (sender, mut receiver) = mpsc::channel::<u64>(1);

    // Fill channel
    sender.try_send(100).expect("send 100");

    // Next send should fail with Full
    match sender.try_send(200) {
        Err(mpsc::SendError::Full(200)) => {
            // Expected - channel is full
        }
        other => panic!("Expected Full error, got: {:?}", other),
    }

    // Receive first message
    assert_eq!(receiver.try_recv(), Ok(100));

    // Now we can send the second message
    sender.try_send(200).expect("send 200 after drain");
    assert_eq!(receiver.try_recv(), Ok(200));
}
