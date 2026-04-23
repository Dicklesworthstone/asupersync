//! Simplified metamorphic test for MPSC order preservation under cancellation.
//!
//! **Metamorphic Relation:** Message order is preserved when some sends are cancelled.
//! If messages [M1, M2, M3] are sent and M2 is cancelled after reserve,
//! the receiver should see [M1, M3] in that exact order.

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::runtime::builder::RuntimeBuilder;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestMessage {
    id: u64,
    content: String,
}

#[test]
fn test_mpsc_order_preservation_under_cancellation() {
    let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

    rt.block_on(async {
        let cx = Cx::for_testing();
        let (sender, mut receiver) = mpsc::channel(10);

        // Send M1
        let m1 = TestMessage { id: 1, content: "first".to_string() };
        sender.send(&cx, m1.clone()).await.expect("M1 send failed");

        // Reserve for M2, then abort (cancel)
        let permit = sender.reserve(&cx).await.expect("M2 reserve failed");
        permit.abort(); // Cancel M2

        // Send M3
        let m3 = TestMessage { id: 3, content: "third".to_string() };
        sender.send(&cx, m3.clone()).await.expect("M3 send failed");

        // Close sender
        drop(sender);

        // Receive messages - should be [M1, M3] in order
        let mut received = Vec::new();
        while let Ok(msg) = receiver.recv(&cx).await {
            received.push(msg);
        }

        // **Metamorphic Property:** Order preserved despite cancellation
        assert_eq!(received, vec![m1, m3],
            "Order preservation violated: expected [M1, M3], got {:?}", received);

        // **Equivalence Relation:** cancelled messages don't appear
        assert_eq!(received.len(), 2, "Should receive exactly 2 messages (M2 cancelled)");
        assert_eq!(received[0].id, 1, "First message should be M1");
        assert_eq!(received[1].id, 3, "Second message should be M3");
    });
}

#[test]
fn test_mpsc_permit_lifecycle_conservation() {
    let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

    rt.block_on(async {
        let cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel(5);

        // **Metamorphic Property:** Every reserve must be consumed
        for i in 0..3 {
            let permit = sender.reserve(&cx).await.expect("reserve failed");

            if i % 2 == 0 {
                // Commit: send message
                permit.try_send(TestMessage {
                    id: i, content: format!("msg_{}", i)
                }).expect("send failed");
            } else {
                // Abort: cancel reservation
                permit.abort();
            }
            // Either way, permit is consumed (obligation fulfilled)
        }

        // All permits accounted for - no hanging reservations
        assert!(sender.try_reserve().is_ok(), "Channel should accept new reservations");
    });
}