//! Regression coverage for MPSC reserve cancellation error attribution.

use asupersync::channel::mpsc;
use asupersync::channel::mpsc::SendError;
use asupersync::cx::Cx;
use futures_lite::future::block_on;

#[test]
fn reserve_on_cancelled_full_channel_returns_cancelled_without_consuming_message() {
    let (tx, rx) = mpsc::channel::<i32>(1);
    let cx: Cx = Cx::for_testing();

    block_on(async {
        tx.send(&cx, 1).await.unwrap();
    });
    assert_eq!(rx.len(), 1);
    assert!(!tx.is_closed(), "receiver must stay alive for this repro");

    cx.set_cancel_requested(true);

    let result = block_on(async { tx.reserve(&cx).await });
    assert!(
        matches!(result, Err(SendError::Cancelled(()))),
        "cancelled reserve on a live full channel must report Cancelled, got {result:?}"
    );
    assert_eq!(
        rx.len(),
        1,
        "cancelled reserve must not consume or drop the queued message"
    );
}
