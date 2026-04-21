#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::combinator::bulkhead::{Bulkhead, BulkheadPolicy};
use asupersync::types::Time;

#[test]
fn test_cancel_head_of_line_blocking() {
    let bh = Bulkhead::new(BulkheadPolicy {
        max_concurrent: 10,
        max_queue: 10,
        ..Default::default()
    });
    let now = Time::from_millis(0);

    // Consume 7 permits, leaving 3 available
    let _p = bh.try_acquire(7).unwrap();

    // Try to enqueue A wanting 5 (will block)
    let a_id = bh.enqueue(5, now).unwrap();

    // Try to enqueue B wanting 2 (will block because A is ahead of it in FIFO)
    let b_id = bh.enqueue(2, now).unwrap();

    // Process queue (nothing happens because A wants 5 and we have 3)
    bh.process_queue(now);

    assert!(matches!(bh.check_entry(a_id, now), Ok(None)));
    assert!(matches!(bh.check_entry(b_id, now), Ok(None)));

    // Cancel A
    bh.cancel_entry(a_id, now);

    // B should now be granted! Because A was blocking it, and now A is gone.
    let b_status = bh.check_entry(b_id, now).unwrap();
    assert!(
        b_status.is_some(),
        "B should be granted after A is cancelled"
    );
}
