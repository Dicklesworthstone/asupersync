#![allow(missing_docs)]

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::thread;
use std::time::Duration;

fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

#[test]
fn test_mpsc_fifo_starvation() {
    // Capacity 1
    let (tx, rx) = mpsc::channel::<i32>(1);
    let cx = test_cx();

    // Fill the channel
    tx.try_send(1).expect("first send");

    let tx_a = tx.clone();
    let cx_a = cx;

    // Sender A: waits for capacity
    let handle_a = thread::spawn(move || {
        // This will block until rx receives
        futures_lite::future::block_on(tx_a.send(&cx_a, 2)).expect("A send");
    });

    // Give A time to block and enter the wait queue
    thread::sleep(Duration::from_millis(50));

    // Receiver pops one, freeing a slot.
    // In buggy impl: this wakes A but also clears the queue.
    let val = rx.try_recv().expect("recv 1");
    assert_eq!(val, 1);

    // Sync to ensure Recv has processed (and cleared queue) but A hasn't claimed yet
    // Hard to guarantee exact interleaving with threads, but...
    // If we are fast enough, B can steal.

    // Sender B: tries to send immediately
    let result_b = tx.try_send(3);

    // In a fair FIFO channel, B should fail (Full) because A is waiting.
    // In the buggy channel, B succeeds because A was removed from queue upon wake.
    assert!(
        result_b.is_err(),
        "FIFO violation: Sender B stole the slot while Sender A was waiting!"
    );

    handle_a.join().unwrap();
}
