#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::lab::LabConfig;
use asupersync::lab::LabRuntime;
use asupersync::types::Budget;

#[test]
#[ignore = "Known deadlock: mpsc uses blocking condvar in single-threaded lab runtime"]
fn repro_mpsc_deadlock_in_single_threaded_runtime() {
    common::init_test_logging();

    // Create a deterministic lab runtime (single-threaded Phase 0 kernel)
    let mut lab = LabRuntime::new(LabConfig::new(1));
    let region = lab.state.create_root_region(Budget::INFINITE);

    let (tx, rx) = mpsc::channel::<i32>(1); // Capacity 1

    // Spawn receiver
    let (recv_id, _recv_handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx set");
            // Sleep a bit to let sender fill the channel
            // In a proper async runtime, this would yield.
            // In LabRuntime, this advances virtual time.
            // But if the sender is BLOCKING the thread, we never get here.
            tracing::info!("Receiver started");

            // Try to receive
            let val = rx.recv(&cx).await.expect("recv 1");
            tracing::info!("Received {}", val);

            let val = rx.recv(&cx).await.expect("recv 2");
            tracing::info!("Received {}", val);
        })
        .expect("create receiver");

    // Spawn sender
    let (send_id, _send_handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx set");
            tracing::info!("Sender started");

            // Send 1 - succeeds (fills capacity)
            tx.send(&cx, 1).await.expect("send 1");
            tracing::info!("Sent 1");

            // Send 2 - should block until receiver runs
            // BUT: In Phase 0, mpsc uses Condvar::wait_timeout.
            // This blocks the OS thread.
            // The receiver task is on the SAME OS thread.
            // So the receiver never runs. Deadlock.
            tx.send(&cx, 2).await.expect("send 2");
            tracing::info!("Sent 2");
        })
        .expect("create sender");

    lab.scheduler.lock().unwrap().schedule(recv_id, 0);
    lab.scheduler.lock().unwrap().schedule(send_id, 0);

    lab.run_until_quiescent();
}
