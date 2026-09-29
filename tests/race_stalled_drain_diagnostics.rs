//! A drain-correct race whose loser cannot observe its cancellation is named by
//! `Diagnostics::find_stalled_race_drains` instead of hanging silently
//! (asupersync-bi2462.89), and the child-context factory form never stalls.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::cx::RaceFactory;
use asupersync::runtime::RuntimeBuilder;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

type Branch = Pin<Box<dyn Future<Output = u8> + Send>>;

fn factory(work: impl FnOnce(Cx) -> Branch + Send + 'static) -> RaceFactory<u8> {
    Box::new(work)
}

fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_caller_cx_loser_is_reported_as_a_stalled_drain_until_it_finishes() {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let (sender, receiver) = mpsc::channel::<u8>(1);
    let race = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("admitted native task");
        let caller = cx.clone();
        let mut receiver = receiver;
        let branches: Vec<Branch> = vec![
            Box::pin(async { 7 }),
            // The hazard: this loser waits on the CALLER's context, so the
            // race-loser cancellation aimed at its own task never reaches it.
            Box::pin(async move { receiver.recv(&caller).await.unwrap_or(0) }),
        ];
        cx.race_drained(branches).await
    });

    let started = Instant::now();
    let stalled = wait_for("the stalled drain to be reported", || {
        runtime
            .diagnostics()
            .find_stalled_race_drains(Duration::ZERO)
            .into_iter()
            .find(|race| race.winner_selected)
    });
    eprintln!(
        "scenario=caller-cx-loser reported_after={:?} stalled={stalled:?}",
        started.elapsed()
    );
    assert_eq!(stalled.pending.len(), 1, "{stalled:?}");
    assert_eq!(stalled.pending[0].0, 1, "the recv branch is still pending");

    // The loser cannot see its cancellation, so the drain stays pending.
    std::thread::sleep(Duration::from_millis(200));
    let still = runtime
        .diagnostics()
        .find_stalled_race_drains(Duration::from_millis(200));
    eprintln!("scenario=caller-cx-loser after_200ms={still:?}");
    assert!(
        still.iter().any(|race| race.race_id == stalled.race_id),
        "the drain is still pending 200 ms later: {still:?}"
    );

    // Closing the channel lets the loser finish on its own; only then does
    // the race return, and the report clears.
    drop(sender);
    let result = runtime.block_on(race);
    assert_eq!(result.expect("winner"), 7);
    let after = runtime
        .diagnostics()
        .find_stalled_race_drains(Duration::ZERO);
    eprintln!("scenario=caller-cx-loser after_release={after:?}");
    assert!(after.iter().all(|race| race.race_id != stalled.race_id));
}

#[test]
fn a_child_context_loser_observes_cancellation_and_leaves_no_stalled_drain() {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    // The sender stays open: only loser cancellation can end the recv.
    let (sender, receiver) = mpsc::channel::<u8>(1);
    let started = Instant::now();
    let result = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("admitted native task");
        let mut receiver = receiver;
        let factories = vec![
            factory(|_child| Box::pin(async { 7 })),
            factory(move |child| Box::pin(async move { receiver.recv(&child).await.unwrap_or(0) })),
        ];
        cx.race_drained_with(factories).await
    }));
    let stalled = runtime
        .diagnostics()
        .find_stalled_race_drains(Duration::ZERO);
    eprintln!(
        "scenario=child-cx-loser elapsed={:?} result={result:?} stalled={stalled:?}",
        started.elapsed()
    );
    assert_eq!(result.expect("winner"), 7);
    assert!(stalled.is_empty(), "{stalled:?}");
    drop(sender);
}
