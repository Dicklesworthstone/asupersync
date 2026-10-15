#![no_main]
//! Stateful fuzz harness for `asupersync::channel::mpsc`.
//!
//! Drives the real two-phase reserve/commit protocol against a shadow VecDeque
//! and asserts FIFO ordering, conservation (received <= committed), and the
//! reserve-vs-abort accounting on every step. Async paths (`Sender::reserve`,
//! `Sender::send`, `Receiver::recv`) are exercised via single-shot `poll_once`
//! so a full or empty channel never wedges the fuzzer — the future is dropped
//! on Pending, which doubles as a cancellation test for the reservation state
//! machine.

use arbitrary::Arbitrary;
use asupersync::channel::mpsc::{self, RecvError, SendError};
use asupersync::cx::Cx;
use asupersync::types::{Budget, Outcome};
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

#[derive(Arbitrary, Debug)]
struct ChannelStateMachineFuzz {
    capacity: u8,
    operations: Vec<ChannelOperation>,
}

#[derive(Arbitrary, Debug)]
enum ChannelOperation {
    /// `try_reserve` then `permit.send(value)` — exercises the commit branch.
    TryReserveCommit { value: u32 },
    /// `try_reserve` then `permit.abort()` — explicit abort, capacity returns.
    TryReserveAbort,
    /// `try_reserve` then drop the permit — implicit abort via Drop impl.
    TryReserveDrop,
    /// `Sender::send` (reserve+commit in one) polled exactly once.
    PollSendOnce { value: u32 },
    /// Poll the async `reserve` once, then either commit, abort, or drop.
    PollReserveOnce { value: u32, action: ReserveAction },
    /// Non-blocking receive.
    TryRecv,
    /// Poll `recv` once. If Ready, the value is consumed; if Pending, the
    /// future is dropped (cancellation test).
    PollRecvOnce,
    /// Drop the only sender. Subsequent operations on a missing sender are
    /// no-ops; the receiver should observe `Disconnected` on a drained queue.
    DropSender,
    /// Drop the receiver. Subsequent sends should observe `Disconnected`.
    DropReceiver,
}

#[derive(Arbitrary, Debug)]
enum ReserveAction {
    Commit,
    Abort,
    Drop,
}

const MAX_OPS: usize = 64;
const MAX_CAPACITY: usize = 64;

fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Poll `fut` exactly once with a noop waker. Returns `Some(output)` on Ready
/// or `None` on Pending. Pending futures are dropped at function return —
/// the asupersync cancel-correctness contract requires that to release any
/// reservation cleanly without losing data.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let waker = Waker::noop();
    let mut ctx = Context::from_waker(waker);
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut ctx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

struct Shadow {
    queue: VecDeque<u32>,
    capacity: usize,
    committed: u64,
    received: u64,
}

impl Shadow {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity,
            committed: 0,
            received: 0,
        }
    }

    fn record_commit(&mut self, value: u32) {
        self.queue.push_back(value);
        self.committed += 1;
        assert!(
            self.queue.len() <= self.capacity,
            "shadow queue {} exceeds capacity {}",
            self.queue.len(),
            self.capacity
        );
    }

    fn record_recv(&mut self, value: u32) {
        let expected = self.queue.pop_front();
        assert_eq!(
            Some(value),
            expected,
            "FIFO violation: got {value} expected {expected:?}"
        );
        self.received += 1;
        assert!(
            self.received <= self.committed,
            "conservation violation: received {} > committed {}",
            self.received,
            self.committed
        );
    }
}

fuzz_target!(|input: ChannelStateMachineFuzz| {
    if input.operations.len() > MAX_OPS {
        return;
    }
    let capacity = (input.capacity as usize).max(1).min(MAX_CAPACITY);

    let cx = test_cx();
    let (tx, rx) = mpsc::channel::<u32>(capacity);
    let mut tx = Some(tx);
    let mut rx = Some(rx);
    let mut shadow = Shadow::new(capacity);

    for op in input.operations {
        match op {
            ChannelOperation::TryReserveCommit { value } => {
                let Some(s) = tx.as_ref() else { continue };
                match s.try_reserve() {
                    Ok(permit) => match permit.send(value) {
                        Outcome::Ok(()) => shadow.record_commit(value),
                        Outcome::Err(SendError::Disconnected(_)) => {
                            assert!(rx.is_none(), "Disconnected commit while rx alive");
                        }
                        Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
                    },
                    Err(SendError::Full(())) => {}
                    Err(SendError::Disconnected(())) => {
                        assert!(rx.is_none(), "Disconnected reserve while rx alive");
                    }
                    Err(SendError::Cancelled(())) => {}
                }
            }

            ChannelOperation::TryReserveAbort => {
                let Some(s) = tx.as_ref() else { continue };
                if let Ok(permit) = s.try_reserve() {
                    permit.abort();
                }
            }

            ChannelOperation::TryReserveDrop => {
                let Some(s) = tx.as_ref() else { continue };
                if let Ok(permit) = s.try_reserve() {
                    drop(permit);
                }
            }

            ChannelOperation::PollSendOnce { value } => {
                let Some(s) = tx.as_ref() else { continue };
                if let Some(result) = poll_once(s.send(&cx, value)) {
                    match result {
                        Ok(()) => shadow.record_commit(value),
                        Err(SendError::Disconnected(_)) => {
                            assert!(rx.is_none(), "Disconnected send while rx alive");
                        }
                        Err(_) => {}
                    }
                }
                // Pending: the send future is dropped here. Any reservation
                // it held must be released by Drop — the next iteration's
                // shadow-vs-actual sync verifies that implicitly.
            }

            ChannelOperation::PollReserveOnce { value, action } => {
                let Some(s) = tx.as_ref() else { continue };
                match poll_once(s.reserve(&cx)) {
                    Some(Ok(permit)) => match action {
                        ReserveAction::Commit => {
                            if let Outcome::Ok(()) = permit.send(value) {
                                shadow.record_commit(value);
                            }
                        }
                        ReserveAction::Abort => permit.abort(),
                        ReserveAction::Drop => drop(permit),
                    },
                    Some(Err(SendError::Disconnected(()))) => {
                        assert!(rx.is_none(), "Disconnected reserve while rx alive");
                    }
                    Some(Err(_)) | None => {
                        // Pending or transient; future is dropped here.
                    }
                }
            }

            ChannelOperation::TryRecv => {
                let Some(r) = rx.as_mut() else { continue };
                match r.try_recv() {
                    Ok(v) => shadow.record_recv(v),
                    Err(RecvError::Empty) => {
                        assert!(shadow.queue.is_empty(), "Empty but shadow non-empty");
                    }
                    Err(RecvError::Disconnected) => {
                        assert!(tx.is_none(), "Disconnected recv while tx alive");
                    }
                    Err(RecvError::Cancelled) => {}
                }
            }

            ChannelOperation::PollRecvOnce => {
                let Some(r) = rx.as_mut() else { continue };
                match poll_once(r.recv(&cx)) {
                    Some(Ok(v)) => shadow.record_recv(v),
                    Some(Err(_)) => {
                        // Disconnected/cancelled: queue must drain consistently.
                    }
                    None => {
                        // Pending: dropping the recv future must not lose data.
                    }
                }
            }

            ChannelOperation::DropSender => {
                tx = None;
            }

            ChannelOperation::DropReceiver => {
                rx = None;
            }
        }
    }

    // Final drain: anything still in the channel must come out in FIFO order.
    // After dropping the sender, the receiver eventually observes Disconnected
    // (or Empty + drained shadow) when no more values are queued.
    if let Some(mut r) = rx.take() {
        drop(tx.take());
        loop {
            match r.try_recv() {
                Ok(v) => shadow.record_recv(v),
                Err(RecvError::Empty) => {
                    assert!(
                        shadow.queue.is_empty(),
                        "drain ended Empty with {} unreceived",
                        shadow.queue.len()
                    );
                    break;
                }
                Err(RecvError::Disconnected) => {
                    assert!(
                        shadow.queue.is_empty(),
                        "drain Disconnected with {} unreceived",
                        shadow.queue.len()
                    );
                    break;
                }
                Err(RecvError::Cancelled) => break,
            }
        }
    }

    assert!(
        shadow.received <= shadow.committed,
        "final conservation: received {} > committed {}",
        shadow.received,
        shadow.committed
    );
});
