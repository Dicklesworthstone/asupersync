//! Behavioral fanout tests. Virtual timers and explicitly controlled transports
//! exercise the same driver used by the public distributor; no wall-clock sleeps.

use super::*;
use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
use crate::types::{CancelKind, symbol::{ObjectParams, Symbol}};
use crate::security::AuthKey;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

struct Fixture {
    cx: Cx,
    replicas: Vec<ReplicaInfo>,
    encoded: EncodedState,
    security: SecurityContext,
    clock: Arc<VirtualClock>,
    driver: Arc<TimerDriver<VirtualClock>>,
    timer: TimerDriverHandle,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let replicas: Vec<_> = (0..count).map(|i| ReplicaInfo::new(&format!("r{i}"), "unused")).collect();
        let security = SecurityContext::new(AuthKey::from_seed(42));
        for replica in &replicas { security.authorize_replica(&replica.id, None).unwrap(); }
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let timer = TimerDriverHandle::new(Arc::clone(&driver));
        Self {
            cx: Cx::for_testing(), replicas, security, clock, driver, timer,
            encoded: EncodedState {
                params: ObjectParams::new_for_test(1, 1024),
                symbols: (0..4).map(|i| Symbol::new_for_test(1, 0, i, &[0; 16])).collect(),
                source_count: 3, repair_count: 1, original_size: 48,
                encoded_at: Time::ZERO, layout_decision: Default::default(),
            },
        }
    }
    fn run<'a>(&'a self, config: &'a DistributionConfig, transport: &'a Probe)
        -> impl Future<Output = driver::FanoutResult> + Send + 'a
    {
        let assignments = SymbolDistributor::compute_assignments_with_auth(
            &self.encoded, &self.replicas, &self.security, None,
        );
        driver::run(config, &self.cx, &self.encoded, assignments, transport, &self.security, Some(self.timer.clone()))
    }
    fn advance(&self, nanos: u64) {
        self.clock.advance(nanos);
        self.driver.process_timers();
    }
}

// mode: 0 correct; 1 wrong identity; 2 too few symbols; 3 too many;
// 4 transport error with deliberately incorrect attribution.
struct Probe {
    ready: Vec<AtomicBool>,
    mode: Vec<u8>,
    cancel_on_poll: Option<Cx>,
    active: AtomicUsize,
    peak: AtomicUsize,
    started: Mutex<Vec<String>>,
    dropped: Mutex<Vec<String>>,
    waiters: Mutex<Vec<Option<Waker>>>,
}
impl Probe {
    fn new(count: usize, ready: bool) -> Self {
        Self {
            ready: (0..count).map(|_| AtomicBool::new(ready)).collect(),
            mode: vec![0; count], cancel_on_poll: None, active: AtomicUsize::new(0), peak: AtomicUsize::new(0),
            started: Mutex::new(Vec::new()), dropped: Mutex::new(Vec::new()),
            waiters: Mutex::new((0..count).map(|_| None).collect()),
        }
    }
    fn release(&self, index: usize) {
        self.ready[index].store(true, Ordering::Release);
        let wake = self.waiters.lock().unwrap()[index].take();
        if let Some(waker) = wake { waker.wake(); }
    }
    fn started(&self) -> Vec<String> { self.started.lock().unwrap().clone() }
    fn active(&self) -> usize { self.active.load(Ordering::SeqCst) }
}
struct SendProbe<'a> {
    transport: &'a Probe,
    id: String,
    index: usize,
    symbols: Vec<AuthenticatedSymbol>,
}
impl Future for SendProbe<'_> {
    type Output = Result<ReplicaAck, ReplicaFailure>;
    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        if self.transport.mode[self.index] == 5 {
            self.transport.cancel_on_poll.as_ref().unwrap().cancel_fast(CancelKind::User);
            return Poll::Pending;
        }
        if !self.transport.ready[self.index].load(Ordering::Acquire) {
            let waker = task.waker().clone();
            let old = self.transport.waiters.lock().unwrap()[self.index].replace(waker);
            drop(old);
            return Poll::Pending;
        }
        let mut ack = ReplicaAck {
            replica_id: self.id.clone(), symbols_received: self.symbols.len() as u32, ack_time: Time::ZERO,
        };
        match self.transport.mode[self.index] {
            1 => ack.replica_id = "different-replica".into(),
            2 => ack.symbols_received -= 1,
            3 => ack.symbols_received += 1,
            4 => return Poll::Ready(Err(ReplicaFailure {
                replica_id: "different-replica".into(), error: "transport sentinel".into(), error_kind: ErrorKind::NodeUnavailable,
            })),
            _ => {}
        }
        Poll::Ready(Ok(ack))
    }
}
impl Drop for SendProbe<'_> {
    fn drop(&mut self) {
        self.transport.active.fetch_sub(1, Ordering::SeqCst);
        self.transport.dropped.lock().unwrap().push(self.id.clone());
        let old = self.transport.waiters.lock().unwrap()[self.index].take();
        drop(old);
    }
}
impl DistributorTransport for Probe {
    fn send_symbols(&self, replica_id: &str, symbols: Vec<AuthenticatedSymbol>)
        -> impl Future<Output = Result<ReplicaAck, ReplicaFailure>> + Send
    {
        // Deliberately eager: invocation itself admits resources, not first poll
        // of SendProbe. Queued distributor plans must NOT call this method.
        self.started.lock().unwrap().push(replica_id.to_owned());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        SendProbe { transport: self, id: replica_id.to_owned(), index: replica_id[1..].parse().unwrap(), symbols }
    }
}
#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount { fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); } }
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn finish<F: Future>(future: Pin<&mut F>) -> F::Output {
    let mut future = future;
    for _ in 0..100 { if let Poll::Ready(result) = poll(future.as_mut()) { return result; } }
    panic!("fanout did not reach a terminal result");
}
fn config(capacity: usize) -> DistributionConfig {
    DistributionConfig { max_concurrent: capacity, ack_timeout: Duration::from_millis(100), ..Default::default() }
}
fn count_ok(result: &driver::FanoutResult) -> usize {
    result.outcomes.iter().filter(|outcome| matches!(outcome, Outcome::Ok(_))).count()
}

#[test]
fn slow_first_peer_does_not_block_healthy_peers() {
    let f = Fixture::new(3); let transport = Probe::new(3, true); transport.ready[0].store(false, Ordering::Relaxed);
    let config = config(3); let mut future = Box::pin(f.run(&config, &transport));
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(transport.started(), ["r0", "r1", "r2"]);
    assert_eq!(transport.active(), 1);
    f.advance(100_000_000);
    let result = finish(future.as_mut());
    assert_eq!(count_ok(&result), 2);
    assert_eq!(result.symbols_attempted, 12);
    assert!(matches!(&result.outcomes[0], Outcome::Err(error) if error.error_kind == ErrorKind::DeadlineExceeded));
    assert_eq!(transport.active(), 0); assert!(f.driver.is_empty());
}

#[test]
fn concurrency_credits_cover_future_destruction_and_queued_sends_stay_lazy() {
    let f = Fixture::new(5); let transport = Probe::new(5, false); let config = config(2);
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(transport.started().is_empty());
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(transport.started(), ["r0", "r1"]);
    transport.release(1); assert!(poll(future.as_mut()).is_pending());
    assert_eq!(transport.active(), 1);
    assert_eq!(*transport.dropped.lock().unwrap(), ["r1"]);
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(transport.started(), ["r0", "r1", "r2"]);
    for i in 0..5 { transport.release(i); }
    let result = finish(future.as_mut());
    assert_eq!(count_ok(&result), 5); assert_eq!(transport.active(), 0);
    assert!(transport.peak.load(Ordering::SeqCst) <= 2);
    assert_eq!(transport.dropped.lock().unwrap().len(), 5);
}

#[test]
fn completion_order_does_not_reorder_the_report() {
    let f = Fixture::new(3); let transport = Probe::new(3, false); let config = config(3);
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(poll(future.as_mut()).is_pending());
    for i in [2, 1] { transport.release(i); assert!(poll(future.as_mut()).is_pending()); }
    transport.release(0); let result = finish(future.as_mut());
    let ids: Vec<_> = result.outcomes.iter().map(|o| match o { Outcome::Ok(ack) => ack.replica_id.as_str(), _ => panic!("unexpected failure") }).collect();
    assert_eq!(ids, ["r0", "r1", "r2"]);
}

#[test]
fn queued_peer_gets_a_fresh_timeout_at_admission() {
    let f = Fixture::new(2); let transport = Probe::new(2, false); let config = config(1);
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(poll(future.as_mut()).is_pending());
    f.advance(100_000_000); assert!(poll(future.as_mut()).is_pending());
    assert_eq!(transport.active(), 0);
    assert!(poll(future.as_mut()).is_pending()); assert_eq!(transport.active(), 1);
    f.advance(99_000_000); assert!(poll(future.as_mut()).is_pending());
    transport.release(1); let result = finish(future.as_mut());
    assert_eq!(count_ok(&result), 1); assert_eq!(result.symbols_attempted, 8);
}

#[test]
fn deadline_wins_over_an_ack_ready_at_the_same_instant() {
    let f = Fixture::new(1); let transport = Probe::new(1, false); let config = config(1);
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(poll(future.as_mut()).is_pending());
    f.advance(100_000_000); transport.release(0);
    assert_eq!(count_ok(&finish(future.as_mut())), 0);
    assert_eq!(transport.active(), 0);
}

#[test]
fn parked_cancellation_wakes_and_retires_all_admitted_sends() {
    let f = Fixture::new(5); let transport = Probe::new(5, false); let config = config(2);
    let count = Arc::new(WakeCount::default()); let waker = Waker::from(Arc::clone(&count));
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    let before = count.0.load(Ordering::SeqCst);
    f.cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > before);
    let result = finish(future.as_mut());
    assert_eq!(transport.started(), ["r0", "r1"]);
    assert_eq!(transport.active(), 0); assert!(f.driver.is_empty());
    assert_eq!(result.symbols_attempted, 8); assert_eq!(result.eligible_replicas, 5);
    assert!(result.outcomes.iter().all(|o| matches!(o, Outcome::Err(e) if e.error_kind == ErrorKind::Cancelled)));
}

#[test]
fn pre_cancelled_distribution_never_calls_the_transport() {
    let f = Fixture::new(3); f.cx.cancel_fast(CancelKind::Shutdown);
    let transport = Probe::new(3, true); let config = config(3);
    let mut future = Box::pin(f.run(&config, &transport)); let result = finish(future.as_mut());
    assert!(transport.started().is_empty()); assert_eq!(result.symbols_attempted, 0);
    assert_eq!(result.outcomes.len(), 3); assert_eq!(count_ok(&result), 0);
}

#[test]
fn external_drop_releases_attempts_timers_and_cancellation_registration() {
    let f = Fixture::new(4); let transport = Probe::new(4, false); let config = config(2);
    let count = Arc::new(WakeCount::default()); let waker = Waker::from(Arc::clone(&count));
    let mut future = Box::pin(f.run(&config, &transport));
    assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(future);
    assert_eq!(transport.active(), 0); assert!(f.driver.is_empty());
    let before = count.0.load(Ordering::SeqCst); f.cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), before);
    assert_eq!(transport.started(), ["r0", "r1"]);
}

#[test]
fn zero_concurrency_refuses_all_without_lowering_the_eligible_denominator() {
    let f = Fixture::new(3); let transport = Probe::new(3, true); let config = config(0);
    let mut future = Box::pin(f.run(&config, &transport)); let result = finish(future.as_mut());
    assert!(transport.started().is_empty()); assert_eq!(result.symbols_attempted, 0);
    assert_eq!(result.eligible_replicas, 3);
    assert!(result.outcomes.iter().all(|o| matches!(o, Outcome::Err(e) if e.error_kind == ErrorKind::AdmissionDenied)));
}

#[test]
fn zero_ack_budget_refuses_before_signing_or_transport_invocation() {
    let f = Fixture::new(5); let transport = Probe::new(5, true); let mut config = config(2); config.ack_timeout = Duration::ZERO;
    let mut future = Box::pin(f.run(&config, &transport)); let result = finish(future.as_mut());
    assert!(transport.started().is_empty()); assert_eq!(result.symbols_attempted, 0);
    assert_eq!(result.outcomes.len(), 5);
    assert!(result.outcomes.iter().all(|o| matches!(o, Outcome::Err(e) if e.error_kind == ErrorKind::DeadlineExceeded)));
}

#[test]
fn acknowledgements_must_match_replica_and_complete_assigned_count() {
    let f = Fixture::new(3); let mut transport = Probe::new(3, true); transport.mode = vec![1, 2, 3];
    let mut distributor = SymbolDistributor::new(config(3));
    let result = futures_lite::future::block_on(distributor.distribute(&f.cx, &f.encoded, &f.replicas, &transport, &f.security));
    assert!(!result.quorum_achieved); assert!(result.acks.is_empty()); assert_eq!(result.failures.len(), 3);
    assert!(result.failures.iter().all(|e| e.error_kind == ErrorKind::ProtocolError));
    assert_eq!(distributor.metrics.acks_received_total, 0); assert_eq!(distributor.metrics.symbols_sent_total, 12);
}

#[test]
fn provider_failure_cannot_impersonate_another_replica() {
    let f = Fixture::new(1); let mut transport = Probe::new(1, true); transport.mode[0] = 4;
    let mut distributor = SymbolDistributor::new(config(1));
    let result = futures_lite::future::block_on(distributor.distribute(&f.cx, &f.encoded, &f.replicas, &transport, &f.security));
    assert_eq!(result.failures[0].replica_id, "r0"); assert_eq!(result.failures[0].error, "transport sentinel");
    assert_eq!(result.failures[0].error_kind, ErrorKind::NodeUnavailable);
}

#[test]
fn duplicate_replica_ids_cannot_create_duplicate_votes_or_sends() {
    let mut f = Fixture::new(2); f.replicas.push(ReplicaInfo::new("r0", "duplicate"));
    let transport = Probe::new(2, true); let mut distributor = SymbolDistributor::new(config(3));
    let result = futures_lite::future::block_on(distributor.distribute(&f.cx, &f.encoded, &f.replicas, &transport, &f.security));
    assert!(result.quorum_achieved); assert_eq!(result.acks.len(), 2);
    assert_eq!(transport.started(), ["r0", "r1"]); assert_eq!(result.symbols_distributed, 8);
}

#[test]
fn pending_without_context_timer_fails_instead_of_using_ambient_authority() {
    let f = Fixture::new(2); let transport = Probe::new(2, false); let mut distributor = SymbolDistributor::new(config(2));
    assert!(f.cx.timer_driver().is_none());
    let result = futures_lite::future::block_on(distributor.distribute(&f.cx, &f.encoded, &f.replicas, &transport, &f.security));
    assert!(!result.quorum_achieved); assert_eq!(transport.active(), 0);
    assert!(result.failures.iter().all(|e| e.error_kind == ErrorKind::ConfigError));
}

#[test]
fn ready_success_without_a_timer_preserves_existing_consumer_behavior() {
    let f = Fixture::new(4); let transport = Probe::new(4, true); let mut distributor = SymbolDistributor::new(config(2));
    let result = futures_lite::future::block_on(distributor.distribute(&f.cx, &f.encoded, &f.replicas, &transport, &f.security));
    assert!(result.quorum_achieved); assert_eq!(result.acks.len(), 4); assert_eq!(result.symbols_distributed, 16);
    assert_eq!(transport.active(), 0); assert_eq!(distributor.metrics.distributions_total, 1);
}

#[test]
fn cancellation_during_a_send_stops_other_admitted_but_unpolled_work() {
    let f = Fixture::new(3); let mut transport = Probe::new(3, true);
    transport.mode[0] = 5; transport.cancel_on_poll = Some(f.cx.clone());
    let config = config(2); let mut future = Box::pin(f.run(&config, &transport));
    let result = finish(future.as_mut());
    assert_eq!(transport.started(), ["r0"]); assert_eq!(transport.active(), 0);
    assert_eq!(result.symbols_attempted, 4);
    assert!(result.outcomes.iter().all(|o| matches!(o, Outcome::Err(e) if e.error_kind == ErrorKind::Cancelled)));
}
