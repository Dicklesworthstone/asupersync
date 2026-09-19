use super::*;
use crate::record::distributed_region::ReplicaInfo;
use crate::security::{AuthKey, AuthenticatedSymbol};
use crate::time::{TimerDriver, VirtualClock};
use crate::types::{CancelKind, symbol::{ObjectParams, Symbol}};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn waker() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    (Arc::clone(&counter), Waker::from(counter))
}
fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}
fn done<F: Future>(future: Pin<&mut F>, waker: &Waker) -> F::Output {
    match poll(future, waker) { Poll::Ready(value) => value, Poll::Pending => panic!("expected terminal result") }
}
fn config(level: ConsistencyLevel, capacity: usize) -> DistributionConfig {
    DistributionConfig {
        consistency: level, max_concurrent: capacity, hedge_enabled: true,
        hedge_delay: std::time::Duration::from_millis(10),
        ack_timeout: std::time::Duration::from_millis(100),
        ..Default::default()
    }
}
struct Fixture {
    cx: Cx,
    encoded: EncodedState,
    replicas: Vec<ReplicaInfo>,
    auth: SecurityContext,
    clock: Arc<VirtualClock>,
    driver: Arc<TimerDriver<VirtualClock>>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let auth = SecurityContext::new(AuthKey::from_seed(42));
        let replicas: Vec<_> = (0..count).map(|i| ReplicaInfo::new(&format!("r{i}"), "unused")).collect();
        for r in &replicas { auth.authorize_replica(&r.id, None).unwrap(); }
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        Self {
            cx: Cx::for_testing(), replicas, auth, clock, driver,
            encoded: EncodedState {
                params: ObjectParams::new_for_test(1, 64),
                symbols: (0..4).map(|i| Symbol::new_for_test(1, 0, i, &[5; 16])).collect(),
                source_count: 4, repair_count: 0, original_size: 64,
                encoded_at: Time::ZERO, layout_decision: Default::default(),
            },
        }
    }
    fn run<'a>(&'a self, config: &'a DistributionConfig, probe: &'a Probe)
        -> impl Future<Output = FanoutResult> + Send + 'a
    {
        let assignments = SymbolDistributor::compute_assignments_with_auth(&self.encoded, &self.replicas, &self.auth, None);
        super::super::run(config, &self.cx, &self.encoded, assignments, probe, &self.auth,
            Some(TimerDriverHandle::new(Arc::clone(&self.driver))))
    }
    // Use whole milliseconds: the production timer wheel has 1ms slots.
    fn advance(&self, millis: u64) {
        self.clock.advance(millis.checked_mul(1_000_000).unwrap());
        self.driver.process_timers();
    }
}

// Mode 0 parks, 1 succeeds, 2 errors, 3 lies about count, 4 lies about
// identity, and 5 panics. Invocation itself acquires resources deliberately.
struct Probe {
    modes: Vec<AtomicU8>,
    calls: Mutex<Vec<usize>>,
    waiters: Mutex<Vec<Option<Waker>>>,
    active: AtomicUsize,
    peak: AtomicUsize,
}
impl Probe {
    fn new(modes: &[u8]) -> Self {
        Self {
            modes: modes.iter().map(|&mode| AtomicU8::new(mode)).collect(),
            calls: Mutex::new(Vec::new()), waiters: Mutex::new(modes.iter().map(|_| None).collect()),
            active: AtomicUsize::new(0), peak: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> Vec<usize> { self.calls.lock().unwrap().clone() }
    fn active(&self) -> usize { self.active.load(Ordering::SeqCst) }
    fn release(&self, index: usize) {
        self.modes[index].store(1, Ordering::Release);
        let wake = self.waiters.lock().unwrap()[index].take();
        if let Some(wake) = wake { wake.wake(); }
    }
}
struct Sending<'a> { probe: &'a Probe, index: usize, symbols: Vec<AuthenticatedSymbol> }
impl Future for Sending<'_> {
    type Output = super::super::SendResult;
    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let mode = self.probe.modes[self.index].load(Ordering::Acquire);
        if mode == 0 {
            let candidate = task.waker().clone();
            let old = self.probe.waiters.lock().unwrap()[self.index].replace(candidate);
            drop(old);
            return Poll::Pending;
        }
        if mode == 5 { panic!("transport poll sentinel"); }
        let id = format!("r{}", self.index);
        if mode == 2 { return Poll::Ready(Err(failure(&id, ErrorKind::ConnectionLost, "replica refused"))); }
        Poll::Ready(Ok(super::super::ReplicaAck {
            replica_id: if mode == 4 { "forged".into() } else { id },
            symbols_received: self.symbols.len() as u32 - u32::from(mode == 3),
            ack_time: Time::ZERO,
        }))
    }
}
impl Drop for Sending<'_> {
    fn drop(&mut self) {
        let old = self.probe.waiters.lock().unwrap()[self.index].take();
        drop(old);
        self.probe.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl DistributorTransport for Probe {
    fn send_symbols(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>)
        -> impl Future<Output = super::super::SendResult> + Send
    {
        let index = replica[1..].parse().unwrap();
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.calls.lock().unwrap().push(index);
        Sending { probe: self, index, symbols }
    }
}
fn successes(result: &FanoutResult) -> usize { result.outcomes.iter().filter(|o| matches!(o, Outcome::Ok(_))).count() }
fn kind(result: &FanoutResult, index: usize) -> ErrorKind {
    match &result.outcomes[index] { Outcome::Err(error) => error.error_kind, _ => panic!("expected failure") }
}

#[test]
fn immediate_quorum_never_contacts_backups_and_counts_only_attempted_symbols() {
    let f = Fixture::new(5); let p = Probe::new(&[1; 5]); let c = config(ConsistencyLevel::Quorum, 5);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(p.calls().is_empty());
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0, 1, 2]); assert_eq!(p.active(), 0);
    assert_eq!(successes(&result), 3); assert_eq!(result.eligible_replicas, 5);
    assert_eq!(result.symbols_attempted, 12); assert_eq!(kind(&result, 4), ErrorKind::Cancelled);
}

#[test]
fn default_path_still_contacts_every_eligible_replica() {
    let f = Fixture::new(5); let p = Probe::new(&[1; 5]);
    let mut c = config(ConsistencyLevel::One, 5); c.hedge_enabled = false;
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0, 1, 2, 3, 4]); assert_eq!(successes(&result), 5);
    assert_eq!(result.symbols_attempted, 20);
}

#[test]
fn timer_wakes_delayed_backup_and_quorum_retires_the_stalled_primary() {
    let f = Fixture::new(3); let p = Probe::new(&[0, 1, 1]); let c = config(ConsistencyLevel::One, 3);
    let (counter, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0]);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    f.advance(9); assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0]);
    f.advance(1); assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(poll(run.as_mut(), &w).is_pending()); // Admit one backup, do not invoke it yet.
    assert_eq!(p.calls(), [0]);
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0, 1]); assert_eq!(p.active(), 0);
    assert_eq!(p.peak.load(Ordering::SeqCst), 2); assert_eq!(successes(&result), 1);
    assert_eq!(result.symbols_attempted, 8);
    let before = counter.0.load(Ordering::SeqCst); f.advance(1000);
    assert_eq!(counter.0.load(Ordering::SeqCst), before, "retired timers must not wake the finished owner");
}

#[test]
fn primary_ready_on_hedge_deadline_avoids_redundant_dispatch() {
    let f = Fixture::new(3); let p = Probe::new(&[0, 1, 1]); let c = config(ConsistencyLevel::One, 3);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); f.advance(10); p.release(0);
    assert_eq!(successes(&done(run.as_mut(), &w)), 1); assert_eq!(p.calls(), [0]);
}

#[test]
fn fast_refusal_replaces_primary_without_waiting_for_hedge_timer() {
    let f = Fixture::new(3); let p = Probe::new(&[2, 1, 1]); let c = config(ConsistencyLevel::One, 3);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.active(), 0);
    let result = done(run.as_mut(), &w); assert_eq!(p.calls(), [0, 1]);
    assert_eq!(kind(&result, 0), ErrorKind::ConnectionLost); assert_eq!(successes(&result), 1);
}

#[test]
fn full_capacity_does_not_arm_useless_hedge_wakes_and_replacement_gets_full_timeout() {
    let f = Fixture::new(3); let p = Probe::new(&[0, 0, 1]); let c = config(ConsistencyLevel::One, 1);
    let (counter, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); f.advance(10);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0]);
    f.advance(90); assert!(poll(run.as_mut(), &w).is_pending()); // First attempt expires.
    assert_eq!(p.active(), 0);
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0, 1]);
    f.advance(99); p.release(1); let result = done(run.as_mut(), &w);
    assert_eq!(successes(&result), 1); assert_eq!(kind(&result, 0), ErrorKind::DeadlineExceeded);
    assert_eq!(p.peak.load(Ordering::SeqCst), 1);
}

#[test]
fn late_timer_wake_admits_one_backup_not_a_catchup_burst() {
    let f = Fixture::new(5); let p = Probe::new(&[0; 5]); let c = config(ConsistencyLevel::One, 5);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); f.advance(50);
    for _ in 0..4 { assert!(poll(run.as_mut(), &w).is_pending()); }
    assert_eq!(p.calls(), [0, 1]);
    f.advance(10); assert!(poll(run.as_mut(), &w).is_pending());
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0, 1, 2]);
    drop(run); assert_eq!(p.active(), 0);
}

#[test]
fn zero_delay_admits_one_speculative_attempt_per_poll_with_bounded_capacity() {
    let f = Fixture::new(5); let p = Probe::new(&[0; 5]);
    let mut c = config(ConsistencyLevel::One, 2); c.hedge_delay = std::time::Duration::ZERO;
    let (counter, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0]);
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0, 1]);
    let before = counter.0.load(Ordering::SeqCst);
    for _ in 0..3 { assert!(poll(run.as_mut(), &w).is_pending()); }
    assert_eq!(counter.0.load(Ordering::SeqCst), before);
    assert_eq!(p.peak.load(Ordering::SeqCst), 2); drop(run); assert_eq!(p.active(), 0);
}

#[test]
fn impossible_all_quorum_does_not_dispatch_the_rest_of_the_plan() {
    let f = Fixture::new(4); let p = Probe::new(&[2, 1, 1, 1]); let c = config(ConsistencyLevel::All, 2);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0]); assert_eq!(successes(&result), 0); assert_eq!(p.active(), 0);
    assert_eq!(result.eligible_replicas, 4); assert_eq!(result.symbols_attempted, 4);
    assert_eq!(kind(&result, 1), ErrorKind::QuorumNotReached);
}

#[test]
fn replica_failures_never_lower_the_original_quorum_threshold() {
    let f = Fixture::new(5); let p = Probe::new(&[2, 2, 2, 1, 1]); let c = config(ConsistencyLevel::Quorum, 5);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0, 1, 2]); assert_eq!(result.eligible_replicas, 5);
    assert_eq!(successes(&result), 0); assert_eq!(kind(&result, 4), ErrorKind::QuorumNotReached);
}

#[test]
fn invalid_acknowledgements_cannot_establish_early_quorum() {
    for invalid in [3, 4] {
        let f = Fixture::new(3); let p = Probe::new(&[invalid, 1, 1]); let c = config(ConsistencyLevel::Quorum, 3);
        let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
        assert!(poll(run.as_mut(), &w).is_pending()); let result = done(run.as_mut(), &w);
        assert_eq!(p.calls(), [0, 1, 2]); assert_eq!(successes(&result), 2);
        assert_eq!(kind(&result, 0), ErrorKind::ProtocolError);
    }
}

#[test]
fn cancellation_wakes_parked_owner_and_never_admits_backup() {
    let f = Fixture::new(3); let p = Probe::new(&[0; 3]); let c = config(ConsistencyLevel::One, 3);
    let (counter, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending());
    f.cx.cancel_fast(CancelKind::User); assert!(counter.0.load(Ordering::SeqCst) > 0);
    let result = done(run.as_mut(), &w);
    assert_eq!(p.calls(), [0]); assert_eq!(p.active(), 0);
    for i in 0..3 { assert_eq!(kind(&result, i), ErrorKind::Cancelled); }
    let before = counter.0.load(Ordering::SeqCst); f.advance(1000);
    assert_eq!(counter.0.load(Ordering::SeqCst), before);
}

#[test]
fn external_drop_retires_hedge_timer_and_all_send_owners() {
    let f = Fixture::new(3); let p = Probe::new(&[0; 3]); let c = config(ConsistencyLevel::One, 3);
    let (counter, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); drop(run); assert_eq!(p.active(), 0);
    let before = counter.0.load(Ordering::SeqCst); f.advance(1000); f.cx.cancel_fast(CancelKind::User);
    assert_eq!(counter.0.load(Ordering::SeqCst), before);
}

#[test]
fn zero_concurrency_or_acknowledgement_budget_never_invokes_transport() {
    for c in [config(ConsistencyLevel::One, 0), DistributionConfig {
        ack_timeout: std::time::Duration::ZERO, ..config(ConsistencyLevel::All, 3)
    }] {
        let f = Fixture::new(3); let p = Probe::new(&[1; 3]); let (_, w) = waker();
        let mut run = Box::pin(f.run(&c, &p)); let result = done(run.as_mut(), &w);
        assert!(p.calls().is_empty()); assert_eq!(result.symbols_attempted, 0); assert_eq!(successes(&result), 0);
    }
}

#[test]
fn local_consistency_and_empty_nonlocal_plans_do_not_dispatch() {
    let f = Fixture::new(3); let p = Probe::new(&[1; 3]); let c = config(ConsistencyLevel::Local, 3);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert_eq!(done(run.as_mut(), &w).symbols_attempted, 0); assert!(p.calls().is_empty());
    let f = Fixture::new(0); let c = config(ConsistencyLevel::All, 3); let mut run = Box::pin(f.run(&c, &p));
    let result = done(run.as_mut(), &w); assert_eq!(result.eligible_replicas, 0); assert_eq!(successes(&result), 0);
}

#[test]
fn duplicate_input_identities_do_not_create_primary_votes() {
    let mut f = Fixture::new(2); f.replicas.insert(1, f.replicas[0].clone());
    let p = Probe::new(&[1, 0]); let c = config(ConsistencyLevel::Quorum, 3);
    let (_, w) = waker(); let mut run = Box::pin(f.run(&c, &p));
    assert!(poll(run.as_mut(), &w).is_pending()); assert_eq!(p.calls(), [0, 1]);
    f.advance(100); let result = done(run.as_mut(), &w);
    assert_eq!(result.eligible_replicas, 2); assert_eq!(successes(&result), 1);
}

#[test]
fn ready_only_without_timer_remains_supported_but_pending_fails_closed() {
    for modes in [[1, 1, 1], [0, 0, 0]] {
        let f = Fixture::new(3); let p = Probe::new(&modes);
        let mut c = config(ConsistencyLevel::One, 3); c.ack_timeout = std::time::Duration::from_secs(10);
        let assignments = SymbolDistributor::compute_assignments_with_auth(&f.encoded, &f.replicas, &f.auth, None);
        let result = futures_lite::future::block_on(super::super::run(&c, &f.cx, &f.encoded, assignments, &p, &f.auth, None));
        if modes[0] == 1 { assert_eq!(p.calls(), [0]); assert_eq!(successes(&result), 1); }
        else { for i in 0..3 { assert_eq!(kind(&result, i), ErrorKind::ConfigError); } }
        assert_eq!(p.active(), 0);
    }
}

#[test]
fn transport_panic_propagates_and_drops_other_admitted_futures() {
    let f = Fixture::new(3); let p = Probe::new(&[0, 5, 1]); let c = config(ConsistencyLevel::Quorum, 3);
    let (_, w) = waker();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut run = Box::pin(f.run(&c, &p)); let _ = poll(run.as_mut(), &w);
    }));
    assert!(result.is_err()); assert_eq!(p.active(), 0); assert_eq!(p.calls(), [0, 1]);
}
