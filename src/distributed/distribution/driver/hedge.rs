//! Opt-in quorum-first fanout, sharing the normal driver's attempt validation.
//!
//! Start the required number of replicas (up to the concurrency ceiling). Replace
//! failed attempts immediately. While sufficient attempts are still pending, add
//! one spare after each hedge interval, never exceeding that same ceiling. Poll
//! existing attempts before a due hedge so an already-ready quorum avoids extra
//! dispatch. Stop at a verified quorum or once the fixed quorum is impossible.
//!
//! All sends and timers are invocation-owned. Cancelling a loser retires local
//! ownership, NOT remote storage, transmitted bytes, or a remote drain protocol.
//! The default non-hedged path still contacts and waits for every eligible replica.

use super::{
    Attempt, Cx, DistributionConfig, DistributorTransport, EncodedState, ErrorKind,
    FanoutResult, Future, Outcome, Pin, Poll, ReplicaAssignment, ReplicaFailure,
    SecurityContext, Sleep, Time, TimerDriverHandle, failure, now, poll_fn,
};
use crate::distributed::distribution::SymbolDistributor;
use crate::record::distributed_region::ConsistencyLevel;

#[derive(Clone, Copy)]
enum Stop {
    Quorum,
    Impossible,
    Cancelled,
    Denied,
}

impl Stop {
    fn failure(self, id: &str, admitted: bool) -> ReplicaFailure {
        let (kind, message) = match (self, admitted) {
            (Self::Quorum, true) => (ErrorKind::Cancelled,
                "hedged quorum achieved; redundant local send retired, delivery may be partial"),
            (Self::Quorum, false) => (ErrorKind::Cancelled,
                "hedged quorum achieved; backup was not admitted"),
            (Self::Impossible, true) => (ErrorKind::QuorumNotReached,
                "fixed replica quorum is unreachable; local send retired, delivery may be partial"),
            (Self::Impossible, false) => (ErrorKind::QuorumNotReached,
                "fixed replica quorum is unreachable; backup was not admitted"),
            (Self::Cancelled, true) => (ErrorKind::Cancelled,
                "hedged distribution cancelled; admitted delivery may be partial"),
            (Self::Cancelled, false) => (ErrorKind::Cancelled,
                "hedged distribution cancelled before replica admission"),
            (Self::Denied, _) => (ErrorKind::AdmissionDenied,
                "distribution concurrency limit is zero"),
        };
        failure(id, kind, message)
    }
}

// The future owns the signed batch but does not invoke even an eager transport
// until Attempt::poll admits the first send. The same acknowledgement and
// deadline checker is used by both hedged and non-hedged execution.
fn admit<'a, T: DistributorTransport>(
    index: usize,
    assignment: &ReplicaAssignment,
    config: &DistributionConfig,
    encoded: &EncodedState,
    transport: &'a T,
    auth: &SecurityContext,
    timer: Option<&TimerDriverHandle>,
) -> Result<Attempt<'a>, ReplicaFailure> {
    let id = &assignment.replica_id;
    let expected_symbols = u32::try_from(assignment.symbol_indices.len()).map_err(|_| {
        failure(id, ErrorKind::DataTooLarge, "assigned symbol count exceeds acknowledgement range")
    })?;
    if config.ack_timeout.is_zero() {
        return Err(failure(id, ErrorKind::DeadlineExceeded,
            "replica acknowledgement budget is zero; no send attempted"));
    }
    let deadline = now(timer) + config.ack_timeout;
    let symbols = assignment.symbol_indices.iter()
        .map(|&index| auth.sign_symbol(&encoded.symbols[index])).collect();
    let send_id = id.clone();
    let future = Box::pin(async move { transport.send_symbols(&send_id, symbols).await });
    let timeout = timer.map(|timer| Box::pin(Sleep::with_timer_driver(deadline, timer.clone())));
    Ok(Attempt {
        index, replica_id: id.clone(), expected_symbols, deadline,
        timeout, future, attempted: false,
    })
}

pub(super) async fn run<T: DistributorTransport>(
    config: &DistributionConfig,
    cx: &Cx,
    encoded: &EncodedState,
    assignments: Vec<ReplicaAssignment>,
    transport: &T,
    auth: &SecurityContext,
    timer: Option<TimerDriverHandle>,
) -> FanoutResult {
    // The caller already filtered empty/unauthorized assignments and duplicate
    // identities. Keep this denominator fixed even for unstarted backups.
    let count = assignments.len();
    let required = if count == 0 && config.consistency != ConsistencyLevel::Local { 1 }
        else { SymbolDistributor::required_acks(config.consistency, count) };
    let capacity = config.max_concurrent.min(count);
    let mut outcomes: Vec<_> = (0..count).map(|_| None).collect();
    let mut slots: Vec<Option<Attempt<'_>>> = (0..capacity).map(|_| None).collect();
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let mut hedge_at: Option<Time> = None;
    let mut hedge_sleep: Option<Pin<Box<Sleep>>> = None;
    let (mut next, mut finished, mut successes) = (0, 0, 0);
    let mut symbols_attempted = 0_u64;

    let stop = poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Stop::Cancelled); }
        if successes >= required { return Poll::Ready(Stop::Quorum); }
        if required - successes > count - finished { return Poll::Ready(Stop::Impossible); }
        if capacity == 0 { return Poll::Ready(Stop::Denied); }

        // Maintain enough live attempts to reach quorum without speculating.
        // Failed attempts free their credit before replacement on a fresh poll.
        let mut active = slots.iter().filter(|slot| slot.is_some()).count();
        let needed = required - successes;
        for slot in &mut slots {
            if active >= needed || next == count { break; }
            if slot.is_some() { continue; }
            if cx.is_cancel_requested() { return Poll::Ready(Stop::Cancelled); }
            let index = next;
            next += 1;
            match admit(index, &assignments[index], config, encoded, transport, auth, timer.as_ref()) {
                Ok(attempt) => {
                    hedge_at.get_or_insert_with(|| now(timer.as_ref()) + config.hedge_delay);
                    *slot = Some(attempt);
                    active += 1;
                }
                Err(error) => {
                    outcomes[index] = Some(Outcome::Err(error));
                    finished += 1;
                    if required - successes > count - finished { return Poll::Ready(Stop::Impossible); }
                }
            }
        }

        // Existing acknowledgements beat a hedge whose delay expires on this
        // turn. Attempt::poll still gives each acknowledgement deadline priority.
        for slot in &mut slots {
            if cx.is_cancel_requested() { return Poll::Ready(Stop::Cancelled); }
            let Some(attempt) = slot.as_mut() else { continue; };
            let was_attempted = attempt.attempted;
            let result = attempt.poll(task, timer.as_ref(), cx);
            if !was_attempted && attempt.attempted {
                symbols_attempted = symbols_attempted.saturating_add(u64::from(attempt.expected_symbols));
            }
            if let Poll::Ready(result) = result {
                let index = attempt.index;
                drop(slot.take());
                outcomes[index] = Some(match result {
                    Ok(ack) => { successes += 1; Outcome::Ok(ack) }
                    Err(error) => Outcome::Err(error),
                });
                finished += 1;
                if successes >= required { return Poll::Ready(Stop::Quorum); }
                if required - successes > count - finished { return Poll::Ready(Stop::Impossible); }
            }
        }
        if cx.is_cancel_requested() { return Poll::Ready(Stop::Cancelled); }
        active = slots.iter().filter(|slot| slot.is_some()).count();
        let spare = active < capacity && next < count;
        if spare && active < required - successes {
            // Immediate replacement is NOT delayed behind speculative hedging.
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        if !spare {
            // No useless expired-timer wake loop when capacity is full. Keep the
            // absolute hedge deadline so later capacity does not restart the delay.
            drop(hedge_sleep.take());
            return Poll::Pending;
        }
        let at = hedge_at.expect("live attempts establish a hedge deadline");
        let due = if now(timer.as_ref()) >= at { true } else {
            let Some(timer) = timer.as_ref() else {
                // A pending Attempt without this timer already fails ConfigError.
                // Never invent an ambient clock registration to rescue it.
                return Poll::Ready(Stop::Impossible);
            };
            let sleep = hedge_sleep.get_or_insert_with(|| Box::pin(Sleep::with_timer_driver(at, timer.clone())));
            sleep.as_mut().poll(task).is_ready()
        };
        if due {
            drop(hedge_sleep.take());
            let index = next;
            next += 1;
            match admit(index, &assignments[index], config, encoded, transport, auth, timer.as_ref()) {
                Ok(attempt) => {
                    *slots.iter_mut().find(|slot| slot.is_none()).expect("spare capacity") = Some(attempt);
                }
                Err(error) => {
                    outcomes[index] = Some(Outcome::Err(error));
                    finished += 1;
                    if required - successes > count - finished { return Poll::Ready(Stop::Impossible); }
                }
            }
            // At most ONE extra replica per interval, even after a late wake.
            // Zero delay admits one per poll, not an unbounded within-poll loop.
            hedge_at = Some(now(timer.as_ref()) + config.hedge_delay);
            task.waker().wake_by_ref();
        }
        Poll::Pending
    }).await;

    // Retire every timer and future BEFORE exposing even a successful result.
    // A completed future may retain resources; a panicking destructor propagates
    // rather than letting cleanup be reported as successful. No lock is held.
    drop(hedge_sleep);
    drop(slots);
    for (index, assignment) in assignments.iter().enumerate() {
        if outcomes[index].is_none() {
            outcomes[index] = Some(Outcome::Err(stop.failure(&assignment.replica_id, index < next)));
        }
    }
    FanoutResult {
        outcomes: outcomes.into_iter().map(|value| value.expect("every plan has an outcome")).collect(),
        symbols_attempted,
        eligible_replicas: count,
    }
}

#[cfg(test)]
mod tests;
