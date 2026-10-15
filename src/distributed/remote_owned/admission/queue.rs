//! Bounded, cancellation-aware reservations sharing the executor's active quotas.
//!
//! Waiting reserves only bounded metadata and an original-input-byte charge;
//! it starts no task or network operation. FIFO is per logical peer. Across
//! peers the oldest currently feasible head wins, avoiding a blocked peer's
//! head-of-line stall. Explicit priority mode uses FIFO within each peer/class,
//! with admission-count promotion rather than a wall-clock starvation promise.
//! All callbacks run outside the budget lock.

use super::{Permit, RemoteAdmissionError, RemoteAdmissionLimits, RemoteAdmissionUsage,
    RemoteExecutor, RemotePeerLimits, Shared, State, charge, next_usage};
use crate::cx::Cx;
use crate::distributed::remote_owned::{RemoteRunConfig, RemoteRunError, RemoteRunReport, run_admitted};
use crate::remote::{ComputationName, NodeId, RemoteInput};
use crate::sync::Notify;
use crate::time::Sleep;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Independent queued-request limits. Active executions retain their old bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteQueueLimits {
    /// Maximum registered waiters across all peers.
    pub max_waiters: usize,
    /// Sum of declared original input lengths while waiting.
    pub max_input_bytes: usize,
    /// Maximum registered waiters for any one configured peer.
    pub max_waiters_per_peer: usize,
    /// Sum of declared waiting input lengths for any one peer.
    pub max_input_bytes_per_peer: usize,
}

/// Waiting requests only; a delivered reservation moves to active usage.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RemoteQueueUsage {
    /// Registered waiters, including closed/cancelled ones not yet polled/dropped.
    pub waiters: usize,
    /// Declared original input bytes retained as a logical waiting charge.
    pub input_bytes: usize,
}

/// Locally selected application scheduling class, never protocol-control authority.
///
/// These classes share every active and waiting quota. No class can reserve
/// extra capacity, bypass authentication, preempt running work, or impersonate
/// cancellation/renewal traffic. Inbound registration fixes the class locally;
/// never derive it from an untrusted request field without an authorization policy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RemotePriority {
    /// Deferrable application work, still eligible for bounded-bypass promotion.
    Background,
    /// Class used by the existing reserve/run_waiting entry points.
    #[default]
    Normal,
    /// Latency-sensitive application work, not a privileged control lane.
    Urgent,
}

impl RemotePriority {
    const fn index(self) -> usize {
        match self { Self::Background => 0, Self::Normal => 1, Self::Urgent => 2 }
    }
}

/// Explicit scheduling policy for a newly constructed priority-enabled queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemotePriorityPolicy {
    /// After this many other queued admissions, prefer the oldest feasible
    /// promoted head over all ordinary priorities. Zero immediately promotes.
    /// Counts admissions, not polls, completions, bytes, or wall-clock time.
    /// A continuously feasible head cannot be overtaken by younger work after
    /// promotion; older promoted heads may still precede it. Blocked requests,
    /// unpolled selected waiters and indefinitely held permits have no time bound.
    pub max_bypass: usize,
}

/// Typed refusal with no input bytes or peer labels in diagnostics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteReserveError {
    /// The existing quota/configuration policy refused admission.
    #[error(transparent)]
    Admission(#[from] RemoteAdmissionError),
    /// Waiting must be explicitly enabled at executor construction.
    #[error("remote executor has no wait queue")]
    Disabled,
    /// A non-normal class requires explicit priority-mode construction.
    #[error("remote executor has no priority scheduling policy")]
    PriorityDisabled,
    /// Aggregate or per-peer waiting count/bytes cannot fit another request.
    #[error("remote wait queue limit reached: {0}")]
    QueueLimit(&'static str),
    /// Sequence identities never wrap or recycle.
    #[error("remote wait queue sequence exhausted")]
    SequenceExhausted,
    /// A context timer is required even when admission might be immediate.
    #[error("remote reservation requires an explicit context timer")]
    NoTimer,
    /// Caller cancellation is acknowledged before returning this refusal.
    #[error("remote reservation cancelled")]
    Cancelled,
    /// Admission did not complete in the positive caller-selected interval.
    #[error("remote reservation deadline reached")]
    Deadline,
    /// The consumed payload must have exactly the reserved length.
    #[error("remote reservation input length mismatch")]
    InputLength,
    /// Existing execution setup failed after admission; ownership returns credit.
    #[error(transparent)]
    Run(#[from] RemoteRunError),
}

struct Entry { peer: usize, bytes: usize, priority: RemotePriority, bypasses: usize }
struct Peer { usage: RemoteQueueUsage, heads: [Option<u64>; 3] }
pub(super) struct QueueState {
    limits: RemoteQueueLimits,
    entries: BTreeMap<u64, Entry>,
    peers: Vec<Peer>,
    total: RemoteQueueUsage,
    next: u64,
    priority: Option<RemotePriorityPolicy>,
}

impl QueueState {
    fn new(limits: RemoteQueueLimits, peers: usize) -> Result<Self, RemoteAdmissionError> {
        let mut usage = Vec::new();
        usage.try_reserve_exact(peers).map_err(|_| RemoteAdmissionError::Allocation)?;
        usage.resize_with(peers, || Peer { usage: RemoteQueueUsage::default(), heads: [None; 3] });
        Ok(Self { limits, entries: BTreeMap::new(), peers: usage,
            total: RemoteQueueUsage::default(), next: 0, priority: None })
    }

    #[cfg(test)]
    fn insert(&mut self, peer: usize, bytes: usize) -> Result<u64, RemoteReserveError> {
        self.insert_priority(peer, bytes, RemotePriority::Normal)
    }

    fn insert_priority(&mut self, peer: usize, bytes: usize, priority: RemotePriority)
        -> Result<u64, RemoteReserveError>
    {
        if self.priority.is_none() && priority != RemotePriority::Normal {
            return Err(RemoteReserveError::PriorityDisabled);
        }
        let total = queued_next(self.total, bytes, self.limits.max_waiters,
            self.limits.max_input_bytes, "waiters", "input bytes")?;
        let usage = queued_next(self.peers[peer].usage, bytes, self.limits.max_waiters_per_peer,
            self.limits.max_input_bytes_per_peer, "peer waiters", "peer input bytes")?;
        let id = self.next.checked_add(1).ok_or(RemoteReserveError::SequenceExhausted)?;
        self.entries.insert(id, Entry { peer, bytes, priority, bypasses: 0 });
        self.next = id;
        self.total = total;
        self.peers[peer].usage = usage;
        self.peers[peer].heads[priority.index()].get_or_insert(id);
        Ok(id)
    }

    fn admitted(&mut self) {
        if let Some(policy) = self.priority {
            // One bounded pass per queued admission. Saturation preserves the
            // promotion predicate even at usize::MAX; polling does not age work.
            for entry in self.entries.values_mut() {
                entry.bypasses = entry.bypasses.saturating_add(1).min(policy.max_bypass);
            }
        }
    }

    fn remove(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            self.total.waiters -= 1;
            self.total.input_bytes -= entry.bytes;
            self.peers[entry.peer].usage.waiters -= 1;
            self.peers[entry.peer].usage.input_bytes -= entry.bytes;
            let head = &mut self.peers[entry.peer].heads[entry.priority.index()];
            if *head == Some(id) {
                *head = self.entries.iter()
                    .find(|(_, next)| next.peer == entry.peer && next.priority == entry.priority)
                    .map(|(&next, _)| next);
            }
        }
    }
}

fn queued_next(current: RemoteQueueUsage, bytes: usize, count_limit: usize,
    byte_limit: usize, count_name: &'static str, byte_name: &'static str,
) -> Result<RemoteQueueUsage, RemoteReserveError> {
    Ok(RemoteQueueUsage {
        waiters: current.waiters.checked_add(1).filter(|n| *n <= count_limit)
            .ok_or(RemoteReserveError::QueueLimit(count_name))?,
        input_bytes: current.input_bytes.checked_add(bytes).filter(|n| *n <= byte_limit)
            .ok_or(RemoteReserveError::QueueLimit(byte_name))?,
    })
}

// One bounded ordered scan. Ordinary queues retain their per-peer FIFO; explicit
// priority queues have one FIFO head per peer/class. Promoted heads outrank every
// ordinary class, in enrollment order. Capacity is always checked independently.
fn selected(shared: &Shared, state: &State) -> Option<u64> {
    let queue = state.queue.as_ref()?;
    let mut candidate = None;
    for (&id, entry) in &queue.entries {
        if queue.peers[entry.peer].heads[entry.priority.index()] != Some(id)
            || next_usage(shared.limits, shared.peers[entry.peer], state.total,
                state.peers[entry.peer], entry.bytes).is_err()
        { continue; }
        let Some(policy) = queue.priority else { return Some(id); };
        if entry.bypasses >= policy.max_bypass { return Some(id); }
        if candidate.is_none_or(|(_, priority)| entry.priority > priority) {
            candidate = Some((id, entry.priority));
        }
    }
    candidate.map(|(id, _)| id)
}

pub(super) fn blocks_immediate(shared: &Shared, state: &State, peer: usize) -> bool {
    state.queue.as_ref().is_some_and(|queue| {
        queue.peers[peer].heads.iter().any(Option::is_some) || selected(shared, state).is_some()
    })
}

/// Non-cloneable reservation for exactly one peer and original input length.
///
/// Not a runtime obligation or remote capability. Holding it consumes active
/// quota even before execution; dropping it returns that quota. Existing issued
/// reservations remain valid after close_admission, just like admitted calls.
/// Execute using the original executor's proxy/scope charge, without reacquiring.
#[must_use = "dropping the reservation releases its active quota"]
pub struct RemoteReservation {
    node: NodeId,
    bytes: usize,
    pub(super) permit: Permit,
}
impl fmt::Debug for RemoteReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteReservation").field("input_bytes", &self.bytes).finish_non_exhaustive()
    }
}
impl RemoteReservation {
    /// Exact reserved original payload length, not allocator/wire/response bytes.
    #[must_use]
    pub fn input_bytes(&self) -> usize { self.bytes }

    /// Consume the reservation and run using the existing owned remote workflow.
    /// The execution timeout starts now, separately from the completed queue wait.
    /// No alternate destination can be supplied. Length mismatch never dispatches.
    pub async fn run(self, cx: &Cx, computation: ComputationName, input: RemoteInput,
        config: RemoteRunConfig,
    ) -> Result<RemoteRunReport, RemoteReserveError> {
        if input.len() != self.bytes { return Err(RemoteReserveError::InputLength); }
        Ok(run_admitted(cx, self.node, computation, input, config, Some(self.permit)).await?)
    }
}

struct Ticket { shared: Arc<Shared>, id: Option<u64> }
impl Ticket {
    fn ready(&self) -> bool {
        let state = self.shared.state.lock();
        state.closed || selected(&self.shared, &state) == self.id
    }
    fn claim(&mut self) -> Result<Option<Permit>, RemoteAdmissionError> {
        let mut state = self.shared.state.lock();
        if state.closed { return Err(RemoteAdmissionError::Closed); }
        if selected(&self.shared, &state) != self.id { return Ok(None); }
        let id = self.id.expect("registered ticket");
        let entry = &state.queue.as_ref().expect("enabled queue").entries[&id];
        let (peer, bytes) = (entry.peer, entry.bytes);
        // Allocation precedes count publication; removal contains no callbacks.
        let permit = charge(&self.shared, &mut state, peer, bytes)?;
        let queue = state.queue.as_mut().expect("enabled queue");
        queue.remove(id);
        queue.admitted();
        self.id = None;
        drop(state);
        self.shared.notify_queue();
        Ok(Some(permit))
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.shared.state.lock().queue.as_mut().expect("enabled queue").remove(id);
            self.shared.notify_queue();
        }
    }
}

impl RemoteExecutor {
    /// Opt into bounded waiting. The existing constructor/run still refuse on
    /// saturation; immediate calls on THIS executor share counters and cannot
    /// bypass an eligible waiter or an earlier waiter for the same peer.
    pub fn new_queued<I>(limits: RemoteAdmissionLimits, peers: I, queue: RemoteQueueLimits)
        -> Result<Self, RemoteAdmissionError>
    where I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        let mut executor = Self::new(limits, peers)?;
        let shared = Arc::get_mut(&mut executor.shared).expect("new unique executor");
        shared.state.get_mut().queue = Some(QueueState::new(queue, shared.peers.len())?);
        shared.queue_notify = Some(Notify::new());
        Ok(executor)
    }

    /// Opt into three application priorities plus admission-count promotion.
    /// All classes use the same active and waiting counters. Existing immediate
    /// calls and ordinary reservations on this executor also share that domain.
    /// Same-peer work may overtake across classes, never within one class.
    /// Ordinary new_queued construction retains its original per-peer FIFO.
    pub fn new_prioritized<I>(limits: RemoteAdmissionLimits, peers: I,
        queue: RemoteQueueLimits, priority: RemotePriorityPolicy,
    ) -> Result<Self, RemoteAdmissionError>
    where I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        let mut executor = Self::new_queued(limits, peers, queue)?;
        let shared = Arc::get_mut(&mut executor.shared).expect("new unique executor");
        shared.state.get_mut().queue.as_mut().expect("enabled queue").priority = Some(priority);
        Ok(executor)
    }

    /// Logical waiting charges, independent of usage()'s active reservations.
    #[must_use]
    pub fn queue_usage(&self) -> RemoteQueueUsage {
        self.shared.state.lock().queue.as_ref().map_or(RemoteQueueUsage::default(), |queue| queue.total)
    }

    /// Waiting charges for a configured logical peer; None for unknown peers.
    #[must_use]
    pub fn peer_queue_usage(&self, node: &NodeId) -> Option<RemoteQueueUsage> {
        let &peer = self.shared.index.get(node)?;
        Some(self.shared.state.lock().queue.as_ref()
            .map_or(RemoteQueueUsage::default(), |queue| queue.peers[peer].usage))
    }

    /// Reserve active quota, waiting with independent count/byte bounds when full.
    ///
    /// Enrollment happens on first poll, before any task or network dispatch.
    /// Impossible requests refuse immediately. Cancellation and deadline win
    /// readiness ties and destroy the ticket. Drop removes it without dispatch.
    /// Close wakes waiters to refusal but preserves already-delivered reservations.
    ///
    /// Ordinary queues retain FIFO within a peer, oldest feasible heads across
    /// peers. On a priority-enabled executor this uses Normal. An earlier
    /// byte-heavy head may wait while another peer progresses; no starvation or
    /// wall-clock fairness guarantee is implied. Input stays with the caller;
    /// byte accounting is declared here and checked again by reservation.run.
    /// Predicate-aware notification closes release-before-registration races.
    pub async fn reserve(&self, cx: &Cx, node: &NodeId, bytes: usize, timeout: Duration)
        -> Result<RemoteReservation, RemoteReserveError>
    {
        self.reserve_with_priority(cx, node, bytes, timeout, RemotePriority::Normal).await
    }

    /// Reserve with an explicitly authorized local application priority.
    /// A non-normal priority refuses on an ordinary queue rather than silently
    /// changing its FIFO contract. Priority affects selection only after enqueue;
    /// it never preempts issued reservations, relaxes quotas or extends deadlines.
    pub async fn reserve_with_priority(&self, cx: &Cx, node: &NodeId, bytes: usize,
        timeout: Duration, priority: RemotePriority,
    ) -> Result<RemoteReservation, RemoteReserveError>
    {
        if cx.checkpoint().is_err() { return Err(RemoteReserveError::Cancelled); }
        let notify = self.shared.queue_notify.as_ref().ok_or(RemoteReserveError::Disabled)?;
        if priority != RemotePriority::Normal
            && self.shared.state.lock().queue.as_ref().expect("enabled queue").priority.is_none()
        { return Err(RemoteReserveError::PriorityDisabled); }
        let clock = cx.timer_driver().ok_or(RemoteReserveError::NoTimer)?;
        let now = clock.now();
        let deadline = now + timeout;
        if timeout.is_zero() || deadline <= now { return Err(RemoteReserveError::Deadline); }
        let &peer = self.shared.index.get(node).ok_or(RemoteAdmissionError::UnknownPeer)?;
        let policy = self.shared.peers[peer];
        if bytes > policy.max_request_bytes { return Err(RemoteAdmissionError::RequestBytes.into()); }
        // A request that cannot fit even in an empty executor must never park.
        next_usage(self.shared.limits, policy, RemoteAdmissionUsage::default(),
            RemoteAdmissionUsage::default(), bytes)?;
        if let Ok(permit) = self.acquire(node, bytes) {
            if cx.checkpoint().is_err() { return Err(RemoteReserveError::Cancelled); }
            if clock.now() >= deadline { return Err(RemoteReserveError::Deadline); }
            return Ok(RemoteReservation { node: node.clone(), bytes, permit });
        }
        let mut ticket = Ticket { shared: Arc::clone(&self.shared), id: None };
        {
            let mut state = self.shared.state.lock();
            if state.closed { return Err(RemoteAdmissionError::Closed.into()); }
            ticket.id = Some(state.queue.as_mut().expect("enabled queue").insert_priority(peer, bytes, priority)?);
        }
        let mut cancelled = std::pin::pin!(cx.cancelled());
        let mut timer = std::pin::pin!(Sleep::with_timer_driver(deadline, clock.clone()));
        loop {
            {
                let mut changed = std::pin::pin!(notify.wait_until(|| ticket.ready()));
                poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() {
                        let _ = cx.checkpoint();
                        return Poll::Ready(Err(RemoteReserveError::Cancelled));
                    }
                    if clock.now() >= deadline || timer.as_mut().poll(task).is_ready() {
                        return Poll::Ready(Err(RemoteReserveError::Deadline));
                    }
                    changed.as_mut().poll(task).map(|()| Ok(()))
                }).await?;
            }
            if cx.checkpoint().is_err() { return Err(RemoteReserveError::Cancelled); }
            if clock.now() >= deadline { return Err(RemoteReserveError::Deadline); }
            if let Some(permit) = ticket.claim()? {
                // claim notifies other waiters outside the mutex. Those safe
                // callbacks may cancel this caller or advance its clock before
                // delivery, just as callbacks during immediate admission can.
                if cx.checkpoint().is_err() { return Err(RemoteReserveError::Cancelled); }
                if clock.now() >= deadline { return Err(RemoteReserveError::Deadline); }
                return Ok(RemoteReservation { node: node.clone(), bytes, permit });
            }
        }
    }

    /// Queue and execute without retry. Input is charged while waiting and then
    /// by the single active reservation through the existing proxy/scope drain.
    /// Waiting and execution have separate explicit timeout intervals.
    pub async fn run_waiting(&self, cx: &Cx, node: NodeId, computation: ComputationName,
        input: RemoteInput, wait_timeout: Duration, config: RemoteRunConfig,
    ) -> Result<RemoteRunReport, RemoteReserveError> {
        self.reserve(cx, &node, input.len(), wait_timeout).await?
            .run(cx, computation, input, config).await
    }

    /// Priority-aware counterpart of run_waiting, using the same checked proxy
    /// and scope ownership. Wait and execution budgets remain separate intervals.
    pub async fn run_waiting_with_priority(&self, cx: &Cx, node: NodeId,
        computation: ComputationName, input: RemoteInput, wait_timeout: Duration,
        priority: RemotePriority, config: RemoteRunConfig,
    ) -> Result<RemoteRunReport, RemoteReserveError> {
        self.reserve_with_priority(cx, &node, input.len(), wait_timeout, priority).await?
            .run(cx, computation, input, config).await
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod priority_tests;
