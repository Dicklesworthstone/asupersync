//! Bounded, cancellation-aware reservations sharing the executor's active quotas.
//!
//! Waiting reserves only bounded metadata and an original-input-byte charge;
//! it starts no task or network operation. FIFO is per logical peer. Across
//! peers the oldest currently feasible head wins, avoiding a blocked peer's
//! head-of-line stall. This is not priority scheduling or a starvation bound
//! for differently sized requests. All callbacks run outside the budget lock.

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

struct Entry { peer: usize, bytes: usize }
struct Peer { usage: RemoteQueueUsage, head: Option<u64> }
pub(super) struct QueueState {
    limits: RemoteQueueLimits,
    entries: BTreeMap<u64, Entry>,
    peers: Vec<Peer>,
    total: RemoteQueueUsage,
    next: u64,
}

impl QueueState {
    fn new(limits: RemoteQueueLimits, peers: usize) -> Result<Self, RemoteAdmissionError> {
        let mut usage = Vec::new();
        usage.try_reserve_exact(peers).map_err(|_| RemoteAdmissionError::Allocation)?;
        usage.resize_with(peers, || Peer { usage: RemoteQueueUsage::default(), head: None });
        Ok(Self { limits, entries: BTreeMap::new(), peers: usage,
            total: RemoteQueueUsage::default(), next: 0 })
    }

    fn insert(&mut self, peer: usize, bytes: usize) -> Result<u64, RemoteReserveError> {
        let total = queued_next(self.total, bytes, self.limits.max_waiters,
            self.limits.max_input_bytes, "waiters", "input bytes")?;
        let usage = queued_next(self.peers[peer].usage, bytes, self.limits.max_waiters_per_peer,
            self.limits.max_input_bytes_per_peer, "peer waiters", "peer input bytes")?;
        let id = self.next.checked_add(1).ok_or(RemoteReserveError::SequenceExhausted)?;
        self.entries.insert(id, Entry { peer, bytes });
        self.next = id;
        self.total = total;
        self.peers[peer].usage = usage;
        self.peers[peer].head.get_or_insert(id);
        Ok(id)
    }

    fn remove(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            self.total.waiters -= 1;
            self.total.input_bytes -= entry.bytes;
            self.peers[entry.peer].usage.waiters -= 1;
            self.peers[entry.peer].usage.input_bytes -= entry.bytes;
            if self.peers[entry.peer].head == Some(id) {
                self.peers[entry.peer].head = self.entries.iter()
                    .find(|(_, next)| next.peer == entry.peer).map(|(&next, _)| next);
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

// One bounded ordered scan; a blocked head prevents only later work for its peer.
fn selected(shared: &Shared, state: &State) -> Option<u64> {
    let queue = state.queue.as_ref()?;
    queue.entries.iter().find(|(id, entry)| {
        queue.peers[entry.peer].head == Some(**id)
            && next_usage(shared.limits, shared.peers[entry.peer], state.total,
                state.peers[entry.peer], entry.bytes).is_ok()
    }).map(|(&id, _)| id)
}

pub(super) fn blocks_immediate(shared: &Shared, state: &State, peer: usize) -> bool {
    state.queue.as_ref().is_some_and(|queue| {
        queue.peers[peer].head.is_some() || selected(shared, state).is_some()
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
        state.queue.as_mut().expect("enabled queue").remove(id);
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
    /// FIFO holds within a peer, oldest feasible heads across peers. An earlier
    /// byte-heavy head may wait while another peer progresses; no starvation or
    /// wall-clock fairness guarantee is implied. Input stays with the caller;
    /// byte accounting is declared here and checked again by reservation.run.
    /// Predicate-aware notification closes release-before-registration races.
    pub async fn reserve(&self, cx: &Cx, node: &NodeId, bytes: usize, timeout: Duration)
        -> Result<RemoteReservation, RemoteReserveError>
    {
        if cx.checkpoint().is_err() { return Err(RemoteReserveError::Cancelled); }
        let notify = self.shared.queue_notify.as_ref().ok_or(RemoteReserveError::Disabled)?;
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
            ticket.id = Some(state.queue.as_mut().expect("enabled queue").insert(peer, bytes)?);
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
}

#[cfg(test)]
mod tests;
