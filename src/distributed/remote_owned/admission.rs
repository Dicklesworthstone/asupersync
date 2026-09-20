//! Shared outbound admission for checked, region-owned remote invocations.
//!
//! Bounds are charged before region admission and retained by both the calling
//! scope and its actual proxy task. Cancelling or dropping the caller cannot
//! release capacity while the proxy is still collecting the remote terminal.
//! Waiting is explicitly opt-in; no retry, route discovery, or transport is added.

use super::{RemoteRunConfig, RemoteRunError, RemoteRunReport, run_admitted};
use crate::cx::Cx;
use crate::remote::{ComputationName, NodeId, RemoteInput};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Whole-executor limits. Zero deliberately denies the corresponding admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteAdmissionLimits {
    /// Maximum number of configured logical peer entries, including duplicates.
    pub max_peers: usize,
    /// Total admitted invocations, including region admission and cancellation drain.
    pub max_in_flight: usize,
    /// Sum of original request payload lengths for admitted invocations.
    pub max_input_bytes: usize,
}

/// Per-logical-destination limits, independent of the aggregate ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemotePeerLimits {
    /// Concurrent invocations for this peer, including cleanup.
    pub max_in_flight: usize,
    /// Aggregate charged request payload bytes for this peer.
    pub max_input_bytes: usize,
    /// Maximum payload bytes in one request; zero still permits empty requests.
    pub max_request_bytes: usize,
}

/// Logical charges, not exact heap usage, buffered responses, or wire bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RemoteAdmissionUsage {
    /// Invocations whose scope or proxy still retains admission ownership.
    pub in_flight: usize,
    /// Original request bytes retained as a charge until both owners retire.
    pub input_bytes: usize,
}

/// Payload-free refusal before any remote dispatch or child-region admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteAdmissionError {
    /// A peer label is empty or exceeds 255 UTF-8 bytes.
    #[error("invalid remote admission peer label")]
    InvalidPeer,
    /// Repeated destinations cannot overwrite an earlier admission policy.
    #[error("duplicate remote admission peer")]
    DuplicatePeer,
    /// The bounded configuration iterator supplied too many entries.
    #[error("remote admission peer configuration limit exceeded")]
    PeerLimit,
    /// Configuration storage could not be reserved.
    #[error("remote admission allocation failed")]
    Allocation,
    /// Only explicitly configured logical destinations may use this executor.
    #[error("remote admission peer is not configured")]
    UnknownPeer,
    /// The single-request payload limit was exceeded.
    #[error("remote request payload exceeds its admission limit")]
    RequestBytes,
    /// The destination has exhausted its invocation allowance.
    #[error("remote peer invocation limit reached")]
    PeerInFlight,
    /// The destination has exhausted its original-payload byte allowance.
    #[error("remote peer payload byte limit reached")]
    PeerBytes,
    /// All destinations share this aggregate invocation allowance.
    #[error("remote aggregate invocation limit reached")]
    TotalInFlight,
    /// All destinations share this aggregate original-payload byte allowance.
    #[error("remote aggregate payload byte limit reached")]
    TotalBytes,
    /// Admission has been explicitly closed; existing invocations still drain.
    #[error("remote executor admission is closed")]
    Closed,
    /// An explicitly enabled queue has an earlier eligible or same-peer waiter.
    #[error("remote admission is reserved for queued work")]
    Queued,
}

/// Admission refusal or the existing owned-execution setup failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteExecutorError {
    /// No invocation was started.
    #[error(transparent)]
    Admission(#[from] RemoteAdmissionError),
    /// Admission credit is returned on an execution-setup failure.
    #[error(transparent)]
    Run(#[from] RemoteRunError),
}

struct State {
    total: RemoteAdmissionUsage,
    peers: Vec<RemoteAdmissionUsage>,
    closed: bool,
    queue: Option<queue::QueueState>,
}
struct Shared {
    limits: RemoteAdmissionLimits,
    index: BTreeMap<NodeId, usize>,
    peers: Vec<RemotePeerLimits>,
    state: Mutex<State>,
    queue_notify: Option<crate::sync::Notify>,
}
impl Shared {
    fn notify_queue(&self) {
        if let Some(notify) = &self.queue_notify {
            // Notify already isolates its fanout. During another unwind, do not
            // turn a hostile wake callback into a double-panic process abort.
            if std::thread::panicking() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| notify.notify_waiters()));
            } else {
                notify.notify_waiters();
            }
        }
    }
}

/// Cloneable, bounded admission in front of the existing `run_remote` workflow.
///
/// Every clone shares global and per-destination counters. Peer labels configure
/// admission only; they neither grant remote authority nor select addresses or
/// certificates. The caller's Cx still supplies the authenticated RemoteRuntime.
/// Aliases for the same physical peer have separate logical quotas, so provision
/// labels accordingly. Separately constructed executors have separate budgets.
/// Direct `run_remote` / `spawn_remote` calls do not acquire this opt-in budget.
///
/// The existing constructor/run refuse saturation. `new_queued` and `reserve`
/// opt into bounded waiting on these SAME counters; no hidden queue is created.
/// Cancellation and terminal collection do not require another admission credit.
/// Charged payload size excludes caller copies, serialization expansion, replies,
/// task/region metadata and backend buffers; retain the backend's own limits.
#[derive(Clone)]
pub struct RemoteExecutor {
    shared: Arc<Shared>,
}

impl fmt::Debug for RemoteExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("RemoteExecutor")
            .field("configured_peers", &self.shared.peers.len())
            .field("usage", &state.total)
            .field("closed", &state.closed)
            .finish_non_exhaustive()
    }
}

impl RemoteExecutor {
    /// Provision a bounded fixed peer set without acquiring network authority.
    /// Invalid entries and duplicates fail, rather than replacing earlier limits.
    pub fn new<I>(limits: RemoteAdmissionLimits, peers: I) -> Result<Self, RemoteAdmissionError>
    where
        I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        let mut index = BTreeMap::new();
        let mut policies = Vec::new();
        let mut usage = Vec::new();
        for (node, policy) in peers {
            if policies.len() >= limits.max_peers { return Err(RemoteAdmissionError::PeerLimit); }
            if node.as_str().is_empty() || node.as_str().len() > 255 {
                return Err(RemoteAdmissionError::InvalidPeer);
            }
            if index.contains_key(&node) { return Err(RemoteAdmissionError::DuplicatePeer); }
            policies.try_reserve(1).map_err(|_| RemoteAdmissionError::Allocation)?;
            usage.try_reserve(1).map_err(|_| RemoteAdmissionError::Allocation)?;
            index.insert(node, policies.len());
            policies.push(policy);
            usage.push(RemoteAdmissionUsage::default());
        }
        Ok(Self { shared: Arc::new(Shared { limits, index, peers: policies,
            state: Mutex::new(State { total: RemoteAdmissionUsage::default(), peers: usage, closed: false, queue: None }),
            queue_notify: None,
        }) })
    }

    /// Current aggregate charges, including cancelled or abandoned calls still draining.
    #[must_use]
    pub fn usage(&self) -> RemoteAdmissionUsage { self.shared.state.lock().total }

    /// Current charges for one configured logical peer; unknown labels return None.
    #[must_use]
    pub fn peer_usage(&self, node: &NodeId) -> Option<RemoteAdmissionUsage> {
        let &index = self.shared.index.get(node)?;
        Some(self.shared.state.lock().peers[index])
    }

    /// Permanently refuse later admissions through every clone. Does not cancel
    /// current invocations or issued reservations. Queued callers wake to refusal.
    /// Their waiting bytes remain accounted until those futures retire.
    pub fn close_admission(&self) -> bool {
        let changed = {
            let mut state = self.shared.state.lock();
            !std::mem::replace(&mut state.closed, true)
        };
        if changed { self.shared.notify_queue(); }
        changed
    }

    fn acquire(&self, node: &NodeId, bytes: usize) -> Result<Permit, RemoteAdmissionError> {
        let &index = self.shared.index.get(node).ok_or(RemoteAdmissionError::UnknownPeer)?;
        let policy = self.shared.peers[index];
        if bytes > policy.max_request_bytes { return Err(RemoteAdmissionError::RequestBytes); }
        let mut state = self.shared.state.lock();
        if state.closed { return Err(RemoteAdmissionError::Closed); }
        if queue::blocks_immediate(&self.shared, &state, index) {
            return Err(RemoteAdmissionError::Queued);
        }
        charge(&self.shared, &mut state, index, bytes)
    }

    /// Acquire shared admission on the FIRST poll, before opening a child region,
    /// then execute the same checked proxy as `run_remote`. The original input is
    /// caller-owned; rejected calls do not copy or dispatch it. No retry is added.
    ///
    /// Credit remains until both the caller's scope and proxy future are destroyed.
    /// Thus external future drop cannot free a slot while its region-owned proxy
    /// awaits remote terminal collection. Ordinary completion retains credit
    /// through child-region/finalizer close. Transport failure can still leave
    /// remote effects unknown, and forced proxy destruction is only local cleanup.
    pub async fn run(
        &self, cx: &Cx, node: NodeId, computation: ComputationName, input: RemoteInput,
        config: RemoteRunConfig,
    ) -> Result<RemoteRunReport, RemoteExecutorError> {
        if cx.is_cancel_requested() { return Err(RemoteRunError::Cancelled.into()); }
        let permit = self.acquire(&node, input.len())?;
        Ok(run_admitted(cx, node, computation, input, config, Some(permit)).await?)
    }
}

fn next_usage(limits: RemoteAdmissionLimits, policy: RemotePeerLimits,
    total: RemoteAdmissionUsage, peer: RemoteAdmissionUsage, bytes: usize,
) -> Result<(RemoteAdmissionUsage, RemoteAdmissionUsage), RemoteAdmissionError> {
    let next_peer = RemoteAdmissionUsage {
        in_flight: peer.in_flight.checked_add(1).filter(|n| *n <= policy.max_in_flight)
            .ok_or(RemoteAdmissionError::PeerInFlight)?,
        input_bytes: peer.input_bytes.checked_add(bytes).filter(|n| *n <= policy.max_input_bytes)
            .ok_or(RemoteAdmissionError::PeerBytes)?,
    };
    let next_total = RemoteAdmissionUsage {
        in_flight: total.in_flight.checked_add(1).filter(|n| *n <= limits.max_in_flight)
            .ok_or(RemoteAdmissionError::TotalInFlight)?,
        input_bytes: total.input_bytes.checked_add(bytes).filter(|n| *n <= limits.max_input_bytes)
            .ok_or(RemoteAdmissionError::TotalBytes)?,
    };
    Ok((next_peer, next_total))
}

fn charge(shared: &Arc<Shared>, state: &mut State, index: usize, bytes: usize)
    -> Result<Permit, RemoteAdmissionError>
{
    let (next_peer, next_total) = next_usage(shared.limits, shared.peers[index], state.total, state.peers[index], bytes)?;
    let permit = Permit { _charge: Arc::new(Charge { shared: Arc::clone(shared), index, bytes }) };
    state.peers[index] = next_peer;
    state.total = next_total;
    Ok(permit)
}

// Clones are two references to ONE charge, not new admissions. Root ownership
// covers local close; the task copy covers an abandoned caller's pending drain.
#[derive(Clone)]
pub(super) struct Permit { _charge: Arc<Charge> }
struct Charge { shared: Arc<Shared>, index: usize, bytes: usize }
impl Drop for Charge {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock();
            state.total.in_flight -= 1;
            state.total.input_bytes -= self.bytes;
            state.peers[self.index].in_flight -= 1;
            state.peers[self.index].input_bytes -= self.bytes;
        }
        self.shared.notify_queue();
    }
}

#[cfg(test)]
mod tests;

mod service;
pub use service::RemoteServiceAdmission;

mod queue;
pub use queue::{RemotePriority, RemotePriorityPolicy, RemoteQueueLimits, RemoteQueueUsage,
    RemoteReservation, RemoteReserveError};
