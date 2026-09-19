//! Bounded network collection and authenticated snapshot reconstruction.
//!
//! Plans and snapshot provenance are caller-trusted metadata, not discovered from
//! whichever peer answers first. This does not apply a snapshot to a live region,
//! resurrect futures, elect an authority, or prove disk durability.

use super::{RemoteSymbolError, RemoteSymbolTransport, SymbolBatchKey};
use crate::cx::Cx;
use crate::distributed::recovery::{RecoveryDecodingConfig, StateDecoder};
use crate::distributed::snapshot::RegionSnapshot;
use crate::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::symbol::{ObjectId, ObjectParams};
use crate::types::{RegionId, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

/// A locally authorized replica and the exact immutable batch expected from it.
#[derive(Debug, Clone)]
pub struct ReplicaFetch {
    /// Must name a provisioned transport route, never an untrusted address.
    pub replica_id: String,
    /// Object and canonical batch digest retained in the caller's metadata.
    pub key: SymbolBatchKey,
}

/// Independent network-work and retained-collection limits. No unbounded default.
#[derive(Debug, Clone, Copy)]
pub struct RemoteRecoveryConfig {
    /// Maximum input plan length, including invalid or repeated entries.
    pub max_replicas: usize,
    /// Concurrent fetch futures, additionally limited by shared transport admission.
    pub max_concurrent_requests: usize,
    /// Distinct successful replica responses required; never reduced by failure.
    pub required_replicas: usize,
    /// Total collection and, for `recover_snapshot`, decode budget.
    pub recovery_timeout: Duration,
    /// Individual deadline starting at admission, not while waiting in the plan.
    pub replica_timeout: Duration,
    /// Total symbols received, INCLUDING duplicates across successful replicas.
    pub max_received_symbols: usize,
    /// Total received payload bytes, INCLUDING duplicates across replicas.
    pub max_received_payload_bytes: usize,
}

/// Payload-free failure classification for a contacted replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaFetchFailureKind {
    /// This fetch exceeded its per-admission deadline.
    Deadline,
    /// Shared transport admission was exhausted by another caller.
    Admission,
    /// Authentication, exact digest or batch structure was invalid.
    InvalidBatch,
    /// The authenticated service refused the request.
    Refused,
    /// Connection or service exchange failed.
    Transport,
    /// Route/protocol configuration was invalid.
    Configuration,
    /// The transport's owner was cancelled.
    Cancelled,
}

/// Failure attributed to the plan entry, never to a remote diagnostic string.
#[derive(Debug, Clone)]
pub struct ReplicaFetchFailure {
    /// Locally configured replica label.
    pub replica_id: String,
    /// Redacted failure kind.
    pub kind: ReplicaFetchFailureKind,
}

/// No partial successful collection or snapshot escapes these refusals.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteRecoveryError {
    /// Empty, repeated, mixed-object, unknown-route or impossible-quorum plan.
    #[error("invalid remote recovery plan or limits")]
    Configuration,
    /// An explicit count, payload or decode ceiling was exceeded.
    #[error("remote recovery exceeds its {0} limit")]
    Limit(&'static str),
    /// Bounded bookkeeping allocation failed.
    #[error("remote recovery allocation failed")]
    Allocation,
    /// No explicit timer authority is attached to the owning context.
    #[error("remote recovery requires an explicit context timer driver")]
    NoTimer,
    /// The owning context requested cancellation.
    #[error("remote recovery cancelled")]
    Cancelled,
    /// The whole recovery deadline was reached.
    #[error("remote recovery deadline exceeded")]
    Deadline,
    /// The same symbol identity carried conflicting authenticated data or tags.
    #[error("conflicting replica symbol identity")]
    Conflict,
    /// Too few distinct successful replicas; the configured denominator is fixed.
    #[error("remote recovery received {received} replicas but requires {required}")]
    Quorum {
        /// Required distinct successful responses.
        required: usize,
        /// Actual distinct successful responses.
        received: usize,
        /// Per-replica failures in plan order.
        failures: Vec<ReplicaFetchFailure>,
    },
    /// RaptorQ decode or reconstructed snapshot authentication failed.
    #[error("remote snapshot decoding or authentication failed")]
    Decode,
    /// A signed snapshot did not match the exact caller-authorized provenance.
    #[error("remote snapshot provenance does not match the recovery plan")]
    SnapshotIdentity,
}

/// Exact locally authorized snapshot branch, generation-safe region, and sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotIdentity {
    /// Includes both arena slot and generation.
    pub region_id: RegionId,
    /// Snapshot authority incarnation.
    pub origin_id: u64,
    /// Authority branch epoch.
    pub epoch: u64,
    /// Exact sequence, not just a lower bound chosen by a responding peer.
    pub sequence: u64,
}

/// Bounds applied before allocating the existing RaptorQ decoder.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotDecodeLimits {
    /// Maximum reconstructed authenticated snapshot encoding.
    pub max_snapshot_bytes: usize,
    /// Maximum source symbols per block; bounds the decoder's block dimension.
    pub max_source_symbols_per_block: u16,
    /// Maximum source blocks; the protocol additionally caps this at 256.
    pub max_source_blocks: u16,
}

/// Fully collected unique symbols with deterministic order and replica accounting.
///
/// Symbol values are not printed by Debug. Memory for active fetch frames and
/// decoded replies is separately bounded per transport call; this collection's
/// symbol/payload bounds include duplicates before deduplication. These are not
/// allocator/RSS bounds, nor do they include caller-retained returned values.
pub struct RecoveredSymbols {
    object_id: ObjectId,
    symbols: Vec<AuthenticatedSymbol>,
    responding_replicas: Vec<String>,
    failures: Vec<ReplicaFetchFailure>,
    duration: Duration,
}

impl fmt::Debug for RecoveredSymbols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredSymbols").field("symbols", &self.symbols.len())
            .field("responding_replicas", &self.responding_replicas.len())
            .field("failed_replicas", &self.failures.len()).finish_non_exhaustive()
    }
}

impl RecoveredSymbols {
    /// Unique symbols in canonical (block, ESI) order.
    pub fn symbols(&self) -> &[AuthenticatedSymbol] { &self.symbols }
    /// Distinct successful replicas in plan order, including redundant copies.
    pub fn responding_replicas(&self) -> &[String] { &self.responding_replicas }
    /// Per-replica refusals in plan order.
    pub fn failures(&self) -> &[ReplicaFetchFailure] { &self.failures }
    /// Collection duration on the owner's timer source.
    pub const fn duration(&self) -> Duration { self.duration }

    /// Reverify symbol tags, decode with the existing RaptorQ pipeline, authenticate
    /// the snapshot, and check exact caller-provided provenance. No region mutates.
    /// The explicit symbol and snapshot keys are independent. This synchronous
    /// decode cannot be preempted inside a poll; bound its block dimensions.
    pub fn decode_snapshot(
        &self, params: ObjectParams, expected: SnapshotIdentity, limits: SnapshotDecodeLimits,
        symbol_key: &AuthKey, snapshot_key: &AuthKey,
    ) -> Result<RegionSnapshot, RemoteRecoveryError> {
        validate_decode(params, limits)?;
        if params.object_id != self.object_id { return Err(RemoteRecoveryError::SnapshotIdentity); }
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
            verify_integrity: true,
            auth_context: Some(SecurityContext::new(symbol_key.clone())),
            snapshot_auth_key: Some(snapshot_key.clone()),
            max_decode_attempts: 1,
            allow_partial_decode: false,
        });
        for symbol in &self.symbols {
            decoder.add_symbol(symbol).map_err(|_| RemoteRecoveryError::Decode)?;
        }
        let snapshot = decoder.decode_snapshot(&params).map_err(|_| RemoteRecoveryError::Decode)?;
        if (snapshot.region_id, snapshot.origin_id, snapshot.epoch, snapshot.sequence)
            != (expected.region_id, expected.origin_id, expected.epoch, expected.sequence)
        { return Err(RemoteRecoveryError::SnapshotIdentity); }
        Ok(snapshot)
    }
}

fn validate_decode(params: ObjectParams, limits: SnapshotDecodeLimits) -> Result<(), RemoteRecoveryError> {
    if params.object_size == 0 || params.symbol_size == 0 || params.symbols_per_block == 0
        || params.source_blocks == 0 || params.source_blocks > 256
    { return Err(RemoteRecoveryError::Configuration); }
    if params.object_size > u64::try_from(limits.max_snapshot_bytes).unwrap_or(u64::MAX)
        || params.symbols_per_block > limits.max_source_symbols_per_block
        || params.source_blocks > limits.max_source_blocks
    { return Err(RemoteRecoveryError::Limit("snapshot decode")); }
    let block_bytes = u64::from(params.symbol_size) * u64::from(params.symbols_per_block);
    if params.object_size.div_ceil(block_bytes) != u64::from(params.source_blocks) {
        return Err(RemoteRecoveryError::Configuration);
    }
    Ok(())
}

impl RemoteSymbolTransport {
    /// Fetch every planned replica with bounded parallelism and per-admission
    /// deadlines. A slow first peer cannot prevent later peers from progressing.
    /// Success requires the fixed distinct-replica threshold. No automatic retry,
    /// ambient discovery, partial-success downgrade or detached work is added.
    /// All owned fetch futures/timers are destroyed before any result is returned.
    pub async fn collect_symbols(
        &self, requests: &[ReplicaFetch], mut config: RemoteRecoveryConfig,
    ) -> Result<RecoveredSymbols, RemoteRecoveryError> {
        if self.cx.is_cancel_requested() { return Err(RemoteRecoveryError::Cancelled); }
        validate_plan(requests, config)?;
        if requests.iter().any(|request| !self.routes.contains_key(&request.replica_id)) {
            return Err(RemoteRecoveryError::Configuration);
        }
        config.max_concurrent_requests = config.max_concurrent_requests.min(self.max_in_flight());
        if config.max_concurrent_requests == 0 { return Err(RemoteRecoveryError::Limit("transport admission")); }
        let timer = self.cx.timer_driver().ok_or(RemoteRecoveryError::NoTimer)?;
        collect(&self.cx, requests, config, timer, |replica, key| Box::pin(self.fetch_symbols(replica, key))).await
    }

    /// Complete the network-to-authenticated-snapshot journey, without applying it.
    /// Decode limits and trusted metadata are checked before any network request.
    /// The whole deadline is rechecked after synchronous decoding; it does not
    /// preempt CPU work or assert arbitrary-future/remote-quiescence guarantees.
    pub async fn recover_snapshot(
        &self, requests: &[ReplicaFetch], config: RemoteRecoveryConfig,
        params: ObjectParams, expected: SnapshotIdentity, decode_limits: SnapshotDecodeLimits,
        snapshot_key: &AuthKey,
    ) -> Result<RegionSnapshot, RemoteRecoveryError> {
        validate_decode(params, decode_limits)?;
        if requests.iter().any(|request| request.key.object_id != params.object_id) {
            return Err(RemoteRecoveryError::SnapshotIdentity);
        }
        let timer = self.cx.timer_driver().ok_or(RemoteRecoveryError::NoTimer)?;
        let deadline = timer.now() + config.recovery_timeout;
        let symbols = self.collect_symbols(requests, config).await?;
        if self.cx.is_cancel_requested() { return Err(RemoteRecoveryError::Cancelled); }
        if timer.now() >= deadline { return Err(RemoteRecoveryError::Deadline); }
        let result = symbols.decode_snapshot(params, expected, decode_limits, &self.auth_key, snapshot_key);
        if self.cx.is_cancel_requested() { return Err(RemoteRecoveryError::Cancelled); }
        if timer.now() >= deadline { return Err(RemoteRecoveryError::Deadline); }
        result
    }
}

fn validate_plan(requests: &[ReplicaFetch], config: RemoteRecoveryConfig) -> Result<(), RemoteRecoveryError> {
    if requests.len() > config.max_replicas { return Err(RemoteRecoveryError::Limit("replicas")); }
    if requests.is_empty() || config.max_concurrent_requests == 0 || config.required_replicas == 0
        || config.required_replicas > requests.len() || config.recovery_timeout.is_zero() || config.replica_timeout.is_zero()
    { return Err(RemoteRecoveryError::Configuration); }
    let object = requests[0].key.object_id;
    let mut seen = BTreeSet::new();
    for request in requests {
        if !super::super::valid_identity(&request.replica_id) || request.key.object_id != object
            || !seen.insert(request.replica_id.as_str())
        { return Err(RemoteRecoveryError::Configuration); }
    }
    Ok(())
}

type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<AuthenticatedSymbol>, RemoteSymbolError>> + Send + 'a>>;
struct Attempt<'a> { index: usize, future: FetchFuture<'a>, deadline: Time, timer: Pin<Box<Sleep>> }

fn failure_kind(error: &RemoteSymbolError) -> ReplicaFetchFailureKind {
    match error {
        RemoteSymbolError::Admission => ReplicaFetchFailureKind::Admission,
        RemoteSymbolError::Batch(_) => ReplicaFetchFailureKind::InvalidBatch,
        RemoteSymbolError::Refused => ReplicaFetchFailureKind::Refused,
        RemoteSymbolError::Cancelled => ReplicaFetchFailureKind::Cancelled,
        RemoteSymbolError::Client(_) => ReplicaFetchFailureKind::Transport,
        RemoteSymbolError::Configuration | RemoteSymbolError::UnknownReplica => ReplicaFetchFailureKind::Configuration,
    }
}

async fn collect<'a, F>(
    cx: &Cx, requests: &'a [ReplicaFetch], config: RemoteRecoveryConfig, driver: TimerDriverHandle, fetch: F,
) -> Result<RecoveredSymbols, RemoteRecoveryError>
where F: Fn(&'a str, SymbolBatchKey) -> FetchFuture<'a>,
{
    validate_plan(requests, config)?;
    let start = driver.now();
    let deadline = start + config.recovery_timeout;
    let mut overall = std::pin::pin!(Sleep::with_timer_driver(deadline, driver.clone()));
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let count = requests.len();
    let capacity = config.max_concurrent_requests.min(count);
    let mut slots: Vec<Option<Attempt<'a>>> = Vec::new();
    slots.try_reserve_exact(capacity).map_err(|_| RemoteRecoveryError::Allocation)?;
    slots.resize_with(capacity, || None);
    let mut states: Vec<Option<Result<(), ReplicaFetchFailureKind>>> = Vec::new();
    states.try_reserve_exact(count).map_err(|_| RemoteRecoveryError::Allocation)?;
    states.resize_with(count, || None);
    let mut unique = BTreeMap::<(u8, u32), AuthenticatedSymbol>::new();
    let (mut next, mut finished, mut received, mut payload) = (0usize, 0usize, 0usize, 0usize);
    let result = poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(RemoteRecoveryError::Cancelled)); }
        if driver.now() >= deadline { return Poll::Ready(Err(RemoteRecoveryError::Deadline)); }
        for slot in &mut slots {
            if slot.is_some() || next == count { continue; }
            if cx.is_cancel_requested() { break; }
            let index = next;
            next += 1;
            let request: &'a ReplicaFetch = &requests[index];
            let attempt_deadline = (driver.now() + config.replica_timeout).min(deadline);
            *slot = Some(Attempt {
                index, future: fetch(&request.replica_id, request.key), deadline: attempt_deadline,
                timer: Box::pin(Sleep::with_timer_driver(attempt_deadline, driver.clone())),
            });
        }
        for slot in &mut slots {
            if cx.is_cancel_requested() { return Poll::Ready(Err(RemoteRecoveryError::Cancelled)); }
            let Some(attempt) = slot.as_mut() else { continue; };
            let reply = if driver.now() >= attempt.deadline {
                Poll::Ready(Err(ReplicaFetchFailureKind::Deadline))
            } else {
                let reply = attempt.future.as_mut().poll(task);
                if driver.now() >= attempt.deadline || (reply.is_pending() && attempt.timer.as_mut().poll(task).is_ready()) {
                    Poll::Ready(Err(ReplicaFetchFailureKind::Deadline))
                } else { reply.map(|result| result.map_err(|error| failure_kind(&error))) }
            };
            if cx.is_cancel_requested() { return Poll::Ready(Err(RemoteRecoveryError::Cancelled)); }
            if let Poll::Ready(reply) = reply {
                let index = attempt.index;
                drop(slot.take()); // Release transport/timer ownership before reuse.
                finished += 1;
                match reply {
                    Err(error) => states[index] = Some(Err(error)),
                    Ok(symbols) if symbols.is_empty() => states[index] = Some(Err(ReplicaFetchFailureKind::InvalidBatch)),
                    Ok(symbols) => {
                        received = match received.checked_add(symbols.len()) {
                            Some(n) if n <= config.max_received_symbols => n,
                            _ => return Poll::Ready(Err(RemoteRecoveryError::Limit("received symbols"))),
                        };
                        for symbol in symbols {
                            payload = match payload.checked_add(symbol.symbol().data().len()) {
                                Some(n) if n <= config.max_received_payload_bytes => n,
                                _ => return Poll::Ready(Err(RemoteRecoveryError::Limit("received payload bytes"))),
                            };
                            if symbol.symbol().id().object_id() != requests[index].key.object_id {
                                return Poll::Ready(Err(RemoteRecoveryError::Conflict));
                            }
                            let id = (symbol.symbol().sbn(), symbol.symbol().esi());
                            if let Some(old) = unique.get(&id) {
                                if old.symbol() != symbol.symbol() || old.tag() != symbol.tag() {
                                    return Poll::Ready(Err(RemoteRecoveryError::Conflict));
                                }
                            } else { unique.insert(id, symbol); }
                        }
                        states[index] = Some(Ok(()));
                    }
                }
            }
        }
        if cx.is_cancel_requested() { return Poll::Ready(Err(RemoteRecoveryError::Cancelled)); }
        if driver.now() >= deadline { return Poll::Ready(Err(RemoteRecoveryError::Deadline)); }
        if finished == count { return Poll::Ready(Ok(())); }
        if next < count && slots.iter().any(Option::is_none) { task.waker().wake_by_ref(); }
        if overall.as_mut().poll(task).is_ready() { Poll::Ready(Err(RemoteRecoveryError::Deadline)) }
        else { Poll::Pending }
    }).await;
    drop(slots); // Also on terminal refusal; external drop owns the same slots.
    result?;
    let mut responding_replicas = Vec::new();
    let mut failures = Vec::new();
    for (request, state) in requests.iter().zip(states) {
        match state.expect("all planned replicas completed") {
            Ok(()) => responding_replicas.push(request.replica_id.clone()),
            Err(kind) => failures.push(ReplicaFetchFailure { replica_id: request.replica_id.clone(), kind }),
        }
    }
    if responding_replicas.len() < config.required_replicas {
        return Err(RemoteRecoveryError::Quorum { required: config.required_replicas, received: responding_replicas.len(), failures });
    }
    Ok(RecoveredSymbols {
        object_id: requests[0].key.object_id, symbols: unique.into_values().collect(), responding_replicas, failures,
        duration: Duration::from_nanos(driver.now().duration_since(start)),
    })
}

#[cfg(test)]
mod tests;
