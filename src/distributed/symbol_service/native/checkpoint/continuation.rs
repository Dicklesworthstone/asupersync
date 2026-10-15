//! Versioned application-state continuation, not suspended Rust-future restoration.
//!
//! V1 supports one explicitly checkpointed workload in an otherwise empty, open
//! root snapshot. It refuses saved task stacks, child topology, finalizers,
//! cancellation and clock/budget restoration. Code, capabilities, connections and
//! destinations come only from a locally supplied [`RestorableWorkload`]. A valid
//! snapshot signature never selects code or grants a new effect capability.
//!
//! The codec is trusted application code: it must be deterministic, bounded and
//! side-effect free. Its owned state must describe an application checkpoint, not
//! contain live runtime owners. The application establishes the checkpoint's safe
//! effect boundary and idempotency. Replaying saved bytes is not exactly-once
//! execution, rollback, leader election, or restoration of old task/region IDs.

use super::super::recovery::SnapshotIdentity;
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::membership::durable::PersistentMembershipController;
use crate::distributed::membership::owned::{
    MembershipWorkError, MembershipWorkReport, OwnedMembershipController,
};
use crate::distributed::{RegionSnapshot, SnapshotError};
use crate::record::region::RegionState;
use crate::remote::NodeId;
use crate::security::AuthKey;
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ASUPCNT\0";
const VERSION: u32 = 1;
const HEADER: usize = 92;
const STATE_DOMAIN: &[u8] = b"asupersync.application-continuation.state.v1";

/// Independent serialized snapshot and application-state admission limits.
///
/// There is no unbounded default. The snapshot limit applies BEFORE its existing
/// authenticated decoder allocates. State input is checked BEFORE application
/// decoding. The application codec's own allocations/CPU and caller-owned inputs
/// are separate; these fields do not promise an RSS or inside-poll time bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationLimits {
    /// Entire existing SNAP encoding, including its authentication tag.
    pub max_snapshot_bytes: usize,
    /// Canonical application-state bytes, excluding continuation framing.
    pub max_state_bytes: usize,
}

/// Redacted application codec refusal; state values are not diagnostic payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateCodecError {
    /// The bytes or typed value are not valid for this workload.
    #[error("invalid continuation application state")]
    Invalid,
    /// The application explicitly does not support this state/effect boundary.
    #[error("unsupported continuation application state")]
    Unsupported,
}

/// A native owned future produced by one locally compiled workload factory.
pub type ContinuationFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Explicit opt-in to a finite, versioned set of application checkpoint formats.
///
/// Implementations are supplied by local code, never loaded from snapshot bytes.
/// `NAME`, `REVISION` and `STATE_SCHEMA` together identify the exact workload and
/// codec contract. Change them when that contract changes; a schema fingerprint
/// is not a measured executable hash or a permission to upgrade incompatible code.
///
/// Encode/decode must be pure and bounded for admitted state sizes, and must
/// round-trip canonically. Decoding cannot retain a borrow of untrusted bytes.
/// `resume` is invoked only inside the admitted child task, with its fresh Cx.
/// Provision effect destinations/credentials on `self`, not by deserializing
/// capability handles, callbacks, sockets or runtime owners from state.
///
/// A user implementation can perform arbitrary Rust effects; this trait is not
/// a sandbox or a proof that its checkpoint was taken at a safe boundary. The
/// application must reject states requiring unsupported external effects and
/// make replayed effects idempotent or coordinate them with its own durable log.
pub trait RestorableWorkload: Send + Sync + 'static {
    /// Stable, nonempty local workload name, at most 255 UTF-8 bytes.
    const NAME: &'static str;
    /// Nonzero revision of the execution/continuation contract.
    const REVISION: u32;
    /// Nonzero, independently provisioned state-codec fingerprint.
    const STATE_SCHEMA: [u8; 32];
    /// Owned application data only; not a suspended future or runtime resource.
    type State: Send + 'static;
    /// Application result, interpreted separately from membership/cleanup success.
    type Output: Send + 'static;

    /// Produce one deterministic canonical state encoding.
    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, StateCodecError>;
    /// Validate and decode one complete state at a supported application boundary.
    fn decode_state(&self, bytes: &[u8]) -> Result<Self::State, StateCodecError>;
    /// Resume actual effects from owned state using newly admitted capabilities.
    fn resume(self: Arc<Self>, cx: Cx, state: Self::State) -> ContinuationFuture<Self::Output>;
}

/// Admission refusal before a workload factory is invoked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContinuationError {
    /// Existing snapshot authentication, version or structure validation failed.
    #[error("continuation snapshot authentication or decoding failed")]
    Snapshot(#[from] SnapshotError),
    /// The snapshot is not the exact independently expected region/branch/sequence.
    #[error("continuation snapshot identity mismatch")]
    Identity,
    /// V1 does not restore tasks, nested regions, finalizers or saved budgets.
    #[error("snapshot requires unsupported runtime-state restoration")]
    UnsupportedSnapshot,
    /// Capture does not overwrite any existing application metadata.
    #[error("continuation capture requires empty snapshot metadata")]
    ExistingMetadata,
    /// Unsupported framing, reserved flags, lengths, digest or trailing bytes.
    #[error("invalid application continuation framing")]
    Format,
    /// The local workload name/revision/schema does not match the checkpoint.
    #[error("application continuation workload or codec does not match")]
    Workload,
    /// Application state was explicitly refused by its trusted codec.
    #[error(transparent)]
    State(#[from] StateCodecError),
    /// Decoded state re-encoded differently; no ambiguous codec representation.
    #[error("application continuation state is not canonical")]
    NonCanonical,
    /// Explicit serialized-byte ceiling was exceeded.
    #[error("application continuation exceeds its {0} limit")]
    Limit(&'static str),
    /// Checked framing arithmetic cannot be represented on the target.
    #[error("application continuation size overflow")]
    Overflow,
    /// Bounded continuation buffer allocation failed.
    #[error("application continuation allocation failed")]
    Allocation,
}

/// Validated owned application state, runnable once through this value.
///
/// No Clone implementation or public state mutator is provided. Calling prepare
/// again on the same persisted bytes is a NEW execution: global deduplication is
/// not claimed. Dropping an unrun value simply destroys its application state;
/// it owns no runtime task, lease or network operation. Debug omits state data.
pub struct PreparedContinuation<W: RestorableWorkload> {
    workload: Arc<W>,
    state: W::State,
    source: SnapshotIdentity,
    state_digest: [u8; 32],
}
impl<W: RestorableWorkload> fmt::Debug for PreparedContinuation<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedContinuation").finish_non_exhaustive()
    }
}

// The existing decoder returns ordinary Vec metadata; protect our temporary
// copy on every refusal path as well as success. Returned snapshots retain the
// existing RegionSnapshot ownership contract, not this private temporary guard.
struct DecodedSnapshot(RegionSnapshot);
impl Drop for DecodedSnapshot {
    fn drop(&mut self) { self.0.metadata.zeroize(); }
}

fn descriptor<W: RestorableWorkload>() -> Result<(), ContinuationError> {
    if W::NAME.is_empty() || W::NAME.len() > 255 || W::REVISION == 0
        || W::STATE_SCHEMA == [0; 32] || W::NAME.chars().any(char::is_control)
    { return Err(ContinuationError::Workload); }
    Ok(())
}
fn shape(snapshot: &RegionSnapshot) -> Result<(), ContinuationError> {
    if snapshot.state != RegionState::Open || !snapshot.tasks.is_empty()
        || !snapshot.children.is_empty() || snapshot.finalizer_count != 0
        || snapshot.cancel_reason.is_some() || snapshot.parent.is_some()
        || snapshot.budget.deadline_nanos.is_some() || snapshot.budget.polls_remaining.is_some()
        || snapshot.budget.cost_remaining.is_some()
    { return Err(ContinuationError::UnsupportedSnapshot); }
    Ok(())
}
fn identity(snapshot: &RegionSnapshot) -> SnapshotIdentity {
    SnapshotIdentity { region_id: snapshot.region_id, origin_id: snapshot.origin_id,
        epoch: snapshot.epoch, sequence: snapshot.sequence }
}
fn add(a: usize, b: usize) -> Result<usize, ContinuationError> {
    a.checked_add(b).ok_or(ContinuationError::Overflow)
}
fn state_hash(bytes: &[u8]) -> Result<[u8; 32], ContinuationError> {
    let length = u64::try_from(bytes.len()).map_err(|_| ContinuationError::Overflow)?;
    let mut hash = Sha256::new();
    hash.update(STATE_DOMAIN);
    hash.update(length.to_le_bytes());
    hash.update(bytes);
    Ok(hash.finalize().into())
}
fn canonical<W: RestorableWorkload>(
    workload: &W, bytes: &[u8], limits: ContinuationLimits,
) -> Result<W::State, ContinuationError> {
    if bytes.len() > limits.max_state_bytes { return Err(ContinuationError::Limit("state bytes")); }
    let state = workload.decode_state(bytes)?;
    let roundtrip = Zeroizing::new(workload.encode_state(&state)?);
    if roundtrip.len() > limits.max_state_bytes { return Err(ContinuationError::Limit("state bytes")); }
    if roundtrip.as_slice() != bytes { return Err(ContinuationError::NonCanonical); }
    Ok(state)
}

/// Seal explicit application state into the existing authenticated SNAP format.
///
/// `snapshot` is an APPLICATION checkpoint carrier, not an automatic capture of
/// the live region. V1 requires an empty open root (no task/child/finalizer/budget
/// restoration) and empty metadata. The caller establishes a safe application
/// checkpoint boundary, then explicitly signs the result. Existing fields and
/// the snapshot wire are preserved; metadata is a distinct versioned envelope.
/// Codec callbacks are trusted and run synchronously without acquiring a Cx.
/// No network, task spawn, file operation or automatic checkpoint persistence.
///
/// The returned RegionSnapshot owns plaintext metadata with its existing drop
/// semantics. Temporary codec/serialization buffers zeroize; caller-retained
/// snapshots, typed state and persisted files require caller-controlled protection.
pub fn checkpoint_workload<W: RestorableWorkload>(
    mut snapshot: RegionSnapshot, workload: &W, state: &W::State,
    snapshot_key: &AuthKey, limits: ContinuationLimits,
) -> Result<RegionSnapshot, ContinuationError> {
    descriptor::<W>()?;
    shape(&snapshot)?;
    if !snapshot.metadata.is_empty() { return Err(ContinuationError::ExistingMetadata); }
    // The caller owns this typed snapshot; size_estimate also encodes its causal
    // clock. Hostile serialized snapshots use prepare_workload's predecode limit.
    if snapshot.size_estimate() > limits.max_snapshot_bytes {
        return Err(ContinuationError::Limit("snapshot bytes"));
    }
    let bytes = Zeroizing::new(workload.encode_state(state)?);
    let _validated = canonical(workload, &bytes, limits)?;
    let length = add(add(HEADER, W::NAME.len())?, bytes.len())?;
    if add(snapshot.size_estimate(), length)? > limits.max_snapshot_bytes {
        return Err(ContinuationError::Limit("snapshot bytes"));
    }
    let mut metadata = Zeroizing::new(Vec::new());
    metadata.try_reserve_exact(length).map_err(|_| ContinuationError::Allocation)?;
    metadata.extend_from_slice(MAGIC);
    metadata.extend_from_slice(&VERSION.to_le_bytes());
    metadata.extend_from_slice(&W::REVISION.to_le_bytes());
    metadata.extend_from_slice(&(W::NAME.len() as u16).to_le_bytes());
    metadata.extend_from_slice(&0_u16.to_le_bytes()); // Reserved, including effect-profile extensions.
    metadata.extend_from_slice(&W::STATE_SCHEMA);
    metadata.extend_from_slice(&u64::try_from(bytes.len()).map_err(|_| ContinuationError::Overflow)?.to_le_bytes());
    metadata.extend_from_slice(&state_hash(&bytes)?);
    metadata.extend_from_slice(W::NAME.as_bytes());
    metadata.extend_from_slice(&bytes);
    snapshot.metadata = std::mem::take(&mut *metadata);
    let mut snapshot = DecodedSnapshot(snapshot);
    snapshot.0.sign(snapshot_key);
    let encoded = Zeroizing::new(snapshot.0.to_bytes());
    if encoded.len() > limits.max_snapshot_bytes { return Err(ContinuationError::Limit("snapshot bytes")); }
    // Preserve existing SNAP admission, including its arena-ID and metadata caps.
    // Do not author an encoding our actual restore decoder refuses.
    Ok(RegionSnapshot::from_bytes_with_key(&encoded, snapshot_key)?)
}

/// Authenticate and validate an exact checkpoint BEFORE invoking its state codec.
///
/// The caller provides the expected snapshot identity and locally compiled
/// workload. No snapshot field chooses an executable, route or capability. The
/// complete SNAP byte bound precedes its authenticated decoder; shape, identity,
/// workload/revision/schema, exact metadata framing and state digest precede the
/// trusted codec. Canonical re-encoding must match before a runnable value escapes.
pub fn prepare_workload<W: RestorableWorkload>(
    snapshot_bytes: &[u8], expected: SnapshotIdentity, snapshot_key: &AuthKey,
    limits: ContinuationLimits, workload: Arc<W>,
) -> Result<PreparedContinuation<W>, ContinuationError> {
    descriptor::<W>()?;
    if snapshot_bytes.len() > limits.max_snapshot_bytes { return Err(ContinuationError::Limit("snapshot bytes")); }
    let snapshot = DecodedSnapshot(RegionSnapshot::from_bytes_with_key(snapshot_bytes, snapshot_key)?);
    if identity(&snapshot.0) != expected { return Err(ContinuationError::Identity); }
    shape(&snapshot.0)?;
    let metadata = &snapshot.0.metadata;
    if metadata.len() < HEADER || &metadata[..8] != MAGIC
        || metadata[8..12] != VERSION.to_le_bytes() || metadata[18..20] != [0; 2]
    { return Err(ContinuationError::Format); }
    let name_len = usize::from(u16::from_le_bytes(metadata[16..18].try_into().expect("name length")));
    let state_len = usize::try_from(u64::from_le_bytes(metadata[52..60].try_into().expect("state length")))
        .map_err(|_| ContinuationError::Overflow)?;
    if state_len > limits.max_state_bytes { return Err(ContinuationError::Limit("state bytes")); }
    let state_start = add(HEADER, name_len)?;
    if name_len == 0 || name_len > 255 || add(state_start, state_len)? != metadata.len() {
        return Err(ContinuationError::Format);
    }
    if metadata[12..16] != W::REVISION.to_le_bytes() || metadata[20..52] != W::STATE_SCHEMA
        || &metadata[HEADER..state_start] != W::NAME.as_bytes()
    { return Err(ContinuationError::Workload); }
    let state_bytes = &metadata[state_start..];
    let digest = state_hash(state_bytes)?;
    if metadata[60..HEADER] != digest { return Err(ContinuationError::Format); }
    let state = canonical(workload.as_ref(), state_bytes, limits)?;
    Ok(PreparedContinuation { workload, state, source: expected, state_digest: digest })
}

impl<W: RestorableWorkload> PreparedContinuation<W> {
    /// Source provenance only. It is NEVER installed as a destination runtime ID.
    pub const fn source(&self) -> SnapshotIdentity { self.source }
    /// Domain-framed state digest, not authorization or an exactly-once token.
    pub const fn state_digest(&self) -> [u8; 32] { self.state_digest }

    /// Consume validated state and run its factory under a fresh membership lease.
    ///
    /// The destination node/incarnation, duration and child capability/budget
    /// envelope are explicit LOCAL authority. No old runtime ID or saved clock
    /// is restored. The existing scoped runner checks admission before the factory,
    /// handles expiry/cancellation, drains descendants/finalizers, and requires a
    /// winning checked commit before `is_success()` can authorize completion.
    /// Application errors inside W::Output remain application-level outcomes.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self, owner: &OwnedMembershipController, cx: &Cx, node: &NodeId,
        incarnation: u64, duration: Duration, spec: ChildRegionSpec,
    ) -> Result<MembershipWorkReport<W::Output>, MembershipWorkError> {
        let Self { workload, state, .. } = self;
        owner.run_scoped(cx, node, incarnation, duration, spec, move |child| async move {
            workload.resume(child, state).await
        }).await
    }

    /// The same execution contract using restart-persistent membership policy.
    /// This does not persist or deduplicate the resumed application's effects.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_persistent(
        self, owner: &PersistentMembershipController, cx: &Cx, node: &NodeId,
        incarnation: u64, duration: Duration, spec: ChildRegionSpec,
    ) -> Result<MembershipWorkReport<W::Output>, MembershipWorkError> {
        let Self { workload, state, .. } = self;
        owner.run_scoped(cx, node, incarnation, duration, spec, move |child| async move {
            workload.resume(child, state).await
        }).await
    }
}

#[cfg(test)]
mod tests;

mod network;
pub use network::ContinuationRecoveryError;
