//! Replication-to-manifest and manifest-to-recovery through existing transports.

use super::{ManifestBytes, ManifestError, ManifestLimits, RecoveryManifest, add, counts, dimensions};
use super::super::{RemoteSymbolTransport, SymbolBatchKey, SymbolStoreError, encode_symbol_batch};
use super::super::recovery::{RemoteRecoveryConfig, RemoteRecoveryError, ReplicaFetch, SnapshotDecodeLimits, SnapshotIdentity};
use crate::cx::Cx;
use crate::distributed::{EncodedState, RegionSnapshot};
use crate::distributed::assignment::{AssignmentStrategy, ReplicaAssignment};
use crate::distributed::distribution::{DistributionResult, DistributorTransport, ReplicaAck, ReplicaFailure, SymbolDistributor};
use crate::distributed::recovery::{RecoveryDecodingConfig, StateDecoder};
use crate::error::ErrorKind;
use crate::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use crate::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;
use sha2::{Digest, Sha256};

/// Explicit authority for publishing one exact authenticated snapshot.
/// The symbol key is supplied by the transport and signing SecurityContext.
pub struct CheckpointAuthority<'a> {
    /// Expected branch, origin incarnation, sequence and generation-safe region.
    pub expected: SnapshotIdentity,
    /// Independent key authenticating the reconstructed snapshot before dispatch.
    pub snapshot_key: &'a AuthKey,
    /// Independent author key authenticating the returned recovery manifest.
    pub manifest_key: &'a AuthKey,
}
impl fmt::Debug for CheckpointAuthority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointAuthority").finish_non_exhaustive()
    }
}

/// Bounds for publication; transport and distributor bounds remain independent.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointConfig {
    /// Complete possible manifest is admitted before any dispatch.
    pub manifest: ManifestLimits,
    /// Decoder bounds for pre-publication authentication of the supplied encoding.
    pub decode: SnapshotDecodeLimits,
    /// Sealed minimum distinct responses for subsequent recovery.
    /// Must not exceed the configured write quorum (Local is unsupported).
    pub minimum_recovery_replicas: usize,
    /// Whole preparation/distribution/sealing deadline on the context timer.
    /// Does not preempt bounded synchronous codec/decoder work inside one poll.
    pub timeout: Duration,
}

/// Failed publication returns no manifest. Remote writes may already have occurred.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    /// Invalid metadata, unknown/unavailable/unauthorized targets or Local policy.
    #[error("invalid checkpoint publication configuration")]
    Configuration,
    /// Metadata authentication, admission or exact expected identity failed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Symbol encoding or a supplied resource bound failed.
    #[error(transparent)]
    Batch(#[from] SymbolStoreError),
    /// Supplied symbols did not reconstruct an independently authenticated snapshot.
    #[error("checkpoint source snapshot decoding or authentication failed")]
    Decode,
    /// Source snapshot differs from the independently authorized exact identity.
    #[error("checkpoint source snapshot identity mismatch")]
    Identity,
    /// Publication or recovery requires explicit owner timer authority.
    #[error("checkpoint requires an explicit context timer")]
    NoTimer,
    /// The owner requested cancellation; local attempts are retired before return.
    #[error("checkpoint cancelled; remote publication may be partial")]
    Cancelled,
    /// The whole operation budget expired; remote publication may be partial.
    #[error("checkpoint deadline exceeded; remote publication may be partial")]
    Deadline,
    /// Distribution did not establish the original fixed write threshold.
    #[error("checkpoint write quorum was not established")]
    Quorum {
        /// Actual completed distribution, without a successful recovery manifest.
        distribution: DistributionResult,
    },
    /// Receipts met the write threshold, but the acknowledged symbol union did
    /// not reconstruct the exact prevalidated snapshot. No manifest was sealed.
    #[error("acknowledged checkpoint stripes do not reconstruct the source snapshot")]
    InsufficientCoverage {
        /// Completed writes may still exist at these replicas.
        distribution: DistributionResult,
    },
    /// A caller attempted to weaken the manifest's minimum recovery requirement.
    #[error("recovery configuration weakens the authenticated replica threshold")]
    RecoveryThreshold,
    /// Existing bounded replica collection or snapshot authentication refused.
    #[error(transparent)]
    Recovery(#[from] RemoteRecoveryError),
}

/// Confirmed replication and the matching authenticated restart metadata.
///
/// Persist `encoded_manifest()` through an explicitly owned durable destination
/// before discarding the publisher state. Returning these bytes does not persist
/// them, negotiate replica durability, or atomically commit publisher metadata
/// with remote writes. Failures after sending never imply remote rollback.
#[derive(Debug)]
pub struct ReplicatedCheckpoint {
    manifest: RecoveryManifest,
    encoded: ManifestBytes,
    distribution: DistributionResult,
}
impl ReplicatedCheckpoint {
    /// Exact acknowledged replica set and sealed recovery requirements.
    pub fn manifest(&self) -> &RecoveryManifest { &self.manifest }
    /// Ready-to-persist authenticated metadata (contains no symbol/snapshot keys).
    pub fn encoded_manifest(&self) -> &[u8] { self.encoded.as_ref() }
    /// Original distributor accounting, including failed or retired losers.
    pub fn distribution(&self) -> &DistributionResult { &self.distribution }
    /// Transfer the independently owned metadata and distribution report.
    pub fn into_parts(self) -> (RecoveryManifest, ManifestBytes, DistributionResult) {
        (self.manifest, self.encoded, self.distribution)
    }
}

// Bind each actual outgoing signed batch to the prevalidated full-copy digest.
// This catches drift in signing context/assignment rather than sealing a key for
// bytes that were never sent. It does not replace the inner authenticated receipt.
struct CheckedTransport<'a> { inner: &'a RemoteSymbolTransport, key: SymbolBatchKey }
impl DistributorTransport for CheckedTransport<'_> {
    async fn send_symbols(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>)
        -> Result<ReplicaAck, ReplicaFailure>
    {
        let matches = encode_symbol_batch(&symbols, self.inner.limits)
            .is_ok_and(|batch| batch.key() == self.key);
        if !matches {
            return Err(ReplicaFailure { replica_id: replica.to_owned(),
                error: "checkpoint outgoing batch changed after validation".into(), error_kind: ErrorKind::ProtocolError });
        }
        self.inner.send_symbols(replica, symbols).await
    }
}

struct Stripe {
    assignment: ReplicaAssignment,
    key: SymbolBatchKey,
    count: u32,
}

// Assignment identity is local authority. Bind every send to the exact batch
// prepared for that replica, including its count, rather than one full-copy key.
struct CheckedStripedTransport<'a> {
    inner: &'a RemoteSymbolTransport,
    stripes: &'a [Stripe],
}
impl DistributorTransport for CheckedStripedTransport<'_> {
    async fn send_symbols(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>)
        -> Result<ReplicaAck, ReplicaFailure>
    {
        let expected = self.stripes.iter().find(|stripe| stripe.assignment.replica_id == replica);
        let matches = expected.is_some_and(|stripe| {
            encode_symbol_batch(&symbols, self.inner.limits)
                .is_ok_and(|batch| batch.key() == stripe.key && batch.symbol_count() == stripe.count)
        });
        if !matches {
            return Err(ReplicaFailure { replica_id: replica.to_owned(),
                error: "checkpoint outgoing stripe changed after validation".into(), error_kind: ErrorKind::ProtocolError });
        }
        self.inner.send_symbols(replica, symbols).await
    }
}

impl RemoteSymbolTransport {
    /// Authenticate a supplied encoding, distribute full copies, and seal only
    /// confirmed replica keys. Reuses the caller's distributor and its metrics,
    /// including opt-in hedging. Unknown, duplicate, unavailable or unauthorized
    /// input targets refuse before dispatch instead of reducing the denominator.
    ///
    /// Source/count/byte/decode/manifest limits are checked before network work.
    /// Reconstructing the source with the existing decoder prevents a signed
    /// manifest from promising an unrelated or unrecoverable snapshot. Preparation
    /// is synchronous and nonpreemptible inside a poll; its dimensions are bounded.
    /// No task is spawned, no address is taken from ReplicaInfo, and no retry is
    /// added. A lost/failed result can follow successful remote stores. Persist the
    /// returned manifest separately; this is not a distributed atomic transaction.
    #[allow(clippy::too_many_arguments)] // Keep existing distributor/security ownership explicit.
    pub async fn replicate_checkpoint(
        &self, distributor: &mut SymbolDistributor, encoded: &EncodedState,
        replicas: &[ReplicaInfo], security: &SecurityContext,
        authority: CheckpointAuthority<'_>, config: CheckpointConfig,
    ) -> Result<ReplicatedCheckpoint, CheckpointError> {
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if config.timeout.is_zero() || self.max_in_flight() == 0 { return Err(CheckpointError::Configuration); }
        let timer = self.cx.timer_driver().ok_or(CheckpointError::NoTimer)?;
        let deadline = timer.now() + config.timeout;
        let (draft, count, required, _) = prepare(self, distributor, encoded, replicas, security, &authority, config)?;
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline); }
        let checked = CheckedTransport { inner: self, key: draft.replicas[0].key };
        let distribution = before_deadline(&self.cx, timer.clone(), deadline,
            distributor.distribute(&self.cx, encoded, replicas, &checked, security)).await?;
        // before_deadline destroys the complete distributor future before sealing.
        let result = seal(draft, distribution, count, required, authority.manifest_key, config.manifest)?;
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline); }
        Ok(result)
    }

    /// Publish erasure-coded stripes and seal their exact per-replica batch keys.
    ///
    /// Each encoded symbol is assigned once, round-robin over the supplied
    /// replicas. Unlike full replication, a single replica need not reconstruct
    /// the snapshot. The acknowledged union must actually decode and authenticate
    /// to the same canonical snapshot as the source before any manifest escapes.
    /// Receipt quorum or a count of symbols is never sufficient by itself.
    ///
    /// Configure enough repair symbols for the intended failure pattern. A
    /// recovery replica floor is an admission policy, not a promise that any
    /// subset of that size decodes. Recovery collects all available manifest
    /// donors and fails if their union is insufficient. Quorum-first hedging may
    /// retire stripes needed for decoding; such a publication refuses with
    /// [`CheckpointError::InsufficientCoverage`] even when its write quorum met.
    ///
    /// All existing source, signing, decoder, transport and manifest limits still
    /// apply to the complete source. Empty stripes refuse before dispatch. V1
    /// batch/manifest bytes and the full-copy [`Self::replicate_checkpoint`] API
    /// are unchanged. The returned metadata must be persisted separately.
    #[allow(clippy::too_many_arguments)]
    pub async fn replicate_striped_checkpoint(
        &self, distributor: &mut SymbolDistributor, encoded: &EncodedState,
        replicas: &[ReplicaInfo], security: &SecurityContext,
        authority: CheckpointAuthority<'_>, config: CheckpointConfig,
    ) -> Result<ReplicatedCheckpoint, CheckpointError> {
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if config.timeout.is_zero() || self.max_in_flight() == 0 { return Err(CheckpointError::Configuration); }
        let timer = self.cx.timer_driver().ok_or(CheckpointError::NoTimer)?;
        let deadline = timer.now() + config.timeout;
        let (mut draft, _, required, snapshot) =
            prepare(self, distributor, encoded, replicas, security, &authority, config)?;
        let source_digest = Sha256::digest(snapshot.to_bytes()).into();
        drop(snapshot);
        let stripes = prepare_stripes(self, encoded, replicas, security)?;
        for replica in &mut draft.replicas {
            let stripe = stripes.iter().find(|stripe| stripe.assignment.replica_id == replica.replica_id)
                .ok_or(CheckpointError::Configuration)?;
            replica.key = stripe.key;
        }
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline); }
        let checked = CheckedStripedTransport { inner: self, stripes: &stripes };
        let assignments = stripes.iter().map(|stripe| stripe.assignment.clone()).collect();
        let distribution = before_deadline(&self.cx, timer.clone(), deadline,
            distributor.distribute_assignments(&self.cx, encoded, assignments, &checked, security)).await?;
        let result = seal_striped(self, draft, distribution, &stripes, encoded, required,
            source_digest, &authority, config.manifest)?;
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline); }
        Ok(result)
    }

    /// Recover from the manifest using only independently provisioned routes/keys.
    /// The transport origin must match the sealed service namespace. Recovery may
    /// require MORE replicas than the manifest floor, but never fewer. Existing
    /// collection/decode bounds, deadlines and exact snapshot checks still apply.
    pub async fn recover_checkpoint(
        &self, manifest: &RecoveryManifest, config: RemoteRecoveryConfig,
        decode_limits: SnapshotDecodeLimits, snapshot_key: &AuthKey,
    ) -> Result<RegionSnapshot, CheckpointError> {
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled); }
        if self.hello.peer_node() != manifest.peer_node() { return Err(ManifestError::Identity.into()); }
        if config.required_replicas < manifest.minimum_replicas() { return Err(CheckpointError::RecoveryThreshold); }
        Ok(self.recover_snapshot(manifest.replicas(), config, manifest.params(), manifest.identity(),
            decode_limits, snapshot_key).await?)
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    transport: &RemoteSymbolTransport, distributor: &SymbolDistributor, encoded: &EncodedState,
    replicas: &[ReplicaInfo], security: &SecurityContext, authority: &CheckpointAuthority<'_>, config: CheckpointConfig,
) -> Result<(RecoveryManifest, u32, usize, RegionSnapshot), CheckpointError> {
    counts(replicas.len(), config.minimum_recovery_replicas, config.manifest)?;
    dimensions(encoded.params)?;
    let policy = distributor.config();
    let required = SymbolDistributor::required_acks(policy.consistency, replicas.len());
    if policy.consistency == ConsistencyLevel::Local || policy.max_concurrent == 0 || policy.ack_timeout.is_zero()
        || config.minimum_recovery_replicas > required
        || encoded.params.object_size != u64::try_from(encoded.original_size).map_err(|_| ManifestError::Overflow)?
    { return Err(CheckpointError::Configuration); }
    if encoded.params.object_size > u64::try_from(config.decode.max_snapshot_bytes).unwrap_or(u64::MAX)
        || encoded.params.source_blocks > config.decode.max_source_blocks
        || encoded.params.symbols_per_block > config.decode.max_source_symbols_per_block
    { return Err(ManifestError::Limit("snapshot decode").into()); }
    let mut names = BTreeSet::new();
    for replica in replicas {
        if !super::valid_label(&replica.id) || !names.insert(replica.id.as_str()) || !transport.routes.contains_key(&replica.id)
            || !security.is_replica_authorized(&replica.id, None)
        {
            return Err(CheckpointError::Configuration);
        }
    }
    let n = encoded.symbols.len();
    if n == 0 || n > transport.limits.max_symbols { return Err(SymbolStoreError::Limit("symbols").into()); }
    let payload = encoded.symbols.iter().try_fold(0usize, |sum, s| add(sum, s.data().len()))?;
    let retained = add(n.checked_mul(std::mem::size_of::<AuthenticatedSymbol>()).ok_or(ManifestError::Overflow)?, payload)?;
    if payload > transport.limits.max_payload_bytes || retained > transport.limits.max_decoded_bytes {
        return Err(SymbolStoreError::Limit("checkpoint signing storage").into());
    }
    n.checked_mul(replicas.len()).and_then(|entries| entries.checked_mul(std::mem::size_of::<usize>()))
        .ok_or(ManifestError::Overflow)?;
    let mut signed = Vec::new();
    signed.try_reserve_exact(n).map_err(|_| ManifestError::Allocation)?;
    for symbol in &encoded.symbols {
        let authenticated = security.sign_symbol(symbol);
        if !authenticated.tag().verify(&transport.auth_key, authenticated.symbol()) {
            return Err(SymbolStoreError::Authentication.into());
        }
        signed.push(authenticated);
    }
    let batch = encode_symbol_batch(&signed, transport.limits)?;
    let mut plans = Vec::new();
    plans.try_reserve_exact(replicas.len()).map_err(|_| ManifestError::Allocation)?;
    for replica in replicas { plans.push(ReplicaFetch { replica_id: replica.id.clone(), key: batch.key() }); }
    let draft = RecoveryManifest::new(transport.hello.peer_node().clone(), encoded.params, authority.expected,
        plans, config.minimum_recovery_replicas, config.manifest)?;
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
        verify_integrity: true, auth_context: Some(SecurityContext::new(transport.auth_key.as_ref().clone())),
        snapshot_auth_key: Some(authority.snapshot_key.clone()), max_decode_attempts: 1, allow_partial_decode: false,
    });
    for symbol in &signed { decoder.add_symbol(symbol).map_err(|_| CheckpointError::Decode)?; }
    drop(signed);
    let snapshot = decoder.decode_snapshot(&encoded.params).map_err(|_| CheckpointError::Decode)?;
    if (snapshot.region_id, snapshot.origin_id, snapshot.epoch, snapshot.sequence)
        != (authority.expected.region_id, authority.expected.origin_id, authority.expected.epoch, authority.expected.sequence)
    { return Err(CheckpointError::Identity); }
    Ok((draft, batch.symbol_count(), required, snapshot))
}

fn prepare_stripes(
    transport: &RemoteSymbolTransport, encoded: &EncodedState,
    replicas: &[ReplicaInfo], security: &SecurityContext,
) -> Result<Vec<Stripe>, CheckpointError> {
    let assignments = SymbolDistributor::compute_assignments_with_strategy(
        encoded, replicas, security, None, AssignmentStrategy::Striped,
    );
    if assignments.len() != replicas.len() || assignments.iter().any(|assignment| assignment.symbol_indices.is_empty()) {
        return Err(CheckpointError::Configuration);
    }
    let mut stripes = Vec::new();
    stripes.try_reserve_exact(assignments.len()).map_err(|_| ManifestError::Allocation)?;
    for assignment in assignments {
        let mut signed = Vec::new();
        signed.try_reserve_exact(assignment.symbol_indices.len()).map_err(|_| ManifestError::Allocation)?;
        for &index in &assignment.symbol_indices {
            let authenticated = security.sign_symbol(&encoded.symbols[index]);
            if !authenticated.tag().verify(&transport.auth_key, authenticated.symbol()) {
                return Err(SymbolStoreError::Authentication.into());
            }
            signed.push(authenticated);
        }
        let batch = encode_symbol_batch(&signed, transport.limits)?;
        stripes.push(Stripe { assignment, key: batch.key(), count: batch.symbol_count() });
    }
    Ok(stripes)
}

#[allow(clippy::too_many_arguments)]
fn seal_striped(
    transport: &RemoteSymbolTransport, mut draft: RecoveryManifest,
    distribution: DistributionResult, stripes: &[Stripe], encoded: &EncodedState,
    required: usize, source_digest: [u8; 32], authority: &CheckpointAuthority<'_>,
    limits: ManifestLimits,
) -> Result<ReplicatedCheckpoint, CheckpointError> {
    if !distribution.quorum_achieved || distribution.acks.len() < required
        || distribution.acks.len() < draft.minimum_replicas
    { return Err(CheckpointError::Quorum { distribution }); }
    if distribution.object_id != draft.params.object_id { return Err(CheckpointError::Configuration); }
    let mut confirmed = BTreeSet::new();
    let mut indices = BTreeSet::new();
    for ack in &distribution.acks {
        let stripe = stripes.iter().find(|stripe| stripe.assignment.replica_id == ack.replica_id)
            .ok_or(CheckpointError::Configuration)?;
        if ack.symbols_received != stripe.count || !confirmed.insert(ack.replica_id.clone()) {
            return Err(CheckpointError::Configuration);
        }
        indices.extend(stripe.assignment.symbol_indices.iter().copied());
    }
    // Source admission already rejected repeated (object, block, ESI) identities
    // across the entire encoding. Deduplicate indices too, so overlapping plans
    // never inflate the union. Decode actual equations rather than trusting K.
    let signing = SecurityContext::new(transport.auth_key.as_ref().clone());
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
        verify_integrity: true, auth_context: Some(SecurityContext::new(transport.auth_key.as_ref().clone())),
        snapshot_auth_key: Some(authority.snapshot_key.clone()), max_decode_attempts: 1, allow_partial_decode: false,
    });
    for index in indices {
        if decoder.add_symbol(&signing.sign_symbol(&encoded.symbols[index])).is_err() {
            return Err(CheckpointError::InsufficientCoverage { distribution });
        }
    }
    let matches_source = decoder.decode_snapshot(&encoded.params).is_ok_and(|snapshot| {
        let digest: [u8; 32] = Sha256::digest(snapshot.to_bytes()).into();
        digest == source_digest
    });
    if !matches_source { return Err(CheckpointError::InsufficientCoverage { distribution }); }
    draft.replicas.retain(|replica| confirmed.contains(replica.replica_id.as_str()));
    drop(confirmed);
    let encoded = draft.to_canonical_bytes(authority.manifest_key, limits.max_encoded_bytes)?;
    Ok(ReplicatedCheckpoint { manifest: draft, encoded, distribution })
}

fn seal(
    mut draft: RecoveryManifest, distribution: DistributionResult, count: u32, required: usize,
    key: &AuthKey, limits: ManifestLimits,
) -> Result<ReplicatedCheckpoint, CheckpointError> {
    if !distribution.quorum_achieved || distribution.acks.len() < required
        || distribution.acks.len() < draft.minimum_replicas
    { return Err(CheckpointError::Quorum { distribution }); }
    if distribution.object_id != draft.params.object_id { return Err(CheckpointError::Configuration); }
    let planned: BTreeSet<_> = draft.replicas.iter().map(|r| r.replica_id.as_str()).collect();
    let mut confirmed = BTreeSet::new();
    for ack in &distribution.acks {
        if ack.symbols_received != count || !planned.contains(ack.replica_id.as_str()) || !confirmed.insert(ack.replica_id.as_str()) {
            return Err(CheckpointError::Configuration);
        }
    }
    drop(planned);
    draft.replicas.retain(|replica| confirmed.contains(replica.replica_id.as_str()));
    drop(confirmed);
    let encoded = draft.to_canonical_bytes(key, limits.max_encoded_bytes)?;
    Ok(ReplicatedCheckpoint { manifest: draft, encoded, distribution })
}

async fn before_deadline<F: Future>(
    cx: &Cx, timer: TimerDriverHandle, deadline: Time, future: F,
) -> Result<F::Output, CheckpointError> {
    {
        let mut work = Box::pin(future);
        let mut cancelled = std::pin::pin!(cx.cancelled());
        let mut timeout = std::pin::pin!(Sleep::with_timer_driver(deadline, timer.clone()));
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(CheckpointError::Cancelled)); }
            if timer.now() >= deadline || timeout.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(CheckpointError::Deadline));
            }
            let result = work.as_mut().poll(task);
            if cx.is_cancel_requested() { return Poll::Ready(Err(CheckpointError::Cancelled)); }
            if timer.now() >= deadline { return Poll::Ready(Err(CheckpointError::Deadline)); }
            result.map(Ok)
        }).await
    }
}

#[cfg(test)]
mod tests;
