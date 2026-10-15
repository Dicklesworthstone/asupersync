//! Fetch an exact replica checkpoint and prepare only its supported application.

use super::{
    ContinuationError, ContinuationLimits, DecodedSnapshot, PreparedContinuation,
    RestorableWorkload, descriptor, prepare_workload,
};
use super::super::{CheckpointError, RecoveryManifest};
use super::super::super::RemoteSymbolTransport;
use super::super::super::recovery::{RemoteRecoveryConfig, SnapshotDecodeLimits};
use crate::security::AuthKey;
use std::sync::Arc;
use zeroize::Zeroizing;

/// No runnable application is returned on network, identity or codec refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContinuationRecoveryError {
    /// Existing bounded checkpoint collection/authentication failed.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    /// The recovered snapshot is not a supported, matching application checkpoint.
    #[error(transparent)]
    Continuation(#[from] ContinuationError),
}

impl RemoteSymbolTransport {
    /// Recover and prepare a locally selected application from an exact manifest.
    ///
    /// Reuses existing mTLS routes, batch verification, fixed replica threshold,
    /// RaptorQ decoding and independent snapshot authentication. The manifest's
    /// whole object must fit the continuation snapshot ceiling BEFORE dispatch.
    /// No workload factory, task, destination lease or resumed effect starts here.
    /// Unknown task/finalizer/topology snapshots and workload/codec drift refuse.
    ///
    /// The recovery deadline also covers serialization and application decoding,
    /// checked before/after these synchronous calls; it cannot preempt a callback
    /// inside one poll. The codec is trusted local code with its own work bounds.
    /// Once returned, prepared state is caller-owned memory outside the transport's
    /// in-flight credit. Run it with a fresh local membership controller/lease.
    /// There is no automatic retry, code loading, checkpoint upgrade or rollback.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_workload<W: RestorableWorkload>(
        &self, manifest: &RecoveryManifest, config: RemoteRecoveryConfig,
        decode_limits: SnapshotDecodeLimits, snapshot_key: &AuthKey,
        limits: ContinuationLimits, workload: Arc<W>,
    ) -> Result<PreparedContinuation<W>, ContinuationRecoveryError> {
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled.into()); }
        descriptor::<W>()?;
        let bytes = usize::try_from(manifest.params().object_size)
            .map_err(|_| ContinuationError::Limit("snapshot bytes"))?;
        if bytes > limits.max_snapshot_bytes {
            return Err(ContinuationError::Limit("snapshot bytes").into());
        }
        let timer = self.cx.timer_driver().ok_or(CheckpointError::NoTimer)?;
        let deadline = timer.now() + config.recovery_timeout;
        let snapshot = DecodedSnapshot(self.recover_checkpoint(manifest, config, decode_limits, snapshot_key).await?);
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled.into()); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline.into()); }
        // The authenticated network decoder already bounded this snapshot by its
        // object size. Keep the additional serialized copy zeroizing and release
        // the previous metadata before admitting the typed application state.
        let encoded = Zeroizing::new(snapshot.0.to_bytes());
        drop(snapshot);
        let result = prepare_workload(&encoded, manifest.identity(), snapshot_key, limits, workload);
        if self.cx.is_cancel_requested() { return Err(CheckpointError::Cancelled.into()); }
        if timer.now() >= deadline { return Err(CheckpointError::Deadline.into()); }
        Ok(result?)
    }
}
