//! Direct, single-peer SDK transfers over the native UDP/TLS data plane.
//!
//! This lane does not use the legacy in-process session negotiator. Sending
//! establishes a real connection and waits for the receiver's verified commit
//! receipt. Binding a receiver exposes its actual socket address before its
//! receive future starts, so applications do not need a port-reservation race.
//!
//! The native transport's support boundaries still apply: server identity is
//! verified by the supplied TLS client configuration, peer labels are not
//! client authorization, and multi-entry publication is not rollback-atomic.
//! This is the ATP-specific wire protocol, not generic QUIC interoperability.

pub mod upload;
pub use upload::{
    NativeUploadCleanupError, NativeUploadError, NativeUploadOptions, NativeUploadReport,
    NativeUploadTask,
};

use super::{AtpSdk, SdkMode};
use crate::cx::{Cx, Scope};
use crate::net::atp::transport_quic::native_link::{
    bind_server_endpoint, receive_on_endpoint_with_options,
};
use crate::net::atp::transport_quic::{
    self, QuicConfig, QuicReceiveOptions, QuicSendOptions, QuicTransportError, ReceiveReport,
    SendReport,
};
use crate::net::quic_native::QuicUdpEndpoint;
use crate::runtime::{SpawnError, TaskHandle};
use crate::types::Policy;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Admission, configuration, or transport failure for a native SDK transfer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeTransferError {
    /// This explicit in-process lane cannot impersonate daemon delegation.
    #[error("native transfers require the in-process SDK mode")]
    UnsupportedMode,
    /// A caller-supplied limit cannot admit any work.
    #[error("native transfer limit must be nonzero and representable: {0}")]
    InvalidLimit(&'static str),
    /// All slots in this client's admission domain are held.
    #[error("native transfer capacity exhausted (limit {limit})")]
    CapacityExceeded {
        /// Maximum sends and bound receivers sharing this client.
        limit: usize,
    },
    /// Sender authentication must be configured before any network effect.
    #[error("native send requires an explicit TLS client configuration")]
    MissingClientTls,
    /// Listener authentication must be configured before binding a socket.
    #[error("native receive requires an explicit TLS server configuration")]
    MissingServerTls,
    /// The sender's report lacked successful commit/integrity flags.
    /// The original receipt, including partial committed paths, is retained.
    #[error("native sender returned without a verified commit receipt")]
    UncommittedSend(Box<SendReport>),
    /// The receiver returned without complete publication.
    /// Retains its report so partial publication can be reconciled.
    #[error("native receiver returned without complete publication")]
    UncommittedReceive(Box<ReceiveReport>),
    /// The runtime refused to enqueue the scope-owned worker.
    #[error("native transfer worker admission failed: {0:?}")]
    Spawn(SpawnError),
    /// Original transport diagnostics, including cancellation, are retained.
    #[error(transparent)]
    Transport(#[from] QuicTransportError),
}

#[derive(Debug)]
struct NativeShared {
    config: QuicConfig,
    send_options: QuicSendOptions,
    peer_label: String,
    limit: usize,
    active: AtomicUsize,
}

/// A bounded native-transfer admission domain.
///
/// Clone this client to share one limit across concurrent sends and bound
/// receivers. Admission is fail-fast: saturation allocates neither a socket
/// nor an unbounded waiter queue. Separately created clients are independent
/// domains; this is not a process-wide or legacy-SDK admission claim.
///
/// Operations borrow the caller's `Cx` and run in the awaiting task; this
/// client never detaches a worker. Drive cancellation to its returned result
/// when cleanup matters. Dropping an operation inherits the native
/// transport's narrower drop/partial-I/O semantics, not a rollback promise.
#[derive(Debug, Clone)]
pub struct NativeTransferClient {
    shared: Arc<NativeShared>,
}

/// Canonical scope-owned sender task, retaining its full transport result.
///
/// Join errors and the inner native transfer result are distinct: runtime
/// cancellation is not converted to a protocol error or fabricated receipt.
pub type NativeSendTask = TaskHandle<Result<SendReport, NativeTransferError>>;

/// Canonical scope-owned receiver task, retaining its full transport result.
pub type NativeReceiveTask = TaskHandle<Result<ReceiveReport, NativeTransferError>>;

// These are postcondition checks on the native engine's reports, not
// independent authentication or hash verification. Never discard the
// evidence a caller needs to reconcile partial remote publication.
fn committed_send(report: SendReport) -> Result<SendReport, NativeTransferError> {
    if !report.receipt.committed || !report.receipt.sha_ok || !report.receipt.merkle_ok {
        return Err(NativeTransferError::UncommittedSend(Box::new(report)));
    }
    Ok(report)
}

fn committed_receive(report: ReceiveReport) -> Result<ReceiveReport, NativeTransferError> {
    if !report.committed {
        return Err(NativeTransferError::UncommittedReceive(Box::new(report)));
    }
    Ok(report)
}

#[derive(Debug)]
struct NativeAdmission {
    shared: Arc<NativeShared>,
}

impl Drop for NativeAdmission {
    fn drop(&mut self) {
        // This counter publishes no side data. Atomicity alone enforces the
        // cap, and each successfully constructed permit owns exactly one unit.
        let previous = self.shared.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "native transfer admission underflow");
    }
}

impl AtpSdk {
    /// Create an explicit native file/directory transfer client.
    ///
    /// Both endpoints must supply their real TLS configuration in `config`.
    /// For direct QUIC/TLS, select
    /// [`QuicConfig::use_transport_authenticated_symbols`] to use transport
    /// AEAD rather than requiring an additional symbol key. No certificate
    /// verifier or authentication policy is replaced by this adapter.
    ///
    /// The returned domain uses `SessionConfig::max_concurrent_transfers`.
    /// Transfer size and streaming hash/read chunk size are the stricter of
    /// `config` and the SDK's corresponding size ceilings. The chunk ceiling
    /// does not describe every native packet, reassembly, or decode buffer.
    ///
    /// Other behavior is explicitly selected by `QuicConfig`: its handshake,
    /// accept and idle timeouts are not a whole-transfer deadline. Use the
    /// caller's structured cancellation/budget for an overall deadline. The
    /// legacy session, compression, retry, progress and checkpoint options
    /// are not interpreted by this separate lane. In particular, a lost
    /// receipt is returned as an error, never automatically retried: the
    /// remote may already have committed the files.
    ///
    /// Sends use the default [`QuicSendOptions`] (no compression); see
    /// [`Self::native_transfers_with_send_options`].
    ///
    /// # Errors
    /// Refuses daemon delegation, zero limits, and invalid transport config
    /// before opening sockets or inspecting a source/destination path.
    pub fn native_transfers(
        &self,
        config: QuicConfig,
    ) -> Result<NativeTransferClient, NativeTransferError> {
        self.native_transfers_with_send_options(config, QuicSendOptions::new())
    }

    /// [`Self::native_transfers`], with `send_options` for every send the
    /// client makes: [`NativeTransferClient::send_path`],
    /// [`NativeTransferClient::spawn_send_path`], uploads and checkpointed
    /// sends.
    ///
    /// This is how an SDK sender compresses (br-asupersync-t1fblr.18):
    /// `QuicSendOptions::new().with_compression(CompressionMode::Zstd)`, or
    /// `CompressionMode::Auto`, offers zstd for the reliable source stream.
    /// A receiver built with the `zstd` feature accepts the offer; an older
    /// receiver ignores it and the stream stays raw. Without the `zstd`
    /// feature the sender makes no offer. Receipts, hashes and reported
    /// byte counts stay on raw bytes either way.
    /// `SessionConfig::enable_compression` is not read here.
    ///
    /// # Errors
    /// As [`Self::native_transfers`].
    pub fn native_transfers_with_send_options(
        &self,
        mut config: QuicConfig,
        send_options: QuicSendOptions,
    ) -> Result<NativeTransferClient, NativeTransferError> {
        if !matches!(self.mode, SdkMode::InProcess) {
            return Err(NativeTransferError::UnsupportedMode);
        }
        let limit = usize::try_from(self.default_config.max_concurrent_transfers)
            .map_err(|_| NativeTransferError::InvalidLimit("max_concurrent_transfers"))?;
        if limit == 0 {
            return Err(NativeTransferError::InvalidLimit(
                "max_concurrent_transfers",
            ));
        }
        if self.transfer_policy.max_transfer_size_bytes == 0 {
            return Err(NativeTransferError::InvalidLimit("max_transfer_size_bytes"));
        }
        if self.transfer_policy.max_chunk_size_bytes == 0 {
            return Err(NativeTransferError::InvalidLimit("max_chunk_size_bytes"));
        }
        config.max_transfer_bytes = config
            .max_transfer_bytes
            .min(self.transfer_policy.max_transfer_size_bytes);
        let chunk_limit =
            usize::try_from(self.transfer_policy.max_chunk_size_bytes).unwrap_or(usize::MAX);
        config.chunk_size = config.chunk_size.min(chunk_limit);
        config.validate()?;
        Ok(NativeTransferClient {
            shared: Arc::new(NativeShared {
                config,
                send_options,
                // A diagnostic label only. It grants no peer authority.
                peer_label: hex::encode(self.default_config.local_peer.as_bytes()),
                limit,
                active: AtomicUsize::new(0),
            }),
        })
    }
}

impl NativeTransferClient {
    /// Number of admitted sends and bound receivers in this shared domain.
    #[must_use]
    pub fn active_transfers(&self) -> usize {
        self.shared.active.load(Ordering::Relaxed)
    }

    /// Maximum concurrent sends and bound receivers in this shared domain.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.limit
    }

    /// The sender options every send of this client uses.
    #[must_use]
    pub fn send_options(&self) -> QuicSendOptions {
        self.shared.send_options
    }

    fn admit(&self) -> Result<NativeAdmission, NativeTransferError> {
        // Use the same CAS retry algorithm on stable and nightly, where
        // fetch_update was renamed to try_update.
        let mut active = self.shared.active.load(Ordering::Relaxed);
        loop {
            // The strict comparison also prevents usize overflow.
            if active >= self.shared.limit {
                return Err(NativeTransferError::CapacityExceeded {
                    limit: self.shared.limit,
                });
            }
            match self.shared.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => active = observed,
            }
        }
        Ok(NativeAdmission {
            shared: Arc::clone(&self.shared),
        })
    }

    fn admit_sender(&self) -> Result<NativeAdmission, NativeTransferError> {
        if self.shared.config.client_tls.is_none() {
            return Err(NativeTransferError::MissingClientTls);
        }
        self.admit()
    }

    /// Send a file or directory and wait for its actual peer commit receipt.
    ///
    /// This invokes the same native UDP/TLS transport as the CLI, including
    /// streaming reads, manifest exchange, hash verification and receiver
    /// publication. It does not construct an inert transfer actor or infer
    /// delivery from local byte counters. The full receipt is preserved.
    ///
    /// # Errors
    /// Returns TLS/admission errors before transport work; otherwise retains
    /// the original native error. An error after transmission does not prove
    /// that the receiver failed to commit; reconcile before retrying.
    pub async fn send_path(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        source: &Path,
    ) -> Result<SendReport, NativeTransferError> {
        let admission = self.admit_sender()?;
        Self::send_admitted(cx, remote, source, admission).await
    }

    async fn send_admitted(
        cx: &Cx,
        remote: SocketAddr,
        source: &Path,
        admission: NativeAdmission,
    ) -> Result<SendReport, NativeTransferError> {
        let report = transport_quic::send_path_with_options(
            cx,
            remote,
            source,
            admission.shared.config.clone(),
            &admission.shared.peer_label,
            admission.shared.send_options,
        )
        .await?;
        committed_send(report)
    }

    /// Admit a sender as a real child of the supplied runtime scope.
    ///
    /// Native capacity is reserved *before* runtime enqueue, bounding queued
    /// workers as well as active sockets. An immediate spawn refusal drops
    /// the reservation. Deferred runtime admission rejection releases it
    /// when the rejected factory is retired, before the canonical join.
    /// The child receives its own `Cx`; no parent context is shared across
    /// task identities. Join the returned handle for the actual receipt.
    ///
    /// Use the task handle's cancellation API and await its canonical join
    /// to observe termination. Dropping the handle never detaches the task
    /// from its region; callers still own that region's eventual drain.
    /// Neither handle construction nor a queued spawn establishes delivery.
    ///
    /// # Errors
    /// Refuses missing sender TLS, exhausted native capacity, or immediate
    /// runtime admission. Transport errors arrive through the joined task.
    pub fn spawn_send_path<P: Policy>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        remote: SocketAddr,
        source: impl Into<PathBuf>,
    ) -> Result<NativeSendTask, NativeTransferError> {
        let admission = self.admit_sender()?;
        let source = source.into();
        cx.spawn_in(scope, move |child| {
            // Type erasure keeps the large native future out of the spawn
            // wrapper while retaining the compiler's Send requirement.
            let future: Pin<
                Box<dyn Future<Output = Result<SendReport, NativeTransferError>> + Send>,
            > = Box::pin(
                async move { Self::send_admitted(&child, remote, &source, admission).await },
            );
            future
        })
        .map_err(NativeTransferError::Spawn)
    }

    /// Bind a real one-shot receiver before advertising its socket address.
    ///
    /// The returned receiver owns the socket and an admission slot until
    /// receive finishes or it is dropped. Port zero is supported; read the
    /// assigned port through [`NativeReceiver::local_addr`]. Publication is
    /// controlled by the caller's native receive options, without inventing
    /// new overwrite, mirror, or peer-authorization rules.
    ///
    /// # Errors
    /// Missing TLS, saturation, cancellation and bind failures are reported
    /// without returning a receiver or retaining an admission slot.
    pub async fn bind_receiver(
        &self,
        cx: &Cx,
        listen: SocketAddr,
        destination: impl Into<PathBuf>,
        options: QuicReceiveOptions,
    ) -> Result<NativeReceiver, NativeTransferError> {
        if self.shared.config.server_tls.is_none() {
            return Err(NativeTransferError::MissingServerTls);
        }
        let admission = self.admit()?;
        let destination = destination.into();
        let endpoint = bind_server_endpoint(cx, listen).await?;
        Ok(NativeReceiver {
            endpoint,
            destination,
            options,
            admission,
        })
    }
}

/// An admitted one-shot receiver with a live, exclusively owned UDP socket.
#[must_use = "receive must be awaited to transfer data; dropping only releases the listener"]
pub struct NativeReceiver {
    // Field order deliberately retires the socket before releasing admission.
    endpoint: QuicUdpEndpoint,
    destination: PathBuf,
    options: QuicReceiveOptions,
    admission: NativeAdmission,
}

impl std::fmt::Debug for NativeReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeReceiver")
            .field("local_addr", &self.local_addr())
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl NativeReceiver {
    /// Actual bound address, available without polling the receive future.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    /// Transfer this bound receiver into a scope-owned runtime worker.
    ///
    /// The already-held admission slot moves with the socket; spawning
    /// neither releases it early nor reserves a second slot. The original
    /// listener address remains valid throughout handoff. Immediate or
    /// deferred runtime rejection retires both resources. The returned
    /// canonical task handle supports cancellation and joined completion.
    ///
    /// # Errors
    /// Returns the actual immediate runtime admission refusal. The receiver
    /// is consumed on failure, closing its socket and releasing its slot.
    pub fn spawn<P: Policy>(
        self,
        cx: &Cx,
        scope: &Scope<'_, P>,
    ) -> Result<NativeReceiveTask, NativeTransferError> {
        cx.spawn_in(scope, move |child| {
            let future: Pin<
                Box<dyn Future<Output = Result<ReceiveReport, NativeTransferError>> + Send>,
            > = Box::pin(async move { self.receive(&child).await });
            future
        })
        .map_err(NativeTransferError::Spawn)
    }

    /// Receive, verify, and publish one transfer using the native data plane.
    ///
    /// Successful return contains the transport's actual committed paths and
    /// counters. Multiple paths are committed individually, not as one
    /// rollback-atomic directory transaction. The admission slot is retained
    /// across the entire native operation, including its receipt write.
    ///
    /// # Errors
    /// Preserves cancellation, authentication, size, I/O and integrity errors.
    /// Partial publication remains possible on failure; no fabricated receipt
    /// or automatic retry hides that boundary.
    pub async fn receive(self, cx: &Cx) -> Result<ReceiveReport, NativeTransferError> {
        let Self {
            endpoint,
            destination,
            options,
            admission,
        } = self;
        let report = receive_on_endpoint_with_options(
            cx,
            endpoint,
            &destination,
            &admission.shared.config,
            &admission.shared.peer_label,
            options,
        )
        .await?;
        committed_receive(report)
    }
}

#[cfg(test)]
#[path = "native_inline_tests.rs"]
mod tests;
