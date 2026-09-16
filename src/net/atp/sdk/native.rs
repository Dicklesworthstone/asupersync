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

use super::{AtpSdk, SdkMode};
use crate::cx::{Cx, Scope};
use crate::net::atp::transport_quic::native_link::{
    bind_server_endpoint, receive_on_endpoint_with_options,
};
use crate::net::atp::transport_quic::{
    self, QuicConfig, QuicReceiveOptions, QuicTransportError, ReceiveReport, SendReport,
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
    /// # Errors
    /// Refuses daemon delegation, zero limits, and invalid transport config
    /// before opening sockets or inspecting a source/destination path.
    pub fn native_transfers(
        &self,
        mut config: QuicConfig,
    ) -> Result<NativeTransferClient, NativeTransferError> {
        if !matches!(self.mode, SdkMode::InProcess) {
            return Err(NativeTransferError::UnsupportedMode);
        }
        let limit = usize::try_from(self.default_config.max_concurrent_transfers)
            .map_err(|_| NativeTransferError::InvalidLimit("max_concurrent_transfers"))?;
        if limit == 0 {
            return Err(NativeTransferError::InvalidLimit("max_concurrent_transfers"));
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
        let chunk_limit = usize::try_from(self.transfer_policy.max_chunk_size_bytes)
            .unwrap_or(usize::MAX);
        config.chunk_size = config.chunk_size.min(chunk_limit);
        config.validate()?;
        Ok(NativeTransferClient {
            shared: Arc::new(NativeShared {
                config,
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

    fn admit(&self) -> Result<NativeAdmission, NativeTransferError> {
        self.shared
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                // The strict comparison also prevents usize overflow.
                if active < self.shared.limit {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .map_err(|_| NativeTransferError::CapacityExceeded {
                limit: self.shared.limit,
            })?;
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
        let report = transport_quic::send_path(
            cx,
            remote,
            source,
            admission.shared.config.clone(),
            &admission.shared.peer_label,
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
            > = Box::pin(async move {
                Self::send_admitted(&child, remote, &source, admission).await
            });
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
mod tests {
    use super::*;
    use crate::net::atp::sdk::{SessionConfig, TransferPolicy};

    fn client(capacity: u32) -> NativeTransferClient {
        AtpSdk::new_in_process(SessionConfig {
            max_concurrent_transfers: capacity,
            ..SessionConfig::default()
        })
        .native_transfers(QuicConfig::default().use_transport_authenticated_symbols())
        .unwrap()
    }

    #[test]
    fn rejected_reports_retain_partial_publication_evidence() {
        use crate::net::atp::transport_quic::ReceiveReceipt;

        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 17,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            reason: None,
            committed_paths: vec!["partial.bin".to_string()],
        };
        let report = SendReport {
            transfer_id: "actual-native-id".to_string(),
            bytes_sent: 17,
            files: 1,
            symbols_sent: 4,
            feedback_rounds: 1,
            merkle_root_hex: "retained-root".to_string(),
            receipt,
            peer: "127.0.0.1:1234".parse().unwrap(),
        };
        assert!(committed_send(report.clone()).is_ok());
        for (committed, sha_ok, merkle_ok) in
            [(false, true, true), (true, false, true), (true, true, false)]
        {
            let mut rejected = report.clone();
            rejected.receipt.committed = committed;
            rejected.receipt.sha_ok = sha_ok;
            rejected.receipt.merkle_ok = merkle_ok;
            rejected.receipt.reason = Some("peer-side failure".to_string());
            let original = rejected.clone();
            match committed_send(rejected) {
                Err(NativeTransferError::UncommittedSend(retained)) => {
                    assert_eq!(retained.receipt, original.receipt);
                    assert_eq!(retained.transfer_id, original.transfer_id);
                    assert_eq!(retained.merkle_root_hex, original.merkle_root_hex);
                    assert_eq!(retained.peer, original.peer);
                }
                other => panic!("invalid receipt was accepted or discarded: {other:?}"),
            }
        }

        let received = ReceiveReport {
            transfer_id: "partially-published".to_string(),
            bytes_received: 17,
            files: 1,
            committed: false,
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            committed_paths: vec![PathBuf::from("partial.bin")],
            peer: report.peer,
        };
        match committed_receive(received) {
            Err(NativeTransferError::UncommittedReceive(retained)) => {
                assert_eq!(retained.transfer_id, "partially-published");
                assert_eq!(retained.committed_paths, vec![PathBuf::from("partial.bin")]);
                assert_eq!(retained.bytes_received, 17);
            }
            other => panic!("partial receive report was accepted or discarded: {other:?}"),
        }
    }

    #[test]
    fn native_size_limits_never_relax_either_policy() {
        let sdk = AtpSdk::new_in_process(SessionConfig::default()).with_transfer_policy(
            TransferPolicy {
                max_transfer_size_bytes: 2048,
                max_chunk_size_bytes: 512,
                ..TransferPolicy::default()
            },
        );
        for (bytes, chunk, expected_bytes, expected_chunk) in
            [(4096, 1024, 2048, 512), (1024, 256, 1024, 256)]
        {
            let config = QuicConfig {
                max_transfer_bytes: bytes,
                chunk_size: chunk,
                ..QuicConfig::default().use_transport_authenticated_symbols()
            };
            let native = sdk.native_transfers(config).unwrap();
            assert_eq!(native.shared.config.max_transfer_bytes, expected_bytes);
            assert_eq!(native.shared.config.chunk_size, expected_chunk);
            assert_eq!(native.active_transfers(), 0);
        }
    }

    #[test]
    fn native_admission_is_shared_across_clones_and_released_on_drop() {
        let client = client(2);
        let clone = client.clone();
        let first = client.admit().unwrap();
        let second = clone.admit().unwrap();
        assert_eq!(client.active_transfers(), 2);
        assert_eq!(clone.active_transfers(), 2);
        assert!(matches!(
            clone.admit(),
            Err(NativeTransferError::CapacityExceeded { limit: 2 })
        ));
        assert_eq!(client.active_transfers(), 2);
        drop(first);
        let replacement = clone.admit().unwrap();
        drop(second);
        assert_eq!(client.active_transfers(), 1);
        drop(replacement);
        assert_eq!(client.active_transfers(), 0);
    }

    #[test]
    fn native_admission_survives_cross_thread_ownership_and_unwind() {
        let client = client(1);
        let permit = client.admit().unwrap();
        let clone = client.clone();
        std::thread::spawn(move || {
            assert!(matches!(
                clone.admit(),
                Err(NativeTransferError::CapacityExceeded { limit: 1 })
            ));
            drop(permit);
        })
        .join()
        .unwrap();
        assert_eq!(client.active_transfers(), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = client.admit().unwrap();
            panic!("exercise native admission cleanup");
        }));
        assert!(result.is_err());
        assert_eq!(client.active_transfers(), 0);
        drop(client.admit().unwrap());
    }

    #[test]
    fn native_configuration_refuses_invalid_limits_and_daemon_mode() {
        let sdk = AtpSdk::new_in_process(SessionConfig {
            max_concurrent_transfers: 0,
            ..SessionConfig::default()
        });
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::InvalidLimit("max_concurrent_transfers"))
        ));
        for (bytes, chunk, field) in [
            (0, 512, "max_transfer_size_bytes"),
            (2048, 0, "max_chunk_size_bytes"),
        ] {
            let sdk = AtpSdk::new_in_process(SessionConfig::default()).with_transfer_policy(
                TransferPolicy {
                    max_transfer_size_bytes: bytes,
                    max_chunk_size_bytes: chunk,
                    ..TransferPolicy::default()
                },
            );
            assert!(matches!(
                sdk.native_transfers(QuicConfig::default()),
                Err(NativeTransferError::InvalidLimit(actual)) if actual == field
            ));
        }
        let sdk = AtpSdk::new_daemon_delegated(
            SessionConfig::default(),
            "unused.invalid:1".to_string(),
            None,
        );
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::UnsupportedMode)
        ));
    }

    #[test]
    fn native_adapter_does_not_supply_missing_authentication() {
        let sdk = AtpSdk::new_in_process(SessionConfig::default());
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::Transport(QuicTransportError::Config(_)))
        ));
        let client = client(1);
        let cx = Cx::for_testing();
        let remote = "127.0.0.1:9".parse().unwrap();
        futures_lite::future::block_on(async {
            assert!(matches!(
                client.send_path(&cx, remote, Path::new("unused-source")).await,
                Err(NativeTransferError::MissingClientTls)
            ));
            assert!(matches!(
                client
                    .bind_receiver(
                        &cx,
                        "127.0.0.1:0".parse().unwrap(),
                        "unused-destination",
                        QuicReceiveOptions::default(),
                    )
                    .await,
                Err(NativeTransferError::MissingServerTls)
            ));
        });
        assert_eq!(client.active_transfers(), 0);
    }
}
