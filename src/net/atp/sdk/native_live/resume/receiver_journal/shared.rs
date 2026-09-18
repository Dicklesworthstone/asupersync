//! Journaled owners behind the existing shared, authenticated resume registry.
//!
//! Factory input is local authority, not peer-supplied recovery evidence. The
//! registry admits the certificate/nonce first. Its worker then revalidates the
//! retained bytes before any reply, using the same decoder as standalone restore.

use super::super::service::{Capacity, ResumeSessionKey};
use super::super::{Budget, Credit, ResumableReceiver, ResumeError, ResumeReport};
use super::{Hello, ReceiverCheckpoint, ReceiverCheckpointPhase, ReceiverCheckpointStore};
use crate::cx::Cx;
use crate::io::AsyncRead;
use crate::net::TcpStream;
use crate::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use crate::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamError, Wire, authorize};
use crate::tls::{TlsAcceptor, TlsStream};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;

/// One sink and its write-ahead store, consumed by shared-service admission.
///
/// Construct this only from protected application state for the factory's exact
/// client/nonce. Keep exclusive access to the sink and journal. An unresolved or
/// missing old journal is not permission to return a new session instead.
/// No networking, source reading, or persistence happens in these constructors.
#[must_use = "return the owned session from ResumableService::next_journaled"]
pub struct JournaledSession<W> {
    sink: W,
    store: Box<dyn ReceiverCheckpointStore + Send + Unpin>,
    restore: Option<(Box<dyn AsyncRead + Send + Unpin>, ReceiverCheckpoint)>,
}

impl<W> fmt::Debug for JournaledSession<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledSession")
            .field("restoring", &self.restore.is_some())
            .finish_non_exhaustive()
    }
}

impl<W> JournaledSession<W> {
    /// Own a genuinely new sink and the store that synchronizes its bytes before ACKs.
    pub fn new<S: ReceiverCheckpointStore + Send + Unpin + 'static>(sink: W, store: S) -> Self {
        Self {
            sink,
            store: Box::new(store),
            restore: None,
        }
    }

    /// Own protected history and a reader positioned at byte zero of this exact sink.
    ///
    /// The sink must append at the actual retained end. Admission validates the
    /// certificate, nonce, original negotiation, attempt ceiling, phase and every
    /// retained byte before replying. `Finalizing` is refused, never recommitted.
    pub fn restore<S, R>(sink: W, store: S, retained: R, saved: ReceiverCheckpoint) -> Self
    where
        S: ReceiverCheckpointStore + Send + Unpin + 'static,
        R: AsyncRead + Send + Unpin + 'static,
    {
        Self {
            sink,
            store: Box::new(store),
            restore: Some((Box::new(retained), saved)),
        }
    }

    // The enclosing factory/initialization future has one cancellation-aware
    // deadline. No separate listener or additional SDK admission is allocated.
    pub(in super::super) async fn initialize(
        self,
        cx: &Cx,
        key: ResumeSessionKey,
        acceptor: TlsAcceptor,
        config: LiveStreamConfig,
        maximum: u32,
        capacity: Arc<Capacity>,
    ) -> Result<JournaledReceiver<W>, LiveStreamError> {
        authorize(cx)?;
        let Self {
            sink,
            store,
            restore,
        } = self;
        let mut receiver = ResumableReceiver {
            sink,
            listener: None,
            acceptor,
            expected_client: key.client,
            config,
            offered: None,
            agreed: None,
            prefix: None,
            hash: Sha256::new(),
            pending: None,
            sink_written_bytes: 0,
            final_receipt: None,
            commit_started: false,
            completed: None,
            failed: false,
            budget: Budget {
                used: 0,
                maximum,
                _credit: Credit::Shared { _capacity: capacity },
            },
        };
        if let Some((mut retained, saved)) = restore {
            let agreed = validate_binding(&saved, key, &receiver.config, maximum)?;
            // Reuse the standalone validator: prefix hashing and exact surviving
            // tail comparison, not a second parser or an offset-only restore.
            let (hash, pending, written) = saved.revalidate(&mut retained).await?;
            receiver.final_receipt =
                (saved.phase != ReceiverCheckpointPhase::Receiving).then(|| saved.receipt());
            receiver.completed = saved.committed_receipt();
            receiver.commit_started = receiver.completed.is_some();
            receiver.offered = Some(saved.offered.to_vec());
            receiver.agreed = Some(agreed);
            receiver.prefix = Some(saved.prefix);
            receiver.hash = hash;
            receiver.pending = pending;
            receiver.sink_written_bytes = written;
            // Preserve the WAL's immutable ceiling even if this service permits more.
            receiver.budget.used = saved.used;
            receiver.budget.maximum = saved.maximum;
        }
        Ok(JournaledReceiver { receiver, store })
    }
}

fn validate_binding(
    saved: &ReceiverCheckpoint,
    key: ResumeSessionKey,
    config: &LiveStreamConfig,
    maximum: u32,
) -> Result<Hello, LiveStreamError> {
    let agreed = saved.validate()?;
    if saved.client != key.client || saved.prefix.stream_nonce != key.nonce {
        return Err(LiveStreamError::Configuration(
            "receiver journal does not match authenticated session key",
        ));
    }
    if agreed.epoch_bytes > config.epoch_bytes
        || agreed.max_bytes > config.max_bytes
        || saved.maximum > maximum
    {
        return Err(LiveStreamError::Configuration(
            "receiver journal exceeds shared service policy",
        ));
    }
    if saved.used >= saved.maximum {
        return Err(LiveStreamError::Configuration(
            "receiver journal attempt budget exhausted",
        ));
    }
    if saved.phase == ReceiverCheckpointPhase::Finalizing {
        return Err(LiveStreamError::Configuration(
            "receiver application commit remains unresolved",
        ));
    }
    Ok(agreed)
}

pub(in super::super) struct JournaledReceiver<W> {
    pub(in super::super) receiver: ResumableReceiver<W>,
    store: Box<dyn ReceiverCheckpointStore + Send + Unpin>,
}

impl<W: LiveStreamCommitSink + Unpin> JournaledReceiver<W> {
    pub(in super::super) async fn attempt(
        &mut self,
        cx: &Cx,
        wire: &mut Wire<TlsStream<TcpStream>>,
        offered: &[u8],
    ) -> ResumeReport {
        let receiver = &mut self.receiver;
        let reused = receiver.completed.is_some();
        let outcome = if receiver.failed {
            Err(ResumeError::LocalFailure)
        } else {
            match authorize(cx)
                .map_err(ResumeError::from)
                .and_then(|()| receiver.budget.take())
            {
                Ok(()) => {
                    let mut store: super::Store<'_> = Some(&mut *self.store);
                    // Charge an existing session's authenticated routed attempt
                    // durably before checking a possibly changed offer or replying.
                    let checkpoint = if receiver.agreed.is_some() {
                        receiver.checkpoint_boundary(cx, &mut store).await
                    } else {
                        Ok(())
                    };
                    match checkpoint {
                        Ok(()) => {
                            receiver.receive_wire_checkpointed(cx, wire, offered, store).await
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome,
            prefix: receiver.prefix.clone(),
            attempts: receiver.budget.used,
            receipt_reused: reused,
            retained_epoch_bytes: receiver
                .pending
                .as_ref()
                .map_or(0, |epoch| epoch.bytes().len()),
            sink_written_bytes: receiver.sink_written_bytes,
            completed: receiver.completed.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{NativeClientCertificateId, digest, initial, offer};
    use crate::io::ReadBuf;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use zeroize::Zeroizing;

    fn saved() -> ReceiverCheckpoint {
        let hello = Hello { nonce: [9; 32], epoch_bytes: 8, max_bytes: 64 };
        ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix: initial(&hello),
            prefix_hash: digest(&Sha256::new()),
            pending_hash: digest(&Sha256::new()),
            used: 1,
            maximum: 4,
            phase: ReceiverCheckpointPhase::Receiving,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    fn profile() -> LiveStreamConfig {
        LiveStreamConfig { epoch_bytes: 8, max_bytes: 64, ..LiveStreamConfig::default() }
    }

    #[test]
    fn shared_restoration_binds_the_full_key_and_current_resource_policy() {
        let saved = saved();
        let key = ResumeSessionKey { client: saved.client, nonce: [9; 32] };
        assert!(validate_binding(&saved, key, &profile(), 4).is_ok());
        for changed in [
            ResumeSessionKey { nonce: [8; 32], ..key },
            ResumeSessionKey { client: NativeClientCertificateId::from_sha256([4; 32]), ..key },
        ] {
            assert!(matches!(validate_binding(&saved, changed, &profile(), 4),
                Err(LiveStreamError::Configuration("receiver journal does not match authenticated session key"))));
        }
        for (config, maximum) in [
            (LiveStreamConfig { epoch_bytes: 4, ..profile() }, 4),
            (LiveStreamConfig { max_bytes: 63, ..profile() }, 4),
            (profile(), 3),
        ] {
            assert!(matches!(validate_binding(&saved, key, &config, maximum),
                Err(LiveStreamError::Configuration("receiver journal exceeds shared service policy"))));
        }
    }

    #[test]
    fn policy_validation_does_not_rewrite_history_or_revive_uncertain_commits() {
        let mut saved = saved();
        let key = ResumeSessionKey { client: saved.client, nonce: [9; 32] };
        let before = saved.to_canonical_bytes().unwrap();
        assert!(validate_binding(&saved, key, &profile(), 8).is_ok());
        assert_eq!(saved.maximum_attempts(), 4);
        assert_eq!(saved.to_canonical_bytes().unwrap().as_slice(), before.as_slice());
        saved.phase = ReceiverCheckpointPhase::Finalizing;
        assert!(matches!(validate_binding(&saved, key, &profile(), 4),
            Err(LiveStreamError::Configuration("receiver application commit remains unresolved"))));
        saved.phase = ReceiverCheckpointPhase::Committed;
        assert!(validate_binding(&saved, key, &profile(), 4).is_ok());
        saved.used = 4;
        assert!(matches!(validate_binding(&saved, key, &profile(), 4),
            Err(LiveStreamError::Configuration("receiver journal attempt budget exhausted"))));
    }

    struct Untouched;
    impl ReceiverCheckpointStore for Untouched {
        fn poll_store(self: Pin<&mut Self>, _: &mut Context<'_>, _: &ReceiverCheckpoint) -> Poll<io::Result<()>> {
            panic!("session construction must not persist");
        }
    }
    impl AsyncRead for Untouched {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            panic!("session construction must not read");
        }
    }

    #[test]
    fn constructing_or_debugging_a_factory_result_does_not_drive_providers() {
        let fresh = JournaledSession::new((), Untouched);
        let restored = JournaledSession::restore((), Untouched, Untouched, saved());
        assert_eq!(format!("{fresh:?}"), "JournaledSession { restoring: false, .. }");
        assert_eq!(format!("{restored:?}"), "JournaledSession { restoring: true, .. }");
    }
}
