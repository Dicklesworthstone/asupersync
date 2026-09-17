//! Connection-resumable live transfers with retained source and sink ownership.
//!
//! This is the distinct `atp-live-resume/1` ALPN, not `atp-live/1`. A session
//! survives a lost connection or a dropped attempt future, NOT process exit.
//! The sender retains at most one unacknowledged epoch. The receiver retains
//! partial sink-write progress, so reconnecting never repeats an accepted write.
//! Reconciliation accepts only the acknowledged prefix or the one pending next
//! prefix, with its exact running hash. It never trusts an arbitrary peer offset.
//!
//! Each attempt performs fresh mandatory mTLS. The receiver requires an explicit
//! client certificate fingerprint; the sender pins the first verified server
//! certificate. A nonce is continuity data, not authorization. Retries are
//! explicit and bounded, and a session holds its admission slot until dropped.
//! Source/sink errors and panics make the session unusable; they cannot safely
//! be retried as though no local effects occurred. Ordinary network interruptions
//! retain continuation state. Keep the session in its owning task/region and
//! join that task; no detached workers or automatic reconnect loops are created.
//!
//! Whole-stream finalization uses LiveStreamCommitSink. A completed application
//! commit is remembered before sending Proof, allowing a lost Proof to be sent
//! again without recommitting. Epoch acknowledgements are still prefix flushes.
//! This is not crash recovery or a general exactly-once external-effects claim.
//! Existing sources/sinks must retain Pending-operation state across dropped
//! attempt futures; never access their underlying handles concurrently.

use super::super::super::NativeClientCertificateId;
use super::super::{
    EPOCH_HEADER_BYTES, HELLO_BYTES, Hello, LiveStreamConfig, LiveStreamError, LiveStreamPrefix,
    LiveStreamReceipt, LiveStreamReceiver, LiveStreamSender, Permit, Wire, advance, authorize,
    bounded, encode_epoch, encode_final, encode_prefix, expect,
};
use super::{LiveStreamCommitError, LiveStreamCommitSink, proof_failed};
use crate::cx::Cx;
use crate::io::{AsyncRead, ReadBuf};
use crate::net::atp::protocol::frames::FrameType;
use crate::net::{TcpListener, TcpStream};
use crate::tls::{TlsAcceptor, TlsConnector, TlsStream};
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Explicitly negotiated profile for retained-session reconnection.
pub const RESUMABLE_LIVE_ALPN: &[u8] = b"atp-live-resume/1";
const MAGIC: &[u8; 8] = b"ATPRSM01";
const OFFER_BYTES: usize = 8 + HELLO_BYTES;
const RESUME_BYTES: usize = OFFER_BYTES + 48 + 32 + 1;

/// Refusal or original transfer failure from one explicit connection attempt.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResumeError {
    /// An original authentication, timeout, cancellation, I/O or commit failure.
    #[error(transparent)]
    Transfer(#[from] LiveStreamError),
    /// An earlier source/sink failure or panic prevents trustworthy continuation.
    #[error("resumable session has a terminal local failure")]
    LocalFailure,
    /// No additional connect/accept attempts are admitted.
    #[error("resumable session attempt budget exhausted")]
    AttemptsExhausted,
    /// A peer did not describe an admissible continuation of this session.
    #[error("resumable stream continuity mismatch: {0}")]
    Continuity(&'static str),
    /// The certificate differs from the explicitly expected or pinned identity.
    #[error("resumable stream peer certificate changed")]
    PeerIdentity,
    /// The local final-state checkpoint failed or was interrupted before finalization.
    #[error(transparent)]
    Checkpoint(#[from] Box<finalization::FinalProofPersistError>),
}

/// Snapshot after an attempt; a prefix alone is never whole-stream success.
#[derive(Debug)]
#[must_use = "inspect outcome and committed receipt before retrying"]
pub struct ResumeReport {
    /// Sender: validated final Proof. Receiver: local commit and Proof write.
    pub outcome: Result<LiveStreamReceipt, ResumeError>,
    /// Last acknowledged (sender) or fully flushed (receiver) prefix.
    pub prefix: Option<LiveStreamPrefix>,
    /// Cumulative admitted connect/accept attempts, including failed handshakes.
    pub attempts: u32,
    /// Whether the final result was already known before this attempt.
    /// A sender then performs no networking; a receiver still authenticates and
    /// retransmits Proof. This is historical evidence, not a new sink commit.
    pub receipt_reused: bool,
    /// Retained data bytes in an unacknowledged/partially written epoch.
    pub retained_epoch_bytes: usize,
    /// Successful receiver sink-write bytes, including a partially flushed epoch.
    pub sink_written_bytes: u64,
    /// Confirmed receiver application commit, even if Proof was interrupted.
    /// On a sender this is populated only after a validated final peer Proof.
    pub completed: Option<LiveStreamReceipt>,
}

// Keep admission alive through destruction of returned, uncollected session
// owners as well as active futures. Neither form grants a second admission.
enum Credit {
    Direct { _permit: Permit },
    Shared { _capacity: Arc<service::Capacity> },
}

struct Budget {
    used: u32,
    maximum: u32,
    _credit: Credit,
}

impl Budget {
    fn take(&mut self) -> Result<(), ResumeError> {
        if self.used >= self.maximum {
            return Err(ResumeError::AttemptsExhausted);
        }
        self.used += 1;
        Ok(())
    }
}

fn validate_attempts(attempts: u32) -> Result<(), LiveStreamError> {
    if !(1..=1024).contains(&attempts) {
        return Err(LiveStreamError::Configuration(
            "resume attempts must be 1..=1024",
        ));
    }
    Ok(())
}

fn offer(hello: &Hello) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&hello.encode());
    bytes
}

fn decode_offer(bytes: &[u8]) -> Result<Hello, ResumeError> {
    if bytes.len() != OFFER_BYTES || &bytes[..8] != MAGIC {
        return Err(ResumeError::Continuity("invalid resume hello"));
    }
    Ok(Hello::decode(&bytes[8..])?)
}

fn initial(hello: &Hello) -> LiveStreamPrefix {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.live.resume.hello.v1");
    hash.update(offer(hello));
    LiveStreamPrefix {
        stream_nonce: hello.nonce,
        epochs: 0,
        bytes: 0,
        chain: hash.finalize().into(),
    }
}

fn digest(hash: &Sha256) -> [u8; 32] {
    hash.clone().finalize().into()
}

fn peer_certificate(tls: &TlsStream<TcpStream>) -> Result<[u8; 32], ResumeError> {
    if tls.alpn_protocol() != Some(RESUMABLE_LIVE_ALPN) {
        return Err(ResumeError::Continuity("resume ALPN was not negotiated"));
    }
    let cert = tls
        .peer_leaf_certificate_der()
        .ok_or(ResumeError::PeerIdentity)?;
    Ok(Sha256::digest(cert).into())
}

struct PendingEpoch {
    payload: Vec<u8>,
    next: LiveStreamPrefix,
    written: usize,
}

impl PendingEpoch {
    fn bytes(&self) -> &[u8] {
        &self.payload[EPOCH_HEADER_BYTES..]
    }
}

/// Owned producer and one-epoch retransmission window across explicit attempts.
///
/// The remote address is fixed, and the first authenticated server certificate
/// is pinned for the session. The producer is never rewound or reread. A dropped
/// attempt releases only that connection; drop the session to release admission.
#[must_use = "retain and drive the session to deliver its source"]
pub struct ResumableSender<R> {
    source: R,
    connector: TlsConnector,
    domain: String,
    remote: SocketAddr,
    config: LiveStreamConfig,
    offered: Hello,
    agreed: Option<Hello>,
    peer: Option<[u8; 32]>,
    prefix: Option<LiveStreamPrefix>,
    hash: Sha256,
    pending: Option<PendingEpoch>,
    buffer: Vec<u8>,
    final_receipt: Option<LiveStreamReceipt>,
    completed: Option<LiveStreamReceipt>,
    failed: bool,
    budget: Budget,
}

impl<R> fmt::Debug for ResumableSender<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumableSender")
            .field("attempts", &self.budget.used)
            .field("completed", &self.completed.is_some())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl LiveStreamSender {
    /// Reserve a resumable producer without networking or polling the source.
    ///
    /// The source, one unacknowledged epoch and admission credit remain owned by
    /// the returned session. Every send call admits at most one connection. The
    /// 1..=1024 attempt bound includes connect/handshake failures. There is no
    /// fallback to a legacy profile or a different server certificate.
    pub fn resumable_reader<R: AsyncRead + Unpin>(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        source: R,
        max_attempts: u32,
    ) -> Result<ResumableSender<R>, ResumeError> {
        authorize(cx)?;
        validate_attempts(max_attempts)?;
        let permit = self.admission.reserve()?;
        let mut nonce = [0; 32];
        cx.random_bytes(&mut nonce);
        let mut tls = (**self.connector.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        Ok(ResumableSender {
            source,
            connector: TlsConnector::new(tls),
            domain: self.domain.clone(),
            remote,
            config: self.config.clone(),
            offered: Hello {
                nonce,
                epoch_bytes: self.config.epoch_bytes,
                max_bytes: self.config.max_bytes,
            },
            agreed: None,
            peer: None,
            prefix: None,
            hash: Sha256::new(),
            pending: None,
            buffer: Vec::new(),
            final_receipt: None,
            completed: None,
            failed: false,
            budget: Budget {
                used: 0,
                maximum: max_attempts,
                _credit: Credit::Direct { _permit: permit },
            },
        })
    }
}

impl<R: AsyncRead + Unpin> ResumableSender<R> {
    /// Last prefix acknowledged by the authenticated receiver, not whole-stream success.
    #[must_use]
    pub fn acknowledged_prefix(&self) -> Option<&LiveStreamPrefix> {
        self.prefix.as_ref()
    }

    /// Final peer Proof retained before returning success, including after a dropped wait.
    #[must_use]
    pub fn completed_receipt(&self) -> Option<&LiveStreamReceipt> {
        self.completed.as_ref()
    }

    /// Attempt delivery once, retaining continuation state on network interruption.
    ///
    /// After success later calls return a marked cached receipt without connecting.
    /// Source errors/panics are terminal. Cancellation is checked by the supplied
    /// Cx; continuation requires an explicitly driven attempt with valid authority.
    pub async fn send(&mut self, cx: &Cx) -> ResumeReport {
        let receipt_reused = self.completed.is_some();
        let outcome = if let Some(receipt) = &self.completed {
            Ok(receipt.clone())
        } else if self.failed {
            Err(ResumeError::LocalFailure)
        } else {
            match authorize(cx)
                .map_err(ResumeError::from)
                .and_then(|()| self.budget.take())
            {
                Ok(()) => self.send_inner(cx, None).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome,
            prefix: self.prefix.clone(),
            attempts: self.budget.used,
            receipt_reused,
            retained_epoch_bytes: self.pending.as_ref().map_or(0, |epoch| epoch.bytes().len()),
            sink_written_bytes: 0,
            completed: self.completed.clone(),
        }
    }

    async fn send_inner(
        &mut self,
        cx: &Cx,
        mut checkpoint: Option<&mut (dyn finalization::FinalProofStore + Send + Unpin)>,
    ) -> Result<LiveStreamReceipt, ResumeError> {
        let timeout = self.config.operation_timeout;
        let tcp = bounded(
            cx,
            timeout,
            "resume connect",
            TcpStream::connect(self.remote),
        )
        .await?;
        let tls = bounded(
            cx,
            timeout,
            "resume TLS",
            self.connector.connect(&self.domain, tcp),
        )
        .await?;
        let peer = peer_certificate(&tls)?;
        if self.peer.is_some_and(|expected| expected != peer) {
            return Err(ResumeError::PeerIdentity);
        }
        self.peer = Some(peer);
        let mut wire = Wire::new(tls);
        bounded(
            cx,
            timeout,
            "resume hello",
            wire.send(FrameType::Handshake, offer(&self.offered)),
        )
        .await?;
        let ack = bounded(cx, timeout, "resume state", wire.receive()).await?;
        self.reconcile(expect(&ack, FrameType::HandshakeAck)?)?;
        loop {
            if self.pending.is_none() && self.final_receipt.is_none() {
                let agreed = self.agreed.as_ref().expect("negotiated session");
                let (epoch_bytes, max_bytes) = (agreed.epoch_bytes, agreed.max_bytes);
                let prefix = self.prefix.as_ref().expect("negotiated prefix").clone();
                let remaining = max_bytes - prefix.bytes;
                let window = epoch_bytes
                    .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
                self.buffer.resize(window, 0);
                let count = bounded(
                    cx,
                    timeout,
                    "resume source",
                    poll_fn(|ctx| {
                        // A provider panic cannot leave this session restartable.
                        self.failed = true;
                        let mut out = ReadBuf::new(&mut self.buffer);
                        let polled = Pin::new(&mut self.source).poll_read(ctx, &mut out);
                        let count = out.filled().len();
                        self.failed = false;
                        match polled {
                            Poll::Pending if count == 0 => Poll::Pending,
                            Poll::Pending => {
                                self.failed = true;
                                Poll::Ready(Err(io::Error::other("source advanced on Pending")))
                            }
                            Poll::Ready(Err(error)) => {
                                self.failed = true;
                                Poll::Ready(Err(error))
                            }
                            Poll::Ready(Ok(())) => Poll::Ready(Ok(count)),
                        }
                    }),
                )
                .await?;
                if count as u64 > remaining {
                    self.failed = true;
                    return Err(LiveStreamError::TooLarge(max_bytes).into());
                }
                if count == 0 {
                    self.final_receipt = Some(LiveStreamReceipt {
                        prefix: prefix.clone(),
                        source_sha256: digest(&self.hash),
                    });
                } else {
                    let payload = encode_epoch(&prefix, &self.buffer[..count]);
                    let next = advance(&prefix, &payload, epoch_bytes, max_bytes)?;
                    self.pending = Some(PendingEpoch {
                        payload,
                        next,
                        written: 0,
                    });
                }
            }
            if let Some(pending) = &self.pending {
                // Wire owns only a copy; the session keeps the retransmission window.
                bounded(
                    cx,
                    timeout,
                    "resume epoch write",
                    wire.send(FrameType::ObjectData, pending.payload.clone()),
                )
                .await?;
                let ack =
                    bounded(cx, timeout, "resume epoch acknowledgement", wire.receive()).await?;
                if expect(&ack, FrameType::Control)? != encode_prefix(&pending.next) {
                    return Err(ResumeError::Continuity("wrong epoch acknowledgement"));
                }
                self.accept_pending();
                continue;
            }
            let receipt = self
                .final_receipt
                .as_ref()
                .expect("source finished")
                .clone();
            if let Some(store) = checkpoint.as_mut() {
                let saved = finalization::FinalProofCheckpoint::capture(self)?;
                finalization::persist(cx, timeout, &mut **store, &saved).await?;
            }
            let payload = encode_final(&receipt);
            bounded(
                cx,
                timeout,
                "resume final write",
                wire.send(FrameType::ObjectComplete, payload.clone()),
            )
            .await?;
            let proof = bounded(cx, timeout, "resume final proof", wire.receive()).await?;
            if expect(&proof, FrameType::Proof)? != payload {
                return Err(ResumeError::Continuity("wrong final proof"));
            }
            self.completed = Some(receipt.clone());
            return Ok(receipt);
        }
    }

    fn accept_pending(&mut self) {
        let pending = self.pending.take().expect("one retained epoch");
        self.hash.update(pending.bytes());
        self.prefix = Some(pending.next);
    }

    fn reconcile(&mut self, bytes: &[u8]) -> Result<(), ResumeError> {
        if bytes.len() != RESUME_BYTES {
            return Err(ResumeError::Continuity("invalid resume state size"));
        }
        let agreed = decode_offer(&bytes[..OFFER_BYTES])?;
        if agreed.nonce != self.offered.nonce
            || agreed.epoch_bytes > self.offered.epoch_bytes
            || agreed.max_bytes > self.offered.max_bytes
        {
            return Err(ResumeError::Continuity(
                "peer widened or rebound the session",
            ));
        }
        if let Some(previous) = &self.agreed {
            if offer(previous) != offer(&agreed) {
                return Err(ResumeError::Continuity("negotiated limits changed"));
            }
        }
        let prefix_bytes = &bytes[OFFER_BYTES..OFFER_BYTES + 48];
        let hash_bytes = &bytes[OFFER_BYTES + 48..OFFER_BYTES + 80];
        let complete = match bytes[OFFER_BYTES + 80] {
            0 => false,
            1 => true,
            _ => return Err(ResumeError::Continuity("invalid completion flag")),
        };
        let initial_prefix = initial(&agreed);
        let current = self.prefix.as_ref().unwrap_or(&initial_prefix);
        let current_matches =
            prefix_bytes == encode_prefix(current) && hash_bytes == digest(&self.hash);
        let pending_matches = self.pending.as_ref().is_some_and(|pending| {
            let mut hash = self.hash.clone();
            hash.update(pending.bytes());
            prefix_bytes == encode_prefix(&pending.next) && hash_bytes == digest(&hash)
        });
        if !current_matches && !pending_matches {
            return Err(ResumeError::Continuity(
                "remote prefix is outside the retained window",
            ));
        }
        if complete
            && self.final_receipt.as_ref().is_none_or(|receipt| {
                prefix_bytes != encode_prefix(&receipt.prefix)
                    || hash_bytes != receipt.source_sha256
            })
        {
            return Err(ResumeError::Continuity(
                "peer completed before verified source EOF",
            ));
        }
        // Validate the entire reply before changing source/hash/cursor state.
        if self.agreed.is_none() {
            self.prefix = Some(initial_prefix);
            self.agreed = Some(agreed);
        }
        if pending_matches {
            self.accept_pending();
        }
        Ok(())
    }
}

/// One retained listener, committing sink, and exact client-bound continuation.
///
/// Partial writes and a pending commit live here, not in attempt-local futures.
/// Application commit is invoked at most once to completion in this session.
/// No mutable access to the sink escapes while continuation is possible.
#[must_use = "retain and drive the session to receive and commit data"]
pub struct ResumableReceiver<W> {
    sink: W,
    // None only for a session privately owned by the shared-port service.
    listener: Option<TcpListener>,
    acceptor: TlsAcceptor,
    expected_client: NativeClientCertificateId,
    config: LiveStreamConfig,
    offered: Option<Vec<u8>>,
    agreed: Option<Hello>,
    prefix: Option<LiveStreamPrefix>,
    hash: Sha256,
    pending: Option<PendingEpoch>,
    sink_written_bytes: u64,
    final_receipt: Option<LiveStreamReceipt>,
    commit_started: bool,
    completed: Option<LiveStreamReceipt>,
    failed: bool,
    budget: Budget,
}

impl<W> fmt::Debug for ResumableReceiver<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumableReceiver")
            .field("attempts", &self.budget.used)
            .field("sink_written_bytes", &self.sink_written_bytes)
            .field("completed", &self.completed.is_some())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl LiveStreamReceiver {
    /// Bind a persistent reconnect endpoint for exactly one authenticated client.
    ///
    /// A single admission credit is held for the entire session, including idle
    /// reconnect periods and retained completion. The sink is supplied locally;
    /// neither nonce nor address grants sink authority. Each receive call accepts
    /// at most one connection, and all accepted attempts consume the finite bound.
    pub async fn bind_resumable_committing<W: LiveStreamCommitSink + Unpin>(
        &self,
        cx: &Cx,
        address: SocketAddr,
        expected_client: NativeClientCertificateId,
        sink: W,
        max_attempts: u32,
    ) -> Result<ResumableReceiver<W>, ResumeError> {
        authorize(cx)?;
        validate_attempts(max_attempts)?;
        let permit = self.admission.reserve()?;
        let mut tls = (**self.acceptor.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        let listener = bounded(
            cx,
            self.config.operation_timeout,
            "resume bind",
            TcpListener::bind(address),
        )
        .await?;
        Ok(ResumableReceiver {
            sink,
            listener: Some(listener),
            acceptor: TlsAcceptor::new(tls),
            expected_client,
            config: self.config.clone(),
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
                maximum: max_attempts,
                _credit: Credit::Direct { _permit: permit },
            },
        })
    }
}

impl<W: LiveStreamCommitSink + Unpin> ResumableReceiver<W> {
    /// Last fully flushed prefix, which may be ahead of the sender's observation.
    #[must_use]
    pub fn flushed_prefix(&self) -> Option<&LiveStreamPrefix> {
        self.prefix.as_ref()
    }

    /// Sink-acknowledged application commit, independent of Proof delivery.
    #[must_use]
    pub fn completed_receipt(&self) -> Option<&LiveStreamReceipt> {
        self.completed.as_ref()
    }

    /// Successful sink writes, including a partially written/unflushed epoch.
    #[must_use]
    pub const fn sink_written_bytes(&self) -> u64 {
        self.sink_written_bytes
    }

    /// Address of the same retained listening socket across all attempts.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener
            .as_ref()
            .expect("standalone resume listener")
            .local_addr()
    }

    /// Accept one connection and continue this client-bound stream.
    ///
    /// A dropped Pending wait retains sink progress. Cooperative timeout or
    /// cancellation drains a started commit before returning, even beyond the
    /// timeout. A lost final Proof can be retransmitted by a later authenticated
    /// attempt without repeating writes or the application commit.
    pub async fn receive(&mut self, cx: &Cx) -> ResumeReport {
        let receipt_reused = self.completed.is_some();
        let outcome = if self.failed {
            Err(ResumeError::LocalFailure)
        } else {
            match authorize(cx)
                .map_err(ResumeError::from)
                .and_then(|()| self.budget.take())
            {
                Ok(()) => self.receive_inner(cx).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome,
            prefix: self.prefix.clone(),
            attempts: self.budget.used,
            receipt_reused,
            retained_epoch_bytes: self.pending.as_ref().map_or(0, |epoch| epoch.bytes().len()),
            sink_written_bytes: self.sink_written_bytes,
            completed: self.completed.clone(),
        }
    }

    async fn receive_inner(&mut self, cx: &Cx) -> Result<LiveStreamReceipt, ResumeError> {
        let timeout = self.config.operation_timeout;
        let listener = self.listener.as_ref().expect("standalone resume listener");
        let (tcp, _) = bounded(cx, timeout, "resume accept", listener.accept()).await?;
        let tls = bounded(cx, timeout, "resume TLS", self.acceptor.accept(tcp)).await?;
        if peer_certificate(&tls)? != *self.expected_client.as_bytes() {
            return Err(ResumeError::PeerIdentity);
        }
        let mut wire = Wire::new(tls);
        let hello = bounded(cx, timeout, "resume hello read", wire.receive()).await?;
        let offered = expect(&hello, FrameType::Handshake)?;
        self.receive_wire(cx, &mut wire, offered).await
    }

    // Shared protocol owner. Callers have authenticated TLS and bound the full
    // client certificate before passing the already-read hello and buffered wire.
    async fn receive_wire(
        &mut self,
        cx: &Cx,
        wire: &mut Wire<TlsStream<TcpStream>>,
        offered: &[u8],
    ) -> Result<LiveStreamReceipt, ResumeError> {
        let timeout = self.config.operation_timeout;
        let mut agreed = decode_offer(offered)?;
        if let Some(previous) = &self.offered {
            if previous != offered {
                return Err(ResumeError::Continuity("session nonce or offer changed"));
            }
        } else {
            agreed.epoch_bytes = agreed.epoch_bytes.min(self.config.epoch_bytes);
            agreed.max_bytes = agreed.max_bytes.min(self.config.max_bytes);
            self.prefix = Some(initial(&agreed));
            self.agreed = Some(agreed);
            self.offered = Some(offered.to_vec());
        }
        let mut state = offer(self.agreed.as_ref().expect("agreed session"));
        state.extend_from_slice(&encode_prefix(self.prefix.as_ref().expect("agreed prefix")));
        state.extend_from_slice(&digest(&self.hash));
        state.push(u8::from(self.completed.is_some()));
        bounded(
            cx,
            timeout,
            "resume state write",
            wire.send(FrameType::HandshakeAck, state),
        )
        .await?;
        loop {
            let frame = bounded(cx, timeout, "resume epoch read", wire.receive()).await?;
            if frame.frame_type() == FrameType::ObjectComplete {
                let receipt = LiveStreamReceipt {
                    prefix: self.prefix.as_ref().expect("agreed prefix").clone(),
                    source_sha256: digest(&self.hash),
                };
                if self.pending.is_some()
                    || expect(&frame, FrameType::ObjectComplete)? != encode_final(&receipt)
                {
                    return Err(ResumeError::Continuity("wrong final commitment"));
                }
                self.final_receipt = Some(receipt.clone());
                self.finalize(cx).await?;
                let proof = bounded(
                    cx,
                    timeout,
                    "resume Proof write",
                    wire.send(FrameType::Proof, encode_final(&receipt)),
                )
                .await;
                proof.map_err(|error| proof_failed(&receipt, error))?;
                return Ok(receipt);
            }
            if self.final_receipt.is_some() {
                return Err(ResumeError::Continuity("epoch after final commitment"));
            }
            let payload = expect(&frame, FrameType::ObjectData)?;
            if let Some(pending) = &self.pending {
                if payload != pending.payload {
                    return Err(ResumeError::Continuity("partially written epoch changed"));
                }
            } else {
                let agreed = self.agreed.as_ref().expect("agreed session");
                let next = advance(
                    self.prefix.as_ref().expect("agreed prefix"),
                    payload,
                    agreed.epoch_bytes,
                    agreed.max_bytes,
                )?;
                self.pending = Some(PendingEpoch {
                    payload: payload.to_vec(),
                    next,
                    written: 0,
                });
            }
            bounded(
                cx,
                timeout,
                "resume sink epoch",
                poll_fn(|ctx| self.poll_epoch(ctx)),
            )
            .await?;
            let prefix = encode_prefix(self.prefix.as_ref().expect("completed epoch"));
            bounded(
                cx,
                timeout,
                "resume epoch acknowledgement",
                wire.send(FrameType::Control, prefix),
            )
            .await?;
        }
    }

    fn poll_epoch(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let pending = self.pending.as_mut().expect("retained epoch");
        if pending.written < pending.bytes().len() {
            self.failed = true;
            let result =
                Pin::new(&mut self.sink).poll_write(ctx, &pending.bytes()[pending.written..]);
            self.failed = false;
            match result {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(count)) => {
                    if count == 0 || count > pending.bytes().len() - pending.written {
                        self.failed = true;
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    pending.written += count;
                    self.sink_written_bytes += count as u64;
                    // At most one sink write per poll, even for always-ready sinks.
                    ctx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
        self.failed = true;
        let result = Pin::new(&mut self.sink).poll_flush(ctx);
        self.failed = false;
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.failed = true;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                let pending = self.pending.take().expect("flushed epoch");
                self.hash.update(pending.bytes());
                self.prefix = Some(pending.next);
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_commit(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.completed.is_some() {
            return Poll::Ready(Ok(()));
        }
        self.commit_started = true;
        self.failed = true;
        let receipt = self
            .final_receipt
            .as_ref()
            .expect("validated final commitment");
        let result = Pin::new(&mut self.sink).poll_commit(ctx, receipt);
        self.failed = false;
        match result {
            Poll::Ready(Ok(())) => {
                // Persist the local observation before any possible network await.
                self.completed = Some(receipt.clone());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.failed = true;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    async fn finalize(&mut self, cx: &Cx) -> Result<(), ResumeError> {
        if self.completed.is_some() {
            return Ok(());
        }
        let timeout = self.config.operation_timeout;
        if !self.commit_started {
            bounded(
                cx,
                timeout,
                "resume final flush",
                poll_fn(|ctx| {
                    self.failed = true;
                    let result = Pin::new(&mut self.sink).poll_flush(ctx);
                    self.failed = matches!(&result, Poll::Ready(Err(_)));
                    result
                }),
            )
            .await?;
        }
        let observed = bounded(
            cx,
            timeout,
            "resume sink commit",
            poll_fn(|ctx| self.poll_commit(ctx)),
        )
        .await;
        let (result, interruption) = match observed {
            Ok(()) => return Ok(()),
            Err(LiveStreamError::Io(error)) => (Err(error), None),
            Err(error) if !self.commit_started => return Err(error.into()),
            Err(error) => (poll_fn(|ctx| self.poll_commit(ctx)).await, Some(error)),
        };
        let receipt = self.final_receipt.as_ref().expect("final receipt");
        match result {
            Ok(()) => Err(proof_failed(receipt, interruption.expect("interrupted commit")).into()),
            Err(source) => Err(LiveStreamError::Commit(Box::new(
                LiveStreamCommitError::Unconfirmed {
                    receipt: Box::new(receipt.clone()),
                    interruption: interruption.map(Box::new),
                    source,
                },
            ))
            .into()),
        }
    }
}

/// Shared-port, bounded routing of authenticated retained resume sessions.
#[path = "resume/service.rs"]
pub mod service;

/// Persist source-EOF state before finalization and recover Proof without the source.
#[path = "resume/finalization.rs"]
pub mod finalization;
