//! Live, bounded ATP epochs over the native TCP/TLS stack.
//!
//! Unlike manifest-first uploads, the receiver can consume a verified epoch
//! before the producer reaches EOF. One epoch is in flight: the sender waits
//! for the sink's flush acknowledgement before reading more input. No spool,
//! detached task, unbounded epoch history, or implicit retry is involved.
//!
//! # Wire profile
//!
//! This is the opt-in `atp-live/1` TLS ALPN, not the QUIC bulk-transfer wire.
//! It reuses canonical ATP V0 frames without extensions. Handshake/HandshakeAck
//! carry `ATPLIVE1 || nonce[32] || epoch_limit:u32 || byte_limit:u64`. Integers
//! are big endian. The receiver can only narrow the limits. ObjectData carries
//! `sequence:u64 || offset:u64 || previous_chain[32] || sha256[32] || bytes`.
//! Control acknowledges `epochs:u64 || bytes:u64 || chain[32]`. ObjectComplete
//! appends the whole-stream SHA-256 to that prefix; Proof echoes it exactly.
//! The initial chain hashes the agreed hello. Each following chain hashes its
//! predecessor and the entire epoch payload, with separate domain separators.
//!
//! # Publication and failure
//!
//! Integrity is checked before an epoch reaches the sink. Sink writes are not
//! rollback-atomic; an error can leave a partial epoch, recorded separately from
//! the last fully flushed prefix. Flush is the sink's contract, not necessarily
//! fsync or durable publication. Raw EOF never completes a logical stream.
//! Lost acknowledgements can leave different prefix observations at the peers;
//! there is no exactly-once or remote-offset-resume claim. Hard-dropping an
//! operation closes its connection and provides no terminal report. Prefer the
//! scope-owned variants and join them to observe cooperative cancellation.

use super::{AtpSdk, NativeAuthenticationError, NativeClientAuthorization, NativeTlsIdentity};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::{CancelWakerToken, Cx, Scope};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameError, FrameType, ProtocolVersion};
use crate::net::atp::sdk::SdkMode;
use crate::net::{TcpListener, TcpStream};
use crate::runtime::{SpawnError, TaskHandle};
use crate::tls::{TlsAcceptor, TlsConnector, TlsError, TlsStream};
use crate::types::{CancelReason, Policy};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Distinct application protocol; never negotiated as a legacy bulk transfer.
pub const LIVE_STREAM_ALPN: &[u8] = b"atp-live/1";
/// Maximum data bytes in one live epoch, independent of total stream length.
pub const MAX_LIVE_EPOCH_BYTES: usize = 64 * 1024;
const MAX_WIRE_BYTES: usize = MAX_LIVE_EPOCH_BYTES + 256;
const EPOCH_HEADER_BYTES: usize = 80;
const PREFIX_BYTES: usize = 48;
const HELLO_BYTES: usize = 52;
const MAGIC: &[u8; 8] = b"ATPLIVE1";

/// Per-stream limits. SDK byte/chunk ceilings further narrow these settings.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LiveStreamConfig {
    /// Maximum data bytes per epoch, between one and 64 KiB.
    pub epoch_bytes: usize,
    /// Maximum total bytes. Zero admits only an explicitly finalized empty stream.
    pub max_bytes: u64,
    /// Deadline for each source read, frame, handshake, accept, or complete sink epoch.
    /// Partial frame progress does not restart this deadline. This cannot
    /// preempt user code that blocks inside a poll method.
    pub operation_timeout: Duration,
}

impl Default for LiveStreamConfig {
    fn default() -> Self {
        Self {
            epoch_bytes: MAX_LIVE_EPOCH_BYTES,
            max_bytes: 4 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Typed failure with no fabricated completion or automatic retry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LiveStreamError {
    /// Invalid local configuration or unsupported SDK mode.
    #[error("invalid live stream configuration: {0}")]
    Configuration(&'static str),
    /// Required context authority is absent.
    #[error("live streams require I/O, time and entropy capabilities")]
    MissingCapability,
    /// The shared admission domain is full.
    #[error("live stream capacity exhausted")]
    Capacity,
    /// Cooperative cancellation with its actual attribution.
    #[error("live stream cancelled: {0:?}")]
    Cancelled(Option<CancelReason>),
    /// A bounded asynchronous operation failed to finish.
    #[error("live stream timeout during {0}")]
    Timeout(&'static str),
    /// An authenticated peer violated this profile or its integrity chain.
    #[error("live stream protocol violation: {0}")]
    Protocol(&'static str),
    /// Input would exceed the negotiated ceiling; no final success is emitted.
    #[error("live stream exceeds negotiated limit of {0} bytes")]
    TooLarge(u64),
    /// Original source, sink, or network error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Original TLS error.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Original frame-codec error.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Explicit certificate/trust configuration failed.
    #[error(transparent)]
    Authentication(#[from] NativeAuthenticationError),
    /// Runtime admission failed before execution.
    #[error("live stream task admission failed: {0:?}")]
    Spawn(SpawnError),
}

/// A contiguous prefix, not evidence that the whole stream is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveStreamPrefix {
    /// Sender nonce bound into the negotiated integrity chain.
    pub stream_nonce: [u8; 32],
    /// Number of complete, nonempty epochs.
    pub epochs: u64,
    /// Complete prefix length.
    pub bytes: u64,
    /// Rolling integrity commitment, bound to negotiated limits and nonce.
    pub chain: [u8; 32],
}

/// Whole-stream result, emitted only after explicit finalization and sink flush.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveStreamReceipt {
    /// Final contiguous prefix.
    pub prefix: LiveStreamPrefix,
    /// SHA-256 over the complete byte stream, independent of epoch boundaries.
    pub source_sha256: [u8; 32],
}

/// Retained progress and failure are independent facts.
#[derive(Debug)]
#[must_use = "inspect outcome; a verified prefix is not whole-stream success"]
pub struct LiveStreamReport {
    /// Sender: actual peer Proof. Receiver: final sink flush and Proof write.
    /// Neither is a guarantee of durable storage or application transaction commit.
    pub outcome: Result<LiveStreamReceipt, LiveStreamError>,
    /// Sender: last acknowledged epoch. Receiver: last fully written/flushed epoch,
    /// possibly not yet acknowledged remotely. Present after hello negotiation.
    pub prefix: Option<LiveStreamPrefix>,
    /// Receiver's successful sink-write bytes, including any partial failed epoch.
    /// Zero on a sender. A timed-out pending sink write has no reported byte count.
    pub sink_written_bytes: u64,
}

#[derive(Default)]
struct Progress {
    prefix: Option<LiveStreamPrefix>,
    sink_written_bytes: u64,
}

impl Progress {
    fn report(self, outcome: Result<LiveStreamReceipt, LiveStreamError>) -> LiveStreamReport {
        LiveStreamReport { outcome, prefix: self.prefix, sink_written_bytes: self.sink_written_bytes }
    }
}

/// A real region-owned live-stream operation; join and domain errors stay distinct.
pub type LiveStreamTask = TaskHandle<LiveStreamReport>;

#[derive(Debug)]
struct Admission {
    active: AtomicUsize,
    capacity: usize,
}

impl Admission {
    fn reserve(self: &Arc<Self>) -> Result<Permit, LiveStreamError> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.capacity { return Err(LiveStreamError::Capacity); }
            match self.active.compare_exchange_weak(active, active + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(Permit(Arc::clone(self))),
                Err(observed) => active = observed,
            }
        }
    }
}

#[derive(Debug)]
struct Permit(Arc<Admission>);
impl Drop for Permit {
    fn drop(&mut self) {
        let old = self.0.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(old > 0);
    }
}

/// Cloneable, mutually authenticated live sender. Clones share admission capacity.
#[derive(Debug, Clone)]
pub struct LiveStreamSender {
    connector: TlsConnector,
    domain: String,
    config: LiveStreamConfig,
    admission: Arc<Admission>,
}

/// Cloneable receiver authority. Bind explicitly before advertising its address.
#[derive(Debug, Clone)]
pub struct LiveStreamReceiver {
    acceptor: TlsAcceptor,
    config: LiveStreamConfig,
    admission: Arc<Admission>,
}

/// A one-shot, already-bound native TCP listener and its reserved admission slot.
#[derive(Debug)]
#[must_use = "receive_into must be driven to obtain stream data"]
pub struct LiveStreamListener {
    listener: TcpListener,
    receiver: LiveStreamReceiver,
    _permit: Permit,
}

fn configure(sdk: &AtpSdk, mut config: LiveStreamConfig) -> Result<(LiveStreamConfig, Arc<Admission>), LiveStreamError> {
    if !matches!(sdk.mode(), SdkMode::InProcess) {
        return Err(LiveStreamError::Configuration("in-process mode required"));
    }
    if config.epoch_bytes == 0 || config.epoch_bytes > MAX_LIVE_EPOCH_BYTES || config.operation_timeout.is_zero() {
        return Err(LiveStreamError::Configuration("invalid epoch size or timeout"));
    }
    let capacity = usize::try_from(sdk.default_config().max_concurrent_transfers)
        .map_err(|_| LiveStreamError::Configuration("capacity is not representable"))?;
    if capacity == 0 || sdk.transfer_policy().max_chunk_size_bytes == 0 {
        return Err(LiveStreamError::Configuration("zero capacity or chunk ceiling"));
    }
    config.epoch_bytes = config.epoch_bytes.min(
        usize::try_from(sdk.transfer_policy().max_chunk_size_bytes).unwrap_or(usize::MAX),
    );
    config.max_bytes = config.max_bytes.min(sdk.transfer_policy().max_transfer_size_bytes);
    Ok((config, Arc::new(Admission { active: AtomicUsize::new(0), capacity })))
}

impl AtpSdk {
    /// Construct an explicitly authenticated live sender, without networking.
    /// Reuses native WebPKI identity policy with a distinct ALPN. No system roots,
    /// TLS resumption, early data, compression, retry or daemon fallback is added.
    pub fn live_stream_sender(
        &self, config: LiveStreamConfig, server_name: ServerName<'static>,
        server_roots: RootCertStore, identity: NativeTlsIdentity,
    ) -> Result<LiveStreamSender, LiveStreamError> {
        let (config, admission) = configure(self, config)?;
        let domain = match &server_name {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            ServerName::IpAddress(address) => {
                let address: std::net::IpAddr = (*address).into();
                address.to_string()
            }
            _ => return Err(LiveStreamError::Configuration("unsupported server name")),
        };
        let tls = super::client_tls(server_name, server_roots, identity)?;
        let mut tls = (*tls.config).clone();
        tls.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
        Ok(LiveStreamSender { connector: TlsConnector::new(tls), domain, config, admission })
    }

    /// Construct a live receiver requiring WebPKI-valid, allowed client certificates.
    /// The shared authorization policy governs each new handshake, not already
    /// established streams. The caller chooses the sink; no peer-supplied path is
    /// opened. Supplied sink writes and flushes define publication semantics.
    pub fn live_stream_receiver(
        &self, config: LiveStreamConfig, identity: NativeTlsIdentity,
        authorization: NativeClientAuthorization,
    ) -> Result<LiveStreamReceiver, LiveStreamError> {
        let (config, admission) = configure(self, config)?;
        let tls = super::server_tls(identity, authorization)?;
        let mut tls = (*tls.config).clone();
        tls.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
        Ok(LiveStreamReceiver { acceptor: TlsAcceptor::new(tls), config, admission })
    }
}

fn authorize(cx: &Cx) -> Result<(), LiveStreamError> {
    let caps = cx.capabilities();
    if !caps.io || !caps.time || !caps.entropy { return Err(LiveStreamError::MissingCapability); }
    checkpoint(cx)
}

fn checkpoint(cx: &Cx) -> Result<(), LiveStreamError> {
    cx.checkpoint().map_err(|_| LiveStreamError::Cancelled(cx.cancel_reason()))
}

struct Cancellation<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

// Timeout/cancellation may interrupt a partial frame. Every caller abandons the
// entire connection on error; no subsequent operation reuses that byte stream.
async fn bounded<T, E: Into<LiveStreamError>>(
    cx: &Cx, timeout: Duration, operation: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, LiveStreamError> {
    let mut cancellation = Cancellation { cx, token: None };
    let mut future = std::pin::pin!(future);
    let checked = poll_fn(|ctx| {
        cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token.take(), ctx.waker()));
        if let Err(error) = checkpoint(cx) { return Poll::Ready(Err(error)); }
        future.as_mut().poll(ctx).map(|result| result.map_err(Into::into))
    });
    crate::time::timeout(cx.now(), timeout, checked).await
        .map_err(|_| LiveStreamError::Timeout(operation))?
}

impl LiveStreamSender {
    /// Number of active/queued streams across clones of this sender.
    #[must_use]
    pub fn active_streams(&self) -> usize { self.admission.active.load(Ordering::Relaxed) }

    /// Stream a source to the peer without a filesystem spool. Each nonempty
    /// read becomes one integrity-checked epoch. Read-ahead stops at one epoch
    /// until the peer acknowledges sink flush. EOF requires an explicit final
    /// exchange; source failure preserves only the last acknowledged prefix.
    pub async fn send_reader<R: AsyncRead + Unpin>(
        &self, cx: &Cx, remote: SocketAddr, mut reader: R,
    ) -> LiveStreamReport {
        let mut progress = Progress::default();
        let outcome = match authorize(cx).and_then(|()| self.admission.reserve()) {
            Ok(_permit) => self.send_inner(cx, remote, &mut reader, &mut progress).await,
            Err(error) => Err(error),
        };
        progress.report(outcome)
    }

    /// Reserve capacity before enqueueing an owned source in the supplied scope.
    /// Runtime rejection releases the slot without polling input or networking.
    pub fn spawn_send_reader<P: Policy, R: AsyncRead + Unpin + Send + 'static>(
        &self, cx: &Cx, scope: &Scope<'_, P>, remote: SocketAddr, mut reader: R,
    ) -> Result<LiveStreamTask, LiveStreamError> {
        authorize(cx)?;
        let permit = self.admission.reserve()?;
        let sender = self.clone();
        cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = LiveStreamReport> + Send>> = Box::pin(async move {
                let _permit = permit;
                let mut progress = Progress::default();
                let outcome = match authorize(&child) {
                    Ok(()) => sender.send_inner(&child, remote, &mut reader, &mut progress).await,
                    Err(error) => Err(error),
                };
                progress.report(outcome)
            });
            future
        }).map_err(LiveStreamError::Spawn)
    }

    async fn send_inner<R: AsyncRead + Unpin>(
        &self, cx: &Cx, remote: SocketAddr, reader: &mut R, progress: &mut Progress,
    ) -> Result<LiveStreamReceipt, LiveStreamError> {
        let timeout = self.config.operation_timeout;
        let tcp = bounded(cx, timeout, "connect", TcpStream::connect(remote)).await?;
        let tls = bounded(cx, timeout, "TLS handshake", self.connector.connect(&self.domain, tcp)).await?;
        check_alpn(&tls)?;
        let mut wire = Wire::new(tls);
        let mut nonce = [0; 32];
        cx.random_bytes(&mut nonce);
        let offered = Hello { nonce, epoch_bytes: self.config.epoch_bytes, max_bytes: self.config.max_bytes };
        bounded(cx, timeout, "hello write", wire.send(FrameType::Handshake, offered.encode())).await?;
        let frame = bounded(cx, timeout, "hello acknowledgement", wire.receive()).await?;
        let agreed = Hello::decode(expect(&frame, FrameType::HandshakeAck)?)?;
        if agreed.nonce != nonce || agreed.epoch_bytes > offered.epoch_bytes || agreed.max_bytes > offered.max_bytes {
            return Err(LiveStreamError::Protocol("receiver widened or rebound the hello"));
        }
        let mut prefix = agreed.prefix();
        progress.prefix = Some(prefix.clone());
        let mut hash = Sha256::new();
        let mut buffer = vec![0; agreed.epoch_bytes];
        loop {
            let remaining = agreed.max_bytes - prefix.bytes;
            let window = buffer.len().min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
            let count = bounded(cx, timeout, "source read", reader.read(&mut buffer[..window])).await?;
            if count == 0 { break; }
            if count as u64 > remaining { return Err(LiveStreamError::TooLarge(agreed.max_bytes)); }
            let payload = encode_epoch(&prefix, &buffer[..count]);
            let next = advance(&prefix, &payload, agreed.epoch_bytes, agreed.max_bytes)?;
            bounded(cx, timeout, "epoch write", wire.send(FrameType::ObjectData, payload)).await?;
            let ack = bounded(cx, timeout, "epoch acknowledgement", wire.receive()).await?;
            if expect(&ack, FrameType::Control)? != encode_prefix(&next) {
                return Err(LiveStreamError::Protocol("wrong epoch acknowledgement"));
            }
            hash.update(&buffer[..count]);
            prefix = next;
            progress.prefix = Some(prefix.clone());
        }
        let receipt = LiveStreamReceipt { prefix, source_sha256: hash.finalize().into() };
        let final_payload = encode_final(&receipt);
        bounded(cx, timeout, "final write", wire.send(FrameType::ObjectComplete, final_payload.clone())).await?;
        let proof = bounded(cx, timeout, "final proof", wire.receive()).await?;
        if expect(&proof, FrameType::Proof)? != final_payload {
            return Err(LiveStreamError::Protocol("wrong final proof"));
        }
        Ok(receipt)
    }
}

impl LiveStreamReceiver {
    /// Bound listeners and active/queued receive operations across receiver clones.
    /// A reusable service reserves its whole connection budget until it drains.
    #[must_use]
    pub fn active_streams(&self) -> usize { self.admission.active.load(Ordering::Relaxed) }

    /// Bind a one-shot listener, reserving capacity before creating its socket.
    pub async fn bind(&self, cx: &Cx, address: SocketAddr) -> Result<LiveStreamListener, LiveStreamError> {
        authorize(cx)?;
        let permit = self.admission.reserve()?;
        let listener = bounded(cx, self.config.operation_timeout, "bind", TcpListener::bind(address)).await?;
        Ok(LiveStreamListener { listener, receiver: self.clone(), _permit: permit })
    }
}

impl LiveStreamListener {
    /// Address of the actual retained listener; port zero is supported.
    pub fn local_addr(&self) -> io::Result<SocketAddr> { self.listener.local_addr() }

    /// Receive verified epochs into a caller-selected sink before source EOF.
    /// The sink is never shut down implicitly. Successful write prefixes survive
    /// cancellation/failure; inspect both `prefix` and `sink_written_bytes`.
    pub async fn receive_into<W: AsyncWrite + Unpin>(self, cx: &Cx, sink: &mut W) -> LiveStreamReport {
        let mut progress = Progress::default();
        let outcome = match authorize(cx) {
            Ok(()) => self.receive_inner(cx, sink, &mut progress).await,
            Err(error) => Err(error),
        };
        progress.report(outcome)
    }

    /// Transfer the existing socket, sink and admission slot into a scoped child.
    /// Immediate/deferred rejection retires the socket and slot; no second
    /// admission is taken. Join the real worker for completion or failure.
    pub fn spawn_receive_into<P: Policy, W: AsyncWrite + Unpin + Send + 'static>(
        self, cx: &Cx, scope: &Scope<'_, P>, mut sink: W,
    ) -> Result<LiveStreamTask, LiveStreamError> {
        authorize(cx)?;
        cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = LiveStreamReport> + Send>> =
                Box::pin(async move { self.receive_into(&child, &mut sink).await });
            future
        }).map_err(LiveStreamError::Spawn)
    }

    async fn receive_inner<W: AsyncWrite + Unpin>(
        &self, cx: &Cx, sink: &mut W, progress: &mut Progress,
    ) -> Result<LiveStreamReceipt, LiveStreamError> {
        let config = &self.receiver.config;
        let timeout = config.operation_timeout;
        let (tcp, _) = bounded(cx, timeout, "accept", self.listener.accept()).await?;
        let tls = bounded(cx, timeout, "TLS handshake", self.receiver.acceptor.accept(tcp)).await?;
        self.receiver.receive_authenticated(cx, tls, sink, progress).await
    }
}

impl LiveStreamReceiver {
    // One protocol owner for the one-shot listener and reusable service. The
    // caller must complete this receiver's TLS accept before handing over I/O.
    async fn receive_authenticated<W: AsyncWrite + Unpin>(
        &self, cx: &Cx, tls: TlsStream<TcpStream>, sink: &mut W, progress: &mut Progress,
    ) -> Result<LiveStreamReceipt, LiveStreamError> {
        let config = &self.config;
        let timeout = config.operation_timeout;
        check_alpn(&tls)?;
        let mut wire = Wire::new(tls);
        let hello = bounded(cx, timeout, "hello read", wire.receive()).await?;
        let mut agreed = Hello::decode(expect(&hello, FrameType::Handshake)?)?;
        agreed.epoch_bytes = agreed.epoch_bytes.min(config.epoch_bytes);
        agreed.max_bytes = agreed.max_bytes.min(config.max_bytes);
        bounded(cx, timeout, "hello acknowledgement", wire.send(FrameType::HandshakeAck, agreed.encode())).await?;
        let mut prefix = agreed.prefix();
        progress.prefix = Some(prefix.clone());
        let mut hash = Sha256::new();
        loop {
            let frame = bounded(cx, timeout, "epoch read", wire.receive()).await?;
            if frame.frame_type() == FrameType::ObjectComplete {
                let receipt = LiveStreamReceipt { prefix, source_sha256: hash.finalize().into() };
                let final_payload = encode_final(&receipt);
                if expect(&frame, FrameType::ObjectComplete)? != final_payload {
                    return Err(LiveStreamError::Protocol("wrong final stream commitment"));
                }
                bounded(cx, timeout, "final sink flush", sink.flush()).await?;
                bounded(cx, timeout, "final proof write", wire.send(FrameType::Proof, final_payload)).await?;
                return Ok(receipt);
            }
            let payload = expect(&frame, FrameType::ObjectData)?;
            let next = advance(&prefix, payload, agreed.epoch_bytes, agreed.max_bytes)?;
            let data = &payload[EPOCH_HEADER_BYTES..];
            // Count only completed sink writes. A partial failing epoch remains
            // visible independently from the last fully flushed prefix.
            bounded(cx, timeout, "sink epoch", write_epoch(sink, data, &mut progress.sink_written_bytes)).await?;
            hash.update(data);
            prefix = next;
            progress.prefix = Some(prefix.clone());
            bounded(cx, timeout, "epoch acknowledgement", wire.send(FrameType::Control, encode_prefix(&prefix))).await?;
        }
    }
}

/// Reusable, bounded, scope-owned live receiver service.
#[path = "native_live/service.rs"]
pub mod service;

async fn write_epoch<W: AsyncWrite + Unpin>(sink: &mut W, data: &[u8], total: &mut u64) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        let count = sink.write(&data[written..]).await?;
        if count == 0 || count > data.len() - written {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "invalid sink write count"));
        }
        written += count;
        *total += count as u64;
    }
    sink.flush().await
}

fn check_alpn(tls: &TlsStream<TcpStream>) -> Result<(), LiveStreamError> {
    if tls.alpn_protocol() != Some(LIVE_STREAM_ALPN) {
        return Err(LiveStreamError::Protocol("live ALPN was not negotiated"));
    }
    Ok(())
}

struct Wire<S> { stream: S, codec: AtpFrameCodec, buffer: BytesMut }
impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    fn new(stream: S) -> Self {
        Self { stream, codec: AtpFrameCodec::with_max_frame_size(MAX_WIRE_BYTES as u64), buffer: BytesMut::new() }
    }
    async fn send(&mut self, kind: FrameType, payload: Vec<u8>) -> Result<(), LiveStreamError> {
        let frame = Frame::new(ProtocolVersion::V0, kind, payload)?;
        let encoded = frame.to_wire_bytes()?;
        if encoded.len() > MAX_WIRE_BYTES { return Err(LiveStreamError::Protocol("oversized outbound frame")); }
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }
    async fn receive(&mut self) -> Result<Frame, LiveStreamError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer)? {
                if !frame.header.extensions.is_empty() { return Err(LiveStreamError::Protocol("live frames have no extensions")); }
                return Ok(frame);
            }
            if self.buffer.len() >= MAX_WIRE_BYTES { return Err(LiveStreamError::Protocol("incomplete oversized frame")); }
            let mut bytes = [0; 4096];
            let window = bytes.len().min(MAX_WIRE_BYTES - self.buffer.len());
            let count = self.stream.read(&mut bytes[..window]).await?;
            if count == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "live stream ended without its next required frame").into());
            }
            self.buffer.extend_from_slice(&bytes[..count]);
        }
    }
}

fn expect(frame: &Frame, kind: FrameType) -> Result<&[u8], LiveStreamError> {
    if frame.frame_type() != kind || !frame.header.extensions.is_empty() {
        return Err(LiveStreamError::Protocol("unexpected frame"));
    }
    Ok(frame.payload())
}

struct Hello { nonce: [u8; 32], epoch_bytes: usize, max_bytes: u64 }
impl Hello {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HELLO_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.epoch_bytes as u32).to_be_bytes());
        bytes.extend_from_slice(&self.max_bytes.to_be_bytes());
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, LiveStreamError> {
        if bytes.len() != HELLO_BYTES || &bytes[..8] != MAGIC {
            return Err(LiveStreamError::Protocol("invalid live hello"));
        }
        let epoch_bytes = u32::from_be_bytes(bytes[40..44].try_into().expect("fixed hello field")) as usize;
        if epoch_bytes == 0 || epoch_bytes > MAX_LIVE_EPOCH_BYTES {
            return Err(LiveStreamError::Protocol("invalid live epoch limit"));
        }
        Ok(Self {
            nonce: bytes[8..40].try_into().expect("fixed nonce field"), epoch_bytes,
            max_bytes: u64::from_be_bytes(bytes[44..52].try_into().expect("fixed byte limit")),
        })
    }
    fn prefix(&self) -> LiveStreamPrefix {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.hello.v1");
        hash.update(self.encode());
        LiveStreamPrefix { stream_nonce: self.nonce, epochs: 0, bytes: 0, chain: hash.finalize().into() }
    }
}

fn encode_prefix(prefix: &LiveStreamPrefix) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PREFIX_BYTES);
    bytes.extend_from_slice(&prefix.epochs.to_be_bytes());
    bytes.extend_from_slice(&prefix.bytes.to_be_bytes());
    bytes.extend_from_slice(&prefix.chain);
    bytes
}
fn encode_final(receipt: &LiveStreamReceipt) -> Vec<u8> {
    let mut bytes = encode_prefix(&receipt.prefix);
    bytes.extend_from_slice(&receipt.source_sha256);
    bytes
}
fn encode_epoch(prefix: &LiveStreamPrefix, data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(EPOCH_HEADER_BYTES + data.len());
    bytes.extend_from_slice(&prefix.epochs.to_be_bytes());
    bytes.extend_from_slice(&prefix.bytes.to_be_bytes());
    bytes.extend_from_slice(&prefix.chain);
    bytes.extend_from_slice(&Sha256::digest(data));
    bytes.extend_from_slice(data);
    bytes
}
fn advance(prefix: &LiveStreamPrefix, payload: &[u8], epoch_limit: usize, byte_limit: u64) -> Result<LiveStreamPrefix, LiveStreamError> {
    if payload.len() <= EPOCH_HEADER_BYTES || payload.len() - EPOCH_HEADER_BYTES > epoch_limit {
        return Err(LiveStreamError::Protocol("empty or oversized live epoch"));
    }
    if payload[..8] != prefix.epochs.to_be_bytes() || payload[8..16] != prefix.bytes.to_be_bytes()
        || payload[16..48] != prefix.chain {
        return Err(LiveStreamError::Protocol("noncontiguous or rebound epoch"));
    }
    let data = &payload[EPOCH_HEADER_BYTES..];
    let digest: [u8; 32] = Sha256::digest(data).into();
    if payload[48..80] != digest { return Err(LiveStreamError::Protocol("epoch digest mismatch")); }
    let bytes = prefix.bytes.checked_add(data.len() as u64).filter(|bytes| *bytes <= byte_limit)
        .ok_or(LiveStreamError::TooLarge(byte_limit))?;
    let epochs = prefix.epochs.checked_add(1).ok_or(LiveStreamError::Protocol("epoch sequence exhausted"))?;
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.live.epoch.v1");
    hash.update(prefix.chain);
    hash.update(payload);
    Ok(LiveStreamPrefix { stream_nonce: prefix.stream_nonce, epochs, bytes, chain: hash.finalize().into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_and_chain_bind_nonce_and_limits() {
        let hello = Hello { nonce: [7; 32], epoch_bytes: 8, max_bytes: 50 };
        assert_eq!(Hello::decode(&hello.encode()).unwrap().prefix(), hello.prefix());
        for other in [
            Hello { nonce: [8; 32], epoch_bytes: 8, max_bytes: 50 },
            Hello { nonce: [7; 32], epoch_bytes: 7, max_bytes: 50 },
            Hello { nonce: [7; 32], epoch_bytes: 8, max_bytes: 49 },
        ] { assert_ne!(hello.prefix().chain, other.prefix().chain); }
        assert!(Hello::decode(&[0; HELLO_BYTES]).is_err());
        let mut trailing = hello.encode(); trailing.push(0);
        assert!(Hello::decode(&trailing).is_err());
    }

    #[test]
    fn epoch_rejects_corruption_replay_reordering_and_truncation() {
        let prefix = Hello { nonce: [1; 32], epoch_bytes: 8, max_bytes: 50 }.prefix();
        let epoch = encode_epoch(&prefix, b"verified");
        let next = advance(&prefix, &epoch, 8, 50).unwrap();
        assert_eq!((next.epochs, next.bytes), (1, 8));
        assert!(advance(&next, &epoch, 8, 50).is_err());
        for index in 0..epoch.len() {
            let mut broken = epoch.clone(); broken[index] ^= 1;
            assert!(advance(&prefix, &broken, 8, 50).is_err(), "byte {index}");
        }
        for end in 0..epoch.len() { assert!(advance(&prefix, &epoch[..end], 8, 50).is_err()); }
    }

    #[test]
    fn epoch_enforces_limits_and_checked_counters() {
        let mut prefix = Hello { nonce: [1; 32], epoch_bytes: 8, max_bytes: 50 }.prefix();
        assert!(advance(&prefix, &encode_epoch(&prefix, b""), 8, 50).is_err());
        assert!(advance(&prefix, &encode_epoch(&prefix, b"123"), 2, 50).is_err());
        assert!(matches!(advance(&prefix, &encode_epoch(&prefix, b"123"), 8, 2), Err(LiveStreamError::TooLarge(2))));
        prefix.bytes = u64::MAX;
        assert!(advance(&prefix, &encode_epoch(&prefix, b"x"), 8, u64::MAX).is_err());
        prefix.bytes = 0; prefix.epochs = u64::MAX;
        assert!(advance(&prefix, &encode_epoch(&prefix, b"x"), 8, 50).is_err());
    }

    #[test]
    fn admission_is_shared_and_released_without_wrapping() {
        let admission = Arc::new(Admission { active: AtomicUsize::new(0), capacity: 1 });
        let permit = admission.reserve().unwrap();
        assert!(matches!(Arc::clone(&admission).reserve(), Err(LiveStreamError::Capacity)));
        drop(permit);
        assert!(admission.reserve().is_ok());
        assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    }
}
