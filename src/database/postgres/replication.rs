//! Caller-driven PostgreSQL logical replication over a dedicated connection.
//!
//! [`PgReplicationConnection`] negotiates `replication=database` using the
//! ordinary PostgreSQL TLS and authentication implementation. Starting a stream
//! uses an existing pgoutput slot and publication names; this API never creates
//! or drops a slot. [`PgReplicationStream`] owns its socket and retains the
//! starting context's authority, cancellation, and deadline across calls.
//!
//! Replication feedback is an application durability decision. Receiving an
//! event never advances the acknowledged positions. A requested keepalive reply
//! repeats only the last explicitly confirmed feedback. Applications should
//! persist their checkpoint before confirming it, and must be prepared for
//! redelivery after reconnecting. There is no implicit reconnect or replay.
//!
//! Wire definitions: <https://www.postgresql.org/docs/current/protocol-replication.html>
//! and <https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-COPY>.

use super::{
    CancelWakerGuard, Cx, FrontendMessage, MAX_BACKEND_MESSAGE_LEN, MessageBuffer,
    MessageReader, Outcome, PgConnectOptions, PgConnection, PgError, PgTlsOptions,
    cancelled_error, outcome_from_error, quote_postgres_identifier,
    unexpected_backend_message,
};
use crate::cx::{CancelWakerToken, cap::CapMask};
use crate::io::AsyncWrite;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default maximum retained backend message body, including its WAL envelope.
pub const DEFAULT_MAX_REPLICATION_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PUBLICATIONS: usize = 1024;
const MAX_START_COMMAND_BYTES: usize = 64 * 1024;
const POLL_STEPS: usize = 32;

/// A PostgreSQL WAL position, rendered in the server's hexadecimal `X/Y` form.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PgLsn(u64);

impl PgLsn {
    /// Construct a position from its unsigned wire representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the unsigned wire representation.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PgLsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}/{:X}", self.0 >> 32, self.0 & u64::from(u32::MAX))
    }
}

impl FromStr for PgLsn {
    type Err = PgError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (high, low) = value
            .split_once('/')
            .ok_or_else(|| protocol("LSN must have hexadecimal X/Y form"))?;
        let part = |value: &str| {
            if value.is_empty() || value.len() > 8 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(protocol("LSN components must contain one to eight hexadecimal digits"));
            }
            u32::from_str_radix(value, 16).map_err(|_| protocol("invalid LSN component"))
        };
        Ok(Self((u64::from(part(high)?) << 32) | u64::from(part(low)?)))
    }
}

/// Options for an existing pgoutput slot, using protocol version 1.
#[derive(Debug, Clone)]
pub struct PgReplicationConfig {
    slot: String,
    publications: Vec<String>,
    start_lsn: PgLsn,
    max_message_bytes: usize,
    binary: bool,
    messages: bool,
}

impl PgReplicationConfig {
    /// Configure an existing slot and at least one publication.
    ///
    /// Slot names use PostgreSQL's lowercase letters, digits, and underscore
    /// grammar. Publication identifiers are quoted independently, including
    /// names containing commas, quotes, spaces, or non-ASCII characters.
    pub fn new<I, S>(
        slot: impl Into<String>,
        publications: I,
        start_lsn: PgLsn,
    ) -> Result<Self, PgError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let slot = slot.into();
        if slot.is_empty()
            || slot.len() > 63
            || !slot.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(protocol("slot name must be 1..=63 lowercase ASCII letters, digits, or underscores"));
        }
        let mut names = Vec::new();
        for name in publications {
            let name = name.into();
            if names.len() == MAX_PUBLICATIONS {
                return Err(protocol("too many replication publications"));
            }
            if name.is_empty() || name.len() > 63 || name.as_bytes().contains(&0) {
                return Err(protocol("publication names must be nonempty, NUL-free, and at most 63 bytes"));
            }
            names.push(name);
        }
        if names.is_empty() {
            return Err(protocol("at least one publication is required"));
        }
        let config = Self {
            slot,
            publications: names,
            start_lsn,
            max_message_bytes: DEFAULT_MAX_REPLICATION_MESSAGE_BYTES,
            binary: false,
            messages: false,
        };
        config.start_command()?;
        Ok(config)
    }

    /// Bound each backend message before its payload allocation.
    ///
    /// The bound also covers control/error messages. It must be at least the
    /// 25-byte XLogData envelope and within the existing PostgreSQL frame cap.
    pub fn with_max_message_bytes(mut self, limit: usize) -> Result<Self, PgError> {
        if !(25..=MAX_BACKEND_MESSAGE_LEN as usize - 4).contains(&limit) {
            return Err(protocol("replication message limit is outside protocol bounds"));
        }
        self.max_message_bytes = limit;
        Ok(self)
    }

    /// Request binary tuple values where the output plugin supports them.
    #[must_use]
    pub fn binary(mut self, enabled: bool) -> Self {
        self.binary = enabled;
        self
    }

    /// Include logical decoding messages emitted with `pg_logical_emit_message`.
    #[must_use]
    pub fn messages(mut self, enabled: bool) -> Self {
        self.messages = enabled;
        self
    }

    fn start_command(&self) -> Result<String, PgError> {
        let names = self.publications.iter()
            .map(|name| quote_postgres_identifier(name))
            .collect::<Vec<_>>()
            .join(",");
        // The replication scanner uses standard strings: embedded single
        // quotes are doubled, and backslashes have no escape semantics.
        let mut command = format!(
            "START_REPLICATION SLOT {} LOGICAL {} (proto_version '1', publication_names '{}')",
            quote_postgres_identifier(&self.slot), self.start_lsn, names.replace('\'', "''"),
        );
        if self.binary || self.messages {
            command.pop();
            if self.binary {
                command.push_str(", binary 'true'");
            }
            if self.messages {
                command.push_str(", messages 'true'");
            }
            command.push(')');
        }
        if command.len() > MAX_START_COMMAND_BYTES {
            return Err(protocol("replication start command exceeds 64 KiB"));
        }
        Ok(command)
    }
}

/// A WAL envelope or primary keepalive received on the replication connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgReplicationEvent {
    /// Plugin output. Logical payload byte length is not a WAL-position delta.
    XLogData {
        /// Starting WAL position reported by the primary.
        wal_start: PgLsn,
        /// Primary's current WAL end; this is not an acknowledged position.
        wal_end: PgLsn,
        /// Primary timestamp in signed microseconds since 2000-01-01 UTC.
        server_time_micros: i64,
        /// Uninterpreted output-plugin payload, bounded by the configured cap.
        data: Vec<u8>,
    },
    /// Primary liveness message. A requested reply is sent before delivery.
    PrimaryKeepAlive {
        /// Primary's current WAL end; this is not an acknowledged position.
        wal_end: PgLsn,
        /// Primary timestamp in signed microseconds since 2000-01-01 UTC.
        server_time_micros: i64,
        /// Whether the primary requested an immediate status response.
        reply_requested: bool,
    },
}

impl PgReplicationEvent {
    /// Decode a single pgoutput v1 message without copying the plugin payload.
    ///
    /// Keepalives contain no pgoutput message. For batched plugin payloads use
    /// [`super::pgoutput::PgOutputMessages`] on the XLogData `data` field.
    pub fn pgoutput(
        &self,
    ) -> Result<Option<super::pgoutput::PgOutputMessage<'_>>, super::pgoutput::PgOutputError> {
        match self {
            Self::XLogData { data, .. } => super::pgoutput::decode_pgoutput(data).map(Some),
            Self::PrimaryKeepAlive { .. } => Ok(None),
        }
    }
}

/// Explicitly confirmed standby progress. Values describe positions after the
/// last written, durably flushed, and applied WAL bytes, respectively.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PgReplicationFeedback {
    written: PgLsn,
    flushed: PgLsn,
    applied: PgLsn,
    request_reply: bool,
}

impl PgReplicationFeedback {
    /// Confirm application progress, requiring `applied <= flushed <= written`.
    pub fn new(written: PgLsn, flushed: PgLsn, applied: PgLsn) -> Result<Self, PgError> {
        if applied > flushed || flushed > written {
            return Err(protocol("feedback requires applied <= flushed <= written"));
        }
        Ok(Self { written, flushed, applied, request_reply: false })
    }

    /// Ask the primary to send an immediate keepalive response.
    #[must_use]
    pub fn request_reply(mut self, enabled: bool) -> Self {
        self.request_reply = enabled;
        self
    }

    /// Last position confirmed written by the application.
    #[must_use]
    pub const fn written(self) -> PgLsn { self.written }

    /// Last position confirmed durably flushed by the application.
    #[must_use]
    pub const fn flushed(self) -> PgLsn { self.flushed }

    /// Last position confirmed applied by the application.
    #[must_use]
    pub const fn applied(self) -> PgLsn { self.applied }

    fn follows(self, previous: Self) -> bool {
        self.written >= previous.written
            && self.flushed >= previous.flushed
            && self.applied >= previous.applied
    }
}

/// An authenticated logical walsender connection, ready to start one stream.
///
/// It deliberately cannot be inserted into the ordinary query pool or expose
/// extended-query APIs. Reconnection is explicit and retains no hidden slot
/// creation or automatic acknowledgement behavior.
#[derive(Debug)]
pub struct PgReplicationConnection {
    connection: Option<PgConnection>,
    owner: Cx,
}

impl PgReplicationConnection {
    /// Connect to a database in logical replication mode using its URL/TLS policy.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, PgError> {
        let (options, tls) = match PgConnectOptions::parse_with_tls(url) {
            Ok(options) => options,
            Err(error) => return Outcome::Err(error),
        };
        Self::connect_with_tls_options(cx, options, tls).await
    }

    /// Connect with ordinary connection options and the default TLS policy.
    pub async fn connect_with_options(cx: &Cx, options: PgConnectOptions) -> Outcome<Self, PgError> {
        Self::connect_with_tls_options(cx, options, PgTlsOptions::default()).await
    }

    /// Connect with explicit trust/verification/timeout policy.
    pub async fn connect_with_tls_options(
        cx: &Cx,
        options: PgConnectOptions,
        tls: PgTlsOptions,
    ) -> Outcome<Self, PgError> {
        if let Err(error) = require_io(cx) {
            return Outcome::Err(error);
        }
        let timeout = options.connect_timeout.unwrap_or(tls.connect_timeout_duration());
        let mut control = ReplicationControl::new(cx);
        control.limit_after(timeout);
        // This dedicated outer control owns the whole-connect timeout on the
        // captured clock. Poll and Drop still use the existing scoped future.
        let connect = cx.with_ambient(async {
            Ok(PgConnection::connect_with_tls_options_inner(cx, options, tls, true).await)
        });
        match control.drive(cx, connect).await {
            Ok(Outcome::Ok(connection)) => Outcome::Ok(Self { connection: Some(connection), owner: cx.clone() }),
            Ok(Outcome::Err(error)) | Err(error) => outcome_from_error(error),
            Ok(Outcome::Cancelled(reason)) => Outcome::Cancelled(reason),
            Ok(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
        }
    }

    /// Start pgoutput version 1 from an existing logical slot.
    ///
    /// The returned stream exclusively owns the connection. Dropping this
    /// future before startup completes closes it, without replaying the command.
    pub async fn start(mut self, cx: &Cx, config: PgReplicationConfig) -> Outcome<PgReplicationStream, PgError> {
        let command = match config.start_command() {
            Ok(command) => command,
            Err(error) => return Outcome::Err(error),
        };
        if let Err(error) = require_io(cx) {
            return Outcome::Err(error);
        }
        let mut buffer = MessageBuffer::new();
        buffer.write_cstring(&command);
        let message = match buffer.build_message(FrontendMessage::Query as u8) {
            Ok(message) => message,
            Err(error) => return Outcome::Err(error),
        };
        let mut stream = PgReplicationStream {
            connection: self.connection.take().expect("owned replication connection"),
            control: ReplicationControl::new(cx),
            max_message_bytes: config.max_message_bytes,
            pending_write: Some(PendingWrite::new(message, WriteKind::Start)),
            pending_event: None,
            feedback: PgReplicationFeedback::default(),
            sender_done: false,
            receiver_done: false,
            completions: 0,
            state: StreamState::Starting,
        };
        stream.connection.inner.closed = true;
        if let Err(error) = stream.flush_pending(cx).await {
            return stream.fail(error).await;
        }
        loop {
            let (tag, data) = match stream.read_message(cx).await {
                Ok(message) => message,
                Err(error) => return stream.fail(error).await,
            };
            match tag {
                b'W' => {
                    let formats = match PgConnection::parse_copy_response("CopyBothResponse", &data) {
                        Ok(formats) => formats,
                        Err(error) => return stream.fail(error).await,
                    };
                    if !formats.1.is_empty() {
                        return stream.fail(protocol("replication CopyBothResponse must have zero columns")).await;
                    }
                    stream.state = StreamState::Streaming;
                    return Outcome::Ok(stream);
                }
                b'E' => {
                    let error = stream.connection.parse_error_response(&data)
                        .unwrap_or_else(|error| error);
                    return stream.fail(error).await;
                }
                _ => match stream.connection.handle_async_backend_message(tag, &data) {
                    Ok(true) => crate::runtime::yield_now().await,
                    Ok(false) => return stream.fail(unexpected_backend_message("replication startup", tag)).await,
                    Err(error) => return stream.fail(error).await,
                },
            }
        }
    }
}

impl Drop for PgReplicationConnection {
    fn drop(&mut self) {
        let _ambient = self.owner.clone().set_current_restricted();
        if let Some(mut connection) = self.connection.take() {
            connection.abort_in_flight_exchange();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState { Starting, Streaming, Completed, Failed }

#[derive(Debug, Clone, Copy)]
enum WriteKind { Start, Feedback(PgReplicationFeedback), Done }

struct PendingWrite {
    frame: Vec<u8>,
    offset: usize,
    kind: WriteKind,
}

impl PendingWrite {
    fn new(frame: Vec<u8>, kind: WriteKind) -> Self {
        Self { frame, offset: 0, kind }
    }
}

/// An owned, bounded, bidirectional logical replication exchange.
///
/// Each call runs in its caller's task. There is no background reader, writer,
/// or implicit buffering of the replication history. Partial backend frames
/// and outbound frame offsets remain in this object when a method future is
/// dropped, so a wait can be resumed or interrupted to send feedback. Dropping
/// the stream itself closes the socket. Explicit cancellation attempts the
/// existing bounded CancelRequest exchange before closing it.
pub struct PgReplicationStream {
    connection: PgConnection,
    control: ReplicationControl,
    max_message_bytes: usize,
    pending_write: Option<PendingWrite>,
    pending_event: Option<PgReplicationEvent>,
    feedback: PgReplicationFeedback,
    sender_done: bool,
    receiver_done: bool,
    completions: u8,
    state: StreamState,
}

impl fmt::Debug for PgReplicationStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgReplicationStream")
            .field("state", &self.state)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("feedback", &self.feedback)
            .field("sender_done", &self.sender_done)
            .field("receiver_done", &self.receiver_done)
            .finish_non_exhaustive()
    }
}

impl PgReplicationStream {
    /// Last complete feedback frame sent to the primary.
    #[must_use]
    pub const fn feedback(&self) -> PgReplicationFeedback { self.feedback }

    /// Receive one bounded WAL event or keepalive, without reading ahead.
    ///
    /// Requested keepalive replies repeat the most recently confirmed feedback;
    /// they never acknowledge `wal_end` or infer LSNs from payload byte counts.
    /// EOF requires both CopyDone messages and the complete terminal exchange.
    pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<PgReplicationEvent>, PgError> {
        match self.state {
            StreamState::Completed => return Outcome::Ok(None),
            StreamState::Failed => return Outcome::Err(protocol("replication stream has failed")),
            StreamState::Starting => return Outcome::Err(protocol("replication has not started")),
            StreamState::Streaming => {}
        }
        loop {
            if let Err(error) = self.flush_pending(cx).await {
                return self.fail(error).await;
            }
            if let Some(event) = self.pending_event.take() {
                return Outcome::Ok(Some(event));
            }
            let (tag, data) = match self.read_message(cx).await {
                Ok(message) => message,
                Err(error) => return self.fail(error).await,
            };
            match tag {
                b'd' if !self.receiver_done => {
                    let event = match parse_event(data) {
                        Ok(event) => event,
                        Err(error) => return self.fail(error).await,
                    };
                    let reply = matches!(&event, PgReplicationEvent::PrimaryKeepAlive { reply_requested: true, .. });
                    self.pending_event = Some(event);
                    if reply && !self.sender_done {
                        self.queue_feedback(self.feedback.request_reply(false));
                    }
                }
                b'c' if !self.receiver_done => {
                    if !data.is_empty() {
                        return self.fail(protocol("replication CopyDone must have no body")).await;
                    }
                    self.receiver_done = true;
                    if !self.sender_done {
                        self.queue_done();
                    }
                }
                b'C' if self.receiver_done && self.sender_done && self.completions < 2 => {
                    let mut reader = MessageReader::new(&data);
                    let command = match reader.read_cstring() {
                        Ok(command) => command,
                        Err(error) => return self.fail(error).await,
                    };
                    if let Err(error) = reader.ensure_consumed("replication CommandComplete") {
                        return self.fail(error).await;
                    }
                    let valid = match self.completions {
                        0 => command == "COPY" || command == "COPY 0",
                        1 => command == "START_REPLICATION",
                        _ => false,
                    };
                    if !valid {
                        return self.fail(protocol("unexpected replication completion tag")).await;
                    }
                    self.completions += 1;
                }
                b'Z' if self.receiver_done && self.sender_done && self.completions == 2 => {
                    if let Err(error) = self.connection.handle_ready_for_query(&data) {
                        return self.fail(error).await;
                    }
                    if self.connection.inner.transaction_status != b'I' {
                        return self.fail(protocol("replication completion is not idle")).await;
                    }
                    self.state = StreamState::Completed;
                    self.control.sleep = None;
                    self.connection.abort_in_flight_exchange();
                    return Outcome::Ok(None);
                }
                b'E' => {
                    let error = self.connection.parse_error_response(&data)
                        .unwrap_or_else(|error| error);
                    // A replication error can require Sync, unlike ordinary
                    // COPY OUT. This dedicated failed connection is closed,
                    // never misrepresented as synchronized query-pool state.
                    return self.fail(error).await;
                }
                _ => match self.connection.handle_async_backend_message(tag, &data) {
                    Ok(true) => crate::runtime::yield_now().await,
                    Ok(false) => return self.fail(unexpected_backend_message("logical replication", tag)).await,
                    Err(error) => return self.fail(error).await,
                },
            }
        }
    }

    /// Send caller-confirmed progress. Each position must be nondecreasing.
    ///
    /// The caller, rather than the network reader, decides what has been durably
    /// flushed/applied. A dropped send future retains its exact frame and offset;
    /// the next operation finishes that frame before sending another one.
    pub async fn send_feedback(&mut self, cx: &Cx, feedback: PgReplicationFeedback) -> Outcome<(), PgError> {
        if self.state != StreamState::Streaming || self.sender_done || self.receiver_done {
            return Outcome::Err(protocol("replication stream no longer accepts feedback"));
        }
        let previous = self.pending_write.as_ref().and_then(|pending| match pending.kind {
            WriteKind::Feedback(feedback) => Some(feedback),
            _ => None,
        }).unwrap_or(self.feedback);
        if !feedback.follows(previous) {
            return Outcome::Err(protocol("replication feedback cannot move backwards"));
        }
        if let Err(error) = self.flush_pending(cx).await {
            return self.fail(error).await;
        }
        self.queue_feedback(feedback);
        match self.flush_pending(cx).await {
            Ok(()) => Outcome::Ok(()),
            Err(error) => self.fail(error).await,
        }
    }

    /// Send CopyDone, drain the primary's terminal exchange, and close.
    ///
    /// Unread WAL messages are discarded without acknowledging their positions.
    /// A context deadline bounds a peer that does not finish. Dropping this
    /// future also drops the owned stream and closes the connection.
    pub async fn finish(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.state == StreamState::Completed {
            return Outcome::Ok(());
        }
        if self.state != StreamState::Streaming {
            return Outcome::Err(protocol("replication stream cannot finish after failure"));
        }
        if let Err(error) = self.flush_pending(cx).await {
            return self.fail(error).await;
        }
        if !self.sender_done {
            self.queue_done();
        }
        loop {
            match self.next(cx).await {
                Outcome::Ok(Some(_)) => crate::runtime::yield_now().await,
                Outcome::Ok(None) => return Outcome::Ok(()),
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
    }

    fn queue_done(&mut self) {
        debug_assert!(self.pending_write.is_none());
        self.pending_write = Some(PendingWrite::new(vec![b'c', 0, 0, 0, 4], WriteKind::Done));
        self.sender_done = true;
    }

    fn queue_feedback(&mut self, feedback: PgReplicationFeedback) {
        debug_assert!(self.pending_write.is_none());
        let mut frame = Vec::with_capacity(39);
        frame.push(b'd');
        frame.extend_from_slice(&38i32.to_be_bytes());
        frame.push(b'r');
        frame.extend_from_slice(&feedback.written.as_u64().to_be_bytes());
        frame.extend_from_slice(&feedback.flushed.as_u64().to_be_bytes());
        frame.extend_from_slice(&feedback.applied.as_u64().to_be_bytes());
        frame.extend_from_slice(&feedback_time_micros().to_be_bytes());
        frame.push(u8::from(feedback.request_reply));
        self.pending_write = Some(PendingWrite::new(frame, WriteKind::Feedback(feedback)));
    }

    async fn flush_pending(&mut self, cx: &Cx) -> Result<(), PgError> {
        let Some(pending) = self.pending_write.as_mut() else {
            // Buffered event delivery is still a live session operation: it
            // cannot bypass owner/poller cancellation or authority checks.
            return self.control.drive(cx, async { Ok(()) }).await;
        };
        let stream = &mut self.connection.inner.stream;
        self.control.drive(cx, poll_fn(|task| poll_pending_write(pending, stream, task))).await?;
        if let Some(PendingWrite { kind: WriteKind::Feedback(feedback), .. }) = self.pending_write.take() {
            self.feedback = feedback;
        }
        Ok(())
    }

    async fn read_message(&mut self, cx: &Cx) -> Result<(u8, Vec<u8>), PgError> {
        let owner = self.control.owner.clone();
        self.control.drive(cx, self.connection.read_message_buffered(
            &owner, self.max_message_bytes, "logical replication",
        )).await
    }

    async fn fail<T>(&mut self, error: PgError) -> Outcome<T, PgError> {
        self.state = StreamState::Failed;
        self.control.sleep = None;
        if matches!(&error, PgError::Cancelled(_)) {
            // The guard closes even when the bounded cancel-drain future is
            // itself dropped while the caller retains this failed stream.
            let owner = self.control.owner.clone();
            let drain = CloseAfterDrain { connection: &mut self.connection, owner: owner.clone() };
            owner.with_ambient(drain.connection.wire_cancel_in_drain(&owner)).await;
        } else {
            self.connection.abort_in_flight_exchange();
        }
        self.pending_write = None;
        self.pending_event = None;
        outcome_from_error(error)
    }
}

impl Drop for PgReplicationStream {
    fn drop(&mut self) {
        let _ambient = self.control.owner.clone().set_current_restricted();
        self.connection.abort_in_flight_exchange();
    }
}

struct CloseAfterDrain<'a> {
    connection: &'a mut PgConnection,
    owner: Cx,
}

impl Drop for CloseAfterDrain<'_> {
    fn drop(&mut self) {
        let _ambient = self.owner.clone().set_current_restricted();
        self.connection.abort_in_flight_exchange();
    }
}

fn poll_pending_write<S: AsyncWrite + Unpin>(
    pending: &mut PendingWrite,
    stream: &mut S,
    task: &mut Context<'_>,
) -> Poll<Result<(), PgError>> {
    for _ in 0..POLL_STEPS {
        if pending.offset == pending.frame.len() {
            return Pin::new(&mut *stream).poll_flush(task).map_err(PgError::Io);
        }
        let remaining = &pending.frame[pending.offset..];
        match Pin::new(&mut *stream).poll_write(task, remaining) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(PgError::Io(io::Error::new(
                io::ErrorKind::WriteZero, "replication write accepted no bytes",
            )))),
            Poll::Ready(Ok(written)) if written <= remaining.len() => pending.offset += written,
            Poll::Ready(Ok(_)) => return Poll::Ready(Err(protocol("transport wrote beyond the supplied buffer"))),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(PgError::Io(error))),
            Poll::Pending => return Poll::Pending,
        }
    }
    task.waker().wake_by_ref();
    Poll::Pending
}

fn protocol(message: &str) -> PgError {
    PgError::Protocol(message.to_owned())
}

fn require_io(cx: &Cx) -> Result<(), PgError> {
    crate::cx::io_gate::require_ambient_io("PostgreSQL replication").map_err(PgError::Io)?;
    if !cx.runtime_mask.has(CapMask::IO) {
        return Err(PgError::Io(io::Error::new(io::ErrorKind::PermissionDenied,
            "PostgreSQL replication requires the explicit context's IO capability")));
    }
    Ok(())
}

fn parse_event(mut data: Vec<u8>) -> Result<PgReplicationEvent, PgError> {
    let read_u64 = |offset: usize| {
        data.get(offset..offset + 8)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| protocol("truncated replication envelope"))
    };
    match data.first().copied() {
        Some(b'w') if data.len() >= 25 => {
            let wal_start = PgLsn::new(read_u64(1)?);
            let wal_end = PgLsn::new(read_u64(9)?);
            let server_time_micros = read_u64(17)? as i64;
            drop(data.drain(..25));
            Ok(PgReplicationEvent::XLogData { wal_start, wal_end, server_time_micros, data })
        }
        Some(b'k') if data.len() == 18 => {
            let wal_end = PgLsn::new(read_u64(1)?);
            let server_time_micros = read_u64(9)? as i64;
            let reply_requested = match data[17] {
                0 => false,
                1 => true,
                _ => return Err(protocol("invalid keepalive reply flag")),
            };
            Ok(PgReplicationEvent::PrimaryKeepAlive { wal_end, server_time_micros, reply_requested })
        }
        _ => Err(protocol("invalid logical replication CopyData envelope")),
    }
}

fn feedback_time_micros() -> i64 {
    const PG_EPOCH_UNIX_MICROS: i128 = 946_684_800_000_000;
    let unix = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_micros() as i128,
        Err(error) => -(error.duration().as_micros() as i128),
    };
    (unix - PG_EPOCH_UNIX_MICROS).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

struct ReplicationControl {
    owner: Cx,
    initial_poller: Option<Cx>,
    driver: Option<TimerDriverHandle>,
    deadline: Option<Time>,
    deadline_is_timeout: bool,
    sleep: Option<Sleep>,
}

struct PollerCancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl Drop for PollerCancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

impl ReplicationControl {
    fn new(cx: &Cx) -> Self {
        let initial_poller = Cx::current();
        let driver = cx.timer_driver()
            .or_else(|| initial_poller.as_ref().and_then(Cx::timer_driver));
        let mut control = Self {
            owner: cx.clone(), initial_poller, driver, deadline: None,
            deadline_is_timeout: false, sleep: None,
        };
        control.tighten(cx);
        if let Some(poller) = control.initial_poller.clone() {
            control.tighten(&poller);
        }
        control
    }

    fn now(&self) -> Time {
        self.driver.as_ref().map_or_else(crate::time::wall_now, TimerDriverHandle::now)
    }

    fn tighten(&mut self, cx: &Cx) {
        let Some(deadline) = cx.budget().deadline else { return; };
        let cx_now = cx.timer_driver().map_or_else(crate::time::wall_now, |driver| driver.now());
        let deadline = self.now().saturating_add_nanos(deadline.as_nanos().saturating_sub(cx_now.as_nanos()));
        self.bound(deadline, false);
    }

    fn limit_after(&mut self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.bound(self.now().saturating_add_nanos(nanos), true);
    }

    fn bound(&mut self, deadline: Time, timeout: bool) {
        if self.deadline == Some(deadline) {
            if !timeout { self.deadline_is_timeout = false; }
            return;
        }
        if self.deadline.is_none_or(|current| deadline < current) {
            self.deadline = Some(deadline);
            self.deadline_is_timeout = timeout;
            match &mut self.sleep {
                Some(sleep) => sleep.reset(deadline),
                None => self.sleep = Some(self.driver.as_ref().map_or_else(
                    || Sleep::new(deadline),
                    |driver| Sleep::with_timer_driver(deadline, driver.clone()),
                )),
            }
        }
    }

    fn expired(&self) -> PgError {
        if self.deadline_is_timeout {
            PgError::Io(io::Error::new(io::ErrorKind::TimedOut, "PostgreSQL replication connection timed out"))
        } else {
            PgError::Cancelled(CancelReason::deadline())
        }
    }

    async fn drive<T>(
        &mut self,
        cx: &Cx,
        future: impl Future<Output = Result<T, PgError>>,
    ) -> Result<T, PgError> {
        let owner = self.owner.clone();
        let initial = self.initial_poller.clone();
        let mut guards = std::iter::once(&owner)
            .chain(initial.as_ref())
            .chain(std::iter::once(cx))
            .map(CancelWakerGuard::new)
            .collect::<Vec<_>>();
        let mut poller: Option<PollerCancellation> = None;
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            require_io(cx)?;
            require_io(&owner)?;
            let current = Cx::current();
            if current.as_ref().is_none_or(|current| poller.as_ref().is_none_or(|previous| {
                !std::sync::Arc::ptr_eq(&previous.cx.inner, &current.inner)
            })) {
                poller = current.map(|cx| PollerCancellation { cx, token: None });
            }
            for guard in &mut guards { guard.refresh(task.waker()); }
            if let Some(poller) = &mut poller {
                poller.token = Some(poller.cx.refresh_cancel_waker(poller.token, task.waker()));
                if poller.cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(&poller.cx)));
                }
                self.tighten(&poller.cx);
            }
            for guard in &guards {
                if guard.cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(guard.cx)));
                }
                self.tighten(guard.cx);
            }
            if self.deadline.is_some_and(|deadline| self.now() >= deadline) {
                return Poll::Ready(Err(self.expired()));
            }
            if let Some(sleep) = &mut self.sleep {
                let _ambient = self.driver.is_none().then(|| owner.clone().set_current_restricted());
                if Pin::new(sleep).poll_deadline(task).is_ready() {
                    return Poll::Ready(Err(self.expired()));
                }
            }
            let result = {
                let _ambient = owner.clone().set_current_restricted();
                future.as_mut().poll(task)
            };
            for guard in &guards {
                if guard.cx.checkpoint().is_err() {
                    let _ambient = owner.clone().set_current_restricted();
                    drop(result);
                    return Poll::Ready(Err(cancelled_error(guard.cx)));
                }
            }
            if let Some(poller) = &poller
                && poller.cx.checkpoint().is_err()
            {
                let _ambient = owner.clone().set_current_restricted();
                drop(result);
                return Poll::Ready(Err(cancelled_error(&poller.cx)));
            }
            result
        }).await
    }
}

#[cfg(test)]
#[path = "replication_tests.rs"]
mod tests;
