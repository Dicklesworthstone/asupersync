//! Native HTTP/3 session mapping over native QUIC stream bytes.
//!
//! [`NativeH3Session`] is deliberately an established-connection adapter: it
//! does not own UDP sockets, TLS handshakes, or a runtime task. Applications
//! drive a [`QuicConnection`], then use this type to put HTTP/3 control,
//! request, and response bytes onto its reliable streams. This keeps the
//! composition usable by both the deterministic lab transport and the native
//! UDP driver without introducing another executor.
//!
//! Outgoing field sections use static QPACK unless acknowledged-only dynamic
//! encoding is enabled explicitly. Opt-in dynamic receive maintains a
//! bounded table and optionally admits bounded blocked streams. Server push and
//! external interoperability certification remain outside this adapter's claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll, Waker};

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::net::quic_core::{QUIC_VARINT_MAX, QuicCoreError, decode_varint, encode_varint};
use crate::net::quic_native::connection::NativeQuicConnectionError;
use crate::net::quic_native::endpoint_api::QuicConnection;
use crate::net::quic_native::streams::{
    FlowControlError, QuicStreamError, StreamDirection, StreamId, StreamReadiness, StreamRole,
    StreamTableError,
};

#[path = "h3_receive_frame.rs"]
mod receive_frame;
use receive_frame::{DataFrameCursor, FrameHeader, FrameHeaderError};

#[path = "h3_request_writer.rs"]
mod request_writer;
pub use request_writer::{NativeH3RequestWriteEvent, NativeH3RequestWriter};
use request_writer::{
    MAX_REQUEST_WRITERS, RequestWriteOwner, RequestWriterState, RequestWriterWake,
};

#[path = "h3_send_qpack.rs"]
mod send_qpack;
use send_qpack::{NativeH3DynamicSend, PreparedQpackSection};

use super::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3EndpointRole, H3Frame, H3NativeError,
    H3QpackMode, H3RequestHead, H3ResponseHead, H3Settings, H3UniStreamType,
    QpackBlockedStreamStatus, QpackDecoderInstruction, QpackEncoderInstruction,
    QpackFieldSectionMetadata, QpackInstructionStreamState,
    header_fields_to_request_head,
    header_fields_to_response_head, qpack_decode_decoder_instruction,
    qpack_decode_encoder_instruction, qpack_decode_field_section_with_context,
    qpack_decode_field_section_with_metadata,
    qpack_encode_decoder_instruction, qpack_encode_request_field_section,
    qpack_encode_response_field_section, qpack_field_section_metadata,
    qpack_encode_trailer_field_section, qpack_plan_field_section_size,
    qpack_plan_to_header_fields, validate_trailer_fields,
    qpack_static_plan_for_request, qpack_static_plan_for_response,
};

/// RFC 9114 application error code `H3_REQUEST_CANCELLED`.
pub const H3_REQUEST_CANCELLED: u64 = 0x010c;

/// RFC 9114 application error code `H3_REQUEST_REJECTED`: the request was
/// not processed, so the client may retry it.
pub const H3_REQUEST_REJECTED: u64 = 0x010b;

/// RFC 9114 application error code `H3_MESSAGE_ERROR`.
const H3_MESSAGE_ERROR: u64 = 0x010e;

/// RFC 9114 application error code for excessive peer load.
const H3_EXCESSIVE_LOAD: u64 = 0x0107;

/// RFC 9114 application error code `H3_REQUEST_INCOMPLETE`.
const H3_REQUEST_INCOMPLETE: u64 = 0x010d;

const H3_CONTROL_STREAM_TYPE: u64 = 0x00;
const FRAME_HEADER_MAX_BYTES: usize = 16;
const MAX_OPEN_STREAM_RUNS: usize = 4096;
const STREAMING_READINESS_BATCH: usize = 32;
const STREAMING_POLL_STEPS: usize = 32;

/// Default advertised receive-table capacity for opt-in dynamic QPACK.
pub const NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY: usize = 4096;

/// Maximum advertised receive-table capacity supported by this session profile.
pub const NATIVE_H3_MAX_QPACK_DECODER_CAPACITY: usize = 64 * 1024;

/// Maximum local active table capacity for opt-in dynamic QPACK encoding.
pub const NATIVE_H3_MAX_QPACK_ENCODER_CAPACITY: usize = 64 * 1024;

/// Maximum uncompressed field-section size advertised by dynamic receive sessions.
pub const NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE: u64 = 1024 * 1024;

/// Maximum advertised number of request streams waiting for QPACK insertions.
pub const NATIVE_H3_MAX_QPACK_BLOCKED_STREAMS: u64 = 16;

/// Aggregate encoded field-section payload retained while awaiting QPACK inserts.
///
/// The parser and scheduler each retain a copy until decoding resumes, so this
/// permits at most twice this many payload bytes plus bounded parser lookahead.
pub const NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES: usize = 1024 * 1024;

const NATIVE_H3_MAX_QPACK_FEEDBACK_BYTES: usize = 64 * 1024;
const NATIVE_H3_DYNAMIC_RECEIVE_CHUNK_BYTES: usize = 64 * 1024;

/// Established-session composition errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeH3SessionError {
    /// Native QUIC transport or stream failure.
    Transport(NativeQuicConnectionError),
    /// HTTP/3 or QPACK protocol failure.
    Protocol(H3NativeError),
    /// The requested operation is not valid in the current session state.
    InvalidState(&'static str),
    /// A peer closed a critical unidirectional stream.
    CriticalStreamClosed {
        /// Closed critical stream.
        stream_id: StreamId,
        /// Critical stream type.
        stream_type: H3UniStreamType,
    },
    /// A QUIC stream ended with an incomplete HTTP/3 frame or type prefix.
    TruncatedStream {
        /// Truncated stream.
        stream_id: StreamId,
        /// Bytes left undecoded at FIN. This can be zero in streaming mode
        /// when a DATA header declared payload bytes that never arrived.
        buffered_bytes: usize,
    },
}

impl fmt::Display for NativeH3SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "native QUIC transport failed: {error}"),
            Self::Protocol(error) => write!(f, "HTTP/3 protocol failed: {error}"),
            Self::InvalidState(message) => write!(f, "invalid HTTP/3 session state: {message}"),
            Self::CriticalStreamClosed {
                stream_id,
                stream_type,
            } => write!(
                f,
                "critical HTTP/3 stream closed: stream={} type={stream_type:?}",
                stream_id.0
            ),
            Self::TruncatedStream {
                stream_id,
                buffered_bytes,
            } => write!(
                f,
                "HTTP/3 stream ended with a truncated frame: stream={} buffered_bytes={buffered_bytes}",
                stream_id.0
            ),
        }
    }
}

impl std::error::Error for NativeH3SessionError {}

impl From<NativeQuicConnectionError> for NativeH3SessionError {
    fn from(value: NativeQuicConnectionError) -> Self {
        Self::Transport(value)
    }
}

impl From<H3NativeError> for NativeH3SessionError {
    fn from(value: H3NativeError) -> Self {
        Self::Protocol(value)
    }
}

/// One decoded event from native QUIC stream bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeH3Event {
    /// Peer control stream delivered SETTINGS.
    Settings(H3Settings),
    /// Server received and decoded a request HEADERS field section.
    RequestHeaders {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Validated request head.
        head: H3RequestHead,
    },
    /// Client received and decoded a response HEADERS field section.
    ResponseHeaders {
        /// QUIC request stream carrying the response.
        stream_id: StreamId,
        /// Validated response head.
        head: H3ResponseHead,
    },
    /// Decoded trailer fields from a HEADERS block after final response headers.
    Trailers {
        /// QUIC request stream carrying trailers.
        stream_id: StreamId,
        /// Validated ordinary HTTP trailer fields.
        fields: Vec<(String, String)>,
    },
    /// DATA bytes on a request/response stream.
    Data {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Frame payload. With [`NativeH3Session::enable_streaming_receive`],
        /// this may be one bounded piece of a DATA frame whose remaining bytes
        /// have not arrived yet. DATA frame boundaries are not preserved in
        /// that opt-in mode; HTTP message completion still requires `Finished`.
        bytes: Bytes,
    },
    /// Peer sent GOAWAY on its control stream.
    Goaway(u64),
    /// A permitted frame not otherwise lifted into a typed event.
    Frame {
        /// QUIC stream carrying the frame.
        stream_id: StreamId,
        /// Decoded frame.
        frame: H3Frame,
    },
    /// Peer FIN completed one request/response direction.
    Finished {
        /// Finished QUIC stream.
        stream_id: StreamId,
    },
    /// Peer reset one request/response stream.
    ///
    /// A session also reports local message refusals this way, with
    /// `final_size` 0: malformed messages use H3_MESSAGE_ERROR (0x10e),
    /// incomplete requests use H3_REQUEST_INCOMPLETE (0x10d), and sections
    /// exceeding the locally advertised size use H3_EXCESSIVE_LOAD (0x107).
    /// Other requests are unaffected.
    StreamReset {
        /// Reset QUIC stream.
        stream_id: StreamId,
        /// Application error code.
        error_code: u64,
        /// Peer-declared final stream size.
        final_size: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IncomingStreamKind {
    AwaitingUniType,
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    UnknownUni,
    RequestResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncomingStream {
    kind: IncomingStreamKind,
    bytes: RecvBuf,
    header_blocks_seen: u8,
    final_response_headers_seen: bool,
    data_frame: Option<DataFrameCursor>,
}

/// Received stream bytes, consumed from the front. Decoding removes items one
/// at a time; `Vec::drain(..n)` shifted the rest of the buffer on every
/// removal, so a peer sending a large run of one-byte instructions or tiny
/// frames cost quadratic copying and stalled every connection on the
/// listener's loop. Consumption moves a start offset instead, and the buffer
/// is compacted only once the consumed prefix is at least half of it.
#[derive(Debug, Clone, Default)]
struct RecvBuf {
    data: Vec<u8>,
    start: usize,
}

impl PartialEq for RecvBuf {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for RecvBuf {}

impl RecvBuf {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Drops the first `n` unconsumed bytes.
    fn consume(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.data.len());
        if self.start >= self.data.len() {
            self.data.clear();
            self.start = 0;
        } else if self.start >= self.data.len() / 2 {
            self.data.drain(..self.start);
            self.start = 0;
        }
    }

    /// Removes and returns the first `n` unconsumed bytes.
    fn take_front(&mut self, n: usize) -> Vec<u8> {
        let taken = self[..n].to_vec();
        self.consume(n);
        taken
    }

    fn clear(&mut self) {
        self.data.clear();
        self.start = 0;
    }
}

impl std::ops::Deref for RecvBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[self.start..]
    }
}

#[derive(Debug, Clone)]
struct StreamingReceive {
    max_chunk_bytes: NonZeroUsize,
    ready: BTreeMap<StreamId, StreamReadiness>,
    paused: BTreeSet<StreamId>,
    poll_after: Option<StreamId>,
    waker: Option<Waker>,
}

/// Remembers which streams have terminated, in memory bounded by how many
/// streams are open at once rather than by the connection's history.
///
/// Per stream-id class (`id & 0x03`), every id at or below the class
/// watermark (the highest terminated id) has terminated, except the ids in
/// that class's open runs. A run `start..=end` holds ids of the class that are
/// still open or not yet seen; QUIC opens every lower id of a class
/// implicitly. So a long-lived stream, such as a control stream or a streaming
/// request, costs one run however many later streams finish.
#[derive(Debug, Clone, Default)]
struct TerminalStreamTracker {
    watermark: [Option<u64>; 4],
    open_runs: [BTreeMap<u64, u64>; 4],
    overflowed: bool,
}

impl TerminalStreamTracker {
    fn ensure_healthy(&self) -> Result<(), H3NativeError> {
        if self.overflowed {
            Err(H3NativeError::ControlProtocol(
                "terminal stream tracking window exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn contains(&self, stream_id: StreamId) -> bool {
        let class = usize::try_from(stream_id.0 & 0x03).expect("stream-id class fits usize");
        self.watermark[class].is_some_and(|high| stream_id.0 <= high)
            && self.open_run(class, stream_id.0).is_none()
    }

    /// The open run of `class` holding `id`, as `(start, end)`.
    fn open_run(&self, class: usize, id: u64) -> Option<(u64, u64)> {
        self.open_runs[class]
            .range(..=id)
            .next_back()
            .filter(|&(_, &end)| id <= end)
            .map(|(&start, &end)| (start, end))
    }

    fn add_open_run(&mut self, class: usize, start: u64, end: u64) -> Result<(), H3NativeError> {
        let runs: usize = self.open_runs.iter().map(BTreeMap::len).sum();
        if runs >= MAX_OPEN_STREAM_RUNS {
            self.overflowed = true;
            return Err(H3NativeError::ControlProtocol(
                "terminal stream tracking window exceeded",
            ));
        }
        self.open_runs[class].insert(start, end);
        Ok(())
    }

    fn insert(&mut self, stream_id: StreamId) -> Result<(), H3NativeError> {
        self.ensure_healthy()?;
        if self.contains(stream_id) {
            return Ok(());
        }
        let id = stream_id.0;
        let class_id = id & 0x03;
        let class = usize::try_from(class_id).expect("stream-id class fits usize");
        match self.watermark[class] {
            Some(high) if id <= high => {
                // Below the watermark and not terminated, so `id` is in an
                // open run: split the run around it.
                let (start, end) = self
                    .open_run(class, id)
                    .expect("an unterminated id below the watermark is in an open run");
                self.open_runs[class].remove(&start);
                if id < end {
                    self.open_runs[class].insert(id + 4, end);
                }
                if start < id {
                    self.add_open_run(class, start, id - 4)?;
                }
            }
            high => {
                // Every id of the class between the old watermark and `id` is
                // open or not yet seen.
                let first = high.map_or(class_id, |high| high.saturating_add(4));
                if first < id {
                    self.add_open_run(class, first, id - 4)?;
                }
                self.watermark[class] = Some(id);
            }
        }
        Ok(())
    }
}

impl IncomingStream {
    fn new(stream_id: StreamId) -> Self {
        let kind = match stream_id.direction() {
            StreamDirection::Unidirectional => IncomingStreamKind::AwaitingUniType,
            StreamDirection::Bidirectional => IncomingStreamKind::RequestResponse,
        };
        Self {
            kind,
            bytes: RecvBuf::default(),
            header_blocks_seen: 0,
            final_response_headers_seen: false,
            data_frame: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeH3ResponsePhase {
    HeadPending,
    Open,
    TerminalPending,
    Finished,
}

/// One incremental HTTP/3 response write committed to the QUIC stream queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeH3WriteEvent {
    /// Final response HEADERS were queued.
    Head {
        /// Whether the HEADERS write also carried QUIC FIN.
        end_stream: bool,
    },
    /// One DATA frame was queued.
    Data {
        /// Application payload bytes carried by the frame.
        payload_bytes: usize,
    },
    /// Trailing HEADERS and QUIC FIN were queued together.
    Trailers,
    /// A FIN-only STREAM write was queued.
    Finished,
}

#[derive(Debug)]
struct NativeH3PendingWrite {
    wire: Bytes,
    fin: bool,
    event: NativeH3WriteEvent,
    next_phase: NativeH3ResponsePhase,
    qpack_section: Option<PreparedQpackSection>,
}

/// Incremental response writer for one established HTTP/3 request stream.
///
/// The writer retains exactly one encoded H3 frame, sending its remaining
/// bytes as both QUIC flow-control scopes grant credit. It also waits for the
/// preceding STREAM fragment to leave packet assembly, so a caller cannot
/// build an unbounded transport-side queue by repeatedly polling a producer.
#[derive(Debug)]
pub(crate) struct NativeH3ResponseWriter {
    stream_id: StreamId,
    phase: NativeH3ResponsePhase,
    pending: Option<NativeH3PendingWrite>,
    max_frame_payload_size: usize,
    // Shared with the session so trailers observe SETTINGS received after
    // this writer was created. u64::MAX represents the absent setting.
    peer_max_field_section_size: Arc<AtomicU64>,
}

impl NativeH3ResponseWriter {
    /// QUIC request stream carrying this response.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Whether an encoded H3 frame is retained awaiting QUIC admission.
    #[must_use]
    pub fn has_pending_write(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether the terminal frame or FIN has been queued successfully.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.phase == NativeH3ResponsePhase::Finished
    }

    #[must_use]
    pub(crate) fn max_frame_payload_size(&self) -> usize {
        self.max_frame_payload_size
    }

    /// Encode and retain one bounded DATA frame.
    pub fn queue_data(&mut self, data: Bytes) -> Result<(), NativeH3SessionError> {
        self.ensure_open_without_pending()?;
        if data.len() > self.max_frame_payload_size {
            return Err(NativeH3SessionError::Protocol(
                H3NativeError::FrameTooLarge {
                    payload_size: data.len(),
                    max_size: self.max_frame_payload_size,
                },
            ));
        }
        let payload_bytes = data.len();
        let wire = encode_frame(H3Frame::Data(data.to_vec()))?;
        self.pending = Some(NativeH3PendingWrite {
            wire,
            fin: false,
            event: NativeH3WriteEvent::Data { payload_bytes },
            next_phase: NativeH3ResponsePhase::Open,
            qpack_section: None,
        });
        Ok(())
    }

    /// Encode and retain one terminal trailing HEADERS block.
    pub fn queue_trailers(
        &mut self,
        fields: &[(String, String)],
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_open_without_pending()?;
        ensure_outgoing_field_section_fits(
            fields.iter().map(|(name, value)| (name.len(), value.len())),
            self.peer_max_field_section_size.load(Ordering::Acquire),
        )?;
        let field_section = qpack_encode_trailer_field_section(fields)?;
        if field_section.len() > self.max_frame_payload_size {
            return Err(NativeH3SessionError::Protocol(
                H3NativeError::FrameTooLarge {
                    payload_size: field_section.len(),
                    max_size: self.max_frame_payload_size,
                },
            ));
        }
        self.pending = Some(NativeH3PendingWrite {
            wire: encode_frame(H3Frame::Headers(field_section))?,
            fin: true,
            event: NativeH3WriteEvent::Trailers,
            next_phase: NativeH3ResponsePhase::Finished,
            qpack_section: None,
        });
        self.phase = NativeH3ResponsePhase::TerminalPending;
        Ok(())
    }

    /// Retain a FIN-only terminal write.
    pub fn finish(&mut self) -> Result<(), NativeH3SessionError> {
        if self.phase == NativeH3ResponsePhase::Finished {
            return Ok(());
        }
        self.ensure_open_without_pending()?;
        self.pending = Some(NativeH3PendingWrite {
            wire: Bytes::new(),
            fin: true,
            event: NativeH3WriteEvent::Finished,
            next_phase: NativeH3ResponsePhase::Finished,
            qpack_section: None,
        });
        self.phase = NativeH3ResponsePhase::TerminalPending;
        Ok(())
    }

    /// Poll one retained frame through QUIC queue and flow admission.
    ///
    /// Each poll queues at most one fragment. `Pending` can mean a prefix was
    /// queued; the retained suffix prevents retries from repeating it. A frame
    /// event and its phase transition occur only after the last byte is queued,
    /// and only that final fragment can carry FIN. `Ok(None)` means no frame
    /// was pending, never partial completion.
    pub fn poll_flush_one(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<NativeH3WriteEvent>, NativeH3SessionError>> {
        let Some(pending) = self.pending.as_ref() else {
            return Poll::Ready(Ok(None));
        };
        // HEADERS and trailers cannot be shortened at the HTTP/3 layer. Wait
        // for one byte, not the entire encoded frame: a small receive window
        // cannot grow until the peer has received and consumed a prefix.
        // FIN-only writes need no byte credit, but still wait for queue drain.
        let required = u64::from(!pending.wire.is_empty());
        let capacity = match connection.poll_stream_write_ready(cx, self.stream_id, required, task_cx) {
            Poll::Ready(Ok(capacity)) => capacity,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(NativeH3SessionError::Transport(error)));
            }
            Poll::Pending => return Poll::Pending,
        };

        let pending = self.pending.as_mut().expect("checked above");
        let count = pending
            .wire
            .len()
            .min(usize::try_from(capacity).unwrap_or(usize::MAX));
        let complete = count == pending.wire.len();
        let wire = pending.wire.slice(..count);
        let fin = complete && pending.fin;
        let written = match &mut pending.qpack_section {
            Some(section) => section.write(cx, connection, self.stream_id, wire, fin),
            None => connection.write_stream(cx, self.stream_id, wire, fin).map_err(Into::into),
        };
        if let Err(error) = written {
            return Poll::Ready(Err(error));
        }
        if !complete {
            let pending = self.pending.as_mut().expect("frame retained until complete");
            pending.wire = pending.wire.slice(count..);
            // Rearm after actual progress, not while flow-blocked. The next
            // poll either advances or parks on queue/credit readiness. This
            // also lets the enclosing listener pump the just-queued fragment.
            task_cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let pending = self.pending.take().expect("write retained until success");
        self.phase = pending.next_phase;
        Poll::Ready(Ok(Some(pending.event)))
    }

    fn ensure_open_without_pending(&self) -> Result<(), NativeH3SessionError> {
        if self.phase != NativeH3ResponsePhase::Open {
            return Err(NativeH3SessionError::InvalidState(
                "incremental response is not open for another frame",
            ));
        }
        if self.pending.is_some() {
            return Err(NativeH3SessionError::InvalidState(
                "incremental response already retains a pending frame",
            ));
        }
        Ok(())
    }
}

/// Exact encoded H3 DATA-frame wire length for a payload size.
pub(crate) fn h3_data_frame_wire_len(payload_len: usize) -> Result<u64, NativeH3SessionError> {
    let payload_len = u64::try_from(payload_len).map_err(|_| {
        NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
            "HTTP/3 DATA payload exceeds addressable range",
        ))
    })?;
    if payload_len > QUIC_VARINT_MAX {
        return Err(NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
            "HTTP/3 DATA payload length exceeds QUIC varint range",
        )));
    }
    let length_prefix = match payload_len {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    let wire_len =
        payload_len
            .checked_add(1 + length_prefix)
            .ok_or(NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
                "encoded HTTP/3 DATA frame length overflow",
            )))?;
    if wire_len > QUIC_VARINT_MAX {
        return Err(NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
            "encoded HTTP/3 DATA frame length exceeds QUIC varint range",
        )));
    }
    Ok(wire_len)
}

fn encode_frame(frame: H3Frame) -> Result<Bytes, NativeH3SessionError> {
    let mut wire = Vec::new();
    frame.encode(&mut wire)?;
    Ok(Bytes::from(wire))
}

fn write_prepared_head(
    section: &mut Option<PreparedQpackSection>,
    cx: &Cx,
    connection: &mut QuicConnection,
    stream_id: StreamId,
    wire: Bytes,
    fin: bool,
) -> Result<(), NativeH3SessionError> {
    match section {
        Some(section) => section.write(cx, connection, stream_id, wire, fin),
        None => connection.write_stream(cx, stream_id, wire, fin).map_err(Into::into),
    }
}

/// Append `body` as DATA frames of at most `max_payload` bytes each. A peer
/// with the same frame limit, such as this crate's sessions, refuses a larger
/// DATA frame as a connection error.
fn encode_body_frames(
    body: &[u8],
    max_payload: usize,
    wire: &mut Vec<u8>,
) -> Result<(), NativeH3SessionError> {
    for chunk in body.chunks(max_payload.max(1)) {
        H3Frame::Data(chunk.to_vec()).encode(wire)?;
    }
    Ok(())
}

/// Dynamic receive state and the decoder instructions it has committed to emit.
///
/// Applying feedback and retaining its exact bytes are one session-owned step.
/// QUIC admission removes only an accepted prefix; cancellation or a flow-control
/// stall cannot drop an ACK after its references have already been released.
#[derive(Debug, Clone)]
struct NativeH3DynamicReceive {
    qpack: QpackInstructionStreamState,
    pending_sections: BTreeMap<StreamId, PendingQpackSection>,
    pending_section_bytes: usize,
    decoder_stream: Option<StreamId>,
    feedback: VecDeque<u8>,
    prefix_queued: bool,
    first_failure: Option<H3NativeError>,
}

#[derive(Debug, Clone)]
struct PendingQpackSection {
    metadata: QpackFieldSectionMetadata,
    wire_bytes: usize,
}

enum DecodedQpackFields {
    Ready(Vec<(String, String)>),
    Blocked,
    Excessive,
}

impl NativeH3DynamicReceive {
    fn new(settings: &H3Settings) -> Result<Self, H3NativeError> {
        // The local encoder remains static regardless of peer permission. Its
        // effective table budget is zero, including before peer SETTINGS arrive.
        let qpack = QpackInstructionStreamState::from_local_and_peer_settings(
            H3QpackMode::DynamicTableAllowed,
            settings,
            &H3Settings::default(),
        )?;
        Ok(Self {
            qpack,
            pending_sections: BTreeMap::new(),
            pending_section_bytes: 0,
            decoder_stream: None,
            feedback: VecDeque::new(),
            prefix_queued: false,
            first_failure: None,
        })
    }

    fn check_live(&self) -> Result<(), H3NativeError> {
        match self.first_failure.as_ref().or_else(|| self.qpack.first_failure()) {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn record_error(&mut self, error: H3NativeError) -> H3NativeError {
        self.first_failure.get_or_insert(error).clone()
    }

    /// Reserve both encoded bytes and queue capacity before changing references
    /// or Known Received Count. The stream type travels in this same FIFO.
    fn prepare_feedback(
        &mut self,
        instruction: &QpackDecoderInstruction,
    ) -> Result<Vec<u8>, H3NativeError> {
        self.check_live()?;
        let mut wire = Vec::new();
        if !self.prefix_queued {
            wire.push(0x03);
        }
        qpack_encode_decoder_instruction(&mut wire, instruction)?;
        if wire.len() > NATIVE_H3_MAX_QPACK_FEEDBACK_BYTES.saturating_sub(self.feedback.len()) {
            return Err(self.record_error(H3NativeError::QpackPolicy(
                "qpack decoder feedback buffer limit exceeded",
            )));
        }
        if self.feedback.try_reserve(wire.len()).is_err() {
            return Err(self.record_error(H3NativeError::QpackPolicy(
                "qpack decoder feedback allocation failed",
            )));
        }
        Ok(wire)
    }

    fn apply_prepared_feedback(
        &mut self,
        instruction: &QpackDecoderInstruction,
        wire: Vec<u8>,
    ) -> Result<(), H3NativeError> {
        if let Err(error) = self.qpack.apply_local_decoder_instruction(instruction) {
            return Err(self.record_error(error));
        }
        self.feedback.extend(wire);
        self.prefix_queued = true;
        Ok(())
    }

    fn queue_feedback(
        &mut self,
        instruction: &QpackDecoderInstruction,
    ) -> Result<(), H3NativeError> {
        let wire = self.prepare_feedback(instruction)?;
        self.apply_prepared_feedback(instruction, wire)
    }

    fn feed_instructions(
        &mut self,
        mapping: &H3ConnectionState,
        stream_id: StreamId,
        bytes: &[u8],
    ) -> Result<Vec<u64>, H3NativeError> {
        self.check_live()?;
        let outcome = mapping
            .feed_qpack_instruction_stream_bytes(&mut self.qpack, stream_id.0, bytes)
            .map_err(|error| self.record_error(error))?;
        let inserted = self.qpack.received_context().dynamic_table().insertion_counter();
        let acknowledged = self.qpack.received_decoder_feedback().known_received_count();
        if inserted > acknowledged {
            // A zero-blocked encoder cannot reference new entries until this
            // receipt reaches it. Preserve its position relative to every ACK.
            self.queue_feedback(&QpackDecoderInstruction::InsertCountIncrement {
                increment: inserted - acknowledged,
            })?;
        }
        Ok(outcome.unblocked_stream_ids().to_vec())
    }

    fn is_blocked(&self, stream_id: StreamId) -> bool {
        self.pending_sections.contains_key(&stream_id)
            && self.qpack.received_blocked_scheduler().stream_status(stream_id.0)
                == Some(QpackBlockedStreamStatus::Blocked)
    }

    fn forget_pending_section(&mut self, stream_id: StreamId) {
        if let Some(pending) = self.pending_sections.remove(&stream_id) {
            self.pending_section_bytes -= pending.wire_bytes;
        }
    }

    fn decode_fields(
        &mut self,
        stream_id: StreamId,
        field_section: &[u8],
        field_limit: u64,
    ) -> Result<DecodedQpackFields, H3NativeError> {
        self.check_live()?;
        let result = self.decode_fields_inner(stream_id, field_section, field_limit);
        result.map_err(|error| self.record_error(error))
    }

    fn decode_fields_inner(
        &mut self,
        stream_id: StreamId,
        field_section: &[u8],
        field_limit: u64,
    ) -> Result<DecodedQpackFields, H3NativeError> {
        if self.is_blocked(stream_id) {
            return Ok(DecodedQpackFields::Blocked);
        }
        let pending = self.pending_sections.get(&stream_id);
        let was_pending = pending.is_some();
        let metadata = match pending {
            Some(pending) => pending.metadata.clone(),
            None => qpack_field_section_metadata(
                field_section,
                H3QpackMode::DynamicTableAllowed,
                Some(self.qpack.received_context()),
            )?,
        };
        let needs_inserts = metadata.required_insert_count()
            > self.qpack.received_context().dynamic_table().insertion_counter();
        if !was_pending && needs_inserts {
            // Exceeding our advertised QPACK promise is a connection error,
            // even if the same section also exceeds local retention policy.
            // Preflight without copying its wire bytes into the scheduler.
            let scheduler = self.qpack.received_blocked_scheduler();
            if scheduler.settings_blocked_streams() == 0 {
                return Err(H3NativeError::QpackPolicy(
                    "qpack blocked stream capacity is zero",
                ));
            }
            if scheduler.blocked_stream_count() >= scheduler.settings_blocked_streams() {
                return Err(H3NativeError::QpackPolicy(
                    "qpack blocked stream capacity exceeded",
                ));
            }
        }
        if !was_pending
            && needs_inserts
            && field_section.len()
                > NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES
                    .saturating_sub(self.pending_section_bytes)
        {
            // This is our local retention policy, not a malformed peer section.
            // Refuse only this stream before the scheduler acquires ownership.
            return Ok(DecodedQpackFields::Excessive);
        }
        let acknowledgement = QpackDecoderInstruction::HeaderAcknowledgement {
            stream_id: stream_id.0,
        };
        let feedback = if metadata.required_insert_count() > 0 {
            Some(self.prepare_feedback(&acknowledgement)?)
        } else {
            None
        };
        // Reserve the ACK before the scheduler can add protected references.
        // A resumed section already owns a scheduler record; submitting it
        // again would duplicate its references and decoder acknowledgement.
        if !was_pending
            && self.qpack.submit_received_field_section(stream_id.0, field_section)?
                == QpackBlockedStreamStatus::Blocked
        {
            self.pending_section_bytes += field_section.len();
            self.pending_sections.insert(
                stream_id,
                PendingQpackSection {
                    metadata,
                    wire_bytes: field_section.len(),
                },
            );
            return Ok(DecodedQpackFields::Blocked);
        }
        let plan = qpack_decode_field_section_with_metadata(
            field_section,
            H3QpackMode::DynamicTableAllowed,
            Some(self.qpack.received_context()),
            &metadata,
        )?;
        let size = qpack_plan_field_section_size(&plan, Some(self.qpack.received_context()))?;
        let fields = if size <= field_limit {
            DecodedQpackFields::Ready(qpack_plan_to_header_fields(
                &plan,
                Some(self.qpack.received_context()),
            )?)
        } else {
            DecodedQpackFields::Excessive
        };
        if let Some(wire) = feedback {
            // QPACK success is independent of HTTP semantic admission. A later
            // message/field-limit rejection queues cancellation after this ACK.
            self.apply_prepared_feedback(&acknowledgement, wire)?;
        }
        self.forget_pending_section(stream_id);
        Ok(fields)
    }

    fn cancel_stream(&mut self, stream_id: StreamId) -> Result<(), H3NativeError> {
        if self.qpack.received_context().max_table_capacity() == 0
            || self.qpack.received_decoder_feedback().cancelled_stream_ids().contains(&stream_id.0)
        {
            return Ok(());
        }
        self.queue_feedback(&QpackDecoderInstruction::StreamCancellation {
            stream_id: stream_id.0,
        })?;
        self.forget_pending_section(stream_id);
        Ok(())
    }
}

/// HTTP/3 mapping over one established native QUIC connection.
///
/// Outgoing field sections use static QPACK by default. Explicit dynamic send
/// uses only entries acknowledged by the peer and never blocks peer HEADERS.
/// Dynamic receive is an opt-in
/// bounded profile that optionally admits blocked streams and emits at most one
/// application event per decoding step. Its DATA events can be chunked.
#[derive(Debug, Clone)]
pub struct NativeH3Session {
    role: H3EndpointRole,
    config: H3ConnectionConfig,
    state: H3ConnectionState,
    local_control: H3ControlState,
    // Our advertised receive limit, not a limit learned from peer SETTINGS.
    max_field_section_size: Option<u64>,
    peer_max_field_section_size: Arc<AtomicU64>,
    local_control_stream: Option<StreamId>,
    dynamic_receive: Option<NativeH3DynamicReceive>,
    dynamic_send: Option<NativeH3DynamicSend>,
    incoming: BTreeMap<StreamId, IncomingStream>,
    terminal_streams: TerminalStreamTracker,
    events: VecDeque<NativeH3Event>,
    initialized: bool,
    closing: bool,
    next_local_request_stream_id: u64,
    streaming_receive: Option<StreamingReceive>,
    /// Malformed or incomplete requests already reported, whose RESET_STREAM
    /// and STOP_SENDING (with the error code) are still to be queued on the
    /// connection.
    rejected_requests: Vec<(StreamId, u64)>,
    request_writers: BTreeMap<StreamId, Arc<RequestWriteOwner>>,
    request_writer_wake: Arc<RequestWriterWake>,
}

impl NativeH3Session {
    /// Construct a client session using the static-QPACK profile.
    #[must_use]
    pub fn client() -> Self {
        Self::with_config(H3ConnectionConfig::default())
    }

    /// Construct a server session using the static-QPACK profile.
    #[must_use]
    pub fn server() -> Self {
        Self::with_config(H3ConnectionConfig {
            endpoint_role: H3EndpointRole::Server,
            ..H3ConnectionConfig::default()
        })
    }

    /// Construct an established-session adapter from explicit HTTP/3 limits.
    ///
    /// Dynamic QPACK enables receive-table decoding only; outgoing field
    /// sections remain static. Initialization advertises a bounded local table
    /// and a blocked-stream limit from zero through sixteen. It also enables
    /// bounded receive with 64 KiB DATA chunks unless an explicit receive chunk
    /// was configured.
    #[must_use]
    pub fn with_config(config: H3ConnectionConfig) -> Self {
        let mut state = H3ConnectionState::with_config(config);
        // This adapter never sends MAX_PUSH_ID and refuses push streams, so a
        // push ID in a server's CANCEL_PUSH or PUSH_PROMISE is out of range.
        state.refuse_server_push();
        Self {
            role: config.endpoint_role,
            config,
            state,
            local_control: H3ControlState::new(),
            max_field_section_size: None,
            peer_max_field_section_size: Arc::new(AtomicU64::new(u64::MAX)),
            local_control_stream: None,
            dynamic_receive: None,
            dynamic_send: None,
            incoming: BTreeMap::new(),
            terminal_streams: TerminalStreamTracker::default(),
            events: VecDeque::new(),
            initialized: false,
            closing: false,
            next_local_request_stream_id: 0,
            streaming_receive: None,
            rejected_requests: Vec::new(),
            request_writers: BTreeMap::new(),
            request_writer_wake: Arc::new(RequestWriterWake::default()),
        }
    }

    /// Enable bounded dynamic compression of outgoing initial/final HEADERS.
    ///
    /// Configure this before initialization. The active table is at most
    /// `capacity` (maximum 64 KiB) and the peer's advertised allowance. Until
    /// peer SETTINGS arrive, all fields remain static/literal. Only `accept`,
    /// `accept-encoding`, `content-type`, `content-encoding`, `cache-control`
    /// and `vary` are inserted; all other fields remain outside the table.
    /// Entries are referenced only after peer acknowledgment, including when
    /// the peer allows zero blocked streams. Table and reference pressure
    /// fall back to literals. Trailers remain statically encoded.
    ///
    /// Continue driving session events and QUIC while sending: encoder bytes
    /// wait for stream admission and byte credit, and decoder feedback enables
    /// reuse. The session retains at most 64 KiB of encoder instruction bytes
    /// and 4096 prepared or outstanding dynamic field sections. Unsent writers
    /// release their prepared references when dropped; exposed references stay
    /// protected until the peer acknowledges or cancels the section.
    pub fn enable_dynamic_qpack_encoder(
        &mut self,
        capacity: NonZeroUsize,
    ) -> Result<(), NativeH3SessionError> {
        if self.initialized {
            return Err(NativeH3SessionError::InvalidState(
                "dynamic QPACK encoding must be configured before initialization",
            ));
        }
        if capacity.get() > NATIVE_H3_MAX_QPACK_ENCODER_CAPACITY {
            return Err(NativeH3SessionError::InvalidState(
                "native QPACK encoder capacity exceeds 64 KiB",
            ));
        }
        self.dynamic_send = Some(NativeH3DynamicSend::new(capacity.get()));
        Ok(())
    }

    /// Enable bounded DATA delivery before initializing this session.
    ///
    /// Each native stream read and each emitted DATA event is bounded by
    /// `max_chunk_bytes`. DATA can be delivered before the rest of its wire
    /// frame arrives. HEADERS and other non-DATA frames retain the configured
    /// `max_frame_payload_size` bound, and every DATA frame's declared length
    /// is checked against that same limit before any payload is emitted.
    ///
    /// The session emits at most one application event per decoding step.
    /// After observing HEADERS or DATA, callers can pause that request stream
    /// while their bounded consumer is full. Pausing leaves further bytes in
    /// QUIC, so receive credit grows only for bytes actually read; the parser
    /// may retain at most one read's lookahead beyond an emitted event.
    ///
    /// This changes DATA event boundaries only for this explicit opt-in. The
    /// default session continues to deliver complete DATA frames. Framing
    /// validation remains session-owned; application message rules such as
    /// Content-Length and request-body policy remain the caller's obligation.
    pub fn enable_streaming_receive(
        &mut self,
        max_chunk_bytes: NonZeroUsize,
    ) -> Result<(), NativeH3SessionError> {
        if self.initialized {
            return Err(NativeH3SessionError::InvalidState(
                "streaming receive must be configured before initialization",
            ));
        }
        self.streaming_receive = Some(StreamingReceive {
            max_chunk_bytes,
            ready: BTreeMap::new(),
            paused: BTreeSet::new(),
            poll_after: None,
            waker: None,
        });
        Ok(())
    }

    /// Pause one decoded request/response stream without pausing its peers.
    ///
    /// Call after its initial HEADERS event. Further DATA, trailers and FIN
    /// wait for [`Self::resume_request_stream`]. A peer reset or local receive
    /// stop is still processed while paused. Critical control/QPACK streams
    /// cannot be paused through this API.
    pub fn pause_request_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        if !self.incoming.get(&stream_id).is_some_and(|stream| {
            stream.kind == IncomingStreamKind::RequestResponse && stream.header_blocks_seen > 0
        }) {
            return Err(NativeH3SessionError::InvalidState(
                "only an active decoded request stream can be paused",
            ));
        }
        let streaming =
            self.streaming_receive
                .as_mut()
                .ok_or(NativeH3SessionError::InvalidState(
                    "streaming receive is not enabled",
                ))?;
        streaming.paused.insert(stream_id);
        Ok(())
    }

    /// Resume a paused stream and wake the event consumer without a new packet.
    ///
    /// Returns whether the stream was paused. Resuming a stream already reset
    /// or finished is a harmless no-op. Buffered readiness and a deferred FIN
    /// remain owned by the session while the stream is paused.
    pub fn resume_request_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<bool, NativeH3SessionError> {
        let streaming =
            self.streaming_receive
                .as_mut()
                .ok_or(NativeH3SessionError::InvalidState(
                    "streaming receive is not enabled",
                ))?;
        let resumed = streaming.paused.remove(&stream_id);
        if resumed && let Some(waker) = streaming.waker.take() {
            waker.wake();
        }
        Ok(resumed)
    }

    /// Open the mandatory local control stream and queue SETTINGS first.
    ///
    /// A supplied `max_field_section_size` also limits each received initial
    /// request, informational/final response, and trailer section independently.
    /// The uncompressed size counts every name and value byte plus 32 bytes
    /// per occurrence, including pseudo-headers and duplicate fields.
    /// Oversized sections reset only their stream with `H3_EXCESSIVE_LOAD`
    /// before a header event is published; no peer FIN is required. In static
    /// mode, `None` keeps existing decoder/frame limits without this extra cap.
    ///
    /// Static receive checks this admission limit after expansion. Dynamic
    /// receive checks resolved lengths before cloning table entries and clamps
    /// the advertised/local limit to 1 MiB. Encoded frames, literal plans,
    /// Huffman workspace and QUIC reassembly retain their own limits.
    ///
    /// When dynamic QPACK is enabled in the connection config, an omitted
    /// receive-table capacity defaults to 4096 bytes. Values above 64 KiB or
    /// blocked-stream limits above sixteen are rejected before opening the
    /// control stream. An omitted blocked-stream limit remains zero. Positive
    /// limits permit HEADERS to wait for encoder instructions while unrelated
    /// requests progress. Their aggregate encoded payload is limited to 1 MiB,
    /// retained once by the parser and once by the scheduler; exceeding this
    /// local budget refuses only the new stream with `H3_EXCESSIVE_LOAD`.
    /// Incomplete frames and parser lookahead retain their configured limits.
    /// The local decoder stream is opened lazily when feedback exists. If the
    /// peer has not granted another unidirectional stream, feedback remains
    /// owned until a MAX_STREAMS grant; polling registers a transport wake.
    /// Dynamic receive always uses the bounded per-event receive engine, with
    /// 64 KiB DATA chunks by default; an explicit streaming chunk is preserved.
    /// This prevents a burst of compressed informational HEADERS from expanding
    /// into an unbounded queue of application events before the caller can run.
    pub fn initialize(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        mut settings: H3Settings,
    ) -> Result<StreamId, NativeH3SessionError> {
        self.ensure_transport_role(connection)?;
        if self.initialized {
            return Err(NativeH3SessionError::InvalidState(
                "session is already initialized",
            ));
        }

        let max_field_section_size = settings.max_field_section_size;
        if max_field_section_size.is_some_and(|limit| limit > QUIC_VARINT_MAX) {
            // Refuse an unencodable local limit before consuming a control
            // stream or sealing local SETTINGS, so the caller can correct it.
            return Err(H3NativeError::InvalidSettingValue(
                super::h3_native::H3_SETTING_MAX_FIELD_SECTION_SIZE,
            )
            .into());
        }

        let dynamic_receive = if self.config.qpack_mode == H3QpackMode::DynamicTableAllowed {
            let blocked_streams = settings.qpack_blocked_streams.unwrap_or(0);
            if blocked_streams > NATIVE_H3_MAX_QPACK_BLOCKED_STREAMS {
                return Err(NativeH3SessionError::InvalidState(
                    "native QPACK blocked stream limit exceeds sixteen",
                ));
            }
            let capacity = settings.qpack_max_table_capacity
                .unwrap_or(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            if capacity > NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64 {
                return Err(NativeH3SessionError::InvalidState(
                    "native QPACK decoder capacity exceeds 64 KiB",
                ));
            }
            settings.qpack_max_table_capacity = Some(capacity);
            settings.qpack_blocked_streams = Some(blocked_streams);
            settings.max_field_section_size = Some(
                settings.max_field_section_size
                    .unwrap_or(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE)
                    .min(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE),
            );
            Some(NativeH3DynamicReceive::new(&settings)?)
        } else {
            // Peer capacity remains permission our static encoder declines.
            settings.qpack_max_table_capacity = settings.qpack_max_table_capacity.map(|_| 0);
            settings.qpack_blocked_streams = settings.qpack_blocked_streams.map(|_| 0);
            None
        };
        let max_field_section_size = settings.max_field_section_size;

        let control_stream = connection.open_uni_stream(cx)?;
        let settings_frame = self.local_control.build_local_settings(settings)?;
        let mut wire = Vec::new();
        encode_varint(H3_CONTROL_STREAM_TYPE, &mut wire)
            .map_err(|_| H3NativeError::InvalidFrame("control stream type out of range"))?;
        settings_frame.encode(&mut wire)?;
        connection.write_stream(cx, control_stream, Bytes::from(wire), false)?;
        self.local_control_stream = Some(control_stream);
        self.dynamic_receive = dynamic_receive;
        self.max_field_section_size = max_field_section_size;
        if self.dynamic_receive.is_some() && self.streaming_receive.is_none() {
            self.enable_streaming_receive(
                NonZeroUsize::new(NATIVE_H3_DYNAMIC_RECEIVE_CHUNK_BYTES)
                    .expect("dynamic receive chunk is non-zero"),
            )?;
        }
        self.initialized = true;
        Ok(control_stream)
    }

    /// Queue one complete request on a new client-initiated bidirectional stream.
    ///
    /// The request is written in one piece, so it must fit both the peer's
    /// initial window for a stream this endpoint opens and the connection's
    /// remaining send credit. A larger request fails with the flow-control
    /// error and opens no stream. The peer's advertised uncompressed field
    /// section limit is checked before encoding or opening a stream.
    pub fn send_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        head: &H3RequestHead,
        body: Bytes,
    ) -> Result<StreamId, NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        self.reap_request_writers(cx, connection)?;
        if self.role != H3EndpointRole::Client {
            return Err(NativeH3SessionError::InvalidState(
                "only a client session can send requests",
            ));
        }
        if self.closing {
            return Err(NativeH3SessionError::InvalidState(
                "session is closing and rejects new requests",
            ));
        }
        if self
            .state
            .goaway_id()
            .is_some_and(|goaway_id| self.next_local_request_stream_id >= goaway_id)
        {
            return Err(NativeH3SessionError::InvalidState(
                "peer GOAWAY rejects the next request stream",
            ));
        }

        self.ensure_peer_request_field_limit(head)?;
        let (field_section, mut qpack_section) = self.prepare_request_head(
            StreamId(self.next_local_request_stream_id), head,
        )?;
        let mut wire = Vec::new();
        H3Frame::Headers(field_section).encode(&mut wire)?;
        encode_body_frames(&body, self.config.max_frame_payload_size, &mut wire)?;
        // The request goes out in one write, which takes all of it or none.
        // Refuse one that a new stream's credit cannot take, with the error
        // that write would give, before opening a stream it would leave open.
        let streams = connection.inner().streams();
        let attempted = wire.len() as u64;
        for remaining in [
            streams.initial_send_windows().local_bidi,
            streams.connection_send_remaining(),
        ] {
            if attempted > remaining {
                return Err(NativeH3SessionError::Transport(
                    NativeQuicConnectionError::Stream(QuicStreamError::Flow(
                        FlowControlError::Exhausted {
                            attempted,
                            remaining,
                        },
                    )),
                ));
            }
        }

        let stream_id = connection.open_bidi_stream(cx)?;
        if stream_id.0 != self.next_local_request_stream_id {
            return Err(NativeH3SessionError::InvalidState(
                "QUIC request stream allocation was shared outside the HTTP/3 session",
            ));
        }
        self.next_local_request_stream_id = self.next_local_request_stream_id.saturating_add(4);
        write_prepared_head(&mut qpack_section, cx, connection, stream_id, Bytes::from(wire), true)?;
        Ok(stream_id)
    }

    /// Open a request whose body can exceed the peer's initial send credit.
    ///
    /// The head is validated and bounded before opening a QUIC stream. The
    /// returned writer retains HEADERS until it is polled, then accepts one
    /// bounded DATA frame at a time. `end_stream` queues FIN with HEADERS for
    /// requests with no body. Otherwise the caller must eventually flush
    /// `finish` or trailers. Both kinds of frame can be fragmented across
    /// multiple stream/connection credit updates.
    ///
    /// This session retains cancellation ownership for unfinished writers.
    /// At most 4096 writers may be live at once, further bounded by an
    /// explicitly configured `max_concurrent_request_streams` and QUIC's own
    /// stream admission. Finished/cancelled writers are reaped on the next
    /// session event poll or request start. Dropping a writer before FIN
    /// schedules RESET_STREAM and STOP_SENDING; continue driving the session
    /// and transport to transmit them.
    pub fn start_request_writer(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        head: &H3RequestHead,
        end_stream: bool,
    ) -> Result<NativeH3RequestWriter, NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        self.reap_request_writers(cx, connection)?;
        if self.role != H3EndpointRole::Client {
            return Err(NativeH3SessionError::InvalidState(
                "only a client session can send requests",
            ));
        }
        if self.closing {
            return Err(NativeH3SessionError::InvalidState(
                "session is closing and rejects new requests",
            ));
        }
        if self
            .state
            .goaway_id()
            .is_some_and(|goaway_id| self.next_local_request_stream_id >= goaway_id)
        {
            return Err(NativeH3SessionError::InvalidState(
                "peer GOAWAY rejects the next request stream",
            ));
        }
        let limit = self
            .config
            .max_concurrent_request_streams
            .map_or(MAX_REQUEST_WRITERS, |limit| {
                usize::try_from(limit)
                    .unwrap_or(usize::MAX)
                    .min(MAX_REQUEST_WRITERS)
            });
        if self.request_writers.len() >= limit {
            return Err(NativeH3SessionError::InvalidState(
                "incremental request writer limit reached",
            ));
        }
        self.ensure_peer_request_field_limit(head)?;
        let (field_section, qpack_section) = self.prepare_request_head(
            StreamId(self.next_local_request_stream_id), head,
        )?;
        if field_section.len() > self.config.max_frame_payload_size {
            return Err(NativeH3SessionError::Protocol(
                H3NativeError::FrameTooLarge {
                    payload_size: field_section.len(),
                    max_size: self.config.max_frame_payload_size,
                },
            ));
        }
        let wire = encode_frame(H3Frame::Headers(field_section))?;
        let stream_id = connection.open_bidi_stream(cx)?;
        if stream_id.0 != self.next_local_request_stream_id {
            // A caller shared this session's stream allocator. Refuse that
            // composition without orphaning the stream we just opened.
            cx.masked(|| {
                connection.reset_stream(cx, stream_id, H3_REQUEST_CANCELLED)?;
                connection.stop_stream_receiving(cx, stream_id, H3_REQUEST_CANCELLED)?;
                Ok::<(), NativeH3SessionError>(())
            })?;
            return Err(NativeH3SessionError::InvalidState(
                "QUIC request stream allocation was shared outside the HTTP/3 session",
            ));
        }
        self.next_local_request_stream_id = self.next_local_request_stream_id.saturating_add(4);
        let owner = Arc::new(RequestWriteOwner::new(Arc::clone(&self.request_writer_wake)));
        self.request_writers.insert(stream_id, Arc::clone(&owner));
        Ok(NativeH3RequestWriter {
            inner: NativeH3ResponseWriter {
                stream_id,
                phase: NativeH3ResponsePhase::HeadPending,
                pending: Some(NativeH3PendingWrite {
                    wire,
                    fin: end_stream,
                    event: NativeH3WriteEvent::Head { end_stream },
                    next_phase: if end_stream {
                        NativeH3ResponsePhase::Finished
                    } else {
                        NativeH3ResponsePhase::Open
                    },
                    qpack_section,
                }),
                max_frame_payload_size: self.config.max_frame_payload_size,
                peer_max_field_section_size: Arc::clone(&self.peer_max_field_section_size),
            },
            owner,
            write_offset: 0,
        })
    }

    fn reap_request_writers(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3SessionError> {
        let retired: Vec<_> = self
            .request_writers
            .iter()
            .filter_map(|(&stream, owner)| {
                (owner.state() != RequestWriterState::Active).then_some(stream)
            })
            .collect();
        for stream in retired {
            if self.request_writers[&stream].state() == RequestWriterState::Abandoned {
                // Only the two bounded cleanup controls are masked. A caller
                // using the cancelled upload's Cx must still release its
                // protocol ownership before the next checkpoint can fail.
                cx.masked(|| self.reset_request(cx, connection, stream, H3_REQUEST_CANCELLED))?;
            }
            self.request_writers.remove(&stream);
        }
        Ok(())
    }

    /// Queue one informational response without closing the response stream.
    pub fn send_informational_response(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        head: &H3ResponseHead,
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if self.role != H3EndpointRole::Server {
            return Err(NativeH3SessionError::InvalidState(
                "only a server session can send responses",
            ));
        }
        if !is_client_bidi(stream_id) {
            return Err(NativeH3SessionError::InvalidState(
                "responses require a client-initiated bidirectional stream",
            ));
        }
        if !(100..200).contains(&head.status) {
            return Err(NativeH3SessionError::InvalidState(
                "informational response status must be in 100..200",
            ));
        }

        self.ensure_peer_response_field_limit(head)?;
        let (field_section, mut qpack_section) = self.prepare_response_head(stream_id, head)?;
        let mut wire = Vec::new();
        H3Frame::Headers(field_section).encode(&mut wire)?;
        write_prepared_head(&mut qpack_section, cx, connection, stream_id, Bytes::from(wire), false)?;
        Ok(())
    }

    /// Prepare an incremental final response writer for an existing request.
    ///
    /// The response head is fully validated and encoded before this returns,
    /// but no QUIC state is mutated until the caller polls the writer. Setting
    /// `end_stream` is intended for HEAD/body-forbidden responses: FIN is
    /// attached to the last HEADERS fragment and no DATA producer is started.
    pub(crate) fn start_response_writer(
        &self,
        connection: &QuicConnection,
        stream_id: StreamId,
        head: &H3ResponseHead,
        end_stream: bool,
    ) -> Result<NativeH3ResponseWriter, NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if self.role != H3EndpointRole::Server {
            return Err(NativeH3SessionError::InvalidState(
                "only a server session can send responses",
            ));
        }
        if !is_client_bidi(stream_id) {
            return Err(NativeH3SessionError::InvalidState(
                "responses require a client-initiated bidirectional stream",
            ));
        }
        if (100..200).contains(&head.status) {
            return Err(NativeH3SessionError::InvalidState(
                "informational responses require send_informational_response",
            ));
        }

        self.ensure_peer_response_field_limit(head)?;
        let (field_section, qpack_section) = self.prepare_response_head(stream_id, head)?;
        if field_section.len() > self.config.max_frame_payload_size {
            return Err(NativeH3SessionError::Protocol(
                H3NativeError::FrameTooLarge {
                    payload_size: field_section.len(),
                    max_size: self.config.max_frame_payload_size,
                },
            ));
        }
        let next_phase = if end_stream {
            NativeH3ResponsePhase::Finished
        } else {
            NativeH3ResponsePhase::Open
        };
        Ok(NativeH3ResponseWriter {
            stream_id,
            phase: NativeH3ResponsePhase::HeadPending,
            pending: Some(NativeH3PendingWrite {
                wire: encode_frame(H3Frame::Headers(field_section))?,
                fin: end_stream,
                event: NativeH3WriteEvent::Head { end_stream },
                next_phase,
                qpack_section,
            }),
            max_frame_payload_size: self.config.max_frame_payload_size,
            peer_max_field_section_size: Arc::clone(&self.peer_max_field_section_size),
        })
    }

    /// Queue one complete final response on an existing request stream.
    ///
    /// The response is written in one piece, so it must fit the stream's and
    /// the connection's remaining send credit; a larger one fails with the
    /// flow-control error and writes nothing. The peer's advertised field
    /// section limit is checked independently before any response bytes queue.
    pub fn send_response(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        head: &H3ResponseHead,
        body: Bytes,
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if self.role != H3EndpointRole::Server {
            return Err(NativeH3SessionError::InvalidState(
                "only a server session can send responses",
            ));
        }
        if !is_client_bidi(stream_id) {
            return Err(NativeH3SessionError::InvalidState(
                "responses require a client-initiated bidirectional stream",
            ));
        }
        if (100..200).contains(&head.status) {
            return Err(NativeH3SessionError::InvalidState(
                "informational responses require send_informational_response",
            ));
        }

        self.ensure_peer_response_field_limit(head)?;
        let (field_section, mut qpack_section) = self.prepare_response_head(stream_id, head)?;
        let mut wire = Vec::new();
        H3Frame::Headers(field_section).encode(&mut wire)?;
        encode_body_frames(&body, self.config.max_frame_payload_size, &mut wire)?;
        write_prepared_head(&mut qpack_section, cx, connection, stream_id, Bytes::from(wire), true)?;
        Ok(())
    }

    fn prepare_request_head(
        &self,
        stream_id: StreamId,
        head: &H3RequestHead,
    ) -> Result<(Vec<u8>, Option<PreparedQpackSection>), NativeH3SessionError> {
        match &self.dynamic_send {
            Some(sender) => sender.prepare(stream_id, qpack_static_plan_for_request(head)).map_err(Into::into),
            None => Ok((qpack_encode_request_field_section(head)?, None)),
        }
    }

    fn prepare_response_head(
        &self,
        stream_id: StreamId,
        head: &H3ResponseHead,
    ) -> Result<(Vec<u8>, Option<PreparedQpackSection>), NativeH3SessionError> {
        match &self.dynamic_send {
            Some(sender) => sender.prepare(stream_id, qpack_static_plan_for_response(head)).map_err(Into::into),
            None => Ok((qpack_encode_response_field_section(head)?, None)),
        }
    }

    /// Queue `H3_REQUEST_CANCELLED` for one request stream.
    pub fn cancel_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        self.reset_request(cx, connection, stream_id, H3_REQUEST_CANCELLED)
    }

    /// Reset a request stream in both directions with `error_code`, for
    /// callers that must say more than [`H3_REQUEST_CANCELLED`]: for example
    /// [`H3_REQUEST_REJECTED`] for a request no handler has seen.
    pub(crate) fn reset_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if !is_client_bidi(stream_id) {
            return Err(NativeH3SessionError::InvalidState(
                "request cancellation requires a client bidirectional stream",
            ));
        }
        if let Some(owner) = self.request_writers.get(&stream_id) {
            owner.abandon();
        }
        connection.reset_stream(cx, stream_id, error_code)?;
        connection.stop_stream_receiving(cx, stream_id, error_code)?;
        self.cancel_received_qpack_stream(stream_id)?;
        if self.terminal_streams.contains(stream_id) {
            // A reset after peer FIN has no remaining receive-stop edge to
            // retire history; the terminal tracker already prevents reuse.
            self.retire_received_qpack_stream(stream_id)?;
        }
        if let Some(owner) = self.request_writers.get(&stream_id) {
            owner.cancel();
        }
        self.drive_qpack_streams(cx, connection, None)?;
        Ok(())
    }

    /// Queue a role-appropriate GOAWAY on the local control stream.
    ///
    /// The caller must continue driving QUIC until the control bytes are
    /// flushed before beginning transport close.
    pub fn graceful_close(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        goaway_id: u64,
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if self.closing {
            return Ok(());
        }
        if self.role == H3EndpointRole::Server && !is_client_bidi(StreamId(goaway_id)) {
            return Err(NativeH3SessionError::InvalidState(
                "server GOAWAY requires a client-initiated bidirectional stream id",
            ));
        }
        let control_stream =
            self.local_control_stream
                .ok_or(NativeH3SessionError::InvalidState(
                    "local control stream is unavailable",
                ))?;
        let mut wire = Vec::new();
        H3Frame::Goaway(goaway_id).encode(&mut wire)?;
        connection.write_stream(cx, control_stream, Bytes::from(wire), false)?;
        self.closing = true;
        Ok(())
    }

    /// Consume one already-buffered or immediately-readable event.
    ///
    /// In streaming mode this synchronous method may perform several bounded
    /// reads to complete a non-DATA frame. Async drivers should use
    /// [`Self::poll_event`], which also bounds decoding steps per poll and
    /// arranges a wake when buffered work needs another turn.
    pub fn next_event(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<Option<NativeH3Event>, NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        self.reap_request_writers(cx, connection)?;
        if self.streaming_receive.is_some() {
            loop {
                self.drive_qpack_streams(cx, connection, None)?;
                if let Some(event) = self.events.pop_front() {
                    return Ok(Some(event));
                }
                if !self.drive_streaming_receive(cx, connection)? {
                    return Ok(None);
                }
            }
        }
        loop {
            self.drive_qpack_streams(cx, connection, None)?;
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            let Some(readiness) = connection.next_readable_stream(cx)? else {
                return Ok(None);
            };
            self.process_readiness(cx, connection, readiness)?;
        }
    }

    /// Poll for one decoded event without busy-polling.
    pub fn poll_event(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<NativeH3Event, NativeH3SessionError>> {
        if let Err(error) = self.ensure_ready_for_messages(connection) {
            return Poll::Ready(Err(error));
        }
        // Register before reaping so a concurrent writer drop cannot leave
        // this event consumer parked without a receive-side transport edge.
        if !self.request_writers.is_empty() {
            self.request_writer_wake.register(task_cx);
            if let Err(error) = self.reap_request_writers(cx, connection) {
                return Poll::Ready(Err(error));
            }
        }
        if self.streaming_receive.is_some() {
            return self.poll_streaming_event(cx, connection, task_cx);
        }
        loop {
            if let Err(error) = self.drive_qpack_streams(cx, connection, Some(task_cx)) {
                return Poll::Ready(Err(error));
            }
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(Ok(event));
            }
            let readiness = match connection.poll_next_readable_stream(cx, task_cx) {
                Poll::Ready(Ok(readiness)) => readiness,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(NativeH3SessionError::Transport(error)));
                }
                Poll::Pending => return Poll::Pending,
            };
            if let Err(error) = self.process_readiness(cx, connection, readiness) {
                return Poll::Ready(Err(error));
            }
        }
    }

    fn poll_streaming_event(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<NativeH3Event, NativeH3SessionError>> {
        let streaming = self.streaming_receive.as_mut().expect("streaming enabled");
        if streaming
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task_cx.waker()))
        {
            streaming.waker = Some(task_cx.waker().clone());
        }
        // Large non-DATA frames and streams that only carry ignored bytes
        // must yield as well. Chunk size alone does not bound poll work.
        for _ in 0..STREAMING_POLL_STEPS {
            if let Err(error) = self.drive_qpack_streams(cx, connection, Some(task_cx)) {
                return Poll::Ready(Err(error));
            }
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(Ok(event));
            }
            match self.drive_streaming_receive(cx, connection) {
                Err(error) => return Poll::Ready(Err(error)),
                Ok(true) => {}
                Ok(false) => match connection.poll_next_readable_stream(cx, task_cx) {
                    Poll::Ready(Ok(readiness)) => {
                        if let Err(error) =
                            self.queue_streaming_readiness(cx, connection, readiness)
                        {
                            return Poll::Ready(Err(error));
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
        if let Err(error) = self.drive_qpack_streams(cx, connection, Some(task_cx)) {
            return Poll::Ready(Err(error));
        }
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        task_cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn drive_qpack_streams(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        mut task_cx: Option<&mut TaskContext<'_>>,
    ) -> Result<(), NativeH3SessionError> {
        self.drive_qpack_feedback(cx, connection, task_cx.as_deref_mut())?;
        if let Some(sender) = &self.dynamic_send {
            sender.drive(cx, connection, task_cx)?;
        }
        Ok(())
    }

    /// Queue at most one retained feedback prefix, independently of application
    /// events. Async callers register for stream-count credit, byte credit and
    /// queue drain; synchronous callers leave feedback owned for their next drive.
    fn drive_qpack_feedback(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        mut task_cx: Option<&mut TaskContext<'_>>,
    ) -> Result<(), NativeH3SessionError> {
        let Some(dynamic) = &mut self.dynamic_receive else {
            return Ok(());
        };
        dynamic.check_live()?;
        let stream_id = match dynamic.decoder_stream {
            Some(stream_id) => stream_id,
            None if dynamic.feedback.is_empty() => return Ok(()),
            None => {
                // Retain the stream type and every instruction while waiting
                // for admission. Pending never consumes a stream ID, and only
                // a successful open commits this decoder stream's identity.
                let stream_id = if let Some(task_cx) = task_cx.as_deref_mut() {
                    match connection.poll_open_uni_stream(cx, task_cx) {
                        Poll::Ready(result) => result?,
                        Poll::Pending => return Ok(()),
                    }
                } else {
                    match connection.open_uni_stream(cx) {
                        Ok(stream_id) => stream_id,
                        Err(NativeQuicConnectionError::StreamTable(
                            StreamTableError::StreamLimitExceeded {
                                direction: StreamDirection::Unidirectional,
                                limit,
                            },
                        )) if limit < (1u64 << 60) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                };
                dynamic.decoder_stream = Some(stream_id);
                stream_id
            }
        };
        // A stopped critical send stream remains an error even after its last
        // feedback byte was queued. Async consumers also retain a real terminal
        // send waiter so STOP_SENDING wakes them without another readable stream.
        if connection.inner().streams().stream(stream_id).is_ok_and(|stream| {
            stream.stop_sending_error_code.is_some()
                || stream.send_reset.is_some()
                || stream.send_final_size.is_some()
        }) {
            return Err(NativeH3SessionError::CriticalStreamClosed {
                stream_id,
                stream_type: H3UniStreamType::QpackDecoder,
            });
        }
        if let Some(task_cx) = task_cx.as_deref_mut() {
            match connection.inner_mut().poll_stream_send_closed(cx, stream_id, task_cx) {
                Poll::Ready(Ok(())) => {
                    return Err(NativeH3SessionError::CriticalStreamClosed {
                        stream_id,
                        stream_type: H3UniStreamType::QpackDecoder,
                    });
                }
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Pending => {}
            }
        }
        if dynamic.feedback.is_empty() {
            return Ok(());
        }
        let capacity = if let Some(task_cx) = task_cx.as_deref_mut() {
            match connection.poll_stream_write_ready(cx, stream_id, 1, task_cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Ok(()),
            }
        } else {
            if connection.has_pending_stream_frames(stream_id) {
                return Ok(());
            }
            connection.inner().stream_send_credit_remaining(stream_id)
                .min(connection.inner().streams().connection_send_remaining())
        };
        let count = dynamic.feedback.len()
            .min(usize::try_from(capacity).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(());
        }
        let wire: Vec<u8> = dynamic.feedback.iter().take(count).copied().collect();
        connection.write_stream(cx, stream_id, Bytes::from(wire), false)?;
        dynamic.feedback.drain(..count);
        if !dynamic.feedback.is_empty()
            && let Some(task_cx) = task_cx
        {
            // Register immediately after partial progress. An encoder-only
            // input creates no H3 event, so a later MAX_DATA/queue-drain edge
            // must wake this consumer without another readable stream.
            match connection.poll_stream_write_ready(cx, stream_id, 1, task_cx) {
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(_)) => task_cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        Ok(())
    }

    fn cancel_received_qpack_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        if let Some(dynamic) = &mut self.dynamic_receive {
            dynamic.cancel_stream(stream_id)?;
        }
        Ok(())
    }

    fn retire_received_qpack_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        debug_assert!(self.terminal_streams.contains(stream_id));
        if let Some(dynamic) = &mut self.dynamic_receive {
            dynamic.qpack.retire_received_stream_history(stream_id.0)?;
        }
        Ok(())
    }

    fn queue_streaming_readiness(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        readiness: StreamReadiness,
    ) -> Result<(), NativeH3SessionError> {
        self.terminal_streams.ensure_healthy()?;
        if readiness.reset.is_some() || readiness.receive_stopped.is_some() {
            // Terminal transport edges bypass paused streams. Processing the
            // real readiness edge also preserves QUIC's exactly-once reset
            // notification, including a reset following a delivered FIN.
            return self.process_readiness(cx, connection, readiness);
        }
        if !self.terminal_streams.contains(readiness.stream_id) {
            self.streaming_receive
                .as_mut()
                .expect("streaming enabled")
                .ready
                .insert(readiness.stream_id, readiness);
        }
        Ok(())
    }

    fn drive_streaming_receive(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<bool, NativeH3SessionError> {
        let mut progress = false;
        // Capture edges before reading. Partial QUIC reads requeue their
        // stream; a private deduplicated map both preserves paused edges and
        // lets higher stream IDs progress alongside a continually readable
        // low stream ID.
        for _ in 0..STREAMING_READINESS_BATCH {
            let Some(readiness) = connection.next_readable_stream(cx)? else {
                break;
            };
            progress = true;
            self.queue_streaming_readiness(cx, connection, readiness)?;
            if !self.events.is_empty() {
                return Ok(true);
            }
        }

        let streaming = self.streaming_receive.as_ref().expect("streaming enabled");
        let mut first = None;
        let mut next = None;
        for id in streaming.ready.keys() {
            if streaming.paused.contains(id)
                || self.dynamic_receive.as_ref().is_some_and(|dynamic| dynamic.is_blocked(*id))
                || !connection
                    .inner()
                    .streams()
                    .stream(*id)
                    .is_ok_and(|stream| {
                        // A fresh reset may be deeper in QUIC's readiness queue.
                        // Never read through its sticky state using a cached old
                        // edge; wait to consume the real terminal notification.
                        stream.recv_reset.is_none() && stream.receive_stopped_error_code.is_none()
                    })
            {
                continue;
            }
            first.get_or_insert(*id);
            if streaming.poll_after.is_none_or(|after| *id > after) {
                next = Some(*id);
                break;
            }
        }
        let Some(stream_id) = next.or(first) else {
            return Ok(progress);
        };
        let streaming = self.streaming_receive.as_mut().expect("streaming enabled");
        let mut readiness = streaming
            .ready
            .remove(&stream_id)
            .expect("ready stream selected");
        streaming.poll_after = Some(stream_id);
        let max_read = streaming.max_chunk_bytes.get();

        self.incoming
            .entry(stream_id)
            .or_insert_with(|| IncomingStream::new(stream_id));
        // Consume parser lookahead before reading more transport bytes. This
        // prevents each small frame from adding another read of lookahead.
        self.decode_stream(stream_id)?;
        if self.dynamic_receive.as_ref().is_some_and(|dynamic| dynamic.is_blocked(stream_id)) {
            // Keep even an exhausted transport edge: this complete HEADERS
            // frame and an already received FIN become runnable on encoder
            // progress, without another packet on the request stream.
            self.streaming_receive
                .as_mut()
                .expect("streaming enabled")
                .ready
                .insert(stream_id, readiness);
            return Ok(true);
        }
        if self.events.is_empty() && readiness.readable_bytes > 0 {
            let limit = usize::try_from(readiness.readable_bytes)
                .unwrap_or(usize::MAX)
                .min(max_read);
            let bytes = connection.read_stream(cx, stream_id, limit)?;
            readiness.readable_bytes = if bytes.is_empty() {
                0
            } else {
                readiness.readable_bytes.saturating_sub(bytes.len() as u64)
            };
            self.incoming
                .get_mut(&stream_id)
                .expect("stream inserted above")
                .bytes
                .extend_from_slice(&bytes);
            self.decode_stream(stream_id)?;
        }
        if self.reset_rejected_requests(cx, connection)? {
            return Ok(true);
        }
        if self.dynamic_receive.as_ref().is_some_and(|dynamic| dynamic.is_blocked(stream_id)) {
            self.streaming_receive
                .as_mut()
                .expect("streaming enabled")
                .ready
                .insert(stream_id, readiness);
            return Ok(true);
        }

        let emitted = !self.events.is_empty();
        let eof = readiness.fin_received && connection.is_stream_eof(stream_id)?;
        if !emitted && eof {
            // A partial DATA cursor, even with no buffered payload bytes,
            // is truncation. FIN is never inferred from Content-Length or an
            // empty read and never overtakes a preceding application event.
            self.finish_stream(stream_id)?;
            self.reset_rejected_requests(cx, connection)?;
            return Ok(true);
        }
        let has_lookahead = !self
            .incoming
            .get(&stream_id)
            .expect("stream exists")
            .bytes
            .is_empty();
        if readiness.readable_bytes > 0 || (emitted && (has_lookahead || eof)) {
            self.streaming_receive
                .as_mut()
                .expect("streaming enabled")
                .ready
                .insert(stream_id, readiness);
        }
        Ok(true)
    }

    fn forget_streaming_readiness(&mut self, stream_id: StreamId) {
        if let Some(streaming) = &mut self.streaming_receive {
            streaming.ready.remove(&stream_id);
            streaming.paused.remove(&stream_id);
        }
    }

    fn process_readiness(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        readiness: StreamReadiness,
    ) -> Result<(), NativeH3SessionError> {
        let stream_id = readiness.stream_id;
        self.terminal_streams.ensure_healthy()?;
        if self.terminal_streams.contains(stream_id)
            && !(readiness.reset.is_some() && is_client_bidi(stream_id))
        {
            return Ok(());
        }
        // Request FIN completes only the peer's sending direction. A later
        // reset still cancels an in-flight handler or response on this stream.
        // QUIC exposes that reset exactly once, including when duplicate
        // transport frames arrive after its terminal receive notification.
        if let Some((error_code, final_size)) = readiness.reset {
            if let Some(owner) = self.request_writers.get(&stream_id) {
                owner.abandon();
            }
            let kind = self.classify_reset_stream(connection, stream_id)?;
            match kind {
                Some(IncomingStreamKind::Control) => {
                    return Err(NativeH3SessionError::CriticalStreamClosed {
                        stream_id,
                        stream_type: H3UniStreamType::Control,
                    });
                }
                Some(IncomingStreamKind::QpackEncoder) => {
                    return Err(NativeH3SessionError::CriticalStreamClosed {
                        stream_id,
                        stream_type: H3UniStreamType::QpackEncoder,
                    });
                }
                Some(IncomingStreamKind::QpackDecoder) => {
                    return Err(NativeH3SessionError::CriticalStreamClosed {
                        stream_id,
                        stream_type: H3UniStreamType::QpackDecoder,
                    });
                }
                Some(IncomingStreamKind::RequestResponse) => {
                    self.cancel_received_qpack_stream(stream_id)?;
                    self.state.abort_request_stream(stream_id.0)?;
                }
                Some(
                    IncomingStreamKind::AwaitingUniType
                    | IncomingStreamKind::Push
                    | IncomingStreamKind::UnknownUni,
                )
                | None => {}
            }
            self.incoming.remove(&stream_id);
            self.forget_streaming_readiness(stream_id);
            self.terminal_streams.insert(stream_id)?;
            if is_client_bidi(stream_id) {
                self.retire_received_qpack_stream(stream_id)?;
            }
            self.events.push_back(NativeH3Event::StreamReset {
                stream_id,
                error_code,
                final_size,
            });
            return Ok(());
        }
        if readiness.receive_stopped.is_some() {
            if is_client_bidi(stream_id) {
                self.cancel_received_qpack_stream(stream_id)?;
                self.state.abort_request_stream(stream_id.0)?;
            }
            self.incoming.remove(&stream_id);
            self.forget_streaming_readiness(stream_id);
            self.terminal_streams.insert(stream_id)?;
            if is_client_bidi(stream_id) {
                self.retire_received_qpack_stream(stream_id)?;
            }
            return Ok(());
        }

        let incoming = self
            .incoming
            .entry(stream_id)
            .or_insert_with(|| IncomingStream::new(stream_id));
        if readiness.readable_bytes > 0 {
            let mut max_read = usize::try_from(readiness.readable_bytes).unwrap_or(usize::MAX);
            if self.dynamic_receive.is_some() {
                max_read = max_read.min(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY);
            }
            let bytes = connection.read_stream(cx, stream_id, max_read)?;
            incoming.bytes.extend_from_slice(&bytes);
        }
        self.decode_stream(stream_id)?;
        if self.reset_rejected_requests(cx, connection)? {
            return Ok(());
        }

        if readiness.fin_received && connection.is_stream_eof(stream_id)? {
            self.finish_stream(stream_id)?;
            self.reset_rejected_requests(cx, connection)?;
        }
        Ok(())
    }

    /// Reject a request (or, on a client, a response) whose field section
    /// decoded but is malformed: it ends only its own stream, with
    /// `H3_MESSAGE_ERROR`. The stream is reported as
    /// a [`NativeH3Event::StreamReset`] so owners release its per-stream
    /// state, and its later bytes are discarded.
    fn reject_malformed_request(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        self.reject_request_stream(stream_id, H3_MESSAGE_ERROR)
    }

    /// End only this request stream with `error_code`, reported as a
    /// [`NativeH3Event::StreamReset`]; the connection carries on.
    fn reject_request_stream(
        &mut self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeH3SessionError> {
        if let Some(owner) = self.request_writers.get(&stream_id) {
            owner.abandon();
        }
        self.cancel_received_qpack_stream(stream_id)?;
        self.state.abort_request_stream(stream_id.0)?;
        self.incoming.remove(&stream_id);
        self.forget_streaming_readiness(stream_id);
        self.terminal_streams.insert(stream_id)?;
        self.retire_received_qpack_stream(stream_id)?;
        self.rejected_requests.push((stream_id, error_code));
        self.events.push_back(NativeH3Event::StreamReset {
            stream_id,
            error_code,
            final_size: 0,
        });
        Ok(())
    }

    /// Queue RESET_STREAM and STOP_SENDING for every request rejected as
    /// malformed, incomplete or over the field limit. Returns true when any
    /// was rejected, so the caller stops processing a stream it no longer owns.
    fn reset_rejected_requests(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<bool, NativeH3SessionError> {
        if self.rejected_requests.is_empty() {
            return Ok(false);
        }
        for (stream_id, error_code) in std::mem::take(&mut self.rejected_requests) {
            connection.reset_stream(cx, stream_id, error_code)?;
            connection.stop_stream_receiving(cx, stream_id, error_code)?;
        }
        Ok(true)
    }

    fn classify_reset_stream(
        &mut self,
        connection: &QuicConnection,
        stream_id: StreamId,
    ) -> Result<Option<IncomingStreamKind>, NativeH3SessionError> {
        if stream_id.direction() == StreamDirection::Bidirectional {
            return Ok(Some(IncomingStreamKind::RequestResponse));
        }
        if let Some(kind) = self
            .incoming
            .get(&stream_id)
            .map(|incoming| incoming.kind.clone())
            && kind != IncomingStreamKind::AwaitingUniType
        {
            return Ok(Some(kind));
        }

        let mut prefix = self
            .incoming
            .get(&stream_id)
            .map_or_else(Vec::new, |incoming| incoming.bytes.to_vec());
        prefix.extend_from_slice(&connection.reset_stream_buffered_prefix(stream_id)?);
        let Some((stream_type, _)) = decode_prefix(&prefix)? else {
            return Ok(Some(IncomingStreamKind::AwaitingUniType));
        };
        let decoded = self
            .state
            .on_remote_uni_stream_type(stream_id.0, stream_type)?;
        Ok(Some(match decoded {
            H3UniStreamType::Control => IncomingStreamKind::Control,
            H3UniStreamType::QpackEncoder => IncomingStreamKind::QpackEncoder,
            H3UniStreamType::QpackDecoder => IncomingStreamKind::QpackDecoder,
            H3UniStreamType::Push => IncomingStreamKind::Push,
            H3UniStreamType::Unknown(_) => IncomingStreamKind::UnknownUni,
        }))
    }

    fn decode_stream(&mut self, stream_id: StreamId) -> Result<(), NativeH3SessionError> {
        loop {
            // Streaming callers can pause immediately after each event. Do
            // not decode the next DATA/trailer/FIN behind their back.
            if self.streaming_receive.is_some() && !self.events.is_empty() {
                return Ok(());
            }
            if self.dynamic_receive.as_ref().is_some_and(|dynamic| dynamic.is_blocked(stream_id)) {
                return Ok(());
            }
            let kind = self
                .incoming
                .get(&stream_id)
                .map(|stream| stream.kind.clone())
                .ok_or(NativeH3SessionError::InvalidState(
                    "incoming stream state disappeared",
                ))?;

            if kind == IncomingStreamKind::AwaitingUniType {
                let Some((stream_type, consumed)) = decode_prefix(
                    &self
                        .incoming
                        .get(&stream_id)
                        .expect("stream checked above")
                        .bytes,
                )?
                else {
                    return Ok(());
                };
                let decoded = self
                    .state
                    .on_remote_uni_stream_type(stream_id.0, stream_type)?;
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                stream.bytes.consume(consumed);
                stream.kind = match decoded {
                    H3UniStreamType::Control => IncomingStreamKind::Control,
                    H3UniStreamType::QpackEncoder => IncomingStreamKind::QpackEncoder,
                    H3UniStreamType::QpackDecoder => IncomingStreamKind::QpackDecoder,
                    H3UniStreamType::Push => IncomingStreamKind::Push,
                    H3UniStreamType::Unknown(_) => IncomingStreamKind::UnknownUni,
                };
                continue;
            }

            if kind == IncomingStreamKind::QpackEncoder
                && let Some(dynamic) = &mut self.dynamic_receive
            {
                let stream = self.incoming.get_mut(&stream_id).expect("stream checked above");
                let unblocked = dynamic.feed_instructions(&self.state, stream_id, &stream.bytes)?;
                stream.bytes.clear();
                if !unblocked.is_empty()
                    && let Some(streaming) = &mut self.streaming_receive
                    && let Some(waker) = streaming.waker.take()
                {
                    waker.wake();
                }
                return Ok(());
            }
            if kind == IncomingStreamKind::QpackEncoder {
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                while let Some(&first) = stream.bytes.first() {
                    // Only Set Dynamic Table Capacity (`001xxxxx`) is legal here.
                    // Refuse anything else on its first byte: waiting for a
                    // complete insert would buffer a peer-declared string
                    // length without bound. The capacity integer is itself
                    // bounded, so a partial one stays a few bytes long.
                    if first & 0b1110_0000 != 0b0010_0000 {
                        return Err(NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
                            "static QPACK forbids dynamic encoder instructions",
                        )));
                    }
                    match qpack_decode_encoder_instruction(&stream.bytes) {
                        Ok((
                            QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
                            n,
                        )) => {
                            stream.bytes.consume(n);
                        }
                        Ok(_) => {
                            return Err(NativeH3SessionError::Protocol(
                                H3NativeError::QpackPolicy(
                                    "static QPACK forbids dynamic encoder instructions",
                                ),
                            ));
                        }
                        Err(H3NativeError::UnexpectedEof) => return Ok(()),
                        Err(error) => return Err(NativeH3SessionError::Protocol(error)),
                    }
                }
                return Ok(());
            }
            if kind == IncomingStreamKind::QpackDecoder {
                if let Some(sender) = &self.dynamic_send {
                    let stream = self.incoming.get_mut(&stream_id).expect("stream checked above");
                    if sender.feed_decoder(&self.state, stream_id, &stream.bytes)? {
                        stream.bytes.clear();
                        return Ok(());
                    }
                }
                // A peer whose own table capacity is non-zero sends Stream
                // Cancellation whenever it resets or abandons a request stream
                // (RFC 9204 section 4.4.2), whether or not our encoder used the
                // table. The other two instructions acknowledge dynamic-table
                // state that our static encoder never creates, including in
                // dynamic receive mode. Ignore cancellations here instead of
                // retaining an unused per-stream outbound cancellation history.
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                while !stream.bytes.is_empty() {
                    match qpack_decode_decoder_instruction(&stream.bytes) {
                        Ok((QpackDecoderInstruction::StreamCancellation { .. }, n)) => {
                            stream.bytes.consume(n);
                        }
                        Ok(_) => {
                            let error = H3NativeError::QpackPolicy(
                                "static QPACK never sends dynamic-table state to acknowledge",
                            );
                            if let Some(dynamic) = &mut self.dynamic_receive {
                                return Err(dynamic.record_error(error).into());
                            }
                            return Err(error.into());
                        }
                        Err(H3NativeError::UnexpectedEof) => return Ok(()),
                        Err(error) => {
                            if let Some(dynamic) = &mut self.dynamic_receive {
                                return Err(dynamic.record_error(error).into());
                            }
                            return Err(error.into());
                        }
                    }
                }
                return Ok(());
            }
            if kind == IncomingStreamKind::UnknownUni {
                self.incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above")
                    .bytes
                    .clear();
                return Ok(());
            }
            if kind == IncomingStreamKind::Push {
                return Err(NativeH3SessionError::InvalidState(
                    "server push is not supported by the static transport adapter",
                ));
            }

            if let Some(streaming) = &self.streaming_receive
                && kind == IncomingStreamKind::RequestResponse
            {
                let max_chunk_bytes = streaming.max_chunk_bytes.get();
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                if let Some(cursor) = &mut stream.data_frame {
                    let len = cursor.take_len(stream.bytes.len(), max_chunk_bytes);
                    if len == 0 && !cursor.is_complete() {
                        return Ok(());
                    }
                    let bytes = Bytes::from(stream.bytes.take_front(len));
                    if cursor.is_complete() {
                        stream.data_frame = None;
                    }
                    self.events
                        .push_back(NativeH3Event::Data { stream_id, bytes });
                    return Ok(());
                }
                let Some(header) = frame_header(&stream.bytes, self.config.max_frame_payload_size)?
                else {
                    return Ok(());
                };
                if header.kind == 0 {
                    // Validate progression once at the wire-frame boundary,
                    // before publishing any part of its payload.
                    self.state
                        .on_request_stream_frame(stream_id.0, &H3Frame::Data(Vec::new()))?;
                    let stream = self
                        .incoming
                        .get_mut(&stream_id)
                        .expect("stream checked above");
                    stream.bytes.consume(header.header_len);
                    stream.data_frame = Some(DataFrameCursor::new(header.payload_len));
                    continue;
                }
            }

            let Some(frame_len) = complete_frame_len(
                &self
                    .incoming
                    .get(&stream_id)
                    .expect("stream checked above")
                    .bytes,
                self.config.max_frame_payload_size,
            )?
            else {
                return Ok(());
            };
            let (frame, consumed) = {
                let stream = self
                    .incoming
                    .get(&stream_id)
                    .expect("stream checked above");
                let (frame, consumed) = H3Frame::decode(&stream.bytes[..frame_len], &self.config)?;
                debug_assert_eq!(consumed, frame_len);
                (frame, consumed)
            };
            let retain_until_decoded = self.dynamic_receive.is_some()
                && kind == IncomingStreamKind::RequestResponse
                && matches!(&frame, H3Frame::Headers(_));
            if !retain_until_decoded {
                self.incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above")
                    .bytes
                    .consume(consumed);
            }
            self.on_frame(stream_id, kind, frame)?;
            if !self.incoming.contains_key(&stream_id) {
                // The frame rejected this stream as a malformed request.
                return Ok(());
            }
            if retain_until_decoded {
                if self.dynamic_receive.as_ref().is_some_and(|dynamic| dynamic.is_blocked(stream_id)) {
                    return Ok(());
                }
                self.incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above")
                    .bytes
                    .consume(consumed);
            }
        }
    }

    /// Preserve QPACK corruption as a protocol error. A decoded section
    /// exceeding our local policy ends only its request/response stream.
    fn decode_received_fields(
        &mut self,
        stream_id: StreamId,
        field_section: &[u8],
    ) -> Result<Option<Vec<(String, String)>>, NativeH3SessionError> {
        let fields = if let Some(dynamic) = &mut self.dynamic_receive {
            let limit = self.max_field_section_size
                .unwrap_or(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE);
            match dynamic.decode_fields(stream_id, field_section, limit)? {
                DecodedQpackFields::Ready(fields) => fields,
                DecodedQpackFields::Blocked => return Ok(None),
                DecodedQpackFields::Excessive => {
                    self.reject_request_stream(stream_id, H3_EXCESSIVE_LOAD)?;
                    return Ok(None);
                }
            }
        } else {
            let plan = qpack_decode_field_section_with_context(
                field_section,
                H3QpackMode::StaticOnly,
                None,
            )?;
            qpack_plan_to_header_fields(&plan, None)?
        };
        if self
            .max_field_section_size
            .is_some_and(|limit| !received_field_section_fits(&fields, limit))
        {
            self.reject_request_stream(stream_id, H3_EXCESSIVE_LOAD)?;
            return Ok(None);
        }
        Ok(Some(fields))
    }

    fn on_frame(
        &mut self,
        stream_id: StreamId,
        kind: IncomingStreamKind,
        frame: H3Frame,
    ) -> Result<(), NativeH3SessionError> {
        match kind {
            IncomingStreamKind::Control => {
                self.state.on_uni_stream_frame(stream_id.0, &frame)?;
                match frame {
                    H3Frame::Settings(settings) => {
                        if let Some(sender) = &self.dynamic_send {
                            sender.configure_peer(&settings)?;
                        }
                        self.peer_max_field_section_size.store(
                            settings.max_field_section_size.unwrap_or(u64::MAX),
                            Ordering::Release,
                        );
                        self.events.push_back(NativeH3Event::Settings(settings));
                    }
                    H3Frame::Goaway(id) => self.events.push_back(NativeH3Event::Goaway(id)),
                    other => self.events.push_back(NativeH3Event::Frame {
                        stream_id,
                        frame: other,
                    }),
                }
            }
            IncomingStreamKind::RequestResponse => match frame {
                H3Frame::Headers(field_section) if self.role == H3EndpointRole::Server => {
                    let header_block_index = self
                        .incoming
                        .get(&stream_id)
                        .expect("request stream exists while decoding")
                        .header_blocks_seen;
                    if header_block_index == 0 {
                        // A field section QPACK cannot decode stays a
                        // connection error. One that decodes but is not a
                        // valid request is malformed, a stream error (RFC 9114
                        // section 4.1.2): reject it without ending the other
                        // requests on this connection.
                        let Some(fields) = self.decode_received_fields(stream_id, &field_section)?
                        else {
                            return Ok(());
                        };
                        let Ok(head) = header_fields_to_request_head(&fields) else {
                            return self.reject_malformed_request(stream_id);
                        };
                        self.state.on_request_stream_frame(
                            stream_id.0,
                            &H3Frame::Headers(field_section),
                        )?;
                        self.incoming
                            .get_mut(&stream_id)
                            .expect("request stream exists while decoding")
                            .header_blocks_seen = 1;
                        self.events
                            .push_back(NativeH3Event::RequestHeaders { stream_id, head });
                        return Ok(());
                    }
                    // Likewise for trailers: one that decodes but HTTP/3
                    // forbids (an uppercase or connection-specific name, a
                    // control character, a pseudo-header) makes only this
                    // request malformed. It used to end the whole connection.
                    let Some(fields) = self.decode_received_fields(stream_id, &field_section)?
                    else {
                        return Ok(());
                    };
                    if validate_trailer_fields(&fields).is_err() {
                        return self.reject_malformed_request(stream_id);
                    }
                    self.state
                        .on_request_stream_frame(stream_id.0, &H3Frame::Headers(field_section))?;
                    self.incoming
                        .get_mut(&stream_id)
                        .expect("request stream exists while decoding")
                        .header_blocks_seen = header_block_index.saturating_add(1);
                    self.events
                        .push_back(NativeH3Event::Trailers { stream_id, fields });
                }
                H3Frame::Headers(field_section) => {
                    let final_response_headers_seen = self
                        .incoming
                        .get(&stream_id)
                        .expect("request stream exists while decoding")
                        .final_response_headers_seen;
                    // A response or trailer section that QPACK decodes but
                    // HTTP/3 forbids makes only this response malformed, a
                    // stream error (RFC 9114 section 4.1.2). It used to close
                    // the connection and every other request on it.
                    let Some(fields) = self.decode_received_fields(stream_id, &field_section)?
                    else {
                        return Ok(());
                    };
                    if final_response_headers_seen {
                        if validate_trailer_fields(&fields).is_err() {
                            return self.reject_malformed_request(stream_id);
                        }
                        self.state.on_request_stream_frame(
                            stream_id.0,
                            &H3Frame::Headers(field_section),
                        )?;
                        let stream = self
                            .incoming
                            .get_mut(&stream_id)
                            .expect("request stream exists while decoding");
                        stream.header_blocks_seen = stream.header_blocks_seen.saturating_add(1);
                        self.events
                            .push_back(NativeH3Event::Trailers { stream_id, fields });
                        return Ok(());
                    }
                    let Ok(head) = header_fields_to_response_head(&fields) else {
                        return self.reject_malformed_request(stream_id);
                    };
                    let informational = (100..200).contains(&head.status);
                    if informational {
                        self.state.on_informational_response_headers(stream_id.0)?;
                    } else {
                        self.state.on_request_stream_frame(
                            stream_id.0,
                            &H3Frame::Headers(field_section),
                        )?;
                    }
                    let stream = self
                        .incoming
                        .get_mut(&stream_id)
                        .expect("request stream exists while decoding");
                    stream.header_blocks_seen = stream.header_blocks_seen.saturating_add(1);
                    stream.final_response_headers_seen = !informational;
                    self.events
                        .push_back(NativeH3Event::ResponseHeaders { stream_id, head });
                }
                H3Frame::Data(bytes) => {
                    self.state
                        .on_request_stream_frame(stream_id.0, &H3Frame::Data(bytes.clone()))?;
                    self.events.push_back(NativeH3Event::Data {
                        stream_id,
                        bytes: Bytes::from(bytes),
                    });
                }
                other => {
                    self.state.on_request_stream_frame(stream_id.0, &other)?;
                    self.events.push_back(NativeH3Event::Frame {
                        stream_id,
                        frame: other,
                    });
                }
            },
            IncomingStreamKind::AwaitingUniType
            | IncomingStreamKind::QpackEncoder
            | IncomingStreamKind::QpackDecoder
            | IncomingStreamKind::Push
            | IncomingStreamKind::UnknownUni => {
                return Err(NativeH3SessionError::InvalidState(
                    "HTTP/3 frame decoded on a non-frame stream",
                ));
            }
        }
        Ok(())
    }

    fn finish_stream(&mut self, stream_id: StreamId) -> Result<(), NativeH3SessionError> {
        let incoming =
            self.incoming
                .remove(&stream_id)
                .ok_or(NativeH3SessionError::InvalidState(
                    "FIN arrived for an unknown HTTP/3 stream",
                ))?;
        if incoming.kind == IncomingStreamKind::AwaitingUniType {
            // RFC 9114 section 6.2: receivers MUST tolerate a unidirectional
            // stream that ends before its type is known. Its bytes, if any,
            // are an incomplete type prefix; discard them.
            return Ok(());
        }
        if !incoming.bytes.is_empty() || incoming.data_frame.is_some() {
            return Err(NativeH3SessionError::TruncatedStream {
                stream_id,
                buffered_bytes: incoming.bytes.len(),
            });
        }
        match incoming.kind {
            IncomingStreamKind::Control => {
                return Err(NativeH3SessionError::CriticalStreamClosed {
                    stream_id,
                    stream_type: H3UniStreamType::Control,
                });
            }
            IncomingStreamKind::QpackEncoder => {
                return Err(NativeH3SessionError::CriticalStreamClosed {
                    stream_id,
                    stream_type: H3UniStreamType::QpackEncoder,
                });
            }
            IncomingStreamKind::QpackDecoder => {
                return Err(NativeH3SessionError::CriticalStreamClosed {
                    stream_id,
                    stream_type: H3UniStreamType::QpackDecoder,
                });
            }
            IncomingStreamKind::RequestResponse => {
                if self.state.request_stream_lacks_initial_headers(stream_id.0) {
                    // RFC 9114 section 4.1: a request stream that ends before
                    // its HEADERS is incomplete, and a response that ends
                    // before its final HEADERS is malformed. Either ends only
                    // this stream, not the connection.
                    let error_code = if self.role == H3EndpointRole::Server {
                        H3_REQUEST_INCOMPLETE
                    } else {
                        H3_MESSAGE_ERROR
                    };
                    return self.reject_request_stream(stream_id, error_code);
                }
                self.state.finish_request_stream(stream_id.0)?;
                self.events.push_back(NativeH3Event::Finished { stream_id });
            }
            IncomingStreamKind::Push | IncomingStreamKind::UnknownUni => {}
            IncomingStreamKind::AwaitingUniType => unreachable!("handled above"),
        }
        self.terminal_streams.insert(stream_id)?;
        if is_client_bidi(stream_id) {
            self.retire_received_qpack_stream(stream_id)?;
        }
        self.forget_streaming_readiness(stream_id);
        Ok(())
    }

    fn ensure_peer_request_field_limit(
        &self,
        head: &H3RequestHead,
    ) -> Result<(), NativeH3SessionError> {
        // These are the pseudo-fields emitted by the static request encoder.
        // Count occurrences and UTF-8 bytes without cloning header strings.
        let pseudo = [
            (":method", head.pseudo.method.as_deref()),
            (":scheme", head.pseudo.scheme.as_deref()),
            (":path", head.pseudo.path.as_deref()),
            (":authority", head.pseudo.authority.as_deref()),
        ];
        let fields = pseudo
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| (name.len(), value.len())))
            .chain(head.headers.iter().map(|(name, value)| (name.len(), value.len())));
        ensure_outgoing_field_section_fits(
            fields,
            self.peer_max_field_section_size.load(Ordering::Acquire),
        )
    }

    fn ensure_peer_response_field_limit(
        &self,
        head: &H3ResponseHead,
    ) -> Result<(), NativeH3SessionError> {
        let status = head.status.to_string();
        let fields = std::iter::once((":status".len(), status.len()))
            .chain(head.headers.iter().map(|(name, value)| (name.len(), value.len())));
        ensure_outgoing_field_section_fits(
            fields,
            self.peer_max_field_section_size.load(Ordering::Acquire),
        )
    }

    fn ensure_transport_role(
        &self,
        connection: &QuicConnection,
    ) -> Result<(), NativeH3SessionError> {
        let matches = matches!(
            (self.role, connection.role()),
            (H3EndpointRole::Client, StreamRole::Client)
                | (H3EndpointRole::Server, StreamRole::Server)
        );
        if matches {
            Ok(())
        } else {
            Err(NativeH3SessionError::InvalidState(
                "HTTP/3 and QUIC endpoint roles do not match",
            ))
        }
    }

    fn ensure_ready_for_messages(
        &self,
        connection: &QuicConnection,
    ) -> Result<(), NativeH3SessionError> {
        if let Some(dynamic) = &self.dynamic_receive {
            dynamic.check_live()?;
        }
        if let Some(sender) = &self.dynamic_send {
            sender.check_live()?;
        }
        self.ensure_transport_role(connection)?;
        if !self.initialized {
            return Err(NativeH3SessionError::InvalidState(
                "HTTP/3 session is not initialized",
            ));
        }
        if !connection.can_send_app_data() {
            return Err(NativeH3SessionError::InvalidState(
                "QUIC connection is not established for application data",
            ));
        }
        Ok(())
    }
}

/// RFC 9114 section 4.2.2 counts occurrences, not unique header names.
/// Subtract from the remaining budget rather than summing potentially
/// overflowing lengths. This does not allocate another header representation.
fn received_field_section_fits(fields: &[(String, String)], limit: u64) -> bool {
    field_section_lengths_fit(
        fields.iter().map(|(name, value)| (name.len(), value.len())),
        limit,
    )
}

fn field_section_lengths_fit(
    fields: impl IntoIterator<Item = (usize, usize)>,
    limit: u64,
) -> bool {
    fields
        .into_iter()
        .try_fold(limit, |remaining, (name, value)| {
            remaining
                .checked_sub(u64::try_from(name).ok()?)?
                .checked_sub(u64::try_from(value).ok()?)?
                .checked_sub(32)
        })
        .is_some()
}

fn ensure_outgoing_field_section_fits(
    fields: impl IntoIterator<Item = (usize, usize)>,
    limit: u64,
) -> Result<(), NativeH3SessionError> {
    if field_section_lengths_fit(fields, limit) {
        Ok(())
    } else {
        Err(NativeH3SessionError::InvalidState(
            "field section exceeds peer SETTINGS_MAX_FIELD_SECTION_SIZE",
        ))
    }
}

fn decode_prefix(input: &[u8]) -> Result<Option<(u64, usize)>, NativeH3SessionError> {
    match decode_varint(input) {
        Ok(decoded) => Ok(Some(decoded)),
        Err(QuicCoreError::UnexpectedEof) => Ok(None),
        Err(_) => Err(NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
            "invalid HTTP/3 stream type varint",
        ))),
    }
}

fn complete_frame_len(
    input: &[u8],
    max_payload_size: usize,
) -> Result<Option<usize>, NativeH3SessionError> {
    let Some(header) = frame_header(input, max_payload_size)? else {
        return Ok(None);
    };
    debug_assert!(header.header_len <= FRAME_HEADER_MAX_BYTES);
    Ok((input.len() >= header.wire_len).then_some(header.wire_len))
}

fn frame_header(
    input: &[u8],
    max_payload_size: usize,
) -> Result<Option<FrameHeader>, NativeH3SessionError> {
    FrameHeader::decode(input, max_payload_size).map_err(|error| match error {
        FrameHeaderError::AddressOverflow => NativeH3SessionError::Protocol(
            H3NativeError::InvalidFrame("HTTP/3 frame length exceeds addressable range"),
        ),
        FrameHeaderError::LengthOverflow => NativeH3SessionError::Protocol(
            H3NativeError::InvalidFrame("HTTP/3 frame length overflow"),
        ),
        FrameHeaderError::PayloadTooLarge {
            payload_size,
            max_size,
        } => NativeH3SessionError::Protocol(H3NativeError::FrameTooLarge {
            payload_size,
            max_size,
        }),
    })
}

fn is_client_bidi(stream_id: StreamId) -> bool {
    stream_id.direction() == StreamDirection::Bidirectional && stream_id.0 & 0x01 == 0
}

#[cfg(test)]
#[path = "h3_quic_inline_tests.rs"]
mod tests;
