//! Native HTTP/3 session mapping over native QUIC stream bytes.
//!
//! [`NativeH3Session`] is deliberately an established-connection adapter: it
//! does not own UDP sockets, TLS handshakes, or a runtime task. Applications
//! drive a [`QuicConnection`], then use this type to put HTTP/3 control,
//! request, and response bytes onto its reliable streams. This keeps the
//! composition usable by both the deterministic lab transport and the native
//! UDP driver without introducing another executor.
//!
//! The first supported profile is static QPACK. Dynamic instruction streams,
//! server push, live-UDP deployment, and external interoperability are outside
//! this adapter's current claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::num::NonZeroUsize;
use std::task::{Context as TaskContext, Poll, Waker};

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::net::quic_core::{QUIC_VARINT_MAX, QuicCoreError, decode_varint, encode_varint};
use crate::net::quic_native::connection::NativeQuicConnectionError;
use crate::net::quic_native::endpoint_api::QuicConnection;
use crate::net::quic_native::streams::{StreamDirection, StreamId, StreamReadiness, StreamRole};

#[path = "h3_receive_frame.rs"]
mod receive_frame;
use receive_frame::{DataFrameCursor, FrameHeader, FrameHeaderError};

use super::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3EndpointRole, H3Frame, H3NativeError,
    H3QpackMode, H3RequestHead, H3ResponseHead, H3Settings, H3UniStreamType,
    QpackEncoderInstruction, qpack_decode_encoder_instruction, qpack_decode_request_field_section,
    qpack_decode_response_field_section, qpack_decode_trailer_field_section,
    qpack_encode_request_field_section, qpack_encode_response_field_section,
    qpack_encode_trailer_field_section,
};

/// RFC 9114 application error code `H3_REQUEST_CANCELLED`.
pub const H3_REQUEST_CANCELLED: u64 = 0x010c;

const H3_CONTROL_STREAM_TYPE: u64 = 0x00;
const FRAME_HEADER_MAX_BYTES: usize = 16;
const MAX_SPARSE_TERMINAL_STREAMS: usize = 4096;
const STREAMING_READINESS_BATCH: usize = 32;
const STREAMING_POLL_STEPS: usize = 32;

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
    bytes: Vec<u8>,
    header_blocks_seen: u8,
    final_response_headers_seen: bool,
    data_frame: Option<DataFrameCursor>,
}

#[derive(Debug, Clone)]
struct StreamingReceive {
    max_chunk_bytes: NonZeroUsize,
    ready: BTreeMap<StreamId, StreamReadiness>,
    paused: BTreeSet<StreamId>,
    poll_after: Option<StreamId>,
    waker: Option<Waker>,
}

#[derive(Debug, Clone, Default)]
struct TerminalStreamTracker {
    contiguous: [Option<u64>; 4],
    sparse: BTreeSet<StreamId>,
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
        self.contiguous[class].is_some_and(|high| stream_id.0 <= high)
            || self.sparse.contains(&stream_id)
    }

    fn insert(&mut self, stream_id: StreamId) -> Result<(), H3NativeError> {
        self.ensure_healthy()?;
        if self.contains(stream_id) {
            return Ok(());
        }
        let class_id = stream_id.0 & 0x03;
        let class = usize::try_from(class_id).expect("stream-id class fits usize");
        let next_contiguous =
            self.contiguous[class].map_or(class_id, |high| high.saturating_add(4));
        if self.sparse.len() >= MAX_SPARSE_TERMINAL_STREAMS && stream_id.0 != next_contiguous {
            self.overflowed = true;
            return Err(H3NativeError::ControlProtocol(
                "terminal stream tracking window exceeded",
            ));
        }
        self.sparse.insert(stream_id);
        let mut next = next_contiguous;
        while self.sparse.remove(&StreamId(next)) {
            self.contiguous[class] = Some(next);
            let Some(successor) = next.checked_add(4) else {
                break;
            };
            next = successor;
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
            bytes: Vec::new(),
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

#[derive(Debug, Clone)]
struct NativeH3PendingWrite {
    wire: Bytes,
    fin: bool,
    event: NativeH3WriteEvent,
    next_phase: NativeH3ResponsePhase,
}

/// Incremental response writer for one established HTTP/3 request stream.
///
/// The writer retains exactly one encoded H3 frame until both QUIC
/// flow-control scopes admit its complete wire length. It also waits for the
/// preceding STREAM frame to leave packet assembly, so a caller cannot build
/// an unbounded transport-side queue by repeatedly polling a body producer.
#[derive(Debug)]
pub(crate) struct NativeH3ResponseWriter {
    stream_id: StreamId,
    phase: NativeH3ResponsePhase,
    pending: Option<NativeH3PendingWrite>,
    max_frame_payload_size: usize,
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
        });
        Ok(())
    }

    /// Encode and retain one terminal trailing HEADERS block.
    pub fn queue_trailers(
        &mut self,
        fields: &[(String, String)],
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_open_without_pending()?;
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
        });
        self.phase = NativeH3ResponsePhase::TerminalPending;
        Ok(())
    }

    /// Poll one retained write through exact QUIC queue and flow admission.
    pub fn poll_flush_one(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<NativeH3WriteEvent>, NativeH3SessionError>> {
        let Some(pending) = self.pending.as_ref() else {
            return Poll::Ready(Ok(None));
        };
        let required = u64::try_from(pending.wire.len()).map_err(|_| {
            NativeH3SessionError::Protocol(H3NativeError::InvalidFrame(
                "encoded HTTP/3 frame exceeds addressable QUIC range",
            ))
        });
        let required = match required {
            Ok(required) => required,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match connection.poll_stream_write_ready(cx, self.stream_id, required, task_cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(NativeH3SessionError::Transport(error)));
            }
            Poll::Pending => return Poll::Pending,
        }

        let pending = self.pending.as_ref().expect("checked above");
        if let Err(error) =
            connection.write_stream(cx, self.stream_id, pending.wire.clone(), pending.fin)
        {
            return Poll::Ready(Err(NativeH3SessionError::Transport(error)));
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

/// Static-QPACK HTTP/3 mapping over one established native QUIC connection.
#[derive(Debug, Clone)]
pub struct NativeH3Session {
    role: H3EndpointRole,
    config: H3ConnectionConfig,
    state: H3ConnectionState,
    local_control: H3ControlState,
    local_control_stream: Option<StreamId>,
    incoming: BTreeMap<StreamId, IncomingStream>,
    terminal_streams: TerminalStreamTracker,
    events: VecDeque<NativeH3Event>,
    initialized: bool,
    closing: bool,
    next_local_request_stream_id: u64,
    streaming_receive: Option<StreamingReceive>,
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
    /// Dynamic QPACK is rejected by operational methods in this first
    /// composition profile; callers can still use `h3_native` directly for its
    /// opt-in dynamic state machine.
    #[must_use]
    pub fn with_config(config: H3ConnectionConfig) -> Self {
        Self {
            role: config.endpoint_role,
            config,
            state: H3ConnectionState::with_config(config),
            local_control: H3ControlState::new(),
            local_control_stream: None,
            incoming: BTreeMap::new(),
            terminal_streams: TerminalStreamTracker::default(),
            events: VecDeque::new(),
            initialized: false,
            closing: false,
            next_local_request_stream_id: 0,
            streaming_receive: None,
        }
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
    pub fn initialize(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        mut settings: H3Settings,
    ) -> Result<StreamId, NativeH3SessionError> {
        self.ensure_static_qpack()?;
        self.ensure_transport_role(connection)?;
        if self.initialized {
            return Err(NativeH3SessionError::InvalidState(
                "session is already initialized",
            ));
        }

        // These are local decoder limits. This adapter has no dynamic-table
        // decoder, so it must advertise zero even if a caller supplies larger
        // values. Peer non-zero limits remain legal permission that our static
        // encoder simply declines to use.
        settings.qpack_max_table_capacity = settings.qpack_max_table_capacity.map(|_| 0);
        settings.qpack_blocked_streams = settings.qpack_blocked_streams.map(|_| 0);

        let control_stream = connection.open_uni_stream(cx)?;
        let settings_frame = self.local_control.build_local_settings(settings)?;
        let mut wire = Vec::new();
        encode_varint(H3_CONTROL_STREAM_TYPE, &mut wire)
            .map_err(|_| H3NativeError::InvalidFrame("control stream type out of range"))?;
        settings_frame.encode(&mut wire)?;
        connection.write_stream(cx, control_stream, Bytes::from(wire), false)?;
        self.local_control_stream = Some(control_stream);
        self.initialized = true;
        Ok(control_stream)
    }

    /// Queue one complete request on a new client-initiated bidirectional stream.
    pub fn send_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        head: &H3RequestHead,
        body: Bytes,
    ) -> Result<StreamId, NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
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

        let stream_id = connection.open_bidi_stream(cx)?;
        if stream_id.0 != self.next_local_request_stream_id {
            return Err(NativeH3SessionError::InvalidState(
                "QUIC request stream allocation was shared outside the HTTP/3 session",
            ));
        }
        self.next_local_request_stream_id = self.next_local_request_stream_id.saturating_add(4);
        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_request_field_section(head)?).encode(&mut wire)?;
        if !body.is_empty() {
            H3Frame::Data(body.to_vec()).encode(&mut wire)?;
        }
        connection.write_stream(cx, stream_id, Bytes::from(wire), true)?;
        Ok(stream_id)
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

        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_response_field_section(head)?).encode(&mut wire)?;
        connection.write_stream(cx, stream_id, Bytes::from(wire), false)?;
        Ok(())
    }

    /// Prepare an incremental final response writer for an existing request.
    ///
    /// The response head is fully validated and encoded before this returns,
    /// but no QUIC state is mutated until the caller polls the writer. Setting
    /// `end_stream` is intended for HEAD/body-forbidden responses: final
    /// HEADERS and FIN are then committed atomically and no DATA producer is
    /// started.
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

        let field_section = qpack_encode_response_field_section(head)?;
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
            }),
            max_frame_payload_size: self.config.max_frame_payload_size,
        })
    }

    /// Queue one complete final response on an existing request stream.
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

        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_response_field_section(head)?).encode(&mut wire)?;
        if !body.is_empty() {
            H3Frame::Data(body.to_vec()).encode(&mut wire)?;
        }
        connection.write_stream(cx, stream_id, Bytes::from(wire), true)?;
        Ok(())
    }

    /// Queue `H3_REQUEST_CANCELLED` for one request stream.
    pub fn cancel_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        self.ensure_ready_for_messages(connection)?;
        if !is_client_bidi(stream_id) {
            return Err(NativeH3SessionError::InvalidState(
                "request cancellation requires a client bidirectional stream",
            ));
        }
        connection.reset_stream(cx, stream_id, H3_REQUEST_CANCELLED)?;
        connection.stop_stream_receiving(cx, stream_id, H3_REQUEST_CANCELLED)?;
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
        if self.streaming_receive.is_some() {
            loop {
                if let Some(event) = self.events.pop_front() {
                    return Ok(Some(event));
                }
                if !self.drive_streaming_receive(cx, connection)? {
                    return Ok(None);
                }
            }
        }
        loop {
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
        if self.streaming_receive.is_some() {
            return self.poll_streaming_event(cx, connection, task_cx);
        }
        loop {
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
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        task_cx.waker().wake_by_ref();
        Poll::Pending
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

        let emitted = !self.events.is_empty();
        let eof = readiness.fin_received && connection.is_stream_eof(stream_id)?;
        if !emitted && eof {
            // A partial DATA cursor, even with no buffered payload bytes,
            // is truncation. FIN is never inferred from Content-Length or an
            // empty read and never overtakes a preceding application event.
            self.finish_stream(stream_id)?;
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
            self.events.push_back(NativeH3Event::StreamReset {
                stream_id,
                error_code,
                final_size,
            });
            return Ok(());
        }
        if readiness.receive_stopped.is_some() {
            if is_client_bidi(stream_id) {
                self.state.abort_request_stream(stream_id.0)?;
            }
            self.incoming.remove(&stream_id);
            self.forget_streaming_readiness(stream_id);
            self.terminal_streams.insert(stream_id)?;
            return Ok(());
        }

        let incoming = self
            .incoming
            .entry(stream_id)
            .or_insert_with(|| IncomingStream::new(stream_id));
        if readiness.readable_bytes > 0 {
            let max_read = usize::try_from(readiness.readable_bytes).unwrap_or(usize::MAX);
            let bytes = connection.read_stream(cx, stream_id, max_read)?;
            incoming.bytes.extend_from_slice(&bytes);
        }
        self.decode_stream(stream_id)?;

        if readiness.fin_received && connection.is_stream_eof(stream_id)? {
            self.finish_stream(stream_id)?;
        }
        Ok(())
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
            .map_or_else(Vec::new, |incoming| incoming.bytes.clone());
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
                stream.bytes.drain(..consumed);
                stream.kind = match decoded {
                    H3UniStreamType::Control => IncomingStreamKind::Control,
                    H3UniStreamType::QpackEncoder => IncomingStreamKind::QpackEncoder,
                    H3UniStreamType::QpackDecoder => IncomingStreamKind::QpackDecoder,
                    H3UniStreamType::Push => IncomingStreamKind::Push,
                    H3UniStreamType::Unknown(_) => IncomingStreamKind::UnknownUni,
                };
                continue;
            }

            if kind == IncomingStreamKind::QpackEncoder {
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                while !stream.bytes.is_empty() {
                    match qpack_decode_encoder_instruction(&stream.bytes) {
                        Ok((
                            QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 0 },
                            n,
                        )) => {
                            stream.bytes.drain(..n);
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
                if !self
                    .incoming
                    .get(&stream_id)
                    .expect("stream checked above")
                    .bytes
                    .is_empty()
                {
                    return Err(NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
                        "static QPACK forbids decoder instructions",
                    )));
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
                    let bytes = Bytes::from(stream.bytes.drain(..len).collect::<Vec<_>>());
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
                    stream.bytes.drain(..header.header_len);
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
            let frame = {
                let stream = self
                    .incoming
                    .get_mut(&stream_id)
                    .expect("stream checked above");
                let (frame, consumed) = H3Frame::decode(&stream.bytes[..frame_len], &self.config)?;
                debug_assert_eq!(consumed, frame_len);
                stream.bytes.drain(..consumed);
                frame
            };
            self.on_frame(stream_id, kind, frame)?;
        }
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
                        let head = qpack_decode_request_field_section(
                            &field_section,
                            H3QpackMode::StaticOnly,
                            None,
                        )?;
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
                    let fields = qpack_decode_trailer_field_section(
                        &field_section,
                        H3QpackMode::StaticOnly,
                        None,
                    )?;
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
                    if final_response_headers_seen {
                        let fields = qpack_decode_trailer_field_section(
                            &field_section,
                            H3QpackMode::StaticOnly,
                            None,
                        )?;
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
                    let head = qpack_decode_response_field_section(
                        &field_section,
                        H3QpackMode::StaticOnly,
                        None,
                    )?;
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
        if !incoming.bytes.is_empty()
            || incoming.data_frame.is_some()
            || incoming.kind == IncomingStreamKind::AwaitingUniType
        {
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
                self.state.finish_request_stream(stream_id.0)?;
                self.events.push_back(NativeH3Event::Finished { stream_id });
            }
            IncomingStreamKind::Push | IncomingStreamKind::UnknownUni => {}
            IncomingStreamKind::AwaitingUniType => unreachable!("handled above"),
        }
        self.terminal_streams.insert(stream_id)?;
        self.forget_streaming_readiness(stream_id);
        Ok(())
    }

    fn ensure_static_qpack(&self) -> Result<(), NativeH3SessionError> {
        if self.config.qpack_mode != H3QpackMode::StaticOnly {
            return Err(NativeH3SessionError::InvalidState(
                "native QUIC session adapter currently requires static QPACK",
            ));
        }
        Ok(())
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
        self.ensure_static_qpack()?;
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
mod tests {
    use super::*;
    use crate::http::h3_native::H3PseudoHeaders;
    use crate::net::quic_native::NativeQuicConnectionConfig;

    fn server_with_request_limit(cx: &Cx, limit: u64) -> (NativeH3Session, QuicConnection) {
        let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
        connection.begin_handshake(cx).expect("begin handshake");
        connection
            .mark_handshake_keys_available(cx)
            .expect("handshake keys");
        connection
            .mark_app_keys_available(cx)
            .expect("application keys");
        connection.confirm_handshake(cx).expect("confirm handshake");
        let mut session = NativeH3Session::with_config(H3ConnectionConfig {
            endpoint_role: H3EndpointRole::Server,
            max_concurrent_request_streams: Some(limit),
            ..H3ConnectionConfig::default()
        });
        session
            .initialize(cx, &mut connection, H3Settings::default())
            .expect("initialize server session");
        (session, connection)
    }

    fn receive_request_head(
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        fin: bool,
    ) -> u64 {
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.test".to_string()),
                path: Some("/".to_string()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        )
        .expect("valid request head");
        let wire = encode_frame(H3Frame::Headers(
            qpack_encode_request_field_section(&head).expect("encode request head"),
        ))
        .expect("encode HEADERS frame");
        let final_size = u64::try_from(wire.len()).expect("bounded request wire size");
        connection
            .inner_mut()
            .accept_remote_stream(cx, stream_id)
            .expect("accept request stream");
        connection
            .inner_mut()
            .receive_stream_bytes(cx, stream_id, 0, wire, fin)
            .expect("receive request HEADERS");
        final_size
    }

    #[test]
    fn native_h3_session_local_receive_stop_releases_request_concurrency() {
        let cx = Cx::for_testing();
        let (mut session, mut connection) = server_with_request_limit(&cx, 1);
        let refused = StreamId(0);
        receive_request_head(&cx, &mut connection, refused, false);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("request HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == refused
        ));
        assert_eq!(session.state.active_request_stream_count(), 1);
        session
            .cancel_request(&cx, &mut connection, refused)
            .expect("cancel incomplete request");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("receive stop"),
            None
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(!session.incoming.contains_key(&refused));
        assert!(session.terminal_streams.contains(refused));

        let survivor = StreamId(4);
        receive_request_head(&cx, &mut connection, survivor, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("survivor HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == survivor
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("survivor FIN"),
            Some(NativeH3Event::Finished {
                stream_id: survivor
            })
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(session.incoming.is_empty());
    }

    #[test]
    fn native_h3_session_peer_reset_after_request_fin_is_delivered_once() {
        let cx = Cx::for_testing();
        let (mut session, mut connection) = server_with_request_limit(&cx, 1);
        let cancelled = StreamId(0);
        let final_size = receive_request_head(&cx, &mut connection, cancelled, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("request HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == cancelled
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("request FIN"),
            Some(NativeH3Event::Finished {
                stream_id: cancelled
            })
        );
        assert!(session.terminal_streams.contains(cancelled));
        assert_eq!(session.state.active_request_stream_count(), 0);

        connection
            .inner_mut()
            .reset_stream_receive(&cx, cancelled, H3_REQUEST_CANCELLED, final_size)
            .expect("peer cancels after request FIN");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("late peer reset"),
            Some(NativeH3Event::StreamReset {
                stream_id: cancelled,
                error_code: H3_REQUEST_CANCELLED,
                final_size,
            })
        );
        session
            .cancel_request(&cx, &mut connection, cancelled)
            .expect("acknowledge cancelled dispatch");
        connection
            .inner_mut()
            .reset_stream_receive(&cx, cancelled, H3_REQUEST_CANCELLED, final_size)
            .expect("duplicate peer reset");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("no repeated reset"),
            None
        );
        assert_eq!(session.state.active_request_stream_count(), 0);

        let survivor = StreamId(4);
        receive_request_head(&cx, &mut connection, survivor, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("survivor HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == survivor
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("survivor FIN"),
            Some(NativeH3Event::Finished {
                stream_id: survivor
            })
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(session.incoming.is_empty());
    }

    #[test]
    fn produced_h3_data_wire_length_tracks_varint_boundaries_exactly() {
        assert_eq!(h3_data_frame_wire_len(0).expect("zero"), 2);
        assert_eq!(h3_data_frame_wire_len(63).expect("63"), 65);
        assert_eq!(h3_data_frame_wire_len(64).expect("64"), 67);
        assert_eq!(h3_data_frame_wire_len(16_383).expect("16383"), 16_386);
        assert_eq!(h3_data_frame_wire_len(16_384).expect("16384"), 16_389);
        if let Ok(max_payload) = usize::try_from(QUIC_VARINT_MAX) {
            assert!(
                h3_data_frame_wire_len(max_payload).is_err(),
                "payload plus H3 framing must fit the QUIC varint credit range"
            );
        }
    }

    #[test]
    fn native_h3_adapter_terminal_stream_tracker_compacts_contiguous_classes() {
        let mut tracker = TerminalStreamTracker::default();
        tracker.insert(StreamId(8)).expect("track stream 8");
        assert_eq!(tracker.sparse.len(), 1);
        tracker.insert(StreamId(0)).expect("track stream 0");
        assert_eq!(tracker.sparse.len(), 1);
        tracker.insert(StreamId(4)).expect("track stream 4");
        assert!(tracker.sparse.is_empty());
        assert_eq!(tracker.contiguous[0], Some(8));
        for stream_id in [0, 4, 8] {
            assert!(tracker.contains(StreamId(stream_id)));
        }

        tracker.insert(StreamId(3)).expect("track stream 3");
        tracker.insert(StreamId(7)).expect("track stream 7");
        assert_eq!(tracker.contiguous[3], Some(7));
        assert!(tracker.sparse.is_empty());
    }

    #[test]
    fn native_h3_adapter_terminal_stream_tracker_fails_closed_at_sparse_budget() {
        let mut tracker = TerminalStreamTracker::default();
        for ordinal in 1..=MAX_SPARSE_TERMINAL_STREAMS {
            tracker
                .insert(StreamId((ordinal as u64) * 4))
                .expect("within sparse terminal budget");
        }
        let error = tracker
            .insert(StreamId(((MAX_SPARSE_TERMINAL_STREAMS as u64) + 1) * 4))
            .expect_err("terminal tracker must fail closed at its hard bound");
        assert_eq!(
            error,
            H3NativeError::ControlProtocol("terminal stream tracking window exceeded")
        );
        assert_eq!(tracker.ensure_healthy(), Err(error));
    }
}
