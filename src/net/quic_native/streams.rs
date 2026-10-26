//! Native QUIC stream table + flow-control model.

use crate::bytes::{Bytes, BytesMut};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::protocol::varint::VARINT_MAX;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Stream role relative to this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    /// Client-side endpoint.
    Client,
    /// Server-side endpoint.
    Server,
}

/// Stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Bidirectional stream.
    Bidirectional,
    /// Unidirectional stream.
    Unidirectional,
}

/// QUIC stream ID wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Construct a local stream ID from sequence index.
    #[must_use]
    pub fn local(role: StreamRole, dir: StreamDirection, seq: u64) -> Self {
        let initiator_bit = match role {
            StreamRole::Client => 0u64,
            StreamRole::Server => 1u64,
        };
        let direction_bit = match dir {
            StreamDirection::Bidirectional => 0u64,
            StreamDirection::Unidirectional => 1u64,
        };
        // QUIC stream IDs use 2 low bits for type, leaving 62 bits for sequence.
        debug_assert!(
            seq < (1u64 << 62),
            "QUIC stream sequence exceeds 62-bit limit"
        );
        Self((seq << 2) | (direction_bit << 1) | initiator_bit)
    }

    /// Whether this stream is locally initiated for `role`.
    #[must_use]
    pub fn is_local_for(self, role: StreamRole) -> bool {
        (self.0 & 0x1)
            == match role {
                StreamRole::Client => 0,
                StreamRole::Server => 1,
            }
    }

    /// Stream direction.
    #[must_use]
    pub fn direction(self) -> StreamDirection {
        if (self.0 & 0x2) == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }
}

/// Flow-control accounting errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowControlError {
    /// Credit exceeded.
    Exhausted {
        /// Attempted credit consumption.
        attempted: u64,
        /// Remaining credit.
        remaining: u64,
    },
    /// Limit regression.
    LimitRegression {
        /// Current limit.
        current: u64,
        /// Requested new limit.
        requested: u64,
    },
}

impl fmt::Display for FlowControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted {
                attempted,
                remaining,
            } => {
                write!(
                    f,
                    "flow control exhausted: attempted={attempted}, remaining={remaining}"
                )
            }
            Self::LimitRegression { current, requested } => {
                write!(
                    f,
                    "flow-control limit regression: current={current}, requested={requested}"
                )
            }
        }
    }
}

impl std::error::Error for FlowControlError {}

/// Simple flow-control credit tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowCredit {
    limit: u64,
    used: u64,
}

impl FlowCredit {
    /// Create a new credit tracker.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Remaining credit.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Current used credit.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Current credit limit.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Consume credit.
    pub fn consume(&mut self, amount: u64) -> Result<(), FlowControlError> {
        self.can_consume(amount)?;
        self.used = self.used.saturating_add(amount);
        Ok(())
    }

    /// Validate that credit can be consumed without mutating state.
    pub fn can_consume(&self, amount: u64) -> Result<(), FlowControlError> {
        let remaining = self.remaining();
        if amount > remaining {
            return Err(FlowControlError::Exhausted {
                attempted: amount,
                remaining,
            });
        }
        Ok(())
    }

    /// Consume up to a target absolute usage watermark.
    ///
    /// Returns the newly consumed delta.
    pub fn consume_to(&mut self, target_used: u64) -> Result<u64, FlowControlError> {
        if target_used <= self.used {
            return Ok(0);
        }
        let delta = target_used.saturating_sub(self.used);
        self.consume(delta)?;
        Ok(delta)
    }

    /// Release previously consumed credit (used for rollback/recovery paths).
    pub fn release(&mut self, amount: u64) {
        self.used = self.used.saturating_sub(amount);
    }

    /// Increase limit monotonically.
    pub fn increase_limit(&mut self, new_limit: u64) -> Result<(), FlowControlError> {
        if new_limit < self.limit {
            return Err(FlowControlError::LimitRegression {
                current: self.limit,
                requested: new_limit,
            });
        }
        self.limit = new_limit;
        Ok(())
    }

    /// Lower the limit to `new_limit`, clamped so already-consumed credit stays
    /// valid. Returns the limit actually applied. Used when converting a stream
    /// opened with the unbounded default into a bounded-window stream.
    pub fn reduce_limit_clamped(&mut self, new_limit: u64) -> u64 {
        let applied = new_limit.max(self.used).min(self.limit);
        self.limit = applied;
        applied
    }
}

/// Stream-level errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicStreamError {
    /// Flow-control issue.
    Flow(FlowControlError),
    /// Final size violated stream invariants.
    InvalidFinalSize {
        /// Final size announced by peer.
        final_size: u64,
        /// Bytes already received.
        received: u64,
    },
    /// Peer requested sender to stop transmitting.
    SendStopped {
        /// STOP_SENDING application error code.
        code: u64,
    },
    /// Receive side was explicitly stopped.
    ReceiveStopped {
        /// STOP_RECEIVING application error code.
        code: u64,
    },
    /// Peer reset the receive side with RESET_STREAM.
    ReceiveReset {
        /// RESET_STREAM application error code.
        code: u64,
        /// Final stream size declared by the peer.
        final_size: u64,
    },
    /// Inconsistent RESET_STREAM final-size announcement.
    InconsistentReset {
        /// Previously declared final size.
        previous_final_size: u64,
        /// Newly declared final size.
        new_final_size: u64,
    },
    /// Offset + length overflowed `u64`.
    OffsetOverflow {
        /// Segment offset.
        offset: u64,
        /// Segment length.
        len: u64,
    },
    /// Send side already emitted a FIN and cannot accept more bytes.
    SendFinished {
        /// Final stream size already committed by FIN.
        final_size: u64,
    },
}

impl fmt::Display for QuicStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flow(err) => write!(f, "{err}"),
            Self::InvalidFinalSize {
                final_size,
                received,
            } => write!(
                f,
                "invalid final size: final_size={final_size}, already_received={received}"
            ),
            Self::SendStopped { code } => write!(f, "send stopped by peer: code={code}"),
            Self::ReceiveStopped { code } => write!(f, "receive side stopped: code={code}"),
            Self::ReceiveReset { code, final_size } => {
                write!(
                    f,
                    "receive side reset by peer: code={code}, final_size={final_size}"
                )
            }
            Self::InconsistentReset {
                previous_final_size,
                new_final_size,
            } => write!(
                f,
                "inconsistent reset final size: previous={previous_final_size}, new={new_final_size}"
            ),
            Self::OffsetOverflow { offset, len } => {
                write!(f, "stream offset overflow: offset={offset}, len={len}")
            }
            Self::SendFinished { final_size } => {
                write!(f, "stream send side finished: final_size={final_size}")
            }
        }
    }
}

impl std::error::Error for QuicStreamError {}

impl From<FlowControlError> for QuicStreamError {
    fn from(value: FlowControlError) -> Self {
        Self::Flow(value)
    }
}

/// Application STREAM frame payload ready for packet assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFramePayload {
    /// Stream carrying the payload.
    pub stream_id: StreamId,
    /// Absolute byte offset in the stream.
    pub offset: u64,
    /// Payload bytes.
    pub data: Bytes,
    /// Whether this frame carries FIN.
    pub fin: bool,
    /// Whether this frame was requeued after loss.
    pub retransmit: bool,
}

/// One edge-triggered notification that a QUIC stream can make receive-side
/// progress.
///
/// Notifications are ordered by [`StreamId`] for deterministic consumers. A
/// notification is consumed when returned by
/// [`StreamTable::take_next_readable_stream`]; callers should then drain the
/// reported stream with [`StreamTable::read_stream_bytes`]. If contiguous
/// bytes remain after a partial read, the table queues a fresh notification;
/// terminal FIN/RESET/receive-stop state is reported only on its original
/// edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamReadiness {
    /// Stream whose receive side changed.
    pub stream_id: StreamId,
    /// Contiguous bytes currently available from the application read offset.
    pub readable_bytes: u64,
    /// Whether a peer FIN has established the stream final size.
    pub fin_received: bool,
    /// Peer RESET_STREAM state `(application error code, final size)`.
    pub reset: Option<(u64, u64)>,
    /// Local STOP_RECEIVING application error code, when present.
    pub receive_stopped: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedStreamFrame {
    offset: u64,
    data: Bytes,
    fin: bool,
    retransmit: bool,
}

/// One contiguous receive range. Keep the original payload slices so joining
/// adjacent frames does not repeatedly copy an entire receive window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RecvRun {
    pieces: VecDeque<Bytes>,
    len: u64,
}

/// Payload-free projection used only when a packet could reach the run cap.
/// Its size depends on holes, never on the number of retained payload slices.
struct RecvPacketRuns {
    read_offset: u64,
    runs: Vec<(u64, u64)>,
    reset: bool,
}

impl RecvPacketRuns {
    fn insert(&mut self, offset: u64, end: u64) {
        if self.reset || offset == end || end <= self.read_offset {
            return;
        }
        let mut start = offset.max(self.read_offset);
        let mut end = end;
        let first = self
            .runs
            .partition_point(|&(_, known_end)| known_end < start);
        let mut last = first;
        while let Some(&(known_start, known_end)) = self.runs.get(last) {
            if known_start > end {
                break;
            }
            start = start.min(known_start);
            end = end.max(known_end);
            last += 1;
        }
        self.runs.splice(first..last, [(start, end)]);
    }

    fn exceeds(&self, limit: usize) -> bool {
        self.runs.len() > limit || self.out_of_order() > limit.saturating_sub(1)
    }

    /// Runs other than a readable one at the read offset.
    fn out_of_order(&self) -> usize {
        let head = self
            .runs
            .first()
            .is_some_and(|&(start, _)| start == self.read_offset);
        self.runs.len().saturating_sub(usize::from(head))
    }
}

/// Resident cost of one retained slice: its handle plus its own allocation.
/// A run whose slices cost more than the bytes they hold is joined into one.
const RECV_PIECE_OVERHEAD: u64 = 64;

/// The part `range` of a received frame that reassembly keeps. A whole frame
/// stays a zero-copy slice: `NativeQuicConnection::decode_frames_bytes` keeps
/// only frames that use at least a quarter of their datagram. A trimmed part is
/// copied, because a frame that mostly repeats bytes already received would
/// otherwise pin its whole datagram for its few new bytes. Every slice
/// reassembly stores then keeps at most four times its length resident; the
/// remainder a partial read leaves stays a slice until the application reads it.
fn recv_slice(data: &Bytes, range: std::ops::Range<usize>) -> Bytes {
    if range.len() == data.len() {
        data.clone()
    } else {
        Bytes::copy_from_slice(&data[range])
    }
}

impl RecvRun {
    fn push_back(&mut self, bytes: Bytes) {
        self.len += bytes.len() as u64;
        self.pieces.push_back(bytes);
        self.compact_if_fragmented();
    }

    /// A peer can split credited bytes into one-byte frames, in either order.
    /// Joining only when the slices outweigh their payload keeps large frames
    /// zero-copy and costs about `RECV_PIECE_OVERHEAD` copied bytes per tiny
    /// frame, amortized.
    fn compact_if_fragmented(&mut self) {
        let pieces = self.pieces.len() as u64;
        if pieces <= 1 || pieces.saturating_mul(RECV_PIECE_OVERHEAD) <= self.len {
            return;
        }
        let mut joined = BytesMut::with_capacity(usize::try_from(self.len).unwrap_or(0));
        for piece in self.pieces.drain(..) {
            joined.extend_from_slice(&piece);
        }
        self.pieces.push_back(joined.freeze());
    }

    fn append(&mut self, mut other: Self) {
        self.len += other.len;
        // Move the smaller set of slice handles. Prepending many individual
        // frames to a large run must remain amortized linear, just like append.
        if self.pieces.len() < other.pieces.len() {
            while let Some(piece) = self.pieces.pop_back() {
                other.pieces.push_front(piece);
            }
            self.pieces = other.pieces;
        } else {
            self.pieces.append(&mut other.pieces);
        }
        self.compact_if_fragmented();
    }

    fn read(&mut self, max_len: usize) -> Bytes {
        let Some(mut piece) = self.pieces.pop_front() else {
            return Bytes::new();
        };
        let n = piece.len().min(max_len);
        let out = piece.slice(..n);
        if n < piece.len() {
            self.pieces.push_front(piece.split_off(n));
        }
        self.len -= n as u64;
        out
    }
}

/// One stream's flow + offset state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicStream {
    /// Stream identifier.
    pub id: StreamId,
    /// Locally sent bytes.
    pub send_offset: u64,
    /// Received bytes accepted by reassembly.
    pub recv_offset: u64,
    /// Received bytes consumed by the application.
    pub read_offset: u64,
    /// Send-side flow credit.
    pub send_credit: FlowCredit,
    /// Receive-side flow credit.
    pub recv_credit: FlowCredit,
    /// Optional final size received via FIN/RESET.
    pub final_size: Option<u64>,
    /// Optional final size committed by a locally sent FIN.
    pub send_final_size: Option<u64>,
    /// Optional local reset state `(error_code, final_size)`.
    pub send_reset: Option<(u64, u64)>,
    /// Optional peer STOP_SENDING error code.
    pub stop_sending_error_code: Option<u64>,
    /// Optional local receive-stop error code.
    pub receive_stopped_error_code: Option<u64>,
    /// Optional peer reset state `(error_code, final_size)`.
    pub recv_reset: Option<(u64, u64)>,
    /// Whether the receive-readiness consumer observed the peer reset.
    /// The sticky reset state must not produce another edge when duplicate
    /// RESET_STREAM, late STREAM, or local receive-stop traffic arrives.
    reset_readiness_delivered: bool,
    /// Up to one QUIC-varint prefix retained across RESET_STREAM so an
    /// application protocol can classify an already-buffered unidirectional
    /// stream before treating a critical-stream reset as fatal.
    reset_buffered_prefix: Bytes,
    /// Buffered receive ranges keyed by start offset, value = exclusive end.
    recv_ranges: BTreeMap<u64, u64>,
    /// Nonempty, disjoint receive runs keyed by absolute stream offset.
    /// Adjacent runs are merged, so each node after the readable head represents
    /// a hole rather than another packet's payload slice.
    recv_chunks: BTreeMap<u64, RecvRun>,
    /// Bounded receive-window size for this stream. `None` keeps the historic
    /// unbounded-credit behavior; `Some(w)` makes the local receive limit track
    /// `read_offset + w` and drives MAX_STREAM_DATA advertisements so the peer
    /// can never buffer more than ~`w` un-read bytes into `recv_chunks`.
    recv_window_bytes: Option<u64>,
    /// Highest receive limit advertised to the peer via MAX_STREAM_DATA (or the
    /// initial window at configure time). Only meaningful when
    /// `recv_window_bytes` is `Some`.
    recv_limit_advertised: u64,
    /// Ceiling for sender-gated growth of `recv_window_bytes`
    /// ([`StreamTable::note_peer_stream_data_blocked`]); `None` or a value at
    /// or below the current window keeps the window fixed.
    recv_window_max_bytes: Option<u64>,
    /// Reassembly-fragment budget used to veto growth on a holey stream
    /// (0 disables the veto). Growth stops once a quarter of it is buffered.
    recv_window_fragment_ceiling: usize,
    /// `read_offset` when the bounded window was configured or last grew:
    /// growth requires one full window consumed since then.
    recv_window_grown_at_read_offset: u64,
    /// STREAM frames queued for packet assembly.
    pending_send_frames: VecDeque<QueuedStreamFrame>,
    /// STREAM frames emitted at least once and available for retransmission.
    sent_stream_frames: BTreeMap<u64, QueuedStreamFrame>,
}

impl QuicStream {
    fn new(id: StreamId, send_window: u64, recv_window: u64) -> Self {
        Self {
            id,
            send_offset: 0,
            recv_offset: 0,
            read_offset: 0,
            send_credit: FlowCredit::new(send_window),
            recv_credit: FlowCredit::new(recv_window),
            final_size: None,
            send_final_size: None,
            send_reset: None,
            stop_sending_error_code: None,
            receive_stopped_error_code: None,
            recv_reset: None,
            reset_readiness_delivered: false,
            reset_buffered_prefix: Bytes::new(),
            recv_ranges: BTreeMap::new(),
            recv_chunks: BTreeMap::new(),
            recv_window_bytes: None,
            recv_limit_advertised: 0,
            recv_window_max_bytes: None,
            recv_window_fragment_ceiling: 0,
            recv_window_grown_at_read_offset: 0,
            pending_send_frames: VecDeque::new(),
            sent_stream_frames: BTreeMap::new(),
        }
    }

    /// Account bytes written to this stream.
    pub fn write(&mut self, len: u64) -> Result<(), QuicStreamError> {
        self.ensure_can_send(len)?;
        self.send_credit.consume(len)?;
        self.send_offset = self.send_offset.saturating_add(len);
        Ok(())
    }

    /// Queue application bytes for STREAM frame emission.
    pub fn write_bytes(&mut self, data: Bytes, fin: bool) -> Result<(), QuicStreamError> {
        let len = data.len() as u64;
        self.ensure_can_send(len)?;
        self.send_credit.consume(len)?;
        let offset = self.send_offset;
        self.send_offset = self.send_offset.saturating_add(len);
        if fin {
            self.send_final_size = Some(self.send_offset);
        }
        if len > 0 || fin {
            self.pending_send_frames.push_back(QueuedStreamFrame {
                offset,
                data,
                fin,
                retransmit: false,
            });
        }
        Ok(())
    }

    /// Queue a FIN without additional bytes.
    pub fn finish_send(&mut self) -> Result<(), QuicStreamError> {
        self.write_bytes(Bytes::new(), true)
    }

    fn ensure_can_send(&self, len: u64) -> Result<(), QuicStreamError> {
        if let Some(code) = self.stop_sending_error_code {
            return Err(QuicStreamError::SendStopped { code });
        }
        // RFC 9000 §3.1: after issuing RESET_STREAM, no further STREAM frames.
        if let Some((code, _)) = self.send_reset {
            return Err(QuicStreamError::SendStopped { code });
        }
        if let Some(final_size) = self.send_final_size {
            return Err(QuicStreamError::SendFinished { final_size });
        }
        self.send_credit.can_consume(len)?;
        Ok(())
    }

    /// Account bytes received on this stream.
    pub fn receive(&mut self, len: u64) -> Result<(), QuicStreamError> {
        let _ = self.receive_segment(self.recv_offset, len, false)?;
        Ok(())
    }

    /// Account bytes received on this stream at a specific offset.
    ///
    /// Returns the receive-window delta newly consumed by this segment.
    pub fn receive_segment(
        &mut self,
        offset: u64,
        len: u64,
        is_fin: bool,
    ) -> Result<u64, QuicStreamError> {
        // RFC 9000 §3.2 / §3.5: STREAM data that arrives after RESET_STREAM,
        // or after this side sent STOP_SENDING (the peer may keep sending
        // until it processes it), is discarded. Reordered data must still
        // respect flow control and the established final size; a FIN must
        // agree with that final size. Otherwise ordinary reordering is not
        // an error for this packet or its other coalesced frames.
        if let Some((_, final_size)) = self.recv_reset {
            let end = offset
                .checked_add(len)
                .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
            if end > final_size {
                return Err(QuicStreamError::InvalidFinalSize {
                    final_size,
                    received: end,
                });
            }
            if is_fin && end != final_size {
                return Err(QuicStreamError::InvalidFinalSize {
                    final_size: end,
                    received: final_size,
                });
            }
            return Ok(0);
        }
        let end = self.validate_receive_segment(offset, len, is_fin)?;
        let flow_delta = self.recv_credit.consume_to(end)?;
        if is_fin {
            if let Err(err) = self.set_final_size(end) {
                self.recv_credit.release(flow_delta);
                return Err(err);
            }
        }
        if len > 0 && self.receive_stopped_error_code.is_none() {
            self.insert_recv_range(offset, end);
            self.advance_contiguous_recv_offset();
        }
        Ok(flow_delta)
    }

    fn validate_receive_segment(
        &self,
        offset: u64,
        len: u64,
        is_fin: bool,
    ) -> Result<u64, QuicStreamError> {
        // A reset receive side is checked against its final size separately.
        // A locally stopped side still validates and accounts late peer bytes
        // before discarding their payload.
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        if let Some(final_size) = self.final_size
            && end > final_size
        {
            return Err(QuicStreamError::InvalidFinalSize {
                final_size,
                received: end,
            });
        }
        let prior_used = self.recv_credit.used();
        self.recv_credit
            .can_consume(end.saturating_sub(prior_used))?;
        if is_fin {
            let highest_observed = prior_used.max(end);
            if end < highest_observed || self.final_size.is_some_and(|existing| existing != end) {
                return Err(QuicStreamError::InvalidFinalSize {
                    final_size: end,
                    received: highest_observed,
                });
            }
        }
        Ok(end)
    }

    /// Receive bytes on this stream at an explicit offset.
    ///
    /// Returns the receive-window delta newly consumed by this segment.
    pub fn receive_bytes(
        &mut self,
        offset: u64,
        data: Bytes,
        is_fin: bool,
    ) -> Result<u64, QuicStreamError> {
        let len = data.len() as u64;
        let flow_delta = self.receive_segment(offset, len, is_fin)?;
        // Terminal receives still pass final-size/flow validation above, but
        // their discarded payload must never repopulate the reassembly queue.
        if len > 0 && self.recv_reset.is_none() && self.receive_stopped_error_code.is_none() {
            self.insert_recv_bytes(offset, data)?;
        }
        Ok(flow_delta)
    }

    /// Read contiguous bytes already reassembled for the application.
    #[must_use]
    pub fn read_bytes(&mut self, max_len: usize) -> Bytes {
        if max_len == 0 {
            return Bytes::new();
        }
        let Some(mut run) = self.recv_chunks.remove(&self.read_offset) else {
            return Bytes::new();
        };
        let out = run.read(max_len);
        self.read_offset = self.read_offset.saturating_add(out.len() as u64);
        if run.len > 0 {
            self.recv_chunks.insert(self.read_offset, run);
        }
        out
    }

    /// Whether this stream has reached application EOF.
    #[must_use]
    pub fn is_read_eof(&self) -> bool {
        self.recv_reset.is_none() && self.final_size == Some(self.read_offset)
    }

    /// Contiguous payload bytes actually buffered at the application read offset.
    #[must_use]
    fn readable_bytes(&self) -> u64 {
        self.recv_chunks
            .get(&self.read_offset)
            .map_or(0, |run| run.len)
    }

    /// Whether packet assembly has STREAM frames waiting for this stream.
    #[must_use]
    pub fn has_pending_stream_frames(&self) -> bool {
        !self.pending_send_frames.is_empty()
    }

    /// Number of STREAM frames waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_frame_count(&self) -> usize {
        self.pending_send_frames.len()
    }

    /// Queued STREAM payload bytes waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_data_bytes(&self) -> u64 {
        self.pending_send_frames.iter().fold(0u64, |acc, frame| {
            acc.saturating_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX))
        })
    }

    /// Pop the next queued STREAM frame, splitting it to `max_data_len`.
    pub fn pop_pending_stream_frame(&mut self, max_data_len: usize) -> Option<StreamFramePayload> {
        let mut frame = self.pending_send_frames.pop_front()?;
        if max_data_len == 0 && !frame.data.is_empty() {
            self.pending_send_frames.push_front(frame);
            return None;
        }
        if frame.data.len() > max_data_len {
            let tail = frame.data.slice(max_data_len..);
            let tail_offset = frame.offset.saturating_add(max_data_len as u64);
            self.pending_send_frames.push_front(QueuedStreamFrame {
                offset: tail_offset,
                data: tail,
                fin: frame.fin,
                retransmit: frame.retransmit,
            });
            frame.data = frame.data.slice(..max_data_len);
            frame.fin = false;
        } else if frame.retransmit && !frame.fin {
            // Coalesce contiguous queued RETRANSMIT frames into one wire
            // frame. Loss requeues the ORIGINAL emission's frame boundaries,
            // and recovery bandwidth collapses when each retransmit packet
            // carries hundreds of tiny frames (each paying its own frame
            // header) — one loss event then stalls the stream for seconds.
            // The bounded copy below (at most one wire frame) is far
            // cheaper. First-emission frames are already written at
            // near-wire size and are left untouched.
            let mut merged: Option<BytesMut> = None;
            let mut merged_fin = false;
            loop {
                let merged_len = merged.as_ref().map_or(frame.data.len(), BytesMut::len);
                let room = max_data_len.saturating_sub(merged_len);
                if room == 0 || merged_fin {
                    break;
                }
                let contiguous_end = frame
                    .offset
                    .saturating_add(u64::try_from(merged_len).unwrap_or(u64::MAX));
                let Some(next) = self.pending_send_frames.front() else {
                    break;
                };
                if !next.retransmit || next.offset != contiguous_end {
                    break;
                }
                let next = self
                    .pending_send_frames
                    .pop_front()
                    .expect("front checked above");
                // Drop the absorbed frame's stale retained copy: its bytes are
                // now carried by the merged frame at `frame.offset`, so a later
                // loss of the merged frame re-sends this range via
                // `requeue_sent_stream_frame(frame.offset)`. Without this,
                // `release_sent_stream_frame` (keyed by the emitted offset) can
                // only ever release `frame.offset`, so every merged-in sub-frame
                // leaks its `sent_stream_frames` entry — and the source `Bytes`
                // it pins — for the connection's lifetime, defeating the bound
                // this map was added to enforce (sender RSS then scales with the
                // number of coalescing events on lossy transfers). In the
                // partial-merge branch below, the un-absorbed remainder is
                // requeued at a fresh offset and gets its own entry when emitted,
                // so this removal is correct for both full and partial merges.
                self.sent_stream_frames.remove(&next.offset);
                let buf = merged.get_or_insert_with(|| {
                    let mut buf = BytesMut::with_capacity(max_data_len);
                    buf.extend_from_slice(&frame.data);
                    buf
                });
                if next.data.len() <= room {
                    buf.extend_from_slice(&next.data);
                    merged_fin = next.fin;
                } else {
                    buf.extend_from_slice(&next.data.slice(..room));
                    self.pending_send_frames.push_front(QueuedStreamFrame {
                        offset: next.offset.saturating_add(room as u64),
                        data: next.data.slice(room..),
                        fin: next.fin,
                        retransmit: true,
                    });
                    break;
                }
            }
            if let Some(buf) = merged {
                frame.data = buf.freeze();
                frame.fin = merged_fin;
            }
        }
        self.sent_stream_frames.insert(frame.offset, frame.clone());
        Some(StreamFramePayload {
            stream_id: self.id,
            offset: frame.offset,
            data: frame.data,
            fin: frame.fin,
            retransmit: frame.retransmit,
        })
    }

    /// Put a popped STREAM frame back when packet assembly did not emit it.
    pub fn requeue_unemitted_stream_frame(&mut self, payload: StreamFramePayload) {
        debug_assert_eq!(payload.stream_id, self.id);
        if !payload.retransmit {
            self.sent_stream_frames.remove(&payload.offset);
        }
        self.pending_send_frames.push_front(QueuedStreamFrame {
            offset: payload.offset,
            data: payload.data,
            fin: payload.fin,
            retransmit: payload.retransmit,
        });
    }

    /// Requeue a previously emitted STREAM frame after packet loss.
    ///
    /// An offset whose retained copy was already released by
    /// [`Self::release_sent_stream_frame`] is a no-op: release happens only
    /// on acknowledgment, so the peer has the data and a retransmission
    /// would be redundant (an ack-gap loss judgment can race a late ACK for
    /// the same offset carried by another in-flight packet).
    pub fn requeue_sent_stream_frame(&mut self, offset: u64) -> Result<(), QuicStreamError> {
        let Some(frame) = self.sent_stream_frames.get(&offset).cloned() else {
            return Ok(());
        };
        if self
            .pending_send_frames
            .iter()
            .any(|pending| pending.retransmit && pending.offset == offset)
        {
            return Ok(());
        }
        self.pending_send_frames.push_front(QueuedStreamFrame {
            retransmit: true,
            ..frame
        });
        Ok(())
    }

    /// Release the retained retransmission copy of an acknowledged frame.
    ///
    /// Without this, `sent_stream_frames` pins every sent payload for the
    /// stream's lifetime and sender memory scales with the transfer size.
    /// Unknown offsets are ignored (duplicate ACKs, already-released frames).
    pub fn release_sent_stream_frame(&mut self, offset: u64) {
        self.sent_stream_frames.remove(&offset);
    }

    /// Release a retained copy only when it still represents the exact wire
    /// frame being acknowledged.
    ///
    /// A retransmission may coalesce more bytes at the same starting offset.
    /// A late ACK for the older, shorter frame must not release that newer
    /// superset or its unacknowledged tail would become unrecoverable.
    fn release_sent_stream_frame_if_matches(&mut self, offset: u64, data_len: usize, fin: bool) {
        let matches = self
            .sent_stream_frames
            .get(&offset)
            .is_some_and(|frame| frame.data.len() == data_len && frame.fin == fin);
        if matches {
            self.sent_stream_frames.remove(&offset);
        }
    }

    /// Set final size from FIN/RESET.
    pub fn set_final_size(&mut self, final_size: u64) -> Result<(), QuicStreamError> {
        let highest_observed = self.recv_credit.used();
        if final_size < highest_observed {
            return Err(QuicStreamError::InvalidFinalSize {
                final_size,
                received: highest_observed,
            });
        }
        if let Some(existing) = self.final_size
            && existing != final_size
        {
            return Err(QuicStreamError::InvalidFinalSize {
                final_size,
                received: highest_observed,
            });
        }
        self.final_size = Some(final_size);
        Ok(())
    }

    /// Apply a peer `STOP_SENDING` signal.
    pub fn on_stop_sending(&mut self, error_code: u64) {
        self.stop_sending_error_code.get_or_insert(error_code);
    }

    /// Locally stop receiving this stream.
    pub fn stop_receiving(&mut self, error_code: u64) {
        self.receive_stopped_error_code = Some(error_code);
        // Retain offsets, credit and the final size for transport accounting;
        // the application can no longer consume any retained payload.
        self.recv_ranges.clear();
        self.recv_chunks.clear();
    }

    /// Apply a peer RESET_STREAM to this stream's receive side.
    pub fn reset_receive(
        &mut self,
        error_code: u64,
        final_size: u64,
    ) -> Result<u64, QuicStreamError> {
        if let Some((_, previous_final_size)) = self.recv_reset
            && previous_final_size != final_size
        {
            return Err(QuicStreamError::InconsistentReset {
                previous_final_size,
                new_final_size: final_size,
            });
        }
        let flow_delta = self.recv_credit.consume_to(final_size)?;
        if let Err(err) = self.set_final_size(final_size) {
            self.recv_credit.release(flow_delta);
            return Err(err);
        }
        if self.recv_reset.is_none() {
            let mut prefix = BytesMut::with_capacity(8);
            if let Some(run) = self.recv_chunks.get(&self.read_offset) {
                for piece in &run.pieces {
                    let take = piece.len().min(8usize.saturating_sub(prefix.len()));
                    prefix.extend_from_slice(&piece[..take]);
                    if prefix.len() == 8 {
                        break;
                    }
                }
            }
            self.reset_buffered_prefix = prefix.freeze();
        }
        self.recv_reset.get_or_insert((error_code, final_size));
        self.recv_ranges.clear();
        self.recv_chunks.clear();
        Ok(flow_delta)
    }

    /// Buffered prefix retained when peer RESET_STREAM discarded receive data.
    #[must_use]
    pub fn reset_buffered_prefix(&self) -> Bytes {
        self.reset_buffered_prefix.clone()
    }

    /// Locally reset the send side (`RESET_STREAM`).
    ///
    /// `final_size` must equal the bytes this side has sent: RFC 9000
    /// section 4.5 makes it the flow-control credit the stream consumed.
    pub fn reset_send(&mut self, error_code: u64, final_size: u64) -> Result<(), QuicStreamError> {
        if final_size < self.send_offset {
            return Err(QuicStreamError::InvalidFinalSize {
                final_size,
                received: self.send_offset,
            });
        }
        if let Some((_, previous_final_size)) = self.send_reset
            && previous_final_size != final_size
        {
            return Err(QuicStreamError::InconsistentReset {
                previous_final_size,
                new_final_size: final_size,
            });
        }
        // A larger final size would charge the peer's flow control for bytes
        // never sent, and can exceed its limit (br-asupersync-tzjbn9 F8).
        if final_size > self.send_offset {
            return Err(QuicStreamError::InvalidFinalSize {
                final_size,
                received: self.send_offset,
            });
        }
        self.send_reset = Some((error_code, final_size));
        // RFC 9000 section 3.1: once RESET_STREAM is issued, the endpoint MUST
        // NOT send further STREAM frames for this send side. Drop both queued
        // first-transmission bytes and retained retransmission copies so the
        // packet assembler cannot emit data after the reset control frame.
        self.pending_send_frames.clear();
        self.sent_stream_frames.clear();
        Ok(())
    }

    fn insert_recv_range(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut merged_start = start;
        let mut merged_end = end;

        if let Some((&prev_start, &prev_end)) = self.recv_ranges.range(..=start).next_back()
            && prev_end >= start
        {
            merged_start = prev_start.min(merged_start);
            merged_end = prev_end.max(merged_end);
        }

        let overlapping_keys: Vec<u64> = self
            .recv_ranges
            .range(merged_start..=merged_end)
            .filter_map(|(&range_start, &range_end)| {
                if range_start <= merged_end && range_end >= merged_start {
                    Some(range_start)
                } else {
                    None
                }
            })
            .collect();

        for key in overlapping_keys {
            if let Some(existing_end) = self.recv_ranges.remove(&key) {
                merged_start = merged_start.min(key);
                merged_end = merged_end.max(existing_end);
            }
        }

        self.recv_ranges.insert(merged_start, merged_end);
    }

    fn advance_contiguous_recv_offset(&mut self) {
        while let Some((&start, &end)) = self.recv_ranges.first_key_value() {
            if start > self.recv_offset {
                break;
            }
            self.recv_ranges.remove(&start);
            if end > self.recv_offset {
                self.recv_offset = end;
            }
        }
    }

    fn insert_recv_bytes(&mut self, offset: u64, data: Bytes) -> Result<(), QuicStreamError> {
        let len = data.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        if end <= self.read_offset {
            return Ok(());
        }

        let mut cursor = offset.max(self.read_offset);
        let mut data_cursor = cursor.saturating_sub(offset) as usize;
        let overlapping: Vec<(u64, u64)> = self
            .recv_chunks
            .range(self.recv_run_range_start(cursor)..end)
            .filter_map(|(&start, run)| {
                let chunk_end = start.saturating_add(run.len);
                if chunk_end > cursor && start < end {
                    Some((start, chunk_end))
                } else {
                    None
                }
            })
            .collect();

        for (known_start, known_end) in overlapping {
            if cursor < known_start {
                let gap_len = (known_start - cursor) as usize;
                self.insert_recv_gap(
                    cursor,
                    recv_slice(&data, data_cursor..data_cursor + gap_len),
                );
                cursor = known_start;
                data_cursor += gap_len;
            }
            if known_end > cursor {
                let skip = (known_end - cursor) as usize;
                cursor = known_end;
                data_cursor = data_cursor.saturating_add(skip);
            }
        }

        if cursor < end {
            let tail_len = (end - cursor) as usize;
            self.insert_recv_gap(
                cursor,
                recv_slice(&data, data_cursor..data_cursor + tail_len),
            );
        }
        Ok(())
    }

    /// Include at most one predecessor that overlaps or abuts this offset.
    /// Older runs cannot participate, so neither insertion nor admission needs
    /// to scan the already-buffered prefix of a large stream.
    fn recv_run_range_start(&self, offset: u64) -> u64 {
        self.recv_chunks
            .range(..=offset)
            .next_back()
            .filter(|(start, run)| start.saturating_add(run.len) >= offset)
            .map_or(offset, |(&start, _)| start)
    }

    /// Insert a nonempty, previously uncovered slice and join its neighbors.
    fn insert_recv_gap(&mut self, offset: u64, data: Bytes) {
        let end = offset + data.len() as u64;
        let start = self.recv_run_range_start(offset);
        let mut run = self.recv_chunks.remove(&start).unwrap_or_default();
        run.push_back(data);
        if let Some(successor) = self.recv_chunks.remove(&end) {
            run.append(successor);
        }
        self.recv_chunks.insert(start, run);
    }

    fn projected_recv_chunk_count(&self, offset: u64, len: u64) -> Result<usize, QuicStreamError> {
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        if len == 0 || end <= self.read_offset {
            return Ok(self.recv_chunks.len());
        }

        let start = self.recv_run_range_start(offset.max(self.read_offset));
        // The incoming interval connects every intersecting or adjacent run
        // into one. A bridge may reduce the count, which an unsigned
        // "additional fragments" estimate cannot represent.
        let merged = self.recv_chunks.range(start..=end).count();
        Ok(self.recv_chunks.len() - merged + 1)
    }

    /// Buffered receive runs other than a readable one at the read offset.
    fn out_of_order_recv_runs(&self) -> usize {
        self.recv_chunks.len() - usize::from(self.recv_chunks.contains_key(&self.read_offset))
    }
}

/// Stream table errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTableError {
    /// Stream ID already exists.
    DuplicateStream(StreamId),
    /// Stream ID not found.
    UnknownStream(StreamId),
    /// Stream ID is locally initiated and cannot be accepted as remote.
    InvalidRemoteStream(StreamId),
    /// Stream is not writable (e.g. remote unidirectional stream).
    StreamNotWritable(StreamId),
    /// Stream is not readable (e.g. local unidirectional stream).
    StreamNotReadable(StreamId),
    /// Stream limit exceeded.
    StreamLimitExceeded {
        /// Direction that hit the limit.
        direction: StreamDirection,
        /// Configured limit.
        limit: u64,
    },
    /// Stream-level protocol or flow-control error.
    Stream(QuicStreamError),
}

impl fmt::Display for StreamTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateStream(id) => write!(f, "duplicate stream: {}", id.0),
            Self::UnknownStream(id) => write!(f, "unknown stream: {}", id.0),
            Self::InvalidRemoteStream(id) => {
                write!(f, "invalid remote stream id (locally initiated): {}", id.0)
            }
            Self::StreamNotWritable(id) => write!(f, "stream not writable: {}", id.0),
            Self::StreamNotReadable(id) => write!(f, "stream not readable: {}", id.0),
            Self::StreamLimitExceeded { direction, limit } => {
                write!(f, "stream limit exceeded for {direction:?}: {limit}")
            }
            Self::Stream(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for StreamTableError {}

impl From<QuicStreamError> for StreamTableError {
    fn from(value: QuicStreamError) -> Self {
        Self::Stream(value)
    }
}

/// Initial per-stream flow-control windows keyed by stream type (RFC 9000 §18.2).
///
/// `local_bidi` applies to bidirectional streams this endpoint opens,
/// `remote_bidi` to bidirectional streams the peer opens, and `uni` to the
/// single data-carrying direction of unidirectional streams. The same shape
/// describes both sides of a connection:
///
/// - send windows come from the peer's transport parameters: a locally opened
///   bidirectional stream may send `initial_max_stream_data_bidi_remote` bytes
///   (it is remote from the peer's point of view), a peer-opened bidirectional
///   stream may send `initial_max_stream_data_bidi_local`, and a locally opened
///   unidirectional stream may send `initial_max_stream_data_uni`;
/// - receive windows come from this endpoint's own parameters with the
///   mirrored mapping: `bidi_local` for locally opened, `bidi_remote` for
///   peer-opened, `uni` for peer-opened unidirectional streams.
///
/// A parameter the peer omits is zero for that stream type only; it never
/// lowers the window of another type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamWindows {
    /// Window for bidirectional streams this endpoint opened.
    pub local_bidi: u64,
    /// Window for bidirectional streams the peer opened.
    pub remote_bidi: u64,
    /// Window for the data-carrying direction of unidirectional streams.
    pub uni: u64,
}

impl StreamWindows {
    /// The same window for every stream type.
    #[must_use]
    pub const fn uniform(window: u64) -> Self {
        Self {
            local_bidi: window,
            remote_bidi: window,
            uni: window,
        }
    }
}

/// Stream table with local-open limits.
#[derive(Debug, Clone)]
pub struct StreamTable {
    role: StreamRole,
    max_local_bidi: u64,
    max_local_uni: u64,
    /// Maximum number of remotely-initiated bidirectional streams this endpoint
    /// will accept (RFC 9000 §4.6 `MAX_STREAMS`). Defaults to `u64::MAX` so
    /// callers that do not opt into a finite cap keep the prior unbounded
    /// behavior; install a finite bound with [`Self::set_remote_stream_limits`].
    max_remote_bidi: u64,
    /// Maximum number of remotely-initiated unidirectional streams this endpoint
    /// will accept (RFC 9000 §4.6 `MAX_STREAMS`). See [`Self::max_remote_bidi`].
    max_remote_uni: u64,
    next_local_bidi_seq: u64,
    next_local_uni_seq: u64,
    streams: BTreeMap<StreamId, QuicStream>,
    /// Initial send windows per stream type (peer-advertised).
    send_windows: StreamWindows,
    /// Initial receive windows per stream type (locally advertised).
    recv_windows: StreamWindows,
    send_connection_credit: FlowCredit,
    recv_connection_credit: FlowCredit,
    rr_cursor: Option<StreamId>,
    readable_streams: std::collections::BTreeSet<StreamId>,
    readable_stream_waker: Option<Waker>,
    read_wakers: BTreeMap<StreamId, Waker>,
    write_wakers: BTreeMap<StreamId, Waker>,
}

impl StreamTable {
    /// Create a new stream table.
    #[must_use]
    pub fn new(
        role: StreamRole,
        max_local_bidi: u64,
        max_local_uni: u64,
        send_window: u64,
        recv_window: u64,
    ) -> Self {
        Self::new_with_connection_limits(
            role,
            max_local_bidi,
            max_local_uni,
            send_window,
            recv_window,
            u64::MAX,
            u64::MAX,
        )
    }

    /// Create a new stream table with explicit connection-level limits.
    #[must_use]
    pub fn new_with_connection_limits(
        role: StreamRole,
        max_local_bidi: u64,
        max_local_uni: u64,
        send_window: u64,
        recv_window: u64,
        connection_send_limit: u64,
        connection_recv_limit: u64,
    ) -> Self {
        Self {
            role,
            max_local_bidi,
            max_local_uni,
            // Unbounded by default; the connection layer installs a finite cap so
            // a peer cannot force unbounded remote-stream allocations from the
            // wire (see `set_remote_stream_limits`).
            max_remote_bidi: u64::MAX,
            max_remote_uni: u64::MAX,
            next_local_bidi_seq: 0,
            next_local_uni_seq: 0,
            streams: BTreeMap::new(),
            send_windows: StreamWindows::uniform(send_window),
            recv_windows: StreamWindows::uniform(recv_window),
            send_connection_credit: FlowCredit::new(connection_send_limit),
            recv_connection_credit: FlowCredit::new(connection_recv_limit),
            rr_cursor: None,
            readable_streams: std::collections::BTreeSet::new(),
            readable_stream_waker: None,
            read_wakers: BTreeMap::new(),
            write_wakers: BTreeMap::new(),
        }
    }

    /// Open next local bidirectional stream.
    pub fn open_local_bidi(&mut self) -> Result<StreamId, StreamTableError> {
        if self.next_local_bidi_seq >= self.max_local_bidi {
            return Err(StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Bidirectional,
                limit: self.max_local_bidi,
            });
        }
        let id = StreamId::local(
            self.role,
            StreamDirection::Bidirectional,
            self.next_local_bidi_seq,
        );
        self.next_local_bidi_seq += 1;
        self.insert_new_stream(id)?;
        Ok(id)
    }

    /// Open next local unidirectional stream.
    pub fn open_local_uni(&mut self) -> Result<StreamId, StreamTableError> {
        if self.next_local_uni_seq >= self.max_local_uni {
            return Err(StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                limit: self.max_local_uni,
            });
        }
        let id = StreamId::local(
            self.role,
            StreamDirection::Unidirectional,
            self.next_local_uni_seq,
        );
        self.next_local_uni_seq += 1;
        self.insert_new_stream(id)?;
        Ok(id)
    }

    /// Apply an already validated peer MAX_STREAMS limit. Limits count all
    /// streams opened in a direction over the connection's lifetime, including
    /// closed streams; a new grant never resets the next stream sequence.
    pub(crate) fn increase_local_stream_limit(
        &mut self,
        direction: StreamDirection,
        maximum_streams: u64,
    ) {
        let limit = match direction {
            StreamDirection::Bidirectional => &mut self.max_local_bidi,
            StreamDirection::Unidirectional => &mut self.max_local_uni,
        };
        // Reordered and retransmitted grants cannot revoke credit already
        // received (RFC 9000 sections 4.6 and 19.11).
        *limit = (*limit).max(maximum_streams);
    }

    /// Set the maximum number of remotely-initiated streams (per direction) this
    /// endpoint will accept from the wire (RFC 9000 §4.6 `MAX_STREAMS`).
    ///
    /// A remote stream whose sequence index meets or exceeds the limit for its
    /// direction is rejected by [`Self::accept_remote_stream`] with
    /// [`StreamTableError::StreamLimitExceeded`], bounding memory against a peer
    /// that opens unbounded streams.
    pub fn set_remote_stream_limits(&mut self, max_remote_bidi: u64, max_remote_uni: u64) {
        self.max_remote_bidi = max_remote_bidi;
        self.max_remote_uni = max_remote_uni;
    }

    /// Current remotely-initiated stream limits advertised by this endpoint.
    #[must_use]
    pub fn remote_stream_limits(&self) -> (u64, u64) {
        (self.max_remote_bidi, self.max_remote_uni)
    }

    /// Install the per-type initial stream windows negotiated in the transport
    /// parameters (RFC 9000 §18.2).
    ///
    /// `send` holds the windows the peer advertised and `recv` the windows this
    /// endpoint advertised; see [`StreamWindows`] for the type mapping. Streams
    /// opened or accepted afterwards start with the window for their type;
    /// streams that already exist keep their credit.
    pub fn set_initial_stream_windows(&mut self, send: StreamWindows, recv: StreamWindows) {
        self.send_windows = send;
        self.recv_windows = recv;
    }

    /// Initial send windows applied to newly opened or accepted streams.
    #[must_use]
    pub fn initial_send_windows(&self) -> StreamWindows {
        self.send_windows
    }

    /// Initial receive windows applied to newly opened or accepted streams.
    #[must_use]
    pub fn initial_recv_windows(&self) -> StreamWindows {
        self.recv_windows
    }

    /// Accept a remotely initiated stream ID.
    pub fn accept_remote_stream(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        if id.is_local_for(self.role) {
            return Err(StreamTableError::InvalidRemoteStream(id));
        }
        // RFC 9000 §4.6: a remote stream of sequence index N requires the peer
        // to have been granted at least N+1 streams of that type. Reject any
        // stream at or beyond the advertised limit so a hostile peer cannot
        // force unbounded `QuicStream` allocations from the wire (one allocation
        // per STREAM/RESET_STREAM frame carrying a fresh remote ID) — a
        // memory-exhaustion DoS. The two low bits of the ID are the type, so the
        // 62-bit sequence index is `id.0 >> 2`.
        let sequence = id.0 >> 2;
        let direction = id.direction();
        let limit = match direction {
            StreamDirection::Bidirectional => self.max_remote_bidi,
            StreamDirection::Unidirectional => self.max_remote_uni,
        };
        if sequence >= limit {
            return Err(StreamTableError::StreamLimitExceeded { direction, limit });
        }
        self.insert_new_stream(id)
    }

    /// Convert `id` into a bounded receive-window stream, accepting it as a
    /// remote stream first when it is not open yet.
    ///
    /// The window is advisory-but-honored: this endpoint advertises
    /// `read_offset + window` via MAX_STREAM_DATA (the caller owns putting the
    /// advertisement on the wire) and a compliant sender installs the same
    /// value as its initial send-credit limit, bounding its un-read bytes —
    /// and therefore this endpoint's reassembly memory — to roughly one
    /// window. The local receive-credit enforcement limit is deliberately NOT
    /// lowered, so a peer that predates bounded windows keeps the historic
    /// unbounded behavior instead of failing the transfer.
    pub fn configure_stream_recv_window(
        &mut self,
        id: StreamId,
        window: u64,
    ) -> Result<u64, StreamTableError> {
        if window > VARINT_MAX {
            return Err(StreamTableError::Stream(QuicStreamError::OffsetOverflow {
                offset: 0,
                len: window,
            }));
        }
        if !self.streams.contains_key(&id) {
            self.accept_remote_stream(id)?;
        }
        let stream = self.stream_mut(id)?;
        let requested = stream
            .read_offset
            .checked_add(window)
            .filter(|limit| *limit <= VARINT_MAX)
            .ok_or(StreamTableError::Stream(QuicStreamError::OffsetOverflow {
                offset: stream.read_offset,
                len: window,
            }))?;
        let advertised = requested.max(stream.recv_limit_advertised);
        if advertised > stream.recv_credit.limit() {
            stream
                .recv_credit
                .increase_limit(advertised)
                .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        }
        stream.recv_window_bytes = Some(window);
        stream.recv_limit_advertised = advertised;
        stream.recv_window_grown_at_read_offset = stream.read_offset;
        Ok(advertised)
    }

    /// Let the bounded receive window on `id` grow up to `max_window` bytes
    /// through [`Self::note_peer_stream_data_blocked`]. A cap at or below the
    /// current window disables growth; an unbounded stream never grows.
    pub fn allow_stream_recv_window_growth(
        &mut self,
        id: StreamId,
        max_window: u64,
        fragment_ceiling: usize,
    ) -> Result<(), StreamTableError> {
        let stream = self.stream_mut(id)?;
        stream.recv_window_max_bytes = Some(max_window.min(VARINT_MAX));
        stream.recv_window_fragment_ceiling = fragment_ceiling;
        Ok(())
    }

    /// Current bounded receive window of `id` (`None` = unbounded).
    pub fn stream_recv_window_bytes(&self, id: StreamId) -> Result<Option<u64>, StreamTableError> {
        Ok(self.stream(id)?.recv_window_bytes)
    }

    /// Connection receive bytes consumed by reads or terminal discard.
    ///
    /// Unread bytes and holes on a live stream do not replenish connection
    /// credit. A reset or local receive stop discards its retained payload,
    /// releasing the stream's validated receive high-water mark. Late bytes
    /// after a local stop count only when transport accounting accepts their
    /// byte range or final size; this never grants credit from unvalidated
    /// wire offsets.
    #[cfg(any(
        test,
        all(feature = "http3", feature = "tls", not(target_arch = "wasm32"))
    ))]
    pub(crate) fn consumed_connection_receive_bytes(&self) -> u64 {
        self.streams
            .values()
            .fold(0_u64, |consumed, stream| {
                let released =
                    if stream.recv_reset.is_some() || stream.receive_stopped_error_code.is_some() {
                        stream.recv_credit.used()
                    } else {
                        stream.read_offset
                    };
                consumed.saturating_add(released)
            })
            .min(VARINT_MAX)
    }

    /// React to the peer's STREAM_DATA_BLOCKED on a bounded-window stream.
    ///
    /// The window doubles (up to the growth cap) only when every gate holds,
    /// so a sender that is repairing loss (it never reports being blocked
    /// while credit is not its limiter) and a slow reader (whose un-read
    /// bytes, not the window, are the bound) keep the window they have:
    /// * growth is allowed and the cap is above the current window;
    /// * `limit` is within one window of the edge we advertised: on a
    ///   high-BDP path the peer's view lags our advertisements by up to a
    ///   window of in-flight MAX_STREAM_DATA frames, while a frame from
    ///   further back is stale and ignored;
    /// * the application has consumed at least one full window since the
    ///   window was configured or last grew.
    ///
    /// Returns the new advertisement for the caller to put on the wire as
    /// MAX_STREAM_DATA, or `None` when nothing changed.
    pub fn note_peer_stream_data_blocked(
        &mut self,
        id: StreamId,
        limit: u64,
    ) -> Result<Option<u64>, StreamTableError> {
        let stream = self.stream_mut(id)?;
        let (Some(window), Some(max_window)) =
            (stream.recv_window_bytes, stream.recv_window_max_bytes)
        else {
            return Ok(None);
        };
        if max_window <= window {
            return Ok(None);
        }
        // A stream already holding a quarter of its reassembly budget in
        // out-of-order chunks is holey: a larger window would buy more holes
        // and can only end at the fragment guard, which is fatal to the
        // connection. Refuse to grow rather than approach it.
        if stream.recv_window_fragment_ceiling != 0
            && stream
                .recv_chunks
                .len()
                .saturating_mul(4)
                .ge(&stream.recv_window_fragment_ceiling)
        {
            return Ok(None);
        }
        if limit.saturating_add(window) < stream.recv_limit_advertised {
            return Ok(None);
        }
        if stream
            .read_offset
            .saturating_sub(stream.recv_window_grown_at_read_offset)
            < window
        {
            return Ok(None);
        }
        let grown = window.saturating_mul(2).min(max_window);
        stream.recv_window_bytes = Some(grown);
        stream.recv_window_grown_at_read_offset = stream.read_offset;
        let desired = stream.read_offset.saturating_add(grown).min(VARINT_MAX);
        if desired <= stream.recv_limit_advertised {
            return Ok(None);
        }
        if desired > stream.recv_credit.limit() {
            stream
                .recv_credit
                .increase_limit(desired)
                .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        }
        stream.recv_limit_advertised = desired;
        Ok(Some(desired))
    }

    /// Lower a freshly-opened local stream's send-credit limit so the sender
    /// side of a bounded-window stream enforces the same window the receiver
    /// advertises; the limit then grows only via peer MAX_STREAM_DATA frames.
    /// Clamped against already-consumed credit; returns the applied limit.
    pub fn set_fresh_stream_send_limit(
        &mut self,
        id: StreamId,
        limit: u64,
    ) -> Result<u64, StreamTableError> {
        let stream = self.stream_mut(id)?;
        Ok(stream.send_credit.reduce_limit_clamped(limit))
    }

    /// Clamp connection send credit at or above already-consumed bytes.
    ///
    /// This is a deterministic test hook for planting an exact post-handshake
    /// `MAX_DATA` stall. Production limits are negotiated by the transport.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn constrain_connection_send_limit_for_testing(&mut self, limit: u64) -> u64 {
        self.send_connection_credit.reduce_limit_clamped(limit)
    }

    /// Remaining send credit for one stream (0 for unknown streams).
    #[must_use]
    pub fn stream_send_credit_remaining(&self, id: StreamId) -> u64 {
        self.streams
            .get(&id)
            .map_or(0, |stream| stream.send_credit.remaining())
    }

    /// Poll the exact application payload capacity available to one stream.
    ///
    /// Capacity is the smaller of the stream and connection send windows. A
    /// caller waiting for `required` bytes is registered for both
    /// `MAX_STREAM_DATA` and `MAX_DATA` wakeups. Terminal send-side states are
    /// reported as errors rather than looking like flow-control stalls.
    pub fn poll_stream_send_capacity(
        &mut self,
        id: StreamId,
        required: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Result<u64, StreamTableError>> {
        let capacity = {
            let stream = self.stream(id)?;
            stream.ensure_can_send(0)?;
            stream
                .send_credit
                .remaining()
                .min(self.send_connection_credit.remaining())
        };
        if capacity >= required {
            return Poll::Ready(Ok(capacity));
        }

        self.register_write_waker(id, cx.waker());

        // Re-check after registration so future synchronization inside the
        // table cannot create a lost-wakeup window around this operation.
        let capacity = {
            let stream = self.stream(id)?;
            stream.ensure_can_send(0)?;
            stream
                .send_credit
                .remaining()
                .min(self.send_connection_credit.remaining())
        };
        if capacity >= required {
            self.write_wakers.remove(&id);
            Poll::Ready(Ok(capacity))
        } else {
            Poll::Pending
        }
    }

    /// Observe closure of a send direction without reserving payload credit.
    ///
    /// Critical protocol streams remain observable while their application
    /// queue is empty. The existing writer wake also covers STOP_SENDING and
    /// local reset; credit and queue-drain wakes simply require another poll.
    #[cfg(feature = "http3")]
    pub(crate) fn poll_stream_send_closed(
        &mut self,
        id: StreamId,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamTableError>> {
        let is_closed = |stream: &QuicStream| {
            stream.stop_sending_error_code.is_some()
                || stream.send_reset.is_some()
                || stream.send_final_size.is_some()
        };
        if is_closed(self.stream(id)?) {
            return Poll::Ready(Ok(()));
        }
        self.register_write_waker(id, cx.waker());
        if is_closed(self.stream(id)?) {
            self.write_wakers.remove(&id);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// Poll until one stream can accept a new application frame.
    ///
    /// In addition to the flow-control admission performed by
    /// [`Self::poll_stream_send_capacity`], this waits for every previously
    /// queued STREAM frame (including a zero-byte FIN) to leave packet
    /// assembly. That makes it safe for a bounded producer to dequeue at most
    /// one higher-level frame at a time.
    pub fn poll_stream_write_ready(
        &mut self,
        id: StreamId,
        required: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Result<u64, StreamTableError>> {
        let pending = self.stream(id)?.has_pending_stream_frames();
        if !pending {
            return self.poll_stream_send_capacity(id, required, cx);
        }

        self.register_write_waker(id, cx.waker());
        if self.stream(id)?.has_pending_stream_frames() {
            Poll::Pending
        } else {
            self.poll_stream_send_capacity(id, required, cx)
        }
    }

    /// Poll until every queued STREAM frame for one stream leaves packet
    /// assembly.
    ///
    /// Unlike write readiness, this remains usable after a FIN or reset made
    /// the send side terminal. It is the terminal-response reaping primitive.
    pub fn poll_stream_queue_drained(
        &mut self,
        id: StreamId,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamTableError>> {
        if !self.stream(id)?.has_pending_stream_frames() {
            return Poll::Ready(Ok(()));
        }
        self.register_write_waker(id, cx.waker());
        if self.stream(id)?.has_pending_stream_frames() {
            Poll::Pending
        } else {
            self.write_wakers.remove(&id);
            Poll::Ready(Ok(()))
        }
    }

    /// Advance bounded receive windows after application reads.
    ///
    /// The desired limit is CONSUMPTION-clocked (`read_offset + window`) —
    /// SETTLED after four attempts (MATRIX-224/225/226/227, do not re-try
    /// without new evidence): receipt-clocking the credit failed three ways
    /// — (a) bare: congestion collapse, ~2× payload re-sent (M224); (b)
    /// atop a BDP cap fed by dishonest ACK-window aggregates: collapse
    /// twice (M225); (c) atop the honest delivered-counter cap with a
    /// constant 1.25× gain: +60 %, nothing drained the queue (M226) — and
    /// finally, (d) atop the FULL honest stack (delivered-counter cap +
    /// PROBE_BW gain cycling, M227), it engaged cleanly and measured a
    /// WASH-to-worse (med ≥46.8 vs 47.0 cycling-alone, +73 MB extra
    /// re-sends): once the gain cycle's 0.75× drain phase cut the
    /// over-offer that was punching the holes, the window stall it was
    /// meant to remove had already stopped being the binding constraint.
    /// The stall is now a cheap backstop, not a tax.
    ///
    /// For every bounded stream whose desired limit has moved at least a
    /// sixteenth-window past the advertised limit, record the new
    /// advertisement and return the `(stream, limit)` pairs the caller must
    /// put on the wire as MAX_STREAM_DATA frames.
    pub fn advance_bounded_recv_windows(&mut self) -> Vec<(StreamId, u64)> {
        let mut updates = Vec::new();
        for (id, stream) in &mut self.streams {
            let Some(window) = stream.recv_window_bytes else {
                continue;
            };
            let desired = stream.read_offset.saturating_add(window).min(VARINT_MAX);
            // Advertisement granularity is also the sender's credit-grant
            // step: a quarter-window step quantized the whole transfer into
            // one flush-window per RTT (measured 50M/good 3.5 s → 4.9 s), so
            // keep steps fine enough that credit growth looks continuous.
            let hysteresis = (window / 16).max(1);
            if desired.saturating_sub(stream.recv_limit_advertised) < hysteresis {
                continue;
            }
            if desired > stream.recv_credit.limit() {
                stream
                    .recv_credit
                    .increase_limit(desired)
                    .expect("larger advertised receive limit must be monotonic");
            }
            stream.recv_limit_advertised = desired;
            updates.push((*id, desired));
        }
        updates
    }

    /// Current bounded-window advertisements as `(stream, limit)` pairs.
    ///
    /// Re-attached to outgoing ACKs so a lost MAX_STREAM_DATA frame cannot
    /// wedge a credit-blocked sender: advertisements are idempotent monotonic
    /// maxima, so repeating the current limit is always safe. A stream whose
    /// final size is known, or whose receive side was reset or stopped, needs
    /// no more credit (RFC 9000 3.2) and is left out.
    #[must_use]
    pub fn bounded_recv_window_advertisements(&self) -> Vec<(StreamId, u64)> {
        self.streams
            .iter()
            .filter(|(_, stream)| {
                stream.recv_window_bytes.is_some()
                    && stream.final_size.is_none()
                    && stream.recv_reset.is_none()
                    && stream.receive_stopped_error_code.is_none()
            })
            .map(|(id, stream)| (*id, stream.recv_limit_advertised))
            .collect()
    }

    /// Get mutable stream handle.
    pub fn stream_mut(&mut self, id: StreamId) -> Result<&mut QuicStream, StreamTableError> {
        self.streams
            .get_mut(&id)
            .ok_or(StreamTableError::UnknownStream(id))
    }

    /// Get immutable stream handle.
    pub fn stream(&self, id: StreamId) -> Result<&QuicStream, StreamTableError> {
        self.streams
            .get(&id)
            .ok_or(StreamTableError::UnknownStream(id))
    }

    /// Account bytes written to one stream with connection-level flow control.
    pub fn write_stream(&mut self, id: StreamId, len: u64) -> Result<(), StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && !id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotWritable(id));
        }
        {
            let stream = self.stream(id)?;
            stream
                .ensure_can_send(len)
                .map_err(StreamTableError::Stream)?;
        }
        self.send_connection_credit
            .can_consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        self.send_connection_credit
            .consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let stream = self.stream_mut(id)?;
        stream.write(len)?;
        Ok(())
    }

    /// Queue bytes for one writable stream with connection-level flow control.
    pub fn write_stream_bytes(
        &mut self,
        id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<(), StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && !id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotWritable(id));
        }
        let len = data.len() as u64;
        {
            let stream = self.stream(id)?;
            stream
                .ensure_can_send(len)
                .map_err(StreamTableError::Stream)?;
        }
        self.send_connection_credit
            .can_consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        self.send_connection_credit
            .consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        self.stream_mut(id)?.write_bytes(data, fin)?;
        Ok(())
    }

    /// Queue a FIN-only STREAM frame for one writable stream.
    pub fn finish_stream_send(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        self.write_stream_bytes(id, Bytes::new(), true)
    }

    /// Account bytes received on one stream at its current contiguous receive offset.
    pub fn receive_stream(&mut self, id: StreamId, len: u64) -> Result<(), StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotReadable(id));
        }
        let offset = self.stream(id)?.recv_offset;
        self.receive_stream_segment(id, offset, len, false)
    }

    /// Account bytes received on one stream at an explicit offset.
    pub fn receive_stream_segment(
        &mut self,
        id: StreamId,
        offset: u64,
        len: u64,
        is_fin: bool,
    ) -> Result<(), StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotReadable(id));
        }
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        let prior_used = self.stream(id)?.recv_credit.used();
        let connection_delta = end.saturating_sub(prior_used);
        self.recv_connection_credit
            .can_consume(connection_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let flow_delta = self.stream_mut(id)?.receive_segment(offset, len, is_fin)?;
        self.recv_connection_credit
            .consume(flow_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        // This API records flow-control/range accounting only; it deliberately
        // stores no payload bytes. Advertising byte-readiness here makes a
        // consumer observe `readable_bytes > 0` followed by an empty read and
        // can create a permanent poll loop. FIN remains a real terminal edge.
        let stream = self.stream(id)?;
        if is_fin && stream.recv_reset.is_none() && stream.receive_stopped_error_code.is_none() {
            self.mark_stream_readable(id);
        }
        Ok(())
    }

    /// Out-of-order receive runs buffered across every stream. A readable run
    /// at a stream's read offset does not count, so a frame that closes a
    /// head-of-line gap stays admissible however full the budget is.
    fn out_of_order_recv_runs(&self) -> usize {
        self.streams
            .values()
            .map(QuicStream::out_of_order_recv_runs)
            .sum()
    }

    /// Check whether accepting a STREAM payload would exceed a fragment cap.
    ///
    /// This is a read-only preflight so callers can reject hostile
    /// fragmentation before flow-control or reassembly state is mutated.
    /// The connection screens with
    /// [`Self::stream_reassembly_limits_would_be_exceeded`].
    #[cfg(test)]
    pub(crate) fn stream_reassembly_fragment_limit_would_be_exceeded(
        &self,
        id: StreamId,
        offset: u64,
        len: u64,
        is_fin: bool,
        limit: usize,
    ) -> Result<bool, StreamTableError> {
        self.stream_reassembly_limits_would_be_exceeded(id, offset, len, is_fin, limit, usize::MAX)
    }

    /// As [`Self::stream_reassembly_fragment_limit_would_be_exceeded`], and
    /// also refuse a payload that would take the out-of-order runs buffered
    /// across every stream above `connection_limit`. The per-stream cap alone
    /// lets a peer hold that many tiny holes on each of its streams at once.
    pub(crate) fn stream_reassembly_limits_would_be_exceeded(
        &self,
        id: StreamId,
        offset: u64,
        len: u64,
        is_fin: bool,
        limit: usize,
        connection_limit: usize,
    ) -> Result<bool, StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotReadable(id));
        }
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        let stream = self.stream(id)?;
        // Data for a reset or stopped receive side is discarded on receipt
        // (see `receive_segment`), so it is always admissible here and must
        // not be screened against reassembly limits it will never occupy.
        if stream.recv_reset.is_some() || stream.receive_stopped_error_code.is_some() {
            return Ok(false);
        }
        let connection_delta = end.saturating_sub(stream.recv_credit.used());
        self.recv_connection_credit
            .can_consume(connection_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        stream.validate_receive_segment(offset, len, is_fin)?;
        let projected = stream.projected_recv_chunk_count(offset, len)?;

        // Reserve one node for the chunk at `read_offset`. Without that
        // reservation, a peer can fill every slot with out-of-order chunks and
        // make the one frame that closes the head-of-line gap inadmissible.
        // The readable head is unique, so this keeps the total node count at
        // `limit` while preserving forward progress.
        let readable_head_present = stream.recv_chunks.contains_key(&stream.read_offset);
        let incoming_makes_head_readable =
            len > 0 && offset <= stream.read_offset && end > stream.read_offset;
        let projected_out_of_order = projected.saturating_sub(usize::from(
            readable_head_present || incoming_makes_head_readable,
        ));
        let max_out_of_order = limit.saturating_sub(1);
        if projected > limit || projected_out_of_order > max_out_of_order {
            return Ok(true);
        }
        if connection_limit == usize::MAX {
            return Ok(false);
        }
        let elsewhere = self.out_of_order_recv_runs() - stream.out_of_order_recv_runs();
        Ok(elsewhere.saturating_add(projected_out_of_order) > connection_limit)
    }

    /// Screen the entire packet's reassembly budget before any frame effects.
    /// Protocol validation still belongs to the ordinary frame-processing path.
    /// No payloads, send queues, wakers, or other streams are cloned here.
    /// The connection screens with
    /// [`Self::packet_reassembly_limits_would_be_exceeded`].
    #[cfg(test)]
    pub(crate) fn packet_reassembly_fragment_limit_would_be_exceeded(
        &self,
        frames: &[QuicFrame],
        limit: usize,
    ) -> bool {
        self.packet_reassembly_limits_would_be_exceeded(frames, limit, usize::MAX)
    }

    /// As [`Self::packet_reassembly_fragment_limit_would_be_exceeded`], and
    /// also bound the out-of-order runs buffered across every stream by
    /// `connection_limit` (see [`Self::stream_reassembly_limits_would_be_exceeded`]).
    pub(crate) fn packet_reassembly_limits_would_be_exceeded(
        &self,
        frames: &[QuicFrame],
        limit: usize,
        connection_limit: usize,
    ) -> bool {
        let stream_frames = frames
            .iter()
            .filter(|frame| matches!(frame, QuicFrame::Stream { .. }))
            .count();
        if stream_frames == 0 {
            return false;
        }
        // An interval adds at most one run. Most packets therefore need only
        // this allocation-free upper bound, even when carrying several streams.
        let could_reach_limit = frames.iter().any(|frame| {
            let QuicFrame::Stream { stream_id, .. } = frame else {
                return false;
            };
            self.streams
                .get(&StreamId(stream_id.value()))
                .map_or(0, |stream| stream.recv_chunks.len())
                .saturating_add(frames.len())
                > limit.saturating_sub(1)
        });
        // Tracked only under a connection limit: the sum visits every stream.
        let mut out_of_order =
            (connection_limit != usize::MAX).then(|| self.out_of_order_recv_runs());
        if !could_reach_limit
            && out_of_order
                .is_none_or(|total| total.saturating_add(stream_frames) <= connection_limit)
        {
            return false;
        }

        let mut projected = BTreeMap::<StreamId, RecvPacketRuns>::new();
        for frame in frames {
            let stream_id = match frame {
                QuicFrame::Stream { stream_id, .. } | QuicFrame::ResetStream { stream_id, .. } => {
                    *stream_id
                }
                // No later STREAM can be accepted after a peer close. Leave
                // close/error processing to the normal connection state machine.
                QuicFrame::ConnectionClose { .. } => break,
                _ => continue,
            };
            let id = StreamId(stream_id.value());
            let projection = projected.entry(id).or_insert_with(|| {
                let stream = self.streams.get(&id);
                RecvPacketRuns {
                    read_offset: stream.map_or(0, |stream| stream.read_offset),
                    runs: stream.map_or_else(Vec::new, |stream| {
                        stream
                            .recv_chunks
                            .iter()
                            .map(|(&start, run)| (start, start + run.len))
                            .collect()
                    }),
                    reset: stream.is_some_and(|stream| {
                        stream.recv_reset.is_some() || stream.receive_stopped_error_code.is_some()
                    }),
                }
            });
            match frame {
                QuicFrame::Stream { offset, data, .. } => {
                    let offset = offset.map_or(0, |value| value.value());
                    let Some(end) = offset.checked_add(data.len() as u64) else {
                        // The normal processor reports this malformed frame;
                        // it cannot reach a subsequent reassembly admission.
                        break;
                    };
                    let before = projection.out_of_order();
                    projection.insert(offset, end);
                    // The total includes this stream's runs, so it is at
                    // least `before`.
                    if let Some(total) = out_of_order.as_mut() {
                        *total = *total - before + projection.out_of_order();
                    }
                    if projection.exceeds(limit)
                        || out_of_order.is_some_and(|total| total > connection_limit)
                    {
                        return true;
                    }
                }
                QuicFrame::ResetStream { .. } => {
                    if let Some(total) = out_of_order.as_mut() {
                        *total -= projection.out_of_order();
                    }
                    projection.runs.clear();
                    projection.reset = true;
                }
                _ => unreachable!("only STREAM and RESET_STREAM projections are constructed"),
            }
        }
        false
    }

    /// Receive STREAM payload bytes on one stream at an explicit offset.
    pub fn receive_stream_bytes(
        &mut self,
        id: StreamId,
        offset: u64,
        data: Bytes,
        is_fin: bool,
    ) -> Result<(), StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotReadable(id));
        }
        let len = data.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or(QuicStreamError::OffsetOverflow { offset, len })?;
        let prior_used = self.stream(id)?.recv_credit.used();
        let connection_delta = end.saturating_sub(prior_used);
        self.recv_connection_credit
            .can_consume(connection_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let flow_delta = self.stream_mut(id)?.receive_bytes(offset, data, is_fin)?;
        self.recv_connection_credit
            .consume(flow_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let stream = self.stream(id)?;
        if (len > 0 || is_fin)
            && stream.recv_reset.is_none()
            && stream.receive_stopped_error_code.is_none()
        {
            self.mark_stream_readable(id);
        }
        Ok(())
    }

    /// Read contiguous application bytes from one readable stream.
    pub fn read_stream_bytes(
        &mut self,
        id: StreamId,
        max_len: usize,
    ) -> Result<Bytes, StreamTableError> {
        if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
            return Err(StreamTableError::StreamNotReadable(id));
        }
        let bytes = {
            let stream = self.stream_mut(id)?;
            if let Some((code, final_size)) = stream.recv_reset {
                return Err(StreamTableError::Stream(QuicStreamError::ReceiveReset {
                    code,
                    final_size,
                }));
            }
            if let Some(code) = stream.receive_stopped_error_code {
                return Err(StreamTableError::Stream(QuicStreamError::ReceiveStopped {
                    code,
                }));
            }
            stream.read_bytes(max_len)
        };
        // Requeue only when a partial application read left actual contiguous
        // bytes buffered. FIN, RESET_STREAM, and local receive-stop are
        // one-shot edges; repeatedly requeueing EOF makes readiness spin.
        if self.stream_readiness(id)?.readable_bytes > 0 {
            self.mark_stream_readable(id);
        }
        Ok(bytes)
    }

    /// Consume the lowest-id pending receive-side readiness notification.
    ///
    /// The notification is edge-triggered. Callers should read or otherwise
    /// disposition the stream before requesting another notification. A
    /// partial read automatically requeues the stream while contiguous bytes
    /// remain observable; terminal state is a one-shot edge.
    pub fn take_next_readable_stream(&mut self) -> Option<StreamReadiness> {
        let stream_id = self.readable_streams.pop_first()?;
        let readiness = self.stream_readiness(stream_id).ok()?;
        if readiness.reset.is_some() {
            self.streams
                .get_mut(&stream_id)
                .expect("readiness requires an existing stream")
                .reset_readiness_delivered = true;
        }
        Some(readiness)
    }

    /// Poll for the next deterministic receive-side stream notification.
    ///
    /// When no stream is ready, the task waker is retained until bytes, FIN,
    /// RESET_STREAM, or a local receive stop changes a stream.
    pub fn poll_next_readable_stream(
        &mut self,
        task_cx: &mut Context<'_>,
    ) -> Poll<StreamReadiness> {
        if let Some(readiness) = self.take_next_readable_stream() {
            return Poll::Ready(readiness);
        }
        let should_replace = self
            .readable_stream_waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task_cx.waker()));
        if should_replace {
            self.readable_stream_waker = Some(task_cx.waker().clone());
        }
        Poll::Pending
    }

    fn stream_readiness(&self, id: StreamId) -> Result<StreamReadiness, StreamTableError> {
        let stream = self.stream(id)?;
        Ok(StreamReadiness {
            stream_id: id,
            readable_bytes: stream.readable_bytes(),
            fin_received: stream.final_size.is_some() && stream.recv_reset.is_none(),
            reset: stream.recv_reset,
            receive_stopped: stream.receive_stopped_error_code,
        })
    }

    /// Whether a stream has reached application EOF.
    pub fn is_stream_read_eof(&self, id: StreamId) -> Result<bool, StreamTableError> {
        Ok(self.stream(id)?.is_read_eof())
    }

    /// Return the bounded buffered prefix retained across peer RESET_STREAM.
    pub fn reset_stream_buffered_prefix(&self, id: StreamId) -> Result<Bytes, StreamTableError> {
        Ok(self.stream(id)?.reset_buffered_prefix())
    }

    /// Current stream-level send limit.
    pub fn stream_send_limit(&self, id: StreamId) -> Result<u64, StreamTableError> {
        Ok(self.stream(id)?.send_credit.limit())
    }

    /// Requeue one previously emitted STREAM frame after packet loss.
    pub fn requeue_sent_stream_frame(
        &mut self,
        id: StreamId,
        offset: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.requeue_sent_stream_frame(offset)?;
        Ok(())
    }

    /// Release the retained retransmission copy of an acknowledged frame.
    pub fn release_sent_stream_frame(
        &mut self,
        id: StreamId,
        offset: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.release_sent_stream_frame(offset);
        Ok(())
    }

    /// Release a retained STREAM copy only if its current extent still
    /// matches the acknowledged wire frame.
    pub(crate) fn release_sent_stream_frame_if_matches(
        &mut self,
        id: StreamId,
        offset: u64,
        data_len: usize,
        fin: bool,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?
            .release_sent_stream_frame_if_matches(offset, data_len, fin);
        Ok(())
    }

    /// Put a popped STREAM frame back when packet assembly did not emit it.
    pub fn requeue_unemitted_stream_frame(
        &mut self,
        payload: StreamFramePayload,
    ) -> Result<(), StreamTableError> {
        let id = payload.stream_id;
        self.stream_mut(id)?.requeue_unemitted_stream_frame(payload);
        Ok(())
    }

    /// Whether any stream has queued STREAM frames awaiting packet assembly.
    #[must_use]
    pub fn has_pending_stream_frames(&self) -> bool {
        self.streams
            .values()
            .any(QuicStream::has_pending_stream_frames)
    }

    /// Whether one stream has queued STREAM frames awaiting packet assembly.
    #[must_use]
    pub fn has_pending_stream_frames_for(&self, id: StreamId) -> bool {
        self.streams
            .get(&id)
            .is_some_and(QuicStream::has_pending_stream_frames)
    }

    /// Number of queued STREAM frames waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_frame_count(&self) -> usize {
        self.streams
            .values()
            .map(QuicStream::pending_stream_frame_count)
            .sum()
    }

    /// Queued STREAM payload bytes waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_data_bytes(&self) -> u64 {
        self.streams.values().fold(0u64, |acc, stream| {
            acc.saturating_add(stream.pending_stream_data_bytes())
        })
    }

    /// Queued STREAM payload bytes for one stream.
    #[must_use]
    pub fn pending_stream_data_bytes_for(&self, id: StreamId) -> u64 {
        self.streams
            .get(&id)
            .map_or(0, QuicStream::pending_stream_data_bytes)
    }

    /// Pop the next queued STREAM frame for one stream.
    pub fn pop_stream_frame_for(
        &mut self,
        id: StreamId,
        max_data_len: usize,
    ) -> Option<StreamFramePayload> {
        if max_data_len == 0 {
            return None;
        }
        let payload = self
            .stream_mut(id)
            .ok()?
            .pop_pending_stream_frame(max_data_len);
        if payload.is_some() && !self.has_pending_stream_frames_for(id) {
            self.wake_writer(id);
        }
        payload
    }

    /// Pop the next queued STREAM frame, splitting payload bytes to `max_data_len`.
    pub fn pop_next_stream_frame(&mut self, max_data_len: usize) -> Option<StreamFramePayload> {
        if max_data_len == 0 {
            return None;
        }
        let cursor = self.rr_cursor;
        let iter1 = self.streams.range((
            cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
            std::ops::Bound::Unbounded,
        ));
        let iter2 = self.streams.range((
            std::ops::Bound::Unbounded,
            cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Included),
        ));
        let next_id = iter1
            .chain(
                if cursor.is_none() { None } else { Some(iter2) }
                    .into_iter()
                    .flatten(),
            )
            .find_map(|(id, stream)| stream.has_pending_stream_frames().then_some(*id))?;
        self.rr_cursor = Some(next_id);
        let payload = self
            .stream_mut(next_id)
            .ok()?
            .pop_pending_stream_frame(max_data_len);
        if payload.is_some() && !self.has_pending_stream_frames_for(next_id) {
            self.wake_writer(next_id);
        }
        payload
    }

    /// Borrow a stream as an `AsyncRead + AsyncWrite` adapter.
    pub fn stream_io(&mut self, id: StreamId) -> Result<QuicStreamIo<'_>, StreamTableError> {
        let _ = self.stream(id)?;
        Ok(QuicStreamIo { table: self, id })
    }

    /// Apply a peer `STOP_SENDING` signal and wake any blocked writer.
    pub fn on_stop_sending(
        &mut self,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.on_stop_sending(error_code);
        self.wake_writer(id);
        Ok(())
    }

    /// Locally stop receiving a stream and wake any blocked reader.
    pub fn stop_receiving(
        &mut self,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), StreamTableError> {
        let stream = self.stream_mut(id)?;
        let previous = stream.receive_stopped_error_code;
        stream.stop_receiving(error_code);
        if previous != Some(error_code) {
            self.mark_stream_readable(id);
        }
        Ok(())
    }

    /// Apply peer RESET_STREAM to a stream receive side and wake any blocked reader.
    pub fn reset_stream_receive(
        &mut self,
        id: StreamId,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), StreamTableError> {
        let prior_used = self.stream(id)?.recv_credit.used();
        let connection_delta = final_size.saturating_sub(prior_used);
        self.recv_connection_credit
            .can_consume(connection_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let flow_delta = self.stream_mut(id)?.reset_receive(error_code, final_size)?;
        self.recv_connection_credit
            .consume(flow_delta)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        self.mark_stream_readable(id);
        Ok(())
    }

    /// Locally reset one stream's send side and wake any blocked writer.
    pub fn reset_stream_send(
        &mut self,
        id: StreamId,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.reset_send(error_code, final_size)?;
        self.wake_writer(id);
        Ok(())
    }

    /// Set stream final size.
    pub fn set_stream_final_size(
        &mut self,
        id: StreamId,
        final_size: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.set_final_size(final_size)?;
        self.mark_stream_readable(id);
        Ok(())
    }

    /// Increase connection-level send limit monotonically.
    ///
    /// RFC 9000 §19.9: a MAX_DATA that does not increase the limit is
    /// ignored, not an error — reordered frames legitimately repeat older
    /// maxima.
    pub fn increase_connection_send_limit(
        &mut self,
        new_limit: u64,
    ) -> Result<(), FlowControlError> {
        if new_limit <= self.send_connection_credit.limit() {
            return Ok(());
        }
        let before = self.send_connection_credit.remaining();
        let result = self.send_connection_credit.increase_limit(new_limit);
        if result.is_ok() && self.send_connection_credit.remaining() > before {
            self.wake_all_writers();
        }
        result
    }

    /// Increase stream-level send limit monotonically.
    pub fn increase_stream_send_limit(
        &mut self,
        id: StreamId,
        new_limit: u64,
    ) -> Result<(), StreamTableError> {
        let before = self.stream(id)?.send_credit.remaining();
        // RFC 9000 §19.10: a MAX_STREAM_DATA that does not increase the limit
        // is ignored, not an error — reordered or re-attached advertisements
        // legitimately repeat older maxima.
        if new_limit <= self.stream(id)?.send_credit.limit() {
            return Ok(());
        }
        self.stream_mut(id)?
            .send_credit
            .increase_limit(new_limit)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        if self.stream(id)?.send_credit.remaining() > before {
            self.wake_writer(id);
        }
        Ok(())
    }

    /// Increase connection-level receive limit monotonically.
    pub fn increase_connection_recv_limit(
        &mut self,
        new_limit: u64,
    ) -> Result<(), FlowControlError> {
        // RFC 9000 §19.9: a MAX_DATA that does not increase the connection
        // limit is ignored, not an error — mirrors `increase_connection_send_limit`
        // and `increase_stream_send_limit` (§19.10). Re-attached/reordered
        // advertisements legitimately repeat older maxima, so a non-increasing
        // value is a no-op rather than a `LimitRegression`.
        if new_limit <= self.recv_connection_credit.limit() {
            return Ok(());
        }
        self.recv_connection_credit.increase_limit(new_limit)
    }

    /// Remaining connection-level send credit.
    #[must_use]
    pub fn connection_send_remaining(&self) -> u64 {
        self.send_connection_credit.remaining()
    }

    /// The connection-level send limit, the peer's latest MAX_DATA.
    #[must_use]
    pub(crate) fn connection_send_limit(&self) -> u64 {
        self.send_connection_credit.limit()
    }

    /// Remaining connection-level receive credit.
    #[must_use]
    pub fn connection_recv_remaining(&self) -> u64 {
        self.recv_connection_credit.remaining()
    }

    /// Current connection-level receive limit.
    #[must_use]
    pub fn connection_recv_limit(&self) -> u64 {
        self.recv_connection_credit.limit()
    }

    /// Next locally initiated stream with pending send credit (round-robin).
    #[must_use]
    pub fn next_writable_stream(&mut self) -> Option<StreamId> {
        if self.connection_send_remaining() == 0 || self.streams.is_empty() {
            return None;
        }

        // We need an allocation-free round-robin traversal of the BTreeMap.
        // We find elements AFTER the cursor, then chain elements BEFORE the cursor.

        let cursor = self.rr_cursor;

        let iter1 = self.streams.range((
            cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
            std::ops::Bound::Unbounded,
        ));

        let iter2 = self.streams.range((
            std::ops::Bound::Unbounded,
            cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Included),
        ));

        // If cursor was None, iter1 covers everything and iter2 covers everything,
        // so we just take iter1. If cursor was Some, we chain them.
        for (id, stream) in iter1.chain(
            if cursor.is_none() { None } else { Some(iter2) }
                .into_iter()
                .flatten(),
        ) {
            let writable = match id.direction() {
                StreamDirection::Bidirectional => true,
                StreamDirection::Unidirectional => id.is_local_for(self.role),
            } && stream.send_reset.is_none()
                && stream.stop_sending_error_code.is_none()
                && stream.send_credit.remaining() > 0;

            if writable {
                self.rr_cursor = Some(*id);
                return Some(*id);
            }
        }
        None
    }

    /// Stream count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    fn register_read_waker(&mut self, id: StreamId, waker: &Waker) {
        self.read_wakers
            .entry(id)
            .and_modify(|registered| {
                if !registered.will_wake(waker) {
                    registered.clone_from(waker);
                }
            })
            .or_insert_with(|| waker.clone());
    }

    fn register_write_waker(&mut self, id: StreamId, waker: &Waker) {
        self.write_wakers
            .entry(id)
            .and_modify(|registered| {
                if !registered.will_wake(waker) {
                    registered.clone_from(waker);
                }
            })
            .or_insert_with(|| waker.clone());
    }

    fn wake_reader(&mut self, id: StreamId) {
        if let Some(waker) = self.read_wakers.remove(&id) {
            waker.wake();
        }
    }

    fn mark_stream_readable(&mut self, id: StreamId) {
        if self
            .streams
            .get(&id)
            .is_some_and(|stream| stream.reset_readiness_delivered)
        {
            return;
        }
        self.readable_streams.insert(id);
        self.wake_reader(id);
        if let Some(waker) = self.readable_stream_waker.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self, id: StreamId) {
        if let Some(waker) = self.write_wakers.remove(&id) {
            waker.wake();
        }
    }

    fn wake_all_writers(&mut self) {
        let wakers = std::mem::take(&mut self.write_wakers);
        for (_, waker) in wakers {
            waker.wake();
        }
    }

    fn insert_new_stream(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        if self.streams.contains_key(&id) {
            return Err(StreamTableError::DuplicateStream(id));
        }
        // RFC 9000 §18.2: each stream type has its own initial window; the
        // data-carrying direction of a unidirectional stream uses `uni` and
        // its other direction carries no data, so the same value is harmless.
        let (send_window, recv_window) = match (id.is_local_for(self.role), id.direction()) {
            (true, StreamDirection::Bidirectional) => {
                (self.send_windows.local_bidi, self.recv_windows.local_bidi)
            }
            (false, StreamDirection::Bidirectional) => {
                (self.send_windows.remote_bidi, self.recv_windows.remote_bidi)
            }
            (_, StreamDirection::Unidirectional) => (self.send_windows.uni, self.recv_windows.uni),
        };
        self.streams
            .insert(id, QuicStream::new(id, send_window, recv_window));
        Ok(())
    }
}

/// Poll-based application I/O adapter for one QUIC stream.
pub struct QuicStreamIo<'a> {
    table: &'a mut StreamTable,
    id: StreamId,
}

impl QuicStreamIo<'_> {
    fn io_error(err: StreamTableError) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, err.to_string())
    }
}

impl AsyncRead for QuicStreamIo<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match this.table.read_stream_bytes(this.id, buf.remaining()) {
            Ok(bytes) if !bytes.is_empty() => {
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            Ok(_) => match this.table.is_stream_read_eof(this.id) {
                Ok(true) => Poll::Ready(Ok(())),
                Ok(false) => {
                    this.table.register_read_waker(this.id, cx.waker());
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(Self::io_error(err))),
            },
            Err(err) => Poll::Ready(Err(Self::io_error(err))),
        }
    }
}

impl AsyncWrite for QuicStreamIo<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Accept what the stream and connection windows allow now, as an
        // AsyncWrite may. Waiting for credit for the whole buffer never ends
        // when the peer grants more only after it receives these bytes.
        let capacity = match this.table.poll_stream_send_capacity(this.id, 1, cx) {
            Poll::Ready(Ok(capacity)) => capacity,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(Self::io_error(err))),
            Poll::Pending => return Poll::Pending,
        };
        let len = buf
            .len()
            .min(usize::try_from(capacity).unwrap_or(usize::MAX));
        match this
            .table
            .write_stream_bytes(this.id, Bytes::copy_from_slice(&buf[..len]), false)
        {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(StreamTableError::Stream(QuicStreamError::Flow(_))) => {
                this.table.register_write_waker(this.id, cx.waker());
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(Self::io_error(err))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.table.finish_stream_send(this.id) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Self::io_error(err))),
        }
    }
}

#[cfg(test)]
#[path = "streams_inline_tests.rs"]
mod tests;
