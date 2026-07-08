//! Native QUIC stream table + flow-control model.

use crate::bytes::{Bytes, BytesMut};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedStreamFrame {
    offset: u64,
    data: Bytes,
    fin: bool,
    retransmit: bool,
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
    /// Buffered receive ranges keyed by start offset, value = exclusive end.
    recv_ranges: BTreeMap<u64, u64>,
    /// Buffered receive bytes keyed by absolute stream offset.
    recv_chunks: BTreeMap<u64, Bytes>,
    /// Bounded receive-window size for this stream. `None` keeps the historic
    /// unbounded-credit behavior; `Some(w)` makes the local receive limit track
    /// `read_offset + w` and drives MAX_STREAM_DATA advertisements so the peer
    /// can never buffer more than ~`w` un-read bytes into `recv_chunks`.
    recv_window_bytes: Option<u64>,
    /// Highest receive limit advertised to the peer via MAX_STREAM_DATA (or the
    /// initial window at configure time). Only meaningful when
    /// `recv_window_bytes` is `Some`.
    recv_limit_advertised: u64,
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
            recv_ranges: BTreeMap::new(),
            recv_chunks: BTreeMap::new(),
            recv_window_bytes: None,
            recv_limit_advertised: 0,
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
        if let Some((code, final_size)) = self.recv_reset {
            return Err(QuicStreamError::ReceiveReset { code, final_size });
        }
        if let Some(code) = self.receive_stopped_error_code {
            return Err(QuicStreamError::ReceiveStopped { code });
        }
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
        let flow_delta = self.recv_credit.consume_to(end)?;
        if is_fin {
            if let Err(err) = self.set_final_size(end) {
                self.recv_credit.release(flow_delta);
                return Err(err);
            }
        }
        if len > 0 {
            self.insert_recv_range(offset, end);
            self.advance_contiguous_recv_offset();
        }
        Ok(flow_delta)
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
        if len > 0 {
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
        let Some(mut chunk) = self.recv_chunks.remove(&self.read_offset) else {
            return Bytes::new();
        };
        let n = chunk.len().min(max_len);
        let out = chunk.slice(..n);
        if n < chunk.len() {
            let tail = chunk.split_off(n);
            self.recv_chunks
                .insert(self.read_offset.saturating_add(n as u64), tail);
        }
        self.read_offset = self.read_offset.saturating_add(n as u64);
        out
    }

    /// Whether this stream has reached application EOF.
    #[must_use]
    pub fn is_read_eof(&self) -> bool {
        self.final_size == Some(self.read_offset)
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
        self.recv_reset.get_or_insert((error_code, final_size));
        self.recv_ranges.clear();
        self.recv_chunks.clear();
        Ok(flow_delta)
    }

    /// Locally reset the send side (`RESET_STREAM`).
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
        self.send_reset = Some((error_code, final_size));
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
            .range(..end)
            .filter_map(|(&start, chunk)| {
                let chunk_end = start.saturating_add(chunk.len() as u64);
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
                self.recv_chunks
                    .insert(cursor, data.slice(data_cursor..data_cursor + gap_len));
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
            self.recv_chunks
                .insert(cursor, data.slice(data_cursor..data_cursor + tail_len));
        }
        Ok(())
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
    send_window: u64,
    recv_window: u64,
    send_connection_credit: FlowCredit,
    recv_connection_credit: FlowCredit,
    rr_cursor: Option<StreamId>,
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
            send_window,
            recv_window,
            send_connection_credit: FlowCredit::new(connection_send_limit),
            recv_connection_credit: FlowCredit::new(connection_recv_limit),
            rr_cursor: None,
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
        if !self.streams.contains_key(&id) {
            self.accept_remote_stream(id)?;
        }
        let stream = self.stream_mut(id)?;
        let advertised = stream.read_offset.saturating_add(window);
        stream.recv_window_bytes = Some(window);
        stream.recv_limit_advertised = advertised;
        Ok(advertised)
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

    /// Remaining send credit for one stream (0 for unknown streams).
    #[must_use]
    pub fn stream_send_credit_remaining(&self, id: StreamId) -> u64 {
        self.streams
            .get(&id)
            .map_or(0, |stream| stream.send_credit.remaining())
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
            let desired = stream.read_offset.saturating_add(window);
            // Advertisement granularity is also the sender's credit-grant
            // step: a quarter-window step quantized the whole transfer into
            // one flush-window per RTT (measured 50M/good 3.5 s → 4.9 s), so
            // keep steps fine enough that credit growth looks continuous.
            let hysteresis = (window / 16).max(1);
            if desired.saturating_sub(stream.recv_limit_advertised) < hysteresis {
                continue;
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
    /// maxima, so repeating the current limit is always safe.
    #[must_use]
    pub fn bounded_recv_window_advertisements(&self) -> Vec<(StreamId, u64)> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.recv_window_bytes.is_some())
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
        if len > 0 || is_fin {
            self.wake_reader(id);
        }
        Ok(())
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
        if len > 0 || is_fin {
            self.wake_reader(id);
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
        Ok(stream.read_bytes(max_len))
    }

    /// Whether a stream has reached application EOF.
    pub fn is_stream_read_eof(&self, id: StreamId) -> Result<bool, StreamTableError> {
        Ok(self.stream(id)?.is_read_eof())
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
        self.stream_mut(id)
            .ok()?
            .pop_pending_stream_frame(max_data_len)
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
        self.stream_mut(next_id)
            .ok()?
            .pop_pending_stream_frame(max_data_len)
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
        self.stream_mut(id)?.stop_receiving(error_code);
        self.wake_reader(id);
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
        self.wake_reader(id);
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
        self.wake_reader(id);
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

    /// Remaining connection-level receive credit.
    #[must_use]
    pub fn connection_recv_remaining(&self) -> u64 {
        self.recv_connection_credit.remaining()
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
        self.streams
            .insert(id, QuicStream::new(id, self.send_window, self.recv_window));
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
        match this
            .table
            .write_stream_bytes(this.id, Bytes::copy_from_slice(buf), false)
        {
            Ok(()) => Poll::Ready(Ok(buf.len())),
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    /// Adversarial reassembly property: deliver a stream as randomized,
    /// reordered, duplicated segments with shifted (coalesced-retransmit)
    /// boundaries, interleaved with partial application reads, and require
    /// that once every byte has been delivered at least once the reader can
    /// always drain the full stream (br-asupersync-u6m3dy tree-manifest
    /// wedge: receiver held full frame-level coverage but `read_bytes`
    /// stalled).
    #[test]
    fn adversarial_reassembly_always_drains() {
        // Deterministic xorshift so failures replay by seed.
        fn next(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }
        const TOTAL: usize = 4096;
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        for seed in 1..=64u64 {
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut stream = QuicStream::new(StreamId(0), 1 << 30, 1 << 30);
            // Base segmentation with irregular boundaries.
            let mut segments: Vec<(u64, u64)> = Vec::new();
            let mut at = 0u64;
            while at < TOTAL as u64 {
                let len = 1 + (next(&mut rng) % 96);
                let end = (at + len).min(TOTAL as u64);
                segments.push((at, end));
                at = end;
            }
            // Duplicates with SHIFTED boundaries (coalesced retransmits):
            // spans overlapping several base segments.
            let dup_count = segments.len() / 3;
            for _ in 0..dup_count {
                let start = next(&mut rng) % TOTAL as u64;
                let len = 1 + (next(&mut rng) % 256);
                let end = (start + len).min(TOTAL as u64);
                if start < end {
                    segments.push((start, end));
                }
            }
            // Shuffle (reorder).
            for i in (1..segments.len()).rev() {
                let j = (next(&mut rng) as usize) % (i + 1);
                segments.swap(i, j);
            }
            let mut read_back: Vec<u8> = Vec::new();
            for (idx, &(s, e)) in segments.iter().enumerate() {
                let data = Bytes::copy_from_slice(&payload[s as usize..e as usize]);
                stream
                    .receive_bytes(s, data, false)
                    .expect("in-window segment must be accepted");
                // Interleave partial reads like the control-frame reader.
                if idx % 3 == 0 {
                    let chunk_len = 1 + (next(&mut rng) as usize % 512);
                    let chunk = stream.read_bytes(chunk_len);
                    read_back.extend_from_slice(&chunk);
                }
            }
            // All bytes delivered at least once: the reader must now drain
            // to TOTAL no matter the arrival order.
            loop {
                let chunk = stream.read_bytes(512);
                if chunk.is_empty() {
                    break;
                }
                read_back.extend_from_slice(&chunk);
            }
            assert_eq!(
                read_back.len(),
                TOTAL,
                "seed {seed}: reader stalled at {} of {TOTAL}",
                read_back.len()
            );
            assert_eq!(read_back, payload, "seed {seed}: bytes corrupted");
        }
    }

    #[derive(Default)]
    struct CountingWake {
        count: std::sync::atomic::AtomicUsize,
    }

    impl CountingWake {
        fn count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl std::task::Wake for CountingWake {
        fn wake(self: std::sync::Arc<Self>) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (std::sync::Arc<CountingWake>, std::task::Waker) {
        let counter = std::sync::Arc::new(CountingWake::default());
        let waker = std::task::Waker::from(counter.clone());
        (counter, waker)
    }

    #[test]
    fn stream_id_encoding_and_role_checks() {
        let c_bidi0 = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        let c_uni1 = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 1);
        assert!(c_bidi0.is_local_for(StreamRole::Client));
        assert!(!c_bidi0.is_local_for(StreamRole::Server));
        assert_eq!(c_bidi0.direction(), StreamDirection::Bidirectional);
        assert_eq!(c_uni1.direction(), StreamDirection::Unidirectional);
    }

    #[test]
    fn local_open_respects_limits() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 1024, 1024);
        let _first = tbl.open_local_bidi().expect("first");
        let err = tbl.open_local_bidi().expect_err("must hit limit");
        assert_eq!(
            err,
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Bidirectional,
                limit: 1
            }
        );
    }

    #[test]
    fn stream_flow_control_enforced() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 10, 10);
        let id = tbl.open_local_bidi().expect("open");
        let s = tbl.stream_mut(id).expect("stream");
        s.write(8).expect("write");
        let err = s.write(3).expect_err("exhausted");
        assert!(matches!(
            err,
            QuicStreamError::Flow(FlowControlError::Exhausted { .. })
        ));
    }

    #[test]
    fn final_size_invariant_enforced() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        let s = tbl.stream_mut(id).expect("stream");
        s.receive(5).expect("recv");
        let err = s.set_final_size(4).expect_err("invalid");
        assert_eq!(
            err,
            QuicStreamError::InvalidFinalSize {
                final_size: 4,
                received: 5
            }
        );
    }

    #[test]
    fn stop_sending_blocks_future_writes() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 16, 16);
        let id = tbl.open_local_bidi().expect("open");
        let s = tbl.stream_mut(id).expect("stream");
        s.write(4).expect("initial write");
        s.on_stop_sending(42);
        let err = s.write(1).expect_err("must fail");
        assert_eq!(err, QuicStreamError::SendStopped { code: 42 });
    }

    #[test]
    fn stop_receiving_blocks_future_reads() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 16, 16);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        let s = tbl.stream_mut(id).expect("stream");
        s.stop_receiving(9);
        let err = s.receive(1).expect_err("must fail");
        assert_eq!(err, QuicStreamError::ReceiveStopped { code: 9 });
    }

    #[test]
    fn reset_receive_discards_buffered_data_and_blocks_future_reads() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        tbl.receive_stream_bytes(id, 0, Bytes::from_static(b"abc"), false)
            .expect("buffer data");

        tbl.reset_stream_receive(id, 0x44, 8).expect("reset");
        let s = tbl.stream(id).expect("stream");
        assert_eq!(s.recv_reset, Some((0x44, 8)));
        assert_eq!(s.final_size, Some(8));

        let err = tbl
            .receive_stream_segment(id, 3, 1, false)
            .expect_err("post-reset stream frame rejected");
        assert_eq!(
            err,
            StreamTableError::Stream(QuicStreamError::ReceiveReset {
                code: 0x44,
                final_size: 8
            })
        );
        let err = tbl
            .read_stream_bytes(id, 8)
            .expect_err("post-reset buffered bytes discarded");
        assert_eq!(
            err,
            StreamTableError::Stream(QuicStreamError::ReceiveReset {
                code: 0x44,
                final_size: 8
            })
        );
    }

    #[test]
    fn reset_send_final_size_must_cover_sent_bytes() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 32, 32);
        let id = tbl.open_local_bidi().expect("open");
        let s = tbl.stream_mut(id).expect("stream");
        s.write(8).expect("write");
        let err = s.reset_send(7, 7).expect_err("must fail");
        assert_eq!(
            err,
            QuicStreamError::InvalidFinalSize {
                final_size: 7,
                received: 8
            }
        );
        s.reset_send(7, 8).expect("valid reset");
        let err = s.reset_send(7, 9).expect_err("must fail");
        assert_eq!(
            err,
            QuicStreamError::InconsistentReset {
                previous_final_size: 8,
                new_final_size: 9
            }
        );
    }

    // ---- FlowCredit ----

    #[test]
    fn flow_credit_new_and_accessors() {
        let fc = FlowCredit::new(100);
        assert_eq!(fc.limit(), 100);
        assert_eq!(fc.used(), 0);
        assert_eq!(fc.remaining(), 100);
    }

    #[test]
    fn flow_credit_consume_exact_limit() {
        let mut fc = FlowCredit::new(10);
        fc.consume(10).expect("exact limit");
        assert_eq!(fc.remaining(), 0);
        assert_eq!(fc.used(), 10);
    }

    #[test]
    fn flow_credit_consume_zero() {
        let mut fc = FlowCredit::new(5);
        fc.consume(0).expect("zero consume");
        assert_eq!(fc.remaining(), 5);
    }

    #[test]
    fn flow_credit_consume_overflow_rejected() {
        let mut fc = FlowCredit::new(5);
        let err = fc.consume(6).unwrap_err();
        assert_eq!(
            err,
            FlowControlError::Exhausted {
                attempted: 6,
                remaining: 5
            }
        );
    }

    #[test]
    fn flow_credit_increase_limit_success() {
        let mut fc = FlowCredit::new(10);
        fc.consume(5).unwrap();
        fc.increase_limit(20).expect("increase");
        assert_eq!(fc.limit(), 20);
        assert_eq!(fc.remaining(), 15);
    }

    #[test]
    fn flow_credit_increase_limit_same_value() {
        let mut fc = FlowCredit::new(10);
        fc.increase_limit(10).expect("same value is ok");
    }

    #[test]
    fn flow_credit_increase_limit_regression() {
        let mut fc = FlowCredit::new(10);
        let err = fc.increase_limit(5).unwrap_err();
        assert_eq!(
            err,
            FlowControlError::LimitRegression {
                current: 10,
                requested: 5
            }
        );
    }

    // ---- Error Display ----

    #[test]
    fn flow_control_error_display_exhausted() {
        let err = FlowControlError::Exhausted {
            attempted: 100,
            remaining: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("exhausted"), "{msg}");
        assert!(msg.contains("100"), "{msg}");
        assert!(msg.contains('5'), "{msg}");
    }

    #[test]
    fn flow_control_error_display_regression() {
        let err = FlowControlError::LimitRegression {
            current: 20,
            requested: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains("regression"), "{msg}");
    }

    #[test]
    fn quic_stream_error_display_all_variants() {
        let tests: Vec<(QuicStreamError, &str)> = vec![
            (
                QuicStreamError::Flow(FlowControlError::Exhausted {
                    attempted: 1,
                    remaining: 0,
                }),
                "exhausted",
            ),
            (
                QuicStreamError::InvalidFinalSize {
                    final_size: 10,
                    received: 20,
                },
                "invalid final size",
            ),
            (QuicStreamError::SendStopped { code: 42 }, "send stopped"),
            (
                QuicStreamError::ReceiveStopped { code: 7 },
                "receive side stopped",
            ),
            (
                QuicStreamError::ReceiveReset {
                    code: 9,
                    final_size: 11,
                },
                "receive side reset",
            ),
            (
                QuicStreamError::InconsistentReset {
                    previous_final_size: 100,
                    new_final_size: 200,
                },
                "inconsistent reset",
            ),
            (
                QuicStreamError::SendFinished { final_size: 12 },
                "send side finished",
            ),
        ];
        for (err, expected_substr) in tests {
            let msg = err.to_string();
            assert!(msg.contains(expected_substr), "{msg}");
        }
    }

    #[test]
    fn stream_table_error_display_all_variants() {
        let id = StreamId(42);
        assert!(
            StreamTableError::DuplicateStream(id)
                .to_string()
                .contains("duplicate")
        );
        assert!(
            StreamTableError::UnknownStream(id)
                .to_string()
                .contains("unknown")
        );
        assert!(
            StreamTableError::InvalidRemoteStream(id)
                .to_string()
                .contains("invalid remote stream")
        );
        assert!(
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                limit: 10
            }
            .to_string()
            .contains("limit exceeded")
        );
    }

    // ---- StreamTable ----

    #[test]
    fn stream_table_len_and_is_empty() {
        let mut tbl = StreamTable::new(StreamRole::Client, 5, 5, 100, 100);
        assert!(tbl.is_empty());
        assert_eq!(tbl.len(), 0);
        tbl.open_local_bidi().unwrap();
        assert!(!tbl.is_empty());
        assert_eq!(tbl.len(), 1);
    }

    #[test]
    fn stream_table_unknown_stream() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 1, 100, 100);
        let unknown_stream_id = StreamId(999);
        let err = tbl.stream_mut(unknown_stream_id).unwrap_err();
        assert_eq!(err, StreamTableError::UnknownStream(unknown_stream_id));
    }

    #[test]
    fn stream_table_accept_duplicate_remote() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("first accept");
        let err = tbl.accept_remote_stream(id).unwrap_err();
        assert_eq!(err, StreamTableError::DuplicateStream(id));
    }

    #[test]
    fn stream_table_rejects_locally_initiated_id_as_remote() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 100, 100);
        let local_id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 5);
        let err = tbl
            .accept_remote_stream(local_id)
            .expect_err("locally initiated id must not be accepted as remote");
        assert_eq!(err, StreamTableError::InvalidRemoteStream(local_id));
    }

    #[test]
    fn stream_table_rejects_remote_stream_over_limit() {
        // Server endpoint accepting client-initiated (remote) streams, capped at
        // 2 per direction. This is the RFC 9000 §4.6 MAX_STREAMS bound that
        // prevents a peer from forcing unbounded remote-stream allocations.
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        tbl.set_remote_stream_limits(2, 2);

        // Bidi sequences 0 and 1 are within the limit of 2.
        for seq in 0..2 {
            let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, seq);
            tbl.accept_remote_stream(id)
                .expect("within-limit remote bidi accepted");
        }
        // Sequence 2 (the third) is at the limit and must be rejected.
        let over_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 2);
        assert_eq!(
            tbl.accept_remote_stream(over_bidi).unwrap_err(),
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Bidirectional,
                limit: 2,
            }
        );

        // The unidirectional limit is tracked independently of bidirectional.
        let uni0 = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 0);
        tbl.accept_remote_stream(uni0)
            .expect("within-limit remote uni accepted");
        let over_uni = StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 2);
        assert_eq!(
            tbl.accept_remote_stream(over_uni).unwrap_err(),
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                limit: 2,
            }
        );
    }

    #[test]
    fn stream_table_remote_limit_defaults_to_unbounded() {
        // Without an explicit `set_remote_stream_limits`, acceptance stays
        // unbounded so existing callers keep their prior behavior; only the
        // connection layer opts into a finite cap.
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let high = StreamId::local(
            StreamRole::Client,
            StreamDirection::Bidirectional,
            1_000_000,
        );
        tbl.accept_remote_stream(high)
            .expect("default remote limit must be unbounded");
    }

    #[test]
    fn stream_table_open_local_uni() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 2, 100, 100);
        let id1 = tbl.open_local_uni().expect("first uni");
        let id2 = tbl.open_local_uni().expect("second uni");
        assert_ne!(id1, id2);
        assert_eq!(id1.direction(), StreamDirection::Unidirectional);
        assert!(id1.is_local_for(StreamRole::Server));

        let err = tbl.open_local_uni().unwrap_err();
        assert!(matches!(
            err,
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                ..
            }
        ));
    }

    // ---- StreamId ----

    #[test]
    fn stream_id_server_initiated() {
        let s_bidi = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
        assert!(s_bidi.is_local_for(StreamRole::Server));
        assert!(!s_bidi.is_local_for(StreamRole::Client));
        assert_eq!(s_bidi.direction(), StreamDirection::Bidirectional);
    }

    #[test]
    fn stream_id_sequence_encoding() {
        // Client bidi: bits = (seq << 2) | 0b00
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 3);
        assert_eq!(id.0, 3 << 2); // 12
        // Server uni: bits = (seq << 2) | 0b11
        let id = StreamId::local(StreamRole::Server, StreamDirection::Unidirectional, 2);
        assert_eq!(id.0, (2 << 2) | 0b11); // 11
    }

    // ---- QuicStream ----

    #[test]
    fn quic_stream_set_final_size_matching_existing() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).unwrap();
        let s = tbl.stream_mut(id).unwrap();
        s.set_final_size(50).expect("first set");
        s.set_final_size(50).expect("same value should succeed");
    }

    #[test]
    fn quic_stream_set_final_size_mismatch() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).unwrap();
        let s = tbl.stream_mut(id).unwrap();
        s.set_final_size(50).unwrap();
        let err = s.set_final_size(60).unwrap_err();
        assert!(matches!(err, QuicStreamError::InvalidFinalSize { .. }));
    }

    #[test]
    fn quic_stream_receive_past_final_size() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).unwrap();
        let s = tbl.stream_mut(id).unwrap();
        s.set_final_size(5).unwrap();
        s.receive(3).expect("within limit");
        let err = s.receive(3).unwrap_err();
        assert!(matches!(err, QuicStreamError::InvalidFinalSize { .. }));
    }

    #[test]
    fn quic_stream_on_stop_sending_only_takes_first_code() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 100, 100);
        let id = tbl.open_local_bidi().unwrap();
        let s = tbl.stream_mut(id).unwrap();
        s.on_stop_sending(10);
        s.on_stop_sending(20); // should be ignored
        let err = s.write(1).unwrap_err();
        assert_eq!(err, QuicStreamError::SendStopped { code: 10 });
    }

    #[test]
    fn quic_stream_error_from_flow_control() {
        let fc_err = FlowControlError::Exhausted {
            attempted: 5,
            remaining: 3,
        };
        let qs_err: QuicStreamError = fc_err.into();
        assert!(matches!(qs_err, QuicStreamError::Flow(_)));
    }

    #[test]
    fn flow_credit_consume_to_and_release() {
        let mut fc = FlowCredit::new(100);
        assert_eq!(fc.consume_to(10).expect("consume to 10"), 10);
        assert_eq!(fc.consume_to(10).expect("idempotent"), 0);
        assert_eq!(fc.consume_to(25).expect("consume to 25"), 15);
        fc.release(5);
        assert_eq!(fc.used(), 20);
        assert_eq!(fc.remaining(), 80);
    }

    #[test]
    fn stream_reassembly_advances_when_gap_is_filled() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");

        tbl.receive_stream_segment(id, 5, 5, false)
            .expect("out-of-order receive");
        assert_eq!(tbl.stream(id).expect("stream").recv_offset, 0);

        tbl.receive_stream_segment(id, 0, 5, false)
            .expect("fill initial gap");
        assert_eq!(tbl.stream(id).expect("stream").recv_offset, 10);
    }

    #[test]
    fn bounded_recv_window_advertises_on_read_with_hysteresis() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 1 << 20, 1 << 20);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        let advertised = tbl
            .configure_stream_recv_window(id, 100)
            .expect("configure");
        assert_eq!(advertised, 100);
        assert_eq!(tbl.bounded_recv_window_advertisements(), vec![(id, 100)]);

        // Under a sixteenth window drained: no fresh advertisement yet.
        tbl.receive_stream_bytes(id, 0, Bytes::from_static(&[0u8; 4]), false)
            .expect("recv");
        assert_eq!(tbl.read_stream_bytes(id, 4).expect("read").len(), 4);
        assert!(tbl.advance_bounded_recv_windows().is_empty());

        // Crossing the sixteenth-window hysteresis advances the advertisement.
        tbl.receive_stream_bytes(id, 4, Bytes::from_static(&[0u8; 4]), false)
            .expect("recv2");
        assert_eq!(tbl.read_stream_bytes(id, 4).expect("read2").len(), 4);
        assert_eq!(tbl.advance_bounded_recv_windows(), vec![(id, 108)]);
        assert_eq!(tbl.bounded_recv_window_advertisements(), vec![(id, 108)]);
        // Receive-credit enforcement stays permissive (fail-open for peers
        // that predate bounded windows): only the advertisement moved.
        assert!(tbl.stream(id).expect("stream").recv_credit.limit() >= 1 << 20);
    }

    #[test]
    fn bounded_recv_window_credit_stays_consumption_clocked_past_a_hole() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 1 << 20, 1 << 20);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        assert_eq!(
            tbl.configure_stream_recv_window(id, 100)
                .expect("configure"),
            100
        );
        // A segment arrives beyond a head-of-line hole (0..10 missing): the
        // application cannot read, and the advertised credit must NOT chase
        // the received offset — settled after four attempts (MATRIX-227
        // history on advance_bounded_recv_windows).
        tbl.receive_stream_bytes(id, 10, Bytes::from(vec![7u8; 40]), false)
            .expect("recv past hole");
        assert!(tbl.read_stream_bytes(id, 100).expect("read").is_empty());
        assert!(tbl.advance_bounded_recv_windows().is_empty());
    }

    #[test]
    fn fresh_stream_send_limit_caps_writes_and_grows_via_max_stream_data() {
        let mut tbl = StreamTable::new_with_connection_limits(
            StreamRole::Client,
            1,
            0,
            1 << 20,
            1 << 20,
            1 << 20,
            1 << 20,
        );
        let stream = tbl.open_local_bidi().expect("open");
        assert_eq!(
            tbl.set_fresh_stream_send_limit(stream, 10).expect("cap"),
            10
        );
        assert_eq!(tbl.stream_send_credit_remaining(stream), 10);
        tbl.write_stream_bytes(stream, Bytes::from_static(b"0123456789"), false)
            .expect("fill window");
        let err = tbl
            .write_stream_bytes(stream, Bytes::from_static(b"x"), false)
            .expect_err("write past the bounded window must fail");
        assert!(matches!(
            err,
            StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted { .. }))
        ));
        // A stale/duplicate (lower) advertisement is ignored, not an error
        // (RFC 9000 §19.10) — re-attached advertisements repeat older maxima.
        tbl.increase_stream_send_limit(stream, 5)
            .expect("stale advertisement is a no-op");
        assert_eq!(tbl.stream_send_credit_remaining(stream), 0);
        tbl.increase_stream_send_limit(stream, 16).expect("grow");
        assert_eq!(tbl.stream_send_credit_remaining(stream), 6);
        tbl.write_stream_bytes(stream, Bytes::from_static(b"abcdef"), false)
            .expect("write after the window grew");
    }

    #[test]
    fn stream_receive_segment_fin_sets_final_size() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");

        tbl.receive_stream_segment(id, 0, 4, true)
            .expect("receive with fin");
        let s = tbl.stream(id).expect("stream");
        assert_eq!(s.recv_offset, 4);
        assert_eq!(s.final_size, Some(4));
    }

    #[test]
    fn stream_receive_segment_fin_error_rolls_back_credit() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        tbl.receive_stream_segment(id, 0, 4, true)
            .expect("first fin at offset 4");
        let before_used = tbl.stream(id).expect("stream").recv_credit.used();
        let err = tbl
            .receive_stream_segment(id, 6, 2, true)
            .expect_err("inconsistent final size must fail");
        assert!(matches!(
            err,
            StreamTableError::Stream(QuicStreamError::InvalidFinalSize { .. })
        ));
        let after_used = tbl.stream(id).expect("stream").recv_credit.used();
        assert_eq!(before_used, after_used);
    }

    #[test]
    fn stream_bytes_round_trip_out_of_order_with_retransmit_and_fin() {
        let mut sender =
            StreamTable::new_with_connection_limits(StreamRole::Client, 1, 0, 64, 64, 64, 64);
        let stream = sender.open_local_bidi().expect("open");
        let payload = Bytes::from_static(b"hello reliable stream control");
        sender
            .write_stream_bytes(stream, payload.clone(), true)
            .expect("queue payload");

        let first = sender.pop_next_stream_frame(8).expect("first frame");
        let lost = sender.pop_next_stream_frame(8).expect("lost frame");
        let last = sender.pop_next_stream_frame(64).expect("last frame");
        assert_eq!(first.offset, 0);
        assert_eq!(lost.offset, 8);
        assert_eq!(last.offset, 16);
        assert!(last.fin);
        assert!(!lost.retransmit);

        sender
            .requeue_sent_stream_frame(stream, lost.offset)
            .expect("requeue lost frame");
        let retransmit = sender
            .pop_next_stream_frame(8)
            .expect("retransmitted frame");
        assert_eq!(retransmit.offset, lost.offset);
        assert_eq!(retransmit.data, lost.data);
        assert!(retransmit.retransmit);

        let mut receiver =
            StreamTable::new_with_connection_limits(StreamRole::Server, 0, 0, 64, 64, 64, 64);
        receiver.accept_remote_stream(stream).expect("accept");

        receiver
            .receive_stream_bytes(stream, last.offset, last.data.clone(), last.fin)
            .expect("receive tail first");
        assert_eq!(receiver.stream(stream).expect("stream").recv_offset, 0);
        receiver
            .receive_stream_bytes(stream, first.offset, first.data.clone(), first.fin)
            .expect("receive head");
        assert_eq!(receiver.stream(stream).expect("stream").recv_offset, 8);
        receiver
            .receive_stream_bytes(
                stream,
                retransmit.offset,
                retransmit.data.clone(),
                retransmit.fin,
            )
            .expect("receive retransmit");
        receiver
            .receive_stream_bytes(stream, lost.offset, lost.data.clone(), lost.fin)
            .expect("duplicate lost frame must dedup");

        let mut out = Vec::new();
        while !receiver.is_stream_read_eof(stream).expect("eof check") {
            let chunk = receiver.read_stream_bytes(stream, 5).expect("read chunk");
            assert!(!chunk.is_empty(), "no read gap after retransmit");
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, payload.as_ref());
    }

    #[test]
    fn stream_io_async_read_observes_fin_as_eof() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Server, 0, 0, 16, 16, 16, 16);
        let stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        table.accept_remote_stream(stream).expect("accept");
        table
            .receive_stream_bytes(stream, 0, Bytes::from_static(b"abc"), true)
            .expect("receive fin");

        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut storage);
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut read_buf);
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }
        assert_eq!(read_buf.filled(), b"abc");

        let mut eof_storage = [0u8; 8];
        let mut eof_buf = ReadBuf::new(&mut eof_storage);
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut eof_buf);
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }
        assert!(eof_buf.filled().is_empty());
        assert!(table.is_stream_read_eof(stream).expect("eof"));
    }

    #[test]
    fn stream_io_async_write_enforces_flow_control_without_consuming_credit() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Client, 1, 0, 4, 4, 4, 4);
        let stream = table.open_local_bidi().expect("open");
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);

        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncWrite::poll_write(Pin::new(&mut io), &mut cx, b"abcde");
            assert!(matches!(poll, Poll::Pending));
        }
        assert_eq!(table.connection_send_remaining(), 4);
        assert_eq!(table.stream(stream).expect("stream").send_offset, 0);

        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncWrite::poll_write(Pin::new(&mut io), &mut cx, b"abcd");
            assert!(matches!(poll, Poll::Ready(Ok(4))));
        }
        assert_eq!(table.connection_send_remaining(), 0);
        let frame = table.pop_next_stream_frame(16).expect("stream frame");
        assert_eq!(frame.data.as_ref(), b"abcd");
        assert!(!frame.fin);
    }

    #[test]
    fn stream_io_pending_read_wakes_when_bytes_arrive() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Server, 0, 0, 16, 16, 16, 16);
        let stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        table.accept_remote_stream(stream).expect("accept");

        let (counter, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut storage);
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut read_buf);
            assert!(matches!(poll, Poll::Pending));
        }
        assert_eq!(counter.count(), 0, "pending read must not self-wake");

        table
            .receive_stream_bytes(stream, 0, Bytes::from_static(b"abc"), true)
            .expect("receive bytes");
        assert_eq!(counter.count(), 1, "received bytes must wake reader");

        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut read_buf);
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }
        assert_eq!(read_buf.filled(), b"abc");
    }

    #[test]
    fn stream_io_pending_write_wakes_after_flow_limit_increase() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Client, 1, 0, 4, 16, 16, 16);
        let stream = table.open_local_bidi().expect("open");

        let (counter, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncWrite::poll_write(Pin::new(&mut io), &mut cx, b"abcde");
            assert!(matches!(poll, Poll::Pending));
        }
        assert_eq!(counter.count(), 0, "pending write must not self-wake");
        assert_eq!(table.stream(stream).expect("stream").send_offset, 0);

        table
            .increase_stream_send_limit(stream, 8)
            .expect("increase stream limit");
        assert_eq!(counter.count(), 1, "limit increase must wake writer");

        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncWrite::poll_write(Pin::new(&mut io), &mut cx, b"abcde");
            assert!(matches!(poll, Poll::Ready(Ok(5))));
        }
        let frame = table.pop_next_stream_frame(16).expect("stream frame");
        assert_eq!(frame.data.as_ref(), b"abcde");
    }

    #[test]
    fn stream_io_pending_read_wakes_when_receive_side_stops() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Server, 0, 0, 16, 16, 16, 16);
        let stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        table.accept_remote_stream(stream).expect("accept");

        let (counter, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut storage);
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut read_buf);
            assert!(matches!(poll, Poll::Pending));
        }
        table.stop_receiving(stream, 9).expect("stop receiving");
        assert_eq!(counter.count(), 1, "stop_receiving must wake reader");
        {
            let mut io = table.stream_io(stream).expect("io");
            let poll = AsyncRead::poll_read(Pin::new(&mut io), &mut cx, &mut read_buf);
            assert!(matches!(poll, Poll::Ready(Err(_))));
        }
    }

    #[test]
    fn pop_pending_stream_frame_coalesces_contiguous_retransmits() {
        let mut table = StreamTable::new_with_connection_limits(
            StreamRole::Client,
            1,
            0,
            65536,
            65536,
            65536,
            65536,
        );
        let stream = table.open_local_bidi().expect("open");
        table
            .write_stream_bytes(stream, Bytes::from(vec![0xAB; 4096]), false)
            .expect("queue stream bytes");

        // First emission at tiny wire size: 8 frames of 512 bytes.
        let mut emitted = Vec::new();
        while let Some(frame) = table.pop_next_stream_frame(512) {
            emitted.push((frame.offset, frame.data.len()));
        }
        assert_eq!(emitted.len(), 8, "eight tiny first-emission frames");

        // Loss: requeue all eight in REVERSE (each requeue pushes to the
        // queue front), mirroring the transport's retransmit path, so the
        // pending queue ends up in ascending offset order.
        for (offset, _) in emitted.iter().rev() {
            table
                .requeue_sent_stream_frame(stream, *offset)
                .expect("requeue");
        }

        // Retransmission at full wire size coalesces the contiguous tiny
        // frames into one frame instead of eight.
        let frame = table
            .pop_next_stream_frame(8192)
            .expect("coalesced retransmit frame");
        assert!(frame.retransmit);
        assert_eq!(frame.offset, 0);
        assert_eq!(
            frame.data.len(),
            4096,
            "eight contiguous 512-byte retransmits must merge into one frame"
        );
        assert_eq!(&frame.data[..], vec![0xAB; 4096].as_slice());
        assert!(
            table.pop_next_stream_frame(8192).is_none(),
            "no residual retransmit fragments"
        );
    }

    #[test]
    fn requeue_unemitted_stream_frame_preserves_original_send_state() {
        let mut table =
            StreamTable::new_with_connection_limits(StreamRole::Client, 1, 0, 64, 64, 64, 64);
        let stream = table.open_local_bidi().expect("open");
        table
            .write_stream_bytes(stream, Bytes::from_static(b"packet-budget"), true)
            .expect("queue stream bytes");

        let frame = table.pop_next_stream_frame(6).expect("stream frame");
        assert!(!frame.retransmit);
        let offset = frame.offset;
        let data = frame.data.clone();
        table
            .requeue_unemitted_stream_frame(frame)
            .expect("requeue unemitted");
        assert!(
            !table
                .stream(stream)
                .expect("stream exists")
                .sent_stream_frames
                .contains_key(&offset),
            "unemitted frames must not remain marked as sent"
        );

        let next = table.pop_next_stream_frame(6).expect("requeued frame");
        assert_eq!(next.offset, offset);
        assert_eq!(next.data, data);
        assert!(!next.retransmit);
    }

    #[test]
    fn connection_send_limit_is_enforced() {
        let mut tbl =
            StreamTable::new_with_connection_limits(StreamRole::Client, 2, 0, 100, 100, 10, 100);
        let s1 = tbl.open_local_bidi().expect("s1");
        let s2 = tbl.open_local_bidi().expect("s2");
        tbl.write_stream(s1, 7).expect("first write");
        let err = tbl.write_stream(s2, 4).expect_err("must exceed conn send");
        assert!(matches!(
            err,
            StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted { .. }))
        ));
    }

    #[test]
    fn connection_recv_limit_is_enforced() {
        let mut tbl =
            StreamTable::new_with_connection_limits(StreamRole::Server, 0, 0, 100, 100, 100, 6);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        tbl.receive_stream_segment(id, 0, 6, false)
            .expect("within limit");
        let err = tbl
            .receive_stream_segment(id, 6, 1, false)
            .expect_err("must exceed conn recv");
        assert!(matches!(
            err,
            StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted { .. }))
        ));
    }

    #[test]
    fn writable_stream_selection_round_robin() {
        let mut tbl = StreamTable::new(StreamRole::Client, 3, 0, 10, 10);
        let s1 = tbl.open_local_bidi().expect("s1");
        let s2 = tbl.open_local_bidi().expect("s2");
        let s3 = tbl.open_local_bidi().expect("s3");
        assert_eq!(tbl.next_writable_stream(), Some(s1));
        assert_eq!(tbl.next_writable_stream(), Some(s2));
        assert_eq!(tbl.next_writable_stream(), Some(s3));
        assert_eq!(tbl.next_writable_stream(), Some(s1));
    }

    // ---- Gap-filling tests ----

    #[test]
    fn receive_segment_offset_overflow_u64() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, u64::MAX, u64::MAX);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");
        let s = tbl.stream_mut(id).expect("stream");
        let err = s
            .receive_segment(u64::MAX, 1, false)
            .expect_err("must overflow");
        assert_eq!(
            err,
            QuicStreamError::OffsetOverflow {
                offset: u64::MAX,
                len: 1,
            }
        );
        // Also verify a large offset + large len that overflows
        let err2 = s
            .receive_segment(u64::MAX - 5, 10, false)
            .expect_err("must overflow");
        assert_eq!(
            err2,
            QuicStreamError::OffsetOverflow {
                offset: u64::MAX - 5,
                len: 10,
            }
        );
    }

    #[test]
    fn increase_connection_send_and_recv_limits() {
        let mut tbl =
            StreamTable::new_with_connection_limits(StreamRole::Client, 2, 0, 100, 100, 10, 10);
        // Increase send limit
        tbl.increase_connection_send_limit(20)
            .expect("increase send");
        assert_eq!(tbl.connection_send_remaining(), 20);
        // RFC 9000 §19.9: a MAX_DATA that does not increase the limit is
        // ignored, not an error (re-attached advertisements repeat maxima).
        tbl.increase_connection_send_limit(15)
            .expect("non-increasing limit ignored");
        assert_eq!(tbl.connection_send_remaining(), 20);
        // Same value is also a no-op.
        tbl.increase_connection_send_limit(20)
            .expect("same value ok");
        assert_eq!(tbl.connection_send_remaining(), 20);

        // Increase recv limit
        tbl.increase_connection_recv_limit(30)
            .expect("increase recv");
        assert_eq!(tbl.connection_recv_remaining(), 30);
        // RFC 9000 §19.9: a non-increasing connection recv limit is ignored.
        tbl.increase_connection_recv_limit(5)
            .expect("non-increasing limit ignored");
        assert_eq!(tbl.connection_recv_remaining(), 30);
    }

    #[test]
    fn connection_send_and_recv_remaining_accessors() {
        let mut tbl =
            StreamTable::new_with_connection_limits(StreamRole::Client, 2, 0, 100, 100, 50, 40);
        assert_eq!(tbl.connection_send_remaining(), 50);
        assert_eq!(tbl.connection_recv_remaining(), 40);

        // Consume some send credit
        let s1 = tbl.open_local_bidi().expect("s1");
        tbl.write_stream(s1, 15).expect("write");
        assert_eq!(tbl.connection_send_remaining(), 35);

        // Consume some recv credit via an accepted remote stream
        let remote_id = StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(remote_id).expect("accept");
        tbl.receive_stream_segment(remote_id, 0, 10, false)
            .expect("recv");
        assert_eq!(tbl.connection_recv_remaining(), 30);
    }

    #[test]
    fn next_writable_stream_with_connection_send_exhausted() {
        let mut tbl =
            StreamTable::new_with_connection_limits(StreamRole::Client, 2, 0, 100, 100, 5, 100);
        let s1 = tbl.open_local_bidi().expect("s1");
        let _s2 = tbl.open_local_bidi().expect("s2");
        // Exhaust all connection send credit
        tbl.write_stream(s1, 5).expect("write all conn credit");
        assert_eq!(tbl.connection_send_remaining(), 0);
        // Even though per-stream credit remains, connection credit is gone
        assert_eq!(tbl.next_writable_stream(), None);
    }

    #[test]
    fn next_writable_stream_skips_stop_sending() {
        let mut tbl = StreamTable::new(StreamRole::Client, 3, 0, 100, 100);
        let s1 = tbl.open_local_bidi().expect("s1");
        let s2 = tbl.open_local_bidi().expect("s2");
        let s3 = tbl.open_local_bidi().expect("s3");

        // Advance cursor to s1
        assert_eq!(tbl.next_writable_stream(), Some(s1));

        // Stop-send s2 so it should be skipped
        tbl.stream_mut(s2).expect("stream").on_stop_sending(99);

        // Next should skip s2 and return s3
        assert_eq!(tbl.next_writable_stream(), Some(s3));

        // And the one after that wraps around to s1 (s2 still skipped)
        assert_eq!(tbl.next_writable_stream(), Some(s1));

        // Another round should again skip s2
        assert_eq!(tbl.next_writable_stream(), Some(s3));
    }

    #[test]
    fn next_writable_stream_skips_send_reset() {
        let mut tbl = StreamTable::new(StreamRole::Client, 3, 0, 100, 100);
        let s1 = tbl.open_local_bidi().expect("s1");
        let s2 = tbl.open_local_bidi().expect("s2");
        let s3 = tbl.open_local_bidi().expect("s3");

        // Advance cursor to s1
        assert_eq!(tbl.next_writable_stream(), Some(s1));

        // Write some data to s2 then reset it
        tbl.write_stream(s2, 5).expect("write s2");
        tbl.stream_mut(s2)
            .expect("stream")
            .reset_send(42, 5)
            .expect("reset");

        // Next should skip s2 (reset) and return s3
        assert_eq!(tbl.next_writable_stream(), Some(s3));

        // Wrap around skips s2 again
        assert_eq!(tbl.next_writable_stream(), Some(s1));
        assert_eq!(tbl.next_writable_stream(), Some(s3));
    }

    #[test]
    fn next_writable_stream_includes_remote_bidi() {
        let mut tbl = StreamTable::new(StreamRole::Server, 1, 0, 100, 100);

        // Remote client opens a bidi stream
        let remote_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(remote_bidi)
            .expect("accept remote bidi");

        // Server opens a local bidi stream
        let local_bidi = tbl.open_local_bidi().expect("local bidi");

        let first = tbl
            .next_writable_stream()
            .expect("should have writable stream");
        let second = tbl
            .next_writable_stream()
            .expect("should have second writable stream");

        assert_ne!(first, second);
        assert!(first == remote_bidi || first == local_bidi);
        assert!(second == remote_bidi || second == local_bidi);
    }

    #[test]
    fn overlapping_recv_ranges_merge() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 200, 200);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");

        let s = tbl.stream_mut(id).expect("stream");

        // Insert ranges [10..15), [20..25), [30..35) with gaps
        s.receive_segment(10, 5, false).expect("10..15");
        s.receive_segment(20, 5, false).expect("20..25");
        s.receive_segment(30, 5, false).expect("30..35");
        // recv_offset should still be 0 since [0..10) is missing
        assert_eq!(s.recv_offset, 0);

        // Case 1: full-contains -- insert [12..14) which is fully inside [10..15)
        s.receive_segment(12, 2, false).expect("contained");
        assert_eq!(s.recv_offset, 0);

        // Case 2: spans multiple existing ranges -- insert [14..31) which merges
        // [10..15) + gap + [20..25) + gap + [30..35) into one big [10..35)
        s.receive_segment(14, 17, false).expect("span multiple");
        // Still 0 because [0..10) is missing
        assert_eq!(s.recv_offset, 0);

        // Now fill [0..10) and everything should advance to 35
        s.receive_segment(0, 10, false).expect("fill head");
        assert_eq!(s.recv_offset, 35);
    }

    #[test]
    fn fin_with_zero_length_final_segment() {
        let mut tbl = StreamTable::new(StreamRole::Server, 0, 0, 100, 100);
        let id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(id).expect("accept");

        // Receive 10 bytes first
        tbl.receive_stream_segment(id, 0, 10, false)
            .expect("recv data");
        let s = tbl.stream(id).expect("stream");
        assert_eq!(s.recv_offset, 10);
        assert_eq!(s.final_size, None);

        // FIN with zero-length segment at offset=10
        tbl.receive_stream_segment(id, 10, 0, true)
            .expect("fin zero len");
        let s = tbl.stream(id).expect("stream");
        assert_eq!(s.final_size, Some(10));
        // recv_offset should not regress
        assert_eq!(s.recv_offset, 10);
    }

    #[test]
    fn write_after_reset_send_is_rejected() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 0, 100, 100);
        let id = tbl.open_local_bidi().expect("open");
        let s = tbl.stream_mut(id).expect("stream");
        s.write(5).expect("initial write");
        s.reset_send(42, 5).expect("reset");
        assert_eq!(s.send_reset, Some((42, 5)));

        // RFC 9000 §3.1: after RESET_STREAM, no further STREAM frames.
        // Stream-level write must reject:
        let err = s.write(1).expect_err("must fail after reset_send");
        assert_eq!(err, QuicStreamError::SendStopped { code: 42 });

        // Table-level write_stream must also reject after reset_send alone
        // (without requiring on_stop_sending):
        let err = tbl.write_stream(id, 1).expect_err("table write must fail");
        assert_eq!(
            err,
            StreamTableError::Stream(QuicStreamError::SendStopped { code: 42 })
        );
    }

    #[test]
    fn server_role_bidi_limit_enforcement() {
        // Server role: bidi limit=2, uni limit=1
        let mut tbl = StreamTable::new(StreamRole::Server, 2, 1, 100, 100);

        // Open 2 bidi streams from Server
        let s1 = tbl.open_local_bidi().expect("server bidi 0");
        let s2 = tbl.open_local_bidi().expect("server bidi 1");
        assert!(s1.is_local_for(StreamRole::Server));
        assert!(s2.is_local_for(StreamRole::Server));
        assert_eq!(s1.direction(), StreamDirection::Bidirectional);
        assert_eq!(s2.direction(), StreamDirection::Bidirectional);
        assert_ne!(s1, s2);

        // Third should fail with limit
        let err = tbl.open_local_bidi().expect_err("bidi limit");
        assert_eq!(
            err,
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Bidirectional,
                limit: 2,
            }
        );

        // Uni limit at 1
        let u1 = tbl.open_local_uni().expect("server uni 0");
        assert!(u1.is_local_for(StreamRole::Server));
        assert_eq!(u1.direction(), StreamDirection::Unidirectional);

        let err = tbl.open_local_uni().expect_err("uni limit");
        assert_eq!(
            err,
            StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                limit: 1,
            }
        );

        // Server can still accept client-initiated bidi streams (no limit on remote accept)
        let remote_bidi = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);
        tbl.accept_remote_stream(remote_bidi)
            .expect("accept client bidi");
        assert!(!remote_bidi.is_local_for(StreamRole::Server));
        assert_eq!(tbl.len(), 4); // 2 local bidi + 1 local uni + 1 remote bidi
    }

    // =========================================================================
    // Wave 44 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn stream_role_debug_clone_copy_eq() {
        let r = StreamRole::Client;
        let copied = r;
        let cloned = r;
        assert_eq!(copied, cloned);
        assert_ne!(StreamRole::Client, StreamRole::Server);
        assert!(format!("{r:?}").contains("Client"));
        assert!(format!("{:?}", StreamRole::Server).contains("Server"));
    }

    #[test]
    fn stream_direction_debug_clone_copy_eq() {
        let d = StreamDirection::Bidirectional;
        let copied = d;
        let cloned = d;
        assert_eq!(copied, cloned);
        assert_ne!(
            StreamDirection::Bidirectional,
            StreamDirection::Unidirectional
        );
        assert!(format!("{d:?}").contains("Bidirectional"));
    }

    #[test]
    fn stream_id_debug_clone_copy_ord_hash() {
        use std::collections::HashSet;
        let a = StreamId(0);
        let b = StreamId(4);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("StreamId"), "{dbg}");
        let copied = a;
        let cloned = a;
        assert_eq!(copied, cloned);
        assert!(a < b);
        assert!(b > a);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn flow_control_error_debug_clone_eq_display() {
        let e1 = FlowControlError::Exhausted {
            attempted: 100,
            remaining: 50,
        };
        let e2 = FlowControlError::LimitRegression {
            current: 200,
            requested: 100,
        };
        assert!(format!("{e1:?}").contains("Exhausted"));
        assert!(format!("{e2:?}").contains("LimitRegression"));
        assert!(format!("{e1}").contains("exhausted"));
        assert!(format!("{e2}").contains("regression"));
        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);
        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn quic_stream_error_debug_clone_eq_display() {
        let e1 = QuicStreamError::SendStopped { code: 42 };
        let e2 = QuicStreamError::ReceiveStopped { code: 7 };
        let e3 = QuicStreamError::OffsetOverflow {
            offset: 10,
            len: 20,
        };
        assert!(format!("{e1:?}").contains("SendStopped"));
        assert!(format!("{e1}").contains("send stopped"));
        assert!(format!("{e2}").contains("receive side stopped"));
        assert!(format!("{e3}").contains("overflow"));
        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);
    }

    #[test]
    fn stream_read_write_constraints_enforced() {
        let mut tbl = StreamTable::new(StreamRole::Client, 1, 1, 100, 100);

        // Client-initiated uni stream: Client can write, cannot read.
        let local_uni = tbl.open_local_uni().expect("open local uni");
        let err = tbl
            .receive_stream_segment(local_uni, 0, 10, false)
            .unwrap_err();
        assert_eq!(err, StreamTableError::StreamNotReadable(local_uni));
        tbl.write_stream(local_uni, 10)
            .expect("can write local uni");

        // Server-initiated uni stream: Client can read, cannot write.
        let remote_uni = StreamId::local(StreamRole::Server, StreamDirection::Unidirectional, 0);
        tbl.accept_remote_stream(remote_uni)
            .expect("accept remote uni");
        let err = tbl.write_stream(remote_uni, 10).unwrap_err();
        assert_eq!(err, StreamTableError::StreamNotWritable(remote_uni));
        tbl.receive_stream_segment(remote_uni, 0, 10, false)
            .expect("can read remote uni");
    }

    #[test]
    fn stream_table_error_debug_clone_eq_display() {
        let e1 = StreamTableError::DuplicateStream(StreamId(0));
        let e2 = StreamTableError::UnknownStream(StreamId(1));
        let e3 = StreamTableError::InvalidRemoteStream(StreamId(2));
        let e4 = StreamTableError::StreamNotWritable(StreamId(3));
        let e5 = StreamTableError::StreamNotReadable(StreamId(4));
        assert!(format!("{e1:?}").contains("DuplicateStream"));
        assert!(format!("{e1}").contains("duplicate stream"));
        assert!(format!("{e2}").contains("unknown stream"));
        assert!(format!("{e3}").contains("invalid remote stream"));
        assert!(format!("{e4}").contains("stream not writable"));
        assert!(format!("{e5}").contains("stream not readable"));
        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);
        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn stream_table_error_from_quic_stream_error() {
        let inner = QuicStreamError::SendStopped { code: 99 };
        let outer: StreamTableError = inner.clone().into();
        assert_eq!(outer, StreamTableError::Stream(inner));
    }

    // ========================================================================
    // Golden tests for HTTP/3 flow-control + stream-reset race conditions
    // ========================================================================

    #[cfg(feature = "http3")]
    mod h3_flow_reset_golden_tests {
        use super::*;

        /// Serialize flow control state for golden comparison.
        fn serialize_flow_state(table: &StreamTable, stream_id: StreamId) -> String {
            let stream = table.stream(stream_id).expect("stream exists");
            format!(
                "connection_send_used={},connection_send_limit={},connection_send_remaining={},\
                 stream_send_used={},stream_send_limit={},stream_send_remaining={},\
                 stream_send_offset={},stream_recv_offset={},send_reset={:?}",
                table.send_connection_credit.used(),
                table.send_connection_credit.limit(),
                table.send_connection_credit.remaining(),
                stream.send_credit.used(),
                stream.send_credit.limit(),
                stream.send_credit.remaining(),
                stream.send_offset,
                stream.recv_offset,
                stream.send_reset
            )
        }

        #[test]
        fn golden_max_data_increment_after_reset() {
            // Test scenario 1: MAX_DATA increment after RESET
            let mut table = StreamTable::new_with_connection_limits(
                StreamRole::Client,
                2,   // max bidi
                0,   // max uni
                100, // stream send window
                100, // stream recv window
                200, // connection send limit
                200, // connection recv limit
            );

            let stream_id = table.open_local_bidi().expect("open stream");

            // Initial state
            let initial_state = serialize_flow_state(&table, stream_id);
            assert_eq!(
                initial_state,
                "connection_send_used=0,connection_send_limit=200,connection_send_remaining=200,\
                 stream_send_used=0,stream_send_limit=100,stream_send_remaining=100,\
                 stream_send_offset=0,stream_recv_offset=0,send_reset=None"
            );

            // Write some data
            table.write_stream(stream_id, 50).expect("write data");
            let after_write_state = serialize_flow_state(&table, stream_id);
            assert_eq!(
                after_write_state,
                "connection_send_used=50,connection_send_limit=200,connection_send_remaining=150,\
                 stream_send_used=50,stream_send_limit=100,stream_send_remaining=50,\
                 stream_send_offset=50,stream_recv_offset=0,send_reset=None"
            );

            // Reset stream - connection budget should be released
            table
                .stream_mut(stream_id)
                .expect("stream")
                .reset_send(42, 50)
                .expect("reset");
            let after_reset_state = serialize_flow_state(&table, stream_id);
            assert_eq!(
                after_reset_state,
                "connection_send_used=50,connection_send_limit=200,connection_send_remaining=150,\
                 stream_send_used=50,stream_send_limit=100,stream_send_remaining=50,\
                 stream_send_offset=50,stream_recv_offset=0,send_reset=Some((42, 50))"
            );

            // Apply a MAX_DATA frame increasing the connection limit.
            table
                .send_connection_credit
                .increase_limit(300)
                .expect("increase limit");
            let after_max_data_state = serialize_flow_state(&table, stream_id);
            assert_eq!(
                after_max_data_state,
                "connection_send_used=50,connection_send_limit=300,connection_send_remaining=250,\
                 stream_send_used=50,stream_send_limit=100,stream_send_remaining=50,\
                 stream_send_offset=50,stream_recv_offset=0,send_reset=Some((42, 50))"
            );
        }

        #[test]
        fn golden_flow_control_bytes_released_on_reset() {
            // Test scenario 2: Flow-control bytes released on reset
            let mut table = StreamTable::new_with_connection_limits(
                StreamRole::Client,
                2,   // max bidi
                0,   // max uni
                80,  // stream send window
                80,  // stream recv window
                100, // connection send limit (tight)
                100, // connection recv limit
            );

            let stream1 = table.open_local_bidi().expect("open stream1");
            let stream2 = table.open_local_bidi().expect("open stream2");

            // Fill up most of connection budget with stream1
            table.write_stream(stream1, 70).expect("write to stream1");
            let state_stream1_written = format!(
                "stream1: {}, stream2: {}",
                serialize_flow_state(&table, stream1),
                serialize_flow_state(&table, stream2)
            );
            assert_eq!(
                state_stream1_written,
                "stream1: connection_send_used=70,connection_send_limit=100,connection_send_remaining=30,\
                 stream_send_used=70,stream_send_limit=80,stream_send_remaining=10,\
                 stream_send_offset=70,stream_recv_offset=0,send_reset=None, \
                 stream2: connection_send_used=70,connection_send_limit=100,connection_send_remaining=30,\
                 stream_send_used=0,stream_send_limit=80,stream_send_remaining=80,\
                 stream_send_offset=0,stream_recv_offset=0,send_reset=None"
            );

            // Try to write to stream2 - should fail due to connection limit
            let write_err = table
                .write_stream(stream2, 40)
                .expect_err("should fail - connection limit");
            assert!(matches!(
                write_err,
                StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted {
                    attempted: 40,
                    remaining: 30
                }))
            ));

            // Reset stream1 - this should conceptually release its connection budget
            table
                .stream_mut(stream1)
                .expect("stream1")
                .reset_send(99, 70)
                .expect("reset stream1");

            // Manually release connection budget (simulating what QUIC implementation should do)
            table.send_connection_credit.release(70);

            let state_after_reset = format!(
                "stream1: {}, stream2: {}",
                serialize_flow_state(&table, stream1),
                serialize_flow_state(&table, stream2)
            );
            assert_eq!(
                state_after_reset,
                "stream1: connection_send_used=0,connection_send_limit=100,connection_send_remaining=100,\
                 stream_send_used=70,stream_send_limit=80,stream_send_remaining=10,\
                 stream_send_offset=70,stream_recv_offset=0,send_reset=Some((99, 70)), \
                 stream2: connection_send_used=0,connection_send_limit=100,connection_send_remaining=100,\
                 stream_send_used=0,stream_send_limit=80,stream_send_remaining=80,\
                 stream_send_offset=0,stream_recv_offset=0,send_reset=None"
            );
        }

        #[test]
        fn golden_new_stream_reuses_released_budget() {
            // Test scenario 3: New stream reuses released budget
            let mut table = StreamTable::new_with_connection_limits(
                StreamRole::Client,
                3,   // max bidi
                0,   // max uni
                60,  // stream send window
                60,  // stream recv window
                100, // connection send limit
                100, // connection recv limit
            );

            let stream1 = table.open_local_bidi().expect("open stream1");
            let stream2 = table.open_local_bidi().expect("open stream2");

            // Use connection budget across both streams
            table.write_stream(stream1, 40).expect("write to stream1");
            table.write_stream(stream2, 50).expect("write to stream2");

            let state_both_written = format!(
                "connection_budget_used={}, stream1_used={}, stream2_used={}",
                table.send_connection_credit.used(),
                table.stream(stream1).unwrap().send_credit.used(),
                table.stream(stream2).unwrap().send_credit.used()
            );
            assert_eq!(
                state_both_written,
                "connection_budget_used=90, stream1_used=40, stream2_used=50"
            );

            // Reset stream1 and release its budget
            table
                .stream_mut(stream1)
                .expect("stream1")
                .reset_send(1, 40)
                .expect("reset stream1");
            table.send_connection_credit.release(40); // Recovered send budget.

            // Open new stream3 and verify it can use the released budget
            let stream3 = table.open_local_bidi().expect("open stream3");
            table
                .write_stream(stream3, 35)
                .expect("write to stream3 - using released budget");

            let state_after_reuse = format!(
                "connection_budget_used={}, stream1_reset={:?}, stream2_used={}, stream3_used={}",
                table.send_connection_credit.used(),
                table.stream(stream1).unwrap().send_reset,
                table.stream(stream2).unwrap().send_credit.used(),
                table.stream(stream3).unwrap().send_credit.used()
            );
            assert_eq!(
                state_after_reuse,
                "connection_budget_used=85, stream1_reset=Some((1, 40)), stream2_used=50, stream3_used=35"
            );
        }

        #[test]
        fn golden_peer_initiated_vs_local_reset() {
            // Test scenario 4: Peer-initiated reset vs. local reset
            let mut client_table = StreamTable::new_with_connection_limits(
                StreamRole::Client,
                2,   // max bidi
                0,   // max uni
                50,  // stream window
                50,  // stream window
                100, // connection limit
                100, // connection limit
            );

            // Client opens stream and writes data
            let stream_id = client_table.open_local_bidi().expect("open client stream");
            client_table
                .write_stream(stream_id, 30)
                .expect("client writes");

            let client_after_write = serialize_flow_state(&client_table, stream_id);
            assert_eq!(
                client_after_write,
                "connection_send_used=30,connection_send_limit=100,connection_send_remaining=70,\
                 stream_send_used=30,stream_send_limit=50,stream_send_remaining=20,\
                 stream_send_offset=30,stream_recv_offset=0,send_reset=None"
            );

            // Scenario A: Local reset (client resets its own stream)
            let mut local_reset_table = client_table.clone();
            local_reset_table
                .stream_mut(stream_id)
                .expect("stream")
                .reset_send(42, 30)
                .expect("local reset");
            let local_reset_state = serialize_flow_state(&local_reset_table, stream_id);
            assert_eq!(
                local_reset_state,
                "connection_send_used=30,connection_send_limit=100,connection_send_remaining=70,\
                 stream_send_used=30,stream_send_limit=50,stream_send_remaining=20,\
                 stream_send_offset=30,stream_recv_offset=0,send_reset=Some((42, 30))"
            );

            // Scenario B: Peer-initiated reset (server resets client's stream via STOP_SENDING)
            let mut peer_reset_table = client_table;
            peer_reset_table
                .stream_mut(stream_id)
                .expect("stream")
                .on_stop_sending(99);
            let peer_stop_state = format!(
                "connection_send_used={},stream_send_used={},send_offset={},stop_sending_error_code={:?}",
                peer_reset_table.send_connection_credit.used(),
                peer_reset_table
                    .stream(stream_id)
                    .unwrap()
                    .send_credit
                    .used(),
                peer_reset_table.stream(stream_id).unwrap().send_offset,
                peer_reset_table
                    .stream(stream_id)
                    .unwrap()
                    .stop_sending_error_code
            );
            assert_eq!(
                peer_stop_state,
                "connection_send_used=30,stream_send_used=30,send_offset=30,stop_sending_error_code=Some(99)"
            );

            // Verify peer-reset prevents further writes
            let write_after_stop_err = peer_reset_table
                .write_stream(stream_id, 5)
                .expect_err("should fail");
            assert_eq!(
                write_after_stop_err,
                StreamTableError::Stream(QuicStreamError::SendStopped { code: 99 })
            );
        }

        #[test]
        fn golden_connection_level_budget_recovery() {
            // Test scenario 5: Connection-level budget recovery
            let mut table = StreamTable::new_with_connection_limits(
                StreamRole::Server,
                3,  // max bidi
                1,  // max uni
                40, // stream window
                40, // stream window
                80, // connection send limit (tight)
                80, // connection recv limit
            );

            let bidi1 = table.open_local_bidi().expect("open bidi1");
            let bidi2 = table.open_local_bidi().expect("open bidi2");
            let uni1 = table.open_local_uni().expect("open uni1");

            // Fill connection budget across multiple streams
            table.write_stream(bidi1, 25).expect("write bidi1");
            table.write_stream(bidi2, 30).expect("write bidi2");
            table.write_stream(uni1, 20).expect("write uni1");

            let state_budget_full = format!(
                "connection_used={},connection_remaining={},bidi1_used={},bidi2_used={},uni1_used={}",
                table.send_connection_credit.used(),
                table.send_connection_credit.remaining(),
                table.stream(bidi1).unwrap().send_credit.used(),
                table.stream(bidi2).unwrap().send_credit.used(),
                table.stream(uni1).unwrap().send_credit.used()
            );
            assert_eq!(
                state_budget_full,
                "connection_used=75,connection_remaining=5,bidi1_used=25,bidi2_used=30,uni1_used=20"
            );

            // Connection budget nearly exhausted - new writes should fail
            let write_fail_err = table
                .write_stream(bidi1, 10)
                .expect_err("should fail - connection exhausted");
            assert!(matches!(
                write_fail_err,
                StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted {
                    attempted: 10,
                    remaining: 5
                }))
            ));

            // Reset bidi2 and uni1, then recover their connection budget
            table
                .stream_mut(bidi2)
                .expect("bidi2")
                .reset_send(1, 30)
                .expect("reset bidi2");
            table
                .stream_mut(uni1)
                .expect("uni1")
                .reset_send(2, 20)
                .expect("reset uni1");
            table.send_connection_credit.release(50); // Recover bidi2(30) + uni1(20) budget

            let state_after_recovery = format!(
                "connection_used={},connection_remaining={},bidi1_used={},bidi2_reset={:?},uni1_reset={:?}",
                table.send_connection_credit.used(),
                table.send_connection_credit.remaining(),
                table.stream(bidi1).unwrap().send_credit.used(),
                table.stream(bidi2).unwrap().send_reset,
                table.stream(uni1).unwrap().send_reset
            );
            assert_eq!(
                state_after_recovery,
                "connection_used=25,connection_remaining=55,bidi1_used=25,bidi2_reset=Some((1, 30)),uni1_reset=Some((2, 20))"
            );

            // Now bidi1 can write again with recovered budget
            table
                .write_stream(bidi1, 15)
                .expect("write bidi1 with recovered budget");

            let final_state = format!(
                "connection_used={},connection_remaining={},bidi1_used={}",
                table.send_connection_credit.used(),
                table.send_connection_credit.remaining(),
                table.stream(bidi1).unwrap().send_credit.used()
            );
            assert_eq!(
                final_state,
                "connection_used=40,connection_remaining=40,bidi1_used=40"
            );
        }
    }
}
