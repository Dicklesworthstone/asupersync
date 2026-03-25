//! Native QUIC stream table + flow-control model.

use std::collections::BTreeMap;
use std::fmt;

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
        }
    }
}

impl std::error::Error for QuicStreamError {}

impl From<FlowControlError> for QuicStreamError {
    fn from(value: FlowControlError) -> Self {
        Self::Flow(value)
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
    /// Send-side flow credit.
    pub send_credit: FlowCredit,
    /// Receive-side flow credit.
    pub recv_credit: FlowCredit,
    /// Optional final size received via FIN/RESET.
    pub final_size: Option<u64>,
    /// Optional local reset state `(error_code, final_size)`.
    pub send_reset: Option<(u64, u64)>,
    /// Optional peer STOP_SENDING error code.
    pub stop_sending_error_code: Option<u64>,
    /// Optional local receive-stop error code.
    pub receive_stopped_error_code: Option<u64>,
    /// Buffered receive ranges keyed by start offset, value = exclusive end.
    recv_ranges: BTreeMap<u64, u64>,
}

impl QuicStream {
    fn new(id: StreamId, send_window: u64, recv_window: u64) -> Self {
        Self {
            id,
            send_offset: 0,
            recv_offset: 0,
            send_credit: FlowCredit::new(send_window),
            recv_credit: FlowCredit::new(recv_window),
            final_size: None,
            send_reset: None,
            stop_sending_error_code: None,
            receive_stopped_error_code: None,
            recv_ranges: BTreeMap::new(),
        }
    }

    /// Account bytes written to this stream.
    pub fn write(&mut self, len: u64) -> Result<(), QuicStreamError> {
        if let Some(code) = self.stop_sending_error_code {
            return Err(QuicStreamError::SendStopped { code });
        }
        // RFC 9000 §3.1: after issuing RESET_STREAM, no further STREAM frames.
        if let Some((code, _)) = self.send_reset {
            return Err(QuicStreamError::SendStopped { code });
        }
        self.send_credit.consume(len)?;
        self.send_offset = self.send_offset.saturating_add(len);
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
    next_local_bidi_seq: u64,
    next_local_uni_seq: u64,
    streams: BTreeMap<StreamId, QuicStream>,
    send_window: u64,
    recv_window: u64,
    send_connection_credit: FlowCredit,
    recv_connection_credit: FlowCredit,
    rr_cursor: Option<StreamId>,
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
            next_local_bidi_seq: 0,
            next_local_uni_seq: 0,
            streams: BTreeMap::new(),
            send_window,
            recv_window,
            send_connection_credit: FlowCredit::new(connection_send_limit),
            recv_connection_credit: FlowCredit::new(connection_recv_limit),
            rr_cursor: None,
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

    /// Accept a remotely initiated stream ID.
    pub fn accept_remote_stream(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        if id.is_local_for(self.role) {
            return Err(StreamTableError::InvalidRemoteStream(id));
        }
        self.insert_new_stream(id)
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
            if let Some(code) = stream.stop_sending_error_code {
                return Err(StreamTableError::Stream(QuicStreamError::SendStopped {
                    code,
                }));
            }
            // RFC 9000 §3.1: after issuing RESET_STREAM, no further STREAM frames.
            if let Some((code, _)) = stream.send_reset {
                return Err(StreamTableError::Stream(QuicStreamError::SendStopped {
                    code,
                }));
            }
            stream
                .send_credit
                .can_consume(len)
                .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        }
        self.send_connection_credit
            .can_consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        self.send_connection_credit
            .consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        let stream = self.stream_mut(id)?;
        stream
            .send_credit
            .consume(len)
            .map_err(|err| StreamTableError::Stream(QuicStreamError::Flow(err)))?;
        stream.send_offset = stream.send_offset.saturating_add(len);
        Ok(())
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
        Ok(())
    }

    /// Set stream final size.
    pub fn set_stream_final_size(
        &mut self,
        id: StreamId,
        final_size: u64,
    ) -> Result<(), StreamTableError> {
        self.stream_mut(id)?.set_final_size(final_size)?;
        Ok(())
    }

    /// Increase connection-level send limit monotonically.
    pub fn increase_connection_send_limit(
        &mut self,
        new_limit: u64,
    ) -> Result<(), FlowControlError> {
        self.send_connection_credit.increase_limit(new_limit)
    }

    /// Increase connection-level receive limit monotonically.
    pub fn increase_connection_recv_limit(
        &mut self,
        new_limit: u64,
    ) -> Result<(), FlowControlError> {
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

    fn insert_new_stream(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        if self.streams.contains_key(&id) {
            return Err(StreamTableError::DuplicateStream(id));
        }
        self.streams
            .insert(id, QuicStream::new(id, self.send_window, self.recv_window));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                QuicStreamError::InconsistentReset {
                    previous_final_size: 100,
                    new_final_size: 200,
                },
                "inconsistent reset",
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
        let fake_id = StreamId(999);
        let err = tbl.stream_mut(fake_id).unwrap_err();
        assert_eq!(err, StreamTableError::UnknownStream(fake_id));
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
        // Regression must fail
        let err = tbl
            .increase_connection_send_limit(15)
            .expect_err("regression");
        assert_eq!(
            err,
            FlowControlError::LimitRegression {
                current: 20,
                requested: 15,
            }
        );
        // Same value is fine
        tbl.increase_connection_send_limit(20)
            .expect("same value ok");

        // Increase recv limit
        tbl.increase_connection_recv_limit(30)
            .expect("increase recv");
        assert_eq!(tbl.connection_recv_remaining(), 30);
        // Regression must fail
        let err = tbl
            .increase_connection_recv_limit(5)
            .expect_err("regression");
        assert_eq!(
            err,
            FlowControlError::LimitRegression {
                current: 30,
                requested: 5,
            }
        );
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
}
