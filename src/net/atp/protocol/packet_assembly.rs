//! QUIC Packet Assembly and Constraints
//!
//! Implements packet assembly that coalesces QUIC frames within various
//! constraints including congestion control, MTU limits, packet number spaces,
//! and anti-amplification limits.

use crate::bytes::{Bytes, BytesMut};
use crate::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};
use std::collections::{BTreeMap, VecDeque};

/// Maximum theoretical UDP payload size
pub const MAX_UDP_PAYLOAD: usize = 65535;

/// Default path MTU for IPv4
pub const DEFAULT_IPV4_MTU: usize = 1500;

/// Default path MTU for IPv6
pub const DEFAULT_IPV6_MTU: usize = 1500;

/// Minimum QUIC packet size to avoid amplification
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// Packet number space for QUIC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet space
    Initial,
    /// Handshake packet space
    Handshake,
    /// Application data packet space
    ApplicationData,
}

/// Packet assembly constraints
#[derive(Debug, Clone)]
pub struct PacketConstraints {
    /// Maximum packet size (MTU constraint)
    pub max_packet_size: usize,
    /// Current congestion window limit
    pub congestion_window: usize,
    /// Bytes in flight (for congestion control)
    pub bytes_in_flight: usize,
    /// Anti-amplification limit for unvalidated paths
    pub anti_amplification_limit: Option<usize>,
    /// Current packet number space
    pub packet_number_space: PacketNumberSpace,
}

impl PacketConstraints {
    /// Create default constraints
    pub fn new() -> Self {
        Self {
            max_packet_size: DEFAULT_IPV4_MTU - 40, // IPv4 + UDP headers
            congestion_window: 10 * 1460,           // Initial congestion window
            bytes_in_flight: 0,
            anti_amplification_limit: Some(MIN_INITIAL_PACKET_SIZE * 3), // RFC 9000
            packet_number_space: PacketNumberSpace::Initial,
        }
    }

    /// Set MTU-based packet size limit
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.max_packet_size = mtu.saturating_sub(40); // Account for headers
        self
    }

    /// Set congestion window
    pub fn with_congestion_window(mut self, window: usize) -> Self {
        self.congestion_window = window;
        self
    }

    /// Set packet number space
    pub fn with_packet_number_space(mut self, space: PacketNumberSpace) -> Self {
        self.packet_number_space = space;
        self
    }

    /// Disable anti-amplification (for validated paths)
    pub fn without_anti_amplification(mut self) -> Self {
        self.anti_amplification_limit = None;
        self
    }

    /// Calculate available packet budget
    pub fn available_packet_budget(&self) -> usize {
        let congestion_available = self.congestion_window.saturating_sub(self.bytes_in_flight);
        let mut budget = congestion_available.min(self.max_packet_size);

        if let Some(amp_limit) = self.anti_amplification_limit {
            budget = budget.min(amp_limit);
        }

        budget
    }
}

impl Default for PacketConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame with priority for assembly ordering
#[derive(Debug, Clone)]
pub struct PrioritizedFrame {
    /// The QUIC frame
    pub frame: QuicFrame,
    /// Assembly priority (higher = more important)
    pub priority: u8,
    /// Whether frame can be retransmitted
    pub retransmittable: bool,
    /// Whether frame is ack-eliciting
    pub ack_eliciting: bool,
}

impl PrioritizedFrame {
    /// Create a prioritized frame with auto-detected properties
    pub fn new(frame: QuicFrame) -> Self {
        let (priority, retransmittable, ack_eliciting) = match &frame {
            // High priority control frames
            QuicFrame::ConnectionClose { .. } => (255, true, true),
            QuicFrame::HandshakeDone => (200, true, true),
            QuicFrame::Crypto { .. } => (180, true, true),

            // Stream control frames
            QuicFrame::ResetStream { .. } => (160, true, true),
            QuicFrame::StopSending { .. } => (160, true, true),

            // Flow control frames
            QuicFrame::MaxData { .. } => (140, true, true),
            QuicFrame::MaxStreamData { .. } => (140, true, true),
            QuicFrame::MaxStreams { .. } => (140, true, true),
            QuicFrame::DataBlocked { .. } => (120, true, true),
            QuicFrame::StreamDataBlocked { .. } => (120, true, true),
            QuicFrame::StreamsBlocked { .. } => (120, true, true),

            // Path validation
            QuicFrame::PathChallenge { .. } => (100, true, true),
            QuicFrame::PathResponse { .. } => (100, true, true),

            // Application data
            QuicFrame::Stream { .. } => (80, true, true),

            // ACK frames - not retransmittable but important
            QuicFrame::Ack { .. } => (60, false, false),

            // Low priority frames
            QuicFrame::Ping => (40, true, true),
            QuicFrame::Padding { .. } => (0, false, false),
        };

        Self {
            frame,
            priority,
            retransmittable,
            ack_eliciting,
        }
    }

    /// Create with explicit priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Estimate encoded size of this frame
    pub fn estimated_size(&self) -> usize {
        match &self.frame {
            QuicFrame::Padding { length } => *length,
            QuicFrame::Ping => 1,
            QuicFrame::Ack {
                ack_ranges,
                ecn_counts,
                ..
            } => {
                // Rough estimate: base fields + ranges + ECN
                20 + (ack_ranges.len() * 4) + if ecn_counts.is_some() { 6 } else { 0 }
            }
            QuicFrame::ResetStream { .. } => 12, // Type + stream_id + error + size
            QuicFrame::StopSending { .. } => 8,  // Type + stream_id + error
            QuicFrame::Crypto { data, .. } => 8 + data.len(), // Type + offset + length + data
            QuicFrame::Stream { data, offset, .. } => {
                let base = 4; // Type + stream_id
                let offset_size = if offset.is_some() { 4 } else { 0 };
                let length_size = if !data.is_empty() { 4 } else { 0 };
                base + offset_size + length_size + data.len()
            }
            QuicFrame::MaxData { .. } => 5, // Type + maximum_data
            QuicFrame::MaxStreamData { .. } => 8, // Type + stream_id + maximum
            QuicFrame::MaxStreams { .. } => 5, // Type + maximum
            QuicFrame::DataBlocked { .. } => 5, // Type + maximum
            QuicFrame::StreamDataBlocked { .. } => 8, // Type + stream_id + maximum
            QuicFrame::StreamsBlocked { .. } => 5, // Type + maximum
            QuicFrame::PathChallenge { .. } => 9, // Type + 8 bytes
            QuicFrame::PathResponse { .. } => 9, // Type + 8 bytes
            QuicFrame::ConnectionClose { reason_phrase, .. } => {
                12 + reason_phrase.len() // Type + error + frame_type + length + phrase
            }
            QuicFrame::HandshakeDone => 1, // Just type
        }
    }
}

/// Packet assembler that coalesces frames within constraints
#[derive(Debug)]
pub struct PacketAssembler {
    /// Pending frames keyed by assembly priority.
    pending_frames: BTreeMap<u8, VecDeque<PrioritizedFrame>>,
    /// Number of queued frames across all priority buckets.
    pending_frame_count: usize,
    /// Current constraints
    constraints: PacketConstraints,
}

impl PacketAssembler {
    /// Create new packet assembler
    pub fn new(constraints: PacketConstraints) -> Self {
        Self {
            pending_frames: BTreeMap::new(),
            pending_frame_count: 0,
            constraints,
        }
    }

    /// Add frame for assembly
    pub fn add_frame(&mut self, frame: PrioritizedFrame) {
        self.pending_frames
            .entry(frame.priority)
            .or_default()
            .push_back(frame);
        self.pending_frame_count += 1;
    }

    /// Add frame with automatic prioritization
    pub fn add_quic_frame(&mut self, frame: QuicFrame) {
        self.add_frame(PrioritizedFrame::new(frame));
    }

    /// Update constraints
    pub fn set_constraints(&mut self, constraints: PacketConstraints) {
        self.constraints = constraints;
    }

    /// Check if any frames are pending
    pub fn has_pending_frames(&self) -> bool {
        self.pending_frame_count > 0
    }

    /// Assemble packet from pending frames
    pub fn assemble_packet(&mut self) -> Result<Option<AssembledPacket>, PacketAssemblyError> {
        if !self.has_pending_frames() {
            return Ok(None);
        }

        let available_budget = self.constraints.available_packet_budget();
        if available_budget < 4 {
            // Not enough budget for even a minimal frame
            return Ok(None);
        }

        let mut packet = AssembledPacket::new(self.constraints.packet_number_space);
        let mut used_budget = 0;
        let mut frames_added = 0;

        // Try to fit frames in priority order
        while let Some(frame) = self.highest_priority_frame() {
            let estimated_size = frame.estimated_size();

            // Check if frame fits in remaining budget
            if used_budget + estimated_size > available_budget {
                break;
            }

            // Check packet number space compatibility
            if !is_frame_allowed_in_space(&frame.frame, self.constraints.packet_number_space) {
                // Remove incompatible frame and continue
                self.pop_highest_priority_frame();
                continue;
            }

            // Add frame to packet
            let frame = match self.pop_highest_priority_frame() {
                Some(frame) => frame,
                None => break, // No more frames available
            };
            used_budget += estimated_size;

            if frame.ack_eliciting {
                packet.ack_eliciting = true;
            }
            if frame.retransmittable {
                packet.retransmittable = true;
            }

            packet.frames.push(frame.frame);
            frames_added += 1;

            // Limit number of frames per packet
            if frames_added >= 64 {
                break;
            }
        }

        if packet.frames.is_empty() {
            return Ok(None);
        }

        // Add padding if needed for anti-amplification
        if self.constraints.packet_number_space == PacketNumberSpace::Initial
            && packet.estimated_size() < MIN_INITIAL_PACKET_SIZE
        {
            let padding_needed = MIN_INITIAL_PACKET_SIZE - packet.estimated_size();
            if used_budget + padding_needed <= available_budget {
                packet.frames.push(QuicFrame::Padding {
                    length: padding_needed,
                });
            }
        }

        packet.calculate_size();
        Ok(Some(packet))
    }

    /// Clear all pending frames
    pub fn clear_pending_frames(&mut self) {
        self.pending_frames.clear();
        self.pending_frame_count = 0;
    }

    /// Get count of pending frames
    pub fn pending_frame_count(&self) -> usize {
        self.pending_frame_count
    }

    fn highest_priority_frame(&self) -> Option<&PrioritizedFrame> {
        self.pending_frames
            .last_key_value()
            .and_then(|(_priority, frames)| frames.front())
    }

    fn pop_highest_priority_frame(&mut self) -> Option<PrioritizedFrame> {
        let priority = *self.pending_frames.last_key_value()?.0;
        let frames = self.pending_frames.get_mut(&priority)?;
        let frame = frames.pop_front()?;
        self.pending_frame_count -= 1;
        if frames.is_empty() {
            self.pending_frames.remove(&priority);
        }
        Some(frame)
    }
}

/// Assembled packet ready for transmission
#[derive(Debug, Clone)]
pub struct AssembledPacket {
    /// Frames in the packet
    pub frames: Vec<QuicFrame>,
    /// Packet number space
    pub packet_number_space: PacketNumberSpace,
    /// Whether packet contains ack-eliciting frames
    pub ack_eliciting: bool,
    /// Whether packet contains retransmittable frames
    pub retransmittable: bool,
    /// Estimated packet size
    pub size: usize,
}

impl AssembledPacket {
    /// Create new assembled packet
    pub fn new(packet_number_space: PacketNumberSpace) -> Self {
        Self {
            frames: Vec::new(),
            packet_number_space,
            ack_eliciting: false,
            retransmittable: false,
            size: 0,
        }
    }

    /// Encode packet frames to buffer
    pub fn encode_frames(&self) -> Result<Bytes, QuicFrameError> {
        let mut buf = BytesMut::with_capacity(self.size);

        for frame in &self.frames {
            frame.encode(&mut buf)?;
        }

        Ok(buf.freeze())
    }

    /// Calculate packet size
    fn calculate_size(&mut self) {
        self.size = self
            .frames
            .iter()
            .map(|frame| {
                let mut temp_buf = BytesMut::new();
                let _ = frame.encode(&mut temp_buf);
                temp_buf.len()
            })
            .sum();
    }

    /// Get estimated size
    pub fn estimated_size(&self) -> usize {
        self.size
    }
}

/// Check if frame is allowed in the given packet number space
fn is_frame_allowed_in_space(frame: &QuicFrame, space: PacketNumberSpace) -> bool {
    match space {
        PacketNumberSpace::Initial => {
            matches!(
                frame,
                QuicFrame::Padding { .. }
                    | QuicFrame::Ping
                    | QuicFrame::Ack { .. }
                    | QuicFrame::Crypto { .. }
                    | QuicFrame::ConnectionClose { .. }
            )
        }
        PacketNumberSpace::Handshake => {
            matches!(
                frame,
                QuicFrame::Padding { .. }
                    | QuicFrame::Ping
                    | QuicFrame::Ack { .. }
                    | QuicFrame::Crypto { .. }
                    | QuicFrame::ConnectionClose { .. }
            )
        }
        PacketNumberSpace::ApplicationData => {
            // All frame types are allowed in application data packets
            true
        }
    }
}

/// Packet assembly errors
#[derive(Debug, thiserror::Error)]
pub enum PacketAssemblyError {
    /// Frame encoding error
    #[error("frame encoding error: {0}")]
    FrameEncoding(#[from] QuicFrameError),

    /// Packet exceeds maximum size
    #[error("packet exceeds maximum size: {size} > {max}")]
    PacketTooLarge {
        /// Encoded packet size.
        size: usize,
        /// Configured maximum packet size.
        max: usize,
    },

    /// No budget available for assembly
    #[error("no budget available for packet assembly")]
    NoBudgetAvailable,

    /// Invalid frame for packet number space
    #[error("frame not allowed in packet number space: {space:?}")]
    InvalidFrameForSpace {
        /// Packet number space that rejected the frame.
        space: PacketNumberSpace,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::varint::VarInt;

    #[test]
    fn test_packet_constraints_budget() {
        let constraints = PacketConstraints::new()
            .with_congestion_window(1000)
            .with_mtu(1200);

        // Should be limited by congestion window
        assert_eq!(constraints.available_packet_budget(), 1000);
    }

    #[test]
    fn test_frame_prioritization() {
        let ping = PrioritizedFrame::new(QuicFrame::Ping);
        let close = PrioritizedFrame::new(QuicFrame::ConnectionClose {
            error_code: VarInt::new(0).unwrap(),
            frame_type: None,
            reason_phrase: Bytes::from_static(b"test"),
        });

        assert!(close.priority > ping.priority);
        assert!(close.ack_eliciting);
        assert!(ping.retransmittable); // PING is retransmittable
    }

    #[test]
    fn test_packet_assembly() {
        let mut assembler = PacketAssembler::new(PacketConstraints::new());

        // Add some frames
        assembler.add_quic_frame(QuicFrame::Ping);
        assembler.add_quic_frame(QuicFrame::MaxData {
            maximum_data: VarInt::new(1024).unwrap(),
        });

        let packet = assembler.assemble_packet().unwrap().unwrap();
        assert_eq!(packet.frames.len(), 2);
        assert!(packet.ack_eliciting);
    }

    #[test]
    fn test_packet_assembly_priority_buckets_preserve_order() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );

        assembler.add_frame(PrioritizedFrame::new(QuicFrame::Ping).with_priority(10));
        assembler.add_frame(
            PrioritizedFrame::new(QuicFrame::MaxData {
                maximum_data: VarInt::new(1024).unwrap(),
            })
            .with_priority(10),
        );
        assembler.add_frame(
            PrioritizedFrame::new(QuicFrame::ConnectionClose {
                error_code: VarInt::new(0).unwrap(),
                frame_type: None,
                reason_phrase: Bytes::from_static(b"test"),
            })
            .with_priority(20),
        );

        assert_eq!(assembler.pending_frame_count(), 3);

        let packet = assembler.assemble_packet().unwrap().unwrap();
        assert!(matches!(
            packet.frames[0],
            QuicFrame::ConnectionClose { .. }
        ));
        assert!(matches!(packet.frames[1], QuicFrame::Ping));
        assert!(matches!(packet.frames[2], QuicFrame::MaxData { .. }));
        assert_eq!(assembler.pending_frame_count(), 0);
    }

    #[test]
    fn test_packet_number_space_filtering() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new().with_packet_number_space(PacketNumberSpace::Initial),
        );

        // Add frames - some allowed in Initial space, some not
        assembler.add_quic_frame(QuicFrame::Ping); // Allowed
        assembler.add_quic_frame(QuicFrame::Stream {
            stream_id: VarInt::new(0).unwrap(),
            offset: None,
            data: Bytes::from_static(b"test"),
            fin: false,
        }); // Not allowed in Initial space
        assembler.add_quic_frame(QuicFrame::Crypto {
            offset: VarInt::new(0).unwrap(),
            data: Bytes::from_static(b"handshake"),
        }); // Allowed

        let packet = assembler.assemble_packet().unwrap().unwrap();

        // Initial packets may be padded to the transport minimum, so filter
        // padding before checking packet-number-space frame filtering.
        let non_padding_frames: Vec<_> = packet
            .frames
            .iter()
            .filter(|frame| !matches!(frame, QuicFrame::Padding { .. }))
            .collect();
        assert_eq!(non_padding_frames.len(), 2);
        assert!(matches!(non_padding_frames[0], QuicFrame::Crypto { .. })); // Higher priority
        assert!(matches!(non_padding_frames[1], QuicFrame::Ping));
    }

    #[test]
    fn test_anti_amplification_padding() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::Initial)
                .with_mtu(2000), // Large MTU
        );

        assembler.add_quic_frame(QuicFrame::Ping); // Small frame

        let packet = assembler.assemble_packet().unwrap().unwrap();

        // Should have padding added to meet minimum size
        let has_padding = packet
            .frames
            .iter()
            .any(|f| matches!(f, QuicFrame::Padding { .. }));
        assert!(has_padding);
        assert!(packet.estimated_size() >= MIN_INITIAL_PACKET_SIZE);
    }
}
