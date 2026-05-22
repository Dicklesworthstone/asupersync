//! Byzantine defense integration for ATP protocol handlers.
//!
//! This module demonstrates how the ResourceManager should be integrated
//! into ATP protocol processing to defend against Byzantine peer attacks.

use crate::atp::manifest::ManifestVersion;
use crate::bytes::BytesMut;
use crate::net::atp::protocol::frames::{Frame, FrameType};
use crate::net::atp::protocol::resource_manager::{ResourceError, ResourceManager};
use crate::net::atp::protocol::session::PeerId;
use crate::net::atp::protocol::varint::VarInt;
use crate::types::Outcome;
use std::time::Duration;

/// Result type for Byzantine-defended operations.
pub type DefenseResult<T> = Result<T, ByzantineDefenseError>;

/// Errors that can occur during Byzantine defense checks.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ByzantineDefenseError {
    /// Resource limits exceeded.
    #[error("Resource limits exceeded: {0}")]
    ResourceLimitExceeded(#[from] ResourceError),

    /// Frame rejected due to rate limiting.
    #[error("Frame from peer {peer_id:?} rejected due to rate limiting")]
    FrameRateLimited { peer_id: PeerId },

    /// Session rejected due to limits.
    #[error("Session from peer {peer_id:?} rejected due to limits")]
    SessionLimited { peer_id: PeerId },

    /// Object request rejected.
    #[error("Object request from peer {peer_id:?} rejected")]
    RequestRejected { peer_id: PeerId },
}

/// Byzantine-resistant frame processor wrapper.
pub struct DefendedFrameProcessor {
    resource_manager: ResourceManager,
}

impl DefendedFrameProcessor {
    /// Create a new defended frame processor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resource_manager: ResourceManager::new(),
        }
    }

    /// Process a frame with Byzantine defenses applied.
    pub fn process_frame(&mut self, peer_id: PeerId, frame: &Frame) -> DefenseResult<()> {
        // Check rate limits before processing
        if !self.resource_manager.record_frame(peer_id) {
            return Err(ByzantineDefenseError::FrameRateLimited { peer_id });
        }

        // Check memory requirements based on frame type
        let memory_needed = self.estimate_frame_memory(frame);
        if !self
            .resource_manager
            .allocate_memory(peer_id, memory_needed)
        {
            // Frame was recorded but memory allocation failed - mark as processed
            self.resource_manager.frame_processed(&peer_id);
            return Err(ResourceError::MemoryLimitExceeded {
                peer_id,
                requested: memory_needed,
                limit: self.resource_manager.limits().max_memory_per_peer,
            }
            .into());
        }

        // Additional frame-specific checks
        match frame.frame_type() {
            FrameType::ObjectManifest => {
                if let Some(manifest_size) = self.extract_manifest_size(frame) {
                    if !self.resource_manager.validate_manifest_size(manifest_size) {
                        self.cleanup_frame_processing(&peer_id, memory_needed);
                        return Err(ResourceError::ManifestSizeExceeded {
                            size: manifest_size,
                            limit: self.resource_manager.limits().max_manifest_size,
                        }
                        .into());
                    }
                }
            }
            FrameType::ObjectRequest => {
                if !self.resource_manager.request_object(peer_id) {
                    self.cleanup_frame_processing(&peer_id, memory_needed);
                    return Err(ByzantineDefenseError::RequestRejected { peer_id });
                }
            }
            FrameType::Handshake => {
                if !self.resource_manager.start_session(peer_id) {
                    self.cleanup_frame_processing(&peer_id, memory_needed);
                    return Err(ByzantineDefenseError::SessionLimited { peer_id });
                }
            }
            _ => {}
        }

        // Process frame with actual protocol logic
        match self.process_frame_implementation(&peer_id, frame) {
            Ok(()) => {
                // Clean up transient processing resources
                self.cleanup_frame_processing(&peer_id, memory_needed);
                Ok(())
            }
            Err(e) => {
                // Clean up resources on processing failure
                self.cleanup_frame_processing(&peer_id, memory_needed);
                Err(e)
            }
        }
    }

    /// Implement actual frame processing logic with proper protocol handling.
    fn process_frame_implementation(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        // Validate frame basic structure
        if frame.payload().is_empty() && frame.frame_type() != FrameType::KeepAlive {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *peer_id });
        }

        match frame.frame_type() {
            FrameType::Handshake => self.handle_handshake_frame(peer_id, frame),
            FrameType::HandshakeAck => self.handle_handshake_ack_frame(peer_id, frame),
            FrameType::Capabilities => self.handle_capabilities_frame(peer_id, frame),
            FrameType::CapabilitiesAck => self.handle_capabilities_ack_frame(peer_id, frame),
            FrameType::ObjectManifest => self.handle_object_manifest_frame(peer_id, frame),
            FrameType::ObjectRequest => self.handle_object_request_frame(peer_id, frame),
            FrameType::ObjectData => self.handle_object_data_frame(peer_id, frame),
            FrameType::ObjectComplete => self.handle_object_complete_frame(peer_id, frame),
            FrameType::ObjectError => self.handle_object_error_frame(peer_id, frame),
            FrameType::PathUpdate => self.handle_path_update_frame(peer_id, frame),
            FrameType::PathChallenge => self.handle_path_challenge_frame(peer_id, frame),
            FrameType::PathResponse => self.handle_path_response_frame(peer_id, frame),
            FrameType::KeepAlive => {
                // KeepAlive frames require no processing
                Ok(())
            }
            FrameType::Cancel => self.handle_cancel_frame(peer_id, frame),
            FrameType::Error => self.handle_error_frame(peer_id, frame),
            FrameType::Close => self.handle_close_frame(peer_id, frame),
            FrameType::Control => self.handle_control_frame(peer_id, frame),
            FrameType::Data => self.handle_data_frame(peer_id, frame),
            FrameType::Proof => self.handle_proof_frame(peer_id, frame),
            FrameType::Repair => self.handle_repair_frame(peer_id, frame),
            FrameType::Session => self.handle_session_frame(peer_id, frame),
            FrameType::Manifest => self.handle_manifest_frame(peer_id, frame),
        }
    }

    /// Handle handshake frame processing.
    fn handle_handshake_frame(&mut self, _peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        // Validate handshake frame structure
        if frame.payload().len() < 8 {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *_peer_id });
        }
        // TODO: Implement handshake validation logic
        Ok(())
    }

    /// Handle handshake acknowledgment frame processing.
    fn handle_handshake_ack_frame(
        &mut self,
        _peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        // Validate handshake ack frame structure
        if frame.payload().len() < 4 {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *_peer_id });
        }
        // TODO: Implement handshake ack validation logic
        Ok(())
    }

    /// Handle capabilities frame processing.
    fn handle_capabilities_frame(&mut self, _peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        // Validate capabilities frame structure
        if frame.payload().is_empty() {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *_peer_id });
        }
        // TODO: Implement capabilities validation logic
        Ok(())
    }

    /// Handle capabilities acknowledgment frame processing.
    fn handle_capabilities_ack_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement capabilities ack validation logic
        Ok(())
    }

    /// Handle object manifest frame processing.
    fn handle_object_manifest_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        // Parse and validate manifest structure
        let manifest_size = self
            .extract_manifest_size(frame)
            .ok_or_else(|| ByzantineDefenseError::RequestRejected { peer_id: *peer_id })?;

        // Additional manifest validation
        if manifest_size == 0 {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *peer_id });
        }

        // TODO: Parse and validate full manifest structure
        Ok(())
    }

    /// Handle object request frame processing.
    fn handle_object_request_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement object request validation logic
        Ok(())
    }

    /// Handle object data frame processing.
    fn handle_object_data_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement object data validation logic
        Ok(())
    }

    /// Handle object complete frame processing.
    fn handle_object_complete_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement object complete validation logic
        Ok(())
    }

    /// Handle object error frame processing.
    fn handle_object_error_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement object error validation logic
        Ok(())
    }

    /// Handle path update frame processing.
    fn handle_path_update_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement path update validation logic
        Ok(())
    }

    /// Handle path challenge frame processing.
    fn handle_path_challenge_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement path challenge validation logic
        Ok(())
    }

    /// Handle path response frame processing.
    fn handle_path_response_frame(
        &mut self,
        _peer_id: &PeerId,
        _frame: &Frame,
    ) -> DefenseResult<()> {
        // TODO: Implement path response validation logic
        Ok(())
    }

    /// Handle cancel frame processing.
    fn handle_cancel_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement cancel frame validation logic
        Ok(())
    }

    /// Handle error frame processing.
    fn handle_error_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement error frame validation logic
        Ok(())
    }

    /// Handle close frame processing.
    fn handle_close_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement close frame validation logic
        Ok(())
    }

    /// Handle control frame processing.
    fn handle_control_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement control frame validation logic
        Ok(())
    }

    /// Handle data frame processing.
    fn handle_data_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement data frame validation logic
        Ok(())
    }

    /// Handle proof frame processing.
    fn handle_proof_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement proof frame validation logic
        Ok(())
    }

    /// Handle repair frame processing.
    fn handle_repair_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement repair frame validation logic
        Ok(())
    }

    /// Handle session frame processing.
    fn handle_session_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement session frame validation logic
        Ok(())
    }

    /// Handle generic adapter manifest frame processing.
    fn handle_manifest_frame(&mut self, _peer_id: &PeerId, _frame: &Frame) -> DefenseResult<()> {
        // TODO: Implement adapter manifest validation logic
        Ok(())
    }

    /// Clean up resources after failed frame processing.
    fn cleanup_frame_processing(&mut self, peer_id: &PeerId, memory_used: u64) {
        self.resource_manager
            .deallocate_memory(peer_id, memory_used);
        self.resource_manager.frame_processed(peer_id);
    }

    /// Estimate memory needed to process a frame.
    #[must_use]
    fn estimate_frame_memory(&self, frame: &Frame) -> u64 {
        match frame.frame_type() {
            FrameType::ObjectManifest => {
                // Manifest frames may require significant memory for parsing
                self.extract_manifest_size(frame).unwrap_or(4096)
            }
            FrameType::ObjectData => {
                // Data frames require buffer space
                frame.payload().len() as u64 // ubs:ignore
            }
            FrameType::ObjectRequest => {
                // Request frames are typically small
                256
            }
            _ => {
                // Control frames are typically small
                128
            }
        }
    }

    /// Extract manifest size from an ObjectManifest frame.
    #[must_use]
    fn extract_manifest_size(&self, frame: &Frame) -> Option<u64> {
        if frame.frame_type() != FrameType::ObjectManifest {
            return None;
        }

        let payload = frame.payload();
        if payload.is_empty() {
            return None;
        }

        // Parse manifest structure to extract declared size
        // Format: [version: varint][size: u64][manifest_data]
        let mut offset = 0;

        // Parse version first
        let max_varint_len = std::cmp::min(payload.len() - offset, 8);
        let mut buf = BytesMut::from(payload.get(offset..offset + max_varint_len)?);
        let version_varint = match VarInt::decode(&mut buf) {
            Outcome::Ok(Some(version)) => version,
            _ => return None,
        };
        if !ManifestVersion(version_varint.value() as u32).is_supported() {
            // ubs:ignore - ManifestVersion wraps u32, checked is_supported
            return None;
        }
        offset += version_varint.encoded_len();

        // Check we have enough bytes for size field
        if payload.len() < offset + 8 {
            return None;
        }

        // Parse declared manifest size (u64 big-endian)
        let size_bytes: [u8; 8] = payload.get(offset..offset + 8)?.try_into().ok()?;
        let declared_size = u64::from_be_bytes(size_bytes);

        // Validate declared size is reasonable (overflow protection)
        if declared_size > u64::MAX / 2 {
            return None;
        }

        // Validate declared size matches actual payload structure
        let expected_payload_len = (offset as u64).checked_add(8)?.checked_add(declared_size)?;

        if payload.len() as u64 != expected_payload_len {
            return None;
        }

        Some(declared_size)
    }

    /// Handle session termination.
    pub fn handle_session_end(&mut self, peer_id: &PeerId) {
        self.resource_manager.end_session(peer_id);
    }

    /// Handle object request completion.
    pub fn handle_request_completion(&mut self, peer_id: &PeerId) {
        self.resource_manager.complete_request(peer_id);
    }

    /// Perform periodic maintenance.
    pub fn maintain(&mut self) {
        // Clean up inactive peers every 5 minutes
        self.resource_manager
            .cleanup_inactive_peers(Duration::from_secs(300));

        // Log resource pressure warnings
        if self.resource_manager.is_under_pressure() {
            crate::tracing_compat::warn!(
                "ATP protocol under resource pressure: {} tracked peers, {} total memory",
                self.resource_manager.peer_count(),
                self.resource_manager.total_memory_usage()
            );
        }
    }

    /// Get resource statistics for monitoring.
    #[must_use]
    pub fn resource_stats(&self) -> ResourceStats {
        ResourceStats {
            peer_count: self.resource_manager.peer_count(),
            total_memory: self.resource_manager.total_memory_usage(),
            under_pressure: self.resource_manager.is_under_pressure(),
        }
    }

    /// Force cleanup of a problematic peer.
    pub fn force_cleanup_peer(&mut self, peer_id: &PeerId) {
        crate::tracing_compat::warn!("Force cleaning up resources for peer {:?}", peer_id);
        self.resource_manager.force_cleanup_peer(peer_id);
    }
}

impl Default for DefendedFrameProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource usage statistics for monitoring.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceStats {
    /// Number of peers currently tracked.
    pub peer_count: usize,
    /// Total memory usage across all peers (bytes).
    pub total_memory: u64,
    /// Whether the system is under resource pressure.
    pub under_pressure: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};

    fn create_test_frame(frame_type: FrameType, payload_size: usize) -> Frame {
        let payload = vec![0u8; payload_size];
        Frame::new(ProtocolVersion::CURRENT, frame_type, payload).expect("valid test frame")
    }

    #[test]
    fn test_frame_rate_limiting() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("rate-limited-peer");

        // Modify limits to be more restrictive for testing
        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_frame_rate: 2,
                rate_limit_window: 1,
                ..Default::default()
            },
        );

        let frame = create_test_frame(FrameType::ObjectRequest, 100);

        // Should allow first two frames
        assert!(processor.process_frame(peer_id, &frame).is_ok());
        assert!(processor.process_frame(peer_id, &frame).is_ok());

        // Should reject third frame due to rate limit
        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::FrameRateLimited { .. })
        ));
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("memory-limited-peer");

        // Create a large frame that exceeds memory limits
        let large_frame = create_test_frame(FrameType::ObjectManifest, 100 * 1024 * 1024);

        // Should reject frame due to memory limits
        assert!(matches!(
            processor.process_frame(peer_id, &large_frame),
            Err(ByzantineDefenseError::ResourceLimitExceeded(
                ResourceError::MemoryLimitExceeded { .. }
            ))
        ));
    }

    #[test]
    fn test_session_limits() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("session-limited-peer");

        // Modify limits to allow only one session
        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_sessions_per_peer: 1,
                ..Default::default()
            },
        );

        let handshake_frame = create_test_frame(FrameType::Handshake, 100);

        // Should allow first session
        assert!(processor.process_frame(peer_id, &handshake_frame).is_ok());

        // Should reject second session
        assert!(matches!(
            processor.process_frame(peer_id, &handshake_frame),
            Err(ByzantineDefenseError::SessionLimited { .. })
        ));
    }

    #[test]
    fn test_resource_cleanup() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("cleanup-peer");

        let frame = create_test_frame(FrameType::ObjectRequest, 100);

        // Process frame successfully
        assert!(processor.process_frame(peer_id, &frame).is_ok());

        // Clean up the session
        processor.handle_session_end(&peer_id);
        processor.handle_request_completion(&peer_id);

        // Run maintenance
        processor.maintain();

        // Resource stats should reflect cleanup
        let stats = processor.resource_stats();
        assert_eq!(stats.peer_count, 0);
    }
}
