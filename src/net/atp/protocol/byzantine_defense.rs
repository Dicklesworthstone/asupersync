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
use std::collections::BTreeSet;
use std::time::Duration;

const PEER_ID_LEN: usize = 32;
const TRANSFER_NONCE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const MAX_FEATURE_COUNT: usize = 12;
const MAX_ACTION_COUNT: usize = 9;
const MAX_GRANT_COUNT: usize = 64;
const MAX_CONTEXT_COUNT: usize = 4;
const MAX_REASON_LEN: usize = 512;
const MAX_SCOPE_ITEM_COUNT: usize = 64;
const MAX_SCOPE_PREFIX_LEN: usize = 256;

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

struct PayloadReader<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.payload.len().saturating_sub(self.offset)
    }

    fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let slice = self.payload.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    fn read_u8(&mut self) -> Option<u8> {
        Some(*self.read_slice(1)?.first()?)
    }

    fn read_bool(&mut self) -> Option<bool> {
        match self.read_u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.read_slice(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.read_slice(8)?.try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }

    fn read_len_prefixed_str(&mut self, max_len: usize) -> Option<&'a str> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        if len > max_len {
            return None;
        }
        std::str::from_utf8(self.read_slice(len)?).ok()
    }

    fn finish(self) -> bool {
        self.offset == self.payload.len()
    }
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
        let mut started_object_request = false;
        let mut started_session = false;
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
                started_object_request = true;
            }
            FrameType::Handshake => {
                if !self.resource_manager.start_session(peer_id) {
                    self.cleanup_frame_processing(&peer_id, memory_needed);
                    return Err(ByzantineDefenseError::SessionLimited { peer_id });
                }
                started_session = true;
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
                if started_object_request {
                    self.resource_manager.complete_request(&peer_id);
                }
                if started_session {
                    self.resource_manager.end_session(&peer_id);
                }
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
        if frame.version() != crate::net::atp::protocol::frames::ProtocolVersion::CURRENT {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *peer_id });
        }

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

    fn reject(peer_id: &PeerId) -> ByzantineDefenseError {
        ByzantineDefenseError::RequestRejected { peer_id: *peer_id }
    }

    fn validate_exact_len(peer_id: &PeerId, frame: &Frame, expected: usize) -> DefenseResult<()> {
        if frame.payload().len() == expected {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    fn validate_min_len(peer_id: &PeerId, frame: &Frame, min: usize) -> DefenseResult<()> {
        if frame.payload().len() >= min {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    fn read_peer_id(reader: &mut PayloadReader<'_>) -> Option<[u8; PEER_ID_LEN]> {
        let peer_id: [u8; PEER_ID_LEN] = reader.read_slice(PEER_ID_LEN)?.try_into().ok()?;
        if peer_id.iter().all(|byte| *byte == 0) {
            return None;
        }
        Some(peer_id)
    }

    fn read_digest(reader: &mut PayloadReader<'_>) -> Option<[u8; DIGEST_LEN]> {
        let digest: [u8; DIGEST_LEN] = reader.read_slice(DIGEST_LEN)?.try_into().ok()?;
        if digest.iter().all(|byte| *byte == 0) {
            return None;
        }
        Some(digest)
    }

    fn read_optional_u64(reader: &mut PayloadReader<'_>) -> Option<Option<u64>> {
        if reader.read_bool()? {
            Some(Some(reader.read_u64()?))
        } else {
            Some(None)
        }
    }

    fn read_optional_hash(reader: &mut PayloadReader<'_>) -> Option<Option<[u8; DIGEST_LEN]>> {
        if reader.read_bool()? {
            Some(Some(Self::read_digest(reader)?))
        } else {
            Some(None)
        }
    }

    fn read_optional_peer_id(reader: &mut PayloadReader<'_>) -> Option<Option<[u8; PEER_ID_LEN]>> {
        if reader.read_bool()? {
            Some(Some(Self::read_peer_id(reader)?))
        } else {
            Some(None)
        }
    }

    fn validate_context_code(code: u8) -> bool {
        usize::from(code) < MAX_CONTEXT_COUNT
    }

    fn read_feature_set(reader: &mut PayloadReader<'_>) -> Option<()> {
        Self::read_counted_codes(reader, MAX_FEATURE_COUNT, MAX_FEATURE_COUNT)
    }

    fn read_action_set(reader: &mut PayloadReader<'_>) -> Option<()> {
        Self::read_counted_codes(reader, MAX_ACTION_COUNT, MAX_ACTION_COUNT)
    }

    fn read_context_set(reader: &mut PayloadReader<'_>) -> Option<()> {
        Self::read_counted_codes(reader, MAX_CONTEXT_COUNT, MAX_CONTEXT_COUNT)
    }

    fn read_counted_codes(
        reader: &mut PayloadReader<'_>,
        max_count: usize,
        code_limit: usize,
    ) -> Option<()> {
        let count = usize::try_from(reader.read_u32()?).ok()?;
        if count > max_count {
            return None;
        }

        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let code = reader.read_u8()?;
            if usize::from(code) >= code_limit || !seen.insert(code) {
                return None;
            }
        }
        Some(())
    }

    fn read_capability_grant(reader: &mut PayloadReader<'_>) -> Option<()> {
        Self::read_digest(reader)?;
        let issuer = Self::read_peer_id(reader)?;
        let subject = Self::read_peer_id(reader)?;
        if issuer == subject {
            return None;
        }

        Self::read_action_set(reader)?;
        let valid_from = reader.read_u64()?;
        if let Some(expires_at) = Self::read_optional_u64(reader)? {
            if expires_at <= valid_from {
                return None;
            }
        }

        reader.read_bool()?;
        reader.read_u8()?;
        reader.read_bool()?;
        Self::read_capability_scope(reader)
    }

    fn read_capability_scope(reader: &mut PayloadReader<'_>) -> Option<()> {
        reader.read_bool()?;
        let path_id_count = usize::try_from(reader.read_u32()?).ok()?;
        if path_id_count > MAX_SCOPE_ITEM_COUNT {
            return None;
        }
        for _ in 0..path_id_count {
            reader.read_u64()?;
        }

        let prefix_count = usize::try_from(reader.read_u32()?).ok()?;
        if prefix_count > MAX_SCOPE_ITEM_COUNT {
            return None;
        }
        for _ in 0..prefix_count {
            reader.read_len_prefixed_str(MAX_SCOPE_PREFIX_LEN)?;
        }

        reader.read_bool()?;
        let relay_count = usize::try_from(reader.read_u32()?).ok()?;
        if relay_count > MAX_SCOPE_ITEM_COUNT {
            return None;
        }
        for _ in 0..relay_count {
            Self::read_peer_id(reader)?;
        }

        reader.read_bool()?;
        let root_count = usize::try_from(reader.read_u32()?).ok()?;
        if root_count > MAX_SCOPE_ITEM_COUNT {
            return None;
        }
        for _ in 0..root_count {
            Self::read_digest(reader)?;
        }

        Self::read_context_set(reader)
    }

    fn validate_manifest_payload(payload: &[u8]) -> bool {
        Self::extract_manifest_size_from_payload(payload).is_some_and(|size| size > 0)
    }

    fn extract_manifest_size_from_payload(payload: &[u8]) -> Option<u64> {
        if payload.is_empty() {
            return None;
        }

        // Format: [version: varint][size: u64][manifest_data].
        let mut offset = 0;
        let max_varint_len = std::cmp::min(payload.len() - offset, 8);
        let mut buf = BytesMut::from(payload.get(offset..offset + max_varint_len)?);
        let version_varint = match VarInt::decode(&mut buf) {
            Outcome::Ok(Some(version)) => version,
            _ => return None,
        };
        if !ManifestVersion(version_varint.value() as u32).is_supported() {
            return None;
        }
        offset += version_varint.encoded_len();

        let size_bytes: [u8; 8] = payload
            .get(offset..offset.checked_add(8)?)?
            .try_into()
            .ok()?;
        let declared_size = u64::from_be_bytes(size_bytes);
        if declared_size > u64::MAX / 2 {
            return None;
        }

        let expected_payload_len = (offset as u64).checked_add(8)?.checked_add(declared_size)?;
        if payload.len() as u64 != expected_payload_len {
            return None;
        }
        Some(declared_size)
    }

    /// Handle handshake frame processing.
    fn handle_handshake_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        let initiator = Self::read_peer_id(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        let responder = Self::read_peer_id(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if initiator == responder {
            return Err(Self::reject(peer_id));
        }

        let nonce = reader
            .read_slice(TRANSFER_NONCE_LEN)
            .ok_or_else(|| Self::reject(peer_id))?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(Self::reject(peer_id));
        }
        if reader.read_u32().ok_or_else(|| Self::reject(peer_id))? != frame.version().0 {
            return Err(Self::reject(peer_id));
        }
        Self::read_optional_hash(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        Self::read_optional_u64(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if let Some(relay_peer) =
            Self::read_optional_peer_id(&mut reader).ok_or_else(|| Self::reject(peer_id))?
        {
            if relay_peer == initiator || relay_peer == responder {
                return Err(Self::reject(peer_id));
            }
        }

        let context = reader.read_u8().ok_or_else(|| Self::reject(peer_id))?;
        if !Self::validate_context_code(context) {
            return Err(Self::reject(peer_id));
        }
        Self::read_feature_set(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        Self::read_action_set(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;

        let grant_count = usize::try_from(reader.read_u32().ok_or_else(|| Self::reject(peer_id))?)
            .map_err(|_| Self::reject(peer_id))?;
        if grant_count > MAX_GRANT_COUNT {
            return Err(Self::reject(peer_id));
        }
        for _ in 0..grant_count {
            Self::read_capability_grant(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        }

        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle handshake acknowledgment frame processing.
    fn handle_handshake_ack_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        let acceptor = Self::read_peer_id(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        let initiator = Self::read_peer_id(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if acceptor == initiator {
            return Err(Self::reject(peer_id));
        }
        let nonce = reader
            .read_slice(TRANSFER_NONCE_LEN)
            .ok_or_else(|| Self::reject(peer_id))?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(Self::reject(peer_id));
        }
        if reader.read_u32().ok_or_else(|| Self::reject(peer_id))? != frame.version().0 {
            return Err(Self::reject(peer_id));
        }
        let context = reader.read_u8().ok_or_else(|| Self::reject(peer_id))?;
        if !Self::validate_context_code(context) {
            return Err(Self::reject(peer_id));
        }
        Self::read_feature_set(&mut reader).ok_or_else(|| Self::reject(peer_id))?;

        let warning_count =
            usize::try_from(reader.read_u32().ok_or_else(|| Self::reject(peer_id))?)
                .map_err(|_| Self::reject(peer_id))?;
        if warning_count > MAX_FEATURE_COUNT {
            return Err(Self::reject(peer_id));
        }
        for _ in 0..warning_count {
            let feature = reader.read_u8().ok_or_else(|| Self::reject(peer_id))?;
            if usize::from(feature) >= MAX_FEATURE_COUNT {
                return Err(Self::reject(peer_id));
            }
            reader
                .read_len_prefixed_str(MAX_REASON_LEN)
                .ok_or_else(|| Self::reject(peer_id))?;
        }

        let accepted_grants =
            usize::try_from(reader.read_u32().ok_or_else(|| Self::reject(peer_id))?)
                .map_err(|_| Self::reject(peer_id))?;
        if accepted_grants > MAX_GRANT_COUNT {
            return Err(Self::reject(peer_id));
        }
        for _ in 0..accepted_grants {
            Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        }
        reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;

        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle capabilities frame processing.
    fn handle_capabilities_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_feature_set(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle capabilities acknowledgment frame processing.
    fn handle_capabilities_ack_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        self.handle_capabilities_frame(peer_id, frame)
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
            .ok_or(ByzantineDefenseError::RequestRejected { peer_id: *peer_id })?;

        // Additional manifest validation
        if manifest_size == 0 {
            return Err(ByzantineDefenseError::RequestRejected { peer_id: *peer_id });
        }

        if Self::validate_manifest_payload(frame.payload()) {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle object request frame processing.
    fn handle_object_request_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        match reader.remaining() {
            0 => Ok(()),
            16 => {
                reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;
                if reader.read_u64().ok_or_else(|| Self::reject(peer_id))? == 0 {
                    return Err(Self::reject(peer_id));
                }
                Ok(())
            }
            _ => Err(Self::reject(peer_id)),
        }
    }

    /// Handle object data frame processing.
    fn handle_object_data_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;
        let declared_len = usize::try_from(reader.read_u64().ok_or_else(|| Self::reject(peer_id))?)
            .map_err(|_| Self::reject(peer_id))?;
        if declared_len == 0 || declared_len != reader.remaining() {
            return Err(Self::reject(peer_id));
        }
        reader
            .read_slice(declared_len)
            .ok_or_else(|| Self::reject(peer_id))?;
        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle object complete frame processing.
    fn handle_object_complete_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        Self::validate_exact_len(peer_id, frame, DIGEST_LEN * 2)?;
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        Ok(())
    }

    /// Handle object error frame processing.
    fn handle_object_error_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if reader.read_u32().ok_or_else(|| Self::reject(peer_id))? == 0 {
            return Err(Self::reject(peer_id));
        }
        reader
            .read_len_prefixed_str(MAX_REASON_LEN)
            .ok_or_else(|| Self::reject(peer_id))?;
        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    /// Handle path update frame processing.
    fn handle_path_update_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        let path_id = reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;
        let sequence = reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;
        let state = reader.read_u8().ok_or_else(|| Self::reject(peer_id))?;
        if path_id == 0 || sequence == 0 || state > 3 || !reader.finish() {
            return Err(Self::reject(peer_id));
        }
        Ok(())
    }

    /// Handle path challenge frame processing.
    fn handle_path_challenge_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &Frame,
    ) -> DefenseResult<()> {
        Self::validate_exact_len(peer_id, frame, 8)?;
        let mut reader = PayloadReader::new(frame.payload());
        if reader.read_u64().ok_or_else(|| Self::reject(peer_id))? == 0 {
            Err(Self::reject(peer_id))
        } else {
            Ok(())
        }
    }

    /// Handle path response frame processing.
    fn handle_path_response_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        self.handle_path_challenge_frame(peer_id, frame)
    }

    /// Handle cancel frame processing.
    fn handle_cancel_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        Self::validate_min_len(peer_id, frame, 12)?;
        Self::validate_control_reason_payload(peer_id, frame)
    }

    /// Handle error frame processing.
    fn handle_error_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        Self::validate_min_len(peer_id, frame, 12)?;
        Self::validate_control_reason_payload(peer_id, frame)
    }

    /// Handle close frame processing.
    fn handle_close_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        Self::validate_min_len(peer_id, frame, 12)?;
        Self::validate_control_reason_payload(peer_id, frame)
    }

    /// Handle control frame processing.
    fn handle_control_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let opcode = *frame
            .payload()
            .first()
            .ok_or_else(|| Self::reject(peer_id))?;
        if opcode == 0 {
            Err(Self::reject(peer_id))
        } else {
            Ok(())
        }
    }

    /// Handle data frame processing.
    fn handle_data_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        Self::validate_min_len(peer_id, frame, 1)
    }

    /// Handle proof frame processing.
    fn handle_proof_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        if reader.remaining() == 0 {
            Err(Self::reject(peer_id))
        } else {
            Ok(())
        }
    }

    /// Handle repair frame processing.
    fn handle_repair_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        let repair_group = reader.read_u64().ok_or_else(|| Self::reject(peer_id))?;
        let symbol_count = reader.read_u32().ok_or_else(|| Self::reject(peer_id))?;
        if repair_group == 0 || symbol_count == 0 {
            return Err(Self::reject(peer_id));
        }
        Ok(())
    }

    /// Handle session frame processing.
    fn handle_session_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        Self::read_digest(&mut reader).ok_or_else(|| Self::reject(peer_id))?;
        let state = reader.read_u8().ok_or_else(|| Self::reject(peer_id))?;
        if state > 5 {
            return Err(Self::reject(peer_id));
        }
        Ok(())
    }

    /// Handle generic adapter manifest frame processing.
    fn handle_manifest_frame(&mut self, peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        if Self::validate_manifest_payload(frame.payload()) {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
    }

    fn validate_control_reason_payload(peer_id: &PeerId, frame: &Frame) -> DefenseResult<()> {
        let mut reader = PayloadReader::new(frame.payload());
        if reader.read_u64().ok_or_else(|| Self::reject(peer_id))? == 0 {
            return Err(Self::reject(peer_id));
        }
        if reader.read_u32().ok_or_else(|| Self::reject(peer_id))? == 0 {
            return Err(Self::reject(peer_id));
        }
        reader
            .read_len_prefixed_str(MAX_REASON_LEN)
            .ok_or_else(|| Self::reject(peer_id))?;
        if reader.finish() {
            Ok(())
        } else {
            Err(Self::reject(peer_id))
        }
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

        Self::extract_manifest_size_from_payload(frame.payload())
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

    fn nonzero_bytes(value: u8, len: usize) -> Vec<u8> {
        vec![value; len]
    }

    fn object_request_frame() -> Frame {
        Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            nonzero_bytes(7, DIGEST_LEN),
        )
        .expect("valid object request frame")
    }

    fn manifest_frame(manifest_size: usize) -> Frame {
        let mut payload = Vec::new();
        let mut version = BytesMut::new();
        VarInt::new(ManifestVersion::CURRENT.0.into())
            .expect("manifest version fits varint")
            .encode(&mut version)
            .expect("encode manifest version");
        payload.extend_from_slice(&version);
        payload.extend_from_slice(&(manifest_size as u64).to_be_bytes());
        payload.extend(std::iter::repeat_n(0x5a, manifest_size));
        Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectManifest, payload)
            .expect("valid manifest frame")
    }

    fn handshake_frame() -> Frame {
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonzero_bytes(1, PEER_ID_LEN));
        payload.extend_from_slice(&nonzero_bytes(2, PEER_ID_LEN));
        payload.extend_from_slice(&nonzero_bytes(3, TRANSFER_NONCE_LEN));
        payload.extend_from_slice(&ProtocolVersion::CURRENT.0.to_be_bytes());
        payload.push(0); // no manifest root
        payload.push(0); // no path id
        payload.push(0); // no relay peer
        payload.push(0); // direct context
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.push(3); // encryption_policy
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        Frame::new(ProtocolVersion::CURRENT, FrameType::Handshake, payload)
            .expect("valid handshake frame")
    }

    fn create_test_frame(frame_type: FrameType, payload: Vec<u8>) -> Frame {
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

        let frame = object_request_frame();

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

        processor.resource_manager.update_limits(
            crate::net::atp::protocol::resource_manager::ResourceLimits {
                max_memory_per_peer: 64,
                max_manifest_size: 1024,
                ..Default::default()
            },
        );

        let large_frame = manifest_frame(128);

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

        let handshake_frame = handshake_frame();

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

        let frame = object_request_frame();

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

    #[test]
    fn capabilities_ack_rejects_empty_payload() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("capabilities-ack-peer");
        let frame = create_test_frame(FrameType::CapabilitiesAck, Vec::new());

        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::RequestRejected { .. })
        ));
    }

    #[test]
    fn path_challenge_requires_exact_nonzero_eight_bytes() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("path-challenge-peer");
        let short = create_test_frame(FrameType::PathChallenge, vec![1; 7]);
        let zero = create_test_frame(FrameType::PathChallenge, vec![0; 8]);
        let valid = create_test_frame(FrameType::PathChallenge, 9u64.to_be_bytes().to_vec());

        assert!(processor.process_frame(peer_id, &short).is_err());
        assert!(processor.process_frame(peer_id, &zero).is_err());
        assert!(processor.process_frame(peer_id, &valid).is_ok());
    }

    #[test]
    fn object_request_requires_nonzero_object_id() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("object-request-peer");
        let bad = create_test_frame(FrameType::ObjectRequest, vec![0; DIGEST_LEN]);
        let good = object_request_frame();

        assert!(processor.process_frame(peer_id, &bad).is_err());
        assert!(processor.process_frame(peer_id, &good).is_ok());
    }

    #[test]
    fn object_error_requires_code_and_utf8_reason() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("object-error-peer");
        let mut payload = nonzero_bytes(11, DIGEST_LEN);
        payload.extend_from_slice(&7u32.to_be_bytes());
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(b"lost");
        let valid = create_test_frame(FrameType::ObjectError, payload);

        let mut invalid_utf8 = nonzero_bytes(11, DIGEST_LEN);
        invalid_utf8.extend_from_slice(&7u32.to_be_bytes());
        invalid_utf8.extend_from_slice(&1u32.to_be_bytes());
        invalid_utf8.push(0xff);
        let invalid = create_test_frame(FrameType::ObjectError, invalid_utf8);

        assert!(processor.process_frame(peer_id, &valid).is_ok());
        assert!(processor.process_frame(peer_id, &invalid).is_err());
    }

    #[test]
    fn manifest_rejects_declared_size_mismatch() {
        let mut processor = DefendedFrameProcessor::new();
        let peer_id = PeerId::from_label("manifest-peer");
        let mut payload = Vec::new();
        payload.push(ManifestVersion::CURRENT.0 as u8);
        payload.extend_from_slice(&8u64.to_be_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        let frame = create_test_frame(FrameType::ObjectManifest, payload);

        assert!(matches!(
            processor.process_frame(peer_id, &frame),
            Err(ByzantineDefenseError::RequestRejected { .. })
        ));
    }
}
