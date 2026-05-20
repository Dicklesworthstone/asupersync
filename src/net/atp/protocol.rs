//! ATP protocol frame types for H3 adapter.

/// ATP frame types for protocol-level identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Control frame for session management.
    Control,
    /// Data frame for payload transmission.
    Data,
    /// Proof frame for verification data.
    Proof,
    /// Repair frame for error correction.
    Repair,
    /// Session frame for handshake/negotiation.
    Session,
    /// Manifest frame for object metadata.
    Manifest,
}

/// ATP frame used by adapter development surfaces.
#[derive(Debug)]
pub struct AtpFrame {
    frame_type: FrameType,
    payload: Vec<u8>,
}

impl AtpFrame {
    /// Create an ATP frame with explicit payload bytes.
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            frame_type,
            payload,
        })
    }

    /// Create an ATP frame with no payload.
    pub fn empty(frame_type: FrameType) -> Result<Self, String> {
        Self::new(frame_type, Vec::new())
    }

    /// Get the frame type.
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Get the frame payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
