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

/// ATP frame placeholder for H3 adapter development.
#[derive(Debug)]
pub struct AtpFrame {
    frame_type: FrameType,
    payload: Vec<u8>,
}

impl AtpFrame {
    /// Create a placeholder ATP frame for testing.
    pub fn new_placeholder(frame_type: FrameType) -> Result<Self, String> {
        Ok(Self {
            frame_type,
            payload: match frame_type {
                FrameType::Control => b"ATP-CONTROL-PLACEHOLDER".to_vec(),
                FrameType::Data => b"ATP-DATA-PLACEHOLDER".to_vec(),
                FrameType::Proof => b"ATP-PROOF-PLACEHOLDER".to_vec(),
                FrameType::Repair => b"ATP-REPAIR-PLACEHOLDER".to_vec(),
                FrameType::Session => b"ATP-SESSION-PLACEHOLDER".to_vec(),
                FrameType::Manifest => b"ATP-MANIFEST-PLACEHOLDER".to_vec(),
            },
        })
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