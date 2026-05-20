//! ATP-over-H3 adapter implementation.

use super::{AtpH3Error, AtpH3Result, H3FrameCodec, H3Session};
use crate::net::atp::protocol::{AtpFrame, FrameType};
use std::collections::{HashMap, hash_map::Entry};

/// ATP-over-H3 adapter configuration.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// Maximum concurrent bidirectional streams.
    pub max_streams: u32,
    /// Maximum datagram payload size.
    pub max_datagram_size: usize,
    /// Enable unreliable repair frame transmission.
    pub enable_unreliable_repair: bool,
    /// WebTransport connection timeout.
    pub connection_timeout_ms: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            max_streams: 100,
            max_datagram_size: 1350, // Conservative MTU
            enable_unreliable_repair: true,
            connection_timeout_ms: 30000,
        }
    }
}

/// Feature support matrix for ATP-over-H3.
#[derive(Debug, Clone)]
pub struct FeatureSupport {
    /// Native ATP features supported over WebTransport.
    pub supported: Vec<String>,
    /// Native ATP features not available over WebTransport.
    pub unsupported: Vec<String>,
    /// Browser-specific constraints.
    pub constraints: Vec<String>,
}

impl Default for FeatureSupport {
    fn default() -> Self {
        Self {
            supported: vec![
                "ATP frame codec".to_string(),
                "Session negotiation".to_string(),
                "Proof bundle verification".to_string(),
                "Content addressing".to_string(),
                "Manifest validation".to_string(),
                "Basic replay evidence".to_string(),
            ],
            unsupported: vec![
                "Native QUIC connection migration".to_string(),
                "Raw UDP socket access".to_string(),
                "Custom QUIC extensions".to_string(),
                "Zero-copy buffer management".to_string(),
                "Fine-grained flow control".to_string(),
                "STUN/relay operations".to_string(),
                "Direct packet pacing control".to_string(),
            ],
            constraints: vec![
                "Same-origin policy".to_string(),
                "Certificate validation required".to_string(),
                "WASM memory model limitations".to_string(),
                "Limited threading model".to_string(),
                "No raw networking access".to_string(),
            ],
        }
    }
}

/// Main ATP-over-H3 adapter.
#[derive(Debug)]
pub struct AtpH3Adapter {
    /// Adapter configuration.
    config: AdapterConfig,
    /// Active H3 sessions.
    sessions: HashMap<String, H3Session>,
    /// Frame codec for ATP-over-WebTransport.
    codec: H3FrameCodec,
    /// Feature support matrix.
    features: FeatureSupport,
}

impl AtpH3Adapter {
    /// Create a new ATP-over-H3 adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            codec: H3FrameCodec::new(),
            features: FeatureSupport::default(),
        }
    }

    /// Get feature support information.
    pub fn feature_support(&self) -> &FeatureSupport {
        &self.features
    }

    /// Check if an ATP feature is supported over WebTransport.
    pub fn is_feature_supported(&self, feature: &str) -> bool {
        self.features.supported.iter().any(|f| f.contains(feature))
    }

    /// Create a new H3 session.
    pub fn create_session(&mut self, session_id: String) -> AtpH3Result<&mut H3Session> {
        if self.sessions.len() >= self.config.max_streams as usize {
            return Err(AtpH3Error::Session("Maximum sessions exceeded".to_string()));
        }

        let session = H3Session::new(session_id.clone(), &self.config)?;
        match self.sessions.entry(session_id) {
            Entry::Vacant(entry) => Ok(entry.insert(session)),
            Entry::Occupied(mut entry) => {
                entry.insert(session);
                Ok(entry.into_mut())
            }
        }
    }

    /// Get an existing H3 session.
    pub fn get_session(&self, session_id: &str) -> Option<&H3Session> {
        self.sessions.get(session_id)
    }

    /// Get a mutable reference to an existing H3 session.
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut H3Session> {
        self.sessions.get_mut(session_id)
    }

    /// Remove and close an H3 session.
    pub fn close_session(&mut self, session_id: &str) -> AtpH3Result<()> {
        if let Some(session) = self.sessions.remove(session_id) {
            session.close()?;
        }
        Ok(())
    }

    /// Map ATP frame to WebTransport transmission.
    pub fn map_atp_frame(&self, frame: &AtpFrame) -> AtpH3Result<TransmissionStrategy> {
        match frame.frame_type() {
            FrameType::Control => Ok(TransmissionStrategy::ReliableStream),
            FrameType::Data => Ok(TransmissionStrategy::ReliableStream),
            FrameType::Proof => Ok(TransmissionStrategy::ReliableStream),
            FrameType::Repair => {
                if self.config.enable_unreliable_repair {
                    Ok(TransmissionStrategy::UnreliableDatagram)
                } else {
                    Ok(TransmissionStrategy::ReliableStream)
                }
            }
            FrameType::Session => Ok(TransmissionStrategy::ReliableStream),
            FrameType::Manifest => Ok(TransmissionStrategy::ReliableStream),
            _ => Err(AtpH3Error::UnsupportedFeature(format!(
                "Frame type {:?} not supported over WebTransport",
                frame.frame_type()
            ))),
        }
    }

    /// Encode ATP frame for WebTransport transmission.
    pub fn encode_frame(&self, frame: &AtpFrame) -> AtpH3Result<Vec<u8>> {
        self.codec.encode_atp_frame(frame)
    }

    /// Decode WebTransport data to ATP frame.
    pub fn decode_frame(&self, data: &[u8]) -> AtpH3Result<AtpFrame> {
        self.codec.decode_atp_frame(data)
    }

    /// Validate frame size for WebTransport constraints.
    pub fn validate_frame_size(
        &self,
        frame: &AtpFrame,
        strategy: &TransmissionStrategy,
    ) -> AtpH3Result<()> {
        let encoded_size = self.encode_frame(frame)?.len();

        match strategy {
            TransmissionStrategy::UnreliableDatagram => {
                if encoded_size > self.config.max_datagram_size {
                    return Err(AtpH3Error::SecurityConstraint(format!(
                        "Frame size {} exceeds datagram limit {}",
                        encoded_size, self.config.max_datagram_size
                    )));
                }
            }
            TransmissionStrategy::ReliableStream => {
                // Streams can handle larger frames but may need fragmentation
                if encoded_size > 64 * 1024 {
                    return Err(AtpH3Error::Stream(
                        "Frame too large for efficient stream transmission".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get adapter statistics.
    pub fn stats(&self) -> AdapterStats {
        AdapterStats {
            active_sessions: self.sessions.len(),
            max_sessions: self.config.max_streams as usize,
            supported_features: self.features.supported.len(),
            unsupported_features: self.features.unsupported.len(),
        }
    }
}

/// WebTransport transmission strategy for ATP frames.
#[derive(Debug, Clone, PartialEq)]
pub enum TransmissionStrategy {
    /// Send over reliable bidirectional stream.
    ReliableStream,
    /// Send over unreliable datagram.
    UnreliableDatagram,
}

/// Adapter usage statistics.
#[derive(Debug, Clone)]
pub struct AdapterStats {
    /// Number of active H3 sessions.
    pub active_sessions: usize,
    /// Maximum allowed sessions.
    pub max_sessions: usize,
    /// Number of supported ATP features.
    pub supported_features: usize,
    /// Number of unsupported ATP features.
    pub unsupported_features: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let config = AdapterConfig::default();
        let adapter = AtpH3Adapter::new(config);

        assert_eq!(adapter.sessions.len(), 0);
        assert!(adapter.feature_support().supported.len() > 0);
        assert!(adapter.feature_support().unsupported.len() > 0);
    }

    #[test]
    fn test_feature_support_query() {
        let adapter = AtpH3Adapter::new(AdapterConfig::default());

        assert!(adapter.is_feature_supported("ATP frame codec"));
        assert!(!adapter.is_feature_supported("Raw UDP socket"));
        assert!(!adapter.is_feature_supported("QUIC migration"));
    }

    #[test]
    fn test_session_management() {
        let mut adapter = AtpH3Adapter::new(AdapterConfig::default());

        // Create session
        let session_id = "test-session-1".to_string();
        assert!(adapter.create_session(session_id.clone()).is_ok());
        assert_eq!(adapter.sessions.len(), 1);

        // Get session
        assert!(adapter.get_session(&session_id).is_some());

        // Close session
        assert!(adapter.close_session(&session_id).is_ok());
        assert_eq!(adapter.sessions.len(), 0);
    }

    #[test]
    fn test_create_session_returns_inserted_session() {
        let mut adapter = AtpH3Adapter::new(AdapterConfig::default());
        let session_id = "test-session-entry".to_string();

        let session = adapter.create_session(session_id.clone()).unwrap();

        assert_eq!(session.session_id(), session_id);
        assert!(adapter.get_session("test-session-entry").is_some());
    }
}
