//! ATP-over-H3 adapter implementation.

use super::{AtpH3Error, AtpH3Result, H3FrameCodec, H3Session};
use crate::net::atp::protocol::{AtpFrame, FrameType};
use std::collections::{HashMap, hash_map::Entry};

/// Stable adapter kind for ATP-over-H3/WebTransport compatibility reports.
pub const H3_WEBTRANSPORT_ADAPTER_KIND: &str = "h3_webtransport_adapter";
/// Stable foundation kind that remains authoritative for native ATP semantics.
pub const NATIVE_ATP_FOUNDATION_KIND: &str = "native_atp_over_native_quic";

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

/// Stable diagnostic report for one compatibility-adapter negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterNegotiationReport {
    /// Adapter kind that produced this report.
    pub adapter_kind: String,
    /// Native ATP foundation this adapter is layered after.
    pub foundation_kind: String,
    /// Whether this is an adapter after native ATP instead of a foundation.
    pub adapter_after_native: bool,
    /// Whether this adapter claims to replace native QUIC.
    pub replacement_for_native_quic: bool,
    /// Stable list of features supported by this adapter.
    pub supported_features: Vec<String>,
    /// Stable list of explicit downgrades for unsupported native features.
    pub downgrades: Vec<AdapterDowngrade>,
    /// Stable list of adapter-specific constraints.
    pub constraints: Vec<String>,
}

/// One explicit compatibility-adapter downgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDowngrade {
    /// Native ATP feature that is downgraded or unavailable.
    pub feature: String,
    /// Stable machine-readable downgrade reason.
    pub reason_code: String,
    /// Stable user-facing caveat for diagnostics.
    pub caveat: String,
}

impl AdapterDowngrade {
    fn for_unsupported_feature(feature: &str) -> Self {
        let (reason_code, caveat) = if feature.contains("QUIC connection migration") {
            (
                "native_quic_migration_unavailable",
                "connection migration stays a native ATP capability",
            )
        } else if feature.contains("Raw UDP") || feature.contains("STUN") {
            (
                "raw_udp_unavailable",
                "browser and H3 adapter paths cannot expose raw UDP primitives",
            )
        } else if feature.contains("Custom QUIC") {
            (
                "custom_quic_extensions_unavailable",
                "custom QUIC extension negotiation stays in the native ATP path",
            )
        } else if feature.contains("Zero-copy") {
            (
                "zero_copy_unavailable",
                "adapter framing copies across WebTransport and WASM boundaries",
            )
        } else if feature.contains("flow control") {
            (
                "h3_flow_control_boundary",
                "fine-grained flow control is mediated by the H3/WebTransport layer",
            )
        } else if feature.contains("pacing") {
            (
                "packet_pacing_unavailable",
                "packet pacing is mediated by browser and H3 transport policy",
            )
        } else {
            (
                "adapter_feature_unavailable",
                "feature is unavailable in this compatibility adapter",
            )
        };

        Self {
            feature: feature.to_string(),
            reason_code: reason_code.to_string(),
            caveat: caveat.to_string(),
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

    /// Build a stable negotiation report for diagnostics and proof artifacts.
    pub fn negotiation_report(&self) -> AdapterNegotiationReport {
        let mut supported_features = self.features.supported.clone();
        supported_features.sort();

        let mut downgrades: Vec<_> = self
            .features
            .unsupported
            .iter()
            .map(|feature| AdapterDowngrade::for_unsupported_feature(feature))
            .collect();
        downgrades.sort_by(|left, right| left.feature.cmp(&right.feature));

        let mut constraints = self.features.constraints.clone();
        constraints.sort();

        AdapterNegotiationReport {
            adapter_kind: H3_WEBTRANSPORT_ADAPTER_KIND.to_string(),
            foundation_kind: NATIVE_ATP_FOUNDATION_KIND.to_string(),
            adapter_after_native: true,
            replacement_for_native_quic: false,
            supported_features,
            downgrades,
            constraints,
        }
    }

    /// Build a stable unsupported-feature error for adapter diagnostics.
    pub fn unsupported_feature_error(&self, feature: &str) -> AtpH3Error {
        let downgrade = AdapterDowngrade::for_unsupported_feature(feature);
        AtpH3Error::UnsupportedFeature(format!(
            "{feature} unavailable in {H3_WEBTRANSPORT_ADAPTER_KIND}; \
             native foundation={NATIVE_ATP_FOUNDATION_KIND}; \
             replacement_for_native_quic=false; downgrade_reason={}",
            downgrade.reason_code
        ))
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
    fn test_negotiation_report_is_stable_and_adapter_scoped() {
        let adapter = AtpH3Adapter::new(AdapterConfig::default());
        let report = adapter.negotiation_report();

        assert_eq!(report.adapter_kind, H3_WEBTRANSPORT_ADAPTER_KIND);
        assert_eq!(report.foundation_kind, NATIVE_ATP_FOUNDATION_KIND);
        assert!(report.adapter_after_native);
        assert!(!report.replacement_for_native_quic);
        assert_eq!(report, adapter.negotiation_report());
        assert!(
            report
                .downgrades
                .iter()
                .any(|downgrade| downgrade.reason_code == "raw_udp_unavailable")
        );
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
