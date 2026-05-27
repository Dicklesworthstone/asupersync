//! WebTransport adapter for ATP over HTTP/3.
//!
//! Implements ATP-over-WebTransport for browser compatibility while preserving
//! ATP's verification, stream semantics, and proof generation capabilities.

use super::{AdapterNegotiation, AdapterType, FeatureSupport, PerformanceCaveat, SessionStats};
use crate::atp::object::ObjectId;
use crate::error::{Error, ErrorKind, Result};
use crate::types::TraceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// WebTransport-specific configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTransportConfig {
    /// WebTransport session configuration
    pub session_config: WebTransportSessionConfig,
    /// Stream configuration
    pub stream_config: StreamConfig,
    /// Datagram configuration
    pub datagram_config: DatagramConfig,
    /// Browser security policy
    pub security_policy: BrowserSecurityPolicy,
}

/// WebTransport session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTransportSessionConfig {
    /// Maximum bidirectional streams
    pub max_bidirectional_streams: u32,
    /// Maximum unidirectional streams
    pub max_unidirectional_streams: u32,
    /// Session timeout
    pub session_timeout: Duration,
    /// Close timeout
    pub close_timeout: Duration,
}

/// Stream configuration for WebTransport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Default stream priority
    pub default_priority: u8,
    /// Flow control window
    pub flow_control_window: u32,
    /// Maximum frame size
    pub max_frame_size: u32,
    /// Stream idle timeout
    pub idle_timeout: Duration,
}

/// Datagram configuration for WebTransport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramConfig {
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Datagram queue size
    pub queue_size: usize,
    /// Enable datagram flow control
    pub flow_control: bool,
}

/// Browser security policy constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSecurityPolicy {
    /// CORS policy enforcement
    pub cors_policy: CorsPolicy,
    /// Certificate validation requirements
    pub cert_validation: CertValidationPolicy,
    /// Origin restrictions
    pub origin_restrictions: Vec<String>,
    /// Feature permissions
    pub feature_permissions: FeaturePermissions,
}

/// CORS policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicy {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight cache
    pub max_age: Duration,
}

/// Certificate validation policy for WebTransport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertValidationPolicy {
    /// Require valid certificate chain
    RequireValid,
    /// Allow self-signed for development
    AllowSelfSigned,
    /// Custom validation logic
    CustomValidation,
}

/// Feature permissions in browser environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturePermissions {
    /// Allow WebTransport connections
    pub webtransport_enabled: bool,
    /// Allow datagram usage
    pub datagrams_enabled: bool,
    /// Allow streams
    pub streams_enabled: bool,
    /// File system access for proof storage
    pub filesystem_access: bool,
}

/// WebTransport adapter implementation.
#[derive(Debug)]
pub struct WebTransportAdapter {
    /// Adapter configuration
    config: WebTransportConfig,
    /// Active sessions
    sessions: HashMap<String, WebTransportSession>,
    /// Adapter statistics
    stats: WebTransportStats,
}

/// WebTransport session state.
#[derive(Debug, Clone)]
pub struct WebTransportSession {
    /// Session identifier
    pub session_id: String,
    /// WebTransport connection state
    pub connection_state: ConnectionState,
    /// Active streams
    pub active_streams: HashMap<u64, StreamInfo>,
    /// Datagram payloads accepted for transmission by the WebTransport session.
    pub outbound_datagrams: Vec<Vec<u8>>,
    /// Session statistics
    pub session_stats: SessionStats,
    /// Created timestamp
    pub created_at: SystemTime,
}

/// WebTransport connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is ready for use
    Connected,
    /// Connection is closing gracefully
    Closing,
    /// Connection is closed
    Closed,
    /// Connection failed
    Failed,
}

/// Information about active stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    /// Stream ID
    pub stream_id: u64,
    /// Stream type (bidirectional or unidirectional)
    pub stream_type: StreamType,
    /// Current stream state
    pub state: StreamState,
    /// Bytes sent on this stream
    pub bytes_sent: u64,
    /// Bytes received on this stream
    pub bytes_received: u64,
    /// Frames accepted for transmission on this stream.
    pub outbound_frames: Vec<Vec<u8>>,
    /// Stream priority
    pub priority: u8,
    /// Created timestamp
    pub created_at: SystemTime,
}

/// WebTransport stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamType {
    /// Bidirectional stream
    Bidirectional,
    /// Unidirectional outbound stream
    UnidirectionalOutbound,
    /// Unidirectional inbound stream
    UnidirectionalInbound,
}

/// Stream state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamState {
    /// Stream is open and active
    Open,
    /// Stream is half-closed (local)
    HalfClosedLocal,
    /// Stream is half-closed (remote)
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
    /// Stream reset by peer
    Reset,
}

/// WebTransport adapter statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTransportStats {
    /// Total sessions created
    pub total_sessions: u64,
    /// Current active sessions
    pub active_sessions: u64,
    /// Total streams created
    pub total_streams: u64,
    /// Total datagrams sent
    pub total_datagrams_sent: u64,
    /// Total datagrams received
    pub total_datagrams_received: u64,
    /// Connection failures
    pub connection_failures: u64,
    /// Stream errors
    pub stream_errors: u64,
    /// Average session duration
    pub avg_session_duration: Duration,
    /// Last updated
    pub last_updated: SystemTime,
}

impl WebTransportAdapter {
    /// Create new WebTransport adapter with configuration.
    pub fn new(config: WebTransportConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            stats: WebTransportStats::new(),
        }
    }

    /// Negotiate WebTransport adapter capabilities.
    pub async fn negotiate(&self, trace_id: TraceId) -> Result<AdapterNegotiation> {
        // Check browser WebTransport support
        if !self
            .config
            .security_policy
            .feature_permissions
            .webtransport_enabled
        {
            return Err(Error::new(ErrorKind::ConnectionRefused));
        }

        let mut performance_caveats = Vec::new();

        // WebTransport-specific performance characteristics
        performance_caveats.push(PerformanceCaveat::NestedTransportOverhead);

        // Browser sandbox limitations
        if !self
            .config
            .security_policy
            .feature_permissions
            .filesystem_access
        {
            performance_caveats.push(PerformanceCaveat::ReliabilityConcerns(
                "Limited proof storage in browser sandbox".to_string(),
            ));
        }

        // Add latency caveat for browser overhead
        performance_caveats.push(PerformanceCaveat::IncreasedLatency(Duration::from_millis(
            20,
        )));

        Ok(AdapterNegotiation {
            selected_adapter: AdapterType::WebTransport,
            feature_parity: self.get_feature_parity(),
            downgrade_reasons: Vec::new(),
            performance_caveats,
            adapter_metadata: self.build_metadata(trace_id),
            negotiated_at: SystemTime::now(),
        })
    }

    /// Start WebTransport session for object transfer.
    pub async fn start_session(&mut self, object_id: ObjectId, url: &str) -> Result<String> {
        validate_webtransport_url(url)?;

        let session_id = format!(
            "wt-{}-{}",
            object_id,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let session = WebTransportSession {
            session_id: session_id.clone(),
            connection_state: ConnectionState::Connected,
            active_streams: HashMap::new(),
            outbound_datagrams: Vec::new(),
            session_stats: SessionStats::new(),
            created_at: SystemTime::now(),
        };

        self.sessions.insert(session_id.clone(), session);
        self.stats.total_sessions += 1;
        self.stats.active_sessions += 1;
        self.stats.last_updated = SystemTime::now();

        Ok(session_id)
    }

    /// Create bidirectional stream for ATP communication.
    pub async fn create_stream(&mut self, session_id: &str, priority: u8) -> Result<u64> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        if session.connection_state != ConnectionState::Connected {
            return Err(Error::new(ErrorKind::ConnectionLost));
        }

        // Check stream limits
        let bidirectional_count = session
            .active_streams
            .values()
            .filter(|s| s.stream_type == StreamType::Bidirectional)
            .count();

        if bidirectional_count >= self.config.session_config.max_bidirectional_streams as usize {
            return Err(Error::new(ErrorKind::ChannelFull));
        }

        // Generate new stream ID (even numbers for bidirectional streams)
        let stream_id = (session.active_streams.len() as u64) * 2;

        let stream_info = StreamInfo {
            stream_id,
            stream_type: StreamType::Bidirectional,
            state: StreamState::Open,
            bytes_sent: 0,
            bytes_received: 0,
            outbound_frames: Vec::new(),
            priority,
            created_at: SystemTime::now(),
        };

        session.active_streams.insert(stream_id, stream_info);
        self.stats.total_streams += 1;
        self.stats.last_updated = SystemTime::now();

        Ok(stream_id)
    }

    /// Send ATP frame over WebTransport stream.
    pub async fn send_frame(
        &mut self,
        session_id: &str,
        stream_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        let stream = session
            .active_streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::new(ErrorKind::StreamEnded))?;

        if stream.state != StreamState::Open {
            return Err(Error::new(ErrorKind::StreamEnded));
        }

        if data.len() > self.config.stream_config.max_frame_size as usize {
            return Err(Error::new(ErrorKind::DataTooLarge));
        }

        stream.bytes_sent += data.len() as u64;
        stream.outbound_frames.push(data.to_vec());
        session.session_stats.bytes_sent += data.len() as u64;

        Ok(())
    }

    /// Send datagram over WebTransport.
    pub async fn send_datagram(&mut self, session_id: &str, data: &[u8]) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::new(ErrorKind::ConnectionLost))?;

        if session.connection_state != ConnectionState::Connected {
            return Err(Error::new(ErrorKind::ConnectionLost));
        }

        if !self
            .config
            .security_policy
            .feature_permissions
            .datagrams_enabled
        {
            return Err(Error::new(ErrorKind::ConnectionRefused));
        }

        if data.len() > self.config.datagram_config.max_datagram_size {
            return Err(Error::new(ErrorKind::DataTooLarge));
        }

        if session.outbound_datagrams.len() >= self.config.datagram_config.queue_size {
            return Err(Error::new(ErrorKind::ChannelFull));
        }

        session.outbound_datagrams.push(data.to_vec());
        session.session_stats.bytes_sent += data.len() as u64;
        self.stats.total_datagrams_sent += 1;
        self.stats.last_updated = SystemTime::now();

        Ok(())
    }

    /// Get adapter statistics.
    pub fn stats(&self) -> &WebTransportStats {
        &self.stats
    }

    /// Close WebTransport session.
    pub async fn close_session(&mut self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.connection_state = ConnectionState::Closing;

            // Close all active streams
            for stream in session.active_streams.values_mut() {
                stream.state = StreamState::Closed;
            }

            // Update statistics
            if self.stats.active_sessions > 0 {
                self.stats.active_sessions -= 1;
            }

            let session_duration = SystemTime::now()
                .duration_since(session.created_at)
                .unwrap_or(Duration::from_secs(0));

            // Update average session duration
            self.stats.avg_session_duration = if self.stats.total_sessions > 1 {
                Duration::from_millis(
                    (self.stats.avg_session_duration.as_millis() as u64
                        * (self.stats.total_sessions - 1)
                        + session_duration.as_millis() as u64)
                        / self.stats.total_sessions,
                )
            } else {
                session_duration
            };

            self.stats.last_updated = SystemTime::now();
        }

        Ok(())
    }

    /// Get feature parity for WebTransport adapter.
    fn get_feature_parity(&self) -> crate::atp::adapter::AdapterParity {
        crate::atp::adapter::AdapterParity {
            object_support: FeatureSupport::Full,
            stream_support: FeatureSupport::Full,
            proof_support: FeatureSupport::Partial, // Limited by browser sandbox
            path_support: FeatureSupport::Partial,  // Limited path control
            repair_support: FeatureSupport::Partial, // Limited repair strategies
            datagram_support: FeatureSupport::Full,
            mailbox_support: FeatureSupport::Full,
            swarm_support: FeatureSupport::Partial, // Limited coordination
            diagnostic_support: FeatureSupport::Partial, // Limited diagnostics
        }
    }

    /// Build adapter metadata.
    fn build_metadata(&self, trace_id: TraceId) -> crate::atp::adapter::AdapterMetadata {
        use crate::atp::adapter::{
            AdapterMetadata, CertValidationMode, SecurityParams, TransportPath,
        };

        AdapterMetadata {
            version: "1.0.0".to_string(),
            path_info: TransportPath {
                local_endpoint: "browser".to_string(),
                remote_endpoint: "server.example.com:443".to_string(),
                intermediate_hops: vec!["HTTP/3".to_string(), "WebTransport".to_string()],
                path_mtu: Some(1200), // Conservative for browser
            },
            relay_info: None,
            security_params: SecurityParams {
                tls_version: Some("TLS 1.3".to_string()),
                cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
                cert_validation: CertValidationMode::Full,
                security_flags: vec![
                    "WebTransport".to_string(),
                    "CORS".to_string(),
                    "SOP".to_string(), // Same-Origin Policy
                ],
            },
            replay_pointer: Some(format!("webtransport-trace-{}", trace_id.as_u128())),
        }
    }
}

fn validate_webtransport_url(url: &str) -> Result<()> {
    let authority = url
        .strip_prefix("https://")
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
    let authority = authority.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            session_config: WebTransportSessionConfig {
                max_bidirectional_streams: 100,
                max_unidirectional_streams: 100,
                session_timeout: Duration::from_secs(300),
                close_timeout: Duration::from_secs(5),
            },
            stream_config: StreamConfig {
                default_priority: 128,
                flow_control_window: 65536,
                max_frame_size: 16384,
                idle_timeout: Duration::from_secs(30),
            },
            datagram_config: DatagramConfig {
                max_datagram_size: 1200,
                queue_size: 100,
                flow_control: true,
            },
            security_policy: BrowserSecurityPolicy {
                cors_policy: CorsPolicy {
                    allowed_origins: vec!["*".to_string()],
                    allowed_headers: vec!["*".to_string()],
                    allow_credentials: false,
                    max_age: Duration::from_secs(3600),
                },
                cert_validation: CertValidationPolicy::RequireValid,
                origin_restrictions: Vec::new(),
                feature_permissions: FeaturePermissions {
                    webtransport_enabled: true,
                    datagrams_enabled: true,
                    streams_enabled: true,
                    filesystem_access: false, // Typically limited in browsers
                },
            },
        }
    }
}

impl WebTransportStats {
    fn new() -> Self {
        Self {
            total_sessions: 0,
            active_sessions: 0,
            total_streams: 0,
            total_datagrams_sent: 0,
            total_datagrams_received: 0,
            connection_failures: 0,
            stream_errors: 0,
            avg_session_duration: Duration::from_secs(0),
            last_updated: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_webtransport_config_default() {
        let config = WebTransportConfig::default();
        assert_eq!(config.session_config.max_bidirectional_streams, 100);
        assert_eq!(config.datagram_config.max_datagram_size, 1200);
        assert!(
            config
                .security_policy
                .feature_permissions
                .webtransport_enabled
        );
    }

    #[test]
    fn test_webtransport_session_lifecycle() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            // Start session
            let session_id = adapter
                .start_session(object_id, "https://example.com")
                .await
                .unwrap();
            assert_eq!(adapter.stats.active_sessions, 1);

            // Create stream
            let stream_id = adapter.create_stream(&session_id, 128).await.unwrap();
            assert_eq!(stream_id, 0); // First stream should be ID 0

            // Send frame
            let data = b"ATP frame data";
            adapter
                .send_frame(&session_id, stream_id, data)
                .await
                .unwrap();

            // Send datagram
            let datagram_data = b"ATP datagram";
            adapter
                .send_datagram(&session_id, datagram_data)
                .await
                .unwrap();

            // Close session
            adapter.close_session(&session_id).await.unwrap();
            assert_eq!(adapter.stats.active_sessions, 0);
        });
    }

    #[test]
    fn test_webtransport_negotiation() {
        block_on(async {
            let adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = adapter.negotiate(trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert_eq!(
                negotiation.feature_parity.object_support,
                FeatureSupport::Full
            );
            assert_eq!(
                negotiation.feature_parity.proof_support,
                FeatureSupport::Partial
            );
        });
    }

    #[test]
    fn test_stream_limits() {
        block_on(async {
            let config = WebTransportConfig {
                session_config: WebTransportSessionConfig {
                    max_bidirectional_streams: 1, // Limit to 1 stream
                    max_unidirectional_streams: 1,
                    session_timeout: Duration::from_secs(300),
                    close_timeout: Duration::from_secs(5),
                },
                ..Default::default()
            };

            let mut adapter = WebTransportAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let session_id = adapter
                .start_session(object_id, "https://example.com")
                .await
                .unwrap();

            // First stream should succeed
            adapter.create_stream(&session_id, 128).await.unwrap();

            // Second stream should fail due to limit
            let result = adapter.create_stream(&session_id, 128).await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_stream_frame_and_datagram_queues() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let session_id = adapter
                .start_session(object_id, "https://example.com/atp")
                .await
                .unwrap();
            let stream_id = adapter.create_stream(&session_id, 128).await.unwrap();

            adapter
                .send_frame(&session_id, stream_id, b"stream-frame")
                .await
                .unwrap();
            adapter
                .send_datagram(&session_id, b"datagram")
                .await
                .unwrap();

            let session = adapter.sessions.get(&session_id).unwrap();
            let stream = session.active_streams.get(&stream_id).unwrap();
            assert_eq!(stream.outbound_frames, vec![b"stream-frame".to_vec()]);
            assert_eq!(session.outbound_datagrams, vec![b"datagram".to_vec()]);
        });
    }

    #[test]
    fn test_invalid_webtransport_url_is_rejected() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            let result = adapter.start_session(object_id, "http://example.com").await;

            assert!(matches!(
                result,
                Err(err) if err.kind() == ErrorKind::InvalidInput
            ));
        });
    }
}
