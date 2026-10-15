//! DATAGRAM Transport Parameter Support
//!
//! Implements max_datagram_frame_size transport parameter negotiation
//! and DATAGRAM capability detection.

use crate::net::atp::datagram::frame::DatagramError;
use crate::net::atp::handshake::transport_params::{TransportParamId, TransportParameters};
use crate::types::outcome::Outcome;

/// DATAGRAM transport parameter ID (RFC 9221)
pub const MAX_DATAGRAM_FRAME_SIZE_PARAM_ID: u64 = 0x20;

/// Default maximum DATAGRAM frame size (conservative default)
pub const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

/// Minimum allowed DATAGRAM frame size
pub const MIN_DATAGRAM_SIZE: u64 = 16;

/// Maximum allowed DATAGRAM frame size (to prevent DoS)
pub const MAX_DATAGRAM_SIZE: u64 = 65535;

/// DATAGRAM transport parameter handler
#[derive(Debug, Clone)]
pub struct DatagramTransport {
    /// Local maximum DATAGRAM frame size
    local_max_size: u64,
    /// Peer's maximum DATAGRAM frame size
    peer_max_size: Option<u64>,
    /// Whether DATAGRAM is enabled locally
    local_enabled: bool,
    /// Whether peer supports DATAGRAM
    peer_enabled: bool,
}

impl DatagramTransport {
    /// Create new DATAGRAM transport handler
    pub fn new(local_enabled: bool, local_max_size: u64) -> Outcome<Self, DatagramError> {
        if local_enabled && !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_SIZE).contains(&local_max_size) {
            return Outcome::err(DatagramError::InvalidFrame(format!(
                "invalid max datagram size: {} (must be {}-{})",
                local_max_size, MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE
            )));
        }

        Outcome::ok(Self {
            local_max_size: if local_enabled { local_max_size } else { 0 },
            peer_max_size: None,
            local_enabled,
            peer_enabled: false,
        })
    }

    /// Create disabled DATAGRAM transport
    pub fn disabled() -> Self {
        Self {
            local_max_size: 0,
            peer_max_size: None,
            local_enabled: false,
            peer_enabled: false,
        }
    }

    /// Create default enabled DATAGRAM transport
    pub fn default_enabled() -> Self {
        match Self::new(true, DEFAULT_MAX_DATAGRAM_SIZE) {
            Outcome::Ok(transport) => transport,
            _ => unreachable!("default values are valid"),
        }
    }

    /// Add DATAGRAM transport parameter to local parameters
    pub fn add_to_transport_params(&self, params: &mut TransportParameters) {
        if self.local_enabled {
            params.set_integer(TransportParamId::MaxDatagramFrameSize, self.local_max_size);
        }
    }

    /// Process peer transport parameters for DATAGRAM support
    pub fn process_peer_params(
        &mut self,
        params: &TransportParameters,
    ) -> Outcome<(), DatagramError> {
        let Some(peer_max_size) = params.get_integer(TransportParamId::MaxDatagramFrameSize) else {
            self.peer_enabled = false;
            self.peer_max_size = None;
            return Outcome::ok(());
        };

        if !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_SIZE).contains(&peer_max_size) {
            return Outcome::err(DatagramError::InvalidFrame(format!(
                "invalid peer max datagram size: {} (must be {}-{})",
                peer_max_size, MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE
            )));
        }

        self.peer_enabled = true;
        self.peer_max_size = Some(peer_max_size);
        Outcome::ok(())
    }

    /// Check if DATAGRAM is supported by both peers
    pub fn is_enabled(&self) -> bool {
        self.local_enabled && self.peer_enabled
    }

    /// Get effective maximum DATAGRAM frame size
    pub fn max_frame_size(&self) -> Option<u64> {
        if self.is_enabled() {
            Some(self.local_max_size.min(self.peer_max_size.unwrap_or(0)))
        } else {
            None
        }
    }

    /// Get local maximum frame size
    pub fn local_max_size(&self) -> u64 {
        self.local_max_size
    }

    /// Get peer maximum frame size
    pub fn peer_max_size(&self) -> Option<u64> {
        self.peer_max_size
    }

    /// Validate datagram size against negotiated limits
    pub fn validate_size(&self, size: usize) -> Outcome<(), DatagramError> {
        if !self.is_enabled() {
            return Outcome::err(DatagramError::NotSupported);
        }

        let max_size = self.max_frame_size().unwrap() as usize;
        if size > max_size {
            return Outcome::err(DatagramError::PayloadTooLarge {
                size,
                max: max_size,
            });
        }

        Outcome::ok(())
    }

    /// Check if peer supports DATAGRAM
    pub fn peer_supports_datagram(&self) -> bool {
        self.peer_enabled
    }

    /// Reset peer state (for connection retry)
    pub fn reset_peer_state(&mut self) {
        self.peer_enabled = false;
        self.peer_max_size = None;
    }
}

impl Default for DatagramTransport {
    fn default() -> Self {
        Self::disabled()
    }
}

/// DATAGRAM capability configuration
#[derive(Debug, Clone)]
pub struct DatagramConfig {
    /// Enable DATAGRAM support
    pub enabled: bool,
    /// Maximum DATAGRAM frame size to advertise
    pub max_frame_size: u64,
    /// Whether to require DATAGRAM support from peer
    pub required: bool,
    /// Enable path probes via DATAGRAM
    pub enable_path_probes: bool,
    /// Enable path beacons via DATAGRAM
    pub enable_path_beacons: bool,
    /// Enable telemetry via DATAGRAM
    pub enable_telemetry: bool,
}

impl DatagramConfig {
    /// Create new DATAGRAM configuration
    pub fn new() -> Self {
        Self {
            enabled: false,
            max_frame_size: DEFAULT_MAX_DATAGRAM_SIZE,
            required: false,
            enable_path_probes: false,
            enable_path_beacons: false,
            enable_telemetry: false,
        }
    }

    /// Enable DATAGRAM with default settings
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            max_frame_size: DEFAULT_MAX_DATAGRAM_SIZE,
            required: false,
            enable_path_probes: true,
            enable_path_beacons: true,
            enable_telemetry: true,
        }
    }

    /// Create configuration for path probes only
    pub fn path_probes_only() -> Self {
        Self {
            enabled: true,
            max_frame_size: 64, // Small frames for probes
            required: false,
            enable_path_probes: true,
            enable_path_beacons: false,
            enable_telemetry: false,
        }
    }

    /// Create configuration for beacons only
    pub fn beacons_only() -> Self {
        Self {
            enabled: true,
            max_frame_size: 256, // Medium frames for beacons
            required: false,
            enable_path_probes: false,
            enable_path_beacons: true,
            enable_telemetry: false,
        }
    }

    /// Set maximum frame size
    pub fn with_max_frame_size(mut self, size: u64) -> Self {
        self.max_frame_size = size.clamp(MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE);
        self
    }

    /// Require DATAGRAM support from peer
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Outcome<(), DatagramError> {
        if self.enabled {
            if self.max_frame_size < MIN_DATAGRAM_SIZE || self.max_frame_size > MAX_DATAGRAM_SIZE {
                return Outcome::err(DatagramError::InvalidFrame(format!(
                    "invalid max frame size: {} (must be {}-{})",
                    self.max_frame_size, MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE
                )));
            }
        }

        Outcome::ok(())
    }

    /// Create transport handler from configuration
    pub fn create_transport(&self) -> Outcome<DatagramTransport, DatagramError> {
        match self.validate() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        DatagramTransport::new(self.enabled, self.max_frame_size)
    }
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// DATAGRAM negotiation result
#[derive(Debug, Clone)]
pub struct DatagramNegotiation {
    /// Whether DATAGRAM is enabled after negotiation
    pub enabled: bool,
    /// Negotiated maximum frame size
    pub max_frame_size: Option<u64>,
    /// Local configuration
    pub local_config: DatagramConfig,
    /// Peer capabilities
    pub peer_max_size: Option<u64>,
}

impl DatagramNegotiation {
    /// Create negotiation result
    pub fn new(local_config: DatagramConfig, transport: &DatagramTransport) -> Self {
        Self {
            enabled: transport.is_enabled(),
            max_frame_size: transport.max_frame_size(),
            local_config,
            peer_max_size: transport.peer_max_size(),
        }
    }

    /// Check if negotiation was successful
    pub fn is_successful(&self) -> bool {
        self.enabled || !self.local_config.required
    }

    /// Get effective maximum frame size
    pub fn effective_max_size(&self) -> Option<usize> {
        self.max_frame_size.map(|size| size as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_transport_creation() {
        let transport = DatagramTransport::new(true, 1024).unwrap();
        assert_eq!(transport.local_max_size(), 1024);
        assert!(!transport.is_enabled()); // Peer not configured yet
        assert!(!transport.peer_supports_datagram());

        let disabled = DatagramTransport::disabled();
        assert_eq!(disabled.local_max_size(), 0);
        assert!(!disabled.is_enabled());

        let default_enabled = DatagramTransport::default_enabled();
        assert_eq!(default_enabled.local_max_size(), DEFAULT_MAX_DATAGRAM_SIZE);
    }

    #[test]
    fn test_datagram_transport_validation() {
        // Invalid size - too small
        let result = DatagramTransport::new(true, MIN_DATAGRAM_SIZE - 1);
        assert!(result.is_err());

        // Invalid size - too large
        let result = DatagramTransport::new(true, MAX_DATAGRAM_SIZE + 1);
        assert!(result.is_err());

        // Valid sizes
        assert!(DatagramTransport::new(true, MIN_DATAGRAM_SIZE).is_ok());
        assert!(DatagramTransport::new(true, MAX_DATAGRAM_SIZE).is_ok());
        assert!(DatagramTransport::new(true, DEFAULT_MAX_DATAGRAM_SIZE).is_ok());
    }

    #[test]
    fn test_datagram_config() {
        let config = DatagramConfig::new();
        assert!(!config.enabled);
        config.validate().unwrap();

        let enabled_config = DatagramConfig::enabled();
        assert!(enabled_config.enabled);
        assert!(enabled_config.enable_path_probes);
        assert!(enabled_config.enable_path_beacons);
        assert!(enabled_config.enable_telemetry);

        let probes_only = DatagramConfig::path_probes_only();
        assert!(probes_only.enable_path_probes);
        assert!(!probes_only.enable_path_beacons);
        assert!(!probes_only.enable_telemetry);

        let beacons_only = DatagramConfig::beacons_only();
        assert!(!beacons_only.enable_path_probes);
        assert!(beacons_only.enable_path_beacons);
        assert!(!beacons_only.enable_telemetry);
    }

    #[test]
    fn test_datagram_config_validation() {
        let invalid_config = DatagramConfig::new().with_max_frame_size(MAX_DATAGRAM_SIZE + 1);

        // Validation should clamp the size
        assert_eq!(invalid_config.max_frame_size, MAX_DATAGRAM_SIZE);

        let too_small = DatagramConfig::new().with_max_frame_size(MIN_DATAGRAM_SIZE - 1);

        // Validation should clamp the size
        assert_eq!(too_small.max_frame_size, MIN_DATAGRAM_SIZE);
    }

    #[test]
    fn test_size_validation() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();

        // Not enabled yet (no peer)
        assert!(transport.validate_size(100).is_err());

        // Apply peer negotiation state.
        transport.peer_enabled = true;
        transport.peer_max_size = Some(512);

        // Should use minimum of local and peer
        assert_eq!(transport.max_frame_size(), Some(512));

        // Valid size
        assert!(transport.validate_size(256).is_ok());

        // Too large
        assert!(transport.validate_size(1024).is_err());
    }

    #[test]
    fn test_transport_parameter_negotiation_uses_rfc9221_id() {
        let transport = DatagramTransport::new(true, 1024).unwrap();
        let mut params = TransportParameters::new();

        transport.add_to_transport_params(&mut params);

        assert_eq!(
            params.get_integer(TransportParamId::MaxDatagramFrameSize),
            Some(1024)
        );
        assert!(
            params
                .get_integer(TransportParamId::MaxIdleTimeout)
                .is_none(),
            "DATAGRAM negotiation must not overwrite max_idle_timeout"
        );
    }

    #[test]
    fn test_peer_params_absent_fail_closed() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();
        let params = TransportParameters::new();

        transport.process_peer_params(&params).unwrap();

        assert!(!transport.peer_supports_datagram());
        assert!(!transport.is_enabled());
        assert_eq!(transport.peer_max_size(), None);
    }

    #[test]
    fn test_peer_params_enable_with_valid_rfc9221_value() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxDatagramFrameSize, 512);

        transport.process_peer_params(&params).unwrap();

        assert!(transport.peer_supports_datagram());
        assert!(transport.is_enabled());
        assert_eq!(transport.max_frame_size(), Some(512));
    }

    #[test]
    fn test_datagram_negotiation() {
        let config = DatagramConfig::enabled();
        let transport = DatagramTransport::default_enabled();

        let negotiation = DatagramNegotiation::new(config.clone(), &transport);
        assert!(!negotiation.enabled); // No peer yet

        // With required flag
        let required_config = config.required();
        let required_transport = DatagramTransport::disabled();
        let required_negotiation = DatagramNegotiation::new(required_config, &required_transport);
        assert!(!required_negotiation.is_successful());
    }
}
