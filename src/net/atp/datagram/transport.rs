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
#[path = "transport_inline_tests.rs"]
mod tests;
