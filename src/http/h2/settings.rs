//! HTTP/2 connection settings.
//!
//! Manages HTTP/2 settings as defined in RFC 7540 Section 6.5.

use super::error::{ErrorCode, H2Error};
use super::frame::Setting;

/// Default header table size (4 KB).
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

/// Default enable push (true for servers, false for clients).
pub const DEFAULT_ENABLE_PUSH: bool = true;

/// Default max concurrent streams (256).
///
/// A reasonable default that balances concurrency with resource protection.
/// Servers should configure this based on their capacity requirements.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Default initial window size (64 KB - 1).
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

/// Default max frame size (16 KB).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// Default max header list size (64 KB).
///
/// Protects against memory exhaustion attacks via oversized headers.
/// Most legitimate requests have headers well under this limit.
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 65536;

/// Default continuation timeout (5 seconds).
///
/// Maximum time allowed for a CONTINUATION frame sequence to complete.
/// Protects against DoS attacks where a peer sends HEADERS without END_HEADERS
/// and never sends the CONTINUATION frames.
pub const DEFAULT_CONTINUATION_TIMEOUT_MS: u64 = 5000;

/// Maximum allowed initial window size.
pub const MAX_INITIAL_WINDOW_SIZE: u32 = 0x7fff_ffff;

/// Maximum allowed frame size.
pub const MAX_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;

/// Minimum allowed frame size.
pub const MIN_MAX_FRAME_SIZE: u32 = 16384;

/// HTTP/2 connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Maximum size of the header compression table.
    pub header_table_size: u32,
    /// Whether server push is enabled.
    pub enable_push: bool,
    /// Maximum number of concurrent streams.
    pub max_concurrent_streams: u32,
    /// Initial window size for stream-level flow control.
    pub initial_window_size: u32,
    /// Maximum frame payload size.
    pub max_frame_size: u32,
    /// Maximum size of header list.
    pub max_header_list_size: u32,
    /// Continuation sequence timeout in milliseconds.
    ///
    /// Maximum time allowed for a HEADERS/PUSH_PROMISE CONTINUATION sequence
    /// to complete. If the peer doesn't send END_HEADERS within this time,
    /// the connection returns a protocol error.
    ///
    /// This protects against DoS attacks where a malicious peer sends a
    /// HEADERS frame without END_HEADERS and never sends CONTINUATION.
    pub continuation_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: DEFAULT_ENABLE_PUSH,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            continuation_timeout_ms: DEFAULT_CONTINUATION_TIMEOUT_MS,
        }
    }
}

impl Settings {
    /// Create new default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create client-side default settings (push disabled).
    #[must_use]
    pub fn client() -> Self {
        Self {
            enable_push: false,
            ..Self::default()
        }
    }

    /// Create server-side default settings.
    #[must_use]
    pub fn server() -> Self {
        Self::default()
    }

    /// Apply a setting value.
    ///
    /// Returns an error if the value is invalid per RFC 7540 Section 6.5.2:
    /// - `SETTINGS_INITIAL_WINDOW_SIZE` above 2^31-1: FLOW_CONTROL_ERROR
    /// - `SETTINGS_MAX_FRAME_SIZE` outside 16384..16777215: PROTOCOL_ERROR
    pub fn apply(&mut self, setting: Setting) -> Result<(), H2Error> {
        match setting {
            Setting::HeaderTableSize(v) => {
                self.header_table_size = v;
                Ok(())
            }
            Setting::EnablePush(v) => {
                self.enable_push = v;
                Ok(())
            }
            Setting::MaxConcurrentStreams(v) => {
                self.max_concurrent_streams = v;
                Ok(())
            }
            Setting::InitialWindowSize(v) => {
                if v > MAX_INITIAL_WINDOW_SIZE {
                    // RFC 7540 Section 6.5.2: Values above 2^31-1 MUST be treated
                    // as a connection error of type FLOW_CONTROL_ERROR
                    Err(H2Error::connection(
                        ErrorCode::FlowControlError,
                        "initial window size exceeds maximum (2^31-1)",
                    ))
                } else {
                    self.initial_window_size = v;
                    Ok(())
                }
            }
            Setting::MaxFrameSize(v) => {
                if (MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&v) {
                    self.max_frame_size = v;
                    Ok(())
                } else {
                    // RFC 7540 Section 6.5.2: Values outside 16384..16777215
                    // MUST be treated as a connection error of type PROTOCOL_ERROR
                    Err(H2Error::protocol("max frame size out of valid range"))
                }
            }
            Setting::MaxHeaderListSize(v) => {
                self.max_header_list_size = v;
                Ok(())
            }
        }
    }

    /// Convert settings to a list of Setting values for encoding.
    #[must_use]
    pub fn to_settings(&self) -> Vec<Setting> {
        vec![
            Setting::HeaderTableSize(self.header_table_size),
            Setting::EnablePush(self.enable_push),
            Setting::MaxConcurrentStreams(self.max_concurrent_streams),
            Setting::InitialWindowSize(self.initial_window_size),
            Setting::MaxFrameSize(self.max_frame_size),
            Setting::MaxHeaderListSize(self.max_header_list_size),
        ]
    }

    /// Convert settings to a minimal list (only non-default values).
    #[must_use]
    pub fn to_settings_minimal(&self) -> Vec<Setting> {
        let default = Self::default();
        let mut settings = Vec::new();

        if self.header_table_size != default.header_table_size {
            settings.push(Setting::HeaderTableSize(self.header_table_size));
        }
        if self.enable_push != default.enable_push {
            settings.push(Setting::EnablePush(self.enable_push));
        }
        if self.max_concurrent_streams != default.max_concurrent_streams {
            settings.push(Setting::MaxConcurrentStreams(self.max_concurrent_streams));
        }
        if self.initial_window_size != default.initial_window_size {
            settings.push(Setting::InitialWindowSize(self.initial_window_size));
        }
        if self.max_frame_size != default.max_frame_size {
            settings.push(Setting::MaxFrameSize(self.max_frame_size));
        }
        if self.max_header_list_size != default.max_header_list_size {
            settings.push(Setting::MaxHeaderListSize(self.max_header_list_size));
        }

        settings
    }
}

/// Builder for configuring HTTP/2 settings.
#[derive(Debug, Clone)]
pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    /// Create a new settings builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings::default(),
        }
    }

    /// Create a builder for client settings.
    #[must_use]
    pub fn client() -> Self {
        Self {
            settings: Settings::client(),
        }
    }

    /// Create a builder for server settings.
    #[must_use]
    pub fn server() -> Self {
        Self {
            settings: Settings::server(),
        }
    }

    /// Set the header table size.
    #[must_use]
    pub fn header_table_size(mut self, size: u32) -> Self {
        self.settings.header_table_size = size;
        self
    }

    /// Enable or disable server push.
    #[must_use]
    pub fn enable_push(mut self, enable: bool) -> Self {
        self.settings.enable_push = enable;
        self
    }

    /// Set the maximum concurrent streams.
    #[must_use]
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.settings.max_concurrent_streams = max;
        self
    }

    /// Set the initial window size.
    #[must_use]
    pub fn initial_window_size(mut self, size: u32) -> Self {
        self.settings.initial_window_size = size.min(MAX_INITIAL_WINDOW_SIZE);
        self
    }

    /// Set the maximum frame size.
    #[must_use]
    pub fn max_frame_size(mut self, size: u32) -> Self {
        self.settings.max_frame_size = size.clamp(MIN_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE);
        self
    }

    /// Set the maximum header list size.
    #[must_use]
    pub fn max_header_list_size(mut self, size: u32) -> Self {
        self.settings.max_header_list_size = size;
        self
    }

    /// Set the continuation sequence timeout in milliseconds.
    ///
    /// This controls how long a HEADERS/PUSH_PROMISE CONTINUATION sequence
    /// can remain incomplete before the connection times out.
    #[must_use]
    pub fn continuation_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.settings.continuation_timeout_ms = timeout_ms;
        self
    }

    /// Build the settings.
    #[must_use]
    pub fn build(self) -> Settings {
        self.settings
    }
}

impl Default for SettingsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert_eq!(settings.header_table_size, 4096);
        assert!(settings.enable_push);
        assert_eq!(
            settings.max_concurrent_streams,
            DEFAULT_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(settings.initial_window_size, 65535);
        assert_eq!(settings.max_frame_size, 16384);
        assert_eq!(settings.max_header_list_size, DEFAULT_MAX_HEADER_LIST_SIZE);
    }

    #[test]
    fn test_client_settings() {
        let settings = Settings::client();
        assert!(!settings.enable_push);
    }

    #[test]
    fn test_apply_valid_settings() {
        let mut settings = Settings::default();
        assert!(settings.apply(Setting::InitialWindowSize(32768)).is_ok());
        assert_eq!(settings.initial_window_size, 32768);
    }

    #[test]
    fn test_apply_invalid_initial_window_size() {
        let mut settings = Settings::default();
        // Value too large
        let err = settings
            .apply(Setting::InitialWindowSize(0x8000_0000))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn test_apply_invalid_max_frame_size() {
        let mut settings = Settings::default();
        // Value too small
        let err = settings.apply(Setting::MaxFrameSize(1000)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        // Value too large
        let err = settings
            .apply(Setting::MaxFrameSize(0x0100_0000))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_apply_max_frame_size_bounds() {
        let mut settings = Settings::default();
        assert!(settings
            .apply(Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE))
            .is_ok());
        assert!(settings
            .apply(Setting::MaxFrameSize(MAX_MAX_FRAME_SIZE))
            .is_ok());
    }

    #[test]
    fn test_settings_builder() {
        let settings = SettingsBuilder::new()
            .header_table_size(8192)
            .enable_push(false)
            .max_concurrent_streams(100)
            .initial_window_size(131_072)
            .max_frame_size(32768)
            .continuation_timeout_ms(2500)
            .build();

        assert_eq!(settings.header_table_size, 8192);
        assert!(!settings.enable_push);
        assert_eq!(settings.max_concurrent_streams, 100);
        assert_eq!(settings.initial_window_size, 131_072);
        assert_eq!(settings.max_frame_size, 32768);
        assert_eq!(settings.continuation_timeout_ms, 2500);
    }

    #[test]
    fn test_to_settings_minimal() {
        let settings = SettingsBuilder::new()
            .enable_push(false)
            .max_concurrent_streams(100)
            .build();

        let minimal = settings.to_settings_minimal();
        assert_eq!(minimal.len(), 2);
    }
}
