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
        self.to_settings_for_role(true)
    }

    /// Convert settings to a list of Setting values for encoding, with role rules.
    ///
    /// Per RFC 7540 §6.5.2, servers MUST NOT send `SETTINGS_ENABLE_PUSH`.
    /// Set `is_client` to `false` when serializing server settings.
    #[must_use]
    pub fn to_settings_for_role(&self, is_client: bool) -> Vec<Setting> {
        let mut settings = Vec::with_capacity(if is_client { 6 } else { 5 });
        settings.push(Setting::HeaderTableSize(self.header_table_size));
        if is_client {
            settings.push(Setting::EnablePush(self.enable_push));
        }
        settings.push(Setting::MaxConcurrentStreams(self.max_concurrent_streams));
        settings.push(Setting::InitialWindowSize(self.initial_window_size));
        settings.push(Setting::MaxFrameSize(self.max_frame_size));
        settings.push(Setting::MaxHeaderListSize(self.max_header_list_size));
        settings
    }

    /// Convert settings to a minimal list (only non-default values).
    #[must_use]
    pub fn to_settings_minimal(&self) -> Vec<Setting> {
        self.to_settings_minimal_for_role(true)
    }

    /// Convert settings to a minimal list (only non-default values), with role rules.
    ///
    /// Per RFC 7540 §6.5.2, servers MUST NOT send `SETTINGS_ENABLE_PUSH`.
    /// Set `is_client` to `false` when serializing server settings.
    #[must_use]
    pub fn to_settings_minimal_for_role(&self, is_client: bool) -> Vec<Setting> {
        let mut settings = Vec::new();

        if self.header_table_size != 4096 {
            settings.push(Setting::HeaderTableSize(self.header_table_size));
        }
        if is_client && !self.enable_push {
            settings.push(Setting::EnablePush(self.enable_push));
        }
        // RFC default is unlimited. Since our default is 256, we should always send it unless it's unlimited (u32::MAX).
        if self.max_concurrent_streams != u32::MAX {
            settings.push(Setting::MaxConcurrentStreams(self.max_concurrent_streams));
        }
        if self.initial_window_size != 65535 {
            settings.push(Setting::InitialWindowSize(self.initial_window_size));
        }
        if self.max_frame_size != 16384 {
            settings.push(Setting::MaxFrameSize(self.max_frame_size));
        }
        // RFC default is unlimited. Since our default is 65536, we should always send it unless it's unlimited (u32::MAX).
        if self.max_header_list_size != u32::MAX {
            settings.push(Setting::MaxHeaderListSize(self.max_header_list_size));
        }

        settings
    }
}

/// Builder for configuring HTTP/2 settings.
#[derive(Debug, Clone, Default)]
pub struct SettingsBuilder {
    settings: Settings,
}

macro_rules! settings_builder_setters {
    ($(
        $(#[$meta:meta])*
        $method:ident($arg:ident: $ty:ty) => $field:ident = $value:expr;
    )*) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $method(mut self, $arg: $ty) -> Self {
                self.settings.$field = $value;
                self
            }
        )*
    };
}

impl SettingsBuilder {
    /// Create a new settings builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    settings_builder_setters! {
        /// Set the header table size.
        header_table_size(size: u32) => header_table_size = size;

        /// Enable or disable server push.
        enable_push(enable: bool) => enable_push = enable;

        /// Set the maximum concurrent streams.
        max_concurrent_streams(max: u32) => max_concurrent_streams = max;

        /// Set the initial window size.
        initial_window_size(size: u32) => initial_window_size = size.min(MAX_INITIAL_WINDOW_SIZE);

        /// Set the maximum frame size.
        max_frame_size(size: u32) => max_frame_size = size.clamp(MIN_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE);

        /// Set the maximum header list size.
        max_header_list_size(size: u32) => max_header_list_size = size;

        /// Set the continuation sequence timeout in milliseconds.
        ///
        /// This controls how long a HEADERS/PUSH_PROMISE CONTINUATION sequence
        /// can remain incomplete before the connection times out.
        continuation_timeout_ms(timeout_ms: u64) => continuation_timeout_ms = timeout_ms;
    }

    /// Build the settings.
    #[must_use]
    pub fn build(self) -> Settings {
        self.settings
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
        assert!(
            settings
                .apply(Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE))
                .is_ok()
        );
        assert!(
            settings
                .apply(Setting::MaxFrameSize(MAX_MAX_FRAME_SIZE))
                .is_ok()
        );
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
    fn settings_builder_clamps_protocol_bounded_fields() {
        let settings = SettingsBuilder::new()
            .initial_window_size(MAX_INITIAL_WINDOW_SIZE + 1)
            .max_frame_size(MIN_MAX_FRAME_SIZE - 1)
            .build();

        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);

        let settings = SettingsBuilder::new()
            .initial_window_size(MAX_INITIAL_WINDOW_SIZE)
            .max_frame_size(MAX_MAX_FRAME_SIZE + 1)
            .build();

        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MAX_MAX_FRAME_SIZE);
    }

    #[test]
    fn test_to_settings_minimal() {
        let settings = SettingsBuilder::new()
            .enable_push(false)
            .max_concurrent_streams(100)
            .build();

        let minimal = settings.to_settings_minimal();
        // EnablePush (false != true), MaxConcurrentStreams (100 != MAX), MaxHeaderListSize (65536 != MAX)
        assert_eq!(minimal.len(), 3);
        assert!(minimal.contains(&Setting::EnablePush(false)));
        assert!(minimal.contains(&Setting::MaxConcurrentStreams(100)));
        assert!(minimal.contains(&Setting::MaxHeaderListSize(DEFAULT_MAX_HEADER_LIST_SIZE)));
    }

    #[test]
    fn to_settings_minimal_omits_rfc_unlimited_settings() {
        let settings = SettingsBuilder::new()
            .max_concurrent_streams(u32::MAX)
            .max_header_list_size(u32::MAX)
            .build();

        let minimal = settings.to_settings_minimal();

        assert!(
            minimal.is_empty(),
            "RFC 7540 defaults are implicit and should not be serialized: {minimal:?}"
        );
    }

    #[test]
    fn test_to_settings_for_server_omits_enable_push() {
        let settings = SettingsBuilder::server().enable_push(false).build();
        let serialized = settings.to_settings_for_role(false);
        assert!(
            !serialized
                .iter()
                .any(|setting| matches!(setting, Setting::EnablePush(_)))
        );
    }

    #[test]
    fn test_to_settings_minimal_for_server_omits_enable_push() {
        let settings = SettingsBuilder::server().enable_push(false).build();
        let minimal = settings.to_settings_minimal_for_role(false);
        assert!(
            !minimal
                .iter()
                .any(|setting| matches!(setting, Setting::EnablePush(_)))
        );
    }

    #[test]
    fn server_settings_serialization_is_invariant_to_enable_push() {
        let disabled = SettingsBuilder::server()
            .enable_push(false)
            .header_table_size(8192)
            .max_concurrent_streams(32)
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .max_header_list_size(16_384)
            .build();
        let mut enabled = disabled.clone();
        enabled.enable_push = true;

        assert_eq!(
            disabled.to_settings_for_role(false),
            enabled.to_settings_for_role(false),
            "server SETTINGS serialization must not depend on enable_push"
        );
        assert_eq!(
            disabled.to_settings_minimal_for_role(false),
            enabled.to_settings_minimal_for_role(false),
            "minimal server SETTINGS serialization must not depend on enable_push"
        );
        assert_ne!(
            disabled.to_settings_for_role(true),
            enabled.to_settings_for_role(true),
            "client serialization still carries enable_push differences"
        );
    }

    #[test]
    fn repeated_settings_apply_with_last_value_wins() {
        let mut settings = Settings::default();
        let sequence = [
            Setting::HeaderTableSize(8192),
            Setting::HeaderTableSize(16_384),
            Setting::EnablePush(false),
            Setting::EnablePush(true),
            Setting::MaxConcurrentStreams(64),
            Setting::MaxConcurrentStreams(128),
            Setting::InitialWindowSize(32_768),
            Setting::InitialWindowSize(MAX_INITIAL_WINDOW_SIZE),
            Setting::MaxFrameSize(32_768),
            Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE),
            Setting::MaxHeaderListSize(16_384),
            Setting::MaxHeaderListSize(32_768),
        ];

        for setting in sequence {
            settings.apply(setting).expect("valid setting applies");
        }

        assert_eq!(settings.header_table_size, 16_384);
        assert!(settings.enable_push);
        assert_eq!(settings.max_concurrent_streams, 128);
        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);
        assert_eq!(settings.max_header_list_size, 32_768);
    }

    #[test]
    fn client_settings_full_serialization_reconstructs_state() {
        let original = SettingsBuilder::client()
            .header_table_size(8192)
            .enable_push(false)
            .max_concurrent_streams(64)
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .max_header_list_size(16_384)
            .continuation_timeout_ms(1234)
            .build();

        let mut reconstructed = Settings::default();
        for setting in original.to_settings_for_role(true) {
            reconstructed
                .apply(setting)
                .expect("serialized client setting must be valid");
        }
        reconstructed.continuation_timeout_ms = original.continuation_timeout_ms;

        assert_eq!(reconstructed, original);
    }

    #[test]
    fn invalid_peer_settings_do_not_mutate_existing_state() {
        let mut settings = SettingsBuilder::new()
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .build();
        let before = settings.clone();

        let err = settings
            .apply(Setting::InitialWindowSize(MAX_INITIAL_WINDOW_SIZE + 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
        assert_eq!(settings, before);

        let err = settings
            .apply(Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE - 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(settings, before);

        let err = settings
            .apply(Setting::MaxFrameSize(MAX_MAX_FRAME_SIZE + 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(settings, before);
    }

    // --- wave 77 trait coverage ---

    #[test]
    fn settings_debug_clone_eq_default() {
        let s = Settings::default();
        let s2 = s.clone();
        assert_eq!(s, s2);
        let modified = Settings {
            max_frame_size: 32768,
            ..Settings::default()
        };
        assert_ne!(s, modified);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Settings"));
    }

    #[test]
    fn settings_builder_debug_clone() {
        let b = SettingsBuilder::new();
        let b2 = b.clone();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("SettingsBuilder"));
        assert_eq!(b.build(), b2.build());
    }
}
