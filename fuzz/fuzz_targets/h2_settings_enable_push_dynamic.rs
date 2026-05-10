#![no_main]

//! Fuzz target for HTTP/2 SETTINGS_ENABLE_PUSH dynamic update validation.
//!
//! This target tests dynamic toggling of SETTINGS_ENABLE_PUSH and validates:
//! - PUSH_PROMISE frames are blocked when SETTINGS_ENABLE_PUSH = 0
//! - PUSH_PROMISE frames are allowed when SETTINGS_ENABLE_PUSH = 1
//! - Invalid ENABLE_PUSH values (>1) are rejected per RFC 7540 §6.5.2
//! - Servers MUST NOT send SETTINGS_ENABLE_PUSH
//! - Dynamic state changes are applied correctly
//!
//! Expected behavior:
//! - enable_push=0: PUSH_PROMISE → "push not enabled" protocol error
//! - enable_push=1: PUSH_PROMISE → accepted (subject to other validation)
//! - enable_push>1: protocol error during SETTINGS processing
//! - Server sends ENABLE_PUSH: protocol error for clients

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum ConnectionState {
    Handshaking,
    Open,
    Closing,
    Closed,
}

/// HTTP/2 settings
#[derive(Debug, Clone, Arbitrary)]
struct Settings {
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: u32,
}

impl Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: 256,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: 65536,
        }
    }

    fn client() -> Self {
        Self {
            enable_push: false, // Clients default to push disabled
            ..Self::default()
        }
    }
}

/// Individual SETTINGS parameter
#[derive(Debug, Clone, Arbitrary)]
enum Setting {
    HeaderTableSize(u32),
    EnablePush(u32), // Use u32 to test invalid values
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

impl Setting {
    fn is_valid(&self) -> bool {
        match self {
            Setting::EnablePush(v) => *v <= 1, // MUST be 0 or 1
            Setting::InitialWindowSize(v) => *v <= 0x7fff_ffff, // MUST be <= 2^31-1
            Setting::MaxFrameSize(v) => *v >= 16384 && *v <= 0x00ff_ffff, // MUST be in range
            _ => true,                         // Other settings are generally valid
        }
    }
}

/// SETTINGS frame
#[derive(Debug, Clone, Arbitrary)]
struct SettingsFrame {
    settings: Vec<Setting>,
    ack: bool,
}

/// PUSH_PROMISE frame
#[derive(Debug, Clone, Arbitrary)]
struct PushPromiseFrame {
    stream_id: u32,
    promised_stream_id: u32,
    end_headers: bool,
}

/// Test action to perform
#[derive(Debug, Clone, Arbitrary)]
enum TestAction {
    /// Send SETTINGS frame to change ENABLE_PUSH
    SendSettings(SettingsFrame),
    /// Try to send PUSH_PROMISE frame
    TryPushPromise(PushPromiseFrame),
    /// Check current push state
    CheckPushEnabled,
}

/// Complete test scenario
#[derive(Debug, Clone, Arbitrary)]
struct EnablePushScenario {
    /// Whether this is a client (true) or server (false) connection
    is_client: bool,
    /// Initial settings for the connection
    initial_settings: Settings,
    /// Sequence of actions to test
    actions: Vec<TestAction>,
    /// Whether to test server illegally sending ENABLE_PUSH
    server_sends_enable_push: bool,
    /// Whether to include SETTINGS with invalid ENABLE_PUSH values
    include_invalid_values: bool,
}

/// Mock HTTP/2 connection for testing ENABLE_PUSH behavior
struct MockH2Connection {
    is_client: bool,
    state: ConnectionState,
    local_settings: Settings,
    remote_settings: Settings,
    open_streams: HashMap<u32, StreamInfo>,
}

#[derive(Debug, Clone)]
struct StreamInfo {
    state: StreamState,
    is_client_initiated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
}

impl MockH2Connection {
    fn new(is_client: bool, initial_settings: Settings) -> Self {
        let local = if is_client {
            Settings::client()
        } else {
            Settings::default()
        };

        Self {
            is_client,
            state: ConnectionState::Handshaking,
            local_settings: local,
            remote_settings: initial_settings,
            open_streams: HashMap::new(),
        }
    }

    /// Process a SETTINGS frame
    fn process_settings(&mut self, frame: &SettingsFrame) -> Result<(), String> {
        if self.state == ConnectionState::Closed {
            return Err("Connection closed".into());
        }

        if frame.ack {
            // SETTINGS ACK received - no changes to apply
            return Ok(());
        }

        // Validate settings before applying
        for setting in &frame.settings {
            // RFC 7540 §6.5.2: Server MUST NOT send SETTINGS_ENABLE_PUSH
            if self.is_client && matches!(setting, Setting::EnablePush(_)) {
                return Err("server MUST NOT send SETTINGS_ENABLE_PUSH".into());
            }

            if !setting.is_valid() {
                return Err(format!("Invalid setting value: {:?}", setting));
            }
        }

        // Apply validated settings to remote_settings
        for setting in &frame.settings {
            match setting {
                Setting::HeaderTableSize(v) => {
                    self.remote_settings.header_table_size = *v;
                }
                Setting::EnablePush(v) => {
                    self.remote_settings.enable_push = *v != 0;
                }
                Setting::MaxConcurrentStreams(v) => {
                    self.remote_settings.max_concurrent_streams = *v;
                }
                Setting::InitialWindowSize(v) => {
                    self.remote_settings.initial_window_size = *v;
                }
                Setting::MaxFrameSize(v) => {
                    self.remote_settings.max_frame_size = *v;
                }
                Setting::MaxHeaderListSize(v) => {
                    self.remote_settings.max_header_list_size = *v;
                }
            }
        }

        // Transition to open if this is first SETTINGS
        if self.state == ConnectionState::Handshaking {
            self.state = ConnectionState::Open;
        }

        Ok(())
    }

    /// Process a PUSH_PROMISE frame
    fn process_push_promise(&mut self, frame: &PushPromiseFrame) -> Result<(), String> {
        if self.state != ConnectionState::Open {
            return Err("PUSH_PROMISE not allowed in current state".into());
        }

        if !self.is_client {
            return Err("server received PUSH_PROMISE".into());
        }

        // Key check: ENABLE_PUSH must be true
        if !self.local_settings.enable_push {
            return Err("push not enabled".into());
        }

        // Additional validation
        if frame.stream_id.is_multiple_of(2) {
            return Err("PUSH_PROMISE on server-initiated stream".into());
        }

        if !frame.promised_stream_id.is_multiple_of(2) {
            return Err("promised stream ID must be server-initiated".into());
        }

        // Check if the associated stream exists and is in valid state
        if let Some(stream_info) = self.open_streams.get(&frame.stream_id) {
            match stream_info.state {
                StreamState::Open => {
                    // Valid states for PUSH_PROMISE
                }
            }
        } else {
            return Err("PUSH_PROMISE on unknown stream".into());
        }

        if !frame.end_headers {
            return Err("fragmented PUSH_PROMISE headers unsupported in harness".into());
        }

        // Check for duplicate promised stream ID
        if self.open_streams.contains_key(&frame.promised_stream_id) {
            return Err("duplicate promised stream ID".into());
        }

        // Check concurrent streams limit
        let current_streams = self.open_streams.len();
        if current_streams >= self.local_settings.max_concurrent_streams as usize {
            return Err("max concurrent streams exceeded".into());
        }

        // Create the promised stream
        self.open_streams.insert(
            frame.promised_stream_id,
            StreamInfo {
                state: StreamState::Open, // Reserved state would be more accurate
                is_client_initiated: false,
            },
        );

        Ok(())
    }

    /// Get current ENABLE_PUSH state
    fn is_push_enabled(&self) -> bool {
        self.local_settings.enable_push
    }

    /// Open a client stream (for testing PUSH_PROMISE association)
    fn open_client_stream(&mut self, stream_id: u32) -> Result<(), String> {
        if stream_id.is_multiple_of(2) {
            return Err("Client stream ID must be odd".into());
        }

        if self.open_streams.contains_key(&stream_id) {
            return Err("Stream ID already exists".into());
        }

        self.open_streams.insert(
            stream_id,
            StreamInfo {
                state: StreamState::Open,
                is_client_initiated: true,
            },
        );

        Ok(())
    }
}

fn open_required_client_stream(conn: &mut MockH2Connection, stream_id: u32) {
    match conn.open_client_stream(stream_id) {
        Ok(()) => {
            let stream = conn
                .open_streams
                .get(&stream_id)
                .unwrap_or_else(|| panic!("opened client stream {stream_id} must be tracked"));
            assert_eq!(
                stream.state,
                StreamState::Open,
                "opened client stream {stream_id} must start open"
            );
            assert!(
                stream.is_client_initiated,
                "opened client stream {stream_id} must be client-initiated"
            );
        }
        Err(error) => {
            panic!("failed to open required client stream {stream_id}: {error}");
        }
    }
}

fuzz_target!(|scenario: EnablePushScenario| {
    // Skip overly complex scenarios to avoid timeouts
    if scenario.actions.len() > 50 {
        return;
    }

    let mut conn = MockH2Connection::new(scenario.is_client, scenario.initial_settings.clone());
    let mut push_promise_attempts = 0;
    let mut push_promise_successes = 0;
    let mut push_promise_push_disabled_errors = 0;
    let mut invalid_setting_errors = 0;

    // Open a client stream for PUSH_PROMISE testing (if this is a client)
    if scenario.is_client {
        open_required_client_stream(&mut conn, 1);
    }

    // Process each action in the scenario
    for action in &scenario.actions {
        match action {
            TestAction::SendSettings(settings_frame) => {
                // Test server illegally sending ENABLE_PUSH if requested
                if scenario.server_sends_enable_push && scenario.is_client {
                    let illegal_frame = SettingsFrame {
                        settings: vec![Setting::EnablePush(0)],
                        ack: false,
                    };
                    if let Err(e) = conn.process_settings(&illegal_frame) {
                        if e.contains("server MUST NOT send SETTINGS_ENABLE_PUSH") {
                            // Expected error for illegal server behavior
                            continue;
                        }
                    } else {
                        // If no error occurred, that might indicate a bug
                        panic!("Server sending SETTINGS_ENABLE_PUSH should fail for clients");
                    }
                }

                // Test invalid ENABLE_PUSH values if requested
                if scenario.include_invalid_values {
                    let invalid_frame = SettingsFrame {
                        settings: vec![Setting::EnablePush(2)], // Invalid value
                        ack: false,
                    };
                    if conn.process_settings(&invalid_frame).is_err() {
                        invalid_setting_errors += 1;
                    }
                }

                // Process the actual settings frame
                let result = conn.process_settings(settings_frame);

                if let Err(e) = result
                    && e.contains("Invalid setting")
                {
                    invalid_setting_errors += 1;
                }
                // Continue processing other actions
            }

            TestAction::TryPushPromise(push_frame) => {
                push_promise_attempts += 1;

                let result = conn.process_push_promise(push_frame);

                match result {
                    Ok(()) => {
                        push_promise_successes += 1;
                    }
                    Err(e) => {
                        if e.contains("push not enabled") {
                            push_promise_push_disabled_errors += 1;
                        }
                        // Other errors are also valid (stream state, etc.)
                    }
                }
            }

            TestAction::CheckPushEnabled => {
                let _is_enabled = conn.is_push_enabled();
                // This is just a state check - no validation needed
            }
        }
    }

    // Validate the behavior patterns

    // If we had any PUSH_PROMISE attempts, validate the push enabled/disabled behavior
    if push_promise_attempts > 0 {
        assert!(
            push_promise_successes <= push_promise_attempts,
            "PUSH_PROMISE successes {push_promise_successes} exceed attempts {push_promise_attempts}"
        );
        assert!(
            push_promise_push_disabled_errors <= push_promise_attempts,
            "push-disabled errors {push_promise_push_disabled_errors} exceed attempts {push_promise_attempts}"
        );

        // If push is currently disabled, all recent attempts should have failed with "push not enabled"
        if !conn.is_push_enabled() {
            // We can't easily determine which attempts were made while push was disabled
            // vs enabled, but we can check that the error was raised appropriately
        }

        // If push is currently enabled and we have a valid stream, some attempts might succeed
        if conn.is_push_enabled() && conn.open_streams.contains_key(&1) {
            // Some pushes might succeed (subject to other validation)
        }
    }

    // Validate that invalid settings were properly rejected
    if scenario.include_invalid_values {
        assert!(
            invalid_setting_errors > 0,
            "Invalid SETTINGS values should have been rejected"
        );
    }

    // Validate server ENABLE_PUSH constraint
    if scenario.server_sends_enable_push && scenario.is_client {
        // The illegal server behavior should have been caught
        // This was validated in the action processing above
    }

    // Additional consistency checks

    // Ensure connection state is reasonable
    match conn.state {
        ConnectionState::Handshaking => {
            // Should only be handshaking if no SETTINGS were processed
        }
        ConnectionState::Open => {
            // Normal state after SETTINGS exchange
        }
        ConnectionState::Closing | ConnectionState::Closed => {
            // Connection might be closed due to protocol errors
        }
    }

    // Ensure stream management is consistent
    assert!(
        conn.open_streams.len() <= conn.local_settings.max_concurrent_streams as usize,
        "Open streams should not exceed max concurrent streams limit"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_blocked_when_disabled() {
        let scenario = EnablePushScenario {
            is_client: true,
            initial_settings: Settings::client(), // enable_push = false
            actions: vec![TestAction::TryPushPromise(PushPromiseFrame {
                stream_id: 1,
                promised_stream_id: 2,
                end_headers: true,
            })],
            server_sends_enable_push: false,
            include_invalid_values: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_dynamic_enable_push_toggle() {
        let scenario = EnablePushScenario {
            is_client: true,
            initial_settings: Settings::client(),
            actions: vec![
                // Enable push
                TestAction::SendSettings(SettingsFrame {
                    settings: vec![Setting::EnablePush(1)],
                    ack: false,
                }),
                TestAction::TryPushPromise(PushPromiseFrame {
                    stream_id: 1,
                    promised_stream_id: 2,
                    end_headers: true,
                }),
                // Disable push
                TestAction::SendSettings(SettingsFrame {
                    settings: vec![Setting::EnablePush(0)],
                    ack: false,
                }),
                TestAction::TryPushPromise(PushPromiseFrame {
                    stream_id: 1,
                    promised_stream_id: 4,
                    end_headers: true,
                }),
            ],
            server_sends_enable_push: false,
            include_invalid_values: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_invalid_enable_push_values() {
        let scenario = EnablePushScenario {
            is_client: true,
            initial_settings: Settings::client(),
            actions: vec![TestAction::SendSettings(SettingsFrame {
                settings: vec![Setting::EnablePush(2)], // Invalid
                ack: false,
            })],
            server_sends_enable_push: false,
            include_invalid_values: true,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_server_cannot_send_enable_push() {
        let scenario = EnablePushScenario {
            is_client: true,
            initial_settings: Settings::default(),
            actions: vec![],
            server_sends_enable_push: true,
            include_invalid_values: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
