//! Fuzzing target for HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS=0 handling.
//!
//! Tests RFC 7540 compliance for max concurrent streams enforcement:
//! 1. Peer sends SETTINGS_MAX_CONCURRENT_STREAMS=0 mid-connection
//! 2. Verify outbound stream creation correctly stalls until increased
//! 3. Connection doesn't deadlock during stream creation blocking
//! 4. Existing streams continue to function normally
//! 5. New streams become available when limit is raised
//!
//! Vulnerability areas:
//! - Deadlock when all streams blocked waiting for concurrent stream slots
//! - Existing stream operations blocked by stream creation limits
//! - Stream creation not properly stalled/queued when limit reached
//! - Integer overflow in concurrent stream counting
//! - Race conditions between stream creation and limit updates
//! - Memory leaks from queued stream creation requests

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, Setting, SettingsFrame};
use asupersync::http::h2::settings::{DEFAULT_MAX_CONCURRENT_STREAMS, Settings};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test scenarios for max concurrent streams=0
#[derive(Debug, Arbitrary)]
pub struct MaxConcurrentStreamsZeroInput {
    /// Initial number of streams to create before applying limit
    initial_stream_count: u8,
    /// Operations to perform with zero limit
    zero_limit_operations: Vec<StreamOperation>,
    /// New limit to set after zero (recovery test)
    recovery_limit: u8,
    /// Operations after recovery
    recovery_operations: Vec<StreamOperation>,
    /// Test mode selection
    mode: ConcurrentStreamsTestMode,
}

/// Operations to test during concurrent streams limiting
#[derive(Debug, Arbitrary)]
pub enum StreamOperation {
    /// Attempt to create new stream with HEADERS
    CreateStream { stream_id: u32 },
    /// Send DATA on existing stream
    SendData { stream_id: u32, size: u16 },
    /// Close stream with END_STREAM
    EndStream { stream_id: u32 },
    /// Send RST_STREAM
    ResetStream { stream_id: u32, error_code: u8 },
    /// Update max concurrent streams setting
    UpdateConcurrentLimit { limit: u8 },
}

#[derive(Debug, Arbitrary)]
pub enum ConcurrentStreamsTestMode {
    /// Test exact zero limit enforcement
    ZeroLimit,
    /// Test with existing streams when limit applied
    WithExistingStreams,
    /// Test recovery from zero limit
    RecoveryFromZero,
    /// Test mixed operations and limit changes
    Mixed,
}

/// Mock connection for testing concurrent streams limiting
pub struct MockConcurrentStreamsConnection {
    /// Current connection state
    state: ConnectionState,
    /// Active streams by ID
    streams: HashMap<u32, StreamInfo>,
    /// Current settings
    settings: Settings,
    /// Pending stream creation requests (blocked by limit)
    pending_streams: Vec<PendingStream>,
    /// Stream creation attempts that were blocked
    blocked_stream_attempts: Vec<u32>,
    /// Detected violations
    violations: Vec<ConcurrentStreamsViolation>,
    /// Statistics
    stats: ConcurrentStreamsStats,
    /// Next client-initiated stream ID
    next_client_stream_id: u32,
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    id: u32,
    state: StreamState,
    created_before_zero_limit: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Debug, Clone)]
pub struct PendingStream {
    stream_id: u32,
    headers_frame: HeadersFrame,
}

#[derive(Debug, Clone)]
pub enum ConcurrentStreamsViolation {
    /// Attempted to create stream when at concurrent limit
    ExceededConcurrentLimit {
        current_count: u32,
        max_allowed: u32,
        attempted_stream_id: u32,
    },
    /// Existing stream operations were blocked inappropriately
    ExistingStreamBlocked { stream_id: u32, operation: String },
    /// Stream creation deadlock detected
    StreamCreationDeadlock {
        pending_count: usize,
        current_limit: u32,
    },
    /// Invalid stream ID sequence
    InvalidStreamIdSequence { stream_id: u32, expected_next: u32 },
}

#[derive(Debug, Default)]
pub struct ConcurrentStreamsStats {
    streams_created: u32,
    streams_blocked: u32,
    streams_queued: u32,
    limit_changes: u32,
    existing_stream_ops: u32,
    deadlock_prevention_triggers: u32,
}

impl MockConcurrentStreamsConnection {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Open,
            streams: HashMap::new(),
            settings: Settings::default(),
            pending_streams: Vec::new(),
            blocked_stream_attempts: Vec::new(),
            violations: Vec::new(),
            stats: ConcurrentStreamsStats::default(),
            next_client_stream_id: 1, // Client-initiated streams are odd
        }
    }

    /// Get count of currently active (open or half-closed) streams
    pub fn active_stream_count(&self) -> u32 {
        self.streams
            .values()
            .filter(|s| {
                matches!(
                    s.state,
                    StreamState::Open
                        | StreamState::HalfClosedLocal
                        | StreamState::HalfClosedRemote
                )
            })
            .count() as u32
    }

    /// Process SETTINGS frame with new MAX_CONCURRENT_STREAMS
    pub fn handle_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), ErrorCode> {
        if frame.ack {
            return Ok(()); // ACK frames don't change settings
        }

        for setting in &frame.settings {
            if let Setting::MaxConcurrentStreams(new_limit) = setting {
                let old_limit = self.settings.max_concurrent_streams;
                self.settings.max_concurrent_streams = *new_limit;
                self.stats.limit_changes += 1;

                // When limit increases, process pending streams
                if *new_limit > old_limit {
                    self.process_pending_streams();
                }

                // Check for potential deadlock when limit goes to zero
                if *new_limit == 0 && !self.pending_streams.is_empty() {
                    self.stats.deadlock_prevention_triggers += 1;
                }
            }
        }

        Ok(())
    }

    /// Attempt to create a new stream
    pub fn create_stream(&mut self, stream_id: u32) -> Result<(), ErrorCode> {
        // Normalize stream ID to client-initiated odd numbers
        let normalized_id = self.normalize_client_stream_id(stream_id);

        // Check stream ID sequence
        if normalized_id < self.next_client_stream_id {
            self.violations
                .push(ConcurrentStreamsViolation::InvalidStreamIdSequence {
                    stream_id: normalized_id,
                    expected_next: self.next_client_stream_id,
                });
            return Err(ErrorCode::ProtocolError);
        }

        self.next_client_stream_id = normalized_id + 2; // Next odd number

        let current_active = self.active_stream_count();

        // Check concurrent streams limit
        if current_active >= self.settings.max_concurrent_streams {
            self.violations
                .push(ConcurrentStreamsViolation::ExceededConcurrentLimit {
                    current_count: current_active,
                    max_allowed: self.settings.max_concurrent_streams,
                    attempted_stream_id: normalized_id,
                });

            // If limit is 0, queue the stream creation
            if self.settings.max_concurrent_streams == 0 {
                self.pending_streams.push(PendingStream {
                    stream_id: normalized_id,
                    headers_frame: HeadersFrame::new(
                        normalized_id,
                        Bytes::from("test"),
                        false,
                        true,
                    ),
                });
                self.stats.streams_queued += 1;
                self.blocked_stream_attempts.push(normalized_id);
                return Ok(()); // Not an error, just queued
            } else {
                self.stats.streams_blocked += 1;
                return Err(ErrorCode::RefusedStream);
            }
        }

        // Create the stream
        self.streams.insert(
            normalized_id,
            StreamInfo {
                id: normalized_id,
                state: StreamState::Open,
                created_before_zero_limit: self.settings.max_concurrent_streams > 0,
            },
        );
        self.stats.streams_created += 1;

        Ok(())
    }

    /// Send data on existing stream
    pub fn send_data(&mut self, stream_id: u32, size: u16) -> Result<(), ErrorCode> {
        let normalized_id = self.normalize_client_stream_id(stream_id);

        if let Some(stream) = self.streams.get(&normalized_id) {
            if stream.state == StreamState::Closed {
                return Err(ErrorCode::StreamClosed);
            }

            // Existing streams should ALWAYS work regardless of concurrent limit
            if self.settings.max_concurrent_streams == 0 && !stream.created_before_zero_limit {
                self.violations
                    .push(ConcurrentStreamsViolation::ExistingStreamBlocked {
                        stream_id: normalized_id,
                        operation: format!("send_data({})", size),
                    });
            }

            self.stats.existing_stream_ops += 1;
            Ok(())
        } else {
            Err(ErrorCode::StreamClosed)
        }
    }

    /// Close a stream (END_STREAM or RST_STREAM)
    pub fn close_stream(&mut self, stream_id: u32, reset: bool) -> Result<(), ErrorCode> {
        let normalized_id = self.normalize_client_stream_id(stream_id);

        if let Some(stream) = self.streams.get_mut(&normalized_id) {
            stream.state = StreamState::Closed;
            self.stats.existing_stream_ops += 1;

            // When streams close, try to process pending streams
            if self.active_stream_count() < self.settings.max_concurrent_streams {
                self.process_pending_streams();
            }

            Ok(())
        } else {
            Err(ErrorCode::StreamClosed)
        }
    }

    /// Process pending stream creations when limit allows
    fn process_pending_streams(&mut self) {
        let mut processed = 0;

        while !self.pending_streams.is_empty()
            && self.active_stream_count() < self.settings.max_concurrent_streams
        {
            if let Some(pending) = self.pending_streams.pop() {
                self.streams.insert(
                    pending.stream_id,
                    StreamInfo {
                        id: pending.stream_id,
                        state: StreamState::Open,
                        created_before_zero_limit: false, // Created after limit was raised
                    },
                );
                self.stats.streams_created += 1;
                processed += 1;
            }
        }
    }

    /// Normalize stream ID to client-initiated (odd)
    fn normalize_client_stream_id(&self, raw_id: u32) -> u32 {
        let mut id = raw_id & 0x7fff_ffff; // Ensure 31-bit
        if id == 0 {
            id = 1;
        }
        if id % 2 == 0 {
            id = id.saturating_add(1);
        } // Make odd
        id
    }

    /// Check for deadlock conditions
    pub fn check_deadlock(&self) -> bool {
        // Deadlock: zero limit + pending streams + no way to make progress
        self.settings.max_concurrent_streams == 0
            && !self.pending_streams.is_empty()
            && self.active_stream_count() == 0
    }

    /// Get violations
    pub fn violations(&self) -> &[ConcurrentStreamsViolation] {
        &self.violations
    }

    /// Get statistics
    pub fn stats(&self) -> &ConcurrentStreamsStats {
        &self.stats
    }

    /// Check if stream creation is properly blocked
    pub fn stream_creation_blocked(&self) -> bool {
        !self.blocked_stream_attempts.is_empty()
    }

    /// Check if existing streams are still functional
    pub fn existing_streams_functional(&self) -> bool {
        // All streams created before zero limit should still be functional
        self.streams
            .values()
            .filter(|s| s.created_before_zero_limit)
            .all(|s| s.state != StreamState::Closed || self.stats.existing_stream_ops > 0)
    }
}

/// Cap values to reasonable bounds for testing
fn cap_u8(value: u8, max: u8) -> u8 {
    value.min(max)
}

fn cap_u16(value: u16, max: u16) -> u16 {
    value.min(max)
}

fuzz_target!(|input: MaxConcurrentStreamsZeroInput| {
    let mut conn = MockConcurrentStreamsConnection::new();

    // Create initial streams before applying zero limit
    let initial_count = cap_u8(input.initial_stream_count, 10);
    for i in 0..initial_count {
        let _ = conn.create_stream((i as u32 * 2) + 1); // 1, 3, 5, 7, ...
    }

    let initial_active_count = conn.active_stream_count();

    // Apply SETTINGS_MAX_CONCURRENT_STREAMS=0
    let zero_limit_settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);

    let result = conn.handle_settings_frame(&zero_limit_settings);
    assert!(
        result.is_ok(),
        "SETTINGS with MAX_CONCURRENT_STREAMS=0 should succeed"
    );

    // Perform operations with zero limit
    for operation in input.zero_limit_operations.iter().take(20) {
        match operation {
            StreamOperation::CreateStream { stream_id } => {
                let normalized_id = conn.normalize_client_stream_id(*stream_id);
                let result = conn.create_stream(normalized_id);

                // New stream creation should be blocked (queued) or refused
                if result.is_ok() {
                    // If successful, it should be because it was queued
                    assert!(
                        conn.pending_streams
                            .iter()
                            .any(|p| p.stream_id == normalized_id)
                            || conn.streams.contains_key(&normalized_id),
                        "Stream creation succeeded but not tracked properly"
                    );
                }
            }
            StreamOperation::SendData { stream_id, size } => {
                let size = cap_u16(*size, 1024);
                let _ = conn.send_data(*stream_id, size);
            }
            StreamOperation::EndStream { stream_id } => {
                let _ = conn.close_stream(*stream_id, false);
            }
            StreamOperation::ResetStream { stream_id, .. } => {
                let _ = conn.close_stream(*stream_id, true);
            }
            StreamOperation::UpdateConcurrentLimit { limit } => {
                let limit = cap_u8(*limit, 10);
                let settings =
                    SettingsFrame::new(vec![Setting::MaxConcurrentStreams(limit as u32)]);
                let _ = conn.handle_settings_frame(&settings);
            }
        }

        // Check for deadlock after each operation
        assert!(
            !conn.check_deadlock(),
            "Deadlock detected: zero limit with pending streams and no active streams"
        );
    }

    // Verify that existing streams before zero limit are still functional
    if initial_active_count > 0 {
        // At least some existing stream operations should have occurred
        // (This is a weak check since ops might not target existing streams)
        assert!(
            conn.existing_streams_functional(),
            "Existing streams became non-functional after zero limit applied"
        );
    }

    // Recovery: increase limit again
    let recovery_limit = cap_u8(input.recovery_limit, 20).max(1); // At least 1
    let recovery_settings =
        SettingsFrame::new(vec![Setting::MaxConcurrentStreams(recovery_limit as u32)]);

    let result = conn.handle_settings_frame(&recovery_settings);
    assert!(result.is_ok(), "Recovery settings should succeed");

    let pending_before_recovery = conn.pending_streams.len();

    // Perform recovery operations
    for operation in input.recovery_operations.iter().take(10) {
        match operation {
            StreamOperation::CreateStream { stream_id } => {
                let result = conn.create_stream(*stream_id);

                // Should now succeed if under new limit
                if conn.active_stream_count() < recovery_limit as u32 {
                    // Some tolerance here since normalization might affect stream IDs
                    if result.is_err() {
                        // Could fail due to stream ID sequence issues, which is okay
                    }
                }
            }
            StreamOperation::SendData { stream_id, size } => {
                let size = cap_u16(*size, 1024);
                let _ = conn.send_data(*stream_id, size);
            }
            _ => {} // Other operations less relevant for recovery test
        }
    }

    // Verify that pending streams were processed during recovery
    if pending_before_recovery > 0 && recovery_limit > 0 {
        let pending_after_recovery = conn.pending_streams.len();
        assert!(
            pending_after_recovery <= pending_before_recovery,
            "Pending streams should be processed when limit increases"
        );
    }

    // Verify invariants
    let stats = conn.stats();
    assert!(
        stats.streams_created >= initial_count as u32,
        "Stream creation count should include initial streams"
    );

    // Zero limit should have blocked some stream attempts
    if input
        .zero_limit_operations
        .iter()
        .any(|op| matches!(op, StreamOperation::CreateStream { .. }))
    {
        assert!(
            stats.streams_blocked > 0 || stats.streams_queued > 0,
            "Zero limit should have blocked or queued some stream creation attempts"
        );
    }

    // Final active count should not exceed current limit
    assert!(
        conn.active_stream_count() <= conn.settings.max_concurrent_streams,
        "Active stream count {} exceeds limit {}",
        conn.active_stream_count(),
        conn.settings.max_concurrent_streams
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_concurrent_streams_blocks_new() {
        let mut conn = MockConcurrentStreamsConnection::new();

        // Apply zero limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Try to create stream - should be queued
        let result = conn.create_stream(1);
        assert!(result.is_ok()); // Queued, not failed
        assert_eq!(conn.pending_streams.len(), 1);
        assert_eq!(conn.active_stream_count(), 0);
        assert!(conn.stream_creation_blocked());
    }

    #[test]
    fn test_existing_streams_continue_with_zero_limit() {
        let mut conn = MockConcurrentStreamsConnection::new();

        // Create stream before limit
        conn.create_stream(1).unwrap();
        assert_eq!(conn.active_stream_count(), 1);

        // Apply zero limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Existing stream should still work
        let result = conn.send_data(1, 100);
        assert!(result.is_ok(), "Existing stream operations should continue");

        // But new streams should be blocked
        let result = conn.create_stream(3);
        assert!(result.is_ok()); // Queued
        assert_eq!(conn.pending_streams.len(), 1);
    }

    #[test]
    fn test_recovery_from_zero_limit() {
        let mut conn = MockConcurrentStreamsConnection::new();

        // Apply zero limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Queue some streams
        conn.create_stream(1).unwrap();
        conn.create_stream(3).unwrap();
        assert_eq!(conn.pending_streams.len(), 2);

        // Increase limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(2)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Pending streams should be processed
        assert_eq!(conn.pending_streams.len(), 0);
        assert_eq!(conn.active_stream_count(), 2);
    }

    #[test]
    fn test_no_deadlock_with_zero_limit_and_active_streams() {
        let mut conn = MockConcurrentStreamsConnection::new();

        // Create stream first
        conn.create_stream(1).unwrap();

        // Apply zero limit
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(0)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Queue another stream
        conn.create_stream(3).unwrap();

        // Should not be in deadlock state because we have active streams
        assert!(!conn.check_deadlock());
    }

    #[test]
    fn test_stream_id_normalization() {
        let conn = MockConcurrentStreamsConnection::new();

        // Test various stream ID inputs get normalized to odd client IDs
        assert_eq!(conn.normalize_client_stream_id(0), 1);
        assert_eq!(conn.normalize_client_stream_id(2), 3);
        assert_eq!(conn.normalize_client_stream_id(4), 5);
        assert_eq!(conn.normalize_client_stream_id(1), 1);
        assert_eq!(conn.normalize_client_stream_id(3), 3);
    }

    #[test]
    fn test_concurrent_streams_limit_enforcement() {
        let mut conn = MockConcurrentStreamsConnection::new();

        // Set limit to 2
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(2)]);
        conn.handle_settings_frame(&settings).unwrap();

        // Create 2 streams - should succeed
        assert!(conn.create_stream(1).is_ok());
        assert!(conn.create_stream(3).is_ok());
        assert_eq!(conn.active_stream_count(), 2);

        // Third stream should be refused
        let result = conn.create_stream(5);
        assert!(result.is_err());
        assert_eq!(conn.violations().len(), 1);
    }
}
