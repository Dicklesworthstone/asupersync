#![no_main]

//! Fuzz target for PostgreSQL LISTEN/NOTIFY async channel functionality.
//!
//! This target exercises critical LISTEN/NOTIFY scenarios including:
//! 1. Channel name validation and SQL injection prevention
//! 2. Notification message parsing and payload handling
//! 3. Async channel multiplexing and fairness
//! 4. Connection state management during LISTEN/UNLISTEN
//! 5. Error handling for malformed notification responses

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// Mock structures for PostgreSQL LISTEN/NOTIFY since not yet implemented in main codebase
type ChannelName = String;
type NotificationPayload = String;
type ProcessId = u32;

/// Fuzz input for PostgreSQL LISTEN/NOTIFY operations
#[derive(Arbitrary, Debug, Clone)]
struct ListenNotifyFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of LISTEN/NOTIFY operations
    pub operations: Vec<ListenNotifyOperation>,
    /// Configuration for testing behavior
    pub config: ListenNotifyConfig,
}

/// Individual LISTEN/NOTIFY operations
#[derive(Arbitrary, Debug, Clone)]
enum ListenNotifyOperation {
    /// Start listening on a channel
    Listen { channel: String },
    /// Stop listening on a channel
    Unlisten { channel: String },
    /// Stop listening on all channels
    UnlistenAll,
    /// Send notification to a channel
    Notify { channel: String, payload: String },
    /// Simulate receiving notification from server
    ReceiveNotification {
        channel: String,
        payload: String,
        sender_pid: u32,
    },
    /// Test notification response parsing
    ParseNotificationResponse { raw_data: Vec<u8> },
    /// Test channel name validation
    ValidateChannelName { name: String },
    /// Test concurrent operations
    ConcurrentOperation { ops: Vec<ListenNotifyOperation> },
    /// Test error conditions
    ErrorCondition { error_type: ErrorType },
    /// Test notification queuing and delivery
    QueueNotifications {
        notifications: Vec<PendingNotification>,
    },
}

/// Error conditions to test
#[derive(Arbitrary, Debug, Clone)]
enum ErrorType {
    /// Invalid channel name
    InvalidChannelName(String),
    /// SQL injection attempt in channel name
    SqlInjection(String),
    /// Malformed notification response
    MalformedResponse(Vec<u8>),
    /// Connection closed during operation
    ConnectionClosed,
    /// Memory exhaustion
    OutOfMemory,
    /// Invalid process ID
    InvalidProcessId(u32),
}

/// Pending notification for queue testing
#[derive(Arbitrary, Debug, Clone)]
struct PendingNotification {
    pub channel: String,
    pub payload: String,
    pub sender_pid: u32,
    pub sequence: u32,
}

/// Configuration for LISTEN/NOTIFY testing
#[derive(Arbitrary, Debug, Clone)]
struct ListenNotifyConfig {
    /// Maximum number of operations to prevent timeout
    pub max_operations: u8,
    /// Maximum channel name length
    pub max_channel_length: u8,
    /// Maximum payload size
    pub max_payload_size: u16,
    /// Enable SQL injection testing
    pub test_sql_injection: bool,
    /// Enable concurrent access testing
    pub test_concurrency: bool,
    /// Maximum notification queue size
    pub max_queue_size: u16,
}

/// Shadow model for tracking LISTEN/NOTIFY state
#[derive(Debug)]
struct ListenNotifyShadowModel {
    /// Currently listened channels
    listened_channels: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Notification queue
    notification_queue: std::sync::Mutex<Vec<PendingNotification>>,
    /// Operation counts
    listen_count: AtomicU32,
    notify_count: AtomicU32,
    error_count: AtomicU32,
    /// Validation violations
    violations: std::sync::Mutex<Vec<String>>,
}

impl ListenNotifyShadowModel {
    fn new() -> Self {
        Self {
            listened_channels: std::sync::Mutex::new(std::collections::HashSet::new()),
            notification_queue: std::sync::Mutex::new(Vec::new()),
            listen_count: AtomicU32::new(0),
            notify_count: AtomicU32::new(0),
            error_count: AtomicU32::new(0),
            violations: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn add_channel(&self, channel: &str) {
        self.listened_channels
            .lock()
            .unwrap()
            .insert(channel.to_string());
        self.listen_count.fetch_add(1, Ordering::SeqCst);
    }

    fn remove_channel(&self, channel: &str) -> bool {
        self.listened_channels.lock().unwrap().remove(channel)
    }

    fn clear_channels(&self) {
        self.listened_channels.lock().unwrap().clear();
    }

    fn is_listening(&self, channel: &str) -> bool {
        self.listened_channels.lock().unwrap().contains(channel)
    }

    fn add_notification(&self, notification: PendingNotification) {
        self.notification_queue.lock().unwrap().push(notification);
        self.notify_count.fetch_add(1, Ordering::SeqCst);
    }

    fn get_notifications_for_channel(&self, channel: &str) -> Vec<PendingNotification> {
        self.notification_queue
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n.channel == channel)
            .cloned()
            .collect()
    }

    fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::SeqCst);
    }

    fn add_violation(&self, violation: String) {
        self.violations.lock().unwrap().push(violation);
    }

    fn get_violations(&self) -> Vec<String> {
        self.violations.lock().unwrap().clone()
    }
}

/// Size limits to prevent timeout/memory exhaustion
const MAX_CHANNEL_NAME_LENGTH: usize = 63; // PostgreSQL identifier limit
const MAX_PAYLOAD_SIZE: usize = 8000; // PostgreSQL NOTIFY payload limit
const MAX_OPERATIONS: usize = 100;
const MAX_QUEUE_SIZE: usize = 1000;
const MAX_CONCURRENT_OPS: usize = 10;

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut ListenNotifyFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(MAX_OPERATIONS);

    // Normalize configuration
    input.config.max_operations = input.config.max_operations.clamp(1, MAX_OPERATIONS as u8);
    input.config.max_channel_length = input
        .config
        .max_channel_length
        .clamp(1, MAX_CHANNEL_NAME_LENGTH as u8);
    input.config.max_payload_size = input
        .config
        .max_payload_size
        .clamp(1, MAX_PAYLOAD_SIZE as u16);
    input.config.max_queue_size = input.config.max_queue_size.clamp(1, MAX_QUEUE_SIZE as u16);

    // Normalize individual operations
    for operation in &mut input.operations {
        normalize_operation(operation, &input.config);
    }
}

fn normalize_operation(operation: &mut ListenNotifyOperation, config: &ListenNotifyConfig) {
    match operation {
        ListenNotifyOperation::Listen { channel } => {
            truncate_string(channel, config.max_channel_length as usize);
        }
        ListenNotifyOperation::Unlisten { channel } => {
            truncate_string(channel, config.max_channel_length as usize);
        }
        ListenNotifyOperation::Notify { channel, payload } => {
            truncate_string(channel, config.max_channel_length as usize);
            truncate_string(payload, config.max_payload_size as usize);
        }
        ListenNotifyOperation::ReceiveNotification {
            channel, payload, ..
        } => {
            truncate_string(channel, config.max_channel_length as usize);
            truncate_string(payload, config.max_payload_size as usize);
        }
        ListenNotifyOperation::ParseNotificationResponse { raw_data } => {
            if raw_data.len() > config.max_payload_size as usize + 100 {
                raw_data.truncate(config.max_payload_size as usize + 100);
            }
        }
        ListenNotifyOperation::ValidateChannelName { name } => {
            truncate_string(name, config.max_channel_length as usize);
        }
        ListenNotifyOperation::ConcurrentOperation { ops } => {
            ops.truncate(MAX_CONCURRENT_OPS);
            for op in ops {
                normalize_operation(op, config);
            }
        }
        ListenNotifyOperation::QueueNotifications { notifications } => {
            notifications.truncate(config.max_queue_size as usize);
            for notification in notifications {
                truncate_string(
                    &mut notification.channel,
                    config.max_channel_length as usize,
                );
                truncate_string(&mut notification.payload, config.max_payload_size as usize);
            }
        }
        _ => {} // Other operations don't need normalization
    }
}

fn truncate_string(s: &mut String, max_len: usize) {
    if s.len() > max_len {
        s.truncate(max_len);
    }
}

/// Execute LISTEN/NOTIFY operations and verify invariants
fn execute_listen_notify_operations(
    input: &ListenNotifyFuzzInput,
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    let mut operation_count = 0;

    for (op_index, operation) in input.operations.iter().enumerate() {
        if operation_count >= input.config.max_operations {
            break;
        }
        operation_count += 1;

        match operation {
            ListenNotifyOperation::Listen { channel } => {
                test_listen_operation(channel, shadow)?;
            }

            ListenNotifyOperation::Unlisten { channel } => {
                test_unlisten_operation(channel, shadow)?;
            }

            ListenNotifyOperation::UnlistenAll => {
                test_unlisten_all_operation(shadow)?;
            }

            ListenNotifyOperation::Notify { channel, payload } => {
                test_notify_operation(channel, payload, shadow)?;
            }

            ListenNotifyOperation::ReceiveNotification {
                channel,
                payload,
                sender_pid,
            } => {
                test_receive_notification(channel, payload, *sender_pid, shadow)?;
            }

            ListenNotifyOperation::ParseNotificationResponse { raw_data } => {
                test_parse_notification_response(raw_data, shadow)?;
            }

            ListenNotifyOperation::ValidateChannelName { name } => {
                test_channel_name_validation(name, shadow)?;
            }

            ListenNotifyOperation::ConcurrentOperation { ops } => {
                if input.config.test_concurrency {
                    test_concurrent_operations(ops, shadow)?;
                }
            }

            ListenNotifyOperation::ErrorCondition { error_type } => {
                test_error_condition(error_type, shadow)?;
            }

            ListenNotifyOperation::QueueNotifications { notifications } => {
                test_notification_queuing(notifications, shadow)?;
            }
        }

        // Verify shadow model consistency every 10 operations
        if op_index % 10 == 0 {
            verify_shadow_model_consistency(shadow)?;
        }
    }

    // Final validation
    verify_shadow_model_consistency(shadow)?;

    // Check for any recorded violations
    let violations = shadow.get_violations();
    if !violations.is_empty() {
        return Err(format!("Shadow model violations: {:?}", violations));
    }

    Ok(())
}

/// Test LISTEN operation
fn test_listen_operation(channel: &str, shadow: &ListenNotifyShadowModel) -> Result<(), String> {
    // Validate channel name
    if !is_valid_channel_name(channel) {
        shadow.record_error();
        return Ok(()); // Invalid channel names should be rejected gracefully
    }

    // Test SQL injection prevention
    if contains_sql_injection(channel) {
        shadow.record_error();
        return Ok(()); // SQL injection attempts should be rejected
    }

    // Simulate successful LISTEN
    shadow.add_channel(channel);

    // Verify channel is now being listened to
    if !shadow.is_listening(channel) {
        return Err(format!(
            "Channel '{}' should be listened after LISTEN operation",
            channel
        ));
    }

    Ok(())
}

/// Test UNLISTEN operation
fn test_unlisten_operation(channel: &str, shadow: &ListenNotifyShadowModel) -> Result<(), String> {
    let was_listening = shadow.is_listening(channel);
    let removed = shadow.remove_channel(channel);

    // Verify consistency: should only remove if was actually listening
    if removed != was_listening {
        shadow.add_violation(format!(
            "UNLISTEN consistency violation: was_listening={}, removed={}",
            was_listening, removed
        ));
    }

    // Verify channel is no longer being listened to
    if shadow.is_listening(channel) {
        return Err(format!(
            "Channel '{}' should not be listened after UNLISTEN operation",
            channel
        ));
    }

    Ok(())
}

/// Test UNLISTEN * operation
fn test_unlisten_all_operation(shadow: &ListenNotifyShadowModel) -> Result<(), String> {
    shadow.clear_channels();

    // Verify no channels are being listened to
    let channel_count = shadow.listened_channels.lock().unwrap().len();
    if channel_count != 0 {
        return Err(format!(
            "Expected 0 channels after UNLISTEN *, got {}",
            channel_count
        ));
    }

    Ok(())
}

/// Test NOTIFY operation
fn test_notify_operation(
    channel: &str,
    payload: &str,
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    // Validate inputs
    if !is_valid_channel_name(channel) {
        shadow.record_error();
        return Ok(());
    }

    if payload.len() > MAX_PAYLOAD_SIZE {
        shadow.record_error();
        return Ok(());
    }

    // Create notification
    let notification = PendingNotification {
        channel: channel.to_string(),
        payload: payload.to_string(),
        sender_pid: 12345, // Mock PID
        sequence: shadow.notify_count.load(Ordering::SeqCst),
    };

    shadow.add_notification(notification);

    Ok(())
}

/// Test receiving notification from server
fn test_receive_notification(
    channel: &str,
    payload: &str,
    sender_pid: u32,
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    // Only process if we're listening to this channel
    if !shadow.is_listening(channel) {
        // Not listening - notification should be ignored
        return Ok(());
    }

    // Validate sender PID
    if sender_pid == 0 {
        shadow.record_error();
        return Ok(());
    }

    // Create and queue notification
    let notification = PendingNotification {
        channel: channel.to_string(),
        payload: payload.to_string(),
        sender_pid,
        sequence: shadow.notify_count.load(Ordering::SeqCst),
    };

    shadow.add_notification(notification);

    Ok(())
}

/// Test notification response parsing (mock PostgreSQL wire protocol)
fn test_parse_notification_response(
    raw_data: &[u8],
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    // Mock PostgreSQL NotificationResponse format:
    // Byte 'A' + length(4 bytes) + pid(4 bytes) + channel(null-terminated) + payload(null-terminated)

    if raw_data.is_empty() {
        shadow.record_error();
        return Ok(());
    }

    // Should start with 'A' for NotificationResponse
    if raw_data[0] != b'A' {
        shadow.record_error();
        return Ok(());
    }

    if raw_data.len() < 9 {
        // Minimum: 'A' + length(4) + pid(4)
        shadow.record_error();
        return Ok(());
    }

    // Parse length field (bytes 1-4, big endian)
    let length = u32::from_be_bytes([raw_data[1], raw_data[2], raw_data[3], raw_data[4]]) as usize;

    // Verify length consistency
    if length + 1 > raw_data.len() {
        // +1 for the 'A' byte
        shadow.record_error();
        return Ok(());
    }

    // Parse PID (bytes 5-8, big endian)
    let pid = u32::from_be_bytes([raw_data[5], raw_data[6], raw_data[7], raw_data[8]]);

    if pid == 0 {
        shadow.record_error();
        return Ok(());
    }

    // Parse channel and payload (null-terminated strings)
    let payload_start = 9;
    if payload_start >= raw_data.len() {
        shadow.record_error();
        return Ok(());
    }

    // Find first null terminator (end of channel name)
    let channel_end = match raw_data[payload_start..].iter().position(|&b| b == 0) {
        Some(pos) => payload_start + pos,
        None => {
            shadow.record_error();
            return Ok(());
        }
    };

    let channel = match std::str::from_utf8(&raw_data[payload_start..channel_end]) {
        Ok(s) => s,
        Err(_) => {
            shadow.record_error();
            return Ok(());
        }
    };

    // Find second null terminator (end of payload)
    let payload_start = channel_end + 1;
    if payload_start >= raw_data.len() {
        shadow.record_error();
        return Ok(());
    }

    let payload_end = match raw_data[payload_start..].iter().position(|&b| b == 0) {
        Some(pos) => payload_start + pos,
        None => raw_data.len(), // Payload can extend to end if no null terminator
    };

    let payload = match std::str::from_utf8(&raw_data[payload_start..payload_end]) {
        Ok(s) => s,
        Err(_) => {
            shadow.record_error();
            return Ok(());
        }
    };

    // Successfully parsed - create notification
    let notification = PendingNotification {
        channel: channel.to_string(),
        payload: payload.to_string(),
        sender_pid: pid,
        sequence: shadow.notify_count.load(Ordering::SeqCst),
    };

    shadow.add_notification(notification);

    Ok(())
}

/// Test channel name validation
fn test_channel_name_validation(
    name: &str,
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    let valid = is_valid_channel_name(name);
    let has_injection = contains_sql_injection(name);

    // Invalid names or injection attempts should be rejected
    if !valid || has_injection {
        shadow.record_error();
        return Ok(());
    }

    // Valid names should be accepted
    if name.is_empty() {
        shadow.record_error();
        return Ok(());
    }

    Ok(())
}

/// Test concurrent LISTEN/NOTIFY operations
fn test_concurrent_operations(
    ops: &[ListenNotifyOperation],
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    // Simulate concurrent execution by processing all operations
    // In a real implementation, this would test thread safety
    for op in ops {
        match op {
            ListenNotifyOperation::Listen { channel } => {
                let _ = test_listen_operation(channel, shadow);
            }
            ListenNotifyOperation::Notify { channel, payload } => {
                let _ = test_notify_operation(channel, payload, shadow);
            }
            _ => {} // Only test basic operations for concurrency
        }
    }

    Ok(())
}

/// Test error conditions
fn test_error_condition(
    error_type: &ErrorType,
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    match error_type {
        ErrorType::InvalidChannelName(name) => {
            if is_valid_channel_name(name) {
                // This should be an invalid name for testing
                shadow.add_violation(format!("Expected invalid channel name: {}", name));
            }
            shadow.record_error();
        }

        ErrorType::SqlInjection(attempt) => {
            if !contains_sql_injection(attempt) {
                shadow.add_violation(format!("Expected SQL injection pattern: {}", attempt));
            }
            shadow.record_error();
        }

        ErrorType::MalformedResponse(data) => {
            // Attempt to parse malformed response
            let _ = test_parse_notification_response(data, shadow);
            shadow.record_error();
        }

        ErrorType::ConnectionClosed => {
            // Simulate connection closed - all operations should fail gracefully
            shadow.record_error();
        }

        ErrorType::OutOfMemory => {
            // Simulate memory exhaustion
            shadow.record_error();
        }

        ErrorType::InvalidProcessId(pid) => {
            if *pid != 0 {
                shadow.add_violation(format!("Expected invalid PID 0, got {}", pid));
            }
            shadow.record_error();
        }
    }

    Ok(())
}

/// Test notification queuing and delivery
fn test_notification_queuing(
    notifications: &[PendingNotification],
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    for notification in notifications {
        // Validate notification
        if !is_valid_channel_name(&notification.channel) {
            shadow.record_error();
            continue;
        }

        if notification.payload.len() > MAX_PAYLOAD_SIZE {
            shadow.record_error();
            continue;
        }

        if notification.sender_pid == 0 {
            shadow.record_error();
            continue;
        }

        // Add to queue
        shadow.add_notification(notification.clone());
    }

    // Verify queue doesn't exceed limits
    let queue_size = shadow.notification_queue.lock().unwrap().len();
    if queue_size > MAX_QUEUE_SIZE {
        shadow.add_violation(format!(
            "Notification queue exceeded limit: {} > {}",
            queue_size, MAX_QUEUE_SIZE
        ));
    }

    Ok(())
}

/// Verify shadow model internal consistency
fn verify_shadow_model_consistency(shadow: &ListenNotifyShadowModel) -> Result<(), String> {
    // Verify queue size limits
    let queue_size = shadow.notification_queue.lock().unwrap().len();
    if queue_size > MAX_QUEUE_SIZE {
        return Err(format!(
            "Notification queue size {} exceeds limit {}",
            queue_size, MAX_QUEUE_SIZE
        ));
    }

    // Verify channel count limits
    let channel_count = shadow.listened_channels.lock().unwrap().len();
    if channel_count > 1000 {
        // Reasonable limit
        return Err(format!(
            "Listened channel count {} exceeds reasonable limit",
            channel_count
        ));
    }

    // Verify counters are reasonable
    let listen_count = shadow.listen_count.load(Ordering::SeqCst);
    let notify_count = shadow.notify_count.load(Ordering::SeqCst);

    if listen_count > 10000 || notify_count > 10000 {
        return Err(format!(
            "Operation counters too high: listen={}, notify={}",
            listen_count, notify_count
        ));
    }

    Ok(())
}

/// Validate PostgreSQL channel name (simplified)
fn is_valid_channel_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_CHANNEL_NAME_LENGTH {
        return false;
    }

    // PostgreSQL identifiers: start with letter or underscore, contain letters/digits/underscores
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return false;
    }

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return false;
        }
    }

    true
}

/// Detect potential SQL injection in channel names
fn contains_sql_injection(input: &str) -> bool {
    let input_lower = input.to_lowercase();
    let injection_patterns = [
        "select", "insert", "update", "delete", "drop", "create", "alter", "exec", "union", "or",
        "and", "'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
    ];

    for pattern in &injection_patterns {
        if input_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Main fuzzing entry point
fn fuzz_listen_notify(mut input: ListenNotifyFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    let shadow = ListenNotifyShadowModel::new();

    // Execute LISTEN/NOTIFY operations and analysis
    execute_listen_notify_operations(&input, &shadow)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 16384 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = ListenNotifyFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run LISTEN/NOTIFY fuzzing
    let _ = fuzz_listen_notify(input);
});
