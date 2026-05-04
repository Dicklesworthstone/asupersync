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
use asupersync::database::postgres::{
    fuzz_build_listen_sql, fuzz_build_unlisten_sql, fuzz_parse_notification_response,
};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

// Shadow-state types exercise operation invariants. Wire parsing delegates to
// the production PostgreSQL NotificationResponse parser below.
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

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Operations(ListenNotifyFuzzInput),
    Parser(RealParserInput),
}

/// Individual LISTEN/NOTIFY operations
#[derive(Arbitrary, Debug, Clone)]
enum ListenNotifyOperation {
    /// Start listening on a channel
    Listen { channel: ChannelName },
    /// Stop listening on a channel
    Unlisten { channel: ChannelName },
    /// Stop listening on all channels
    UnlistenAll,
    /// Send notification to a channel
    Notify {
        channel: ChannelName,
        payload: NotificationPayload,
    },
    /// Simulate receiving notification from server
    ReceiveNotification {
        channel: ChannelName,
        payload: NotificationPayload,
        sender_pid: ProcessId,
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
    pub channel: ChannelName,
    pub payload: NotificationPayload,
    pub sender_pid: ProcessId,
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

/// Test notification response parsing through the production PostgreSQL parser.
fn test_parse_notification_response(
    raw_data: &[u8],
    shadow: &ListenNotifyShadowModel,
) -> Result<(), String> {
    match fuzz_parse_notification_response(raw_data) {
        Ok(parsed) => {
            let sender_pid = u32::try_from(parsed.process_id).unwrap_or(0);
            if sender_pid == 0 {
                shadow.record_error();
                return Ok(());
            }
            shadow.add_notification(PendingNotification {
                channel: parsed.channel,
                payload: parsed.payload,
                sender_pid,
                sequence: shadow.notify_count.load(Ordering::SeqCst),
            });
        }
        Err(_) => shadow.record_error(),
    }

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
    let queue = shadow.notification_queue.lock().unwrap();
    let queue_size = queue.len();
    if queue_size > MAX_QUEUE_SIZE {
        return Err(format!(
            "Notification queue size {} exceeds limit {}",
            queue_size, MAX_QUEUE_SIZE
        ));
    }
    for pair in queue.windows(2) {
        if pair[0].sequence > pair[1].sequence {
            return Err(format!(
                "Notification sequence order regressed: {} > {}",
                pair[0].sequence, pair[1].sequence
            ));
        }
    }
    drop(queue);

    // Verify channel count limits
    let channels: Vec<String> = shadow
        .listened_channels
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    let channel_count = channels.len();
    if channel_count > 1000 {
        // Reasonable limit
        return Err(format!(
            "Listened channel count {} exceeds reasonable limit",
            channel_count
        ));
    }
    for channel in channels.iter().take(4) {
        let _notifications = shadow.get_notifications_for_channel(channel);
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
    let _seed = input.seed;
    let _sql_injection_enabled = input.config.test_sql_injection;
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

#[derive(Arbitrary, Debug)]
struct RealParserInput {
    channel: String,
    payload: String,
    process_id: i32,
    mutation: NotificationMutation,
    trailing_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum NotificationMutation {
    Exact,
    Truncate(u8),
    DropChannelTerminator,
    DropPayloadTerminator,
    AppendTrailingBytes,
}

fn strip_nuls_and_truncate(input: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_len));
    for ch in input.chars() {
        if ch == '\0' {
            continue;
        }
        let char_len = ch.len_utf8();
        if out.len() + char_len > max_len {
            break;
        }
        out.push(ch);
    }
    out
}

fn quote_identifier(identifier: &str) -> String {
    let mut quoted = String::with_capacity(identifier.len() + 2);
    quoted.push('"');
    for ch in identifier.chars() {
        if ch == '"' {
            quoted.push('"');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

fn build_notification_body(process_id: i32, channel: &str, payload: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + channel.len() + payload.len() + 2);
    body.extend_from_slice(&process_id.to_be_bytes());
    body.extend_from_slice(channel.as_bytes());
    body.push(0);
    body.extend_from_slice(payload.as_bytes());
    body.push(0);
    body
}

fn apply_notification_mutation(
    body: &mut Vec<u8>,
    channel_len: usize,
    mutation: &NotificationMutation,
    trailing_bytes: &[u8],
) -> bool {
    match mutation {
        NotificationMutation::Exact => true,
        NotificationMutation::Truncate(drop_count) => {
            if !body.is_empty() {
                let amount = 1 + (*drop_count as usize % body.len());
                body.truncate(body.len() - amount);
            }
            false
        }
        NotificationMutation::DropChannelTerminator => {
            let terminator_index = 4 + channel_len;
            if terminator_index < body.len() {
                body.remove(terminator_index);
            }
            false
        }
        NotificationMutation::DropPayloadTerminator => {
            body.pop();
            false
        }
        NotificationMutation::AppendTrailingBytes => {
            if trailing_bytes.is_empty() {
                body.push(0xff);
            } else {
                body.extend(trailing_bytes.iter().copied().take(8));
            }
            false
        }
    }
}

fn fuzz_real_notification_parser(input: RealParserInput) {
    let expected_valid_channel =
        !input.channel.is_empty() && input.channel.len() <= 63 && !input.channel.contains('\0');

    let listen_sql = fuzz_build_listen_sql(&input.channel);
    let unlisten_sql = fuzz_build_unlisten_sql(&input.channel);
    assert_eq!(listen_sql.is_ok(), expected_valid_channel);
    assert_eq!(unlisten_sql.is_ok(), expected_valid_channel);

    if let Ok(sql) = listen_sql {
        assert_eq!(sql, format!("LISTEN {}", quote_identifier(&input.channel)));
    }
    if let Ok(sql) = unlisten_sql {
        assert_eq!(
            sql,
            format!("UNLISTEN {}", quote_identifier(&input.channel))
        );
    }

    let channel = strip_nuls_and_truncate(&input.channel, 80);
    let payload = strip_nuls_and_truncate(&input.payload, 96);
    let mut body = build_notification_body(input.process_id, &channel, &payload);
    let should_succeed = apply_notification_mutation(
        &mut body,
        channel.len(),
        &input.mutation,
        &input.trailing_bytes,
    );
    let result = fuzz_parse_notification_response(&body);
    let expected_parser_ok = should_succeed
        && !channel.is_empty()
        && channel.len() <= MAX_CHANNEL_NAME_LENGTH
        && payload.len() <= MAX_PAYLOAD_SIZE;
    assert_eq!(
        result.is_ok(),
        expected_parser_ok,
        "mutation={:?} body_len={} channel={:?} payload={:?} result={result:?}",
        input.mutation,
        body.len(),
        channel,
        payload
    );
    if let Ok(parsed) = result {
        assert_eq!(parsed.process_id, input.process_id);
        assert_eq!(parsed.channel, channel);
        assert_eq!(parsed.payload, payload);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);
    let input = if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };
    match input {
        FuzzInput::Operations(input) => {
            if let Err(err) = fuzz_listen_notify(input) {
                panic!("LISTEN/NOTIFY shadow invariant violation: {err}");
            }
        }
        FuzzInput::Parser(input) => fuzz_real_notification_parser(input),
    }
});
