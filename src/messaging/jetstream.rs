//! NATS JetStream client with Cx integration.
//!
//! This module extends the NATS client with JetStream support for durable
//! streams, consumers, and exactly-once delivery semantics.
//!
//! # Overview
//!
//! JetStream is NATS' persistence layer providing:
//! - Durable message streams
//! - Pull and push consumers
//! - Exactly-once delivery with ack/nack
//! - Message deduplication
//!
//! # Example
//!
//! ```ignore
//! let client = NatsClient::connect(cx, "nats://localhost:4222").await?;
//! let js = JetStreamContext::new(client);
//!
//! // Create a stream
//! let stream = js.create_stream(cx, StreamConfig::new("ORDERS").subjects(&["orders.>"])).await?;
//!
//! // Publish with acknowledgement
//! let ack = js.publish(cx, "orders.new", b"order data").await?;
//!
//! // Create a consumer
//! let consumer = js.create_consumer(cx, "ORDERS", ConsumerConfig::new("processor")).await?;
//!
//! // Pull and process messages
//! for msg in consumer.pull(cx, 10).await? {
//!     process_order(&msg.payload);
//!     msg.ack(cx).await?;
//! }
//! ```

use super::nats::{
    Message, NatsClient, NatsError, validate_nats_publish_subject,
    validate_nats_subscription_pattern,
};
use crate::cx::Cx;
use crate::time::{timeout_at, wall_now};
use crate::tracing_compat::warn;
use crate::types::Time;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64};

/// br-asupersync-w7n2qx: client-side cap on stream and consumer name
/// length, in bytes. Mirrors the upstream `nats-server` 256-byte cap on
/// stream / consumer names so a buggy or hostile caller cannot smuggle
/// a megabyte-long name into the JSON request body or the
/// `format!()`-built NATS subject.
const MAX_NAME_BYTES: usize = 256;

/// JetStream spec requirement for durable consumer name length in characters.
/// Per JetStream specification, durable consumer names must be 1-128 characters.
const MAX_CONSUMER_NAME_CHARS: usize = 128;

/// JetStream stream subjects are regular NATS subscription patterns and share
/// the same practical size ceiling as the underlying NATS parser.
const MAX_STREAM_SUBJECT_BYTES: usize = 4 * 1024;

/// Pull rate limiting: minimum interval between consecutive pull requests per consumer (ms)
const MIN_PULL_INTERVAL_MS: u64 = 50; // 20 requests/second max per consumer

/// Pull rate limiting: exponential backoff base multiplier for rapid requests
const PULL_BACKOFF_MULTIPLIER: f64 = 1.5;

/// Pull rate limiting: maximum backoff interval (ms)
const MAX_PULL_BACKOFF_MS: u64 = 5000; // 5 seconds max

/// Dynamic batch sizing: memory pressure threshold to start reducing batch sizes
const MEMORY_PRESSURE_THRESHOLD_MB: u64 = 512; // Start reducing at 512MB consumer memory usage

/// Dynamic batch sizing: minimum batch size under memory pressure
const MIN_BATCH_SIZE_UNDER_PRESSURE: usize = 16;

/// System-wide pull request rate limiting: max pull requests per second across all consumers
const GLOBAL_PULL_RATE_LIMIT: u64 = 1000;

/// br-asupersync-w7n2qx: client-side cap on the `batch` argument to
/// pull-consumer requests. The pull path pre-allocates
/// `Vec::with_capacity(batch)` for received messages; without a cap a
/// caller passing `usize::MAX` would either panic the allocator or
/// silently consume gigabytes of resident memory while waiting for
/// responses that the server's own `max_ack_pending` will never let
/// arrive. 1024 matches the typical batch ceiling in the upstream
/// nats.go pull-consumer client and the NATS JetStream documented
/// recommendation.
const MAX_PULL_BATCH: usize = 1024;

/// Inbox room for a pull's status replies (404/408/409...) beyond its batch.
const PULL_INBOX_STATUS_SLACK: usize = 8;

/// Messages a pull's inbox buffers: the whole batch plus its status replies,
/// since a supervised client dispatches what the server sends before the pull
/// drains the inbox, and a full inbox drops messages.
fn pull_inbox_capacity(batch: usize) -> usize {
    batch.saturating_add(PULL_INBOX_STATUS_SLACK)
}

/// Pull request rate limiter to prevent DoS via rapid pull requests.
/// Implements per-consumer rate limiting with exponential backoff.
#[derive(Debug)]
struct PullRateLimiter {
    /// Timestamp of last pull request (nanoseconds since UNIX_EPOCH)
    last_pull_ns: AtomicU64,
    /// Current backoff interval (milliseconds)
    current_backoff_ms: AtomicU64,
    /// Number of consecutive rapid requests
    rapid_request_count: AtomicU64,
    /// Whether rate limiting is currently active
    rate_limiting_active: AtomicBool,
}

/// System-wide pull rate tracker to prevent global DoS attacks
#[derive(Debug)]
struct GlobalPullRateTracker {
    /// Pull request timestamps for the last second (circular buffer)
    recent_pulls: Vec<u64>,
    /// Current position in the circular buffer
    buffer_position: usize,
    /// Total system memory usage estimate (bytes)
    estimated_memory_usage: u64,
}

/// Global pull rate tracker for system-wide DoS protection
static GLOBAL_PULL_RATE_TRACKER: std::sync::LazyLock<Mutex<GlobalPullRateTracker>> =
    std::sync::LazyLock::new(|| Mutex::new(GlobalPullRateTracker::new()));

impl PullRateLimiter {
    fn new() -> Self {
        Self {
            last_pull_ns: AtomicU64::new(0),
            current_backoff_ms: AtomicU64::new(0),
            rapid_request_count: AtomicU64::new(0),
            rate_limiting_active: AtomicBool::new(false),
        }
    }

    /// Check if a pull request is allowed and update rate limiting state.
    /// Returns Ok(()) if allowed, Err with delay duration if rate limited.
    fn check_pull_request(&self, now_ns: u64) -> Result<(), Duration> {
        let last_pull_ns = self.last_pull_ns.load(Ordering::Relaxed);
        let time_since_last_ms = (now_ns - last_pull_ns) / 1_000_000; // Convert to milliseconds

        // Check minimum interval
        if time_since_last_ms < MIN_PULL_INTERVAL_MS {
            // Rapid request detected - apply exponential backoff
            let rapid_count = self.rapid_request_count.fetch_add(1, Ordering::Relaxed);
            let backoff_ms = self.calculate_backoff(rapid_count);
            self.current_backoff_ms.store(backoff_ms, Ordering::Relaxed);
            self.rate_limiting_active.store(true, Ordering::Relaxed);

            warn!(
                "JetStream pull rate limit exceeded - backoff required: {}ms (rapid requests: {})",
                backoff_ms,
                rapid_count + 1
            );

            return Err(Duration::from_millis(backoff_ms));
        }

        // Check if we need to wait for backoff
        let current_backoff_ms = self.current_backoff_ms.load(Ordering::Relaxed);
        if current_backoff_ms > 0 && time_since_last_ms < current_backoff_ms {
            let remaining_backoff = current_backoff_ms - time_since_last_ms;
            return Err(Duration::from_millis(remaining_backoff));
        }

        // Request is allowed - update state
        self.last_pull_ns.store(now_ns, Ordering::Relaxed);

        // Reset backoff if we've waited long enough
        if time_since_last_ms > current_backoff_ms * 2 {
            self.rapid_request_count.store(0, Ordering::Relaxed);
            self.current_backoff_ms.store(0, Ordering::Relaxed);
            self.rate_limiting_active.store(false, Ordering::Relaxed);
        }

        Ok(())
    }

    fn calculate_backoff(&self, rapid_count: u64) -> u64 {
        let base_backoff = MIN_PULL_INTERVAL_MS * 2; // Start with 2x minimum interval
        let exponential_backoff =
            (base_backoff as f64 * PULL_BACKOFF_MULTIPLIER.powi(rapid_count as i32)) as u64;
        exponential_backoff.min(MAX_PULL_BACKOFF_MS)
    }

    fn is_rate_limiting_active(&self) -> bool {
        self.rate_limiting_active.load(Ordering::Relaxed)
    }
}

impl GlobalPullRateTracker {
    fn new() -> Self {
        Self {
            recent_pulls: vec![0; 2000], // Track up to 2000 requests (2x the rate limit)
            buffer_position: 0,
            estimated_memory_usage: 0,
        }
    }

    /// Check if a global pull request is allowed and update tracking.
    fn check_global_pull_request(
        &mut self,
        now_ns: u64,
        estimated_batch_memory: u64,
    ) -> Result<(), Duration> {
        let now_ms = now_ns / 1_000_000; // Convert to milliseconds
        let one_second_ago = now_ms.saturating_sub(1000);

        // Count recent pulls in the last second
        let recent_count = self
            .recent_pulls
            .iter()
            .filter(|&&timestamp| timestamp > one_second_ago)
            .count();

        // Check global rate limit
        if recent_count >= GLOBAL_PULL_RATE_LIMIT as usize {
            warn!(
                "JetStream global pull rate limit exceeded: {} requests/second (limit: {})",
                recent_count, GLOBAL_PULL_RATE_LIMIT
            );
            return Err(Duration::from_millis(100)); // Brief delay for global rate limit
        }

        // Check memory pressure
        let new_memory_usage = self.estimated_memory_usage + estimated_batch_memory;
        if new_memory_usage > MEMORY_PRESSURE_THRESHOLD_MB * 1_024 * 1_024 {
            warn!(
                "JetStream memory pressure detected: {}MB estimated usage (threshold: {}MB)",
                new_memory_usage / (1_024 * 1_024),
                MEMORY_PRESSURE_THRESHOLD_MB
            );
            return Err(Duration::from_millis(500)); // Longer delay for memory pressure
        }

        // Update tracking
        self.recent_pulls[self.buffer_position] = now_ms;
        self.buffer_position = (self.buffer_position + 1) % self.recent_pulls.len();
        self.estimated_memory_usage = new_memory_usage;

        Ok(())
    }

    /// Give back a finished pull's estimate. The estimate used to be trimmed
    /// by only half a pull's worth per pull, so it grew without bound and,
    /// after a few thousand pulls, refused every pull in the process.
    fn release(&mut self, estimated_batch_memory: u64) {
        self.estimated_memory_usage = self
            .estimated_memory_usage
            .saturating_sub(estimated_batch_memory);
    }
}

/// The local flow-control bound for a consumer's `max_ack_pending`.
/// JetStream uses -1 for "unlimited" (and 0 for "server default"); clamping
/// those to 1 made each pull keep its first message and drop the rest
/// without a NAK.
fn local_max_ack_pending(server_value: i64) -> usize {
    usize::try_from(server_value)
        .ok()
        .filter(|&limit| limit > 0)
        .unwrap_or(usize::MAX)
}

/// A pull's share of the global memory estimate, released when the pull
/// completes, fails or is dropped.
struct GlobalPullReservation(u64);

impl Drop for GlobalPullReservation {
    fn drop(&mut self) {
        GLOBAL_PULL_RATE_TRACKER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(self.0);
    }
}

fn redacted_name_fingerprint(value: &str) -> String {
    // Stable FNV-1a fingerprint for deterministic redaction/logging.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("bytes={},fnv1a64={hash:016x}", value.len())
}

fn validate_pull_batch_size(batch: usize) -> Result<(), JsError> {
    // br-asupersync-w7n2qx: cap the batch argument client-side.
    // Vec::with_capacity(batch) below would otherwise allocate
    // proportional to a caller-controlled value; usize::MAX panics
    // the allocator and even moderate batches like 1_000_000 commit
    // multi-megabyte allocations whose backing memory the server's
    // own max_ack_pending will never let us fill. 1024 matches the
    // typical batch ceiling in the upstream nats.go pull client.
    if batch == 0 {
        return Err(JsError::InvalidConfig(
            "pull batch size must be > 0".to_string(),
        ));
    }
    if batch > MAX_PULL_BATCH {
        return Err(JsError::InvalidConfig(format!(
            "pull batch size {batch} exceeds {MAX_PULL_BATCH}-message cap; \
             issue multiple smaller pulls or raise the cap deliberately"
        )));
    }
    Ok(())
}

/// Enhanced pull batch size validation with dynamic sizing based on system pressure.
/// Returns the validated (and potentially clamped) batch size.
fn validate_and_clamp_pull_batch_size(
    requested_batch: usize,
    consumer: &Consumer,
) -> Result<usize, JsError> {
    // First apply basic validation
    validate_pull_batch_size(requested_batch)?;

    // Check if rate limiting is active - reduce batch size under pressure
    let clamped_batch = if consumer.pull_rate_limiter.is_rate_limiting_active() {
        let reduced_batch = (requested_batch / 2).max(MIN_BATCH_SIZE_UNDER_PRESSURE);
        warn!(
            stream = %consumer.stream,
            consumer = %consumer.name,
            requested = requested_batch,
            clamped = reduced_batch,
            "JetStream batch size reduced due to rate limiting"
        );
        reduced_batch
    } else {
        // Check global memory pressure
        let global_tracker = GLOBAL_PULL_RATE_TRACKER.lock().unwrap();
        let current_memory_mb = global_tracker.estimated_memory_usage / (1_024 * 1_024);

        if current_memory_mb > MEMORY_PRESSURE_THRESHOLD_MB / 2 {
            // Under moderate memory pressure - reduce batch size
            let pressure_factor =
                (current_memory_mb as f64 / MEMORY_PRESSURE_THRESHOLD_MB as f64).min(1.0);
            let reduced_batch = ((requested_batch as f64 * (1.0 - pressure_factor * 0.5)) as usize)
                .max(MIN_BATCH_SIZE_UNDER_PRESSURE);

            if reduced_batch < requested_batch {
                warn!(
                    stream = %consumer.stream,
                    consumer = %consumer.name,
                    requested = requested_batch,
                    clamped = reduced_batch,
                    memory_mb = current_memory_mb,
                    "JetStream batch size reduced due to memory pressure"
                );
            }
            reduced_batch
        } else {
            requested_batch
        }
    };

    Ok(clamped_batch)
}

/// br-asupersync-dpdmsy: a single `JetStreamContext` publishes through
/// `&mut self`, so the honest per-context default is one outstanding publish
/// request at a time. Anything broader needs an explicit multi-context
/// controller, not wishful thinking inside this type.
const DEFAULT_MAX_IN_FLIGHT_PUBLISHES: usize = 1;
/// br-asupersync-dpdmsy: foundation slice uses an explicit refusal policy
/// rather than queuing hidden waiters.
const DEFAULT_MAX_PUBLISH_WAITERS: usize = 0;
/// br-asupersync-dpdmsy: under emergency pressure, fail closed before opening a
/// new publish request.
const DEFAULT_EMERGENCY_MAX_IN_FLIGHT_PUBLISHES: usize = 0;

/// JetStream-specific errors.
#[derive(Debug)]
pub enum JsError {
    /// Underlying NATS error.
    Nats(NatsError),
    /// JetStream API error response.
    Api {
        /// Error code returned by the JetStream API.
        code: u32,
        /// Human-readable error description.
        description: String,
    },
    /// Stream not found.
    StreamNotFound(String),
    /// Consumer not found.
    ConsumerNotFound {
        /// Stream name where the consumer is expected.
        stream: String,
        /// Consumer name that was not found.
        consumer: String,
    },
    /// Message not acknowledged.
    NotAcked,
    /// Message was already acknowledged, nacked, or terminated.
    AlreadyAcknowledged,
    /// Invalid configuration.
    InvalidConfig(String),
    /// Parse error in API response.
    ParseError(String),
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nats(e) => write!(f, "JetStream NATS error: {e}"),
            Self::Api { code, description } => {
                write!(f, "JetStream API error {code}: {description}")
            }
            Self::StreamNotFound(name) => write!(f, "JetStream stream not found: {name}"),
            Self::ConsumerNotFound { stream, consumer } => {
                write!(f, "JetStream consumer not found: {stream}/{consumer}")
            }
            Self::NotAcked => write!(f, "JetStream message not acknowledged"),
            Self::AlreadyAcknowledged => {
                write!(
                    f,
                    "JetStream message already acknowledged/nacked/terminated"
                )
            }
            Self::InvalidConfig(msg) => write!(f, "JetStream invalid config: {msg}"),
            Self::ParseError(msg) => write!(f, "JetStream parse error: {msg}"),
        }
    }
}

impl std::error::Error for JsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Nats(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NatsError> for JsError {
    fn from(err: NatsError) -> Self {
        Self::Nats(err)
    }
}

impl JsError {
    /// Whether this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Nats(e) => e.is_transient(),
            Self::Api { code, .. } => matches!(code, 503 | 408),
            Self::NotAcked => true,
            _ => false,
        }
    }

    /// Whether this error indicates a connection-level failure.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Nats(e) if e.is_connection_error())
    }

    /// Whether this error indicates resource/capacity exhaustion.
    #[must_use]
    pub fn is_capacity_error(&self) -> bool {
        matches!(self, Self::Api { code: 429, .. })
    }

    /// Whether this error is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Nats(e) => e.is_timeout(),
            Self::Api { code: 408, .. } | Self::NotAcked => true,
            _ => false,
        }
    }

    /// Whether the operation should be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }
}

/// Stream configuration.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Stream name (must be alphanumeric + dash/underscore).
    pub name: String,
    /// Subjects this stream captures.
    pub subjects: Vec<String>,
    /// Retention policy.
    pub retention: RetentionPolicy,
    /// Storage type.
    pub storage: StorageType,
    /// Maximum messages in stream.
    pub max_msgs: Option<i64>,
    /// Maximum bytes in stream.
    pub max_bytes: Option<i64>,
    /// Maximum age of messages.
    pub max_age: Option<Duration>,
    /// Maximum message size.
    pub max_msg_size: Option<i32>,
    /// Discard policy when limits reached.
    pub discard: DiscardPolicy,
    /// Number of replicas (for clustering).
    pub replicas: u32,
    /// Duplicate detection window.
    pub duplicate_window: Option<Duration>,
}

impl StreamConfig {
    /// Create a new stream configuration with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            subjects: Vec::new(),
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_msgs: None,
            max_bytes: None,
            max_age: None,
            max_msg_size: None,
            discard: DiscardPolicy::Old,
            replicas: 1,
            duplicate_window: None,
        }
    }

    /// Set subjects for this stream.
    #[must_use]
    pub fn subjects(mut self, subjects: &[&str]) -> Self {
        self.subjects = subjects.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Set retention policy.
    #[must_use]
    pub fn retention(mut self, policy: RetentionPolicy) -> Self {
        self.retention = policy;
        self
    }

    /// Set storage type.
    #[must_use]
    pub fn storage(mut self, storage: StorageType) -> Self {
        self.storage = storage;
        self
    }

    /// Set maximum messages.
    #[must_use]
    pub fn max_messages(mut self, max: i64) -> Self {
        self.max_msgs = Some(max);
        self
    }

    /// Set maximum bytes.
    #[must_use]
    pub fn max_bytes(mut self, max: i64) -> Self {
        self.max_bytes = Some(max);
        self
    }

    /// Set maximum message age.
    #[must_use]
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    /// Set replica count.
    #[must_use]
    pub fn replicas(mut self, count: u32) -> Self {
        self.replicas = count;
        self
    }

    /// Set duplicate detection window.
    #[must_use]
    pub fn duplicate_window(mut self, window: Duration) -> Self {
        self.duplicate_window = Some(window);
        self
    }

    fn validate(&self) -> Result<(), JsError> {
        ConsumerConfig::validate_stream_name(&self.name)?;

        for (index, subject) in self.subjects.iter().enumerate() {
            validate_stream_subject_pattern(subject).map_err(|reason| {
                JsError::InvalidConfig(format!("stream subjects[{index}] {reason}: {subject:?}"))
            })?;
        }

        if let Some(max_msgs) = self.max_msgs
            && max_msgs < 0
        {
            return Err(JsError::InvalidConfig(
                "stream max_msgs must be >= 0 when set".to_string(),
            ));
        }
        if let Some(max_bytes) = self.max_bytes
            && max_bytes < 0
        {
            return Err(JsError::InvalidConfig(
                "stream max_bytes must be >= 0 when set".to_string(),
            ));
        }
        if let Some(max_msg_size) = self.max_msg_size
            && max_msg_size < 0
        {
            return Err(JsError::InvalidConfig(
                "stream max_msg_size must be >= 0 when set".to_string(),
            ));
        }
        if self.replicas == 0 {
            return Err(JsError::InvalidConfig(
                "stream replicas must be >= 1".to_string(),
            ));
        }

        Ok(())
    }

    /// Encode to JSON for API request.
    fn to_json(&self) -> String {
        let mut json = String::from("{");
        write!(&mut json, "\"name\":\"{}\"", json_escape(&self.name)).expect("write to String");

        if !self.subjects.is_empty() {
            json.push_str(",\"subjects\":[");
            for (i, s) in self.subjects.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                write!(&mut json, "\"{}\"", json_escape(s)).expect("write to String");
            }
            json.push(']');
        }

        write!(&mut json, ",\"retention\":\"{}\"", self.retention.as_str())
            .expect("write to String");
        write!(&mut json, ",\"storage\":\"{}\"", self.storage.as_str()).expect("write to String");
        write!(&mut json, ",\"discard\":\"{}\"", self.discard.as_str()).expect("write to String");
        write!(&mut json, ",\"num_replicas\":{}", self.replicas).expect("write to String");

        if let Some(max) = self.max_msgs {
            write!(&mut json, ",\"max_msgs\":{max}").expect("write to String");
        }
        if let Some(max) = self.max_bytes {
            write!(&mut json, ",\"max_bytes\":{max}").expect("write to String");
        }
        if let Some(age) = self.max_age {
            write!(&mut json, ",\"max_age\":{}", age.as_nanos()).expect("write to String");
        }
        if let Some(size) = self.max_msg_size {
            write!(&mut json, ",\"max_msg_size\":{size}").expect("write to String");
        }
        if let Some(window) = self.duplicate_window {
            write!(&mut json, ",\"duplicate_window\":{}", window.as_nanos())
                .expect("write to String");
        }

        json.push('}');
        json
    }

    /// The configuration a server reports for a stream. A negative limit
    /// (the server's "unlimited") and a zero age or window become `None`; an
    /// enum value this crate does not model keeps its default.
    fn from_server_json(name: String, json: &str) -> Self {
        let limit = |key: &str| extract_json_i64_simple(json, key).filter(|value| *value >= 0);
        let nanos = |key: &str| {
            extract_json_u64(json, key)
                .filter(|value| *value > 0)
                .map(Duration::from_nanos)
        };
        Self {
            name,
            subjects: extract_json_string_array(json, "subjects").unwrap_or_default(),
            retention: match extract_json_string_simple(json, "retention").as_deref() {
                Some("interest") => RetentionPolicy::Interest,
                Some("workqueue") => RetentionPolicy::WorkQueue,
                _ => RetentionPolicy::Limits,
            },
            storage: match extract_json_string_simple(json, "storage").as_deref() {
                Some("memory") => StorageType::Memory,
                _ => StorageType::File,
            },
            max_msgs: limit("max_msgs"),
            max_bytes: limit("max_bytes"),
            max_age: nanos("max_age"),
            max_msg_size: limit("max_msg_size").and_then(|value| i32::try_from(value).ok()),
            discard: match extract_json_string_simple(json, "discard").as_deref() {
                Some("new") => DiscardPolicy::New,
                _ => DiscardPolicy::Old,
            },
            replicas: extract_json_u64(json, "num_replicas")
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .unwrap_or(1),
            duplicate_window: nanos("duplicate_window"),
        }
    }
}

/// Retention policy for streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    /// Keep messages until limits are reached (default).
    #[default]
    Limits,
    /// Keep messages until acknowledged by all consumers.
    Interest,
    /// Keep messages until acknowledged by any consumer.
    WorkQueue,
}

impl RetentionPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Limits => "limits",
            Self::Interest => "interest",
            Self::WorkQueue => "workqueue",
        }
    }
}

/// Storage type for streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageType {
    /// File-based storage (default, persistent).
    #[default]
    File,
    /// Memory-based storage (faster, not persistent).
    Memory,
}

impl StorageType {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Memory => "memory",
        }
    }
}

/// Discard policy when stream limits are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscardPolicy {
    /// Discard old messages (default).
    #[default]
    Old,
    /// Discard new messages.
    New,
}

impl DiscardPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::New => "new",
        }
    }
}

/// Stream information returned by JetStream API.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream configuration.
    pub config: StreamConfig,
    /// Current state.
    pub state: StreamState,
}

/// Current state of a stream.
#[derive(Debug, Clone, Default)]
pub struct StreamState {
    /// Total messages in stream.
    pub messages: u64,
    /// Total bytes in stream.
    pub bytes: u64,
    /// First sequence number.
    pub first_seq: u64,
    /// Last sequence number.
    pub last_seq: u64,
    /// Number of consumers.
    pub consumer_count: u32,
}

/// Consumer configuration.
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// Consumer name (durable consumers).
    pub name: Option<String>,
    /// Durable name (deprecated, use name).
    pub durable_name: Option<String>,
    /// Push-consumer delivery subject.
    pub deliver_subject: Option<String>,
    /// Delivery policy.
    pub deliver_policy: DeliverPolicy,
    /// Ack policy.
    pub ack_policy: AckPolicy,
    /// Ack wait timeout.
    pub ack_wait: Duration,
    /// Max deliveries before giving up.
    pub max_deliver: i64,
    /// Filter subject.
    pub filter_subject: Option<String>,
    /// Push-consumer delivery throttle in bits per second.
    pub rate_limit_bps: Option<u64>,
    /// Max ack pending.
    pub max_ack_pending: i64,
}

impl ConsumerConfig {
    /// Create a new consumer configuration.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            durable_name: None,
            deliver_subject: None,
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_deliver: -1,
            filter_subject: None,
            rate_limit_bps: None,
            max_ack_pending: 1000,
        }
    }

    /// Create an ephemeral consumer (no name).
    #[must_use]
    pub fn ephemeral() -> Self {
        Self {
            name: None,
            durable_name: None,
            deliver_subject: None,
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_deliver: -1,
            filter_subject: None,
            rate_limit_bps: None,
            max_ack_pending: 1000,
        }
    }

    /// Set push-consumer delivery subject.
    #[must_use]
    pub fn deliver_subject(mut self, subject: impl Into<String>) -> Self {
        self.deliver_subject = Some(subject.into());
        self
    }

    /// Set delivery policy.
    #[must_use]
    pub fn deliver_policy(mut self, policy: DeliverPolicy) -> Self {
        self.deliver_policy = policy;
        self
    }

    /// Set ack policy.
    #[must_use]
    pub fn ack_policy(mut self, policy: AckPolicy) -> Self {
        self.ack_policy = policy;
        self
    }

    /// Set ack wait timeout.
    #[must_use]
    pub fn ack_wait(mut self, wait: Duration) -> Self {
        self.ack_wait = wait;
        self
    }

    /// Set max deliveries.
    #[must_use]
    pub fn max_deliver(mut self, max: i64) -> Self {
        self.max_deliver = max;
        self
    }

    /// Set filter subject.
    #[must_use]
    pub fn filter_subject(mut self, subject: impl Into<String>) -> Self {
        self.filter_subject = Some(subject.into());
        self
    }

    /// Set push-consumer delivery throttle in bits per second.
    #[must_use]
    pub fn rate_limit_bps(mut self, bits_per_second: u64) -> Self {
        self.rate_limit_bps = Some(bits_per_second);
        self
    }

    /// Set maximum unacknowledged messages the server should allow.
    #[must_use]
    pub fn max_ack_pending(mut self, max_ack_pending: i64) -> Self {
        self.max_ack_pending = max_ack_pending;
        self
    }

    fn validate(&mut self) -> Result<(), JsError> {
        self.normalize_identity()?;
        if let Some(deliver_subject) = self.deliver_subject.as_deref() {
            validate_nats_publish_subject(deliver_subject, "deliver_subject")
                .map_err(|err| JsError::InvalidConfig(err.to_string()))?;
        }
        if let Some(filter_subject) = self.filter_subject.as_deref() {
            validate_nats_subscription_pattern(filter_subject, "filter_subject")
                .map_err(|err| JsError::InvalidConfig(err.to_string()))?;
        }
        if self.rate_limit_bps.is_some() && self.deliver_subject.is_none() {
            return Err(JsError::InvalidConfig(
                "consumer rate_limit_bps requires deliver_subject for push consumers".to_string(),
            ));
        }
        Ok(())
    }

    /// Canonicalize the deprecated durable alias into one validated consumer identity.
    fn normalize_identity(&mut self) -> Result<(), JsError> {
        let name = Self::validate_consumer_name("name", self.name.as_deref())?;
        let durable_name =
            Self::validate_consumer_name("durable_name", self.durable_name.as_deref())?;

        let canonical_name = match (name, durable_name) {
            (Some(name), Some(durable_name)) if name != durable_name => {
                return Err(JsError::InvalidConfig(format!(
                    "consumer name mismatch: name '{name}' != durable_name '{durable_name}'"
                )));
            }
            (Some(name), _) => Some(name.to_string()),
            (None, Some(durable_name)) => Some(durable_name.to_string()),
            (None, None) => None,
        };

        self.name = canonical_name;
        self.durable_name = None;
        Ok(())
    }

    fn validate_consumer_name<'a>(
        field: &str,
        value: Option<&'a str>,
    ) -> Result<Option<&'a str>, JsError> {
        let Some(value) = value else {
            return Ok(None);
        };

        if value.is_empty() {
            return Err(JsError::InvalidConfig(format!(
                "consumer {field} must be non-empty when set"
            )));
        }

        // JetStream spec requirement: durable consumer names must be 1-128 characters
        let char_count = value.chars().count();
        if char_count > MAX_CONSUMER_NAME_CHARS {
            return Err(JsError::InvalidConfig(format!(
                "consumer {field} exceeds JetStream spec limit of {MAX_CONSUMER_NAME_CHARS} characters (got {char_count})"
            )));
        }

        // br-asupersync-w7n2qx: bound consumer-name length client-side.
        // The NATS server enforces its own cap (256 bytes per the
        // upstream nats-server defaults) but a buggy caller passing a
        // megabyte-long name would otherwise smuggle that string into
        // the JSON request body and the format!()-built subject before
        // the wire ever sees a server. A client-side cap turns that
        // into a typed configuration error at the call site.
        if value.len() > MAX_NAME_BYTES {
            return Err(JsError::InvalidConfig(format!(
                "consumer {field} exceeds {MAX_NAME_BYTES}-byte cap (got {} bytes)",
                value.len(),
            )));
        }

        // JetStream spec requirement: only valid UTF-8 alphanumeric + hyphen/underscore
        // Stricter validation per JetStream specification - only allow ASCII letters,
        // digits, hyphens, and underscores
        if value
            .chars()
            .any(|ch| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_'))
        {
            let fingerprint = redacted_name_fingerprint(value);
            return Err(JsError::InvalidConfig(format!(
                "consumer {field} must contain only ASCII letters, digits, '-' or '_' per JetStream spec (fingerprint {fingerprint}, {char_count} chars)"
            )));
        }

        Ok(Some(value))
    }

    /// br-asupersync-w7n2qx: validate a stream name with the same
    /// length + character-set rules that already apply to consumer
    /// names. Stream names flow through both the JSON request body
    /// (`json_escape`'d, so JSON-injection-safe) AND the NATS
    /// subject `format!("{}.STREAM.CREATE.{}", prefix, name)` — the
    /// subject path has no upstream escape, so a name containing
    /// `.`, `*`, `>` lands as a wildcard-bearing subject that the
    /// underlying NATS layer rejects with a confusing protocol
    /// error several layers down. Validating at the JetStream API
    /// boundary surfaces the typed `JsError::InvalidConfig` at the
    /// natural callsite and matches `ConsumerConfig::validate_consumer_name`.
    pub(crate) fn validate_stream_name(name: &str) -> Result<(), JsError> {
        if name.is_empty() {
            return Err(JsError::InvalidConfig(
                "stream name must be non-empty".to_string(),
            ));
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(JsError::InvalidConfig(format!(
                "stream name exceeds {MAX_NAME_BYTES}-byte cap (got {} bytes)",
                name.len(),
            )));
        }
        if name
            .chars()
            .any(|ch| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_'))
        {
            let fingerprint = redacted_name_fingerprint(name);
            return Err(JsError::InvalidConfig(format!(
                "stream name must contain only ASCII letters, digits, '-' or '_' (fingerprint {fingerprint})"
            )));
        }
        Ok(())
    }

    /// Encode to JSON for API request.
    fn to_json(&self) -> String {
        let mut json = String::from("{");
        let mut parts = Vec::new();

        if let Some(ref name) = self.name {
            parts.push(format!("\"name\":\"{}\"", json_escape(name)));
        }
        // The server makes a consumer durable only when durable_name is set;
        // with name alone it is a named ephemeral consumer, deleted after its
        // inactivity threshold (5 s by default). A named consumer here is
        // documented as durable, so it carries durable_name too.
        if let Some(durable) = self.durable_name.as_ref().or(self.name.as_ref()) {
            parts.push(format!("\"durable_name\":\"{}\"", json_escape(durable)));
        }
        if let Some(ref deliver_subject) = self.deliver_subject {
            parts.push(format!(
                "\"deliver_subject\":\"{}\"",
                json_escape(deliver_subject)
            ));
        }
        parts.push(format!(
            "\"deliver_policy\":\"{}\"",
            self.deliver_policy.as_str()
        ));
        match self.deliver_policy {
            DeliverPolicy::ByStartSequence(seq) => {
                parts.push(format!("\"opt_start_seq\":{seq}"));
            }
            DeliverPolicy::ByStartTime(start_time) => {
                parts.push(format!(
                    "\"opt_start_time\":\"{}\"",
                    json_escape(&format_system_time_rfc3339(start_time))
                ));
            }
            DeliverPolicy::All
            | DeliverPolicy::New
            | DeliverPolicy::Last
            | DeliverPolicy::LastPerSubject => {}
        }
        parts.push(format!("\"ack_policy\":\"{}\"", self.ack_policy.as_str()));
        parts.push(format!("\"ack_wait\":{}", self.ack_wait.as_nanos()));
        parts.push(format!("\"max_deliver\":{}", self.max_deliver));
        if let Some(rate_limit_bps) = self.rate_limit_bps {
            parts.push(format!("\"rate_limit_bps\":{rate_limit_bps}"));
        }
        parts.push(format!("\"max_ack_pending\":{}", self.max_ack_pending));
        if let Some(ref filter) = self.filter_subject {
            parts.push(format!("\"filter_subject\":\"{}\"", json_escape(filter)));
        }

        json.push_str(&parts.join(","));
        json.push('}');
        json
    }
}

/// Delivery policy for consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliverPolicy {
    /// Deliver all messages (default).
    #[default]
    All,
    /// Deliver only new messages.
    New,
    /// Deliver from a specific sequence.
    ByStartSequence(u64),
    /// Deliver from the first message on or after the given RFC3339 wall-clock time.
    ByStartTime(SystemTime),
    /// Deliver from last received.
    Last,
    /// Deliver from last per subject.
    LastPerSubject,
}

impl DeliverPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::New => "new",
            Self::ByStartSequence(_) => "by_start_sequence",
            Self::ByStartTime(_) => "by_start_time",
            Self::Last => "last",
            Self::LastPerSubject => "last_per_subject",
        }
    }
}

/// Ack policy for consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AckPolicy {
    /// Require explicit ack (default).
    #[default]
    Explicit,
    /// No ack required.
    None,
    /// Ack all messages up to this one.
    All,
}

impl AckPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::None => "none",
            Self::All => "all",
        }
    }
}

/// Publish acknowledgement from JetStream.
#[derive(Debug, Clone)]
pub struct PubAck {
    /// Stream the message was stored in.
    pub stream: String,
    /// Sequence number in the stream.
    pub seq: u64,
    /// Whether this was a duplicate.
    pub duplicate: bool,
}

/// A message from JetStream with ack capabilities.
pub struct JsMessage {
    /// Original NATS message.
    pub subject: String,
    /// Message payload.
    pub payload: Vec<u8>,
    /// Stream sequence number.
    pub sequence: u64,
    /// Delivery count.
    pub delivered: u32,
    /// Reply subject for ack.
    reply_subject: String,
    /// Terminal ack state for ack/nack/term transitions.
    ack_state: AtomicU8,
    /// Shared pending ack counter for flow control.
    pending_acks: Option<Arc<AtomicUsize>>,
}

impl fmt::Debug for JsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsMessage")
            .field("subject", &self.subject)
            .field("sequence", &self.sequence)
            .field("delivered", &self.delivered)
            .field("payload_len", &self.payload.len())
            .field("reply_subject", &self.reply_subject)
            .field("acked", &self.is_acked())
            .finish()
    }
}

impl JsMessage {
    /// Check if the message has been acknowledged.
    pub fn is_acked(&self) -> bool {
        self.ack_state.load(Ordering::Acquire) != ACK_STATE_PENDING
    }
}

impl Drop for JsMessage {
    fn drop(&mut self) {
        if self.ack_state.load(Ordering::Acquire) == ACK_STATE_PENDING {
            warn!(
                subject = %self.subject,
                sequence = self.sequence,
                "JetStream message dropped without ack/nack - will be redelivered"
            );
            // Decrement pending ack count for flow control
            if let Some(ref pending) = self.pending_acks {
                decrement_pending_counter(pending);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JetStreamPublishBackpressurePolicy {
    max_in_flight_publishes: usize,
    max_waiters: usize,
    emergency_max_in_flight_publishes: usize,
}

impl Default for JetStreamPublishBackpressurePolicy {
    fn default() -> Self {
        Self {
            max_in_flight_publishes: DEFAULT_MAX_IN_FLIGHT_PUBLISHES,
            max_waiters: DEFAULT_MAX_PUBLISH_WAITERS,
            emergency_max_in_flight_publishes: DEFAULT_EMERGENCY_MAX_IN_FLIGHT_PUBLISHES,
        }
    }
}

#[derive(Debug)]
struct JetStreamPublishBackpressureGate {
    policy: JetStreamPublishBackpressurePolicy,
    in_flight_publishes: AtomicUsize,
    refused_publishes: AtomicUsize,
}

impl JetStreamPublishBackpressureGate {
    fn new(policy: JetStreamPublishBackpressurePolicy) -> Self {
        Self {
            policy,
            in_flight_publishes: AtomicUsize::new(0),
            refused_publishes: AtomicUsize::new(0),
        }
    }

    fn pressure_level_label(cx: &Cx) -> &'static str {
        cx.pressure()
            .map_or("detached", crate::types::SystemPressure::level_label)
    }

    fn effective_max_in_flight_publishes(&self, cx: &Cx) -> usize {
        if cx
            .pressure()
            .is_some_and(|pressure| pressure.degradation_level() >= 4)
        {
            self.policy
                .emergency_max_in_flight_publishes
                .min(self.policy.max_in_flight_publishes)
        } else {
            self.policy.max_in_flight_publishes
        }
    }

    fn refuse(&self, cx: &Cx, subject: &str, current: usize, limit: usize) -> JsError {
        self.refused_publishes.fetch_add(1, Ordering::Relaxed);
        JsError::Api {
            code: 429,
            description: format!(
                "local publish backpressure: subject={subject} in_flight={current} limit={limit} \
                 max_waiters={} pressure={}",
                self.policy.max_waiters,
                Self::pressure_level_label(cx),
            ),
        }
    }

    fn begin_publish<'a>(
        &'a self,
        cx: &Cx,
        subject: &str,
    ) -> Result<JetStreamPublishPermit<'a>, JsError> {
        let limit = self.effective_max_in_flight_publishes(cx);
        let mut current = self.in_flight_publishes.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return Err(self.refuse(cx, subject, current, limit));
            }
            match self.in_flight_publishes.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(JetStreamPublishPermit { gate: self });
                }
                Err(observed) => {
                    current = observed;
                }
            }
        }
    }
}

struct JetStreamPublishPermit<'a> {
    gate: &'a JetStreamPublishBackpressureGate,
}

impl Drop for JetStreamPublishPermit<'_> {
    fn drop(&mut self) {
        self.gate
            .in_flight_publishes
            .fetch_sub(1, Ordering::Release);
    }
}

fn decrement_pending_counter(counter: &AtomicUsize) {
    let mut current = counter.load(Ordering::Relaxed);
    while current > 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// JetStream context for stream and consumer operations.
pub struct JetStreamContext {
    client: NatsClient,
    prefix: String,
    publish_backpressure: JetStreamPublishBackpressureGate,
}

impl fmt::Debug for JetStreamContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JetStreamContext")
            .field("prefix", &self.prefix)
            .field(
                "publish_backpressure_policy",
                &self.publish_backpressure.policy,
            )
            .finish_non_exhaustive()
    }
}

impl JetStreamContext {
    /// Create a new JetStream context from a NATS client.
    pub fn new(client: NatsClient) -> Self {
        Self {
            client,
            prefix: "$JS.API".to_string(),
            publish_backpressure: JetStreamPublishBackpressureGate::new(Default::default()),
        }
    }

    /// Create with a custom API prefix (for account isolation).
    pub fn with_prefix(client: NatsClient, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
            publish_backpressure: JetStreamPublishBackpressureGate::new(Default::default()),
        }
    }

    /// Create a stream.
    ///
    /// The server returns the existing stream when one with this name has an
    /// identical configuration, and refuses a different one; change an existing
    /// stream with [`Self::update_stream`]. The returned [`StreamInfo`] holds
    /// the configuration the server applied, including its defaults.
    pub async fn create_stream(
        &mut self,
        cx: &Cx,
        config: StreamConfig,
    ) -> Result<StreamInfo, JsError> {
        self.stream_config_request(cx, "CREATE", config).await
    }

    /// Update an existing stream's configuration.
    ///
    /// The server refuses an unknown stream ([`JsError::StreamNotFound`]) and
    /// changes it cannot apply in place, such as the storage type. The returned
    /// [`StreamInfo`] holds the configuration the server applied.
    pub async fn update_stream(
        &mut self,
        cx: &Cx,
        config: StreamConfig,
    ) -> Result<StreamInfo, JsError> {
        self.stream_config_request(cx, "UPDATE", config).await
    }

    async fn stream_config_request(
        &mut self,
        cx: &Cx,
        operation: &str,
        config: StreamConfig,
    ) -> Result<StreamInfo, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        config.validate()?;

        let subject = format!("{}.STREAM.{operation}.{}", self.prefix, config.name);
        let payload = config.to_json();

        let response = self
            .client
            .request(cx, &subject, payload.as_bytes())
            .await?;

        Self::parse_stream_info(&response.payload)
    }

    /// Get information about a stream.
    pub async fn get_stream(&mut self, cx: &Cx, name: &str) -> Result<StreamInfo, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        ConsumerConfig::validate_stream_name(name)?;
        let subject = format!("{}.STREAM.INFO.{}", self.prefix, name);
        let response = self.client.request(cx, &subject, b"").await?;

        Self::parse_stream_info(&response.payload)
    }

    /// Delete a stream.
    pub async fn delete_stream(&mut self, cx: &Cx, name: &str) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        ConsumerConfig::validate_stream_name(name)?;
        let subject = format!("{}.STREAM.DELETE.{}", self.prefix, name);
        let response = self.client.request(cx, &subject, b"").await?;

        // Check for error in response
        let response_str = String::from_utf8_lossy(&response.payload);
        if has_json_api_error(&response_str) {
            return Err(Self::parse_api_error(&response_str));
        }

        Ok(())
    }

    /// Publish a message to a stream with acknowledgement.
    pub async fn publish(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<PubAck, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let _permit = self.publish_backpressure.begin_publish(cx, subject)?;
        // JetStream publishes go to regular subjects, ack comes via reply
        let response = self.client.request(cx, subject, payload).await?;
        Self::parse_pub_ack(&response.payload)
    }

    /// Publish with a message ID for server-side deduplication.
    ///
    /// JetStream uses the `Nats-Msg-Id` header to detect duplicate publishes
    /// within the stream's `duplicate_window`. Two publishes with the same
    /// `msg_id` to the same stream within that window are coalesced — the
    /// second response carries the original sequence number and a flag
    /// indicating it was a duplicate. This is the runtime's path to
    /// dedup / exactly-once-style delivery on top of JetStream's underlying
    /// at-least-once contract (br-asupersync-byc2d1).
    ///
    /// Requires the connected NATS server to advertise `headers:true` in
    /// its INFO frame (NATS 2.2+); older brokers cause an immediate
    /// `Protocol` error rather than a silent duplicate.
    pub async fn publish_with_id(
        &mut self,
        cx: &Cx,
        subject: &str,
        msg_id: &str,
        payload: &[u8],
    ) -> Result<PubAck, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if msg_id.is_empty() {
            return Err(JsError::InvalidConfig(
                "publish_with_id: msg_id must be non-empty".to_string(),
            ));
        }

        let _permit = self.publish_backpressure.begin_publish(cx, subject)?;
        let headers: [(&str, &[u8]); 1] = [("Nats-Msg-Id", msg_id.as_bytes())];
        let response = self
            .client
            .request_with_headers(cx, subject, &headers, payload)
            .await?;
        Self::parse_pub_ack(&response.payload)
    }

    /// Create a consumer on a stream.
    pub async fn create_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        mut config: ConsumerConfig,
    ) -> Result<Consumer, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        ConsumerConfig::validate_stream_name(stream)?;
        config.validate()?;
        let consumer_name = config.name.clone().unwrap_or_default();
        let subject = if consumer_name.is_empty() {
            format!("{}.CONSUMER.CREATE.{}", self.prefix, stream)
        } else {
            format!(
                "{}.CONSUMER.CREATE.{}.{}",
                self.prefix, stream, consumer_name
            )
        };

        let payload = format!(
            "{{\"stream_name\":\"{}\",\"config\":{}}}",
            json_escape(stream),
            config.to_json()
        );
        let response = self
            .client
            .request(cx, &subject, payload.as_bytes())
            .await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if has_json_api_error(&response_str) {
            return Err(Self::parse_api_error(&response_str));
        }

        // Extract consumer name from response
        let name = extract_json_string_simple(&response_str, "name")
            .unwrap_or_else(|| consumer_name.clone());

        Ok(Consumer {
            stream: stream.to_string(),
            name,
            prefix: self.prefix.clone(),
            pending_acks: Arc::new(AtomicUsize::new(0)),
            max_ack_pending: local_max_ack_pending(config.max_ack_pending),
            pull_rate_limiter: PullRateLimiter::new(),
        })
    }

    /// Get an existing consumer.
    pub async fn get_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        consumer: &str,
    ) -> Result<Consumer, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.CONSUMER.INFO.{}.{}", self.prefix, stream, consumer);
        let response = self.client.request(cx, &subject, b"").await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if has_json_api_error(&response_str) {
            return Err(Self::parse_api_error(&response_str));
        }

        // Extract max_ack_pending from consumer info response, fallback to default
        let max_ack_pending = local_max_ack_pending(
            extract_json_i64_simple(&response_str, "max_ack_pending").unwrap_or(1000),
        );

        Ok(Consumer {
            stream: stream.to_string(),
            name: consumer.to_string(),
            prefix: self.prefix.clone(),
            pending_acks: Arc::new(AtomicUsize::new(0)),
            max_ack_pending,
            pull_rate_limiter: PullRateLimiter::new(),
        })
    }

    /// Delete a consumer.
    pub async fn delete_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        consumer: &str,
    ) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.CONSUMER.DELETE.{}.{}", self.prefix, stream, consumer);
        let response = self.client.request(cx, &subject, b"").await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if has_json_api_error(&response_str) {
            return Err(Self::parse_api_error(&response_str));
        }

        Ok(())
    }

    /// Get the underlying NATS client (for direct operations).
    pub fn client(&mut self) -> &mut NatsClient {
        &mut self.client
    }

    fn parse_stream_info(payload: &[u8]) -> Result<StreamInfo, JsError> {
        let json = String::from_utf8_lossy(payload);

        if has_json_api_error(&json) {
            return Err(Self::parse_api_error(&json));
        }

        // The server reports the configuration it applied under `config` and
        // the counters under `state` (k6pxks item 19); a reply without them is
        // read flat, as before.
        let config_json = extract_json_object(&json, "config").unwrap_or(&*json);
        let state_json = extract_json_object(&json, "state").unwrap_or(&*json);
        let name = extract_json_string_simple(config_json, "name")
            .ok_or_else(|| JsError::ParseError("missing stream name".to_string()))?;

        let state = StreamState {
            messages: extract_json_u64(state_json, "messages").unwrap_or(0),
            bytes: extract_json_u64(state_json, "bytes").unwrap_or(0),
            first_seq: extract_json_u64(state_json, "first_seq").unwrap_or(0),
            last_seq: extract_json_u64(state_json, "last_seq").unwrap_or(0),
            consumer_count: extract_json_u64(state_json, "consumer_count")
                .unwrap_or(0)
                .min(u64::from(u32::MAX)) as u32,
        };

        Ok(StreamInfo {
            config: StreamConfig::from_server_json(name, config_json),
            state,
        })
    }

    fn parse_pub_ack(payload: &[u8]) -> Result<PubAck, JsError> {
        let json = String::from_utf8_lossy(payload);

        if has_json_api_error(&json) {
            return Err(Self::parse_api_error(&json));
        }

        let stream = extract_json_string_simple(&json, "stream")
            .ok_or_else(|| JsError::ParseError("missing stream in PubAck".to_string()))?;
        let seq = extract_json_u64(&json, "seq")
            .ok_or_else(|| JsError::ParseError("missing seq in PubAck".to_string()))?;
        let duplicate = extract_json_bool(&json, "duplicate").unwrap_or(false);

        Ok(PubAck {
            stream,
            seq,
            duplicate,
        })
    }

    fn parse_api_error(json: &str) -> JsError {
        let error_json = extract_json_object(json, "error").unwrap_or(json);
        let code = extract_json_u64(error_json, "code").unwrap_or(0) as u32;
        // JetStream uses `err_code` for application-level error codes (e.g.,
        // 10059 = stream not found).  The `code` field is the HTTP-style
        // status (404, 500, etc.).
        let err_code = extract_json_u64(error_json, "err_code").unwrap_or(0) as u32;
        let description = extract_json_string_simple(error_json, "description")
            .unwrap_or_else(|| "unknown error".to_string());

        if err_code == 10059 {
            // Stream not found
            return JsError::StreamNotFound(description);
        }

        JsError::Api { code, description }
    }
}

/// A JetStream consumer for pulling messages.
pub struct Consumer {
    stream: String,
    name: String,
    prefix: String,
    /// Client-side pending ack counter for flow control (shared with messages).
    pending_acks: Arc<AtomicUsize>,
    /// Maximum pending acks allowed (from ConsumerConfig).
    max_ack_pending: usize,
    /// Pull rate limiter to prevent DoS via rapid pull requests.
    pull_rate_limiter: PullRateLimiter,
}

impl fmt::Debug for Consumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumer")
            .field("stream", &self.stream)
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .field("pending_acks", &self.pending_acks.load(Ordering::Relaxed))
            .field("max_ack_pending", &self.max_ack_pending)
            .field(
                "rate_limiting_active",
                &self.pull_rate_limiter.is_rate_limiting_active(),
            )
            .finish()
    }
}

impl Consumer {
    /// Default timeout for pull operations.
    pub const DEFAULT_PULL_TIMEOUT: Duration = Duration::from_secs(30);
    /// Extra time to allow server-side expiry/status messages to arrive.
    const CLIENT_TIMEOUT_SLACK: Duration = Duration::from_millis(100);

    // DoS Protection Implementation (asupersync-uculjz):
    //
    // This Consumer implementation includes comprehensive protection against
    // DoS attacks via pull batch size manipulation:
    //
    // 1. Per-Consumer Rate Limiting:
    //    - Enforces minimum 50ms interval between pull requests per consumer
    //    - Applies exponential backoff for rapid requests (1.5x multiplier, max 5s)
    //    - Tracks request history and activates rate limiting on abuse
    //
    // 2. Dynamic Batch Size Clamping:
    //    - Reduces batch sizes by up to 50% under rate limiting pressure
    //    - Monitors global memory usage and clamps batches under memory pressure
    //    - Maintains minimum viable batch size (16 messages) for functionality
    //
    // 3. Global Rate Limiting:
    //    - System-wide limit of 1000 pull requests/second across all consumers
    //    - Tracks recent request timestamps in circular buffer
    //    - Prevents cascade failure from overwhelming the JetStream cluster
    //
    // 4. Memory Pressure Monitoring:
    //    - Estimates memory usage per pull request (2KB per message)
    //    - Triggers progressive batch size reduction above 256MB threshold
    //    - Rejects requests that would exceed 512MB total memory usage
    //
    // 5. Exponential Backoff Strategy:
    //    - Rapid requests trigger progressively longer delays
    //    - Automatic recovery when request rate normalizes
    //    - Prevents both rapid-fire attacks and legitimate traffic starvation

    /// Get the consumer name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the stream name.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Get current pending acks count.
    #[must_use]
    pub fn pending_acks(&self) -> usize {
        self.pending_acks.load(Ordering::Relaxed)
    }

    /// Check if we can accept more messages based on max_ack_pending limit.
    #[must_use]
    pub fn can_accept_message(&self) -> bool {
        self.pending_acks.load(Ordering::Relaxed) < self.max_ack_pending
    }

    /// Admits a pulled message under `max_ack_pending`, or drops it.
    ///
    /// A refused message is dropped with its counter handle detached:
    /// `increment_pending` already rolled back its own increment, and the
    /// message's `Drop` decrementing again freed a slot held by another
    /// outstanding message (br-asupersync-pm29wb).
    fn admit_pulled_message(&self, mut js_msg: JsMessage) -> Option<JsMessage> {
        if self.increment_pending() {
            return Some(js_msg);
        }
        warn!(
            stream = %self.stream,
            consumer = %self.name,
            pending = self.pending_acks(),
            max_ack_pending = self.max_ack_pending,
            sequence = js_msg.sequence,
            "JetStream flow control: dropping message - max_ack_pending exceeded"
        );
        js_msg.pending_acks = None;
        None
    }

    /// Increment pending ack count (called when receiving a message).
    fn increment_pending(&self) -> bool {
        let current = self.pending_acks.fetch_add(1, Ordering::Relaxed);
        if current >= self.max_ack_pending {
            // Rollback the increment if we exceeded the limit
            self.pending_acks.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    /// Decrement pending ack count (called when ack/nack).
    #[cfg(any(test, feature = "test-internals"))]
    fn decrement_pending(&self) {
        decrement_pending_counter(&self.pending_acks);
    }

    /// Acknowledge a message and update pending ack count.
    ///
    /// This is the flow-control-aware version of `JsMessage::ack()`.
    pub async fn ack_message(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        msg: &JsMessage,
    ) -> Result<(), JsError> {
        msg.ack(client, cx).await
    }

    /// Negative acknowledge a message and update pending ack count.
    ///
    /// This is the flow-control-aware version of `JsMessage::nack()`.
    pub async fn nack_message(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        msg: &JsMessage,
    ) -> Result<(), JsError> {
        msg.nack(client, cx).await
    }

    /// Negative acknowledge a message with delay and update pending ack count.
    ///
    /// This is the flow-control-aware version of `JsMessage::nack_with_delay()`.
    pub async fn nack_message_with_delay(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        msg: &JsMessage,
        delay: Duration,
    ) -> Result<(), JsError> {
        msg.nack_with_delay(client, cx, delay).await
    }

    /// Pull a batch of messages.
    pub async fn pull(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        batch: usize,
    ) -> Result<Vec<JsMessage>, JsError> {
        self.pull_with_timeout(client, cx, batch, Self::DEFAULT_PULL_TIMEOUT)
            .await
    }

    /// Pull a batch of messages with a timeout.
    ///
    /// A zero duration disables the client-side timeout and sets JetStream
    /// `expires` to 0 (no expiry). Use a non-zero duration to bound the request.
    pub async fn pull_with_timeout(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        batch: usize,
        pull_timeout: Duration,
    ) -> Result<Vec<JsMessage>, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // DoS Protection Step 1: Rate limiting check
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        if let Err(delay) = self.pull_rate_limiter.check_pull_request(now_ns) {
            return Err(JsError::InvalidConfig(format!(
                "JetStream pull request rate limited - retry after {}ms",
                delay.as_millis()
            )));
        }

        // DoS Protection Step 2: Enhanced batch size validation with dynamic clamping
        let effective_batch = validate_and_clamp_pull_batch_size(batch, self)?;

        // DoS Protection Step 3: Global rate limiting and memory pressure check
        let estimated_batch_memory = effective_batch as u64 * 2048; // Rough estimate: 2KB per message
        {
            let mut global_tracker = GLOBAL_PULL_RATE_TRACKER.lock().unwrap();
            if let Err(delay) =
                global_tracker.check_global_pull_request(now_ns, estimated_batch_memory)
            {
                return Err(JsError::InvalidConfig(format!(
                    "JetStream global rate limit or memory pressure - retry after {}ms",
                    delay.as_millis()
                )));
            }
        }
        let _reservation = GlobalPullReservation(estimated_batch_memory);

        let subject = format!(
            "{}.CONSUMER.MSG.NEXT.{}.{}",
            self.prefix, self.stream, self.name
        );
        let expires = if pull_timeout.is_zero() {
            0_i64
        } else {
            let nanos = pull_timeout.as_nanos();
            let max = i64::MAX as u128;
            let clamped = if nanos > max { max } else { nanos };
            clamped as i64
        };
        let request = build_pull_request_json(effective_batch, expires, None);

        // Subscribe to get batch responses. A message dropped by a full inbox
        // is redelivered only after ack_wait, or lost with AckNone.
        let mut sub = client
            .subscribe_with_capacity(
                cx,
                &format!("_INBOX.{}", random_id(cx)),
                pull_inbox_capacity(effective_batch),
            )
            .await?;
        let sid = sub.sid();
        if let Err(err) = client
            .publish_request(cx, &subject, sub.subject(), request.as_bytes())
            .await
        {
            let _ = client.unsubscribe(cx, sid).await;
            return Err(err.into());
        }

        let mut messages = Vec::with_capacity(effective_batch);
        let mut pull_state = PullSubscriberState::new(effective_batch);
        let now = cx
            .timer_driver()
            .map_or_else(wall_now, |driver| driver.now());
        let client_deadline =
            compute_client_deadline(now, pull_timeout, Self::CLIENT_TIMEOUT_SLACK);

        // Collect messages until we get batch or timeout.
        // A live JetStream broker only delivers pull responses once the
        // underlying NATS socket is actively pumped; awaiting `sub.next()`
        // alone is insufficient because nothing reads frames off the wire.
        // Keep driving the client via `process()` and only break on timeout,
        // connection close, or a real protocol/server error.
        loop {
            if !pull_state.is_active() {
                break;
            }

            while pull_state.is_active() && pull_state.received() < effective_batch {
                let Some(msg) = sub.try_next() else {
                    break;
                };
                // Status replies carry no reply subject, so they were taken
                // for foreign messages and the pull waited out its timeout,
                // returning no error even for a deleted consumer.
                match super::nats::status_reply(&msg) {
                    // No messages (404), or the request expired on the server
                    // (408): the pull is over and returns what it has.
                    Some((404 | 408, _)) => {
                        pull_state.observe_request_end();
                        continue;
                    }
                    // 409 (consumer deleted, a pull limit exceeded), 503 (no
                    // JetStream responders) and the rest fail the pull.
                    Some((_, error)) => {
                        pull_state.observe_error(JsError::Nats(error));
                        continue;
                    }
                    None => {}
                }
                if let Some(js_msg) = Self::parse_js_message(msg, Some(self.pending_acks.clone())) {
                    // Flow control: check if we can accept this message
                    if let Some(js_msg) = self.admit_pulled_message(js_msg) {
                        messages.push(js_msg);
                        pull_state.observe_parsed_message();
                    } else {
                        pull_state.observe_ignored_message();
                    }
                } else {
                    pull_state.observe_ignored_message();
                }
            }

            if !pull_state.is_active() {
                break;
            }

            let process_result = if let Some(deadline) = client_deadline {
                let next = std::pin::pin!(client.process(cx));
                timeout_at(deadline, next).await
            } else {
                Ok(client.process(cx).await)
            };

            match process_result {
                Ok(Ok(())) => pull_state.observe_process_ready(),
                Ok(Err(NatsError::Closed)) => pull_state.observe_closed(),
                Err(_) => pull_state.observe_timeout(),
                Ok(Err(err)) => pull_state.observe_error(err.into()),
            }
        }

        #[allow(unused_variables)] // err used by warn! macro when tracing is enabled
        if let Err(err) = client.unsubscribe(cx, sid).await {
            warn!(
                subject = %sub.subject(),
                sid,
                error = ?err,
                "JetStream pull unsubscribe failed"
            );
            #[cfg(not(feature = "tracing-integration"))]
            let _ = &err;
        }

        finish_pull(messages, pull_state)
    }

    fn parse_js_message(msg: Message, pending_acks: Option<Arc<AtomicUsize>>) -> Option<JsMessage> {
        // JetStream messages have metadata in headers (reply subject format)
        // Format: $JS.ACK.<stream>.<consumer>.<delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>
        // Note: stream and consumer names may contain dots, so we parse
        // the 5 trailing numeric fields from the right rather than using
        // fixed left-hand indices.
        let reply = msg.reply_to?;

        if !reply.starts_with("$JS.ACK.") {
            return None;
        }

        let parts: Vec<&str> = reply.split('.').collect();
        // $JS (0), ACK (1), <stream..> , <consumer..>, delivered, stream_seq,
        // consumer_seq, timestamp, pending => at least 9 tokens when stream
        // and consumer are each a single segment; with dotted names there
        // will be more. The last 5 tokens are always the numeric fields.
        if parts.len() < 9 {
            return None;
        }

        // The v2 form, $JS.ACK.<domain>.<account hash>.<stream>.<consumer>.
        // <delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>.<token>,
        // has at least 12 tokens and ends in a random token. Read from the tail,
        // it put the stream sequence in `delivered` (dropping the message once
        // it no longer fit a u32) and the consumer sequence in `sequence`. As
        // nats.go does, 12 or more tokens are read by position. Shorter
        // subjects are read from the tail: pending(-1), timestamp(-2),
        // consumer_seq(-3), stream_seq(-4), delivered(-5).
        let (delivered, sequence) = if parts.len() >= 12 {
            (parts[6], parts[7])
        } else {
            (parts[parts.len() - 5], parts[parts.len() - 4])
        };
        let delivered: u32 = delivered.parse().ok()?;
        let sequence: u64 = sequence.parse().ok()?;

        Some(JsMessage {
            subject: msg.subject,
            payload: msg.payload,
            sequence,
            delivered,
            reply_subject: reply,
            ack_state: AtomicU8::new(ACK_STATE_PENDING),
            pending_acks,
        })
    }
}

fn finish_pull(
    messages: Vec<JsMessage>,
    pull_state: PullSubscriberState,
) -> Result<Vec<JsMessage>, JsError> {
    // A client-side fetch timeout only bounds this pull request. It is not
    // enough evidence to classify the consumer or stream as invalid.
    pull_state.result().map(|()| messages)
}

#[derive(Debug)]
struct PullSubscriberState {
    batch: usize,
    received: usize,
    termination: PullSubscriberTermination,
    error: Option<JsError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PullSubscriberTermination {
    Active,
    Completed,
    Closed,
    TimedOut,
    Error,
}

impl PullSubscriberState {
    fn new(batch: usize) -> Self {
        debug_assert!(batch > 0);
        Self {
            batch,
            received: 0,
            termination: PullSubscriberTermination::Active,
            error: None,
        }
    }

    fn received(&self) -> usize {
        self.received
    }

    fn is_active(&self) -> bool {
        matches!(self.termination, PullSubscriberTermination::Active)
    }

    #[cfg(any(test, feature = "test-internals"))]
    fn termination(&self) -> PullSubscriberTermination {
        self.termination
    }

    fn observe_parsed_message(&mut self) {
        if !self.is_active() {
            return;
        }
        self.received = self.received.saturating_add(1).min(self.batch);
        if self.received >= self.batch {
            self.termination = PullSubscriberTermination::Completed;
        }
    }

    fn observe_ignored_message(&mut self) {}

    /// The server ended the pull request (no messages, or it expired).
    fn observe_request_end(&mut self) {
        if self.is_active() {
            self.termination = PullSubscriberTermination::Completed;
        }
    }

    fn observe_process_ready(&mut self) {}

    fn observe_closed(&mut self) {
        if self.is_active() {
            self.termination = PullSubscriberTermination::Closed;
        }
    }

    fn observe_timeout(&mut self) {
        if self.is_active() {
            self.termination = PullSubscriberTermination::TimedOut;
        }
    }

    fn observe_error(&mut self, err: JsError) {
        if self.is_active() {
            self.termination = PullSubscriberTermination::Error;
            self.error = Some(err);
        }
    }

    fn result(self) -> Result<(), JsError> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

const ACK_STATE_PENDING: u8 = 0;
const ACK_STATE_ACK_IN_FLIGHT: u8 = 1;
const ACK_STATE_ACKED: u8 = 2;
const ACK_STATE_NAK_IN_FLIGHT: u8 = 3;
const ACK_STATE_NAKED: u8 = 4;
const ACK_STATE_TERM_IN_FLIGHT: u8 = 5;
const ACK_STATE_TERMED: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalAckKind {
    Ack,
    Nak,
    Term,
}

impl TerminalAckKind {
    const fn in_flight_state(self) -> u8 {
        match self {
            Self::Ack => ACK_STATE_ACK_IN_FLIGHT,
            Self::Nak => ACK_STATE_NAK_IN_FLIGHT,
            Self::Term => ACK_STATE_TERM_IN_FLIGHT,
        }
    }

    const fn committed_state(self) -> u8 {
        match self {
            Self::Ack => ACK_STATE_ACKED,
            Self::Nak => ACK_STATE_NAKED,
            Self::Term => ACK_STATE_TERMED,
        }
    }

    const fn is_idempotent(self) -> bool {
        matches!(self, Self::Ack)
    }
}

/// br-asupersync-c2gquz — compact JetStream ACK metadata returned by the real
/// reply-subject parser for fuzz harnesses.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzJsAckMetadata {
    /// Original published subject.
    pub subject: String,
    /// Parsed JetStream stream sequence number.
    pub sequence: u64,
    /// Parsed JetStream delivery count.
    pub delivered: u32,
    /// Payload length carried by the source NATS message.
    pub payload_len: usize,
}

/// br-asupersync-c2gquz — fuzz-target re-exporter for the StreamInfo parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_stream_info(payload: &[u8]) -> Result<StreamInfo, JsError> {
    JetStreamContext::parse_stream_info(payload)
}

/// br-asupersync-c2gquz — fuzz-target re-exporter for the PubAck parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_pub_ack(payload: &[u8]) -> Result<PubAck, JsError> {
    JetStreamContext::parse_pub_ack(payload)
}

/// br-asupersync-c2gquz — fuzz-target re-exporter for the API error parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_api_error(json: &str) -> JsError {
    JetStreamContext::parse_api_error(json)
}

/// br-asupersync-c2gquz — fuzz-target re-exporter for the JetStream ACK reply
/// subject parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_js_message(msg: Message) -> Option<FuzzJsAckMetadata> {
    Consumer::parse_js_message(msg, None).map(|parsed| FuzzJsAckMetadata {
        subject: parsed.subject.clone(),
        sequence: parsed.sequence,
        delivered: parsed.delivered,
        payload_len: parsed.payload.len(),
    })
}

/// br-asupersync-6ba4qs — compact control-token classification for JetStream
/// ack payload fuzzing.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzJsAckControl {
    Ack,
    Nak,
    InProgress,
    Term,
    Unknown,
}

/// br-asupersync-6ba4qs — fuzz-target re-exporter for JetStream ack control
/// payload parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_ack_control(payload: &[u8]) -> FuzzJsAckControl {
    match payload {
        b"+ACK" => FuzzJsAckControl::Ack,
        b"-NAK" => FuzzJsAckControl::Nak,
        b"+WPI" => FuzzJsAckControl::InProgress,
        b"+TERM" => FuzzJsAckControl::Term,
        _ => FuzzJsAckControl::Unknown,
    }
}

/// Fuzz-target re-exporter for durable consumer-name validation and alias
/// canonicalization.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_normalize_consumer_identity(
    name: Option<&str>,
    durable_name: Option<&str>,
) -> Result<Option<String>, JsError> {
    let mut config = ConsumerConfig::ephemeral();
    config.name = name.map(ToOwned::to_owned);
    config.durable_name = durable_name.map(ToOwned::to_owned);
    config.normalize_identity()?;
    Ok(config.name)
}

/// Conformance-target re-exporter for the full JetStream ConsumerConfig
/// validation boundary used by `create_consumer`.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_consumer_config(
    name: Option<&str>,
    durable_name: Option<&str>,
    filter_subject: Option<&str>,
) -> Result<Option<String>, String> {
    let mut config = ConsumerConfig::ephemeral();
    config.name = name.map(ToOwned::to_owned);
    config.durable_name = durable_name.map(ToOwned::to_owned);
    config.filter_subject = filter_subject.map(ToOwned::to_owned);
    config.validate().map_err(|err| err.to_string())?;
    Ok(config.name)
}

/// Conformance-target re-exporter for push-consumer validation boundaries.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_push_consumer_config(
    name: Option<&str>,
    durable_name: Option<&str>,
    deliver_subject: Option<&str>,
    filter_subject: Option<&str>,
    rate_limit_bps: Option<u64>,
) -> Result<Option<String>, String> {
    let mut config = ConsumerConfig::ephemeral();
    config.name = name.map(ToOwned::to_owned);
    config.durable_name = durable_name.map(ToOwned::to_owned);
    config.deliver_subject = deliver_subject.map(ToOwned::to_owned);
    config.filter_subject = filter_subject.map(ToOwned::to_owned);
    config.rate_limit_bps = rate_limit_bps;
    config.validate().map_err(|err| err.to_string())?;
    Ok(config.name)
}

/// Fuzz-target re-exporter for the JetStream stream-name length cap.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub const fn fuzz_stream_name_max_bytes() -> usize {
    MAX_NAME_BYTES
}

/// Fuzz-target re-exporter for JetStream stream-name validation.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_stream_name(name: &str) -> Result<(), String> {
    ConsumerConfig::validate_stream_name(name).map_err(|err| err.to_string())
}

/// Fuzz-target re-exporter for the JetStream stream subject byte cap.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub const fn fuzz_stream_subject_max_bytes() -> usize {
    MAX_STREAM_SUBJECT_BYTES
}

/// Fuzz-target re-exporter for whole-stream configuration validation.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_stream_config(config: &StreamConfig) -> Result<String, String> {
    config.validate().map_err(|err| err.to_string())?;
    Ok(config.to_json())
}

/// Fuzz-target formatter export for DeliverByStartTime wall-clock serialization.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_format_deliver_by_start_time_rfc3339(time: SystemTime) -> String {
    format_system_time_rfc3339(time)
}

/// Fuzz-target JSON export for DeliverByStartTime consumer configuration.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_consumer_config_deliver_by_start_time_json(time: SystemTime) -> String {
    ConsumerConfig::ephemeral()
        .deliver_policy(DeliverPolicy::ByStartTime(time))
        .to_json()
}

/// Compact snapshot of the publish-side backpressure gate for audit and fuzz
/// harnesses.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzJetStreamPublishBackpressureSnapshot {
    pub effective_max_in_flight_publishes: usize,
    pub max_waiters: usize,
    pub acquired: bool,
    pub in_flight_publishes_after: usize,
    pub refused_publishes: usize,
    pub pressure_level: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "test-internals")]
fn quantile_from_sorted_micros(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let span = samples.len().saturating_sub(1);
    let rank = (span.saturating_mul(numerator) + denominator.saturating_sub(1)) / denominator;
    samples[rank]
}

/// Deterministic tail-evidence snapshot for the current refusal-only publish
/// policy. The modeled wait is exact because this controller never parks
/// waiters: each attempt either acquires immediately or is refused immediately.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzJetStreamPublishBackpressureTailSnapshot {
    pub tail_sample_count: usize,
    pub accepted_count: usize,
    pub refused_count: usize,
    pub waiter_queue_absent: bool,
    pub waiter_fairness_mode: String,
    pub refusal_only_policy: bool,
    pub tail_evidence_mode: String,
    pub pressure_level: Option<String>,
    pub publish_wait_latency_p95_micros: u64,
    pub publish_wait_latency_p99_micros: u64,
    pub publish_wait_latency_p999_micros: u64,
}

/// Deterministic cohort-tail snapshot for the current refusal-only publish
/// policy across many independent JetStream contexts. This is a finite-capacity
/// M/G/1/1 loss-system certificate per publisher: no waiter queue exists, so
/// each publisher either acquires immediately or is refused immediately.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzJetStreamPublishBackpressureCohortSnapshot {
    pub publisher_count: usize,
    pub occupied_publisher_count: usize,
    pub accepted_count: usize,
    pub refused_count: usize,
    pub waiter_queue_absent: bool,
    pub waiter_fairness_mode: String,
    pub refusal_only_policy: bool,
    pub queueing_model: String,
    pub multi_publisher_tail_evidence_present: bool,
    pub publish_wait_latency_p95_micros: u64,
    pub publish_wait_latency_p99_micros: u64,
    pub publish_wait_latency_p999_micros: u64,
}

/// Test-internals probe for the publish-side backpressure controller.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_probe_publish_backpressure(
    pressure_headroom: Option<f32>,
    preexisting_in_flight_publishes: usize,
) -> FuzzJetStreamPublishBackpressureSnapshot {
    let gate = JetStreamPublishBackpressureGate::new(Default::default());
    gate.in_flight_publishes
        .store(preexisting_in_flight_publishes, Ordering::Relaxed);

    let mut cx = Cx::new(
        crate::types::RegionId::new_for_test(0, 1),
        crate::types::TaskId::testing_default(),
        crate::types::Budget::INFINITE,
    );
    let pressure_level = if let Some(headroom) = pressure_headroom {
        let pressure = Arc::new(crate::types::SystemPressure::with_headroom(headroom));
        let label = pressure.level_label().to_string();
        cx = cx.with_pressure(pressure);
        Some(label)
    } else {
        None
    };

    let effective_max_in_flight_publishes = gate.effective_max_in_flight_publishes(&cx);
    let probe = gate.begin_publish(&cx, "audit.subject");
    let (acquired, error) = match probe {
        Ok(permit) => {
            drop(permit);
            (true, None)
        }
        Err(err) => (false, Some(err.to_string())),
    };

    FuzzJetStreamPublishBackpressureSnapshot {
        effective_max_in_flight_publishes,
        max_waiters: gate.policy.max_waiters,
        acquired,
        in_flight_publishes_after: gate.in_flight_publishes.load(Ordering::Relaxed),
        refused_publishes: gate.refused_publishes.load(Ordering::Relaxed),
        pressure_level,
        error,
    }
}

/// Deterministic tail-evidence probe for the current publish-side refusal
/// controller.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_probe_publish_backpressure_tail_evidence(
    pressure_headroom: Option<f32>,
    preexisting_in_flight_publishes: usize,
    attempts: usize,
) -> FuzzJetStreamPublishBackpressureTailSnapshot {
    let gate = JetStreamPublishBackpressureGate::new(Default::default());
    gate.in_flight_publishes
        .store(preexisting_in_flight_publishes, Ordering::Relaxed);

    let mut cx = Cx::new(
        crate::types::RegionId::new_for_test(0, 1),
        crate::types::TaskId::testing_default(),
        crate::types::Budget::INFINITE,
    );
    let pressure_level = if let Some(headroom) = pressure_headroom {
        let pressure = Arc::new(crate::types::SystemPressure::with_headroom(headroom));
        let label = pressure.level_label().to_string();
        cx = cx.with_pressure(pressure);
        Some(label)
    } else {
        None
    };

    let attempts = attempts.max(1);
    let mut accepted_count = 0usize;
    let mut wait_samples_micros = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        match gate.begin_publish(&cx, "audit.subject") {
            Ok(permit) => {
                accepted_count += 1;
                wait_samples_micros.push(0);
                drop(permit);
            }
            Err(_) => {
                wait_samples_micros.push(0);
            }
        }
    }
    wait_samples_micros.sort_unstable();

    FuzzJetStreamPublishBackpressureTailSnapshot {
        tail_sample_count: wait_samples_micros.len(),
        accepted_count,
        refused_count: gate.refused_publishes.load(Ordering::Relaxed),
        waiter_queue_absent: DEFAULT_MAX_PUBLISH_WAITERS == 0,
        waiter_fairness_mode: "vacuous_zero_wait_refusal".to_string(),
        refusal_only_policy: DEFAULT_MAX_PUBLISH_WAITERS == 0,
        tail_evidence_mode: "zero_wait_refusal_only".to_string(),
        pressure_level,
        publish_wait_latency_p95_micros: quantile_from_sorted_micros(&wait_samples_micros, 95, 100),
        publish_wait_latency_p99_micros: quantile_from_sorted_micros(&wait_samples_micros, 99, 100),
        publish_wait_latency_p999_micros: quantile_from_sorted_micros(
            &wait_samples_micros,
            999,
            1000,
        ),
    }
}

/// Deterministic multi-publisher tail-evidence probe for the current
/// conservative refusal-only controller.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_probe_publish_backpressure_cohort_tail_evidence(
    publisher_count: usize,
    occupied_publisher_count: usize,
) -> FuzzJetStreamPublishBackpressureCohortSnapshot {
    let publisher_count = publisher_count.max(1);
    let occupied_publisher_count = occupied_publisher_count.min(publisher_count);
    let mut wait_samples_micros = Vec::with_capacity(publisher_count);
    let mut accepted_count = 0usize;
    let mut refused_count = 0usize;

    for publisher_index in 0..publisher_count {
        let gate = JetStreamPublishBackpressureGate::new(Default::default());
        if publisher_index < occupied_publisher_count {
            gate.in_flight_publishes.store(1, Ordering::Relaxed);
        }
        let cx = Cx::new(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::testing_default(),
            crate::types::Budget::INFINITE,
        );
        match gate.begin_publish(&cx, "audit.subject") {
            Ok(permit) => {
                accepted_count += 1;
                wait_samples_micros.push(0);
                drop(permit);
            }
            Err(_) => {
                refused_count += 1;
                wait_samples_micros.push(0);
            }
        }
    }

    wait_samples_micros.sort_unstable();
    FuzzJetStreamPublishBackpressureCohortSnapshot {
        publisher_count,
        occupied_publisher_count,
        accepted_count,
        refused_count,
        waiter_queue_absent: DEFAULT_MAX_PUBLISH_WAITERS == 0,
        waiter_fairness_mode: "vacuous_zero_wait_refusal".to_string(),
        refusal_only_policy: DEFAULT_MAX_PUBLISH_WAITERS == 0,
        queueing_model: "mg11_loss_system".to_string(),
        multi_publisher_tail_evidence_present: true,
        publish_wait_latency_p95_micros: quantile_from_sorted_micros(&wait_samples_micros, 95, 100),
        publish_wait_latency_p99_micros: quantile_from_sorted_micros(&wait_samples_micros, 99, 100),
        publish_wait_latency_p999_micros: quantile_from_sorted_micros(
            &wait_samples_micros,
            999,
            1000,
        ),
    }
}

/// Test-internals constructor for a minimal consumer with a configurable
/// `max_ack_pending` budget.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_create_test_consumer(max_ack_pending: usize) -> Consumer {
    Consumer {
        stream: "TEST_STREAM".to_string(),
        name: "test_consumer".to_string(),
        prefix: "$JS.API".to_string(),
        pending_acks: Arc::new(AtomicUsize::new(0)),
        max_ack_pending: max_ack_pending.max(1),
        pull_rate_limiter: PullRateLimiter::new(),
    }
}

/// Test-internals getter for the consumer-side `max_ack_pending` limit.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_consumer_max_ack_pending(consumer: &Consumer) -> usize {
    consumer.max_ack_pending
}

/// Test-internals shim for incrementing the pending-ack counter.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_consumer_increment_pending(consumer: &Consumer) -> bool {
    consumer.increment_pending()
}

/// Test-internals shim for decrementing the pending-ack counter.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_consumer_decrement_pending(consumer: &Consumer) {
    consumer.decrement_pending();
}

/// Test-internals constructor for a pending JetStream message that shares the
/// consumer's flow-control counter.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_create_test_js_message(sequence: u64, consumer: Option<&Consumer>) -> JsMessage {
    JsMessage {
        subject: "orders.new".to_string(),
        payload: b"test payload".to_vec(),
        sequence,
        delivered: 1,
        reply_subject: "$JS.ACK.TEST_STREAM.test_consumer.1.1.1.1234567890.0".to_string(),
        ack_state: AtomicU8::new(ACK_STATE_PENDING),
        pending_acks: consumer.map(|consumer| Arc::clone(&consumer.pending_acks)),
    }
}

/// Compact termination classes for the pull-subscriber loop state machine.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzPullSubscriberTerminal {
    Active,
    Completed,
    Closed,
    TimedOut,
    Error,
}

/// Step kinds accepted by the pull-subscriber loop reducer.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzPullSubscriberStep {
    ParsedMessage,
    IgnoredMessage,
    ProcessReady,
    ProcessClosed,
    ProcessTimedOut,
    ProcessError,
}

/// Snapshot of the pull-subscriber loop state for fuzzing.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzPullSubscriberState {
    pub batch: usize,
    pub received: usize,
    pub ignored: usize,
    pub terminal: FuzzPullSubscriberTerminal,
}

/// Fuzz-target reducer for the JetStream pull-subscriber loop state machine.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_apply_pull_subscriber_step(
    state: &mut FuzzPullSubscriberState,
    step: FuzzPullSubscriberStep,
) {
    let batch = state.batch.max(1);
    let mut inner = PullSubscriberState {
        batch,
        received: state.received.min(batch),
        termination: match state.terminal {
            FuzzPullSubscriberTerminal::Active => PullSubscriberTermination::Active,
            FuzzPullSubscriberTerminal::Completed => PullSubscriberTermination::Completed,
            FuzzPullSubscriberTerminal::Closed => PullSubscriberTermination::Closed,
            FuzzPullSubscriberTerminal::TimedOut => PullSubscriberTermination::TimedOut,
            FuzzPullSubscriberTerminal::Error => PullSubscriberTermination::Error,
        },
        error: None,
    };

    match step {
        FuzzPullSubscriberStep::ParsedMessage => inner.observe_parsed_message(),
        FuzzPullSubscriberStep::IgnoredMessage => {
            if inner.is_active() {
                state.ignored = state.ignored.saturating_add(1);
            }
            inner.observe_ignored_message();
        }
        FuzzPullSubscriberStep::ProcessReady => inner.observe_process_ready(),
        FuzzPullSubscriberStep::ProcessClosed => inner.observe_closed(),
        FuzzPullSubscriberStep::ProcessTimedOut => inner.observe_timeout(),
        FuzzPullSubscriberStep::ProcessError => {
            inner.observe_error(JsError::InvalidConfig("fuzz-process-error".to_string()));
        }
    }

    state.batch = batch;
    state.received = inner.received();
    state.terminal = match inner.termination() {
        PullSubscriberTermination::Active => FuzzPullSubscriberTerminal::Active,
        PullSubscriberTermination::Completed => FuzzPullSubscriberTerminal::Completed,
        PullSubscriberTermination::Closed => FuzzPullSubscriberTerminal::Closed,
        PullSubscriberTermination::TimedOut => FuzzPullSubscriberTerminal::TimedOut,
        PullSubscriberTermination::Error => FuzzPullSubscriberTerminal::Error,
    };
}

/// Ordered-consumer reducer phases for reset-on-gap handling.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzOrderedConsumerPhase {
    Tracking,
    ResetPending,
}

/// Step kinds accepted by the ordered-consumer gap-reset reducer.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzOrderedConsumerStep {
    Observe { sequence: u64, delivered: u32 },
    CompleteReset,
}

/// Snapshot of ordered-consumer sequence tracking state for fuzzing.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzOrderedConsumerState {
    pub phase: FuzzOrderedConsumerPhase,
    pub last_sequence: Option<u64>,
    pub accepted_messages: u64,
    pub reset_count: u32,
    pub pending_gap_from: Option<u64>,
}

/// Fuzz-target reducer for ordered-consumer reset-on-gap sequencing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_apply_ordered_consumer_step(
    state: &mut FuzzOrderedConsumerState,
    step: FuzzOrderedConsumerStep,
) {
    match step {
        FuzzOrderedConsumerStep::Observe {
            sequence,
            delivered,
        } => match state.phase {
            FuzzOrderedConsumerPhase::Tracking => {
                let contiguous = state
                    .last_sequence
                    .is_none_or(|last| sequence == last.saturating_add(1));
                if delivered == 1 && contiguous {
                    state.last_sequence = Some(sequence);
                    state.accepted_messages = state.accepted_messages.saturating_add(1);
                } else {
                    state.phase = FuzzOrderedConsumerPhase::ResetPending;
                    state.reset_count = state.reset_count.saturating_add(1);
                    state.pending_gap_from = state.last_sequence.map(|last| last.saturating_add(1));
                }
            }
            FuzzOrderedConsumerPhase::ResetPending => {}
        },
        FuzzOrderedConsumerStep::CompleteReset => {
            if matches!(state.phase, FuzzOrderedConsumerPhase::ResetPending) {
                state.phase = FuzzOrderedConsumerPhase::Tracking;
                state.last_sequence = None;
                state.pending_gap_from = None;
            }
        }
    }
}

/// Terminal states for local MaxDeliver-per-message enforcement fuzzing.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzMaxDeliverTerminal {
    Pending,
    Acked,
    DeadLettered,
}

/// Step kinds accepted by the MaxDeliver enforcement reducer.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzMaxDeliverStep {
    Redeliver,
    Ack,
    ResetMessage,
}

/// Snapshot of per-message MaxDeliver enforcement state for fuzzing.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzMaxDeliverState {
    pub max_deliver: i64,
    pub delivered: u32,
    pub accepted_deliveries: u32,
    pub rejected_deliveries: u32,
    pub dlq_messages: u32,
    pub terminal: FuzzMaxDeliverTerminal,
}

/// Fuzz-target reducer for local MaxDeliver-per-message poison routing.
///
/// JetStream itself keeps maxed-out messages in the stream and emits an
/// advisory when `MaxDeliver` is exceeded. This reducer models the runtime's
/// local policy seam: once a message arrives with `delivered > max_deliver`,
/// stop surfacing it to worker code and classify it for dead-letter handling.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_apply_max_deliver_step(state: &mut FuzzMaxDeliverState, step: FuzzMaxDeliverStep) {
    let max_deliver = state.max_deliver.max(-1);

    match step {
        FuzzMaxDeliverStep::Redeliver => match state.terminal {
            FuzzMaxDeliverTerminal::Pending => {
                let delivered = state.delivered.saturating_add(1);
                state.delivered = delivered;

                if max_deliver >= 0 && i64::from(delivered) > max_deliver {
                    state.rejected_deliveries = state.rejected_deliveries.saturating_add(1);
                    state.dlq_messages = state.dlq_messages.saturating_add(1);
                    state.terminal = FuzzMaxDeliverTerminal::DeadLettered;
                } else {
                    state.accepted_deliveries = state.accepted_deliveries.saturating_add(1);
                }
            }
            FuzzMaxDeliverTerminal::Acked | FuzzMaxDeliverTerminal::DeadLettered => {
                state.rejected_deliveries = state.rejected_deliveries.saturating_add(1);
            }
        },
        FuzzMaxDeliverStep::Ack => {
            if matches!(state.terminal, FuzzMaxDeliverTerminal::Pending) && state.delivered > 0 {
                state.terminal = FuzzMaxDeliverTerminal::Acked;
            }
        }
        FuzzMaxDeliverStep::ResetMessage => {
            state.delivered = 0;
            state.terminal = FuzzMaxDeliverTerminal::Pending;
        }
    }
}

impl JsMessage {
    /// Acknowledge the message (marks as processed).
    ///
    /// Repeating `ack()` after a successful explicit ack is a no-op:
    /// JetStream treats `+ACK` as idempotent, so the client returns
    /// `Ok(())` without sending a second wire frame. On a transient
    /// publish failure the message is **not** marked acknowledged, so
    /// the caller can retry (br-asupersync-vl5agi).
    pub async fn ack(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        self.publish_terminal_ack(client, cx, Cow::Borrowed(b"+ACK"), TerminalAckKind::Ack)
            .await
    }

    /// Negative acknowledge (request redelivery).
    ///
    /// Returns `Err(JsError::AlreadyAcknowledged)` if the message was
    /// previously acknowledged, nacked, or terminated. On a transient
    /// publish failure the message is **not** marked acknowledged.
    /// (br-asupersync-vl5agi)
    pub async fn nack(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        self.publish_terminal_ack(
            client,
            cx,
            build_nak_payload(Duration::ZERO),
            TerminalAckKind::Nak,
        )
        .await
    }

    /// Negative acknowledge with a delayed redelivery request.
    ///
    /// Matches the nats.go JetStream reference wire format:
    /// `-NAK {"delay": <nanoseconds>}` for positive delays and bare
    /// `-NAK` for zero delay.
    pub async fn nack_with_delay(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        delay: Duration,
    ) -> Result<(), JsError> {
        self.publish_terminal_ack(client, cx, build_nak_payload(delay), TerminalAckKind::Nak)
            .await
    }

    /// Acknowledge in progress (extend ack deadline).
    ///
    /// Does **not** transition the terminal ack state — `+WPI` is a
    /// keepalive, multiple in-progress signals per message are legal.
    pub async fn in_progress(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        client.publish(cx, &self.reply_subject, b"+WPI").await?;
        Ok(())
    }

    /// Terminate processing (do not redeliver).
    ///
    /// Returns `Err(JsError::AlreadyAcknowledged)` if the message was
    /// previously acknowledged, nacked, or terminated. On a transient
    /// publish failure the message is **not** marked acknowledged.
    /// (br-asupersync-vl5agi)
    pub async fn term(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        self.publish_terminal_ack(client, cx, Cow::Borrowed(b"+TERM"), TerminalAckKind::Term)
            .await
    }

    /// Shared body for `ack` / `nack` / `term`.
    ///
    /// Reserves the terminal-ack slot via an in-flight state, publishes the
    /// ack frame, and commits the final terminal state on success. Publish
    /// failure rolls the state back to pending so the caller can retry.
    /// Previously the ack flag was set unconditionally before publish, which
    /// meant a transient `client.publish` error left the message permanently
    /// \"acked\" with no path back. (br-asupersync-vl5agi)
    ///
    /// Concurrency note: `JsMessage` is not designed for concurrent
    /// terminal acks from multiple threads. Post-success repeated
    /// `ack()` calls are intentionally idempotent, but a concurrent
    /// same-ack racing with an in-flight publish still sees
    /// `AlreadyAcknowledged`. If the first publish later rolls back,
    /// that racing caller will already have failed.
    async fn publish_terminal_ack(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        payload: Cow<'_, [u8]>,
        kind: TerminalAckKind,
    ) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let in_flight = kind.in_flight_state();
        let committed = kind.committed_state();

        loop {
            match self.ack_state.load(Ordering::Acquire) {
                ACK_STATE_PENDING => {
                    if self
                        .ack_state
                        .compare_exchange(
                            ACK_STATE_PENDING,
                            in_flight,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                state if state == committed && kind.is_idempotent() => return Ok(()),
                _ => return Err(JsError::AlreadyAcknowledged),
            }
        }

        // If this future is dropped mid-publish (a timeout, a cancelled
        // select), the reservation is rolled back: left in flight, every later
        // ack returned AlreadyAcknowledged and the pending credit was never
        // released.
        let _reservation = InFlightAck {
            state: &self.ack_state,
            in_flight,
        };

        // The server takes acks only on the reply subject exactly as delivered:
        // it subscribes `$JS.ACK.<stream>.<consumer>` plus five tokens. A
        // subject with anything appended matched no subscription, so every
        // ack, nak and term was dropped while this call returned Ok.
        match client
            .publish(cx, &self.reply_subject, payload.as_ref())
            .await
        {
            Ok(()) => {
                self.ack_state.store(committed, Ordering::Release);
                // Decrement pending ack count for flow control
                if let Some(ref pending) = self.pending_acks {
                    decrement_pending_counter(pending);
                }
                Ok(())
            }
            Err(err) => {
                self.ack_state.store(ACK_STATE_PENDING, Ordering::Release);
                Err(JsError::Nats(err))
            }
        }
    }
}

/// Returns a terminal-ack reservation to pending when it is dropped still in
/// flight, that is, when the publishing future was dropped before the publish
/// finished. A finished publish has already stored the outcome, so the guard
/// then does nothing.
struct InFlightAck<'a> {
    state: &'a AtomicU8,
    in_flight: u8,
}

impl Drop for InFlightAck<'_> {
    fn drop(&mut self) {
        let _ = self.state.compare_exchange(
            self.in_flight,
            ACK_STATE_PENDING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn build_nak_payload(delay: Duration) -> Cow<'static, [u8]> {
    if delay.is_zero() {
        Cow::Borrowed(b"-NAK")
    } else {
        Cow::Owned(format!("-NAK {{\"delay\": {}}}", delay.as_nanos()).into_bytes())
    }
}

// Helper functions

/// Escape a string for safe embedding in JSON values.
/// Handles `"`, `\`, and control characters.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                // \uXXXX for the Unicode code point (not per-byte)
                write!(&mut out, "\\u{:04x}", c as u32).expect("write to String");
            }
            c => out.push(c),
        }
    }
    out
}

fn has_json_api_error(json: &str) -> bool {
    extract_json_object(json, "error")
        .is_some_and(|error_json| extract_json_u64(error_json, "code").is_some())
}

fn json_value_after_key<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let mut search_start = 0;

    while search_start < json.len() {
        let quote_start = search_start + json[search_start..].find('"')?;
        let (matches_key, after_quote) = scan_json_string_literal(json, quote_start, key)?;
        search_start = after_quote;

        if !matches_key {
            continue;
        }

        if let Some(after_colon) = json[after_quote..].trim_start().strip_prefix(':') {
            return Some(after_colon.trim_start());
        }
    }

    None
}

fn scan_json_string_literal(json: &str, quote_start: usize, key: &str) -> Option<(bool, usize)> {
    // Ensure quote_start + 1 doesn't overflow or go out of bounds
    if quote_start.saturating_add(1) >= json.len() {
        return None;
    }

    let mut key_chars = key.chars();
    let mut matches_key = true;
    let mut escaped = false;

    for (offset, ch) in json[quote_start + 1..].char_indices() {
        let idx = quote_start.saturating_add(1).saturating_add(offset);

        if escaped {
            matches_key = false;
            escaped = false;
            continue;
        }

        match ch {
            '\\' => {
                matches_key = false;
                escaped = true;
            }
            '"' => return Some((matches_key && key_chars.next().is_none(), idx + 1)),
            _ => {
                if key_chars.next() != Some(ch) {
                    matches_key = false;
                }
            }
        }
    }

    None
}

fn extract_json_object<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let rest = json_value_after_key(json, key)?;
    if !rest.starts_with('{') {
        return None;
    }

    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in rest.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&rest[..=idx]);
                }
            }
            _ => {}
        }
    }

    None
}

fn extract_json_string_simple(json: &str, key: &str) -> Option<String> {
    let rest = json_value_after_key(json, key)?;
    parse_json_string_literal(rest).map(|(value, _)| value)
}

/// A JSON array of strings, such as a stream's `subjects`.
fn extract_json_string_array(json: &str, key: &str) -> Option<Vec<String>> {
    let mut rest = json_value_after_key(json, key)?
        .strip_prefix('[')?
        .trim_start();
    let mut values = Vec::new();
    if rest.starts_with(']') {
        return Some(values);
    }
    loop {
        let (value, after) = parse_json_string_literal(rest)?;
        values.push(value);
        let after = after.trim_start();
        if after.starts_with(']') {
            return Some(values);
        }
        rest = after.strip_prefix(',')?.trim_start();
    }
}

/// Decodes the JSON string literal at the start of `rest`; returns it and the
/// text after its closing quote.
fn parse_json_string_literal(rest: &str) -> Option<(String, &str)> {
    let slice = rest.strip_prefix('"')?;
    // Walk forward, respecting backslash escapes and building unescaped string
    let mut chars = slice.char_indices();
    let mut result = String::new();
    loop {
        match chars.next()? {
            (idx, '"') => return Some((result, &slice[idx + 1..])),
            (_, '\\') => {
                let (_, esc) = chars.next()?;
                match esc {
                    'b' => result.push('\x08'),
                    'f' => result.push('\x0C'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'u' => {
                        let mut hex = String::with_capacity(4);
                        for _ in 0..4 {
                            let (_, h) = chars.next()?;
                            hex.push(h);
                        }
                        if let Ok(val) = u32::from_str_radix(&hex, 16) {
                            if let Some(c) = std::char::from_u32(val) {
                                result.push(c);
                            } else {
                                result.push(std::char::REPLACEMENT_CHARACTER);
                            }
                        } else {
                            result.push(std::char::REPLACEMENT_CHARACTER);
                        }
                    }
                    _ => result.push(esc),
                }
            }
            (_, c) => result.push(c),
        }
    }
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let rest = json_value_after_key(json, key)?;
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_json_i64_simple(json: &str, key: &str) -> Option<i64> {
    let rest = json_value_after_key(json, key)?;
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let rest = json_value_after_key(json, key)?;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            1 => (u32::from(chunk[0]) << 16, 2),
            2 => ((u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8), 3),
            3 => (
                (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
                4,
            ),
            _ => continue,
        };

        for i in 0..n.1 {
            let idx = ((n.0 >> (18 - 6 * i)) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    // Padding
    let padding = (3 - data.len() % 3) % 3;
    for _ in 0..padding {
        result.push('=');
    }

    result
}

fn random_id(cx: &Cx) -> String {
    format!("{:016x}", cx.random_u64())
}

fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn validate_stream_subject_pattern(subject: &str) -> Result<(), &'static str> {
    if subject.is_empty() {
        return Err("must be non-empty");
    }
    if subject.len() > MAX_STREAM_SUBJECT_BYTES {
        return Err("exceeds the 4096-byte NATS subject bound");
    }

    let tokens: Vec<_> = subject.split('.').collect();
    let token_count = tokens.len();
    if tokens.iter().any(|token| {
        token.is_empty()
            || token
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    }) {
        return Err("contains empty tokens, whitespace, or control characters");
    }

    for (index, token) in tokens.into_iter().enumerate() {
        match token {
            "*" => {}
            ">" if index.saturating_add(1) == token_count => {}
            ">" => return Err("contains an invalid NATS wildcard placement"),
            _ if token.contains('*') || token.contains('>') => {
                return Err("contains an invalid NATS wildcard placement");
            }
            _ => {}
        }
    }

    Ok(())
}

fn format_system_time_rfc3339(time: SystemTime) -> String {
    const NANOS_PER_SEC: i128 = 1_000_000_000;
    const SECS_PER_DAY: i128 = 86_400;

    let total_nanos = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX),
        Err(err) => -i128::try_from(err.duration().as_nanos()).unwrap_or(i128::MAX),
    };
    let total_secs = total_nanos.div_euclid(NANOS_PER_SEC);
    let nanos = total_nanos.rem_euclid(NANOS_PER_SEC) as u32;
    let days = total_secs.div_euclid(SECS_PER_DAY);
    let secs_of_day = total_secs.rem_euclid(SECS_PER_DAY) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z",
        month = month as u32,
        day = day as u32
    )
}

fn compute_client_deadline(now: Time, pull_timeout: Duration, slack: Duration) -> Option<Time> {
    if pull_timeout.is_zero() {
        None
    } else {
        let timeout_dur = pull_timeout.saturating_add(slack);
        Some(now.saturating_add_nanos(duration_to_nanos_saturating(timeout_dur)))
    }
}

fn build_pull_request_json(batch: usize, expires: i64, max_bytes: Option<usize>) -> String {
    let mut request = format!("{{\"batch\":{batch},\"expires\":{expires}");
    if let Some(max_bytes) = max_bytes {
        write!(&mut request, ",\"max_bytes\":{max_bytes}").expect("write to String");
    }
    request.push('}');
    request
}

#[cfg(test)]
#[path = "jetstream_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "jetstream_dedup_boundary_audit.rs"]
mod jetstream_dedup_boundary_audit;

#[cfg(test)]
#[path = "jetstream_flow_control_audit.rs"]
mod jetstream_flow_control_audit;
