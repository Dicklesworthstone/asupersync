//! Kafka consumer with Cx integration for cancel-correct message consumption.
//!
//! This module defines the API surface for a Kafka consumer that integrates
//! with the Asupersync `Cx` context. When the `kafka` feature is disabled,
//! broker operations fail loudly with [`KafkaError::FeatureDisabled`] outside
//! unit tests. Unit tests keep a cfg-gated deterministic broker so the offset
//! state machine remains covered without shipping broker surrogate behavior.
//!
//! # Cancel-Correct Behavior
//!
//! - Poll operations honor cancellation checkpoints
//! - Offset commits are explicit and budget-aware
//! - Consumer close wakes in-flight poll waiters so they can observe closure

// The public surface remains async so the fallback path and eventual broker-
// backed implementation share one API shape.
#![allow(clippy::unused_async)]

use crate::cx::Cx;
use crate::messaging::kafka::{
    KafkaError, KafkaSaslConfig, KafkaSecurityConfig, KafkaTlsConfig, RedactedProperties,
    is_loopback_bootstrap_server,
};
#[cfg(feature = "kafka")]
use crate::messaging::kafka::{apply_security_config, redacted_config_message};
#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
use crate::messaging::kafka::{
    deterministic_broker_end_offset, deterministic_broker_fetch, deterministic_broker_notify,
};
use crate::sync::Notify;
#[cfg(any(
    feature = "kafka",
    all(not(feature = "kafka"), any(test, feature = "test-internals"))
))]
use crate::time::Sleep;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(any(
    feature = "kafka",
    all(not(feature = "kafka"), any(test, feature = "test-internals"))
))]
use std::future::Future;
#[cfg(any(
    feature = "kafka",
    all(not(feature = "kafka"), any(test, feature = "test-internals"))
))]
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(
    feature = "kafka",
    all(not(feature = "kafka"), any(test, feature = "test-internals"))
))]
use std::task::Poll;
use std::time::Duration;

mod owned;
pub use owned::{KafkaConsumerHandle, KafkaConsumerLease};

#[cfg(feature = "kafka")]
use rdkafka::{
    client::ClientContext,
    consumer::{BaseConsumer, CommitMode, Consumer, ConsumerContext},
    error::KafkaError as RdKafkaError,
    message::{Headers, Message},
    topic_partition_list::{Offset, TopicPartitionList},
    types::{RDKafkaErrorCode, RDKafkaRespErr},
};

/// Offset reset strategy when no committed offset exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoOffsetReset {
    /// Start from the earliest available offset.
    Earliest,
    /// Start from the latest offset.
    #[default]
    Latest,
    /// Fail if no committed offset is present.
    None,
}

/// Isolation level for reading transactional messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// Read uncommitted messages (default).
    #[default]
    ReadUncommitted,
    /// Read only committed messages.
    ReadCommitted,
}

/// Configuration for a Kafka consumer.
///
/// Typed fields cover the common librdkafka settings; anything else goes
/// through [`ConsumerConfig::with_property`] (typed fields win on conflict).
/// `Debug` retains typed settings and raw property names, but redacts every
/// raw property value. Keep credentials in values, never in property names.
///
/// **Assignor rule.** The rebalance protocol is fixed at construction from
/// `partition.assignment.strategy`: a value containing `cooperative-sticky`
/// makes the consumer's rebalance handler take the incremental
/// assign/unassign path, anything else (the default `range,roundrobin`) the
/// eager path. [`KafkaConsumer::rebalance_protocol`] reports what the group
/// negotiated and [`KafkaConsumer::rebalance_stats`] counts which path ran.
///
/// **Leaving the group.** [`KafkaConsumer::close`] (and dropping a
/// subscribed consumer without `close()`) unsubscribes and drains the
/// resulting revoke in normal polling mode, bounded to about five seconds,
/// before the librdkafka handle is closed; the close path itself never waits
/// on the group.
#[derive(Clone)]
pub struct ConsumerConfig {
    /// Bootstrap server addresses (host:port).
    pub bootstrap_servers: Vec<String>,
    /// Consumer group ID.
    pub group_id: String,
    /// Client identifier.
    pub client_id: Option<String>,
    /// Session timeout (detect failed consumers).
    pub session_timeout: Duration,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Auto offset reset behavior.
    pub auto_offset_reset: AutoOffsetReset,
    /// Enable auto-commit of offsets.
    ///
    /// **Defaults to `false` (manual-commit / at-least-once)** as of
    /// br-asupersync-2i2e21. The implementation stores the offset at
    /// **poll time** (`store_offset_from_message` immediately after
    /// `consumer.poll`), so enabling auto-commit means the offset is
    /// recorded *before* your application has acknowledged successful
    /// processing of the message. Combined with `auto_commit_interval`
    /// flushing in the background, this is silent **at-most-once**
    /// delivery: a process crash between poll and commit is invisible,
    /// but a crash between poll and your application's processing
    /// completion drops the message.
    ///
    /// Set this to `true` only when the application explicitly accepts
    /// at-most-once semantics. The asupersync default is at-least-once,
    /// so the application is expected to call `commit_offset` after it
    /// has finished processing each record.
    pub enable_auto_commit: bool,
    /// Auto-commit interval.
    pub auto_commit_interval: Duration,
    /// Max records returned per poll. Not applied: `KafkaConsumer::poll`
    /// returns one record per call; this is only checked to be non-zero.
    pub max_poll_records: usize,
    /// Fetch minimum bytes.
    pub fetch_min_bytes: usize,
    /// Fetch maximum bytes.
    pub fetch_max_bytes: usize,
    /// Maximum wait time for fetch.
    pub fetch_max_wait: Duration,
    /// Isolation level for transactional reads.
    pub isolation_level: IsolationLevel,
    /// Transport security for Kafka broker connections.
    pub security: KafkaSecurityConfig,
    /// Force real Kafka connection even in unit-test mode.
    ///
    /// When `true`, feature-enabled unit tests use the `rdkafka` broker
    /// connection path. When `false`, unit tests may exercise the local offset
    /// state machine without a broker. Non-test builds always require the
    /// `kafka` feature for broker operations.
    pub force_real_kafka: bool,
    /// Maximum number of retries for retriable operations (offset commits, etc.).
    pub retries: u32,
    /// Internal test/debug-only opt-in for PLAINTEXT / unauthenticated remote brokers.
    ///
    /// The secure default is fail-closed for non-loopback plaintext bootstrap
    /// servers. Keep this private so release callers cannot enable the bypass
    /// through a struct literal.
    allow_insecure_transport_for_testing: bool,
    /// Internal opt-in for the no-feature deterministic broker in downstream
    /// integration tests.
    #[cfg(any(test, feature = "test-internals"))]
    allow_deterministic_broker_for_testing: bool,
    /// Raw librdkafka properties applied before the typed fields
    /// ([`ConsumerConfig::with_property`]), in insertion order.
    extra_properties: Vec<(String, String)>,
}

impl fmt::Debug for ConsumerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ConsumerConfig");
        debug
            .field("bootstrap_servers", &self.bootstrap_servers)
            .field("group_id", &self.group_id)
            .field("client_id", &self.client_id)
            .field("session_timeout", &self.session_timeout)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("auto_offset_reset", &self.auto_offset_reset)
            .field("enable_auto_commit", &self.enable_auto_commit)
            .field("auto_commit_interval", &self.auto_commit_interval)
            .field("max_poll_records", &self.max_poll_records)
            .field("fetch_min_bytes", &self.fetch_min_bytes)
            .field("fetch_max_bytes", &self.fetch_max_bytes)
            .field("fetch_max_wait", &self.fetch_max_wait)
            .field("isolation_level", &self.isolation_level)
            .field("security", &self.security)
            .field("force_real_kafka", &self.force_real_kafka)
            .field("retries", &self.retries)
            .field(
                "allow_insecure_transport_for_testing",
                &self.allow_insecure_transport_for_testing,
            );
        #[cfg(any(test, feature = "test-internals"))]
        debug.field(
            "allow_deterministic_broker_for_testing",
            &self.allow_deterministic_broker_for_testing,
        );
        debug
            .field(
                "extra_properties",
                &RedactedProperties(&self.extra_properties),
            )
            .finish()
    }
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: vec!["localhost:9092".to_string()],
            group_id: "asupersync-default".to_string(),
            client_id: None,
            session_timeout: Duration::from_secs(45),
            heartbeat_interval: Duration::from_secs(3),
            auto_offset_reset: AutoOffsetReset::Latest,
            // br-asupersync-2i2e21: default is manual-commit (at-least-once).
            // The driver stores the offset at poll time when auto-commit is
            // on, so enabling it means the offset can be flushed to the
            // broker before the application has finished processing — a
            // silent at-most-once footgun that callers must opt into
            // explicitly via `.enable_auto_commit(true)`.
            enable_auto_commit: false,
            auto_commit_interval: Duration::from_secs(5),
            max_poll_records: 500,
            fetch_min_bytes: 1,
            fetch_max_bytes: 50 * 1024 * 1024,
            fetch_max_wait: Duration::from_millis(500),
            isolation_level: IsolationLevel::ReadUncommitted,
            security: KafkaSecurityConfig::default(),
            force_real_kafka: false,
            retries: 3,
            allow_insecure_transport_for_testing: false,
            #[cfg(any(test, feature = "test-internals"))]
            allow_deterministic_broker_for_testing: false,
            extra_properties: Vec::new(),
        }
    }
}

impl ConsumerConfig {
    /// Create a new consumer configuration.
    #[must_use]
    pub fn new(bootstrap_servers: Vec<String>, group_id: impl Into<String>) -> Self {
        Self {
            bootstrap_servers,
            group_id: group_id.into(),
            ..Default::default()
        }
    }

    /// Set the client identifier.
    #[must_use]
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    /// Forward a raw librdkafka property (for example
    /// `partition.assignment.strategy` = `cooperative-sticky`).
    ///
    /// Properties are applied in insertion order BEFORE the typed fields, so
    /// a typed field always wins over a raw property with the same key; a
    /// later `with_property` for the same key overrides an earlier one.
    /// Unknown keys are rejected by librdkafka when the consumer is created
    /// ([`KafkaError::Config`]).
    ///
    /// `Debug` redacts all raw values, including non-secret values. Property
    /// names remain visible and must not contain credentials.
    /// Native configuration rejection reports the property name and result
    /// code, without the value or free-form native error description.
    #[must_use]
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_property(key, value);
        self
    }

    /// In-place form of [`Self::with_property`].
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(slot) = self
            .extra_properties
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            slot.1 = value;
        } else {
            self.extra_properties.push((key, value));
        }
    }

    /// The raw properties set through [`Self::with_property`], in the order
    /// they are applied.
    ///
    /// Unlike this configuration's `Debug` output, this explicit accessor
    /// returns the original values, which may contain credentials.
    #[must_use]
    pub fn extra_properties(&self) -> &[(String, String)] {
        &self.extra_properties
    }

    /// Set the session timeout.
    #[must_use]
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Set the heartbeat interval.
    #[must_use]
    pub fn heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Set auto offset reset behavior.
    #[must_use]
    pub const fn auto_offset_reset(mut self, reset: AutoOffsetReset) -> Self {
        self.auto_offset_reset = reset;
        self
    }

    /// Enable or disable auto-commit.
    #[must_use]
    pub const fn enable_auto_commit(mut self, enable: bool) -> Self {
        self.enable_auto_commit = enable;
        self
    }

    /// Set auto-commit interval.
    #[must_use]
    pub fn auto_commit_interval(mut self, interval: Duration) -> Self {
        self.auto_commit_interval = interval;
        self
    }

    /// Set max records returned per poll. Not applied (see
    /// [`ConsumerConfig::max_poll_records`]).
    #[must_use]
    pub const fn max_poll_records(mut self, max: usize) -> Self {
        self.max_poll_records = max;
        self
    }

    /// Set fetch minimum bytes.
    #[must_use]
    pub const fn fetch_min_bytes(mut self, min: usize) -> Self {
        self.fetch_min_bytes = min;
        self
    }

    /// Set fetch maximum bytes.
    #[must_use]
    pub const fn fetch_max_bytes(mut self, max: usize) -> Self {
        self.fetch_max_bytes = max;
        self
    }

    /// Set fetch maximum wait time.
    #[must_use]
    pub fn fetch_max_wait(mut self, wait: Duration) -> Self {
        self.fetch_max_wait = wait;
        self
    }

    /// Set isolation level.
    #[must_use]
    pub const fn isolation_level(mut self, level: IsolationLevel) -> Self {
        self.isolation_level = level;
        self
    }

    /// Force real Kafka connection even in test mode.
    #[must_use]
    pub const fn force_real_kafka(mut self, force: bool) -> Self {
        self.force_real_kafka = force;
        self
    }

    /// Set maximum number of retries for retriable operations.
    #[must_use]
    pub const fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Set Kafka broker transport security.
    #[must_use]
    pub fn security(mut self, security: KafkaSecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Require TLS for Kafka broker transport.
    #[must_use]
    pub fn tls(self, tls: KafkaTlsConfig) -> Self {
        self.security(KafkaSecurityConfig::Tls(tls))
    }

    /// Require SASL/SCRAM-SHA-256 over TLS for Kafka broker transport.
    #[must_use]
    pub fn sasl_scram_sha_256(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.security(KafkaSecurityConfig::SaslSsl(
            KafkaSaslConfig::scram_sha_256(username, password),
        ))
    }

    /// Require SASL/SCRAM-SHA-512 over TLS for Kafka broker transport.
    #[must_use]
    pub fn sasl_scram_sha_512(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.security(KafkaSecurityConfig::SaslSsl(
            KafkaSaslConfig::scram_sha_512(username, password),
        ))
    }

    /// Scary test/debug-only opt-in for remote PLAINTEXT / unauthenticated brokers.
    ///
    /// This setter is intentionally unavailable in release builds so
    /// production callers cannot compile with a remote plaintext-broker bypass.
    #[cfg(any(test, debug_assertions))]
    #[must_use]
    pub const fn allow_insecure_transport_for_testing(mut self, allow: bool) -> Self {
        self.allow_insecure_transport_for_testing = allow;
        self
    }

    /// Opt into the deterministic no-feature broker for downstream tests.
    ///
    /// Crate unit tests use the deterministic broker automatically, but
    /// integration tests compile as downstream consumers and must opt in
    /// explicitly so default broker operations keep failing closed.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub const fn allow_deterministic_broker_for_testing(mut self, allow: bool) -> Self {
        self.allow_deterministic_broker_for_testing = allow;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), KafkaError> {
        if self.bootstrap_servers.is_empty() {
            return Err(KafkaError::Config(
                "bootstrap_servers cannot be empty".to_string(),
            ));
        }
        if self.group_id.trim().is_empty() {
            return Err(KafkaError::Config("group_id cannot be empty".to_string()));
        }
        if self.max_poll_records == 0 {
            return Err(KafkaError::Config(
                "max_poll_records must be > 0".to_string(),
            ));
        }
        if self.fetch_min_bytes > self.fetch_max_bytes {
            return Err(KafkaError::Config(
                "fetch_min_bytes must be <= fetch_max_bytes".to_string(),
            ));
        }
        self.security.validate()?;
        if !self.allow_insecure_transport_for_testing && !self.security.is_remote_secure() {
            for server in &self.bootstrap_servers {
                if !is_loopback_bootstrap_server(server) {
                    return Err(KafkaError::Config(format!(
                        "remote Kafka bootstrap server '{server}' is rejected by default: \
                         configure TLS or SASL_SSL SCRAM security for non-loopback brokers"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// A topic/partition/offset tuple for commits and seeks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicPartitionOffset {
    /// Topic name.
    pub topic: String,
    /// Partition number.
    pub partition: i32,
    /// Offset to commit or seek.
    pub offset: i64,
}

impl TopicPartitionOffset {
    /// Create a new topic/partition/offset tuple.
    #[must_use]
    pub fn new(topic: impl Into<String>, partition: i32, offset: i64) -> Self {
        Self {
            topic: topic.into(),
            partition,
            offset,
        }
    }
}

/// An owned snapshot of a consumer's group membership for transactional offsets.
///
/// Obtain this from [`KafkaConsumer::group_metadata`] after polling the records
/// being processed. Clones refer to the same snapshot. Local assignment changes
/// invalidate it. The broker validates its native generation and member identity,
/// including rebalances that preserve the same assignment. Capture a fresh
/// snapshot after every rebalance rather than relying only on [`Self::generation`].
/// The snapshot does not retain a native consumer or delay scoped teardown.
#[derive(Clone)]
pub struct ConsumerGroupMetadata {
    inner: Arc<ConsumerGroupMetadataInner>,
}

#[cfg_attr(not(any(feature = "kafka", test)), allow(dead_code))]
struct ConsumerGroupMetadataInner {
    group_id: String,
    generation: u64,
    assignments: BTreeSet<(String, i32)>,
    state: Weak<Mutex<ConsumerState>>,
    closed: Weak<AtomicBool>,
    #[cfg(feature = "kafka")]
    native: Option<rdkafka::consumer::ConsumerGroupMetadata>,
}

impl fmt::Debug for ConsumerGroupMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumerGroupMetadata")
            .field("group_id", &self.inner.group_id)
            .field("generation", &self.inner.generation)
            .field("partitions", &self.inner.assignments.len())
            .finish_non_exhaustive()
    }
}

impl ConsumerGroupMetadata {
    /// Consumer group whose offsets this snapshot can enroll.
    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.inner.group_id
    }

    /// The wrapper's assignment generation when the snapshot was captured.
    /// This is not the broker's wire generation identifier.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// Whether this snapshot still describes its consumer's live membership.
    ///
    /// A closed or dropped consumer, a new rebalance generation or a changed
    /// assignment never becomes current again, so a failure here is final
    /// for the snapshot.
    #[cfg(feature = "kafka")]
    pub(crate) fn check_membership(&self) -> Result<(), KafkaError> {
        let state = self.inner.state.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let closed = self.inner.closed.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let state = state.lock();
        self.validate_membership(&state, &closed)
    }

    #[cfg(any(feature = "kafka", test))]
    pub(crate) fn prepare_offsets(
        &self,
        offsets: &[TopicPartitionOffset],
    ) -> Result<PreparedTransactionOffsets, KafkaError> {
        if offsets.is_empty() {
            return Err(KafkaError::Config("offsets cannot be empty".into()));
        }
        // The snapshot's assignment bounds both allocation and the amount of
        // work before a duplicate/foreign partition can be rejected.
        if offsets.len() > self.inner.assignments.len() {
            return Err(KafkaError::Config(
                "offset batch exceeds the captured assignment".into(),
            ));
        }
        let state = self.inner.state.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let closed = self.inner.closed.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let state = state.lock();
        self.validate_membership(&state, &closed)?;
        let mut normalized = BTreeMap::new();
        for offset in offsets {
            validate_partition_number(offset.partition)?;
            if offset.offset < 0 {
                return Err(KafkaError::Config("offsets must be non-negative".into()));
            }
            let key = (offset.topic.clone(), offset.partition);
            if !self.inner.assignments.contains(&key) {
                return Err(KafkaError::Config(
                    "partition is not assigned to the captured consumer group member".into(),
                ));
            }
            if state
                .committed_offsets
                .get(&key)
                .is_some_and(|previous| offset.offset < *previous)
            {
                return Err(KafkaError::Config("offset commit regression is not allowed".into()));
            }
            if normalized.insert(key, offset.offset).is_some() {
                return Err(KafkaError::Config(
                    "duplicate topic/partition entry in commit batch".into(),
                ));
            }
        }
        Ok(PreparedTransactionOffsets {
            metadata: self.clone(),
            offsets: normalized,
        })
    }

    fn validate_membership(
        &self,
        state: &ConsumerState,
        closed: &AtomicBool,
    ) -> Result<(), KafkaError> {
        if closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".into()));
        }
        if state.rebalance_generation != self.inner.generation
            || state.assigned_partitions != self.inner.assignments
        {
            return Err(KafkaError::Transaction(
                "consumer group metadata is stale after a rebalance".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "kafka")]
    pub(crate) fn native(&self) -> Result<&rdkafka::consumer::ConsumerGroupMetadata, KafkaError> {
        self.inner.native.as_ref().ok_or(KafkaError::FeatureDisabled)
    }
}

/// Local bookkeeping for offsets already validated against one membership
/// snapshot. It never sends a standalone consumer offset commit.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransactionOffsets {
    pub(crate) metadata: ConsumerGroupMetadata,
    pub(crate) offsets: BTreeMap<(String, i32), i64>,
}

impl PreparedTransactionOffsets {
    #[cfg(any(feature = "kafka", test))]
    pub(crate) fn merge(&self, next: &Self) -> Result<Self, KafkaError> {
        if !Arc::ptr_eq(&self.metadata.inner, &next.metadata.inner) {
            return Err(KafkaError::Transaction(
                "one transaction must use the same consumer group metadata snapshot".into(),
            ));
        }
        let mut merged = self.clone();
        for (key, offset) in &next.offsets {
            if merged.offsets.get(key).is_some_and(|previous| offset < previous) {
                return Err(KafkaError::Config(
                    "transactional offset regression is not allowed".into(),
                ));
            }
            merged.offsets.insert(key.clone(), *offset);
        }
        Ok(merged)
    }

    /// Revalidate immediately before entering librdkafka, after any blocking
    /// pool queue delay. Broker-side membership fencing remains authoritative.
    #[cfg(any(feature = "kafka", test))]
    pub(crate) fn validate_current(&self) -> Result<(), KafkaError> {
        let state = self.metadata.inner.state.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let closed = self.metadata.inner.closed.upgrade().ok_or_else(|| {
            KafkaError::Config("consumer group metadata owner has been dropped".into())
        })?;
        let state = state.lock();
        self.metadata.validate_membership(&state, &closed)?;
        if self.offsets.iter().any(|(key, offset)| {
            state.committed_offsets.get(key).is_some_and(|previous| offset < previous)
        }) {
            return Err(KafkaError::Config("offset commit regression is not allowed".into()));
        }
        Ok(())
    }

    /// Called only after a successful broker transaction commit. A stale or
    /// dropped consumer must not have its new assignment's local state changed.
    pub(crate) fn publish_committed(self) {
        let Some(state) = self.metadata.inner.state.upgrade() else {
            return;
        };
        let Some(closed) = self.metadata.inner.closed.upgrade() else {
            return;
        };
        let mut state = state.lock();
        if self.metadata.validate_membership(&state, &closed).is_err() {
            return;
        }
        for (key, offset) in self.offsets {
            let current = state.committed_offsets.entry(key).or_insert(offset);
            *current = (*current).max(offset);
        }
    }
}

/// Result emitted after a consumer group rebalance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceResult {
    /// Monotonic rebalance generation for this consumer instance.
    pub generation: u64,
    /// Current assigned partitions after rebalance.
    pub assigned: Vec<(String, i32)>,
    /// Partitions revoked by the rebalance.
    pub revoked: Vec<(String, i32)>,
}

/// A record returned from a Kafka consumer poll.
///
/// This compatibility representation maps null payloads and null header values
/// to empty bytes. Use [`KafkaConsumer::poll_nullable`] when consuming compacted
/// topics or otherwise distinguishing a Kafka null from an empty value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerRecord {
    /// Topic name.
    pub topic: String,
    /// Partition number.
    pub partition: i32,
    /// Offset of the record.
    pub offset: i64,
    /// Optional key.
    pub key: Option<Vec<u8>>,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// Record timestamp (ms since epoch).
    pub timestamp: Option<i64>,
    /// Header key/value pairs.
    pub headers: Vec<(String, Vec<u8>)>,
}

/// A Kafka consumer record that preserves null payloads and header values.
///
/// [`KafkaConsumer::poll_nullable`] retains this representation through broker
/// polling and cancellation buffering. A keyed record with `payload: None` is
/// a compaction tombstone; `Some(Vec::new())` is an ordinary empty value. Header
/// order and duplicate header names are preserved, including each value's null
/// versus empty distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullableConsumerRecord {
    /// Topic name.
    pub topic: String,
    /// Partition number.
    pub partition: i32,
    /// Offset of the record.
    pub offset: i64,
    /// Optional key; an empty key is distinct from a null key.
    pub key: Option<Vec<u8>>,
    /// Payload bytes, or `None` for a Kafka null value.
    pub payload: Option<Vec<u8>>,
    /// Record timestamp (ms since epoch).
    pub timestamp: Option<i64>,
    /// Ordered header key/value pairs, preserving duplicate names and nulls.
    pub headers: Vec<(String, Option<Vec<u8>>)>,
}

impl From<NullableConsumerRecord> for ConsumerRecord {
    /// Project into the compatibility representation, mapping null values to
    /// empty bytes. This conversion intentionally loses null information.
    fn from(record: NullableConsumerRecord) -> Self {
        Self {
            topic: record.topic,
            partition: record.partition,
            offset: record.offset,
            key: record.key,
            payload: record.payload.unwrap_or_default(),
            timestamp: record.timestamp,
            headers: record
                .headers
                .into_iter()
                .map(|(key, value)| (key, value.unwrap_or_default()))
                .collect(),
        }
    }
}

impl From<ConsumerRecord> for NullableConsumerRecord {
    /// Wrap every payload and header value in `Some`. The compatibility record
    /// has no null information to recover, including for empty byte vectors.
    fn from(record: ConsumerRecord) -> Self {
        Self {
            topic: record.topic,
            partition: record.partition,
            offset: record.offset,
            key: record.key,
            payload: Some(record.payload),
            timestamp: record.timestamp,
            headers: record
                .headers
                .into_iter()
                .map(|(key, value)| (key, Some(value)))
                .collect(),
        }
    }
}

#[cfg(any(
    feature = "kafka",
    all(not(feature = "kafka"), any(test, feature = "test-internals"))
))]
fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "kafka")]
const MAX_BROKER_POLL_SLICE: Duration = Duration::from_millis(50);

/// Consumer context for the real-broker backend.
///
/// The stock `ConsumerContext::rebalance` asks librdkafka which rebalance
/// protocol is active on every event. During `rd_kafka_consumer_close`, which
/// `BaseConsumer`'s `Drop` runs for a consumer that was never closed, that
/// query is an infinite-timeout op the terminating group never answers, so
/// dropping a subscribed consumer (for example during panic unwinding) hung
/// the dropping thread forever. The protocol is fixed at construction from the
/// configured assignment strategy instead, and the handler assigns directly.
#[cfg(feature = "kafka")]
#[derive(Clone, Debug)]
struct BrokerConsumerContext {
    cooperative: bool,
    counters: Arc<RebalanceCounters>,
}

/// Live counters behind [`RebalanceStats`], shared by the consumer and its
/// rebalance context (librdkafka owns the context; the consumer reads these).
#[cfg(feature = "kafka")]
#[derive(Debug, Default)]
struct RebalanceCounters {
    incremental_assigns: std::sync::atomic::AtomicU64,
    eager_assigns: std::sync::atomic::AtomicU64,
    incremental_unassigns: std::sync::atomic::AtomicU64,
    eager_unassigns: std::sync::atomic::AtomicU64,
    /// Partitions the group assigned through the callback and has not revoked;
    /// an explicit `KafkaConsumer::rebalance` leaves this count untouched.
    group_partitions: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    native_drop_thread: Mutex<Option<(std::thread::ThreadId, Option<String>)>>,
}

#[cfg(all(test, feature = "kafka"))]
impl Drop for BrokerConsumerContext {
    fn drop(&mut self) {
        let thread = std::thread::current();
        *self.counters.native_drop_thread.lock() =
            Some((thread.id(), thread.name().map(str::to_owned)));
    }
}

#[cfg(feature = "kafka")]
impl RebalanceCounters {
    fn snapshot(&self, cooperative: bool) -> RebalanceStats {
        RebalanceStats {
            cooperative,
            incremental_assigns: self.incremental_assigns.load(Ordering::Relaxed),
            eager_assigns: self.eager_assigns.load(Ordering::Relaxed),
            incremental_unassigns: self.incremental_unassigns.load(Ordering::Relaxed),
            eager_unassigns: self.eager_unassigns.load(Ordering::Relaxed),
        }
    }
}

/// Which rebalance path a [`KafkaConsumer`] has taken so far
/// ([`KafkaConsumer::rebalance_stats`]).
///
/// `cooperative` is decided at construction from
/// `partition.assignment.strategy` (see [`ConsumerConfig`]); the counters
/// record every rebalance callback librdkafka delivered. Without the `kafka`
/// feature, or before a group is joined, every counter is zero.
/// `#[non_exhaustive]`: fields may be added in later `0.4.x` releases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RebalanceStats {
    /// The handler was configured for the cooperative (incremental) path.
    pub cooperative: bool,
    /// `incremental_assign` calls (cooperative assign callbacks).
    pub incremental_assigns: u64,
    /// `assign` calls (eager assign callbacks).
    pub eager_assigns: u64,
    /// `incremental_unassign` calls (cooperative revoke callbacks).
    pub incremental_unassigns: u64,
    /// `unassign` calls (eager revoke and every other rebalance outcome).
    pub eager_unassigns: u64,
}

/// The rebalance protocol a consumer group negotiated, read outside any
/// rebalance callback ([`KafkaConsumer::rebalance_protocol`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KafkaRebalanceProtocol {
    /// No group joined yet, no broker backend, or the `kafka` feature is off.
    Unknown,
    /// Eager (stop-the-world) rebalancing: `range` / `roundrobin` assignors.
    Eager,
    /// Cooperative incremental rebalancing: the `cooperative-sticky` assignor.
    Cooperative,
}

#[cfg(feature = "kafka")]
impl ClientContext for BrokerConsumerContext {}

#[cfg(feature = "kafka")]
impl ConsumerContext for BrokerConsumerContext {
    fn rebalance(
        &self,
        base_consumer: &BaseConsumer<Self>,
        err: RDKafkaRespErr,
        tpl: &mut TopicPartitionList,
    ) {
        let counters = &self.counters;
        let result = match (err, self.cooperative) {
            (RDKafkaRespErr::RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS, true) => {
                counters.incremental_assigns.fetch_add(1, Ordering::Relaxed);
                counters.group_assigned(tpl.count(), false);
                base_consumer.incremental_assign(tpl)
            }
            (RDKafkaRespErr::RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS, false) => {
                counters.eager_assigns.fetch_add(1, Ordering::Relaxed);
                counters.group_assigned(tpl.count(), true);
                base_consumer.assign(tpl)
            }
            (RDKafkaRespErr::RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS, true) => {
                counters
                    .incremental_unassigns
                    .fetch_add(1, Ordering::Relaxed);
                counters.group_revoked(tpl.count());
                base_consumer.incremental_unassign(tpl)
            }
            // Eager revoke and every other outcome: drop the whole assignment,
            // exactly what the stock handler does.
            _ => {
                counters.eager_unassigns.fetch_add(1, Ordering::Relaxed);
                counters.group_revoked(usize::MAX);
                base_consumer.unassign()
            }
        };
        // Errors here are reported to the caller through the next poll
        // (librdkafka queues them); there is no channel back from a callback.
        let _ = result;
    }
}

/// Upper bound on the 50 ms polls spent draining the revoke that
/// `unsubscribe()` triggers (about five seconds).
#[cfg(feature = "kafka")]
const LEAVE_GROUP_DRAIN_POLLS: usize = 100;

/// Unsubscribe and drive the resulting revoke through the rebalance callback
/// while the consumer is still in normal polling mode.
///
/// librdkafka only completes a rebalance once the callback has made its
/// assign/unassign call. A revoke that is still queued when `BaseConsumer`'s
/// `Drop` closes the handle fires inside `rd_kafka_consumer_close`, where that
/// call is routed back to the very queue the dropping thread is polling and
/// blocks forever. Leaving the group here, before the handle is closed, keeps
/// that path from ever being taken. Records surfaced while draining belong to
/// a consumer that is closing without commit and are discarded. An eager member
/// also drains when only the group holds its partitions: an explicit empty
/// rebalance clears the local assignment alone (see `holds_partitions`).
#[cfg(feature = "kafka")]
fn leave_group_bounded(consumer: &BaseConsumer<BrokerConsumerContext>) {
    let had_assignment = holds_partitions(consumer);
    consumer.unsubscribe();
    if !had_assignment {
        return;
    }
    for _ in 0..LEAVE_GROUP_DRAIN_POLLS {
        let _ = consumer.poll(Duration::from_millis(50));
        if !holds_partitions(consumer) {
            break;
        }
    }
}

/// Serializes native calls and accounts for every handle retained by an
/// in-flight blocking operation. Scoped teardown fences admission and waits for
/// these leases; a cancelled async waiter is not evidence that its native call
/// has returned.
#[cfg(feature = "kafka")]
#[derive(Debug, Default)]
struct BrokerOperations {
    serial: Mutex<()>,
    lifetime: Mutex<BrokerOperationLifetime>,
    retired: parking_lot::Condvar,
    #[cfg(test)]
    before_lock: Mutex<Option<crate::channel::oneshot::Sender<()>>>,
    #[cfg(test)]
    after_record_buffered: Mutex<Option<BufferedRecordHook>>,
}

#[cfg(all(test, feature = "kafka"))]
#[derive(Debug)]
struct BufferedRecordHook {
    published: crate::channel::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(feature = "kafka")]
#[derive(Debug, Default)]
struct BrokerOperationLifetime {
    leases: usize,
    retiring: bool,
}

#[cfg(feature = "kafka")]
impl BrokerOperations {
    fn lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        #[cfg(test)]
        let witness = self.before_lock.lock().take();
        #[cfg(test)]
        if let Some(witness) = witness {
            let _ = witness.send_blocking(());
        }
        self.serial.lock()
    }

    fn retire_and_wait(&self) {
        let mut state = self.lifetime.lock();
        state.retiring = true;
        while state.leases != 0 {
            self.retired.wait(&mut state);
        }
    }
}

/// The native reference is released before the lease's retirement notification.
/// Consequently observing zero leases after admission is fenced proves that the
/// lifetime worker retains the only native handle, including after future drop.
#[cfg(feature = "kafka")]
struct BrokerConsumerLease {
    consumer: Option<Arc<BaseConsumer<BrokerConsumerContext>>>,
    operations: Arc<BrokerOperations>,
}

#[cfg(feature = "kafka")]
impl BrokerConsumerLease {
    fn acquire(
        consumer: &Arc<BaseConsumer<BrokerConsumerContext>>,
        operations: &Arc<BrokerOperations>,
    ) -> Option<Self> {
        let mut state = operations.lifetime.lock();
        if state.retiring {
            return None;
        }
        state.leases = state.leases.checked_add(1).expect("native consumer lease count overflow");
        Some(Self {
            consumer: Some(Arc::clone(consumer)),
            operations: Arc::clone(operations),
        })
    }
}

#[cfg(feature = "kafka")]
impl Clone for BrokerConsumerLease {
    fn clone(&self) -> Self {
        let mut state = self.operations.lifetime.lock();
        // An existing operation may make another attempt after retirement has
        // begun. Its own lease keeps the count nonzero throughout that handoff.
        state.leases = state.leases.checked_add(1).expect("native consumer lease count overflow");
        Self {
            consumer: Some(Arc::clone(self.consumer.as_ref().expect("live native consumer lease"))),
            operations: Arc::clone(&self.operations),
        }
    }
}

#[cfg(feature = "kafka")]
impl std::ops::Deref for BrokerConsumerLease {
    type Target = BaseConsumer<BrokerConsumerContext>;

    fn deref(&self) -> &Self::Target {
        self.consumer.as_deref().expect("live native consumer lease")
    }
}

#[cfg(feature = "kafka")]
impl Drop for BrokerConsumerLease {
    fn drop(&mut self) {
        drop(self.consumer.take());
        let mut state = self.operations.lifetime.lock();
        state.leases -= 1;
        if state.leases == 0 {
            self.operations.retired.notify_all();
        }
    }
}

impl Drop for KafkaConsumer {
    fn drop(&mut self) {
        #[cfg(feature = "kafka")]
        if !self.closed.load(Ordering::Acquire) {
            if let Some((consumer, broker_ops)) = self.broker_backend() {
                // A consumer dropped without `close()` (panic unwinding, early
                // return) leaves the group here, bounded, so rdkafka's own Drop
                // never has to service a revoke mid-close.
                let _guard = broker_ops.lock();
                leave_group_bounded(&consumer);
            }
        }
    }
}

/// Kafka consumer with Cx-aware real-broker operations.
///
/// The no-feature build keeps the type and configuration surface available, but
/// broker operations return [`KafkaError::FeatureDisabled`] unless the code is
/// compiled as crate unit tests.
pub struct KafkaConsumer {
    config: ConsumerConfig,
    state: Arc<Mutex<ConsumerState>>,
    closed: Arc<AtomicBool>,
    state_notify: Notify,
    #[cfg(feature = "kafka")]
    consumer: Option<Arc<BaseConsumer<BrokerConsumerContext>>>,
    #[cfg(feature = "kafka")]
    rebalance: Option<(bool, Arc<RebalanceCounters>)>,
    #[cfg(feature = "kafka")]
    broker_ops: Option<Arc<BrokerOperations>>,
    #[cfg(feature = "kafka")]
    buffered_outcome: Arc<Mutex<Option<Result<BrokerPollOutcome, KafkaError>>>>,
    #[cfg(test)]
    rebalance_after_open_hook: Mutex<Option<Arc<RebalanceAfterOpenHook>>>,
    #[cfg(all(test, not(feature = "kafka")))]
    poll_before_wait_hook: Mutex<Option<Arc<PollBeforeWaitHook>>>,
}

impl fmt::Debug for KafkaConsumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaConsumer")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// A broker error that [`KafkaConsumer::poll`] swallowed because it self-heals.
///
/// librdkafka reports it while the condition is still transient (today:
/// `UnknownTopicOrPartition` while a subscribed topic is still being
/// created). Exposed through [`KafkaConsumer::last_transient_error`] so a
/// consumer that only ever returns `Ok(None)` is distinguishable from an
/// idle topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransientConsumerError {
    /// librdkafka error code name.
    pub code: String,
    /// Runtime time of the first occurrence of this code (since the last
    /// distinct code).
    pub first_seen: crate::types::Time,
    /// Runtime time of the most recent occurrence.
    pub last_seen: crate::types::Time,
    /// Occurrences of this code since `first_seen`.
    pub count: u32,
}

/// Record a swallowed transient error on the consumer state.
///
/// Returns the entry to announce when this is the first occurrence of a
/// distinct code (callers trace once per code, never once per poll).
#[cfg_attr(not(feature = "kafka"), allow(dead_code))]
fn record_transient_error(
    state: &mut ConsumerState,
    code: &'static str,
    now: crate::types::Time,
) -> Option<TransientConsumerError> {
    match state.last_transient_error.as_mut() {
        Some(existing) if existing.code == code => {
            existing.count = existing.count.saturating_add(1);
            existing.last_seen = now;
            None
        }
        _ => {
            let entry = TransientConsumerError {
                code: code.to_owned(),
                first_seen: now,
                last_seen: now,
                count: 1,
            };
            state.last_transient_error = Some(entry.clone());
            Some(entry)
        }
    }
}

#[derive(Debug, Default)]
struct ConsumerState {
    last_transient_error: Option<TransientConsumerError>,
    subscribed_topics: BTreeSet<String>,
    assigned_partitions: BTreeSet<(String, i32)>,
    committed_offsets: BTreeMap<(String, i32), i64>,
    positions: BTreeMap<(String, i32), i64>,
    #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
    poll_cursor: usize,
    rebalance_generation: u64,
    last_revoked_partitions: BTreeSet<(String, i32)>,
}

#[cfg(test)]
#[derive(Debug)]
struct RebalanceAfterOpenHook {
    arrived: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(all(test, not(feature = "kafka")))]
#[derive(Debug)]
struct PollBeforeWaitHook {
    arrived: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(all(test, not(feature = "kafka")))]
impl PollBeforeWaitHook {
    fn new() -> Self {
        Self {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        }
    }
}

#[cfg(test)]
impl RebalanceAfterOpenHook {
    fn new() -> Self {
        Self {
            arrived: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        }
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug, Default)]
struct BrokerSnapshot {
    assigned_partitions: BTreeSet<(String, i32)>,
    positions: BTreeMap<(String, i32), i64>,
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct BrokerPollOutcome {
    record: Option<NullableConsumerRecord>,
    snapshot: BrokerSnapshot,
    /// An informational librdkafka error that this poll swallowed (it
    /// self-heals; see `KafkaConsumer::poll`), named for observability.
    transient_error: Option<&'static str>,
}

#[cfg(feature = "kafka")]
fn auto_offset_reset_str(reset: AutoOffsetReset) -> &'static str {
    match reset {
        AutoOffsetReset::Earliest => "earliest",
        AutoOffsetReset::Latest => "latest",
        AutoOffsetReset::None => "error",
    }
}

#[cfg(feature = "kafka")]
fn isolation_level_str(level: IsolationLevel) -> &'static str {
    match level {
        IsolationLevel::ReadUncommitted => "read_uncommitted",
        IsolationLevel::ReadCommitted => "read_committed",
    }
}

#[cfg(feature = "kafka")]
fn duration_to_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "kafka")]
fn build_consumer_config(config: &ConsumerConfig) -> rdkafka::ClientConfig {
    let mut client = rdkafka::ClientConfig::new();
    // Raw passthrough first: the typed setters below override any key they
    // own, so typed fields win on conflict (documented on `with_property`).
    for (key, value) in &config.extra_properties {
        client.set(key.as_str(), value.as_str());
    }
    client.set("bootstrap.servers", config.bootstrap_servers.join(","));
    apply_security_config(&mut client, &config.security);
    client.set("group.id", &config.group_id);
    if let Some(client_id) = &config.client_id {
        client.set("client.id", client_id);
    }
    client.set(
        "session.timeout.ms",
        duration_to_millis(config.session_timeout).to_string(),
    );
    client.set(
        "heartbeat.interval.ms",
        duration_to_millis(config.heartbeat_interval).to_string(),
    );
    client.set(
        "auto.offset.reset",
        auto_offset_reset_str(config.auto_offset_reset),
    );
    client.set("enable.auto.commit", config.enable_auto_commit.to_string());
    client.set("enable.auto.offset.store", "false");
    client.set(
        "auto.commit.interval.ms",
        duration_to_millis(config.auto_commit_interval).to_string(),
    );
    client.set("fetch.min.bytes", config.fetch_min_bytes.to_string());
    client.set("fetch.max.bytes", config.fetch_max_bytes.to_string());
    client.set(
        "fetch.wait.max.ms",
        duration_to_millis(config.fetch_max_wait).to_string(),
    );
    client.set(
        "isolation.level",
        isolation_level_str(config.isolation_level),
    );
    client.set("enable.partition.eof", "true");
    client
}

#[cfg(feature = "kafka")]
fn map_consumer_error(err: RdKafkaError) -> KafkaError {
    match err {
        RdKafkaError::Canceled => KafkaError::Cancelled,
        RdKafkaError::ClientConfig(result, _, key, _) => {
            KafkaError::Config(redacted_config_message(result, &key))
        }
        RdKafkaError::ClientCreation(msg) | RdKafkaError::Subscription(msg) => {
            KafkaError::Config(msg)
        }
        _ => KafkaError::Broker(err.to_string()),
    }
}

#[cfg(feature = "kafka")]
fn consumer_retry_backoff(config: &ConsumerConfig, attempt: u32) -> Duration {
    let base_ms = config.heartbeat_interval.as_millis().max(1) as u64;
    let exp = 1_u64 << attempt.min(6);
    Duration::from_millis(base_ms.saturating_mul(exp).min(5000))
}

#[cfg(feature = "kafka")]
async fn wait_consumer_retry_backoff(cx: &Cx, delay: Duration) -> Result<(), KafkaError> {
    if delay.is_zero() {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        crate::runtime::yield_now().await;
        return cx.checkpoint().map_err(|_| KafkaError::Cancelled);
    }

    let now = cx
        .timer_driver()
        .map_or_else(crate::time::wall_now, |driver| driver.now());
    let mut sleeper = crate::time::sleep(now, delay);
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return std::task::Poll::Ready(Err(KafkaError::Cancelled));
        }
        std::pin::Pin::new(&mut sleeper)
            .poll(task_cx)
            .map(|()| Ok(()))
    })
    .await
}

#[cfg(feature = "kafka")]
async fn retry_consumer_operation<T, F, Fut>(
    cx: &Cx,
    config: &ConsumerConfig,
    mut attempt_operation: F,
) -> Result<T, KafkaError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, KafkaError>>,
{
    let mut attempt = 0;
    loop {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        match attempt_operation().await {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt < config.retries => {
                let delay = consumer_retry_backoff(config, attempt);
                attempt = attempt.saturating_add(1);
                wait_consumer_retry_backoff(cx, delay).await?;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(feature = "kafka")]
fn offset_from_rdkafka(offset: Offset) -> Option<i64> {
    match offset {
        Offset::Offset(value) if value >= 0 => Some(value),
        _ => None,
    }
}

#[cfg(feature = "kafka")]
fn broker_snapshot_from_topic_maps(
    assigned: BTreeSet<(String, i32)>,
    positions: BTreeMap<(String, i32), i64>,
) -> BrokerSnapshot {
    BrokerSnapshot {
        assigned_partitions: assigned,
        positions,
    }
}

#[cfg(feature = "kafka")]
fn capture_broker_snapshot(
    consumer: &BaseConsumer<BrokerConsumerContext>,
) -> Result<BrokerSnapshot, KafkaError> {
    let assignment = consumer.assignment().map_err(map_consumer_error)?;
    let assigned_partitions: BTreeSet<(String, i32)> =
        assignment.to_topic_map().into_keys().collect();
    let positions = if assigned_partitions.is_empty() {
        BTreeMap::new()
    } else {
        consumer
            .position()
            .map_err(map_consumer_error)?
            .to_topic_map()
            .into_iter()
            .filter_map(|(key, offset)| offset_from_rdkafka(offset).map(|offset| (key, offset)))
            .collect()
    };
    Ok(broker_snapshot_from_topic_maps(
        assigned_partitions,
        positions,
    ))
}

#[cfg(feature = "kafka")]
fn consumer_record_from_message(message: &impl Message) -> NullableConsumerRecord {
    let headers = message
        .headers()
        .map(|headers| {
            (0..headers.count())
                .map(|index| {
                    let header = headers.get(index);
                    (
                        header.key.to_string(),
                        header.value.map(std::borrow::ToOwned::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    NullableConsumerRecord {
        topic: message.topic().to_string(),
        partition: message.partition(),
        offset: message.offset(),
        key: message.key().map(std::borrow::ToOwned::to_owned),
        payload: message.payload().map(std::borrow::ToOwned::to_owned),
        timestamp: message.timestamp().to_millis(),
        headers,
    }
}

/// Rebases a broker poll result still buffered when `seek` moves
/// `(topic, partition)` to `offset` (a poll was cancelled after its broker
/// poll finished). A record it holds for that partition was fetched before the
/// seek and is dropped: the broker fetches again from the new offset. Its
/// snapshot takes the new position, so applying it later cannot move the
/// partition back to where it was before the seek. A record for another
/// partition is kept.
#[cfg(feature = "kafka")]
fn rebase_buffered_after_seek(
    buffered: &mut Option<Result<BrokerPollOutcome, KafkaError>>,
    topic: &str,
    partition: i32,
    offset: i64,
) {
    if let Some(Ok(outcome)) = buffered {
        if outcome
            .record
            .as_ref()
            .is_some_and(|record| record.topic == topic && record.partition == partition)
        {
            outcome.record = None;
        }
        outcome
            .snapshot
            .positions
            .insert((topic.to_string(), partition), offset);
    }
}

#[cfg(feature = "kafka")]
fn apply_broker_snapshot(state: &mut ConsumerState, snapshot: BrokerSnapshot) {
    let previous_assignments = state.assigned_partitions.clone();
    if previous_assignments != snapshot.assigned_partitions {
        state.rebalance_generation = state.rebalance_generation.saturating_add(1);
        state.last_revoked_partitions = previous_assignments
            .difference(&snapshot.assigned_partitions)
            .cloned()
            .collect();
    }

    state.assigned_partitions = snapshot.assigned_partitions;
    state
        .positions
        .retain(|key, _| state.assigned_partitions.contains(key));
    for (key, offset) in snapshot.positions {
        if state.assigned_partitions.contains(&key) {
            state.positions.insert(key, offset);
        }
    }
}

impl KafkaConsumer {
    /// Create a new Kafka consumer.
    pub fn new(config: ConsumerConfig) -> Result<Self, KafkaError> {
        config.validate()?;
        #[cfg(feature = "kafka")]
        let consumer = if cfg!(not(test)) || config.force_real_kafka {
            let client_config = build_consumer_config(&config);
            let cooperative = client_config
                .get("partition.assignment.strategy")
                .is_some_and(|strategy| strategy.contains("cooperative-sticky"));
            let counters = Arc::new(RebalanceCounters::default());
            let base = client_config
                .create_with_context::<BrokerConsumerContext, BaseConsumer<BrokerConsumerContext>>(
                    BrokerConsumerContext {
                        cooperative,
                        counters: Arc::clone(&counters),
                    },
                )
                .map_err(map_consumer_error)?;
            Some((base, cooperative, counters))
        } else {
            None
        };
        #[cfg(feature = "kafka")]
        let (consumer, rebalance) = match consumer {
            Some((base, cooperative, counters)) => {
                (Some(Arc::new(base)), Some((cooperative, counters)))
            }
            None => (None, None),
        };
        #[cfg(feature = "kafka")]
        let broker_ops = consumer.as_ref().map(|_| Arc::new(BrokerOperations::default()));
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(ConsumerState::default())),
            closed: Arc::new(AtomicBool::new(false)),
            state_notify: Notify::new(),
            #[cfg(feature = "kafka")]
            consumer,
            #[cfg(feature = "kafka")]
            rebalance,
            #[cfg(feature = "kafka")]
            broker_ops,
            #[cfg(feature = "kafka")]
            buffered_outcome: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            rebalance_after_open_hook: Mutex::new(None),
            #[cfg(all(test, not(feature = "kafka")))]
            poll_before_wait_hook: Mutex::new(None),
        })
    }

    /// Which rebalance path this consumer has taken so far
    /// (br-asupersync-bi2462.26).
    ///
    /// Whether the handler was configured cooperative, and how many
    /// incremental vs eager assign/unassign callbacks ran.
    #[must_use]
    pub fn rebalance_stats(&self) -> RebalanceStats {
        #[cfg(feature = "kafka")]
        {
            self.rebalance
                .as_ref()
                .map_or_else(RebalanceStats::default, |(cooperative, counters)| {
                    counters.snapshot(*cooperative)
                })
        }
        #[cfg(not(feature = "kafka"))]
        {
            RebalanceStats::default()
        }
    }

    /// The rebalance protocol the group negotiated for this consumer.
    ///
    /// Read from librdkafka outside any rebalance callback (where it is safe
    /// to query). [`KafkaRebalanceProtocol::Unknown`] before a group is
    /// joined, without a broker backend, or without the `kafka` feature.
    #[must_use]
    pub fn rebalance_protocol(&self) -> KafkaRebalanceProtocol {
        #[cfg(feature = "kafka")]
        {
            use rdkafka::consumer::RebalanceProtocol;
            match self
                .consumer
                .as_ref()
                .map(|consumer| consumer.rebalance_protocol())
            {
                Some(RebalanceProtocol::Eager) => KafkaRebalanceProtocol::Eager,
                Some(RebalanceProtocol::Cooperative) => KafkaRebalanceProtocol::Cooperative,
                Some(RebalanceProtocol::None) | None => KafkaRebalanceProtocol::Unknown,
            }
        }
        #[cfg(not(feature = "kafka"))]
        {
            KafkaRebalanceProtocol::Unknown
        }
    }

    #[cfg(feature = "kafka")]
    fn broker_backend(&self) -> Option<(BrokerConsumerLease, Arc<BrokerOperations>)> {
        self.consumer
            .as_ref()
            .zip(self.broker_ops.as_ref())
            .and_then(|(consumer, broker_ops)| {
                BrokerConsumerLease::acquire(consumer, broker_ops)
                    .map(|lease| (lease, Arc::clone(broker_ops)))
            })
    }

    #[cfg(test)]
    fn install_rebalance_after_open_hook(&self, hook: Arc<RebalanceAfterOpenHook>) {
        *self.rebalance_after_open_hook.lock() = Some(hook);
    }

    #[cfg(all(test, not(feature = "kafka")))]
    fn install_poll_before_wait_hook(&self, hook: Arc<PollBeforeWaitHook>) {
        *self.poll_before_wait_hook.lock() = Some(hook);
    }

    /// Copy only wrapper state for private state-machine tests. The absent
    /// native metadata deliberately makes the public enrollment API refuse it.
    #[cfg(test)]
    pub(crate) fn group_metadata_for_state_test(&self) -> ConsumerGroupMetadata {
        let state = self.state.lock();
        ConsumerGroupMetadata {
            inner: Arc::new(ConsumerGroupMetadataInner {
                group_id: self.config.group_id.clone(),
                generation: state.rebalance_generation,
                assignments: state.assigned_partitions.clone(),
                state: Arc::downgrade(&self.state),
                closed: Arc::downgrade(&self.closed),
                #[cfg(feature = "kafka")]
                native: None,
            }),
        }
    }

    /// Subscribe to a set of topics.
    #[allow(unused_variables)]
    pub async fn subscribe(&self, cx: &Cx, topics: &[&str]) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;

        if topics.is_empty() {
            return Err(KafkaError::Config("topics cannot be empty".to_string()));
        }

        let mut normalized = BTreeSet::new();
        for topic in topics {
            let topic = topic.trim();
            if topic.is_empty() {
                return Err(KafkaError::Config("topic cannot be empty".to_string()));
            }
            normalized.insert(topic.to_string());
        }

        #[cfg(feature = "kafka")]
        if let Some((consumer, broker_ops)) = self.broker_backend() {
            let topic_list: Vec<String> = normalized.iter().cloned().collect();
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                let _guard = broker_ops.lock();
                let topic_refs: Vec<&str> = topic_list.iter().map(String::as_str).collect();
                consumer.subscribe(&topic_refs).map_err(map_consumer_error)
            })
            .await?;
        }

        if self.broker_operations_feature_disabled() {
            return Err(KafkaError::FeatureDisabled);
        }

        let mut state = self.state.lock();
        // Re-check closed under lock to prevent TOCTOU race with close().
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        let resubscribed = !state.subscribed_topics.is_empty();
        state.subscribed_topics = normalized;
        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        {
            state.assigned_partitions = state
                .subscribed_topics
                .iter()
                .cloned()
                .map(|topic| (topic, 0))
                .collect();
        }
        #[cfg(feature = "kafka")]
        {
            if self.broker_backend().is_some() {
                state.assigned_partitions.clear();
            } else {
                state.assigned_partitions = state
                    .subscribed_topics
                    .iter()
                    .cloned()
                    .map(|topic| (topic, 0))
                    .collect();
            }
        }
        state.positions.clear();
        // The generation is monotonic: a new subscription is a membership
        // change, so group metadata captured before it must never validate
        // again. Resetting it to 0 let two later rebalances bring stale
        // metadata back to a matching generation (asupersync-lde436).
        if resubscribed {
            state.rebalance_generation = state.rebalance_generation.saturating_add(1);
        }
        state.last_revoked_partitions.clear();
        drop(state);
        self.state_notify.notify_waiters();
        Ok(())
    }

    /// Apply a deterministic rebalance assignment.
    ///
    /// The provided assignments replace current partition ownership. Any
    /// previously assigned partition not present in `assignments` is revoked.
    #[allow(clippy::too_many_lines)]
    pub async fn rebalance(
        &self,
        cx: &Cx,
        assignments: &[TopicPartitionOffset],
    ) -> Result<RebalanceResult, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;

        if self.broker_operations_feature_disabled() {
            return Err(KafkaError::FeatureDisabled);
        }

        #[cfg(test)]
        let rebalance_after_open_hook = self.rebalance_after_open_hook.lock().clone();
        #[cfg(test)]
        if let Some(hook) = rebalance_after_open_hook {
            hook.arrived.wait();
            hook.release.wait();
        }

        let mut normalized = BTreeMap::new();
        let (next_assignments, assigned, revoked) = {
            let state = self.state.lock();
            if self.closed.load(Ordering::Acquire) {
                return Err(KafkaError::Config("consumer is closed".to_string()));
            }
            if state.subscribed_topics.is_empty() {
                return Err(KafkaError::Config(
                    "consumer has no active topic subscription".to_string(),
                ));
            }

            for tpo in assignments {
                if tpo.topic.trim().is_empty() {
                    return Err(KafkaError::Config("topic cannot be empty".to_string()));
                }
                validate_partition_number(tpo.partition)?;
                if !state.subscribed_topics.contains(&tpo.topic) {
                    return Err(KafkaError::InvalidTopic(tpo.topic.clone()));
                }
                if tpo.offset < 0 {
                    return Err(KafkaError::Config(
                        "rebalance offsets must be non-negative".to_string(),
                    ));
                }
                if normalized
                    .insert((tpo.topic.clone(), tpo.partition), tpo.offset)
                    .is_some()
                {
                    return Err(KafkaError::Config(
                        "duplicate topic/partition entry in rebalance batch".to_string(),
                    ));
                }
            }
            let previous_assignments = state.assigned_partitions.clone();
            let next_assignments: BTreeSet<(String, i32)> = normalized.keys().cloned().collect();
            let revoked: Vec<(String, i32)> = previous_assignments
                .difference(&next_assignments)
                .cloned()
                .collect();
            let assigned: Vec<(String, i32)> = next_assignments.iter().cloned().collect();
            drop(state);
            (next_assignments, assigned, revoked)
        };

        #[cfg(feature = "kafka")]
        if let Some((consumer, broker_ops)) = self.broker_backend() {
            let assignment_list: Vec<TopicPartitionOffset> = assignments.to_vec();
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                let _guard = broker_ops.lock();
                if assignment_list.is_empty() {
                    if matches!(
                        consumer.rebalance_protocol(),
                        rdkafka::consumer::RebalanceProtocol::Cooperative
                    ) {
                        // Cooperative consumers reject eager unassign. Unlike close(),
                        // this path has not left the group and drained revoke callbacks,
                        // so it must explicitly remove the actual native assignment.
                        let current = consumer.assignment().map_err(map_consumer_error)?;
                        consumer
                            .incremental_unassign(&current)
                            .map_err(map_consumer_error)
                    } else {
                        consumer.unassign().map_err(map_consumer_error)
                    }
                } else if matches!(
                    consumer.rebalance_protocol(),
                    rdkafka::consumer::RebalanceProtocol::Cooperative
                ) {
                    let current = consumer.assignment().map_err(map_consumer_error)?;
                    let mut to_unassign = TopicPartitionList::new();
                    for elem in current.elements() {
                        let in_target = assignment_list.iter().any(|tpo| {
                            tpo.topic == elem.topic() && tpo.partition == elem.partition()
                        });
                        if !in_target {
                            to_unassign.add_partition(elem.topic(), elem.partition());
                        }
                    }
                    if to_unassign.count() > 0 {
                        consumer
                            .incremental_unassign(&to_unassign)
                            .map_err(map_consumer_error)?;
                    }

                    let mut to_assign = TopicPartitionList::new();
                    for tpo in &assignment_list {
                        let already_assigned = current.elements().iter().any(|elem| {
                            elem.topic() == tpo.topic && elem.partition() == tpo.partition
                        });
                        if !already_assigned {
                            to_assign
                                .add_partition_offset(
                                    &tpo.topic,
                                    tpo.partition,
                                    Offset::Offset(tpo.offset),
                                )
                                .map_err(map_consumer_error)?;
                        } else {
                            consumer
                                .seek(
                                    &tpo.topic,
                                    tpo.partition,
                                    Offset::Offset(tpo.offset),
                                    Duration::from_secs(1),
                                )
                                .map_err(map_consumer_error)?;
                        }
                    }
                    if to_assign.count() > 0 {
                        consumer
                            .incremental_assign(&to_assign)
                            .map_err(map_consumer_error)?;
                    }
                    Ok(())
                } else {
                    let mut tpl = TopicPartitionList::new();
                    for tpo in &assignment_list {
                        tpl.add_partition_offset(
                            &tpo.topic,
                            tpo.partition,
                            Offset::Offset(tpo.offset),
                        )
                        .map_err(map_consumer_error)?;
                    }
                    consumer.assign(&tpl).map_err(map_consumer_error)
                }
            })
            .await?;
        }

        let mut state = self.state.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        state.assigned_partitions = next_assignments;
        let retained_assignments = state.assigned_partitions.clone();
        state
            .positions
            .retain(|key, _| retained_assignments.contains(key));
        for (partition, offset) in normalized {
            state.positions.insert(partition, offset);
        }
        state.rebalance_generation = state.rebalance_generation.saturating_add(1);
        state.last_revoked_partitions = revoked.iter().cloned().collect();
        let generation = state.rebalance_generation;
        drop(state);
        self.state_notify.notify_waiters();

        Ok(RebalanceResult {
            generation,
            assigned,
            revoked,
        })
    }

    /// Poll for the next record.
    ///
    /// Returns `Ok(None)` when no record arrived before `timeout`. Errors
    /// from the broker backend are returned as `Err`, with one exception:
    /// librdkafka's informational `UnknownTopicOrPartition` (reported while a
    /// subscribed topic is still being created or its metadata propagates)
    /// self-heals once the topic exists, so it is treated as "no message
    /// yet" and polling continues until the deadline. Such an occurrence is
    /// recorded and readable through [`KafkaConsumer::last_transient_error`]
    /// and traced once per distinct code. Transport failures still return
    /// `Err`.
    ///
    /// Null payloads and header values are mapped to empty bytes for backwards
    /// compatibility. Use [`Self::poll_nullable`] to distinguish tombstones.
    pub async fn poll(
        &self,
        cx: &Cx,
        timeout: Duration,
    ) -> Result<Option<ConsumerRecord>, KafkaError> {
        self.poll_nullable(cx, timeout)
            .await
            .map(|record| record.map(ConsumerRecord::from))
    }

    /// Poll for the next record without collapsing Kafka null values.
    ///
    /// A null payload remains `None`, while an empty payload remains
    /// `Some(Vec::new())`. Null header values, duplicate header names, and their
    /// order are also retained. This permits compacted-topic consumers to apply
    /// keyed tombstones as deletes instead of overwriting a value with emptiness.
    ///
    /// Timeout, assignment, cancellation, offset storage and retry semantics are
    /// identical to [`Self::poll`]. Both entry points consume the same stream;
    /// switching between them does not redeliver or skip a buffered record.
    #[allow(unused_variables, clippy::too_many_lines)]
    pub async fn poll_nullable(
        &self,
        cx: &Cx,
        timeout: Duration,
    ) -> Result<Option<NullableConsumerRecord>, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;

        if self.broker_operations_feature_disabled() {
            return Err(KafkaError::FeatureDisabled);
        }

        self.ensure_has_subscription()?;

        #[cfg(feature = "kafka")]
        {
            if let Some((consumer, broker_ops)) = self.broker_backend() {
                let auto_commit = self.config.enable_auto_commit;
                // br-asupersync-mskwk7: route deadline computation
                // through `cx.timer_driver()` so a VirtualClock-backed
                // lab harness can drive deterministic poll timeouts on
                // the kafka-feature broker-backend path. Pre-fix this
                // path read `wall_now()` directly, defeating
                // `LabRuntime::advance` (mirroring the same defect that
                // br-asupersync-my0rls fixed for the no-kafka fallback path).
                let now_fn = || {
                    cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |d| d.now())
                };
                let deadline = now_fn().saturating_add_nanos(duration_to_nanos(timeout));
                let mut first_iteration = true;

                loop {
                    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
                    let now = now_fn();

                    // The result of the broker poll that just finished is
                    // taken before the deadline is checked. Checked first,
                    // a record fetched as the deadline passed (its offset
                    // already stored under auto-commit) stayed buffered, and
                    // the next poll replayed it, even after a seek.
                    let buffered_res = self.buffered_outcome.lock().take();
                    if let Some(res) = buffered_res {
                        match res {
                            Ok(outcome) => {
                                // br-asupersync-yis4hl: apply the broker snapshot
                                // (which may reflect a rebalance that occurred
                                // between consumer.poll() and now) and check
                                // ATOMICALLY under the state lock that the
                                // record's (topic, partition) is still in our
                                // assignment. If revoked, DROP the record —
                                // delivering it would let the application
                                // process records for a partition we no longer
                                // own (Kafka protocol violation; offset
                                // clobber on the successor consumer in the
                                // adversarial case).
                                //
                                // The auto-commit at line ~892 has already
                                // written to rdkafka's local offset store, but
                                // the broker rejects offset commits with a
                                // stale generation id (standard Kafka
                                // ConsumerGroupGeneration fence), so the
                                // server-side state is naturally protected.
                                // The remaining defense is to not let the
                                // application observe the revoked record.
                                let (dropped_record_for_revoked, announce_transient): (
                                    bool,
                                    Option<TransientConsumerError>,
                                ) = {
                                    let mut state = self.state.lock();
                                    apply_broker_snapshot(&mut state, outcome.snapshot);
                                    let announce = outcome.transient_error.and_then(|code| {
                                        record_transient_error(&mut state, code, now_fn())
                                    });
                                    let dropped = if let Some(ref rec) = outcome.record {
                                        let owned = state
                                            .assigned_partitions
                                            .contains(&(rec.topic.clone(), rec.partition));
                                        !owned
                                    } else {
                                        false
                                    };
                                    (dropped, announce)
                                };
                                if let Some(transient) = announce_transient {
                                    // Once per distinct code, not once per poll: the
                                    // condition self-heals and a busy consumer would
                                    // otherwise emit a line every 50 ms.
                                    cx.trace(&format!(
                                        "kafka consumer: transient {} while polling; kept polling until the deadline",
                                        transient.code
                                    ));
                                }

                                if !dropped_record_for_revoked {
                                    if let Some(record) = outcome.record {
                                        return Ok(Some(record));
                                    }
                                }
                                // Revoked record dropped silently. The next
                                // poll iteration will fetch a fresh record
                                // for an actually-owned partition.
                            }
                            Err(e) => return Err(e),
                        }
                        if timeout.is_zero() {
                            return Ok(None);
                        }
                        first_iteration = false;
                        continue;
                    }

                    if !first_iteration && now >= deadline {
                        return Ok(None);
                    }

                    let wait_for = if timeout.is_zero() {
                        Duration::ZERO
                    } else {
                        let remaining = Duration::from_nanos(deadline.duration_since(now));
                        remaining.min(MAX_BROKER_POLL_SLICE)
                    };

                    let outcome_res = crate::runtime::spawn_blocking::spawn_blocking_on_thread({
                        let consumer = consumer.clone();
                        let broker_ops = Arc::clone(&broker_ops);
                        let buffered_outcome = Arc::clone(&self.buffered_outcome);
                        move || -> Result<(), KafkaError> {
                            let _guard = broker_ops.lock();
                            // The broker thread of a poll whose future was
                            // dropped may have buffered its result while this
                            // one waited for the lock. Polling again would
                            // overwrite that record, already past its position
                            // (and stored under auto-commit): leave it for the
                            // caller (br-asupersync-pm29wb).
                            if buffered_outcome.lock().is_some() {
                                return Ok(());
                            }
                            let mut transient_error: Option<&'static str> = None;
                            let record = match consumer.poll(wait_for) {
                                Some(Ok(message)) => {
                                    if auto_commit {
                                        if let Err(e) = consumer
                                            .store_offset_from_message(&message)
                                            .map_err(map_consumer_error)
                                        {
                                            *buffered_outcome.lock() = Some(Err(e));
                                            return Ok(());
                                        }
                                    }
                                    Some(consumer_record_from_message(&message))
                                }
                                Some(Err(
                                    RdKafkaError::NoMessageReceived | RdKafkaError::PartitionEOF(_),
                                ))
                                | None => None,
                                // librdkafka raises this informational error while a
                                // subscribed topic is still being created or its
                                // metadata is propagating (a consumer that subscribes
                                // before the first produce sees it against Redpanda
                                // and Kafka alike). It self-heals once the topic
                                // appears, so it is "no message yet", not a failure:
                                // keep polling until the caller's deadline.
                                Some(Err(RdKafkaError::MessageConsumption(
                                    RDKafkaErrorCode::UnknownTopicOrPartition,
                                ))) => {
                                    transient_error = Some("UnknownTopicOrPartition");
                                    None
                                }
                                Some(Err(err)) => {
                                    *buffered_outcome.lock() = Some(Err(map_consumer_error(err)));
                                    return Ok(());
                                }
                            };
                            let snapshot = match capture_broker_snapshot(&consumer) {
                                Ok(s) => s,
                                Err(e) => {
                                    *buffered_outcome.lock() = Some(Err(e));
                                    return Ok(());
                                }
                            };
                            #[cfg(test)]
                            let has_record = record.is_some();
                            *buffered_outcome.lock() = Some(Ok(BrokerPollOutcome {
                                record,
                                snapshot,
                                transient_error,
                            }));
                            #[cfg(test)]
                            if has_record {
                                let hook = broker_ops.after_record_buffered.lock().take();
                                if let Some(hook) = hook {
                                    let _ = hook.published.send_blocking(());
                                    hook.release
                                        .recv_timeout(Duration::from_secs(20))
                                        .expect("release the buffered-record witness");
                                }
                            }
                            Ok(())
                        }
                    })
                    .await;

                    outcome_res?;
                }
            }
        }

        #[cfg(feature = "kafka")]
        {
            // Fall back to deterministic test-mode behavior when force_real_kafka is false.
            if timeout.is_zero() {
                return Ok(None);
            }

            // br-asupersync-6mlvbi: route deadline through
            // `cx.timer_driver()` on the kafka-feature fallback path
            // (this branch fires when broker_backend() returns None
            // even though the kafka feature is enabled — typically a
            // test harness with force_real_kafka=false). Same defect
            // shape as br-asupersync-mskwk7 (kafka broker backend
            // path) and br-asupersync-my0rls (no-kafka fallback path).
            let now_fn = || {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |d| d.now())
            };
            let deadline = now_fn().saturating_add_nanos(duration_to_nanos(timeout));
            loop {
                cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

                let mut state_wait = self.state_notify.notified();
                let mut sleep = Sleep::new(deadline);

                self.ensure_open()?;
                self.ensure_has_subscription()?;
                if now_fn() >= deadline {
                    return Ok(None);
                }

                () = std::future::poll_fn(|task_cx| {
                    if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                        return Poll::Ready(());
                    }
                    if Pin::new(&mut sleep).poll(task_cx).is_ready() {
                        return Poll::Ready(());
                    }
                    if Pin::new(&mut state_wait).poll(task_cx).is_ready() {
                        return Poll::Ready(());
                    }
                    Poll::Pending
                })
                .await;
            }
        }

        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        {
            if let Some(record) = self.try_poll_local_record()? {
                return Ok(Some(record));
            }

            if timeout.is_zero() {
                return Ok(None);
            }

            // br-asupersync-my0rls: route the deadline computation
            // through `cx.timer_driver()` when one is attached so a
            // VirtualClock-backed lab harness can advance time and
            // unblock the poll deterministically. The previous shape
            // pinned the deadline to wall-clock via `wall_now()` even
            // in the no-kafka fallback path, defeating
            // `LabRuntime::advance` for any test that relied on
            // exercising poll-timeout flow without the kafka feature.
            // Mirrors the pattern at messaging/kafka.rs line 522-524.
            let now_fn = || {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |d| d.now())
            };
            let deadline = now_fn().saturating_add_nanos(duration_to_nanos(timeout));
            loop {
                cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

                #[cfg(all(test, not(feature = "kafka")))]
                let poll_before_wait_hook = self.poll_before_wait_hook.lock().clone();
                #[cfg(all(test, not(feature = "kafka")))]
                if let Some(hook) = poll_before_wait_hook {
                    hook.arrived.wait();
                    hook.release.wait();
                }

                let mut state_wait = self.state_notify.notified();
                let mut broker_wait = deterministic_broker_notify().notified();
                let mut sleep = Sleep::new(deadline);

                self.ensure_open()?;
                self.ensure_has_subscription()?;
                if let Some(record) = self.try_poll_local_record()? {
                    return Ok(Some(record));
                }
                if now_fn() >= deadline {
                    return Ok(None);
                }

                () = std::future::poll_fn(|task_cx| {
                    if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                        return Poll::Ready(());
                    }
                    if Pin::new(&mut sleep).poll(task_cx).is_ready() {
                        return Poll::Ready(());
                    }
                    if Pin::new(&mut state_wait).poll(task_cx).is_ready() {
                        return Poll::Ready(());
                    }
                    if Pin::new(&mut broker_wait).poll(task_cx).is_ready() {
                        return Poll::Ready(());
                    }
                    Poll::Pending
                })
                .await;
            }
        }

        #[cfg(all(not(feature = "kafka"), not(any(test, feature = "test-internals"))))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }

    /// Capture group membership for an atomic consume/produce transaction.
    ///
    /// Automatic consumer commits must be disabled. After processing records,
    /// pass this snapshot and their next offsets to
    /// [`super::kafka::Transaction::send_offsets_to_transaction`], then commit
    /// the producer transaction. Do not also call [`Self::commit_offsets`].
    /// Capture a new snapshot for each transaction, and after every rebalance.
    ///
    /// The native metadata copy is made on a dedicated blocking thread under the
    /// same operation lease as other consumer calls, never on the runtime pool,
    /// where a scoped consumer's lifetime job holds a worker until release. Its
    /// lifetime is independent of the native consumer. The no-`kafka` and
    /// model-only test backends return [`KafkaError::FeatureDisabled`]; they
    /// cannot attest broker atomicity.
    #[allow(unused_variables)]
    pub async fn group_metadata(&self, cx: &Cx) -> Result<ConsumerGroupMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;
        if self.config.enable_auto_commit {
            return Err(KafkaError::Config(
                "transactional offsets require enable_auto_commit=false".into(),
            ));
        }

        #[cfg(feature = "kafka")]
        {
            let (consumer, broker_ops) = self.broker_backend().ok_or(KafkaError::FeatureDisabled)?;
            let state = Arc::clone(&self.state);
            let closed = Arc::clone(&self.closed);
            let group_id = self.config.group_id.clone();
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                let _guard = broker_ops.lock();
                if closed.load(Ordering::Acquire) {
                    return Err(KafkaError::Config("consumer is closed".into()));
                }
                let native = consumer.group_metadata().ok_or_else(|| {
                    KafkaError::Transaction("consumer has no broker group metadata".into())
                })?;
                let snapshot = capture_broker_snapshot(&consumer)?;
                let weak_state = Arc::downgrade(&state);
                let mut state = state.lock();
                apply_broker_snapshot(&mut state, snapshot);
                if state.assigned_partitions.is_empty() {
                    return Err(KafkaError::Transaction(
                        "consumer has no assigned partitions; poll before capturing metadata".into(),
                    ));
                }
                Ok(ConsumerGroupMetadata {
                    inner: Arc::new(ConsumerGroupMetadataInner {
                        group_id,
                        generation: state.rebalance_generation,
                        assignments: state.assigned_partitions.clone(),
                        state: weak_state,
                        closed: Arc::downgrade(&closed),
                        native: Some(native),
                    }),
                })
            })
            .await
        }
        #[cfg(not(feature = "kafka"))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }

    /// Commit offsets explicitly.
    #[allow(unused_variables)]
    pub async fn commit_offsets(
        &self,
        cx: &Cx,
        offsets: &[TopicPartitionOffset],
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;

        if self.broker_operations_feature_disabled() {
            return Err(KafkaError::FeatureDisabled);
        }

        if offsets.is_empty() {
            return Err(KafkaError::Config("offsets cannot be empty".to_string()));
        }

        let mut normalized = BTreeMap::new();
        {
            let state = self.state.lock();
            if self.closed.load(Ordering::Acquire) {
                return Err(KafkaError::Config("consumer is closed".to_string()));
            }
            for tpo in offsets {
                validate_partition_number(tpo.partition)?;
                if !state.subscribed_topics.contains(&tpo.topic) {
                    return Err(KafkaError::InvalidTopic(tpo.topic.clone()));
                }
                let key = (tpo.topic.clone(), tpo.partition);
                if !state.assigned_partitions.contains(&key) {
                    return Err(KafkaError::Config(
                        "partition is not assigned to this consumer".to_string(),
                    ));
                }
                if tpo.offset < 0 {
                    return Err(KafkaError::Config(
                        "offsets must be non-negative".to_string(),
                    ));
                }
                if let Some(previous) = state.committed_offsets.get(&key)
                    && tpo.offset < *previous
                {
                    return Err(KafkaError::Config(
                        "offset commit regression is not allowed".to_string(),
                    ));
                }
                if normalized.insert(key, tpo.offset).is_some() {
                    return Err(KafkaError::Config(
                        "duplicate topic/partition entry in commit batch".to_string(),
                    ));
                }
            }
            drop(state);
        }

        #[cfg(feature = "kafka")]
        if let Some((consumer, broker_ops)) = self.broker_backend() {
            let commit_batch = normalized.clone();
            let config = &self.config;

            retry_consumer_operation(cx, config, || {
                // Clone owned handles per attempt so the synchronous
                // `commit(CommitMode::Sync)` runs on the blocking pool via a
                // `'static` closure (matching subscribe/poll/etc.) instead of
                // pinning the executor worker thread through
                // `thread::scope().join()` for the full broker round-trip.
                let commit_batch = commit_batch.clone();
                let consumer = consumer.clone();
                let broker_ops = Arc::clone(&broker_ops);

                async move {
                    crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                        let _guard = broker_ops.lock();
                        let mut tpl = TopicPartitionList::new();
                        for ((topic, partition), offset) in &commit_batch {
                            tpl.add_partition_offset(topic, *partition, Offset::Offset(*offset))
                                .map_err(map_consumer_error)?;
                        }
                        consumer
                            .commit(&tpl, CommitMode::Sync)
                            .map_err(map_consumer_error)
                    })
                    .await
                }
            })
            .await?;
        }

        let mut state = self.state.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        for (key, offset) in normalized {
            state.committed_offsets.insert(key, offset);
        }
        drop(state);
        self.state_notify.notify_waiters();
        Ok(())
    }

    /// Seek to a specific offset.
    #[allow(unused_variables)]
    pub async fn seek(&self, cx: &Cx, tpo: &TopicPartitionOffset) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;

        if self.broker_operations_feature_disabled() {
            return Err(KafkaError::FeatureDisabled);
        }

        validate_partition_number(tpo.partition)?;
        if tpo.offset < 0 {
            return Err(KafkaError::Config(
                "seek offset must be non-negative".to_string(),
            ));
        }

        {
            let state = self.state.lock();
            if self.closed.load(Ordering::Acquire) {
                return Err(KafkaError::Config("consumer is closed".to_string()));
            }
            if !state.subscribed_topics.contains(&tpo.topic) {
                return Err(KafkaError::InvalidTopic(tpo.topic.clone()));
            }
            if !state
                .assigned_partitions
                .contains(&(tpo.topic.clone(), tpo.partition))
            {
                return Err(KafkaError::Config(
                    "partition is not assigned to this consumer".to_string(),
                ));
            }
        }

        #[cfg(feature = "kafka")]
        if let Some((consumer, broker_ops)) = self.broker_backend() {
            let topic = tpo.topic.clone();
            let partition = tpo.partition;
            let offset = tpo.offset;
            let buffered_outcome = Arc::clone(&self.buffered_outcome);
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                let _guard = broker_ops.lock();
                consumer
                    .seek(
                        &topic,
                        partition,
                        Offset::Offset(offset),
                        Duration::from_secs(1),
                    )
                    .map_err(map_consumer_error)?;
                rebase_buffered_after_seek(&mut buffered_outcome.lock(), &topic, partition, offset);
                Ok::<(), KafkaError>(())
            })
            .await?;
        }

        let mut state = self.state.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        state
            .positions
            .insert((tpo.topic.clone(), tpo.partition), tpo.offset);
        drop(state);
        self.state_notify.notify_waiters();
        Ok(())
    }

    /// Close the consumer.
    #[allow(unused_variables)]
    pub async fn close(&self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        let was_closed = self.closed.swap(true, Ordering::AcqRel);
        if !was_closed {
            #[cfg(feature = "kafka")]
            if let Some((consumer, broker_ops)) = self.broker_backend() {
                crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                    use rdkafka::consumer::RebalanceProtocol;
                    let _guard = broker_ops.lock();
                    leave_group_bounded(&consumer);
                    // `unassign()` is the EAGER API. librdkafka refuses it
                    // with `RD_KAFKA_RESP_ERR__STATE` ("Local: Erroneous
                    // state") on a consumer that negotiated the cooperative
                    // protocol, so a cooperative-sticky consumer used to fail
                    // its own close. The leave-group drain above already ran
                    // the revoke through the callback, which unassigns
                    // incrementally, so there is nothing left to drop here.
                    if matches!(
                        consumer.rebalance_protocol(),
                        RebalanceProtocol::Cooperative
                    ) {
                        Ok(())
                    } else {
                        consumer.unassign().map_err(map_consumer_error)
                    }
                })
                .await?;
            }
            let mut state = self.state.lock();
            state.subscribed_topics.clear();
            state.assigned_partitions.clear();
            state.committed_offsets.clear();
            state.positions.clear();
            state.last_revoked_partitions.clear();
            drop(state);
            self.state_notify.notify_waiters();
        }
        Ok(())
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &ConsumerConfig {
        &self.config
    }

    /// Snapshot of currently subscribed topics.
    #[must_use]
    pub fn subscriptions(&self) -> Vec<String> {
        self.state
            .lock()
            .subscribed_topics
            .iter()
            .cloned()
            .collect()
    }

    /// Snapshot of assigned topic/partitions for the current subscription.
    #[must_use]
    pub fn assigned_partitions(&self) -> Vec<(String, i32)> {
        self.state
            .lock()
            .assigned_partitions
            .iter()
            .cloned()
            .collect()
    }

    /// The most recent informational broker error that `poll` swallowed.
    ///
    /// Carries first/last occurrence times and a count (see
    /// [`TransientConsumerError`]). `None` until one occurs. Cleared only
    /// when a different code replaces it.
    #[must_use]
    pub fn last_transient_error(&self) -> Option<TransientConsumerError> {
        self.state.lock().last_transient_error.clone()
    }

    /// Monotonic rebalance generation counter.
    #[must_use]
    pub fn rebalance_generation(&self) -> u64 {
        self.state.lock().rebalance_generation
    }

    /// Snapshot of partitions revoked during the latest rebalance.
    #[must_use]
    pub fn last_revoked_partitions(&self) -> Vec<(String, i32)> {
        self.state
            .lock()
            .last_revoked_partitions
            .iter()
            .cloned()
            .collect()
    }

    /// Read committed offset for a topic/partition.
    #[must_use]
    pub fn committed_offset(&self, topic: &str, partition: i32) -> Option<i64> {
        self.state
            .lock()
            .committed_offsets
            .get(&(topic.to_string(), partition))
            .copied()
    }

    /// Read current seek position for a topic/partition.
    #[must_use]
    pub fn position(&self, topic: &str, partition: i32) -> Option<i64> {
        self.state
            .lock()
            .positions
            .get(&(topic.to_string(), partition))
            .copied()
    }

    /// Returns true once `close()` has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn ensure_open(&self) -> Result<(), KafkaError> {
        if self.closed.load(Ordering::Acquire) {
            Err(KafkaError::Config("consumer is closed".to_string()))
        } else {
            Ok(())
        }
    }

    fn ensure_has_subscription(&self) -> Result<(), KafkaError> {
        let state = self.state.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        if state.subscribed_topics.is_empty() {
            return Err(KafkaError::Config(
                "consumer has no active topic subscription".to_string(),
            ));
        }
        drop(state);
        Ok(())
    }

    fn broker_operations_feature_disabled(&self) -> bool {
        #[cfg(feature = "kafka")]
        {
            false
        }
        #[cfg(all(not(feature = "kafka"), test))]
        {
            false
        }
        #[cfg(all(not(feature = "kafka"), not(test), feature = "test-internals"))]
        {
            !self.config.allow_deterministic_broker_for_testing
        }
        #[cfg(all(not(feature = "kafka"), not(test), not(feature = "test-internals")))]
        {
            true
        }
    }

    #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
    fn try_poll_local_record(&self) -> Result<Option<NullableConsumerRecord>, KafkaError> {
        let mut state = self.state.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        if state.subscribed_topics.is_empty() {
            return Err(KafkaError::Config(
                "consumer has no active topic subscription".to_string(),
            ));
        }

        let assignments: Vec<(String, i32)> = state.assigned_partitions.iter().cloned().collect();
        if assignments.is_empty() {
            drop(state);
            return Ok(None);
        }

        let start = state.poll_cursor % assignments.len();
        for step in 0..assignments.len() {
            let index = (start + step) % assignments.len();
            let (topic, partition) = &assignments[index];
            let offset =
                Self::current_position_for_partition(&self.config, &mut state, topic, *partition)?;
            if let Some(record) = deterministic_broker_fetch(topic, *partition, offset) {
                state
                    .positions
                    .insert((topic.clone(), *partition), offset.saturating_add(1));
                state.poll_cursor = (index + 1) % assignments.len();
                drop(state);
                return Ok(Some(NullableConsumerRecord {
                    topic: record.topic,
                    partition: record.partition,
                    offset,
                    key: record.key,
                    payload: record.payload,
                    timestamp: record.timestamp,
                    headers: record.headers,
                }));
            }
        }

        drop(state);
        Ok(None)
    }

    #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
    fn current_position_for_partition(
        config: &ConsumerConfig,
        state: &mut ConsumerState,
        topic: &str,
        partition: i32,
    ) -> Result<i64, KafkaError> {
        let key = (topic.to_string(), partition);
        if let Some(position) = state.positions.get(&key) {
            return Ok(*position);
        }
        if let Some(committed) = state.committed_offsets.get(&key) {
            state.positions.insert(key, *committed);
            return Ok(*committed);
        }

        let initial_offset = match config.auto_offset_reset {
            AutoOffsetReset::Earliest => 0,
            AutoOffsetReset::Latest => deterministic_broker_end_offset(topic, partition),
            AutoOffsetReset::None => {
                return Err(KafkaError::Config(format!(
                    "no offset available for {topic}[{partition}] and auto_offset_reset is None"
                )));
            }
        };
        state.positions.insert(key, initial_offset);
        Ok(initial_offset)
    }
}

fn validate_partition_number(partition: i32) -> Result<(), KafkaError> {
    if partition < 0 {
        Err(KafkaError::Config(
            "partition must be non-negative".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "kafka")]
impl RebalanceCounters {
    /// Records partitions the group assigned through the rebalance callback:
    /// an eager assignment replaces the previous one, a cooperative one adds.
    fn group_assigned(&self, partitions: usize, replace: bool) {
        if replace {
            self.group_partitions.store(partitions, Ordering::Release);
        } else {
            self.group_partitions
                .fetch_add(partitions, Ordering::AcqRel);
        }
    }

    /// Records partitions the group revoked through the callback; `usize::MAX`
    /// revokes all of them.
    fn group_revoked(&self, partitions: usize) {
        let mut held = self.group_partitions.load(Ordering::Acquire);
        while let Err(actual) = self.group_partitions.compare_exchange_weak(
            held,
            held.saturating_sub(partitions),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            held = actual;
        }
    }
}

/// Whether this member still holds partitions: in its local assignment, or, for
/// an eager member, assigned by the group through the rebalance callback and not
/// yet revoked there (an explicit empty rebalance clears only the local
/// assignment). The eager callback answers a revoke with `unassign()`, which
/// succeeds whatever is assigned locally. A cooperative member answers with
/// `incremental_unassign(revoked)`, and draining that revoke after an explicit
/// empty rebalance hung in `native_empty_rebalance_cooperative_releases_assignment`,
/// so a cooperative member keeps the local-assignment test.
#[cfg(feature = "kafka")]
fn holds_partitions(consumer: &BaseConsumer<BrokerConsumerContext>) -> bool {
    let context = consumer.context();
    consumer
        .assignment()
        .map(|assignment| assignment.count() > 0)
        .unwrap_or(false)
        || (!context.cooperative && context.counters.group_partitions.load(Ordering::Acquire) > 0)
}

#[cfg(test)]
#[path = "kafka_consumer_inline_tests.rs"]
mod tests;
