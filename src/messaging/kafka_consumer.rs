//! Kafka consumer with Cx integration for cancel-correct message consumption.
//!
//! This module defines the API surface for a Kafka consumer that integrates
//! with the Asupersync `Cx` context. When the `kafka` feature is disabled, the
//! consumer uses the same harness-only deterministic in-process broker as the
//! fallback producer path so tests and contract validation can exercise
//! subscribe/poll/seek/commit semantics without implying a real Kafka
//! deployment.
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
use crate::messaging::kafka::KafkaError;
#[cfg(not(feature = "kafka"))]
use crate::messaging::kafka::{stub_broker_end_offset, stub_broker_fetch, stub_broker_notify};
use crate::sync::Notify;
#[cfg(any(not(feature = "kafka"), test))]
use crate::time::Sleep;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(any(not(feature = "kafka"), test))]
use std::future::Future;
#[cfg(any(not(feature = "kafka"), test))]
use std::pin::Pin;
#[cfg(any(test, feature = "kafka"))]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(not(feature = "kafka"), test))]
use std::task::Poll;
use std::time::Duration;

#[cfg(feature = "kafka")]
use rdkafka::{
    config::ClientConfig,
    consumer::{BaseConsumer, CommitMode, Consumer},
    error::KafkaError as RdKafkaError,
    message::{Headers, Message},
    topic_partition_list::{Offset, TopicPartitionList},
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
#[derive(Debug, Clone)]
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
    pub enable_auto_commit: bool,
    /// Auto-commit interval.
    pub auto_commit_interval: Duration,
    /// Max records returned per poll.
    pub max_poll_records: usize,
    /// Fetch minimum bytes.
    pub fetch_min_bytes: usize,
    /// Fetch maximum bytes.
    pub fetch_max_bytes: usize,
    /// Maximum wait time for fetch.
    pub fetch_max_wait: Duration,
    /// Isolation level for transactional reads.
    pub isolation_level: IsolationLevel,
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
            enable_auto_commit: true,
            auto_commit_interval: Duration::from_secs(5),
            max_poll_records: 500,
            fetch_min_bytes: 1,
            fetch_max_bytes: 50 * 1024 * 1024,
            fetch_max_wait: Duration::from_millis(500),
            isolation_level: IsolationLevel::ReadUncommitted,
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

    /// Set max records returned per poll.
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

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "kafka")]
const MAX_BROKER_POLL_SLICE: Duration = Duration::from_millis(50);

/// Kafka consumer with a harness-only deterministic brokerless fallback.
pub struct KafkaConsumer {
    config: ConsumerConfig,
    state: Mutex<ConsumerState>,
    closed: AtomicBool,
    state_notify: Notify,
    #[cfg(feature = "kafka")]
    consumer: Option<Arc<BaseConsumer>>,
    #[cfg(feature = "kafka")]
    broker_ops: Option<Arc<Mutex<()>>>,
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

#[derive(Debug, Default)]
struct ConsumerState {
    subscribed_topics: BTreeSet<String>,
    assigned_partitions: BTreeSet<(String, i32)>,
    committed_offsets: BTreeMap<(String, i32), i64>,
    positions: BTreeMap<(String, i32), i64>,
    #[cfg(not(feature = "kafka"))]
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
    record: Option<ConsumerRecord>,
    snapshot: BrokerSnapshot,
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
fn build_consumer_config(config: &ConsumerConfig) -> ClientConfig {
    let mut client = ClientConfig::new();
    client.set("bootstrap.servers", config.bootstrap_servers.join(","));
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
        RdKafkaError::ClientConfig(_, desc, key, value) => {
            KafkaError::Config(format!("{desc} (key: {key}, value: {value})"))
        }
        RdKafkaError::ClientCreation(msg) | RdKafkaError::Subscription(msg) => {
            KafkaError::Config(msg)
        }
        _ => KafkaError::Broker(err.to_string()),
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
fn capture_broker_snapshot(consumer: &BaseConsumer) -> Result<BrokerSnapshot, KafkaError> {
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
fn consumer_record_from_message(message: &rdkafka::message::BorrowedMessage<'_>) -> ConsumerRecord {
    let headers = message
        .headers()
        .map(|headers| {
            (0..headers.count())
                .map(|index| {
                    let header = headers.get(index);
                    (
                        header.key.to_string(),
                        header
                            .value
                            .map_or_else(Vec::new, std::borrow::ToOwned::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    ConsumerRecord {
        topic: message.topic().to_string(),
        partition: message.partition(),
        offset: message.offset(),
        key: message.key().map(std::borrow::ToOwned::to_owned),
        payload: message
            .payload()
            .map_or_else(Vec::new, std::borrow::ToOwned::to_owned),
        timestamp: message.timestamp().to_millis(),
        headers,
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
    state
        .committed_offsets
        .retain(|key, _| state.assigned_partitions.contains(key));
}

impl KafkaConsumer {
    /// Create a new Kafka consumer.
    pub fn new(config: ConsumerConfig) -> Result<Self, KafkaError> {
        config.validate()?;
        #[cfg(all(feature = "kafka", not(test)))]
        let consumer = Some(
            build_consumer_config(&config)
                .create::<BaseConsumer>()
                .map_err(map_consumer_error)?,
        );
        #[cfg(all(feature = "kafka", test))]
        let consumer = None;
        #[cfg(feature = "kafka")]
        let consumer = consumer.map(Arc::new);
        #[cfg(feature = "kafka")]
        let broker_ops = consumer.as_ref().map(|_| Arc::new(Mutex::new(())));
        Ok(Self {
            config,
            state: Mutex::new(ConsumerState::default()),
            closed: AtomicBool::new(false),
            state_notify: Notify::new(),
            #[cfg(feature = "kafka")]
            consumer,
            #[cfg(feature = "kafka")]
            broker_ops,
            #[cfg(test)]
            rebalance_after_open_hook: Mutex::new(None),
            #[cfg(all(test, not(feature = "kafka")))]
            poll_before_wait_hook: Mutex::new(None),
        })
    }

    #[cfg(feature = "kafka")]
    fn broker_backend(&self) -> Option<(Arc<BaseConsumer>, Arc<Mutex<()>>)> {
        self.consumer
            .as_ref()
            .zip(self.broker_ops.as_ref())
            .map(|(consumer, broker_ops)| (Arc::clone(consumer), Arc::clone(broker_ops)))
    }

    #[cfg(test)]
    fn install_rebalance_after_open_hook(&self, hook: Arc<RebalanceAfterOpenHook>) {
        *self.rebalance_after_open_hook.lock() = Some(hook);
    }

    #[cfg(all(test, not(feature = "kafka")))]
    fn install_poll_before_wait_hook(&self, hook: Arc<PollBeforeWaitHook>) {
        *self.poll_before_wait_hook.lock() = Some(hook);
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

        let mut state = self.state.lock();
        // Re-check closed under lock to prevent TOCTOU race with close().
        if self.closed.load(Ordering::Acquire) {
            return Err(KafkaError::Config("consumer is closed".to_string()));
        }
        state.subscribed_topics = normalized;
        #[cfg(not(feature = "kafka"))]
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
        state.committed_offsets.clear();
        state.rebalance_generation = 0;
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
                    consumer.unassign().map_err(map_consumer_error)
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
        state
            .committed_offsets
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
    #[allow(unused_variables, clippy::too_many_lines)]
    pub async fn poll(
        &self,
        cx: &Cx,
        timeout: Duration,
    ) -> Result<Option<ConsumerRecord>, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;
        self.ensure_has_subscription()?;

        #[cfg(feature = "kafka")]
        {
            if let Some((consumer, broker_ops)) = self.broker_backend() {
                let auto_commit = self.config.enable_auto_commit;
                let deadline =
                    crate::time::wall_now().saturating_add_nanos(duration_to_nanos(timeout));
                let mut first_iteration = true;

                loop {
                    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
                    let now = crate::time::wall_now();
                    if !first_iteration && now >= deadline {
                        return Ok(None);
                    }

                    let wait_for = if timeout.is_zero() {
                        Duration::ZERO
                    } else {
                        let remaining = Duration::from_nanos(deadline.duration_since(now));
                        remaining.min(MAX_BROKER_POLL_SLICE)
                    };

                    let outcome = crate::runtime::spawn_blocking::spawn_blocking_on_thread({
                        let consumer = Arc::clone(&consumer);
                        let broker_ops = Arc::clone(&broker_ops);
                        move || -> Result<BrokerPollOutcome, KafkaError> {
                            let _guard = broker_ops.lock();
                            let record = match consumer.poll(wait_for) {
                                Some(Ok(message)) => {
                                    if auto_commit {
                                        consumer
                                            .store_offset_from_message(&message)
                                            .map_err(map_consumer_error)?;
                                    }
                                    Some(consumer_record_from_message(&message))
                                }
                                Some(Err(
                                    RdKafkaError::NoMessageReceived | RdKafkaError::PartitionEOF(_),
                                ))
                                | None => None,
                                Some(Err(err)) => return Err(map_consumer_error(err)),
                            };
                            let snapshot = capture_broker_snapshot(&consumer)?;
                            Ok(BrokerPollOutcome { record, snapshot })
                        }
                    })
                    .await?;

                    let mut state = self.state.lock();
                    apply_broker_snapshot(&mut state, outcome.snapshot);
                    drop(state);

                    if let Some(record) = outcome.record {
                        return Ok(Some(record));
                    }
                    if timeout.is_zero() {
                        return Ok(None);
                    }
                    first_iteration = false;
                }
            }
        }

        #[cfg(all(feature = "kafka", not(test)))]
        unreachable!("feature-enabled KafkaConsumer should always have a broker backend");

        #[cfg(all(feature = "kafka", test))]
        {
            if timeout.is_zero() {
                return Ok(None);
            }

            let deadline = crate::time::wall_now().saturating_add_nanos(duration_to_nanos(timeout));
            loop {
                cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

                let mut state_wait = self.state_notify.notified();
                let mut sleep = Sleep::new(deadline);

                self.ensure_open()?;
                self.ensure_has_subscription()?;
                if crate::time::wall_now() >= deadline {
                    return Ok(None);
                }

                () = std::future::poll_fn(|task_cx| {
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

        #[cfg(not(feature = "kafka"))]
        {
            if let Some(record) = self.try_poll_local_record()? {
                return Ok(Some(record));
            }

            if timeout.is_zero() {
                return Ok(None);
            }

            let deadline = crate::time::wall_now().saturating_add_nanos(duration_to_nanos(timeout));
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
                let mut broker_wait = stub_broker_notify().notified();
                let mut sleep = Sleep::new(deadline);

                self.ensure_open()?;
                self.ensure_has_subscription()?;
                if let Some(record) = self.try_poll_local_record()? {
                    return Ok(Some(record));
                }
                if crate::time::wall_now() >= deadline {
                    return Ok(None);
                }

                () = std::future::poll_fn(|task_cx| {
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
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                let _guard = broker_ops.lock();
                consumer
                    .seek(
                        &topic,
                        partition,
                        Offset::Offset(offset),
                        Duration::from_secs(1),
                    )
                    .map_err(map_consumer_error)
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
                    let _guard = broker_ops.lock();
                    consumer.unsubscribe();
                    consumer.unassign().map_err(map_consumer_error)
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

    #[cfg(not(feature = "kafka"))]
    fn try_poll_local_record(&self) -> Result<Option<ConsumerRecord>, KafkaError> {
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
            if let Some(record) = stub_broker_fetch(topic, *partition, offset) {
                state
                    .positions
                    .insert((topic.clone(), *partition), offset.saturating_add(1));
                state.poll_cursor = (index + 1) % assignments.len();
                drop(state);
                return Ok(Some(ConsumerRecord {
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

    #[cfg(not(feature = "kafka"))]
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
            AutoOffsetReset::Latest => stub_broker_end_offset(topic, partition),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "kafka"))]
    use crate::messaging::kafka::{
        KafkaProducer, ProducerConfig, StubBrokerTestGuard, lock_stub_broker_for_tests,
    };
    use crate::test_utils::run_test_with_cx;
    #[cfg(feature = "kafka")]
    use rdkafka::topic_partition_list::Offset;
    use std::sync::Arc;
    #[cfg(not(feature = "kafka"))]
    use std::time::Instant;

    #[cfg(not(feature = "kafka"))]
    fn stub_broker_guard() -> StubBrokerTestGuard {
        lock_stub_broker_for_tests()
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn broker_snapshot_update_tracks_generation_and_revocations() {
        let mut state = ConsumerState::default();
        apply_broker_snapshot(
            &mut state,
            broker_snapshot_from_topic_maps(
                BTreeSet::from([("orders".to_string(), 0), ("orders".to_string(), 1)]),
                BTreeMap::from([
                    (("orders".to_string(), 0), 4),
                    (("orders".to_string(), 1), 8),
                ]),
            ),
        );
        assert_eq!(state.rebalance_generation, 1);
        assert_eq!(state.last_revoked_partitions.len(), 0);
        assert_eq!(state.positions.get(&("orders".to_string(), 1)), Some(&8));

        apply_broker_snapshot(
            &mut state,
            broker_snapshot_from_topic_maps(
                BTreeSet::from([("orders".to_string(), 1)]),
                BTreeMap::from([(("orders".to_string(), 1), 9)]),
            ),
        );
        assert_eq!(state.rebalance_generation, 2);
        assert_eq!(
            state.last_revoked_partitions,
            BTreeSet::from([("orders".to_string(), 0)])
        );
        assert_eq!(state.positions.get(&("orders".to_string(), 1)), Some(&9));
        assert!(!state.positions.contains_key(&("orders".to_string(), 0)));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn offset_from_rdkafka_only_keeps_absolute_offsets() {
        assert_eq!(offset_from_rdkafka(Offset::Offset(7)), Some(7));
        assert_eq!(offset_from_rdkafka(Offset::Offset(-1)), None);
        assert_eq!(offset_from_rdkafka(Offset::Beginning), None);
        assert_eq!(offset_from_rdkafka(Offset::End), None);
        assert_eq!(offset_from_rdkafka(Offset::Stored), None);
        assert_eq!(offset_from_rdkafka(Offset::Invalid), None);
    }

    #[test]
    fn test_config_defaults() {
        let config = ConsumerConfig::default();
        assert_eq!(config.group_id, "asupersync-default");
        assert_eq!(config.max_poll_records, 500);
        assert!(config.enable_auto_commit);
    }

    #[test]
    fn test_config_builder() {
        let config = ConsumerConfig::new(vec!["kafka:9092".to_string()], "group-1")
            .client_id("consumer-1")
            .auto_offset_reset(AutoOffsetReset::Earliest)
            .enable_auto_commit(false)
            .max_poll_records(1000)
            .fetch_min_bytes(4)
            .fetch_max_bytes(1024)
            .isolation_level(IsolationLevel::ReadCommitted);

        assert_eq!(config.bootstrap_servers, vec!["kafka:9092"]);
        assert_eq!(config.group_id, "group-1");
        assert_eq!(config.client_id, Some("consumer-1".to_string()));
        assert_eq!(config.auto_offset_reset, AutoOffsetReset::Earliest);
        assert!(!config.enable_auto_commit);
        assert_eq!(config.max_poll_records, 1000);
        assert_eq!(config.fetch_min_bytes, 4);
        assert_eq!(config.fetch_max_bytes, 1024);
        assert_eq!(config.isolation_level, IsolationLevel::ReadCommitted);
    }

    #[test]
    fn test_config_validation() {
        let empty_servers = ConsumerConfig {
            bootstrap_servers: vec![],
            ..Default::default()
        };
        assert!(empty_servers.validate().is_err());

        let empty_group = ConsumerConfig::new(vec!["kafka:9092".to_string()], "");
        assert!(empty_group.validate().is_err());

        let bad_fetch = ConsumerConfig::new(vec!["kafka:9092".to_string()], "group")
            .fetch_min_bytes(10)
            .fetch_max_bytes(1);
        assert!(bad_fetch.validate().is_err());
    }

    #[test]
    fn test_topic_partition_offset() {
        let tpo = TopicPartitionOffset::new("topic", 1, 42);
        assert_eq!(tpo.topic, "topic");
        assert_eq!(tpo.partition, 1);
        assert_eq!(tpo.offset, 42);
    }

    #[test]
    fn test_consumer_creation() {
        let config = ConsumerConfig::default();
        let consumer = KafkaConsumer::new(config);
        assert!(consumer.is_ok());
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn auto_offset_reset_default() {
        let d = AutoOffsetReset::default();
        assert_eq!(d, AutoOffsetReset::Latest);
    }

    #[test]
    fn auto_offset_reset_debug_copy_eq() {
        let e = AutoOffsetReset::Earliest;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Earliest"));

        // Copy
        let e2 = e;
        assert_eq!(e, e2);

        // Clone
        let e3 = e;
        assert_eq!(e, e3);

        // Inequality
        assert_ne!(AutoOffsetReset::Earliest, AutoOffsetReset::Latest);
        assert_ne!(AutoOffsetReset::Latest, AutoOffsetReset::None);
    }

    #[test]
    fn isolation_level_default() {
        let d = IsolationLevel::default();
        assert_eq!(d, IsolationLevel::ReadUncommitted);
    }

    #[test]
    fn isolation_level_debug_copy_eq() {
        let rc = IsolationLevel::ReadCommitted;
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("ReadCommitted"));

        let rc2 = rc;
        assert_eq!(rc, rc2);

        assert_ne!(
            IsolationLevel::ReadCommitted,
            IsolationLevel::ReadUncommitted
        );
    }

    #[test]
    fn consumer_config_debug_clone() {
        let cfg = ConsumerConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("asupersync-default"));

        let cloned = cfg;
        assert_eq!(cloned.group_id, "asupersync-default");
    }

    #[test]
    fn consumer_config_new_overrides_defaults() {
        let cfg = ConsumerConfig::new(vec!["broker:9092".into()], "my-group");
        assert_eq!(cfg.bootstrap_servers, vec!["broker:9092"]);
        assert_eq!(cfg.group_id, "my-group");
        // Other fields still have defaults
        assert_eq!(cfg.max_poll_records, 500);
        assert!(cfg.enable_auto_commit);
    }

    #[test]
    fn consumer_config_session_timeout_builder() {
        let cfg = ConsumerConfig::default().session_timeout(Duration::from_secs(60));
        assert_eq!(cfg.session_timeout, Duration::from_secs(60));
    }

    #[test]
    fn consumer_config_heartbeat_builder() {
        let cfg = ConsumerConfig::default().heartbeat_interval(Duration::from_secs(10));
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(10));
    }

    #[test]
    fn consumer_config_auto_commit_interval_builder() {
        let cfg = ConsumerConfig::default().auto_commit_interval(Duration::from_secs(15));
        assert_eq!(cfg.auto_commit_interval, Duration::from_secs(15));
    }

    #[test]
    fn consumer_config_fetch_max_wait_builder() {
        let cfg = ConsumerConfig::default().fetch_max_wait(Duration::from_secs(1));
        assert_eq!(cfg.fetch_max_wait, Duration::from_secs(1));
    }

    #[test]
    fn consumer_config_validate_zero_poll_records() {
        let cfg = ConsumerConfig::default().max_poll_records(0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn consumer_config_validate_whitespace_group() {
        let cfg = ConsumerConfig::new(vec!["kafka:9092".into()], "   ");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn consumer_config_validate_ok() {
        let cfg = ConsumerConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn topic_partition_offset_debug_clone_eq() {
        let tpo = TopicPartitionOffset::new("events", 0, 100);
        let dbg = format!("{tpo:?}");
        assert!(dbg.contains("events"));
        assert!(dbg.contains("100"));

        let cloned = tpo.clone();
        assert_eq!(tpo, cloned);
    }

    #[test]
    fn topic_partition_offset_inequality() {
        let a = TopicPartitionOffset::new("t1", 0, 0);
        let b = TopicPartitionOffset::new("t2", 0, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn consumer_record_debug_clone() {
        let rec = ConsumerRecord {
            topic: "test-topic".into(),
            partition: 3,
            offset: 42,
            key: Some(b"key".to_vec()),
            payload: b"value".to_vec(),
            timestamp: Some(1000),
            headers: vec![("h1".into(), b"v1".to_vec())],
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("test-topic"));
        assert!(dbg.contains("42"));

        let cloned = rec;
        assert_eq!(cloned.topic, "test-topic");
        assert_eq!(cloned.partition, 3);
        assert_eq!(cloned.key, Some(b"key".to_vec()));
    }

    #[test]
    fn consumer_record_no_key_no_timestamp() {
        let rec = ConsumerRecord {
            topic: "t".into(),
            partition: 0,
            offset: 0,
            key: None,
            payload: vec![],
            timestamp: None,
            headers: vec![],
        };
        assert!(rec.key.is_none());
        assert!(rec.timestamp.is_none());
    }

    #[test]
    fn kafka_consumer_debug_config_accessor() {
        let cfg = ConsumerConfig::default();
        let consumer = KafkaConsumer::new(cfg).unwrap();
        let dbg = format!("{consumer:?}");
        assert!(dbg.contains("KafkaConsumer"));

        assert_eq!(consumer.config().group_id, "asupersync-default");
    }

    #[test]
    fn kafka_consumer_rejects_invalid_config() {
        let cfg = ConsumerConfig {
            bootstrap_servers: vec![],
            ..Default::default()
        };
        assert!(KafkaConsumer::new(cfg).is_err());
    }

    #[test]
    fn auto_offset_reset_debug_clone_copy_eq_default() {
        let a = AutoOffsetReset::default();
        assert_eq!(a, AutoOffsetReset::Latest);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, AutoOffsetReset::Earliest);
        assert_ne!(a, AutoOffsetReset::None);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Latest"));
    }

    #[test]
    fn isolation_level_debug_clone_copy_eq_default() {
        let a = IsolationLevel::default();
        assert_eq!(a, IsolationLevel::ReadUncommitted);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, IsolationLevel::ReadCommitted);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("ReadUncommitted"));
    }

    #[test]
    fn consumer_config_debug_clone_default() {
        let cfg = ConsumerConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.group_id, "asupersync-default");
        assert_eq!(cloned.auto_offset_reset, AutoOffsetReset::Latest);
        assert_eq!(cloned.isolation_level, IsolationLevel::ReadUncommitted);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("ConsumerConfig"));
    }

    #[test]
    fn consumer_subscribe_tracks_assignments() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer
                .subscribe(&cx, &["orders", "orders", "payments"])
                .await
                .unwrap();

            assert_eq!(
                consumer.subscriptions(),
                vec!["orders".to_string(), "payments".to_string()]
            );
            assert_eq!(
                consumer.assigned_partitions(),
                vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
            );
            assert!(
                consumer
                    .poll(&cx, Duration::from_millis(1))
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn consumer_commit_and_seek_track_offsets() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 7)])
                .await
                .unwrap();
            assert_eq!(consumer.committed_offset("orders", 0), Some(7));

            consumer
                .seek(&cx, &TopicPartitionOffset::new("orders", 0, 42))
                .await
                .unwrap();
            assert_eq!(consumer.position("orders", 0), Some(42));

            let missing = consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("missing", 0, 1)])
                .await
                .unwrap_err();
            assert!(matches!(missing, KafkaError::InvalidTopic(topic) if topic == "missing"));

            let negative = consumer
                .seek(&cx, &TopicPartitionOffset::new("orders", 0, -1))
                .await
                .unwrap_err();
            assert!(matches!(negative, KafkaError::Config(msg) if msg.contains("non-negative")));
        });
    }

    #[test]
    fn consumer_close_is_idempotent_and_blocks_operations() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();
            consumer.close(&cx).await.unwrap();
            consumer.close(&cx).await.unwrap();
            assert!(consumer.is_closed());

            let err = consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 1)])
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("closed")));

            let seek_err = consumer
                .seek(&cx, &TopicPartitionOffset::new("orders", 0, 42))
                .await
                .unwrap_err();
            assert!(matches!(seek_err, KafkaError::Config(msg) if msg.contains("closed")));
        });
    }

    #[test]
    fn consumer_rejects_empty_topic_entries() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            let err = consumer.subscribe(&cx, &["orders", ""]).await.unwrap_err();
            assert!(
                matches!(err, KafkaError::Config(msg) if msg.contains("topic cannot be empty"))
            );
        });
    }

    #[test]
    fn consumer_rebalance_tracks_assignment_and_revocation() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer
                .subscribe(&cx, &["orders", "payments"])
                .await
                .unwrap();

            let result = consumer
                .rebalance(
                    &cx,
                    &[
                        TopicPartitionOffset::new("orders", 1, 10),
                        TopicPartitionOffset::new("orders", 2, 0),
                    ],
                )
                .await
                .unwrap();

            assert_eq!(result.generation, 1);
            assert_eq!(
                result.assigned,
                vec![("orders".to_string(), 1), ("orders".to_string(), 2)]
            );
            assert_eq!(
                result.revoked,
                vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
            );
            assert_eq!(consumer.position("orders", 1), Some(10));
            assert_eq!(consumer.position("orders", 2), Some(0));
            assert_eq!(consumer.rebalance_generation(), 1);
            assert_eq!(
                consumer.last_revoked_partitions(),
                vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
            );
        });
    }

    #[test]
    fn consumer_rebalance_rejects_duplicate_partition_entries() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer
                .subscribe(&cx, &["orders", "payments"])
                .await
                .unwrap();

            let err = consumer
                .rebalance(
                    &cx,
                    &[
                        TopicPartitionOffset::new("orders", 1, 10),
                        TopicPartitionOffset::new("orders", 1, 25),
                    ],
                )
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("duplicate")));
            assert_eq!(
                consumer.assigned_partitions(),
                vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
            );
            assert_eq!(consumer.rebalance_generation(), 0);
            assert!(consumer.last_revoked_partitions().is_empty());
            assert_eq!(consumer.position("orders", 1), None);
        });
    }

    #[test]
    fn consumer_rebalance_rejects_close_race_after_open() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = Arc::new(KafkaConsumer::new(ConsumerConfig::default()).unwrap());
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            let hook = Arc::new(RebalanceAfterOpenHook::new());
            consumer.install_rebalance_after_open_hook(Arc::clone(&hook));

            let rebalance_consumer = Arc::clone(&consumer);
            let rebalance_cx = cx.clone();
            let handle = std::thread::spawn(move || {
                futures_lite::future::block_on(
                    rebalance_consumer
                        .rebalance(&rebalance_cx, &[TopicPartitionOffset::new("orders", 1, 10)]),
                )
            });

            hook.arrived.wait();
            consumer.closed.store(true, Ordering::Release);
            hook.release.wait();

            let err = handle
                .join()
                .expect("rebalance thread panicked")
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("closed")));
            assert_eq!(consumer.rebalance_generation(), 0);
            assert_eq!(
                consumer.assigned_partitions(),
                vec![("orders".to_string(), 0)]
            );
            assert_eq!(consumer.position("orders", 1), None);
        });
    }

    #[test]
    fn consumer_rebalance_rejects_negative_partition_numbers() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer
                .subscribe(&cx, &["orders", "payments"])
                .await
                .unwrap();

            let err = consumer
                .rebalance(&cx, &[TopicPartitionOffset::new("orders", -1, 10)])
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("non-negative")));
            assert_eq!(
                consumer.assigned_partitions(),
                vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
            );
            assert_eq!(consumer.rebalance_generation(), 0);
            assert!(consumer.last_revoked_partitions().is_empty());
            assert_eq!(consumer.position("orders", -1), None);
        });
    }

    #[test]
    fn consumer_commit_rejects_unassigned_partitions_and_regression() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            let unassigned = consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 1, 5)])
                .await
                .unwrap_err();
            assert!(matches!(unassigned, KafkaError::Config(msg) if msg.contains("not assigned")));

            consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 8)])
                .await
                .unwrap();
            let regression = consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 7)])
                .await
                .unwrap_err();
            assert!(matches!(regression, KafkaError::Config(msg) if msg.contains("regression")));
        });
    }

    #[test]
    fn consumer_commit_rejects_duplicate_partition_entries_in_single_batch() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            let err = consumer
                .commit_offsets(
                    &cx,
                    &[
                        TopicPartitionOffset::new("orders", 0, 8),
                        TopicPartitionOffset::new("orders", 0, 7),
                    ],
                )
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("duplicate")));
            assert_eq!(consumer.committed_offset("orders", 0), None);
        });
    }

    #[test]
    fn consumer_commit_and_seek_reject_negative_partition_numbers() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            let commit_err = consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", -1, 8)])
                .await
                .unwrap_err();
            assert!(matches!(commit_err, KafkaError::Config(msg) if msg.contains("non-negative")));
            assert_eq!(consumer.committed_offset("orders", -1), None);

            let seek_err = consumer
                .seek(&cx, &TopicPartitionOffset::new("orders", -1, 42))
                .await
                .unwrap_err();
            assert!(matches!(seek_err, KafkaError::Config(msg) if msg.contains("non-negative")));
            assert_eq!(consumer.position("orders", -1), None);
        });
    }

    #[test]
    fn consumer_seek_rejects_unassigned_partitions() {
        #[cfg(not(feature = "kafka"))]
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
            consumer.subscribe(&cx, &["orders"]).await.unwrap();

            let err = consumer
                .seek(&cx, &TopicPartitionOffset::new("orders", 1, 1))
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("not assigned")));
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn consumer_poll_returns_brokerless_records_and_advances_position() {
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let topic = "consumer-poll-returns-brokerless-records";
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let consumer = KafkaConsumer::new(
                ConsumerConfig::new(vec!["localhost:9092".to_string()], "group-a")
                    .auto_offset_reset(AutoOffsetReset::Earliest),
            )
            .unwrap();

            producer
                .send(&cx, topic, Some(b"k1"), b"one", Some(0))
                .await
                .unwrap();
            producer
                .send(&cx, topic, Some(b"k2"), b"two", Some(0))
                .await
                .unwrap();

            consumer.subscribe(&cx, &[topic]).await.unwrap();

            let first = consumer
                .poll(&cx, Duration::ZERO)
                .await
                .unwrap()
                .expect("first record");
            assert_eq!(first.topic, topic);
            assert_eq!(first.partition, 0);
            assert_eq!(first.offset, 0);
            assert_eq!(first.key.as_deref(), Some(&b"k1"[..]));
            assert_eq!(first.payload, b"one");

            let second = consumer
                .poll(&cx, Duration::ZERO)
                .await
                .unwrap()
                .expect("second record");
            assert_eq!(second.offset, 1);
            assert_eq!(second.key.as_deref(), Some(&b"k2"[..]));
            assert_eq!(second.payload, b"two");
            assert_eq!(consumer.position(topic, 0), Some(2));
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn consumer_latest_offset_reset_skips_existing_backlog() {
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let topic = "consumer-latest-offset-reset-skips-existing-backlog";
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let consumer =
                KafkaConsumer::new(ConsumerConfig::new(vec!["localhost:9092".to_string()], "g"))
                    .unwrap();

            producer
                .send(&cx, topic, None, b"existing-before-subscribe", Some(0))
                .await
                .unwrap();

            consumer.subscribe(&cx, &[topic]).await.unwrap();
            assert!(consumer.poll(&cx, Duration::ZERO).await.unwrap().is_none());

            producer
                .send(&cx, topic, None, b"after-subscribe", Some(0))
                .await
                .unwrap();

            let record = consumer
                .poll(&cx, Duration::ZERO)
                .await
                .unwrap()
                .expect("post-subscribe record");
            assert_eq!(record.offset, 1);
            assert_eq!(record.payload, b"after-subscribe");
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn consumer_offset_reset_none_requires_existing_position() {
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let topic = "consumer-offset-reset-none-requires-existing-position";
            let consumer = KafkaConsumer::new(
                ConsumerConfig::new(vec!["localhost:9092".to_string()], "g")
                    .auto_offset_reset(AutoOffsetReset::None),
            )
            .unwrap();

            consumer.subscribe(&cx, &[topic]).await.unwrap();
            let err = consumer.poll(&cx, Duration::ZERO).await.unwrap_err();
            assert!(matches!(err, KafkaError::Config(msg) if msg.contains("no offset available")));
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn consumer_poll_rechecks_brokerless_records_after_waiter_registration() {
        let _broker = stub_broker_guard();
        run_test_with_cx(|cx| async move {
            let topic = "consumer-poll-rechecks-brokerless-records-after-waiter-registration";
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let consumer = Arc::new(
                KafkaConsumer::new(
                    ConsumerConfig::new(vec!["localhost:9092".to_string()], "group-recheck")
                        .auto_offset_reset(AutoOffsetReset::Earliest),
                )
                .unwrap(),
            );
            consumer.subscribe(&cx, &[topic]).await.unwrap();

            let hook = Arc::new(PollBeforeWaitHook::new());
            consumer.install_poll_before_wait_hook(Arc::clone(&hook));

            let poll_consumer = Arc::clone(&consumer);
            let poll_cx = cx.clone();
            let started = Instant::now();
            let handle = std::thread::spawn(move || {
                futures_lite::future::block_on(poll_consumer.poll(&poll_cx, Duration::from_secs(1)))
            });

            hook.arrived.wait();
            producer
                .send(&cx, topic, Some(b"k"), b"wake", Some(0))
                .await
                .unwrap();
            hook.release.wait();

            let record = handle
                .join()
                .expect("poll thread panicked")
                .unwrap()
                .expect("poll should return the brokerless record without sleeping until timeout");

            assert_eq!(record.topic, topic);
            assert_eq!(record.partition, 0);
            assert_eq!(record.offset, 0);
            assert_eq!(record.key.as_deref(), Some(&b"k"[..]));
            assert_eq!(record.payload, b"wake");
            assert!(
                started.elapsed() < Duration::from_millis(400),
                "poll should recheck immediately after waiter registration instead of idling until timeout"
            );
        });
    }
}
