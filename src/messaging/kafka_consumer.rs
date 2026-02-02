//! Kafka consumer with Cx integration for cancel-correct message consumption.
//!
//! This module defines the API surface for a Kafka consumer that integrates
//! with the Asupersync `Cx` context. The Phase 0 implementation is a stub
//! that returns a clear error until rdkafka integration is added.
//!
//! # Cancel-Correct Behavior
//!
//! - Poll operations honor cancellation checkpoints
//! - Offset commits are explicit and budget-aware
//! - Consumer close drains in-flight operations (future implementation)

// Phase 0 stubs return errors immediately; async is for API consistency
// with eventual rdkafka integration.
#![allow(clippy::unused_async)]

use crate::cx::Cx;
use crate::messaging::kafka::KafkaError;
use std::io;
use std::time::Duration;

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

/// A record returned from a Kafka consumer poll.
#[derive(Debug, Clone)]
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

/// Kafka consumer (Phase 0 stub).
#[derive(Debug)]
pub struct KafkaConsumer {
    config: ConsumerConfig,
}

impl KafkaConsumer {
    /// Create a new Kafka consumer.
    pub fn new(config: ConsumerConfig) -> Result<Self, KafkaError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Subscribe to a set of topics.
    #[allow(unused_variables)]
    pub async fn subscribe(&self, cx: &Cx, topics: &[&str]) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        if topics.is_empty() {
            return Err(KafkaError::Config("topics cannot be empty".to_string()));
        }

        Err(stub_err())
    }

    /// Poll for the next record.
    #[allow(unused_variables)]
    pub async fn poll(
        &self,
        cx: &Cx,
        timeout: Duration,
    ) -> Result<Option<ConsumerRecord>, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        let _ = timeout;
        Err(stub_err())
    }

    /// Commit offsets explicitly.
    #[allow(unused_variables)]
    pub async fn commit_offsets(
        &self,
        cx: &Cx,
        offsets: &[TopicPartitionOffset],
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        if offsets.is_empty() {
            return Err(KafkaError::Config("offsets cannot be empty".to_string()));
        }

        Err(stub_err())
    }

    /// Seek to a specific offset.
    #[allow(unused_variables)]
    pub async fn seek(&self, cx: &Cx, tpo: &TopicPartitionOffset) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        let _ = tpo;
        Err(stub_err())
    }

    /// Close the consumer.
    #[allow(unused_variables)]
    pub async fn close(&self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        Err(stub_err())
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &ConsumerConfig {
        &self.config
    }
}

fn stub_err() -> KafkaError {
    KafkaError::Io(io::Error::other("Phase 0: requires rdkafka integration"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
