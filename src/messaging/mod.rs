//! Messaging clients for external services (Redis, NATS, Kafka).
//!
//! This module provides cancel-correct clients for common messaging systems,
//! all integrated with the Asupersync `Cx` context for proper cancellation handling.

pub mod nats;
pub mod redis;

pub use nats::{Message as NatsMessage, NatsClient, NatsConfig, NatsError, Subscription};
pub use redis::{RedisClient, RedisConfig, RedisError};
