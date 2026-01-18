//! Service abstractions and middleware layering.
//!
//! This module provides the core service traits used for composable middleware
//! pipelines. It mirrors the conceptual structure of Tower-style services while
//! remaining runtime-agnostic and cancel-correct when used with Asupersync.
//!
//! # Middleware Layers
//!
//! The following middleware layers are provided:
//!
//! - [`timeout`]: Impose time limits on requests
//! - [`load_shed`]: Shed load when the inner service is not ready
//! - [`concurrency_limit`]: Limit concurrent in-flight requests
//! - [`rate_limit`]: Rate-limit requests using a token bucket
//! - [`retry`]: Retry failed requests according to a policy

mod builder;
pub mod concurrency_limit;
mod layer;
pub mod load_shed;
pub mod rate_limit;
pub mod retry;
mod service;
pub mod timeout;

pub use builder::ServiceBuilder;
pub use concurrency_limit::{ConcurrencyLimit, ConcurrencyLimitError, ConcurrencyLimitLayer};
pub use layer::{Identity, Layer, Stack};
pub use load_shed::{LoadShed, LoadShedError, LoadShedLayer, Overloaded};
pub use rate_limit::{RateLimit, RateLimitError, RateLimitLayer};
pub use retry::{LimitedRetry, NoRetry, Policy, Retry, RetryLayer};
pub use service::{Oneshot, Ready, Service, ServiceExt};
pub use timeout::{Timeout, TimeoutError, TimeoutLayer};
