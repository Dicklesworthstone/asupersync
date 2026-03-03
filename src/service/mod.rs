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
//! - [`buffer`]: Buffer requests via a bounded channel

pub mod buffer;
mod builder;
pub mod concurrency_limit;
pub mod discover;
pub mod filter;
pub mod hedge;
mod layer;
pub mod load_balance;
pub mod load_shed;
pub mod rate_limit;
pub mod reconnect;
pub mod retry;
mod service;
pub mod steer;
pub mod timeout;

pub use buffer::{Buffer, BufferError, BufferLayer};
pub use builder::ServiceBuilder;
pub use concurrency_limit::{ConcurrencyLimit, ConcurrencyLimitError, ConcurrencyLimitLayer};
pub use discover::{
    Change, Discover, DnsDiscoveryConfig, DnsDiscoveryError, DnsServiceDiscovery, StaticList,
};
pub use filter::{AsyncFilter, Filter, FilterError, FilterFuture, FilterLayer};
pub use hedge::{Hedge, HedgeConfig, HedgeError, HedgeFuture, HedgeLayer};
pub use layer::{Identity, Layer, Stack};
pub use load_balance::{
    LoadBalanceError, LoadBalancedFuture, LoadBalancer, PowerOfTwoChoices, RoundRobin, Strategy,
    Weighted,
};
pub use load_shed::{LoadShed, LoadShedError, LoadShedLayer, Overloaded};
pub use rate_limit::{RateLimit, RateLimitError, RateLimitLayer};
pub use reconnect::{MakeService, Reconnect, ReconnectError, ReconnectFuture, ReconnectLayer};
pub use retry::{LimitedRetry, NoRetry, Policy, Retry, RetryLayer};
pub use steer::{Steer, SteerError};
// Tower adapter types (available without feature flag for configuration)
pub use service::{
    AdapterConfig, CancellationMode, DefaultErrorAdapter, ErrorAdapter, TowerAdapterError,
};
#[cfg(feature = "tower")]
pub use service::{AsupersyncAdapter, FixedCxProvider, TowerAdapter, TowerAdapterWithProvider};
pub use service::{
    AsupersyncService, AsupersyncServiceExt, MapErr, MapResponse, Oneshot, Ready, Service,
    ServiceExt,
};
pub use timeout::{Timeout, TimeoutError, TimeoutLayer};
