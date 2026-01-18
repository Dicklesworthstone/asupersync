//! Service abstractions and middleware layering.
//!
//! This module provides the core service traits used for composable middleware
//! pipelines. It mirrors the conceptual structure of Tower-style services while
//! remaining runtime-agnostic and cancel-correct when used with Asupersync.

mod builder;
mod layer;
mod service;

pub use builder::ServiceBuilder;
pub use layer::{Identity, Layer, Stack};
pub use service::{Oneshot, Ready, Service, ServiceExt};
