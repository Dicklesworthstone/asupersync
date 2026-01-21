//! Cancel-safe resource pooling with obligation-based return semantics.
//!
//! The pool trait defines the contract for acquiring and returning resources
//! in a cancel-safe manner. A `PooledResource` acts as an obligation: when it
//! is dropped (or explicitly returned), the resource is sent back to the pool.
//!
//! # Example (sketch)
//! ```ignore
//! use asupersync::sync::{Pool, PoolReturn, PoolReturnReceiver, PoolReturnSender, PoolStats, PooledResource};
//! use asupersync::Cx;
//! use std::sync::mpsc;
//!
//! struct MyPool {
//!     return_tx: PoolReturnSender<Vec<u8>>,
//!     return_rx: PoolReturnReceiver<Vec<u8>>,
//! }
//!
//! impl MyPool {
//!     fn new() -> Self {
//!         let (tx, rx) = mpsc::channel();
//!         Self { return_tx: tx, return_rx: rx }
//!     }
//! }
//!
//! impl Pool for MyPool {
//!     type Resource = Vec<u8>;
//!     type Error = std::io::Error;
//!
//!     fn acquire<'a>(&'a self, _cx: &'a Cx) -> asupersync::sync::PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>> {
//!         let resource = vec![0u8; 128];
//!         let pooled = PooledResource::new(resource, self.return_tx.clone());
//!         Box::pin(async move { Ok(pooled) })
//!     }
//!
//!     fn try_acquire(&self) -> Option<PooledResource<Self::Resource>> {
//!         Some(PooledResource::new(vec![0u8; 128], self.return_tx.clone()))
//!     }
//!
//!     fn stats(&self) -> PoolStats {
//!         PoolStats::default()
//!     }
//!
//!     fn close<'a>(&'a self) -> asupersync::sync::PoolFuture<'a, ()> {
//!         Box::pin(async move { })
//!     }
//! }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::cx::Cx;

/// Boxed future helper for async trait-like APIs.
pub type PoolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sender used to return resources back to a pool.
pub type PoolReturnSender<R> = mpsc::Sender<PoolReturn<R>>;

/// Receiver used to observe resources returning to a pool.
pub type PoolReturnReceiver<R> = mpsc::Receiver<PoolReturn<R>>;

/// Trait for resource pools with cancel-safe acquisition.
pub trait Pool: Send + Sync {
    /// The type of resource managed by this pool.
    type Resource: Send;

    /// Error type for acquisition failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Acquire a resource from the pool.
    ///
    /// This may block if no resources are available and the pool
    /// is at capacity. The acquire respects the `Cx` deadline.
    ///
    /// # Cancel-Safety
    ///
    /// - Cancelled while waiting: no resource is leaked.
    /// - Cancelled after acquisition: the `PooledResource` returns on drop.
    fn acquire<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> PoolFuture<'a, Result<PooledResource<Self::Resource>, Self::Error>>;

    /// Try to acquire without waiting.
    ///
    /// Returns `None` if no resource is immediately available.
    fn try_acquire(&self) -> Option<PooledResource<Self::Resource>>;

    /// Get current pool statistics.
    fn stats(&self) -> PoolStats;

    /// Close the pool, rejecting new acquisitions.
    fn close<'a>(&'a self) -> PoolFuture<'a, ()>;
}

/// Pool usage statistics.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Resources currently in use.
    pub active: usize,
    /// Resources idle in pool.
    pub idle: usize,
    /// Total resources (active + idle).
    pub total: usize,
    /// Maximum pool size.
    pub max_size: usize,
    /// Waiters blocked on acquire.
    pub waiters: usize,
    /// Total acquisitions since pool creation.
    pub total_acquisitions: u64,
    /// Total time spent waiting for resources.
    pub total_wait_time: Duration,
}

/// Return messages sent from `PooledResource` back to a pool implementation.
#[derive(Debug)]
pub enum PoolReturn<R> {
    /// Resource is healthy; return to idle pool.
    Return(R),
    /// Resource is broken; discard it.
    Discard,
}

#[derive(Debug)]
struct ReturnObligation {
    discharged: bool,
}

impl ReturnObligation {
    fn new() -> Self {
        Self { discharged: false }
    }

    fn discharge(&mut self) {
        self.discharged = true;
    }

    fn is_discharged(&self) -> bool {
        self.discharged
    }
}

/// A resource acquired from a pool.
///
/// This type uses an obligation-style contract: when dropped, it
/// returns the resource to the pool unless explicitly discarded.
#[must_use = "PooledResource must be returned or dropped"]
pub struct PooledResource<R> {
    resource: Option<R>,
    return_obligation: ReturnObligation,
    return_tx: PoolReturnSender<R>,
    acquired_at: Instant,
}

impl<R> PooledResource<R> {
    /// Creates a new pooled resource wrapper.
    #[must_use]
    pub fn new(resource: R, return_tx: PoolReturnSender<R>) -> Self {
        Self {
            resource: Some(resource),
            return_obligation: ReturnObligation::new(),
            return_tx,
            acquired_at: Instant::now(),
        }
    }

    /// Access the resource.
    #[must_use]
    pub fn get(&self) -> &R {
        self.resource.as_ref().expect("resource taken")
    }

    /// Mutably access the resource.
    pub fn get_mut(&mut self) -> &mut R {
        self.resource.as_mut().expect("resource taken")
    }

    /// Explicitly return the resource to the pool.
    ///
    /// This discharges the return obligation.
    pub fn return_to_pool(mut self) {
        self.return_inner();
    }

    /// Mark the resource as broken and discard it.
    ///
    /// The pool will create a new resource to replace this one.
    pub fn discard(mut self) {
        self.discard_inner();
    }

    /// How long this resource has been held.
    #[must_use]
    pub fn held_duration(&self) -> Duration {
        self.acquired_at.elapsed()
    }

    fn return_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return(resource));
        }

        self.return_obligation.discharge();
    }

    fn discard_inner(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        self.resource.take();
        let _ = self.return_tx.send(PoolReturn::Discard);
        self.return_obligation.discharge();
    }
}

impl<R> Drop for PooledResource<R> {
    fn drop(&mut self) {
        if self.return_obligation.is_discharged() {
            return;
        }

        if let Some(resource) = self.resource.take() {
            let _ = self.return_tx.send(PoolReturn::Return(resource));
        }

        self.return_obligation.discharge();
    }
}

impl<R> std::ops::Deref for PooledResource<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<R> std::ops::DerefMut for PooledResource<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn pooled_resource_returns_on_drop() {
        init_test("pooled_resource_returns_on_drop");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(42u8, tx);
        drop(pooled);

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 42, "return value", 42u8, value);
            }
            PoolReturn::Discard => panic!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_returns_on_drop");
    }

    #[test]
    fn pooled_resource_return_to_pool_sends_return() {
        init_test("pooled_resource_return_to_pool_sends_return");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(7u8, tx);
        pooled.return_to_pool();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return(value) => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
            }
            PoolReturn::Discard => panic!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_return_to_pool_sends_return");
    }

    #[test]
    fn pooled_resource_discard_sends_discard() {
        init_test("pooled_resource_discard_sends_discard");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(9u8, tx);
        pooled.discard();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return(_) => panic!("unexpected return"),
            PoolReturn::Discard => {
                crate::assert_with_log!(true, "discard", true, true);
            }
        }
        crate::test_complete!("pooled_resource_discard_sends_discard");
    }

    #[test]
    fn pooled_resource_deref_access() {
        init_test("pooled_resource_deref_access");
        let (tx, _rx) = mpsc::channel();
        let mut pooled = PooledResource::new(1u8, tx);
        *pooled = 3;
        crate::assert_with_log!(*pooled == 3, "deref", 3u8, *pooled);
        crate::test_complete!("pooled_resource_deref_access");
    }
}
