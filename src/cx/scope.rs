//! Scope API for spawning work within a region.
//!
//! A `Scope` provides the API for spawning tasks, creating child regions,
//! and registering finalizers.

use crate::runtime::RuntimeState;
use crate::types::{Budget, Policy, RegionId};
use std::future::Future;
use std::marker::PhantomData;

/// A scope for spawning work within a region.
///
/// The scope provides methods for:
/// - Spawning tasks
/// - Creating child regions
/// - Registering finalizers
/// - Cancelling all children
pub struct Scope<'r, P: Policy = crate::types::policy::FailFast> {
    /// The region this scope belongs to.
    pub(crate) region: RegionId,
    /// The budget for this scope.
    pub(crate) budget: Budget,
    /// Phantom data for the policy type.
    pub(crate) _policy: PhantomData<&'r P>,
}

impl<P: Policy> Scope<'_, P> {
    /// Creates a new scope (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new(region: RegionId, budget: Budget) -> Self {
        Self {
            region,
            budget,
            _policy: PhantomData,
        }
    }

    /// Returns the region ID for this scope.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region
    }

    /// Returns the budget for this scope.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.budget
    }

    // Note: Actual spawn methods will be implemented in later phases
    // when we have the full runtime infrastructure.

    /// Placeholder for spawn (to be implemented in Phase 0 kernel work).
    pub fn spawn_placeholder(&self) {
        // This is a placeholder that will be replaced with real implementation
    }

    // =========================================================================
    // Finalizer Registration
    // =========================================================================

    /// Registers a synchronous finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and executed during the Finalizing
    /// phase, after all children have completed. Use this for lightweight
    /// cleanup that doesn't need to await.
    ///
    /// # Arguments
    /// * `state` - The runtime state
    /// * `f` - The synchronous cleanup function
    ///
    /// # Returns
    /// `true` if the finalizer was registered successfully.
    ///
    /// # Example
    /// ```ignore
    /// scope.defer_sync(&mut state, || {
    ///     println!("Cleaning up!");
    /// });
    /// ```
    pub fn defer_sync<F>(&self, state: &mut RuntimeState, f: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        state.register_sync_finalizer(self.region, f)
    }

    /// Registers an asynchronous finalizer to run when the region closes.
    ///
    /// Async finalizers run under a cancel mask to prevent interruption.
    /// They are driven to completion with a bounded budget. Use this for
    /// cleanup that needs to perform async operations (e.g., closing
    /// connections, flushing buffers).
    ///
    /// # Arguments
    /// * `state` - The runtime state
    /// * `future` - The async cleanup future
    ///
    /// # Returns
    /// `true` if the finalizer was registered successfully.
    ///
    /// # Example
    /// ```ignore
    /// scope.defer_async(&mut state, async {
    ///     close_connection().await;
    /// });
    /// ```
    pub fn defer_async<F>(&self, state: &mut RuntimeState, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        state.register_async_finalizer(self.region, future)
    }
}

impl<P: Policy> std::fmt::Debug for Scope<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("region", &self.region)
            .field("budget", &self.budget)
            .finish()
    }
}
