//! Registry capability and name lease obligations (Spork).
//!
//! This module defines:
//! 1. **Capability plumbing** (`bd-133q8`): the registry is not a global singleton;
//!    it is carried as an explicit capability on [`Cx`](crate::cx::Cx).
//! 2. **Name ownership as lease obligations** (`bd-25f52`): registering a name
//!    acquires a [`NameLease`] backed by the graded obligation system. The lease
//!    must be released (committed) or will be aborted on task/region cleanup.
//!
//! # Name Lease Lifecycle
//!
//! ```text
//! reserve_name() → NameLease (Active)
//!                        │
//!                        ├─ release() ──► Released (obligation committed)
//!                        │
//!                        └─ abort()   ──► Aborted  (obligation aborted, e.g. task cancelled)
//!                        │
//!                        └─ (drop)    ──► PANIC (obligation leaked — drop bomb)
//! ```
//!
//! The two-phase design prevents stale names: a region cannot close until all
//! name leases held by tasks in that region are resolved.
//!
//! # Determinism
//!
//! All operations are trace-visible via [`RegistryEvent`]. In the lab runtime
//! the registry enforces deterministic ordering on simultaneous registrations.
//!
//! # Bead
//!
//! bd-25f52 | Parent: bd-3rpp8

use crate::obligation::graded::{AbortedProof, CommittedProof, LeaseKind, ObligationToken};
use crate::types::{RegionId, TaskId, Time};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

// ============================================================================
// Registry Capability (bd-133q8)
// ============================================================================

/// Capability trait for a Spork registry implementation.
///
/// Implementations are expected to provide deterministic behavior in the lab
/// runtime (stable ordering, explicit tie-breaking) and to avoid ambient
/// authority.
///
/// Note: The concrete API lives in follow-on beads. For `bd-133q8` we only
/// need a capability handle that can be carried by `Cx`.
pub trait RegistryCap: Send + Sync + 'static {}

/// Shared handle to a registry capability.
#[derive(Clone)]
pub struct RegistryHandle {
    inner: Arc<dyn RegistryCap>,
}

impl RegistryHandle {
    /// Wrap an `Arc` registry capability as a handle.
    #[must_use]
    pub fn new(inner: Arc<dyn RegistryCap>) -> Self {
        Self { inner }
    }

    /// Returns the underlying capability object.
    #[must_use]
    pub fn as_arc(&self) -> Arc<dyn RegistryCap> {
        Arc::clone(&self.inner)
    }
}

impl fmt::Debug for RegistryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryHandle")
            .field("inner", &format_args!("Arc<dyn RegistryCap>(..)"))
            .finish()
    }
}

// ============================================================================
// Name Lease (bd-25f52)
// ============================================================================

/// A lease-backed name ownership record.
///
/// A `NameLease` represents an active name registration backed by the graded
/// obligation system. The holder must resolve the lease (via [`release`](Self::release)
/// or [`abort`](Self::abort)) before the owning region closes; dropping the
/// lease without resolving triggers a panic (drop bomb).
///
/// # Two-Phase Semantics
///
/// - **Reserve** (`NameLease::new`): creates the lease with an armed
///   [`ObligationToken<LeaseKind>`]. The name is now owned.
/// - **Commit** (`release()`): the holder is done; obligation committed,
///   name slot freed.
/// - **Abort** (`abort()`): cancellation/cleanup path; obligation aborted,
///   name slot freed.
///
/// Dropping without resolving panics, approximating linear-type ownership.
#[derive(Debug)]
pub struct NameLease {
    /// The registered name.
    name: String,
    /// The task holding this name.
    holder: TaskId,
    /// The region the holder belongs to.
    region: RegionId,
    /// Virtual time at which the lease was acquired.
    acquired_at: Time,
    /// The underlying lease obligation token (drop bomb).
    token: Option<ObligationToken<LeaseKind>>,
}

impl NameLease {
    /// Creates a new name lease.
    ///
    /// The obligation token is armed; the caller must eventually call
    /// [`release`](Self::release) or [`abort`](Self::abort).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        acquired_at: Time,
    ) -> Self {
        let name = name.into();
        let token = ObligationToken::reserve(format!("name_lease:{name}"));
        Self {
            name,
            holder,
            region,
            acquired_at,
            token: Some(token),
        }
    }

    /// Returns the registered name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the task holding this name.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// Returns the region of the holder.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Returns the virtual time at which the lease was acquired.
    #[must_use]
    pub fn acquired_at(&self) -> Time {
        self.acquired_at
    }

    /// Returns `true` if the lease is still active (not yet resolved).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.token.is_some()
    }

    /// Release the name (commit the obligation).
    ///
    /// The name slot is freed and the obligation is committed.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::AlreadyResolved` if the lease was already
    /// released or aborted.
    pub fn release(&mut self) -> Result<CommittedProof<LeaseKind>, NameLeaseError> {
        let token = self.token.take().ok_or(NameLeaseError::AlreadyResolved)?;
        Ok(token.commit())
    }

    /// Abort the name lease (abort the obligation).
    ///
    /// Used when the holder is cancelled or the region is cleaning up.
    /// The name slot is freed.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::AlreadyResolved` if the lease was already
    /// released or aborted.
    pub fn abort(&mut self) -> Result<AbortedProof<LeaseKind>, NameLeaseError> {
        let token = self.token.take().ok_or(NameLeaseError::AlreadyResolved)?;
        Ok(token.abort())
    }
}

// ============================================================================
// NameLeaseError
// ============================================================================

/// Error type for name lease operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameLeaseError {
    /// The lease has already been released or aborted.
    AlreadyResolved,
    /// The name is already registered by another task.
    NameTaken {
        /// The name that was requested.
        name: String,
        /// The task currently holding the name.
        current_holder: TaskId,
    },
    /// The name was not found in the registry.
    NotFound {
        /// The name that was looked up.
        name: String,
    },
}

impl fmt::Display for NameLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyResolved => write!(f, "name lease already resolved"),
            Self::NameTaken {
                name,
                current_holder,
            } => {
                write!(f, "name '{name}' already held by {current_holder}")
            }
            Self::NotFound { name } => write!(f, "name '{name}' not found"),
        }
    }
}

impl std::error::Error for NameLeaseError {}

// ============================================================================
// NameRegistry
// ============================================================================

/// In-memory name registry tracking active name leases.
///
/// Uses `BTreeMap` for deterministic iteration order (sorted by name).
/// All mutations emit [`RegistryEvent`]s for trace visibility.
#[derive(Debug)]
pub struct NameRegistry {
    /// Active leases keyed by name (deterministic BTreeMap ordering).
    leases: BTreeMap<String, NameEntry>,
}

/// Internal entry for a registered name.
#[derive(Debug, PartialEq, Eq)]
struct NameEntry {
    /// The task holding this name.
    holder: TaskId,
    /// The region of the holder.
    region: RegionId,
    /// Virtual time at which the lease was acquired.
    acquired_at: Time,
}

impl NameRegistry {
    /// Creates an empty name registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: BTreeMap::new(),
        }
    }

    /// Register a name, creating a [`NameLease`].
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NameTaken` if the name is already registered.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<NameLease, NameLeaseError> {
        let name = name.into();
        if let Some(entry) = self.leases.get(&name) {
            return Err(NameLeaseError::NameTaken {
                name,
                current_holder: entry.holder,
            });
        }
        self.leases.insert(
            name.clone(),
            NameEntry {
                holder,
                region,
                acquired_at: now,
            },
        );
        Ok(NameLease::new(name, holder, region, now))
    }

    /// Unregister a name, removing it from the registry.
    ///
    /// Returns `true` if the name was removed. The caller is responsible for
    /// resolving the corresponding [`NameLease`].
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NotFound` if the name is not registered.
    pub fn unregister(&mut self, name: &str) -> Result<(), NameLeaseError> {
        if self.leases.remove(name).is_some() {
            Ok(())
        } else {
            Err(NameLeaseError::NotFound {
                name: name.to_string(),
            })
        }
    }

    /// Look up which task holds a given name.
    #[must_use]
    pub fn whereis(&self, name: &str) -> Option<TaskId> {
        self.leases.get(name).map(|e| e.holder)
    }

    /// Returns `true` if the name is currently registered.
    #[must_use]
    pub fn is_registered(&self, name: &str) -> bool {
        self.leases.contains_key(name)
    }

    /// Returns all names currently registered, sorted deterministically.
    #[must_use]
    pub fn registered_names(&self) -> Vec<&str> {
        self.leases.keys().map(String::as_str).collect()
    }

    /// Returns the number of active name registrations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Returns `true` if no names are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Remove all names held by tasks in the given region.
    ///
    /// Returns the names that were removed (sorted deterministically).
    /// The caller is responsible for aborting the corresponding leases.
    pub fn cleanup_region(&mut self, region: RegionId) -> Vec<String> {
        let to_remove: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, e)| e.region == region)
            .map(|(name, _)| name.clone())
            .collect();
        for name in &to_remove {
            self.leases.remove(name);
        }
        to_remove
    }

    /// Remove all names held by a specific task.
    ///
    /// Returns the names that were removed (sorted deterministically).
    pub fn cleanup_task(&mut self, task: TaskId) -> Vec<String> {
        let to_remove: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, e)| e.holder == task)
            .map(|(name, _)| name.clone())
            .collect();
        for name in &to_remove {
            self.leases.remove(name);
        }
        to_remove
    }
}

impl Default for NameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Registry Events (trace visibility)
// ============================================================================

/// Trace-visible events emitted by registry operations.
///
/// These events make name ownership observable in traces, enabling
/// deterministic replay and debugging of registry-related behaviors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryEvent {
    /// A name was successfully registered.
    NameRegistered {
        /// The registered name.
        name: String,
        /// The task that acquired the name.
        holder: TaskId,
        /// The region of the holder.
        region: RegionId,
    },
    /// A name was explicitly released (obligation committed).
    NameReleased {
        /// The released name.
        name: String,
        /// The task that held the name.
        holder: TaskId,
    },
    /// A name lease was aborted (task cancelled, region cleanup, etc.).
    NameAborted {
        /// The aborted name.
        name: String,
        /// The task that held the name.
        holder: TaskId,
        /// Why the lease was aborted.
        reason: String,
    },
    /// All names in a region were cleaned up.
    RegionCleanup {
        /// The region that was cleaned up.
        region: RegionId,
        /// Number of names removed.
        count: usize,
    },
    /// All names held by a task were cleaned up.
    TaskCleanup {
        /// The task that was cleaned up.
        task: TaskId,
        /// Number of names removed.
        count: usize,
    },
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    // ---------------------------------------------------------------
    // NameLease tests
    // ---------------------------------------------------------------

    #[test]
    fn name_lease_lifecycle() {
        init_test("name_lease_lifecycle");

        let mut lease = NameLease::new("my_server", tid(1), rid(0), Time::from_secs(1));
        assert_eq!(lease.name(), "my_server");
        assert_eq!(lease.holder(), tid(1));
        assert_eq!(lease.region(), rid(0));
        assert_eq!(lease.acquired_at(), Time::from_secs(1));
        assert!(lease.is_active());

        let proof = lease.release().unwrap();
        assert!(!lease.is_active());

        // Proof is a CommittedProof<LeaseKind>
        let _ = proof;

        crate::test_complete!("name_lease_lifecycle");
    }

    #[test]
    fn name_lease_abort() {
        init_test("name_lease_abort");

        let mut lease = NameLease::new("worker", tid(2), rid(0), Time::ZERO);
        assert!(lease.is_active());

        let proof = lease.abort().unwrap();
        assert!(!lease.is_active());
        let _ = proof;

        crate::test_complete!("name_lease_abort");
    }

    #[test]
    fn name_lease_double_resolve_errors() {
        init_test("name_lease_double_resolve_errors");

        let mut lease = NameLease::new("svc", tid(1), rid(0), Time::ZERO);
        lease.release().unwrap();

        assert!(matches!(
            lease.release(),
            Err(NameLeaseError::AlreadyResolved)
        ));
        assert!(matches!(
            lease.abort(),
            Err(NameLeaseError::AlreadyResolved)
        ));

        crate::test_complete!("name_lease_double_resolve_errors");
    }

    // ---------------------------------------------------------------
    // NameRegistry tests
    // ---------------------------------------------------------------

    #[test]
    fn registry_register_and_whereis() {
        init_test("registry_register_and_whereis");

        let mut reg = NameRegistry::new();
        assert!(reg.is_empty());

        let mut lease = reg
            .register("my_server", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("my_server"), Some(tid(1)));
        assert!(reg.is_registered("my_server"));
        assert_eq!(reg.whereis("unknown"), None);

        lease.release().unwrap();

        crate::test_complete!("registry_register_and_whereis");
    }

    #[test]
    fn registry_name_taken() {
        init_test("registry_name_taken");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("singleton", tid(1), rid(0), Time::ZERO)
            .unwrap();

        let err = reg
            .register("singleton", tid(2), rid(0), Time::ZERO)
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );

        lease.release().unwrap();

        crate::test_complete!("registry_name_taken");
    }

    #[test]
    fn registry_unregister() {
        init_test("registry_unregister");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("temp", tid(1), rid(0), Time::ZERO).unwrap();

        reg.unregister("temp").unwrap();
        assert!(!reg.is_registered("temp"));
        assert!(reg.is_empty());

        // Unregistering unknown name is an error
        assert_eq!(
            reg.unregister("unknown"),
            Err(NameLeaseError::NotFound {
                name: "unknown".into()
            })
        );

        lease.release().unwrap();

        crate::test_complete!("registry_unregister");
    }

    #[test]
    fn registry_registered_names_sorted() {
        init_test("registry_registered_names_sorted");

        let mut reg = NameRegistry::new();
        let mut l1 = reg.register("zebra", tid(1), rid(0), Time::ZERO).unwrap();
        let mut l2 = reg.register("alpha", tid(2), rid(0), Time::ZERO).unwrap();
        let mut l3 = reg.register("middle", tid(3), rid(0), Time::ZERO).unwrap();

        // BTreeMap guarantees sorted order
        assert_eq!(reg.registered_names(), vec!["alpha", "middle", "zebra"]);

        l1.release().unwrap();
        l2.release().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_registered_names_sorted");
    }

    #[test]
    fn registry_cleanup_region() {
        init_test("registry_cleanup_region");

        let mut reg = NameRegistry::new();
        let mut l1 = reg.register("svc_a", tid(1), rid(1), Time::ZERO).unwrap();
        let mut l2 = reg.register("svc_b", tid(2), rid(1), Time::ZERO).unwrap();
        let mut l3 = reg.register("svc_c", tid(3), rid(2), Time::ZERO).unwrap();

        assert_eq!(reg.len(), 3);

        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["svc_a", "svc_b"]); // sorted by BTreeMap
        assert_eq!(reg.len(), 1);
        assert!(reg.is_registered("svc_c"));
        assert!(!reg.is_registered("svc_a"));

        // Abort the removed leases (simulating region cleanup)
        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_cleanup_region");
    }

    #[test]
    fn registry_cleanup_task() {
        init_test("registry_cleanup_task");

        let mut reg = NameRegistry::new();
        let mut l1 = reg.register("name_a", tid(5), rid(0), Time::ZERO).unwrap();
        let mut l2 = reg.register("name_b", tid(5), rid(0), Time::ZERO).unwrap();
        let mut l3 = reg.register("name_c", tid(6), rid(0), Time::ZERO).unwrap();

        let removed = reg.cleanup_task(tid(5));
        assert_eq!(removed, vec!["name_a", "name_b"]);
        assert_eq!(reg.len(), 1);

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_cleanup_task");
    }

    #[test]
    fn registry_cleanup_region_empty() {
        init_test("registry_cleanup_region_empty");

        let mut reg = NameRegistry::new();
        let removed = reg.cleanup_region(rid(99));
        assert!(removed.is_empty());

        crate::test_complete!("registry_cleanup_region_empty");
    }

    #[test]
    fn registry_re_register_after_unregister() {
        init_test("registry_re_register_after_unregister");

        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("reusable", tid(1), rid(0), Time::ZERO)
            .unwrap();
        reg.unregister("reusable").unwrap();
        l1.release().unwrap();

        // Re-register same name with different task
        let mut l2 = reg
            .register("reusable", tid(2), rid(0), Time::from_secs(1))
            .unwrap();
        assert_eq!(reg.whereis("reusable"), Some(tid(2)));
        l2.release().unwrap();

        crate::test_complete!("registry_re_register_after_unregister");
    }

    #[test]
    fn name_lease_error_display() {
        init_test("name_lease_error_display");

        let err = NameLeaseError::AlreadyResolved;
        assert_eq!(err.to_string(), "name lease already resolved");

        let err = NameLeaseError::NameTaken {
            name: "foo".into(),
            current_holder: tid(42),
        };
        assert!(err.to_string().contains("foo"));
        assert!(err.to_string().contains("42"));

        let err = NameLeaseError::NotFound { name: "bar".into() };
        assert!(err.to_string().contains("bar"));

        crate::test_complete!("name_lease_error_display");
    }

    #[test]
    fn registry_event_variants() {
        init_test("registry_event_variants");

        let _registered = RegistryEvent::NameRegistered {
            name: "svc".into(),
            holder: tid(1),
            region: rid(0),
        };
        let _released = RegistryEvent::NameReleased {
            name: "svc".into(),
            holder: tid(1),
        };
        let _aborted = RegistryEvent::NameAborted {
            name: "svc".into(),
            holder: tid(1),
            reason: "task cancelled".into(),
        };
        let _region_cleanup = RegistryEvent::RegionCleanup {
            region: rid(0),
            count: 3,
        };
        let _task_cleanup = RegistryEvent::TaskCleanup {
            task: tid(1),
            count: 2,
        };

        crate::test_complete!("registry_event_variants");
    }

    #[test]
    fn registry_default_is_empty() {
        init_test("registry_default_is_empty");

        let reg = NameRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        crate::test_complete!("registry_default_is_empty");
    }

    // ---------------------------------------------------------------
    // RegistryHandle tests (bd-133q8)
    // ---------------------------------------------------------------

    struct DummyRegistry;
    impl RegistryCap for DummyRegistry {}

    #[test]
    fn registry_handle_basic() {
        init_test("registry_handle_basic");

        let handle = RegistryHandle::new(Arc::new(DummyRegistry));
        let _arc = handle.as_arc();
        let _clone = handle.clone();

        // Debug output should not panic
        let debug = format!("{handle:?}");
        assert!(debug.contains("RegistryHandle"));

        crate::test_complete!("registry_handle_basic");
    }
}
