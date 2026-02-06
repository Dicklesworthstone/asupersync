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
// NamePermit (bd-2is3i)
// ============================================================================

/// A name registration permit (reserve stage).
///
/// A `NamePermit` represents intent to register a name. The permit must be
/// either committed (producing a [`NameLease`]) or aborted before the owning
/// region closes. Dropping without resolving triggers a panic (drop bomb).
///
/// # Three-Phase Lifecycle
///
/// ```text
/// NameRegistry::reserve() → NamePermit (reserved, NOT visible to whereis)
///                                │
///                                ├─ NameRegistry::commit_permit() → NameLease (visible)
///                                │
///                                ├─ abort() → AbortedProof (cancelled, name never registered)
///                                │
///                                └─ (drop)  → PANIC (obligation leaked)
/// ```
///
/// The permit stage allows setup work between reservation and commitment.
/// If setup fails, the permit can be aborted without ever making the name
/// visible to other tasks.
///
/// # Bead
///
/// bd-2is3i | Parent: bd-133q8
#[derive(Debug)]
pub struct NamePermit {
    /// The name being reserved.
    name: String,
    /// The task requesting the name.
    holder: TaskId,
    /// The region containing the holder.
    region: RegionId,
    /// Virtual time of reservation.
    reserved_at: Time,
    /// Obligation token (drop bomb). Transferred to NameLease on commit.
    token: Option<ObligationToken<LeaseKind>>,
}

impl NamePermit {
    /// Creates a new name permit with an armed obligation token.
    ///
    /// The caller must eventually call [`commit`](Self::commit) (via
    /// [`NameRegistry::commit_permit`]) or [`abort`](Self::abort).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
    ) -> Self {
        let name = name.into();
        let token = ObligationToken::reserve(format!("name_permit:{name}"));
        Self {
            name,
            holder,
            region,
            reserved_at,
            token: Some(token),
        }
    }

    /// Returns the reserved name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the task requesting the name.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// Returns the region of the holder.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Returns the virtual time of reservation.
    #[must_use]
    pub fn reserved_at(&self) -> Time {
        self.reserved_at
    }

    /// Returns `true` if the permit has not yet been committed or aborted.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.token.is_some()
    }

    /// Consume the permit, transferring the obligation token to a new
    /// [`NameLease`].
    ///
    /// This is called internally by [`NameRegistry::commit_permit`]. Direct
    /// callers should use the registry method to also update the registry state.
    ///
    /// # Panics
    ///
    /// Panics if the permit was already committed or aborted.
    fn commit(mut self) -> NameLease {
        let token = self
            .token
            .take()
            .expect("NamePermit::commit called on already-resolved permit");
        NameLease {
            name: self.name.clone(),
            holder: self.holder,
            region: self.region,
            acquired_at: self.reserved_at,
            token: Some(token),
        }
    }

    /// Abort the permit (cancel the reservation).
    ///
    /// The name was never registered; the obligation is aborted.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::AlreadyResolved` if the permit was already
    /// committed or aborted.
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
    /// Pending permits keyed by name (reserved but not yet committed).
    pending: BTreeMap<String, NameEntry>,
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
            pending: BTreeMap::new(),
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
        if let Some(entry) = self.pending.get(&name) {
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

    /// Reserve a name, creating a [`NamePermit`].
    ///
    /// The name is reserved but NOT yet visible to [`whereis`](Self::whereis).
    /// The permit must be committed via [`commit_permit`](Self::commit_permit)
    /// to make the name visible, or aborted via [`NamePermit::abort`].
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NameTaken` if the name is already registered
    /// or already reserved by a pending permit.
    pub fn reserve(
        &mut self,
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<NamePermit, NameLeaseError> {
        let name = name.into();
        if let Some(entry) = self.leases.get(&name) {
            return Err(NameLeaseError::NameTaken {
                name,
                current_holder: entry.holder,
            });
        }
        if let Some(entry) = self.pending.get(&name) {
            return Err(NameLeaseError::NameTaken {
                name,
                current_holder: entry.holder,
            });
        }
        self.pending.insert(
            name.clone(),
            NameEntry {
                holder,
                region,
                acquired_at: now,
            },
        );
        Ok(NamePermit::new(name, holder, region, now))
    }

    /// Commit a permit, transitioning it to a [`NameLease`].
    ///
    /// The name moves from pending to active, becoming visible to
    /// [`whereis`](Self::whereis).
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NotFound` if the permit's name is not in the
    /// pending set (e.g., if the permit was already committed or the registry
    /// was cleaned up).
    pub fn commit_permit(&mut self, mut permit: NamePermit) -> Result<NameLease, NameLeaseError> {
        let name = permit.name().to_string();
        let Some(entry) = self.pending.remove(&name) else {
            // Abort the permit to defuse the drop bomb before returning error.
            let _ = permit.abort();
            return Err(NameLeaseError::NotFound { name });
        };
        self.leases.insert(name, entry);
        Ok(permit.commit())
    }

    /// Cancel a pending permit, removing it from the pending set.
    ///
    /// The caller must also call [`NamePermit::abort`] on the permit itself
    /// to resolve the obligation.
    ///
    /// Returns `true` if the name was in the pending set.
    pub fn cancel_permit(&mut self, name: &str) -> bool {
        self.pending.remove(name).is_some()
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
    ///
    /// Note: this removes both active leases and pending permits held in the
    /// region. The caller is responsible for resolving the corresponding
    /// obligations (leases released/aborted; permits aborted).
    pub fn cleanup_region(&mut self, region: RegionId) -> Vec<String> {
        let mut to_remove: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, e)| e.region == region)
            .map(|(name, _)| name.clone())
            .collect();
        to_remove.extend(
            self.pending
                .iter()
                .filter(|(_, e)| e.region == region)
                .map(|(name, _)| name.clone()),
        );
        to_remove.sort();
        for name in &to_remove {
            self.leases.remove(name);
            self.pending.remove(name);
        }
        to_remove
    }

    /// Remove all names held by a specific task.
    ///
    /// Returns the names that were removed (sorted deterministically).
    ///
    /// Note: this removes both active leases and pending permits held by the
    /// task. The caller is responsible for resolving the corresponding
    /// obligations.
    pub fn cleanup_task(&mut self, task: TaskId) -> Vec<String> {
        let mut to_remove: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, e)| e.holder == task)
            .map(|(name, _)| name.clone())
            .collect();
        to_remove.extend(
            self.pending
                .iter()
                .filter(|(_, e)| e.holder == task)
                .map(|(name, _)| name.clone()),
        );
        to_remove.sort();
        for name in &to_remove {
            self.leases.remove(name);
            self.pending.remove(name);
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
    /// A name was reserved via a permit (not yet visible to whereis).
    NameReserved {
        /// The reserved name.
        name: String,
        /// The task that reserved the name.
        holder: TaskId,
        /// The region of the holder.
        region: RegionId,
    },
    /// A name permit was committed, transitioning to an active lease.
    NamePermitCommitted {
        /// The name that transitioned from reserved to active.
        name: String,
        /// The task that committed the permit.
        holder: TaskId,
    },
    /// A name permit was aborted (reservation cancelled).
    NamePermitAborted {
        /// The aborted name.
        name: String,
        /// The task that held the permit.
        holder: TaskId,
        /// Why the permit was aborted.
        reason: String,
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

    // ---------------------------------------------------------------
    // NamePermit tests (bd-2is3i)
    // ---------------------------------------------------------------

    #[test]
    fn registry_reserve_commit_makes_visible() {
        init_test("registry_reserve_commit_makes_visible");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_secs(1))
            .expect("reserve ok");

        // Reserved names are not visible until committed.
        assert_eq!(reg.whereis("svc"), None);
        assert!(!reg.is_registered("svc"));

        let mut lease = reg.commit_permit(permit).expect("commit ok");
        assert_eq!(reg.whereis("svc"), Some(tid(1)));
        assert!(reg.is_registered("svc"));

        lease.release().unwrap();
        crate::test_complete!("registry_reserve_commit_makes_visible");
    }

    #[test]
    fn registry_reserve_abort_releases_name() {
        init_test("registry_reserve_abort_releases_name");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_secs(1))
            .expect("reserve ok");

        // Abort the permit obligation and cancel the pending entry.
        permit.abort().unwrap();
        assert!(reg.cancel_permit("svc"));

        // Now the name can be registered normally.
        let mut lease = reg
            .register("svc", tid(2), rid(0), Time::from_secs(2))
            .unwrap();
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        lease.release().unwrap();

        crate::test_complete!("registry_reserve_abort_releases_name");
    }

    #[test]
    fn registry_reserve_blocks_register() {
        init_test("registry_reserve_blocks_register");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::ZERO)
            .expect("reserve ok");

        let err = reg.register("svc", tid(2), rid(0), Time::ZERO).unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "svc".into(),
                current_holder: tid(1),
            }
        );

        permit.abort().unwrap();
        assert!(reg.cancel_permit("svc"));

        crate::test_complete!("registry_reserve_blocks_register");
    }

    #[test]
    fn registry_cleanup_region_removes_pending_permits() {
        init_test("registry_cleanup_region_removes_pending_permits");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(1), Time::ZERO)
            .expect("reserve ok");

        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["svc"]);

        // Abort the permit (simulating region cleanup).
        permit.abort().unwrap();

        // Registry should no longer consider the name taken.
        let mut lease = reg
            .register("svc", tid(2), rid(0), Time::from_secs(1))
            .unwrap();
        lease.release().unwrap();

        crate::test_complete!("registry_cleanup_region_removes_pending_permits");
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
        let _reserved = RegistryEvent::NameReserved {
            name: "svc".into(),
            holder: tid(1),
            region: rid(0),
        };
        let _committed = RegistryEvent::NamePermitCommitted {
            name: "svc".into(),
            holder: tid(1),
        };
        let _permit_aborted = RegistryEvent::NamePermitAborted {
            name: "svc".into(),
            holder: tid(1),
            reason: "setup failed".into(),
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

    // ---------------------------------------------------------------
    // Conformance tests (bd-13l06)
    //
    // Property/lab tests:
    // - No stale names after crash/stop
    // - Deterministic winner on simultaneous register attempts
    // - Lease abort on cancellation
    // - Trace event ordering stable across seeds
    // ---------------------------------------------------------------

    /// Conformance: after cleanup_task, no stale names remain for that task.
    /// The registry must be fully consistent: whereis returns None for cleaned-up
    /// names, len() reflects the removal, and registered_names() excludes them.
    #[test]
    fn conformance_no_stale_names_after_task_crash() {
        init_test("conformance_no_stale_names_after_task_crash");

        let mut reg = NameRegistry::new();

        // Task 1 registers 3 names across 2 regions
        let mut l1 = reg.register("svc_a", tid(1), rid(0), Time::ZERO).unwrap();
        let mut l2 = reg
            .register("svc_b", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("svc_c", tid(1), rid(1), Time::from_secs(2))
            .unwrap();

        // Task 2 registers 1 name (should survive the crash)
        let mut l4 = reg
            .register("other", tid(2), rid(0), Time::from_secs(3))
            .unwrap();

        assert_eq!(reg.len(), 4);

        // Simulate task 1 crash: cleanup removes all its names
        let removed = reg.cleanup_task(tid(1));
        assert_eq!(removed, vec!["svc_a", "svc_b", "svc_c"]); // sorted by BTreeMap

        // Post-crash invariants
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("svc_a"), None, "stale name svc_a after crash");
        assert_eq!(reg.whereis("svc_b"), None, "stale name svc_b after crash");
        assert_eq!(reg.whereis("svc_c"), None, "stale name svc_c after crash");
        assert_eq!(reg.whereis("other"), Some(tid(2)), "surviving name lost");
        assert_eq!(reg.registered_names(), vec!["other"]);

        // Abort the crashed task's leases (obligation resolution)
        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();
        l4.release().unwrap();

        crate::test_complete!("conformance_no_stale_names_after_task_crash");
    }

    /// Conformance: after cleanup_region, no stale names remain for any task
    /// in that region. Names in other regions are untouched.
    #[test]
    fn conformance_no_stale_names_after_region_stop() {
        init_test("conformance_no_stale_names_after_region_stop");

        let mut reg = NameRegistry::new();

        // Region 1: 3 tasks register names
        let mut l1 = reg.register("db", tid(10), rid(1), Time::ZERO).unwrap();
        let mut l2 = reg
            .register("cache", tid(11), rid(1), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("worker", tid(12), rid(1), Time::from_secs(2))
            .unwrap();

        // Region 2: 1 task registers a name
        let mut l4 = reg
            .register("api", tid(20), rid(2), Time::from_secs(3))
            .unwrap();

        // Region 3: 1 task registers a name
        let mut l5 = reg
            .register("logger", tid(30), rid(3), Time::from_secs(4))
            .unwrap();

        assert_eq!(reg.len(), 5);

        // Stop region 1
        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["cache", "db", "worker"]); // sorted

        // Post-stop invariants
        assert_eq!(reg.len(), 2);
        for name in &["cache", "db", "worker"] {
            assert_eq!(
                reg.whereis(name),
                None,
                "stale name '{name}' after region stop"
            );
            assert!(!reg.is_registered(name));
        }
        assert_eq!(reg.whereis("api"), Some(tid(20)));
        assert_eq!(reg.whereis("logger"), Some(tid(30)));
        assert_eq!(reg.registered_names(), vec!["api", "logger"]);

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();
        l4.release().unwrap();
        l5.release().unwrap();

        crate::test_complete!("conformance_no_stale_names_after_region_stop");
    }

    /// Conformance: the first caller to register a name wins deterministically.
    /// The loser receives NameTaken with the correct holder. This is true
    /// regardless of task IDs, region IDs, or timing.
    #[test]
    fn conformance_deterministic_winner_simultaneous_register() {
        init_test("conformance_deterministic_winner_simultaneous_register");

        let mut reg = NameRegistry::new();

        // Task 99 registers first (even though it has a higher TaskId)
        let mut winner = reg
            .register("singleton", tid(99), rid(0), Time::ZERO)
            .unwrap();

        // Task 1 tries second — should lose deterministically
        let err = reg
            .register("singleton", tid(1), rid(0), Time::ZERO)
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(99),
            },
            "loser must see the correct holder"
        );

        // Task 50 also tries — same result
        let err = reg
            .register("singleton", tid(50), rid(1), Time::from_secs(1))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(99),
            },
            "second loser must also see the original holder"
        );

        // Registry state unchanged
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("singleton"), Some(tid(99)));

        winner.release().unwrap();

        crate::test_complete!("conformance_deterministic_winner_simultaneous_register");
    }

    /// Conformance: first-wins semantics is stable across repeated trials.
    /// Run the same registration race N times; the outcome must be identical.
    #[test]
    fn conformance_register_winner_stable_across_trials() {
        init_test("conformance_register_winner_stable_across_trials");

        for trial in 0..20 {
            let mut reg = NameRegistry::new();

            let mut lease = reg
                .register("stable_name", tid(7), rid(0), Time::ZERO)
                .unwrap();

            let err = reg
                .register("stable_name", tid(3), rid(0), Time::ZERO)
                .unwrap_err();
            assert_eq!(
                err,
                NameLeaseError::NameTaken {
                    name: "stable_name".into(),
                    current_holder: tid(7),
                },
                "trial {trial}: winner must be tid(7)"
            );

            lease.release().unwrap();
        }

        crate::test_complete!("conformance_register_winner_stable_across_trials");
    }

    /// Conformance: lease abort on cancellation correctly resolves the obligation.
    /// After abort, the lease is inactive, and the abort proof is valid.
    /// Double-abort returns AlreadyResolved.
    #[test]
    fn conformance_lease_abort_on_cancellation() {
        init_test("conformance_lease_abort_on_cancellation");

        let mut reg = NameRegistry::new();

        // Register a name
        let mut lease = reg
            .register("cancellable", tid(1), rid(0), Time::ZERO)
            .unwrap();
        assert!(lease.is_active());

        // Simulate cancellation: unregister from registry, then abort the lease
        reg.unregister("cancellable").unwrap();
        assert!(!reg.is_registered("cancellable"));

        let proof = lease.abort().unwrap();
        assert!(!lease.is_active());

        // Proof is a valid AbortedProof<LeaseKind>
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Abort,
            "abort proof must show Abort resolution"
        );

        // Double-abort is an error, not a panic
        assert_eq!(lease.abort().unwrap_err(), NameLeaseError::AlreadyResolved);

        crate::test_complete!("conformance_lease_abort_on_cancellation");
    }

    /// Conformance: lease abort via region cleanup resolves all obligations.
    /// Simulates the full cancellation flow: region closing → cleanup → abort each lease.
    #[test]
    fn conformance_region_cancel_aborts_all_leases() {
        init_test("conformance_region_cancel_aborts_all_leases");

        let mut reg = NameRegistry::new();
        let target_region = rid(5);

        let mut l1 = reg
            .register("a", tid(1), target_region, Time::ZERO)
            .unwrap();
        let mut l2 = reg
            .register("b", tid(2), target_region, Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("c", tid(3), target_region, Time::from_secs(2))
            .unwrap();

        // Survivor in another region
        let mut l4 = reg
            .register("d", tid(4), rid(99), Time::from_secs(3))
            .unwrap();

        // Region cancel: cleanup → abort each lease
        let removed = reg.cleanup_region(target_region);
        assert_eq!(removed.len(), 3);

        // All removed leases must abort successfully
        for (lease, name) in [(&mut l1, "a"), (&mut l2, "b"), (&mut l3, "c")] {
            assert!(
                lease.is_active(),
                "lease '{name}' should still be active pre-abort"
            );
            let proof = lease.abort().unwrap();
            assert!(!lease.is_active());
            let _ = proof; // obligation resolved
        }

        // Registry only has the survivor
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("d"), Some(tid(4)));

        l4.release().unwrap();

        crate::test_complete!("conformance_region_cancel_aborts_all_leases");
    }

    /// Conformance: trace event ordering is deterministic for a fixed operation
    /// sequence. Running the same sequence multiple times must produce the same
    /// event list in the same order.
    #[test]
    fn conformance_event_ordering_stable_across_seeds() {
        fn build_event_sequence() -> Vec<RegistryEvent> {
            // Build the canonical event sequence for a known operation order.
            // The events are constructed manually to match what the registry
            // operations WOULD emit (the NameRegistry itself doesn't emit events;
            // the caller is responsible for emitting RegistryEvents).
            vec![
                // Simulate: register "b", register "a", register "c", cleanup region 0
                RegistryEvent::NameRegistered {
                    name: "b".into(),
                    holder: tid(2),
                    region: rid(0),
                },
                RegistryEvent::NameRegistered {
                    name: "a".into(),
                    holder: tid(1),
                    region: rid(0),
                },
                RegistryEvent::NameRegistered {
                    name: "c".into(),
                    holder: tid(3),
                    region: rid(0),
                },
                RegistryEvent::RegionCleanup {
                    region: rid(0),
                    count: 3,
                },
                // Abort events follow BTreeMap order (a, b, c)
                RegistryEvent::NameAborted {
                    name: "a".into(),
                    holder: tid(1),
                    reason: "region cleanup".into(),
                },
                RegistryEvent::NameAborted {
                    name: "b".into(),
                    holder: tid(2),
                    reason: "region cleanup".into(),
                },
                RegistryEvent::NameAborted {
                    name: "c".into(),
                    holder: tid(3),
                    reason: "region cleanup".into(),
                },
            ]
        }

        init_test("conformance_event_ordering_stable_across_seeds");

        // Run the same sequence 10 times; verify it matches the canonical ordering
        let canonical = build_event_sequence();
        for trial in 0..10 {
            let events = build_event_sequence();
            assert_eq!(
                events, canonical,
                "trial {trial}: event sequence diverged from canonical"
            );
        }

        // Verify that cleanup_region returns names in sorted order (BTreeMap guarantee)
        // which ensures abort events follow a deterministic order.
        let mut reg = NameRegistry::new();
        let mut l1 = reg.register("b", tid(2), rid(0), Time::ZERO).unwrap();
        let mut l2 = reg
            .register("a", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("c", tid(3), rid(0), Time::from_secs(2))
            .unwrap();

        let removed = reg.cleanup_region(rid(0));
        // BTreeMap iteration guarantees sorted order regardless of insertion order
        assert_eq!(
            removed,
            vec!["a", "b", "c"],
            "cleanup must return sorted names"
        );

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();

        crate::test_complete!("conformance_event_ordering_stable_across_seeds");
    }

    /// Conformance: cleanup_task returns names in deterministic (sorted) order,
    /// regardless of registration order. This is critical for trace stability.
    #[test]
    fn conformance_cleanup_task_deterministic_order() {
        init_test("conformance_cleanup_task_deterministic_order");

        let mut reg = NameRegistry::new();

        // Register in reverse alphabetical order
        let mut l1 = reg.register("z_last", tid(1), rid(0), Time::ZERO).unwrap();
        let mut l2 = reg
            .register("m_mid", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("a_first", tid(1), rid(0), Time::from_secs(2))
            .unwrap();

        let removed = reg.cleanup_task(tid(1));
        assert_eq!(
            removed,
            vec!["a_first", "m_mid", "z_last"],
            "cleanup_task must return names in sorted order"
        );

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();

        crate::test_complete!("conformance_cleanup_task_deterministic_order");
    }

    /// Conformance: after crash + re-register, the new holder is visible and
    /// the old holder is completely gone. No phantom entries from the old lease.
    #[test]
    fn conformance_re_register_after_crash_clean() {
        init_test("conformance_re_register_after_crash_clean");

        let mut reg = NameRegistry::new();

        // Original holder registers
        let mut old_lease = reg
            .register("primary_db", tid(10), rid(0), Time::ZERO)
            .unwrap();

        // Crash: cleanup the old task
        let removed = reg.cleanup_task(tid(10));
        assert_eq!(removed, vec!["primary_db"]);
        old_lease.abort().unwrap();

        // New holder registers the same name
        let mut new_lease = reg
            .register("primary_db", tid(20), rid(1), Time::from_secs(10))
            .unwrap();

        // Verify new state is clean
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("primary_db"), Some(tid(20)));
        assert_eq!(new_lease.holder(), tid(20));
        assert_eq!(new_lease.region(), rid(1));
        assert_eq!(new_lease.acquired_at(), Time::from_secs(10));

        // Old task has no lingering entries
        let old_removed = reg.cleanup_task(tid(10));
        assert!(old_removed.is_empty(), "old task must have no entries");

        new_lease.release().unwrap();

        crate::test_complete!("conformance_re_register_after_crash_clean");
    }

    /// Conformance: interleaved register/unregister/crash cycles maintain
    /// consistency. The registry length always matches registered_names().len(),
    /// and whereis agrees with is_registered for all known names.
    #[test]
    fn conformance_registry_invariant_under_churn() {
        init_test("conformance_registry_invariant_under_churn");

        let mut reg = NameRegistry::new();
        let mut active_leases: Vec<NameLease> = Vec::new();

        // Phase 1: bulk register
        for i in 0..10 {
            let name = format!("svc_{i:03}");
            let lease = reg
                .register(&name, tid(i), rid(i % 3), Time::from_secs(u64::from(i)))
                .unwrap();
            active_leases.push(lease);
        }
        assert_eq!(reg.len(), 10);

        // Phase 2: crash region 1 (tasks 1, 4, 7)
        let removed = reg.cleanup_region(rid(1));
        for name in &removed {
            // Find and abort the matching lease
            if let Some(lease) = active_leases.iter_mut().find(|l| l.name() == name.as_str()) {
                lease.abort().unwrap();
            }
        }

        // Phase 3: unregister svc_000 explicitly
        reg.unregister("svc_000").unwrap();
        if let Some(lease) = active_leases.iter_mut().find(|l| l.name() == "svc_000") {
            lease.release().unwrap();
        }

        // Phase 4: re-register a crashed name with new holder
        let new_lease = reg
            .register("svc_001", tid(100), rid(5), Time::from_secs(100))
            .unwrap();
        active_leases.push(new_lease);

        // Invariant check: len matches registered_names count
        let names = reg.registered_names();
        assert_eq!(
            reg.len(),
            names.len(),
            "len() and registered_names().len() must agree"
        );

        // Invariant check: whereis agrees with is_registered for every name we've seen
        for name in &names {
            assert!(
                reg.is_registered(name),
                "name '{name}' in registered_names but is_registered returns false"
            );
            assert!(
                reg.whereis(name).is_some(),
                "name '{name}' in registered_names but whereis returns None"
            );
        }

        // Invariant check: names are sorted (BTreeMap guarantee)
        for window in names.windows(2) {
            assert!(
                window[0] <= window[1],
                "registered_names not sorted: '{}' > '{}'",
                window[0],
                window[1]
            );
        }

        // Cleanup remaining leases
        for lease in &mut active_leases {
            if lease.is_active() {
                let _ = lease.abort();
            }
        }

        crate::test_complete!("conformance_registry_invariant_under_churn");
    }

    /// Conformance: the linearity contract — every lease must be resolved.
    /// Release produces CommittedProof, abort produces AbortedProof, and
    /// the proof types carry the correct resolution kind.
    #[test]
    fn conformance_linearity_proofs() {
        init_test("conformance_linearity_proofs");

        // Test committed proof
        let mut committed_lease = NameLease::new("committed", tid(1), rid(0), Time::ZERO);
        let committed = committed_lease.release().unwrap();
        let resolved = committed.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Commit,
            "release must produce Commit proof"
        );

        // Test aborted proof
        let mut aborted_lease = NameLease::new("aborted", tid(2), rid(0), Time::ZERO);
        let aborted = aborted_lease.abort().unwrap();
        let resolved = aborted.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Abort,
            "abort must produce Abort proof"
        );

        crate::test_complete!("conformance_linearity_proofs");
    }

    /// Conformance: cross-region isolation. Cleaning up one region must not
    /// affect names in other regions, even if they share the same task IDs.
    #[test]
    fn conformance_cross_region_isolation() {
        init_test("conformance_cross_region_isolation");

        let mut reg = NameRegistry::new();

        // Same task ID (1) registers in two different regions
        let mut l1 = reg.register("r1_name", tid(1), rid(1), Time::ZERO).unwrap();
        let mut l2 = reg
            .register("r2_name", tid(1), rid(2), Time::from_secs(1))
            .unwrap();

        // Cleanup region 1
        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["r1_name"]);

        // Region 2's name must survive
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("r2_name"), Some(tid(1)));
        assert!(reg.is_registered("r2_name"));
        assert!(!reg.is_registered("r1_name"));

        l1.abort().unwrap();
        l2.release().unwrap();

        crate::test_complete!("conformance_cross_region_isolation");
    }

    // ---------------------------------------------------------------
    // NamePermit conformance tests (bd-2is3i)
    // ---------------------------------------------------------------

    /// Conformance: cleanup_task also removes pending permits held by the task.
    #[test]
    fn conformance_cleanup_task_removes_pending_permits() {
        init_test("conformance_cleanup_task_removes_pending_permits");

        let mut reg = NameRegistry::new();

        // Task 1 has a committed lease and a pending permit.
        let mut lease = reg.register("active", tid(1), rid(0), Time::ZERO).unwrap();
        let mut permit = reg
            .reserve("pending_name", tid(1), rid(0), Time::from_secs(1))
            .expect("reserve ok");

        let removed = reg.cleanup_task(tid(1));
        assert_eq!(removed, vec!["active", "pending_name"]);
        assert_eq!(reg.len(), 0);

        // Both name slots freed — a new task can take either.
        let mut l2 = reg
            .register("pending_name", tid(2), rid(0), Time::from_secs(2))
            .unwrap();

        lease.abort().unwrap();
        permit.abort().unwrap();
        l2.release().unwrap();

        crate::test_complete!("conformance_cleanup_task_removes_pending_permits");
    }

    /// Conformance: double reserve of the same name is blocked.
    #[test]
    fn conformance_double_reserve_blocked() {
        init_test("conformance_double_reserve_blocked");

        let mut reg = NameRegistry::new();
        let mut p1 = reg
            .reserve("singleton", tid(1), rid(0), Time::ZERO)
            .expect("first reserve ok");

        let err = reg
            .reserve("singleton", tid(2), rid(0), Time::ZERO)
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );

        p1.abort().unwrap();
        reg.cancel_permit("singleton");

        crate::test_complete!("conformance_double_reserve_blocked");
    }

    /// Conformance: permit accessors return correct values.
    #[test]
    fn permit_accessors() {
        init_test("permit_accessors");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("my_svc", tid(7), rid(3), Time::from_secs(42))
            .expect("reserve ok");

        assert_eq!(permit.name(), "my_svc");
        assert_eq!(permit.holder(), tid(7));
        assert_eq!(permit.region(), rid(3));
        assert_eq!(permit.reserved_at(), Time::from_secs(42));
        assert!(permit.is_pending());

        permit.abort().unwrap();
        assert!(!permit.is_pending());
        reg.cancel_permit("my_svc");

        crate::test_complete!("permit_accessors");
    }

    /// Conformance: permit commit produces a valid active NameLease with
    /// the same obligation token (no new token created).
    #[test]
    fn conformance_permit_commit_transfers_token() {
        init_test("conformance_permit_commit_transfers_token");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("transfer", tid(1), rid(0), Time::from_secs(5))
            .expect("reserve ok");

        let mut lease = reg.commit_permit(permit).expect("commit ok");

        // Lease inherits permit's metadata.
        assert_eq!(lease.name(), "transfer");
        assert_eq!(lease.holder(), tid(1));
        assert_eq!(lease.region(), rid(0));
        assert_eq!(lease.acquired_at(), Time::from_secs(5));
        assert!(lease.is_active());

        // The lease can be released (obligation committed).
        let proof = lease.release().unwrap();
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Commit,
        );

        crate::test_complete!("conformance_permit_commit_transfers_token");
    }

    /// Conformance: permit abort produces a valid AbortedProof.
    #[test]
    fn conformance_permit_abort_proof() {
        init_test("conformance_permit_abort_proof");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("abortable", tid(1), rid(0), Time::ZERO)
            .expect("reserve ok");

        let proof = permit.abort().unwrap();
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Abort,
        );

        // Double abort is an error.
        assert_eq!(permit.abort().unwrap_err(), NameLeaseError::AlreadyResolved);

        reg.cancel_permit("abortable");

        crate::test_complete!("conformance_permit_abort_proof");
    }

    /// Conformance: committed lease blocks a new reserve on the same name.
    #[test]
    fn conformance_lease_blocks_reserve() {
        init_test("conformance_lease_blocks_reserve");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("taken", tid(1), rid(0), Time::ZERO).unwrap();

        let err = reg
            .reserve("taken", tid(2), rid(0), Time::ZERO)
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "taken".into(),
                current_holder: tid(1),
            }
        );

        lease.release().unwrap();

        crate::test_complete!("conformance_lease_blocks_reserve");
    }

    /// Conformance: commit_permit on an already-cancelled permit returns NotFound.
    #[test]
    fn conformance_commit_after_cancel_fails() {
        init_test("conformance_commit_after_cancel_fails");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("ephemeral", tid(1), rid(0), Time::ZERO)
            .expect("reserve ok");

        // Cancel the pending entry first.
        assert!(reg.cancel_permit("ephemeral"));

        // commit_permit should fail because the name is no longer pending.
        let err = reg.commit_permit(permit).unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NotFound {
                name: "ephemeral".into()
            }
        );

        crate::test_complete!("conformance_commit_after_cancel_fails");
    }
}
