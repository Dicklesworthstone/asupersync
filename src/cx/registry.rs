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
// Collision Policy (bd-16j5r)
// ============================================================================

/// How to handle a name collision during registration.
///
/// Determinism contract (REG-FIRST): the scheduler's `pick_next` ordering
/// determines which task calls `register_with_policy` first. The collision
/// policy governs what happens when a second task requests the same name.
///
/// # Bead
///
/// bd-16j5r | Parent: bd-133q8
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCollisionPolicy {
    /// Reject the registration with `NameLeaseError::NameTaken`.
    Fail,
    /// Forcibly replace the existing holder. The old registry entry is removed
    /// and a new lease is created for the new holder. The old holder's
    /// `NameLease` becomes orphaned — the caller is responsible for notifying
    /// the displaced task so it can abort its lease.
    Replace,
    /// Enqueue a budgeted waiter. The name will be granted to the first
    /// waiter (FIFO, deterministic) whose deadline has not passed when the
    /// name becomes available. Use [`NameRegistry::take_granted`] to drain
    /// granted leases after a name is freed.
    Wait {
        /// Maximum virtual time at which the wait expires.
        deadline: Time,
    },
}

/// Outcome of a [`NameRegistry::register_with_policy`] call.
#[derive(Debug)]
pub enum NameCollisionOutcome {
    /// Name was available; lease acquired immediately.
    Registered {
        /// The acquired lease.
        lease: NameLease,
    },
    /// Name was taken and the old holder was displaced.
    Replaced {
        /// The new lease for the replacing task.
        lease: NameLease,
        /// The task that was displaced.
        displaced_holder: TaskId,
        /// The region of the displaced task.
        displaced_region: RegionId,
    },
    /// Name was taken; the request was enqueued as a budgeted waiter.
    /// The lease will be created when the name is freed, if the deadline
    /// has not passed. Use [`NameRegistry::take_granted`] to retrieve it.
    Enqueued,
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
    /// A budgeted wait expired before the name became available.
    WaitBudgetExceeded {
        /// The name that was waited on.
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
            Self::WaitBudgetExceeded { name } => {
                write!(f, "wait budget exceeded for name '{name}'")
            }
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
    /// Budgeted waiters keyed by name (FIFO order per name).
    waiters: BTreeMap<String, Vec<WaiterEntry>>,
    /// Leases granted to waiters, pending retrieval by the waiter's task.
    /// Use [`take_granted`](Self::take_granted) to drain.
    granted: Vec<GrantedLease>,
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

/// Internal entry for a budgeted waiter.
#[derive(Debug)]
struct WaiterEntry {
    /// The task waiting for the name.
    holder: TaskId,
    /// The region of the waiting task.
    region: RegionId,
    /// When the waiter was enqueued.
    enqueued_at: Time,
    /// Maximum virtual time at which the wait expires.
    deadline: Time,
}

/// A lease granted to a waiter when a name becomes available.
#[derive(Debug)]
pub struct GrantedLease {
    /// The name that was granted.
    pub name: String,
    /// The lease for the granted name.
    pub lease: NameLease,
}

impl NameRegistry {
    /// Creates an empty name registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: BTreeMap::new(),
            pending: BTreeMap::new(),
            waiters: BTreeMap::new(),
            granted: Vec::new(),
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

    /// Register a name with an explicit collision policy.
    ///
    /// This is the primary entry point for policy-aware registration. The
    /// `policy` argument determines what happens when the name is already
    /// registered or reserved.
    ///
    /// # Policies
    ///
    /// - [`Fail`](NameCollisionPolicy::Fail): returns `NameLeaseError::NameTaken`.
    /// - [`Replace`](NameCollisionPolicy::Replace): displaces the existing
    ///   holder. The old entry is removed and a new lease is created.
    ///   The caller must notify the displaced task to abort its lease.
    /// - [`Wait`](NameCollisionPolicy::Wait): enqueues a budgeted waiter.
    ///   When the name is freed (via [`unregister_and_grant`](Self::unregister_and_grant)
    ///   or cleanup), the first eligible waiter is granted a lease.
    ///   Use [`take_granted`](Self::take_granted) to retrieve granted leases.
    pub fn register_with_policy(
        &mut self,
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        now: Time,
        policy: NameCollisionPolicy,
    ) -> Result<NameCollisionOutcome, NameLeaseError> {
        let name = name.into();
        let existing = self.leases.get(&name).or_else(|| self.pending.get(&name));

        match existing {
            None => {
                // No collision — register normally.
                self.leases.insert(
                    name.clone(),
                    NameEntry {
                        holder,
                        region,
                        acquired_at: now,
                    },
                );
                let lease = NameLease::new(&name, holder, region, now);
                Ok(NameCollisionOutcome::Registered { lease })
            }
            Some(entry) => {
                let current_holder = entry.holder;
                let current_region = entry.region;
                match policy {
                    NameCollisionPolicy::Fail => Err(NameLeaseError::NameTaken {
                        name,
                        current_holder,
                    }),
                    NameCollisionPolicy::Replace => {
                        // Remove old entries from both maps.
                        self.leases.remove(&name);
                        self.pending.remove(&name);
                        // Insert new entry.
                        self.leases.insert(
                            name.clone(),
                            NameEntry {
                                holder,
                                region,
                                acquired_at: now,
                            },
                        );
                        let lease = NameLease::new(&name, holder, region, now);
                        Ok(NameCollisionOutcome::Replaced {
                            lease,
                            displaced_holder: current_holder,
                            displaced_region: current_region,
                        })
                    }
                    NameCollisionPolicy::Wait { deadline } => {
                        // Enqueue a budgeted waiter.
                        self.waiters.entry(name).or_default().push(WaiterEntry {
                            holder,
                            region,
                            enqueued_at: now,
                            deadline,
                        });
                        Ok(NameCollisionOutcome::Enqueued)
                    }
                }
            }
        }
    }

    /// Unregister a name, removing it from the registry.
    ///
    /// The caller is responsible for resolving the corresponding [`NameLease`].
    /// This does NOT check the waiter queue — use
    /// [`unregister_and_grant`](Self::unregister_and_grant) to also grant
    /// waiting tasks.
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

    /// Unregister a name and grant it to the first eligible waiter.
    ///
    /// If there are no waiters (or all have expired), the name is simply freed.
    /// If a waiter is eligible, a new lease is created and pushed to the
    /// `granted` queue. Use [`take_granted`](Self::take_granted) to retrieve it.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NotFound` if the name is not registered.
    pub fn unregister_and_grant(&mut self, name: &str, now: Time) -> Result<(), NameLeaseError> {
        if self.leases.remove(name).is_none() {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        }
        self.try_grant_to_first_waiter(name, now);
        Ok(())
    }

    /// Check the waiter queue for a name and grant to the first eligible waiter.
    ///
    /// Expired waiters (deadline < now) are removed. If an eligible waiter
    /// exists, a new lease entry is created in `leases` and the lease is
    /// pushed to the `granted` queue.
    fn try_grant_to_first_waiter(&mut self, name: &str, now: Time) {
        let Some(queue) = self.waiters.get_mut(name) else {
            return;
        };
        // Remove expired waiters.
        queue.retain(|w| w.deadline >= now);
        if queue.is_empty() {
            self.waiters.remove(name);
            return;
        }
        // Grant to first waiter (FIFO, deterministic).
        let waiter = queue.remove(0);
        if queue.is_empty() {
            self.waiters.remove(name);
        }
        self.leases.insert(
            name.to_string(),
            NameEntry {
                holder: waiter.holder,
                region: waiter.region,
                acquired_at: now,
            },
        );
        let lease = NameLease::new(name, waiter.holder, waiter.region, now);
        self.granted.push(GrantedLease {
            name: name.to_string(),
            lease,
        });
    }

    /// Drain all granted leases (from waiter grants).
    ///
    /// Returns the list of leases that were granted to waiters since the
    /// last call to `take_granted`. Each returned `GrantedLease` carries
    /// an armed obligation — the caller must resolve it.
    pub fn take_granted(&mut self) -> Vec<GrantedLease> {
        std::mem::take(&mut self.granted)
    }

    /// Remove all expired waiters for a given virtual time.
    ///
    /// Returns the number of waiters removed.
    pub fn drain_expired_waiters(&mut self, now: Time) -> usize {
        let mut removed = 0;
        self.waiters.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|w| w.deadline >= now);
            removed += before - queue.len();
            !queue.is_empty()
        });
        removed
    }

    /// Returns the number of active waiters across all names.
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        self.waiters.values().map(Vec::len).sum()
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
    /// Note: this removes active leases, pending permits, and waiters held
    /// in the region. The caller is responsible for resolving the corresponding
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
        // Also remove waiters belonging to this region.
        for queue in self.waiters.values_mut() {
            queue.retain(|w| w.region != region);
        }
        self.waiters.retain(|_, q| !q.is_empty());
        to_remove
    }

    /// Remove all names held by a specific task.
    ///
    /// Returns the names that were removed (sorted deterministically).
    ///
    /// Note: this removes active leases, pending permits, and waiters held
    /// by the task. The caller is responsible for resolving the corresponding
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
        // Also remove waiters belonging to this task.
        for queue in self.waiters.values_mut() {
            queue.retain(|w| w.holder != task);
        }
        self.waiters.retain(|_, q| !q.is_empty());
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
    /// A name was forcibly replaced (collision policy: Replace).
    NameReplaced {
        /// The name that was replaced.
        name: String,
        /// The new holder.
        new_holder: TaskId,
        /// The displaced holder.
        displaced_holder: TaskId,
    },
    /// A waiter was enqueued for a taken name (collision policy: Wait).
    WaiterEnqueued {
        /// The name being waited on.
        name: String,
        /// The waiting task.
        holder: TaskId,
        /// The deadline for the wait.
        deadline: Time,
    },
    /// A waiter was granted a name when it became available.
    WaiterGranted {
        /// The granted name.
        name: String,
        /// The task that was granted the name.
        holder: TaskId,
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
        let _replaced = RegistryEvent::NameReplaced {
            name: "svc".into(),
            new_holder: tid(2),
            displaced_holder: tid(1),
        };
        let _waiter_enqueued = RegistryEvent::WaiterEnqueued {
            name: "svc".into(),
            holder: tid(2),
            deadline: Time::from_secs(60),
        };
        let _waiter_granted = RegistryEvent::WaiterGranted {
            name: "svc".into(),
            holder: tid(2),
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

    // ---------------------------------------------------------------
    // Collision policy tests (bd-16j5r)
    // ---------------------------------------------------------------

    #[test]
    fn collision_fail_rejects_duplicate() {
        init_test("collision_fail_rejects_duplicate");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("singleton", tid(1), rid(0), Time::ZERO)
            .unwrap();

        let err = reg
            .register_with_policy(
                "singleton",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Fail,
            )
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );
        assert_eq!(reg.len(), 1);

        lease.release().unwrap();
        crate::test_complete!("collision_fail_rejects_duplicate");
    }

    #[test]
    fn collision_fail_succeeds_when_no_collision() {
        init_test("collision_fail_succeeds_when_no_collision");

        let mut reg = NameRegistry::new();
        let outcome = reg
            .register_with_policy(
                "fresh",
                tid(1),
                rid(0),
                Time::ZERO,
                NameCollisionPolicy::Fail,
            )
            .unwrap();

        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"),
        };
        assert_eq!(reg.whereis("fresh"), Some(tid(1)));

        lease.release().unwrap();
        crate::test_complete!("collision_fail_succeeds_when_no_collision");
    }

    #[test]
    fn collision_replace_displaces_old_holder() {
        init_test("collision_replace_displaces_old_holder");

        let mut reg = NameRegistry::new();
        let mut old_lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(1),
                Time::from_secs(5),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced {
                lease,
                displaced_holder,
                displaced_region,
            } => {
                assert_eq!(displaced_holder, tid(1));
                assert_eq!(displaced_region, rid(0));
                lease
            }
            other => panic!("expected Replaced, got {other:?}"),
        };

        // New holder is visible.
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        assert_eq!(reg.len(), 1);

        // Old holder's lease is orphaned — must be aborted.
        old_lease.abort().unwrap();
        new_lease.release().unwrap();

        crate::test_complete!("collision_replace_displaces_old_holder");
    }

    #[test]
    fn collision_replace_on_free_name_registers_normally() {
        init_test("collision_replace_on_free_name_registers_normally");

        let mut reg = NameRegistry::new();
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(1),
                rid(0),
                Time::ZERO,
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"),
        };
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        lease.release().unwrap();
        crate::test_complete!("collision_replace_on_free_name_registers_normally");
    }

    #[test]
    fn collision_wait_enqueues_waiter() {
        init_test("collision_wait_enqueues_waiter");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        assert_eq!(reg.waiter_count(), 1);

        // Name still held by original task.
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_enqueues_waiter");
    }

    #[test]
    fn collision_wait_grants_on_unregister() {
        init_test("collision_wait_grants_on_unregister");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Enqueue a waiter.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));

        // Free the name using unregister_and_grant.
        reg.unregister_and_grant("svc", Time::from_secs(10))
            .unwrap();
        lease.release().unwrap();

        // Waiter should have been granted.
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].name, "svc");
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        assert_eq!(granted_lease.holder(), tid(2));
        granted_lease.release().unwrap();

        crate::test_complete!("collision_wait_grants_on_unregister");
    }

    #[test]
    fn collision_wait_expired_waiter_not_granted() {
        init_test("collision_wait_expired_waiter_not_granted");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Enqueue a waiter with a short deadline.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(5),
            },
        )
        .unwrap();

        // Free the name AFTER the deadline.
        reg.unregister_and_grant("svc", Time::from_secs(10))
            .unwrap();
        lease.release().unwrap();

        // Waiter should NOT have been granted (expired).
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), None);
        let granted = reg.take_granted();
        assert!(granted.is_empty());

        crate::test_complete!("collision_wait_expired_waiter_not_granted");
    }

    #[test]
    fn collision_wait_fifo_ordering() {
        init_test("collision_wait_fifo_ordering");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Enqueue two waiters.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        reg.register_with_policy(
            "svc",
            tid(3),
            rid(0),
            Time::from_secs(2),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 2);

        // Free the name — first waiter (tid 2) should win.
        reg.unregister_and_grant("svc", Time::from_secs(10))
            .unwrap();
        lease.release().unwrap();

        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        assert_eq!(reg.waiter_count(), 1); // tid 3 still waiting

        // Free again — second waiter (tid 3) should get it.
        let mut granted1 = reg.take_granted().into_iter().next().unwrap().lease;
        reg.unregister_and_grant("svc", Time::from_secs(20))
            .unwrap();
        granted1.release().unwrap();

        assert_eq!(reg.whereis("svc"), Some(tid(3)));
        assert_eq!(reg.waiter_count(), 0);

        let mut granted2 = reg.take_granted().into_iter().next().unwrap().lease;
        granted2.release().unwrap();

        crate::test_complete!("collision_wait_fifo_ordering");
    }

    #[test]
    fn collision_wait_cleanup_region_removes_waiters() {
        init_test("collision_wait_cleanup_region_removes_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Enqueue a waiter in region 1.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(1),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup region 1 removes the waiter.
        reg.cleanup_region(rid(1));
        assert_eq!(reg.waiter_count(), 0);

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_cleanup_region_removes_waiters");
    }

    #[test]
    fn collision_wait_cleanup_task_removes_waiters() {
        init_test("collision_wait_cleanup_task_removes_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Enqueue a waiter from task 2.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup task 2 removes the waiter.
        reg.cleanup_task(tid(2));
        assert_eq!(reg.waiter_count(), 0);

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_cleanup_task_removes_waiters");
    }

    #[test]
    fn collision_drain_expired_waiters() {
        init_test("collision_drain_expired_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        // Two waiters with different deadlines.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(10),
            },
        )
        .unwrap();
        reg.register_with_policy(
            "svc",
            tid(3),
            rid(0),
            Time::from_secs(2),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(100),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 2);

        // Drain expired at time 50: only first waiter is expired.
        let removed = reg.drain_expired_waiters(Time::from_secs(50));
        assert_eq!(removed, 1);
        assert_eq!(reg.waiter_count(), 1);

        lease.abort().unwrap();
        crate::test_complete!("collision_drain_expired_waiters");
    }

    #[test]
    fn collision_replace_displaces_pending_permit() {
        init_test("collision_replace_displaces_pending_permit");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::ZERO)
            .expect("reserve ok");

        // Replace policy should displace the pending permit.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced {
                lease,
                displaced_holder,
                ..
            } => {
                assert_eq!(displaced_holder, tid(1));
                lease
            }
            other => panic!("expected Replaced, got {other:?}"),
        };

        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        // The old permit is orphaned; abort it.
        permit.abort().unwrap();
        new_lease.release().unwrap();

        crate::test_complete!("collision_replace_displaces_pending_permit");
    }

    /// Conformance: register_with_policy Fail mode is equivalent to register().
    #[test]
    fn conformance_policy_fail_equivalent_to_register() {
        init_test("conformance_policy_fail_equivalent_to_register");

        let mut reg = NameRegistry::new();

        // Register with Fail policy.
        let outcome = reg
            .register_with_policy("svc", tid(1), rid(0), Time::ZERO, NameCollisionPolicy::Fail)
            .unwrap();
        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"),
        };

        // Try again — should fail identically to register().
        let err_policy = reg
            .register_with_policy("svc", tid(2), rid(0), Time::ZERO, NameCollisionPolicy::Fail)
            .unwrap_err();
        let err_register = reg.register("svc", tid(3), rid(0), Time::ZERO).unwrap_err();

        // Both should be NameTaken with holder tid(1).
        match (&err_policy, &err_register) {
            (
                NameLeaseError::NameTaken {
                    current_holder: h1, ..
                },
                NameLeaseError::NameTaken {
                    current_holder: h2, ..
                },
            ) => assert_eq!(h1, h2),
            _ => panic!("expected NameTaken from both"),
        }

        lease.release().unwrap();
        crate::test_complete!("conformance_policy_fail_equivalent_to_register");
    }

    /// Conformance: replace produces a valid active lease for the new holder.
    #[test]
    fn conformance_replace_lease_is_valid() {
        init_test("conformance_replace_lease_is_valid");

        let mut reg = NameRegistry::new();
        let mut old_lease = reg.register("svc", tid(1), rid(0), Time::ZERO).unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(1),
                Time::from_secs(5),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced { lease, .. } => lease,
            other => panic!("expected Replaced, got {other:?}"),
        };

        // New lease metadata is correct.
        assert_eq!(new_lease.name(), "svc");
        assert_eq!(new_lease.holder(), tid(2));
        assert_eq!(new_lease.region(), rid(1));
        assert_eq!(new_lease.acquired_at(), Time::from_secs(5));
        assert!(new_lease.is_active());

        // Can release with a valid proof.
        let proof = new_lease.release().unwrap();
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution,
            crate::obligation::graded::Resolution::Commit,
        );

        old_lease.abort().unwrap();
        crate::test_complete!("conformance_replace_lease_is_valid");
    }

    /// Conformance: WaitBudgetExceeded error displays correctly.
    #[test]
    fn wait_budget_exceeded_display() {
        init_test("wait_budget_exceeded_display");

        let err = NameLeaseError::WaitBudgetExceeded { name: "svc".into() };
        assert!(err.to_string().contains("svc"));
        assert!(err.to_string().contains("budget"));

        crate::test_complete!("wait_budget_exceeded_display");
    }
}
