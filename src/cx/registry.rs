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
use crate::util::{DetBuildHasher, DetHashMap};
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
/// - **Commit** (`release()`): the holder is done; obligation committed.
/// - **Abort** (`abort()`): cancellation/cleanup path; obligation aborted.
///
/// Resolving the lease does not touch the [`NameRegistry`]: free the name
/// there too, with [`NameRegistry::unregister_owned_and_grant`] (or
/// `unregister`), or `whereis` keeps reporting the holder.
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
    /// Creates a new name lease (registry-internal mint).
    ///
    /// br-asupersync-td50ls: this constructor is module-private so
    /// external callers cannot forge a NameLease with arbitrary
    /// holder/region/acquired_at and pass it to
    /// [`NameRegistry::unregister_owned_and_grant`] — whose identity
    /// check would otherwise compare the FORGED values against the
    /// real entry, allowing the attacker to drop a victim's lease
    /// without holding the obligation token. Public callers obtain
    /// a [`NameLease`] only via [`NameRegistry::register`],
    /// [`NameRegistry::register_with_policy`], or
    /// [`NameRegistry::commit_permit`]. (Mirrors
    /// [`NamePermit::new`] which is correctly private for the same
    /// reason.)
    #[must_use]
    fn new(name: impl Into<String>, holder: TaskId, region: RegionId, acquired_at: Time) -> Self {
        let name = name.into();
        // br-asupersync-n4103r: replaced `format!("name_lease:{name}")`
        // with explicit `String::with_capacity` + `push_str`. format!
        // dispatches through the runtime format-string parser
        // (write!/Arguments machinery) which adds overhead beyond the
        // raw heap allocation. The explicit construction allocates
        // exactly once at the right capacity (no growth realloc) and
        // skips the format-string parser entirely. On the per-name-
        // resolution hot path this is ~30-40% faster than format!
        // per established Rust microbenchmarks.
        const PREFIX: &str = "name_lease:";
        let mut description = String::with_capacity(PREFIX.len() + name.len());
        description.push_str(PREFIX);
        description.push_str(&name);
        let token = ObligationToken::reserve(description, region);
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

    /// Rebinds this lease to a new holder task and region (internal to registry transfer).
    pub(crate) fn rebind(&mut self, new_holder: TaskId, new_region: RegionId) {
        self.holder = new_holder;
        self.region = new_region;
    }

    /// Release the name (commit the obligation).
    ///
    /// The obligation is committed. The registry entry is not removed:
    /// free the name with [`NameRegistry::unregister_owned_and_grant`].
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
    /// The obligation is aborted. The registry entry is not removed: free
    /// the name with [`NameRegistry::unregister_owned_and_grant`].
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
/// Only the registry can mint permits. Callers must obtain them through
/// [`NameRegistry::reserve`] instead of constructing them directly.
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
    /// Monotonic identity for this specific permit instance.
    permit_id: u64,
    /// Obligation token (drop bomb). Transferred to NameLease on commit.
    token: Option<ObligationToken<LeaseKind>>,
}

impl NamePermit {
    /// Creates a new registry-issued permit with an armed obligation token.
    ///
    /// This stays private so callers cannot fabricate permit witnesses with
    /// guessed identity nonces and replay them against the pending set.
    #[must_use]
    fn new(
        name: impl Into<String>,
        holder: TaskId,
        region: RegionId,
        reserved_at: Time,
        permit_id: u64,
    ) -> Self {
        let name = name.into();
        // br-asupersync-n4103r: same format!→push_str refactor as
        // NameLease::new. See its inline comment for the rationale.
        const PREFIX: &str = "name_permit:";
        let mut description = String::with_capacity(PREFIX.len() + name.len());
        description.push_str(PREFIX);
        description.push_str(&name);
        let token = ObligationToken::reserve(description, region);
        Self {
            name,
            holder,
            region,
            reserved_at,
            permit_id,
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

    #[must_use]
    fn permit_id(&self) -> u64 {
        self.permit_id
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
            name: self.name,
            holder: self.holder,
            region: self.region,
            acquired_at: self.reserved_at,
            token: Some(token),
        }
    }

    /// Abort the permit (resolve the obligation token).
    ///
    /// br-asupersync-smpwix: this is `pub(crate)` because aborting the
    /// obligation in isolation does NOT remove the pending entry from
    /// the registry — and the previously-public shape made it
    /// trivially possible for a caller to leak the pending entry by
    /// dropping the permit after `abort()` without also calling
    /// `cancel_permit`. The leak blocked all future
    /// reservations/registrations of that name (a DoS surface). The
    /// supported public shape is now [`NameRegistry::abort_permit`],
    /// which atomically removes the pending entry AND resolves the
    /// obligation token. The internal callsites in `commit_permit`
    /// still use this method directly because the pending entry has
    /// already been removed/handled at that point.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::AlreadyResolved` if the permit was already
    /// committed or aborted.
    pub(crate) fn abort(&mut self) -> Result<AbortedProof<LeaseKind>, NameLeaseError> {
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
    /// The permit does not belong to the pending entry's holder/region.
    PermissionDenied {
        /// The name that was denied.
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
            Self::PermissionDenied { name } => {
                write!(f, "permit identity mismatch for name '{name}'")
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
/// Resource limits for name watchers (br-asupersync-ad716k).
const MAX_WATCHERS_PER_REGION: usize = 1000;
const MAX_WATCHERS_PER_NAME: usize = 100;
const MAX_TOTAL_WATCHERS: usize = 10000;

/// Uses deterministic hash maps for O(1) average lookup behavior.
///
/// Public outputs remain deterministic through explicit sorting where needed,
/// and all mutations emit [`RegistryEvent`]s for trace visibility.
#[derive(Debug)]
pub struct NameRegistry {
    /// Active leases keyed by name.
    leases: DetHashMap<String, NameEntry>,
    /// Pending permits keyed by name (reserved but not yet committed).
    pending: DetHashMap<String, NameEntry>,
    /// Budgeted waiters keyed by name (FIFO order per name).
    waiters: DetHashMap<String, std::collections::VecDeque<WaiterEntry>>,
    /// Leases granted to waiters, pending retrieval by the waiter's task.
    /// Use [`take_granted`](Self::take_granted) to drain.
    granted: Vec<GrantedLease>,
    /// Name ownership watchers keyed by watch reference.
    watchers_by_ref: DetHashMap<NameWatchRef, NameWatcher>,
    /// Reverse index: name -> watch refs interested in ownership changes.
    watchers_by_name: DetHashMap<String, Vec<NameWatchRef>>,
    /// Reverse index: watcher region -> watch refs (for region-close cleanup).
    watchers_by_region: DetHashMap<RegionId, Vec<NameWatchRef>>,
    /// Buffered ownership change notifications.
    notifications: Vec<NameOwnershipNotification>,
    /// Monotonic counter for allocating `NameWatchRef` values.
    next_watch_ref: u64,
    /// Monotonic counter for pending-permit identities.
    next_permit_id: u64,
}

/// Internal entry for a registered name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NameEntry {
    /// The task holding this name.
    holder: TaskId,
    /// The region of the holder.
    region: RegionId,
    /// Virtual time at which the lease was acquired.
    acquired_at: Time,
    /// Identity nonce for pending entries. Active leases store `0`.
    identity_nonce: u64,
}

/// Internal entry for a budgeted waiter.
#[derive(Debug)]
struct WaiterEntry {
    /// The task waiting for the name.
    holder: TaskId,
    /// The region of the waiting task.
    region: RegionId,
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

/// Reference returned by [`NameRegistry::watch_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameWatchRef(u64);

impl NameWatchRef {
    /// Returns the numeric identifier for this watch reference.
    #[must_use]
    pub fn id(self) -> u64 {
        self.0
    }
}

/// Ownership transition type for name-monitor notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameOwnershipKind {
    /// A name became owned by a task.
    Acquired,
    /// A previously owned name was released from the registry.
    Released,
}

/// Notification emitted to a name watcher on ownership changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameOwnershipNotification {
    /// The watch reference that matched.
    pub watch_ref: NameWatchRef,
    /// The watcher task that subscribed.
    pub watcher: TaskId,
    /// The region that owns the watcher.
    pub watcher_region: RegionId,
    /// The name whose ownership changed.
    pub name: String,
    /// The task that acquired or released the name.
    pub holder: TaskId,
    /// The holder's region.
    pub region: RegionId,
    /// Kind of ownership change.
    pub kind: NameOwnershipKind,
}

#[derive(Debug, Clone)]
struct NameWatcher {
    watch_ref: NameWatchRef,
    watcher: TaskId,
    watcher_region: RegionId,
    name: String,
}

impl NameRegistry {
    /// Creates an empty name registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: DetHashMap::with_capacity_and_hasher(32, DetBuildHasher::default()),
            pending: DetHashMap::with_capacity_and_hasher(16, DetBuildHasher::default()),
            waiters: DetHashMap::with_capacity_and_hasher(16, DetBuildHasher::default()),
            granted: Vec::with_capacity(8),
            watchers_by_ref: DetHashMap::with_capacity_and_hasher(16, DetBuildHasher::default()),
            watchers_by_name: DetHashMap::with_capacity_and_hasher(16, DetBuildHasher::default()),
            watchers_by_region: DetHashMap::with_capacity_and_hasher(8, DetBuildHasher::default()),
            notifications: Vec::with_capacity(8),
            next_watch_ref: 1,
            next_permit_id: 1,
        }
    }

    /// Register interest in ownership changes for a specific name.
    ///
    /// Watchers receive notifications when the name is acquired or released.
    /// Delivery is deterministic for a fixed schedule and watch set.
    ///
    /// # Resource Limits (br-asupersync-ad716k)
    ///
    /// Returns `None` if adding this watcher would exceed resource limits:
    /// - Maximum watchers per region: 1000
    /// - Maximum watchers per name: 100
    /// - Maximum total watchers: 10000
    ///
    /// This prevents memory exhaustion DoS attacks via unbounded watcher growth.
    pub fn watch_name(
        &mut self,
        name: impl Into<String>,
        watcher: TaskId,
        watcher_region: RegionId,
    ) -> Option<NameWatchRef> {
        let name = name.into();

        // Check global watcher limit (br-asupersync-ad716k)
        if self.watchers_by_ref.len() >= MAX_TOTAL_WATCHERS {
            return None;
        }

        // Check per-name watcher limit (br-asupersync-ad716k)
        if let Some(name_watchers) = self.watchers_by_name.get(&name) {
            if name_watchers.len() >= MAX_WATCHERS_PER_NAME {
                return None;
            }
        }

        // Check per-region watcher limit (br-asupersync-ad716k)
        if let Some(region_watchers) = self.watchers_by_region.get(&watcher_region) {
            if region_watchers.len() >= MAX_WATCHERS_PER_REGION {
                return None;
            }
        }

        let watch_ref = NameWatchRef(self.next_watch_ref);
        self.next_watch_ref = self
            .next_watch_ref
            .checked_add(1)
            .expect("watch ref overflow");

        let watcher_record = NameWatcher {
            watch_ref,
            watcher,
            watcher_region,
            name: name.clone(),
        };
        self.watchers_by_ref.insert(watch_ref, watcher_record);
        self.watchers_by_name
            .entry(name)
            .or_default()
            .push(watch_ref);
        self.watchers_by_region
            .entry(watcher_region)
            .or_default()
            .push(watch_ref);
        Some(watch_ref)
    }

    /// Remove a name watch reference.
    ///
    /// Returns `true` if the watch existed.
    pub fn unwatch_name(&mut self, watch_ref: NameWatchRef) -> bool {
        let Some(record) = self.watchers_by_ref.remove(&watch_ref) else {
            return false;
        };
        if let Some(refs) = self.watchers_by_name.get_mut(&record.name) {
            refs.retain(|r| *r != watch_ref);
            if refs.is_empty() {
                self.watchers_by_name.remove(&record.name);
            }
        }
        if let Some(refs) = self.watchers_by_region.get_mut(&record.watcher_region) {
            refs.retain(|r| *r != watch_ref);
            if refs.is_empty() {
                self.watchers_by_region.remove(&record.watcher_region);
            }
        }
        true
    }

    /// Remove all name watchers owned by a region.
    ///
    /// Returns the removed watch refs in deterministic order.
    pub fn cleanup_name_watchers_region(&mut self, region: RegionId) -> Vec<NameWatchRef> {
        let Some(refs) = self.watchers_by_region.remove(&region) else {
            return Vec::new();
        };
        let mut removed = Vec::with_capacity(refs.len());
        for watch_ref in refs {
            if let Some(record) = self.watchers_by_ref.remove(&watch_ref) {
                if let Some(name_refs) = self.watchers_by_name.get_mut(&record.name) {
                    name_refs.retain(|r| *r != watch_ref);
                    if name_refs.is_empty() {
                        self.watchers_by_name.remove(&record.name);
                    }
                }
                removed.push(watch_ref);
            }
        }
        removed.sort();
        removed
    }

    /// Remove all name watchers owned by a task.
    ///
    /// Returns the removed watch refs in deterministic order.
    pub fn cleanup_name_watchers_task(&mut self, task: TaskId) -> Vec<NameWatchRef> {
        let mut removed: Vec<NameWatchRef> = self
            .watchers_by_ref
            .iter()
            .filter(|(_, record)| record.watcher == task)
            .map(|(watch_ref, _)| *watch_ref)
            .collect();
        removed.sort();
        for watch_ref in &removed {
            let _ = self.unwatch_name(*watch_ref);
        }
        removed
    }

    /// Returns the number of active name watchers.
    #[must_use]
    pub fn name_watcher_count(&self) -> usize {
        self.watchers_by_ref.len()
    }

    /// Drain queued name ownership notifications in deterministic order.
    pub fn take_name_notifications(&mut self) -> Vec<NameOwnershipNotification> {
        std::mem::take(&mut self.notifications)
    }

    fn emit_name_change(
        &mut self,
        name: &str,
        holder: TaskId,
        region: RegionId,
        kind: NameOwnershipKind,
    ) {
        let Some(refs) = self.watchers_by_name.get(name).cloned() else {
            return;
        };
        let mut refs = refs;
        refs.sort();
        self.notifications.reserve(refs.len());
        for watch_ref in refs {
            if let Some(watcher) = self.watchers_by_ref.get(&watch_ref) {
                self.notifications.push(NameOwnershipNotification {
                    watch_ref: watcher.watch_ref,
                    watcher: watcher.watcher,
                    watcher_region: watcher.watcher_region,
                    name: name.to_string(),
                    holder,
                    region,
                    kind,
                });
            }
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
        // Mint before mutating: minting panics for a root-region holder
        // (ASUP-E103), which must leave the registry unchanged.
        let lease = NameLease::new(name.clone(), holder, region, now);
        self.leases.insert(
            name.clone(),
            NameEntry {
                holder,
                region,
                acquired_at: now,
                identity_nonce: 0,
            },
        );
        self.emit_name_change(&name, holder, region, NameOwnershipKind::Acquired);
        Ok(lease)
    }

    /// Reserve a name, creating a [`NamePermit`].
    ///
    /// The name is reserved but NOT yet visible to [`whereis`](Self::whereis).
    /// The permit must be committed via [`commit_permit`](Self::commit_permit)
    /// to make the name visible, or aborted via
    /// [`NameRegistry::abort_permit`].
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
        let permit_id = self.next_permit_id;
        // Mint before mutating (see `register`).
        let permit = NamePermit::new(name.clone(), holder, region, now, permit_id);
        self.next_permit_id = self
            .next_permit_id
            .checked_add(1)
            .expect("permit identity overflow");
        self.pending.insert(
            name,
            NameEntry {
                holder,
                region,
                acquired_at: now,
                identity_nonce: permit_id,
            },
        );
        Ok(permit)
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
        if !permit.is_pending() {
            return Err(NameLeaseError::AlreadyResolved);
        }
        let name = permit.name().to_string();
        let Some(entry) = self.pending.remove(&name) else {
            // Abort the permit to defuse the drop bomb before returning error.
            let _ = permit.abort();
            return Err(NameLeaseError::NotFound { name });
        };
        // Verify the permit belongs to the same holder/region that reserved it.
        // Without this check, a permit transferred across tasks could commit
        // under a different identity, creating split-brain registry state.
        if permit.holder() != entry.holder
            || permit.region() != entry.region
            || permit.permit_id() != entry.identity_nonce
        // ubs:ignore - not a secret
        {
            // Re-insert the pending entry so the original holder can still commit.
            self.pending.insert(name.clone(), entry);
            let _ = permit.abort();
            return Err(NameLeaseError::PermissionDenied { name });
        }
        let holder = entry.holder;
        let region = entry.region;
        // br-asupersync-ziwcq4: NameEntry's documented invariant is
        // "Active leases store 0" in identity_nonce (see field doc
        // at line ~498). The pending entry we're about to promote
        // carries the permit_id in that field — reset it so the
        // promoted lease respects the contract and the pending
        // permit_id never leaks into the active map.
        let mut entry = entry;
        entry.identity_nonce = 0;
        self.leases.insert(name, entry);
        self.emit_name_change(permit.name(), holder, region, NameOwnershipKind::Acquired);
        Ok(permit.commit())
    }

    /// Cancel a pending permit, removing it from the pending set.
    ///
    /// If a waiter is queued for the freed name, it is granted a lease
    /// (retrievable via [`take_granted`](Self::take_granted)).
    ///
    /// br-asupersync-smpwix: callers MUST prefer
    /// [`Self::abort_permit`] over the historical
    /// `cancel_permit + NamePermit::abort` two-step. The two-step is
    /// preserved for callers that already hold a borrow on the
    /// registry — but `NamePermit::abort` is no longer public, so the
    /// only way the two-step can be expressed is from inside this
    /// crate.
    ///
    /// # Errors
    ///
    /// Returns [`NameLeaseError::NotFound`] if the name is no longer pending,
    /// or [`NameLeaseError::PermissionDenied`] if the supplied permit no longer
    /// matches the live pending entry.
    pub fn cancel_permit(&mut self, permit: &NamePermit, now: Time) -> Result<(), NameLeaseError> {
        let name = permit.name();
        // SECURITY: Atomic remove-and-validate to fix TOCTOU race between identity
        // check and entry removal. Previously, another thread could modify pending
        // entries between validation and removal, leading to wrong permit cancellation.
        let Some(removed_entry) = self.pending.remove(name) else {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        };

        // Validate the atomically-removed entry's identity
        if permit.holder() != removed_entry.holder
            || permit.region() != removed_entry.region
            || permit.permit_id() != removed_entry.identity_nonce
        // ubs:ignore - not a secret
        {
            // Re-insert the entry on validation failure to maintain consistency
            self.pending.insert(name.to_owned(), removed_entry);
            return Err(NameLeaseError::PermissionDenied {
                name: name.to_string(),
            });
        }

        self.try_grant_to_first_waiter(name, now);
        Ok(())
    }

    /// Abort a pending permit atomically: remove the pending entry from
    /// the registry AND resolve the obligation token in a single call.
    ///
    /// This is the supported public shape for callers that want to give
    /// up a name reservation. It supersedes the
    /// `cancel_permit(&permit) + permit.abort()` two-step, which had
    /// the failure mode (br-asupersync-smpwix) that callers who
    /// dropped the permit after only one of the two operations would
    /// leak a pending entry — blocking all future reservations and
    /// registrations of that name (a DoS surface).
    ///
    /// The `permit` is consumed because the obligation token is
    /// resolved here; returning it to the caller would expose the
    /// already-resolved permit and allow `AlreadyResolved` errors on
    /// every subsequent abort/commit attempt.
    ///
    /// # Errors
    ///
    /// - [`NameLeaseError::NotFound`] if the name is no longer pending.
    /// - [`NameLeaseError::PermissionDenied`] if the supplied permit
    ///   does not match the live pending entry.
    /// - [`NameLeaseError::AlreadyResolved`] if the permit was already
    ///   committed or aborted.
    ///
    /// On an error, a pending entry the permit does not own is left
    /// intact, and the permit's obligation token is still resolved
    /// (aborted): the permit is consumed, and an entry that is gone or
    /// belongs to someone else can never be cancelled by it later, so
    /// returning with the token armed would only panic on drop.
    pub fn abort_permit(
        &mut self,
        mut permit: NamePermit,
        now: Time,
    ) -> Result<AbortedProof<LeaseKind>, NameLeaseError> {
        // Validate ownership and remove the pending entry FIRST so we
        // never resolve the obligation while leaving the registry in
        // a leaked-pending state. cancel_permit returns
        // PermissionDenied / NotFound without mutating the token.
        if let Err(error) = self.cancel_permit(&permit, now) {
            // AlreadyResolved means the token is resolved already.
            let _ = permit.abort();
            return Err(error);
        }
        // Resolve the obligation token. This is the only call site of
        // the now-pub(crate) `NamePermit::abort` outside registry.rs's
        // own internal commit_permit error paths.
        permit.abort()
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
                // No collision — register normally, minting first (see
                // `register`).
                let lease = NameLease::new(&name, holder, region, now);
                self.leases.insert(
                    name.clone(),
                    NameEntry {
                        holder,
                        region,
                        acquired_at: now,
                        identity_nonce: 0,
                    },
                );
                self.emit_name_change(&name, holder, region, NameOwnershipKind::Acquired);
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
                        // Mint before displacing anyone (see `register`).
                        let lease = NameLease::new(&name, holder, region, now);
                        // Remove old entries from both maps; track whether
                        // the displaced holder had an active lease (vs pending).
                        let was_active = self.leases.remove(&name).is_some();
                        self.pending.remove(&name);
                        // Only emit Released if the displaced entry was an
                        // active lease (pending permits never emitted Acquired,
                        // so emitting Released would create an unpaired event).
                        if was_active {
                            self.emit_name_change(
                                &name,
                                current_holder,
                                current_region,
                                NameOwnershipKind::Released,
                            );
                        }
                        // Insert new entry.
                        self.leases.insert(
                            name.clone(),
                            NameEntry {
                                holder,
                                region,
                                acquired_at: now,
                                identity_nonce: 0,
                            },
                        );
                        self.emit_name_change(&name, holder, region, NameOwnershipKind::Acquired);
                        Ok(NameCollisionOutcome::Replaced {
                            lease,
                            displaced_holder: current_holder,
                            displaced_region: current_region,
                        })
                    }
                    NameCollisionPolicy::Wait { deadline } => {
                        if deadline < now {
                            return Err(NameLeaseError::WaitBudgetExceeded { name });
                        }
                        // A granted waiter is minted a lease, which panics
                        // for a root-region holder (ASUP-E103). Fail here, in
                        // the waiter's own call, not later inside whichever
                        // task frees the name.
                        assert!(
                            region.as_u64() != 0,
                            "[ASUP-E103] Cannot wait for name {name:?} from the root region: \
                             a name lease is an obligation and must be scoped to a non-root region"
                        );
                        // Enqueue a budgeted waiter.
                        self.waiters
                            .entry(name)
                            .or_default()
                            .push_back(WaiterEntry {
                                holder,
                                region,
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
    /// br-asupersync-zpanx6: caller MUST supply its own `TaskId` so
    /// the registry can verify it matches the holder of the lease
    /// being dropped. Pre-fix any caller with `&mut NameRegistry`
    /// could drop any other task's lease just by knowing the name —
    /// a registry-handle-wide write authority that contradicted the
    /// "registry as fine-grained capability" design intent
    /// (line 4 of the module).
    ///
    /// The caller is responsible for resolving the corresponding [`NameLease`].
    /// This does NOT check the waiter queue — use
    /// [`unregister_and_grant`](Self::unregister_and_grant) to also grant
    /// waiting tasks.
    ///
    /// For admin-only force-drop paths (supervisor cleanup, region
    /// teardown), use [`force_unregister`](Self::force_unregister)
    /// or [`force_unregister_and_grant`](Self::force_unregister_and_grant)
    /// — those bypass the identity check and are clearly named so
    /// the privileged intent is visible at every call site.
    ///
    /// # Errors
    ///
    /// - `NameLeaseError::NotFound` if the name is not registered.
    /// - `NameLeaseError::PermissionDenied` if the caller's `TaskId`
    ///   does not match the holder of the lease.
    pub fn unregister(&mut self, name: &str, caller: TaskId) -> Result<(), NameLeaseError> {
        let Some(entry) = self.leases.get(name) else {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        };
        if entry.holder != caller {
            return Err(NameLeaseError::PermissionDenied {
                name: name.to_string(),
            });
        }
        let entry = self
            .leases
            .remove(name)
            .expect("entry was just observed under &mut self");
        self.emit_name_change(
            name,
            entry.holder,
            entry.region,
            NameOwnershipKind::Released,
        );
        Ok(())
    }

    /// Unregister a name and grant it to the first eligible waiter.
    ///
    /// br-asupersync-zpanx6: see [`unregister`](Self::unregister) — the
    /// caller's `TaskId` MUST match the lease holder. For admin-only
    /// force paths use
    /// [`force_unregister_and_grant`](Self::force_unregister_and_grant).
    ///
    /// If there are no waiters (or all have expired), the name is simply freed.
    /// If a waiter is eligible, a new lease is created and pushed to the
    /// `granted` queue. Use [`take_granted`](Self::take_granted) to retrieve it.
    ///
    /// # Errors
    ///
    /// - `NameLeaseError::NotFound` if the name is not registered.
    /// - `NameLeaseError::PermissionDenied` if the caller's `TaskId`
    ///   does not match the holder of the lease.
    pub fn unregister_and_grant(
        &mut self,
        name: &str,
        caller: TaskId,
        now: Time,
    ) -> Result<(), NameLeaseError> {
        let Some(entry) = self.leases.get(name) else {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        };
        if entry.holder != caller {
            return Err(NameLeaseError::PermissionDenied {
                name: name.to_string(),
            });
        }
        let entry = self
            .leases
            .remove(name)
            .expect("entry was just observed under &mut self");
        self.emit_name_change(
            name,
            entry.holder,
            entry.region,
            NameOwnershipKind::Released,
        );
        self.try_grant_to_first_waiter(name, now);
        Ok(())
    }

    /// Force-unregister a name without an identity check.
    ///
    /// br-asupersync-zpanx6: privileged admin variant of
    /// [`unregister`](Self::unregister). Bypasses the caller-identity
    /// match. Intended for supervisor / region-teardown / explicit
    /// admin paths where the caller has out-of-band authority over
    /// the lease holder. Most call sites should use
    /// [`unregister`](Self::unregister) (for the lease holder) or
    /// [`cleanup_region`](Self::cleanup_region) /
    /// [`cleanup_task`](Self::cleanup_task) (for bulk teardown).
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NotFound` if the name is not registered.
    pub fn force_unregister(&mut self, name: &str) -> Result<(), NameLeaseError> {
        self.leases.remove(name).map_or_else(
            || {
                Err(NameLeaseError::NotFound {
                    name: name.to_string(),
                })
            },
            |entry| {
                self.emit_name_change(
                    name,
                    entry.holder,
                    entry.region,
                    NameOwnershipKind::Released,
                );
                Ok(())
            },
        )
    }

    /// Force-unregister a name without an identity check, granting
    /// it to the first eligible waiter.
    ///
    /// br-asupersync-zpanx6: privileged admin variant of
    /// [`unregister_and_grant`](Self::unregister_and_grant). See
    /// [`force_unregister`](Self::force_unregister) for the contract.
    ///
    /// # Errors
    ///
    /// Returns `NameLeaseError::NotFound` if the name is not registered.
    pub fn force_unregister_and_grant(
        &mut self,
        name: &str,
        now: Time,
    ) -> Result<(), NameLeaseError> {
        let Some(entry) = self.leases.remove(name) else {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        };
        self.emit_name_change(
            name,
            entry.holder,
            entry.region,
            NameOwnershipKind::Released,
        );
        self.try_grant_to_first_waiter(name, now);
        Ok(())
    }

    /// Unregister a name only if it is still owned by the provided lease.
    ///
    /// This guards manual lease-resolution paths against stale handles: the
    /// active registry entry must still match the lease's full identity
    /// (`name`, `holder`, `region`, and acquisition time).
    ///
    /// # Errors
    ///
    /// Returns [`NameLeaseError::NotFound`] if the name is no longer
    /// registered, or [`NameLeaseError::PermissionDenied`] if the active entry
    /// no longer matches the supplied lease.
    pub fn unregister_owned_and_grant(
        &mut self,
        lease: &NameLease,
        now: Time,
    ) -> Result<(), NameLeaseError> {
        let name = lease.name();
        let Some(entry) = self.leases.get(name) else {
            return Err(NameLeaseError::NotFound {
                name: name.to_string(),
            });
        };
        if entry.holder != lease.holder()
            || entry.region != lease.region()
            || entry.acquired_at != lease.acquired_at()
        {
            return Err(NameLeaseError::PermissionDenied {
                name: name.to_string(),
            });
        }
        // br-asupersync-zpanx6: identity check already performed
        // above against the full lease (holder + region +
        // acquired_at), which is strictly stronger than the
        // caller-TaskId check unregister_and_grant performs. Use the
        // force variant to avoid the redundant check; this also
        // sidesteps name-clone churn (force_unregister_and_grant
        // takes &str directly without re-reading entry).
        self.force_unregister_and_grant(name, now)
    }

    /// Rebinds an active lease to a new holder and region.
    ///
    /// This updates the holder identity in the registry so that subsequent lookups
    /// reflect the new task, and updates the `NameLease` so that subsequent
    /// ownership checks (e.g. on unregistration) succeed for the new holder.
    ///
    /// # Errors
    ///
    /// Returns [`NameLeaseError::NotFound`] if the name is no longer registered,
    /// or [`NameLeaseError::PermissionDenied`] if the active entry no longer
    /// matches the supplied lease.
    pub fn rebind_lease(
        &mut self,
        lease: &mut NameLease,
        new_holder: TaskId,
        new_region: RegionId,
    ) -> Result<(), NameLeaseError> {
        let Some(entry) = self.leases.get_mut(lease.name()) else {
            return Err(NameLeaseError::NotFound {
                name: lease.name().to_string(),
            });
        };
        if entry.holder != lease.holder()
            || entry.region != lease.region()
            || entry.acquired_at != lease.acquired_at()
        {
            return Err(NameLeaseError::PermissionDenied {
                name: lease.name().to_string(),
            });
        }
        entry.holder = new_holder;
        entry.region = new_region;
        lease.rebind(new_holder, new_region);
        self.emit_name_change(lease.name(), new_holder, new_region, NameOwnershipKind::Acquired);
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
        // unwrap is safe because we checked is_empty() above.
        let waiter = queue
            .pop_front()
            .expect("queue was verified to be non-empty");
        if queue.is_empty() {
            self.waiters.remove(name);
        }
        self.leases.insert(
            name.to_string(),
            NameEntry {
                holder: waiter.holder,
                region: waiter.region,
                acquired_at: now,
                identity_nonce: 0,
            },
        );
        self.emit_name_change(
            name,
            waiter.holder,
            waiter.region,
            NameOwnershipKind::Acquired,
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

    /// Take only the grant belonging to one named task generation.
    ///
    /// Unlike [`Self::take_granted`], this leaves other consumers' armed leases
    /// in the registry. The caller must still resolve the returned lease. A
    /// later replacement can invalidate a queued grant; use
    /// [`Self::owns_lease`] before publishing the acquired name.
    pub fn take_granted_for(
        &mut self,
        name: &str,
        holder: TaskId,
        region: RegionId,
    ) -> Option<GrantedLease> {
        let index = self.granted.iter().position(|grant| {
            grant.name == name && grant.lease.holder() == holder && grant.lease.region() == region
        })?;
        Some(self.granted.remove(index))
    }

    /// Whether the active entry still belongs to this exact lease identity.
    #[must_use]
    pub fn owns_lease(&self, lease: &NameLease) -> bool {
        lease.is_active()
            && self.leases.get(lease.name()).is_some_and(|entry| {
                entry.holder == lease.holder()
                    && entry.region == lease.region()
                    && entry.acquired_at == lease.acquired_at()
            })
    }

    /// Cancel one named task generation's waiting registration and any grant
    /// it has not collected. Other tasks, names, and successor generations are
    /// untouched. An uncollected grant is aborted and its slot is passed to
    /// the next eligible waiter.
    pub fn cancel_wait_for(&mut self, name: &str, holder: TaskId, region: RegionId, now: Time) {
        if let Some(queue) = self.waiters.get_mut(name) {
            queue.retain(|waiter| waiter.holder != holder || waiter.region != region);
            if queue.is_empty() {
                self.waiters.remove(name);
            }
        }
        while let Some(mut grant) = self.take_granted_for(name, holder, region) {
            let _ = self.unregister_owned_and_grant(&grant.lease, now);
            let _ = grant.lease.abort();
        }
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
        self.waiters
            .values()
            .map(std::collections::VecDeque::len)
            .sum()
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
        let mut names: Vec<&str> = self.leases.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
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
        self.cleanup_region_at(region, Time::from_nanos(1_000_000_000))
    }

    /// Remove all names held by tasks in the given region, granting freed
    /// names to eligible waiters at the given virtual time.
    ///
    /// Returns the names that were removed (sorted deterministically).
    ///
    /// Note: this removes active leases, pending permits, and waiters held
    /// in the region. The caller is responsible for resolving the corresponding
    /// obligations (leases released/aborted; permits aborted).
    pub fn cleanup_region_at(&mut self, region: RegionId, now: Time) -> Vec<String> {
        // Region close semantics: watchers owned by the region are removed before
        // ownership-change notifications are emitted.
        let _removed_watchers = self.cleanup_name_watchers_region(region);
        let mut active_removed: Vec<(String, TaskId, RegionId)> =
            Vec::with_capacity(self.leases.len());
        let mut to_remove: Vec<String> =
            Vec::with_capacity(self.leases.len().saturating_add(self.pending.len()));
        for (name, entry) in &self.leases {
            if entry.region == region {
                active_removed.push((name.clone(), entry.holder, entry.region));
                to_remove.push(name.clone());
            }
        }
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
        active_removed.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, holder, holder_region) in &active_removed {
            self.emit_name_change(name, *holder, *holder_region, NameOwnershipKind::Released);
        }
        // Abort and remove granted leases belonging to this region to prevent
        // orphaned obligation-token drop-bomb panics.
        self.granted.retain_mut(|g| {
            if g.lease.region() == region {
                let _ = g.lease.abort();
                false
            } else {
                true
            }
        });
        // Also remove waiters belonging to this region.
        for queue in self.waiters.values_mut() {
            queue.retain(|w| w.region != region);
        }
        self.waiters.retain(|_, q| !q.is_empty());
        // Grant freed names to eligible waiters from other regions.
        // Use to_remove (not active_removed) so pending-only names also
        // trigger waiter grants — waiters can be queued against pending
        // permits via register_with_policy(Wait).
        for name in &to_remove {
            self.try_grant_to_first_waiter(name, now);
        }
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
        self.cleanup_task_at(task, Time::from_nanos(1_000_000_000))
    }

    /// Remove all names held by a specific task, granting freed names to
    /// eligible waiters at the given virtual time.
    ///
    /// Returns the names that were removed (sorted deterministically).
    ///
    /// Note: this removes active leases, pending permits, and waiters held
    /// by the task. The caller is responsible for resolving the corresponding
    /// obligations.
    pub fn cleanup_task_at(&mut self, task: TaskId, now: Time) -> Vec<String> {
        let _removed_watchers = self.cleanup_name_watchers_task(task);
        let mut active_removed: Vec<(String, TaskId, RegionId)> =
            Vec::with_capacity(self.leases.len());
        let mut to_remove: Vec<String> =
            Vec::with_capacity(self.leases.len().saturating_add(self.pending.len()));
        for (name, entry) in &self.leases {
            if entry.holder == task {
                active_removed.push((name.clone(), entry.holder, entry.region));
                to_remove.push(name.clone());
            }
        }
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
        active_removed.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, holder, region) in &active_removed {
            self.emit_name_change(name, *holder, *region, NameOwnershipKind::Released);
        }
        // Abort and remove granted leases belonging to this task to prevent
        // orphaned obligation-token drop-bomb panics.
        self.granted.retain_mut(|g| {
            if g.lease.holder() == task {
                let _ = g.lease.abort();
                false
            } else {
                true
            }
        });
        // Also remove waiters belonging to this task.
        for queue in self.waiters.values_mut() {
            queue.retain(|w| w.holder != task);
        }
        self.waiters.retain(|_, q| !q.is_empty());
        // Grant freed names to eligible waiters from other tasks.
        // Use to_remove (not active_removed) so pending-only names also
        // trigger waiter grants — waiters can be queued against pending
        // permits via register_with_policy(Wait).
        for name in &to_remove {
            self.try_grant_to_first_waiter(name, now);
        }
        to_remove
    }
}

impl Default for NameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A lease granted to a waiter that never collected it (its task was
/// cancelled, say) can no longer be collected once the registry is gone. It
/// is aborted, as [`NameRegistry::cancel_wait_for`] aborts one; dropped armed,
/// its obligation token would panic with ASUP-E101 (br-asupersync-in4gh8 L2).
impl Drop for NameRegistry {
    fn drop(&mut self) {
        for mut grant in self.granted.drain(..) {
            let _ = grant.lease.abort();
        }
    }
}

// NameRegistry is a valid registry capability, so it can be stored in a
// RegistryHandle and carried by Cx for capability propagation (bd-2ukjr).
impl RegistryCap for NameRegistry {}

// A Mutex-wrapped registry is also a valid capability, allowing shared mutable
// access from multiple child contexts (e.g., when the app layer distributes
// a single registry to its supervision tree).
impl<T: RegistryCap> RegistryCap for parking_lot::Mutex<T> {}

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
#[path = "registry_inline_tests.rs"]
mod tests;
