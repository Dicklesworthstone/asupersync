//! Runtime lock ordering enforcement for deadlock prevention.
//!
//! Implements the asupersync lock hierarchy: E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations).
//! In debug builds or with `lock-metrics` feature, tracks lock acquisition order per task
//! (falling back to the current thread outside a runtime) and panics on violations.
//! In release builds without `lock-metrics`, all checks are compiled away for zero cost.
//!
//! # Cross-Module Enforcement
//!
//! Beyond basic rank ordering, this module enforces cross-module lock acquisition patterns
//! to prevent deadlocks when operations span multiple asupersync modules. Each lock is
//! tagged with both its rank and module, enabling detection of problematic cross-module patterns.

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::cell::RefCell;
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::hash::{Hash, Hasher};
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::sync::{Arc, LazyLock, Mutex as StdMutex, MutexGuard as StdMutexGuard};

const LOCK_ORDER_VIOLATION_CODE: &str = "ASUP-E205";

/// Stable reason emitted when a lock name maps to the rank hierarchy.
pub const LOCK_ORDER_REASON_RANKED: &str = "ranked-lock";
/// Stable reason emitted for the default intentionally-unranked primitive name.
pub const LOCK_ORDER_REASON_DEFAULT_UNRANKED: &str = "allowed-default-unranked-lock";
/// Stable reason emitted for the legacy unified runtime-state lock.
pub const LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE: &str = "allowed-legacy-runtime-state-lock";
/// Stable reason emitted for the ATP-local transfer registry lock.
pub const LOCK_ORDER_REASON_ATP_REGISTRY: &str = "allowed-atp-transfer-registry-lock";
/// Stable reason emitted for the ATP in-memory object-store lock.
pub const LOCK_ORDER_REASON_ATP_OBJECT_STORE: &str = "allowed-atp-object-store-lock";
/// Stable reason emitted for ATP-local transfer actor locks.
pub const LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR: &str = "allowed-atp-transfer-actor-lock";
/// Stable reason emitted for the epoch-GC rate limiter lock.
pub const LOCK_ORDER_REASON_EPOCH_GC_RATE_LIMITER: &str = "allowed-epoch-gc-rate-limiter-lock";
/// Stable reason emitted for the service-adapter wrapper lock.
pub const LOCK_ORDER_REASON_SERVICE_ADAPTER: &str = "allowed-service-adapter-lock";
/// Stable reason emitted for lock-order test helper locks.
pub const LOCK_ORDER_REASON_TEST_HELPER: &str = "allowed-lock-order-test-helper";
/// Stable reason emitted when a lock name has no rank and no explicit allowance.
pub const LOCK_ORDER_REASON_UNKNOWN_RANK: &str = "denied-unknown-lock-rank";

/// Lock rank categories following the asupersync hierarchy.
/// Lower numeric values must be acquired before higher values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockRank {
    /// E: Configuration locks (lowest rank, acquired first)
    Config = 10,
    /// D: Instrumentation and metrics locks
    Instrumentation = 20,
    /// B: Region management locks
    Regions = 30,
    /// A: Task scheduling and state locks
    Tasks = 40,
    /// C: Obligation tracking locks (highest rank, acquired last)
    Obligations = 50,
}

/// Asupersync module identification for cross-module lock tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockModule {
    /// Core runtime module (scheduler, regions, tasks)
    Runtime,
    /// Synchronization primitives module
    Sync,
    /// Capability context module
    Cx,
    /// Cancellation protocol module
    Cancel,
    /// Obligation tracking module
    Obligation,
    /// Channel and messaging modules
    Channel,
    /// I/O and networking modules
    Io,
    /// Other/unknown modules
    Other,
}

/// Fail-closed lock-name policy used by production `lock-metrics` callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockNamePolicy {
    /// The lock is covered by the rank hierarchy and should be enforced.
    Ranked {
        /// Rank inferred from the lock name.
        rank: LockRank,
        /// Module inferred from the lock name.
        module: LockModule,
    },
    /// The lock is intentionally outside the rank hierarchy.
    AllowedUnranked {
        /// Module inferred from the lock name.
        module: LockModule,
        /// Stable reason string documenting the allowance.
        reason: &'static str,
    },
    /// The lock has no known rank and no documented allowance.
    DeniedUnknown {
        /// Module inferred from the lock name.
        module: LockModule,
        /// Stable reason string suitable for diagnostics.
        reason: &'static str,
    },
}

/// One deterministic lock-order edge observed by the atlas.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockOrderEdge {
    /// Lock already held when the edge was observed.
    pub held_lock_name: String,
    /// Rank of the already-held lock.
    pub held_rank: LockRank,
    /// Module of the already-held lock.
    pub held_module: LockModule,
    /// Lock being acquired.
    pub acquired_lock_name: String,
    /// Rank of the lock being acquired.
    pub acquired_rank: LockRank,
    /// Module of the lock being acquired.
    pub acquired_module: LockModule,
}

/// One deterministic lock-order violation observed before enforcement panics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockOrderViolation {
    /// Lock whose acquisition violated the hierarchy.
    pub lock_name: String,
    /// Rank of the violating lock.
    pub lock_rank: LockRank,
    /// Module of the violating lock.
    pub lock_module: LockModule,
    /// Rank already held when the violation occurred.
    pub held_rank: LockRank,
    /// Stable violation reason for reports and tests.
    pub reason: String,
}

/// Deterministic lock-order atlas snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOrderAtlasSnapshot {
    /// Exercised held-lock to acquired-lock order edges.
    pub order_edges_exercised: Vec<LockOrderEdge>,
    /// Violations recorded before enforcement panicked.
    pub order_violations: Vec<LockOrderViolation>,
    /// Instrumentation mode that produced the snapshot.
    pub instrumentation_mode: &'static str,
}

/// Information about an acquired lock for cross-module tracking.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    /// Lock name recorded for ordering checks.
    pub name: String,
    /// Lock rank recorded for ordering checks.
    pub rank: LockRank,
    /// Lock module recorded for ordering checks.
    pub module: LockModule,
}

/// Stable owner of one lock-order tracking scope.
///
/// Runtime tasks retain the same `Cx` allocation while the scheduler moves
/// their future between workers, so its address is a stable migration-safe
/// identity. Synchronous callers without an installed `Cx` retain the legacy
/// per-thread behavior.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Clone)]
enum LockOrderOwner {
    Task(Arc<parking_lot::RwLock<crate::types::CxInner>>),
    Thread(std::thread::ThreadId),
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl std::fmt::Debug for LockOrderOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Task(inner) => f
                .debug_tuple("Task")
                .field(&(Arc::as_ptr(inner).cast::<()>() as usize))
                .finish(),
            Self::Thread(id) => f.debug_tuple("Thread").field(id).finish(),
        }
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl PartialEq for LockOrderOwner {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Task(left), Self::Task(right)) => Arc::ptr_eq(left, right),
            (Self::Thread(left), Self::Thread(right)) => left == right,
            _ => false,
        }
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl Eq for LockOrderOwner {}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl Hash for LockOrderOwner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Task(inner) => (Arc::as_ptr(inner).cast::<()>() as usize).hash(state),
            Self::Thread(id) => id.hash(state),
        }
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Clone)]
struct TrackedLock {
    acquisition_id: u64,
    info: LockInfo,
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Default)]
struct HeldLockState {
    ranks: BTreeSet<LockRank>,
    locks: BTreeMap<LockRank, Vec<TrackedLock>>,
}

/// Exact ownership token carried by movable lock guards.
///
/// The token intentionally has no `Drop` implementation: leaking a real guard
/// must leave the diagnostic record live, just as the lock remains held.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug)]
pub(crate) struct LockOrderToken {
    owner: LockOrderOwner,
    acquisition_id: u64,
}

/// Per-guard tracking state.
///
/// This is zero-sized when lock-order instrumentation is disabled, preserving
/// the release-build layout and zero-cost contract of the synchronization
/// guards.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
pub(crate) type GuardLockOrder = Option<LockOrderToken>;

#[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
pub(crate) type GuardLockOrder = ();

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
type HeldLocksByOwner = HashMap<LockOrderOwner, HeldLockState>;

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
static HELD_LOCKS_BY_OWNER: LazyLock<StdMutex<HeldLocksByOwner>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
static NEXT_ACQUISITION_ID: AtomicU64 = AtomicU64::new(1);

/// Owned violation details captured while the held-lock tables are borrowed.
///
/// Keeping this descriptor independent of the thread-local `RefCell` guards
/// lets panic hooks safely re-enter lock-order bookkeeping.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingLockOrderViolation {
    RankOrder {
        held_rank: LockRank,
    },
    CancelBeforeObligation {
        held_rank: LockRank,
        held_lock_name: String,
    },
    CxBeforeCancel {
        held_rank: LockRank,
        held_lock_name: String,
    },
    ObligationBeforeRuntimeTask {
        held_rank: LockRank,
        held_lock_name: String,
    },
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
impl PendingLockOrderViolation {
    const fn held_rank(&self) -> LockRank {
        match self {
            Self::RankOrder { held_rank }
            | Self::CancelBeforeObligation { held_rank, .. }
            | Self::CxBeforeCancel { held_rank, .. }
            | Self::ObligationBeforeRuntimeTask { held_rank, .. } => *held_rank,
        }
    }

    const fn reason(&self) -> &'static str {
        match self {
            Self::RankOrder { .. } => "rank-order",
            Self::CancelBeforeObligation { .. } => "cancel-before-obligation",
            Self::CxBeforeCancel { .. } => "cx-before-cancel",
            Self::ObligationBeforeRuntimeTask { .. } => "obligation-before-runtime-task",
        }
    }
}

#[inline]
fn contains_ignore_ascii_case(value: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }

    value
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

#[inline]
fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

impl LockModule {
    /// Parse a lock module from a name or file path.
    ///
    /// Matching is allocation-free and ASCII-case-insensitive so module
    /// enforcement cannot be bypassed by changing the spelling's case.
    pub fn from_name(name: &str) -> Self {
        if contains_ignore_ascii_case(name, "runtime")
            || contains_ignore_ascii_case(name, "scheduler")
        {
            LockModule::Runtime
        } else if contains_ignore_ascii_case(name, "sync")
            || starts_with_ignore_ascii_case(name, "mutex")
            || starts_with_ignore_ascii_case(name, "rwlock")
        {
            LockModule::Sync
        } else if contains_ignore_ascii_case(name, "cx")
            || contains_ignore_ascii_case(name, "scope")
            || contains_ignore_ascii_case(name, "macaroon")
        {
            LockModule::Cx
        } else if contains_ignore_ascii_case(name, "cancel")
            || contains_ignore_ascii_case(name, "progress")
        {
            LockModule::Cancel
        } else if contains_ignore_ascii_case(name, "obligation") {
            LockModule::Obligation
        } else if contains_ignore_ascii_case(name, "channel")
            || contains_ignore_ascii_case(name, "mpsc")
            || contains_ignore_ascii_case(name, "oneshot")
        {
            LockModule::Channel
        } else if contains_ignore_ascii_case(name, "io")
            || contains_ignore_ascii_case(name, "net")
            || contains_ignore_ascii_case(name, "tcp")
        {
            LockModule::Io
        } else {
            LockModule::Other
        }
    }

    /// Get the name of this module for error messages.
    #[allow(dead_code)]
    pub fn name(self) -> &'static str {
        match self {
            LockModule::Runtime => "Runtime",
            LockModule::Sync => "Sync",
            LockModule::Cx => "Cx",
            LockModule::Cancel => "Cancel",
            LockModule::Obligation => "Obligation",
            LockModule::Channel => "Channel",
            LockModule::Io => "Io",
            LockModule::Other => "Other",
        }
    }
}

impl LockRank {
    /// Parse a lock rank from a name prefix.
    ///
    /// Matching is case-insensitive: lock names are advisory diagnostic
    /// labels, so `"tasks_queue"` and `"TASKS_QUEUE"` must map to the same
    /// rank. Returns `None` for names with no recognized prefix (no ordering
    /// is enforced for such locks).
    pub fn from_name(name: &str) -> Option<Self> {
        if starts_with_ignore_ascii_case(name, "config") {
            Some(LockRank::Config)
        } else if starts_with_ignore_ascii_case(name, "metrics")
            || starts_with_ignore_ascii_case(name, "instrumentation")
            || starts_with_ignore_ascii_case(name, "trace")
        {
            Some(LockRank::Instrumentation)
        } else if starts_with_ignore_ascii_case(name, "region") {
            Some(LockRank::Regions)
        } else if starts_with_ignore_ascii_case(name, "task")
            || starts_with_ignore_ascii_case(name, "scheduler")
        {
            Some(LockRank::Tasks)
        } else if starts_with_ignore_ascii_case(name, "obligation") {
            Some(LockRank::Obligations)
        } else {
            None // Unknown rank, no ordering enforced
        }
    }

    /// Get the name of this rank for error messages.
    #[allow(dead_code)]
    pub fn name(self) -> &'static str {
        match self {
            LockRank::Config => "Config",
            LockRank::Instrumentation => "Instrumentation",
            LockRank::Regions => "Regions",
            LockRank::Tasks => "Tasks",
            LockRank::Obligations => "Obligations",
        }
    }
}

impl LockNamePolicy {
    /// Return true when this policy should participate in rank enforcement.
    #[must_use]
    pub const fn is_ranked(self) -> bool {
        matches!(self, LockNamePolicy::Ranked { .. })
    }

    /// Return true when this policy rejects the lock name.
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, LockNamePolicy::DeniedUnknown { .. })
    }

    /// Return the rank when the lock is covered by the hierarchy.
    #[must_use]
    pub const fn rank(self) -> Option<LockRank> {
        match self {
            LockNamePolicy::Ranked { rank, .. } => Some(rank),
            LockNamePolicy::AllowedUnranked { .. } | LockNamePolicy::DeniedUnknown { .. } => None,
        }
    }

    /// Return the inferred module for this lock name.
    #[must_use]
    pub const fn module(self) -> LockModule {
        match self {
            LockNamePolicy::Ranked { module, .. }
            | LockNamePolicy::AllowedUnranked { module, .. }
            | LockNamePolicy::DeniedUnknown { module, .. } => module,
        }
    }

    /// Return the stable machine-readable reason for this policy.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            LockNamePolicy::Ranked { .. } => LOCK_ORDER_REASON_RANKED,
            LockNamePolicy::AllowedUnranked { reason, .. }
            | LockNamePolicy::DeniedUnknown { reason, .. } => reason,
        }
    }
}

/// Classify a lock name using the production lock-order policy.
///
/// This is stricter than [`LockRank::from_name`]. `from_name` remains the
/// low-level prefix classifier used by existing lock wrappers; this policy adds
/// the L2 explicit allow/deny decision so callers that need fail-closed
/// behavior can reject undocumented unknown names with a stable reason.
#[must_use]
pub fn classify_lock_name(name: &str) -> LockNamePolicy {
    let module = LockModule::from_name(name);
    if let Some(rank) = LockRank::from_name(name) {
        return LockNamePolicy::Ranked { rank, module };
    }

    if let Some(reason) = allowed_unranked_reason(name) {
        LockNamePolicy::AllowedUnranked { module, reason }
    } else {
        LockNamePolicy::DeniedUnknown {
            module,
            reason: LOCK_ORDER_REASON_UNKNOWN_RANK,
        }
    }
}

/// Enforce the documented lock-name policy.
///
/// Ranked locks and explicitly allowed unranked locks are returned to the
/// caller. Undocumented unknown names fail closed with a stable reason string.
#[inline]
#[track_caller]
pub fn enforce_lock_name_policy(lock_name: &str) -> LockNamePolicy {
    let policy = classify_lock_name(lock_name);
    assert!(
        !policy.is_denied(),
        "[{}] LOCK ORDER POLICY: lock '{}' is not covered by automatic rank enforcement; reason={}",
        LOCK_ORDER_VIOLATION_CODE,
        lock_name,
        policy.reason()
    );
    policy
}

/// Return the rank used by lock wrappers for a lock name.
///
/// Default builds preserve the historical low-level classifier. When
/// `lock-metrics` is enabled, the same constructor path applies the documented
/// allow/deny policy and fails closed on undocumented unknown names.
#[must_use]
#[inline]
pub fn rank_for_lock_name(lock_name: &str) -> Option<LockRank> {
    #[cfg(feature = "lock-metrics")]
    {
        enforce_lock_name_policy(lock_name).rank()
    }

    #[cfg(not(feature = "lock-metrics"))]
    {
        LockRank::from_name(lock_name)
    }
}

/// Require a lock name to be covered by the rank hierarchy.
///
/// This helper is intentionally separate from current lock constructors. It
/// gives production `lock-metrics` paths a fail-closed API while preserving the
/// legacy unranked constructors until each call site has an explicit policy
/// migration.
#[inline]
#[track_caller]
pub fn require_ranked_lock_name(lock_name: &str) -> (LockRank, LockModule) {
    match enforce_lock_name_policy(lock_name) {
        LockNamePolicy::Ranked { rank, module } => (rank, module),
        policy => panic!(
            "[{}] LOCK ORDER POLICY: lock '{}' is not covered by automatic rank enforcement; reason={}",
            LOCK_ORDER_VIOLATION_CODE,
            lock_name,
            policy.reason()
        ),
    }
}

fn allowed_unranked_reason(name: &str) -> Option<&'static str> {
    match name {
        "unknown" => Some(LOCK_ORDER_REASON_DEFAULT_UNRANKED),
        "runtime_state"
        | "metamorphic.runtime_state"
        | "ws_fairness.runtime_state"
        | "test_runtime_state"
        | "test_state" => Some(LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE),
        "atp_transfer_registry" => Some(LOCK_ORDER_REASON_ATP_REGISTRY),
        "atp_memory_object_store" => Some(LOCK_ORDER_REASON_ATP_OBJECT_STORE),
        "transfer_actor" | "atp_transfer_actor" => Some(LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR),
        "epoch_gc.last_advance" => Some(LOCK_ORDER_REASON_EPOCH_GC_RATE_LIMITER),
        "service_adapter" => Some(LOCK_ORDER_REASON_SERVICE_ADAPTER),
        "test_abandon_read" | "test_abandon_write" => Some(LOCK_ORDER_REASON_TEST_HELPER),
        _ => None,
    }
}

// The atlas remains thread-local because it is a diagnostic observation log.
// Held-lock state is task-owned (or thread-owned outside a runtime) below so a
// Send future can migrate without corrupting the deadlock detector.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
thread_local! {
    static ORDER_EDGES: RefCell<BTreeSet<LockOrderEdge>> = const { RefCell::new(BTreeSet::new()) };
    static ORDER_VIOLATIONS: RefCell<Vec<LockOrderViolation>> = const { RefCell::new(Vec::new()) };
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn current_owner() -> LockOrderOwner {
    if let Some(inner) = crate::cx::Cx::with_current(|cx| Arc::clone(&cx.inner)) {
        LockOrderOwner::Task(inner)
    } else {
        LockOrderOwner::Thread(std::thread::current().id())
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn held_locks_by_owner() -> StdMutexGuard<'static, HeldLocksByOwner> {
    HELD_LOCKS_BY_OWNER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn current_held_snapshot() -> (BTreeSet<LockRank>, BTreeMap<LockRank, Vec<LockInfo>>) {
    let owner = current_owner();
    let tracker = held_locks_by_owner();
    let Some(state) = tracker.get(&owner) else {
        return (BTreeSet::new(), BTreeMap::new());
    };
    let locks = state
        .locks
        .iter()
        .map(|(rank, entries)| {
            (
                *rank,
                entries.iter().map(|entry| entry.info.clone()).collect(),
            )
        })
        .collect();
    (state.ranks.clone(), locks)
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn next_acquisition_id() -> u64 {
    let id = NEXT_ACQUISITION_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(id, 0, "lock-order acquisition id space exhausted");
    id
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn insert_tracked_lock(lock_name: &str, rank: LockRank, module: LockModule) -> LockOrderToken {
    let owner = current_owner();
    let acquisition_id = next_acquisition_id();
    let mut tracker = held_locks_by_owner();
    let state = tracker.entry(owner.clone()).or_default();
    state.ranks.insert(rank);
    state.locks.entry(rank).or_default().push(TrackedLock {
        acquisition_id,
        info: LockInfo {
            name: lock_name.to_string(),
            rank,
            module,
        },
    });
    LockOrderToken {
        owner,
        acquisition_id,
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn remove_tracked_lock(token: LockOrderToken) {
    let mut tracker = held_locks_by_owner();
    let remove_owner = if let Some(state) = tracker.get_mut(&token.owner) {
        let mut removed_rank = None;
        for (rank, entries) in &mut state.locks {
            if let Some(index) = entries
                .iter()
                .position(|entry| entry.acquisition_id == token.acquisition_id)
            {
                entries.remove(index);
                if entries.is_empty() {
                    removed_rank = Some(*rank);
                }
                break;
            }
        }
        if let Some(rank) = removed_rank {
            state.locks.remove(&rank);
            state.ranks.remove(&rank);
        }
        state.locks.is_empty()
    } else {
        false
    };
    if remove_owner {
        tracker.remove(&token.owner);
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn remove_current_matching_lock(lock_name: &str, rank: LockRank, module: LockModule) {
    let owner = current_owner();
    let mut tracker = held_locks_by_owner();
    let remove_owner = if let Some(state) = tracker.get_mut(&owner) {
        if let Some(entries) = state.locks.get_mut(&rank) {
            if let Some(index) = entries
                .iter()
                .rposition(|entry| entry.info.name == lock_name && entry.info.module == module)
            {
                entries.remove(index);
            }
            if entries.is_empty() {
                state.locks.remove(&rank);
                state.ranks.remove(&rank);
            }
        }
        state.locks.is_empty()
    } else {
        false
    };
    if remove_owner {
        tracker.remove(&owner);
    }
}

/// Check if acquiring a lock of the given rank would violate ordering.
/// In debug builds, panics on violations. In release builds, does nothing.
#[inline]
pub fn check_acquire(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        check_acquire_with_module(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warnings
    }
}

/// Check if acquiring a lock would violate ordering, with explicit module specification.
/// This is the enhanced version that performs cross-module validation.
#[inline]
pub fn check_acquire_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        let (held_ranks, held_locks) = current_held_snapshot();
        record_order_edges(lock_name, rank, module, &held_locks);

        let violation = held_ranks
            .iter()
            .next_back()
            .copied()
            .filter(|highest_held| rank < *highest_held)
            .map(|held_rank| PendingLockOrderViolation::RankOrder { held_rank })
            .or_else(|| detect_cross_module_violation(rank, module, &held_locks));

        if let Some(violation) = violation {
            record_order_violation(
                lock_name,
                rank,
                module,
                violation.held_rank(),
                violation.reason(),
            );
            emit_lock_order_violation(lock_name, rank, module, violation);
        }
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn record_order_edges(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    held_locks: &BTreeMap<LockRank, Vec<LockInfo>>,
) {
    ORDER_EDGES.with(|edges| {
        let mut edges = edges.borrow_mut();
        for locks_at_rank in held_locks.values() {
            for held in locks_at_rank {
                edges.insert(LockOrderEdge {
                    held_lock_name: held.name.clone(), // ubs:ignore - debug diagnostic allocation
                    held_rank: held.rank,
                    held_module: held.module,
                    acquired_lock_name: lock_name.to_string(),
                    acquired_rank: rank,
                    acquired_module: module,
                });
            }
        }
    });
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn record_order_violation(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    held_rank: LockRank,
    reason: &'static str,
) {
    ORDER_VIOLATIONS.with(|violations| {
        violations.borrow_mut().push(LockOrderViolation {
            lock_name: lock_name.to_string(),
            lock_rank: rank,
            lock_module: module,
            held_rank,
            reason: reason.to_string(),
        });
    });
}

/// Detect cross-module lock acquisition patterns that can cause complex deadlocks.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn detect_cross_module_violation(
    rank: LockRank,
    module: LockModule,
    held_locks: &BTreeMap<LockRank, Vec<LockInfo>>,
) -> Option<PendingLockOrderViolation> {
    // Rule 1: Obligations module locks should not be acquired while holding Cancel module locks
    // (prevents obligation tracking from deadlocking with cancellation)
    if module == LockModule::Obligation && rank == LockRank::Obligations {
        for locks_at_rank in held_locks.values() {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Cancel {
                    return Some(PendingLockOrderViolation::CancelBeforeObligation {
                        held_rank: lock_info.rank,
                        held_lock_name: lock_info.name.clone(),
                    });
                }
            }
        }
    }

    // Rule 2: Cx module locks should be acquired before Cancel module locks
    // (capability contexts must be established before cancellation operations)
    if module == LockModule::Cancel {
        for (held_rank, locks_at_rank) in held_locks {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Cx && *held_rank > rank {
                    return Some(PendingLockOrderViolation::CxBeforeCancel {
                        held_rank: *held_rank,
                        held_lock_name: lock_info.name.clone(),
                    });
                }
            }
        }
    }

    // Rule 3: Runtime module locks should be acquired in a specific order relative to other modules
    // (scheduler state must be consistent with obligation state)
    if module == LockModule::Runtime && rank == LockRank::Tasks {
        for locks_at_rank in held_locks.values() {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Obligation
                    && lock_info.rank == LockRank::Obligations
                {
                    return Some(PendingLockOrderViolation::ObligationBeforeRuntimeTask {
                        held_rank: lock_info.rank,
                        held_lock_name: lock_info.name.clone(),
                    });
                }
            }
        }
    }

    None
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[cold]
#[inline(never)]
fn emit_lock_order_violation(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    violation: PendingLockOrderViolation,
) -> ! {
    match violation {
        PendingLockOrderViolation::RankOrder { held_rank } => {
            panic!(
                "[{}] DEADLOCK PREVENTION: Lock ordering violation!\n\
                Attempted to acquire '{}' (rank {:?}, module {:?}) while holding locks of rank {:?}.\n\
                Correct order: Config -> Instrumentation -> Regions -> Tasks -> Obligations\n\
                This violates the asupersync lock hierarchy and could cause deadlocks.",
                LOCK_ORDER_VIOLATION_CODE, lock_name, rank, module, held_rank
            );
        }
        PendingLockOrderViolation::CancelBeforeObligation { held_lock_name, .. } => {
            panic!(
                "[{}] CROSS-MODULE DEADLOCK PREVENTION: Lock ordering violation. \
                Attempted to acquire obligation lock '{}' \
                while holding cancel module lock '{}'. This pattern can cause deadlocks \
                between cancellation and obligation tracking.",
                LOCK_ORDER_VIOLATION_CODE, lock_name, held_lock_name
            );
        }
        PendingLockOrderViolation::CxBeforeCancel {
            held_rank,
            held_lock_name,
        } => {
            panic!(
                "[{}] CROSS-MODULE DEADLOCK PREVENTION: Lock ordering violation. \
                Attempted to acquire cancel lock '{}' (rank {:?}) \
                while holding higher-ranked Cx lock '{}' (rank {:?}). \
                Capability context operations must complete before cancellation.",
                LOCK_ORDER_VIOLATION_CODE, lock_name, rank, held_lock_name, held_rank
            );
        }
        PendingLockOrderViolation::ObligationBeforeRuntimeTask { held_lock_name, .. } => {
            panic!(
                "[{}] CROSS-MODULE DEADLOCK PREVENTION: Lock ordering violation. \
                Attempted to acquire task lock '{}' \
                while holding obligation lock '{}'. Task scheduling must be coordinated \
                with obligation tracking to prevent state inconsistencies.",
                LOCK_ORDER_VIOLATION_CODE, lock_name, held_lock_name
            );
        }
    }
}

/// Record that a lock of the given rank has been acquired.
/// Only active in debug builds.
#[inline]
pub fn record_acquire(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        let _ = insert_tracked_lock(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warning
    }
}

/// Record that a lock has been acquired with full module information.
/// This is the enhanced version that tracks cross-module relationships.
#[inline]
pub fn record_acquire_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        let _ = insert_tracked_lock(lock_name, rank, module);
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

/// Record that a lock of the given rank has been released.
/// Only active in debug builds.
#[inline]
pub fn record_release(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        record_release_with_module(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warning
    }
}

/// Record that a specific lock has been released with full module information.
/// This is the enhanced version that maintains cross-module tracking accuracy.
#[inline]
pub fn record_release_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        remove_current_matching_lock(lock_name, rank, module);
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

/// Record one movable guard acquisition and return its exact tracking state.
#[inline]
pub(crate) fn record_guard_acquire(lock_name: &str, rank: Option<LockRank>) -> GuardLockOrder {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        rank.map(|rank| insert_tracked_lock(lock_name, rank, LockModule::from_name(lock_name)))
    }

    #[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
    {
        let _ = (lock_name, rank);
    }
}

/// Release the exact acquisition represented by movable guard tracking state.
#[inline]
pub(crate) fn record_guard_release(lock_order: &mut GuardLockOrder) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        if let Some(token) = lock_order.take() {
            remove_tracked_lock(token);
        }
    }

    #[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
    {
        let _ = lock_order;
    }
}

/// Transfer movable guard tracking state without releasing it.
#[inline]
pub(crate) fn take_guard_lock_order(lock_order: &mut GuardLockOrder) -> GuardLockOrder {
    std::mem::take(lock_order)
}

/// Get the currently held lock ranks for debugging.
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn current_held_ranks() -> Vec<LockRank> {
    current_held_snapshot().0.into_iter().collect()
}

/// Get detailed information about all currently held locks for debugging.
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn current_held_locks() -> BTreeMap<LockRank, Vec<LockInfo>> {
    current_held_snapshot().1
}

/// Clear all held lock tracking (for testing purposes only).
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn clear_held_locks() {
    held_locks_by_owner().remove(&current_owner());
    clear_lock_order_atlas();
}

/// Return the current deterministic lock-order atlas snapshot.
#[must_use]
pub fn lock_order_atlas_snapshot() -> LockOrderAtlasSnapshot {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        let order_edges_exercised =
            ORDER_EDGES.with(|edges| edges.borrow().iter().cloned().collect());
        let order_violations = ORDER_VIOLATIONS.with(|violations| violations.borrow().clone());

        LockOrderAtlasSnapshot {
            order_edges_exercised,
            order_violations,
            instrumentation_mode: "debug_lock_ordering",
        }
    }

    #[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
    {
        LockOrderAtlasSnapshot {
            order_edges_exercised: Vec::new(),
            order_violations: Vec::new(),
            instrumentation_mode: "disabled",
        }
    }
}

/// Clear deterministic lock-order atlas state for the current thread.
pub fn clear_lock_order_atlas() {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        ORDER_EDGES.with(|edges| edges.borrow_mut().clear());
        ORDER_VIOLATIONS.with(|violations| violations.borrow_mut().clear());
    }
}

/// Enhanced API for Mutex to use cross-module lock ordering enforcement.
/// This replaces the basic check_acquire/record_acquire pattern with module-aware tracking.
#[allow(dead_code)]
pub struct LockOrderEnforcer {
    lock_name: String,
    rank: LockRank,
    module: LockModule,
}

impl LockOrderEnforcer {
    /// Create a new lock order enforcer for the given lock.
    #[allow(dead_code)]
    pub fn new(lock_name: &str, rank: LockRank) -> Self {
        let module = LockModule::from_name(lock_name);
        Self {
            lock_name: lock_name.to_string(),
            rank,
            module,
        }
    }

    /// Create a lock order enforcer with explicit module specification.
    #[allow(dead_code)]
    pub fn with_module(lock_name: &str, rank: LockRank, module: LockModule) -> Self {
        Self {
            lock_name: lock_name.to_string(),
            rank,
            module,
        }
    }

    /// Check if acquiring this lock would violate ordering and record the acquisition.
    #[allow(dead_code)]
    #[inline]
    pub fn acquire(&self) {
        check_acquire_with_module(&self.lock_name, self.rank, self.module);
        record_acquire_with_module(&self.lock_name, self.rank, self.module);
    }

    /// Record the release of this lock.
    #[allow(dead_code)]
    #[inline]
    pub fn release(&self) {
        record_release_with_module(&self.lock_name, self.rank, self.module);
    }

    /// Check if acquiring this lock would violate ordering (without recording).
    #[allow(dead_code)]
    #[inline]
    pub fn check_only(&self) {
        check_acquire_with_module(&self.lock_name, self.rank, self.module);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => match payload.downcast::<&'static str>() {
                Ok(message) => (*message).to_string(),
                Err(_) => "<non-string panic payload>".to_string(),
            },
        }
    }

    #[test]
    fn test_lock_rank_from_name() {
        assert_eq!(LockRank::from_name("config_cache"), Some(LockRank::Config));
        assert_eq!(LockRank::from_name("CONFIG_CACHE"), Some(LockRank::Config));
        assert_eq!(
            LockRank::from_name("metrics_collector"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("InStRuMeNtAtIoN_State"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("regions_table"),
            Some(LockRank::Regions)
        );
        assert_eq!(LockRank::from_name("TASKS_QUEUE"), Some(LockRank::Tasks));
        assert_eq!(
            LockRank::from_name("ObLiGaTiOnS_Ledger"),
            Some(LockRank::Obligations)
        );
        assert_eq!(LockRank::from_name("unknown_lock"), None);
    }

    #[test]
    fn lock_name_policy_marks_ranked_locks_as_enforced() {
        let policy = classify_lock_name("tasks_queue");

        assert_eq!(
            policy,
            LockNamePolicy::Ranked {
                rank: LockRank::Tasks,
                module: LockModule::Other,
            }
        );
        assert!(policy.is_ranked());
        assert!(!policy.is_denied());
        assert_eq!(policy.rank(), Some(LockRank::Tasks));
        assert_eq!(policy.module(), LockModule::Other);
        assert_eq!(policy.reason(), LOCK_ORDER_REASON_RANKED);
    }

    #[test]
    fn lock_name_policy_documents_allowed_unranked_locks() {
        for (name, reason) in [
            ("unknown", LOCK_ORDER_REASON_DEFAULT_UNRANKED),
            ("runtime_state", LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE),
            (
                "metamorphic.runtime_state",
                LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE,
            ),
            ("test_state", LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE),
            ("atp_transfer_registry", LOCK_ORDER_REASON_ATP_REGISTRY),
            (
                "epoch_gc.last_advance",
                LOCK_ORDER_REASON_EPOCH_GC_RATE_LIMITER,
            ),
            ("service_adapter", LOCK_ORDER_REASON_SERVICE_ADAPTER),
            (
                "atp_memory_object_store",
                LOCK_ORDER_REASON_ATP_OBJECT_STORE,
            ),
            ("transfer_actor", LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR),
            ("atp_transfer_actor", LOCK_ORDER_REASON_ATP_TRANSFER_ACTOR),
            ("test_abandon_read", LOCK_ORDER_REASON_TEST_HELPER),
        ] {
            let policy = classify_lock_name(name);
            assert!(
                matches!(policy, LockNamePolicy::AllowedUnranked { .. }),
                "{name} should be an explicitly allowed unranked lock"
            );
            assert!(!policy.is_ranked());
            assert!(!policy.is_denied());
            assert_eq!(policy.rank(), None);
            assert_eq!(policy.reason(), reason);
        }
    }

    #[test]
    fn lock_name_policy_denies_undocumented_unknown_locks() {
        let policy = classify_lock_name("side_table_without_rank");

        assert_eq!(
            policy,
            LockNamePolicy::DeniedUnknown {
                module: LockModule::Other,
                reason: LOCK_ORDER_REASON_UNKNOWN_RANK,
            }
        );
        assert!(!policy.is_ranked());
        assert!(policy.is_denied());
        assert_eq!(policy.rank(), None);
        assert_eq!(policy.reason(), LOCK_ORDER_REASON_UNKNOWN_RANK);
    }

    #[test]
    fn require_ranked_lock_name_returns_rank_and_module_for_known_locks() {
        assert_eq!(
            require_ranked_lock_name("obligation_tracker"),
            (LockRank::Obligations, LockModule::Obligation)
        );
    }

    #[test]
    fn enforce_lock_name_policy_allows_documented_unranked_locks() {
        let policy = enforce_lock_name_policy("runtime_state");

        assert_eq!(
            policy,
            LockNamePolicy::AllowedUnranked {
                module: LockModule::Runtime,
                reason: LOCK_ORDER_REASON_LEGACY_RUNTIME_STATE,
            }
        );
    }

    #[test]
    fn rank_for_lock_name_preserves_ranked_results() {
        assert_eq!(rank_for_lock_name("regions_table"), Some(LockRank::Regions));
    }

    #[test]
    fn enforce_lock_name_policy_panics_with_stable_reason_for_unknown_lock() {
        let panic = std::panic::catch_unwind(|| {
            let _ = enforce_lock_name_policy("side_table_without_rank");
        })
        .expect_err("undocumented unknown lock should fail closed");
        let message = panic_payload_to_string(panic);

        assert!(
            message.starts_with("[ASUP-E205]"),
            "policy panic should start with ASUP-E205 token: {message}"
        );
        assert!(
            message.contains(LOCK_ORDER_REASON_UNKNOWN_RANK),
            "policy panic should include stable reason: {message}"
        );
    }

    #[test]
    fn require_ranked_lock_name_panics_with_stable_reason_for_unknown_lock() {
        let panic = std::panic::catch_unwind(|| {
            let _ = require_ranked_lock_name("side_table_without_rank");
        })
        .expect_err("undocumented unknown lock should fail closed");
        let message = panic_payload_to_string(panic);

        assert!(
            message.starts_with("[ASUP-E205]"),
            "policy panic should start with ASUP-E205 token: {message}"
        );
        assert!(
            message.contains(LOCK_ORDER_REASON_UNKNOWN_RANK),
            "policy panic should include stable reason: {message}"
        );
    }

    #[test]
    fn test_lock_rank_ordering() {
        assert!(LockRank::Config < LockRank::Instrumentation);
        assert!(LockRank::Instrumentation < LockRank::Regions);
        assert!(LockRank::Regions < LockRank::Tasks);
        assert!(LockRank::Tasks < LockRank::Obligations);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_correct_lock_ordering() {
        // This should not panic - correct ordering
        check_acquire("config_test", LockRank::Config);
        record_acquire("config_test", LockRank::Config);

        check_acquire("regions_test", LockRank::Regions);
        record_acquire("regions_test", LockRank::Regions);

        check_acquire("tasks_test", LockRank::Tasks);
        record_acquire("tasks_test", LockRank::Tasks);

        record_release("tasks_test", LockRank::Tasks);
        record_release("regions_test", LockRank::Regions);
        record_release("config_test", LockRank::Config);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_incorrect_lock_ordering() {
        clear_held_locks(); // Start with clean state
        let panic = std::panic::catch_unwind(|| {
            // This should panic - trying to acquire Config after Tasks
            record_acquire("tasks_test", LockRank::Tasks);
            check_acquire("config_test", LockRank::Config);
        })
        .expect_err("rank-order inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("Lock ordering violation"),
            "rank-order panic should mention ordering violation: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn rank_order_violation_panic_starts_with_asup_e205() {
        clear_held_locks();

        let panic = std::panic::catch_unwind(|| {
            record_acquire("tasks_test", LockRank::Tasks);
            check_acquire("config_test", LockRank::Config);
        })
        .expect_err("rank-order violation should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.starts_with("[ASUP-E205]"),
            "rank-order panic should start with ASUP-E205 token: {message}"
        );
    }

    #[test]
    fn test_module_from_name() {
        for (expected, variants) in [
            (LockModule::Runtime, ["runtime", "RuNtImE", "RUNTIME"]),
            (LockModule::Runtime, ["scheduler", "ScHeDuLeR", "SCHEDULER"]),
            (LockModule::Sync, ["sync", "SyNc", "SYNC"]),
            (LockModule::Sync, ["mutex", "MuTeX", "MUTEX"]),
            (LockModule::Sync, ["rwlock", "RwLoCk", "RWLOCK"]),
            (LockModule::Cx, ["cx", "cX", "CX"]),
            (LockModule::Cx, ["scope", "ScOpE", "SCOPE"]),
            (LockModule::Cx, ["macaroon", "MaCaRoOn", "MACAROON"]),
            (LockModule::Cancel, ["cancel", "CaNcEl", "CANCEL"]),
            (LockModule::Cancel, ["progress", "PrOgReSs", "PROGRESS"]),
            (
                LockModule::Obligation,
                ["obligation", "ObLiGaTiOn", "OBLIGATION"],
            ),
            (LockModule::Channel, ["channel", "ChAnNeL", "CHANNEL"]),
            (LockModule::Channel, ["mpsc", "MpSc", "MPSC"]),
            (LockModule::Channel, ["oneshot", "OnEsHoT", "ONESHOT"]),
            (LockModule::Io, ["io", "Io", "IO"]),
            (LockModule::Io, ["net", "NeT", "NET"]),
            (LockModule::Io, ["tcp", "TcP", "TCP"]),
            (
                LockModule::Other,
                ["widget_state", "WiDgEt_sTaTe", "WIDGET_STATE"],
            ),
        ] {
            for name in variants {
                assert_eq!(
                    LockModule::from_name(name),
                    expected,
                    "module classification must ignore ASCII case for {name}"
                );
            }
        }
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_module_correct_patterns() {
        clear_held_locks(); // Start with clean state

        // This should work - Cx before Cancel
        check_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
        record_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);

        check_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);

        // Clean up
        record_release_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_release_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_module_obligation_cancel_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold a Cancel module lock
            record_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);

            // This should panic - acquiring Obligation lock while holding Cancel lock
            check_acquire_with_module(
                "obligation_tracker",
                LockRank::Obligations,
                LockModule::Obligation,
            );
        })
        .expect_err("cancel-before-obligation pattern should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("CROSS-MODULE DEADLOCK PREVENTION"),
            "cross-module panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn cross_module_violation_panic_starts_with_asup_e205() {
        clear_held_locks();

        let panic = std::panic::catch_unwind(|| {
            record_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);
            check_acquire_with_module(
                "obligation_tracker",
                LockRank::Obligations,
                LockModule::Obligation,
            );
        })
        .expect_err("cross-module violation should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.starts_with("[ASUP-E205]"),
            "cross-module panic should start with ASUP-E205 token: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    // The basic rank-order guard fires first here (acquiring a lower-ranked
    // Cancel lock while holding a higher-ranked Cx lock), emitting the
    // "DEADLOCK PREVENTION" message. Matching the shared prefix keeps this
    // robust whether the rank-order or the cross-module rule trips first.
    fn test_cross_module_cx_cancel_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold a higher-ranked Cx lock
            record_acquire_with_module("cx_macaroon", LockRank::Obligations, LockModule::Cx);

            // This should panic - acquiring lower-ranked Cancel lock while holding higher-ranked Cx lock
            check_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);
        })
        .expect_err("cx-before-cancel rank inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("DEADLOCK PREVENTION"),
            "cx/cancel panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    // Acquiring a Tasks-rank lock while holding an Obligations-rank lock is
    // a plain rank-order inversion, so the basic guard fires first with the
    // "DEADLOCK PREVENTION" message before the Runtime/Obligation cross-module
    // rule is reached. Match the shared prefix.
    fn test_cross_module_runtime_obligation_violation() {
        clear_held_locks(); // Start with clean state

        let panic = std::panic::catch_unwind(|| {
            // Hold an Obligation lock
            record_acquire_with_module(
                "obligation_ledger",
                LockRank::Obligations,
                LockModule::Obligation,
            );

            // This should panic - acquiring Task lock while holding Obligation lock
            check_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
        })
        .expect_err("runtime/obligation rank inversion should panic");
        let message = panic_payload_to_string(panic);

        clear_held_locks();

        assert!(
            message.contains("DEADLOCK PREVENTION"),
            "runtime/obligation panic should mention deadlock prevention: {message}"
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_detailed_lock_tracking() {
        clear_held_locks(); // Start with clean state

        // Acquire multiple locks
        record_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        record_acquire_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);

        let held_locks = current_held_locks();
        assert_eq!(held_locks.len(), 2);

        assert!(held_locks.contains_key(&LockRank::Config));
        assert!(held_locks.contains_key(&LockRank::Tasks));

        let config_locks = &held_locks[&LockRank::Config];
        assert_eq!(config_locks.len(), 1);
        assert_eq!(config_locks[0].name, "config_cache");
        assert_eq!(config_locks[0].module, LockModule::Runtime);

        // Clean up
        record_release_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);
        record_release_with_module("config_cache", LockRank::Config, LockModule::Runtime);

        let held_locks_after = current_held_locks();
        assert_eq!(held_locks_after.len(), 0);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn lock_order_atlas_records_instrumentation_edges_and_violations() {
        clear_held_locks();

        check_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        record_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        check_acquire_with_module(
            "trace_buffer",
            LockRank::Instrumentation,
            LockModule::Runtime,
        );
        record_acquire_with_module(
            "trace_buffer",
            LockRank::Instrumentation,
            LockModule::Runtime,
        );

        let snapshot = lock_order_atlas_snapshot();
        assert_eq!(snapshot.instrumentation_mode, "debug_lock_ordering");
        assert!(snapshot.order_violations.is_empty());
        assert!(snapshot.order_edges_exercised.iter().any(|edge| {
            edge.held_lock_name == "config_cache"
                && edge.held_rank == LockRank::Config
                && edge.held_module == LockModule::Runtime
                && edge.acquired_lock_name == "trace_buffer"
                && edge.acquired_rank == LockRank::Instrumentation
                && edge.acquired_module == LockModule::Runtime
        }));

        clear_held_locks();
        record_acquire_with_module("tasks_queue", LockRank::Tasks, LockModule::Runtime);

        let inversion = std::panic::catch_unwind(|| {
            check_acquire_with_module(
                "trace_buffer",
                LockRank::Instrumentation,
                LockModule::Runtime,
            );
        });
        assert!(inversion.is_err());

        let snapshot = lock_order_atlas_snapshot();
        assert!(snapshot.order_violations.iter().any(|violation| {
            violation.lock_name == "trace_buffer"
                && violation.lock_rank == LockRank::Instrumentation
                && violation.lock_module == LockModule::Runtime
                && violation.held_rank == LockRank::Tasks
                && violation.reason == "rank-order"
        }));

        clear_held_locks();
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn duplicate_lock_name_release_preserves_remaining_acquisition() {
        clear_held_locks();

        record_acquire_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);
        record_acquire_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);

        let held_locks = current_held_locks();
        assert_eq!(held_locks[&LockRank::Tasks].len(), 2);

        record_release_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);

        let held_locks = current_held_locks();
        assert_eq!(held_locks[&LockRank::Tasks].len(), 1);
        assert!(current_held_ranks().contains(&LockRank::Tasks));

        let lower_rank_result =
            std::panic::catch_unwind(|| check_acquire("config_cache", LockRank::Config));
        assert!(
            lower_rank_result.is_err(),
            "remaining same-name task lock must keep its rank active"
        );

        record_release_with_module("tasks_duplicate", LockRank::Tasks, LockModule::Runtime);
        assert!(current_held_locks().is_empty());
        assert!(current_held_ranks().is_empty());
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn guard_token_follows_task_context_across_worker_migration() {
        let cx = crate::Cx::for_testing();
        let token = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            clear_held_locks();
            let token = record_guard_acquire("tasks_migrating_guard", Some(LockRank::Tasks));
            assert_eq!(current_held_ranks(), vec![LockRank::Tasks]);
            token
        };

        let worker = std::thread::spawn(move || {
            let _current = crate::Cx::set_current(Some(cx));
            assert_eq!(
                current_held_ranks(),
                vec![LockRank::Tasks],
                "the migrated task must retain its held-rank view"
            );

            let inversion = std::panic::catch_unwind(|| {
                check_acquire("config_after_migration", LockRank::Config);
            });
            assert!(
                inversion.is_err(),
                "migration must not hide a real rank inversion"
            );

            let mut token = token;
            record_guard_release(&mut token);
            assert!(current_held_locks().is_empty());
            assert!(current_held_ranks().is_empty());
            clear_held_locks();
        });
        worker.join().expect("migration worker should complete");
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn exact_guard_token_cannot_erase_another_tasks_same_name_lock() {
        let first_cx = crate::Cx::for_testing();
        let second_cx = crate::Cx::for_testing();

        let first_token = {
            let _current = crate::Cx::set_current(Some(first_cx));
            clear_held_locks();
            record_guard_acquire("tasks_same_name", Some(LockRank::Tasks))
        };

        let _current = crate::Cx::set_current(Some(second_cx));
        clear_held_locks();
        let mut second_token = record_guard_acquire("tasks_same_name", Some(LockRank::Tasks));

        let mut first_token = first_token;
        record_guard_release(&mut first_token);
        let held = current_held_locks();
        assert_eq!(held[&LockRank::Tasks].len(), 1);
        assert_eq!(held[&LockRank::Tasks][0].name, "tasks_same_name");

        record_guard_release(&mut second_token);
        assert!(current_held_locks().is_empty());
        clear_held_locks();
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn shipped_send_guards_release_exact_tracking_after_worker_migration() {
        fn drop_on_matching_task<T: Send>(cx: &crate::Cx, guard: T) {
            let cx = cx.clone();
            std::thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let _current = crate::Cx::set_current(Some(cx));
                        assert_eq!(current_held_ranks(), vec![LockRank::Tasks]);
                        drop(guard);
                        assert!(current_held_locks().is_empty());
                    })
                    .join()
                    .expect("guard migration worker should complete");
            });
        }

        let cx = crate::Cx::for_testing();

        let mutex = std::sync::Arc::new(crate::sync::Mutex::with_name(
            "tasks_owned_mutex_migration",
            1_u8,
        ));
        let mutex_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedMutexGuard::try_lock(std::sync::Arc::clone(&mutex))
                .expect("owned mutex should be immediately available")
        };
        drop_on_matching_task(&cx, mutex_guard);

        let mapped_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedMutexGuard::try_lock(std::sync::Arc::clone(&mutex))
                .expect("owned mutex should remain available")
                .map(|value| value)
        };
        drop_on_matching_task(&cx, mapped_guard);

        let rwlock = crate::sync::RwLock::with_name("tasks_rwlock_migration", 1_u8);
        let read_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            rwlock.try_read().expect("read guard should be available")
        };
        drop_on_matching_task(&cx, read_guard);

        let write_guard = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            rwlock.try_write().expect("write guard should be available")
        };
        drop_on_matching_task(&cx, write_guard);

        let owned_rwlock = std::sync::Arc::new(crate::sync::RwLock::with_name(
            "tasks_owned_rwlock_migration",
            1_u8,
        ));
        let owned_read = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedRwLockReadGuard::try_read(std::sync::Arc::clone(&owned_rwlock))
                .expect("owned read guard should be available")
        };
        drop_on_matching_task(&cx, owned_read);

        let owned_write = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedRwLockWriteGuard::try_write(std::sync::Arc::clone(&owned_rwlock))
                .expect("owned write guard should be available")
        };
        drop_on_matching_task(&cx, owned_write);

        let semaphore = crate::sync::Semaphore::with_name("tasks_semaphore_migration", 1);
        let permit = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            semaphore
                .try_acquire(1)
                .expect("borrowed permit should be available")
        };
        drop_on_matching_task(&cx, permit);

        let owned_semaphore = std::sync::Arc::new(crate::sync::Semaphore::with_name(
            "tasks_owned_semaphore_migration",
            1,
        ));
        let owned_permit = {
            let _current = crate::Cx::set_current(Some(cx.clone()));
            crate::sync::OwnedSemaphorePermit::try_acquire(
                std::sync::Arc::clone(&owned_semaphore),
                1,
            )
            .expect("owned permit should be available")
        };
        drop_on_matching_task(&cx, owned_permit);

        let _current = crate::Cx::set_current(Some(cx));
        assert!(current_held_locks().is_empty());
        clear_held_locks();
    }
}
