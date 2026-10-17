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
        // Test-only lock names created by in-crate unit tests. Under
        // `lock-metrics` the constructor fails closed on undocumented names,
        // which turned these tests red on every OS once CI ran the lib suite
        // with that feature (2026-09-02).
        // The second group turned 15 lib tests red when the suite first ran with the
        // production feature set, which includes `lock-metrics` (2026-09-29,
        // asupersync-kh02d2).
        "test_abandon_read" | "test_abandon_write" | "external-tasks" | "reader_fanout"
        | "close_fanout" | "worker_retirement" | "request_race" | "queued_local_handoff"
        | "dispatch_tasks" | "external_task_table" | "checked_external_state"
        | "checked_external_tasks" | "transfer_state" | "transfer_external_tasks"
        | "confirmed_leak_tasks" | "confirmed_leak_obligations" | "confirmed_leak_state" => {
            Some(LOCK_ORDER_REASON_TEST_HELPER)
        }
        _ => None,
    }
}

// The atlas remains thread-local because it is a diagnostic observation log.
// Movable (Send) guard state is task-owned (or thread-owned outside a runtime)
// below so a Send future can migrate without corrupting the deadlock detector.
// Name-tracked guards (`record_acquire*`, ContendedMutex) cannot leave their
// thread, so they are thread-owned: one Cx may be current on several threads at
// once (ambient binding), and a lock held by one of them must not appear held
// by another.
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
        thread_owner()
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn thread_owner() -> LockOrderOwner {
    LockOrderOwner::Thread(std::thread::current().id())
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn held_locks_by_owner() -> StdMutexGuard<'static, HeldLocksByOwner> {
    HELD_LOCKS_BY_OWNER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Locks held by this thread plus movable guards held by the current task.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn current_held_snapshot() -> (BTreeSet<LockRank>, BTreeMap<LockRank, Vec<LockInfo>>) {
    let thread = thread_owner();
    let task = current_owner();
    let tracker = held_locks_by_owner();
    let mut ranks = BTreeSet::new();
    let mut locks: BTreeMap<LockRank, Vec<LockInfo>> = BTreeMap::new();
    let owners = if task == thread { vec![thread] } else { vec![thread, task] };
    for owner in owners {
        let Some(state) = tracker.get(&owner) else {
            continue;
        };
        ranks.extend(state.ranks.iter().copied());
        for (rank, entries) in &state.locks {
            locks
                .entry(*rank)
                .or_default()
                .extend(entries.iter().map(|entry| entry.info.clone()));
        }
    }
    (ranks, locks)
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn next_acquisition_id() -> u64 {
    let id = NEXT_ACQUISITION_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(id, 0, "lock-order acquisition id space exhausted");
    id
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn insert_tracked_lock(
    owner: LockOrderOwner,
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
) -> LockOrderToken {
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
    let owner = thread_owner();
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
        let module = LockModule::from_name(lock_name);
        let _ = insert_tracked_lock(thread_owner(), lock_name, rank, module);
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
        let _ = insert_tracked_lock(thread_owner(), lock_name, rank, module);
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
#[allow(
    clippy::single_option_map,
    reason = "this boundary centralizes cfg-dependent guard instrumentation for every sync primitive"
)]
pub(crate) fn record_guard_acquire(lock_name: &str, rank: Option<LockRank>) -> GuardLockOrder {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        rank.map(|rank| {
            insert_tracked_lock(current_owner(), lock_name, rank, LockModule::from_name(lock_name))
        })
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
    let mut tracker = held_locks_by_owner();
    tracker.remove(&thread_owner());
    tracker.remove(&current_owner());
    drop(tracker);
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
#[path = "lock_ordering_inline_tests.rs"]
mod tests;
