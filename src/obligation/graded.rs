//! Graded/quantitative types for obligations and budgets.
//!
//! Explores an opt-in type layer where obligations carry resource annotations,
//! making "no obligation leaks" a type error (or at minimum a `#[must_use]`
//! warning + panic-on-drop) for code using the graded surface.
//!
//! # Typing Judgment Sketch
//!
//! The graded type discipline assigns resource weights to obligation values:
//!
//! ```text
//! Γ ⊢ reserve(K)    : Obligation<K>     [creates 1 unit of resource K]
//! Γ, x: Obligation<K> ⊢ commit(x) : ()  [consumes 1 unit of resource K]
//! Γ, x: Obligation<K> ⊢ abort(x)  : ()  [consumes 1 unit of resource K]
//!
//! // Scope rule: exit with 0 outstanding obligations
//! Γ ⊢ scope(body) : τ    iff    Γ_exit has no live Obligation<K> values
//! ```
//!
//! In a fully linear type system, forgetting to consume an obligation would
//! be a *type error*. Rust is affine (values may be dropped silently), not
//! linear. We approximate linearity with:
//!
//! 1. **`#[must_use]`**: Compiler warns if an `Obligation<K>` is ignored.
//! 2. **Drop bomb**: `Drop` impl panics if the obligation was not resolved.
//!    In debug/lab mode this catches leaks immediately. In release mode,
//!    this can be replaced with a log+metric.
//! 3. **API shape**: The only ways to disarm the drop bomb are `commit()`,
//!    `abort()`, or `into_raw()` (escape hatch for FFI/tests).
//!
//! # Resource Semiring
//!
//! The graded annotation forms a semiring over obligation counts:
//!
//! ```text
//! (ℕ, +, 0, ×, 1)
//! ```
//!
//! - `0`: no obligation held (empty)
//! - `1`: one obligation held (reserve)
//! - `+`: sequential composition (obligations accumulate)
//! - `×`: parallel composition (obligations from both branches)
//!
//! # Example
//!
//! ```
//! use asupersync::obligation::graded::{GradedObligation, Resolution};
//! use asupersync::record::ObligationKind;
//!
//! // Correct usage: obligation is resolved before scope exit.
//! let ob = GradedObligation::reserve(ObligationKind::SendPermit, "test permit");
//! ob.resolve(Resolution::Commit);
//!
//! // This would panic on drop:
//! // let leaked = GradedObligation::reserve(ObligationKind::Ack, "leaked");
//! // drop(leaked); // PANIC: obligation leaked!
//! ```

// The `TokenKind` markers near the bottom of this file (`SendPermit`,
// `AckKind`, `LeaseKind`, `IoOpKind`, `SemaphorePermitKind`,
// `TransactionKind`) are deliberately uninhabited: they are type-level tags
// only, and an empty enum is the one shape that cannot be constructed at all.
// clippy's `empty_enum` (in the pinned nightly's lint set) suggests the never
// type instead; these are public items under the 0.4.x compatibility gate, so
// their shape cannot change without an approved break.
#![allow(clippy::empty_enums)]

use crate::record::{ObligationKind, ObligationState};
use crate::types::{RegionId, id::next_bootstrap_region_id};
use std::fmt;
use std::marker::PhantomData;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Panic-Safe Leak Tracker
// ============================================================================

/// Tracks obligation leaks that occur during panic unwinding.
///
/// This preserves the "no obligation leaks" invariant even when obligations
/// are dropped during panic unwinding, where we cannot panic again.
struct PanicLeakTracker {
    /// Total number of obligations leaked during panic unwinding.
    leak_count: AtomicU64,
}

impl PanicLeakTracker {
    const fn new() -> Self {
        Self {
            leak_count: AtomicU64::new(0),
        }
    }

    /// Record an obligation leak during panic unwinding.
    ///
    /// This is panic-safe and will not panic even if called during unwinding.
    fn record_panic_leak(&self) {
        self.leak_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of panic leaks recorded.
    pub fn leak_count(&self) -> u64 {
        self.leak_count.load(Ordering::Relaxed)
    }
}

/// Global panic leak tracker instance.
static PANIC_LEAK_TRACKER: LazyLock<PanicLeakTracker> = LazyLock::new(PanicLeakTracker::new);

/// Snapshot of obligation leaks observed during panic unwinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanicLeakSnapshot {
    /// Total obligations dropped unresolved while the thread was already panicking.
    pub total_leaked: u64,
}

/// Returns the number of obligations that have leaked during panic unwinding.
///
/// This is useful for tests and monitoring to ensure that the "no obligation leaks"
/// invariant is maintained even during exceptional circumstances.
pub fn panic_leak_count() -> u64 {
    PANIC_LEAK_TRACKER.leak_count()
}

/// Returns a snapshot of leaks recorded during panic unwinding.
///
/// This is the structured diagnostic form of [`panic_leak_count`]. It is safe to
/// call while handling a panic and never mutates obligation state.
///
/// # Examples
///
/// ```
/// use asupersync::obligation::graded::{panic_leak_count, panic_leaks};
///
/// let snapshot = panic_leaks();
/// assert_eq!(snapshot.total_leaked, panic_leak_count());
/// ```
#[must_use]
pub fn panic_leaks() -> PanicLeakSnapshot {
    PanicLeakSnapshot {
        total_leaked: PANIC_LEAK_TRACKER.leak_count(),
    }
}

// ============================================================================
// Resolution
// ============================================================================

/// How an obligation was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Obligation was committed (effect took place).
    Commit,
    /// Obligation was aborted (clean cancellation).
    Abort,
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit => f.write_str("commit"),
            Self::Abort => f.write_str("abort"),
        }
    }
}

impl Resolution {
    /// Returns the matching runtime obligation record state.
    #[inline]
    #[must_use]
    pub const fn obligation_state(self) -> ObligationState {
        match self {
            Self::Commit => ObligationState::Committed,
            Self::Abort => ObligationState::Aborted,
        }
    }
}

// ============================================================================
// GradedObligation
// ============================================================================

/// A graded obligation value that must be resolved before being dropped.
///
/// This type approximates a linear type in Rust's affine type system.
/// It uses `#[must_use]` to warn at compile time if the value is unused,
/// and panics on `Drop` if the obligation was not resolved.
///
/// # Graded Semantics
///
/// Each `GradedObligation` represents exactly 1 unit of resource.
/// Resolving it (via `resolve()`) consumes the resource and returns
/// a `Resolved<K>` proof token. Dropping without resolving panics.
///
/// # Type-Level Encoding
///
/// In a fully graded type system, we would write:
/// ```text
/// reserve : () →₁ Obligation<K>
/// commit  : Obligation<K> →₁ ()
/// abort   : Obligation<K> →₁ ()
/// ```
/// where `→₁` means "consumes exactly 1 unit". In Rust, we approximate
/// this with move semantics (value is consumed) and Drop (leak detection).
#[must_use = "obligations must be resolved (commit or abort); dropping leaks the obligation"]
pub struct GradedObligation {
    /// The kind of obligation.
    kind: ObligationKind,
    /// Description for diagnostics.
    description: String,
    /// Whether the obligation has been resolved.
    resolved: bool,
}

impl GradedObligation {
    /// Reserve a new obligation of the given kind.
    ///
    /// This is the `reserve` typing rule:
    /// ```text
    /// Γ ⊢ reserve(K, desc) : Obligation<K>     [+1 resource]
    /// ```
    pub fn reserve(kind: ObligationKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
            resolved: false,
        }
    }

    /// Resolve the obligation (commit or abort), consuming the graded value.
    ///
    /// This is the `commit`/`abort` typing rule:
    /// ```text
    /// Γ, x: Obligation<K> ⊢ resolve(x, r) : Proof<K>     [-1 resource]
    /// ```
    ///
    /// Returns a [`ResolvedProof`] token that proves the obligation was handled.
    #[must_use]
    pub fn resolve(mut self, resolution: Resolution) -> ResolvedProof {
        self.resolved = true;
        ResolvedProof {
            kind: self.kind,
            resolution,
        }
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// Returns the description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns whether the obligation has been resolved.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.resolved
    }

    /// Escape hatch: disarm the drop bomb without resolving.
    ///
    /// Use only for FFI boundaries, test harnesses, or migration paths.
    /// This intentionally leaks the obligation.
    #[must_use]
    pub fn into_raw(mut self) -> RawObligation {
        self.resolved = true; // Disarm the bomb.
        RawObligation {
            kind: self.kind,
            description: std::mem::take(&mut self.description),
        }
    }
}

impl Drop for GradedObligation {
    fn drop(&mut self) {
        if !self.resolved {
            if std::thread::panicking() {
                // During panic unwinding, we cannot panic again, but we must still
                // track the obligation leak to maintain the "no obligation leaks" invariant.
                // This preserves leak detection even during panic unwinding.
                PANIC_LEAK_TRACKER.record_panic_leak();
                return;
            }
            // In lab/debug mode: panic to surface the bug immediately.
            // In production: this could log+metric instead of panicking.
            panic!(
                "[ASUP-E101] OBLIGATION LEAKED: {} obligation '{}' was dropped without being resolved. \
                 Call .resolve(Resolution::Commit) or .resolve(Resolution::Abort) before scope exit.",
                self.kind, self.description,
            );
        }
    }
}

impl fmt::Debug for GradedObligation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GradedObligation")
            .field("kind", &self.kind)
            .field("description", &self.description)
            .field("resolved", &self.resolved)
            .finish()
    }
}

// ============================================================================
// ResolvedProof
// ============================================================================

/// Proof token that an obligation was resolved.
///
/// Created by [`GradedObligation::resolve`]. This is a zero-cost witness
/// value: it proves at the type level that the obligation was handled.
/// The fields are intentionally opaque so callers cannot forge resolution
/// proofs without actually consuming an obligation.
///
/// In a dependent type system, this would be:
/// ```text
/// ResolvedProof<K, R> : Type    where R ∈ {Commit, Abort}
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedProof {
    /// The kind of obligation that was resolved.
    kind: ObligationKind,
    /// How it was resolved.
    resolution: Resolution,
}

impl ResolvedProof {
    /// Returns the obligation kind proven to be resolved.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// Returns how the obligation was resolved.
    #[must_use]
    pub fn resolution(&self) -> Resolution {
        self.resolution
    }

    /// Returns the matching runtime obligation record state.
    #[must_use]
    pub fn obligation_state(&self) -> ObligationState {
        self.resolution.obligation_state()
    }
}

impl fmt::Display for ResolvedProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resolved({}, {})", self.kind, self.resolution)
    }
}

// ============================================================================
// RawObligation
// ============================================================================

/// An obligation that was disarmed via [`GradedObligation::into_raw`].
///
/// Holds the metadata but not the drop bomb. Used for FFI, migration,
/// and test harness escape paths.
#[derive(Debug, Clone)]
pub struct RawObligation {
    /// The kind of obligation.
    pub kind: ObligationKind,
    /// Description.
    pub description: String,
}

// ============================================================================
// GradedScope
// ============================================================================

/// A scope that tracks obligation counts and verifies zero-leak at exit.
///
/// Models the scope typing rule:
/// ```text
/// Γ ⊢ scope(body) : τ    iff    Γ_exit has 0 outstanding obligations
/// ```
///
/// The scope tracks how many obligations have been reserved and resolved.
/// At scope exit (via `close()`), it verifies the counts match.
pub struct GradedScope {
    /// Label for diagnostics.
    label: String,
    /// Number of obligations reserved.
    reserved: u32,
    /// Number of obligations resolved.
    resolved: u32,
    /// Whether the scope has been explicitly closed.
    closed: bool,
}

impl GradedScope {
    /// Open a new graded scope.
    #[must_use]
    pub fn open(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            reserved: 0,
            resolved: 0,
            closed: false,
        }
    }

    /// Record a reservation (obligation created in this scope).
    pub fn on_reserve(&mut self) {
        self.reserved = self
            .reserved
            .checked_add(1)
            .expect("on_reserve overflowed outstanding obligation count");
    }

    /// Record a resolution (obligation resolved in this scope).
    ///
    /// # Panics
    ///
    /// Panics if called more times than `on_reserve`, which would indicate
    /// a double-resolution bug.
    pub fn on_resolve(&mut self) {
        assert!(
            self.resolved < self.reserved,
            "on_resolve called more times than on_reserve ({} >= {})",
            self.resolved,
            self.reserved,
        );
        self.resolved = self
            .resolved
            .checked_add(1)
            .expect("on_resolve overflowed resolved obligation count");
    }

    /// Returns the number of outstanding (unresolved) obligations.
    #[must_use]
    pub fn outstanding(&self) -> u32 {
        self.reserved.saturating_sub(self.resolved)
    }

    /// Close the scope, verifying zero outstanding obligations.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the number of leaked obligations if any remain.
    #[must_use = "close() must be checked; Err indicates leaked obligations"]
    pub fn close(mut self) -> Result<ScopeProof, ScopeLeakError> {
        let outstanding = self.outstanding();
        if outstanding == 0 {
            self.closed = true;
            Ok(ScopeProof {
                label: self.label.clone(),
                total_reserved: self.reserved,
                total_resolved: self.resolved,
            })
        } else {
            let err = ScopeLeakError {
                label: self.label.clone(),
                outstanding,
                reserved: self.reserved,
                resolved: self.resolved,
            };
            // Mark closed so Drop doesn't panic — the caller explicitly
            // called close() and received the error, so they are aware of
            // the leak. Drop panics are reserved for implicit drops where
            // close() was never called.
            self.closed = true;
            Err(err)
        }
    }

    /// Returns the scope label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Drop for GradedScope {
    fn drop(&mut self) {
        if !self.closed && self.outstanding() > 0 {
            if std::thread::panicking() {
                return;
            }
            panic!(
                "SCOPE LEAKED: scope '{}' dropped with {} outstanding obligation(s) \
                 ({} reserved, {} resolved). Call .close() before scope exit.",
                self.label,
                self.outstanding(),
                self.reserved,
                self.resolved,
            );
        }
    }
}

impl fmt::Debug for GradedScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GradedScope")
            .field("label", &self.label)
            .field("reserved", &self.reserved)
            .field("resolved", &self.resolved)
            .field("outstanding", &self.outstanding())
            .field("closed", &self.closed)
            .finish()
    }
}

// ============================================================================
// ScopeProof / ScopeLeakError
// ============================================================================

/// Proof that a scope was closed with zero outstanding obligations.
///
/// This witness is intentionally opaque so callers cannot fabricate a clean
/// closure proof without running the scope accounting.
#[derive(Debug, PartialEq, Eq)]
pub struct ScopeProof {
    /// Scope label.
    label: String,
    /// Total obligations reserved.
    total_reserved: u32,
    /// Total obligations resolved.
    total_resolved: u32,
}

impl ScopeProof {
    /// Returns the label of the cleanly closed scope.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns how many obligations were reserved in the scope.
    #[must_use]
    pub fn total_reserved(&self) -> u32 {
        self.total_reserved
    }

    /// Returns how many obligations were resolved in the scope.
    #[must_use]
    pub fn total_resolved(&self) -> u32 {
        self.total_resolved
    }
}

impl fmt::Display for ScopeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scope '{}' clean: {}/{} resolved",
            self.label, self.total_resolved, self.total_reserved
        )
    }
}

/// Error when a scope is closed with outstanding obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLeakError {
    /// Scope label.
    pub label: String,
    /// Number of leaked obligations.
    pub outstanding: u32,
    /// Total reserved.
    pub reserved: u32,
    /// Total resolved.
    pub resolved: u32,
}

impl fmt::Display for ScopeLeakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scope '{}' leaked: {} outstanding ({} reserved, {} resolved)",
            self.label, self.outstanding, self.reserved, self.resolved,
        )
    }
}

impl std::error::Error for ScopeLeakError {}

// ============================================================================
// Toy API demonstration
// ============================================================================

/// Demonstrates the graded obligation API with a toy channel-like pattern.
///
/// This module shows how the graded type discipline makes obligation leaks
/// into compile warnings or runtime panics, while correct usage compiles
/// and runs cleanly.
pub mod toy_api {
    use super::{GradedObligation, ObligationKind, Resolution, ResolvedProof};

    fn assert_send_permit(permit: &GradedObligation, operation: &str) {
        assert_eq!(
            permit.kind(),
            ObligationKind::SendPermit,
            "{operation} requires a SendPermit obligation (got {})",
            permit.kind()
        );
    }

    /// A toy channel that uses graded obligations for the two-phase send.
    pub struct ToyChannel {
        capacity: usize,
        messages: Vec<String>,
        reserved_permits: usize,
    }

    impl ToyChannel {
        /// Creates a new channel with the given capacity.
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            Self {
                capacity,
                messages: Vec::new(),
                reserved_permits: 0,
            }
        }

        #[cfg(test)]
        pub(super) fn from_state(
            capacity: usize,
            messages: Vec<String>,
            reserved_permits: usize,
        ) -> Self {
            Self {
                capacity,
                messages,
                reserved_permits,
            }
        }

        /// Reserve a send permit.
        ///
        /// Returns a [`GradedObligation`] that must be resolved:
        /// - `resolve(Commit)` — message is sent
        /// - `resolve(Abort)` — permit is cancelled
        ///
        /// Dropping the permit without resolving panics.
        #[must_use]
        pub fn reserve_send(&mut self) -> Option<GradedObligation> {
            let occupied = self
                .messages
                .len()
                .checked_add(self.reserved_permits)
                .expect("toy channel occupancy overflowed");
            if occupied < self.capacity {
                self.reserved_permits = self
                    .reserved_permits
                    .checked_add(1)
                    .expect("toy channel reserved permit count overflowed");
                Some(GradedObligation::reserve(
                    ObligationKind::SendPermit,
                    "toy channel send permit",
                ))
            } else {
                None
            }
        }

        /// Commit a send: consumes the permit and enqueues the message.
        pub fn commit_send(&mut self, permit: GradedObligation, message: String) -> ResolvedProof {
            assert_send_permit(&permit, "commit_send");
            self.reserved_permits = self
                .reserved_permits
                .checked_sub(1)
                .expect("commit_send requires an outstanding reservation");
            self.messages.push(message);
            permit.resolve(Resolution::Commit)
        }

        /// Abort a send: cancels the permit without sending.
        #[must_use]
        pub fn abort_send(&mut self, permit: GradedObligation) -> ResolvedProof {
            assert_send_permit(&permit, "abort_send");
            self.reserved_permits = self
                .reserved_permits
                .checked_sub(1)
                .expect("abort_send requires an outstanding reservation");
            permit.resolve(Resolution::Abort)
        }

        /// Returns the number of messages in the channel.
        #[must_use]
        pub fn len(&self) -> usize {
            self.messages.len()
        }

        /// Returns true if the channel is empty.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.messages.is_empty()
        }
    }
}

// ============================================================================
// Sealed trait pattern (prevents external impls of TokenKind)
// ============================================================================

mod sealed {
    pub trait Sealed {}
}

// ============================================================================
// TokenKind trait + kind marker enums
// ============================================================================

/// Trait mapping a zero-sized kind marker to its [`ObligationKind`] variant.
///
/// Sealed: cannot be implemented outside this crate.
pub trait TokenKind: sealed::Sealed {
    /// Returns the [`ObligationKind`] corresponding to this marker.
    fn obligation_kind() -> ObligationKind;
}

/// Error returned when dynamic obligation metadata does not match a typed token.
///
/// This is the migration bridge from existing runtime/ledger surfaces that
/// still carry [`ObligationKind`] dynamically into the stronger typestate API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedObligationKindError {
    /// Static obligation kind required by the requested token type.
    pub expected: ObligationKind,
    /// Dynamic obligation kind supplied by the caller.
    pub actual: ObligationKind,
}

impl fmt::Display for TypedObligationKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "typed obligation kind mismatch: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for TypedObligationKindError {}

/// Contract row describing the typed obligation bridge evidence surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedObligationBridgeContract {
    /// Bead that introduced the bridge contract.
    pub bead_id: &'static str,
    /// Protocol family strengthened by the typed bridge.
    pub protocol_family: &'static str,
    /// Typed API entrypoint that materializes a static obligation token.
    pub typed_entrypoint: &'static str,
    /// Dynamic fallback path that remains authoritative during migration.
    pub dynamic_fallback: &'static str,
    /// Compile-fail proof surface for invalid typestate transitions.
    pub compile_fail_surface: &'static str,
    /// Focused reproduction command for the contract evidence.
    pub replay_command: &'static str,
    /// Stable invariant checklist covered by the focused tests.
    pub invariants: &'static [&'static str],
}

const TYPED_OBLIGATION_BRIDGE_INVARIANTS: &[&str] = &[
    "matching dynamic kind creates a typed token",
    "mismatched dynamic kind does not arm a token",
    "scope accounting increments only after kind proof succeeds",
    "abort cleanup balances a scoped lease token",
    "committed proof has no abort transition",
];

/// Returns the contract row for the dynamic-to-typed obligation bridge.
#[must_use]
pub const fn typed_obligation_bridge_contract() -> TypedObligationBridgeContract {
    TypedObligationBridgeContract {
        bead_id: "asupersync-d87ytw.13",
        protocol_family: "send-permit/ack/lease graded obligations",
        typed_entrypoint: "asupersync::obligation::graded::ObligationToken::try_reserve_kind",
        dynamic_fallback: "asupersync::record::ObligationKind",
        compile_fail_surface: "src/obligation/graded.rs::ObligationToken commit-then-abort doctest",
        replay_command: "rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_graded_bridge cargo test -p asupersync --lib dynamic_kind_bridge --features test-internals -- --nocapture",
        invariants: TYPED_OBLIGATION_BRIDGE_INVARIANTS,
    }
}

/// Marker type for [`ObligationKind::SendPermit`].
#[derive(Debug)]
pub enum SendPermit {}
impl sealed::Sealed for SendPermit {}
impl TokenKind for SendPermit {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::SendPermit
    }
}

/// Marker type for [`ObligationKind::Ack`].
#[derive(Debug)]
pub enum AckKind {}
impl sealed::Sealed for AckKind {}
impl TokenKind for AckKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::Ack
    }
}

/// Marker type for [`ObligationKind::Lease`].
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseKind {}
impl sealed::Sealed for LeaseKind {}
impl TokenKind for LeaseKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::Lease
    }
}

/// Marker type for [`ObligationKind::IoOp`].
#[derive(Debug)]
pub enum IoOpKind {}
impl sealed::Sealed for IoOpKind {}
impl TokenKind for IoOpKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::IoOp
    }
}

/// Marker type for [`ObligationKind::SemaphorePermit`].
#[derive(Debug)]
pub enum SemaphorePermitKind {}
impl sealed::Sealed for SemaphorePermitKind {}
impl TokenKind for SemaphorePermitKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::SemaphorePermit
    }
}

/// Marker type for [`ObligationKind::Transaction`].
///
/// A database transaction holds an [`ObligationToken<TransactionKind>`] for its
/// open lifetime: `commit` consumes it via [`ObligationToken::commit`], while
/// rollback (explicit or on drop/cancel) consumes it via
/// [`ObligationToken::abort`]. This makes "an open transaction is an
/// obligation" structural, mirroring the name-lease pattern in
/// [`crate::cx::registry`] (br-asupersync-server-stack-hardening-eeexl1.5).
#[derive(Debug)]
pub enum TransactionKind {}
impl sealed::Sealed for TransactionKind {}
impl TokenKind for TransactionKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::Transaction
    }
}

// ============================================================================
// ObligationToken<K> — typestate linear token
// ============================================================================

/// A typestate-encoded obligation token that must be consumed via
/// [`commit`](Self::commit) or [`abort`](Self::abort).
///
/// Dropping without consuming panics ("drop bomb"), approximating a linear
/// type in Rust's affine type system.
///
/// Invalid transitions stay unrepresentable: after a token is committed, the
/// resulting proof has no `abort` transition.
///
/// ```compile_fail
/// use asupersync::obligation::graded::{ObligationToken, SendPermitToken};
///
/// let token: SendPermitToken = ObligationToken::reserve_test("send");
/// let committed = token.commit();
/// let _late_abort = committed.abort();
/// ```
#[must_use = "obligation tokens must be consumed via commit() or abort()"]
pub struct ObligationToken<K: TokenKind> {
    description: String,
    region: RegionId,
    armed: bool,
    _kind: PhantomData<K>,
}

impl<K: TokenKind> ObligationToken<K> {
    /// Reserve a new obligation token with the given description and region context.
    ///
    /// This method ensures the obligation is properly scoped to a region, preventing
    /// obligation leaks that could occur if tokens outlive their intended scope.
    ///
    /// # Region Validation
    ///
    /// The region must be valid and active. Creating obligations outside of proper
    /// region context violates the "no obligation leaks" invariant.
    #[allow(clippy::double_must_use)]
    #[must_use = "obligation tokens must be committed or aborted"]
    pub fn reserve(description: impl Into<String>, region: RegionId) -> Self {
        let description = description.into();
        // Validate that the region is not the root region (which should not hold obligations)
        // and that we're in a valid execution context. The root region typically has
        // index 0, generation 0.
        assert!(
            region.as_u64() != 0,
            "[ASUP-E103] Cannot create obligation token in root region: obligations must be \
             scoped to non-root regions to prevent leaks. Description: {description}"
        );

        Self {
            description,
            region,
            armed: true,
            _kind: PhantomData,
        }
    }

    /// Returns the region this obligation is scoped to.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Reserve a token for testing with a synthetic test region.
    ///
    /// This method should only be used in tests where proper region context
    /// is not available. Production code should use `reserve()` with a real
    /// region from the current Cx.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use = "obligation tokens must be committed or aborted"]
    pub fn reserve_test(description: impl Into<String>) -> Self {
        Self::reserve(description, RegionId::new_ephemeral())
    }

    /// Reserve a typed token from dynamic obligation metadata.
    ///
    /// This preserves the existing dynamic [`ObligationKind`] source of truth
    /// while refusing to manufacture a static token for the wrong protocol
    /// family. On mismatch no token is created, so no drop bomb is armed.
    ///
    /// # Errors
    ///
    /// Returns [`TypedObligationKindError`] when `kind` differs from `K`.
    pub fn try_reserve_kind(
        kind: ObligationKind,
        description: impl Into<String>,
        region: RegionId,
    ) -> Result<Self, TypedObligationKindError> {
        let expected = K::obligation_kind();
        if kind == expected {
            Ok(Self::reserve(description, region))
        } else {
            Err(TypedObligationKindError {
                expected,
                actual: kind,
            })
        }
    }

    /// Commit the obligation, consuming the token and returning a
    /// [`CommittedProof`].
    #[must_use]
    pub fn commit(mut self) -> CommittedProof<K> {
        self.armed = false;
        CommittedProof { _kind: PhantomData }
    }

    /// Abort the obligation, consuming the token and returning an
    /// [`AbortedProof`].
    #[must_use]
    pub fn abort(mut self) -> AbortedProof<K> {
        self.armed = false;
        AbortedProof { _kind: PhantomData }
    }

    /// Escape hatch: disarm the drop bomb and convert to a [`RawObligation`].
    ///
    /// Use only for FFI boundaries, test harnesses, or migration paths.
    #[must_use]
    pub fn into_raw(mut self) -> RawObligation {
        self.armed = false;
        let description = std::mem::take(&mut self.description);
        RawObligation {
            kind: K::obligation_kind(),
            description,
        }
    }

    /// Returns the description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl<K: TokenKind> Drop for ObligationToken<K> {
    fn drop(&mut self) {
        if self.armed {
            if std::thread::panicking() {
                // Counted like GradedObligation (br-asupersync-27bbrg).
                PANIC_LEAK_TRACKER.record_panic_leak();
                return;
            }
            panic!(
                // ubs:ignore - intentional panic on leak in debug build
                "[ASUP-E101] OBLIGATION TOKEN LEAKED: {} token '{}' was dropped without being consumed. \
                 Call .commit() or .abort() before scope exit.",
                K::obligation_kind(),
                self.description,
            );
        }
    }
}

impl<K: TokenKind> fmt::Debug for ObligationToken<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObligationToken")
            .field("kind", &K::obligation_kind())
            .field("description", &self.description)
            .field("armed", &self.armed)
            .finish()
    }
}

// ============================================================================
// CommittedProof<K> / AbortedProof<K> — ZST witnesses
// ============================================================================

/// Proof that an [`ObligationToken`] was committed.
///
/// Commit proofs are affine witnesses: they are intentionally non-cloneable
/// and can only be constructed by consuming a live token.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedProof<K: TokenKind> {
    _kind: PhantomData<K>,
}

impl<K: TokenKind> CommittedProof<K> {
    /// Bridge to the existing [`ResolvedProof`] system.
    #[must_use]
    pub fn into_resolved_proof(self) -> ResolvedProof {
        ResolvedProof {
            kind: K::obligation_kind(),
            resolution: Resolution::Commit,
        }
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        K::obligation_kind()
    }
}

/// Proof that an [`ObligationToken`] was aborted.
///
/// Abort proofs are affine witnesses: they are intentionally non-cloneable
/// and can only be constructed by consuming a live token.
#[derive(Debug, PartialEq, Eq)]
pub struct AbortedProof<K: TokenKind> {
    _kind: PhantomData<K>,
}

impl<K: TokenKind> AbortedProof<K> {
    /// Bridge to the existing [`ResolvedProof`] system.
    #[must_use]
    pub fn into_resolved_proof(self) -> ResolvedProof {
        ResolvedProof {
            kind: K::obligation_kind(),
            resolution: Resolution::Abort,
        }
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        K::obligation_kind()
    }
}

// ============================================================================
// Type aliases (ergonomic names)
// ============================================================================

/// Token for a send-permit obligation.
pub type SendPermitToken = ObligationToken<SendPermit>;
/// Token for an acknowledgement obligation.
pub type AckToken = ObligationToken<AckKind>;
/// Token for a lease obligation.
pub type LeaseToken = ObligationToken<LeaseKind>;
/// Token for an I/O operation obligation.
pub type IoOpToken = ObligationToken<IoOpKind>;

// ============================================================================
// GradedScope convenience methods for tokens
// ============================================================================

impl GradedScope {
    /// Reserve a typed obligation token, recording it in this scope.
    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn reserve_token<K: TokenKind>(
        &mut self,
        description: impl Into<String>,
    ) -> ObligationToken<K> {
        self.on_reserve();
        ObligationToken::reserve(description, next_bootstrap_region_id())
    }

    /// Reserve a typed token from dynamic obligation metadata and record it.
    ///
    /// Scope accounting is updated only after the dynamic kind matches the
    /// requested static token kind. A mismatch therefore cannot create a
    /// synthetic outstanding obligation in the graded scope.
    ///
    /// # Errors
    ///
    /// Returns [`TypedObligationKindError`] when `kind` differs from `K`.
    pub fn try_reserve_token_kind<K: TokenKind>(
        &mut self,
        kind: ObligationKind,
        description: impl Into<String>,
    ) -> Result<ObligationToken<K>, TypedObligationKindError> {
        let token =
            ObligationToken::try_reserve_kind(kind, description, next_bootstrap_region_id())?;
        self.on_reserve();
        Ok(token)
    }

    /// Commit a typed obligation token, recording the resolution in this scope.
    #[must_use]
    pub fn resolve_commit<K: TokenKind>(&mut self, token: ObligationToken<K>) -> CommittedProof<K> {
        self.on_resolve();
        token.commit()
    }

    /// Abort a typed obligation token, recording the resolution in this scope.
    #[must_use]
    pub fn resolve_abort<K: TokenKind>(&mut self, token: ObligationToken<K>) -> AbortedProof<K> {
        self.on_resolve();
        token.abort()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "graded_inline_tests.rs"]
mod tests;
