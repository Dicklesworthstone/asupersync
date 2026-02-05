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

use crate::record::ObligationKind;
use std::fmt;
use std::marker::PhantomData;

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
        // In lab/debug mode: panic to surface the bug immediately.
        // In production: this could log+metric instead of panicking.
        assert!(
            self.resolved,
            "OBLIGATION LEAKED: {} obligation '{}' was dropped without being resolved. \
             Call .resolve(Resolution::Commit) or .resolve(Resolution::Abort) before scope exit.",
            self.kind, self.description,
        );
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
///
/// In a dependent type system, this would be:
/// ```text
/// ResolvedProof<K, R> : Type    where R ∈ {Commit, Abort}
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProof {
    /// The kind of obligation that was resolved.
    pub kind: ObligationKind,
    /// How it was resolved.
    pub resolution: Resolution,
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
        self.reserved += 1;
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
        self.resolved += 1;
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
    pub fn close(mut self) -> Result<ScopeProof, ScopeLeakError> {
        self.closed = true;
        let outstanding = self.outstanding();
        if outstanding == 0 {
            Ok(ScopeProof {
                label: self.label.clone(),
                total_reserved: self.reserved,
                total_resolved: self.resolved,
            })
        } else {
            Err(ScopeLeakError {
                label: self.label.clone(),
                outstanding,
                reserved: self.reserved,
                resolved: self.resolved,
            })
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
        assert!(
            self.closed || self.outstanding() == 0,
            "SCOPE LEAKED: scope '{}' dropped with {} outstanding obligation(s) \
             ({} reserved, {} resolved). Call .close() before scope exit.",
            self.label,
            self.outstanding(),
            self.reserved,
            self.resolved,
        );
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeProof {
    /// Scope label.
    pub label: String,
    /// Total obligations reserved.
    pub total_reserved: u32,
    /// Total obligations resolved.
    pub total_resolved: u32,
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

    /// A toy channel that uses graded obligations for the two-phase send.
    pub struct ToyChannel {
        capacity: usize,
        messages: Vec<String>,
    }

    impl ToyChannel {
        /// Creates a new channel with the given capacity.
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            Self {
                capacity,
                messages: Vec::new(),
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
        pub fn reserve_send(&self) -> Option<GradedObligation> {
            if self.messages.len() < self.capacity {
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
            self.messages.push(message);
            permit.resolve(Resolution::Commit)
        }

        /// Abort a send: cancels the permit without sending.
        #[must_use]
        pub fn abort_send(&self, permit: GradedObligation) -> ResolvedProof {
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

/// Marker type for [`ObligationKind::SendPermit`].
pub enum SendPermit {}
impl sealed::Sealed for SendPermit {}
impl TokenKind for SendPermit {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::SendPermit
    }
}

/// Marker type for [`ObligationKind::Ack`].
pub enum AckKind {}
impl sealed::Sealed for AckKind {}
impl TokenKind for AckKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::Ack
    }
}

/// Marker type for [`ObligationKind::Lease`].
pub enum LeaseKind {}
impl sealed::Sealed for LeaseKind {}
impl TokenKind for LeaseKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::Lease
    }
}

/// Marker type for [`ObligationKind::IoOp`].
pub enum IoOpKind {}
impl sealed::Sealed for IoOpKind {}
impl TokenKind for IoOpKind {
    fn obligation_kind() -> ObligationKind {
        ObligationKind::IoOp
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
#[must_use = "obligation tokens must be consumed via commit() or abort()"]
pub struct ObligationToken<K: TokenKind> {
    description: String,
    armed: bool,
    _kind: PhantomData<K>,
}

impl<K: TokenKind> ObligationToken<K> {
    /// Reserve a new obligation token with the given description.
    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn reserve(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            armed: true,
            _kind: PhantomData,
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
        assert!(
            !self.armed,
            "OBLIGATION TOKEN LEAKED: {} token '{}' was dropped without being consumed. \
             Call .commit() or .abort() before scope exit.",
            K::obligation_kind(),
            self.description,
        );
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        ObligationToken::reserve(description)
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
mod tests {
    use super::*;
    use crate::record::ObligationKind;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // ---- GradedObligation: correct usage -----------------------------------

    #[test]
    fn obligation_commit_clean() {
        init_test("obligation_commit_clean");
        let ob = GradedObligation::reserve(ObligationKind::SendPermit, "test");
        let kind = ob.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        let is_resolved = ob.is_resolved();
        crate::assert_with_log!(!is_resolved, "not yet resolved", false, is_resolved);

        let proof = ob.resolve(Resolution::Commit);
        let r = proof.resolution;
        crate::assert_with_log!(r == Resolution::Commit, "resolution", Resolution::Commit, r);
        crate::test_complete!("obligation_commit_clean");
    }

    #[test]
    fn obligation_abort_clean() {
        init_test("obligation_abort_clean");
        let ob = GradedObligation::reserve(ObligationKind::Ack, "ack-test");
        let proof = ob.resolve(Resolution::Abort);
        let r = proof.resolution;
        crate::assert_with_log!(r == Resolution::Abort, "resolution", Resolution::Abort, r);
        crate::test_complete!("obligation_abort_clean");
    }

    #[test]
    fn obligation_into_raw_disarms() {
        init_test("obligation_into_raw_disarms");
        let ob = GradedObligation::reserve(ObligationKind::Lease, "lease-test");
        let raw = ob.into_raw();
        let kind = raw.kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "raw kind",
            ObligationKind::Lease,
            kind
        );
        // raw can be dropped without panic.
        drop(raw);
        crate::test_complete!("obligation_into_raw_disarms");
    }

    // ---- GradedObligation: leak detection ----------------------------------

    #[test]
    #[should_panic(expected = "OBLIGATION LEAKED")]
    fn obligation_drop_without_resolve_panics() {
        init_test("obligation_drop_without_resolve_panics");
        let _ob = GradedObligation::reserve(ObligationKind::IoOp, "leaked-io");
        // Dropped without resolving — should panic.
    }

    // ---- GradedScope: correct usage ----------------------------------------

    #[test]
    fn scope_clean_close() {
        init_test("scope_clean_close");
        let mut scope = GradedScope::open("test-scope");
        scope.on_reserve();
        scope.on_resolve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let proof = scope.close().expect("scope should close cleanly");
        let label = &proof.label;
        crate::assert_with_log!(label == "test-scope", "label", "test-scope", label);
        let total = proof.total_reserved;
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_clean_close");
    }

    #[test]
    fn scope_multiple_obligations() {
        init_test("scope_multiple_obligations");
        let mut scope = GradedScope::open("multi");
        scope.on_reserve();
        scope.on_reserve();
        scope.on_reserve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 3, "outstanding", 3, outstanding);

        scope.on_resolve();
        scope.on_resolve();
        scope.on_resolve();
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let proof = scope.close().expect("clean");
        let total = proof.total_reserved;
        crate::assert_with_log!(total == 3, "reserved", 3, total);
        crate::test_complete!("scope_multiple_obligations");
    }

    #[test]
    fn scope_close_with_leak_returns_error() {
        init_test("scope_close_with_leak_returns_error");
        let mut scope = GradedScope::open("leaky-scope");
        scope.on_reserve();
        scope.on_reserve();
        scope.on_resolve(); // Only 1 of 2 resolved.

        let err = scope.close().expect_err("should fail");
        let outstanding = err.outstanding;
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);
        let label = &err.label;
        crate::assert_with_log!(label == "leaky-scope", "label", "leaky-scope", label);

        // Verify Display impl.
        let msg = format!("{err}");
        let has_leaked = msg.contains("leaked");
        crate::assert_with_log!(has_leaked, "display has leaked", true, has_leaked);
        crate::test_complete!("scope_close_with_leak_returns_error");
    }

    #[test]
    #[should_panic(expected = "SCOPE LEAKED")]
    fn scope_drop_with_outstanding_panics() {
        init_test("scope_drop_with_outstanding_panics");
        let mut scope = GradedScope::open("drop-leak");
        scope.on_reserve();
        // Dropped without closing — should panic because outstanding > 0.
    }

    #[test]
    fn scope_drop_without_close_ok_when_empty() {
        init_test("scope_drop_without_close_ok_when_empty");
        let _scope = GradedScope::open("empty-scope");
        // No obligations reserved, drop is fine.
    }

    // ---- Combined: obligation + scope --------------------------------------

    #[test]
    fn combined_obligation_and_scope() {
        init_test("combined_obligation_and_scope");
        let mut scope = GradedScope::open("combined");

        // Reserve two obligations.
        let ob1 = GradedObligation::reserve(ObligationKind::SendPermit, "send");
        scope.on_reserve();
        let ob2 = GradedObligation::reserve(ObligationKind::Ack, "ack");
        scope.on_reserve();

        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 2, "outstanding", 2, outstanding);

        // Resolve both.
        let _proof1 = ob1.resolve(Resolution::Commit);
        scope.on_resolve();
        let _proof2 = ob2.resolve(Resolution::Abort);
        scope.on_resolve();

        // Close scope.
        let proof = scope.close().expect("clean close");
        let total = proof.total_reserved;
        crate::assert_with_log!(total == 2, "total reserved", 2, total);
        crate::test_complete!("combined_obligation_and_scope");
    }

    // ---- Toy API -----------------------------------------------------------

    #[test]
    fn toy_channel_correct_usage() {
        init_test("toy_channel_correct_usage");
        let mut ch = toy_api::ToyChannel::new(10);

        // Reserve and commit.
        let permit = ch.reserve_send().expect("should get permit");
        let proof = ch.commit_send(permit, "hello".to_string());
        let resolution = proof.resolution;
        crate::assert_with_log!(
            resolution == Resolution::Commit,
            "commit",
            Resolution::Commit,
            resolution
        );
        let len = ch.len();
        crate::assert_with_log!(len == 1, "len", 1, len);
        crate::test_complete!("toy_channel_correct_usage");
    }

    #[test]
    fn toy_channel_abort_usage() {
        init_test("toy_channel_abort_usage");
        let ch = toy_api::ToyChannel::new(10);

        let permit = ch.reserve_send().expect("should get permit");
        let proof = ch.abort_send(permit);
        let resolution = proof.resolution;
        crate::assert_with_log!(
            resolution == Resolution::Abort,
            "abort",
            Resolution::Abort,
            resolution
        );
        let len = ch.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("toy_channel_abort_usage");
    }

    #[test]
    #[should_panic(expected = "OBLIGATION LEAKED")]
    fn toy_channel_leaked_permit_panics() {
        init_test("toy_channel_leaked_permit_panics");
        let ch = toy_api::ToyChannel::new(10);
        let _permit = ch.reserve_send().expect("should get permit");
        // Dropped without commit or abort — panics.
    }

    #[test]
    fn toy_channel_full_returns_none() {
        init_test("toy_channel_full_returns_none");
        let ch = toy_api::ToyChannel::new(0);
        let permit = ch.reserve_send();
        let is_none = permit.is_none();
        crate::assert_with_log!(is_none, "full", true, is_none);
        crate::test_complete!("toy_channel_full_returns_none");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("graded_display_impls");
        let proof = ResolvedProof {
            kind: ObligationKind::SendPermit,
            resolution: Resolution::Commit,
        };
        let s = format!("{proof}");
        let has_resolved = s.contains("resolved");
        crate::assert_with_log!(has_resolved, "proof display", true, has_resolved);

        let scope_proof = ScopeProof {
            label: "test".to_string(),
            total_reserved: 3,
            total_resolved: 3,
        };
        let s = format!("{scope_proof}");
        let has_clean = s.contains("clean");
        crate::assert_with_log!(has_clean, "scope proof display", true, has_clean);

        let err = ScopeLeakError {
            label: "bad".to_string(),
            outstanding: 2,
            reserved: 5,
            resolved: 3,
        };
        let s = format!("{err}");
        let has_leaked = s.contains("leaked");
        crate::assert_with_log!(has_leaked, "scope error display", true, has_leaked);

        let resolution = format!("{}", Resolution::Commit);
        crate::assert_with_log!(
            resolution == "commit",
            "resolution display",
            "commit",
            resolution
        );

        crate::test_complete!("graded_display_impls");
    }

    // ---- Typing judgment demonstration -------------------------------------

    #[test]
    fn typing_judgment_demonstration() {
        init_test("typing_judgment_demonstration");
        // This test demonstrates the typing discipline:
        //
        // 1. reserve() creates an obligation (1 resource unit)
        // 2. resolve() consumes it (0 resource units)
        // 3. Scope verifies zero-leak at exit
        //
        // The key insight: in a linear type system, step 2 is mandatory.
        // In Rust (affine), we enforce it with Drop + #[must_use].

        let mut scope = GradedScope::open("typing_demo");

        // Typing rule: Γ ⊢ reserve(SendPermit) : Obligation<SendPermit>  [+1]
        let ob = GradedObligation::reserve(ObligationKind::SendPermit, "demo");
        scope.on_reserve();

        // Typing rule: Γ, ob: Obligation<SendPermit> ⊢ resolve(ob, Commit) : Proof  [-1]
        let proof = ob.resolve(Resolution::Commit);
        scope.on_resolve();

        // Typing rule: Γ ⊢ scope_close : ScopeProof   [requires 0 outstanding]
        let scope_proof = scope.close().expect("scope should be clean");

        // Verify the proof tokens exist (zero-cost witnesses).
        let kind = proof.kind;
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "proof kind",
            ObligationKind::SendPermit,
            kind
        );
        let label = &scope_proof.label;
        crate::assert_with_log!(label == "typing_demo", "scope label", "typing_demo", label);

        crate::test_complete!("typing_judgment_demonstration");
    }

    // ---- Resource semiring properties --------------------------------------

    #[test]
    fn resource_semiring_identity() {
        init_test("resource_semiring_identity");
        // 0 is the identity for +: scope with 0 obligations is clean.
        let scope = GradedScope::open("zero");
        let proof = scope.close().expect("zero obligations = clean");
        let total = proof.total_reserved;
        crate::assert_with_log!(total == 0, "zero reserved", 0, total);
        crate::test_complete!("resource_semiring_identity");
    }

    #[test]
    fn resource_semiring_additive() {
        init_test("resource_semiring_additive");
        // + is additive: obligations accumulate and must all be resolved.
        let mut scope = GradedScope::open("additive");

        // Reserve 3 obligations (1 + 1 + 1 = 3).
        for _ in 0..3 {
            let ob = GradedObligation::reserve(ObligationKind::Lease, "lease");
            scope.on_reserve();
            let _proof = ob.resolve(Resolution::Commit);
            scope.on_resolve();
        }

        let proof = scope.close().expect("all resolved");
        let total = proof.total_reserved;
        crate::assert_with_log!(total == 3, "3 reserved", 3, total);
        let resolved = proof.total_resolved;
        crate::assert_with_log!(resolved == 3, "3 resolved", 3, resolved);
        crate::test_complete!("resource_semiring_additive");
    }

    // ---- ObligationToken typestate tests ------------------------------------

    #[test]
    fn token_commit_returns_proof() {
        init_test("token_commit_returns_proof");
        let token: SendPermitToken = ObligationToken::reserve("commit-test");
        let proof = token.commit();
        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "proof kind",
            ObligationKind::SendPermit,
            kind
        );
        crate::test_complete!("token_commit_returns_proof");
    }

    #[test]
    fn token_abort_returns_proof() {
        init_test("token_abort_returns_proof");
        let token: AckToken = ObligationToken::reserve("abort-test");
        let proof = token.abort();
        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "proof kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("token_abort_returns_proof");
    }

    #[test]
    #[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
    fn token_drop_without_consume_panics() {
        init_test("token_drop_without_consume_panics");
        let _token: SendPermitToken = ObligationToken::reserve("leaked-token");
        // Dropped without commit or abort — should panic.
    }

    #[test]
    fn token_into_raw_disarms() {
        init_test("token_into_raw_disarms");
        let token: LeaseToken = ObligationToken::reserve("raw-escape");
        let raw = token.into_raw();
        let kind = raw.kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "raw kind",
            ObligationKind::Lease,
            kind
        );
        drop(raw);
        crate::test_complete!("token_into_raw_disarms");
    }

    #[test]
    fn committed_proof_bridge() {
        init_test("committed_proof_bridge");
        let token: SendPermitToken = ObligationToken::reserve("bridge-commit");
        let committed = token.commit();
        let resolved = committed.into_resolved_proof();
        let r = resolved.resolution;
        crate::assert_with_log!(r == Resolution::Commit, "resolution", Resolution::Commit, r);
        let kind = resolved.kind;
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        crate::test_complete!("committed_proof_bridge");
    }

    #[test]
    fn aborted_proof_bridge() {
        init_test("aborted_proof_bridge");
        let token: AckToken = ObligationToken::reserve("bridge-abort");
        let aborted = token.abort();
        let resolved = aborted.into_resolved_proof();
        let r = resolved.resolution;
        crate::assert_with_log!(r == Resolution::Abort, "resolution", Resolution::Abort, r);
        let kind = resolved.kind;
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("aborted_proof_bridge");
    }

    #[test]
    fn token_kind_mapping() {
        init_test("token_kind_mapping");
        let sp = SendPermit::obligation_kind();
        crate::assert_with_log!(
            sp == ObligationKind::SendPermit,
            "SendPermit",
            ObligationKind::SendPermit,
            sp
        );
        let ack = AckKind::obligation_kind();
        crate::assert_with_log!(
            ack == ObligationKind::Ack,
            "AckKind",
            ObligationKind::Ack,
            ack
        );
        let lease = LeaseKind::obligation_kind();
        crate::assert_with_log!(
            lease == ObligationKind::Lease,
            "LeaseKind",
            ObligationKind::Lease,
            lease
        );
        let io = IoOpKind::obligation_kind();
        crate::assert_with_log!(
            io == ObligationKind::IoOp,
            "IoOpKind",
            ObligationKind::IoOp,
            io
        );
        crate::test_complete!("token_kind_mapping");
    }

    #[test]
    fn scope_reserve_and_commit_token() {
        init_test("scope_reserve_and_commit_token");
        let mut scope = GradedScope::open("token-scope-commit");
        let token: SendPermitToken = scope.reserve_token("scoped-send");
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);

        let proof = scope.resolve_commit(token);
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );

        let scope_proof = scope.close().expect("scope should close cleanly");
        let total = scope_proof.total_reserved;
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_reserve_and_commit_token");
    }

    #[test]
    fn scope_reserve_and_abort_token() {
        init_test("scope_reserve_and_abort_token");
        let mut scope = GradedScope::open("token-scope-abort");
        let token: AckToken = scope.reserve_token("scoped-ack");
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 1, "outstanding", 1, outstanding);

        let proof = scope.resolve_abort(token);
        let outstanding = scope.outstanding();
        crate::assert_with_log!(outstanding == 0, "outstanding", 0, outstanding);

        let kind = proof.kind();
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );

        let scope_proof = scope.close().expect("scope should close cleanly");
        let total = scope_proof.total_reserved;
        crate::assert_with_log!(total == 1, "reserved", 1, total);
        crate::test_complete!("scope_reserve_and_abort_token");
    }

    #[test]
    fn all_four_token_kinds() {
        init_test("all_four_token_kinds");

        // SendPermit
        let t1: SendPermitToken = ObligationToken::reserve("sp");
        let p1 = t1.commit();
        let k1 = p1.kind();
        crate::assert_with_log!(
            k1 == ObligationKind::SendPermit,
            "SendPermit",
            ObligationKind::SendPermit,
            k1
        );

        // Ack
        let t2: AckToken = ObligationToken::reserve("ack");
        let p2 = t2.abort();
        let k2 = p2.kind();
        crate::assert_with_log!(k2 == ObligationKind::Ack, "Ack", ObligationKind::Ack, k2);

        // Lease
        let t3: LeaseToken = ObligationToken::reserve("lease");
        let p3 = t3.commit();
        let k3 = p3.kind();
        crate::assert_with_log!(
            k3 == ObligationKind::Lease,
            "Lease",
            ObligationKind::Lease,
            k3
        );

        // IoOp
        let t4: IoOpToken = ObligationToken::reserve("io");
        let p4 = t4.abort();
        let k4 = p4.kind();
        crate::assert_with_log!(k4 == ObligationKind::IoOp, "IoOp", ObligationKind::IoOp, k4);

        crate::test_complete!("all_four_token_kinds");
    }
}
