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
/// a [`Resolved<K>`] proof token. Dropping without resolving panics.
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
    pub fn on_resolve(&mut self) {
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
}
