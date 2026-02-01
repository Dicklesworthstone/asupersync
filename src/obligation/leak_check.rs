//! Static obligation leak checker via abstract interpretation.
//!
//! Walks a structured obligation IR and detects paths where obligations
//! may be leaked (scope exit while still held).

use crate::record::ObligationKind;
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// ObligationVar
// ============================================================================

/// Identifies an obligation variable in the IR.
///
/// Variables are lightweight handles: `ObligationVar(0)`, `ObligationVar(1)`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObligationVar(pub u32);

impl fmt::Display for ObligationVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ============================================================================
// VarState (Abstract Domain)
// ============================================================================

/// Abstract state of a single obligation variable.
///
/// Lattice for forward dataflow:
/// ```text
///           MayHold(K)
///          /         \
///     Held(K)     Resolved
///          \         /
///           Empty
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarState {
    /// No obligation held.
    Empty,
    /// Definitely holds an obligation of this kind.
    Held(ObligationKind),
    /// May hold an obligation (depends on control flow).
    MayHold(ObligationKind),
    /// May hold an obligation, but the kind is ambiguous (different paths had different kinds).
    MayHoldAmbiguous,
    /// Obligation has been resolved (committed or aborted).
    Resolved,
}

impl VarState {
    /// Join two abstract states (lattice join for forward analysis).
    ///
    /// Used when control flow paths merge (e.g., after an if/else).
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        use VarState::*;
        match (self, other) {
            // Identity cases.
            (Empty, Empty) => Empty,
            (Resolved | Empty, Resolved) | (Resolved, Empty) => Resolved,

            // Same kinds.
            (Held(k1), Held(k2)) if k1 == k2 => Held(k1),
            (MayHold(k1), MayHold(k2)) if k1 == k2 => MayHold(k1),
            (Held(k1), MayHold(k2)) | (MayHold(k2), Held(k1)) if k1 == k2 => MayHold(k1),

            // Held in one path, not in another => MayHold.
            (Held(k) | MayHold(k), Resolved | Empty) | (Resolved | Empty, Held(k) | MayHold(k)) => {
                MayHold(k)
            }

            // Ambiguous cases (mismatched kinds or existing ambiguity).
            (MayHoldAmbiguous, _)
            | (_, MayHoldAmbiguous)
            | (Held(_) | MayHold(_), Held(_) | MayHold(_)) => MayHoldAmbiguous,
        }
    }

    /// Returns true if this state indicates a potential leak.
    #[must_use]
    pub fn is_leak(&self) -> bool {
        matches!(
            self,
            Self::Held(_) | Self::MayHold(_) | Self::MayHoldAmbiguous
        )
    }

    /// Returns the obligation kind, if any.
    #[must_use]
    pub fn kind(&self) -> Option<ObligationKind> {
        match self {
            Self::Held(k) | Self::MayHold(k) => Some(*k),
            Self::Empty | Self::Resolved | Self::MayHoldAmbiguous => None,
        }
    }
}

impl fmt::Display for VarState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty"),
            Self::Held(k) => write!(f, "held({k})"),
            Self::MayHold(k) => write!(f, "may-hold({k})"),
            Self::MayHoldAmbiguous => f.write_str("may-hold(ambiguous)"),
            Self::Resolved => f.write_str("resolved"),
        }
    }
}

// ============================================================================
// Instruction (IR)
// ============================================================================

/// An instruction in the obligation IR.
///
/// The IR is structured (not a CFG): branches are nested, which simplifies
/// the prototype checker while covering the key patterns.
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Reserve an obligation: var becomes `Held(kind)`.
    Reserve {
        /// Variable to bind.
        var: ObligationVar,
        /// Obligation kind.
        kind: ObligationKind,
    },
    /// Commit (resolve) an obligation: var becomes `Resolved`.
    Commit {
        /// Variable to resolve.
        var: ObligationVar,
    },
    /// Abort (resolve) an obligation: var becomes `Resolved`.
    Abort {
        /// Variable to resolve.
        var: ObligationVar,
    },
    /// Conditional branch: each arm is a sequence of instructions.
    /// After the branch, abstract states from all arms are joined.
    Branch {
        /// Branch arms (e.g., if/else = 2 arms, match = N arms).
        arms: Vec<Vec<Self>>,
    },
}

// ============================================================================
// Body
// ============================================================================

/// A function body to check.
///
/// Contains a name (for diagnostics) and a sequence of instructions.
#[derive(Debug, Clone)]
pub struct Body {
    /// Name of the function/scope being checked.
    pub name: String,
    /// Instructions in program order.
    pub instructions: Vec<Instruction>,
}

impl Body {
    /// Creates a new body with the given name and instructions.
    #[must_use]
    pub fn new(name: impl Into<String>, instructions: Vec<Instruction>) -> Self {
        Self {
            name: name.into(),
            instructions,
        }
    }
}

// ============================================================================
// Diagnostics
// ============================================================================

/// Diagnostic severity/kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticKind {
    /// Obligation is definitely leaked (held at scope exit in all paths).
    DefiniteLeak,
    /// Obligation may be leaked (held in some but not all paths).
    PotentialLeak,
    /// Obligation resolved twice.
    DoubleResolve,
    /// Resolve on a variable that was never reserved.
    ResolveUnheld,
}

impl fmt::Display for DiagnosticKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefiniteLeak => f.write_str("definite-leak"),
            Self::PotentialLeak => f.write_str("potential-leak"),
            Self::DoubleResolve => f.write_str("double-resolve"),
            Self::ResolveUnheld => f.write_str("resolve-unheld"),
        }
    }
}

/// A diagnostic emitted by the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// What kind of issue.
    pub kind: DiagnosticKind,
    /// The variable involved.
    pub var: ObligationVar,
    /// The obligation kind, if known.
    pub obligation_kind: Option<ObligationKind>,
    /// The function/scope name where the issue was found.
    pub scope: String,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} in `{}`: {}",
            self.kind, self.var, self.scope, self.message
        )
    }
}

// ============================================================================
// CheckResult
// ============================================================================

/// Result of checking a body.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// The function/scope checked.
    pub scope: String,
    /// Diagnostics found.
    pub diagnostics: Vec<Diagnostic>,
}

impl CheckResult {
    /// Returns true if no issues were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Returns only leak diagnostics (definite + potential).
    #[must_use]
    pub fn leaks(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    DiagnosticKind::DefiniteLeak | DiagnosticKind::PotentialLeak
                )
            })
            .collect()
    }

    /// Returns only double-resolve diagnostics.
    #[must_use]
    pub fn double_resolves(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::DoubleResolve)
            .collect()
    }
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            write!(f, "`{}`: no issues", self.scope)
        } else {
            writeln!(
                f,
                "`{}`: {} diagnostic(s)",
                self.scope,
                self.diagnostics.len()
            )?;
            for d in &self.diagnostics {
                writeln!(f, "  {d}")?;
            }
            Ok(())
        }
    }
}

// ============================================================================
// LeakChecker
// ============================================================================

/// The static obligation leak checker.
///
/// Performs abstract interpretation over a [`Body`] to detect obligation leaks.
/// The checker maintains a map from [`ObligationVar`] to [`VarState`] and walks
/// instructions in order, emitting [`Diagnostic`]s when issues are found.
#[derive(Debug, Default)]
pub struct LeakChecker {
    /// Current abstract state: var → state.
    state: HashMap<ObligationVar, VarState>,
    /// Accumulated diagnostics.
    diagnostics: Vec<Diagnostic>,
    /// Current scope name (for diagnostic messages).
    scope_name: String,
}

impl LeakChecker {
    /// Creates a new checker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a body for obligation leaks.
    ///
    /// Returns a [`CheckResult`] with any diagnostics found. The checker
    /// is reset before each invocation, so it can be reused across bodies.
    #[must_use]
    pub fn check(&mut self, body: &Body) -> CheckResult {
        self.state.clear();
        self.diagnostics.clear();
        self.scope_name.clone_from(&body.name);

        self.check_instructions(&body.instructions);
        self.check_exit_leaks();

        CheckResult {
            scope: body.name.clone(),
            diagnostics: self.diagnostics.clone(),
        }
    }

    fn check_instructions(&mut self, instructions: &[Instruction]) {
        for instr in instructions {
            self.check_instruction(instr);
        }
    }

    fn check_instruction(&mut self, instr: &Instruction) {
        match instr {
            Instruction::Reserve { var, kind } => {
                // If var already holds an obligation, that's a leak (overwrite).
                if let Some(existing) = self.state.get(var) {
                    if existing.is_leak() {
                        self.diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::DefiniteLeak,
                            var: *var,
                            obligation_kind: existing.kind(),
                            scope: self.scope_name.clone(),
                            message: format!(
                                "{var} already holds {}, overwriting with new {} reserve",
                                existing,
                                kind.as_str(),
                            ),
                        });
                    }
                }
                self.state.insert(*var, VarState::Held(*kind));
            }

            Instruction::Commit { var } | Instruction::Abort { var } => {
                let action = if matches!(instr, Instruction::Commit { .. }) {
                    "commit"
                } else {
                    "abort"
                };
                match self.state.get(var) {
                    Some(VarState::Held(_) | VarState::MayHold(_) | VarState::MayHoldAmbiguous) => {
                        self.state.insert(*var, VarState::Resolved);
                    }
                    Some(VarState::Resolved) => {
                        self.diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::DoubleResolve,
                            var: *var,
                            obligation_kind: None,
                            scope: self.scope_name.clone(),
                            message: format!("{var} already resolved, {action} is redundant/error"),
                        });
                    }
                    Some(VarState::Empty) | None => {
                        self.diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::ResolveUnheld,
                            var: *var,
                            obligation_kind: None,
                            scope: self.scope_name.clone(),
                            message: format!("{var} was never reserved, cannot {action}"),
                        });
                    }
                }
            }

            Instruction::Branch { arms } => {
                self.check_branch(arms);
            }
        }
    }

    fn check_branch(&mut self, arms: &[Vec<Instruction>]) {
        if arms.is_empty() {
            return;
        }

        let entry_state = self.state.clone();
        let mut arm_states: Vec<HashMap<ObligationVar, VarState>> = Vec::new();

        // Analyze each arm independently, starting from the entry state.
        for arm in arms {
            self.state.clone_from(&entry_state);
            self.check_instructions(arm);
            arm_states.push(self.state.clone());
        }

        // Join all arm exit states.
        self.state = Self::join_states(&arm_states);
    }

    fn join_states(
        states: &[HashMap<ObligationVar, VarState>],
    ) -> HashMap<ObligationVar, VarState> {
        if states.is_empty() {
            return HashMap::new();
        }
        if states.len() == 1 {
            return states[0].clone();
        }

        // Collect all vars across all arms.
        let all_vars: HashSet<ObligationVar> =
            states.iter().flat_map(|s| s.keys().copied()).collect();

        let mut result = HashMap::new();
        for var in all_vars {
            let mut joined = states[0].get(&var).copied().unwrap_or(VarState::Empty);
            for s in &states[1..] {
                let other = s.get(&var).copied().unwrap_or(VarState::Empty);
                joined = joined.join(other);
            }
            result.insert(var, joined);
        }

        result
    }

    fn check_exit_leaks(&mut self) {
        // Collect vars and sort by index for deterministic output.
        let mut vars: Vec<(ObligationVar, VarState)> =
            self.state.iter().map(|(v, s)| (*v, *s)).collect();
        vars.sort_by_key(|(v, _)| v.0);

        for (var, state) in vars {
            match state {
                VarState::Held(kind) => {
                    self.diagnostics.push(Diagnostic {
                        kind: DiagnosticKind::DefiniteLeak,
                        var,
                        obligation_kind: Some(kind),
                        scope: self.scope_name.clone(),
                        message: format!("{var} holds {} obligation at scope exit", kind.as_str(),),
                    });
                }
                VarState::MayHold(kind) => {
                    self.diagnostics.push(Diagnostic {
                        kind: DiagnosticKind::PotentialLeak,
                        var,
                        obligation_kind: Some(kind),
                        scope: self.scope_name.clone(),
                        message: format!(
                            "{var} may hold {} obligation at scope exit (depends on control flow)",
                            kind.as_str(),
                        ),
                    });
                }
                VarState::MayHoldAmbiguous => {
                    self.diagnostics.push(Diagnostic {
                        kind: DiagnosticKind::PotentialLeak,
                        var,
                        obligation_kind: None,
                        scope: self.scope_name.clone(),
                        message: format!(
                            "{var} may hold an ambiguous obligation at scope exit (different kinds on different paths)",
                        ),
                    });
                }
                VarState::Empty | VarState::Resolved => {}
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn v(n: u32) -> ObligationVar {
        ObligationVar(n)
    }

    // ---- Clean paths -------------------------------------------------------

    #[test]
    fn clean_reserve_commit() {
        init_test("clean_reserve_commit");
        let body = Body::new(
            "clean_fn",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_reserve_commit");
    }

    #[test]
    fn clean_reserve_abort() {
        init_test("clean_reserve_abort");
        let body = Body::new(
            "clean_abort",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Ack,
                },
                Instruction::Abort { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_reserve_abort");
    }

    #[test]
    fn clean_branch_both_resolve() {
        init_test("clean_branch_both_resolve");
        let body = Body::new(
            "clean_branch",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_branch_both_resolve");
    }

    #[test]
    fn clean_multiple_obligations() {
        init_test("clean_multiple_obligations");
        let body = Body::new(
            "multi_clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Commit { var: v(0) },
                Instruction::Commit { var: v(1) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_multiple_obligations");
    }

    // ---- Definite leaks ----------------------------------------------------

    #[test]
    fn definite_leak_no_resolve() {
        init_test("definite_leak_no_resolve");
        let body = Body::new(
            "leaky_fn",
            vec![Instruction::Reserve {
                var: v(0),
                kind: ObligationKind::SendPermit,
            }],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::DefiniteLeak,
            "kind",
            "definite-leak",
            kind
        );
        let obl_kind = leaks[0].obligation_kind;
        crate::assert_with_log!(
            obl_kind == Some(ObligationKind::SendPermit),
            "obligation_kind",
            Some(ObligationKind::SendPermit),
            obl_kind
        );
        crate::test_complete!("definite_leak_no_resolve");
    }

    #[test]
    fn definite_leak_multiple_vars() {
        init_test("definite_leak_multiple_vars");
        let body = Body::new(
            "double_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::IoOp,
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 2, "leak count", 2, len);
        // Deterministic order: v0, v1.
        let var0 = leaks[0].var;
        crate::assert_with_log!(var0 == v(0), "var0", v(0), var0);
        let var1 = leaks[1].var;
        crate::assert_with_log!(var1 == v(1), "var1", v(1), var1);
        crate::test_complete!("definite_leak_multiple_vars");
    }

    // ---- Potential leaks (branch-dependent) --------------------------------

    #[test]
    fn potential_leak_one_arm_missing_resolve() {
        init_test("potential_leak_one_arm");
        let body = Body::new(
            "branch_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Ack,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![], // No resolve in this arm.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("potential_leak_one_arm");
    }

    #[test]
    fn potential_leak_three_arms_one_missing() {
        init_test("potential_leak_three_arms");
        let body = Body::new(
            "match_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                        vec![], // Missing resolve.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("potential_leak_three_arms");
    }

    // ---- Double resolve ----------------------------------------------------

    #[test]
    fn double_resolve_detected() {
        init_test("double_resolve_detected");
        let body = Body::new(
            "double_resolve",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let doubles = result.double_resolves();
        let len = doubles.len();
        crate::assert_with_log!(len == 1, "double count", 1, len);
        let leaks = result.leaks();
        let leak_len = leaks.len();
        crate::assert_with_log!(leak_len == 0, "no leaks", 0, leak_len);
        crate::test_complete!("double_resolve_detected");
    }

    // ---- Resolve unheld ----------------------------------------------------

    #[test]
    fn resolve_unheld_detected() {
        init_test("resolve_unheld_detected");
        let body = Body::new("resolve_unheld", vec![Instruction::Commit { var: v(0) }]);

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let first_kind = &result.diagnostics[0].kind;
        crate::assert_with_log!(
            *first_kind == DiagnosticKind::ResolveUnheld,
            "kind",
            "resolve-unheld",
            first_kind
        );
        crate::test_complete!("resolve_unheld_detected");
    }

    // ---- Overwrite leak (reserve over held) --------------------------------

    #[test]
    fn overwrite_leak_detected() {
        init_test("overwrite_leak_detected");
        let body = Body::new(
            "overwrite",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                // Overwrite without resolving first.
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        // Should detect the overwrite-leak.
        let leak_count = result
            .diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::DefiniteLeak)
            .count();
        crate::assert_with_log!(leak_count == 1, "overwrite leak", 1, leak_count);
        // The second obligation is committed, so no exit leak.
        crate::test_complete!("overwrite_leak_detected");
    }

    // ---- Nested branches ---------------------------------------------------

    #[test]
    fn nested_branch_clean() {
        init_test("nested_branch_clean");
        let body = Body::new(
            "nested_clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Branch {
                            arms: vec![
                                vec![Instruction::Commit { var: v(0) }],
                                vec![Instruction::Abort { var: v(0) }],
                            ],
                        }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("nested_branch_clean");
    }

    #[test]
    fn nested_branch_leak() {
        init_test("nested_branch_leak");
        let body = Body::new(
            "nested_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Branch {
                            arms: vec![
                                vec![Instruction::Commit { var: v(0) }],
                                vec![], // Nested leak path.
                            ],
                        }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("nested_branch_leak");
    }

    // ---- Realistic: channel send permit pattern ----------------------------

    #[test]
    fn realistic_channel_send_permit() {
        init_test("realistic_channel_send_permit");
        // Models the two-phase send pattern:
        //   let permit = channel.reserve_send();  // Reserve
        //   if condition {
        //     permit.send(data);                  // Commit
        //   } else {
        //     permit.cancel();                    // Abort
        //   }
        let body = Body::new(
            "channel_send",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean send permit", true, is_clean);
        crate::test_complete!("realistic_channel_send_permit");
    }

    #[test]
    fn realistic_leaky_send_permit() {
        init_test("realistic_leaky_send_permit");
        // Models a buggy pattern where the error path forgets to cancel:
        //   let permit = channel.reserve_send();
        //   if ok {
        //     permit.send(data);
        //   } else {
        //     log_error();  // BUG: forgot to cancel permit
        //   }
        let body = Body::new(
            "leaky_send",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![], // Bug: no cancel on error path.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        eprintln!("{result}");
        crate::test_complete!("realistic_leaky_send_permit");
    }

    // ---- Realistic: I/O operation with timeout and cancel ------------------

    #[test]
    fn realistic_io_with_timeout() {
        init_test("realistic_io_with_timeout");
        // Models:
        //   let io = reserve_io();
        //   match race(io_complete, timeout) {
        //     IoComplete => io.commit(),
        //     Timeout => io.abort(),
        //     Cancel => io.abort(),
        //   }
        let body = Body::new(
            "io_timeout",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("realistic_io_with_timeout");
    }

    // ---- Realistic: lease with nested region close -------------------------

    #[test]
    fn realistic_lease_pattern() {
        init_test("realistic_lease_pattern");
        // Models a lease pattern with multiple obligations:
        //   let lease = acquire_lease();         // v0: Lease
        //   let ack = receive_message();          // v1: Ack
        //   process(data);
        //   ack.acknowledge();                    // commit v1
        //   lease.release();                      // commit v0
        let body = Body::new(
            "lease_and_ack",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Ack,
                },
                Instruction::Commit { var: v(1) },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("realistic_lease_pattern");
    }

    #[test]
    fn realistic_lease_leak_on_error() {
        init_test("realistic_lease_leak_on_error");
        // Models a buggy lease pattern: error during processing leaks the lease.
        //   let lease = acquire_lease();         // v0: Lease
        //   let ack = receive_message();          // v1: Ack
        //   if error {
        //     ack.reject();                       // abort v1
        //     // BUG: forgot to release lease
        //   } else {
        //     process(data);
        //     ack.acknowledge();                  // commit v1
        //     lease.release();                    // commit v0
        //   }
        let body = Body::new(
            "lease_error_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Ack,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![
                            Instruction::Abort { var: v(1) },
                            // BUG: v0 not resolved.
                        ],
                        vec![
                            Instruction::Commit { var: v(1) },
                            Instruction::Commit { var: v(0) },
                        ],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let leaked_var = leaks[0].var;
        crate::assert_with_log!(leaked_var == v(0), "leaked var", v(0), leaked_var);
        let leaked_kind = leaks[0].obligation_kind;
        crate::assert_with_log!(
            leaked_kind == Some(ObligationKind::Lease),
            "leaked kind",
            Some(ObligationKind::Lease),
            leaked_kind
        );
        eprintln!("{result}");
        crate::test_complete!("realistic_lease_leak_on_error");
    }

    // ---- Checker reuse -----------------------------------------------------

    #[test]
    fn checker_reuse_across_bodies() {
        init_test("checker_reuse_across_bodies");
        let mut checker = LeakChecker::new();

        let clean_body = Body::new(
            "clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
            ],
        );
        let r1 = checker.check(&clean_body);
        let is_clean = r1.is_clean();
        crate::assert_with_log!(is_clean, "first clean", true, is_clean);

        let leaky_body = Body::new(
            "leaky",
            vec![Instruction::Reserve {
                var: v(0),
                kind: ObligationKind::Lease,
            }],
        );
        let r2 = checker.check(&leaky_body);
        let is_clean2 = r2.is_clean();
        crate::assert_with_log!(!is_clean2, "second leaky", false, is_clean2);

        // Check that first result was not contaminated.
        let first_leaks = r1.leaks().len();
        crate::assert_with_log!(first_leaks == 0, "first still clean", 0, first_leaks);
        crate::test_complete!("checker_reuse_across_bodies");
    }

    // ---- Deterministic output ----------------------------------------------

    #[test]
    fn deterministic_diagnostic_order() {
        init_test("deterministic_diagnostic_order");
        // Multiple leaks should be reported in variable-index order.
        let body = Body::new(
            "multi_leak",
            vec![
                Instruction::Reserve {
                    var: v(2),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Lease,
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 3, "leak count", 3, len);
        let vars: Vec<u32> = leaks.iter().map(|d| d.var.0).collect();
        crate::assert_with_log!(vars == vec![0, 1, 2], "order", vec![0u32, 1, 2], vars);
        crate::test_complete!("deterministic_diagnostic_order");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("display_impls");
        let var = ObligationVar(42);
        let var_str = format!("{var}");
        crate::assert_with_log!(var_str == "v42", "var display", "v42", var_str);

        let state = VarState::Held(ObligationKind::SendPermit);
        let state_str = format!("{state}");
        crate::assert_with_log!(
            state_str == "held(send_permit)",
            "state display",
            "held(send_permit)",
            state_str
        );

        let diag = Diagnostic {
            kind: DiagnosticKind::DefiniteLeak,
            var: ObligationVar(0),
            obligation_kind: Some(ObligationKind::SendPermit),
            scope: "test_fn".to_string(),
            message: "v0 leaked".to_string(),
        };
        let diag_str = format!("{diag}");
        let has_fn = diag_str.contains("test_fn");
        crate::assert_with_log!(has_fn, "diag has scope", true, has_fn);
        let has_kind = diag_str.contains("definite-leak");
        crate::assert_with_log!(has_kind, "diag has kind", true, has_kind);
        crate::test_complete!("display_impls");
    }

    // ---- VarState lattice join exhaustive ----------------------------------

    #[test]
    fn var_state_join_lattice() {
        init_test("var_state_join_lattice");
        let k = ObligationKind::SendPermit;
        let k2 = ObligationKind::IoOp;

        // Identity.
        let r = VarState::Empty.join(VarState::Empty);
        crate::assert_with_log!(r == VarState::Empty, "e+e", VarState::Empty, r);
        let r = VarState::Resolved.join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::Resolved, "r+r", VarState::Resolved, r);
        let r = VarState::Held(k).join(VarState::Held(k));
        crate::assert_with_log!(r == VarState::Held(k), "h+h", VarState::Held(k), r);

        // Held + Resolved => MayHold.
        let r = VarState::Held(k).join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::MayHold(k), "h+r", VarState::MayHold(k), r);

        // Held + Empty => MayHold.
        let r = VarState::Held(k).join(VarState::Empty);
        crate::assert_with_log!(r == VarState::MayHold(k), "h+e", VarState::MayHold(k), r);

        // Resolved + Empty => Resolved.
        let r = VarState::Resolved.join(VarState::Empty);
        crate::assert_with_log!(r == VarState::Resolved, "r+e", VarState::Resolved, r);

        // MayHold propagates.
        let r = VarState::MayHold(k).join(VarState::Empty);
        crate::assert_with_log!(r == VarState::MayHold(k), "m+e", VarState::MayHold(k), r);
        let r = VarState::MayHold(k).join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::MayHold(k), "m+r", VarState::MayHold(k), r);

        // Different kinds => MayHold.
        let r = VarState::Held(k).join(VarState::Held(k2));
        let is_may = matches!(r, VarState::MayHold(_));
        crate::assert_with_log!(is_may, "h(k1)+h(k2)", true, is_may);

        // Commutativity check.
        let r1 = VarState::Held(k).join(VarState::Resolved);
        let r2 = VarState::Resolved.join(VarState::Held(k));
        crate::assert_with_log!(r1 == r2, "commutative", r1, r2);

        crate::test_complete!("var_state_join_lattice");
    }

    // ---- Empty body --------------------------------------------------------

    #[test]
    fn empty_body_is_clean() {
        init_test("empty_body_is_clean");
        let body = Body::new("empty", vec![]);
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("empty_body_is_clean");
    }

    // ---- CheckResult display -----------------------------------------------

    #[test]
    fn check_result_display() {
        init_test("check_result_display");
        let clean = CheckResult {
            scope: "clean_fn".to_string(),
            diagnostics: vec![],
        };
        let clean_str = format!("{clean}");
        let has_no_issues = clean_str.contains("no issues");
        crate::assert_with_log!(has_no_issues, "clean display", true, has_no_issues);

        let dirty = CheckResult {
            scope: "dirty_fn".to_string(),
            diagnostics: vec![Diagnostic {
                kind: DiagnosticKind::DefiniteLeak,
                var: v(0),
                obligation_kind: Some(ObligationKind::SendPermit),
                scope: "dirty_fn".to_string(),
                message: "test".to_string(),
            }],
        };
        let dirty_str = format!("{dirty}");
        let has_count = dirty_str.contains("1 diagnostic");
        crate::assert_with_log!(has_count, "dirty display", true, has_count);
        crate::test_complete!("check_result_display");
    }
}
