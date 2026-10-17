//! Static obligation leak checker via abstract interpretation.
//!
//! Walks a structured obligation IR and detects paths where obligations
//! may be leaked (scope exit while still held).

use crate::record::ObligationKind;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ============================================================================
// ObligationVar
// ============================================================================

/// Identifies an obligation variable in the IR.
///
/// Variables are lightweight handles: `ObligationVar(0)`, `ObligationVar(1)`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        use VarState::{Empty, Held, MayHold, MayHoldAmbiguous, Resolved};
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

/// Stable machine-readable diagnostic codes for CI/logging consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// Obligation definitely leaked at scope exit.
    LeakExitDefinite,
    /// Obligation may leak depending on control flow.
    LeakExitPotential,
    /// A live obligation was overwritten by a new reserve on the same variable.
    OverwriteActive,
    /// The same obligation was resolved more than once.
    DoubleResolve,
    /// A resolve was attempted on a variable that never held an obligation.
    ResolveUnheld,
}

impl DiagnosticCode {
    /// Stable string code for structured diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeakExitDefinite => "OBL-STATIC-LEAK-EXIT-DEFINITE",
            Self::LeakExitPotential => "OBL-STATIC-LEAK-EXIT-POTENTIAL",
            Self::OverwriteActive => "OBL-STATIC-OVERWRITE-ACTIVE",
            Self::DoubleResolve => "OBL-STATIC-DOUBLE-RESOLVE",
            Self::ResolveUnheld => "OBL-STATIC-RESOLVE-UNHELD",
        }
    }

    /// Deterministic remediation hint paired with the code.
    #[must_use]
    pub const fn remediation_hint(self) -> &'static str {
        match self {
            Self::LeakExitDefinite => {
                "Resolve the obligation before scope exit by committing or aborting it."
            }
            Self::LeakExitPotential => {
                "Ensure every branch resolves the obligation or makes ownership transfer explicit."
            }
            Self::OverwriteActive => {
                "Resolve or move the existing obligation before reusing the same variable."
            }
            Self::DoubleResolve => {
                "Remove the duplicate commit/abort so each obligation is consumed exactly once."
            }
            Self::ResolveUnheld => {
                "Only resolve variables that were reserved on the current analyzed path."
            }
        }
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Distinguishes concrete instruction diagnostics from scope-exit findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLocationKind {
    /// The issue is attached to a specific instruction in the structured IR.
    Instruction,
    /// The issue is attached to scope exit after control-flow joining.
    ScopeExit,
}

impl fmt::Display for DiagnosticLocationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instruction => f.write_str("instruction"),
            Self::ScopeExit => f.write_str("scope_exit"),
        }
    }
}

/// Stable location inside the structured obligation IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticLocation {
    /// Whether the location refers to a concrete instruction or scope exit.
    pub kind: DiagnosticLocationKind,
    /// Nested instruction indices from the root body to the current instruction.
    pub instruction_path: Vec<usize>,
    /// Branch-arm selections taken between each nested instruction index.
    pub branch_arms: Vec<usize>,
}

impl DiagnosticLocation {
    /// Location for a concrete IR instruction.
    #[must_use]
    pub fn instruction(instruction_path: Vec<usize>, branch_arms: Vec<usize>) -> Self {
        Self {
            kind: DiagnosticLocationKind::Instruction,
            instruction_path,
            branch_arms,
        }
    }

    /// Location for a scope-exit diagnostic after control-flow joins.
    #[must_use]
    pub fn scope_exit() -> Self {
        Self {
            kind: DiagnosticLocationKind::ScopeExit,
            instruction_path: Vec::new(),
            branch_arms: Vec::new(),
        }
    }
}

impl fmt::Display for DiagnosticLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DiagnosticLocationKind::ScopeExit => f.write_str("scope_exit"),
            DiagnosticLocationKind::Instruction => {
                f.write_str("instruction:")?;
                if let Some(first) = self.instruction_path.first() {
                    write!(f, "i{first}")?;
                    for (depth, index) in self.instruction_path.iter().enumerate().skip(1) {
                        let arm = self.branch_arms.get(depth - 1).copied().unwrap_or_default();
                        write!(f, "/a{arm}/i{index}")?;
                    }
                } else {
                    f.write_str("root")?;
                }
                Ok(())
            }
        }
    }
}

/// Explicit scope and non-goals for the restricted static leak checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLeakCheckContract {
    /// Stable identifier for the current restricted pilot.
    pub checker_id: &'static str,
    /// Structured IR surface covered by the checker.
    pub ir_surface: &'static str,
    /// Supported IR instructions in the prototype.
    pub supported_instructions: &'static [&'static str],
    /// Stable machine-readable codes emitted by the checker.
    pub diagnostic_codes: &'static [&'static str],
    /// Patterns intentionally covered by the pilot.
    pub in_scope_patterns: &'static [&'static str],
    /// Patterns intentionally left to runtime or future analyses.
    pub out_of_scope_patterns: &'static [&'static str],
    /// Runtime enforcement/oracle surfaces that remain authoritative.
    pub runtime_oracles: &'static [&'static str],
    /// Guidance for interpreting clean/dirty results conservatively.
    pub interpretation_guidance: &'static [&'static str],
}

/// Contract for the restricted structured-IR static leak-checker pilot.
#[must_use]
pub const fn static_leak_check_contract() -> StaticLeakCheckContract {
    StaticLeakCheckContract {
        checker_id: "obligation-static-leak-checker-v1",
        ir_surface: "Body with Instruction::{Reserve, Commit, Abort, Branch}",
        supported_instructions: &["Reserve", "Commit", "Abort", "Branch"],
        diagnostic_codes: &[
            "OBL-STATIC-LEAK-EXIT-DEFINITE",
            "OBL-STATIC-LEAK-EXIT-POTENTIAL",
            "OBL-STATIC-OVERWRITE-ACTIVE",
            "OBL-STATIC-DOUBLE-RESOLVE",
            "OBL-STATIC-RESOLVE-UNHELD",
        ],
        in_scope_patterns: &[
            "single-body reserve/commit-or-abort flows",
            "branch-sensitive resolution on structured if/match-style control flow",
            "conservative peak outstanding-obligation counting on the same structured IR",
        ],
        out_of_scope_patterns: &[
            "loops/recursion without explicit unrolling into the IR",
            "interprocedural aliasing, borrowing, or ownership transfer not represented in Body",
            "ambient Drop-based cleanup or runtime side effects outside the IR",
            "Rust-source parsing, macro expansion, and dynamic dispatch analysis",
        ],
        runtime_oracles: &[
            "RuntimeObligationValidator live reserve/commit/abort hook API",
            "src/obligation/ledger.rs",
            "src/obligation/marking.rs",
            "src/obligation/no_leak_proof.rs",
            "src/obligation/graded.rs",
        ],
        interpretation_guidance: &[
            "clean results apply only to the supplied structured IR, not arbitrary Rust code",
            "graded budget counts are conservative upper bounds for the restricted IR, not admission proofs",
            "runtime oracles remain authoritative for uncovered patterns and production enforcement",
        ],
    }
}

/// Conservative budget summary for the restricted structured-IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradedBudgetSummary {
    /// Maximum simultaneously-live obligations observed across all analyzed paths.
    pub conservative_peak_outstanding: usize,
    /// Outstanding obligations that may remain at scope exit after path joins.
    pub exit_outstanding_upper_bound: usize,
    /// Per-kind peak simultaneously-live obligation counts.
    pub peak_outstanding_by_kind: BTreeMap<ObligationKind, usize>,
    /// Peak count of ambiguous obligations where kind information was lost by joins.
    pub ambiguous_peak_outstanding: usize,
    /// Guidance for interpreting the budget summary conservatively.
    pub interpretation: &'static str,
}

impl Default for GradedBudgetSummary {
    fn default() -> Self {
        Self {
            conservative_peak_outstanding: 0,
            exit_outstanding_upper_bound: 0,
            peak_outstanding_by_kind: BTreeMap::new(),
            ambiguous_peak_outstanding: 0,
            interpretation: "Conservative upper bounds over the structured IR only; runtime oracles remain authoritative outside this restricted pilot.",
        }
    }
}

/// A diagnostic emitted by the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable machine-readable code for logs/CI.
    pub code: DiagnosticCode,
    /// What kind of issue.
    pub kind: DiagnosticKind,
    /// The variable involved.
    pub var: ObligationVar,
    /// The obligation kind, if known.
    pub obligation_kind: Option<ObligationKind>,
    /// Stable location in the structured IR.
    pub location: DiagnosticLocation,
    /// The function/scope name where the issue was found.
    pub scope: String,
    /// Deterministic remediation hint for the issue class.
    pub remediation_hint: &'static str,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}/{} @ {}] {} in `{}`: {} | hint: {}",
            self.kind,
            self.code,
            self.location,
            self.var,
            self.scope,
            self.message,
            self.remediation_hint
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
    /// Explicit boundary for what the prototype checker does and does not prove.
    pub contract: StaticLeakCheckContract,
    /// Conservative outstanding-obligation budget summary over the same IR.
    pub graded_budget: GradedBudgetSummary,
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
    state: BTreeMap<ObligationVar, VarState>,
    /// Accumulated diagnostics.
    diagnostics: Vec<Diagnostic>,
    /// Current scope name (for diagnostic messages).
    scope_name: String,
    /// Conservative peak simultaneously-outstanding obligations across explored paths.
    peak_outstanding: usize,
    /// Conservative per-kind outstanding peaks.
    peak_outstanding_by_kind: BTreeMap<ObligationKind, usize>,
    /// Peak ambiguous outstanding obligations after kind-losing joins.
    peak_ambiguous_outstanding: usize,
    /// May-hold variables that some joined path had already resolved: only
    /// these make a later commit or abort a potential double resolve.
    may_be_resolved: BTreeSet<ObligationVar>,
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
        self.peak_outstanding = 0;
        self.peak_outstanding_by_kind.clear();
        self.peak_ambiguous_outstanding = 0;
        self.may_be_resolved.clear();
        self.record_budget_snapshot();

        self.check_instructions(&body.instructions, &[], &[]);
        self.check_exit_leaks();

        self.check_result()
    }

    fn check_instructions(
        &mut self,
        instructions: &[Instruction],
        instruction_prefix: &[usize],
        branch_arms: &[usize],
    ) {
        for (index, instr) in instructions.iter().enumerate() {
            let mut instruction_path = instruction_prefix.to_vec();
            instruction_path.push(index);
            self.check_instruction(instr, &instruction_path, branch_arms);
            self.record_budget_snapshot();
        }
    }

    fn check_instruction(
        &mut self,
        instr: &Instruction,
        instruction_path: &[usize],
        branch_arms: &[usize],
    ) {
        let location =
            DiagnosticLocation::instruction(instruction_path.to_vec(), branch_arms.to_vec());
        match instr {
            Instruction::Reserve { var, kind } => {
                // If var already holds an obligation, that's a leak (overwrite).
                if let Some(existing) = self.state.get(var) {
                    if existing.is_leak() {
                        let diagnostic_kind = if matches!(existing, VarState::Held(_)) {
                            DiagnosticKind::DefiniteLeak
                        } else {
                            DiagnosticKind::PotentialLeak
                        };
                        self.push_diagnostic(
                            DiagnosticCode::OverwriteActive,
                            diagnostic_kind,
                            *var,
                            existing.kind(),
                            location,
                            format!(
                                "{var} already holds {}, overwriting with new {} reserve",
                                existing,
                                kind.as_str(),
                            ),
                        );
                    }
                }
                self.state.insert(*var, VarState::Held(*kind));
                self.may_be_resolved.remove(var);
            }

            Instruction::Commit { var } | Instruction::Abort { var } => {
                let action = if matches!(instr, Instruction::Commit { .. }) {
                    "commit"
                } else {
                    "abort"
                };
                match self.state.get(var) {
                    Some(VarState::Held(_)) => {
                        self.state.insert(*var, VarState::Resolved);
                    }
                    Some(VarState::MayHold(_) | VarState::MayHoldAmbiguous) => {
                        // Only a path that already resolved the variable makes
                        // this a double resolve. With reservations of different
                        // kinds on each path (MayHoldAmbiguous), every path holds
                        // exactly one live obligation. With a reservation on
                        // only some paths, the others commit nothing; that is
                        // not reported either, as in v0.4.3.
                        if self.may_be_resolved.remove(var) {
                            self.push_diagnostic(
                                DiagnosticCode::DoubleResolve,
                                DiagnosticKind::DoubleResolve,
                                *var,
                                self.state.get(var).and_then(VarState::kind),
                                location,
                                format!(
                                    "{var} may already be resolved, {action} is a potential double resolve"
                                ),
                            );
                        }
                        self.state.insert(*var, VarState::Resolved);
                    }
                    Some(VarState::Resolved) => {
                        self.push_diagnostic(
                            DiagnosticCode::DoubleResolve,
                            DiagnosticKind::DoubleResolve,
                            *var,
                            None,
                            location,
                            format!("{var} already resolved, {action} is redundant/error"),
                        );
                    }
                    Some(VarState::Empty) | None => {
                        self.push_diagnostic(
                            DiagnosticCode::ResolveUnheld,
                            DiagnosticKind::ResolveUnheld,
                            *var,
                            None,
                            location,
                            format!("{var} was never reserved, cannot {action}"),
                        );
                    }
                }
            }

            Instruction::Branch { arms } => {
                self.check_branch(arms, instruction_path, branch_arms);
            }
        }
    }

    fn check_branch(
        &mut self,
        arms: &[Vec<Instruction>],
        parent_instruction_path: &[usize],
        parent_branch_arms: &[usize],
    ) {
        if arms.is_empty() {
            return;
        }

        let entry_state = self.state.clone();
        let entry_may_be_resolved = self.may_be_resolved.clone();
        let mut arm_states: Vec<BTreeMap<ObligationVar, VarState>> = Vec::new();
        let mut arm_may_be_resolved: Vec<BTreeSet<ObligationVar>> = Vec::new();

        // Analyze each arm independently, starting from the entry state.
        for (arm_index, arm) in arms.iter().enumerate() {
            self.state.clone_from(&entry_state);
            self.may_be_resolved.clone_from(&entry_may_be_resolved);
            let mut branch_path = parent_branch_arms.to_vec();
            branch_path.push(arm_index);
            self.check_instructions(arm, parent_instruction_path, &branch_path);
            arm_states.push(self.state.clone());
            arm_may_be_resolved.push(self.may_be_resolved.clone());
        }

        // Join all arm exit states.
        self.state = Self::join_states(&arm_states);
        // A joined may-hold variable may already be resolved if some arm
        // resolved it, or carried that doubt from a nested join.
        self.may_be_resolved = self
            .state
            .iter()
            .filter(|(_, joined)| {
                matches!(joined, VarState::MayHold(_) | VarState::MayHoldAmbiguous)
            })
            .filter(|&(var, _)| {
                arm_states
                    .iter()
                    .zip(&arm_may_be_resolved)
                    .any(|(arm, doubt)| {
                        arm.get(var) == Some(&VarState::Resolved) || doubt.contains(var)
                    })
            })
            .map(|(var, _)| *var)
            .collect();
    }

    fn join_states(
        states: &[BTreeMap<ObligationVar, VarState>],
    ) -> BTreeMap<ObligationVar, VarState> {
        if states.is_empty() {
            return BTreeMap::new();
        }
        if states.len() == 1 {
            return states[0].clone();
        }

        // Collect all vars across all arms.
        let all_vars: BTreeSet<ObligationVar> =
            states.iter().flat_map(|s| s.keys().copied()).collect();

        let mut result = BTreeMap::new();
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
                    self.push_diagnostic(
                        DiagnosticCode::LeakExitDefinite,
                        DiagnosticKind::DefiniteLeak,
                        var,
                        Some(kind),
                        DiagnosticLocation::scope_exit(),
                        format!("{var} holds {} obligation at scope exit", kind.as_str()),
                    );
                }
                VarState::MayHold(kind) => {
                    self.push_diagnostic(
                        DiagnosticCode::LeakExitPotential,
                        DiagnosticKind::PotentialLeak,
                        var,
                        Some(kind),
                        DiagnosticLocation::scope_exit(),
                        format!(
                            "{var} may hold {} obligation at scope exit (depends on control flow)",
                            kind.as_str(),
                        ),
                    );
                }
                VarState::MayHoldAmbiguous => {
                    self.push_diagnostic(
                        DiagnosticCode::LeakExitPotential,
                        DiagnosticKind::PotentialLeak,
                        var,
                        None,
                        DiagnosticLocation::scope_exit(),
                        format!(
                            "{var} may hold an ambiguous obligation at scope exit (different kinds on different paths)",
                        ),
                    );
                }
                VarState::Empty | VarState::Resolved => {}
            }
        }
    }

    fn push_diagnostic(
        &mut self,
        code: DiagnosticCode,
        kind: DiagnosticKind,
        var: ObligationVar,
        obligation_kind: Option<ObligationKind>,
        location: DiagnosticLocation,
        message: String,
    ) {
        self.diagnostics.push(Diagnostic {
            code,
            kind,
            var,
            obligation_kind,
            location,
            scope: self.scope_name.clone(),
            remediation_hint: code.remediation_hint(),
            message,
        });
    }

    fn record_budget_snapshot(&mut self) {
        let mut outstanding = 0usize;
        let mut outstanding_by_kind = BTreeMap::new();
        let mut ambiguous_outstanding = 0usize;

        for state in self.state.values() {
            match state {
                VarState::Held(kind) | VarState::MayHold(kind) => {
                    outstanding += 1;
                    *outstanding_by_kind.entry(*kind).or_insert(0usize) += 1;
                }
                VarState::MayHoldAmbiguous => {
                    outstanding += 1;
                    ambiguous_outstanding += 1;
                }
                VarState::Empty | VarState::Resolved => {}
            }
        }

        self.peak_outstanding = self.peak_outstanding.max(outstanding);
        self.peak_ambiguous_outstanding =
            self.peak_ambiguous_outstanding.max(ambiguous_outstanding);
        for (kind, count) in outstanding_by_kind {
            self.peak_outstanding_by_kind
                .entry(kind)
                .and_modify(|peak| *peak = (*peak).max(count))
                .or_insert(count);
        }
    }

    fn graded_budget_summary(&self) -> GradedBudgetSummary {
        GradedBudgetSummary {
            conservative_peak_outstanding: self.peak_outstanding,
            exit_outstanding_upper_bound: self
                .state
                .values()
                .filter(|state| state.is_leak())
                .count(),
            peak_outstanding_by_kind: self.peak_outstanding_by_kind.clone(),
            ambiguous_peak_outstanding: self.peak_ambiguous_outstanding,
            ..GradedBudgetSummary::default()
        }
    }

    fn check_result(&self) -> CheckResult {
        CheckResult {
            scope: self.scope_name.clone(),
            diagnostics: self.diagnostics.clone(),
            contract: static_leak_check_contract(),
            graded_budget: self.graded_budget_summary(),
        }
    }
}

// ============================================================================
// RuntimeObligationValidator
// ============================================================================

/// Runtime hook surface for validating observed obligation transitions.
///
/// The static checker verifies a complete structured [`Body`]. This validator
/// applies the same transition rules to the concrete reserve/commit/abort events
/// emitted by a live path, then checks pending obligations when [`Self::finish`]
/// is called.
#[derive(Debug)]
pub struct RuntimeObligationValidator {
    checker: LeakChecker,
    next_instruction_index: usize,
}

impl RuntimeObligationValidator {
    /// Start validating observed transitions for a runtime scope.
    #[must_use]
    pub fn new(scope: impl Into<String>) -> Self {
        let mut checker = LeakChecker::new();
        checker.scope_name = scope.into();
        checker.record_budget_snapshot();
        Self {
            checker,
            next_instruction_index: 0,
        }
    }

    /// Apply a reserve event for an observed obligation variable.
    #[must_use]
    pub fn reserve(&mut self, var: ObligationVar, kind: ObligationKind) -> &[Diagnostic] {
        self.apply(Instruction::Reserve { var, kind })
    }

    /// Apply a commit event for an observed obligation variable.
    #[must_use]
    pub fn commit(&mut self, var: ObligationVar) -> &[Diagnostic] {
        self.apply(Instruction::Commit { var })
    }

    /// Apply an abort event for an observed obligation variable.
    #[must_use]
    pub fn abort(&mut self, var: ObligationVar) -> &[Diagnostic] {
        self.apply(Instruction::Abort { var })
    }

    /// Apply one observed IR instruction.
    ///
    /// `Reserve`, `Commit`, and `Abort` model live transition hooks directly.
    /// `Branch` keeps the existing static all-arm semantics for callers that
    /// validate an already-materialized structured sub-flow.
    #[must_use]
    pub fn apply(&mut self, instruction: Instruction) -> &[Diagnostic] {
        let instruction_path = vec![self.next_instruction_index];
        self.next_instruction_index += 1;
        self.checker
            .check_instruction(&instruction, &instruction_path, &[]);
        self.checker.record_budget_snapshot();
        &self.checker.diagnostics
    }

    /// Diagnostics emitted before scope-exit validation.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.checker.diagnostics
    }

    /// Returns true when all observed transitions have respected the rules so far.
    #[must_use]
    pub fn is_clean_so_far(&self) -> bool {
        self.checker.diagnostics.is_empty()
    }

    /// Finish the observed scope and emit pending-obligation leak diagnostics.
    #[must_use]
    pub fn finish(mut self) -> CheckResult {
        self.checker.check_exit_leaks();
        self.checker.check_result()
    }
}

// ============================================================================
// BodyBuilder — fluent IR construction
// ============================================================================

/// Fluent builder for constructing obligation [`Body`] IR.
///
/// Bridges the gap between real obligation code patterns and the static
/// checker's structured IR. Variables are auto-assigned incrementally.
///
/// # Example
///
/// ```
/// use asupersync::obligation::BodyBuilder;
/// use asupersync::record::ObligationKind;
///
/// let mut b = BodyBuilder::new("send_handler");
/// let permit = b.reserve(ObligationKind::SendPermit);
/// b.branch(|bb| {
///     bb.arm(|a| { a.commit(permit); });
///     bb.arm(|a| { a.abort(permit); });
/// });
/// let body = b.build();
///
/// let mut checker = asupersync::obligation::LeakChecker::new();
/// let result = checker.check(&body);
/// assert!(result.is_clean());
/// ```
#[derive(Debug)]
pub struct BodyBuilder {
    name: String,
    instructions: Vec<Instruction>,
    next_var: u32,
}

impl BodyBuilder {
    /// Create a new builder for a scope/function with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            instructions: Vec::new(),
            next_var: 0,
        }
    }

    /// Reserve a new obligation, returning the auto-assigned variable.
    pub fn reserve(&mut self, kind: ObligationKind) -> ObligationVar {
        let var = ObligationVar(self.next_var);
        self.next_var += 1;
        self.instructions.push(Instruction::Reserve { var, kind });
        var
    }

    /// Record a commit instruction for the given variable.
    pub fn commit(&mut self, var: ObligationVar) -> &mut Self {
        self.instructions.push(Instruction::Commit { var });
        self
    }

    /// Record an abort instruction for the given variable.
    pub fn abort(&mut self, var: ObligationVar) -> &mut Self {
        self.instructions.push(Instruction::Abort { var });
        self
    }

    /// Add a branch (if/else, match) with multiple arms.
    ///
    /// Each arm is built via the [`BranchBuilder`] callback.
    pub fn branch(&mut self, build: impl FnOnce(&mut BranchBuilder)) -> &mut Self {
        let mut bb = BranchBuilder { arms: Vec::new() };
        build(&mut bb);
        self.instructions
            .push(Instruction::Branch { arms: bb.arms });
        self
    }

    /// Consume the builder and produce a [`Body`].
    #[must_use]
    pub fn build(self) -> Body {
        Body {
            name: self.name,
            instructions: self.instructions,
        }
    }

    /// Returns the next variable index (useful for manual variable allocation).
    #[must_use]
    pub fn next_var_index(&self) -> u32 {
        self.next_var
    }
}

/// Builder for branch arms within a [`BodyBuilder::branch`] call.
#[derive(Debug)]
pub struct BranchBuilder {
    arms: Vec<Vec<Instruction>>,
}

impl BranchBuilder {
    /// Add a branch arm. The callback receives an [`ArmBuilder`] to populate
    /// the arm's instructions.
    pub fn arm(&mut self, build: impl FnOnce(&mut ArmBuilder)) -> &mut Self {
        let mut ab = ArmBuilder {
            instructions: Vec::new(),
        };
        build(&mut ab);
        self.arms.push(ab.instructions);
        self
    }
}

/// Builder for a single branch arm's instruction sequence.
#[derive(Debug)]
pub struct ArmBuilder {
    instructions: Vec<Instruction>,
}

impl ArmBuilder {
    /// Record a commit in this arm.
    pub fn commit(&mut self, var: ObligationVar) -> &mut Self {
        self.instructions.push(Instruction::Commit { var });
        self
    }

    /// Record an abort in this arm.
    pub fn abort(&mut self, var: ObligationVar) -> &mut Self {
        self.instructions.push(Instruction::Abort { var });
        self
    }

    /// Reserve a new obligation within this arm (for obligations local to one branch).
    pub fn reserve(&mut self, var: ObligationVar, kind: ObligationKind) -> &mut Self {
        self.instructions.push(Instruction::Reserve { var, kind });
        self
    }

    /// Add a nested branch within this arm.
    pub fn branch(&mut self, build: impl FnOnce(&mut BranchBuilder)) -> &mut Self {
        let mut bb = BranchBuilder { arms: Vec::new() };
        build(&mut bb);
        self.instructions
            .push(Instruction::Branch { arms: bb.arms });
        self
    }
}

// ============================================================================
// ObligationAnalyzer — record-then-check bridge
// ============================================================================

/// Records obligation operations and validates them via the static [`LeakChecker`].
///
/// Bridges real obligation usage patterns to the static checker. Construct an
/// analyzer, call `reserve`/`commit`/`abort` as your code would, then call
/// `check()` to run the leak analysis.
///
/// # Example
///
/// ```
/// use asupersync::obligation::ObligationAnalyzer;
/// use asupersync::record::ObligationKind;
///
/// let mut analyzer = ObligationAnalyzer::new("my_handler");
/// let permit = analyzer.reserve(ObligationKind::SendPermit);
/// analyzer.commit(permit);
/// let result = analyzer.check();
/// assert!(result.is_clean());
/// ```
#[derive(Debug)]
pub struct ObligationAnalyzer {
    builder: BodyBuilder,
}

impl ObligationAnalyzer {
    /// Create a new analyzer for the given scope name.
    #[must_use]
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            builder: BodyBuilder::new(scope),
        }
    }

    /// Record a reserve operation, returning the variable handle.
    pub fn reserve(&mut self, kind: ObligationKind) -> ObligationVar {
        self.builder.reserve(kind)
    }

    /// Record a commit operation.
    pub fn commit(&mut self, var: ObligationVar) {
        self.builder.commit(var);
    }

    /// Record an abort operation.
    pub fn abort(&mut self, var: ObligationVar) {
        self.builder.abort(var);
    }

    /// Record a branch with multiple arms.
    pub fn branch(&mut self, build: impl FnOnce(&mut BranchBuilder)) {
        self.builder.branch(build);
    }

    /// Run the leak checker and return the result.
    #[must_use]
    pub fn check(self) -> CheckResult {
        let body = self.builder.build();
        let mut checker = LeakChecker::new();
        checker.check(&body)
    }

    /// Assert that the recorded operations have no leaks.
    ///
    /// # Panics
    ///
    /// Panics with diagnostic details if any leaks are found.
    pub fn assert_clean(self) {
        let result = self.check();
        assert!(result.is_clean(), "obligation leak check failed:\n{result}");
    }

    /// Assert that the recorded operations have exactly `expected` leak diagnostics.
    ///
    /// # Panics
    ///
    /// Panics if the number of leaks doesn't match.
    pub fn assert_leaks(self, expected: usize) {
        let result = self.check();
        let leaks = result.leaks();
        assert_eq!(
            leaks.len(),
            expected,
            "expected {expected} leak(s) but found {}:\n{result}",
            leaks.len()
        );
    }
}

// ============================================================================
// Macros — DSL for inline body construction + assertion
// ============================================================================

/// Construct an obligation [`Body`] from a concise inline description.
///
/// # Syntax
///
/// ```text
/// obligation_body!("scope_name", |b| {
///     let permit = b.reserve(ObligationKind::SendPermit);
///     b.branch(|bb| {
///         bb.arm(|a| { a.commit(permit); });
///         bb.arm(|a| { a.abort(permit); });
///     });
/// })
/// ```
///
/// # Example
///
/// ```
/// use asupersync::obligation_body;
/// use asupersync::record::ObligationKind;
///
/// let body = obligation_body!("handler", |b| {
///     let v = b.reserve(ObligationKind::SendPermit);
///     b.commit(v);
/// });
///
/// let mut checker = asupersync::obligation::LeakChecker::new();
/// assert!(checker.check(&body).is_clean());
/// ```
#[macro_export]
macro_rules! obligation_body {
    ($name:expr, |$b:ident| $block:block) => {{
        let mut $b = $crate::obligation::BodyBuilder::new($name);
        $block
        $b.build()
    }};
}

/// Assert that an obligation body (or inline builder) has no leaks.
///
/// # Forms
///
/// ```text
/// // Check an existing Body:
/// assert_no_leaks!(body);
///
/// // Build and check inline:
/// assert_no_leaks!("scope_name", |b| {
///     let v = b.reserve(ObligationKind::SendPermit);
///     b.commit(v);
/// });
/// ```
///
/// # Example
///
/// ```
/// use asupersync::assert_no_leaks;
/// use asupersync::record::ObligationKind;
///
/// // Inline form:
/// assert_no_leaks!("clean_handler", |b| {
///     let v = b.reserve(ObligationKind::SendPermit);
///     b.commit(v);
/// });
/// ```
///
/// ```should_panic
/// use asupersync::assert_no_leaks;
/// use asupersync::record::ObligationKind;
///
/// // This panics because the obligation is never resolved:
/// assert_no_leaks!("leaky_handler", |b| {
///     let _v = b.reserve(ObligationKind::SendPermit);
/// });
/// ```
#[macro_export]
macro_rules! assert_no_leaks {
    ($body:expr) => {{
        let mut __checker = $crate::obligation::LeakChecker::new();
        let __result = __checker.check(&$body);
        assert!(
            __result.is_clean(),
            "obligation leak check failed:\n{__result}"
        );
    }};
    ($name:expr, |$b:ident| $block:block) => {{
        let __body = $crate::obligation_body!($name, |$b| $block);
        $crate::assert_no_leaks!(__body);
    }};
}

/// Assert that an obligation body has exactly the specified number of leaks.
///
/// # Example
///
/// ```
/// use asupersync::{assert_has_leaks, obligation_body};
/// use asupersync::record::ObligationKind;
///
/// let body = obligation_body!("leaky", |b| {
///     let _v = b.reserve(ObligationKind::SendPermit);
///     // No commit or abort — definite leak.
/// });
/// assert_has_leaks!(body, 1);
/// ```
#[macro_export]
macro_rules! assert_has_leaks {
    ($body:expr, $expected:expr) => {{
        let mut __checker = $crate::obligation::LeakChecker::new();
        let __result = __checker.check(&$body);
        let __leaks = __result.leaks();
        assert_eq!(
            __leaks.len(),
            $expected,
            "expected {} leak(s) but found {}:\n{__result}",
            $expected,
            __leaks.len()
        );
    }};
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "leak_check_inline_tests.rs"]
mod tests;
