//! Spork Evidence Ledger Schema + Deterministic Rendering (bd-2dfoo)
//!
//! Every Spork decision — supervision, registry, link/monitor — produces a
//! structured evidence record explaining *why* the decision was made and
//! *which constraint was binding*.  This module defines the unified schema
//! and a deterministic rendering format.
//!
//! # Design Principles
//!
//! 1. **Deterministic**: Evidence rendering is a pure function of the record.
//!    Identical inputs always produce identical output (byte-for-byte).
//! 2. **Test-assertable**: Records can be compared structurally, and rendered
//!    output can be matched against expected strings in tests.
//! 3. **Module-agnostic**: The `EvidenceRecord` envelope is the same regardless
//!    of which Spork subsystem produced it; the `detail` field carries the
//!    subsystem-specific constraint.
//! 4. **Append-only**: Ledgers only grow.  Entries are never mutated or removed.
//!
//! # Schema Overview
//!
//! ```text
//! EvidenceRecord
//! ├── timestamp: u64 (virtual nanoseconds)
//! ├── task_id: TaskId
//! ├── region_id: RegionId
//! ├── subsystem: Subsystem (Supervision | Registry | Link | Monitor)
//! ├── detail: EvidenceDetail (enum over subsystem-specific constraints)
//! └── verdict: Verdict (one-word outcome: Restart, Stop, Escalate, Accept, Reject, Propagate, …)
//! ```

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{CancelReason, Outcome, RegionId, TaskId};

// ---------------------------------------------------------------------------
// Subsystem + Verdict enums
// ---------------------------------------------------------------------------

/// Spork subsystem that produced the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subsystem {
    /// Supervisor restart/stop/escalate decisions.
    Supervision,
    /// Registry name lease accept/reject/cleanup decisions.
    Registry,
    /// Link exit-signal propagation decisions.
    Link,
    /// Monitor down-notification delivery decisions.
    Monitor,
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervision => write!(f, "supervision"),
            Self::Registry => write!(f, "registry"),
            Self::Link => write!(f, "link"),
            Self::Monitor => write!(f, "monitor"),
        }
    }
}

/// One-word verdict summarizing the decision outcome.
///
/// The verdict is the "what happened" counterpart to the detail's "why".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    // -- Supervision --
    /// Actor will be restarted.
    Restart,
    /// Actor will be stopped permanently.
    Stop,
    /// Failure will be escalated to parent region.
    Escalate,

    // -- Registry --
    /// Name registration accepted.
    Accept,
    /// Name registration rejected (collision, closed region, etc.).
    Reject,
    /// Name lease released (normal lifecycle).
    Release,
    /// Name lease aborted (cancellation, cleanup).
    Abort,

    // -- Link --
    /// Exit signal propagated to linked task.
    Propagate,
    /// Exit signal suppressed (trap_exit, demonitor, etc.).
    Suppress,

    // -- Monitor --
    /// Down notification delivered.
    Deliver,
    /// Down notification dropped (watcher already terminated, region cleaned up).
    Drop,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restart => write!(f, "RESTART"),
            Self::Stop => write!(f, "STOP"),
            Self::Escalate => write!(f, "ESCALATE"),
            Self::Accept => write!(f, "ACCEPT"),
            Self::Reject => write!(f, "REJECT"),
            Self::Release => write!(f, "RELEASE"),
            Self::Abort => write!(f, "ABORT"),
            Self::Propagate => write!(f, "PROPAGATE"),
            Self::Suppress => write!(f, "SUPPRESS"),
            Self::Deliver => write!(f, "DELIVER"),
            Self::Drop => write!(f, "DROP"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence Detail (subsystem-specific constraint / reasoning)
// ---------------------------------------------------------------------------

/// Subsystem-specific evidence detail explaining *why* a decision was made.
///
/// Each variant carries the binding constraint: the specific rule, limit,
/// or condition that determined the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceDetail {
    /// Supervision decision detail.
    Supervision(SupervisionDetail),
    /// Registry decision detail.
    Registry(RegistryDetail),
    /// Link decision detail.
    Link(LinkDetail),
    /// Monitor decision detail.
    Monitor(MonitorDetail),
}

impl fmt::Display for EvidenceDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervision(d) => write!(f, "{d}"),
            Self::Registry(d) => write!(f, "{d}"),
            Self::Link(d) => write!(f, "{d}"),
            Self::Monitor(d) => write!(f, "{d}"),
        }
    }
}

// -- Supervision detail --

/// Why a supervision decision was made.
///
/// Maps directly to the `BindingConstraint` enum in `src/supervision.rs`
/// but expressed in the generalized evidence schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisionDetail {
    /// Outcome severity prevents restart (Panicked / Cancelled / Ok).
    MonotoneSeverity {
        /// The outcome kind label.
        outcome_kind: String,
    },
    /// Strategy is explicitly `Stop`.
    ExplicitStop,
    /// Strategy is explicitly `Escalate`.
    ExplicitEscalate,
    /// Strategy is `Escalate`, but there is no parent supervisor to receive it.
    EscalateWithoutParent,
    /// Restart was allowed: window + budget checks passed.
    RestartAllowed {
        /// Which attempt (1-indexed).
        attempt: u32,
        /// Delay before restart (if any).
        delay: Option<Duration>,
    },
    /// Sliding-window restart count exhausted.
    WindowExhausted {
        /// Maximum restarts in window.
        max_restarts: u32,
        /// Window duration.
        window: Duration,
    },
    /// Budget constraint refused restart.
    BudgetRefused {
        /// Human-readable constraint description.
        constraint: String,
    },
}

impl fmt::Display for SupervisionDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MonotoneSeverity { outcome_kind } => {
                write!(f, "monotone severity: {outcome_kind} is not restartable")
            }
            Self::ExplicitStop => write!(f, "strategy is Stop"),
            Self::ExplicitEscalate => write!(f, "strategy is Escalate"),
            Self::EscalateWithoutParent => {
                write!(f, "strategy is Escalate but no parent region exists")
            }
            Self::RestartAllowed { attempt, delay } => match delay {
                Some(d) => write!(f, "restart allowed (attempt {attempt}, delay {d:?})"),
                None => write!(f, "restart allowed (attempt {attempt})"),
            },
            Self::WindowExhausted {
                max_restarts,
                window,
            } => write!(f, "window exhausted: {max_restarts} restarts in {window:?}"),
            Self::BudgetRefused { constraint } => {
                write!(f, "budget refused: {constraint}")
            }
        }
    }
}

// -- Registry detail --

/// Why a registry decision was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryDetail {
    /// Name was available and registration succeeded.
    NameAvailable,
    /// Name was already held by another task (collision).
    NameCollision {
        /// The existing holder.
        existing_holder: TaskId,
    },
    /// Region is closed; registration refused.
    RegionClosed {
        /// The closed region.
        region: RegionId,
    },
    /// Name lease released by holder (obligation committed).
    LeaseCommitted,
    /// Name lease aborted due to cancellation.
    LeaseCancelled {
        /// Cancellation reason.
        reason: CancelReason,
    },
    /// Name lease aborted due to region cleanup.
    LeaseCleanedUp {
        /// The region being cleaned up.
        region: RegionId,
    },
    /// Name lease aborted due to task cleanup.
    TaskCleanedUp {
        /// The task being cleaned up.
        task: TaskId,
    },
}

impl fmt::Display for RegistryDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameAvailable => write!(f, "name available"),
            Self::NameCollision { existing_holder } => {
                write!(f, "name collision: held by {existing_holder:?}")
            }
            Self::RegionClosed { region } => {
                write!(f, "region closed: {region:?}")
            }
            Self::LeaseCommitted => write!(f, "lease committed (normal release)"),
            Self::LeaseCancelled { reason } => {
                write!(f, "lease cancelled: {reason}")
            }
            Self::LeaseCleanedUp { region } => {
                write!(f, "lease cleaned up (region {region:?} closing)")
            }
            Self::TaskCleanedUp { task } => {
                write!(f, "lease cleaned up (task {task:?} terminating)")
            }
        }
    }
}

// -- Link detail --

/// Why a link decision was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkDetail {
    /// Linked task failed; exit signal propagated.
    ExitPropagated {
        /// The source of the failure.
        source: TaskId,
        /// The failure outcome.
        reason: Outcome<(), ()>,
    },
    /// Exit signal suppressed because target is trapping exits.
    TrapExit {
        /// The source of the failure.
        source: TaskId,
    },
    /// Link removed before failure occurred (no propagation).
    Unlinked,
    /// Link cleaned up due to region closure.
    RegionCleanup {
        /// The region being closed.
        region: RegionId,
    },
}

impl fmt::Display for LinkDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExitPropagated { source, reason } => {
                write!(f, "exit propagated from {source:?} ({reason:?})")
            }
            Self::TrapExit { source } => {
                write!(f, "exit trapped from {source:?}")
            }
            Self::Unlinked => write!(f, "unlinked before failure"),
            Self::RegionCleanup { region } => {
                write!(f, "link cleaned up (region {region:?} closing)")
            }
        }
    }
}

// -- Monitor detail --

/// Why a monitor decision was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorDetail {
    /// Down notification delivered to watcher.
    DownDelivered {
        /// The terminated task.
        monitored: TaskId,
        /// The termination outcome.
        reason: Outcome<(), ()>,
    },
    /// Down notification dropped because watcher region was cleaned up.
    WatcherRegionClosed {
        /// The watcher's region.
        region: RegionId,
    },
    /// Monitor removed before task terminated.
    Demonitored,
    /// Monitor cleaned up due to region closure.
    RegionCleanup {
        /// The region being closed.
        region: RegionId,
        /// Number of monitors released.
        count: usize,
    },
}

impl fmt::Display for MonitorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DownDelivered { monitored, reason } => {
                write!(f, "down delivered for {monitored:?} ({reason:?})")
            }
            Self::WatcherRegionClosed { region } => {
                write!(f, "watcher region {region:?} closed")
            }
            Self::Demonitored => write!(f, "demonitored before termination"),
            Self::RegionCleanup { region, count } => {
                write!(f, "region {region:?} cleanup released {count} monitor(s)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence Record
// ---------------------------------------------------------------------------

/// A single evidence record capturing why a Spork decision was made.
///
/// This is the generalized, subsystem-agnostic envelope.  Every Spork
/// subsystem produces `EvidenceRecord` entries with identical metadata
/// layout and subsystem-specific `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Virtual timestamp (nanoseconds) when the decision was made.
    pub timestamp: u64,
    /// The task involved in the decision.
    pub task_id: TaskId,
    /// The region containing the task.
    pub region_id: RegionId,
    /// Which Spork subsystem produced this evidence.
    pub subsystem: Subsystem,
    /// One-word verdict: what happened.
    pub verdict: Verdict,
    /// Subsystem-specific detail: why it happened.
    pub detail: EvidenceDetail,
}

impl EvidenceRecord {
    /// Render this record to a deterministic, single-line string.
    ///
    /// Format: `[{timestamp_ns}] {subsystem} {verdict}: {detail}`
    ///
    /// This format is stable and test-assertable.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "[{}] {} {}: {}",
            self.timestamp, self.subsystem, self.verdict, self.detail
        )
    }

    /// Convert this record into an evidence "card" suitable for deterministic,
    /// human/agent-friendly debugging.
    ///
    /// A card is the "galaxy-brain" triple:
    /// - `rule`: a general rule or equation form ("why this verdict follows")
    /// - `substitution`: the same rule with concrete values
    /// - `intuition`: a one-line explanation
    #[must_use]
    pub fn to_card(&self) -> EvidenceCard {
        let (rule, substitution, intuition) =
            evidence_card_triple(self.subsystem, self.verdict, &self.detail);

        EvidenceCard {
            timestamp: self.timestamp,
            task_id: self.task_id,
            region_id: self.region_id,
            subsystem: self.subsystem,
            verdict: self.verdict,
            rule,
            substitution,
            intuition,
        }
    }

    /// Render this record as a deterministic, multi-line evidence card.
    #[must_use]
    pub fn render_card(&self) -> String {
        self.to_card().render()
    }
}

impl fmt::Display for EvidenceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {}: {}",
            self.timestamp, self.subsystem, self.verdict, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// Generalized Evidence Ledger
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Evidence Cards (Galaxy-Brain Rendering)
// ---------------------------------------------------------------------------

/// A deterministic "galaxy-brain" evidence card derived from a single record.
///
/// This is intentionally lightweight and stable so tests can assert exact
/// output and agents can grep for `rule:` / `substitution:` / `intuition:`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCard {
    /// Virtual timestamp (nanoseconds) when the decision was made.
    pub timestamp: u64,
    /// The task involved in the decision.
    pub task_id: TaskId,
    /// The region containing the task.
    pub region_id: RegionId,
    /// Which Spork subsystem produced this evidence.
    pub subsystem: Subsystem,
    /// One-word verdict: what happened.
    pub verdict: Verdict,
    /// General rule/equation form.
    pub rule: String,
    /// Rule with concrete values substituted.
    pub substitution: String,
    /// One-line intuition.
    pub intuition: String,
}

impl EvidenceCard {
    /// Render this card to a deterministic, multi-line string.
    ///
    /// Format:
    ///
    /// ```text
    /// [{timestamp}] {subsystem} {verdict} task={task:?} region={region:?}
    /// rule: ...
    /// substitution: ...
    /// intuition: ...
    /// ```
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "[{}] {} {} task={:?} region={:?}\nrule: {}\nsubstitution: {}\nintuition: {}\n",
            self.timestamp,
            self.subsystem,
            self.verdict,
            self.task_id,
            self.region_id,
            self.rule,
            self.substitution,
            self.intuition
        )
    }
}

impl fmt::Display for EvidenceCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

fn supervision_card_triple(detail: &SupervisionDetail) -> (String, String, String) {
    match detail {
        SupervisionDetail::MonotoneSeverity { outcome_kind } => (
            "If outcome severity is not restartable, the supervisor must STOP.".to_string(),
            format!("outcome_kind={outcome_kind} => STOP"),
            format!(
                "Outcome {outcome_kind} is terminal for supervision; stopping preserves monotone severity."
            ),
        ),
        SupervisionDetail::ExplicitStop => (
            "If supervision strategy is Stop, the supervisor must STOP.".to_string(),
            "strategy=Stop => STOP".to_string(),
            "Strategy is Stop; no restart is attempted.".to_string(),
        ),
        SupervisionDetail::ExplicitEscalate => (
            "If supervision strategy is Escalate, the supervisor must ESCALATE.".to_string(),
            "strategy=Escalate => ESCALATE".to_string(),
            "Strategy is Escalate; failure is propagated to the parent region.".to_string(),
        ),
        SupervisionDetail::EscalateWithoutParent => (
            "If supervision strategy is Escalate but no parent region exists, the supervisor must STOP."
                .to_string(),
            "strategy=Escalate,parent=None => STOP".to_string(),
            "Root escalation has no parent target; stopping preserves a total supervision decision."
                .to_string(),
        ),
        SupervisionDetail::RestartAllowed { attempt, delay } => (
            "If restart window and budget allow, the supervisor may RESTART.".to_string(),
            delay.as_ref().map_or_else(
                || format!("attempt={attempt} => RESTART"),
                |d| format!("attempt={attempt}, delay={d:?} => RESTART"),
            ),
            "Restart attempt is permitted; any configured delay is applied deterministically."
                .to_string(),
        ),
        SupervisionDetail::WindowExhausted {
            max_restarts,
            window,
        } => (
            "If restarts in the intensity window exceed the limit, the supervisor must STOP."
                .to_string(),
            format!("max_restarts={max_restarts}, window={window:?} => STOP"),
            "Restart intensity exceeded; stopping prevents an unbounded crash loop.".to_string(),
        ),
        SupervisionDetail::BudgetRefused { constraint } => (
            "If restart would violate budget constraints, the supervisor must STOP.".to_string(),
            format!("{constraint} => STOP"),
            "Budget would be exceeded; stopping is deterministic and cancel-correct.".to_string(),
        ),
    }
}

fn registry_card_triple(detail: &RegistryDetail) -> (String, String, String) {
    match detail {
        RegistryDetail::NameAvailable => (
            "If the name is unheld, registration is ACCEPTED.".to_string(),
            "name is available => ACCEPT".to_string(),
            "No collision; a name lease is created and must be resolved linearly.".to_string(),
        ),
        RegistryDetail::NameCollision { existing_holder } => (
            "If the name is already held, registration is REJECTED.".to_string(),
            format!("existing_holder={existing_holder:?} => REJECT"),
            "Collision prevents ambiguous ownership; reject to preserve determinism.".to_string(),
        ),
        RegistryDetail::RegionClosed { region } => (
            "If the owning region is closed, registration is REJECTED.".to_string(),
            format!("region={region:?} is closed => REJECT"),
            "Closed regions cannot accept new obligations; reject avoids orphaned leases."
                .to_string(),
        ),
        RegistryDetail::LeaseCommitted => (
            "If the lease obligation is committed, the name is RELEASED.".to_string(),
            "lease committed => RELEASE".to_string(),
            "Normal lifecycle release; name becomes available again.".to_string(),
        ),
        RegistryDetail::LeaseCancelled { reason } => (
            "If cancellation occurs, the lease is ABORTED.".to_string(),
            format!("cancel_reason={reason} => ABORT"),
            "Cancellation triggers cleanup; abort avoids stale names.".to_string(),
        ),
        RegistryDetail::LeaseCleanedUp { region } => (
            "If region cleanup runs, the lease is ABORTED.".to_string(),
            format!("cleanup_region={region:?} => ABORT"),
            "Region close implies quiescence; leases are aborted during cleanup.".to_string(),
        ),
        RegistryDetail::TaskCleanedUp { task } => (
            "If task cleanup runs, the lease is ABORTED.".to_string(),
            format!("cleanup_task={task:?} => ABORT"),
            "Task termination must not leave names held; abort releases the lease.".to_string(),
        ),
    }
}

fn link_card_triple(detail: &LinkDetail) -> (String, String, String) {
    match detail {
        LinkDetail::ExitPropagated { source, reason } => (
            "If a linked task exits and exits are not trapped, the signal is PROPAGATED."
                .to_string(),
            format!("source={source:?}, reason={reason:?} => PROPAGATE"),
            "Linked failures propagate to preserve OTP-style failure semantics.".to_string(),
        ),
        LinkDetail::TrapExit { source } => (
            "If the target traps exits, the signal is SUPPRESSED.".to_string(),
            format!("source={source:?}, trap_exit=true => SUPPRESS"),
            "Target traps exits, so failure is converted into a message instead of killing."
                .to_string(),
        ),
        LinkDetail::Unlinked => (
            "If the link was removed, no propagation occurs.".to_string(),
            "link already removed => SUPPRESS".to_string(),
            "No active link exists; nothing to propagate.".to_string(),
        ),
        LinkDetail::RegionCleanup { region } => (
            "If region cleanup runs, links are cleaned up without propagation.".to_string(),
            format!("cleanup_region={region:?} => SUPPRESS"),
            "Region close implies quiescence; cleanup suppresses further signals.".to_string(),
        ),
    }
}

fn monitor_card_triple(detail: &MonitorDetail) -> (String, String, String) {
    match detail {
        MonitorDetail::DownDelivered { monitored, reason } => (
            "If a monitored task terminates, a DOWN is DELIVERED to the watcher.".to_string(),
            format!("monitored={monitored:?}, reason={reason:?} => DELIVER"),
            "Monitors provide observation without coupling; DOWN is delivered deterministically."
                .to_string(),
        ),
        MonitorDetail::WatcherRegionClosed { region } => (
            "If the watcher region is closed, DOWN delivery is DROPPED.".to_string(),
            format!("watcher_region={region:?} closed => DROP"),
            "Watcher cannot receive messages after cleanup; drop avoids resurrecting work."
                .to_string(),
        ),
        MonitorDetail::Demonitored => (
            "If the monitor was removed, no DOWN is delivered.".to_string(),
            "demonitored => DROP".to_string(),
            "No active monitor exists; nothing to deliver.".to_string(),
        ),
        MonitorDetail::RegionCleanup { region, count } => (
            "If region cleanup runs, monitors are DROPPED.".to_string(),
            format!("cleanup_region={region:?}, released={count} => DROP"),
            "Region close releases monitor obligations; dropping is deterministic cleanup."
                .to_string(),
        ),
    }
}

fn evidence_card_triple(
    _subsystem: Subsystem,
    _verdict: Verdict,
    detail: &EvidenceDetail,
) -> (String, String, String) {
    match detail {
        EvidenceDetail::Supervision(d) => supervision_card_triple(d),
        EvidenceDetail::Registry(d) => registry_card_triple(d),
        EvidenceDetail::Link(d) => link_card_triple(d),
        EvidenceDetail::Monitor(d) => monitor_card_triple(d),
    }
}

/// Deterministic, append-only, subsystem-agnostic evidence ledger.
///
/// Collects [`EvidenceRecord`] entries from any Spork subsystem.
/// Supports filtering by subsystem, verdict, task, or arbitrary predicate.
///
/// # Determinism
///
/// Entry order is insertion order, which is deterministic under virtual time.
/// The [`render`](Self::render) method produces a stable multi-line string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeneralizedLedger {
    entries: Vec<EvidenceRecord>,
}

impl GeneralizedLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an evidence record.
    pub fn push(&mut self, record: EvidenceRecord) {
        self.entries.push(record);
    }

    /// All recorded entries, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[EvidenceRecord] {
        &self.entries
    }

    /// Number of recorded entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries for a specific task.
    pub fn for_task(&self, task_id: TaskId) -> impl Iterator<Item = &EvidenceRecord> {
        self.entries.iter().filter(move |e| e.task_id == task_id)
    }

    /// Iterate over entries from a specific subsystem.
    pub fn for_subsystem(&self, subsystem: Subsystem) -> impl Iterator<Item = &EvidenceRecord> {
        self.entries
            .iter()
            .filter(move |e| e.subsystem == subsystem)
    }

    /// Iterate over entries with a specific verdict.
    pub fn with_verdict(&self, verdict: Verdict) -> impl Iterator<Item = &EvidenceRecord> {
        self.entries.iter().filter(move |e| e.verdict == verdict)
    }

    /// Iterate over entries matching an arbitrary predicate.
    pub fn filter<F>(&self, predicate: F) -> impl Iterator<Item = &EvidenceRecord>
    where
        F: Fn(&EvidenceRecord) -> bool,
    {
        self.entries.iter().filter(move |e| predicate(e))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drains the oldest `count` entries from the ledger.
    pub fn drain_oldest(&mut self, count: usize) {
        let count = count.min(self.entries.len());
        self.entries.drain(..count);
    }

    /// Render the entire ledger to a deterministic, multi-line string.
    ///
    /// Each entry is rendered on its own line using [`EvidenceRecord::render`].
    /// The output is stable and test-assertable.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&entry.render());
            out.push('\n');
        }
        out
    }

    /// Render the entire ledger to deterministic evidence cards.
    ///
    /// Each entry becomes one card, separated by a blank line.
    #[must_use]
    pub fn render_cards(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&entry.render_card());
            out.push('\n');
        }
        out
    }
}

impl fmt::Display for GeneralizedLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            writeln!(f, "{entry}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "evidence_inline_tests.rs"]
mod tests;
