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

use crate::types::{CancelReason, Outcome, RegionId, TaskId};

// ---------------------------------------------------------------------------
// Subsystem + Verdict enums
// ---------------------------------------------------------------------------

/// Spork subsystem that produced the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq)]
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

impl Eq for EvidenceDetail {}

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
#[derive(Debug, Clone, PartialEq)]
pub enum SupervisionDetail {
    /// Outcome severity prevents restart (Panicked / Cancelled / Ok).
    MonotoneSeverity {
        /// The outcome kind label.
        outcome_kind: &'static str,
    },
    /// Strategy is explicitly `Stop`.
    ExplicitStop,
    /// Strategy is explicitly `Escalate`.
    ExplicitEscalate,
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

impl Eq for SupervisionDetail {}

impl fmt::Display for SupervisionDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MonotoneSeverity { outcome_kind } => {
                write!(f, "monotone severity: {outcome_kind} is not restartable")
            }
            Self::ExplicitStop => write!(f, "strategy is Stop"),
            Self::ExplicitEscalate => write!(f, "strategy is Escalate"),
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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

impl Eq for LinkDetail {}

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
#[derive(Debug, Clone, PartialEq)]
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

impl Eq for MonitorDetail {}

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Default)]
pub struct GeneralizedLedger {
    entries: Vec<EvidenceRecord>,
}

impl GeneralizedLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
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
mod tests {
    use super::*;
    use crate::types::PanicPayload;
    use crate::util::ArenaIndex;

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 1))
    }

    fn test_task_id_2() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 2))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn evidence_record_render_supervision_restart() {
        init_test("evidence_record_render_supervision_restart");

        let record = EvidenceRecord {
            timestamp: 1_000_000_000,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 2,
                delay: Some(Duration::from_millis(200)),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("supervision RESTART"));
        assert!(rendered.contains("restart allowed (attempt 2, delay 200ms)"));

        crate::test_complete!("evidence_record_render_supervision_restart");
    }

    #[test]
    fn evidence_record_render_supervision_stop() {
        init_test("evidence_record_render_supervision_stop");

        let record = EvidenceRecord {
            timestamp: 2_000_000_000,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                max_restarts: 3,
                window: Duration::from_mins(1),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("supervision STOP"));
        assert!(rendered.contains("window exhausted: 3 restarts in 60s"));

        crate::test_complete!("evidence_record_render_supervision_stop");
    }

    #[test]
    fn evidence_record_render_registry_accept() {
        init_test("evidence_record_render_registry_accept");

        let record = EvidenceRecord {
            timestamp: 500,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        };

        assert_eq!(record.render(), "[500] registry ACCEPT: name available");

        crate::test_complete!("evidence_record_render_registry_accept");
    }

    #[test]
    fn evidence_record_render_registry_reject_collision() {
        init_test("evidence_record_render_registry_reject_collision");

        let record = EvidenceRecord {
            timestamp: 600,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Reject,
            detail: EvidenceDetail::Registry(RegistryDetail::NameCollision {
                existing_holder: test_task_id_2(),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("registry REJECT"));
        assert!(rendered.contains("name collision"));

        crate::test_complete!("evidence_record_render_registry_reject_collision");
    }

    #[test]
    fn evidence_record_render_link_propagate() {
        init_test("evidence_record_render_link_propagate");

        let record = EvidenceRecord {
            timestamp: 700,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Link,
            verdict: Verdict::Propagate,
            detail: EvidenceDetail::Link(LinkDetail::ExitPropagated {
                source: test_task_id_2(),
                reason: Outcome::Err(()),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("link PROPAGATE"));
        assert!(rendered.contains("exit propagated"));

        crate::test_complete!("evidence_record_render_link_propagate");
    }

    #[test]
    fn evidence_record_render_monitor_deliver() {
        init_test("evidence_record_render_monitor_deliver");

        let record = EvidenceRecord {
            timestamp: 800,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Monitor,
            verdict: Verdict::Deliver,
            detail: EvidenceDetail::Monitor(MonitorDetail::DownDelivered {
                monitored: test_task_id_2(),
                reason: Outcome::Panicked(PanicPayload::new("oops")),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("monitor DELIVER"));
        assert!(rendered.contains("down delivered"));

        crate::test_complete!("evidence_record_render_monitor_deliver");
    }

    #[test]
    fn generalized_ledger_push_and_query() {
        init_test("generalized_ledger_push_and_query");

        let mut ledger = GeneralizedLedger::new();
        assert!(ledger.is_empty());

        // Add supervision entry
        ledger.push(EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: None,
            }),
        });

        // Add registry entry
        ledger.push(EvidenceRecord {
            timestamp: 200,
            task_id: test_task_id_2(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        });

        // Add supervision stop
        ledger.push(EvidenceRecord {
            timestamp: 300,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        });

        assert_eq!(ledger.len(), 3);

        // Filter by subsystem
        assert_eq!(ledger.for_subsystem(Subsystem::Supervision).count(), 2);

        assert_eq!(ledger.for_subsystem(Subsystem::Registry).count(), 1);

        // Filter by verdict
        assert_eq!(ledger.with_verdict(Verdict::Restart).count(), 1);

        assert_eq!(ledger.with_verdict(Verdict::Stop).count(), 1);

        // Filter by task
        assert_eq!(ledger.for_task(test_task_id()).count(), 2);

        assert_eq!(ledger.for_task(test_task_id_2()).count(), 1);

        crate::test_complete!("generalized_ledger_push_and_query");
    }

    #[test]
    fn generalized_ledger_render_deterministic() {
        init_test("generalized_ledger_render_deterministic");

        let mut ledger_a = GeneralizedLedger::new();
        let mut ledger_b = GeneralizedLedger::new();

        let records = vec![
            EvidenceRecord {
                timestamp: 100,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Restart,
                detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                    attempt: 1,
                    delay: None,
                }),
            },
            EvidenceRecord {
                timestamp: 200,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Stop,
                detail: EvidenceDetail::Supervision(SupervisionDetail::MonotoneSeverity {
                    outcome_kind: "Panicked",
                }),
            },
        ];

        for r in &records {
            ledger_a.push(r.clone());
            ledger_b.push(r.clone());
        }

        // Byte-for-byte identical rendering
        assert_eq!(ledger_a.render(), ledger_b.render());

        // Display matches render
        assert_eq!(format!("{ledger_a}"), ledger_a.render());

        crate::test_complete!("generalized_ledger_render_deterministic");
    }

    #[test]
    fn generalized_ledger_clear() {
        init_test("generalized_ledger_clear");

        let mut ledger = GeneralizedLedger::new();
        ledger.push(EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        });

        assert_eq!(ledger.len(), 1);
        ledger.clear();
        assert!(ledger.is_empty());

        crate::test_complete!("generalized_ledger_clear");
    }

    #[test]
    fn subsystem_display() {
        init_test("subsystem_display");

        assert_eq!(format!("{}", Subsystem::Supervision), "supervision");
        assert_eq!(format!("{}", Subsystem::Registry), "registry");
        assert_eq!(format!("{}", Subsystem::Link), "link");
        assert_eq!(format!("{}", Subsystem::Monitor), "monitor");

        crate::test_complete!("subsystem_display");
    }

    #[test]
    fn verdict_display() {
        init_test("verdict_display");

        assert_eq!(format!("{}", Verdict::Restart), "RESTART");
        assert_eq!(format!("{}", Verdict::Stop), "STOP");
        assert_eq!(format!("{}", Verdict::Accept), "ACCEPT");
        assert_eq!(format!("{}", Verdict::Reject), "REJECT");
        assert_eq!(format!("{}", Verdict::Propagate), "PROPAGATE");
        assert_eq!(format!("{}", Verdict::Deliver), "DELIVER");

        crate::test_complete!("verdict_display");
    }

    #[test]
    fn registry_detail_display_variants() {
        init_test("registry_detail_display_variants");

        let details = vec![
            (RegistryDetail::NameAvailable, "name available"),
            (
                RegistryDetail::LeaseCommitted,
                "lease committed (normal release)",
            ),
        ];

        for (detail, expected) in details {
            assert_eq!(format!("{detail}"), expected);
        }

        crate::test_complete!("registry_detail_display_variants");
    }

    #[test]
    fn link_detail_display_variants() {
        init_test("link_detail_display_variants");

        assert_eq!(
            format!("{}", LinkDetail::Unlinked),
            "unlinked before failure"
        );

        crate::test_complete!("link_detail_display_variants");
    }

    #[test]
    fn monitor_detail_display_variants() {
        init_test("monitor_detail_display_variants");

        assert_eq!(
            format!("{}", MonitorDetail::Demonitored),
            "demonitored before termination"
        );

        crate::test_complete!("monitor_detail_display_variants");
    }

    #[test]
    fn generalized_ledger_filter_predicate() {
        init_test("generalized_ledger_filter_predicate");

        let mut ledger = GeneralizedLedger::new();
        for i in 0u64..5 {
            ledger.push(EvidenceRecord {
                timestamp: i * 100,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: if i < 3 {
                    Verdict::Restart
                } else {
                    Verdict::Stop
                },
                detail: EvidenceDetail::Supervision(if i < 3 {
                    SupervisionDetail::RestartAllowed {
                        attempt: (i as u32) + 1,
                        delay: None,
                    }
                } else {
                    SupervisionDetail::WindowExhausted {
                        max_restarts: 3,
                        window: Duration::from_mins(1),
                    }
                }),
            });
        }

        // Custom filter: entries after timestamp 200
        assert_eq!(ledger.filter(|e| e.timestamp > 200).count(), 2);

        crate::test_complete!("generalized_ledger_filter_predicate");
    }

    #[test]
    fn evidence_record_render_card_supervision_restart() {
        init_test("evidence_record_render_card_supervision_restart");

        let record = EvidenceRecord {
            timestamp: 1_000_000_001,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: Some(Duration::from_millis(10)),
            }),
        };

        let rendered = record.render_card();
        assert!(rendered.contains("supervision RESTART"));
        assert!(rendered.contains("rule: If restart window and budget allow"));
        assert!(rendered.contains("substitution: attempt=1, delay=10ms => RESTART"));
        assert!(rendered.contains("intuition: Restart attempt is permitted"));

        crate::test_complete!("evidence_record_render_card_supervision_restart");
    }

    #[test]
    fn generalized_ledger_render_cards_deterministic() {
        init_test("generalized_ledger_render_cards_deterministic");

        let mut ledger_a = GeneralizedLedger::new();
        let mut ledger_b = GeneralizedLedger::new();

        for ledger in [&mut ledger_a, &mut ledger_b] {
            ledger.push(EvidenceRecord {
                timestamp: 10,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Registry,
                verdict: Verdict::Reject,
                detail: EvidenceDetail::Registry(RegistryDetail::NameCollision {
                    existing_holder: test_task_id_2(),
                }),
            });
            ledger.push(EvidenceRecord {
                timestamp: 11,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Stop,
                detail: EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                    max_restarts: 2,
                    window: Duration::from_secs(1),
                }),
            });
        }

        // Byte-for-byte identical rendering
        assert_eq!(ledger_a.render_cards(), ledger_b.render_cards());

        crate::test_complete!("generalized_ledger_render_cards_deterministic");
    }

    // Pure data-type tests (wave 35 – CyanBarn)

    #[test]
    fn subsystem_debug_copy_hash() {
        use std::collections::HashSet;
        let s = Subsystem::Supervision;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Supervision"));

        // Copy
        let s2 = s;
        assert_eq!(s, s2);

        // Hash consistency
        let mut set = HashSet::new();
        set.insert(Subsystem::Supervision);
        set.insert(Subsystem::Registry);
        set.insert(Subsystem::Link);
        set.insert(Subsystem::Monitor);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&Subsystem::Link));
    }

    #[test]
    fn verdict_debug_copy_hash() {
        use std::collections::HashSet;
        let v = Verdict::Restart;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Restart"));

        // Copy
        let v2 = v;
        assert_eq!(v, v2);

        // Hash - all 11 variants distinct
        let mut set = HashSet::new();
        for v in [
            Verdict::Restart, Verdict::Stop, Verdict::Escalate,
            Verdict::Accept, Verdict::Reject, Verdict::Release,
            Verdict::Abort, Verdict::Propagate, Verdict::Suppress,
            Verdict::Deliver, Verdict::Drop,
        ] {
            set.insert(v);
        }
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn evidence_detail_debug_clone_eq() {
        let detail = EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop);
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("Supervision"));
        assert!(dbg.contains("ExplicitStop"));

        let cloned = detail.clone();
        assert_eq!(detail, cloned);

        // Different variants are not equal
        let other = EvidenceDetail::Registry(RegistryDetail::NameAvailable);
        assert_ne!(detail, other);
    }

    #[test]
    fn supervision_detail_debug_clone() {
        let detail = SupervisionDetail::RestartAllowed {
            attempt: 3,
            delay: Some(Duration::from_millis(100)),
        };
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("RestartAllowed"));
        assert!(dbg.contains("3"));

        let cloned = detail.clone();
        assert_eq!(detail, cloned);
    }

    #[test]
    fn evidence_record_debug_clone_eq() {
        let record = EvidenceRecord {
            timestamp: 42,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        };
        let dbg = format!("{record:?}");
        assert!(dbg.contains("EvidenceRecord"));
        assert!(dbg.contains("42"));

        let cloned = record.clone();
        assert_eq!(record, cloned);
    }

    #[test]
    fn evidence_card_debug_clone() {
        let record = EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        };
        let card = record.to_card();
        let dbg = format!("{card:?}");
        assert!(dbg.contains("EvidenceCard"));

        let cloned = card.clone();
        assert_eq!(card, cloned);
    }

    #[test]
    fn generalized_ledger_debug_clone_default() {
        let ledger = GeneralizedLedger::default();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);

        let dbg = format!("{ledger:?}");
        assert!(dbg.contains("GeneralizedLedger"));

        let mut ledger2 = GeneralizedLedger::new();
        ledger2.push(EvidenceRecord {
            timestamp: 1,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Monitor,
            verdict: Verdict::Deliver,
            detail: EvidenceDetail::Monitor(MonitorDetail::Demonitored),
        });
        let cloned = ledger2.clone();
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.entries()[0].timestamp, 1);
    }
}
