//! Deterministic deadlock-radar evidence model.
//!
//! This module turns concurrency-audit observations into stable, reviewable
//! records. It deliberately refuses to report a bug from a pattern match alone:
//! a finding needs both a hazardous shape and a concrete interleaving.

use serde::{Deserialize, Serialize};

/// Stable schema version for deadlock-radar reports.
pub const DEADLOCK_RADAR_SCHEMA_VERSION: &str = "asupersync.deadlock-radar.v1";

/// Canonical lock rank from the project-wide E -> D -> B -> A -> C order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlockRadarLockRank {
    /// E: configuration locks.
    Config,
    /// D: instrumentation and metrics locks.
    Instrumentation,
    /// B: region table/lifecycle locks.
    Regions,
    /// A: task and scheduler locks.
    Tasks,
    /// C: obligation ledger locks.
    Obligations,
}

impl DeadlockRadarLockRank {
    /// Stable single-letter rank code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Config => "E",
            Self::Instrumentation => "D",
            Self::Regions => "B",
            Self::Tasks => "A",
            Self::Obligations => "C",
        }
    }

    const fn order_index(self) -> u8 {
        match self {
            Self::Config => 10,
            Self::Instrumentation => 20,
            Self::Regions => 30,
            Self::Tasks => 40,
            Self::Obligations => 50,
        }
    }
}

/// Deadlock/liveness hazard class tracked by the radar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlockRadarHazardClass {
    /// Lock acquisition violates E -> D -> B -> A -> C.
    LockOrderInversion,
    /// A synchronous guard can be held across an `.await`.
    AwaitHoldingLock,
    /// A read guard can be upgraded to a write guard in-place.
    ReaderUpgrade,
    /// A condvar-style wait can park without predicate rechecks.
    CondvarPredicate,
    /// A notification can be lost because no level-triggered state remains.
    LostNotification,
    /// A shared counter can decrement below zero or wrap.
    CounterUnderflow,
    /// Queue publication and advisory counts can diverge.
    QueuePublicationMismatch,
    /// An optimistic atomic flag is suspected of TOCTOU.
    OptimisticFlagToctou,
}

/// Machine-checkable evidence for one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeadlockRadarEvidence {
    /// Lock ranks in acquisition order for one path.
    LockOrder {
        /// Ordered rank acquisitions observed in the path.
        acquisitions: Vec<DeadlockRadarLockRank>,
    },
    /// Await/guard lifetime evidence.
    AwaitHoldingLock {
        /// Whether the guard is proven dropped before the await point.
        guard_dropped_before_await: bool,
    },
    /// Reader-to-writer transition evidence.
    ReaderUpgrade {
        /// Whether the read guard is proven dropped before write acquisition.
        read_guard_dropped_before_write: bool,
    },
    /// Condvar predicate discipline evidence.
    CondvarPredicate {
        /// Whether the predicate is checked before parking.
        predicate_checked_before_wait: bool,
        /// Whether the predicate is rechecked after every wake.
        predicate_rechecked_after_wake: bool,
    },
    /// Notification publication evidence.
    LostNotification {
        /// Whether a durable state flag survives an early notification.
        level_triggered_state: bool,
        /// Whether waiter registration happens before notification can fire.
        waiter_registered_before_notify: bool,
    },
    /// Counter decrement discipline.
    CounterUnderflow {
        /// Whether decrement uses checked arithmetic.
        checked_decrement: bool,
        /// Whether decrement saturates rather than wraps.
        saturating_decrement: bool,
    },
    /// Queue/count publication discipline.
    QueuePublication {
        /// Whether work is queued before the advisory count is published.
        enqueue_before_count_publish: bool,
        /// Whether cancellation rolls back both queue entry and advisory count.
        cancel_rolls_back_count: bool,
    },
    /// Optimistic flag plus pessimistic lock discipline.
    OptimisticFlag {
        /// Whether writes require exclusive Rust access.
        writer_requires_mut: bool,
        /// Whether the lock-protected slow path rechecks the condition.
        lock_rechecks_condition: bool,
        /// Whether a stale false read only delays work and cannot drop it.
        stale_false_is_safe: bool,
    },
}

impl DeadlockRadarEvidence {
    fn hazard_class(&self) -> DeadlockRadarHazardClass {
        match self {
            Self::LockOrder { .. } => DeadlockRadarHazardClass::LockOrderInversion,
            Self::AwaitHoldingLock { .. } => DeadlockRadarHazardClass::AwaitHoldingLock,
            Self::ReaderUpgrade { .. } => DeadlockRadarHazardClass::ReaderUpgrade,
            Self::CondvarPredicate { .. } => DeadlockRadarHazardClass::CondvarPredicate,
            Self::LostNotification { .. } => DeadlockRadarHazardClass::LostNotification,
            Self::CounterUnderflow { .. } => DeadlockRadarHazardClass::CounterUnderflow,
            Self::QueuePublication { .. } => DeadlockRadarHazardClass::QueuePublicationMismatch,
            Self::OptimisticFlag { .. } => DeadlockRadarHazardClass::OptimisticFlagToctou,
        }
    }

    fn is_hazardous(&self) -> bool {
        match self {
            Self::LockOrder { acquisitions } => acquisitions
                .windows(2)
                .any(|window| window[1].order_index() < window[0].order_index()),
            Self::AwaitHoldingLock {
                guard_dropped_before_await,
            } => !guard_dropped_before_await,
            Self::ReaderUpgrade {
                read_guard_dropped_before_write,
            } => !read_guard_dropped_before_write,
            Self::CondvarPredicate {
                predicate_checked_before_wait,
                predicate_rechecked_after_wake,
            } => !(*predicate_checked_before_wait && *predicate_rechecked_after_wake),
            Self::LostNotification {
                level_triggered_state,
                waiter_registered_before_notify,
            } => !(*level_triggered_state || *waiter_registered_before_notify),
            Self::CounterUnderflow {
                checked_decrement,
                saturating_decrement,
            } => !(*checked_decrement || *saturating_decrement),
            Self::QueuePublication {
                enqueue_before_count_publish,
                cancel_rolls_back_count,
            } => !(*enqueue_before_count_publish && *cancel_rolls_back_count),
            Self::OptimisticFlag {
                writer_requires_mut,
                lock_rechecks_condition,
                stale_false_is_safe,
            } => !(*writer_requires_mut && *lock_rechecks_condition && *stale_false_is_safe),
        }
    }

    fn false_positive_reason(&self) -> &'static str {
        match self {
            Self::LockOrder { .. } => "lock acquisitions preserve E-D-B-A-C order",
            Self::AwaitHoldingLock { .. } => "guard is dropped before await",
            Self::ReaderUpgrade { .. } => "read guard is dropped before write acquisition",
            Self::CondvarPredicate { .. } => "predicate is checked before wait and after wake",
            Self::LostNotification { .. } => {
                "notification is protected by level-triggered state or prior registration"
            }
            Self::CounterUnderflow { .. } => "counter decrement is checked or saturating",
            Self::QueuePublication { .. } => {
                "queue entry and advisory count publish/rollback together"
            }
            Self::OptimisticFlag { .. } => {
                "optimistic flag is only a hint and the locked path is authoritative"
            }
        }
    }
}

/// One deterministic interleaving step used to prove a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlockRadarInterleavingStep {
    /// Actor/task/thread label.
    pub actor: String,
    /// Deterministic action performed by the actor.
    pub action: String,
    /// Locks or resources held before the action.
    pub held_locks: Vec<String>,
    /// Optional lock/resource this actor waits for after the action.
    pub waits_for: Option<String>,
    /// Short explanation for auditors.
    pub note: String,
}

impl DeadlockRadarInterleavingStep {
    /// Construct one interleaving step.
    #[must_use]
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        held_locks: impl IntoIterator<Item = impl Into<String>>,
        waits_for: Option<impl Into<String>>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            held_locks: held_locks.into_iter().map(Into::into).collect(),
            waits_for: waits_for.map(Into::into),
            note: note.into(),
        }
    }

    fn is_concrete(&self) -> bool {
        !self.actor.trim().is_empty()
            && !self.action.trim().is_empty()
            && !self.note.trim().is_empty()
    }
}

/// Candidate observation before classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlockRadarCandidate {
    /// Stable candidate id.
    pub id: String,
    /// Source surface or fixture name.
    pub surface: String,
    /// Source references used to justify the classification.
    pub source_refs: Vec<String>,
    /// Evidence used by the radar.
    pub evidence: DeadlockRadarEvidence,
    /// Concrete interleaving proof, required for findings.
    pub interleaving: Vec<DeadlockRadarInterleavingStep>,
    /// Suggested owner bead for follow-up work.
    pub suggested_owner_bead: Option<String>,
}

impl DeadlockRadarCandidate {
    /// Construct a candidate.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        surface: impl Into<String>,
        evidence: DeadlockRadarEvidence,
    ) -> Self {
        Self {
            id: id.into(),
            surface: surface.into(),
            source_refs: Vec::new(),
            evidence,
            interleaving: Vec::new(),
            suggested_owner_bead: None,
        }
    }

    /// Add source references.
    #[must_use]
    pub fn with_source_refs(mut self, refs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.source_refs = refs.into_iter().map(Into::into).collect();
        self
    }

    /// Add concrete interleaving proof steps.
    #[must_use]
    pub fn with_interleaving(
        mut self,
        steps: impl IntoIterator<Item = DeadlockRadarInterleavingStep>,
    ) -> Self {
        self.interleaving = steps.into_iter().collect();
        self
    }

    /// Add a suggested owner bead.
    #[must_use]
    pub fn with_suggested_owner_bead(mut self, bead: impl Into<String>) -> Self {
        self.suggested_owner_bead = Some(bead.into());
        self
    }

    fn has_concrete_interleaving(&self) -> bool {
        !self.interleaving.is_empty()
            && self
                .interleaving
                .iter()
                .all(DeadlockRadarInterleavingStep::is_concrete)
    }
}

/// Proof status for a classified candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlockRadarProofStatus {
    /// Hazardous shape plus concrete interleaving.
    ProvenInterleaving,
    /// Pattern is safe after checking the actual code path.
    FalsePositive,
    /// Hazardous shape was present, but proof was too weak to report.
    Incomplete,
}

/// Classified candidate row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlockRadarFinding {
    /// Stable candidate id.
    pub id: String,
    /// Source surface or fixture name.
    pub surface: String,
    /// Hazard class.
    pub hazard_class: DeadlockRadarHazardClass,
    /// Proof status.
    pub proof_status: DeadlockRadarProofStatus,
    /// Stable classification reason.
    pub reason: String,
    /// Source references used to justify the classification.
    pub source_refs: Vec<String>,
    /// Concrete interleaving, present for proven findings.
    pub interleaving: Vec<DeadlockRadarInterleavingStep>,
    /// Suggested owner bead for follow-up work.
    pub suggested_owner_bead: Option<String>,
}

/// Overall report verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlockRadarVerdict {
    /// No findings and no incomplete hazardous candidates.
    Pass,
    /// At least one proven finding exists.
    Finding,
    /// No proven findings, but at least one hazardous candidate lacks proof.
    Incomplete,
}

/// Stable deadlock-radar report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlockRadarReport {
    /// Schema version.
    pub schema_version: String,
    /// Number of candidates examined.
    pub candidates_examined: usize,
    /// Proven findings.
    pub findings: Vec<DeadlockRadarFinding>,
    /// Audited false positives.
    pub false_positives: Vec<DeadlockRadarFinding>,
    /// Hazardous candidates that lack concrete interleavings.
    pub incomplete: Vec<DeadlockRadarFinding>,
    /// Overall verdict.
    pub verdict: DeadlockRadarVerdict,
}

/// Classify candidates into a stable radar report.
#[must_use]
pub fn run_deadlock_radar(candidates: &[DeadlockRadarCandidate]) -> DeadlockRadarReport {
    let mut findings = Vec::new();
    let mut false_positives = Vec::new();
    let mut incomplete = Vec::new();

    for candidate in candidates {
        let hazard_class = candidate.evidence.hazard_class();
        let row = if candidate.evidence.is_hazardous() {
            if candidate.has_concrete_interleaving() {
                DeadlockRadarFinding {
                    id: candidate.id.clone(),
                    surface: candidate.surface.clone(),
                    hazard_class,
                    proof_status: DeadlockRadarProofStatus::ProvenInterleaving,
                    reason: "hazardous pattern has concrete interleaving proof".to_string(),
                    source_refs: candidate.source_refs.clone(),
                    interleaving: candidate.interleaving.clone(),
                    suggested_owner_bead: candidate.suggested_owner_bead.clone(),
                }
            } else {
                DeadlockRadarFinding {
                    id: candidate.id.clone(),
                    surface: candidate.surface.clone(),
                    hazard_class,
                    proof_status: DeadlockRadarProofStatus::Incomplete,
                    reason: "hazardous pattern lacks concrete interleaving proof".to_string(),
                    source_refs: candidate.source_refs.clone(),
                    interleaving: Vec::new(),
                    suggested_owner_bead: candidate.suggested_owner_bead.clone(),
                }
            }
        } else {
            DeadlockRadarFinding {
                id: candidate.id.clone(),
                surface: candidate.surface.clone(),
                hazard_class,
                proof_status: DeadlockRadarProofStatus::FalsePositive,
                reason: candidate.evidence.false_positive_reason().to_string(),
                source_refs: candidate.source_refs.clone(),
                interleaving: Vec::new(),
                suggested_owner_bead: candidate.suggested_owner_bead.clone(),
            }
        };

        match row.proof_status {
            DeadlockRadarProofStatus::ProvenInterleaving => findings.push(row),
            DeadlockRadarProofStatus::FalsePositive => false_positives.push(row),
            DeadlockRadarProofStatus::Incomplete => incomplete.push(row),
        }
    }

    let verdict = if !findings.is_empty() {
        DeadlockRadarVerdict::Finding
    } else if !incomplete.is_empty() {
        DeadlockRadarVerdict::Incomplete
    } else {
        DeadlockRadarVerdict::Pass
    };

    DeadlockRadarReport {
        schema_version: DEADLOCK_RADAR_SCHEMA_VERSION.to_string(),
        candidates_examined: candidates.len(),
        findings,
        false_positives,
        incomplete,
        verdict,
    }
}
