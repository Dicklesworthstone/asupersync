//! Online consistency between obligation admission and its arena projection.
//!
//! Checked admission owns a region credit before its Reserve reaches the arena.
//! A terminal decision releases the live quota before the terminal post reaches
//! the arena, and a handoff can move a credit before its record moves. Comparing
//! the region's live count directly with Reserved records is therefore invalid.
//!
//! This checker compares the actual records, current credit decisions, ticket
//! bindings, and region accounting while holding the region's admission gate.
//! Queued checked Reserve/Handoff projections explicitly defer equality. They
//! never masquerade as an empty or verified marking. Terminal posts need no
//! deferral: their decided credit contributes an unapplied barrier but no live
//! quota. Region close additionally requires an empty actual arena marking.
//!
//! When enabled, a second ledger counts arena reservations and terminals even
//! after resolved-record retention reaps their records. Its epoch starts with
//! the pending records present at enablement. Per-region, per-kind conservation
//! includes cross-region handoffs and independently reconstructs live records.
//! Finalized region buckets are retired after verification; aggregate lifetime
//! totals survive. Neither ledger proves conservation of credits whose ownership
//! projection is still queued, including unprojected legacy registration posts.

use super::obligation_mailbox::{
    AdmittedObligation, ObligationCreditProjection, ObligationMailbox,
};
use super::obligation_table::ObligationTable;
use super::region_table::RegionTable;
use crate::record::{ObligationKind, ObligationRecord, ObligationResolution};
use crate::types::{ObligationId, RegionId, TaskId};
use crate::util::det_hash::DetHashMap;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Runtime boundary at which an obligation projection was inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObligationConservationCheckpoint {
    /// An explicit inspection or initial enablement.
    Inspection,
    /// A completed mailbox drain, including a bounded partial drain.
    MailboxDrain,
    /// The final barrier before closing and reclaiming a region.
    RegionClose,
}

/// A disagreement between independently held obligation state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObligationConservationIssue {
    /// A pending arena record references a missing region generation.
    MissingRegion,
    /// A record's stored identity disagrees with its actual arena slot.
    RecordIdentityMismatch {
        /// Identity stored in the record.
        recorded: ObligationId,
    },
    /// A checked credit references an absent or already terminal arena record.
    MissingPendingRecord,
    /// Arena ownership disagrees with the checked credit's exact generations.
    CreditBindingMismatch {
        /// Holder generation named by the credit.
        credit_holder: TaskId,
        /// Region generation named by the credit.
        credit_region: RegionId,
    },
    /// An arena-associated credit was never accepted or already applied.
    InactiveCredit,
    /// A successor still owns a credit after all handoff receipts were applied.
    UnprojectedHandoff,
    /// A checked credit's ticket does not identify its actual arena record.
    TicketBindingMismatch {
        /// Actual ticket binding, including an absent binding.
        observed: Option<ObligationId>,
    },
    /// The live quota disagrees with pending direct and undecided checked work.
    LiveCountMismatch {
        /// Count reconstructed from arena records and credit decisions.
        expected: usize,
        /// Count held by the region's admission gate.
        observed: usize,
    },
    /// The close barrier disagrees with the checked credits awaiting application.
    UnappliedCountMismatch {
        /// Number of current checked credits still awaiting terminal projection.
        expected: usize,
        /// Count held by the region's admission gate.
        observed: usize,
    },
    /// Cached close readiness would reclaim a region with a pending arena record.
    PendingAtClose,
    /// Historical reservations and terminals disagree with actual live records.
    LifetimeCountMismatch {
        /// Counts for this exact region generation and obligation kind.
        counts: ObligationLifetimeCounts,
        /// Last lifecycle transition recorded for this bucket, if any.
        last_transition: Option<ObligationLifetimeTransition>,
    },
    /// A lifetime counter could no longer represent the exact transition count.
    LifetimeCounterOverflow {
        /// Transition whose counter overflowed.
        transition: ObligationLifetimeTransition,
    },
}

/// An arena lifecycle transition counted by the optional lifetime ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObligationLifetimeTransition {
    /// An already-pending record included when monitoring was enabled.
    Baseline,
    /// A new pending record entered the arena.
    Reserve,
    /// A pending record committed.
    Commit,
    /// A pending record aborted.
    Abort,
    /// A pending record was marked leaked.
    Leak,
    /// An existing pending record entered another region generation.
    TransferIn,
    /// An existing pending record left this region generation.
    TransferOut,
    /// Low-level arena access removed a record without a terminal transition.
    RemovePending,
}

/// Lifetime counts since monitoring was enabled, independent of record retention.
///
/// Conservation requires `baseline_live + reserved + transferred_in` to equal
/// `committed + aborted + leaked + transferred_out + live`. `live` is scanned
/// from actual pending arena records, never inferred from the other counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObligationLifetimeCounts {
    /// Pending records present at enablement; earlier history is unavailable.
    pub baseline_live: u128,
    /// New pending records admitted to the arena after enablement.
    pub reserved: u128,
    /// Successful arena commit transitions, including reaped records.
    pub committed: u128,
    /// Successful arena abort transitions, including reaped records.
    pub aborted: u128,
    /// Successful arena leak transitions.
    pub leaked: u128,
    /// Pending records transferred into a different region generation.
    pub transferred_in: u128,
    /// Pending records transferred out to a different region generation.
    pub transferred_out: u128,
    /// Pending records independently observed at this checkpoint.
    pub live: u128,
}

impl ObligationLifetimeCounts {
    /// Whether the exact arithmetic establishes the lifetime place invariant.
    /// Overflow never produces a verified balance.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        let (admitted, accounted) = self.sides();
        admitted.is_some() && admitted == accounted
    }

    fn sides(&self) -> (Option<u128>, Option<u128>) {
        let admitted = self
            .baseline_live
            .checked_add(self.reserved)
            .and_then(|count| count.checked_add(self.transferred_in));
        let accounted = self
            .committed
            .checked_add(self.aborted)
            .and_then(|count| count.checked_add(self.leaked))
            .and_then(|count| count.checked_add(self.transferred_out))
            .and_then(|count| count.checked_add(self.live));
        (admitted, accounted)
    }

    fn note(&mut self, transition: ObligationLifetimeTransition) -> bool {
        let counter = match transition {
            ObligationLifetimeTransition::Baseline => &mut self.baseline_live,
            ObligationLifetimeTransition::Reserve => &mut self.reserved,
            ObligationLifetimeTransition::Commit => &mut self.committed,
            ObligationLifetimeTransition::Abort => &mut self.aborted,
            ObligationLifetimeTransition::Leak => &mut self.leaked,
            ObligationLifetimeTransition::TransferIn => &mut self.transferred_in,
            ObligationLifetimeTransition::TransferOut => &mut self.transferred_out,
            ObligationLifetimeTransition::RemovePending => return true,
        };
        let Some(next) = counter.checked_add(1) else {
            return false;
        };
        *counter = next;
        let (admitted, accounted) = self.sides();
        admitted.is_some() && accounted.is_some()
    }
}

/// Aggregate history for one obligation kind across all region generations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObligationLifetimeKindReport {
    /// Obligation kind whose lifecycle was counted.
    pub kind: ObligationKind,
    /// Counts since enablement, including finalized regions and reaped records.
    pub counts: ObligationLifetimeCounts,
}

/// Lifetime coverage for projected arena records since enablement.
///
/// Queued admission receipts remain governed by the enclosing report's deferral
/// fields. Pre-enable terminals and imported already-terminal records are not
/// reconstructed as history. Re-enabling preserves the original epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObligationLifetimeReport {
    /// Region/kind history buckets retained at this checkpoint.
    pub retained_region_kinds: usize,
    /// Aggregate totals in deterministic obligation-kind order.
    pub by_kind: Vec<ObligationLifetimeKindReport>,
}

#[derive(Debug, Default)]
struct LifetimeBucket {
    counts: ObligationLifetimeCounts,
    last_transition: Option<ObligationLifetimeTransition>,
    last_obligation: Option<ObligationId>,
}

/// Stored with the authoritative arena, so every successful lifecycle operation
/// and ledger update share its existing lock. Disabled monitoring allocates no ledger.
#[derive(Debug, Default)]
pub(crate) struct ObligationLifetimeLedger {
    by_region: BTreeMap<(RegionId, ObligationKind), LifetimeBucket>,
    totals: BTreeMap<ObligationKind, ObligationLifetimeCounts>,
    overflow: Option<(
        RegionId,
        ObligationKind,
        ObligationId,
        ObligationLifetimeTransition,
    )>,
}

impl ObligationLifetimeLedger {
    pub(crate) fn note(
        &mut self,
        id: ObligationId,
        region: RegionId,
        kind: ObligationKind,
        transition: ObligationLifetimeTransition,
    ) {
        let bucket = self.by_region.entry((region, kind)).or_default();
        bucket.last_transition = Some(transition);
        bucket.last_obligation = Some(id);
        let region_exact = bucket.counts.note(transition);
        let total_exact = self.totals.entry(kind).or_default().note(transition);
        if !region_exact || !total_exact {
            self.overflow.get_or_insert((region, kind, id, transition));
        }
    }

    pub(crate) fn resolved(
        &mut self,
        id: ObligationId,
        region: RegionId,
        kind: ObligationKind,
        resolution: ObligationResolution,
    ) {
        let transition = match resolution {
            ObligationResolution::Commit => ObligationLifetimeTransition::Commit,
            ObligationResolution::Abort(_) => ObligationLifetimeTransition::Abort,
            ObligationResolution::Leak => ObligationLifetimeTransition::Leak,
        };
        self.note(id, region, kind, transition);
    }

    pub(crate) fn transferred(
        &mut self,
        id: ObligationId,
        old_region: RegionId,
        region: RegionId,
        kind: ObligationKind,
    ) {
        if old_region != region {
            self.note(
                id,
                old_region,
                kind,
                ObligationLifetimeTransition::TransferOut,
            );
            self.note(id, region, kind, ObligationLifetimeTransition::TransferIn);
        }
    }

    fn check(
        &self,
        live: &BTreeMap<(RegionId, ObligationKind), u128>,
        checkpoint: ObligationConservationCheckpoint,
        only_region: Option<RegionId>,
    ) -> Option<ObligationConservationViolation> {
        if let Some((region, kind, id, transition)) = self.overflow {
            // An inexact global history cannot certify another region's close.
            return Some(ObligationConservationViolation {
                checkpoint,
                region,
                obligation: Some(id),
                kind: Some(kind),
                ticket: None,
                issue: ObligationConservationIssue::LifetimeCounterOverflow { transition },
            });
        }
        // Include observed buckets without any recorded reservation as well as
        // recorded buckets whose entire live marking has disappeared.
        let mut keys: Vec<_> = self
            .by_region
            .keys()
            .chain(live.keys())
            .copied()
            .filter(|(region, _)| only_region.is_none_or(|only| only == *region))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        for (region, kind) in keys {
            if only_region.is_some_and(|only| only != region) {
                continue;
            }
            let bucket = self.by_region.get(&(region, kind));
            let mut counts = bucket.map_or_else(ObligationLifetimeCounts::default, |b| b.counts);
            counts.live = live.get(&(region, kind)).copied().unwrap_or_default();
            if !counts.is_balanced() {
                return Some(ObligationConservationViolation {
                    checkpoint,
                    region,
                    obligation: bucket.and_then(|b| b.last_obligation),
                    kind: Some(kind),
                    ticket: None,
                    issue: ObligationConservationIssue::LifetimeCountMismatch {
                        counts,
                        last_transition: bucket.and_then(|b| b.last_transition),
                    },
                });
            }
        }
        None
    }

    pub(crate) fn inspect(
        &self,
        obligations: &ObligationTable,
        checkpoint: ObligationConservationCheckpoint,
    ) -> (
        ObligationLifetimeReport,
        Option<ObligationConservationViolation>,
    ) {
        let live = live_marking(obligations, None);
        let fault = self.check(&live, checkpoint, None);
        let mut totals = self.totals.clone();
        for (&(_, kind), &count) in &live {
            totals.entry(kind).or_default().live += count;
        }
        (
            ObligationLifetimeReport {
                retained_region_kinds: self.by_region.len(),
                by_kind: totals
                    .into_iter()
                    .map(|(kind, counts)| ObligationLifetimeKindReport { kind, counts })
                    .collect(),
            },
            fault,
        )
    }

    pub(crate) fn check_close(
        &self,
        region: RegionId,
        obligations: &ObligationTable,
    ) -> Option<ObligationConservationViolation> {
        self.check(
            &live_marking(obligations, Some(region)),
            ObligationConservationCheckpoint::RegionClose,
            Some(region),
        )
    }

    /// Called only after independently checking an empty, conserved marking.
    pub(crate) fn retire_region(&mut self, region: RegionId) {
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
            ObligationKind::Transaction,
        ] {
            let _ = self.by_region.remove(&(region, kind));
        }
    }
}

fn live_marking(
    obligations: &ObligationTable,
    only_region: Option<RegionId>,
) -> BTreeMap<(RegionId, ObligationKind), u128> {
    let mut live = BTreeMap::new();
    for (_, record) in obligations.iter().filter(|(_, record)| {
        record.is_pending() && only_region.is_none_or(|region| record.region == region)
    }) {
        *live.entry((record.region, record.kind)).or_default() += 1;
    }
    live
}

/// Typed evidence of the first detected projection disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObligationConservationViolation {
    /// Boundary that detected the disagreement.
    pub checkpoint: ObligationConservationCheckpoint,
    /// Exact region generation affected.
    pub region: RegionId,
    /// Exact arena identity, when the disagreement involves one record.
    /// Lifetime disagreements identify the bucket's last recorded transition.
    pub obligation: Option<ObligationId>,
    /// Obligation kind, when a record supplies it.
    pub kind: Option<ObligationKind>,
    /// Checked admission ticket, when one is involved.
    pub ticket: Option<u64>,
    /// Independently observed states that disagree.
    pub issue: ObligationConservationIssue,
}

impl std::fmt::Display for ObligationConservationViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ASUP-E106] obligation projection invariant at {:?}: region={:?} obligation={:?} kind={:?} ticket={:?} issue={:?}",
            self.checkpoint, self.region, self.obligation, self.kind, self.ticket, self.issue
        )
    }
}

impl std::error::Error for ObligationConservationViolation {}

/// Coverage and evidence from online obligation projection inspection.
///
/// A monitor latches its first violation, even if later drains happen to repair
/// the disagreement. The other fields describe its latest checkpoint. An empty
/// `violation` alone is not a conservation proof: queued ownership projections
/// appear in `deferred_regions` and must be inspected after their receipts apply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObligationConservationReport {
    /// Latest inspected boundary.
    pub checkpoint: ObligationConservationCheckpoint,
    /// Regions whose projection equality was checked at this boundary.
    pub checked_regions: usize,
    /// Regions whose equality could not yet be established.
    pub deferred_regions: Vec<RegionId>,
    /// A checked Reserve/Handoff receipt was pending during inspection.
    /// This remains explicit even when a damaged region table has no rows from
    /// which to name deferred region identities.
    pub pending_ownership_projection: bool,
    /// Aggregate historical arena counts when this checkpoint collected them.
    /// `None` means no aggregate lifetime snapshot was collected.
    pub lifetime: Option<ObligationLifetimeReport>,
    /// First disagreement seen by this inspection or enabled monitor.
    pub violation: Option<ObligationConservationViolation>,
}

impl ObligationConservationReport {
    fn new(checkpoint: ObligationConservationCheckpoint) -> Self {
        Self {
            checkpoint,
            checked_regions: 0,
            deferred_regions: Vec::new(),
            pending_ownership_projection: false,
            lifetime: None,
            violation: None,
        }
    }

    /// Whether this checkpoint established projection equality without a fault.
    /// Historical conservation is included only when `lifetime` is present.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.violation.is_none()
            && self.deferred_regions.is_empty()
            && !self.pending_ownership_projection
    }
}

#[derive(Debug)]
pub(crate) struct ObligationConservationMonitor {
    latest: ObligationConservationReport,
}

impl ObligationConservationMonitor {
    pub(crate) fn new() -> Self {
        Self {
            latest: ObligationConservationReport::new(ObligationConservationCheckpoint::Inspection),
        }
    }

    pub(crate) fn record(&mut self, mut report: ObligationConservationReport) {
        if self.latest.violation.is_some() {
            report.violation.clone_from(&self.latest.violation);
        }
        self.latest = report;
    }

    pub(crate) fn snapshot(&self) -> ObligationConservationReport {
        self.latest.clone()
    }

    pub(crate) fn refuse_close(&mut self, violation: ObligationConservationViolation) {
        let mut report =
            ObligationConservationReport::new(ObligationConservationCheckpoint::RegionClose);
        report.checked_regions = 1;
        report.violation = Some(violation);
        self.record(report);
    }
}

fn violation(
    checkpoint: ObligationConservationCheckpoint,
    region: RegionId,
    record: Option<&ObligationRecord>,
    ticket: Option<u64>,
    issue: ObligationConservationIssue,
) -> ObligationConservationViolation {
    ObligationConservationViolation {
        checkpoint,
        region,
        obligation: record.map(|record| record.id),
        kind: record.map(|record| record.kind),
        ticket,
        issue,
    }
}

/// The state/table owner excludes arena mutation. Each region read gate below
/// excludes producer admit, settle, and both ends of transfer, whose mutations
/// all require that same gate for writing. Never retain a credit decision or
/// ticket guard while acquiring a region gate.
pub(crate) fn inspect_projection(
    regions: &RegionTable,
    obligations: &ObligationTable,
    admitted: &DetHashMap<ObligationId, Arc<AdmittedObligation>>,
    mailbox: Option<&ObligationMailbox>,
    checkpoint: ObligationConservationCheckpoint,
) -> ObligationConservationReport {
    let mut report =
        inspect_current_projection(regions, obligations, admitted, mailbox, checkpoint);
    if let Some((lifetime, fault)) = obligations.inspect_lifetime(checkpoint) {
        report.lifetime = Some(lifetime);
        if report.violation.is_none() {
            report.violation = fault;
        }
    }
    report
}

#[allow(clippy::too_many_lines)]
fn inspect_current_projection(
    regions: &RegionTable,
    obligations: &ObligationTable,
    admitted: &DetHashMap<ObligationId, Arc<AdmittedObligation>>,
    mailbox: Option<&ObligationMailbox>,
    checkpoint: ObligationConservationCheckpoint,
) -> ObligationConservationReport {
    let mut report = ObligationConservationReport::new(checkpoint);
    report.pending_ownership_projection =
        mailbox.is_some_and(ObligationMailbox::has_pending_ownership_projection);
    let mut pending_by_region: BTreeMap<RegionId, Vec<&ObligationRecord>> = BTreeMap::new();
    for (index, record) in obligations.iter().filter(|(_, record)| record.is_pending()) {
        let actual = ObligationId::from_arena(index);
        if record.id != actual {
            let mut fault = violation(
                checkpoint,
                record.region,
                Some(record),
                None,
                ObligationConservationIssue::RecordIdentityMismatch {
                    recorded: record.id,
                },
            );
            fault.obligation = Some(actual);
            report.violation = Some(fault);
            return report;
        }
        if regions.get(record.region.arena_index()).is_none() {
            report.violation = Some(violation(
                checkpoint,
                record.region,
                Some(record),
                None,
                ObligationConservationIssue::MissingRegion,
            ));
            return report;
        }
        pending_by_region
            .entry(record.region)
            .or_default()
            .push(record);
    }

    // Sort by exact identities; deterministic reports must not depend on a map's
    // iteration order when several independent faults were planted.
    let mut credits: Vec<_> = admitted.iter().collect();
    credits.sort_unstable_by_key(|(id, _)| **id);
    let mut credits_by_region: BTreeMap<RegionId, Vec<ObligationId>> = BTreeMap::new();
    for (&id, credit) in credits {
        let (ticket, _, region) = credit.binding();
        if regions.get(region.arena_index()).is_none() {
            report.violation = Some(ObligationConservationViolation {
                checkpoint,
                region,
                obligation: Some(id),
                kind: obligations.get(id.arena_index()).map(|record| record.kind),
                ticket: Some(ticket),
                issue: ObligationConservationIssue::MissingRegion,
            });
            return report;
        }
        credits_by_region.entry(region).or_default().push(id);
    }

    for (_, region) in regions.iter() {
        let checked = region.with_obligation_accounting(|live, unapplied| {
            // Read AFTER acquiring this region's gate. Publication of a credit
            // or handoff involving this region also holds that gate for writing.
            // Other regions can publish concurrently, causing a conservative
            // deferral, but cannot make an unprojected credit here invisible.
            if mailbox.is_some_and(ObligationMailbox::has_pending_ownership_projection) {
                report.pending_ownership_projection = true;
                return None;
            }
            let records = pending_by_region
                .get(&region.id)
                .map_or(&[][..], Vec::as_slice);
            let mut expected_live = 0;
            let mut expected_unapplied = 0;
            for &record in records {
                let Some(credit) = admitted.get(&record.id) else {
                    expected_live += 1;
                    continue;
                };
                let (ticket, holder, credit_region) = credit.binding();
                let fault =
                    |issue| violation(checkpoint, region.id, Some(record), Some(ticket), issue);
                if holder != record.holder || credit_region != record.region {
                    return Some(Err(fault(
                        ObligationConservationIssue::CreditBindingMismatch {
                            credit_holder: holder,
                            credit_region,
                        },
                    )));
                }
                match credit.projection_state() {
                    ObligationCreditProjection::Pending => expected_live += 1,
                    ObligationCreditProjection::Terminal => {}
                    ObligationCreditProjection::Inactive => {
                        return Some(Err(fault(ObligationConservationIssue::InactiveCredit)));
                    }
                    ObligationCreditProjection::HandedOff => {
                        return Some(Err(fault(ObligationConservationIssue::UnprojectedHandoff)));
                    }
                }
                expected_unapplied += 1;
                let observed = mailbox.and_then(|mailbox| mailbox.ticket_binding(ticket));
                if observed != Some(record.id) {
                    return Some(Err(fault(
                        ObligationConservationIssue::TicketBindingMismatch { observed },
                    )));
                }
            }
            for &id in credits_by_region
                .get(&region.id)
                .map_or(&[][..], Vec::as_slice)
            {
                if obligations
                    .get(id.arena_index())
                    .is_none_or(|record| !record.is_pending())
                {
                    return Some(Err(ObligationConservationViolation {
                        checkpoint,
                        region: region.id,
                        obligation: Some(id),
                        kind: obligations.get(id.arena_index()).map(|record| record.kind),
                        ticket: admitted.get(&id).map(|credit| credit.binding().0),
                        issue: ObligationConservationIssue::MissingPendingRecord,
                    }));
                }
            }
            if live != expected_live {
                return Some(Err(violation(
                    checkpoint,
                    region.id,
                    None,
                    None,
                    ObligationConservationIssue::LiveCountMismatch {
                        expected: expected_live,
                        observed: live,
                    },
                )));
            }
            if unapplied != expected_unapplied {
                return Some(Err(violation(
                    checkpoint,
                    region.id,
                    None,
                    None,
                    ObligationConservationIssue::UnappliedCountMismatch {
                        expected: expected_unapplied,
                        observed: unapplied,
                    },
                )));
            }
            Some(Ok(()))
        });
        match checked {
            None => report.deferred_regions.push(region.id),
            Some(Ok(())) => report.checked_regions += 1,
            Some(Err(fault)) => {
                report.violation = Some(fault);
                return report;
            }
        }
    }
    report.deferred_regions.sort_unstable();
    report
}

/// Close cannot rely only on the same counters its readiness predicate reads.
/// Called with the authoritative obligation table already held, before any heap
/// reclamation or region removal; this never reacquires a shard-table lock.
pub(crate) fn pending_at_close(
    region: RegionId,
    obligations: &ObligationTable,
) -> Option<ObligationConservationViolation> {
    obligations
        .iter()
        .find(|(_, record)| record.region == region && record.is_pending())
        .map(|(_, record)| {
            violation(
                ObligationConservationCheckpoint::RegionClose,
                region,
                Some(record),
                None,
                ObligationConservationIssue::PendingAtClose,
            )
        })
        .or_else(|| obligations.lifetime_violation_at_close(region))
}

#[cfg(test)]
#[path = "obligation_conservation_inline_tests.rs"]
mod tests;
