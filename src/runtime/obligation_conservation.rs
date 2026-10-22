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
//! This is projection consistency, not a lifetime conservation ledger. It does
//! not count historical terminals after retention reaps them, and it does not
//! prove conservation of credits whose ownership projection is still queued,
//! including unprojected posts from the legacy unchecked registration API.

use super::obligation_mailbox::{
    AdmittedObligation, ObligationCreditProjection, ObligationMailbox,
};
use super::obligation_table::ObligationTable;
use super::region_table::RegionTable;
use crate::record::{ObligationKind, ObligationRecord};
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
            violation: None,
        }
    }

    /// Whether this checkpoint established projection equality without a fault.
    /// This does not establish lifetime conservation of reaped records.
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
#[allow(clippy::too_many_lines)]
pub(crate) fn inspect_projection(
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
}

#[cfg(test)]
#[path = "obligation_conservation_inline_tests.rs"]
mod tests;
