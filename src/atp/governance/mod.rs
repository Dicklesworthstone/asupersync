//! ATP local resource-governance budget gate.
//!
//! The governor is deliberately deterministic and side-effect free. It turns an
//! explicit profile-derived budget plus measured scheduling demand into a
//! stable allow/reject decision that transfer, repair, disk, and relay code can
//! consume without relying on ambient globals.

use crate::atp::profiles::AtpResourceProfile;
use serde::{Deserialize, Serialize};

/// Enforceable resource budget for one ATP scheduling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpResourceBudget {
    /// Maximum scheduled data bytes per second.
    pub max_bandwidth_bytes_per_second: Option<u64>,
    /// Maximum bytes in flight for one transfer.
    pub max_in_flight_bytes: Option<u64>,
    /// Maximum repair symbols encoded or decoded per second.
    pub max_repair_symbols_per_second: Option<u32>,
    /// Maximum concurrent disk-write jobs for one transfer.
    pub max_disk_write_concurrency: Option<u16>,
    /// Maximum acceptable relay cost in microseconds per MiB.
    pub max_relay_cost_micros_per_mib: Option<u64>,
    /// Whether the transfer should yield to foreground work.
    pub background_priority: bool,
    /// Whether link bytes should be treated as user-visible cost.
    pub metered_network: bool,
}

impl Default for AtpResourceBudget {
    fn default() -> Self {
        Self::from_profile(AtpResourceProfile::default())
    }
}

impl AtpResourceBudget {
    /// Build a budget from a profile preset.
    #[must_use]
    pub const fn from_profile(profile: AtpResourceProfile) -> Self {
        Self {
            max_bandwidth_bytes_per_second: profile.max_bandwidth_bytes_per_second,
            max_in_flight_bytes: profile.max_in_flight_bytes,
            max_repair_symbols_per_second: profile.max_repair_symbols_per_second,
            max_disk_write_concurrency: profile.max_disk_write_concurrency,
            max_relay_cost_micros_per_mib: profile.max_relay_cost_micros_per_mib,
            background_priority: profile.background_priority,
            metered_network: profile.metered_network,
        }
    }
}

/// One transfer scheduling demand to check against a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AtpResourceDemand {
    /// Requested scheduled data bytes per second.
    pub bandwidth_bytes_per_second: u64,
    /// Requested in-flight bytes.
    pub in_flight_bytes: u64,
    /// Requested repair symbols per second.
    pub repair_symbols_per_second: u32,
    /// Requested concurrent disk-write jobs.
    pub disk_write_concurrency: u16,
    /// Expected relay cost in microseconds per MiB, if a relay path is considered.
    pub relay_cost_micros_per_mib: Option<u64>,
}

/// Resource dimension that rejected a demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpGovernanceViolationKind {
    /// Requested bandwidth exceeded the cap.
    BandwidthBytesPerSecond,
    /// Requested in-flight bytes exceeded the cap.
    InFlightBytes,
    /// Requested repair rate exceeded the cap.
    RepairSymbolsPerSecond,
    /// Requested disk-write concurrency exceeded the cap.
    DiskWriteConcurrency,
    /// Expected relay cost exceeded the cap.
    RelayCostMicrosPerMiB,
}

impl AtpGovernanceViolationKind {
    /// Stable metric key for logs and proof artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BandwidthBytesPerSecond => "atp.governance.bandwidth_bytes_per_second",
            Self::InFlightBytes => "atp.governance.in_flight_bytes",
            Self::RepairSymbolsPerSecond => "atp.governance.repair_symbols_per_second",
            Self::DiskWriteConcurrency => "atp.governance.disk_write_concurrency",
            Self::RelayCostMicrosPerMiB => "atp.governance.relay_cost_micros_per_mib",
        }
    }
}

/// One rejected resource dimension with observed and configured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpGovernanceViolation {
    /// Rejected resource dimension.
    pub kind: AtpGovernanceViolationKind,
    /// Requested or observed value.
    pub requested: u64,
    /// Configured cap.
    pub limit: u64,
}

impl AtpGovernanceViolation {
    const fn new(kind: AtpGovernanceViolationKind, requested: u64, limit: u64) -> Self {
        Self {
            kind,
            requested,
            limit,
        }
    }
}

/// Deterministic decision from one resource-governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpGovernanceDecision {
    /// True when every requested resource is within budget.
    pub allowed: bool,
    /// Budget used for the decision.
    pub budget: AtpResourceBudget,
    /// Demand checked by the governor.
    pub demand: AtpResourceDemand,
    /// Rejected dimensions, if any.
    pub violations: Vec<AtpGovernanceViolation>,
    /// Stable reason for human status, JSON status, and proof artifacts.
    pub reason_code: String,
}

impl AtpGovernanceDecision {
    /// Return true when the governor rejected at least one resource dimension.
    #[must_use]
    pub fn rejected(&self) -> bool {
        !self.allowed
    }
}

/// Side-effect-free ATP resource governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpResourceGovernor {
    /// Active enforceable budget.
    pub budget: AtpResourceBudget,
}

impl Default for AtpResourceGovernor {
    fn default() -> Self {
        Self {
            budget: AtpResourceBudget::default(),
        }
    }
}

impl AtpResourceGovernor {
    /// Build a governor from an explicit budget.
    #[must_use]
    pub const fn new(budget: AtpResourceBudget) -> Self {
        Self { budget }
    }

    /// Build a governor from a profile preset.
    #[must_use]
    pub const fn from_profile(profile: AtpResourceProfile) -> Self {
        Self::new(AtpResourceBudget::from_profile(profile))
    }

    /// Check one proposed scheduling demand against the active budget.
    #[must_use]
    pub fn evaluate(&self, demand: AtpResourceDemand) -> AtpGovernanceDecision {
        let mut violations = Vec::new();
        push_if_exceeded(
            &mut violations,
            AtpGovernanceViolationKind::BandwidthBytesPerSecond,
            demand.bandwidth_bytes_per_second,
            self.budget.max_bandwidth_bytes_per_second,
        );
        push_if_exceeded(
            &mut violations,
            AtpGovernanceViolationKind::InFlightBytes,
            demand.in_flight_bytes,
            self.budget.max_in_flight_bytes,
        );
        push_if_exceeded(
            &mut violations,
            AtpGovernanceViolationKind::RepairSymbolsPerSecond,
            u64::from(demand.repair_symbols_per_second),
            self.budget.max_repair_symbols_per_second.map(u64::from),
        );
        push_if_exceeded(
            &mut violations,
            AtpGovernanceViolationKind::DiskWriteConcurrency,
            u64::from(demand.disk_write_concurrency),
            self.budget.max_disk_write_concurrency.map(u64::from),
        );
        if let Some(relay_cost) = demand.relay_cost_micros_per_mib {
            push_if_exceeded(
                &mut violations,
                AtpGovernanceViolationKind::RelayCostMicrosPerMiB,
                relay_cost,
                self.budget.max_relay_cost_micros_per_mib,
            );
        }

        let allowed = violations.is_empty();
        AtpGovernanceDecision {
            allowed,
            budget: self.budget,
            demand,
            violations,
            reason_code: String::from(if allowed {
                "within_resource_budget"
            } else {
                "resource_budget_exceeded"
            }),
        }
    }
}

fn push_if_exceeded(
    violations: &mut Vec<AtpGovernanceViolation>,
    kind: AtpGovernanceViolationKind,
    requested: u64,
    limit: Option<u64>,
) {
    if let Some(limit) = limit {
        if requested > limit {
            violations.push(AtpGovernanceViolation::new(kind, requested, limit));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AtpGovernanceViolationKind, AtpResourceDemand, AtpResourceGovernor};
    use crate::atp::profiles::{AtpPowerProfile, AtpResourceProfile};

    #[test]
    fn balanced_governor_allows_demand_inside_budget() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: 64 * 1_048_576,
            in_flight_bytes: 64 * 1_048_576,
            repair_symbols_per_second: 512,
            disk_write_concurrency: 2,
            relay_cost_micros_per_mib: Some(100_000),
        });

        assert!(decision.allowed);
        assert!(!decision.rejected());
        assert_eq!(decision.reason_code, "within_resource_budget");
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn battery_saver_rejects_over_budget_repair_and_relay_cost() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::BatterySaver,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: 8 * 1_048_576,
            in_flight_bytes: 8 * 1_048_576,
            repair_symbols_per_second: 2_048,
            disk_write_concurrency: 1,
            relay_cost_micros_per_mib: Some(900_000),
        });

        assert!(decision.rejected());
        assert_eq!(decision.reason_code, "resource_budget_exceeded");
        assert_eq!(decision.violations.len(), 2);
        assert_eq!(
            decision.violations[0].kind,
            AtpGovernanceViolationKind::RepairSymbolsPerSecond
        );
        assert_eq!(decision.violations[0].requested, 2_048);
        assert_eq!(decision.violations[0].limit, 512);
        assert_eq!(
            decision.violations[1].kind.as_str(),
            "atp.governance.relay_cost_micros_per_mib"
        );
    }

    #[test]
    fn custom_profile_is_unrestricted_until_callers_set_caps() {
        let governor = AtpResourceGovernor::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Custom,
        ));
        let decision = governor.evaluate(AtpResourceDemand {
            bandwidth_bytes_per_second: u64::MAX,
            in_flight_bytes: u64::MAX,
            repair_symbols_per_second: u32::MAX,
            disk_write_concurrency: u16::MAX,
            relay_cost_micros_per_mib: Some(u64::MAX),
        });

        assert!(decision.allowed);
        assert!(decision.violations.is_empty());
    }
}
