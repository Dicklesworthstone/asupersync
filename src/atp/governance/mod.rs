//! ATP local resource-governance budget gate.
//!
//! The governor is deliberately deterministic and side-effect free. It turns an
//! explicit profile-derived budget plus measured scheduling demand into a
//! stable allow/reject decision that transfer, repair, disk, and relay code can
//! consume without relying on ambient globals.

pub mod config;
#[cfg(test)]
mod e2e_tests;

use crate::atp::profiles::AtpResourceProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Priority class used by weighted fair-share scheduling.
    pub priority: AtpDemandPriority,
}

/// Priority class for ATP resource demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AtpDemandPriority {
    /// Latency-sensitive control work.
    Interactive,
    /// Normal user-visible transfer work.
    #[default]
    Foreground,
    /// Throughput work that may yield to foreground transfers.
    Background,
    /// Best-effort cache fill, seeding, and speculative work.
    BestEffort,
}

impl AtpDemandPriority {
    /// Relative scheduler weight used by priority-weighted fairness.
    #[must_use]
    pub const fn weight(self) -> f64 {
        match self {
            Self::Interactive => 2.0,
            Self::Foreground => 1.0,
            Self::Background => 0.25,
            Self::BestEffort => 0.10,
        }
    }
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpResourceGovernor {
    /// Active enforceable budget.
    pub budget: AtpResourceBudget,
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

/// Transfer identifier for fairness tracking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AtpTransferId(pub String);

impl From<String> for AtpTransferId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for AtpTransferId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Fair share allocation for one transfer among concurrent transfers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtpFairShareAllocation {
    /// Transfer receiving this allocation.
    pub transfer_id: AtpTransferId,
    /// Allocated bandwidth in bytes per second.
    pub bandwidth_bytes_per_second: u64,
    /// Allocated in-flight bytes.
    pub in_flight_bytes: u64,
    /// Allocated repair symbols per second.
    pub repair_symbols_per_second: u32,
    /// Allocated disk write concurrency.
    pub disk_write_concurrency: u16,
    /// Fair share ratio (0.0-1.0) of total resources.
    pub share_ratio: f64,
}

/// Policy for distributing resources among concurrent transfers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpFairnessPolicy {
    /// Equal sharing among all concurrent transfers.
    #[default]
    EqualShare,
    /// Priority-based sharing with background transfers getting less.
    PriorityWeighted,
    /// First transfer gets full allocation, others get limited shares.
    FirstComeFirstServed,
    /// Proportional to transfer size (larger transfers get more).
    SizeProportional,
}

/// Fairness coordinator for distributing resources among concurrent transfers.
#[derive(Debug, Clone)]
pub struct AtpFairnessCoordinator {
    /// Base budget to distribute among transfers.
    budget: AtpResourceBudget,
    /// Policy for fair sharing.
    policy: AtpFairnessPolicy,
    /// Currently tracked transfers and their demands.
    active_transfers: BTreeMap<AtpTransferId, AtpResourceDemand>,
}

impl AtpFairnessCoordinator {
    /// Create a new fairness coordinator with the given budget and policy.
    #[must_use]
    pub fn new(budget: AtpResourceBudget, policy: AtpFairnessPolicy) -> Self {
        Self {
            budget,
            policy,
            active_transfers: BTreeMap::new(),
        }
    }

    /// Register a transfer with its resource demand.
    pub fn register_transfer(&mut self, transfer_id: AtpTransferId, demand: AtpResourceDemand) {
        self.active_transfers.insert(transfer_id, demand);
    }

    /// Unregister a completed or cancelled transfer.
    pub fn unregister_transfer(&mut self, transfer_id: &AtpTransferId) {
        self.active_transfers.remove(transfer_id);
    }

    /// Get current number of active transfers.
    #[must_use]
    pub fn active_transfer_count(&self) -> usize {
        self.active_transfers.len()
    }

    /// Calculate fair share allocations for all active transfers.
    #[must_use]
    pub fn calculate_allocations(&self) -> Vec<AtpFairShareAllocation> {
        if self.active_transfers.is_empty() {
            return Vec::new();
        }

        let transfer_count = self.active_transfers.len();
        let mut allocations = Vec::with_capacity(transfer_count);

        match self.policy {
            AtpFairnessPolicy::EqualShare => {
                self.calculate_equal_share_allocations(&mut allocations, transfer_count)
            }
            AtpFairnessPolicy::PriorityWeighted => {
                self.calculate_priority_weighted_allocations(&mut allocations)
            }
            AtpFairnessPolicy::FirstComeFirstServed => {
                self.calculate_fcfs_allocations(&mut allocations)
            }
            AtpFairnessPolicy::SizeProportional => {
                self.calculate_size_proportional_allocations(&mut allocations)
            }
        }

        allocations
    }

    fn calculate_equal_share_allocations(
        &self,
        allocations: &mut Vec<AtpFairShareAllocation>,
        transfer_count: usize,
    ) {
        let share_ratio = 1.0 / transfer_count as f64;

        for transfer_id in self.active_transfers.keys() {
            allocations.push(AtpFairShareAllocation {
                transfer_id: transfer_id.clone(),
                bandwidth_bytes_per_second: self
                    .budget
                    .max_bandwidth_bytes_per_second
                    .map_or(u64::MAX, |b| b / transfer_count as u64),
                in_flight_bytes: self
                    .budget
                    .max_in_flight_bytes
                    .map_or(u64::MAX, |b| b / transfer_count as u64),
                repair_symbols_per_second: self
                    .budget
                    .max_repair_symbols_per_second
                    .map_or(u32::MAX, |r| r / transfer_count as u32),
                disk_write_concurrency: self
                    .budget
                    .max_disk_write_concurrency
                    .map_or(u16::MAX, |d| d.max(1) / transfer_count as u16),
                share_ratio,
            });
        }
    }

    fn calculate_priority_weighted_allocations(
        &self,
        allocations: &mut Vec<AtpFairShareAllocation>,
    ) {
        let total_weight: f64 = self
            .active_transfers
            .values()
            .map(|demand| demand.priority.weight())
            .sum();

        for (transfer_id, demand) in &self.active_transfers {
            let weight = demand.priority.weight();
            let share_ratio = weight / total_weight;

            allocations.push(AtpFairShareAllocation {
                transfer_id: transfer_id.clone(),
                bandwidth_bytes_per_second: self
                    .budget
                    .max_bandwidth_bytes_per_second
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                in_flight_bytes: self
                    .budget
                    .max_in_flight_bytes
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                repair_symbols_per_second: self
                    .budget
                    .max_repair_symbols_per_second
                    .map_or(u32::MAX, |r| ((r as f64) * share_ratio) as u32),
                disk_write_concurrency: self
                    .budget
                    .max_disk_write_concurrency
                    .map_or(u16::MAX, |d| (((d as f64) * share_ratio) as u16).max(1)),
                share_ratio,
            });
        }
    }

    fn calculate_fcfs_allocations(&self, allocations: &mut Vec<AtpFairShareAllocation>) {
        // First transfer gets 70% of resources, others share the remaining 30%
        let mut is_first = true;
        let remaining_count = self.active_transfers.len().saturating_sub(1);

        for transfer_id in self.active_transfers.keys() {
            let share_ratio = if is_first {
                0.7
            } else if remaining_count > 0 {
                0.3 / remaining_count as f64
            } else {
                0.0
            };

            allocations.push(AtpFairShareAllocation {
                transfer_id: transfer_id.clone(),
                bandwidth_bytes_per_second: self
                    .budget
                    .max_bandwidth_bytes_per_second
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                in_flight_bytes: self
                    .budget
                    .max_in_flight_bytes
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                repair_symbols_per_second: self
                    .budget
                    .max_repair_symbols_per_second
                    .map_or(u32::MAX, |r| ((r as f64) * share_ratio) as u32),
                disk_write_concurrency: self
                    .budget
                    .max_disk_write_concurrency
                    .map_or(u16::MAX, |d| (((d as f64) * share_ratio) as u16).max(1)),
                share_ratio,
            });

            is_first = false;
        }
    }

    fn calculate_size_proportional_allocations(
        &self,
        allocations: &mut Vec<AtpFairShareAllocation>,
    ) {
        // Use in_flight_bytes as a proxy for transfer size
        let total_size: u64 = self
            .active_transfers
            .values()
            .map(|demand| demand.in_flight_bytes.max(1))
            .sum();

        for (transfer_id, demand) in &self.active_transfers {
            let transfer_size = demand.in_flight_bytes.max(1);
            let share_ratio = transfer_size as f64 / total_size as f64;

            allocations.push(AtpFairShareAllocation {
                transfer_id: transfer_id.clone(),
                bandwidth_bytes_per_second: self
                    .budget
                    .max_bandwidth_bytes_per_second
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                in_flight_bytes: self
                    .budget
                    .max_in_flight_bytes
                    .map_or(u64::MAX, |b| ((b as f64) * share_ratio) as u64),
                repair_symbols_per_second: self
                    .budget
                    .max_repair_symbols_per_second
                    .map_or(u32::MAX, |r| ((r as f64) * share_ratio) as u32),
                disk_write_concurrency: self
                    .budget
                    .max_disk_write_concurrency
                    .map_or(u16::MAX, |d| (((d as f64) * share_ratio) as u16).max(1)),
                share_ratio,
            });
        }
    }

    /// Get the base budget being distributed.
    #[must_use]
    pub const fn budget(&self) -> &AtpResourceBudget {
        &self.budget
    }

    /// Get the fairness policy being used.
    #[must_use]
    pub const fn policy(&self) -> AtpFairnessPolicy {
        self.policy
    }

    /// Update the base budget (typically from config changes).
    pub fn update_budget(&mut self, budget: AtpResourceBudget) {
        self.budget = budget;
    }

    /// Update the fairness policy.
    pub fn update_policy(&mut self, policy: AtpFairnessPolicy) {
        self.policy = policy;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AtpDemandPriority, AtpFairnessCoordinator, AtpFairnessPolicy, AtpGovernanceViolationKind,
        AtpResourceBudget, AtpResourceDemand, AtpResourceGovernor, AtpTransferId,
    };
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
            priority: AtpDemandPriority::Foreground,
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
            priority: AtpDemandPriority::Foreground,
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
            priority: AtpDemandPriority::Foreground,
        });

        assert!(decision.allowed);
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn fairness_coordinator_equal_share_distributes_resources() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        // Register two transfers
        coordinator.register_transfer(
            "transfer1".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 64 * 1_048_576,
                in_flight_bytes: 32 * 1_048_576,
                repair_symbols_per_second: 1_024,
                disk_write_concurrency: 2,
                relay_cost_micros_per_mib: None,
                priority: AtpDemandPriority::Foreground,
            },
        );
        coordinator.register_transfer(
            "transfer2".into(),
            AtpResourceDemand {
                bandwidth_bytes_per_second: 32 * 1_048_576,
                in_flight_bytes: 16 * 1_048_576,
                repair_symbols_per_second: 512,
                disk_write_concurrency: 1,
                relay_cost_micros_per_mib: None,
                priority: AtpDemandPriority::Foreground,
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 2);

        // Each should get 50% of resources
        for allocation in &allocations {
            assert!((allocation.share_ratio - 0.5).abs() < 0.01);
            assert_eq!(allocation.bandwidth_bytes_per_second, 64 * 1_048_576); // 128/2
            assert_eq!(allocation.in_flight_bytes, 64 * 1_048_576); // 128/2
            assert_eq!(allocation.repair_symbols_per_second, 2_048); // 4096/2
            assert_eq!(allocation.disk_write_concurrency, 2); // 4/2
        }
    }

    #[test]
    fn fairness_coordinator_priority_weighted_uses_demand_priority() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::PriorityWeighted);

        coordinator.register_transfer(
            "interactive".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Interactive,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "foreground".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Foreground,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "background".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::Background,
                ..AtpResourceDemand::default()
            },
        );
        coordinator.register_transfer(
            "best_effort".into(),
            AtpResourceDemand {
                priority: AtpDemandPriority::BestEffort,
                ..AtpResourceDemand::default()
            },
        );

        let allocations = coordinator.calculate_allocations();
        let interactive = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "interactive")
            .unwrap();
        let foreground = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "foreground")
            .unwrap();
        let background = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "background")
            .unwrap();
        let best_effort = allocations
            .iter()
            .find(|allocation| allocation.transfer_id.0 == "best_effort")
            .unwrap();

        assert!(interactive.share_ratio > foreground.share_ratio);
        assert!(foreground.share_ratio > background.share_ratio);
        assert!(background.share_ratio > best_effort.share_ratio);
        assert!(
            (allocations
                .iter()
                .map(|allocation| allocation.share_ratio)
                .sum::<f64>()
                - 1.0)
                .abs()
                < 0.000_001
        );
    }

    #[test]
    fn fairness_coordinator_fcfs_gives_priority_to_first_transfer() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::FirstComeFirstServed);

        // Register transfers in order
        coordinator.register_transfer("first".into(), AtpResourceDemand::default());
        coordinator.register_transfer("second".into(), AtpResourceDemand::default());
        coordinator.register_transfer("third".into(), AtpResourceDemand::default());

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 3);

        // First transfer should get 70% of resources
        assert!((allocations[0].share_ratio - 0.7).abs() < 0.01);
        assert_eq!(allocations[0].transfer_id.0, "first");

        // Others should share the remaining 30% (15% each)
        for allocation in &allocations[1..] {
            assert!((allocation.share_ratio - 0.15).abs() < 0.01);
        }
    }

    #[test]
    fn fairness_coordinator_size_proportional_allocates_by_transfer_size() {
        let budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::Balanced,
        ));
        let mut coordinator =
            AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::SizeProportional);

        // Small transfer: 1 MiB
        coordinator.register_transfer(
            "small".into(),
            AtpResourceDemand {
                in_flight_bytes: 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        // Large transfer: 9 MiB
        coordinator.register_transfer(
            "large".into(),
            AtpResourceDemand {
                in_flight_bytes: 9 * 1_048_576,
                ..AtpResourceDemand::default()
            },
        );

        let allocations = coordinator.calculate_allocations();
        assert_eq!(allocations.len(), 2);

        // Small transfer should get ~10% (1/10)
        let small_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "small")
            .unwrap();
        assert!((small_alloc.share_ratio - 0.1).abs() < 0.01);

        // Large transfer should get ~90% (9/10)
        let large_alloc = allocations
            .iter()
            .find(|a| a.transfer_id.0 == "large")
            .unwrap();
        assert!((large_alloc.share_ratio - 0.9).abs() < 0.01);
    }

    #[test]
    fn fairness_coordinator_unregister_transfer_removes_from_tracking() {
        let budget = AtpResourceBudget::default();
        let mut coordinator = AtpFairnessCoordinator::new(budget, AtpFairnessPolicy::EqualShare);

        let transfer_id: AtpTransferId = "test_transfer".into();
        coordinator.register_transfer(transfer_id.clone(), AtpResourceDemand::default());
        assert_eq!(coordinator.active_transfer_count(), 1);

        coordinator.unregister_transfer(&transfer_id);
        assert_eq!(coordinator.active_transfer_count(), 0);
        assert!(coordinator.calculate_allocations().is_empty());
    }

    #[test]
    fn fairness_coordinator_budget_and_policy_updates() {
        let initial_budget = AtpResourceBudget::default();
        let mut coordinator =
            AtpFairnessCoordinator::new(initial_budget, AtpFairnessPolicy::EqualShare);

        assert_eq!(coordinator.policy(), AtpFairnessPolicy::EqualShare);

        // Update policy
        coordinator.update_policy(AtpFairnessPolicy::FirstComeFirstServed);
        assert_eq!(
            coordinator.policy(),
            AtpFairnessPolicy::FirstComeFirstServed
        );

        // Update budget
        let new_budget = AtpResourceBudget::from_profile(AtpResourceProfile::for_power_profile(
            AtpPowerProfile::MaxSpeed,
        ));
        coordinator.update_budget(new_budget);
        assert_eq!(*coordinator.budget(), new_budget);
    }

    #[test]
    fn fairness_policy_default_is_equal_share() {
        assert_eq!(AtpFairnessPolicy::default(), AtpFairnessPolicy::EqualShare);
    }

    #[test]
    fn transfer_id_conversions_work() {
        let id1: AtpTransferId = "test".into();
        let id2: AtpTransferId = String::from("test").into();
        assert_eq!(id1, id2);
        assert_eq!(id1.0, "test");
    }
}
