//! Deterministic NUMA-aware pressure projection for artifact-cache lab runs.
//!
//! This module does not probe host topology. It consumes explicit cache and
//! locality inputs so high-core scenarios can replay the same decision on any
//! machine, including CI workers without NUMA visibility.

use crate::runtime::cache::ArtifactMemoryPressureSnapshot;
use serde::{Deserialize, Serialize};

const BPS_DENOMINATOR: u64 = 10_000;

/// Input for deterministic NUMA/cache pressure projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaCachePressureInput {
    /// Stable scenario id for replay receipts.
    pub scenario_id: String,
    /// Cache pressure snapshot produced by the runtime artifact cache.
    pub cache: ArtifactMemoryPressureSnapshot,
    /// Per-agent memory budget for this modeled workload.
    pub agent_budget_bytes: u64,
    /// Current resident bytes attributed to the modeled agent.
    pub agent_resident_bytes: u64,
    /// Bytes expected to be consumed on the local NUMA node.
    pub local_node_bytes: u64,
    /// Bytes expected to be consumed from a remote NUMA node.
    pub remote_node_bytes: u64,
    /// Topology confidence in basis points.
    pub topology_confidence_bps: u16,
    /// Replay pointer for the source scenario or proof bundle.
    pub replay_pointer: String,
}

/// Coarse pressure class used by admission and lab receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPressureClass {
    /// No eviction or spill action is required.
    Green,
    /// Pressure is elevated; cold spill-eligible bytes should move first.
    Amber,
    /// Pressure is critical; admission should defer large artifact producers.
    Red,
}

/// Deterministic projection emitted by the NUMA-aware lab model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaCachePressureProjection {
    /// Stable scenario id.
    pub scenario_id: String,
    /// Combined pressure in basis points.
    pub pressure_bps: u16,
    /// Agent-budget pressure in basis points.
    pub agent_budget_pressure_bps: u16,
    /// Cache pressure in basis points.
    pub cache_pressure_bps: u16,
    /// Remote NUMA access penalty in basis points.
    pub remote_numa_penalty_bps: u16,
    /// Hot-cache discount applied to avoid evicting useful shared bytes.
    pub hot_cache_discount_bps: u16,
    /// Bytes admission should try to evict from memory.
    pub recommended_eviction_bytes: u64,
    /// Bytes safe to spill before evicting non-spillable entries.
    pub spill_to_disk_bytes: u64,
    /// Pressure class.
    pub pressure_class: NumaPressureClass,
    /// True when topology evidence was strong enough to apply NUMA penalty.
    pub numa_hint_used: bool,
    /// Replay pointer for receipts.
    pub replay_pointer: String,
}

/// Project cache and NUMA inputs into a deterministic memory-pressure decision.
#[must_use]
pub fn project_numa_cache_pressure(input: &NumaCachePressureInput) -> NumaCachePressureProjection {
    let agent_budget_pressure_bps = ratio_bps(input.agent_resident_bytes, input.agent_budget_bytes);
    let cache_pressure_bps = input.cache.pressure_bps;
    let numa_hint_used = input.topology_confidence_bps >= 7_500;
    let remote_numa_penalty_bps = if numa_hint_used {
        ratio_bps(input.remote_node_bytes, local_remote_total(input))
    } else {
        0
    };
    let hot_cache_discount_bps = ratio_bps(
        input.cache.hot_resident_bytes,
        input.cache.resident_bytes.max(1),
    )
    .min(2_500);

    let raw_pressure = u64::from(agent_budget_pressure_bps)
        .max(u64::from(cache_pressure_bps))
        .saturating_add(u64::from(remote_numa_penalty_bps) / 2)
        .saturating_sub(u64::from(hot_cache_discount_bps) / 4);
    let pressure_bps = u16::try_from(raw_pressure).unwrap_or(u16::MAX);
    let pressure_class = classify_pressure(pressure_bps);
    let recommended_eviction_bytes = recommended_eviction_bytes(input, pressure_class);
    let spill_to_disk_bytes = input
        .cache
        .spill_eligible_bytes
        .min(recommended_eviction_bytes);

    NumaCachePressureProjection {
        scenario_id: input.scenario_id.clone(),
        pressure_bps,
        agent_budget_pressure_bps,
        cache_pressure_bps,
        remote_numa_penalty_bps,
        hot_cache_discount_bps,
        recommended_eviction_bytes,
        spill_to_disk_bytes,
        pressure_class,
        numa_hint_used,
        replay_pointer: input.replay_pointer.clone(),
    }
}

fn local_remote_total(input: &NumaCachePressureInput) -> u64 {
    input
        .local_node_bytes
        .saturating_add(input.remote_node_bytes)
        .max(1)
}

const fn classify_pressure(pressure_bps: u16) -> NumaPressureClass {
    if pressure_bps >= 9_000 {
        NumaPressureClass::Red
    } else if pressure_bps >= 7_000 {
        NumaPressureClass::Amber
    } else {
        NumaPressureClass::Green
    }
}

fn recommended_eviction_bytes(
    input: &NumaCachePressureInput,
    pressure_class: NumaPressureClass,
) -> u64 {
    match pressure_class {
        NumaPressureClass::Green => 0,
        NumaPressureClass::Amber => input
            .cache
            .resident_bytes
            .saturating_sub(input.cache.hot_resident_bytes)
            .min(input.cache.cold_resident_bytes),
        NumaPressureClass::Red => {
            let over_cache_budget = input
                .cache
                .resident_bytes
                .saturating_sub(input.cache.max_resident_bytes);
            let over_agent_budget = input
                .agent_resident_bytes
                .saturating_sub(input.agent_budget_bytes);
            over_cache_budget
                .saturating_add(over_agent_budget)
                .max(input.cache.cold_resident_bytes)
        }
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return u16::MAX;
    }
    let scaled =
        u128::from(numerator).saturating_mul(u128::from(BPS_DENOMINATOR)) / u128::from(denominator);
    u16::try_from(scaled).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        resident_bytes: u64,
        hot_resident_bytes: u64,
        spill_eligible_bytes: u64,
        pressure_bps: u16,
    ) -> ArtifactMemoryPressureSnapshot {
        ArtifactMemoryPressureSnapshot {
            resident_bytes,
            max_resident_bytes: 1_000,
            hot_resident_bytes,
            cold_resident_bytes: resident_bytes.saturating_sub(hot_resident_bytes),
            spill_eligible_bytes,
            remote_numa_bytes: 0,
            pressure_bps,
            high_pressure: pressure_bps >= 8_500,
            duplicate_bytes_avoided: 0,
            artifact_count: 8,
        }
    }

    fn input(cache: ArtifactMemoryPressureSnapshot) -> NumaCachePressureInput {
        NumaCachePressureInput {
            scenario_id: "asw4-64c-256g".to_string(),
            cache,
            agent_budget_bytes: 1_000,
            agent_resident_bytes: 760,
            local_node_bytes: 700,
            remote_node_bytes: 300,
            topology_confidence_bps: 9_000,
            replay_pointer: "trace://asw4/numa".to_string(),
        }
    }

    #[test]
    fn projection_uses_numa_penalty_when_topology_confidence_is_high() {
        let projection = project_numa_cache_pressure(&input(snapshot(800, 200, 500, 8_000)));

        assert!(projection.numa_hint_used);
        assert_eq!(projection.remote_numa_penalty_bps, 3_000);
        assert_eq!(projection.hot_cache_discount_bps, 2_500);
        assert_eq!(projection.pressure_class, NumaPressureClass::Amber);
        assert_eq!(projection.recommended_eviction_bytes, 600);
        assert_eq!(projection.spill_to_disk_bytes, 500);
    }

    #[test]
    fn low_topology_confidence_uses_portable_fallback() {
        let mut model = input(snapshot(800, 200, 500, 8_000));
        model.topology_confidence_bps = 4_000;

        let projection = project_numa_cache_pressure(&model);

        assert!(!projection.numa_hint_used);
        assert_eq!(projection.remote_numa_penalty_bps, 0);
        assert_eq!(projection.pressure_class, NumaPressureClass::Amber);
    }

    #[test]
    fn red_pressure_targets_budget_overage_and_cold_bytes() {
        let mut model = input(snapshot(1_200, 100, 900, 12_000));
        model.agent_resident_bytes = 1_400;

        let projection = project_numa_cache_pressure(&model);

        assert_eq!(projection.pressure_class, NumaPressureClass::Red);
        assert_eq!(projection.recommended_eviction_bytes, 1_100);
        assert_eq!(projection.spill_to_disk_bytes, 900);
    }

    #[test]
    fn green_pressure_keeps_cache_resident() {
        let mut model = input(snapshot(400, 350, 200, 4_000));
        model.agent_resident_bytes = 300;
        model.remote_node_bytes = 0;

        let projection = project_numa_cache_pressure(&model);

        assert_eq!(projection.pressure_class, NumaPressureClass::Green);
        assert_eq!(projection.recommended_eviction_bytes, 0);
        assert_eq!(projection.spill_to_disk_bytes, 0);
    }
}
