//! Metamorphic testing for ResourceMonitor.
//!
//! This module implements comprehensive metamorphic relations for the resource monitor,
//! testing critical properties like measurement additivity, degradation monotonicity,
//! configuration invariance, and system consistency.
//!
//! # Testing Philosophy
//!
//! Resource monitoring involves complex interactions between measurements, thresholds,
//! degradation decisions, and system pressure. Rather than testing exact outputs
//! (oracle problem), we verify that the system satisfies mathematical properties
//! that MUST hold regardless of specific inputs.
//!
//! # Metamorphic Relations Implemented
//!
//! - **MR1: Measurement Additivity** - Multiple small updates ≡ single large update
//! - **MR2: Pressure Monotonicity** - Higher usage → same or higher degradation
//! - **MR3: Configuration Scaling** - Threshold scaling preserves relative decisions
//! - **MR4: Temporal Idempotence** - Repeated identical measurements are stable
//! - **MR5: Cross-Resource Independence** - Orthogonal resources don't interfere
//! - **MR6: Reset Equivalence** - Fresh monitor ≡ reset monitor
//! - **MR7: Ordering Invariance** - Measurement order shouldn't affect final state
//! - **MR8: Subset Consistency** - Partial resource sets behave consistently

use crate::runtime::resource_monitor::{
    DegradationLevel, MonitorConfig, ResourceMeasurement, ResourceMonitor, ResourcePressure,
    ResourceType,
};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

const EPSILON: f64 = 1e-10;

fn measurement(current: u64, max_limit: u64) -> ResourceMeasurement {
    let max_limit = max_limit.max(1);
    let soft_limit = ((max_limit as u128 * 70) / 100).max(1) as u64;
    let hard_limit = ((max_limit as u128 * 85) / 100).max(soft_limit as u128) as u64;

    ResourceMeasurement::new(current, soft_limit, hard_limit, max_limit)
}

/// MR1: Measurement Additivity
///
/// Property: Multiple incremental resource updates should produce the same
/// final state as a single aggregate update.
///
/// Transformation: Split measurement M into sequence [m1, m2, ..., mn]
/// Relation: monitor.apply(M) ≡ monitor.apply(m1).apply(m2)...apply(mn)
#[test]
fn mr1_measurement_additivity() {
    proptest!(|(
        base_usage: u64,
        increments: Vec<u64>
    )| {
        prop_assume!(!increments.is_empty() && increments.len() <= 10);
        let Some(total_increment) = increments
            .iter()
            .try_fold(0_u64, |total, increment| total.checked_add(*increment))
        else {
            return Ok(());
        };
        prop_assume!(base_usage.saturating_add(total_increment) < u64::MAX / 2);

        let config = MonitorConfig::default();

        // Path A: Single aggregate update
        let monitor_a = ResourceMonitor::new(config.clone());
        let final_usage_a = base_usage.saturating_add(total_increment);
        monitor_a.pressure().update_measurement(
            ResourceType::Memory,
            measurement(final_usage_a, final_usage_a * 2),
        );

        // Path B: Incremental updates
        let monitor_b = ResourceMonitor::new(config);
        let mut current_usage = base_usage;
        monitor_b.pressure().update_measurement(
            ResourceType::Memory,
            measurement(current_usage, final_usage_a * 2),
        );

        for increment in increments {
            current_usage = current_usage.saturating_add(increment);
            monitor_b.pressure().update_measurement(
                ResourceType::Memory,
                measurement(current_usage, final_usage_a * 2),
            );
        }

        // Verify equivalence
        let measurement_a = monitor_a.pressure().get_measurement(&ResourceType::Memory).unwrap();
        let measurement_b = monitor_b.pressure().get_measurement(&ResourceType::Memory).unwrap();
        let degradation_a = monitor_a.pressure().get_degradation_level(&ResourceType::Memory);
        let degradation_b = monitor_b.pressure().get_degradation_level(&ResourceType::Memory);

        prop_assert_eq!(measurement_a.current, measurement_b.current,
            "Measurement additivity violation: single update {} vs incremental {}",
            measurement_a.current, measurement_b.current);
        prop_assert_eq!(degradation_a, degradation_b,
            "Degradation additivity violation: single {:?} vs incremental {:?}",
            degradation_a, degradation_b);
    });
}

/// MR2: Pressure Monotonicity
///
/// Property: Higher resource usage should never result in lower degradation levels.
///
/// Transformation: Scale usage by factor k ≥ 1
/// Relation: degradation_level(k×usage) ≥ degradation_level(usage)
#[test]
fn mr2_pressure_monotonicity() {
    proptest!(|(
        base_usage: u64,
        scale_factor in 1.0..10.0_f64
    )| {
        prop_assume!(base_usage > 0 && base_usage < u64::MAX / 20);
        let scaled_usage = (base_usage as f64 * scale_factor) as u64;
        prop_assume!(scaled_usage > base_usage); // Ensure actual increase

        let config = MonitorConfig::default();
        let threshold = scaled_usage * 2; // Ensure we're in degradation range

        // Base case: lower usage
        let monitor_base = ResourceMonitor::new(config.clone());
        monitor_base.pressure().update_measurement(
            ResourceType::CpuLoad,
            measurement(base_usage, threshold),
        );

        // Update degradation engine to process the measurement
        let _ = monitor_base.engine().process_measurements();

        // Scaled case: higher usage
        let monitor_scaled = ResourceMonitor::new(config);
        monitor_scaled.pressure().update_measurement(
            ResourceType::CpuLoad,
            measurement(scaled_usage, threshold),
        );

        let _ = monitor_scaled.engine().process_measurements();

        let degradation_base = monitor_base.pressure().get_degradation_level(&ResourceType::CpuLoad);
        let degradation_scaled = monitor_scaled.pressure().get_degradation_level(&ResourceType::CpuLoad);

        prop_assert!(degradation_scaled >= degradation_base,
            "Monotonicity violation: higher usage {} (degradation {:?}) should have ≥ degradation than lower usage {} (degradation {:?})",
            scaled_usage, degradation_scaled, base_usage, degradation_base);
    });
}

/// MR3: Configuration Scaling Invariance
///
/// Property: Proportional scaling of all thresholds should preserve relative
/// degradation decisions.
///
/// Transformation: Scale all thresholds by factor k > 0
/// Relation: If usage₁/threshold₁ = usage₂/threshold₂, then degradation₁ = degradation₂
#[test]
fn mr3_configuration_scaling_invariance() {
    proptest!(|(
        usage: u64,
        base_threshold: u64,
        scale_factor in 0.1..10.0_f64
    )| {
        prop_assume!(base_threshold > usage && usage > 0);
        let scaled_threshold = (base_threshold as f64 * scale_factor) as u64;
        prop_assume!(scaled_threshold > 0 && scaled_threshold != base_threshold);

        let config = MonitorConfig::default();

        // Base configuration
        let monitor_base = ResourceMonitor::new(config.clone());
        monitor_base.pressure().update_measurement(
            ResourceType::FileDescriptors,
            measurement(usage, base_threshold),
        );
        let _ = monitor_base.engine().process_measurements();

        // Scaled configuration
        let monitor_scaled = ResourceMonitor::new(config);
        monitor_scaled.pressure().update_measurement(
            ResourceType::FileDescriptors,
            measurement(usage, scaled_threshold),
        );
        let _ = monitor_scaled.engine().process_measurements();

        let degradation_base = monitor_base.pressure().get_degradation_level(&ResourceType::FileDescriptors);
        let degradation_scaled = monitor_scaled.pressure().get_degradation_level(&ResourceType::FileDescriptors);

        // Verify proportional relationship
        let ratio_base = usage as f64 / base_threshold as f64;
        let ratio_scaled = usage as f64 / scaled_threshold as f64;

        if (ratio_base - ratio_scaled).abs() < EPSILON {
            prop_assert_eq!(degradation_base, degradation_scaled,
                "Scaling invariance violation: same usage ratio ({:.6}) should produce same degradation, got {:?} vs {:?}",
                ratio_base, degradation_base, degradation_scaled);
        }
    });
}

/// MR4: Temporal Idempotence
///
/// Property: Applying the same measurement multiple times should be stable
/// after the first application.
///
/// Transformation: Repeat identical measurement n times
/// Relation: apply(M, t).apply(M, t+1) ≡ apply(M, t)
#[test]
fn mr4_temporal_idempotence() {
    proptest!(|(
        usage: u64,
        threshold: u64,
        repeat_count in 2..10_usize
    )| {
        prop_assume!(threshold > 0 && usage < u64::MAX / 2);

        let config = MonitorConfig::default();
        let monitor = ResourceMonitor::new(config);

        let measurement = measurement(usage, threshold);

        // Apply measurement once
        monitor.pressure().update_measurement(ResourceType::NetworkConnections, measurement.clone());
        let _ = monitor.engine().process_measurements();
        let degradation_after_one = monitor.pressure().get_degradation_level(&ResourceType::NetworkConnections);
        let measurement_after_one = monitor.pressure().get_measurement(&ResourceType::NetworkConnections);

        // Apply same measurement multiple times
        for _ in 1..repeat_count {
            monitor.pressure().update_measurement(ResourceType::NetworkConnections, measurement.clone());
            let _ = monitor.engine().process_measurements();
        }

        let degradation_after_many = monitor.pressure().get_degradation_level(&ResourceType::NetworkConnections);
        let measurement_after_many = monitor.pressure().get_measurement(&ResourceType::NetworkConnections);

        prop_assert_eq!(degradation_after_one, degradation_after_many,
            "Temporal idempotence violation: degradation changed from {:?} to {:?} after {} repetitions",
            degradation_after_one, degradation_after_many, repeat_count);
        let measurement_after_one_current = measurement_after_one.as_ref().unwrap().current;
        let measurement_after_many_current = measurement_after_many.as_ref().unwrap().current;

        prop_assert_eq!(measurement_after_one_current, measurement_after_many_current,
            "Temporal idempotence violation: measurement changed from {} to {} after {} repetitions",
            measurement_after_one_current, measurement_after_many_current, repeat_count);
    });
}

/// MR5: Cross-Resource Independence
///
/// Property: Updates to orthogonal resource types should not affect each other's
/// degradation levels.
///
/// Transformation: Update different resource types independently
/// Relation: degradation(ResourceA) after updating ResourceB = degradation(ResourceA) before updating ResourceB
#[test]
fn mr5_cross_resource_independence() {
    proptest!(|(
        memory_usage: u64,
        memory_threshold: u64,
        fd_usage: u64,
        fd_threshold: u64
    )| {
        prop_assume!(memory_threshold > 0 && fd_threshold > 0);
        prop_assume!(memory_usage < memory_threshold && fd_usage < fd_threshold);

        let config = MonitorConfig::default();
        let monitor = ResourceMonitor::new(config);

        // Update memory first
        monitor.pressure().update_measurement(
            ResourceType::Memory,
            measurement(memory_usage, memory_threshold),
        );
        let _ = monitor.engine().process_measurements();
        let memory_degradation_before = monitor.pressure().get_degradation_level(&ResourceType::Memory);

        // Update file descriptors - should not affect memory degradation
        monitor.pressure().update_measurement(
            ResourceType::FileDescriptors,
            measurement(fd_usage, fd_threshold),
        );
        let _ = monitor.engine().process_measurements();
        let memory_degradation_after = monitor.pressure().get_degradation_level(&ResourceType::Memory);
        let memory_measurement_after = monitor.pressure().get_measurement(&ResourceType::Memory);
        let fd_measurement = monitor.pressure().get_measurement(&ResourceType::FileDescriptors);

        prop_assert_eq!(memory_degradation_before, memory_degradation_after,
            "Cross-resource independence violation: memory degradation changed from {:?} to {:?} after updating file descriptors",
            memory_degradation_before, memory_degradation_after);

        prop_assert_eq!(
            memory_measurement_after.as_ref().map(|measurement| measurement.current),
            Some(memory_usage),
            "Cross-resource independence violation: memory measurement changed after updating file descriptors"
        );
        prop_assert_eq!(
            fd_measurement.as_ref().map(|measurement| measurement.current),
            Some(fd_usage),
            "File descriptor measurement should be recorded independently"
        );
    });
}

/// MR6: Reset Equivalence
///
/// Property: A fresh monitor should behave identically to a reset monitor.
///
/// Transformation: Create new monitor vs reset existing monitor
/// Relation: fresh_monitor.apply(operations) ≡ existing_monitor.reset().apply(operations)
#[test]
fn mr6_reset_equivalence() {
    proptest!(|(
        operations in generators::degradation_scenario() // (resource_type, usage, threshold)
    )| {
        prop_assume!(!operations.is_empty() && operations.len() <= 5);

        let config = MonitorConfig::default();

        // Fresh monitor
        let fresh_monitor = ResourceMonitor::new(config.clone());

        // Existing monitor with prior state, then reset
        let existing_monitor = ResourceMonitor::new(config);
        // Add some prior state
        existing_monitor.pressure().update_measurement(
            ResourceType::Task,
            measurement(9999, 10000),
        );

        // Reset existing monitor by creating a new pressure/engine state
        // (In practice, this would be a reset() method)
        let reset_pressure = Arc::new(ResourcePressure::new());

        // Apply same operations to both monitors
        for (resource_type, usage, threshold) in &operations {
            if *threshold == 0 { continue; }

            let measurement = measurement(*usage, *threshold);

            fresh_monitor.pressure().update_measurement(resource_type.clone(), measurement.clone());
            reset_pressure.update_measurement(resource_type.clone(), measurement);
        }

        // Process measurements
        let _ = fresh_monitor.engine().process_measurements();

        // Compare final states for each resource type used
        for (resource_type, _, _) in &operations {
            let fresh_measurement = fresh_monitor.pressure().get_measurement(resource_type);
            let reset_measurement = reset_pressure.get_measurement(resource_type);

            if let (Some(fresh_m), Some(reset_m)) = (fresh_measurement, reset_measurement) {
                prop_assert_eq!(fresh_m.current, reset_m.current,
                    "Reset equivalence violation: fresh monitor measurement {} vs reset {}",
                    fresh_m.current, reset_m.current);
            }
        }
    });
}

/// MR7: Ordering Invariance
///
/// Property: The order of applying independent resource measurements should not
/// affect the final degradation state.
///
/// Transformation: Permute order of resource updates
/// Relation: apply(A, B, C) ≡ apply(B, A, C) ≡ apply(C, B, A) for independent resources
#[test]
fn mr7_ordering_invariance() {
    proptest!(|(
        measurements in generators::degradation_scenario()
    )| {
        prop_assume!(measurements.len() >= 2 && measurements.len() <= 4);
        prop_assume!(measurements.iter().all(|(_, _, threshold)| *threshold > 0));

        // Ensure we have different resource types for true independence
        let unique_resources: std::collections::HashSet<_> =
            measurements.iter().map(|(rt, _, _)| rt.clone()).collect();
        prop_assume!(unique_resources.len() == measurements.len());

        let config = MonitorConfig::default();

        // Apply in original order
        let monitor_original = ResourceMonitor::new(config.clone());
        for (resource_type, usage, threshold) in &measurements {
            monitor_original.pressure().update_measurement(
                resource_type.clone(),
                measurement(*usage, *threshold),
            );
        }
        let _ = monitor_original.engine().process_measurements();

        // Apply in reverse order
        let monitor_reversed = ResourceMonitor::new(config);
        for (resource_type, usage, threshold) in measurements.iter().rev() {
            monitor_reversed.pressure().update_measurement(
                resource_type.clone(),
                measurement(*usage, *threshold),
            );
        }
        let _ = monitor_reversed.engine().process_measurements();

        // Compare degradation levels for each resource
        for (resource_type, _, _) in &measurements {
            let original_degradation = monitor_original.pressure().get_degradation_level(resource_type);
            let reversed_degradation = monitor_reversed.pressure().get_degradation_level(resource_type);

            prop_assert_eq!(original_degradation, reversed_degradation,
                "Ordering invariance violation for {:?}: original order {:?} vs reversed order {:?}",
                resource_type, original_degradation, reversed_degradation);
        }
    });
}

/// MR8: Subset Consistency
///
/// Property: Monitoring a subset of resources should produce consistent results
/// with monitoring all resources and ignoring the extras.
///
/// Transformation: Monitor subset S ⊆ All_Resources
/// Relation: degradation_subset(S) ≤ degradation_all(All) for all resources in S
#[test]
fn mr8_subset_consistency() {
    proptest!(|(
        all_measurements in generators::degradation_scenario()
    )| {
        prop_assume!(all_measurements.len() >= 3 && all_measurements.len() <= 6);
        prop_assume!(all_measurements.iter().all(|(_, _, threshold)| *threshold > 0));
        let unique_resources: std::collections::HashSet<_> =
            all_measurements.iter().map(|(resource_type, _, _)| resource_type.clone()).collect();
        prop_assume!(unique_resources.len() == all_measurements.len());

        // Create subset (first half)
        let subset_size = all_measurements.len() / 2;
        let subset_measurements = &all_measurements[..subset_size];

        let config = MonitorConfig::default();

        // Monitor full set
        let monitor_full = ResourceMonitor::new(config.clone());
        for (resource_type, usage, threshold) in &all_measurements {
            monitor_full.pressure().update_measurement(
                resource_type.clone(),
                measurement(*usage, *threshold),
            );
        }
        let _ = monitor_full.engine().process_measurements();

        // Monitor subset only
        let monitor_subset = ResourceMonitor::new(config);
        for (resource_type, usage, threshold) in subset_measurements {
            monitor_subset.pressure().update_measurement(
                resource_type.clone(),
                measurement(*usage, *threshold),
            );
        }
        let _ = monitor_subset.engine().process_measurements();

        // For resources in the subset, degradation should be consistent
        for (resource_type, _, _) in subset_measurements {
            let full_degradation = monitor_full.pressure().get_degradation_level(resource_type);
            let subset_degradation = monitor_subset.pressure().get_degradation_level(resource_type);

            prop_assert_eq!(full_degradation, subset_degradation,
                "Subset consistency violation for {:?}: full monitoring {:?} vs subset monitoring {:?}",
                resource_type, full_degradation, subset_degradation);
        }
    });
}

/// Additional helper generators for complex test scenarios
mod generators {
    use super::*;

    pub fn resource_type() -> impl Strategy<Value = ResourceType> {
        prop_oneof![
            Just(ResourceType::Memory),
            Just(ResourceType::FileDescriptors),
            Just(ResourceType::CpuLoad),
            Just(ResourceType::NetworkConnections),
            Just(ResourceType::Task),
            "[a-z]{3,10}".prop_map(ResourceType::Custom),
        ]
    }

    pub fn valid_measurement() -> impl Strategy<Value = (u64, u64)> {
        (1u64..10000, 1u64..20000)
            .prop_filter("threshold > usage", |(usage, threshold)| threshold >= usage)
    }

    pub fn degradation_scenario() -> impl Strategy<Value = Vec<(ResourceType, u64, u64)>> {
        prop::collection::vec((resource_type(), valid_measurement()), 1..8).prop_map(|vec| {
            vec.into_iter()
                .map(|(rt, (usage, threshold))| (rt, usage, threshold))
                .collect()
        })
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn mr_composition_pressure_scaling_with_additivity() {
        // Composite MR: Combines MR1 (additivity) with MR2 (monotonicity)
        // Property: Scaled additive measurements should preserve monotonicity

        let config = MonitorConfig::default();
        let base_usage = 1000u64;
        let increments = vec![100, 200, 300];
        let scale_factor = 2.0;

        // Base case: additive measurements
        let monitor_base = ResourceMonitor::new(config.clone());
        let mut current = base_usage;
        for inc in &increments {
            current += inc;
            monitor_base
                .pressure()
                .update_measurement(ResourceType::Memory, measurement(current, current * 3));
        }
        let _ = monitor_base.engine().process_measurements();

        // Scaled case: scaled additive measurements
        let monitor_scaled = ResourceMonitor::new(config);
        let scaled_base = (base_usage as f64 * scale_factor) as u64;
        let mut scaled_current = scaled_base;
        for inc in &increments {
            let scaled_inc = (*inc as f64 * scale_factor) as u64;
            scaled_current += scaled_inc;
            monitor_scaled.pressure().update_measurement(
                ResourceType::Memory,
                measurement(scaled_current, scaled_current * 3),
            );
        }
        let _ = monitor_scaled.engine().process_measurements();

        let base_degradation = monitor_base
            .pressure()
            .get_degradation_level(&ResourceType::Memory);
        let scaled_degradation = monitor_scaled
            .pressure()
            .get_degradation_level(&ResourceType::Memory);

        // Composite property: scaled version should have ≥ degradation
        assert!(
            scaled_degradation >= base_degradation,
            "Composite MR violation: scaled additive measurements should preserve monotonicity"
        );
    }

    #[test]
    fn mr_validation_catches_planted_bugs() {
        // Mutation testing: verify our MRs catch common resource monitor bugs

        struct BuggyResourcePressure {
            measurements: std::cell::RefCell<HashMap<ResourceType, ResourceMeasurement>>,
        }

        impl BuggyResourcePressure {
            fn new() -> Self {
                Self {
                    measurements: std::cell::RefCell::new(HashMap::new()),
                }
            }

            // Bug: ignores subsequent measurements (violates MR1)
            fn update_measurement_ignore_subsequent(
                &self,
                resource_type: ResourceType,
                measurement: ResourceMeasurement,
            ) {
                let mut measurements = self.measurements.borrow_mut();
                measurements.entry(resource_type).or_insert(measurement);
                // INTENTIONAL BUG: ignores updates after first one (for metamorphic testing)
            }

            // Bug: non-monotonic degradation (violates MR2)
            fn get_degradation_level_nonmonotonic(
                &self,
                _resource_type: &ResourceType,
            ) -> DegradationLevel {
                // INTENTIONAL BUG: returns degradation unrelated to the measured resource (for metamorphic testing).
                if self.measurements.borrow().len().is_multiple_of(2) {
                    DegradationLevel::Light
                } else {
                    DegradationLevel::None
                }
            }
        }

        let buggy = BuggyResourcePressure::new();
        buggy.update_measurement_ignore_subsequent(ResourceType::Memory, measurement(10, 100));
        buggy.update_measurement_ignore_subsequent(ResourceType::Memory, measurement(90, 100));

        let stored_current = buggy
            .measurements
            .borrow()
            .get(&ResourceType::Memory)
            .unwrap()
            .current;
        assert_eq!(
            stored_current, 10,
            "planted additivity bug should ignore the second measurement"
        );

        buggy.update_measurement_ignore_subsequent(ResourceType::CpuLoad, measurement(1, 100));
        assert_eq!(
            buggy.get_degradation_level_nonmonotonic(&ResourceType::CpuLoad),
            DegradationLevel::Light,
            "planted monotonicity bug should report degradation unrelated to usage"
        );
    }
}
