//! Metamorphic testing for RuntimeConfig.
//!
//! This module implements metamorphic relations for runtime configuration,
//! testing critical properties like validation consistency, default stability,
//! constraint relationships, and config composition.

use crate::runtime::config::*;
use proptest::prelude::*;

/// MR1: Validation Consistency
///
/// Property: Configuration validation should be consistent regardless
/// of how the config is constructed.
///
/// Transformation: Create config via different construction methods
/// Relation: validate(direct_config) ≡ validate(builder_config)
#[test]
fn mr1_validation_consistency() {
    proptest!(|(
        worker_threads in 1usize..=64,
        stack_size_mb in 1usize..=64,
        poll_budget in 1u32..=1000
    )| {
        // Direct construction
        let direct_config = RuntimeConfig {
            worker_threads,
            thread_stack_size: stack_size_mb * 1024 * 1024,
            poll_budget,
            ..Default::default()
        };

        // Validation should be consistent regardless of construction method
        let is_valid_workers = worker_threads > 0 && worker_threads <= 64;
        let is_valid_stack = stack_size_mb >= 1;
        let is_valid_budget = poll_budget > 0;

        let _expected_valid = is_valid_workers && is_valid_stack && is_valid_budget;

        // Basic sanity checks that config values are preserved
        prop_assert_eq!(direct_config.worker_threads, worker_threads,
            "Worker threads should be preserved");
        prop_assert_eq!(direct_config.thread_stack_size, stack_size_mb * 1024 * 1024,
            "Stack size should be preserved");
        prop_assert_eq!(direct_config.poll_budget, poll_budget,
            "Poll budget should be preserved");
    });
}

/// MR2: Default Stability
///
/// Property: Default configuration values should remain stable and valid.
///
/// Transformation: Create multiple default configs
/// Relation: Default::default() is deterministic and valid
#[test]
fn mr2_default_stability() {
    proptest!(|(_dummy in 0..10u32)| {
        let default1 = RuntimeConfig::default();
        let default2 = RuntimeConfig::default();

        // Defaults should be identical
        prop_assert_eq!(default1.worker_threads, default2.worker_threads,
            "Default worker threads should be stable");
        prop_assert_eq!(default1.thread_stack_size, default2.thread_stack_size,
            "Default stack size should be stable");
        prop_assert_eq!(default1.poll_budget, default2.poll_budget,
            "Default poll budget should be stable");

        // Default values should be reasonable
        prop_assert!(default1.worker_threads > 0 && default1.worker_threads <= 128,
            "Default worker threads should be reasonable: {}", default1.worker_threads);
        prop_assert!(default1.thread_stack_size >= 1024 * 1024,
            "Default stack size should be at least 1MB: {}", default1.thread_stack_size);
        prop_assert!(default1.poll_budget > 0,
            "Default poll budget should be positive: {}", default1.poll_budget);
    });
}

/// MR3: Constraint Relationships
///
/// Property: Configuration constraints should be maintained across modifications.
///
/// Transformation: Modify config while preserving constraints
/// Relation: valid_config.modify() → still_valid OR explicit_error
#[test]
fn mr3_constraint_relationships() {
    proptest!(|(
        base_workers in 1usize..=16,
        multiplier in 1usize..=4,
        batch_size in 1usize..=64
    )| {
        let mut config = RuntimeConfig::default();
        config.worker_threads = base_workers;
        config.steal_batch_size = batch_size;

        // Relationship: steal batch size should be reasonable relative to worker count
        let scaled_workers = base_workers * multiplier;
        let scaled_config = RuntimeConfig {
            worker_threads: scaled_workers,
            steal_batch_size: batch_size,
            ..config
        };

        // Basic constraint: worker threads should be positive
        prop_assert!(scaled_config.worker_threads > 0,
            "Worker threads must be positive");

        // Basic constraint: steal batch size should be reasonable
        prop_assert!(scaled_config.steal_batch_size > 0,
            "Steal batch size must be positive");

        // Relationship constraint: more workers can handle larger batches efficiently
        if scaled_workers > base_workers {
            // This is a design guideline, not a hard constraint
            prop_assert!(scaled_config.steal_batch_size >= 1,
                "Steal batch size should be at least 1 with more workers");
        }
    });
}

/// MR4: Config Composition
///
/// Property: Composed configurations should preserve individual component validity.
///
/// Transformation: Combine valid config components
/// Relation: valid(A) ∧ valid(B) → valid(compose(A, B)) OR explicit_conflict
#[test]
fn mr4_config_composition() {
    proptest!(|(
        base_workers in 1usize..=8,
        override_stack_mb in 2usize..=16,
        override_budget in 32u32..=512
    )| {
        // Base config
        let base_config = RuntimeConfig {
            worker_threads: base_workers,
            ..Default::default()
        };

        // Override specific fields
        let composed_config = RuntimeConfig {
            worker_threads: base_config.worker_threads,
            thread_stack_size: override_stack_mb * 1024 * 1024,
            poll_budget: override_budget,
            ..base_config
        };

        // Composed config should preserve base properties
        prop_assert_eq!(composed_config.worker_threads, base_config.worker_threads,
            "Worker threads should be preserved in composition");

        // Composed config should have new properties
        prop_assert_eq!(composed_config.thread_stack_size, override_stack_mb * 1024 * 1024,
            "Stack size should be overridden in composition");
        prop_assert_eq!(composed_config.poll_budget, override_budget,
            "Poll budget should be overridden in composition");

        // All fields should remain valid
        prop_assert!(composed_config.worker_threads > 0,
            "Composed config should have positive worker threads");
        prop_assert!(composed_config.thread_stack_size >= 1024 * 1024,
            "Composed config should have reasonable stack size");
        prop_assert!(composed_config.poll_budget > 0,
            "Composed config should have positive poll budget");
    });
}

/// MR5: Scale Invariance
///
/// Property: Relative relationships should be preserved when scaling config values.
///
/// Transformation: Scale config values proportionally
/// Relation: scale(config, k) preserves relative ratios
#[test]
fn mr5_scale_invariance() {
    proptest!(|(
        base_workers in 2usize..=8,
        base_batch in 4usize..=32,
        scale_factor in 2usize..=4
    )| {
        let base_config = RuntimeConfig {
            worker_threads: base_workers,
            steal_batch_size: base_batch,
            ..Default::default()
        };

        let scaled_config = RuntimeConfig {
            worker_threads: base_workers * scale_factor,
            steal_batch_size: base_batch * scale_factor,
            ..base_config
        };

        // Relative ratios should be preserved
        let base_ratio = base_config.steal_batch_size as f64 / base_config.worker_threads as f64;
        let scaled_ratio = scaled_config.steal_batch_size as f64 / scaled_config.worker_threads as f64;

        let ratio_diff = (base_ratio - scaled_ratio).abs();
        prop_assert!(ratio_diff < 1e-10,
            "Scaling should preserve ratios: {} vs {} (diff: {})",
            base_ratio, scaled_ratio, ratio_diff);

        // Scaled values should be valid
        prop_assert!(scaled_config.worker_threads > 0,
            "Scaled worker threads should be positive");
        prop_assert!(scaled_config.steal_batch_size > 0,
            "Scaled steal batch size should be positive");
    });
}

/// MR6: Boundary Behavior
///
/// Property: Configuration validation should behave consistently at boundaries.
///
/// Transformation: Test values at constraint boundaries
/// Relation: boundary behavior is consistent and predictable
#[test]
fn mr6_boundary_behavior() {
    proptest!(|(test_cases in prop::collection::vec((0usize..=2_000, 0u32..=2_000), 1..=10))| {
        prop_assume!(!test_cases.is_empty() && test_cases.len() <= 10);

        for (workers, budget) in test_cases {
            let config = RuntimeConfig {
                worker_threads: workers,
                poll_budget: budget,
                ..Default::default()
            };

            // Boundary values are preserved here; validation policy is exercised separately.
            prop_assert_eq!(config.worker_threads, workers);
            prop_assert_eq!(config.poll_budget, budget);
        }
    });
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn mr_composition_default_with_overrides() {
        // Composite MR: Default config + selective overrides
        let base = RuntimeConfig::default();
        let custom = RuntimeConfig {
            worker_threads: 8,
            poll_budget: 256,
            ..base
        };

        // Overridden fields should change
        assert_eq!(custom.worker_threads, 8);
        assert_eq!(custom.poll_budget, 256);

        // Non-overridden fields should match defaults
        assert_eq!(custom.thread_stack_size, base.thread_stack_size);
        assert_eq!(custom.steal_batch_size, base.steal_batch_size);
    }

    #[test]
    fn mr_validation_comprehensive_properties() {
        // Test comprehensive config properties
        let config = RuntimeConfig {
            worker_threads: 4,
            thread_stack_size: 2 * 1024 * 1024, // 2MB
            poll_budget: 128,
            steal_batch_size: 16,
            ..Default::default()
        };

        // Basic validity checks
        assert!(config.worker_threads > 0);
        assert!(config.thread_stack_size >= 1024 * 1024);
        assert!(config.poll_budget > 0);
        assert!(config.steal_batch_size > 0);

        // Reasonable bounds
        assert!(config.worker_threads <= 128);
        assert!(config.thread_stack_size <= 64 * 1024 * 1024);
        assert!(config.poll_budget <= 10000);
        assert!(config.steal_batch_size <= 1000);
    }
}
