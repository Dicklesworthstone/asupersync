//! Metamorphic tests for EnvConfig component.
//!
//! These tests verify invariant relationships for runtime configuration parsing
//! and precedence resolution, addressing the oracle problem for complex
//! configuration validation logic. Each test focuses on a specific metamorphic
//! relation derived from configuration system domain properties.

#![allow(dead_code, clippy::pedantic, clippy::nursery, clippy::unwrap_used)]

use proptest::prelude::*;
use std::collections::HashMap;
use std::env;

use super::*;
use crate::runtime::config::RuntimeConfig;

const ENV_CONFIG_VARS: &[&str] = &[
    ENV_WORKER_THREADS,
    ENV_TASK_QUEUE_DEPTH,
    ENV_THREAD_STACK_SIZE,
    ENV_THREAD_NAME_PREFIX,
    ENV_STEAL_BATCH_SIZE,
    ENV_BLOCKING_MIN_THREADS,
    ENV_BLOCKING_MAX_THREADS,
    ENV_ENABLE_PARKING,
    ENV_POLL_BUDGET,
    ENV_CANCEL_LANE_MAX_STREAK,
    ENV_ENABLE_GOVERNOR,
    ENV_GOVERNOR_INTERVAL,
    ENV_ENABLE_ADAPTIVE_CANCEL_STREAK,
    ENV_ADAPTIVE_CANCEL_EPOCH_STEPS,
];

fn apply_env_overrides(config: &mut RuntimeConfig) -> Result<(), BuildError> {
    super::apply_env_overrides(config, &SystemEnvReader::new())
}

/// Test environment variable setting for controlled testing.
#[derive(Debug, Clone)]
struct TestEnvVar {
    name: String,
    value: String,
}

/// Generate arbitrary valid environment variables.
fn arb_env_var() -> impl Strategy<Value = TestEnvVar> {
    prop_oneof![
        (1usize..1000).prop_map(|n| TestEnvVar {
            name: ENV_WORKER_THREADS.to_string(),
            value: n.to_string()
        }),
        (1usize..10000).prop_map(|n| TestEnvVar {
            name: ENV_TASK_QUEUE_DEPTH.to_string(),
            value: n.to_string()
        }),
        (1024usize..8388608).prop_map(|n| TestEnvVar {
            name: ENV_THREAD_STACK_SIZE.to_string(),
            value: n.to_string()
        }),
        "[a-z]{3,10}-worker".prop_map(|s| TestEnvVar {
            name: ENV_THREAD_NAME_PREFIX.to_string(),
            value: s
        }),
        (1usize..100).prop_map(|n| TestEnvVar {
            name: ENV_STEAL_BATCH_SIZE.to_string(),
            value: n.to_string()
        }),
        (1usize..10).prop_map(|n| TestEnvVar {
            name: ENV_BLOCKING_MIN_THREADS.to_string(),
            value: n.to_string()
        }),
        (10usize..1000).prop_map(|n| TestEnvVar {
            name: ENV_BLOCKING_MAX_THREADS.to_string(),
            value: n.to_string()
        }),
        prop_oneof!["true", "false", "1", "0", "yes", "no", "on", "off"].prop_map(|s| TestEnvVar {
            name: ENV_ENABLE_PARKING.to_string(),
            value: s.to_string()
        }),
        (1u32..1000).prop_map(|n| TestEnvVar {
            name: ENV_POLL_BUDGET.to_string(),
            value: n.to_string()
        }),
    ]
}

/// Boolean value representations for testing equivalence.
#[derive(Debug, Clone)]
enum BoolRepr {
    True(String),  // "true", "1", "yes", "on"
    False(String), // "false", "0", "no", "off"
}

impl BoolRepr {
    fn value(&self) -> &str {
        match self {
            BoolRepr::True(s) | BoolRepr::False(s) => s,
        }
    }

    fn expected_bool(&self) -> bool {
        match self {
            BoolRepr::True(_) => true,
            BoolRepr::False(_) => false,
        }
    }
}

/// Generate arbitrary boolean representations.
fn arb_bool_repr() -> impl Strategy<Value = BoolRepr> {
    prop_oneof![
        prop_oneof!["true", "1", "yes", "on"].prop_map(|s| BoolRepr::True(s.to_string())),
        prop_oneof!["false", "0", "no", "off"].prop_map(|s| BoolRepr::False(s.to_string())),
    ]
}

/// Configuration field operations for metamorphic testing.
#[derive(Debug, Clone)]
enum ConfigOperation {
    SetEnvVar { var: TestEnvVar },
    UnsetEnvVar { name: String },
    ApplyDefaults,
    ParseField { field_name: String, value: String },
}

/// Generate arbitrary config operations.
fn arb_config_operation() -> impl Strategy<Value = ConfigOperation> {
    prop_oneof![
        arb_env_var().prop_map(|var| ConfigOperation::SetEnvVar { var }),
        prop_oneof![
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET
        ]
        .prop_map(|name| ConfigOperation::UnsetEnvVar {
            name: name.to_string()
        }),
        Just(ConfigOperation::ApplyDefaults),
        ("[a-z_]+", "[0-9]+").prop_map(|(name, value)| ConfigOperation::ParseField {
            field_name: name,
            value
        }),
    ]
}

/// Helper to set environment variables with cleanup.
struct EnvGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    vars_to_unset: Vec<String>,
    vars_to_restore: HashMap<String, String>,
}

impl EnvGuard {
    fn new() -> Self {
        let mut guard = Self {
            _lock: crate::test_utils::env_lock(),
            vars_to_unset: Vec::new(),
            vars_to_restore: HashMap::new(),
        };

        for &name in ENV_CONFIG_VARS {
            guard.unset(name);
        }

        guard
    }

    #[allow(unsafe_code)]
    fn set(&mut self, name: &str, value: &str) {
        // Save original value for restoration
        if let Ok(original) = env::var(name) {
            self.vars_to_restore.insert(name.to_string(), original);
        } else {
            self.vars_to_unset.push(name.to_string());
        }
        // SAFETY: These tests serialize all environment mutation through the
        // crate-wide env_lock, use crate-scoped variable names, and do not
        // spawn worker threads while the guard is live.
        unsafe { env::set_var(name, value) };
    }

    #[allow(unsafe_code)]
    fn unset(&mut self, name: &str) {
        if let Ok(original) = env::var(name) {
            self.vars_to_restore.insert(name.to_string(), original);
        }
        // SAFETY: See EnvGuard::set; the same serialized test-only mutation
        // discipline applies to removal.
        unsafe { env::remove_var(name) };
    }
}

impl Drop for EnvGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // Restore original environment
        for name in &self.vars_to_unset {
            // SAFETY: EnvGuard owns the module-wide environment mutation lock.
            unsafe { env::remove_var(name) };
        }
        for (name, value) in &self.vars_to_restore {
            // SAFETY: EnvGuard owns the module-wide environment mutation lock.
            unsafe { env::set_var(name, value) };
        }
    }
}

/// Capture configuration state for comparison.
#[derive(Debug, Clone, PartialEq)]
struct ConfigSnapshot {
    worker_threads: usize,
    global_queue_limit: usize,
    thread_stack_size: usize,
    thread_name_prefix: String,
    steal_batch_size: usize,
    blocking_min_threads: usize,
    blocking_max_threads: usize,
    enable_parking: bool,
    poll_budget: u32,
    cancel_lane_max_streak: usize,
    enable_governor: bool,
    governor_interval: u32,
}

impl ConfigSnapshot {
    fn capture(config: &RuntimeConfig) -> Self {
        Self {
            worker_threads: config.worker_threads,
            global_queue_limit: config.global_queue_limit,
            thread_stack_size: config.thread_stack_size,
            thread_name_prefix: config.thread_name_prefix.clone(),
            steal_batch_size: config.steal_batch_size,
            blocking_min_threads: config.blocking.min_threads,
            blocking_max_threads: config.blocking.max_threads,
            enable_parking: config.enable_parking,
            poll_budget: config.poll_budget,
            cancel_lane_max_streak: config.cancel_lane_max_streak,
            enable_governor: config.enable_governor,
            governor_interval: config.governor_interval,
        }
    }
}

//
// METAMORPHIC RELATIONS - Configuration system invariants
//

/// MR1: EQUIVALENCE - Default Consistency
/// Default config should be identical regardless of construction path.
#[test]
fn mr_default_consistency() {
    proptest!(|(_case in Just(()))| {
        let mut env_guard = EnvGuard::new();

        // Clear all asupersync env vars for clean test
        for var_name in &[
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_THREAD_STACK_SIZE,
            ENV_THREAD_NAME_PREFIX,
            ENV_STEAL_BATCH_SIZE,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
            ENV_CANCEL_LANE_MAX_STREAK,
            ENV_ENABLE_GOVERNOR,
            ENV_GOVERNOR_INTERVAL,
        ] {
            env_guard.unset(var_name);
        }

        // Create config via default constructor
        let config1 = RuntimeConfig::default();

        // Create config via env application to defaults
        let mut config2 = RuntimeConfig::default();
        let result = apply_env_overrides(&mut config2);
        prop_assert!(
            result.is_ok(),
            "Apply env overrides should succeed with no env vars"
        );

        // Both should be identical
        let snapshot1 = ConfigSnapshot::capture(&config1);
        let snapshot2 = ConfigSnapshot::capture(&config2);

        prop_assert_eq!(
            snapshot1,
            snapshot2,
            "Default configs should be identical: direct vs env_applied"
        );
    });
}

/// MR2: EQUIVALENCE - Boolean Parsing Equivalence
/// Different representations of the same boolean value should parse identically.
#[test]
fn mr_boolean_parsing_equivalence() {
    proptest!(|(repr1 in arb_bool_repr(), repr2 in arb_bool_repr())| {
        // Skip if different expected values
        if repr1.expected_bool() != repr2.expected_bool() {
            return Ok(());
        }

        let mut env_guard = EnvGuard::new();

        // Set same boolean field with different representations
        env_guard.set(ENV_ENABLE_PARKING, repr1.value());
        let mut config1 = RuntimeConfig::default();
        let result1 = apply_env_overrides(&mut config1);

        env_guard.set(ENV_ENABLE_PARKING, repr2.value());
        let mut config2 = RuntimeConfig::default();
        let result2 = apply_env_overrides(&mut config2);

        prop_assert!(result1.is_ok() && result2.is_ok(),
            "Both boolean representations should parse successfully");

        prop_assert_eq!(config1.enable_parking, config2.enable_parking,
            "Boolean equivalence violated: '{}' vs '{}' should produce same result",
            repr1.value(), repr2.value());

        prop_assert_eq!(config1.enable_parking, repr1.expected_bool(),
            "Boolean value should match expected: got {}, expected {}",
            config1.enable_parking, repr1.expected_bool());
    });
}

/// MR3: EQUIVALENCE - Whitespace Invariance
/// Values with different whitespace should parse identically.
#[test]
fn mr_whitespace_invariance() {
    proptest!(|(base_value in 1usize..=1000, whitespace_prefix in ".{0,5}", whitespace_suffix in ".{0,5}")| {
        let base_value = base_value % 1000 + 1; // 1-1000
        let prefix = whitespace_prefix.chars().filter(|c| c.is_whitespace()).take(5).collect::<String>();
        let suffix = whitespace_suffix.chars().filter(|c| c.is_whitespace()).take(5).collect::<String>();

        let mut env_guard = EnvGuard::new();

        // Test with clean value
        env_guard.set(ENV_WORKER_THREADS, &base_value.to_string());
        let mut config1 = RuntimeConfig::default();
        let result1 = apply_env_overrides(&mut config1);

        // Test with whitespace-padded value
        let padded_value = format!("{}{}{}", prefix, base_value, suffix);
        env_guard.set(ENV_WORKER_THREADS, &padded_value);
        let mut config2 = RuntimeConfig::default();
        let result2 = apply_env_overrides(&mut config2);

        prop_assert!(result1.is_ok() && result2.is_ok(),
            "Both clean and whitespace-padded values should parse successfully");

        prop_assert_eq!(config1.worker_threads, config2.worker_threads,
            "Whitespace invariance violated: '{}' vs '{}' should produce same result",
            base_value, padded_value);
    });
}

/// MR4: EQUIVALENCE - Case Insensitive Boolean Parsing
/// Boolean values should be case-insensitive.
#[test]
fn mr_case_insensitive_boolean_parsing() {
    proptest!(|(base_bool in prop::sample::select(vec!["true", "false", "yes", "no", "on", "off", "1", "0"]).prop_map(|s| s.to_string()))| {
        let mut env_guard = EnvGuard::new();

        // Test original case
        env_guard.set(ENV_ENABLE_GOVERNOR, &base_bool);
        let mut config1 = RuntimeConfig::default();
        let result1 = apply_env_overrides(&mut config1);

        // Test uppercase
        env_guard.set(ENV_ENABLE_GOVERNOR, &base_bool.to_uppercase());
        let mut config2 = RuntimeConfig::default();
        let result2 = apply_env_overrides(&mut config2);

        // Test mixed case
        let mixed_case: String = base_bool.chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_uppercase().next().unwrap_or(c) } else { c })
            .collect();
        env_guard.set(ENV_ENABLE_GOVERNOR, &mixed_case);
        let mut config3 = RuntimeConfig::default();
        let result3 = apply_env_overrides(&mut config3);

        prop_assert!(result1.is_ok() && result2.is_ok() && result3.is_ok(),
            "All case variants should parse successfully");

        prop_assert_eq!(config1.enable_governor, config2.enable_governor,
            "Case insensitivity violated: '{}' vs '{}' should produce same result",
            base_bool, base_bool.to_uppercase());

        prop_assert_eq!(config1.enable_governor, config3.enable_governor,
            "Case insensitivity violated: '{}' vs '{}' should produce same result",
            base_bool, mixed_case);
    });
}

/// MR5: EQUIVALENCE - Field Independence
/// Setting one configuration field should not affect others.
#[test]
fn mr_field_independence() {
    proptest!(|(worker_threads in 1usize..=100, poll_budget in 1u32..=1000)| {

        let mut env_guard = EnvGuard::new();

        // Set only worker_threads
        env_guard.set(ENV_WORKER_THREADS, &worker_threads.to_string());
        env_guard.unset(ENV_POLL_BUDGET);
        let mut config1 = RuntimeConfig::default();
        let baseline_poll_budget = config1.poll_budget;
        let result1 = apply_env_overrides(&mut config1);

        // Set both worker_threads and poll_budget
        env_guard.set(ENV_WORKER_THREADS, &worker_threads.to_string());
        env_guard.set(ENV_POLL_BUDGET, &poll_budget.to_string());
        let mut config2 = RuntimeConfig::default();
        let result2 = apply_env_overrides(&mut config2);

        prop_assert!(result1.is_ok() && result2.is_ok(),
            "Both configurations should parse successfully");

        prop_assert_eq!(config1.worker_threads, config2.worker_threads,
            "Worker threads should be identical when poll_budget is also set");

        prop_assert_eq!(config1.poll_budget, baseline_poll_budget,
            "Poll budget should remain at default when only worker_threads is set");

        prop_assert_eq!(config2.poll_budget, poll_budget,
            "Poll budget should be set to specified value");
    });
}

/// MR6: INCLUSIVE - Error Type Consistency
/// Invalid values should produce consistent error types.
#[test]
fn mr_error_type_consistency() {
    proptest!(|(invalid_values in prop::collection::vec("[a-z]{1,8}", 1..=5))| {
        let invalid_values: Vec<String> = invalid_values.into_iter()
            .filter(|s| !s.trim().is_empty() && s.chars().any(|c| !c.is_ascii_digit()))
            .take(5)
            .collect();

        if invalid_values.is_empty() {
            return Ok(());
        }

        let mut env_guard = EnvGuard::new();
        let mut error_types = Vec::new();

        for invalid_value in &invalid_values {
            env_guard.set(ENV_WORKER_THREADS, invalid_value);
            let mut config = RuntimeConfig::default();
            let result = apply_env_overrides(&mut config);

            prop_assert!(result.is_err(),
                "Invalid value '{}' should produce an error", invalid_value);

            if let Err(err) = result {
                error_types.push(format!("{:?}", err));
            }
        }

        // All error messages should contain the variable name and invalid value info
        for (i, error_msg) in error_types.iter().enumerate() {
            prop_assert!(error_msg.contains(ENV_WORKER_THREADS),
                "Error message should contain variable name: {}", error_msg);
            prop_assert!(error_msg.contains(&invalid_values[i]),
                "Error message should contain invalid value: {}", error_msg);
        }
    });
}

/// MR7: MULTIPLICATIVE - Precedence Override Consistency
/// Environment variables should always override defaults.
#[test]
fn mr_precedence_override_consistency() {
    proptest!(|(override_value in 1usize..=100)| {
        let mut env_guard = EnvGuard::new();

        // Get default value
        env_guard.unset(ENV_STEAL_BATCH_SIZE);
        let default_config = RuntimeConfig::default();
        let mut config1 = default_config.clone();
        let result1 = apply_env_overrides(&mut config1);
        prop_assert!(result1.is_ok(), "Default config should apply cleanly");

        // Apply environment override
        env_guard.set(ENV_STEAL_BATCH_SIZE, &override_value.to_string());
        let mut config2 = default_config.clone();
        let result2 = apply_env_overrides(&mut config2);
        prop_assert!(result2.is_ok(), "Override config should apply cleanly");

        // Override should take precedence if different from default
        if default_config.steal_batch_size != override_value {
            prop_assert_ne!(config1.steal_batch_size, config2.steal_batch_size,
                "Override should change value from default");
            prop_assert_eq!(config2.steal_batch_size, override_value,
                "Override value should be applied: expected {}, got {}",
                override_value, config2.steal_batch_size);
        }
    });
}

/// MR8: EQUIVALENCE - Boundary Value Consistency
/// Boundary values (min/max) should be handled consistently.
#[test]
fn mr_boundary_value_consistency() {
    proptest!(|(_case in Just(()))| {
        let mut env_guard = EnvGuard::new();

        // Test minimum valid values
        env_guard.set(ENV_WORKER_THREADS, "1");
        env_guard.set(ENV_BLOCKING_MIN_THREADS, "1");
        let mut config_min = RuntimeConfig::default();
        let result_min = apply_env_overrides(&mut config_min);

        // Test zero values (should be invalid for some fields)
        env_guard.set(ENV_WORKER_THREADS, "0");
        env_guard.set(ENV_BLOCKING_MIN_THREADS, "0");
        let mut config_zero = RuntimeConfig::default();
        let result_zero = apply_env_overrides(&mut config_zero);

        prop_assert!(
            result_min.is_ok(),
            "Minimum valid values should parse successfully"
        );

        // Zero worker threads should be valid (runtime decides actual count)
        // Zero blocking threads should be valid (pool handles minimum)
        prop_assert!(
            result_zero.is_ok(),
            "Zero values should be handled gracefully"
        );

        prop_assert_eq!(
            config_min.worker_threads,
            1,
            "Minimum worker threads should be 1"
        );
        prop_assert_eq!(
            config_min.blocking.min_threads,
            1,
            "Minimum blocking threads should be 1"
        );
    });
}

/// MR9: INVERTIVE - Set-Unset Round Trip
/// Setting a value then unsetting should restore default behavior.
#[test]
fn mr_set_unset_round_trip() {
    proptest!(|(test_value in 50usize..=549)| {
        let mut env_guard = EnvGuard::new();

        // Get baseline (no env var set)
        env_guard.unset(ENV_THREAD_STACK_SIZE);
        let default_config = RuntimeConfig::default();
        let mut config1 = default_config.clone();
        let result1 = apply_env_overrides(&mut config1);
        prop_assert!(result1.is_ok(), "Baseline config should apply cleanly");

        // Set environment variable
        env_guard.set(ENV_THREAD_STACK_SIZE, &test_value.to_string());
        let mut config2 = default_config.clone();
        let result2 = apply_env_overrides(&mut config2);
        prop_assert!(result2.is_ok(), "Override config should apply cleanly");

        // Unset environment variable (round trip)
        env_guard.unset(ENV_THREAD_STACK_SIZE);
        let mut config3 = default_config.clone();
        let result3 = apply_env_overrides(&mut config3);
        prop_assert!(result3.is_ok(), "Round trip config should apply cleanly");

        // Round trip should restore original state
        prop_assert_eq!(config1.thread_stack_size, config3.thread_stack_size,
            "Round trip should restore original value: baseline={}, after_roundtrip={}",
            config1.thread_stack_size, config3.thread_stack_size);

        // Middle state should be different (if test value != default)
        if default_config.thread_stack_size != test_value {
            prop_assert_ne!(config1.thread_stack_size, config2.thread_stack_size,
                "Override should change from default");
            prop_assert_eq!(config2.thread_stack_size, test_value,
                "Override should set specified value");
        }
    });
}

/// MR10: ADDITIVE - Blocking Pool Min/Max Relationship
/// Min threads should always be ≤ max threads after applying overrides.
#[test]
fn mr_blocking_pool_min_max_relationship() {
    proptest!(|(min_threads in 1usize..=20, extra_threads in 0usize..=100)| {
        let max_threads = min_threads + extra_threads;
        let mut env_guard = EnvGuard::new();

        env_guard.set(ENV_BLOCKING_MIN_THREADS, &min_threads.to_string());
        env_guard.set(ENV_BLOCKING_MAX_THREADS, &max_threads.to_string());

        let mut config = RuntimeConfig::default();
        let result = apply_env_overrides(&mut config);

        prop_assert!(result.is_ok(),
            "Valid min/max configuration should apply successfully");

        prop_assert!(config.blocking.min_threads <= config.blocking.max_threads,
            "Min threads {} should be ≤ max threads {} after applying overrides",
            config.blocking.min_threads, config.blocking.max_threads);

        prop_assert_eq!(config.blocking.min_threads, min_threads,
            "Min threads should be set to specified value");
        prop_assert_eq!(config.blocking.max_threads, max_threads,
            "Max threads should be set to specified value");
    });
}

#[cfg(test)]
mod composition_tests {
    use super::*;

    /// Composite MR: Independence + Precedence + Consistency
    /// Tests that field independence, precedence override, and default consistency
    /// all hold simultaneously under complex configuration scenarios.
    #[test]
    fn mr_composite_config_invariants() {
        proptest!(|(operations in prop::collection::vec(arb_config_operation(), 0..=20))| {
            let mut env_guard = EnvGuard::new();

            // Start with clean environment
            for var_name in &[ENV_WORKER_THREADS, ENV_ENABLE_PARKING, ENV_POLL_BUDGET] {
                env_guard.unset(var_name);
            }

            let baseline_config = RuntimeConfig::default();
            let baseline_snapshot = ConfigSnapshot::capture(&baseline_config);

            for op in operations.iter().take(5) {
                match op {
                    ConfigOperation::SetEnvVar { var } => {
                        env_guard.set(&var.name, &var.value);
                    }
                    ConfigOperation::UnsetEnvVar { name } => {
                        env_guard.unset(name);
                    }
                    _ => {} // Skip non-env operations for this test
                }

                let mut config = RuntimeConfig::default();
                let result = apply_env_overrides(&mut config);

                if result.is_ok() {
                    let snapshot = ConfigSnapshot::capture(&config);

                    // MR5: Field independence - unset fields should remain at defaults
                    if env::var(ENV_WORKER_THREADS).is_err() {
                        prop_assert_eq!(snapshot.worker_threads, baseline_snapshot.worker_threads,
                            "Worker threads should remain at default when not set");
                    }

                    if env::var(ENV_ENABLE_PARKING).is_err() {
                        prop_assert_eq!(snapshot.enable_parking, baseline_snapshot.enable_parking,
                            "Parking should remain at default when not set");
                    }

                    // MR7: Precedence - env vars should override defaults when set
                    if let Ok(val) = env::var(ENV_POLL_BUDGET) {
                        if let Ok(parsed_val) = val.parse::<u32>() {
                            prop_assert_eq!(snapshot.poll_budget, parsed_val,
                                "Poll budget should be overridden by env var");
                        }
                    }

                    // MR10: Min/max relationship should always hold
                    prop_assert!(snapshot.blocking_min_threads <= snapshot.blocking_max_threads,
                        "Blocking pool min/max relationship violated");
                }
            }
        });
    }
}
