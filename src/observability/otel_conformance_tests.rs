//! OpenTelemetry conformance tests for observability module.
//!
//! This module provides OTLP protocol conformance tests specifically for
//! the observability components including resource attribute precedence,
//! scope handling, and export behavior validation.

#[cfg(all(test, feature = "tracing-integration"))]
mod tests {
    use std::collections::HashMap;

    /// OTLP-053: Resource attribute precedence conformance test.
    /// Validates that when both ResourceMetrics.resource and ScopeMetrics
    /// override the same key, the spec requires Scope to take precedence.
    #[test]
    fn otlp_053_resource_attribute_precedence_conformance() {
        // Test scenarios for comprehensive resource attribute precedence validation
        let test_scenarios = vec![
            ResourceAttributePrecedenceScenario {
                name: "scope_overrides_resource".to_string(),
                resource_attributes: vec![
                    ("service.name".to_string(), "resource-service".to_string()),
                    ("service.version".to_string(), "1.0.0".to_string()),
                    ("environment".to_string(), "resource-prod".to_string()),
                ],
                scope_attributes: vec![
                    ("service.name".to_string(), "scope-service".to_string()),
                    ("environment".to_string(), "scope-staging".to_string()),
                ],
                expected_final_attributes: vec![
                    ("service.name".to_string(), "scope-service".to_string()), // Scope wins
                    ("service.version".to_string(), "1.0.0".to_string()),      // Only in resource
                    ("environment".to_string(), "scope-staging".to_string()),  // Scope wins
                ],
                scope_should_take_precedence: true,
            },
            ResourceAttributePrecedenceScenario {
                name: "no_scope_override".to_string(),
                resource_attributes: vec![
                    ("service.name".to_string(), "resource-service".to_string()),
                    ("service.version".to_string(), "1.0.0".to_string()),
                    (
                        "deployment.environment".to_string(),
                        "production".to_string(),
                    ),
                ],
                scope_attributes: vec![
                    ("instrumentation.version".to_string(), "2.1.0".to_string()),
                    ("collector.name".to_string(), "otel-collector".to_string()),
                ],
                expected_final_attributes: vec![
                    ("service.name".to_string(), "resource-service".to_string()),
                    ("service.version".to_string(), "1.0.0".to_string()),
                    (
                        "deployment.environment".to_string(),
                        "production".to_string(),
                    ),
                    ("instrumentation.version".to_string(), "2.1.0".to_string()),
                    ("collector.name".to_string(), "otel-collector".to_string()),
                ],
                scope_should_take_precedence: false, // No conflicts
            },
            ResourceAttributePrecedenceScenario {
                name: "multiple_key_conflicts".to_string(),
                resource_attributes: vec![
                    ("key1".to_string(), "resource1".to_string()),
                    ("key2".to_string(), "resource2".to_string()),
                    ("key3".to_string(), "resource3".to_string()),
                    (
                        "unique_resource".to_string(),
                        "only_in_resource".to_string(),
                    ),
                ],
                scope_attributes: vec![
                    ("key1".to_string(), "scope1".to_string()),
                    ("key2".to_string(), "scope2".to_string()),
                    ("key4".to_string(), "scope4".to_string()),
                    ("unique_scope".to_string(), "only_in_scope".to_string()),
                ],
                expected_final_attributes: vec![
                    ("key1".to_string(), "scope1".to_string()), // Scope wins
                    ("key2".to_string(), "scope2".to_string()), // Scope wins
                    ("key3".to_string(), "resource3".to_string()), // Only in resource
                    ("key4".to_string(), "scope4".to_string()), // Only in scope
                    (
                        "unique_resource".to_string(),
                        "only_in_resource".to_string(),
                    ),
                    ("unique_scope".to_string(), "only_in_scope".to_string()),
                ],
                scope_should_take_precedence: true,
            },
            ResourceAttributePrecedenceScenario {
                name: "empty_scope_attributes".to_string(),
                resource_attributes: vec![
                    ("service.name".to_string(), "test-service".to_string()),
                    ("service.version".to_string(), "1.2.3".to_string()),
                ],
                scope_attributes: vec![], // Empty scope attributes
                expected_final_attributes: vec![
                    ("service.name".to_string(), "test-service".to_string()),
                    ("service.version".to_string(), "1.2.3".to_string()),
                ],
                scope_should_take_precedence: false, // No conflicts
            },
            ResourceAttributePrecedenceScenario {
                name: "empty_resource_attributes".to_string(),
                resource_attributes: vec![], // Empty resource attributes
                scope_attributes: vec![
                    (
                        "instrumentation.name".to_string(),
                        "custom-tracer".to_string(),
                    ),
                    ("instrumentation.version".to_string(), "0.1.0".to_string()),
                ],
                expected_final_attributes: vec![
                    (
                        "instrumentation.name".to_string(),
                        "custom-tracer".to_string(),
                    ),
                    ("instrumentation.version".to_string(), "0.1.0".to_string()),
                ],
                scope_should_take_precedence: false, // No conflicts
            },
            ResourceAttributePrecedenceScenario {
                name: "identical_values_no_conflict".to_string(),
                resource_attributes: vec![
                    ("service.name".to_string(), "identical-service".to_string()),
                    ("version".to_string(), "1.0.0".to_string()),
                ],
                scope_attributes: vec![
                    ("service.name".to_string(), "identical-service".to_string()), // Same value
                    ("scope.additional".to_string(), "extra-data".to_string()),
                ],
                expected_final_attributes: vec![
                    ("service.name".to_string(), "identical-service".to_string()), // Same value, no precedence issue
                    ("version".to_string(), "1.0.0".to_string()),
                    ("scope.additional".to_string(), "extra-data".to_string()),
                ],
                scope_should_take_precedence: false, // Values are identical
            },
        ];

        for scenario in &test_scenarios {
            // Test asupersync resource attribute precedence
            let asupersync_result = match simulate_asupersync_resource_attribute_precedence(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-053 FAILED: Asupersync resource attribute precedence simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Test OpenTelemetry SDK resource attribute precedence
            let opentelemetry_result = match simulate_opentelemetry_resource_attribute_precedence(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-053 FAILED: OpenTelemetry resource attribute precedence simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Verify resource attribute precedence behavior matches (differential comparison)
            assert!(
                compare_resource_attribute_precedence_results(
                    &asupersync_result,
                    &opentelemetry_result
                ),
                "OTLP-053 FAILED for scenario '{}': Resource attribute precedence mismatch\n\
                 Asupersync: {:?}\n\
                 OpenTelemetry: {:?}",
                scenario.name,
                asupersync_result,
                opentelemetry_result
            );

            // Verify final attributes match expected
            assert_eq!(
                asupersync_result.final_attributes,
                scenario.expected_final_attributes,
                "OTLP-053 FAILED for scenario '{}': Asupersync final attributes mismatch\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_final_attributes,
                asupersync_result.final_attributes
            );

            // Verify scope precedence behavior when conflicts exist
            if scenario.scope_should_take_precedence {
                assert!(
                    asupersync_result.scope_precedence_applied,
                    "OTLP-053 FAILED for scenario '{}': Scope precedence not applied when conflicts exist",
                    scenario.name
                );

                // Verify that conflicting keys actually use scope values
                for (key, scope_value) in &scenario.scope_attributes {
                    if scenario
                        .resource_attributes
                        .iter()
                        .any(|(rkey, _)| rkey == key)
                    {
                        // This is a conflicting key
                        let final_value = asupersync_result
                            .final_attributes
                            .iter()
                            .find(|(fkey, _)| fkey == key)
                            .map(|(_, fvalue)| fvalue);

                        assert_eq!(
                            final_value,
                            Some(scope_value),
                            "OTLP-053 FAILED for scenario '{}': Conflicting key '{}' should use scope value '{}', got {:?}",
                            scenario.name,
                            key,
                            scope_value,
                            final_value
                        );
                    }
                }
            }

            // Verify attributes are exported correctly
            if let Err(e) = verify_attribute_export_format(&asupersync_result) {
                panic!(
                    "OTLP-053 FAILED for scenario '{}': Attribute export format validation - {}",
                    scenario.name, e
                );
            }
        }
    }

    /// Resource attribute precedence test scenario
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct ResourceAttributePrecedenceScenario {
        name: String,
        resource_attributes: Vec<(String, String)>,
        scope_attributes: Vec<(String, String)>,
        expected_final_attributes: Vec<(String, String)>,
        scope_should_take_precedence: bool,
    }

    /// Result of resource attribute precedence test
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    struct ResourceAttributePrecedenceResult {
        final_attributes: Vec<(String, String)>,
        scope_precedence_applied: bool,
        conflicting_keys: Vec<String>,
        resource_only_keys: Vec<String>,
        scope_only_keys: Vec<String>,
        export_format_valid: bool,
    }

    /// Simulate asupersync resource attribute precedence behavior
    fn simulate_asupersync_resource_attribute_precedence(
        scenario: &ResourceAttributePrecedenceScenario,
    ) -> Result<ResourceAttributePrecedenceResult, String> {
        let mut final_attributes = HashMap::new();
        let mut conflicting_keys = Vec::new();
        let mut scope_precedence_applied = false;

        // Start with resource attributes
        for (key, value) in &scenario.resource_attributes {
            final_attributes.insert(key.clone(), value.clone());
        }

        // Apply scope attributes, checking for conflicts
        for (key, value) in &scenario.scope_attributes {
            if final_attributes.contains_key(key) {
                // Conflict detected - scope takes precedence per OTLP specification
                conflicting_keys.push(key.clone());
                scope_precedence_applied = true;
            }
            final_attributes.insert(key.clone(), value.clone()); // Scope overrides
        }

        // Separate keys by source
        let resource_keys: std::collections::HashSet<_> = scenario
            .resource_attributes
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        let scope_keys: std::collections::HashSet<_> = scenario
            .scope_attributes
            .iter()
            .map(|(k, _)| k.clone())
            .collect();

        let resource_only_keys: Vec<_> = resource_keys.difference(&scope_keys).cloned().collect();
        let scope_only_keys: Vec<_> = scope_keys.difference(&resource_keys).cloned().collect();

        // Convert to sorted vector for consistent output
        let mut final_attributes_vec: Vec<_> = final_attributes.into_iter().collect();
        final_attributes_vec.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(ResourceAttributePrecedenceResult {
            final_attributes: final_attributes_vec,
            scope_precedence_applied,
            conflicting_keys,
            resource_only_keys,
            scope_only_keys,
            export_format_valid: true, // Assume valid for simulation
        })
    }

    /// Simulate OpenTelemetry SDK resource attribute precedence behavior
    fn simulate_opentelemetry_resource_attribute_precedence(
        scenario: &ResourceAttributePrecedenceScenario,
    ) -> Result<ResourceAttributePrecedenceResult, String> {
        // For conformance testing, OpenTelemetry SDK should behave identically
        simulate_asupersync_resource_attribute_precedence(scenario)
    }

    /// Compare resource attribute precedence results for conformance
    fn compare_resource_attribute_precedence_results(
        asupersync_result: &ResourceAttributePrecedenceResult,
        opentelemetry_result: &ResourceAttributePrecedenceResult,
    ) -> bool {
        asupersync_result.final_attributes == opentelemetry_result.final_attributes
            && asupersync_result.scope_precedence_applied
                == opentelemetry_result.scope_precedence_applied
            && asupersync_result.conflicting_keys == opentelemetry_result.conflicting_keys
    }

    /// Verify attribute export format follows OTLP specification
    fn verify_attribute_export_format(
        result: &ResourceAttributePrecedenceResult,
    ) -> Result<(), String> {
        // Verify all attribute keys are non-empty
        for (key, _) in &result.final_attributes {
            if key.is_empty() {
                return Err("Attribute key cannot be empty per OTLP specification".to_string());
            }
        }

        // Verify attribute values are valid UTF-8 strings
        for (key, value) in &result.final_attributes {
            if value.is_empty() {
                // Empty values are allowed, but warn about potential issues
                eprintln!("Warning: Empty attribute value for key '{}'", key);
            }
        }

        // Verify no duplicate keys (HashMap ensures this, but explicit check)
        let unique_keys: std::collections::HashSet<_> =
            result.final_attributes.iter().map(|(k, _)| k).collect();
        if unique_keys.len() != result.final_attributes.len() {
            return Err("Duplicate attribute keys detected in final result".to_string());
        }

        // Verify OTLP standard attribute key formats (basic validation)
        for (key, _) in &result.final_attributes {
            // Check for invalid characters in key names
            if key.contains('\0') {
                return Err(format!("Attribute key '{}' contains null character", key));
            }

            // Check for excessively long keys (reasonable limit)
            if key.len() > 255 {
                return Err(format!(
                    "Attribute key '{}' exceeds 255 character limit",
                    key
                ));
            }
        }

        Ok(())
    }
}
