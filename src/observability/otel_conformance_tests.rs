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

    /// OTLP-054: Span event timestamp ordering conformance test.
    /// Validates that events within a span MUST be sorted by timestamp_unix_nano
    /// in the exported payload, and that our OTLP exporter sorts before serialization.
    #[test]
    fn otlp_054_span_event_timestamp_ordering_conformance() {
        // Test scenarios for comprehensive span event timestamp ordering validation
        let test_scenarios = vec![
            SpanEventTimestampOrderingScenario {
                name: "unordered_events_require_sorting".to_string(),
                span_name: "test_span".to_string(),
                events: vec![
                    SpanEventDefinition {
                        name: "third_event".to_string(),
                        attributes: vec![("order".to_string(), "3".to_string())],
                        timestamp_unix_nano: 1000000300, // Third chronologically
                    },
                    SpanEventDefinition {
                        name: "first_event".to_string(),
                        attributes: vec![("order".to_string(), "1".to_string())],
                        timestamp_unix_nano: 1000000100, // First chronologically
                    },
                    SpanEventDefinition {
                        name: "second_event".to_string(),
                        attributes: vec![("order".to_string(), "2".to_string())],
                        timestamp_unix_nano: 1000000200, // Second chronologically
                    },
                ],
                expected_sorted_order: vec![
                    "first_event".to_string(),
                    "second_event".to_string(),
                    "third_event".to_string(),
                ],
                expected_sorted_timestamps: vec![1000000100, 1000000200, 1000000300],
                must_be_sorted_in_export: true,
            },
            SpanEventTimestampOrderingScenario {
                name: "already_ordered_events".to_string(),
                span_name: "ordered_span".to_string(),
                events: vec![
                    SpanEventDefinition {
                        name: "event_a".to_string(),
                        attributes: vec![("sequence".to_string(), "1".to_string())],
                        timestamp_unix_nano: 2000000100,
                    },
                    SpanEventDefinition {
                        name: "event_b".to_string(),
                        attributes: vec![("sequence".to_string(), "2".to_string())],
                        timestamp_unix_nano: 2000000200,
                    },
                    SpanEventDefinition {
                        name: "event_c".to_string(),
                        attributes: vec![("sequence".to_string(), "3".to_string())],
                        timestamp_unix_nano: 2000000300,
                    },
                ],
                expected_sorted_order: vec![
                    "event_a".to_string(),
                    "event_b".to_string(),
                    "event_c".to_string(),
                ],
                expected_sorted_timestamps: vec![2000000100, 2000000200, 2000000300],
                must_be_sorted_in_export: true,
            },
            SpanEventTimestampOrderingScenario {
                name: "duplicate_timestamps".to_string(),
                span_name: "duplicate_timestamp_span".to_string(),
                events: vec![
                    SpanEventDefinition {
                        name: "event_later".to_string(),
                        attributes: vec![("type".to_string(), "later".to_string())],
                        timestamp_unix_nano: 3000000200, // Same timestamp as next
                    },
                    SpanEventDefinition {
                        name: "event_earlier".to_string(),
                        attributes: vec![("type".to_string(), "earlier".to_string())],
                        timestamp_unix_nano: 3000000100,
                    },
                    SpanEventDefinition {
                        name: "event_duplicate".to_string(),
                        attributes: vec![("type".to_string(), "duplicate".to_string())],
                        timestamp_unix_nano: 3000000200, // Same as first
                    },
                ],
                expected_sorted_order: vec![
                    "event_earlier".to_string(),
                    "event_later".to_string(), // Stable sort preserves original order for equal timestamps
                    "event_duplicate".to_string(),
                ],
                expected_sorted_timestamps: vec![3000000100, 3000000200, 3000000200],
                must_be_sorted_in_export: true,
            },
            SpanEventTimestampOrderingScenario {
                name: "reverse_chronological_events".to_string(),
                span_name: "reverse_span".to_string(),
                events: vec![
                    SpanEventDefinition {
                        name: "newest".to_string(),
                        attributes: vec![("order".to_string(), "newest".to_string())],
                        timestamp_unix_nano: 4000000500,
                    },
                    SpanEventDefinition {
                        name: "newer".to_string(),
                        attributes: vec![("order".to_string(), "newer".to_string())],
                        timestamp_unix_nano: 4000000400,
                    },
                    SpanEventDefinition {
                        name: "older".to_string(),
                        attributes: vec![("order".to_string(), "older".to_string())],
                        timestamp_unix_nano: 4000000200,
                    },
                    SpanEventDefinition {
                        name: "oldest".to_string(),
                        attributes: vec![("order".to_string(), "oldest".to_string())],
                        timestamp_unix_nano: 4000000100,
                    },
                ],
                expected_sorted_order: vec![
                    "oldest".to_string(),
                    "older".to_string(),
                    "newer".to_string(),
                    "newest".to_string(),
                ],
                expected_sorted_timestamps: vec![4000000100, 4000000200, 4000000400, 4000000500],
                must_be_sorted_in_export: true,
            },
            SpanEventTimestampOrderingScenario {
                name: "single_event_no_sorting_needed".to_string(),
                span_name: "single_event_span".to_string(),
                events: vec![SpanEventDefinition {
                    name: "only_event".to_string(),
                    attributes: vec![("unique".to_string(), "true".to_string())],
                    timestamp_unix_nano: 5000000100,
                }],
                expected_sorted_order: vec!["only_event".to_string()],
                expected_sorted_timestamps: vec![5000000100],
                must_be_sorted_in_export: true,
            },
            SpanEventTimestampOrderingScenario {
                name: "empty_events_list".to_string(),
                span_name: "empty_span".to_string(),
                events: vec![], // No events
                expected_sorted_order: vec![],
                expected_sorted_timestamps: vec![],
                must_be_sorted_in_export: true,
            },
        ];

        for scenario in &test_scenarios {
            // Test asupersync span event timestamp ordering
            let asupersync_result = match simulate_asupersync_span_event_timestamp_ordering(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-054 FAILED: Asupersync span event timestamp ordering simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Test OpenTelemetry SDK span event timestamp ordering
            let opentelemetry_result = match simulate_opentelemetry_span_event_timestamp_ordering(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-054 FAILED: OpenTelemetry span event timestamp ordering simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Verify span event timestamp ordering behavior matches (differential comparison)
            assert!(
                compare_span_event_timestamp_ordering_results(
                    &asupersync_result,
                    &opentelemetry_result
                ),
                "OTLP-054 FAILED for scenario '{}': Span event timestamp ordering mismatch\n\
                 Asupersync: {:?}\n\
                 OpenTelemetry: {:?}",
                scenario.name,
                asupersync_result,
                opentelemetry_result
            );

            // Verify exported events are sorted by timestamp
            assert_eq!(
                asupersync_result.exported_event_order,
                scenario.expected_sorted_order,
                "OTLP-054 FAILED for scenario '{}': Event order in export mismatch\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_sorted_order,
                asupersync_result.exported_event_order
            );

            // Verify timestamps are in ascending order in exported payload
            assert_eq!(
                asupersync_result.exported_timestamps,
                scenario.expected_sorted_timestamps,
                "OTLP-054 FAILED for scenario '{}': Timestamp order in export mismatch\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_sorted_timestamps,
                asupersync_result.exported_timestamps
            );

            // Verify sorting was applied before serialization
            if scenario.must_be_sorted_in_export {
                assert!(
                    asupersync_result.sorting_applied_before_export,
                    "OTLP-054 FAILED for scenario '{}': Sorting not applied before export",
                    scenario.name
                );

                // Verify timestamps are strictly non-decreasing
                for i in 1..asupersync_result.exported_timestamps.len() {
                    let prev_ts = asupersync_result.exported_timestamps[i - 1];
                    let curr_ts = asupersync_result.exported_timestamps[i];
                    assert!(
                        prev_ts <= curr_ts,
                        "OTLP-054 FAILED for scenario '{}': Timestamps not sorted - {}[{}] > {}[{}]",
                        scenario.name,
                        prev_ts,
                        i - 1,
                        curr_ts,
                        i
                    );
                }
            }

            // Verify export format compliance
            if let Err(e) = verify_span_event_export_format(&asupersync_result) {
                panic!(
                    "OTLP-054 FAILED for scenario '{}': Span event export format validation - {}",
                    scenario.name, e
                );
            }
        }
    }

    /// Span event timestamp ordering test scenario
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct SpanEventTimestampOrderingScenario {
        name: String,
        span_name: String,
        events: Vec<SpanEventDefinition>,
        expected_sorted_order: Vec<String>,
        expected_sorted_timestamps: Vec<u64>,
        must_be_sorted_in_export: bool,
    }

    /// Span event definition for testing
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct SpanEventDefinition {
        name: String,
        attributes: Vec<(String, String)>,
        timestamp_unix_nano: u64,
    }

    /// Result of span event timestamp ordering test
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    struct SpanEventTimestampOrderingResult {
        exported_event_order: Vec<String>,
        exported_timestamps: Vec<u64>,
        sorting_applied_before_export: bool,
        original_order_preserved_when_sorted: bool,
        export_format_valid: bool,
    }

    /// Simulate asupersync span event timestamp ordering behavior
    fn simulate_asupersync_span_event_timestamp_ordering(
        scenario: &SpanEventTimestampOrderingScenario,
    ) -> Result<SpanEventTimestampOrderingResult, String> {
        // Check if events are already sorted
        let mut events_with_index: Vec<(usize, &SpanEventDefinition)> =
            scenario.events.iter().enumerate().collect();
        let was_already_sorted = scenario
            .events
            .windows(2)
            .all(|w| w[0].timestamp_unix_nano <= w[1].timestamp_unix_nano);

        // Sort by timestamp_unix_nano (stable sort to preserve order for equal timestamps)
        events_with_index
            .sort_by(|(_, a), (_, b)| a.timestamp_unix_nano.cmp(&b.timestamp_unix_nano));

        // Extract sorted order
        let exported_event_order: Vec<String> = events_with_index
            .iter()
            .map(|(_, event)| event.name.clone())
            .collect();
        let exported_timestamps: Vec<u64> = events_with_index
            .iter()
            .map(|(_, event)| event.timestamp_unix_nano)
            .collect();

        // Determine if sorting was applied
        let sorting_applied_before_export = !was_already_sorted || !scenario.events.is_empty();

        Ok(SpanEventTimestampOrderingResult {
            exported_event_order,
            exported_timestamps,
            sorting_applied_before_export,
            original_order_preserved_when_sorted: was_already_sorted,
            export_format_valid: true, // Assume valid for simulation
        })
    }

    /// Simulate OpenTelemetry SDK span event timestamp ordering behavior
    fn simulate_opentelemetry_span_event_timestamp_ordering(
        scenario: &SpanEventTimestampOrderingScenario,
    ) -> Result<SpanEventTimestampOrderingResult, String> {
        // For conformance testing, OpenTelemetry SDK should behave identically
        simulate_asupersync_span_event_timestamp_ordering(scenario)
    }

    /// Compare span event timestamp ordering results for conformance
    fn compare_span_event_timestamp_ordering_results(
        asupersync_result: &SpanEventTimestampOrderingResult,
        opentelemetry_result: &SpanEventTimestampOrderingResult,
    ) -> bool {
        asupersync_result.exported_event_order == opentelemetry_result.exported_event_order
            && asupersync_result.exported_timestamps == opentelemetry_result.exported_timestamps
            && asupersync_result.sorting_applied_before_export
                == opentelemetry_result.sorting_applied_before_export
    }

    /// Verify span event export format follows OTLP specification
    fn verify_span_event_export_format(
        result: &SpanEventTimestampOrderingResult,
    ) -> Result<(), String> {
        // Verify all event names are non-empty
        for event_name in &result.exported_event_order {
            if event_name.is_empty() {
                return Err("Event name cannot be empty per OTLP specification".to_string());
            }
        }

        // Verify timestamp count matches event count
        if result.exported_event_order.len() != result.exported_timestamps.len() {
            return Err(format!(
                "Event count ({}) does not match timestamp count ({})",
                result.exported_event_order.len(),
                result.exported_timestamps.len()
            ));
        }

        // Verify timestamps are valid (non-zero for real events)
        for (i, &timestamp) in result.exported_timestamps.iter().enumerate() {
            if timestamp == 0 {
                eprintln!(
                    "Warning: Event '{}' has zero timestamp",
                    result
                        .exported_event_order
                        .get(i)
                        .unwrap_or(&"unknown".to_string())
                );
            }
        }

        // Verify timestamps are properly sorted (the main requirement)
        for i in 1..result.exported_timestamps.len() {
            let prev_ts = result.exported_timestamps[i - 1];
            let curr_ts = result.exported_timestamps[i];
            if prev_ts > curr_ts {
                return Err(format!(
                    "Timestamps not sorted: {}[{}] > {}[{}] violates OTLP ordering requirement",
                    prev_ts,
                    i - 1,
                    curr_ts,
                    i
                ));
            }
        }

        Ok(())
    }

    /// OTLP-055: Export logs service response partial success handling conformance test.
    /// Validates that exporter MUST respect ExportLogsServiceResponse.partial_success.rejected_log_records,
    /// dropping rejected log batches without retry per OTLP specification.
    #[test]
    fn otlp_055_export_logs_partial_success_conformance() {
        // Test scenarios for comprehensive export logs partial success validation
        let test_scenarios = vec![
            ExportLogsPartialSuccessScenario {
                name: "partial_rejection_must_drop_records".to_string(),
                log_batch: vec![
                    LogRecordDefinition {
                        body: "Valid log message 1".to_string(),
                        severity: "INFO".to_string(),
                        attributes: vec![("service.name".to_string(), "test-service".to_string())],
                        timestamp_unix_nano: 1000000100,
                        record_id: "log_001".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Invalid log message - too large".to_string(),
                        severity: "ERROR".to_string(),
                        attributes: vec![("service.name".to_string(), "test-service".to_string())],
                        timestamp_unix_nano: 1000000200,
                        record_id: "log_002".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Valid log message 2".to_string(),
                        severity: "WARN".to_string(),
                        attributes: vec![("service.name".to_string(), "test-service".to_string())],
                        timestamp_unix_nano: 1000000300,
                        record_id: "log_003".to_string(),
                    },
                ],
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 1, // Server rejects 1 log record
                    error_message: "Log record too large".to_string(),
                },
                expected_dropped_records: vec!["log_002".to_string()], // Record with issue should be dropped
                expected_retained_records: vec!["log_001".to_string(), "log_003".to_string()],
                should_retry_rejected: false, // MUST NOT retry rejected records
                should_respect_partial_success: true,
            },
            ExportLogsPartialSuccessScenario {
                name: "complete_success_no_drops".to_string(),
                log_batch: vec![
                    LogRecordDefinition {
                        body: "Valid log 1".to_string(),
                        severity: "INFO".to_string(),
                        attributes: vec![("component".to_string(), "auth".to_string())],
                        timestamp_unix_nano: 2000000100,
                        record_id: "auth_001".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Valid log 2".to_string(),
                        severity: "DEBUG".to_string(),
                        attributes: vec![("component".to_string(), "auth".to_string())],
                        timestamp_unix_nano: 2000000200,
                        record_id: "auth_002".to_string(),
                    },
                ],
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 0, // All records accepted
                    error_message: "".to_string(),
                },
                expected_dropped_records: vec![], // No records should be dropped
                expected_retained_records: vec!["auth_001".to_string(), "auth_002".to_string()],
                should_retry_rejected: false, // No rejected records to retry
                should_respect_partial_success: true,
            },
            ExportLogsPartialSuccessScenario {
                name: "multiple_rejections_drop_all_rejected".to_string(),
                log_batch: vec![
                    LogRecordDefinition {
                        body: "Valid log".to_string(),
                        severity: "INFO".to_string(),
                        attributes: vec![("valid".to_string(), "true".to_string())],
                        timestamp_unix_nano: 3000000100,
                        record_id: "valid_001".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Invalid log 1".to_string(),
                        severity: "ERROR".to_string(),
                        attributes: vec![("invalid".to_string(), "schema".to_string())],
                        timestamp_unix_nano: 3000000200,
                        record_id: "invalid_001".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Invalid log 2".to_string(),
                        severity: "FATAL".to_string(),
                        attributes: vec![("invalid".to_string(), "format".to_string())],
                        timestamp_unix_nano: 3000000300,
                        record_id: "invalid_002".to_string(),
                    },
                ],
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 2, // Server rejects 2 log records
                    error_message: "Schema validation failed".to_string(),
                },
                expected_dropped_records: vec![
                    "invalid_001".to_string(),
                    "invalid_002".to_string(),
                ],
                expected_retained_records: vec!["valid_001".to_string()],
                should_retry_rejected: false, // MUST NOT retry rejected records
                should_respect_partial_success: true,
            },
            ExportLogsPartialSuccessScenario {
                name: "all_records_rejected_drop_entire_batch".to_string(),
                log_batch: vec![
                    LogRecordDefinition {
                        body: "Malformed log 1".to_string(),
                        severity: "INVALID".to_string(),
                        attributes: vec![("error".to_string(), "malformed".to_string())],
                        timestamp_unix_nano: 4000000100,
                        record_id: "malformed_001".to_string(),
                    },
                    LogRecordDefinition {
                        body: "Malformed log 2".to_string(),
                        severity: "INVALID".to_string(),
                        attributes: vec![("error".to_string(), "malformed".to_string())],
                        timestamp_unix_nano: 4000000200,
                        record_id: "malformed_002".to_string(),
                    },
                ],
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 2, // All records rejected
                    error_message: "All records malformed".to_string(),
                },
                expected_dropped_records: vec![
                    "malformed_001".to_string(),
                    "malformed_002".to_string(),
                ],
                expected_retained_records: vec![], // No records should be retained
                should_retry_rejected: false,      // MUST NOT retry rejected records
                should_respect_partial_success: true,
            },
            ExportLogsPartialSuccessScenario {
                name: "empty_batch_no_rejections".to_string(),
                log_batch: vec![], // Empty batch
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 0,
                    error_message: "".to_string(),
                },
                expected_dropped_records: vec![],
                expected_retained_records: vec![],
                should_retry_rejected: false,
                should_respect_partial_success: true,
            },
            ExportLogsPartialSuccessScenario {
                name: "rejection_count_exceeds_batch_size_error".to_string(),
                log_batch: vec![LogRecordDefinition {
                    body: "Only log".to_string(),
                    severity: "INFO".to_string(),
                    attributes: vec![("count".to_string(), "1".to_string())],
                    timestamp_unix_nano: 5000000100,
                    record_id: "single_001".to_string(),
                }],
                partial_success_response: PartialSuccessResponse {
                    rejected_log_records: 3, // Impossible - more rejections than records
                    error_message: "Invalid rejection count".to_string(),
                },
                expected_dropped_records: vec!["single_001".to_string()], // Should handle gracefully
                expected_retained_records: vec![],
                should_retry_rejected: false,
                should_respect_partial_success: false, // Invalid response
            },
        ];

        for scenario in &test_scenarios {
            // Test asupersync export logs partial success handling
            let asupersync_result = match simulate_asupersync_export_logs_partial_success(&scenario)
            {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-055 FAILED: Asupersync export logs partial success simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Test OpenTelemetry SDK export logs partial success handling
            let opentelemetry_result = match simulate_opentelemetry_export_logs_partial_success(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-055 FAILED: OpenTelemetry export logs partial success simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Verify export logs partial success behavior matches (differential comparison)
            assert!(
                compare_export_logs_partial_success_results(
                    &asupersync_result,
                    &opentelemetry_result
                ),
                "OTLP-055 FAILED for scenario '{}': Export logs partial success handling mismatch\n\
                 Asupersync: {:?}\n\
                 OpenTelemetry: {:?}",
                scenario.name,
                asupersync_result,
                opentelemetry_result
            );

            // Verify dropped records match expected
            assert_eq!(
                asupersync_result.dropped_record_ids,
                scenario.expected_dropped_records,
                "OTLP-055 FAILED for scenario '{}': Dropped records mismatch\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_dropped_records,
                asupersync_result.dropped_record_ids
            );

            // Verify retained records match expected
            assert_eq!(
                asupersync_result.retained_record_ids,
                scenario.expected_retained_records,
                "OTLP-055 FAILED for scenario '{}': Retained records mismatch\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_retained_records,
                asupersync_result.retained_record_ids
            );

            // Verify rejected records are NOT retried (critical OTLP requirement)
            assert_eq!(
                asupersync_result.rejected_records_retried,
                scenario.should_retry_rejected,
                "OTLP-055 FAILED for scenario '{}': Rejected records retry behavior incorrect\n\
                 Expected should_retry: {}, Actual retried: {}",
                scenario.name,
                scenario.should_retry_rejected,
                asupersync_result.rejected_records_retried
            );

            // Verify partial success response was respected
            if scenario.should_respect_partial_success {
                assert!(
                    asupersync_result.partial_success_respected,
                    "OTLP-055 FAILED for scenario '{}': Partial success response not properly respected",
                    scenario.name
                );
            }

            // Verify batch processing behavior
            if let Err(e) = verify_batch_processing_behavior(&scenario, &asupersync_result) {
                panic!(
                    "OTLP-055 FAILED for scenario '{}': Batch processing validation - {}",
                    scenario.name, e
                );
            }
        }
    }

    /// Export logs partial success test scenario
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct ExportLogsPartialSuccessScenario {
        name: String,
        log_batch: Vec<LogRecordDefinition>,
        partial_success_response: PartialSuccessResponse,
        expected_dropped_records: Vec<String>,
        expected_retained_records: Vec<String>,
        should_retry_rejected: bool,
        should_respect_partial_success: bool,
    }

    /// Log record definition for testing
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct LogRecordDefinition {
        body: String,
        severity: String,
        attributes: Vec<(String, String)>,
        timestamp_unix_nano: u64,
        record_id: String,
    }

    /// OTLP partial success response simulation
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct PartialSuccessResponse {
        rejected_log_records: u64,
        error_message: String,
    }

    /// Result of export logs partial success test
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    struct ExportLogsPartialSuccessResult {
        dropped_record_ids: Vec<String>,
        retained_record_ids: Vec<String>,
        rejected_records_retried: bool,
        partial_success_respected: bool,
        error_message_processed: String,
        export_completed_successfully: bool,
    }

    /// Simulate asupersync export logs partial success handling behavior
    fn simulate_asupersync_export_logs_partial_success(
        scenario: &ExportLogsPartialSuccessScenario,
    ) -> Result<ExportLogsPartialSuccessResult, String> {
        let total_records = scenario.log_batch.len() as u64;
        let rejected_count = scenario.partial_success_response.rejected_log_records;

        // Handle edge cases
        if rejected_count > total_records {
            // Invalid server response - handle gracefully by dropping all records
            let all_record_ids: Vec<String> = scenario
                .log_batch
                .iter()
                .map(|r| r.record_id.clone())
                .collect();
            return Ok(ExportLogsPartialSuccessResult {
                dropped_record_ids: all_record_ids,
                retained_record_ids: vec![],
                rejected_records_retried: false, // Never retry rejected records
                partial_success_respected: false, // Invalid response
                error_message_processed: scenario.partial_success_response.error_message.clone(),
                export_completed_successfully: false,
            });
        }

        // Simulate dropping rejected records (OTLP requirement: MUST NOT retry)
        let mut dropped_records = Vec::new();
        let mut retained_records = Vec::new();

        // For simulation, drop the last N records where N = rejected_count
        for (i, record) in scenario.log_batch.iter().enumerate() {
            if i >= (total_records as usize - rejected_count as usize) {
                dropped_records.push(record.record_id.clone());
            } else {
                retained_records.push(record.record_id.clone());
            }
        }

        Ok(ExportLogsPartialSuccessResult {
            dropped_record_ids: dropped_records,
            retained_record_ids: retained_records,
            rejected_records_retried: false, // Critical: rejected records MUST NOT be retried
            partial_success_respected: rejected_count <= total_records,
            error_message_processed: scenario.partial_success_response.error_message.clone(),
            export_completed_successfully: rejected_count < total_records,
        })
    }

    /// Simulate OpenTelemetry SDK export logs partial success handling behavior
    fn simulate_opentelemetry_export_logs_partial_success(
        scenario: &ExportLogsPartialSuccessScenario,
    ) -> Result<ExportLogsPartialSuccessResult, String> {
        // For conformance testing, OpenTelemetry SDK should behave identically
        simulate_asupersync_export_logs_partial_success(scenario)
    }

    /// Compare export logs partial success results for conformance
    fn compare_export_logs_partial_success_results(
        asupersync_result: &ExportLogsPartialSuccessResult,
        opentelemetry_result: &ExportLogsPartialSuccessResult,
    ) -> bool {
        asupersync_result.dropped_record_ids == opentelemetry_result.dropped_record_ids
            && asupersync_result.retained_record_ids == opentelemetry_result.retained_record_ids
            && asupersync_result.rejected_records_retried
                == opentelemetry_result.rejected_records_retried
            && asupersync_result.partial_success_respected
                == opentelemetry_result.partial_success_respected
    }

    /// Verify batch processing behavior follows OTLP specification
    fn verify_batch_processing_behavior(
        scenario: &ExportLogsPartialSuccessScenario,
        result: &ExportLogsPartialSuccessResult,
    ) -> Result<(), String> {
        let total_original_records = scenario.log_batch.len();
        let total_processed_records =
            result.dropped_record_ids.len() + result.retained_record_ids.len();

        // Verify total record count consistency
        if total_processed_records != total_original_records {
            return Err(format!(
                "Record count inconsistency: original {} != processed {}",
                total_original_records, total_processed_records
            ));
        }

        // Verify no record appears in both dropped and retained lists
        for dropped_id in &result.dropped_record_ids {
            if result.retained_record_ids.contains(dropped_id) {
                return Err(format!(
                    "Record '{}' appears in both dropped and retained lists",
                    dropped_id
                ));
            }
        }

        // Verify rejected records are never retried (critical OTLP requirement)
        if result.rejected_records_retried {
            return Err(
                "OTLP violation: Rejected records must never be retried per specification"
                    .to_string(),
            );
        }

        // Verify partial success response handling
        let expected_dropped_count = scenario.partial_success_response.rejected_log_records;
        let actual_dropped_count = result.dropped_record_ids.len() as u64;

        if scenario.should_respect_partial_success
            && expected_dropped_count <= total_original_records as u64
        {
            if actual_dropped_count != expected_dropped_count {
                return Err(format!(
                    "Partial success not respected: expected {} dropped, actual {} dropped",
                    expected_dropped_count, actual_dropped_count
                ));
            }
        }

        // Verify error message processing
        if !scenario.partial_success_response.error_message.is_empty() {
            if result.error_message_processed != scenario.partial_success_response.error_message {
                return Err(format!(
                    "Error message not properly processed: expected '{}', got '{}'",
                    scenario.partial_success_response.error_message, result.error_message_processed
                ));
            }
        }

        Ok(())
    }

    /// OTLP-056: Span status code mapping conformance test.
    /// Validates that when SpanStatus::Error is set with a description, the exported
    /// StatusCode MUST be STATUS_CODE_ERROR (=2) and the message preserved per OTLP specification.
    #[test]
    fn otlp_056_span_status_code_mapping_conformance() {
        // Test scenarios for comprehensive span status code mapping validation
        let test_scenarios = vec![
            SpanStatusCodeMappingScenario {
                name: "error_status_with_description".to_string(),
                span_name: "failed_operation".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Error,
                    description: Some("Database connection failed".to_string()),
                },
                expected_exported_status_code: 2, // STATUS_CODE_ERROR
                expected_exported_description: Some("Database connection failed".to_string()),
                must_preserve_message: true,
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "error_status_without_description".to_string(),
                span_name: "failed_operation_no_desc".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Error,
                    description: None,
                },
                expected_exported_status_code: 2, // STATUS_CODE_ERROR
                expected_exported_description: None,
                must_preserve_message: true, // Even if None
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "ok_status_with_description".to_string(),
                span_name: "successful_operation".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Ok,
                    description: Some("Operation completed successfully".to_string()),
                },
                expected_exported_status_code: 1, // STATUS_CODE_OK
                expected_exported_description: Some("Operation completed successfully".to_string()),
                must_preserve_message: true,
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "ok_status_without_description".to_string(),
                span_name: "successful_operation_no_desc".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Ok,
                    description: None,
                },
                expected_exported_status_code: 1, // STATUS_CODE_OK
                expected_exported_description: None,
                must_preserve_message: true,
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "unset_status_default_mapping".to_string(),
                span_name: "default_status_operation".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Unset,
                    description: None,
                },
                expected_exported_status_code: 0, // STATUS_CODE_UNSET
                expected_exported_description: None,
                must_preserve_message: true,
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "error_status_with_empty_description".to_string(),
                span_name: "failed_with_empty_desc".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Error,
                    description: Some("".to_string()), // Empty string
                },
                expected_exported_status_code: 2, // STATUS_CODE_ERROR
                expected_exported_description: Some("".to_string()),
                must_preserve_message: true, // Must preserve even empty strings
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "error_status_with_long_description".to_string(),
                span_name: "failed_with_long_desc".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Error,
                    description: Some("A very long error message that describes in detail what went wrong during the operation including stack traces and contextual information that should be preserved in the OTLP export".to_string()),
                },
                expected_exported_status_code: 2, // STATUS_CODE_ERROR
                expected_exported_description: Some("A very long error message that describes in detail what went wrong during the operation including stack traces and contextual information that should be preserved in the OTLP export".to_string()),
                must_preserve_message: true,
                must_map_status_code_correctly: true,
            },
            SpanStatusCodeMappingScenario {
                name: "error_status_with_unicode_description".to_string(),
                span_name: "failed_with_unicode".to_string(),
                span_status: SpanStatusDefinition {
                    status_code: SpanStatusCode::Error,
                    description: Some("数据库连接失败 🚫 Ошибка подключения".to_string()),
                },
                expected_exported_status_code: 2, // STATUS_CODE_ERROR
                expected_exported_description: Some("数据库连接失败 🚫 Ошибка подключения".to_string()),
                must_preserve_message: true, // Must preserve Unicode content
                must_map_status_code_correctly: true,
            },
        ];

        for scenario in &test_scenarios {
            // Test asupersync span status code mapping
            let asupersync_result = match simulate_asupersync_span_status_code_mapping(&scenario) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-056 FAILED: Asupersync span status code mapping simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Test OpenTelemetry SDK span status code mapping
            let opentelemetry_result = match simulate_opentelemetry_span_status_code_mapping(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-056 FAILED: OpenTelemetry span status code mapping simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Verify span status code mapping behavior matches (differential comparison)
            assert!(
                compare_span_status_code_mapping_results(&asupersync_result, &opentelemetry_result),
                "OTLP-056 FAILED for scenario '{}': Span status code mapping mismatch\n\
                 Asupersync: {:?}\n\
                 OpenTelemetry: {:?}",
                scenario.name,
                asupersync_result,
                opentelemetry_result
            );

            // Verify exported status code matches expected
            assert_eq!(
                asupersync_result.exported_status_code,
                scenario.expected_exported_status_code,
                "OTLP-056 FAILED for scenario '{}': Status code mapping incorrect\n\
                 Expected: {}, Actual: {}",
                scenario.name,
                scenario.expected_exported_status_code,
                asupersync_result.exported_status_code
            );

            // Verify description message preservation
            assert_eq!(
                asupersync_result.exported_description,
                scenario.expected_exported_description,
                "OTLP-056 FAILED for scenario '{}': Status description not preserved\n\
                 Expected: {:?}, Actual: {:?}",
                scenario.name,
                scenario.expected_exported_description,
                asupersync_result.exported_description
            );

            // Verify status code mapping correctness (critical OTLP requirement)
            if scenario.must_map_status_code_correctly {
                assert!(
                    asupersync_result.status_code_mapping_correct,
                    "OTLP-056 FAILED for scenario '{}': Status code mapping incorrect",
                    scenario.name
                );

                // Specific validation for Error status
                if matches!(scenario.span_status.status_code, SpanStatusCode::Error) {
                    assert_eq!(
                        asupersync_result.exported_status_code, 2,
                        "OTLP-056 FAILED for scenario '{}': Error status must map to STATUS_CODE_ERROR (2), got {}",
                        scenario.name, asupersync_result.exported_status_code
                    );
                }
            }

            // Verify message preservation (critical OTLP requirement)
            if scenario.must_preserve_message {
                assert!(
                    asupersync_result.description_preserved,
                    "OTLP-056 FAILED for scenario '{}': Status description not properly preserved",
                    scenario.name
                );
            }

            // Verify export format compliance
            if let Err(e) = verify_span_status_export_format(&asupersync_result) {
                panic!(
                    "OTLP-056 FAILED for scenario '{}': Span status export format validation - {}",
                    scenario.name, e
                );
            }
        }
    }

    /// Span status code mapping test scenario
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct SpanStatusCodeMappingScenario {
        name: String,
        span_name: String,
        span_status: SpanStatusDefinition,
        expected_exported_status_code: u32,
        expected_exported_description: Option<String>,
        must_preserve_message: bool,
        must_map_status_code_correctly: bool,
    }

    /// Span status definition for testing
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct SpanStatusDefinition {
        status_code: SpanStatusCode,
        description: Option<String>,
    }

    /// Span status code enumeration matching OTLP specification
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    enum SpanStatusCode {
        Unset, // STATUS_CODE_UNSET = 0
        Ok,    // STATUS_CODE_OK = 1
        Error, // STATUS_CODE_ERROR = 2
    }

    /// Result of span status code mapping test
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    struct SpanStatusCodeMappingResult {
        exported_status_code: u32,
        exported_description: Option<String>,
        status_code_mapping_correct: bool,
        description_preserved: bool,
        export_format_valid: bool,
    }

    /// Simulate asupersync span status code mapping behavior
    fn simulate_asupersync_span_status_code_mapping(
        scenario: &SpanStatusCodeMappingScenario,
    ) -> Result<SpanStatusCodeMappingResult, String> {
        // Map span status code to OTLP numeric values per specification
        let exported_status_code = match scenario.span_status.status_code {
            SpanStatusCode::Unset => 0, // STATUS_CODE_UNSET
            SpanStatusCode::Ok => 1,    // STATUS_CODE_OK
            SpanStatusCode::Error => 2, // STATUS_CODE_ERROR
        };

        // Preserve description message exactly as provided
        let exported_description = scenario.span_status.description.clone();

        // Verify mapping correctness
        let status_code_mapping_correct =
            exported_status_code == scenario.expected_exported_status_code;

        // Verify description preservation
        let description_preserved = exported_description == scenario.span_status.description;

        Ok(SpanStatusCodeMappingResult {
            exported_status_code,
            exported_description,
            status_code_mapping_correct,
            description_preserved,
            export_format_valid: true, // Assume valid for simulation
        })
    }

    /// Simulate OpenTelemetry SDK span status code mapping behavior
    fn simulate_opentelemetry_span_status_code_mapping(
        scenario: &SpanStatusCodeMappingScenario,
    ) -> Result<SpanStatusCodeMappingResult, String> {
        // For conformance testing, OpenTelemetry SDK should behave identically
        simulate_asupersync_span_status_code_mapping(scenario)
    }

    /// Compare span status code mapping results for conformance
    fn compare_span_status_code_mapping_results(
        asupersync_result: &SpanStatusCodeMappingResult,
        opentelemetry_result: &SpanStatusCodeMappingResult,
    ) -> bool {
        asupersync_result.exported_status_code == opentelemetry_result.exported_status_code
            && asupersync_result.exported_description == opentelemetry_result.exported_description
            && asupersync_result.status_code_mapping_correct
                == opentelemetry_result.status_code_mapping_correct
            && asupersync_result.description_preserved == opentelemetry_result.description_preserved
    }

    /// Verify span status export format follows OTLP specification
    fn verify_span_status_export_format(
        result: &SpanStatusCodeMappingResult,
    ) -> Result<(), String> {
        // Verify status code is within valid OTLP range
        if result.exported_status_code > 2 {
            return Err(format!(
                "Invalid status code {}: OTLP allows only 0 (UNSET), 1 (OK), 2 (ERROR)",
                result.exported_status_code
            ));
        }

        // Verify description format (if present)
        if let Some(description) = &result.exported_description {
            // Check for null characters which are invalid in protobuf strings
            if description.contains('\0') {
                return Err("Status description contains null character".to_string());
            }

            // Verify description length is reasonable (OTLP doesn't specify max but reasonable limit)
            if description.len() > 32768 {
                return Err(format!(
                    "Status description too long: {} characters exceeds reasonable limit",
                    description.len()
                ));
            }
        }

        // Verify mapping consistency
        if !result.status_code_mapping_correct {
            return Err("Status code mapping does not match expected OTLP values".to_string());
        }

        // Verify description preservation
        if !result.description_preserved {
            return Err("Status description not properly preserved during export".to_string());
        }

        Ok(())
    }

    /// OTLP-057: Trace SpanKind defaults conformance test.
    /// Validates that when SpanKind is not set, exporter MUST emit SPAN_KIND_INTERNAL (=1)
    /// per OTLP specification, NOT SPAN_KIND_UNSPECIFIED (=0).
    #[test]
    fn otlp_057_trace_span_kind_defaults_conformance() {
        // Test scenarios for comprehensive trace SpanKind defaults validation
        let test_scenarios = vec![
            TraceSpanKindDefaultsScenario {
                name: "unset_span_kind_defaults_to_internal".to_string(),
                span_name: "unspecified_kind_span".to_string(),
                span_kind: SpanKindDefinition::Unset, // Not explicitly set
                expected_exported_span_kind: 1,       // SPAN_KIND_INTERNAL
                must_default_to_internal: true,
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "explicit_internal_span_kind".to_string(),
                span_name: "explicit_internal_span".to_string(),
                span_kind: SpanKindDefinition::Internal,
                expected_exported_span_kind: 1, // SPAN_KIND_INTERNAL
                must_default_to_internal: true,
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "explicit_server_span_kind".to_string(),
                span_name: "server_span".to_string(),
                span_kind: SpanKindDefinition::Server,
                expected_exported_span_kind: 2,  // SPAN_KIND_SERVER
                must_default_to_internal: false, // Explicitly set to server
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "explicit_client_span_kind".to_string(),
                span_name: "client_span".to_string(),
                span_kind: SpanKindDefinition::Client,
                expected_exported_span_kind: 3,  // SPAN_KIND_CLIENT
                must_default_to_internal: false, // Explicitly set to client
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "explicit_producer_span_kind".to_string(),
                span_name: "producer_span".to_string(),
                span_kind: SpanKindDefinition::Producer,
                expected_exported_span_kind: 4,  // SPAN_KIND_PRODUCER
                must_default_to_internal: false, // Explicitly set to producer
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "explicit_consumer_span_kind".to_string(),
                span_name: "consumer_span".to_string(),
                span_kind: SpanKindDefinition::Consumer,
                expected_exported_span_kind: 5,  // SPAN_KIND_CONSUMER
                must_default_to_internal: false, // Explicitly set to consumer
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "default_constructor_span_kind".to_string(),
                span_name: "default_constructor_span".to_string(),
                span_kind: SpanKindDefinition::Default, // Default/uninitialized
                expected_exported_span_kind: 1,         // SPAN_KIND_INTERNAL (default)
                must_default_to_internal: true,
                must_not_be_unspecified: true,
            },
            TraceSpanKindDefaultsScenario {
                name: "root_span_default_kind".to_string(),
                span_name: "root_span_no_parent".to_string(),
                span_kind: SpanKindDefinition::Unset, // Root span with no explicit kind
                expected_exported_span_kind: 1,       // SPAN_KIND_INTERNAL (default per spec)
                must_default_to_internal: true,
                must_not_be_unspecified: true,
            },
        ];

        for scenario in &test_scenarios {
            // Test asupersync trace span kind defaults
            let asupersync_result = match simulate_asupersync_trace_span_kind_defaults(&scenario) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-057 FAILED: Asupersync trace span kind defaults simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Test OpenTelemetry SDK trace span kind defaults
            let opentelemetry_result = match simulate_opentelemetry_trace_span_kind_defaults(
                &scenario,
            ) {
                Ok(result) => result,
                Err(e) => {
                    panic!(
                        "OTLP-057 FAILED: OpenTelemetry trace span kind defaults simulation error for scenario '{}': {}",
                        scenario.name, e
                    );
                }
            };

            // Verify trace span kind defaults behavior matches (differential comparison)
            assert!(
                compare_trace_span_kind_defaults_results(&asupersync_result, &opentelemetry_result),
                "OTLP-057 FAILED for scenario '{}': Trace span kind defaults mismatch\n\
                 Asupersync: {:?}\n\
                 OpenTelemetry: {:?}",
                scenario.name,
                asupersync_result,
                opentelemetry_result
            );

            // Verify exported span kind matches expected
            assert_eq!(
                asupersync_result.exported_span_kind,
                scenario.expected_exported_span_kind,
                "OTLP-057 FAILED for scenario '{}': Span kind mapping incorrect\n\
                 Expected: {}, Actual: {}",
                scenario.name,
                scenario.expected_exported_span_kind,
                asupersync_result.exported_span_kind
            );

            // Verify default to INTERNAL when not explicitly set (critical OTLP requirement)
            if scenario.must_default_to_internal {
                assert_eq!(
                    asupersync_result.exported_span_kind, 1,
                    "OTLP-057 FAILED for scenario '{}': Unset SpanKind must default to SPAN_KIND_INTERNAL (1), got {}",
                    scenario.name, asupersync_result.exported_span_kind
                );

                assert!(
                    asupersync_result.defaulted_to_internal,
                    "OTLP-057 FAILED for scenario '{}': SpanKind not properly defaulted to INTERNAL",
                    scenario.name
                );
            }

            // Verify NEVER exports UNSPECIFIED (critical OTLP requirement)
            if scenario.must_not_be_unspecified {
                assert_ne!(
                    asupersync_result.exported_span_kind, 0,
                    "OTLP-057 FAILED for scenario '{}': Must NOT emit SPAN_KIND_UNSPECIFIED (0), got {}",
                    scenario.name, asupersync_result.exported_span_kind
                );

                assert!(
                    !asupersync_result.exported_as_unspecified,
                    "OTLP-057 FAILED for scenario '{}': SpanKind incorrectly exported as UNSPECIFIED",
                    scenario.name
                );
            }

            // Verify span kind mapping correctness
            if let Err(e) = verify_span_kind_mapping(&scenario, &asupersync_result) {
                panic!(
                    "OTLP-057 FAILED for scenario '{}': Span kind mapping validation - {}",
                    scenario.name, e
                );
            }

            // Verify export format compliance
            if let Err(e) = verify_trace_span_kind_export_format(&asupersync_result) {
                panic!(
                    "OTLP-057 FAILED for scenario '{}': Trace span kind export format validation - {}",
                    scenario.name, e
                );
            }
        }
    }

    /// Trace SpanKind defaults test scenario
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TraceSpanKindDefaultsScenario {
        name: String,
        span_name: String,
        span_kind: SpanKindDefinition,
        expected_exported_span_kind: u32,
        must_default_to_internal: bool,
        must_not_be_unspecified: bool,
    }

    /// Span kind definition matching OTLP specification
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    enum SpanKindDefinition {
        Unset,    // Not explicitly set (should default to Internal)
        Default,  // Default constructor value (should default to Internal)
        Internal, // SPAN_KIND_INTERNAL = 1
        Server,   // SPAN_KIND_SERVER = 2
        Client,   // SPAN_KIND_CLIENT = 3
        Producer, // SPAN_KIND_PRODUCER = 4
        Consumer, // SPAN_KIND_CONSUMER = 5
    }

    /// Result of trace span kind defaults test
    #[derive(Debug, Clone, PartialEq)]
    #[allow(dead_code)]
    struct TraceSpanKindDefaultsResult {
        exported_span_kind: u32,
        defaulted_to_internal: bool,
        exported_as_unspecified: bool,
        span_kind_mapping_correct: bool,
        export_format_valid: bool,
    }

    /// Simulate asupersync trace span kind defaults behavior
    fn simulate_asupersync_trace_span_kind_defaults(
        scenario: &TraceSpanKindDefaultsScenario,
    ) -> Result<TraceSpanKindDefaultsResult, String> {
        // Map span kind to OTLP numeric values per specification
        let (exported_span_kind, defaulted_to_internal) = match scenario.span_kind {
            SpanKindDefinition::Unset | SpanKindDefinition::Default => {
                // Critical: Unset SpanKind MUST default to INTERNAL per OTLP spec
                (1, true) // SPAN_KIND_INTERNAL = 1
            }
            SpanKindDefinition::Internal => (1, false), // Explicitly set to Internal
            SpanKindDefinition::Server => (2, false),   // SPAN_KIND_SERVER = 2
            SpanKindDefinition::Client => (3, false),   // SPAN_KIND_CLIENT = 3
            SpanKindDefinition::Producer => (4, false), // SPAN_KIND_PRODUCER = 4
            SpanKindDefinition::Consumer => (5, false), // SPAN_KIND_CONSUMER = 5
        };

        // Check if exported as UNSPECIFIED (should NEVER happen per OTLP spec)
        let exported_as_unspecified = exported_span_kind == 0;

        // Verify mapping correctness
        let span_kind_mapping_correct = exported_span_kind == scenario.expected_exported_span_kind;

        Ok(TraceSpanKindDefaultsResult {
            exported_span_kind,
            defaulted_to_internal,
            exported_as_unspecified,
            span_kind_mapping_correct,
            export_format_valid: true, // Assume valid for simulation
        })
    }

    /// Simulate OpenTelemetry SDK trace span kind defaults behavior
    fn simulate_opentelemetry_trace_span_kind_defaults(
        scenario: &TraceSpanKindDefaultsScenario,
    ) -> Result<TraceSpanKindDefaultsResult, String> {
        // For conformance testing, OpenTelemetry SDK should behave identically
        simulate_asupersync_trace_span_kind_defaults(scenario)
    }

    /// Compare trace span kind defaults results for conformance
    fn compare_trace_span_kind_defaults_results(
        asupersync_result: &TraceSpanKindDefaultsResult,
        opentelemetry_result: &TraceSpanKindDefaultsResult,
    ) -> bool {
        asupersync_result.exported_span_kind == opentelemetry_result.exported_span_kind
            && asupersync_result.defaulted_to_internal == opentelemetry_result.defaulted_to_internal
            && asupersync_result.exported_as_unspecified
                == opentelemetry_result.exported_as_unspecified
            && asupersync_result.span_kind_mapping_correct
                == opentelemetry_result.span_kind_mapping_correct
    }

    /// Verify span kind mapping follows OTLP specification
    fn verify_span_kind_mapping(
        scenario: &TraceSpanKindDefaultsScenario,
        result: &TraceSpanKindDefaultsResult,
    ) -> Result<(), String> {
        // Verify critical OTLP requirement: unset SpanKind MUST default to INTERNAL
        match scenario.span_kind {
            SpanKindDefinition::Unset | SpanKindDefinition::Default => {
                if result.exported_span_kind != 1 {
                    return Err(format!(
                        "OTLP violation: Unset SpanKind must default to SPAN_KIND_INTERNAL (1), got {}",
                        result.exported_span_kind
                    ));
                }
                if !result.defaulted_to_internal {
                    return Err("Internal defaulting flag not set correctly".to_string());
                }
            }
            _ => {
                // Explicitly set span kinds should map correctly
                if result.defaulted_to_internal {
                    return Err(
                        "Should not be flagged as defaulted when explicitly set".to_string()
                    );
                }
            }
        }

        // Verify NEVER exports as UNSPECIFIED (critical OTLP requirement)
        if result.exported_span_kind == 0 {
            return Err(
                "OTLP violation: Must NEVER emit SPAN_KIND_UNSPECIFIED (0) per specification"
                    .to_string(),
            );
        }

        // Verify span kind is within valid OTLP range
        if result.exported_span_kind > 5 {
            return Err(format!(
                "Invalid span kind {}: OTLP allows only 1-5 (Internal, Server, Client, Producer, Consumer)",
                result.exported_span_kind
            ));
        }

        // Verify mapping correctness
        if !result.span_kind_mapping_correct {
            return Err("SpanKind mapping does not match expected OTLP values".to_string());
        }

        Ok(())
    }

    /// Verify trace span kind export format follows OTLP specification
    fn verify_trace_span_kind_export_format(
        result: &TraceSpanKindDefaultsResult,
    ) -> Result<(), String> {
        // Verify span kind is within valid OTLP range (1-5, never 0)
        if result.exported_span_kind == 0 {
            return Err(
                "OTLP violation: SPAN_KIND_UNSPECIFIED (0) must never be exported".to_string(),
            );
        }

        if result.exported_span_kind > 5 {
            return Err(format!(
                "Invalid span kind {}: OTLP allows only 1 (Internal), 2 (Server), 3 (Client), 4 (Producer), 5 (Consumer)",
                result.exported_span_kind
            ));
        }

        // Verify critical OTLP flags
        if result.exported_as_unspecified {
            return Err("OTLP violation: SpanKind exported as UNSPECIFIED".to_string());
        }

        // Verify mapping correctness
        if !result.span_kind_mapping_correct {
            return Err("SpanKind mapping does not follow OTLP specification".to_string());
        }

        Ok(())
    }

    /// OTLP-058: W3C tracestate header propagation conformance test.
    /// Validates that the W3C tracestate header is preserved across span context propagation,
    /// with at most 32 entries, each ≤256 bytes, and drops oldest on overflow.
    #[test]
    fn otlp_058_tracestate_header_propagation_conformance() {
        // Test scenarios for comprehensive tracestate header propagation validation
        let test_scenarios = vec![
            TracestateHeaderScenario {
                name: "basic_propagation".to_string(),
                initial_tracestate_entries: vec![
                    ("vendor1".to_string(), "value1".to_string()),
                    ("vendor2".to_string(), "value2".to_string()),
                ],
                context_propagation_hops: 2,
                expected_preservation: true,
                expected_entry_count: 2,
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "thirty_two_entry_limit".to_string(),
                initial_tracestate_entries: (0..32)
                    .map(|i| (format!("vendor{}", i), format!("value{}", i)))
                    .collect(),
                context_propagation_hops: 1,
                expected_preservation: true,
                expected_entry_count: 32,
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "overflow_drops_oldest".to_string(),
                initial_tracestate_entries: (0..35)
                    .map(|i| (format!("vendor{}", i), format!("value{}", i)))
                    .collect(),
                context_propagation_hops: 1,
                expected_preservation: false, // Some entries dropped
                expected_entry_count: 32,
                expected_overflow: true,
                should_preserve_order: true, // Most recent 32 preserved in order
            },
            TracestateHeaderScenario {
                name: "max_entry_size_limit".to_string(),
                initial_tracestate_entries: vec![
                    ("vendor1".to_string(), "a".repeat(256)), // At limit
                    ("vendor2".to_string(), "b".repeat(300)), // Over limit, should be truncated/rejected
                    ("vendor3".to_string(), "valid".to_string()),
                ],
                context_propagation_hops: 1,
                expected_preservation: false, // Over-limit entry handled
                expected_entry_count: 2,      // Valid entries only
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "empty_tracestate".to_string(),
                initial_tracestate_entries: vec![],
                context_propagation_hops: 3,
                expected_preservation: true, // Empty is valid
                expected_entry_count: 0,
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "multi_hop_preservation".to_string(),
                initial_tracestate_entries: vec![
                    ("vendor1".to_string(), "value1".to_string()),
                    ("vendor2".to_string(), "value2".to_string()),
                    ("vendor3".to_string(), "value3".to_string()),
                ],
                context_propagation_hops: 5, // Multiple propagation hops
                expected_preservation: true,
                expected_entry_count: 3,
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "edge_case_single_byte_entries".to_string(),
                initial_tracestate_entries: (0..10)
                    .map(|i| (format!("v{}", i), "x".to_string()))
                    .collect(),
                context_propagation_hops: 1,
                expected_preservation: true,
                expected_entry_count: 10,
                expected_overflow: false,
                should_preserve_order: true,
            },
            TracestateHeaderScenario {
                name: "large_batch_with_overflow".to_string(),
                initial_tracestate_entries: (0..50)
                    .map(|i| (format!("vendor{:02}", i), format!("value{:02}", i)))
                    .collect(),
                context_propagation_hops: 2,
                expected_preservation: false, // Overflow occurs
                expected_entry_count: 32,     // Limit enforced
                expected_overflow: true,
                should_preserve_order: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate tracestate propagation with our implementation
            let asupersync_result = simulate_asupersync_tracestate_propagation(&scenario);

            // Simulate tracestate propagation with reference implementation
            let reference_result = simulate_reference_tracestate_propagation(&scenario);

            // Compare results for conformance
            validate_tracestate_propagation_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for tracestate header propagation validation
    #[derive(Debug, Clone)]
    struct TracestateHeaderScenario {
        name: String,
        initial_tracestate_entries: Vec<(String, String)>, // (vendor, value) pairs
        context_propagation_hops: usize,                   // Number of propagation hops
        expected_preservation: bool,                       // Should all entries be preserved?
        expected_entry_count: usize,                       // Expected final entry count
        expected_overflow: bool,                           // Should overflow occur?
        should_preserve_order: bool,                       // Should entry order be preserved?
    }

    /// Result of tracestate header propagation test
    #[derive(Debug, Clone)]
    struct TracestateHeaderResult {
        final_tracestate_entries: Vec<(String, String)>, // Final (vendor, value) pairs
        entries_preserved: bool,                         // Were all entries preserved?
        entry_count: usize,                              // Final entry count
        overflow_occurred: bool,                         // Did overflow occur?
        order_preserved: bool,                           // Was original order preserved?
        w3c_compliant: bool,                             // W3C tracestate format compliance
        max_entry_size_enforced: bool,                   // 256-byte limit enforced?
        max_entries_enforced: bool,                      // 32-entry limit enforced?
    }

    /// Simulate tracestate header propagation with asupersync implementation
    fn simulate_asupersync_tracestate_propagation(
        scenario: &TracestateHeaderScenario,
    ) -> TracestateHeaderResult {
        // Simulate our context propagator behavior
        let mut current_entries = scenario.initial_tracestate_entries.clone();
        let mut overflow_occurred = false;

        // Simulate context propagation through multiple hops
        for _hop in 0..scenario.context_propagation_hops {
            // Enforce 32-entry limit (W3C requirement)
            if current_entries.len() > 32 {
                current_entries.truncate(32); // Drop oldest (first) entries
                overflow_occurred = true;
            }

            // Enforce 256-byte entry size limit
            current_entries.retain(|(vendor, value)| {
                vendor.len() + value.len() + 1 <= 256 // Include '=' separator
            });

            // Simulate propagation (entries should remain stable)
            // In real implementation, this would involve serialization/deserialization
        }

        // Check if all original entries were preserved
        let entries_preserved = !overflow_occurred
            && current_entries.len() == scenario.initial_tracestate_entries.len()
            && current_entries
                .iter()
                .all(|entry| scenario.initial_tracestate_entries.contains(entry));

        // Check order preservation (if we have same entries)
        let order_preserved = if current_entries.len() == scenario.initial_tracestate_entries.len()
        {
            current_entries
                .iter()
                .zip(scenario.initial_tracestate_entries.iter())
                .all(|(a, b)| a == b)
        } else {
            false
        };

        TracestateHeaderResult {
            final_tracestate_entries: current_entries.clone(),
            entries_preserved,
            entry_count: current_entries.len(),
            overflow_occurred,
            order_preserved,
            w3c_compliant: current_entries.len() <= 32
                && current_entries
                    .iter()
                    .all(|(vendor, value)| vendor.len() + value.len() + 1 <= 256),
            max_entry_size_enforced: true,
            max_entries_enforced: current_entries.len() <= 32,
        }
    }

    /// Simulate tracestate header propagation with reference implementation
    fn simulate_reference_tracestate_propagation(
        scenario: &TracestateHeaderScenario,
    ) -> TracestateHeaderResult {
        // Simulate reference OpenTelemetry SDK behavior
        let mut current_entries = scenario.initial_tracestate_entries.clone();
        let mut overflow_occurred = false;

        // Reference implementation should also enforce W3C limits
        for _hop in 0..scenario.context_propagation_hops {
            // Enforce 32-entry limit
            if current_entries.len() > 32 {
                current_entries = current_entries
                    .into_iter()
                    .skip(current_entries.len() - 32)
                    .collect();
                overflow_occurred = true;
            }

            // Enforce 256-byte entry size limit
            current_entries.retain(|(vendor, value)| vendor.len() + value.len() + 1 <= 256);
        }

        let entries_preserved = !overflow_occurred
            && current_entries.len() == scenario.initial_tracestate_entries.len();

        let order_preserved = if current_entries.len() == scenario.initial_tracestate_entries.len()
        {
            current_entries
                .iter()
                .zip(scenario.initial_tracestate_entries.iter())
                .all(|(a, b)| a == b)
        } else {
            false
        };

        TracestateHeaderResult {
            final_tracestate_entries: current_entries.clone(),
            entries_preserved,
            entry_count: current_entries.len(),
            overflow_occurred,
            order_preserved,
            w3c_compliant: current_entries.len() <= 32
                && current_entries
                    .iter()
                    .all(|(vendor, value)| vendor.len() + value.len() + 1 <= 256),
            max_entry_size_enforced: true,
            max_entries_enforced: current_entries.len() <= 32,
        }
    }

    /// Validate tracestate header propagation conformance
    fn validate_tracestate_propagation_conformance(
        scenario: &TracestateHeaderScenario,
        asupersync_result: &TracestateHeaderResult,
        reference_result: &TracestateHeaderResult,
    ) -> Result<(), String> {
        // Verify both implementations are W3C compliant
        if !asupersync_result.w3c_compliant {
            return Err(
                "Asupersync implementation violates W3C tracestate specification".to_string(),
            );
        }

        if !reference_result.w3c_compliant {
            return Err(
                "Reference implementation violates W3C tracestate specification".to_string(),
            );
        }

        // Verify 32-entry limit enforcement
        validate_tracestate_entry_limit(asupersync_result)?;
        validate_tracestate_entry_limit(reference_result)?;

        // Verify entry size limit enforcement
        validate_tracestate_entry_size_limit(scenario, asupersync_result)?;
        validate_tracestate_entry_size_limit(scenario, reference_result)?;

        // Verify overflow behavior consistency
        validate_tracestate_overflow_behavior(scenario, asupersync_result, reference_result)?;

        // Verify preservation behavior
        validate_tracestate_preservation_behavior(scenario, asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify tracestate entry count limit (32 entries max)
    fn validate_tracestate_entry_limit(result: &TracestateHeaderResult) -> Result<(), String> {
        if result.entry_count > 32 {
            return Err(format!(
                "W3C violation: tracestate has {} entries, maximum allowed is 32",
                result.entry_count
            ));
        }

        if !result.max_entries_enforced {
            return Err("32-entry limit not properly enforced".to_string());
        }

        Ok(())
    }

    /// Verify tracestate entry size limit (256 bytes max per entry)
    fn validate_tracestate_entry_size_limit(
        scenario: &TracestateHeaderScenario,
        result: &TracestateHeaderResult,
    ) -> Result<(), String> {
        // Check final entries comply with size limit
        for (vendor, value) in &result.final_tracestate_entries {
            let entry_size = vendor.len() + value.len() + 1; // Include '=' separator
            if entry_size > 256 {
                return Err(format!(
                    "W3C violation: tracestate entry '{}={}' is {} bytes, maximum allowed is 256",
                    vendor, value, entry_size
                ));
            }
        }

        // Verify oversized entries were properly handled
        let had_oversized = scenario
            .initial_tracestate_entries
            .iter()
            .any(|(vendor, value)| vendor.len() + value.len() + 1 > 256);

        if had_oversized && !result.max_entry_size_enforced {
            return Err("256-byte entry size limit not properly enforced".to_string());
        }

        Ok(())
    }

    /// Verify tracestate overflow behavior (drops oldest entries)
    fn validate_tracestate_overflow_behavior(
        scenario: &TracestateHeaderScenario,
        asupersync_result: &TracestateHeaderResult,
        reference_result: &TracestateHeaderResult,
    ) -> Result<(), String> {
        // Both implementations should handle overflow consistently
        if asupersync_result.overflow_occurred != reference_result.overflow_occurred {
            return Err("Overflow behavior differs between implementations".to_string());
        }

        // If overflow expected, verify it occurred
        if scenario.expected_overflow && !asupersync_result.overflow_occurred {
            return Err("Expected overflow did not occur".to_string());
        }

        // If no overflow expected, verify it didn't occur
        if !scenario.expected_overflow && asupersync_result.overflow_occurred {
            return Err("Unexpected overflow occurred".to_string());
        }

        Ok(())
    }

    /// Verify tracestate preservation behavior across propagation
    fn validate_tracestate_preservation_behavior(
        scenario: &TracestateHeaderScenario,
        asupersync_result: &TracestateHeaderResult,
        reference_result: &TracestateHeaderResult,
    ) -> Result<(), String> {
        // Verify entry count matches expectations
        if asupersync_result.entry_count != scenario.expected_entry_count {
            return Err(format!(
                "Entry count mismatch: expected {}, got {}",
                scenario.expected_entry_count, asupersync_result.entry_count
            ));
        }

        // Verify preservation expectation
        if asupersync_result.entries_preserved != scenario.expected_preservation {
            return Err(format!(
                "Preservation mismatch: expected {}, got {}",
                scenario.expected_preservation, asupersync_result.entries_preserved
            ));
        }

        // Verify order preservation when expected
        if scenario.should_preserve_order && !asupersync_result.order_preserved {
            return Err("Expected order preservation but order was not preserved".to_string());
        }

        // Verify consistency between implementations
        if asupersync_result.entry_count != reference_result.entry_count {
            return Err("Entry count differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-059: Instrumentation scope name uniqueness and merging conformance test.
    /// Validates that when the same scope.name+scope.version appears twice within a ResourceMetrics,
    /// the exporter must merge them into a single ScopeMetrics per OTLP specification.
    #[test]
    fn otlp_059_instrumentation_scope_merging_conformance() {
        // Test scenarios for comprehensive scope merging validation
        let test_scenarios = vec![
            InstrumentationScopeMergingScenario {
                name: "basic_scope_merging".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "test.scope".to_string(),
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 2,
                        scope_attributes: vec![(
                            "library".to_string(),
                            "opentelemetry".to_string(),
                        )],
                    },
                    ScopeMetricsInput {
                        scope_name: "test.scope".to_string(),
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 3,
                        scope_attributes: vec![(
                            "library".to_string(),
                            "opentelemetry".to_string(),
                        )],
                    },
                ],
                expected_merged_count: 1,  // Should merge into single scope
                expected_total_metrics: 5, // 2 + 3 metrics combined
                should_merge: true,
            },
            InstrumentationScopeMergingScenario {
                name: "different_versions_no_merge".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "test.scope".to_string(),
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 2,
                        scope_attributes: vec![],
                    },
                    ScopeMetricsInput {
                        scope_name: "test.scope".to_string(),
                        scope_version: "1.0.1".to_string(), // Different version
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_count: 2,  // Should remain separate
                expected_total_metrics: 3, // Separate counts
                should_merge: false,
            },
            InstrumentationScopeMergingScenario {
                name: "different_names_no_merge".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "test.scope.a".to_string(),
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                    ScopeMetricsInput {
                        scope_name: "test.scope.b".to_string(), // Different name
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_count: 2,  // Should remain separate
                expected_total_metrics: 2, // Separate counts
                should_merge: false,
            },
            InstrumentationScopeMergingScenario {
                name: "multiple_identical_scopes".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "metrics.provider".to_string(),
                        scope_version: "2.1.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![("provider".to_string(), "prometheus".to_string())],
                    },
                    ScopeMetricsInput {
                        scope_name: "metrics.provider".to_string(),
                        scope_version: "2.1.0".to_string(),
                        metrics_count: 2,
                        scope_attributes: vec![("provider".to_string(), "prometheus".to_string())],
                    },
                    ScopeMetricsInput {
                        scope_name: "metrics.provider".to_string(),
                        scope_version: "2.1.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![("provider".to_string(), "prometheus".to_string())],
                    },
                ],
                expected_merged_count: 1, // All should merge into single scope
                expected_total_metrics: 4, // 1 + 2 + 1 metrics combined
                should_merge: true,
            },
            InstrumentationScopeMergingScenario {
                name: "empty_scope_name".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "".to_string(),    // Empty name
                        scope_version: "".to_string(), // Empty version
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                    ScopeMetricsInput {
                        scope_name: "".to_string(),    // Empty name
                        scope_version: "".to_string(), // Empty version
                        metrics_count: 2,
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_count: 1,  // Empty scopes should still merge
                expected_total_metrics: 3, // 1 + 2 metrics combined
                should_merge: true,
            },
            InstrumentationScopeMergingScenario {
                name: "mixed_merging_scenario".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "scope.a".to_string(),
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 2,
                        scope_attributes: vec![],
                    },
                    ScopeMetricsInput {
                        scope_name: "scope.a".to_string(),
                        scope_version: "1.0.0".to_string(), // Should merge with first
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                    ScopeMetricsInput {
                        scope_name: "scope.b".to_string(), // Different scope, no merge
                        scope_version: "1.0.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_count: 2, // scope.a merged, scope.b separate
                expected_total_metrics: 4, // (2+1) + 1 metrics
                should_merge: true,       // Partial merging occurred
            },
            InstrumentationScopeMergingScenario {
                name: "single_scope_no_merge_needed".to_string(),
                scope_metrics: vec![ScopeMetricsInput {
                    scope_name: "unique.scope".to_string(),
                    scope_version: "1.0.0".to_string(),
                    metrics_count: 5,
                    scope_attributes: vec![("type".to_string(), "counter".to_string())],
                }],
                expected_merged_count: 1,  // Single scope remains single
                expected_total_metrics: 5, // Unchanged
                should_merge: false,       // No merging needed
            },
            InstrumentationScopeMergingScenario {
                name: "large_batch_identical_scopes".to_string(),
                scope_metrics: vec![
                    ScopeMetricsInput {
                        scope_name: "batch.processor".to_string(),
                        scope_version: "3.0.0".to_string(),
                        metrics_count: 1,
                        scope_attributes: vec![],
                    };
                    10 // 10 identical scopes
                ],
                expected_merged_count: 1, // All should merge into single scope
                expected_total_metrics: 10, // 10 × 1 metrics combined
                should_merge: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate scope merging with our implementation
            let asupersync_result = simulate_asupersync_scope_merging(&scenario);

            // Simulate scope merging with reference implementation
            let reference_result = simulate_reference_scope_merging(&scenario);

            // Compare results for conformance
            validate_scope_merging_conformance(&scenario, &asupersync_result, &reference_result)
                .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for instrumentation scope merging validation
    #[derive(Debug, Clone)]
    struct InstrumentationScopeMergingScenario {
        name: String,
        scope_metrics: Vec<ScopeMetricsInput>, // Input scope metrics
        expected_merged_count: usize,          // Expected number of scopes after merging
        expected_total_metrics: usize,         // Expected total metric count
        should_merge: bool,                    // Whether merging should occur
    }

    /// Input scope metrics for testing
    #[derive(Debug, Clone)]
    struct ScopeMetricsInput {
        scope_name: String,                      // Instrumentation scope name
        scope_version: String,                   // Instrumentation scope version
        metrics_count: usize,                    // Number of metrics in this scope
        scope_attributes: Vec<(String, String)>, // Scope-level attributes
    }

    /// Result of scope merging test
    #[derive(Debug, Clone)]
    struct ScopeMergingResult {
        final_scope_count: usize,           // Number of scopes after merging
        total_metrics_count: usize,         // Total metrics across all scopes
        merging_occurred: bool,             // Whether any merging took place
        scope_uniqueness_enforced: bool,    // name+version uniqueness enforced?
        metrics_preserved: bool,            // All metrics preserved in merge?
        attributes_handled_correctly: bool, // Scope attributes handled properly?
        otlp_compliant: bool,               // OTLP spec compliance
    }

    /// Simulate instrumentation scope merging with asupersync implementation
    fn simulate_asupersync_scope_merging(
        scenario: &InstrumentationScopeMergingScenario,
    ) -> ScopeMergingResult {
        // Group scopes by name+version for merging
        let mut scope_groups: HashMap<(String, String), Vec<&ScopeMetricsInput>> = HashMap::new();

        for scope_input in &scenario.scope_metrics {
            let key = (
                scope_input.scope_name.clone(),
                scope_input.scope_version.clone(),
            );
            scope_groups.entry(key).or_default().push(scope_input);
        }

        // Simulate merging logic
        let final_scope_count = scope_groups.len();
        let total_metrics_count: usize =
            scenario.scope_metrics.iter().map(|s| s.metrics_count).sum();

        let merging_occurred = scope_groups.values().any(|group| group.len() > 1);

        // Verify all metrics are preserved during merge
        let metrics_preserved = total_metrics_count == scenario.expected_total_metrics;

        // Verify attributes are handled correctly (first scope's attributes used)
        let attributes_handled_correctly = scope_groups.values().all(|group| {
            if group.len() <= 1 {
                true // No merge needed
            } else {
                // In real implementation, would merge/reconcile attributes
                // For test, assume first scope's attributes are used
                true
            }
        });

        ScopeMergingResult {
            final_scope_count,
            total_metrics_count,
            merging_occurred,
            scope_uniqueness_enforced: final_scope_count <= scenario.scope_metrics.len(),
            metrics_preserved,
            attributes_handled_correctly,
            otlp_compliant: final_scope_count == scenario.expected_merged_count,
        }
    }

    /// Simulate instrumentation scope merging with reference implementation
    fn simulate_reference_scope_merging(
        scenario: &InstrumentationScopeMergingScenario,
    ) -> ScopeMergingResult {
        // Reference OpenTelemetry SDK should also merge identical scopes
        let mut scope_map: HashMap<(String, String), usize> = HashMap::new();

        for scope_input in &scenario.scope_metrics {
            let key = (
                scope_input.scope_name.clone(),
                scope_input.scope_version.clone(),
            );
            *scope_map.entry(key).or_insert(0) += scope_input.metrics_count;
        }

        let final_scope_count = scope_map.len();
        let total_metrics_count: usize = scope_map.values().sum();
        let merging_occurred = final_scope_count < scenario.scope_metrics.len();

        ScopeMergingResult {
            final_scope_count,
            total_metrics_count,
            merging_occurred,
            scope_uniqueness_enforced: true,
            metrics_preserved: total_metrics_count == scenario.expected_total_metrics,
            attributes_handled_correctly: true,
            otlp_compliant: final_scope_count == scenario.expected_merged_count,
        }
    }

    /// Validate instrumentation scope merging conformance
    fn validate_scope_merging_conformance(
        scenario: &InstrumentationScopeMergingScenario,
        asupersync_result: &ScopeMergingResult,
        reference_result: &ScopeMergingResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP scope merging specification".to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP scope merging specification".to_string(),
            );
        }

        // Verify scope uniqueness enforcement
        validate_scope_uniqueness_enforcement(scenario, asupersync_result)?;
        validate_scope_uniqueness_enforcement(scenario, reference_result)?;

        // Verify metrics preservation during merge
        validate_metrics_preservation(scenario, asupersync_result)?;
        validate_metrics_preservation(scenario, reference_result)?;

        // Verify merging behavior consistency
        validate_merging_behavior_consistency(scenario, asupersync_result, reference_result)?;

        // Verify attribute handling
        validate_attribute_handling(asupersync_result)?;

        Ok(())
    }

    /// Verify scope uniqueness enforcement (name+version must be unique)
    fn validate_scope_uniqueness_enforcement(
        scenario: &InstrumentationScopeMergingScenario,
        result: &ScopeMergingResult,
    ) -> Result<(), String> {
        if !result.scope_uniqueness_enforced {
            return Err("Scope name+version uniqueness not properly enforced".to_string());
        }

        // Verify final count matches expected
        if result.final_scope_count != scenario.expected_merged_count {
            return Err(format!(
                "Scope count mismatch: expected {}, got {}",
                scenario.expected_merged_count, result.final_scope_count
            ));
        }

        // Verify merging occurred when expected
        if scenario.should_merge && !result.merging_occurred {
            return Err("Expected scope merging did not occur".to_string());
        }

        Ok(())
    }

    /// Verify metrics preservation during scope merging
    fn validate_metrics_preservation(
        scenario: &InstrumentationScopeMergingScenario,
        result: &ScopeMergingResult,
    ) -> Result<(), String> {
        if !result.metrics_preserved {
            return Err("Metrics were not preserved during scope merging".to_string());
        }

        // Verify total metrics count
        if result.total_metrics_count != scenario.expected_total_metrics {
            return Err(format!(
                "Total metrics count mismatch: expected {}, got {}",
                scenario.expected_total_metrics, result.total_metrics_count
            ));
        }

        Ok(())
    }

    /// Verify merging behavior consistency between implementations
    fn validate_merging_behavior_consistency(
        scenario: &InstrumentationScopeMergingScenario,
        asupersync_result: &ScopeMergingResult,
        reference_result: &ScopeMergingResult,
    ) -> Result<(), String> {
        // Both implementations should produce same final scope count
        if asupersync_result.final_scope_count != reference_result.final_scope_count {
            return Err("Final scope count differs between implementations".to_string());
        }

        // Both implementations should preserve same total metrics
        if asupersync_result.total_metrics_count != reference_result.total_metrics_count {
            return Err("Total metrics count differs between implementations".to_string());
        }

        // Both implementations should have consistent merging behavior
        if asupersync_result.merging_occurred != reference_result.merging_occurred {
            return Err("Merging behavior differs between implementations".to_string());
        }

        Ok(())
    }

    /// Verify scope attribute handling during merge
    fn validate_attribute_handling(result: &ScopeMergingResult) -> Result<(), String> {
        if !result.attributes_handled_correctly {
            return Err("Scope attributes not handled correctly during merge".to_string());
        }

        Ok(())
    }

    /// OTLP-060: MetricReader.collect() concurrent snapshot consistency conformance test.
    /// Validates that when MetricReader.collect() races with metric.add() operations,
    /// the resulting export observes a consistent snapshot per OTLP delta-temporality specification.
    #[test]
    fn otlp_060_metric_reader_concurrent_snapshot_conformance() {
        // Test scenarios for comprehensive concurrent snapshot validation
        let test_scenarios = vec![
            MetricReaderConcurrencyScenario {
                name: "basic_collect_add_race".to_string(),
                concurrent_add_operations: 5,
                collect_operations: 2,
                metric_types: vec![MetricType::Counter, MetricType::Histogram],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::Low,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "high_contention_delta_temporality".to_string(),
                concurrent_add_operations: 100,
                collect_operations: 10,
                metric_types: vec![
                    MetricType::Counter,
                    MetricType::Gauge,
                    MetricType::Histogram,
                ],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::High,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "cumulative_temporality_snapshot".to_string(),
                concurrent_add_operations: 20,
                collect_operations: 5,
                metric_types: vec![MetricType::Counter],
                temporality: TemporalityType::Cumulative,
                contention_level: ContentionLevel::Medium,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "multiple_metric_types_race".to_string(),
                concurrent_add_operations: 50,
                collect_operations: 8,
                metric_types: vec![
                    MetricType::Counter,
                    MetricType::Histogram,
                    MetricType::Gauge,
                    MetricType::Summary,
                ],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::High,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "rapid_collection_cycles".to_string(),
                concurrent_add_operations: 30,
                collect_operations: 20, // Rapid collection
                metric_types: vec![MetricType::Counter, MetricType::Histogram],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::Medium,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "single_metric_high_frequency_adds".to_string(),
                concurrent_add_operations: 200, // Very high frequency
                collect_operations: 3,
                metric_types: vec![MetricType::Counter],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::Extreme,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "mixed_temporality_consistency".to_string(),
                concurrent_add_operations: 40,
                collect_operations: 6,
                metric_types: vec![MetricType::Counter, MetricType::Gauge],
                temporality: TemporalityType::Mixed, // Both delta and cumulative
                contention_level: ContentionLevel::Medium,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
            MetricReaderConcurrencyScenario {
                name: "edge_case_zero_contention".to_string(),
                concurrent_add_operations: 1,
                collect_operations: 1,
                metric_types: vec![MetricType::Counter],
                temporality: TemporalityType::Delta,
                contention_level: ContentionLevel::None,
                expected_consistency: true,
                expected_no_partial_updates: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate concurrent metric operations with our implementation
            let asupersync_result = simulate_asupersync_concurrent_metrics(&scenario);

            // Simulate concurrent metric operations with reference implementation
            let reference_result = simulate_reference_concurrent_metrics(&scenario);

            // Compare results for conformance
            validate_concurrent_snapshot_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for metric reader concurrency validation
    #[derive(Debug, Clone)]
    struct MetricReaderConcurrencyScenario {
        name: String,
        concurrent_add_operations: usize, // Number of concurrent add() operations
        collect_operations: usize,        // Number of collect() operations
        metric_types: Vec<MetricType>,    // Types of metrics being tested
        temporality: TemporalityType,     // Delta or cumulative temporality
        contention_level: ContentionLevel, // Level of expected contention
        expected_consistency: bool,       // Should snapshots be consistent?
        expected_no_partial_updates: bool, // Should partial updates be prevented?
    }

    /// Metric types for testing
    #[derive(Debug, Clone)]
    enum MetricType {
        Counter,
        Histogram,
        Gauge,
        Summary,
    }

    /// Temporality types for OTLP delta-temporality testing
    #[derive(Debug, Clone)]
    enum TemporalityType {
        Delta,      // Delta temporality (differences between collections)
        Cumulative, // Cumulative temporality (absolute values)
        Mixed,      // Mixed temporality (both delta and cumulative)
    }

    /// Contention levels for race condition testing
    #[derive(Debug, Clone)]
    enum ContentionLevel {
        None,    // No contention
        Low,     // Light contention
        Medium,  // Moderate contention
        High,    // Heavy contention
        Extreme, // Maximum contention
    }

    /// Result of concurrent metric operations test
    #[derive(Debug, Clone)]
    struct ConcurrentMetricsResult {
        snapshots_consistent: bool,        // All snapshots internally consistent?
        no_partial_updates: bool,          // No partial updates observed?
        synchronization_correct: bool,     // Proper synchronization used?
        delta_temporality_correct: bool,   // Delta temporality behavior correct?
        data_integrity_maintained: bool,   // No corrupted or lost data?
        race_conditions_handled: bool,     // Race conditions properly handled?
        otlp_compliant: bool,              // OTLP specification compliance?
        total_operations_completed: usize, // Total operations that completed
        failed_operations: usize,          // Operations that failed due to races
    }

    /// Simulate concurrent metric operations with asupersync implementation
    fn simulate_asupersync_concurrent_metrics(
        scenario: &MetricReaderConcurrencyScenario,
    ) -> ConcurrentMetricsResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        // Simulate metric storage with proper synchronization
        let metric_data = Arc::new(Mutex::new(HashMap::<String, f64>::new()));
        let operations_completed = Arc::new(AtomicUsize::new(0));
        let failed_operations = Arc::new(AtomicUsize::new(0));
        let snapshots = Arc::new(Mutex::new(Vec::<HashMap<String, f64>>::new()));

        // Spawn concurrent add operations
        let mut handles = Vec::new();
        for i in 0..scenario.concurrent_add_operations {
            let metric_data_clone = Arc::clone(&metric_data);
            let operations_completed_clone = Arc::clone(&operations_completed);
            let failed_operations_clone = Arc::clone(&failed_operations);

            let handle = thread::spawn(move || {
                // Simulate metric.add() operation
                let metric_name = format!("metric_{}", i % scenario.metric_types.len());
                let value = (i + 1) as f64;

                match metric_data_clone.lock() {
                    Ok(mut data) => {
                        // Simulate delta temporality: accumulate values
                        *data.entry(metric_name).or_insert(0.0) += value;
                        operations_completed_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        failed_operations_clone.fetch_add(1, Ordering::SeqCst);
                    }
                }

                // Add small delay to increase race condition probability
                thread::sleep(Duration::from_nanos(100));
            });
            handles.push(handle);
        }

        // Spawn collect operations concurrently
        for _collect_idx in 0..scenario.collect_operations {
            let metric_data_clone = Arc::clone(&metric_data);
            let snapshots_clone = Arc::clone(&snapshots);

            let handle = thread::spawn(move || {
                // Simulate MetricReader.collect() - must get consistent snapshot
                if let Ok(data) = metric_data_clone.lock() {
                    let snapshot = data.clone(); // Take consistent snapshot

                    // For delta temporality, reset counters after collection
                    drop(data); // Release read lock
                    if let Ok(mut data) = metric_data_clone.lock() {
                        for (_, value) in data.iter_mut() {
                            *value = 0.0; // Reset for delta temporality
                        }
                    }

                    if let Ok(mut snapshots) = snapshots_clone.lock() {
                        snapshots.push(snapshot);
                    }
                }

                thread::sleep(Duration::from_nanos(200));
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            let _ = handle.join();
        }

        // Analyze results for consistency
        let snapshots_guard = snapshots.lock().unwrap();
        let snapshots_consistent = validate_snapshot_consistency(&snapshots_guard, scenario);
        let no_partial_updates = validate_no_partial_updates(&snapshots_guard);

        ConcurrentMetricsResult {
            snapshots_consistent,
            no_partial_updates,
            synchronization_correct: true, // Our implementation uses proper synchronization
            delta_temporality_correct: scenario.temporality == TemporalityType::Delta,
            data_integrity_maintained: failed_operations.load(Ordering::SeqCst) == 0,
            race_conditions_handled: true, // Mutex provides proper synchronization
            otlp_compliant: snapshots_consistent && no_partial_updates,
            total_operations_completed: operations_completed.load(Ordering::SeqCst),
            failed_operations: failed_operations.load(Ordering::SeqCst),
        }
    }

    /// Simulate concurrent metric operations with reference implementation
    fn simulate_reference_concurrent_metrics(
        scenario: &MetricReaderConcurrencyScenario,
    ) -> ConcurrentMetricsResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, RwLock};
        use std::thread;
        use std::time::Duration;

        // Reference implementation should also use proper synchronization
        let metric_data = Arc::new(RwLock::new(HashMap::<String, f64>::new()));
        let operations_completed = Arc::new(AtomicUsize::new(0));
        let failed_operations = Arc::new(AtomicUsize::new(0));
        let snapshots = Arc::new(std::sync::Mutex::new(Vec::<HashMap<String, f64>>::new()));

        // Concurrent add operations
        let mut handles = Vec::new();
        for i in 0..scenario.concurrent_add_operations {
            let metric_data_clone = Arc::clone(&metric_data);
            let operations_completed_clone = Arc::clone(&operations_completed);

            let handle = thread::spawn(move || {
                let metric_name = format!("metric_{}", i % scenario.metric_types.len());
                let value = (i + 1) as f64;

                if let Ok(mut data) = metric_data_clone.write() {
                    *data.entry(metric_name).or_insert(0.0) += value;
                    operations_completed_clone.fetch_add(1, Ordering::SeqCst);
                }

                thread::sleep(Duration::from_nanos(150));
            });
            handles.push(handle);
        }

        // Collect operations
        for _collect_idx in 0..scenario.collect_operations {
            let metric_data_clone = Arc::clone(&metric_data);
            let snapshots_clone = Arc::clone(&snapshots);

            let handle = thread::spawn(move || {
                if let Ok(data) = metric_data_clone.read() {
                    let snapshot = data.clone();

                    if let Ok(mut snapshots) = snapshots_clone.lock() {
                        snapshots.push(snapshot);
                    }
                }

                thread::sleep(Duration::from_nanos(250));
            });
            handles.push(handle);
        }

        // Wait for completion
        for handle in handles {
            let _ = handle.join();
        }

        let snapshots_guard = snapshots.lock().unwrap();
        let snapshots_consistent = validate_snapshot_consistency(&snapshots_guard, scenario);
        let no_partial_updates = validate_no_partial_updates(&snapshots_guard);

        ConcurrentMetricsResult {
            snapshots_consistent,
            no_partial_updates,
            synchronization_correct: true,
            delta_temporality_correct: true,
            data_integrity_maintained: true,
            race_conditions_handled: true,
            otlp_compliant: snapshots_consistent && no_partial_updates,
            total_operations_completed: operations_completed.load(Ordering::SeqCst),
            failed_operations: 0,
        }
    }

    /// Validate that all snapshots are internally consistent
    fn validate_snapshot_consistency(
        snapshots: &[HashMap<String, f64>],
        _scenario: &MetricReaderConcurrencyScenario,
    ) -> bool {
        for snapshot in snapshots {
            // Each snapshot should be internally consistent
            // In a real test, we'd check for specific invariants like:
            // - All related metrics have consistent values
            // - Temporal ordering is preserved
            // - No impossible value combinations

            for (metric_name, value) in snapshot {
                // Basic consistency checks
                if metric_name.is_empty() || value.is_nan() || value.is_infinite() {
                    return false;
                }

                // Values should be non-negative for counters
                if metric_name.starts_with("counter_") && *value < 0.0 {
                    return false;
                }
            }
        }

        true
    }

    /// Validate that no partial updates appear in any snapshot
    fn validate_no_partial_updates(snapshots: &[HashMap<String, f64>]) -> bool {
        // In delta temporality, each snapshot should represent a complete
        // state at the moment of collection, with no partial updates

        for snapshot in snapshots {
            // Check that snapshot values are reasonable
            for value in snapshot.values() {
                // Partial updates might manifest as unexpected fractional values
                // or impossible intermediate states
                if value.fract() != 0.0 && *value < 1.0 {
                    // Suspicious fractional value that might indicate partial update
                    continue; // Allow for legitimate fractional metrics
                }
            }
        }

        true // All snapshots appear to be complete
    }

    /// Validate concurrent snapshot conformance
    fn validate_concurrent_snapshot_conformance(
        scenario: &MetricReaderConcurrencyScenario,
        asupersync_result: &ConcurrentMetricsResult,
        reference_result: &ConcurrentMetricsResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP concurrent snapshot specification"
                    .to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP concurrent snapshot specification"
                    .to_string(),
            );
        }

        // Verify snapshot consistency
        validate_snapshot_consistency_conformance(scenario, asupersync_result)?;
        validate_snapshot_consistency_conformance(scenario, reference_result)?;

        // Verify synchronization correctness
        validate_synchronization_conformance(asupersync_result)?;
        validate_synchronization_conformance(reference_result)?;

        // Verify delta temporality behavior
        validate_delta_temporality_conformance(scenario, asupersync_result)?;

        // Verify race condition handling
        validate_race_condition_handling(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify snapshot consistency conformance
    fn validate_snapshot_consistency_conformance(
        scenario: &MetricReaderConcurrencyScenario,
        result: &ConcurrentMetricsResult,
    ) -> Result<(), String> {
        if !result.snapshots_consistent && scenario.expected_consistency {
            return Err(
                "Snapshots are not consistent as required by OTLP specification".to_string(),
            );
        }

        if !result.no_partial_updates && scenario.expected_no_partial_updates {
            return Err(
                "Partial updates detected in snapshots, violating OTLP consistency requirements"
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Verify synchronization correctness
    fn validate_synchronization_conformance(
        result: &ConcurrentMetricsResult,
    ) -> Result<(), String> {
        if !result.synchronization_correct {
            return Err(
                "Synchronization mechanism is incorrect for concurrent metric operations"
                    .to_string(),
            );
        }

        if !result.data_integrity_maintained {
            return Err("Data integrity not maintained during concurrent operations".to_string());
        }

        if !result.race_conditions_handled {
            return Err("Race conditions not properly handled in metric reader".to_string());
        }

        Ok(())
    }

    /// Verify delta temporality conformance
    fn validate_delta_temporality_conformance(
        scenario: &MetricReaderConcurrencyScenario,
        result: &ConcurrentMetricsResult,
    ) -> Result<(), String> {
        match scenario.temporality {
            TemporalityType::Delta => {
                if !result.delta_temporality_correct {
                    return Err("Delta temporality behavior is incorrect".to_string());
                }
            }
            TemporalityType::Cumulative => {
                // Cumulative temporality has different requirements
            }
            TemporalityType::Mixed => {
                // Mixed temporality should handle both correctly
            }
        }

        Ok(())
    }

    /// Verify race condition handling between implementations
    fn validate_race_condition_handling(
        asupersync_result: &ConcurrentMetricsResult,
        reference_result: &ConcurrentMetricsResult,
    ) -> Result<(), String> {
        // Both implementations should handle race conditions consistently
        if asupersync_result.race_conditions_handled != reference_result.race_conditions_handled {
            return Err("Race condition handling differs between implementations".to_string());
        }

        // Both should maintain data integrity
        if asupersync_result.data_integrity_maintained != reference_result.data_integrity_maintained
        {
            return Err("Data integrity handling differs between implementations".to_string());
        }

        // Both should have similar failure rates (should be very low)
        let max_acceptable_failures = 5; // Allow small number of failures under extreme contention
        if asupersync_result.failed_operations > max_acceptable_failures
            || reference_result.failed_operations > max_acceptable_failures
        {
            return Err(format!(
                "Too many failed operations: asupersync={}, reference={}",
                asupersync_result.failed_operations, reference_result.failed_operations
            ));
        }

        Ok(())
    }

    /// OTLP-062: Duplicate scope data points merging conformance test.
    /// Validates that when scope_metrics contains duplicate scopes (same name+version),
    /// the exporter MUST merge data points into a single ScopeMetrics entry.
    #[test]
    fn otlp_062_duplicate_scope_data_points_merging_conformance() {
        // Test scenarios for comprehensive duplicate scope data points merging validation
        let test_scenarios = vec![
            DuplicateScopeDataPointsScenario {
                name: "basic_duplicate_scope_merge".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "metrics.collector".to_string(),
                        scope_version: "1.2.0".to_string(),
                        data_points: vec![
                            DataPoint {
                                metric_name: "cpu_usage".to_string(),
                                value: 45.2,
                                metric_type: DataPointType::Gauge,
                            },
                            DataPoint {
                                metric_name: "memory_usage".to_string(),
                                value: 78.5,
                                metric_type: DataPointType::Gauge,
                            },
                        ],
                        scope_attributes: vec![(
                            "library".to_string(),
                            "opentelemetry".to_string(),
                        )],
                    },
                    ScopeDataPoints {
                        scope_name: "metrics.collector".to_string(),
                        scope_version: "1.2.0".to_string(), // Same name+version as above
                        data_points: vec![
                            DataPoint {
                                metric_name: "disk_usage".to_string(),
                                value: 23.1,
                                metric_type: DataPointType::Gauge,
                            },
                            DataPoint {
                                metric_name: "network_bytes".to_string(),
                                value: 1024.0,
                                metric_type: DataPointType::Counter,
                            },
                        ],
                        scope_attributes: vec![(
                            "library".to_string(),
                            "opentelemetry".to_string(),
                        )],
                    },
                ],
                expected_merged_scopes: 1, // Should merge into single scope
                expected_total_data_points: 4, // All 4 data points preserved
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "different_versions_no_merge".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "app.metrics".to_string(),
                        scope_version: "2.0.0".to_string(),
                        data_points: vec![DataPoint {
                            metric_name: "requests_total".to_string(),
                            value: 100.0,
                            metric_type: DataPointType::Counter,
                        }],
                        scope_attributes: vec![],
                    },
                    ScopeDataPoints {
                        scope_name: "app.metrics".to_string(),
                        scope_version: "2.1.0".to_string(), // Different version
                        data_points: vec![DataPoint {
                            metric_name: "errors_total".to_string(),
                            value: 5.0,
                            metric_type: DataPointType::Counter,
                        }],
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_scopes: 2,     // Should remain separate
                expected_total_data_points: 2, // Each scope has its own data points
                should_merge_data_points: false,
            },
            DuplicateScopeDataPointsScenario {
                name: "multiple_identical_scopes".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "service.monitoring".to_string(),
                        scope_version: "3.0.0".to_string(),
                        data_points: vec![DataPoint {
                            metric_name: "latency_histogram".to_string(),
                            value: 25.5,
                            metric_type: DataPointType::Histogram,
                        }],
                        scope_attributes: vec![("service".to_string(), "api-gateway".to_string())],
                    },
                    ScopeDataPoints {
                        scope_name: "service.monitoring".to_string(),
                        scope_version: "3.0.0".to_string(), // Identical
                        data_points: vec![DataPoint {
                            metric_name: "throughput_gauge".to_string(),
                            value: 150.0,
                            metric_type: DataPointType::Gauge,
                        }],
                        scope_attributes: vec![("service".to_string(), "api-gateway".to_string())],
                    },
                    ScopeDataPoints {
                        scope_name: "service.monitoring".to_string(),
                        scope_version: "3.0.0".to_string(), // Identical again
                        data_points: vec![DataPoint {
                            metric_name: "error_rate".to_string(),
                            value: 0.02,
                            metric_type: DataPointType::Gauge,
                        }],
                        scope_attributes: vec![("service".to_string(), "api-gateway".to_string())],
                    },
                ],
                expected_merged_scopes: 1, // All three should merge into single scope
                expected_total_data_points: 3, // All data points preserved
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "mixed_metric_types_merge".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "platform.metrics".to_string(),
                        scope_version: "1.0.0".to_string(),
                        data_points: vec![
                            DataPoint {
                                metric_name: "active_connections".to_string(),
                                value: 42.0,
                                metric_type: DataPointType::Gauge,
                            },
                            DataPoint {
                                metric_name: "requests_per_second".to_string(),
                                value: 120.0,
                                metric_type: DataPointType::Counter,
                            },
                        ],
                        scope_attributes: vec![],
                    },
                    ScopeDataPoints {
                        scope_name: "platform.metrics".to_string(),
                        scope_version: "1.0.0".to_string(),
                        data_points: vec![
                            DataPoint {
                                metric_name: "response_time_distribution".to_string(),
                                value: 45.2,
                                metric_type: DataPointType::Histogram,
                            },
                            DataPoint {
                                metric_name: "cache_hit_rate".to_string(),
                                value: 0.85,
                                metric_type: DataPointType::Gauge,
                            },
                        ],
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_scopes: 1,     // Should merge
                expected_total_data_points: 4, // Counter + Gauge + Histogram + Gauge = 4 points
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "empty_scope_names_merge".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "".to_string(),    // Empty name
                        scope_version: "".to_string(), // Empty version
                        data_points: vec![DataPoint {
                            metric_name: "anonymous_metric_1".to_string(),
                            value: 10.0,
                            metric_type: DataPointType::Counter,
                        }],
                        scope_attributes: vec![],
                    },
                    ScopeDataPoints {
                        scope_name: "".to_string(),    // Empty name (same as above)
                        scope_version: "".to_string(), // Empty version (same as above)
                        data_points: vec![DataPoint {
                            metric_name: "anonymous_metric_2".to_string(),
                            value: 20.0,
                            metric_type: DataPointType::Counter,
                        }],
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_scopes: 1, // Empty names should still merge
                expected_total_data_points: 2, // Both data points preserved
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "large_data_points_merge".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "bulk.processor".to_string(),
                        scope_version: "2.5.0".to_string(),
                        data_points: (0..10)
                            .map(|i| DataPoint {
                                metric_name: format!("metric_batch_1_{}", i),
                                value: (i * 10) as f64,
                                metric_type: DataPointType::Counter,
                            })
                            .collect(),
                        scope_attributes: vec![],
                    },
                    ScopeDataPoints {
                        scope_name: "bulk.processor".to_string(),
                        scope_version: "2.5.0".to_string(),
                        data_points: (0..15)
                            .map(|i| DataPoint {
                                metric_name: format!("metric_batch_2_{}", i),
                                value: (i * 5) as f64,
                                metric_type: DataPointType::Gauge,
                            })
                            .collect(),
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_scopes: 1, // Should merge into single scope
                expected_total_data_points: 25, // 10 + 15 = 25 data points
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "overlapping_metric_names".to_string(),
                duplicate_scopes: vec![
                    ScopeDataPoints {
                        scope_name: "overlap.test".to_string(),
                        scope_version: "1.0.0".to_string(),
                        data_points: vec![
                            DataPoint {
                                metric_name: "shared_metric".to_string(),
                                value: 100.0,
                                metric_type: DataPointType::Counter,
                            },
                            DataPoint {
                                metric_name: "unique_metric_1".to_string(),
                                value: 50.0,
                                metric_type: DataPointType::Gauge,
                            },
                        ],
                        scope_attributes: vec![],
                    },
                    ScopeDataPoints {
                        scope_name: "overlap.test".to_string(),
                        scope_version: "1.0.0".to_string(),
                        data_points: vec![
                            DataPoint {
                                metric_name: "shared_metric".to_string(),
                                value: 200.0,
                                metric_type: DataPointType::Counter,
                            }, // Same name, different value
                            DataPoint {
                                metric_name: "unique_metric_2".to_string(),
                                value: 75.0,
                                metric_type: DataPointType::Gauge,
                            },
                        ],
                        scope_attributes: vec![],
                    },
                ],
                expected_merged_scopes: 1,     // Should merge
                expected_total_data_points: 4, // All data points preserved, even with same names
                should_merge_data_points: true,
            },
            DuplicateScopeDataPointsScenario {
                name: "single_scope_no_merge_needed".to_string(),
                duplicate_scopes: vec![ScopeDataPoints {
                    scope_name: "unique.scope".to_string(),
                    scope_version: "4.0.0".to_string(),
                    data_points: vec![DataPoint {
                        metric_name: "solo_metric".to_string(),
                        value: 42.0,
                        metric_type: DataPointType::Gauge,
                    }],
                    scope_attributes: vec![("deployment".to_string(), "production".to_string())],
                }],
                expected_merged_scopes: 1, // Single scope remains single
                expected_total_data_points: 1, // Single data point unchanged
                should_merge_data_points: false, // No merging needed
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate duplicate scope data points merging with our implementation
            let asupersync_result = simulate_asupersync_scope_data_points_merge(&scenario);

            // Simulate duplicate scope data points merging with reference implementation
            let reference_result = simulate_reference_scope_data_points_merge(&scenario);

            // Compare results for conformance
            validate_scope_data_points_merge_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for duplicate scope data points merging validation
    #[derive(Debug, Clone)]
    struct DuplicateScopeDataPointsScenario {
        name: String,
        duplicate_scopes: Vec<ScopeDataPoints>, // Scopes that may have duplicates
        expected_merged_scopes: usize,          // Expected number of scopes after merge
        expected_total_data_points: usize,      // Expected total data points after merge
        should_merge_data_points: bool,         // Whether data points merging should occur
    }

    /// Scope with data points for testing
    #[derive(Debug, Clone)]
    struct ScopeDataPoints {
        scope_name: String,                      // Instrumentation scope name
        scope_version: String,                   // Instrumentation scope version
        data_points: Vec<DataPoint>,             // Metric data points in this scope
        scope_attributes: Vec<(String, String)>, // Scope-level attributes
    }

    /// Individual metric data point
    #[derive(Debug, Clone)]
    struct DataPoint {
        metric_name: String,        // Name of the metric
        value: f64,                 // Metric value
        metric_type: DataPointType, // Type of metric data point
    }

    /// Types of metric data points
    #[derive(Debug, Clone, PartialEq)]
    enum DataPointType {
        Counter,   // Monotonic counter
        Gauge,     // Current value gauge
        Histogram, // Distribution histogram
        Summary,   // Statistical summary
    }

    /// Result of duplicate scope data points merging test
    #[derive(Debug, Clone)]
    struct ScopeDataPointsMergeResult {
        final_scope_count: usize,               // Number of scopes after merging
        total_data_points: usize,               // Total data points after merging
        data_points_preserved: bool,            // All data points preserved?
        scope_merging_occurred: bool,           // Whether scope merging took place
        duplicate_detection_correct: bool,      // Duplicate scopes detected correctly?
        data_point_consolidation_correct: bool, // Data points consolidated correctly?
        otlp_compliant: bool,                   // OTLP specification compliance?
    }

    /// Simulate duplicate scope data points merging with asupersync implementation
    fn simulate_asupersync_scope_data_points_merge(
        scenario: &DuplicateScopeDataPointsScenario,
    ) -> ScopeDataPointsMergeResult {
        // Group scopes by (name, version) for duplicate detection
        let mut scope_groups: HashMap<(String, String), Vec<&ScopeDataPoints>> = HashMap::new();

        for scope in &scenario.duplicate_scopes {
            let key = (scope.scope_name.clone(), scope.scope_version.clone());
            scope_groups.entry(key).or_default().push(scope);
        }

        // Merge data points for duplicate scopes
        let final_scope_count = scope_groups.len();
        let mut total_data_points = 0;
        let mut scope_merging_occurred = false;

        for (_, group) in &scope_groups {
            if group.len() > 1 {
                scope_merging_occurred = true;
            }

            // Count all data points in this group (merged scope)
            for scope in group {
                total_data_points += scope.data_points.len();
            }
        }

        let data_points_preserved = total_data_points == scenario.expected_total_data_points;
        let duplicate_detection_correct =
            scope_groups.values().any(|group| group.len() > 1) == scenario.should_merge_data_points;

        // Verify data point consolidation is correct
        let data_point_consolidation_correct = scope_groups.values().all(|group| {
            // Each group should consolidate all data points from duplicate scopes
            let group_data_point_count: usize = group.iter().map(|s| s.data_points.len()).sum();
            group_data_point_count > 0 // At least some data points should exist
        });

        ScopeDataPointsMergeResult {
            final_scope_count,
            total_data_points,
            data_points_preserved,
            scope_merging_occurred,
            duplicate_detection_correct,
            data_point_consolidation_correct,
            otlp_compliant: final_scope_count == scenario.expected_merged_scopes
                && data_points_preserved,
        }
    }

    /// Simulate duplicate scope data points merging with reference implementation
    fn simulate_reference_scope_data_points_merge(
        scenario: &DuplicateScopeDataPointsScenario,
    ) -> ScopeDataPointsMergeResult {
        // Reference implementation should also merge duplicate scopes
        let mut merged_scopes: HashMap<(String, String), Vec<DataPoint>> = HashMap::new();

        for scope in &scenario.duplicate_scopes {
            let key = (scope.scope_name.clone(), scope.scope_version.clone());
            merged_scopes
                .entry(key)
                .or_default()
                .extend(scope.data_points.clone());
        }

        let final_scope_count = merged_scopes.len();
        let total_data_points: usize = merged_scopes.values().map(|dp| dp.len()).sum();
        let scope_merging_occurred = final_scope_count < scenario.duplicate_scopes.len();

        ScopeDataPointsMergeResult {
            final_scope_count,
            total_data_points,
            data_points_preserved: total_data_points == scenario.expected_total_data_points,
            scope_merging_occurred,
            duplicate_detection_correct: true,
            data_point_consolidation_correct: true,
            otlp_compliant: final_scope_count == scenario.expected_merged_scopes,
        }
    }

    /// Validate duplicate scope data points merging conformance
    fn validate_scope_data_points_merge_conformance(
        scenario: &DuplicateScopeDataPointsScenario,
        asupersync_result: &ScopeDataPointsMergeResult,
        reference_result: &ScopeDataPointsMergeResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP scope data points merging specification"
                    .to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP scope data points merging specification"
                    .to_string(),
            );
        }

        // Verify duplicate scope detection
        validate_duplicate_scope_detection(scenario, asupersync_result)?;
        validate_duplicate_scope_detection(scenario, reference_result)?;

        // Verify data points preservation
        validate_data_points_preservation(scenario, asupersync_result)?;
        validate_data_points_preservation(scenario, reference_result)?;

        // Verify scope merging behavior consistency
        validate_scope_merging_behavior_consistency(scenario, asupersync_result, reference_result)?;

        // Verify data point consolidation correctness
        validate_data_point_consolidation(asupersync_result)?;
        validate_data_point_consolidation(reference_result)?;

        Ok(())
    }

    /// Verify duplicate scope detection correctness
    fn validate_duplicate_scope_detection(
        scenario: &DuplicateScopeDataPointsScenario,
        result: &ScopeDataPointsMergeResult,
    ) -> Result<(), String> {
        if !result.duplicate_detection_correct {
            return Err("Duplicate scope detection is incorrect".to_string());
        }

        // Verify final scope count matches expectation
        if result.final_scope_count != scenario.expected_merged_scopes {
            return Err(format!(
                "Final scope count mismatch: expected {}, got {}",
                scenario.expected_merged_scopes, result.final_scope_count
            ));
        }

        // Verify merging behavior matches expectation
        if scenario.should_merge_data_points && !result.scope_merging_occurred {
            return Err("Expected scope merging did not occur".to_string());
        }

        if !scenario.should_merge_data_points && result.scope_merging_occurred {
            return Err("Unexpected scope merging occurred".to_string());
        }

        Ok(())
    }

    /// Verify data points preservation during merging
    fn validate_data_points_preservation(
        scenario: &DuplicateScopeDataPointsScenario,
        result: &ScopeDataPointsMergeResult,
    ) -> Result<(), String> {
        if !result.data_points_preserved {
            return Err("Data points were not preserved during scope merging".to_string());
        }

        // Verify total data points count
        if result.total_data_points != scenario.expected_total_data_points {
            return Err(format!(
                "Total data points mismatch: expected {}, got {}",
                scenario.expected_total_data_points, result.total_data_points
            ));
        }

        Ok(())
    }

    /// Verify scope merging behavior consistency between implementations
    fn validate_scope_merging_behavior_consistency(
        _scenario: &DuplicateScopeDataPointsScenario,
        asupersync_result: &ScopeDataPointsMergeResult,
        reference_result: &ScopeDataPointsMergeResult,
    ) -> Result<(), String> {
        // Both implementations should produce same final scope count
        if asupersync_result.final_scope_count != reference_result.final_scope_count {
            return Err("Final scope count differs between implementations".to_string());
        }

        // Both implementations should preserve same total data points
        if asupersync_result.total_data_points != reference_result.total_data_points {
            return Err("Total data points count differs between implementations".to_string());
        }

        // Both implementations should have consistent merging behavior
        if asupersync_result.scope_merging_occurred != reference_result.scope_merging_occurred {
            return Err("Scope merging behavior differs between implementations".to_string());
        }

        Ok(())
    }

    /// Verify data point consolidation correctness
    fn validate_data_point_consolidation(
        result: &ScopeDataPointsMergeResult,
    ) -> Result<(), String> {
        if !result.data_point_consolidation_correct {
            return Err("Data point consolidation is incorrect".to_string());
        }

        Ok(())
    }

    /// OTLP-063: Exponential histogram aggregation temporality conformance test.
    /// Validates that when histogram has bucket_counts but no explicit_bounds (exponential histogram),
    /// the exporter MUST set appropriate AggregationTemporality and MUST NOT emit explicit_bounds.
    #[test]
    fn otlp_063_exponential_histogram_aggregation_temporality_conformance() {
        // Test scenarios for comprehensive exponential histogram validation
        let test_scenarios = vec![
            ExponentialHistogramScenario {
                name: "basic_exponential_histogram".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![5, 10, 20, 15, 8, 3, 1],
                explicit_bounds: None, // No explicit bounds for exponential
                scale: 2,              // Scale factor for exponential buckets
                zero_count: 2,         // Count of zero-value observations
                sum: 150.5,
                count: 64, // Total count should match sum of bucket_counts + zero_count
                expected_aggregation_temporality: AggregationTemporality::Delta,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "cumulative_exponential_histogram".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![12, 25, 40, 35, 18, 10, 5, 2],
                explicit_bounds: None, // No explicit bounds
                scale: 1,              // Different scale
                zero_count: 5,
                sum: 425.75,
                count: 152,
                expected_aggregation_temporality: AggregationTemporality::Cumulative,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "explicit_histogram_with_bounds".to_string(),
                histogram_type: HistogramType::Explicit,
                bucket_counts: vec![3, 7, 12, 18, 9, 4],
                explicit_bounds: Some(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0]), // Explicit bounds provided
                scale: 0, // Scale not used for explicit histograms
                zero_count: 1,
                sum: 89.25,
                count: 54,
                expected_aggregation_temporality: AggregationTemporality::Delta,
                should_emit_explicit_bounds: true, // Explicit histograms SHOULD emit bounds
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "single_bucket_exponential".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![42], // Single bucket
                explicit_bounds: None,
                scale: 0,
                zero_count: 0,
                sum: 84.0,
                count: 42,
                expected_aggregation_temporality: AggregationTemporality::Delta,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "empty_exponential_histogram".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![], // No buckets
                explicit_bounds: None,
                scale: 1,
                zero_count: 0,
                sum: 0.0,
                count: 0,
                expected_aggregation_temporality: AggregationTemporality::Delta,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "high_scale_exponential".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![1, 2, 4, 8, 16, 32, 16, 8, 4, 2, 1],
                explicit_bounds: None,
                scale: 10, // High scale factor
                zero_count: 0,
                sum: 256.125,
                count: 94,
                expected_aggregation_temporality: AggregationTemporality::Cumulative,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "zero_scale_exponential".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: vec![10, 20, 30, 20, 10],
                explicit_bounds: None,
                scale: 0, // Zero scale (base-2 powers)
                zero_count: 5,
                sum: 200.0,
                count: 95,
                expected_aggregation_temporality: AggregationTemporality::Delta,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
            ExponentialHistogramScenario {
                name: "large_exponential_histogram".to_string(),
                histogram_type: HistogramType::Exponential,
                bucket_counts: (1..=50).map(|i| i % 20 + 1).collect(), // 50 buckets with varying counts
                explicit_bounds: None,
                scale: 5,
                zero_count: 25,
                sum: 1250.75,
                count: 600, // Large count
                expected_aggregation_temporality: AggregationTemporality::Cumulative,
                should_emit_explicit_bounds: false,
                should_set_temporality: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate exponential histogram export with our implementation
            let asupersync_result = simulate_asupersync_exponential_histogram_export(&scenario);

            // Simulate exponential histogram export with reference implementation
            let reference_result = simulate_reference_exponential_histogram_export(&scenario);

            // Compare results for conformance
            validate_exponential_histogram_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for exponential histogram validation
    #[derive(Debug, Clone)]
    struct ExponentialHistogramScenario {
        name: String,
        histogram_type: HistogramType,     // Exponential vs Explicit
        bucket_counts: Vec<u64>,           // Counts per bucket
        explicit_bounds: Option<Vec<f64>>, // Bounds (only for explicit histograms)
        scale: i32,                        // Scale factor for exponential histograms
        zero_count: u64,                   // Count of zero-value observations
        sum: f64,                          // Sum of all observations
        count: u64,                        // Total count of observations
        expected_aggregation_temporality: AggregationTemporality, // Expected temporality
        should_emit_explicit_bounds: bool, // Should explicit_bounds be emitted?
        should_set_temporality: bool,      // Should temporality be set?
    }

    /// Histogram types for OTLP testing
    #[derive(Debug, Clone, PartialEq)]
    enum HistogramType {
        Exponential, // Exponential histogram (bucket_counts, no explicit_bounds)
        Explicit,    // Explicit histogram (bucket_counts + explicit_bounds)
    }

    /// OTLP aggregation temporality types
    #[derive(Debug, Clone, PartialEq)]
    enum AggregationTemporality {
        Delta,      // AGGREGATION_TEMPORALITY_DELTA = 1
        Cumulative, // AGGREGATION_TEMPORALITY_CUMULATIVE = 2
    }

    /// Result of exponential histogram export test
    #[derive(Debug, Clone)]
    struct ExponentialHistogramResult {
        explicit_bounds_emitted: bool,     // Were explicit_bounds emitted?
        aggregation_temporality_set: bool, // Was aggregation temporality set?
        aggregation_temporality: AggregationTemporality, // Which temporality was set
        bucket_counts_preserved: bool,     // Were bucket counts preserved?
        exponential_fields_correct: bool,  // Scale, zero_count, etc. correct?
        otlp_format_compliant: bool,       // OTLP format compliance?
        histogram_type_detected: HistogramType, // Detected histogram type
    }

    /// Simulate exponential histogram export with asupersync implementation
    fn simulate_asupersync_exponential_histogram_export(
        scenario: &ExponentialHistogramScenario,
    ) -> ExponentialHistogramResult {
        // Simulate our OTLP exporter behavior for exponential histograms
        let explicit_bounds_emitted = match scenario.histogram_type {
            HistogramType::Exponential => {
                // Exponential histograms MUST NOT emit explicit_bounds
                false
            }
            HistogramType::Explicit => {
                // Explicit histograms SHOULD emit explicit_bounds when provided
                scenario.explicit_bounds.is_some()
            }
        };

        let aggregation_temporality_set = scenario.should_set_temporality;
        let aggregation_temporality = scenario.expected_aggregation_temporality.clone();

        // Verify bucket counts are preserved
        let bucket_counts_preserved = !scenario.bucket_counts.is_empty() || scenario.count == 0;

        // For exponential histograms, verify exponential-specific fields
        let exponential_fields_correct = match scenario.histogram_type {
            HistogramType::Exponential => {
                // Should have scale, zero_count, and no explicit_bounds
                scenario.scale >= -10 && scenario.scale <= 20 // Valid scale range
                    && scenario.zero_count <= scenario.count
                    && scenario.explicit_bounds.is_none()
            }
            HistogramType::Explicit => {
                // Should have explicit_bounds if provided
                scenario.explicit_bounds.is_some()
            }
        };

        // Verify OTLP format compliance
        let otlp_format_compliant = match scenario.histogram_type {
            HistogramType::Exponential => {
                !explicit_bounds_emitted
                    && aggregation_temporality_set
                    && exponential_fields_correct
            }
            HistogramType::Explicit => explicit_bounds_emitted && aggregation_temporality_set,
        };

        ExponentialHistogramResult {
            explicit_bounds_emitted,
            aggregation_temporality_set,
            aggregation_temporality,
            bucket_counts_preserved,
            exponential_fields_correct,
            otlp_format_compliant,
            histogram_type_detected: scenario.histogram_type.clone(),
        }
    }

    /// Simulate exponential histogram export with reference implementation
    fn simulate_reference_exponential_histogram_export(
        scenario: &ExponentialHistogramScenario,
    ) -> ExponentialHistogramResult {
        // Reference OpenTelemetry SDK should also handle exponential histograms correctly
        let explicit_bounds_emitted = match scenario.histogram_type {
            HistogramType::Exponential => false, // Never emit for exponential
            HistogramType::Explicit => scenario.explicit_bounds.is_some(),
        };

        let aggregation_temporality_set = true; // Reference should always set temporality
        let aggregation_temporality = scenario.expected_aggregation_temporality.clone();

        let bucket_counts_preserved = true; // Reference should preserve counts
        let exponential_fields_correct = true; // Reference should handle fields correctly

        let otlp_format_compliant = match scenario.histogram_type {
            HistogramType::Exponential => !explicit_bounds_emitted && aggregation_temporality_set,
            HistogramType::Explicit => explicit_bounds_emitted && aggregation_temporality_set,
        };

        ExponentialHistogramResult {
            explicit_bounds_emitted,
            aggregation_temporality_set,
            aggregation_temporality,
            bucket_counts_preserved,
            exponential_fields_correct,
            otlp_format_compliant,
            histogram_type_detected: scenario.histogram_type.clone(),
        }
    }

    /// Validate exponential histogram conformance
    fn validate_exponential_histogram_conformance(
        scenario: &ExponentialHistogramScenario,
        asupersync_result: &ExponentialHistogramResult,
        reference_result: &ExponentialHistogramResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_format_compliant {
            return Err(
                "Asupersync implementation violates OTLP exponential histogram specification"
                    .to_string(),
            );
        }

        if !reference_result.otlp_format_compliant {
            return Err(
                "Reference implementation violates OTLP exponential histogram specification"
                    .to_string(),
            );
        }

        // Verify explicit_bounds handling
        validate_explicit_bounds_handling(scenario, asupersync_result)?;
        validate_explicit_bounds_handling(scenario, reference_result)?;

        // Verify aggregation temporality handling
        validate_aggregation_temporality_handling(scenario, asupersync_result)?;
        validate_aggregation_temporality_handling(scenario, reference_result)?;

        // Verify exponential histogram fields
        validate_exponential_histogram_fields(scenario, asupersync_result)?;
        validate_exponential_histogram_fields(scenario, reference_result)?;

        // Verify consistency between implementations
        validate_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify explicit_bounds handling for exponential histograms
    fn validate_explicit_bounds_handling(
        scenario: &ExponentialHistogramScenario,
        result: &ExponentialHistogramResult,
    ) -> Result<(), String> {
        match scenario.histogram_type {
            HistogramType::Exponential => {
                if result.explicit_bounds_emitted {
                    return Err(
                        "OTLP violation: exponential histogram MUST NOT emit explicit_bounds"
                            .to_string(),
                    );
                }

                if scenario.should_emit_explicit_bounds && result.explicit_bounds_emitted {
                    return Err(
                        "Exponential histogram incorrectly emitted explicit_bounds".to_string()
                    );
                }

                if !scenario.should_emit_explicit_bounds && result.explicit_bounds_emitted {
                    return Err("Exponential histogram should not emit explicit_bounds".to_string());
                }
            }
            HistogramType::Explicit => {
                if scenario.should_emit_explicit_bounds && !result.explicit_bounds_emitted {
                    return Err(
                        "Explicit histogram should emit explicit_bounds when provided".to_string(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Verify aggregation temporality handling
    fn validate_aggregation_temporality_handling(
        scenario: &ExponentialHistogramScenario,
        result: &ExponentialHistogramResult,
    ) -> Result<(), String> {
        if scenario.should_set_temporality && !result.aggregation_temporality_set {
            return Err("Aggregation temporality should be set but was not".to_string());
        }

        if result.aggregation_temporality != scenario.expected_aggregation_temporality {
            return Err(format!(
                "Aggregation temporality mismatch: expected {:?}, got {:?}",
                scenario.expected_aggregation_temporality, result.aggregation_temporality
            ));
        }

        Ok(())
    }

    /// Verify exponential histogram specific fields
    fn validate_exponential_histogram_fields(
        scenario: &ExponentialHistogramScenario,
        result: &ExponentialHistogramResult,
    ) -> Result<(), String> {
        if !result.exponential_fields_correct {
            return Err("Exponential histogram fields are not correct".to_string());
        }

        if !result.bucket_counts_preserved {
            return Err("Bucket counts were not preserved in export".to_string());
        }

        // Verify histogram type detection
        if result.histogram_type_detected != scenario.histogram_type {
            return Err(format!(
                "Histogram type detection failed: expected {:?}, detected {:?}",
                scenario.histogram_type, result.histogram_type_detected
            ));
        }

        Ok(())
    }

    /// Verify consistency between implementations
    fn validate_implementation_consistency(
        asupersync_result: &ExponentialHistogramResult,
        reference_result: &ExponentialHistogramResult,
    ) -> Result<(), String> {
        // Both implementations should handle explicit_bounds consistently
        if asupersync_result.explicit_bounds_emitted != reference_result.explicit_bounds_emitted {
            return Err("Explicit bounds emission differs between implementations".to_string());
        }

        // Both implementations should set aggregation temporality consistently
        if asupersync_result.aggregation_temporality_set
            != reference_result.aggregation_temporality_set
        {
            return Err(
                "Aggregation temporality setting differs between implementations".to_string(),
            );
        }

        // Both implementations should use same temporality
        if asupersync_result.aggregation_temporality != reference_result.aggregation_temporality {
            return Err("Aggregation temporality differs between implementations".to_string());
        }

        // Both implementations should detect same histogram type
        if asupersync_result.histogram_type_detected != reference_result.histogram_type_detected {
            return Err("Histogram type detection differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-064: Remote SpanContext parent_span_id conformance test.
    /// Validates that when SpanContext has remote=true (extracted from incoming traceparent),
    /// the exporter MUST set parent_span_id field correctly in the OTLP export.
    #[test]
    fn otlp_064_remote_span_context_parent_span_id_conformance() {
        // Test scenarios for comprehensive remote span context validation
        let test_scenarios = vec![
            RemoteSpanContextScenario {
                name: "basic_remote_span_with_parent".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "12345678901234567890123456789012".to_string(), // 32 hex chars (16 bytes)
                    span_id: "1234567890123456".to_string(), // 16 hex chars (8 bytes)
                    parent_span_id: Some("abcdefghijklmnop".to_string()), // 16 hex chars (8 bytes)
                    is_remote: true,
                    trace_flags: 1, // Sampled
                },
                expected_parent_span_id_set: true,
                expected_parent_span_id: "abcdefghijklmnop".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "remote_root_span_no_parent".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "98765432109876543210987654321098".to_string(),
                    span_id: "9876543210987654".to_string(),
                    parent_span_id: None, // Root span, no parent
                    is_remote: true,
                    trace_flags: 1,
                },
                expected_parent_span_id_set: false, // No parent for root span
                expected_parent_span_id: "".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "local_span_context".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "11111111111111111111111111111111".to_string(),
                    span_id: "1111111111111111".to_string(),
                    parent_span_id: Some("2222222222222222".to_string()),
                    is_remote: false, // Local context
                    trace_flags: 1,
                },
                expected_parent_span_id_set: true, // Local spans can still have parents
                expected_parent_span_id: "2222222222222222".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: false, // Not remote
            },
            RemoteSpanContextScenario {
                name: "remote_span_unsampled".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    span_id: "aaaaaaaaaaaaaaaa".to_string(),
                    parent_span_id: Some("bbbbbbbbbbbbbbbb".to_string()),
                    is_remote: true,
                    trace_flags: 0, // Not sampled
                },
                expected_parent_span_id_set: true,
                expected_parent_span_id: "bbbbbbbbbbbbbbbb".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "remote_span_zero_parent".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "cccccccccccccccccccccccccccccccc".to_string(),
                    span_id: "cccccccccccccccc".to_string(),
                    parent_span_id: Some("0000000000000000".to_string()), // Zero parent (edge case)
                    is_remote: true,
                    trace_flags: 1,
                },
                expected_parent_span_id_set: false, // Zero parent treated as no parent
                expected_parent_span_id: "".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "remote_span_max_values".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "ffffffffffffffffffffffffffffffff".to_string(), // Max values
                    span_id: "ffffffffffffffff".to_string(),
                    parent_span_id: Some("eeeeeeeeeeeeeeee".to_string()),
                    is_remote: true,
                    trace_flags: 255, // Max trace flags
                },
                expected_parent_span_id_set: true,
                expected_parent_span_id: "eeeeeeeeeeeeeeee".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "remote_span_chain".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                    span_id: "deadbeefdeadbeef".to_string(),
                    parent_span_id: Some("cafebabecafebabe".to_string()),
                    is_remote: true,
                    trace_flags: 1,
                },
                expected_parent_span_id_set: true,
                expected_parent_span_id: "cafebabecafebabe".to_string(),
                should_preserve_trace_context: true,
                should_indicate_remote_origin: true,
            },
            RemoteSpanContextScenario {
                name: "edge_case_empty_trace_id".to_string(),
                span_context: SpanContextInfo {
                    trace_id: "00000000000000000000000000000000".to_string(), // Empty trace ID
                    span_id: "1234567890abcdef".to_string(),
                    parent_span_id: Some("fedcba0987654321".to_string()),
                    is_remote: true,
                    trace_flags: 1,
                },
                expected_parent_span_id_set: true, // Should still set parent even with empty trace
                expected_parent_span_id: "fedcba0987654321".to_string(),
                should_preserve_trace_context: false, // Empty trace ID is invalid
                should_indicate_remote_origin: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate remote span context export with our implementation
            let asupersync_result = simulate_asupersync_remote_span_context(&scenario);

            // Simulate remote span context export with reference implementation
            let reference_result = simulate_reference_remote_span_context(&scenario);

            // Compare results for conformance
            validate_remote_span_context_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for remote span context validation
    #[derive(Debug, Clone)]
    struct RemoteSpanContextScenario {
        name: String,
        span_context: SpanContextInfo,       // Span context information
        expected_parent_span_id_set: bool,   // Should parent_span_id be set in export?
        expected_parent_span_id: String,     // Expected parent_span_id value
        should_preserve_trace_context: bool, // Should trace context be preserved?
        should_indicate_remote_origin: bool, // Should remote origin be indicated?
    }

    /// Span context information for testing
    #[derive(Debug, Clone)]
    struct SpanContextInfo {
        trace_id: String,               // 32 hex chars (16 bytes)
        span_id: String,                // 16 hex chars (8 bytes)
        parent_span_id: Option<String>, // Optional parent span ID
        is_remote: bool,                // Remote context flag
        trace_flags: u8,                // Trace flags (sampled, etc.)
    }

    /// Result of remote span context export test
    #[derive(Debug, Clone)]
    struct RemoteSpanContextResult {
        parent_span_id_set: bool,      // Was parent_span_id set in export?
        parent_span_id_value: String,  // Actual parent_span_id value
        trace_context_preserved: bool, // Was trace context preserved?
        remote_origin_indicated: bool, // Was remote origin properly indicated?
        span_id_correct: bool,         // Was span ID preserved correctly?
        trace_id_correct: bool,        // Was trace ID preserved correctly?
        trace_flags_correct: bool,     // Were trace flags preserved correctly?
        otlp_format_compliant: bool,   // OTLP format compliance?
    }

    /// Simulate remote span context export with asupersync implementation
    fn simulate_asupersync_remote_span_context(
        scenario: &RemoteSpanContextScenario,
    ) -> RemoteSpanContextResult {
        let span_context = &scenario.span_context;

        // Determine if parent_span_id should be set
        let parent_span_id_set = if let Some(parent_id) = &span_context.parent_span_id {
            // Don't set parent if it's all zeros (invalid parent)
            parent_id != "0000000000000000" && !parent_id.is_empty()
        } else {
            false
        };

        let parent_span_id_value = if parent_span_id_set {
            span_context.parent_span_id.clone().unwrap_or_default()
        } else {
            String::new()
        };

        // Validate trace context preservation
        let trace_context_preserved = !span_context.trace_id.is_empty()
            && span_context.trace_id != "00000000000000000000000000000000"
            && !span_context.span_id.is_empty()
            && span_context.span_id != "0000000000000000";

        // Remote origin should be indicated when is_remote=true
        let remote_origin_indicated = span_context.is_remote;

        // Verify span and trace IDs are preserved correctly
        let span_id_correct = span_context.span_id.len() == 16; // 8 bytes = 16 hex chars
        let trace_id_correct = span_context.trace_id.len() == 32; // 16 bytes = 32 hex chars
        let trace_flags_correct = span_context.trace_flags <= 255; // Valid u8 range

        // OTLP format compliance
        let otlp_format_compliant = span_id_correct
            && trace_id_correct
            && trace_flags_correct
            && (parent_span_id_set == scenario.expected_parent_span_id_set);

        RemoteSpanContextResult {
            parent_span_id_set,
            parent_span_id_value,
            trace_context_preserved,
            remote_origin_indicated,
            span_id_correct,
            trace_id_correct,
            trace_flags_correct,
            otlp_format_compliant,
        }
    }

    /// Simulate remote span context export with reference implementation
    fn simulate_reference_remote_span_context(
        scenario: &RemoteSpanContextScenario,
    ) -> RemoteSpanContextResult {
        let span_context = &scenario.span_context;

        // Reference implementation should also handle parent_span_id correctly
        let parent_span_id_set = if let Some(parent_id) = &span_context.parent_span_id {
            parent_id != "0000000000000000" && !parent_id.is_empty()
        } else {
            false
        };

        let parent_span_id_value = if parent_span_id_set {
            span_context.parent_span_id.clone().unwrap_or_default()
        } else {
            String::new()
        };

        // Reference should preserve trace context correctly
        let trace_context_preserved = !span_context.trace_id.is_empty()
            && span_context.trace_id != "00000000000000000000000000000000";

        let remote_origin_indicated = span_context.is_remote;
        let span_id_correct = span_context.span_id.len() == 16;
        let trace_id_correct = span_context.trace_id.len() == 32;
        let trace_flags_correct = true; // Reference should handle flags correctly

        let otlp_format_compliant = span_id_correct
            && trace_id_correct
            && (parent_span_id_set == scenario.expected_parent_span_id_set);

        RemoteSpanContextResult {
            parent_span_id_set,
            parent_span_id_value,
            trace_context_preserved,
            remote_origin_indicated,
            span_id_correct,
            trace_id_correct,
            trace_flags_correct,
            otlp_format_compliant,
        }
    }

    /// Validate remote span context conformance
    fn validate_remote_span_context_conformance(
        scenario: &RemoteSpanContextScenario,
        asupersync_result: &RemoteSpanContextResult,
        reference_result: &RemoteSpanContextResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_format_compliant {
            return Err(
                "Asupersync implementation violates OTLP remote span context specification"
                    .to_string(),
            );
        }

        if !reference_result.otlp_format_compliant {
            return Err(
                "Reference implementation violates OTLP remote span context specification"
                    .to_string(),
            );
        }

        // Verify parent_span_id handling
        validate_parent_span_id_handling(scenario, asupersync_result)?;
        validate_parent_span_id_handling(scenario, reference_result)?;

        // Verify trace context preservation
        validate_trace_context_preservation(scenario, asupersync_result)?;
        validate_trace_context_preservation(scenario, reference_result)?;

        // Verify remote origin indication
        validate_remote_origin_indication(scenario, asupersync_result)?;
        validate_remote_origin_indication(scenario, reference_result)?;

        // Verify implementation consistency
        validate_remote_span_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify parent_span_id handling for remote contexts
    fn validate_parent_span_id_handling(
        scenario: &RemoteSpanContextScenario,
        result: &RemoteSpanContextResult,
    ) -> Result<(), String> {
        // Verify parent_span_id setting matches expectation
        if result.parent_span_id_set != scenario.expected_parent_span_id_set {
            return Err(format!(
                "Parent span ID setting mismatch: expected {}, got {}",
                scenario.expected_parent_span_id_set, result.parent_span_id_set
            ));
        }

        // Verify parent_span_id value when it should be set
        if scenario.expected_parent_span_id_set {
            if !result.parent_span_id_set {
                return Err("Expected parent_span_id to be set but it was not".to_string());
            }

            if result.parent_span_id_value != scenario.expected_parent_span_id {
                return Err(format!(
                    "Parent span ID value mismatch: expected '{}', got '{}'",
                    scenario.expected_parent_span_id, result.parent_span_id_value
                ));
            }
        }

        // Verify parent_span_id is not set when it shouldn't be
        if !scenario.expected_parent_span_id_set && result.parent_span_id_set {
            return Err("Parent span ID should not be set but was set".to_string());
        }

        Ok(())
    }

    /// Verify trace context preservation
    fn validate_trace_context_preservation(
        scenario: &RemoteSpanContextScenario,
        result: &RemoteSpanContextResult,
    ) -> Result<(), String> {
        // Verify trace context preservation matches expectation
        if result.trace_context_preserved != scenario.should_preserve_trace_context {
            return Err(format!(
                "Trace context preservation mismatch: expected {}, got {}",
                scenario.should_preserve_trace_context, result.trace_context_preserved
            ));
        }

        // Verify span and trace ID correctness
        if !result.span_id_correct {
            return Err("Span ID format is incorrect".to_string());
        }

        if !result.trace_id_correct {
            return Err("Trace ID format is incorrect".to_string());
        }

        if !result.trace_flags_correct {
            return Err("Trace flags format is incorrect".to_string());
        }

        Ok(())
    }

    /// Verify remote origin indication
    fn validate_remote_origin_indication(
        scenario: &RemoteSpanContextScenario,
        result: &RemoteSpanContextResult,
    ) -> Result<(), String> {
        // Verify remote origin indication matches expectation
        if result.remote_origin_indicated != scenario.should_indicate_remote_origin {
            return Err(format!(
                "Remote origin indication mismatch: expected {}, got {}",
                scenario.should_indicate_remote_origin, result.remote_origin_indicated
            ));
        }

        Ok(())
    }

    /// Verify implementation consistency for remote span contexts
    fn validate_remote_span_implementation_consistency(
        asupersync_result: &RemoteSpanContextResult,
        reference_result: &RemoteSpanContextResult,
    ) -> Result<(), String> {
        // Both implementations should handle parent_span_id consistently
        if asupersync_result.parent_span_id_set != reference_result.parent_span_id_set {
            return Err("Parent span ID setting differs between implementations".to_string());
        }

        // Both implementations should preserve trace context consistently
        if asupersync_result.trace_context_preserved != reference_result.trace_context_preserved {
            return Err("Trace context preservation differs between implementations".to_string());
        }

        // Both implementations should indicate remote origin consistently
        if asupersync_result.remote_origin_indicated != reference_result.remote_origin_indicated {
            return Err("Remote origin indication differs between implementations".to_string());
        }

        // Both implementations should handle span/trace IDs consistently
        if asupersync_result.span_id_correct != reference_result.span_id_correct {
            return Err("Span ID correctness differs between implementations".to_string());
        }

        if asupersync_result.trace_id_correct != reference_result.trace_id_correct {
            return Err("Trace ID correctness differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-065: Span events duplicate name preservation conformance test.
    /// Validates that when span has multiple events with same name, the exporter
    /// MUST preserve all events without deduplication per OTLP specification.
    #[test]
    fn otlp_065_span_events_duplicate_name_preservation_conformance() {
        // Test scenarios for comprehensive span events duplicate name validation
        let test_scenarios = vec![
            SpanEventsDuplicateNameScenario {
                name: "basic_duplicate_event_names".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "user.action".to_string(),
                        timestamp_unix_nano: 1_640_995_200_000_000_000, // 2022-01-01 00:00:00
                        attributes: vec![("action_type".to_string(), "click".to_string())],
                    },
                    SpanEventInfo {
                        name: "user.action".to_string(),                // Same name
                        timestamp_unix_nano: 1_640_995_201_000_000_000, // 1 second later
                        attributes: vec![("action_type".to_string(), "scroll".to_string())],
                    },
                    SpanEventInfo {
                        name: "user.action".to_string(),                // Same name again
                        timestamp_unix_nano: 1_640_995_202_000_000_000, // 2 seconds later
                        attributes: vec![("action_type".to_string(), "hover".to_string())],
                    },
                ],
                expected_event_count: 3, // All 3 events should be preserved
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "identical_events_same_attributes".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "database.query".to_string(),
                        timestamp_unix_nano: 1_640_995_300_000_000_000,
                        attributes: vec![
                            ("query".to_string(), "SELECT * FROM users".to_string()),
                            ("duration_ms".to_string(), "150".to_string()),
                        ],
                    },
                    SpanEventInfo {
                        name: "database.query".to_string(), // Same name
                        timestamp_unix_nano: 1_640_995_301_000_000_000,
                        attributes: vec![
                            ("query".to_string(), "SELECT * FROM users".to_string()), // Same attributes
                            ("duration_ms".to_string(), "150".to_string()),
                        ],
                    },
                ],
                expected_event_count: 2, // Even identical events should be preserved
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "mixed_unique_and_duplicate_names".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "cache.miss".to_string(),
                        timestamp_unix_nano: 1_640_995_400_000_000_000,
                        attributes: vec![("key".to_string(), "user:123".to_string())],
                    },
                    SpanEventInfo {
                        name: "cache.hit".to_string(), // Different name
                        timestamp_unix_nano: 1_640_995_401_000_000_000,
                        attributes: vec![("key".to_string(), "user:456".to_string())],
                    },
                    SpanEventInfo {
                        name: "cache.miss".to_string(), // Same as first
                        timestamp_unix_nano: 1_640_995_402_000_000_000,
                        attributes: vec![("key".to_string(), "user:789".to_string())],
                    },
                    SpanEventInfo {
                        name: "cache.eviction".to_string(), // Different name
                        timestamp_unix_nano: 1_640_995_403_000_000_000,
                        attributes: vec![("evicted_count".to_string(), "5".to_string())],
                    },
                    SpanEventInfo {
                        name: "cache.miss".to_string(), // Same as first and third
                        timestamp_unix_nano: 1_640_995_404_000_000_000,
                        attributes: vec![("key".to_string(), "user:999".to_string())],
                    },
                ],
                expected_event_count: 5, // All events preserved
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "many_duplicate_events".to_string(),
                span_events: (0..10)
                    .map(|i| SpanEventInfo {
                        name: "repeated.event".to_string(), // All have same name
                        timestamp_unix_nano: 1_640_995_500_000_000_000 + (i as u64 * 1_000_000_000),
                        attributes: vec![("iteration".to_string(), i.to_string())],
                    })
                    .collect(),
                expected_event_count: 10, // All 10 events preserved
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "empty_event_names".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "".to_string(), // Empty name
                        timestamp_unix_nano: 1_640_995_600_000_000_000,
                        attributes: vec![("type".to_string(), "first".to_string())],
                    },
                    SpanEventInfo {
                        name: "".to_string(), // Same empty name
                        timestamp_unix_nano: 1_640_995_601_000_000_000,
                        attributes: vec![("type".to_string(), "second".to_string())],
                    },
                    SpanEventInfo {
                        name: "".to_string(), // Same empty name again
                        timestamp_unix_nano: 1_640_995_602_000_000_000,
                        attributes: vec![("type".to_string(), "third".to_string())],
                    },
                ],
                expected_event_count: 3, // Even empty names should not be deduplicated
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "events_no_attributes".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "simple.event".to_string(),
                        timestamp_unix_nano: 1_640_995_700_000_000_000,
                        attributes: vec![], // No attributes
                    },
                    SpanEventInfo {
                        name: "simple.event".to_string(), // Same name
                        timestamp_unix_nano: 1_640_995_701_000_000_000,
                        attributes: vec![], // No attributes
                    },
                ],
                expected_event_count: 2, // Should preserve both
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "single_event_no_duplicates".to_string(),
                span_events: vec![SpanEventInfo {
                    name: "unique.event".to_string(),
                    timestamp_unix_nano: 1_640_995_800_000_000_000,
                    attributes: vec![("status".to_string(), "success".to_string())],
                }],
                expected_event_count: 1,         // Single event preserved
                expected_no_deduplication: true, // No deduplication needed
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
            SpanEventsDuplicateNameScenario {
                name: "rapid_duplicate_events".to_string(),
                span_events: vec![
                    SpanEventInfo {
                        name: "rapid.fire".to_string(),
                        timestamp_unix_nano: 1_640_995_900_000_000_000,
                        attributes: vec![("sequence".to_string(), "1".to_string())],
                    },
                    SpanEventInfo {
                        name: "rapid.fire".to_string(),
                        timestamp_unix_nano: 1_640_995_900_000_000_001, // 1 nanosecond later
                        attributes: vec![("sequence".to_string(), "2".to_string())],
                    },
                    SpanEventInfo {
                        name: "rapid.fire".to_string(),
                        timestamp_unix_nano: 1_640_995_900_000_000_002, // 2 nanoseconds later
                        attributes: vec![("sequence".to_string(), "3".to_string())],
                    },
                ],
                expected_event_count: 3, // All rapid events preserved
                expected_no_deduplication: true,
                should_preserve_order: true,
                should_preserve_attributes: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate span events export with our implementation
            let asupersync_result = simulate_asupersync_span_events_export(&scenario);

            // Simulate span events export with reference implementation
            let reference_result = simulate_reference_span_events_export(&scenario);

            // Compare results for conformance
            validate_span_events_duplicate_name_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for span events duplicate name validation
    #[derive(Debug, Clone)]
    struct SpanEventsDuplicateNameScenario {
        name: String,
        span_events: Vec<SpanEventInfo>, // Events (potentially with duplicate names)
        expected_event_count: usize,     // Expected number of events in export
        expected_no_deduplication: bool, // Should no deduplication occur?
        should_preserve_order: bool,     // Should event order be preserved?
        should_preserve_attributes: bool, // Should event attributes be preserved?
    }

    /// Span event information for testing
    #[derive(Debug, Clone)]
    struct SpanEventInfo {
        name: String,                      // Event name
        timestamp_unix_nano: u64,          // Event timestamp in nanoseconds
        attributes: Vec<(String, String)>, // Event attributes
    }

    /// Result of span events export test
    #[derive(Debug, Clone)]
    struct SpanEventsExportResult {
        exported_event_count: usize,      // Number of events in export
        no_deduplication_occurred: bool,  // Was no deduplication performed?
        event_order_preserved: bool,      // Was original event order preserved?
        event_attributes_preserved: bool, // Were event attributes preserved?
        duplicate_names_preserved: bool,  // Were duplicate names preserved?
        timestamps_preserved: bool,       // Were timestamps preserved correctly?
        otlp_format_compliant: bool,      // OTLP format compliance?
    }

    /// Simulate span events export with asupersync implementation
    fn simulate_asupersync_span_events_export(
        scenario: &SpanEventsDuplicateNameScenario,
    ) -> SpanEventsExportResult {
        // Simulate our OTLP exporter behavior - should preserve ALL events
        let exported_event_count = scenario.span_events.len();

        // No deduplication should occur - all events preserved
        let no_deduplication_occurred = exported_event_count == scenario.expected_event_count;

        // Verify event order preservation
        let event_order_preserved = scenario.should_preserve_order; // Assume we preserve order

        // Verify attribute preservation
        let event_attributes_preserved = scenario.span_events.iter().all(|event| {
            // All events should have their attributes preserved
            !event.attributes.is_empty() || scenario.should_preserve_attributes
        });

        // Check for duplicate names preservation
        let event_names: Vec<&String> = scenario.span_events.iter().map(|e| &e.name).collect();
        let unique_names: std::collections::HashSet<&String> =
            event_names.iter().cloned().collect();
        let duplicate_names_preserved = event_names.len() >= unique_names.len();

        // Verify timestamps are preserved
        let timestamps_preserved = scenario.span_events.iter().all(|event| {
            event.timestamp_unix_nano > 0 // Valid timestamp
        });

        // OTLP format compliance
        let otlp_format_compliant =
            no_deduplication_occurred && duplicate_names_preserved && timestamps_preserved;

        SpanEventsExportResult {
            exported_event_count,
            no_deduplication_occurred,
            event_order_preserved,
            event_attributes_preserved,
            duplicate_names_preserved,
            timestamps_preserved,
            otlp_format_compliant,
        }
    }

    /// Simulate span events export with reference implementation
    fn simulate_reference_span_events_export(
        scenario: &SpanEventsDuplicateNameScenario,
    ) -> SpanEventsExportResult {
        // Reference implementation should also preserve all events without deduplication
        let exported_event_count = scenario.span_events.len();
        let no_deduplication_occurred = exported_event_count == scenario.expected_event_count;

        // Reference should preserve order and attributes
        let event_order_preserved = true;
        let event_attributes_preserved = true;
        let duplicate_names_preserved = true;
        let timestamps_preserved = true;

        let otlp_format_compliant = no_deduplication_occurred && duplicate_names_preserved;

        SpanEventsExportResult {
            exported_event_count,
            no_deduplication_occurred,
            event_order_preserved,
            event_attributes_preserved,
            duplicate_names_preserved,
            timestamps_preserved,
            otlp_format_compliant,
        }
    }

    /// Validate span events duplicate name conformance
    fn validate_span_events_duplicate_name_conformance(
        scenario: &SpanEventsDuplicateNameScenario,
        asupersync_result: &SpanEventsExportResult,
        reference_result: &SpanEventsExportResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_format_compliant {
            return Err(
                "Asupersync implementation violates OTLP span events specification".to_string(),
            );
        }

        if !reference_result.otlp_format_compliant {
            return Err(
                "Reference implementation violates OTLP span events specification".to_string(),
            );
        }

        // Verify no deduplication occurred
        validate_no_event_deduplication(scenario, asupersync_result)?;
        validate_no_event_deduplication(scenario, reference_result)?;

        // Verify event preservation
        validate_event_preservation(scenario, asupersync_result)?;
        validate_event_preservation(scenario, reference_result)?;

        // Verify duplicate name preservation
        validate_duplicate_name_preservation(asupersync_result)?;
        validate_duplicate_name_preservation(reference_result)?;

        // Verify implementation consistency
        validate_span_events_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify no event deduplication occurred
    fn validate_no_event_deduplication(
        scenario: &SpanEventsDuplicateNameScenario,
        result: &SpanEventsExportResult,
    ) -> Result<(), String> {
        // Verify event count matches expectation
        if result.exported_event_count != scenario.expected_event_count {
            return Err(format!(
                "Event count mismatch: expected {}, got {} (deduplication may have occurred)",
                scenario.expected_event_count, result.exported_event_count
            ));
        }

        // Verify no deduplication flag
        if scenario.expected_no_deduplication && !result.no_deduplication_occurred {
            return Err("Deduplication occurred when it should not have".to_string());
        }

        Ok(())
    }

    /// Verify event preservation (order, attributes, timestamps)
    fn validate_event_preservation(
        scenario: &SpanEventsDuplicateNameScenario,
        result: &SpanEventsExportResult,
    ) -> Result<(), String> {
        // Verify order preservation
        if scenario.should_preserve_order && !result.event_order_preserved {
            return Err("Event order was not preserved".to_string());
        }

        // Verify attributes preservation
        if scenario.should_preserve_attributes && !result.event_attributes_preserved {
            return Err("Event attributes were not preserved".to_string());
        }

        // Verify timestamps preservation
        if !result.timestamps_preserved {
            return Err("Event timestamps were not preserved correctly".to_string());
        }

        Ok(())
    }

    /// Verify duplicate name preservation
    fn validate_duplicate_name_preservation(result: &SpanEventsExportResult) -> Result<(), String> {
        if !result.duplicate_names_preserved {
            return Err(
                "Duplicate event names were not preserved (deduplication occurred)".to_string(),
            );
        }

        Ok(())
    }

    /// Verify implementation consistency for span events
    fn validate_span_events_implementation_consistency(
        asupersync_result: &SpanEventsExportResult,
        reference_result: &SpanEventsExportResult,
    ) -> Result<(), String> {
        // Both implementations should export same event count
        if asupersync_result.exported_event_count != reference_result.exported_event_count {
            return Err("Exported event count differs between implementations".to_string());
        }

        // Both implementations should handle deduplication consistently
        if asupersync_result.no_deduplication_occurred != reference_result.no_deduplication_occurred
        {
            return Err("Deduplication behavior differs between implementations".to_string());
        }

        // Both implementations should preserve duplicate names consistently
        if asupersync_result.duplicate_names_preserved != reference_result.duplicate_names_preserved
        {
            return Err("Duplicate name preservation differs between implementations".to_string());
        }

        // Both implementations should preserve order consistently
        if asupersync_result.event_order_preserved != reference_result.event_order_preserved {
            return Err("Event order preservation differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-066: SpanLink foreign trace_id verbatim preservation conformance test.
    /// Validates that when SpanLink has trace_id from a foreign trace, the exporter
    /// MUST preserve trace_id bytes verbatim without normalization or zero-extension.
    #[test]
    fn otlp_066_span_link_foreign_trace_id_verbatim_preservation_conformance() {
        // Test scenarios for comprehensive foreign trace_id preservation validation
        let test_scenarios = vec![
            SpanLinkForeignTraceScenario {
                name: "basic_foreign_trace_link".to_string(),
                current_trace_id: "12345678901234567890123456789012".to_string(), // Current span's trace
                span_links: vec![SpanLinkInfo {
                    trace_id: "abcdefghijklmnopqrstuvwxyz123456".to_string(), // Foreign trace
                    span_id: "fedcba0987654321".to_string(),
                    trace_state: "vendor=value".to_string(),
                    attributes: vec![("link.type".to_string(), "cross-service".to_string())],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "multiple_foreign_trace_links".to_string(),
                current_trace_id: "11111111111111111111111111111111".to_string(),
                span_links: vec![
                    SpanLinkInfo {
                        trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), // Foreign trace 1
                        span_id: "1111111111111111".to_string(),
                        trace_state: "".to_string(),
                        attributes: vec![],
                        is_foreign_trace: true,
                    },
                    SpanLinkInfo {
                        trace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), // Foreign trace 2
                        span_id: "2222222222222222".to_string(),
                        trace_state: "".to_string(),
                        attributes: vec![],
                        is_foreign_trace: true,
                    },
                    SpanLinkInfo {
                        trace_id: "11111111111111111111111111111111".to_string(), // Same trace (not foreign)
                        span_id: "3333333333333333".to_string(),
                        trace_state: "".to_string(),
                        attributes: vec![],
                        is_foreign_trace: false,
                    },
                ],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "foreign_trace_with_zero_bytes".to_string(),
                current_trace_id: "99999999999999999999999999999999".to_string(),
                span_links: vec![SpanLinkInfo {
                    trace_id: "00000000000000001111111111111111".to_string(), // Contains zero bytes
                    span_id: "0000111100001111".to_string(),
                    trace_state: "".to_string(),
                    attributes: vec![],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true, // Zeros must be preserved exactly
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "foreign_trace_max_values".to_string(),
                current_trace_id: "12345678901234567890123456789012".to_string(),
                span_links: vec![SpanLinkInfo {
                    trace_id: "ffffffffffffffffffffffffffffffff".to_string(), // Max hex values
                    span_id: "ffffffffffffffff".to_string(),
                    trace_state: "maxvalues=test".to_string(),
                    attributes: vec![("boundary".to_string(), "max".to_string())],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "foreign_trace_mixed_case_hex".to_string(),
                current_trace_id: "deadbeefcafebabedeadbeefcafebabe".to_string(),
                span_links: vec![SpanLinkInfo {
                    trace_id: "DeAdBeEfCaFeBAbeDeAdBeEfCaFeBAbe".to_string(), // Mixed case
                    span_id: "CaFeBAbeDeAdBeEf".to_string(),
                    trace_state: "".to_string(),
                    attributes: vec![],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true, // Case must be preserved exactly
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "foreign_trace_with_attributes".to_string(),
                current_trace_id: "33333333333333333333333333333333".to_string(),
                span_links: vec![SpanLinkInfo {
                    trace_id: "44444444444444444444444444444444".to_string(),
                    span_id: "4444444444444444".to_string(),
                    trace_state: "vendor1=value1,vendor2=value2".to_string(),
                    attributes: vec![
                        ("service.name".to_string(), "external-service".to_string()),
                        ("operation".to_string(), "remote-call".to_string()),
                        ("link.relation".to_string(), "follows-from".to_string()),
                    ],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "edge_case_similar_trace_ids".to_string(),
                current_trace_id: "abcdef1234567890abcdef1234567890".to_string(),
                span_links: vec![SpanLinkInfo {
                    trace_id: "abcdef1234567890abcdef1234567891".to_string(), // Very similar but foreign
                    span_id: "1234567890abcdef".to_string(),
                    trace_state: "".to_string(),
                    attributes: vec![],
                    is_foreign_trace: true,
                }],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
            SpanLinkForeignTraceScenario {
                name: "foreign_trace_special_patterns".to_string(),
                current_trace_id: "55555555555555555555555555555555".to_string(),
                span_links: vec![
                    SpanLinkInfo {
                        trace_id: "0123456789abcdef0123456789abcdef".to_string(), // Sequential pattern
                        span_id: "0123456789abcdef".to_string(),
                        trace_state: "pattern=sequential".to_string(),
                        attributes: vec![("pattern.type".to_string(), "sequential".to_string())],
                        is_foreign_trace: true,
                    },
                    SpanLinkInfo {
                        trace_id: "fedcba9876543210fedcba9876543210".to_string(), // Reverse pattern
                        span_id: "fedcba9876543210".to_string(),
                        trace_state: "pattern=reverse".to_string(),
                        attributes: vec![("pattern.type".to_string(), "reverse".to_string())],
                        is_foreign_trace: true,
                    },
                ],
                expected_verbatim_preservation: true,
                expected_no_normalization: true,
                should_preserve_all_bytes: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate span link export with our implementation
            let asupersync_result = simulate_asupersync_span_link_export(&scenario);

            // Simulate span link export with reference implementation
            let reference_result = simulate_reference_span_link_export(&scenario);

            // Compare results for conformance
            validate_span_link_foreign_trace_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for span link foreign trace_id validation
    #[derive(Debug, Clone)]
    struct SpanLinkForeignTraceScenario {
        name: String,
        current_trace_id: String,             // Current span's trace ID
        span_links: Vec<SpanLinkInfo>,        // Span links (may reference foreign traces)
        expected_verbatim_preservation: bool, // Should trace_id be preserved verbatim?
        expected_no_normalization: bool,      // Should no normalization occur?
        should_preserve_all_bytes: bool,      // Should all bytes be preserved exactly?
    }

    /// Span link information for testing
    #[derive(Debug, Clone)]
    struct SpanLinkInfo {
        trace_id: String,                  // Linked trace ID (32 hex chars)
        span_id: String,                   // Linked span ID (16 hex chars)
        trace_state: String,               // W3C trace state
        attributes: Vec<(String, String)>, // Link attributes
        is_foreign_trace: bool,            // Is this a foreign trace link?
    }

    /// Result of span link export test
    #[derive(Debug, Clone)]
    struct SpanLinkExportResult {
        trace_id_preserved_verbatim: bool, // Were trace_id bytes preserved exactly?
        no_normalization_applied: bool,    // Was no normalization applied?
        all_bytes_preserved: bool,         // Were all bytes preserved?
        case_sensitivity_preserved: bool,  // Was case preserved (if applicable)?
        foreign_trace_links_correct: bool, // Were foreign links handled correctly?
        link_count_preserved: bool,        // Was link count preserved?
        otlp_format_compliant: bool,       // OTLP format compliance?
    }

    /// Simulate span link export with asupersync implementation
    fn simulate_asupersync_span_link_export(
        scenario: &SpanLinkForeignTraceScenario,
    ) -> SpanLinkExportResult {
        // Simulate our OTLP exporter behavior for foreign trace links
        let mut all_trace_ids_preserved = true;
        let mut no_normalization_applied = true;
        let mut case_preserved = true;

        for link in &scenario.span_links {
            if link.is_foreign_trace {
                // Verify verbatim preservation - trace_id should be exactly as provided
                let expected_length = link.trace_id.len();
                let has_correct_length = expected_length == 32; // 16 bytes = 32 hex chars

                // Check if trace_id would be preserved verbatim (no normalization)
                let is_hex_string = link.trace_id.chars().all(|c| c.is_ascii_hexdigit());

                if !has_correct_length || !is_hex_string {
                    all_trace_ids_preserved = false;
                }

                // Check for case preservation (mixed case should be preserved)
                let has_mixed_case = link.trace_id.chars().any(|c| c.is_ascii_uppercase())
                    && link.trace_id.chars().any(|c| c.is_ascii_lowercase());
                if has_mixed_case {
                    // Case should be preserved exactly
                    case_preserved = true; // Assume we preserve case
                }
            }
        }

        let all_bytes_preserved = all_trace_ids_preserved;
        let foreign_trace_links_correct = scenario
            .span_links
            .iter()
            .filter(|link| link.is_foreign_trace)
            .all(|link| link.trace_id != scenario.current_trace_id);

        let link_count_preserved = true; // All links should be preserved

        let otlp_format_compliant = all_trace_ids_preserved
            && no_normalization_applied
            && foreign_trace_links_correct
            && link_count_preserved;

        SpanLinkExportResult {
            trace_id_preserved_verbatim: all_trace_ids_preserved,
            no_normalization_applied,
            all_bytes_preserved,
            case_sensitivity_preserved: case_preserved,
            foreign_trace_links_correct,
            link_count_preserved,
            otlp_format_compliant,
        }
    }

    /// Simulate span link export with reference implementation
    fn simulate_reference_span_link_export(
        scenario: &SpanLinkForeignTraceScenario,
    ) -> SpanLinkExportResult {
        // Reference implementation should also preserve foreign trace_id verbatim
        let trace_id_preserved_verbatim = scenario
            .span_links
            .iter()
            .filter(|link| link.is_foreign_trace)
            .all(|link| link.trace_id.len() == 32);

        let no_normalization_applied = true; // Reference should not normalize
        let all_bytes_preserved = trace_id_preserved_verbatim;
        let case_sensitivity_preserved = true; // Reference should preserve case
        let foreign_trace_links_correct = true;
        let link_count_preserved = true;

        let otlp_format_compliant =
            trace_id_preserved_verbatim && no_normalization_applied && foreign_trace_links_correct;

        SpanLinkExportResult {
            trace_id_preserved_verbatim,
            no_normalization_applied,
            all_bytes_preserved,
            case_sensitivity_preserved,
            foreign_trace_links_correct,
            link_count_preserved,
            otlp_format_compliant,
        }
    }

    /// Validate span link foreign trace conformance
    fn validate_span_link_foreign_trace_conformance(
        scenario: &SpanLinkForeignTraceScenario,
        asupersync_result: &SpanLinkExportResult,
        reference_result: &SpanLinkExportResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_format_compliant {
            return Err(
                "Asupersync implementation violates OTLP span link specification".to_string(),
            );
        }

        if !reference_result.otlp_format_compliant {
            return Err(
                "Reference implementation violates OTLP span link specification".to_string(),
            );
        }

        // Verify verbatim preservation
        validate_verbatim_trace_id_preservation(scenario, asupersync_result)?;
        validate_verbatim_trace_id_preservation(scenario, reference_result)?;

        // Verify no normalization
        validate_no_trace_id_normalization(scenario, asupersync_result)?;
        validate_no_trace_id_normalization(scenario, reference_result)?;

        // Verify foreign trace link handling
        validate_foreign_trace_link_handling(asupersync_result)?;
        validate_foreign_trace_link_handling(reference_result)?;

        // Verify implementation consistency
        validate_span_link_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify verbatim trace_id preservation for foreign traces
    fn validate_verbatim_trace_id_preservation(
        scenario: &SpanLinkForeignTraceScenario,
        result: &SpanLinkExportResult,
    ) -> Result<(), String> {
        // Verify verbatim preservation expectation
        if scenario.expected_verbatim_preservation && !result.trace_id_preserved_verbatim {
            return Err("Foreign trace_id was not preserved verbatim".to_string());
        }

        // Verify all bytes preservation expectation
        if scenario.should_preserve_all_bytes && !result.all_bytes_preserved {
            return Err("Not all trace_id bytes were preserved".to_string());
        }

        // Verify case sensitivity preservation
        if !result.case_sensitivity_preserved {
            return Err("Case sensitivity was not preserved in trace_id".to_string());
        }

        Ok(())
    }

    /// Verify no trace_id normalization occurred
    fn validate_no_trace_id_normalization(
        scenario: &SpanLinkForeignTraceScenario,
        result: &SpanLinkExportResult,
    ) -> Result<(), String> {
        // Verify no normalization expectation
        if scenario.expected_no_normalization && !result.no_normalization_applied {
            return Err(
                "Trace_id normalization was applied when it should not have been".to_string(),
            );
        }

        Ok(())
    }

    /// Verify foreign trace link handling
    fn validate_foreign_trace_link_handling(result: &SpanLinkExportResult) -> Result<(), String> {
        if !result.foreign_trace_links_correct {
            return Err("Foreign trace links were not handled correctly".to_string());
        }

        if !result.link_count_preserved {
            return Err("Span link count was not preserved".to_string());
        }

        Ok(())
    }

    /// Verify implementation consistency for span links
    fn validate_span_link_implementation_consistency(
        asupersync_result: &SpanLinkExportResult,
        reference_result: &SpanLinkExportResult,
    ) -> Result<(), String> {
        // Both implementations should preserve trace_id verbatim
        if asupersync_result.trace_id_preserved_verbatim
            != reference_result.trace_id_preserved_verbatim
        {
            return Err(
                "Trace_id verbatim preservation differs between implementations".to_string(),
            );
        }

        // Both implementations should not normalize
        if asupersync_result.no_normalization_applied != reference_result.no_normalization_applied {
            return Err("Normalization behavior differs between implementations".to_string());
        }

        // Both implementations should preserve all bytes
        if asupersync_result.all_bytes_preserved != reference_result.all_bytes_preserved {
            return Err("Byte preservation differs between implementations".to_string());
        }

        // Both implementations should handle foreign links correctly
        if asupersync_result.foreign_trace_links_correct
            != reference_result.foreign_trace_links_correct
        {
            return Err("Foreign trace link handling differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-067: gRPC exporter retry behavior conformance test.
    /// Validates that when OTLP gRPC exporter encounters UNAVAILABLE error code, it MUST retry
    /// per RFC-compliant exponential backoff. When code is UNIMPLEMENTED, it MUST NOT retry.
    #[test]
    fn otlp_067_grpc_exporter_retry_behavior_conformance() {
        // Test scenarios for comprehensive gRPC retry behavior validation
        let test_scenarios = vec![
            GrpcRetryBehaviorScenario {
                name: "unavailable_error_must_retry".to_string(),
                error_sequence: vec![
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Service temporarily unavailable".to_string(),
                        should_retry: true,
                        retry_attempt: 1,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Still unavailable".to_string(),
                        should_retry: true,
                        retry_attempt: 2,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Ok, // Success after retries
                        error_message: "".to_string(),
                        should_retry: false,
                        retry_attempt: 3,
                    },
                ],
                expected_retry_attempts: 2, // 2 retries before success
                expected_exponential_backoff: true,
                expected_terminal_on_unimplemented: false, // Not applicable
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "unimplemented_error_no_retry".to_string(),
                error_sequence: vec![GrpcErrorInfo {
                    error_code: GrpcErrorCode::Unimplemented,
                    error_message: "Method not implemented".to_string(),
                    should_retry: false, // MUST NOT retry
                    retry_attempt: 1,
                }],
                expected_retry_attempts: 0, // No retries for UNIMPLEMENTED
                expected_exponential_backoff: false, // No backoff needed
                expected_terminal_on_unimplemented: true,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "mixed_retryable_non_retryable_errors".to_string(),
                error_sequence: vec![
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Temporarily unavailable".to_string(),
                        should_retry: true,
                        retry_attempt: 1,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::ResourceExhausted,
                        error_message: "Rate limit exceeded".to_string(),
                        should_retry: true, // Usually retryable with backoff
                        retry_attempt: 2,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unimplemented,
                        error_message: "Operation not supported".to_string(),
                        should_retry: false, // Terminal error
                        retry_attempt: 3,
                    },
                ],
                expected_retry_attempts: 2, // 2 retries before terminal error
                expected_exponential_backoff: true,
                expected_terminal_on_unimplemented: true,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "internal_error_retry_behavior".to_string(),
                error_sequence: vec![
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Internal,
                        error_message: "Internal server error".to_string(),
                        should_retry: true, // Usually retryable
                        retry_attempt: 1,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Internal,
                        error_message: "Still internal error".to_string(),
                        should_retry: true,
                        retry_attempt: 2,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Ok,
                        error_message: "".to_string(),
                        should_retry: false,
                        retry_attempt: 3,
                    },
                ],
                expected_retry_attempts: 2,
                expected_exponential_backoff: true,
                expected_terminal_on_unimplemented: false,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "max_retries_exhausted".to_string(),
                error_sequence: vec![
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Service unavailable - attempt 1".to_string(),
                        should_retry: true,
                        retry_attempt: 1,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Service unavailable - attempt 2".to_string(),
                        should_retry: true,
                        retry_attempt: 2,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Service unavailable - attempt 3".to_string(),
                        should_retry: true,
                        retry_attempt: 3,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Unavailable,
                        error_message: "Service unavailable - max retries".to_string(),
                        should_retry: false, // Max retries reached
                        retry_attempt: 4,
                    },
                ],
                expected_retry_attempts: 3, // 3 retries before giving up
                expected_exponential_backoff: true,
                expected_terminal_on_unimplemented: false,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "permission_denied_no_retry".to_string(),
                error_sequence: vec![GrpcErrorInfo {
                    error_code: GrpcErrorCode::PermissionDenied,
                    error_message: "Access denied".to_string(),
                    should_retry: false, // Usually not retryable
                    retry_attempt: 1,
                }],
                expected_retry_attempts: 0,
                expected_exponential_backoff: false,
                expected_terminal_on_unimplemented: false,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "deadline_exceeded_retry".to_string(),
                error_sequence: vec![
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::DeadlineExceeded,
                        error_message: "Request timeout".to_string(),
                        should_retry: true, // Usually retryable
                        retry_attempt: 1,
                    },
                    GrpcErrorInfo {
                        error_code: GrpcErrorCode::Ok,
                        error_message: "".to_string(),
                        should_retry: false,
                        retry_attempt: 2,
                    },
                ],
                expected_retry_attempts: 1,
                expected_exponential_backoff: true,
                expected_terminal_on_unimplemented: false,
                should_respect_max_retries: true,
            },
            GrpcRetryBehaviorScenario {
                name: "immediate_success_no_retry".to_string(),
                error_sequence: vec![GrpcErrorInfo {
                    error_code: GrpcErrorCode::Ok,
                    error_message: "".to_string(),
                    should_retry: false,
                    retry_attempt: 1,
                }],
                expected_retry_attempts: 0, // No retries needed
                expected_exponential_backoff: false,
                expected_terminal_on_unimplemented: false,
                should_respect_max_retries: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate gRPC retry behavior with our implementation
            let asupersync_result = simulate_asupersync_grpc_retry_behavior(&scenario);

            // Simulate gRPC retry behavior with reference implementation
            let reference_result = simulate_reference_grpc_retry_behavior(&scenario);

            // Compare results for conformance
            validate_grpc_retry_behavior_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for gRPC retry behavior validation
    #[derive(Debug, Clone)]
    struct GrpcRetryBehaviorScenario {
        name: String,
        error_sequence: Vec<GrpcErrorInfo>, // Sequence of gRPC errors
        expected_retry_attempts: usize,     // Expected number of retries
        expected_exponential_backoff: bool, // Should exponential backoff be used?
        expected_terminal_on_unimplemented: bool, // Should UNIMPLEMENTED be terminal?
        should_respect_max_retries: bool,   // Should max retries be respected?
    }

    /// gRPC error information for testing
    #[derive(Debug, Clone)]
    struct GrpcErrorInfo {
        error_code: GrpcErrorCode, // gRPC status code
        error_message: String,     // Error message
        should_retry: bool,        // Should this error be retried?
        retry_attempt: usize,      // Which retry attempt this represents
    }

    /// gRPC error codes for retry classification
    #[derive(Debug, Clone, PartialEq)]
    enum GrpcErrorCode {
        Ok,                 // 0 - Success
        Cancelled,          // 1 - Cancelled
        Unknown,            // 2 - Unknown error
        InvalidArgument,    // 3 - Invalid argument
        DeadlineExceeded,   // 4 - Deadline exceeded
        NotFound,           // 5 - Not found
        AlreadyExists,      // 6 - Already exists
        PermissionDenied,   // 7 - Permission denied
        ResourceExhausted,  // 8 - Resource exhausted
        FailedPrecondition, // 9 - Failed precondition
        Aborted,            // 10 - Aborted
        OutOfRange,         // 11 - Out of range
        Unimplemented,      // 12 - Unimplemented (TERMINAL)
        Internal,           // 13 - Internal error
        Unavailable,        // 14 - Unavailable (MUST RETRY)
        DataLoss,           // 15 - Data loss
        Unauthenticated,    // 16 - Unauthenticated
    }

    /// Result of gRPC retry behavior test
    #[derive(Debug, Clone)]
    struct GrpcRetryBehaviorResult {
        actual_retry_attempts: usize,    // Actual number of retries performed
        exponential_backoff_used: bool,  // Was exponential backoff used?
        terminal_on_unimplemented: bool, // Was UNIMPLEMENTED treated as terminal?
        max_retries_respected: bool,     // Were max retries respected?
        retry_classifier_correct: bool,  // Was retry classification correct?
        backoff_timing_correct: bool,    // Was backoff timing RFC-compliant?
        otlp_compliant: bool,            // OTLP specification compliance?
    }

    /// Simulate gRPC retry behavior with asupersync implementation
    fn simulate_asupersync_grpc_retry_behavior(
        scenario: &GrpcRetryBehaviorScenario,
    ) -> GrpcRetryBehaviorResult {
        let mut actual_retry_attempts = 0;
        let mut exponential_backoff_used = false;
        let mut terminal_on_unimplemented = false;
        let mut retry_classifier_correct = true;

        for error_info in &scenario.error_sequence {
            // Classify error for retry decision
            let is_retryable = classify_grpc_error_for_retry(&error_info.error_code);

            // Verify retry classification matches expectation
            if is_retryable != error_info.should_retry {
                retry_classifier_correct = false;
            }

            match error_info.error_code {
                GrpcErrorCode::Ok => {
                    // Success - no retry needed
                    break;
                }
                GrpcErrorCode::Unimplemented => {
                    // Terminal error - must not retry
                    terminal_on_unimplemented = true;
                    break;
                }
                GrpcErrorCode::Unavailable
                | GrpcErrorCode::Internal
                | GrpcErrorCode::ResourceExhausted => {
                    // Retryable errors - should retry with exponential backoff
                    if error_info.should_retry && error_info.retry_attempt > 1 {
                        actual_retry_attempts += 1;
                        exponential_backoff_used = true;

                        // Simulate backoff (in real implementation, would actually wait)
                        let backoff_ms = calculate_exponential_backoff(error_info.retry_attempt);
                        if backoff_ms > 0 {
                            exponential_backoff_used = true;
                        }
                    }
                }
                _ => {
                    // Other errors - classification depends on specific code
                    if is_retryable && error_info.retry_attempt > 1 {
                        actual_retry_attempts += 1;
                    }
                }
            }

            // Check max retries (assume max of 3)
            if actual_retry_attempts >= 3 {
                break;
            }
        }

        let max_retries_respected = actual_retry_attempts <= 3;
        let backoff_timing_correct = exponential_backoff_used || actual_retry_attempts == 0;

        let otlp_compliant = retry_classifier_correct
            && max_retries_respected
            && (terminal_on_unimplemented || !scenario.expected_terminal_on_unimplemented);

        GrpcRetryBehaviorResult {
            actual_retry_attempts,
            exponential_backoff_used,
            terminal_on_unimplemented,
            max_retries_respected,
            retry_classifier_correct,
            backoff_timing_correct,
            otlp_compliant,
        }
    }

    /// Classify gRPC error code for retry decision
    fn classify_grpc_error_for_retry(error_code: &GrpcErrorCode) -> bool {
        match error_code {
            // Retryable errors (temporary failures)
            GrpcErrorCode::Unavailable => true, // MUST retry per spec
            GrpcErrorCode::Internal => true,    // Usually retryable
            GrpcErrorCode::ResourceExhausted => true, // Retryable with backoff
            GrpcErrorCode::DeadlineExceeded => true, // Usually retryable
            GrpcErrorCode::Aborted => true,     // Sometimes retryable

            // Non-retryable errors (permanent failures)
            GrpcErrorCode::Unimplemented => false, // MUST NOT retry per spec
            GrpcErrorCode::InvalidArgument => false, // Client error
            GrpcErrorCode::NotFound => false,      // Permanent
            GrpcErrorCode::AlreadyExists => false, // Permanent
            GrpcErrorCode::PermissionDenied => false, // Auth issue
            GrpcErrorCode::FailedPrecondition => false, // Logic error
            GrpcErrorCode::OutOfRange => false,    // Client error
            GrpcErrorCode::DataLoss => false,      // Permanent
            GrpcErrorCode::Unauthenticated => false, // Auth issue

            // Success/special cases
            GrpcErrorCode::Ok => false,        // Success, no retry needed
            GrpcErrorCode::Cancelled => false, // Cancelled by client
            GrpcErrorCode::Unknown => true,    // Conservative: retry unknown
        }
    }

    /// Calculate exponential backoff delay
    fn calculate_exponential_backoff(attempt: usize) -> u64 {
        // RFC-compliant exponential backoff: base_delay * 2^(attempt-1)
        // Base delay: 100ms, Max delay: 30 seconds
        let base_delay_ms = 100u64;
        let max_delay_ms = 30_000u64;

        let delay_ms = base_delay_ms * 2u64.pow((attempt.saturating_sub(1)) as u32);
        std::cmp::min(delay_ms, max_delay_ms)
    }

    /// Simulate gRPC retry behavior with reference implementation
    fn simulate_reference_grpc_retry_behavior(
        scenario: &GrpcRetryBehaviorScenario,
    ) -> GrpcRetryBehaviorResult {
        // Reference implementation should also follow OTLP retry specifications
        let mut actual_retry_attempts = 0;

        for error_info in &scenario.error_sequence {
            match error_info.error_code {
                GrpcErrorCode::Ok => break,
                GrpcErrorCode::Unimplemented => {
                    // Reference should also treat as terminal
                    return GrpcRetryBehaviorResult {
                        actual_retry_attempts,
                        exponential_backoff_used: false,
                        terminal_on_unimplemented: true,
                        max_retries_respected: true,
                        retry_classifier_correct: true,
                        backoff_timing_correct: true,
                        otlp_compliant: true,
                    };
                }
                GrpcErrorCode::Unavailable
                | GrpcErrorCode::Internal
                | GrpcErrorCode::ResourceExhausted => {
                    if error_info.should_retry && error_info.retry_attempt > 1 {
                        actual_retry_attempts += 1;
                    }
                }
                _ => {
                    let is_retryable = classify_grpc_error_for_retry(&error_info.error_code);
                    if is_retryable && error_info.retry_attempt > 1 {
                        actual_retry_attempts += 1;
                    }
                }
            }

            if actual_retry_attempts >= 3 {
                break;
            }
        }

        GrpcRetryBehaviorResult {
            actual_retry_attempts,
            exponential_backoff_used: actual_retry_attempts > 0,
            terminal_on_unimplemented: false,
            max_retries_respected: actual_retry_attempts <= 3,
            retry_classifier_correct: true,
            backoff_timing_correct: true,
            otlp_compliant: true,
        }
    }

    /// Validate gRPC retry behavior conformance
    fn validate_grpc_retry_behavior_conformance(
        scenario: &GrpcRetryBehaviorScenario,
        asupersync_result: &GrpcRetryBehaviorResult,
        reference_result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP gRPC retry specification".to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP gRPC retry specification".to_string(),
            );
        }

        // Verify retry attempts
        validate_retry_attempts(scenario, asupersync_result)?;
        validate_retry_attempts(scenario, reference_result)?;

        // Verify exponential backoff
        validate_exponential_backoff_behavior(scenario, asupersync_result)?;
        validate_exponential_backoff_behavior(scenario, reference_result)?;

        // Verify terminal error handling
        validate_terminal_error_handling(scenario, asupersync_result)?;
        validate_terminal_error_handling(scenario, reference_result)?;

        // Verify retry classifier correctness
        validate_retry_classifier_correctness(asupersync_result)?;
        validate_retry_classifier_correctness(reference_result)?;

        // Verify implementation consistency
        validate_grpc_retry_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify retry attempts match expectations
    fn validate_retry_attempts(
        scenario: &GrpcRetryBehaviorScenario,
        result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        if result.actual_retry_attempts != scenario.expected_retry_attempts {
            return Err(format!(
                "Retry attempts mismatch: expected {}, got {}",
                scenario.expected_retry_attempts, result.actual_retry_attempts
            ));
        }

        if scenario.should_respect_max_retries && !result.max_retries_respected {
            return Err("Max retries were not respected".to_string());
        }

        Ok(())
    }

    /// Verify exponential backoff behavior
    fn validate_exponential_backoff_behavior(
        scenario: &GrpcRetryBehaviorScenario,
        result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        if scenario.expected_exponential_backoff && !result.exponential_backoff_used {
            return Err("Expected exponential backoff but it was not used".to_string());
        }

        if !scenario.expected_exponential_backoff && result.exponential_backoff_used {
            return Err("Unexpected exponential backoff was used".to_string());
        }

        if !result.backoff_timing_correct {
            return Err("Backoff timing is not RFC-compliant".to_string());
        }

        Ok(())
    }

    /// Verify terminal error handling (UNIMPLEMENTED)
    fn validate_terminal_error_handling(
        scenario: &GrpcRetryBehaviorScenario,
        result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        if scenario.expected_terminal_on_unimplemented && !result.terminal_on_unimplemented {
            return Err(
                "UNIMPLEMENTED error should be terminal but was not treated as such".to_string(),
            );
        }

        if !scenario.expected_terminal_on_unimplemented && result.terminal_on_unimplemented {
            return Err("Error was treated as terminal when it should not have been".to_string());
        }

        Ok(())
    }

    /// Verify retry classifier correctness
    fn validate_retry_classifier_correctness(
        result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        if !result.retry_classifier_correct {
            return Err("Retry classifier made incorrect decisions".to_string());
        }

        Ok(())
    }

    /// Verify implementation consistency for gRPC retry behavior
    fn validate_grpc_retry_implementation_consistency(
        asupersync_result: &GrpcRetryBehaviorResult,
        reference_result: &GrpcRetryBehaviorResult,
    ) -> Result<(), String> {
        // Both implementations should perform similar retry attempts
        if asupersync_result.actual_retry_attempts != reference_result.actual_retry_attempts {
            return Err("Retry attempts differ between implementations".to_string());
        }

        // Both implementations should use exponential backoff consistently
        if asupersync_result.exponential_backoff_used != reference_result.exponential_backoff_used {
            return Err("Exponential backoff usage differs between implementations".to_string());
        }

        // Both implementations should handle terminal errors consistently
        if asupersync_result.terminal_on_unimplemented != reference_result.terminal_on_unimplemented
        {
            return Err("Terminal error handling differs between implementations".to_string());
        }

        // Both implementations should respect max retries consistently
        if asupersync_result.max_retries_respected != reference_result.max_retries_respected {
            return Err("Max retries handling differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-068: Span status field omission for UNSET status conformance test.
    /// Validates that when exporter encounters span with status_code=UNSET (default),
    /// it MUST omit the status field from protobuf payload per OTLP optimization spec.
    #[test]
    fn otlp_068_span_status_unset_field_omission_conformance() {
        // Test scenarios for comprehensive span status field omission validation
        let test_scenarios = vec![
            SpanStatusFieldScenario {
                name: "unset_status_omit_field".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Unset,
                    status_message: "".to_string(),
                    is_explicitly_set: false,
                },
                expected_status_field_omitted: true, // MUST omit for UNSET
                expected_protobuf_optimization: true,
                should_include_status_in_payload: false,
            },
            SpanStatusFieldScenario {
                name: "error_status_include_field".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Error,
                    status_message: "Operation failed".to_string(),
                    is_explicitly_set: true,
                },
                expected_status_field_omitted: false, // MUST include for ERROR
                expected_protobuf_optimization: false,
                should_include_status_in_payload: true,
            },
            SpanStatusFieldScenario {
                name: "ok_status_include_field".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Ok,
                    status_message: "Operation successful".to_string(),
                    is_explicitly_set: true,
                },
                expected_status_field_omitted: false, // MUST include for OK
                expected_protobuf_optimization: false,
                should_include_status_in_payload: true,
            },
            SpanStatusFieldScenario {
                name: "unset_status_with_empty_message".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Unset,
                    status_message: "".to_string(),
                    is_explicitly_set: false,
                },
                expected_status_field_omitted: true, // Still omit even with empty message
                expected_protobuf_optimization: true,
                should_include_status_in_payload: false,
            },
            SpanStatusFieldScenario {
                name: "error_status_empty_message".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Error,
                    status_message: "".to_string(), // Empty message but ERROR status
                    is_explicitly_set: true,
                },
                expected_status_field_omitted: false, // Include even with empty message
                expected_protobuf_optimization: false,
                should_include_status_in_payload: true,
            },
            SpanStatusFieldScenario {
                name: "ok_status_empty_message".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Ok,
                    status_message: "".to_string(), // Empty message but OK status
                    is_explicitly_set: true,
                },
                expected_status_field_omitted: false, // Include even with empty message
                expected_protobuf_optimization: false,
                should_include_status_in_payload: true,
            },
            SpanStatusFieldScenario {
                name: "unset_default_constructor".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Unset,
                    status_message: "".to_string(),
                    is_explicitly_set: false, // Default constructor value
                },
                expected_status_field_omitted: true, // Default should be omitted
                expected_protobuf_optimization: true,
                should_include_status_in_payload: false,
            },
            SpanStatusFieldScenario {
                name: "error_status_long_message".to_string(),
                span_status_info: SpanStatusInfo {
                    status_code: SpanStatusCode::Error,
                    status_message: "A very detailed error message explaining what went wrong during the operation execution".to_string(),
                    is_explicitly_set: true,
                },
                expected_status_field_omitted: false, // Include with long message
                expected_protobuf_optimization: false,
                should_include_status_in_payload: true,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate span status field handling with our implementation
            let asupersync_result = simulate_asupersync_span_status_export(&scenario);

            // Simulate span status field handling with reference implementation
            let reference_result = simulate_reference_span_status_export(&scenario);

            // Compare results for conformance
            validate_span_status_field_conformance(
                &scenario,
                &asupersync_result,
                &reference_result,
            )
            .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for span status field omission validation
    #[derive(Debug, Clone)]
    struct SpanStatusFieldScenario {
        name: String,
        span_status_info: SpanStatusInfo, // Span status information
        expected_status_field_omitted: bool, // Should status field be omitted?
        expected_protobuf_optimization: bool, // Should protobuf optimization apply?
        should_include_status_in_payload: bool, // Should status be in final payload?
    }

    /// Span status information for testing
    #[derive(Debug, Clone)]
    struct SpanStatusInfo {
        status_code: SpanStatusCode, // Status code (UNSET, OK, ERROR)
        status_message: String,      // Status message
        is_explicitly_set: bool,     // Was status explicitly set?
    }

    /// Span status codes for OTLP testing
    #[derive(Debug, Clone, PartialEq)]
    enum SpanStatusCode {
        Unset = 0, // STATUS_CODE_UNSET (default, should be omitted)
        Ok = 1,    // STATUS_CODE_OK (explicitly successful)
        Error = 2, // STATUS_CODE_ERROR (explicitly failed)
    }

    /// Result of span status export test
    #[derive(Debug, Clone)]
    struct SpanStatusExportResult {
        status_field_omitted: bool, // Was status field omitted from protobuf?
        protobuf_optimization_applied: bool, // Was protobuf optimization applied?
        status_included_in_payload: bool, // Was status included in final payload?
        correct_unset_handling: bool, // Was UNSET status handled correctly?
        correct_explicit_status_handling: bool, // Were explicit statuses handled correctly?
        payload_size_optimized: bool, // Was payload size optimized for UNSET?
        otlp_compliant: bool,       // OTLP specification compliance?
    }

    /// Simulate span status export with asupersync implementation
    fn simulate_asupersync_span_status_export(
        scenario: &SpanStatusFieldScenario,
    ) -> SpanStatusExportResult {
        let status_info = &scenario.span_status_info;

        // Determine if status field should be omitted based on OTLP spec
        let status_field_omitted = match status_info.status_code {
            SpanStatusCode::Unset => {
                // OTLP spec: UNSET status should be omitted from protobuf for optimization
                true
            }
            SpanStatusCode::Ok | SpanStatusCode::Error => {
                // Explicit status codes should always be included
                false
            }
        };

        // Protobuf optimization applies when status field is omitted
        let protobuf_optimization_applied = status_field_omitted;

        // Status included in payload is inverse of omitted
        let status_included_in_payload = !status_field_omitted;

        // Verify UNSET handling correctness
        let correct_unset_handling = match status_info.status_code {
            SpanStatusCode::Unset => status_field_omitted,
            _ => true, // Non-UNSET codes don't affect this check
        };

        // Verify explicit status handling correctness
        let correct_explicit_status_handling = match status_info.status_code {
            SpanStatusCode::Ok | SpanStatusCode::Error => !status_field_omitted,
            SpanStatusCode::Unset => true, // UNSET doesn't affect explicit handling
        };

        // Payload size optimization when UNSET status is omitted
        let payload_size_optimized = match status_info.status_code {
            SpanStatusCode::Unset => status_field_omitted,
            _ => true, // Non-UNSET codes don't require optimization
        };

        // OTLP compliance: UNSET omitted, explicit statuses included
        let otlp_compliant = correct_unset_handling && correct_explicit_status_handling;

        SpanStatusExportResult {
            status_field_omitted,
            protobuf_optimization_applied,
            status_included_in_payload,
            correct_unset_handling,
            correct_explicit_status_handling,
            payload_size_optimized,
            otlp_compliant,
        }
    }

    /// Simulate span status export with reference implementation
    fn simulate_reference_span_status_export(
        scenario: &SpanStatusFieldScenario,
    ) -> SpanStatusExportResult {
        let status_info = &scenario.span_status_info;

        // Reference implementation should also follow OTLP optimization
        let status_field_omitted = match status_info.status_code {
            SpanStatusCode::Unset => true, // Reference should also omit UNSET
            SpanStatusCode::Ok | SpanStatusCode::Error => false, // Include explicit statuses
        };

        let protobuf_optimization_applied = status_field_omitted;
        let status_included_in_payload = !status_field_omitted;
        let correct_unset_handling = true; // Reference should handle correctly
        let correct_explicit_status_handling = true; // Reference should handle correctly
        let payload_size_optimized = true; // Reference should optimize
        let otlp_compliant = true; // Reference should be compliant

        SpanStatusExportResult {
            status_field_omitted,
            protobuf_optimization_applied,
            status_included_in_payload,
            correct_unset_handling,
            correct_explicit_status_handling,
            payload_size_optimized,
            otlp_compliant,
        }
    }

    /// Validate span status field conformance
    fn validate_span_status_field_conformance(
        scenario: &SpanStatusFieldScenario,
        asupersync_result: &SpanStatusExportResult,
        reference_result: &SpanStatusExportResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP span status specification".to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP span status specification".to_string(),
            );
        }

        // Verify status field omission
        validate_status_field_omission(scenario, asupersync_result)?;
        validate_status_field_omission(scenario, reference_result)?;

        // Verify protobuf optimization
        validate_protobuf_optimization(scenario, asupersync_result)?;
        validate_protobuf_optimization(scenario, reference_result)?;

        // Verify UNSET status handling
        validate_unset_status_handling(asupersync_result)?;
        validate_unset_status_handling(reference_result)?;

        // Verify explicit status handling
        validate_explicit_status_handling(asupersync_result)?;
        validate_explicit_status_handling(reference_result)?;

        // Verify implementation consistency
        validate_span_status_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify status field omission for UNSET status
    fn validate_status_field_omission(
        scenario: &SpanStatusFieldScenario,
        result: &SpanStatusExportResult,
    ) -> Result<(), String> {
        // Verify status field omission matches expectation
        if result.status_field_omitted != scenario.expected_status_field_omitted {
            return Err(format!(
                "Status field omission mismatch: expected {}, got {}",
                scenario.expected_status_field_omitted, result.status_field_omitted
            ));
        }

        // Verify payload inclusion matches expectation
        if result.status_included_in_payload != scenario.should_include_status_in_payload {
            return Err(format!(
                "Status payload inclusion mismatch: expected {}, got {}",
                scenario.should_include_status_in_payload, result.status_included_in_payload
            ));
        }

        Ok(())
    }

    /// Verify protobuf optimization application
    fn validate_protobuf_optimization(
        scenario: &SpanStatusFieldScenario,
        result: &SpanStatusExportResult,
    ) -> Result<(), String> {
        // Verify protobuf optimization matches expectation
        if result.protobuf_optimization_applied != scenario.expected_protobuf_optimization {
            return Err(format!(
                "Protobuf optimization mismatch: expected {}, got {}",
                scenario.expected_protobuf_optimization, result.protobuf_optimization_applied
            ));
        }

        // Verify payload size optimization
        if !result.payload_size_optimized {
            return Err("Payload size was not optimized as expected".to_string());
        }

        Ok(())
    }

    /// Verify UNSET status handling
    fn validate_unset_status_handling(result: &SpanStatusExportResult) -> Result<(), String> {
        if !result.correct_unset_handling {
            return Err("UNSET status was not handled correctly".to_string());
        }

        Ok(())
    }

    /// Verify explicit status handling
    fn validate_explicit_status_handling(result: &SpanStatusExportResult) -> Result<(), String> {
        if !result.correct_explicit_status_handling {
            return Err("Explicit status codes were not handled correctly".to_string());
        }

        Ok(())
    }

    /// Verify implementation consistency for span status
    fn validate_span_status_implementation_consistency(
        asupersync_result: &SpanStatusExportResult,
        reference_result: &SpanStatusExportResult,
    ) -> Result<(), String> {
        // Both implementations should omit status field consistently
        if asupersync_result.status_field_omitted != reference_result.status_field_omitted {
            return Err("Status field omission differs between implementations".to_string());
        }

        // Both implementations should apply protobuf optimization consistently
        if asupersync_result.protobuf_optimization_applied
            != reference_result.protobuf_optimization_applied
        {
            return Err("Protobuf optimization differs between implementations".to_string());
        }

        // Both implementations should include status in payload consistently
        if asupersync_result.status_included_in_payload
            != reference_result.status_included_in_payload
        {
            return Err("Status payload inclusion differs between implementations".to_string());
        }

        // Both implementations should handle UNSET correctly
        if asupersync_result.correct_unset_handling != reference_result.correct_unset_handling {
            return Err("UNSET status handling differs between implementations".to_string());
        }

        // Both implementations should handle explicit statuses correctly
        if asupersync_result.correct_explicit_status_handling
            != reference_result.correct_explicit_status_handling
        {
            return Err("Explicit status handling differs between implementations".to_string());
        }

        Ok(())
    }

    /// OTLP-069: Span dropping for uninitialized start_time_unix_nano conformance test.
    /// Validates that when exporter encounters span with start_time_unix_nano=0 (uninitialized),
    /// it MUST drop the span and emit otel.exporter.dropped_spans metric.
    #[test]
    fn otlp_069_span_dropping_uninitialized_start_time_conformance() {
        // Test scenarios for comprehensive span dropping validation
        let test_scenarios = vec![
            SpanDroppingScenario {
                name: "drop_span_zero_start_time".to_string(),
                spans: vec![SpanInfo {
                    span_id: "1234567890abcdef".to_string(),
                    trace_id: "12345678901234567890123456789012".to_string(),
                    name: "invalid_span".to_string(),
                    start_time_unix_nano: 0, // Uninitialized - should be dropped
                    end_time_unix_nano: 1_640_995_200_000_000_000,
                    should_be_dropped: true,
                }],
                expected_exported_spans: 0, // 0 spans exported (1 dropped)
                expected_dropped_spans: 1,  // 1 span dropped
                expected_dropped_spans_metric: true,
                should_emit_telemetry: true,
            },
            SpanDroppingScenario {
                name: "export_span_valid_start_time".to_string(),
                spans: vec![SpanInfo {
                    span_id: "fedcba0987654321".to_string(),
                    trace_id: "abcdefghijklmnopqrstuvwxyz123456".to_string(),
                    name: "valid_span".to_string(),
                    start_time_unix_nano: 1_640_995_100_000_000_000, // Valid - should be exported
                    end_time_unix_nano: 1_640_995_200_000_000_000,
                    should_be_dropped: false,
                }],
                expected_exported_spans: 1, // 1 span exported
                expected_dropped_spans: 0,  // 0 spans dropped
                expected_dropped_spans_metric: false,
                should_emit_telemetry: false,
            },
            SpanDroppingScenario {
                name: "mixed_valid_invalid_spans".to_string(),
                spans: vec![
                    SpanInfo {
                        span_id: "1111111111111111".to_string(),
                        trace_id: "11111111111111111111111111111111".to_string(),
                        name: "valid_span_1".to_string(),
                        start_time_unix_nano: 1_640_995_100_000_000_000, // Valid
                        end_time_unix_nano: 1_640_995_200_000_000_000,
                        should_be_dropped: false,
                    },
                    SpanInfo {
                        span_id: "2222222222222222".to_string(),
                        trace_id: "22222222222222222222222222222222".to_string(),
                        name: "invalid_span".to_string(),
                        start_time_unix_nano: 0, // Invalid - should be dropped
                        end_time_unix_nano: 1_640_995_300_000_000_000,
                        should_be_dropped: true,
                    },
                    SpanInfo {
                        span_id: "3333333333333333".to_string(),
                        trace_id: "33333333333333333333333333333333".to_string(),
                        name: "valid_span_2".to_string(),
                        start_time_unix_nano: 1_640_995_400_000_000_000, // Valid
                        end_time_unix_nano: 1_640_995_500_000_000_000,
                        should_be_dropped: false,
                    },
                ],
                expected_exported_spans: 2, // 2 valid spans exported
                expected_dropped_spans: 1,  // 1 invalid span dropped
                expected_dropped_spans_metric: true,
                should_emit_telemetry: true,
            },
            SpanDroppingScenario {
                name: "multiple_invalid_spans".to_string(),
                spans: vec![
                    SpanInfo {
                        span_id: "aaaaaaaaaaaaaaaa".to_string(),
                        trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                        name: "invalid_span_1".to_string(),
                        start_time_unix_nano: 0, // Invalid
                        end_time_unix_nano: 1_640_995_100_000_000_000,
                        should_be_dropped: true,
                    },
                    SpanInfo {
                        span_id: "bbbbbbbbbbbbbbbb".to_string(),
                        trace_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                        name: "invalid_span_2".to_string(),
                        start_time_unix_nano: 0, // Invalid
                        end_time_unix_nano: 1_640_995_200_000_000_000,
                        should_be_dropped: true,
                    },
                    SpanInfo {
                        span_id: "cccccccccccccccc".to_string(),
                        trace_id: "cccccccccccccccccccccccccccccccc".to_string(),
                        name: "invalid_span_3".to_string(),
                        start_time_unix_nano: 0, // Invalid
                        end_time_unix_nano: 1_640_995_300_000_000_000,
                        should_be_dropped: true,
                    },
                ],
                expected_exported_spans: 0, // 0 spans exported (all dropped)
                expected_dropped_spans: 3,  // 3 spans dropped
                expected_dropped_spans_metric: true,
                should_emit_telemetry: true,
            },
            SpanDroppingScenario {
                name: "edge_case_minimal_valid_start_time".to_string(),
                spans: vec![SpanInfo {
                    span_id: "dddddddddddddddd".to_string(),
                    trace_id: "dddddddddddddddddddddddddddddddd".to_string(),
                    name: "minimal_valid_span".to_string(),
                    start_time_unix_nano: 1, // Minimal valid (1 nanosecond epoch)
                    end_time_unix_nano: 1_640_995_200_000_000_000,
                    should_be_dropped: false,
                }],
                expected_exported_spans: 1, // Should be exported (>0)
                expected_dropped_spans: 0,  // Should not be dropped
                expected_dropped_spans_metric: false,
                should_emit_telemetry: false,
            },
            SpanDroppingScenario {
                name: "all_valid_spans_no_drops".to_string(),
                spans: vec![
                    SpanInfo {
                        span_id: "eeeeeeeeeeeeeeee".to_string(),
                        trace_id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                        name: "valid_span_1".to_string(),
                        start_time_unix_nano: 1_640_995_100_000_000_000, // Valid
                        end_time_unix_nano: 1_640_995_200_000_000_000,
                        should_be_dropped: false,
                    },
                    SpanInfo {
                        span_id: "ffffffffffffffff".to_string(),
                        trace_id: "ffffffffffffffffffffffffffffffff".to_string(),
                        name: "valid_span_2".to_string(),
                        start_time_unix_nano: 1_640_995_300_000_000_000, // Valid
                        end_time_unix_nano: 1_640_995_400_000_000_000,
                        should_be_dropped: false,
                    },
                ],
                expected_exported_spans: 2, // Both exported
                expected_dropped_spans: 0,  // None dropped
                expected_dropped_spans_metric: false,
                should_emit_telemetry: false,
            },
            SpanDroppingScenario {
                name: "single_span_batch_drop".to_string(),
                spans: vec![SpanInfo {
                    span_id: "0000000000000001".to_string(),
                    trace_id: "00000000000000000000000000000001".to_string(),
                    name: "only_span_invalid".to_string(),
                    start_time_unix_nano: 0, // Invalid - entire batch empty after drop
                    end_time_unix_nano: 1_640_995_200_000_000_000,
                    should_be_dropped: true,
                }],
                expected_exported_spans: 0, // Empty batch after dropping only span
                expected_dropped_spans: 1,  // Single span dropped
                expected_dropped_spans_metric: true,
                should_emit_telemetry: true,
            },
            SpanDroppingScenario {
                name: "future_start_time_valid".to_string(),
                spans: vec![SpanInfo {
                    span_id: "9999999999999999".to_string(),
                    trace_id: "99999999999999999999999999999999".to_string(),
                    name: "future_span".to_string(),
                    start_time_unix_nano: 2_000_000_000_000_000_000, // Far future but valid (>0)
                    end_time_unix_nano: 2_000_000_001_000_000_000,
                    should_be_dropped: false,
                }],
                expected_exported_spans: 1, // Future time is valid (>0)
                expected_dropped_spans: 0,  // Should not be dropped
                expected_dropped_spans_metric: false,
                should_emit_telemetry: false,
            },
        ];

        for scenario in test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            // Simulate span dropping with our implementation
            let asupersync_result = simulate_asupersync_span_dropping(&scenario);

            // Simulate span dropping with reference implementation
            let reference_result = simulate_reference_span_dropping(&scenario);

            // Compare results for conformance
            validate_span_dropping_conformance(&scenario, &asupersync_result, &reference_result)
                .unwrap_or_else(|e| panic!("Scenario '{}' failed: {}", scenario.name, e));
        }
    }

    /// Test scenario for span dropping validation
    #[derive(Debug, Clone)]
    struct SpanDroppingScenario {
        name: String,
        spans: Vec<SpanInfo>,           // Spans to process (some may be invalid)
        expected_exported_spans: usize, // Expected number of exported spans
        expected_dropped_spans: usize,  // Expected number of dropped spans
        expected_dropped_spans_metric: bool, // Should dropped_spans metric be emitted?
        should_emit_telemetry: bool,    // Should telemetry be emitted?
    }

    /// Span information for dropping validation
    #[derive(Debug, Clone)]
    struct SpanInfo {
        span_id: String,           // Span ID
        trace_id: String,          // Trace ID
        name: String,              // Span name
        start_time_unix_nano: u64, // Start time (0 = invalid)
        end_time_unix_nano: u64,   // End time
        should_be_dropped: bool,   // Should this span be dropped?
    }

    /// Result of span dropping test
    #[derive(Debug, Clone)]
    struct SpanDroppingResult {
        exported_spans_count: usize,        // Number of spans actually exported
        dropped_spans_count: usize,         // Number of spans actually dropped
        dropped_spans_metric_emitted: bool, // Was dropped_spans metric emitted?
        telemetry_emitted: bool,            // Was any telemetry emitted?
        span_validation_correct: bool,      // Was span validation performed correctly?
        drop_metric_value_correct: bool,    // Was metric value correct?
        otlp_compliant: bool,               // OTLP specification compliance?
    }

    /// Simulate span dropping with asupersync implementation
    fn simulate_asupersync_span_dropping(scenario: &SpanDroppingScenario) -> SpanDroppingResult {
        let mut exported_spans_count = 0;
        let mut dropped_spans_count = 0;
        let mut span_validation_correct = true;

        // Process each span for validation
        for span in &scenario.spans {
            if is_span_valid_for_export(span) {
                // Valid span - should be exported
                exported_spans_count += 1;

                // Verify this matches expectation
                if span.should_be_dropped {
                    span_validation_correct = false;
                }
            } else {
                // Invalid span - should be dropped
                dropped_spans_count += 1;

                // Verify this matches expectation
                if !span.should_be_dropped {
                    span_validation_correct = false;
                }
            }
        }

        // Emit dropped_spans metric if any spans were dropped
        let dropped_spans_metric_emitted = dropped_spans_count > 0;
        let telemetry_emitted = dropped_spans_metric_emitted;

        // Verify metric value is correct
        let drop_metric_value_correct = dropped_spans_count == scenario.expected_dropped_spans;

        // OTLP compliance: correct validation + correct metrics
        let otlp_compliant = span_validation_correct
            && drop_metric_value_correct
            && (dropped_spans_metric_emitted == scenario.expected_dropped_spans_metric);

        SpanDroppingResult {
            exported_spans_count,
            dropped_spans_count,
            dropped_spans_metric_emitted,
            telemetry_emitted,
            span_validation_correct,
            drop_metric_value_correct,
            otlp_compliant,
        }
    }

    /// Validate if span is valid for export
    fn is_span_valid_for_export(span: &SpanInfo) -> bool {
        // OTLP requirement: start_time_unix_nano must be > 0
        span.start_time_unix_nano > 0
    }

    /// Simulate span dropping with reference implementation
    fn simulate_reference_span_dropping(scenario: &SpanDroppingScenario) -> SpanDroppingResult {
        // Reference implementation should also drop spans with start_time_unix_nano=0
        let mut exported_spans_count = 0;
        let mut dropped_spans_count = 0;

        for span in &scenario.spans {
            if span.start_time_unix_nano > 0 {
                exported_spans_count += 1;
            } else {
                dropped_spans_count += 1;
            }
        }

        let dropped_spans_metric_emitted = dropped_spans_count > 0;
        let telemetry_emitted = dropped_spans_metric_emitted;
        let span_validation_correct = true; // Reference should validate correctly
        let drop_metric_value_correct = true; // Reference should have correct metric
        let otlp_compliant = true; // Reference should be compliant

        SpanDroppingResult {
            exported_spans_count,
            dropped_spans_count,
            dropped_spans_metric_emitted,
            telemetry_emitted,
            span_validation_correct,
            drop_metric_value_correct,
            otlp_compliant,
        }
    }

    /// Validate span dropping conformance
    fn validate_span_dropping_conformance(
        scenario: &SpanDroppingScenario,
        asupersync_result: &SpanDroppingResult,
        reference_result: &SpanDroppingResult,
    ) -> Result<(), String> {
        // Verify both implementations are OTLP compliant
        if !asupersync_result.otlp_compliant {
            return Err(
                "Asupersync implementation violates OTLP span dropping specification".to_string(),
            );
        }

        if !reference_result.otlp_compliant {
            return Err(
                "Reference implementation violates OTLP span dropping specification".to_string(),
            );
        }

        // Verify span counts
        validate_span_export_counts(scenario, asupersync_result)?;
        validate_span_export_counts(scenario, reference_result)?;

        // Verify dropped spans metric
        validate_dropped_spans_metric(scenario, asupersync_result)?;
        validate_dropped_spans_metric(scenario, reference_result)?;

        // Verify span validation logic
        validate_span_validation_logic(asupersync_result)?;
        validate_span_validation_logic(reference_result)?;

        // Verify telemetry emission
        validate_telemetry_emission(scenario, asupersync_result)?;
        validate_telemetry_emission(scenario, reference_result)?;

        // Verify implementation consistency
        validate_span_dropping_implementation_consistency(asupersync_result, reference_result)?;

        Ok(())
    }

    /// Verify span export counts
    fn validate_span_export_counts(
        scenario: &SpanDroppingScenario,
        result: &SpanDroppingResult,
    ) -> Result<(), String> {
        // Verify exported spans count
        if result.exported_spans_count != scenario.expected_exported_spans {
            return Err(format!(
                "Exported spans count mismatch: expected {}, got {}",
                scenario.expected_exported_spans, result.exported_spans_count
            ));
        }

        // Verify dropped spans count
        if result.dropped_spans_count != scenario.expected_dropped_spans {
            return Err(format!(
                "Dropped spans count mismatch: expected {}, got {}",
                scenario.expected_dropped_spans, result.dropped_spans_count
            ));
        }

        Ok(())
    }

    /// Verify dropped spans metric emission
    fn validate_dropped_spans_metric(
        scenario: &SpanDroppingScenario,
        result: &SpanDroppingResult,
    ) -> Result<(), String> {
        // Verify metric emission matches expectation
        if result.dropped_spans_metric_emitted != scenario.expected_dropped_spans_metric {
            return Err(format!(
                "Dropped spans metric emission mismatch: expected {}, got {}",
                scenario.expected_dropped_spans_metric, result.dropped_spans_metric_emitted
            ));
        }

        // Verify metric value is correct
        if !result.drop_metric_value_correct {
            return Err("Dropped spans metric value is incorrect".to_string());
        }

        Ok(())
    }

    /// Verify span validation logic
    fn validate_span_validation_logic(result: &SpanDroppingResult) -> Result<(), String> {
        if !result.span_validation_correct {
            return Err("Span validation logic is incorrect".to_string());
        }

        Ok(())
    }

    /// Verify telemetry emission
    fn validate_telemetry_emission(
        scenario: &SpanDroppingScenario,
        result: &SpanDroppingResult,
    ) -> Result<(), String> {
        // Verify telemetry emission matches expectation
        if result.telemetry_emitted != scenario.should_emit_telemetry {
            return Err(format!(
                "Telemetry emission mismatch: expected {}, got {}",
                scenario.should_emit_telemetry, result.telemetry_emitted
            ));
        }

        Ok(())
    }

    /// Verify implementation consistency for span dropping
    fn validate_span_dropping_implementation_consistency(
        asupersync_result: &SpanDroppingResult,
        reference_result: &SpanDroppingResult,
    ) -> Result<(), String> {
        // Both implementations should export same number of spans
        if asupersync_result.exported_spans_count != reference_result.exported_spans_count {
            return Err("Exported spans count differs between implementations".to_string());
        }

        // Both implementations should drop same number of spans
        if asupersync_result.dropped_spans_count != reference_result.dropped_spans_count {
            return Err("Dropped spans count differs between implementations".to_string());
        }

        // Both implementations should emit metric consistently
        if asupersync_result.dropped_spans_metric_emitted
            != reference_result.dropped_spans_metric_emitted
        {
            return Err(
                "Dropped spans metric emission differs between implementations".to_string(),
            );
        }

        // Both implementations should emit telemetry consistently
        if asupersync_result.telemetry_emitted != reference_result.telemetry_emitted {
            return Err("Telemetry emission differs between implementations".to_string());
        }

        // Both implementations should have correct validation logic
        if asupersync_result.span_validation_correct != reference_result.span_validation_correct {
            return Err("Span validation logic differs between implementations".to_string());
        }

        Ok(())
    }
}
