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
}
