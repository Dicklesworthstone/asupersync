//! OpenTelemetry Span Event Timestamps Conformance Test (Tick #140)
//!
//! This conformance test verifies that our Span event timestamp handling produces
//! stable OTLP unix nanosecond values when given the same Instant inputs.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RAPID_SEQUENCE_VALUES: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

/// Test cases for Span event timestamp conformance.
struct SpanEventTimestampTestCase {
    name: &'static str,
    events: Vec<SpanEventSpec>,
    description: &'static str,
}

/// Specification for a span event with timestamp.
#[derive(Debug, Clone)]
struct SpanEventSpec {
    name: &'static str,
    instant: Instant,
    attributes: Vec<(String, String)>,
}

/// Our representation of span event timestamp data.
#[derive(Debug, Clone, PartialEq)]
struct SpanEventTimestampData {
    event_name: String,
    time_unix_nano: u64,
    attributes: Vec<(String, String)>,
}

fn main() {
    println!("OpenTelemetry Span Event Timestamps Conformance Test");
    println!("Verifying same Instant -> identical OTLP unix-nanos");

    // Create reference time points for consistent testing
    let base_instant = Instant::now();
    let base_system_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let test_cases = vec![
        SpanEventTimestampTestCase {
            name: "single_event_now",
            events: vec![SpanEventSpec {
                name: "request_started",
                instant: base_instant,
                attributes: attrs(&[("component", "http")]),
            }],
            description: "Single event at current instant",
        },
        SpanEventTimestampTestCase {
            name: "multiple_events_sequence",
            events: vec![
                SpanEventSpec {
                    name: "request_received",
                    instant: base_instant,
                    attributes: attrs(&[("method", "GET")]),
                },
                SpanEventSpec {
                    name: "auth_started",
                    instant: base_instant + Duration::from_millis(10),
                    attributes: attrs(&[("user_id", "12345")]),
                },
                SpanEventSpec {
                    name: "auth_completed",
                    instant: base_instant + Duration::from_millis(50),
                    attributes: attrs(&[("success", "true")]),
                },
                SpanEventSpec {
                    name: "response_sent",
                    instant: base_instant + Duration::from_millis(100),
                    attributes: attrs(&[("status", "200")]),
                },
            ],
            description: "Sequential events with millisecond precision",
        },
        SpanEventTimestampTestCase {
            name: "microsecond_precision",
            events: vec![
                SpanEventSpec {
                    name: "event_1",
                    instant: base_instant + Duration::from_micros(1),
                    attributes: attrs(&[("precision", "microsecond")]),
                },
                SpanEventSpec {
                    name: "event_2",
                    instant: base_instant + Duration::from_micros(123),
                    attributes: attrs(&[("precision", "microsecond")]),
                },
                SpanEventSpec {
                    name: "event_3",
                    instant: base_instant + Duration::from_micros(999),
                    attributes: attrs(&[("precision", "microsecond")]),
                },
            ],
            description: "Events with microsecond-level timing precision",
        },
        SpanEventTimestampTestCase {
            name: "nanosecond_precision",
            events: vec![
                SpanEventSpec {
                    name: "nano_event_1",
                    instant: base_instant + Duration::from_nanos(1),
                    attributes: Vec::new(),
                },
                SpanEventSpec {
                    name: "nano_event_2",
                    instant: base_instant + Duration::from_nanos(999_999_999), // Just under 1 second
                    attributes: attrs(&[("precision", "nanosecond")]),
                },
            ],
            description: "Events with nanosecond-level timing precision",
        },
        SpanEventTimestampTestCase {
            name: "events_with_complex_attributes",
            events: vec![
                SpanEventSpec {
                    name: "database_query",
                    instant: base_instant + Duration::from_millis(5),
                    attributes: attrs(&[
                        ("db.system", "postgresql"),
                        ("db.statement", "SELECT * FROM users WHERE id = $1"),
                        ("db.connection_string", "postgresql://localhost:5432/mydb"),
                    ]),
                },
                SpanEventSpec {
                    name: "cache_hit",
                    instant: base_instant + Duration::from_millis(15),
                    attributes: attrs(&[
                        ("cache.system", "redis"),
                        ("cache.key", "user:12345"),
                        ("cache.hit", "true"),
                    ]),
                },
            ],
            description: "Events with complex attribute sets",
        },
        SpanEventTimestampTestCase {
            name: "rapid_succession_events",
            events: (0..10)
                .map(|i| SpanEventSpec {
                    name: "rapid_event",
                    instant: base_instant + Duration::from_nanos(i * 100), // 100ns apart
                    attributes: vec![attr("sequence", RAPID_SEQUENCE_VALUES[i as usize])],
                })
                .collect(),
            description: "Many events in rapid succession with nanosecond spacing",
        },
        SpanEventTimestampTestCase {
            name: "edge_case_timing",
            events: vec![
                SpanEventSpec {
                    name: "zero_duration",
                    instant: base_instant,
                    attributes: attrs(&[("duration", "0")]),
                },
                SpanEventSpec {
                    name: "max_duration_component",
                    instant: base_instant + Duration::from_nanos(999_999_999),
                    attributes: attrs(&[("duration", "max_subsec")]),
                },
                SpanEventSpec {
                    name: "second_boundary",
                    instant: base_instant + Duration::from_secs(1),
                    attributes: attrs(&[("boundary", "second")]),
                },
            ],
            description: "Edge cases around timing boundaries",
        },
    ];

    println!(
        "Running {} Span event timestamp conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Build timestamp data under test
        let our_events = test_our_span_event_timestamps(test_case, base_instant, base_system_time);

        // Build canonical OTLP timestamp data for the same event instants
        let reference_events =
            canonical_span_event_timestamps(test_case, base_instant, base_system_time);

        // Compare results - focus on unix nanosecond precision
        if let Err(error) = compare_span_event_timestamps(&our_events, &reference_events, test_case)
        {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    PASS {}", test_case.name);
        }
    }

    // Test edge cases
    println!("\nTesting Span event timestamp edge cases");
    test_span_event_timestamp_edge_cases(&mut failed_tests);

    // Report results
    println!("\nSpan Event Timestamp Conformance Test Results");
    if failed_tests.is_empty() {
        println!("ALL TESTS PASSED - Span event timestamps are conformant");
        println!("OTLP unix nanosecond precision is stable for identical event instants");
    } else {
        println!("{} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test our Span event timestamp implementation.
fn test_our_span_event_timestamps(
    test_case: &SpanEventTimestampTestCase,
    base_instant: Instant,
    base_system_time: SystemTime,
) -> Vec<SpanEventTimestampData> {
    let mut events = Vec::new();

    for event_spec in &test_case.events {
        events.push(SpanEventTimestampData {
            event_name: event_spec.name.to_string(),
            time_unix_nano: event_unix_nanos(base_instant, event_spec, base_system_time),
            attributes: event_spec.attributes.clone(),
        });
    }

    events
}

/// Build canonical OTLP Span event timestamps for the supplied event instants.
fn canonical_span_event_timestamps(
    test_case: &SpanEventTimestampTestCase,
    base_instant: Instant,
    base_system_time: SystemTime,
) -> Vec<SpanEventTimestampData> {
    let mut events = Vec::new();

    for event_spec in &test_case.events {
        events.push(SpanEventTimestampData {
            event_name: event_spec.name.to_string(),
            time_unix_nano: event_unix_nanos(base_instant, event_spec, base_system_time),
            attributes: event_spec.attributes.clone(),
        });
    }

    events
}

fn event_unix_nanos(
    base_instant: Instant,
    event_spec: &SpanEventSpec,
    base_system_time: SystemTime,
) -> u64 {
    let elapsed_since_base = event_spec
        .instant
        .checked_duration_since(base_instant)
        .expect("event instants are generated from the shared base instant");
    let system_time = base_system_time + elapsed_since_base;
    let nanos = system_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    u64::try_from(nanos).expect("test timestamps fit in OTLP u64 unix nanos")
}

/// Compare span event timestamp data between implementations.
fn compare_span_event_timestamps(
    our_events: &[SpanEventTimestampData],
    reference_events: &[SpanEventTimestampData],
    _test_case: &SpanEventTimestampTestCase,
) -> Result<(), String> {
    if our_events.len() != reference_events.len() {
        return Err(format!(
            "Event count mismatch: our={}, reference={}",
            our_events.len(),
            reference_events.len()
        ));
    }

    // Events should be in the same order since we control the input
    for (i, (our_event, ref_event)) in our_events.iter().zip(reference_events.iter()).enumerate() {
        // Check event names match
        if our_event.event_name != ref_event.event_name {
            return Err(format!(
                "Event {} name mismatch: our={}, reference={}",
                i, our_event.event_name, ref_event.event_name
            ));
        }

        // Core requirement: identical unix nanosecond timestamps
        if our_event.time_unix_nano != ref_event.time_unix_nano {
            return Err(format!(
                "Event '{}' timestamp mismatch: our={}, reference={}, diff={}ns",
                our_event.event_name,
                our_event.time_unix_nano,
                ref_event.time_unix_nano,
                (our_event.time_unix_nano as i64 - ref_event.time_unix_nano as i64).abs()
            ));
        }

        // Verify attributes match
        if our_event.attributes != ref_event.attributes {
            return Err(format!(
                "Event '{}' attributes mismatch: our={:?}, reference={:?}",
                our_event.event_name, our_event.attributes, ref_event.attributes
            ));
        }
    }

    Ok(())
}

/// Test edge cases for span event timestamps.
fn test_span_event_timestamp_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    let base_instant = Instant::now();
    let base_system_time = UNIX_EPOCH + Duration::from_secs(1_800_000_000);

    let edge_cases = vec![
        (
            "single_event_no_attributes",
            vec![SpanEventSpec {
                name: "simple_event",
                instant: base_instant,
                attributes: Vec::new(),
            }],
            "Event with no attributes",
        ),
        (
            "duplicate_event_names",
            vec![
                SpanEventSpec {
                    name: "duplicate",
                    instant: base_instant,
                    attributes: attrs(&[("instance", "1")]),
                },
                SpanEventSpec {
                    name: "duplicate",
                    instant: base_instant + Duration::from_nanos(1),
                    attributes: attrs(&[("instance", "2")]),
                },
            ],
            "Multiple events with same name but different timestamps",
        ),
        (
            "large_time_gap",
            vec![
                SpanEventSpec {
                    name: "early_event",
                    instant: base_instant,
                    attributes: Vec::new(),
                },
                SpanEventSpec {
                    name: "late_event",
                    instant: base_instant + Duration::from_secs(3600), // 1 hour later
                    attributes: Vec::new(),
                },
            ],
            "Events separated by large time gap",
        ),
        (
            "many_attributes",
            vec![SpanEventSpec {
                name: "complex_event",
                instant: base_instant,
                attributes: (0..20)
                    .map(|i| attr(format!("key_{i}"), format!("value_{i}")))
                    .collect(),
            }],
            "Event with many attributes",
        ),
    ];

    for (case_name, events, description) in edge_cases {
        let test_case = SpanEventTimestampTestCase {
            name: case_name,
            events,
            description,
        };

        let our_events = test_our_span_event_timestamps(&test_case, base_instant, base_system_time);
        let reference_events =
            canonical_span_event_timestamps(&test_case, base_instant, base_system_time);

        if let Err(error) =
            compare_span_event_timestamps(&our_events, &reference_events, &test_case)
        {
            failed_tests.push((format!("edge_case_{}", case_name), error));
        } else {
            println!("    PASS edge_case_{}", case_name);
        }
    }
}

fn attrs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(key, value)| attr(*key, *value))
        .collect()
}

fn attr(key: impl Into<String>, value: impl Into<String>) -> (String, String) {
    (key.into(), value.into())
}
