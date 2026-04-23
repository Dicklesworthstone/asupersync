use crate::observability::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetailsWire, TaskRegionCountWire,
    TaskStateInfo, TaskSummaryWire,
};
use crate::types::{ObligationId, RegionId, TaskId, Time};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLevel {
    Must,
    Should,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
struct WireConformanceResult {
    requirement_id: &'static str,
    description: &'static str,
    level: RequirementLevel,
    status: TestStatus,
    evidence: String,
}

struct TaskInspectorWireHarness;

impl TaskInspectorWireHarness {
    fn run_all() -> Vec<WireConformanceResult> {
        vec![
            Self::schema_round_trip_is_stable(),
            Self::top_level_field_order_is_stable(),
            Self::enum_variant_tags_are_stable(),
            Self::missing_schema_version_is_rejected(),
            Self::invalid_state_variant_is_rejected(),
            Self::wrong_tasks_shape_is_rejected(),
            Self::unexpected_schema_version_is_flagged(),
        ]
    }

    fn render_matrix(results: &[WireConformanceResult]) -> String {
        use std::fmt::Write;

        let mut out = String::new();
        out.push_str("# Task Inspector Wire Schema Conformance Matrix\n\n");
        out.push_str("| Req ID | Level | Status | Description | Evidence |\n");
        out.push_str("|--------|-------|--------|-------------|----------|\n");

        let mut must_total = 0;
        let mut must_pass = 0;
        let mut should_total = 0;
        let mut should_pass = 0;

        for result in results {
            let level = match result.level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if result.status == TestStatus::Pass {
                        must_pass += 1;
                    }
                    "MUST"
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if result.status == TestStatus::Pass {
                        should_pass += 1;
                    }
                    "SHOULD"
                }
            };
            let status = match result.status {
                TestStatus::Pass => "PASS",
                TestStatus::Fail => "FAIL",
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                result.requirement_id,
                level,
                status,
                result.description,
                result.evidence
            );
        }

        let _ = writeln!(out, "\nSummary:");
        let _ = writeln!(out, "- MUST: {must_pass}/{must_total}");
        let _ = writeln!(out, "- SHOULD: {should_pass}/{should_total}");
        let overall = if must_pass == must_total {
            "CONFORMANT"
        } else {
            "NON-CONFORMANT"
        };
        let _ = writeln!(out, "- Overall: {overall}");

        out
    }

    fn schema_round_trip_is_stable() -> WireConformanceResult {
        let snapshot = valid_snapshot();
        let encoded = snapshot.to_json().expect("wire snapshot should encode");
        let decoded =
            TaskConsoleWireSnapshot::from_json(&encoded).expect("wire snapshot should decode");
        let passes = decoded == snapshot && decoded.tasks[0].id == TaskId::new_for_test(1, 0);

        WireConformanceResult {
            requirement_id: "WIRE-001",
            description: "known-good snapshot round-trips with sorted task order",
            level: RequirementLevel::Must,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!(
                "schema_ok={} first_task={:?}",
                decoded.has_expected_schema(),
                decoded.tasks.first().map(|task| task.id)
            ),
        }
    }

    fn top_level_field_order_is_stable() -> WireConformanceResult {
        let encoded = valid_snapshot()
            .to_json()
            .expect("wire snapshot should encode");
        let schema_idx = encoded.find("\"schema_version\"");
        let generated_idx = encoded.find("\"generated_at\"");
        let summary_idx = encoded.find("\"summary\"");
        let tasks_idx = encoded.find("\"tasks\"");
        let passes = matches!(
            (schema_idx, generated_idx, summary_idx, tasks_idx),
            (Some(a), Some(b), Some(c), Some(d)) if a < b && b < c && c < d
        );

        WireConformanceResult {
            requirement_id: "WIRE-002",
            description: "serializer preserves top-level field order",
            level: RequirementLevel::Should,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: if passes {
                "schema_version<generated_at<summary<tasks".to_string()
            } else {
                format!(
                    "schema={schema_idx:?} generated={generated_idx:?} summary={summary_idx:?} tasks={tasks_idx:?}"
                )
            },
        }
    }

    fn enum_variant_tags_are_stable() -> WireConformanceResult {
        let running = serde_json::to_string(&TaskStateInfo::Running)
            .expect("running state should encode");
        let cancel_requested = serde_json::to_string(&TaskStateInfo::CancelRequested {
            reason: "deadline".to_string(),
        })
        .expect("cancel requested state should encode");
        let passes = running == "\"Running\""
            && cancel_requested == r#"{"CancelRequested":{"reason":"deadline"}}"#;

        WireConformanceResult {
            requirement_id: "WIRE-003",
            description: "enum variant tags stay stable for wire consumers",
            level: RequirementLevel::Must,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!("running={running} cancel={cancel_requested}"),
        }
    }

    fn missing_schema_version_is_rejected() -> WireConformanceResult {
        let mut payload = valid_snapshot_value();
        payload
            .as_object_mut()
            .expect("snapshot should be an object")
            .remove("schema_version");
        let payload = serde_json::to_string(&payload).expect("payload should encode");
        let result = TaskConsoleWireSnapshot::from_json(&payload);
        let passes = result.is_err();

        WireConformanceResult {
            requirement_id: "WIRE-004",
            description: "deserializer rejects payloads missing schema_version",
            level: RequirementLevel::Must,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!("rejected={passes}"),
        }
    }

    fn invalid_state_variant_is_rejected() -> WireConformanceResult {
        let payload = valid_payload_with_state(r#"{"Paused":{}}"#);
        let result = TaskConsoleWireSnapshot::from_json(&payload);
        let passes = result.is_err();

        WireConformanceResult {
            requirement_id: "WIRE-005",
            description: "deserializer rejects unknown task-state enum variants",
            level: RequirementLevel::Must,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!("rejected={passes}"),
        }
    }

    fn wrong_tasks_shape_is_rejected() -> WireConformanceResult {
        let mut payload = valid_snapshot_value();
        payload["tasks"] = serde_json::json!({});
        let payload = serde_json::to_string(&payload).expect("payload should encode");
        let result = TaskConsoleWireSnapshot::from_json(&payload);
        let passes = result.is_err();

        WireConformanceResult {
            requirement_id: "WIRE-006",
            description: "deserializer rejects non-array task collections",
            level: RequirementLevel::Must,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!("rejected={passes}"),
        }
    }

    fn unexpected_schema_version_is_flagged() -> WireConformanceResult {
        let payload = valid_payload_with_schema("asupersync.task_console_wire.v999");
        let snapshot =
            TaskConsoleWireSnapshot::from_json(&payload).expect("structurally valid payload");
        let passes = !snapshot.has_expected_schema();

        WireConformanceResult {
            requirement_id: "WIRE-007",
            description: "unexpected schema versions decode but fail compatibility check",
            level: RequirementLevel::Should,
            status: if passes {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            evidence: format!("schema_version={}", snapshot.schema_version),
        }
    }
}

fn valid_snapshot() -> TaskConsoleWireSnapshot {
    let summary = TaskSummaryWire {
        total_tasks: 2,
        created: 0,
        running: 1,
        cancelling: 1,
        completed: 0,
        stuck_count: 0,
        by_region: vec![TaskRegionCountWire {
            region_id: RegionId::new_for_test(1, 0),
            task_count: 2,
        }],
    };
    let first = TaskDetailsWire {
        id: TaskId::new_for_test(5, 0),
        region_id: RegionId::new_for_test(1, 0),
        state: TaskStateInfo::CancelRequested {
            reason: "deadline".to_string(),
        },
        phase: "CancelRequested".to_string(),
        poll_count: 2,
        polls_remaining: 3,
        created_at: Time::from_nanos(80),
        age_nanos: 220,
        time_since_last_poll_nanos: None,
        wake_pending: false,
        obligations: vec![],
        waiters: vec![],
    };
    let second = TaskDetailsWire {
        id: TaskId::new_for_test(1, 0),
        region_id: RegionId::new_for_test(1, 0),
        state: TaskStateInfo::Running,
        phase: "Running".to_string(),
        poll_count: 4,
        polls_remaining: 10,
        created_at: Time::from_nanos(100),
        age_nanos: 200,
        time_since_last_poll_nanos: Some(30),
        wake_pending: true,
        obligations: vec![ObligationId::new_for_test(2, 0)],
        waiters: vec![TaskId::new_for_test(3, 0)],
    };

    TaskConsoleWireSnapshot::new(Time::from_nanos(999), summary, vec![first, second])
}

fn valid_payload_with_schema(schema_version: &str) -> String {
    valid_snapshot()
        .to_json()
        .expect("valid snapshot should encode")
        .replace(TASK_CONSOLE_WIRE_SCHEMA_V1, schema_version)
}

fn valid_payload_with_state(state_json: &str) -> String {
    valid_payload_with_schema(TASK_CONSOLE_WIRE_SCHEMA_V1).replacen(r#""Running""#, state_json, 1)
}

fn valid_snapshot_value() -> serde_json::Value {
    serde_json::to_value(valid_snapshot()).expect("valid snapshot should convert to value")
}

#[test]
fn task_inspector_wire_schema_conformance_matrix() {
    let results = TaskInspectorWireHarness::run_all();
    let must_total = results
        .iter()
        .filter(|result| result.level == RequirementLevel::Must)
        .count();
    let must_pass = results
        .iter()
        .filter(|result| {
            result.level == RequirementLevel::Must && result.status == TestStatus::Pass
        })
        .count();
    assert_eq!(must_total, must_pass, "all MUST invariants should pass");

    insta::assert_snapshot!(
        "task_inspector_wire_schema_conformance_matrix",
        TaskInspectorWireHarness::render_matrix(&results),
        @r#"
    # Task Inspector Wire Schema Conformance Matrix

    | Req ID | Level | Status | Description | Evidence |
    |--------|-------|--------|-------------|----------|
    | WIRE-001 | MUST | PASS | known-good snapshot round-trips with sorted task order | schema_ok=true first_task=Some(TaskId(1:0)) |
    | WIRE-002 | SHOULD | PASS | serializer preserves top-level field order | schema_version<generated_at<summary<tasks |
    | WIRE-003 | MUST | PASS | enum variant tags stay stable for wire consumers | running="Running" cancel={"CancelRequested":{"reason":"deadline"}} |
    | WIRE-004 | MUST | PASS | deserializer rejects payloads missing schema_version | rejected=true |
    | WIRE-005 | MUST | PASS | deserializer rejects unknown task-state enum variants | rejected=true |
    | WIRE-006 | MUST | PASS | deserializer rejects non-array task collections | rejected=true |
    | WIRE-007 | SHOULD | PASS | unexpected schema versions decode but fail compatibility check | schema_version=asupersync.task_console_wire.v999 |

    Summary:
    - MUST: 5/5
    - SHOULD: 2/2
    - Overall: CONFORMANT
    "#
    );
}
