#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::observability::diagnostics::*;
use asupersync::types::{CancelKind, ObligationId, RegionId, TaskId, Time};
use asupersync::record::{ObligationState, region::RegionState, task::TaskState};
use serde_json::Value;
use std::collections::BTreeMap;

// Maximum size bounds to prevent OOM during fuzzing
const MAX_CYCLES: usize = 100;
const MAX_REASONS: usize = 50;
const MAX_DETAILS: usize = 50;
const MAX_RECOMMENDATIONS: usize = 50;
const MAX_TASKS_PER_CYCLE: usize = 20;
const MAX_STRING_LEN: usize = 1000;

/// Arbitrary implementation for generating fuzz test data
#[derive(Arbitrary, Debug)]
struct FuzzDiagnosticData {
    deadlock_report: FuzzDirectionalDeadlockReport,
    region_explanation: FuzzRegionOpenExplanation,
    task_explanation: FuzzTaskBlockedExplanation,
    obligation_leak: FuzzObligationLeak,
}

#[derive(Arbitrary, Debug)]
struct FuzzDirectionalDeadlockReport {
    severity: u8,  // Will be mapped to DeadlockSeverity
    risk_score: f64,
    cycles: Vec<FuzzDeadlockCycle>,
}

#[derive(Arbitrary, Debug)]
struct FuzzDeadlockCycle {
    tasks: Vec<u64>,  // Will be mapped to TaskId
    ingress_edges: u32,
    egress_edges: u32,
    trapped: bool,
}

#[derive(Arbitrary, Debug)]
struct FuzzRegionOpenExplanation {
    region_id: u64,  // Will be mapped to RegionId
    has_state: bool,
    state_variant: u8,  // Will be mapped to RegionState variants
    reasons: Vec<String>,
    recommendations: Vec<String>,
}

#[derive(Arbitrary, Debug)]
struct FuzzTaskBlockedExplanation {
    task_id: u64,  // Will be mapped to TaskId
    block_reason: u8,  // Will be mapped to BlockReason variants
    details: Vec<String>,
    recommendations: Vec<String>,
}

#[derive(Arbitrary, Debug)]
struct FuzzObligationLeak {
    obligation_id: u64,  // Will be mapped to ObligationId
    obligation_type: String,
    has_holder_task: bool,
    holder_task: u64,  // Will be mapped to TaskId if has_holder_task
    region_id: u64,  // Will be mapped to RegionId
    age_millis: u64,
}

impl FuzzDiagnosticData {
    fn to_real_diagnostics(&self) -> RealDiagnosticData {
        RealDiagnosticData {
            deadlock_report: self.deadlock_report.to_real(),
            region_explanation: self.region_explanation.to_real(),
            task_explanation: self.task_explanation.to_real(),
            obligation_leak: self.obligation_leak.to_real(),
        }
    }
}

struct RealDiagnosticData {
    deadlock_report: DirectionalDeadlockReport,
    region_explanation: RegionOpenExplanation,
    task_explanation: TaskBlockedExplanation,
    obligation_leak: ObligationLeak,
}

impl FuzzDirectionalDeadlockReport {
    fn to_real(&self) -> DirectionalDeadlockReport {
        let severity = match self.severity % 3 {
            0 => DeadlockSeverity::None,
            1 => DeadlockSeverity::Elevated,
            _ => DeadlockSeverity::Critical,
        };

        let cycles = self.cycles.iter()
            .take(MAX_CYCLES)
            .map(|c| c.to_real())
            .collect();

        DirectionalDeadlockReport {
            severity,
            risk_score: self.risk_score.clamp(0.0, 1.0),
            cycles,
        }
    }
}

impl FuzzDeadlockCycle {
    fn to_real(&self) -> DeadlockCycle {
        let tasks = self.tasks.iter()
            .take(MAX_TASKS_PER_CYCLE)
            .map(|&id| TaskId::new_for_test(id as u32, (id >> 32) as u32))
            .collect();

        DeadlockCycle {
            tasks,
            ingress_edges: self.ingress_edges,
            egress_edges: self.egress_edges,
            trapped: self.trapped,
        }
    }
}

impl FuzzRegionOpenExplanation {
    fn to_real(&self) -> RegionOpenExplanation {
        let region_state = if self.has_state {
            Some(match self.state_variant % 4 {
                0 => RegionState::Open,
                1 => RegionState::Closing,
                2 => RegionState::Closed,
                _ => RegionState::Finalizing,
            })
        } else {
            None
        };

        let reasons = self.reasons.iter()
            .take(MAX_REASONS)
            .map(|s| Reason::RegionNotFound) // Use a simple variant for fuzzing
            .collect();

        let recommendations = self.recommendations.iter()
            .take(MAX_RECOMMENDATIONS)
            .map(|s| s.chars().take(MAX_STRING_LEN).collect())
            .collect();

        RegionOpenExplanation {
            region_id: RegionId::new_for_test(self.region_id as u32, (self.region_id >> 32) as u32),
            region_state,
            reasons,
            recommendations,
        }
    }
}

impl FuzzTaskBlockedExplanation {
    fn to_real(&self) -> TaskBlockedExplanation {
        let block_reason = match self.block_reason % 6 {
            0 => BlockReason::TaskNotFound,
            1 => BlockReason::NotStarted,
            2 => BlockReason::AwaitingSchedule,
            3 => BlockReason::AwaitingFuture {
                description: "test future".to_string(),
            },
            4 => BlockReason::CancelRequested {
                reason: CancelReasonInfo {
                    kind: CancelKind::User,
                    message: Some("test cancel reason".to_string()),
                },
            },
            _ => BlockReason::Finalizing {
                reason: CancelReasonInfo {
                    kind: CancelKind::Timeout,
                    message: Some("finalizing".to_string()),
                },
                polls_remaining: 10,
            },
        };

        let details = self.details.iter()
            .take(MAX_DETAILS)
            .map(|s| s.chars().take(MAX_STRING_LEN).collect())
            .collect();

        let recommendations = self.recommendations.iter()
            .take(MAX_RECOMMENDATIONS)
            .map(|s| s.chars().take(MAX_STRING_LEN).collect())
            .collect();

        TaskBlockedExplanation {
            task_id: TaskId::new_for_test(self.task_id as u32, (self.task_id >> 32) as u32),
            block_reason,
            details,
            recommendations,
        }
    }
}

impl FuzzObligationLeak {
    fn to_real(&self) -> ObligationLeak {
        let holder_task = if self.has_holder_task {
            Some(TaskId::new_for_test(self.holder_task as u32, (self.holder_task >> 32) as u32))
        } else {
            None
        };

        let obligation_type = self.obligation_type.chars()
            .take(MAX_STRING_LEN)
            .collect();

        ObligationLeak {
            obligation_id: ObligationId::new_for_test(self.obligation_id as u32, (self.obligation_id >> 32) as u32),
            obligation_type,
            holder_task,
            region_id: RegionId::new_for_test(self.region_id as u32, (self.region_id >> 32) as u32),
            age: std::time::Duration::from_millis(self.age_millis % 86400000), // Cap at 1 day
        }
    }
}

/// Validates that a string contains valid NDJSON format
fn validate_ndjson(ndjson_str: &str) -> Result<(), String> {
    if ndjson_str.is_empty() {
        return Ok(());
    }

    let lines: Vec<&str> = ndjson_str.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        // Each line must be valid JSON
        serde_json::from_str::<Value>(line)
            .map_err(|e| format!("Line {}: Invalid JSON: {} (content: {:?})", i + 1, e, line))?;

        // Check for embedded unescaped newlines within the JSON content
        if line.contains('\n') {
            return Err(format!("Line {}: Contains unescaped newline character", i + 1));
        }

        if line.contains('\r') {
            return Err(format!("Line {}: Contains unescaped carriage return character", i + 1));
        }
    }

    // Ensure the string ends with a newline if non-empty (NDJSON convention)
    if !ndjson_str.ends_with('\n') && !lines.is_empty() {
        return Err("NDJSON should end with newline".to_string());
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > 100_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let fuzz_data = match FuzzDiagnosticData::arbitrary(&mut unstructured) {
        Ok(data) => data,
        Err(_) => return, // Not enough data to generate arbitrary input
    };

    let real_diagnostics = fuzz_data.to_real_diagnostics();

    // Test DirectionalDeadlockReport::to_ndjson()
    let deadlock_ndjson = real_diagnostics.deadlock_report.to_ndjson();
    if let Err(e) = validate_ndjson(&deadlock_ndjson) {
        panic!("DirectionalDeadlockReport NDJSON validation failed: {}", e);
    }

    // Test RegionOpenExplanation::to_ndjson()
    let region_ndjson = real_diagnostics.region_explanation.to_ndjson();
    if let Err(e) = validate_ndjson(&region_ndjson) {
        panic!("RegionOpenExplanation NDJSON validation failed: {}", e);
    }

    // Test TaskBlockedExplanation::to_ndjson()
    let task_ndjson = real_diagnostics.task_explanation.to_ndjson();
    if let Err(e) = validate_ndjson(&task_ndjson) {
        panic!("TaskBlockedExplanation NDJSON validation failed: {}", e);
    }

    // Test ObligationLeak::to_ndjson()
    let obligation_ndjson = real_diagnostics.obligation_leak.to_ndjson();
    if let Err(e) = validate_ndjson(&obligation_ndjson) {
        panic!("ObligationLeak NDJSON validation failed: {}", e);
    }

    // Additional invariant checks

    // Verify that all JSON objects contain expected type field
    if !deadlock_ndjson.is_empty() {
        let first_line = deadlock_ndjson.lines().next().unwrap();
        let json: Value = serde_json::from_str(first_line).unwrap();
        assert!(json.get("type").is_some(), "Missing type field in deadlock report");
    }

    if !region_ndjson.is_empty() {
        let first_line = region_ndjson.lines().next().unwrap();
        let json: Value = serde_json::from_str(first_line).unwrap();
        assert!(json.get("type").is_some(), "Missing type field in region explanation");
    }

    if !task_ndjson.is_empty() {
        let first_line = task_ndjson.lines().next().unwrap();
        let json: Value = serde_json::from_str(first_line).unwrap();
        assert!(json.get("type").is_some(), "Missing type field in task explanation");
    }

    if !obligation_ndjson.is_empty() {
        let json: Value = serde_json::from_str(&obligation_ndjson.trim()).unwrap();
        assert!(json.get("type").is_some(), "Missing type field in obligation leak");
    }

    // Test round-trip: parse the NDJSON and ensure we can reconstruct meaningful data
    for line in deadlock_ndjson.lines() {
        let json: Value = serde_json::from_str(line).unwrap();
        if let Some(type_field) = json.get("type") {
            assert!(type_field.is_string(), "Type field must be string");
        }
    }

    // Verify no control character injection
    for ndjson in [&deadlock_ndjson, &region_ndjson, &task_ndjson, &obligation_ndjson] {
        for ch in ndjson.chars() {
            if ch.is_control() && ch != '\n' && ch != '\t' {
                panic!("Control character found in NDJSON output: {:?} (U+{:04X})", ch, ch as u32);
            }
        }
    }
});