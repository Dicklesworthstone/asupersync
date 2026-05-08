use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Conformance test for SETTINGS_INITIAL_WINDOW_SIZE retroactive updates
/// Fail-closed until it drives both asupersync H2 and a live h2 crate endpoint.
///
/// RFC 9113 §6.5.2: "A change to SETTINGS_INITIAL_WINDOW_SIZE affects the
/// connection flow-control window of all open streams."
const REFERENCE_IMPLEMENTATION: &str = "local-rfc-window-model";
const REFERENCE_STATUS: &str = "xfail-no-live-h2-reference";
const FAIL_CLOSED_REASON: &str = "fail-closed: this harness currently compares local window models and does not drive a live h2 crate reference implementation";

type ConformanceTestCase = (&'static str, fn() -> Result<(), String>, &'static str);

/// Output format for conformance test results
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Markdown,
    Summary,
}

/// Results from conformance testing
#[derive(Debug, Serialize, Deserialize)]
pub struct ConformanceResults {
    /// Whether implementations are conformant
    pub conformant_implementations: bool,
    /// Reference implementation used by this run
    pub reference_implementation: String,
    /// Whether the reference is live or fail-closed
    pub reference_status: String,
    /// Fail-closed reason when no live reference was used
    pub fail_closed_reason: Option<String>,
    /// Number of tests passed
    pub tests_passed: usize,
    /// Number of tests failed
    pub tests_failed: usize,
    /// Individual test results
    pub test_results: Vec<TestResult>,
    /// Overall summary
    pub summary: String,
}

/// Individual test result
#[derive(Debug, Serialize, Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub passed: bool,
    pub reference_status: String,
    pub error_message: Option<String>,
    pub description: String,
}

/// Test scenario for SETTINGS_INITIAL_WINDOW_SIZE conformance
#[derive(Debug, Clone)]
struct WindowSizeScenario {
    /// Initial window size setting
    initial_window_size: u32,
    /// Number of streams to create before settings change
    streams_to_create: u32,
    /// New window size settings to apply
    new_window_sizes: Vec<u32>,
    /// Data to send on each stream (affects window)
    stream_data_sizes: Vec<usize>,
}

/// Local RFC-derived window model used only as sanity coverage.
#[derive(Debug)]
struct ModeledConnectionState {
    /// Current SETTINGS_INITIAL_WINDOW_SIZE
    initial_window_size: u32,
    /// Per-stream flow control windows
    stream_windows: HashMap<u32, i32>,
    /// Next stream ID to assign
    next_stream_id: u32,
}

impl ModeledConnectionState {
    fn new(initial_window_size: u32) -> Self {
        Self {
            initial_window_size,
            stream_windows: HashMap::new(),
            next_stream_id: 1,
        }
    }

    /// Create a new stream with current initial window size
    fn create_stream(&mut self) -> u32 {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Client streams are odd

        // New stream gets the current initial window size
        self.stream_windows
            .insert(stream_id, self.initial_window_size as i32);

        stream_id
    }

    /// Update SETTINGS_INITIAL_WINDOW_SIZE retroactively
    fn update_initial_window_size(
        &mut self,
        new_size: u32,
    ) -> Result<Vec<(u32, i32, i32)>, String> {
        let old_size = self.initial_window_size;
        let window_delta = new_size as i64 - old_size as i64;

        let mut changes = Vec::new();

        // Apply retroactive changes to all existing streams
        for (&stream_id, window) in &mut self.stream_windows {
            let old_window = *window;
            let new_window = (old_window as i64 + window_delta)
                .max(0)
                .min(i32::MAX as i64) as i32;

            *window = new_window;
            changes.push((stream_id, old_window, new_window));
        }

        self.initial_window_size = new_size;
        Ok(changes)
    }

    /// Simulate data sending (decreases window)
    fn send_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            if *window < size as i32 {
                return Err(format!(
                    "Flow control violation: window={}, size={}",
                    window, size
                ));
            }
            *window -= size as i32;
            Ok(*window)
        } else {
            Err(format!("Stream {} not found", stream_id))
        }
    }

    fn get_window(&self, stream_id: u32) -> Option<i32> {
        self.stream_windows.get(&stream_id).copied()
    }
}

/// Modeled candidate-side adapter; not the live asupersync H2 implementation.
struct ModeledCandidateAdapter {
    state: ModeledConnectionState,
}

impl ModeledCandidateAdapter {
    fn new(initial_window_size: u32) -> Self {
        Self {
            state: ModeledConnectionState::new(initial_window_size),
        }
    }

    fn create_stream(&mut self) -> u32 {
        self.state.create_stream()
    }

    fn update_initial_window_size(
        &mut self,
        new_size: u32,
    ) -> Result<Vec<(u32, i32, i32)>, String> {
        self.state.update_initial_window_size(new_size)
    }

    fn send_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        self.state.send_data(stream_id, size)
    }

    fn get_window(&self, stream_id: u32) -> Option<i32> {
        self.state.get_window(stream_id)
    }
}

/// Modeled RFC reference; not the live h2 crate.
struct ModeledReferenceAdapter {
    state: ModeledConnectionState,
}

impl ModeledReferenceAdapter {
    fn new(initial_window_size: u32) -> Self {
        Self {
            state: ModeledConnectionState::new(initial_window_size),
        }
    }

    fn create_stream(&mut self) -> u32 {
        self.state.create_stream()
    }

    fn update_initial_window_size(
        &mut self,
        new_size: u32,
    ) -> Result<Vec<(u32, i32, i32)>, String> {
        // Local RFC model follows the §6.5.2 window-delta rule.
        self.state.update_initial_window_size(new_size)
    }

    fn send_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        self.state.send_data(stream_id, size)
    }

    fn get_window(&self, stream_id: u32) -> Option<i32> {
        self.state.get_window(stream_id)
    }
}

/// Run conformance test comparing implementations
fn test_conformance(scenario: WindowSizeScenario) -> Result<(), String> {
    let mut candidate = ModeledCandidateAdapter::new(scenario.initial_window_size);
    let mut reference = ModeledReferenceAdapter::new(scenario.initial_window_size);

    // Phase 1: Create streams on both implementations
    let mut stream_ids = Vec::new();
    for _ in 0..scenario.streams_to_create {
        let candidate_id = candidate.create_stream();
        let reference_id = reference.create_stream();

        // Stream IDs should match
        if candidate_id != reference_id {
            return Err(format!(
                "Stream ID mismatch: candidate model={}, reference model={}",
                candidate_id, reference_id
            ));
        }

        stream_ids.push(candidate_id);
    }

    // Verify initial window sizes match
    for &stream_id in &stream_ids {
        let candidate_window = candidate.get_window(stream_id).unwrap();
        let reference_window = reference.get_window(stream_id).unwrap();

        if candidate_window != reference_window {
            return Err(format!(
                "Initial window mismatch for stream {}: candidate model={}, reference model={}",
                stream_id, candidate_window, reference_window
            ));
        }
    }

    // Phase 2: Send data on streams (if specified)
    for (i, &data_size) in scenario.stream_data_sizes.iter().enumerate() {
        if i >= stream_ids.len() {
            break;
        }

        let stream_id = stream_ids[i];

        let candidate_result = candidate.send_data(stream_id, data_size);
        let reference_result = reference.send_data(stream_id, data_size);

        match (candidate_result, reference_result) {
            (Ok(candidate_window), Ok(reference_window)) => {
                if candidate_window != reference_window {
                    return Err(format!(
                        "Window mismatch after send on stream {}: candidate model={}, reference model={}",
                        stream_id, candidate_window, reference_window
                    ));
                }
            }
            (Err(candidate_err), Err(reference_err)) => {
                // Both failed - check error similarity
                if candidate_err != reference_err {
                    return Err(format!(
                        "Error mismatch on stream {}: candidate model='{}', reference model='{}'",
                        stream_id, candidate_err, reference_err
                    ));
                }
            }
            (Ok(_), Err(ref_err)) => {
                return Err(format!(
                    "Candidate model succeeded but reference model failed on stream {}: {}",
                    stream_id, ref_err
                ));
            }
            (Err(candidate_err), Ok(_)) => {
                return Err(format!(
                    "Reference model succeeded but candidate model failed on stream {}: {}",
                    stream_id, candidate_err
                ));
            }
        }
    }

    // Phase 3: Apply SETTINGS_INITIAL_WINDOW_SIZE changes
    for &new_window_size in &scenario.new_window_sizes {
        let candidate_changes = candidate.update_initial_window_size(new_window_size)?;
        let reference_changes = reference.update_initial_window_size(new_window_size)?;

        // Verify same number of affected streams
        if candidate_changes.len() != reference_changes.len() {
            return Err(format!(
                "Different number of streams affected: candidate model={}, reference model={}",
                candidate_changes.len(),
                reference_changes.len()
            ));
        }

        // Sort changes by stream ID for comparison
        let mut candidate_sorted = candidate_changes;
        let mut ref_sorted = reference_changes;
        candidate_sorted.sort_by_key(|(id, _, _)| *id);
        ref_sorted.sort_by_key(|(id, _, _)| *id);

        // Compare each stream's window changes
        for ((candidate_id, candidate_old, candidate_new), (ref_id, ref_old, ref_new)) in
            candidate_sorted.iter().zip(ref_sorted.iter())
        {
            if candidate_id != ref_id {
                return Err(format!(
                    "Stream ID mismatch in changes: candidate model={}, reference model={}",
                    candidate_id, ref_id
                ));
            }

            if candidate_old != ref_old {
                return Err(format!(
                    "Old window mismatch for stream {}: candidate model={}, reference model={}",
                    candidate_id, candidate_old, ref_old
                ));
            }

            if candidate_new != ref_new {
                return Err(format!(
                    "New window mismatch for stream {}: candidate model={}, reference model={}",
                    candidate_id, candidate_new, ref_new
                ));
            }
        }

        // Verify final window states match
        for &stream_id in &stream_ids {
            let candidate_window = candidate.get_window(stream_id).unwrap();
            let reference_window = reference.get_window(stream_id).unwrap();

            if candidate_window != reference_window {
                return Err(format!(
                    "Final window mismatch for stream {} after setting to {}: candidate model={}, reference model={}",
                    stream_id, new_window_size, candidate_window, reference_window
                ));
            }
        }
    }

    Ok(())
}

/// Test basic window size increase
fn test_basic_increase() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 3,
        new_window_sizes: vec![131070], // Double the window size
        stream_data_sizes: vec![],
    };

    test_conformance(scenario)
}

/// Test window size decrease
fn test_window_decrease() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 131070,
        streams_to_create: 2,
        new_window_sizes: vec![65535], // Halve the window size
        stream_data_sizes: vec![],
    };

    test_conformance(scenario)
}

/// Test multiple window size changes
fn test_multiple_changes() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 4,
        new_window_sizes: vec![32768, 131070, 65535], // Decrease, increase, back to original
        stream_data_sizes: vec![],
    };

    test_conformance(scenario)
}

/// Test window changes with active data transfer
fn test_with_data_transfer() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 3,
        new_window_sizes: vec![32768], // Decrease after data sent
        stream_data_sizes: vec![16384, 8192, 4096], // Send data on each stream
    };

    test_conformance(scenario)
}

/// Test edge case: decrease to minimum window size
fn test_minimum_window() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 2,
        new_window_sizes: vec![0], // Minimum allowed window size
        stream_data_sizes: vec![],
    };

    test_conformance(scenario)
}

/// Test edge case: maximum window size
fn test_maximum_window() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 2,
        new_window_sizes: vec![2147483647], // Maximum allowed (2^31-1)
        stream_data_sizes: vec![],
    };

    test_conformance(scenario)
}

/// Test retroactive update with mixed stream states
fn test_mixed_stream_states() -> Result<(), String> {
    let scenario = WindowSizeScenario {
        initial_window_size: 65535,
        streams_to_create: 5,
        new_window_sizes: vec![32768, 98304], // Two changes
        stream_data_sizes: vec![10000, 20000, 5000, 15000, 25000], // Different usage per stream
    };

    test_conformance(scenario)
}

/// Test boundary condition: window size changes near flow control limits
fn test_flow_control_boundaries() -> Result<(), String> {
    // Test case where window decrease would make some streams' windows negative
    // Should be clamped to 0
    let scenario = WindowSizeScenario {
        initial_window_size: 32768,
        streams_to_create: 3,
        new_window_sizes: vec![16384], // Decrease by 16384
        stream_data_sizes: vec![20000, 10000, 30000], // Some exceed new window size
    };

    test_conformance(scenario)
}

/// Run basic conformance tests
pub fn run_basic_conformance_tests() -> ConformanceResults {
    run_conformance_tests(false)
}

/// Run all conformance tests (including comprehensive scenarios)
pub fn run_all_conformance_tests() -> ConformanceResults {
    run_conformance_tests(true)
}

/// Internal conformance test runner
fn run_conformance_tests(comprehensive: bool) -> ConformanceResults {
    let mut test_results = Vec::new();

    // Basic test suite
    let basic_tests: Vec<ConformanceTestCase> = vec![
        (
            "Basic window increase",
            test_basic_increase as fn() -> Result<(), String>,
            "Tests increasing SETTINGS_INITIAL_WINDOW_SIZE",
        ),
        (
            "Window size decrease",
            test_window_decrease,
            "Tests decreasing SETTINGS_INITIAL_WINDOW_SIZE",
        ),
        (
            "Multiple window changes",
            test_multiple_changes,
            "Tests sequential window size changes",
        ),
        (
            "Window changes with data transfer",
            test_with_data_transfer,
            "Tests window changes with active data transfer",
        ),
        (
            "Minimum window size",
            test_minimum_window,
            "Tests minimum allowed window size (0)",
        ),
        (
            "Maximum window size",
            test_maximum_window,
            "Tests maximum allowed window size (2^31-1)",
        ),
    ];

    let mut comprehensive_tests: Vec<ConformanceTestCase> = vec![
        (
            "Mixed stream states",
            test_mixed_stream_states,
            "Tests mixed stream states during window changes",
        ),
        (
            "Flow control boundaries",
            test_flow_control_boundaries,
            "Tests flow control boundary conditions",
        ),
    ];

    let mut all_tests = basic_tests;
    if comprehensive {
        all_tests.append(&mut comprehensive_tests);
    }

    let mut tests_failed = 0;

    for (name, test_fn, description) in all_tests {
        match test_fn() {
            Ok(()) => {
                test_results.push(TestResult {
                    test_name: name.to_string(),
                    passed: false,
                    reference_status: REFERENCE_STATUS.to_string(),
                    error_message: Some(FAIL_CLOSED_REASON.to_string()),
                    description: description.to_string(),
                });
                tests_failed += 1;
            }
            Err(error) => {
                test_results.push(TestResult {
                    test_name: name.to_string(),
                    passed: false,
                    reference_status: REFERENCE_STATUS.to_string(),
                    error_message: Some(format!(
                        "fail-closed before live h2 comparison: modeled sanity check failed: {}",
                        error
                    )),
                    description: description.to_string(),
                });
                tests_failed += 1;
            }
        }
    }

    ConformanceResults {
        conformant_implementations: false,
        reference_implementation: REFERENCE_IMPLEMENTATION.to_string(),
        reference_status: REFERENCE_STATUS.to_string(),
        fail_closed_reason: Some(FAIL_CLOSED_REASON.to_string()),
        tests_passed: 0,
        tests_failed,
        test_results,
        summary: format!(
            "{} modeled scenarios were checked, but no result is conformant because the harness does not drive a live h2 crate reference",
            tests_failed
        ),
    }
}

/// Format results as JSON
pub fn format_results_as_json(results: &ConformanceResults) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|_| "Error formatting JSON".to_string())
}

/// Format results as Markdown
pub fn format_results_as_markdown(results: &ConformanceResults) -> String {
    let mut output = String::new();

    output.push_str("# SETTINGS_INITIAL_WINDOW_SIZE Fail-Closed Check Results\n\n");
    output.push_str(&format!(
        "**Status:** {}\n\n",
        if results.conformant_implementations {
            "CONFORMANT"
        } else {
            "FAIL-CLOSED"
        }
    ));
    output.push_str(&format!(
        "**Reference:** {} ({})\n",
        results.reference_implementation, results.reference_status
    ));
    if let Some(reason) = &results.fail_closed_reason {
        output.push_str(&format!("**Reason:** {}\n", reason));
    }
    output.push_str(&format!("**Tests Passed:** {}\n", results.tests_passed));
    output.push_str(&format!("**Tests Failed:** {}\n\n", results.tests_failed));

    output.push_str("## Test Results\n\n");
    output.push_str("| Test | Status | Description |\n");
    output.push_str("|------|--------|-------------|\n");

    for result in &results.test_results {
        let status = if result.passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        };
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            result.test_name, status, result.description
        ));
    }

    if results.tests_failed > 0 {
        output.push_str("\n## Failures\n\n");
        for result in &results.test_results {
            if !result.passed {
                output.push_str(&format!("### {}\n\n", result.test_name));
                if let Some(ref error) = result.error_message {
                    output.push_str(&format!("**Error:** {}\n\n", error));
                }
            }
        }
    }

    output.push_str(&format!("\n## Summary\n\n{}\n", results.summary));
    output
}

/// Format results as summary text
pub fn format_results_as_summary(results: &ConformanceResults) -> String {
    let mut output = String::new();

    output.push_str("SETTINGS_INITIAL_WINDOW_SIZE Fail-Closed Check Results\n");
    output.push_str("=".repeat(59).as_str());
    output.push_str("\n\n");

    output.push_str(&format!(
        "Status: {}\n",
        if results.conformant_implementations {
            "CONFORMANT"
        } else {
            "FAIL-CLOSED"
        }
    ));
    output.push_str(&format!(
        "Reference: {} ({})\n",
        results.reference_implementation, results.reference_status
    ));
    if let Some(reason) = &results.fail_closed_reason {
        output.push_str(&format!("Reason: {}\n", reason));
    }
    output.push_str(&format!("Tests Passed: {}\n", results.tests_passed));
    output.push_str(&format!("Tests Failed: {}\n\n", results.tests_failed));

    for result in &results.test_results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        output.push_str(&format!("  {} ... {}\n", result.test_name, status));
        if !result.passed
            && let Some(ref error) = result.error_message
        {
            output.push_str(&format!("    Error: {}\n", error));
        }
    }

    output.push_str(&format!("\n{}\n", results.summary));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fail_closed_without_live_h2_reference() {
        let results = run_basic_conformance_tests();
        assert!(!results.conformant_implementations);
        assert_eq!(results.reference_status, REFERENCE_STATUS);
        assert_eq!(results.tests_passed, 0);
        assert!(results.tests_failed > 0);
        assert!(
            results
                .fail_closed_reason
                .as_deref()
                .unwrap_or_default()
                .contains("does not drive a live h2 crate reference")
        );
        assert!(results.test_results.iter().all(|result| {
            !result.passed
                && result.reference_status == REFERENCE_STATUS
                && result
                    .error_message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("fail-closed")
        }));
    }

    #[test]
    fn test_public_output_does_not_claim_conformance() {
        let results = run_basic_conformance_tests();
        let summary = format_results_as_summary(&results);
        let markdown = format_results_as_markdown(&results);

        assert!(summary.contains("FAIL-CLOSED"));
        assert!(summary.contains(REFERENCE_STATUS));
        assert!(!summary.contains("Status: CONFORMANT"));
        assert!(markdown.contains("FAIL-CLOSED"));
        assert!(markdown.contains(REFERENCE_STATUS));
    }

    #[test]
    fn test_window_size_math() {
        let mut state = ModeledConnectionState::new(65535);
        let stream_id = state.create_stream();

        // Test increase
        let changes = state.update_initial_window_size(131070).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], (stream_id, 65535, 131070));

        // Test decrease
        let changes = state.update_initial_window_size(32768).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], (stream_id, 131070, 32768));
    }

    #[test]
    fn test_multiple_streams() {
        let mut state = ModeledConnectionState::new(65535);
        state.create_stream();
        state.create_stream();
        state.create_stream();

        let changes = state.update_initial_window_size(98304).unwrap();
        assert_eq!(changes.len(), 3);

        // All streams should have the same change pattern
        for &(_, old_window, new_window) in &changes {
            assert_eq!(old_window, 65535);
            assert_eq!(new_window, 98304);
        }
    }
}
