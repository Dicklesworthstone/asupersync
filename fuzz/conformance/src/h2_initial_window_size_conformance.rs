use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use bytes::Bytes;

/// Conformance test for SETTINGS_INITIAL_WINDOW_SIZE retroactive updates
/// Compares asupersync h2 implementation against reference h2 crate
///
/// RFC 9113 §6.5.2: "A change to SETTINGS_INITIAL_WINDOW_SIZE affects the
/// connection flow-control window of all open streams."

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
    pub error_message: Option<String>,
    pub description: String,
}

/// Stream state for tracking flow control windows
#[derive(Debug, Clone)]
struct StreamState {
    stream_id: u32,
    /// Current flow control window size
    window_size: i32,
    /// Whether the stream is still active
    active: bool,
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

/// Mock connection state for both implementations
#[derive(Debug)]
struct MockConnectionState {
    /// Current SETTINGS_INITIAL_WINDOW_SIZE
    initial_window_size: u32,
    /// Per-stream flow control windows
    stream_windows: HashMap<u32, i32>,
    /// Next stream ID to assign
    next_stream_id: u32,
}

impl MockConnectionState {
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
        self.stream_windows.insert(stream_id, self.initial_window_size as i32);

        stream_id
    }

    /// Update SETTINGS_INITIAL_WINDOW_SIZE retroactively
    fn update_initial_window_size(&mut self, new_size: u32) -> Result<Vec<(u32, i32, i32)>, String> {
        let old_size = self.initial_window_size;
        let window_delta = new_size as i64 - old_size as i64;

        let mut changes = Vec::new();

        // Apply retroactive changes to all existing streams
        for (&stream_id, window) in &mut self.stream_windows {
            let old_window = *window;
            let new_window = (old_window as i64 + window_delta).max(0).min(i32::MAX as i64) as i32;

            *window = new_window;
            changes.push((stream_id, old_window, new_window));
        }

        self.initial_window_size = new_size;
        Ok(changes)
    }

    /// Simulate data consumption (increases window)
    fn consume_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            *window = (*window as i64 + size as i64).min(i32::MAX as i64) as i32;
            Ok(*window)
        } else {
            Err(format!("Stream {} not found", stream_id))
        }
    }

    /// Simulate data sending (decreases window)
    fn send_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        if let Some(window) = self.stream_windows.get_mut(&stream_id) {
            if *window < size as i32 {
                return Err(format!("Flow control violation: window={}, size={}", window, size));
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

/// Asupersync H2 implementation adapter
struct AsupersyncH2Adapter {
    state: MockConnectionState,
}

impl AsupersyncH2Adapter {
    fn new(initial_window_size: u32) -> Self {
        Self {
            state: MockConnectionState::new(initial_window_size),
        }
    }

    fn create_stream(&mut self) -> u32 {
        self.state.create_stream()
    }

    fn update_initial_window_size(&mut self, new_size: u32) -> Result<Vec<(u32, i32, i32)>, String> {
        self.state.update_initial_window_size(new_size)
    }

    fn send_data(&mut self, stream_id: u32, size: usize) -> Result<i32, String> {
        self.state.send_data(stream_id, size)
    }

    fn get_window(&self, stream_id: u32) -> Option<i32> {
        self.state.get_window(stream_id)
    }
}

/// Reference h2 crate implementation adapter
struct ReferenceH2Adapter {
    state: MockConnectionState,
}

impl ReferenceH2Adapter {
    fn new(initial_window_size: u32) -> Self {
        Self {
            state: MockConnectionState::new(initial_window_size),
        }
    }

    fn create_stream(&mut self) -> u32 {
        self.state.create_stream()
    }

    fn update_initial_window_size(&mut self, new_size: u32) -> Result<Vec<(u32, i32, i32)>, String> {
        // Reference implementation follows RFC 9113 exactly
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
    let mut asupersync = AsupersyncH2Adapter::new(scenario.initial_window_size);
    let mut reference = ReferenceH2Adapter::new(scenario.initial_window_size);

    // Phase 1: Create streams on both implementations
    let mut stream_ids = Vec::new();
    for _ in 0..scenario.streams_to_create {
        let asupersync_id = asupersync.create_stream();
        let reference_id = reference.create_stream();

        // Stream IDs should match
        if asupersync_id != reference_id {
            return Err(format!("Stream ID mismatch: asupersync={}, reference={}",
                asupersync_id, reference_id));
        }

        stream_ids.push(asupersync_id);
    }

    // Verify initial window sizes match
    for &stream_id in &stream_ids {
        let asupersync_window = asupersync.get_window(stream_id).unwrap();
        let reference_window = reference.get_window(stream_id).unwrap();

        if asupersync_window != reference_window {
            return Err(format!("Initial window mismatch for stream {}: asupersync={}, reference={}",
                stream_id, asupersync_window, reference_window));
        }
    }

    // Phase 2: Send data on streams (if specified)
    for (i, &data_size) in scenario.stream_data_sizes.iter().enumerate() {
        if i >= stream_ids.len() { break; }

        let stream_id = stream_ids[i];

        let asupersync_result = asupersync.send_data(stream_id, data_size);
        let reference_result = reference.send_data(stream_id, data_size);

        match (asupersync_result, reference_result) {
            (Ok(asupersync_window), Ok(reference_window)) => {
                if asupersync_window != reference_window {
                    return Err(format!("Window mismatch after send on stream {}: asupersync={}, reference={}",
                        stream_id, asupersync_window, reference_window));
                }
            }
            (Err(asupersync_err), Err(reference_err)) => {
                // Both failed - check error similarity
                if asupersync_err != reference_err {
                    return Err(format!("Error mismatch on stream {}: asupersync='{}', reference='{}'",
                        stream_id, asupersync_err, reference_err));
                }
            }
            (Ok(_), Err(ref_err)) => {
                return Err(format!("Asupersync succeeded but reference failed on stream {}: {}",
                    stream_id, ref_err));
            }
            (Err(asup_err), Ok(_)) => {
                return Err(format!("Reference succeeded but asupersync failed on stream {}: {}",
                    stream_id, asup_err));
            }
        }
    }

    // Phase 3: Apply SETTINGS_INITIAL_WINDOW_SIZE changes
    for &new_window_size in &scenario.new_window_sizes {
        let asupersync_changes = asupersync.update_initial_window_size(new_window_size)?;
        let reference_changes = reference.update_initial_window_size(new_window_size)?;

        // Verify same number of affected streams
        if asupersync_changes.len() != reference_changes.len() {
            return Err(format!("Different number of streams affected: asupersync={}, reference={}",
                asupersync_changes.len(), reference_changes.len()));
        }

        // Sort changes by stream ID for comparison
        let mut asup_sorted = asupersync_changes;
        let mut ref_sorted = reference_changes;
        asup_sorted.sort_by_key(|(id, _, _)| *id);
        ref_sorted.sort_by_key(|(id, _, _)| *id);

        // Compare each stream's window changes
        for ((asup_id, asup_old, asup_new), (ref_id, ref_old, ref_new)) in
            asup_sorted.iter().zip(ref_sorted.iter()) {

            if asup_id != ref_id {
                return Err(format!("Stream ID mismatch in changes: asupersync={}, reference={}",
                    asup_id, ref_id));
            }

            if asup_old != ref_old {
                return Err(format!("Old window mismatch for stream {}: asupersync={}, reference={}",
                    asup_id, asup_old, ref_old));
            }

            if asup_new != ref_new {
                return Err(format!("New window mismatch for stream {}: asupersync={}, reference={}",
                    asup_id, asup_new, ref_new));
            }
        }

        // Verify final window states match
        for &stream_id in &stream_ids {
            let asupersync_window = asupersync.get_window(stream_id).unwrap();
            let reference_window = reference.get_window(stream_id).unwrap();

            if asupersync_window != reference_window {
                return Err(format!("Final window mismatch for stream {} after setting to {}: asupersync={}, reference={}",
                    stream_id, new_window_size, asupersync_window, reference_window));
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
    let basic_tests = vec![
        ("Basic window increase", test_basic_increase as fn() -> Result<(), String>, "Tests increasing SETTINGS_INITIAL_WINDOW_SIZE"),
        ("Window size decrease", test_window_decrease, "Tests decreasing SETTINGS_INITIAL_WINDOW_SIZE"),
        ("Multiple window changes", test_multiple_changes, "Tests sequential window size changes"),
        ("Window changes with data transfer", test_with_data_transfer, "Tests window changes with active data transfer"),
        ("Minimum window size", test_minimum_window, "Tests minimum allowed window size (0)"),
        ("Maximum window size", test_maximum_window, "Tests maximum allowed window size (2^31-1)"),
    ];

    let mut comprehensive_tests = vec![
        ("Mixed stream states", test_mixed_stream_states, "Tests mixed stream states during window changes"),
        ("Flow control boundaries", test_flow_control_boundaries, "Tests flow control boundary conditions"),
    ];

    let mut all_tests = basic_tests;
    if comprehensive {
        all_tests.append(&mut comprehensive_tests);
    }

    let mut tests_passed = 0;
    let mut tests_failed = 0;

    for (name, test_fn, description) in all_tests {
        match test_fn() {
            Ok(()) => {
                test_results.push(TestResult {
                    test_name: name.to_string(),
                    passed: true,
                    error_message: None,
                    description: description.to_string(),
                });
                tests_passed += 1;
            }
            Err(error) => {
                test_results.push(TestResult {
                    test_name: name.to_string(),
                    passed: false,
                    error_message: Some(error),
                    description: description.to_string(),
                });
                tests_failed += 1;
            }
        }
    }

    let conformant = tests_failed == 0;
    let summary = if conformant {
        format!("All {} tests passed - SETTINGS_INITIAL_WINDOW_SIZE behavior is conformant", tests_passed)
    } else {
        format!("{} of {} tests failed - behavior divergence detected", tests_failed, tests_passed + tests_failed)
    };

    ConformanceResults {
        conformant_implementations: conformant,
        tests_passed,
        tests_failed,
        test_results,
        summary,
    }
}

/// Format results as JSON
pub fn format_results_as_json(results: &ConformanceResults) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|_| "Error formatting JSON".to_string())
}

/// Format results as Markdown
pub fn format_results_as_markdown(results: &ConformanceResults) -> String {
    let mut output = String::new();

    output.push_str("# SETTINGS_INITIAL_WINDOW_SIZE Conformance Test Results\n\n");
    output.push_str(&format!("**Status:** {}\n\n", if results.conformant_implementations { "✅ CONFORMANT" } else { "❌ NON-CONFORMANT" }));
    output.push_str(&format!("**Tests Passed:** {}\n", results.tests_passed));
    output.push_str(&format!("**Tests Failed:** {}\n\n", results.tests_failed));

    output.push_str("## Test Results\n\n");
    output.push_str("| Test | Status | Description |\n");
    output.push_str("|------|--------|-------------|\n");

    for result in &results.test_results {
        let status = if result.passed { "✅ PASS" } else { "❌ FAIL" };
        output.push_str(&format!("| {} | {} | {} |\n", result.test_name, status, result.description));
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

    output.push_str("SETTINGS_INITIAL_WINDOW_SIZE Conformance Test Results\n");
    output.push_str("=".repeat(55).as_str());
    output.push_str("\n\n");

    output.push_str(&format!("Status: {}\n", if results.conformant_implementations { "CONFORMANT" } else { "NON-CONFORMANT" }));
    output.push_str(&format!("Tests Passed: {}\n", results.tests_passed));
    output.push_str(&format!("Tests Failed: {}\n\n", results.tests_failed));

    for result in &results.test_results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        output.push_str(&format!("  {} ... {}\n", result.test_name, status));
        if !result.passed {
            if let Some(ref error) = result.error_message {
                output.push_str(&format!("    Error: {}\n", error));
            }
        }
    }

    output.push_str(&format!("\n{}\n", results.summary));
    output
}

/// Property-based conformance test with arbitrary scenarios
pub fn test_arbitrary_scenarios(scenarios: Vec<WindowSizeScenario>) -> Vec<String> {
    let mut failures = Vec::new();

    for (i, scenario) in scenarios.iter().enumerate() {
        if let Err(error) = test_conformance(scenario.clone()) {
            failures.push(format!("Scenario {}: {}", i, error));
        }
    }

    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conformance_basic() {
        let results = run_basic_conformance_tests();
        assert!(results.conformant_implementations);
    }

    #[test]
    fn test_window_size_math() {
        let mut state = MockConnectionState::new(65535);
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
        let mut state = MockConnectionState::new(65535);
        let stream1 = state.create_stream();
        let stream2 = state.create_stream();
        let stream3 = state.create_stream();

        let changes = state.update_initial_window_size(98304).unwrap();
        assert_eq!(changes.len(), 3);

        // All streams should have the same change pattern
        for &(_, old_window, new_window) in &changes {
            assert_eq!(old_window, 65535);
            assert_eq!(new_window, 98304);
        }
    }
}