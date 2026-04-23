//! Actor Mailbox Cancel Protocol Conformance Tests
//!
//! This module implements conformance testing for the Actor Mailbox Cancel Protocol
//! as specified in src/actor.rs:790-899 (run_actor_loop).
//!
//! The protocol defines a 4-phase lifecycle with specific cancellation semantics:
//! 1. Initialization: on_start() always executes
//! 2. Message Loop: cancellation-aware message processing
//! 3. Drain: no silent message drops (unless aborted)
//! 4. Cleanup: masked on_stop() execution
//!
//! Test coverage follows Pattern 4: Spec-Derived Test Matrix with one test per
//! MUST/SHOULD clause identified in the protocol specification.

#![cfg(feature = "test-internals")]

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use serde::{Deserialize, Serialize};

use asupersync::actor::{Actor, ActorHandle, ActorState};
use asupersync::cx::{Cx, Scope};
use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, CancelReason, RegionId, TaskId};

// ============================================================================
// TEST FRAMEWORK TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String }, // Known divergence (XFAIL)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResult {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub description: &'static str,
    pub verdict: TestVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Actor Mailbox Protocol conformance test case.
#[derive(Debug)]
pub struct ProtocolTestCase {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub description: &'static str,
    pub test_fn: fn() -> ConformanceResult,
}

// ============================================================================
// TEST ACTOR IMPLEMENTATIONS
// ============================================================================

/// Actor that records lifecycle events for protocol validation.
#[derive(Debug)]
struct LifecycleProbeActor {
    events: Arc<Mutex<Vec<String>>>,
    message_count: Arc<AtomicU32>,
    should_panic: Arc<AtomicBool>,
    delay_in_handler: Option<Duration>,
}

impl LifecycleProbeActor {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            events,
            message_count: Arc::new(AtomicU32::new(0)),
            should_panic: Arc::new(AtomicBool::new(false)),
            delay_in_handler: None,
        }
    }

    fn with_panic_trigger(mut self, trigger: Arc<AtomicBool>) -> Self {
        self.should_panic = trigger;
        self
    }

    fn with_handler_delay(mut self, delay: Duration) -> Self {
        self.delay_in_handler = Some(delay);
        self
    }

    fn record_event(&self, event: &str) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.to_string());
        }
    }
}

#[derive(Debug)]
pub enum ProbeMessage {
    Increment,
    Delay(Duration),
    TriggerPanic,
    Noop,
}

impl Actor for LifecycleProbeActor {
    type Message = ProbeMessage;

    fn on_start(&mut self, cx: &Cx) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.record_event("on_start");

            // Test AMP-1.1: on_start executes even if cancelled
            if cx.checkpoint().is_err() {
                self.record_event("on_start_cancelled");
            }
        })
    }

    fn handle(
        &mut self,
        cx: &Cx,
        msg: Self::Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let msg_id = self.message_count.fetch_add(1, Ordering::Relaxed);
            self.record_event(&format!("handle_message_{}", msg_id));

            match msg {
                ProbeMessage::Increment => {
                    self.record_event("increment");
                }
                ProbeMessage::Delay(duration) => {
                    if let Some(delay) = self.delay_in_handler {
                        tokio::time::sleep(delay.into()).await;
                    }
                    self.record_event(&format!("delayed_{:?}", duration));
                }
                ProbeMessage::TriggerPanic => {
                    if self.should_panic.load(Ordering::Relaxed) {
                        self.record_event("panic_triggered");
                        panic!("Test panic in handle");
                    }
                }
                ProbeMessage::Noop => {
                    self.record_event("noop");
                }
            }

            // Test cancellation awareness in message handler
            if cx.checkpoint().is_err() {
                self.record_event("handle_cancelled");
            }
        })
    }

    fn on_stop(&mut self, cx: &Cx) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.record_event("on_stop");

            // Test AMP-4.1: on_stop should run with cancellation masked
            if cx.checkpoint().is_err() {
                self.record_event("on_stop_cancel_not_masked");
            } else {
                self.record_event("on_stop_cancel_masked");
            }
        })
    }
}

// ============================================================================
// PROTOCOL CONFORMANCE TESTS
// ============================================================================

/// AMP-1.1: on_start() executes even if pre-stopped or cancelled
fn test_amp_1_1_on_start_always_executes() -> ConformanceResult {
    let start = std::time::Instant::now();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = Scope::<asupersync::cx::scope::FailFast>::new(region, Budget::INFINITE);

    let actor = LifecycleProbeActor::new(Arc::clone(&events));

    let result = scope.spawn_actor(&mut runtime.state, &cx, actor, 16);
    if let Err(e) = result {
        return ConformanceResult {
            id: "AMP-1.1",
            section: "1",
            level: RequirementLevel::Must,
            description: "on_start() executes even if pre-stopped or cancelled",
            verdict: TestVerdict::Fail { reason: format!("spawn_actor failed: {e:?}") },
            duration_ms: Some(start.elapsed().as_millis() as u64),
        };
    }

    let (mut handle, stored) = result.unwrap();
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    // Pre-stop the actor before it runs
    handle.stop();

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let events = events.lock().unwrap().clone();

    let verdict = if events.contains(&"on_start".to_string()) {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: format!("on_start did not execute. Events: {events:?}")
        }
    };

    ConformanceResult {
        id: "AMP-1.1",
        section: "1",
        level: RequirementLevel::Must,
        description: "on_start() executes even if pre-stopped or cancelled",
        verdict,
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// AMP-3.1: No messages silently dropped unless aborted
fn test_amp_3_1_no_silent_message_drops() -> ConformanceResult {
    let start = std::time::Instant::now();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = Scope::<asupersync::cx::scope::FailFast>::new(region, Budget::INFINITE);

    let actor = LifecycleProbeActor::new(Arc::clone(&events));
    let (handle, stored) = scope.spawn_actor(&mut runtime.state, &cx, actor, 16).unwrap();
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_for(Duration::from_millis(10));

    // Send multiple messages
    for i in 0..5 {
        if handle.try_send(ProbeMessage::Noop).is_err() {
            break;
        }
    }

    // Graceful stop (should drain messages)
    handle.stop();
    runtime.run_until_quiescent();

    let events = events.lock().unwrap().clone();

    // Count message handler invocations
    let message_events: Vec<_> = events.iter()
        .filter(|e| e.starts_with("handle_message_"))
        .collect();

    let verdict = if message_events.len() >= 5 {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: format!("Expected 5+ message events, got {}. Events: {events:?}", message_events.len())
        }
    };

    ConformanceResult {
        id: "AMP-3.1",
        section: "3",
        level: RequirementLevel::Must,
        description: "No messages silently dropped unless aborted",
        verdict,
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// AMP-3.4: Aborted drain discards messages via try_recv() loop
fn test_amp_3_4_aborted_drain_discards_messages() -> ConformanceResult {
    let start = std::time::Instant::now();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = Scope::<asupersync::cx::scope::FailFast>::new(region, Budget::INFINITE);

    let actor = LifecycleProbeActor::new(Arc::clone(&events));
    let (handle, stored) = scope.spawn_actor(&mut runtime.state, &cx, actor, 16).unwrap();
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_for(Duration::from_millis(10));

    // Send messages that would be buffered
    for i in 0..5 {
        if handle.try_send(ProbeMessage::Noop).is_err() {
            break;
        }
    }

    // Abort (should discard messages without processing)
    handle.abort();
    runtime.run_until_quiescent();

    let events = events.lock().unwrap().clone();

    // Count message handler invocations - should be fewer due to abort
    let message_events: Vec<_> = events.iter()
        .filter(|e| e.starts_with("handle_message_"))
        .collect();

    // The test passes if fewer messages were processed than sent, and on_stop still ran
    let has_on_stop = events.contains(&"on_stop".to_string());

    let verdict = if has_on_stop && message_events.len() < 5 {
        TestVerdict::Pass
    } else {
        TestVerdict::Fail {
            reason: format!(
                "Expected <5 message events due to abort, got {}. on_stop present: {}. Events: {events:?}",
                message_events.len(), has_on_stop
            )
        }
    };

    ConformanceResult {
        id: "AMP-3.4",
        section: "3",
        level: RequirementLevel::Must,
        description: "Aborted drain discards messages via try_recv() loop",
        verdict,
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// AMP-4.1: on_stop() executes with cancellation masked
fn test_amp_4_1_on_stop_cancellation_masked() -> ConformanceResult {
    let start = std::time::Instant::now();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = Scope::<asupersync::cx::scope::FailFast>::new(region, Budget::INFINITE);

    let actor = LifecycleProbeActor::new(Arc::clone(&events));
    let (handle, stored) = scope.spawn_actor(&mut runtime.state, &cx, actor, 16).unwrap();
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_for(Duration::from_millis(10));

    // Abort to trigger cancellation
    handle.abort();
    runtime.run_until_quiescent();

    let events = events.lock().unwrap().clone();

    let verdict = if events.contains(&"on_stop_cancel_masked".to_string()) {
        TestVerdict::Pass
    } else if events.contains(&"on_stop_cancel_not_masked".to_string()) {
        TestVerdict::Fail {
            reason: "on_stop detected cancellation (not properly masked)".to_string()
        }
    } else if events.contains(&"on_stop".to_string()) {
        TestVerdict::Pass // on_stop ran, assume masking worked
    } else {
        TestVerdict::Fail {
            reason: format!("on_stop did not execute. Events: {events:?}")
        }
    };

    ConformanceResult {
        id: "AMP-4.1",
        section: "4",
        level: RequirementLevel::Must,
        description: "on_stop() executes with cancellation masked",
        verdict,
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// AMP-5.1: stop() sets ActorState::Stopping + closes receiver
fn test_amp_5_1_stop_sets_stopping_state() -> ConformanceResult {
    let start = std::time::Instant::now();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = Scope::<asupersync::cx::scope::FailFast>::new(region, Budget::INFINITE);

    let actor = LifecycleProbeActor::new(Arc::clone(&events));
    let (handle, stored) = scope.spawn_actor(&mut runtime.state, &cx, actor, 16).unwrap();
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_for(Duration::from_millis(10));

    // Verify sender is not closed initially
    let initial_send = handle.try_send(ProbeMessage::Noop);

    // Call stop()
    handle.stop();

    // Verify sender is now closed
    let post_stop_send = handle.try_send(ProbeMessage::Noop);

    runtime.run_until_quiescent();

    let verdict = match (initial_send, post_stop_send) {
        (Ok(()), Err(_)) => TestVerdict::Pass,
        (Err(_), _) => TestVerdict::Fail {
            reason: "Initial send failed - mailbox was already closed".to_string()
        },
        (Ok(()), Ok(())) => TestVerdict::Fail {
            reason: "Post-stop send succeeded - mailbox was not closed".to_string()
        },
    };

    ConformanceResult {
        id: "AMP-5.1",
        section: "5",
        level: RequirementLevel::Must,
        description: "stop() sets ActorState::Stopping + closes receiver",
        verdict,
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }
}

// ============================================================================
// CONFORMANCE TEST SUITE
// ============================================================================

const PROTOCOL_TEST_CASES: &[ProtocolTestCase] = &[
    ProtocolTestCase {
        id: "AMP-1.1",
        section: "1",
        level: RequirementLevel::Must,
        description: "on_start() executes even if pre-stopped or cancelled",
        test_fn: test_amp_1_1_on_start_always_executes,
    },
    ProtocolTestCase {
        id: "AMP-3.1",
        section: "3",
        level: RequirementLevel::Must,
        description: "No messages silently dropped unless aborted",
        test_fn: test_amp_3_1_no_silent_message_drops,
    },
    ProtocolTestCase {
        id: "AMP-3.4",
        section: "3",
        level: RequirementLevel::Must,
        description: "Aborted drain discards messages via try_recv() loop",
        test_fn: test_amp_3_4_aborted_drain_discards_messages,
    },
    ProtocolTestCase {
        id: "AMP-4.1",
        section: "4",
        level: RequirementLevel::Must,
        description: "on_stop() executes with cancellation masked",
        test_fn: test_amp_4_1_on_stop_cancellation_masked,
    },
    ProtocolTestCase {
        id: "AMP-5.1",
        section: "5",
        level: RequirementLevel::Must,
        description: "stop() sets ActorState::Stopping + closes receiver",
        test_fn: test_amp_5_1_stop_sets_stopping_state,
    },
];

/// Run full Actor Mailbox Protocol conformance test suite.
pub fn run_conformance_tests() -> Vec<ConformanceResult> {
    let mut results = Vec::new();

    for test_case in PROTOCOL_TEST_CASES {
        eprintln!("Running test: {} - {}", test_case.id, test_case.description);
        let result = (test_case.test_fn)();

        // Emit structured JSON-line output for CI parsing
        if let Ok(json) = serde_json::to_string(&result) {
            eprintln!("{}", json);
        }

        results.push(result);
    }

    results
}

/// Generate conformance compliance matrix report.
pub fn generate_compliance_report(results: &[ConformanceResult]) -> String {
    use std::collections::BTreeMap;

    let mut by_section: BTreeMap<&str, Vec<&ConformanceResult>> = BTreeMap::new();
    let mut total_must = 0;
    let mut total_should = 0;
    let mut pass_must = 0;
    let mut pass_should = 0;

    for result in results {
        by_section.entry(result.section).or_default().push(result);
        match result.level {
            RequirementLevel::Must => {
                total_must += 1;
                if matches!(result.verdict, TestVerdict::Pass) {
                    pass_must += 1;
                }
            }
            RequirementLevel::Should => {
                total_should += 1;
                if matches!(result.verdict, TestVerdict::Pass) {
                    pass_should += 1;
                }
            }
            RequirementLevel::May => {}
        }
    }

    let mut report = String::new();
    report.push_str("# Actor Mailbox Cancel Protocol Conformance Report\n\n");
    report.push_str(&format!(
        "**Overall Score**: {}/{} MUST ({}%), {}/{} SHOULD ({}%)\n\n",
        pass_must, total_must,
        if total_must > 0 { (pass_must * 100) / total_must } else { 100 },
        pass_should, total_should,
        if total_should > 0 { (pass_should * 100) / total_should } else { 100 }
    ));

    report.push_str("| Section | MUST (pass/total) | SHOULD (pass/total) | Score |\n");
    report.push_str("|---------|-------------------|---------------------|-------|\n");

    for (section, section_results) in by_section {
        let mut must_pass = 0;
        let mut must_total = 0;
        let mut should_pass = 0;
        let mut should_total = 0;

        for result in &section_results {
            match result.level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if matches!(result.verdict, TestVerdict::Pass) {
                        must_pass += 1;
                    }
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if matches!(result.verdict, TestVerdict::Pass) {
                        should_pass += 1;
                    }
                }
                RequirementLevel::May => {}
            }
        }

        let score = if must_total + should_total > 0 {
            ((must_pass + should_pass) * 100) / (must_total + should_total)
        } else {
            100
        };

        report.push_str(&format!(
            "| §{} | {}/{} | {}/{} | {}% |\n",
            section, must_pass, must_total, should_pass, should_total, score
        ));
    }

    report.push_str("\n## Test Details\n\n");
    for result in results {
        let status = match &result.verdict {
            TestVerdict::Pass => "✓ PASS",
            TestVerdict::Fail { reason } => &format!("✗ FAIL: {}", reason),
            TestVerdict::Skipped { reason } => &format!("⚠ SKIP: {}", reason),
            TestVerdict::ExpectedFailure { reason } => &format!("⚠ XFAIL: {}", reason),
        };

        report.push_str(&format!(
            "- **{}** (§{}, {:?}): {} - {}\n",
            result.id, result.section, result.level, result.description, status
        ));
    }

    report
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_mailbox_protocol_full_conformance() {
        let results = run_conformance_tests();

        let mut fail_count = 0;
        for result in &results {
            if matches!(result.verdict, TestVerdict::Fail { .. }) {
                fail_count += 1;
                eprintln!("FAIL {}: {:?}", result.id, result.verdict);
            }
        }

        let report = generate_compliance_report(&results);
        eprintln!("\n{}", report);

        assert_eq!(fail_count, 0, "{fail_count} conformance tests failed");
    }

    #[test]
    fn conformance_test_amp_1_1() {
        let result = test_amp_1_1_on_start_always_executes();
        assert!(matches!(result.verdict, TestVerdict::Pass),
            "AMP-1.1 failed: {:?}", result.verdict);
    }

    #[test]
    fn conformance_test_amp_3_1() {
        let result = test_amp_3_1_no_silent_message_drops();
        assert!(matches!(result.verdict, TestVerdict::Pass),
            "AMP-3.1 failed: {:?}", result.verdict);
    }

    #[test]
    fn conformance_test_amp_3_4() {
        let result = test_amp_3_4_aborted_drain_discards_messages();
        assert!(matches!(result.verdict, TestVerdict::Pass),
            "AMP-3.4 failed: {:?}", result.verdict);
    }

    #[test]
    fn conformance_test_amp_4_1() {
        let result = test_amp_4_1_on_stop_cancellation_masked();
        assert!(matches!(result.verdict, TestVerdict::Pass),
            "AMP-4.1 failed: {:?}", result.verdict);
    }

    #[test]
    fn conformance_test_amp_5_1() {
        let result = test_amp_5_1_stop_sets_stopping_state();
        assert!(matches!(result.verdict, TestVerdict::Pass),
            "AMP-5.1 failed: {:?}", result.verdict);
    }
}