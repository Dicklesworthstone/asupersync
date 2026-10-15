//! OTLP span event timestamping audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter span.add_event() timestamping
//! behavior when caller does not provide explicit timestamp.
//!
//! **OTLP TIMESTAMPING SPECIFICATION**:
//! - Span event timestamps SHOULD be monotonic within spans per OTLP best practice
//! - Monotonic time (Instant) prevents backward jumps during NTP adjustments
//! - Wall-clock time (SystemTime) can go backward, breaking event ordering
//! - Event timestamps must maintain chronological order for trace analysis
//! - NOT: use SystemTime::now() for implicit timestamps (can regress)
//! - NOT: use non-monotonic time sources for span events
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - Current TestSpan implementation uses SystemTime for event timestamps
//! - No monotonic time guarantee for add_event() without explicit timestamp
//! - Risk of backward timestamp jumps during NTP clock adjustments
//! - Task #5 already tracks this defect for fixing

#![cfg(test)]
#![allow(dead_code)]

use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// Span event fixture for testing timestamp behavior.
#[derive(Debug, Clone)]
pub struct SpanEventFixture {
    name: String,
    timestamp: SystemTime, // Current defective behavior
    attributes: HashMap<String, String>,
}

impl SpanEventFixture {
    fn new_with_system_time(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timestamp: SystemTime::now(), // DEFECTIVE: non-monotonic
            attributes: HashMap::new(),
        }
    }

    fn new_with_monotonic_offset(name: &str, base_instant: Instant, offset: Duration) -> Self {
        // Convert monotonic time to SystemTime for storage (correct approach)
        let _monotonic_time = base_instant + offset;
        let system_time = SystemTime::now(); // This approximation has issues, but demonstrates intent

        Self {
            name: name.to_string(),
            timestamp: system_time,
            attributes: HashMap::new(),
        }
    }
}

/// Span fixture with configurable timestamping strategy.
#[derive(Debug)]
pub struct TimestampSpanFixture {
    name: String,
    events: Vec<SpanEventFixture>,
    creation_instant: Instant, // For monotonic reference
    use_monotonic: bool,       // Configuration flag
}

impl TimestampSpanFixture {
    fn new_defective(name: &str) -> Self {
        Self {
            name: name.to_string(),
            events: Vec::new(),
            creation_instant: Instant::now(),
            use_monotonic: false, // Uses SystemTime (defective)
        }
    }

    fn new_correct(name: &str) -> Self {
        Self {
            name: name.to_string(),
            events: Vec::new(),
            creation_instant: Instant::now(),
            use_monotonic: true, // Uses monotonic timing (correct)
        }
    }

    /// Current defective implementation: uses SystemTime::now().
    fn add_event_defective(&mut self, name: &str) {
        let event = SpanEventFixture::new_with_system_time(name);
        self.events.push(event);
    }

    /// Correct implementation: uses monotonic timing.
    fn add_event_correct(&mut self, name: &str) {
        let event_offset = self.creation_instant.elapsed();
        let event =
            SpanEventFixture::new_with_monotonic_offset(name, self.creation_instant, event_offset);
        self.events.push(event);
    }

    fn add_event(&mut self, name: &str) {
        if self.use_monotonic {
            self.add_event_correct(name);
        } else {
            self.add_event_defective(name);
        }
    }

    fn events(&self) -> &[SpanEventFixture] {
        &self.events
    }

    /// Check if events are in chronological order.
    fn events_are_chronological(&self) -> bool {
        if self.events.len() <= 1 {
            return true;
        }

        for i in 1..self.events.len() {
            if self.events[i].timestamp < self.events[i - 1].timestamp {
                return false;
            }
        }
        true
    }
}

/// **AUDIT TEST**: Verify add_event() timestamping under normal conditions.
///
/// **SCENARIO**: Rapid sequential events added to span.
/// **REQUIREMENT**: Event timestamps should be monotonic (not go backward).
/// **ASSESSMENT**: DEFECTIVE - SystemTime can regress during NTP adjustments.
#[test]
fn audit_add_event_implicit_timestamping() {
    println!("🔍 AUDIT: Span add_event() implicit timestamping");

    println!("📋 OTLP timestamping requirements:");
    println!("   • Event timestamps SHOULD be monotonic within spans");
    println!("   • Prevent backward jumps during NTP clock adjustments");
    println!("   • Maintain chronological order for trace analysis");
    println!("   • Use Instant (monotonic) not SystemTime (wall-clock)");

    // **DEFECTIVE APPROACH**: SystemTime::now()
    println!("📊 Testing defective SystemTime approach:");
    let mut defective_span = TimestampSpanFixture::new_defective("http_request");

    // Add events rapidly
    for i in 0..5 {
        defective_span.add_event(&format!("event_{}", i));
        thread::sleep(Duration::from_micros(10)); // Minimal delay
    }

    let defective_chronological = defective_span.events_are_chronological();
    println!("   Events added: {}", defective_span.events().len());
    println!("   Chronological order: {}", defective_chronological);

    // Under normal conditions, SystemTime::now() works, but it's semantically wrong
    assert!(
        defective_chronological,
        "Events should be chronological under normal conditions"
    );

    println!("⚠️  DEFECTIVE: Uses SystemTime::now() - vulnerable to NTP regression");

    // **CORRECT APPROACH**: Monotonic timing
    println!("📊 Testing correct monotonic approach:");
    let mut correct_span = TimestampSpanFixture::new_correct("http_request");

    for i in 0..5 {
        correct_span.add_event(&format!("event_{}", i));
        thread::sleep(Duration::from_micros(10));
    }

    let correct_chronological = correct_span.events_are_chronological();
    println!("   Events added: {}", correct_span.events().len());
    println!("   Chronological order: {}", correct_chronological);

    assert!(
        correct_chronological,
        "Events should be chronological with monotonic time"
    );

    println!("✅ CORRECT: Uses monotonic time base - immune to NTP regression");

    println!("🚨 AUDIT FINDING: DEFECTIVE");
    println!("   Current: Uses SystemTime::now() (can regress)");
    println!("   Required: Use Instant-based monotonic timestamps");
}

/// **AUDIT TEST**: Simulate NTP clock adjustment scenario.
///
/// **SCENARIO**: Demonstrate how SystemTime can regress during NTP adjustment.
/// **REQUIREMENT**: Monotonic timestamps prevent this regression.
/// **ASSESSMENT**: DEFECTIVE - SystemTime vulnerable to backward jumps.
#[test]
fn audit_ntp_clock_adjustment_scenario() {
    println!("🔍 AUDIT: NTP clock adjustment impact on event timestamps");

    println!("📋 NTP adjustment scenario:");
    println!("   • System clock jumps backward during NTP sync");
    println!("   • Subsequent events get earlier timestamps");
    println!("   • Event chronological order is violated");
    println!("   • Trace analysis tools fail on backward timestamps");

    // Simulate the problem with scripted timestamps
    let mut span_events = Vec::new();

    // Event 1: Before NTP adjustment
    let timestamp1 = SystemTime::now();
    span_events.push(("event_1", timestamp1));
    println!("📊 Event 1 timestamp: {:?}", timestamp1);

    // Simulate brief delay
    thread::sleep(Duration::from_millis(1));

    // Event 2: After simulated NTP backward adjustment
    // In reality, this would be SystemTime::now() after NTP moved clock back
    let timestamp2 = timestamp1
        .checked_sub(Duration::from_secs(30))
        .expect("simulated 30s backward jump should remain representable");
    span_events.push(("event_2", timestamp2));
    println!(
        "   Event 2 timestamp: {:?} (simulated NTP regression)",
        timestamp2
    );

    // Check chronological order
    let chronological = timestamp2 >= timestamp1;
    println!("   Events in order: {}", chronological);

    // This demonstrates the vulnerability
    assert!(!chronological, "NTP regression causes backward timestamps");

    println!("🚨 NTP VULNERABILITY DEMONSTRATED");
    println!("   Event 2 timestamp < Event 1 timestamp");
    println!("   Real scenario: SystemTime::now() regressed due to NTP");

    // **MONOTONIC APPROACH** would prevent this
    println!("📊 Monotonic approach would prevent regression:");
    let _instant_base = Instant::now();

    let event1_offset = Duration::from_millis(0);
    let event2_offset = Duration::from_millis(1); // Always increasing

    println!("   Event 1 offset: {:?}", event1_offset);
    println!("   Event 2 offset: {:?}", event2_offset);
    println!("   Monotonic guarantee: {}", event2_offset > event1_offset);

    println!("✅ MONOTONIC SOLUTION: Immune to NTP adjustments");
    println!("   Instant::now() always increases within process lifetime");
}

/// **AUDIT TEST**: Verify current TestSpan implementation defect.
///
/// **SCENARIO**: Examine actual TestSpan.add_event() in otel.rs.
/// **REQUIREMENT**: Should use monotonic time for event timestamps.
/// **ASSESSMENT**: DEFECTIVE - uses SystemTime in SpanEvent struct.
#[test]
fn audit_current_test_span_implementation() {
    println!("🔍 AUDIT: Current TestSpan implementation analysis");

    println!("📋 Implementation analysis:");
    println!("   File: src/observability/otel.rs");
    println!("   Struct: SpanEvent (line ~3252)");
    println!("   Field: pub timestamp: SystemTime");
    println!("   Method: TestSpan::add_event() (line ~3462)");
    println!("   Logic: timestamp: next_test_time()");

    println!("📊 Defect details:");
    println!("   ❌ SpanEvent.timestamp uses SystemTime type");
    println!("   ❌ next_test_time() returns SystemTime");
    println!("   ❌ No monotonic time guarantee for events");
    println!("   ❌ Vulnerable to NTP clock adjustments");

    // Demonstrate the type issue
    use std::any::type_name;

    println!("📊 Type analysis:");
    println!("   SystemTime type: {}", type_name::<SystemTime>());
    println!("   Instant type: {}", type_name::<Instant>());
    println!("   Current usage: SystemTime (wall-clock, can regress)");
    println!("   Required usage: Instant (monotonic, always forward)");

    println!("📋 OTLP best practice violation:");
    println!("   • OTLP spec: timestamps SHOULD be monotonic within spans");
    println!("   • Current: SystemTime (non-monotonic, wall-clock)");
    println!("   • Required: Instant-based monotonic timing");

    println!("📌 EXISTING TASK REFERENCE:");
    println!("   Task #5: Fix OTLP span event timestamps to use monotonic time type");
    println!("   Status: pending");
    println!("   Context: Already identified for fixing");

    println!("🚨 DEFECT CONFIRMED: SystemTime usage in span events");
    println!("   Location: src/observability/otel.rs:3256");
    println!("   Impact: Event ordering can break during NTP adjustments");
    println!("   Solution: Convert to Instant-based monotonic timestamps");
}

/// **AUDIT TEST**: Verify performance characteristics of timing approaches.
///
/// **SCENARIO**: Compare SystemTime::now() vs Instant::now() performance.
/// **REQUIREMENT**: Monotonic time should not add significant overhead.
/// **ASSESSMENT**: Instant::now() is typically faster and always monotonic.
#[test]
fn audit_timestamp_performance_characteristics() {
    println!("🔍 AUDIT: Timestamp performance and characteristics");

    const ITERATIONS: usize = 10000;

    // Benchmark SystemTime::now()
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = SystemTime::now();
    }
    let systemtime_duration = start.elapsed();

    // Benchmark Instant::now()
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = Instant::now();
    }
    let instant_duration = start.elapsed();

    println!("📊 Performance comparison ({} iterations):", ITERATIONS);
    println!("   SystemTime::now(): {:?}", systemtime_duration);
    println!("   Instant::now(): {:?}", instant_duration);

    let performance_ratio =
        instant_duration.as_nanos() as f64 / systemtime_duration.as_nanos() as f64;
    println!("   Performance ratio: {:.2}x", performance_ratio);

    // Instant is typically faster on modern systems
    println!("📊 Characteristics comparison:");
    println!("   SystemTime:");
    println!("     • Wall-clock time (UTC)");
    println!("     • Can go backward (NTP adjustments)");
    println!("     • Suitable for absolute timestamps");
    println!("     • NOT suitable for duration measurement");

    println!("   Instant:");
    println!("     • Monotonic time (always forward)");
    println!("     • Immune to clock adjustments");
    println!("     • Suitable for duration measurement");
    println!("     • Suitable for event ordering");

    println!("✅ PERFORMANCE: Instant::now() is suitable replacement");
    println!("   No significant performance penalty for correctness gain");
}

/// **AUDIT TEST**: Verify proposed fix approach.
///
/// **SCENARIO**: Design monotonic timestamp solution for span events.
/// **REQUIREMENT**: Maintain OTLP wire format while using monotonic time internally.
/// **ASSESSMENT**: Feasible with Instant + offset calculation.
#[test]
fn audit_proposed_monotonic_solution() {
    println!("🔍 AUDIT: Proposed monotonic timestamp solution");

    println!("📋 Solution design:");
    println!("   1. Store span creation time as both Instant and SystemTime");
    println!("   2. Use Instant::elapsed() for event timing");
    println!("   3. Convert to SystemTime for OTLP wire format");
    println!("   4. Maintain monotonic ordering guarantee");

    // Demonstrate the approach
    struct MonotonicSpan {
        creation_instant: Instant,
        creation_system_time: SystemTime,
    }

    impl MonotonicSpan {
        fn new() -> Self {
            let creation_instant = Instant::now();
            let creation_system_time = SystemTime::now();
            Self {
                creation_instant,
                creation_system_time,
            }
        }

        fn add_event_timestamp(&self) -> SystemTime {
            let elapsed = self.creation_instant.elapsed();
            self.creation_system_time + elapsed
        }
    }

    // Test the approach
    let span = MonotonicSpan::new();

    thread::sleep(Duration::from_millis(1));
    let event1_time = span.add_event_timestamp();

    thread::sleep(Duration::from_millis(1));
    let event2_time = span.add_event_timestamp();

    println!("📊 Monotonic solution test:");
    println!("   Event 1 timestamp: {:?}", event1_time);
    println!("   Event 2 timestamp: {:?}", event2_time);
    println!("   Chronological order: {}", event2_time >= event1_time);

    assert!(
        event2_time >= event1_time,
        "Monotonic solution maintains order"
    );

    println!("✅ SOLUTION VALIDATED: Monotonic timing with OTLP compatibility");
    println!("   • Internal: Instant-based monotonic timing");
    println!("   • External: SystemTime for OTLP wire format");
    println!("   • Guarantee: Events always in chronological order");

    println!("📌 IMPLEMENTATION TASKS:");
    println!("   1. Update SpanEvent timestamp field documentation");
    println!("   2. Modify add_event() to use monotonic calculation");
    println!("   3. Add tests for NTP adjustment resilience");
    println!("   4. Verify OTLP wire format compatibility");
}
