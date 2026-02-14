//! Clock skew fault injection for testing (bd-2ktrc.4).
//!
//! Wraps a [`TimeSource`] to inject deterministic clock skew, enabling tests
//! to validate that timeout-based protocols (lease expiry, budget deadlines,
//! heartbeat detection) remain correct when clocks diverge.
//!
//! # Skew Modes
//!
//! - **Static offset**: Constant nanosecond offset (positive = ahead, negative = behind).
//! - **Drift**: Progressive time drift at a configurable rate (nanos per second).
//! - **Jump**: One-time clock correction simulating an NTP adjustment.
//!
//! # Determinism
//!
//! Probabilistic decisions use [`ChaosRng`] (xorshift64). Same seed → same
//! skew sequence, enabling reproducible test failures.
//!
//! # Evidence Logging
//!
//! Every skew injection is logged to an [`EvidenceSink`].
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::clock_skew::*;
//! use asupersync::time::{VirtualClock, TimeSource};
//! use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
//! use std::sync::Arc;
//!
//! let base_clock = Arc::new(VirtualClock::new());
//! let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
//! let config = ClockSkewConfig::new(42)
//!     .with_static_offset_ms(50);  // 50ms ahead
//!
//! let skewed = SkewClock::new(base_clock, config, sink);
//! // skewed.now() returns base_clock.now() + 50ms
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::evidence_sink::EvidenceSink;
use crate::lab::chaos::ChaosRng;
use crate::time::TimeSource;
use crate::types::Time;
use franken_evidence::EvidenceLedger;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Signed offset in nanoseconds for clock skew.
///
/// Positive values move the clock ahead; negative move it behind.
type SkewNanos = i64;

/// Configuration for clock skew fault injection.
#[derive(Debug, Clone)]
pub struct ClockSkewConfig {
    /// Deterministic seed for the PRNG.
    pub seed: u64,
    /// Static offset in nanoseconds (positive = ahead, negative = behind).
    pub static_offset_ns: SkewNanos,
    /// Drift rate in nanoseconds per second of base-clock time.
    /// Positive = clock runs fast, negative = runs slow.
    pub drift_rate_ns_per_sec: SkewNanos,
    /// Probability of applying a random jitter on each `now()` call [0.0, 1.0].
    pub jitter_probability: f64,
    /// Maximum jitter magnitude in nanoseconds (applied symmetrically).
    pub jitter_max_ns: u64,
    /// One-time clock jump: (trigger_after_ns, jump_offset_ns).
    /// When base-clock time exceeds `trigger_after_ns`, a single jump of
    /// `jump_offset_ns` is applied.
    pub jump: Option<(u64, SkewNanos)>,
}

impl ClockSkewConfig {
    /// Create a new config with the given seed and no skew.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            static_offset_ns: 0,
            drift_rate_ns_per_sec: 0,
            jitter_probability: 0.0,
            jitter_max_ns: 0,
            jump: None,
        }
    }

    /// Set static offset in milliseconds.
    #[must_use]
    pub const fn with_static_offset_ms(mut self, ms: i64) -> Self {
        self.static_offset_ns = ms.saturating_mul(1_000_000);
        self
    }

    /// Set static offset in nanoseconds.
    #[must_use]
    pub const fn with_static_offset_ns(mut self, ns: SkewNanos) -> Self {
        self.static_offset_ns = ns;
        self
    }

    /// Set drift rate in nanoseconds per second.
    #[must_use]
    pub const fn with_drift_rate(mut self, ns_per_sec: SkewNanos) -> Self {
        self.drift_rate_ns_per_sec = ns_per_sec;
        self
    }

    /// Enable random jitter with the given probability and max magnitude.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in [0.0, 1.0].
    #[must_use]
    pub fn with_jitter(mut self, probability: f64, max_ns: u64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.jitter_probability = probability;
        self.jitter_max_ns = max_ns;
        self
    }

    /// Schedule a one-time clock jump at `trigger_after_ns` base-clock nanos.
    #[must_use]
    pub const fn with_jump(mut self, trigger_after_ns: u64, jump_offset_ns: SkewNanos) -> Self {
        self.jump = Some((trigger_after_ns, jump_offset_ns));
        self
    }

    /// Returns true if any skew is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.static_offset_ns != 0
            || self.drift_rate_ns_per_sec != 0
            || self.jitter_probability > 0.0
            || self.jump.is_some()
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Atomic counters for clock skew injection statistics.
pub struct ClockSkewStats {
    /// Total `now()` calls.
    reads: AtomicU64,
    /// Number of calls where skew was applied.
    skewed_reads: AtomicU64,
    /// Number of jitter injections.
    jitter_count: AtomicU64,
    /// Whether the scheduled jump has fired.
    jump_fired: AtomicU64,
    /// Maximum absolute skew observed (nanoseconds).
    max_abs_skew_ns: AtomicU64,
}

impl ClockSkewStats {
    fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            skewed_reads: AtomicU64::new(0),
            jitter_count: AtomicU64::new(0),
            jump_fired: AtomicU64::new(0),
            max_abs_skew_ns: AtomicU64::new(0),
        }
    }

    fn record_read(&self, abs_skew: u64) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if abs_skew > 0 {
            self.skewed_reads.fetch_add(1, Ordering::Relaxed);
        }
        // Update max using CAS loop.
        loop {
            let current = self.max_abs_skew_ns.load(Ordering::Relaxed);
            if abs_skew <= current {
                break;
            }
            if self
                .max_abs_skew_ns
                .compare_exchange_weak(current, abs_skew, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn record_jitter(&self) {
        self.jitter_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_jump(&self) {
        self.jump_fired.fetch_add(1, Ordering::Relaxed);
    }

    /// Take an immutable snapshot of current statistics.
    #[must_use]
    pub fn snapshot(&self) -> ClockSkewStatsSnapshot {
        ClockSkewStatsSnapshot {
            reads: self.reads.load(Ordering::Relaxed),
            skewed_reads: self.skewed_reads.load(Ordering::Relaxed),
            jitter_count: self.jitter_count.load(Ordering::Relaxed),
            jump_fired: self.jump_fired.load(Ordering::Relaxed) > 0,
            max_abs_skew_ns: self.max_abs_skew_ns.load(Ordering::Relaxed),
        }
    }
}

/// Immutable snapshot of clock skew statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockSkewStatsSnapshot {
    /// Total `now()` calls.
    pub reads: u64,
    /// Number of calls where skew was applied.
    pub skewed_reads: u64,
    /// Number of jitter injections.
    pub jitter_count: u64,
    /// Whether the scheduled jump has fired.
    pub jump_fired: bool,
    /// Maximum absolute skew observed (nanoseconds).
    pub max_abs_skew_ns: u64,
}

// ---------------------------------------------------------------------------
// SkewClock
// ---------------------------------------------------------------------------

/// A [`TimeSource`] wrapper that injects deterministic clock skew.
///
/// Wraps a base `TimeSource` (typically `VirtualClock`) and applies
/// configurable offsets, drift, jitter, and jumps to the returned time.
pub struct SkewClock {
    base: Arc<dyn TimeSource>,
    config: ClockSkewConfig,
    rng: Mutex<ChaosRng>,
    stats: ClockSkewStats,
    jump_fired: AtomicU64,
    evidence_sink: Arc<dyn EvidenceSink>,
}

impl std::fmt::Debug for SkewClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.stats.snapshot();
        f.debug_struct("SkewClock")
            .field("static_offset_ns", &self.config.static_offset_ns)
            .field("drift_rate_ns_per_sec", &self.config.drift_rate_ns_per_sec)
            .field("reads", &snap.reads)
            .field("skewed_reads", &snap.skewed_reads)
            .finish_non_exhaustive()
    }
}

impl SkewClock {
    /// Create a new skewed clock wrapping the given base clock.
    #[must_use]
    pub fn new(
        base: Arc<dyn TimeSource>,
        config: ClockSkewConfig,
        evidence_sink: Arc<dyn EvidenceSink>,
    ) -> Self {
        let rng = ChaosRng::new(config.seed);
        Self {
            base,
            rng: Mutex::new(rng),
            stats: ClockSkewStats::new(),
            jump_fired: AtomicU64::new(0),
            evidence_sink,
            config,
        }
    }

    /// Returns a snapshot of injection statistics.
    #[must_use]
    pub fn stats(&self) -> ClockSkewStatsSnapshot {
        self.stats.snapshot()
    }

    /// Compute the skew offset for a given base time.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn compute_skew(&self, base_nanos: u64) -> SkewNanos {
        let mut total_skew: SkewNanos = self.config.static_offset_ns;

        // Drift: proportional to elapsed base time.
        if self.config.drift_rate_ns_per_sec != 0 {
            let elapsed_secs = base_nanos as f64 / 1_000_000_000.0;
            let drift = (self.config.drift_rate_ns_per_sec as f64 * elapsed_secs) as SkewNanos;
            total_skew = total_skew.saturating_add(drift);
        }

        // Jump: one-time offset after trigger point.
        if let Some((trigger_ns, jump_offset)) = self.config.jump {
            if base_nanos >= trigger_ns
                && self
                    .jump_fired
                    .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                self.stats.record_jump();
                emit_skew_evidence(&self.evidence_sink, "clock_jump", base_nanos, jump_offset);
            }
            if self.jump_fired.load(Ordering::Relaxed) > 0 {
                total_skew = total_skew.saturating_add(jump_offset);
            }
        }

        // Jitter: random symmetric offset.
        if self.config.jitter_probability > 0.0 && self.config.jitter_max_ns > 0 {
            let (should, magnitude, direction) = {
                let mut rng = self.rng.lock().expect("skew rng lock poisoned");
                let should = rng.should_inject(self.config.jitter_probability);
                let mag = rng.next_u64() % self.config.jitter_max_ns;
                let dir = rng.next_u64().is_multiple_of(2);
                drop(rng);
                (should, mag, dir)
            };
            if should {
                let sign: SkewNanos = if direction { 1 } else { -1 };
                #[allow(clippy::cast_possible_wrap)]
                let jitter = sign * (magnitude as SkewNanos);
                total_skew = total_skew.saturating_add(jitter);
                self.stats.record_jitter();
            }
        }

        total_skew
    }

    /// Apply a signed offset to a base time, saturating at bounds.
    fn apply_offset(base_nanos: u64, offset: SkewNanos) -> u64 {
        if offset >= 0 {
            base_nanos.saturating_add(offset.unsigned_abs())
        } else {
            base_nanos.saturating_sub(offset.unsigned_abs())
        }
    }
}

impl TimeSource for SkewClock {
    fn now(&self) -> Time {
        let base = self.base.now();
        let base_nanos = base.as_nanos();
        let skew = self.compute_skew(base_nanos);
        let skewed_nanos = Self::apply_offset(base_nanos, skew);

        self.stats.record_read(skew.unsigned_abs());

        Time::from_nanos(skewed_nanos)
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Create a skewed clock wrapping a base clock.
///
/// Returns the `SkewClock` (as `Arc<SkewClock>` for shared ownership).
#[must_use]
pub fn skew_clock(
    base: Arc<dyn TimeSource>,
    config: ClockSkewConfig,
    evidence_sink: Arc<dyn EvidenceSink>,
) -> Arc<SkewClock> {
    Arc::new(SkewClock::new(base, config, evidence_sink))
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn emit_skew_evidence(sink: &Arc<dyn EvidenceSink>, action: &str, base_ns: u64, offset_ns: i64) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "clock_skew_injector".to_string(),
        action: format!("inject_{action}"),
        posterior: vec![1.0],
        expected_loss_by_action: std::collections::HashMap::from([(
            format!("inject_{action}"),
            0.0,
        )]),
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        top_features: vec![
            ("base_time_ns".to_string(), base_ns as f64),
            ("offset_ns".to_string(), offset_ns as f64),
        ],
    };
    sink.emit(&entry);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_sink::CollectorSink;
    use crate::time::VirtualClock;

    fn make_base_clock() -> Arc<VirtualClock> {
        Arc::new(VirtualClock::new())
    }

    fn make_sink() -> (Arc<CollectorSink>, Arc<dyn EvidenceSink>) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        (collector, sink)
    }

    #[test]
    fn no_skew_passthrough() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        assert_eq!(skewed.now(), Time::from_secs(1));

        let stats = skewed.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.skewed_reads, 0);
    }

    #[test]
    fn static_offset_ahead() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(50); // 50ms ahead
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        let t = skewed.now();
        // Expect 1s + 50ms = 1.05s
        assert_eq!(t, Time::from_nanos(1_050_000_000));

        let stats = skewed.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.skewed_reads, 1);
        assert_eq!(stats.max_abs_skew_ns, 50_000_000);
    }

    #[test]
    fn static_offset_behind() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(-100); // 100ms behind
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        let t = skewed.now();
        // Expect 1s - 100ms = 0.9s
        assert_eq!(t, Time::from_nanos(900_000_000));
    }

    #[test]
    fn static_offset_saturates_at_zero() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Offset behind by 200ms but base is only 100ms
        let config = ClockSkewConfig::new(42).with_static_offset_ms(-200);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(100_000_000); // 100ms
        let t = skewed.now();
        assert_eq!(t, Time::ZERO); // Saturated
    }

    #[test]
    fn drift_makes_clock_run_fast() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Drift: +1ms per second of base time
        let config = ClockSkewConfig::new(42).with_drift_rate(1_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 10s base time, drift = 10ms
        base.advance(10_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(10_010_000_000));
    }

    #[test]
    fn drift_makes_clock_run_slow() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Drift: -2ms per second
        let config = ClockSkewConfig::new(42).with_drift_rate(-2_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 5s base time, drift = -10ms
        base.advance(5_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(4_990_000_000));
    }

    #[test]
    fn jump_fires_once_at_trigger() {
        let base = make_base_clock();
        let (collector, sink) = make_sink();
        // Jump +100ms when base exceeds 2s
        let config = ClockSkewConfig::new(42).with_jump(2_000_000_000, 100_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // Before trigger: no jump
        base.advance(1_000_000_000);
        assert_eq!(skewed.now(), Time::from_secs(1));

        // At trigger: jump fires
        base.advance(1_500_000_000); // base = 2.5s
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(2_600_000_000)); // 2.5s + 100ms

        // After trigger: jump remains applied
        base.advance(1_000_000_000); // base = 3.5s
        let t2 = skewed.now();
        assert_eq!(t2, Time::from_nanos(3_600_000_000)); // 3.5s + 100ms

        let stats = skewed.stats();
        assert!(stats.jump_fired);

        // Evidence should have been emitted
        let entries = collector.entries();
        assert!(
            entries.iter().any(|e| e.action.contains("clock_jump")),
            "Expected evidence for clock_jump"
        );
    }

    #[test]
    fn jump_backward_simulates_ntp_correction() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Jump -50ms when base exceeds 1s (NTP correction backward)
        let config = ClockSkewConfig::new(42).with_jump(1_000_000_000, -50_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(2_000_000_000); // 2s
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(1_950_000_000)); // 2s - 50ms
    }

    #[test]
    fn jitter_is_deterministic() {
        let base1 = make_base_clock();
        let base2 = make_base_clock();
        let (_, sink1) = make_sink();
        let (_, sink2) = make_sink();
        let config = ClockSkewConfig::new(42).with_jitter(1.0, 10_000_000); // always jitter, ±10ms

        let skewed1 = SkewClock::new(base1.clone() as Arc<dyn TimeSource>, config.clone(), sink1);
        let skewed2 = SkewClock::new(base2.clone() as Arc<dyn TimeSource>, config, sink2);

        let mut times1 = Vec::new();
        let mut times2 = Vec::new();

        for i in 1..=20 {
            base1.set(Time::from_secs(i));
            base2.set(Time::from_secs(i));
            times1.push(skewed1.now());
            times2.push(skewed2.now());
        }

        assert_eq!(
            times1, times2,
            "Same seed must produce same jitter sequence"
        );
    }

    #[test]
    fn jitter_bounded() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let max_jitter_ns: u64 = 5_000_000; // 5ms
        let config = ClockSkewConfig::new(42).with_jitter(1.0, max_jitter_ns);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(10_000_000_000); // 10s (far enough to avoid saturation)

        for _ in 0..100 {
            let t = skewed.now();
            let diff = if t.as_nanos() >= 10_000_000_000 {
                t.as_nanos() - 10_000_000_000
            } else {
                10_000_000_000 - t.as_nanos()
            };
            assert!(
                diff < max_jitter_ns,
                "Jitter {diff}ns exceeds max {max_jitter_ns}ns"
            );
        }

        let stats = skewed.stats();
        assert_eq!(stats.jitter_count, 100);
    }

    #[test]
    fn combined_offset_and_drift() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42)
            .with_static_offset_ms(10) // 10ms ahead
            .with_drift_rate(500_000); // +0.5ms per second

        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 20s: offset=10ms, drift=10ms, total=20ms
        base.advance(20_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(20_020_000_000));
    }

    #[test]
    fn stats_track_reads() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(1);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000);
        for _ in 0..10 {
            let _ = skewed.now();
        }

        let stats = skewed.stats();
        assert_eq!(stats.reads, 10);
        assert_eq!(stats.skewed_reads, 10);
    }

    #[test]
    fn config_default_disabled() {
        let config = ClockSkewConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_static_offset_enabled() {
        let config = ClockSkewConfig::new(42).with_static_offset_ms(1);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_drift_enabled() {
        let config = ClockSkewConfig::new(42).with_drift_rate(1);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_jitter_enabled() {
        let config = ClockSkewConfig::new(42).with_jitter(0.5, 1000);
        assert!(config.is_enabled());
    }

    #[test]
    #[should_panic(expected = "probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_jitter_probability() {
        let _ = ClockSkewConfig::new(42).with_jitter(1.5, 1000);
    }

    #[test]
    fn zero_base_time_with_offset() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Positive offset at time zero should work.
        let config = ClockSkewConfig::new(42).with_static_offset_ms(100);
        let skewed = SkewClock::new(base as Arc<dyn TimeSource>, config, sink);
        let t = skewed.now();
        assert_eq!(t, Time::from_millis(100));
    }
}
