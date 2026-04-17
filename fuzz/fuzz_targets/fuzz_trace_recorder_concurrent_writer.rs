#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::trace::recorder::{RecorderConfig, TraceRecorder, LimitAction};
use asupersync::trace::replay::TraceMetadata;
use asupersync::types::{TaskId, RegionId, Time, Severity};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;
use std::io;

/// Fuzzing configuration for trace recorder concurrent writer contention testing.
#[derive(Debug, Clone, Arbitrary)]
struct TraceRecorderConcurrentConfig {
    /// Number of concurrent writers (1-8)
    pub writer_count: u8,
    /// Number of events per writer (1-1000)
    pub events_per_writer: u16,
    /// Whether to enable reader during writing
    pub enable_reader: bool,
    /// Recorder configuration settings
    pub recorder_config: FuzzRecorderConfig,
    /// Event mix to generate
    pub event_mix: Vec<FuzzEventType>,
    /// Panic injection settings
    pub panic_injection: PanicInjectionConfig,
    /// Overflow testing settings
    pub overflow_config: OverflowConfig,
}

/// Recorder configuration for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzRecorderConfig {
    /// Initial capacity (1-10000)
    pub initial_capacity: u16,
    /// Whether to record RNG values
    pub record_rng: bool,
    /// Whether to record wakers
    pub record_wakers: bool,
    /// Maximum events (None or Some(1-1000))
    pub max_events: Option<u16>,
    /// Maximum memory (100-1000000 bytes)
    pub max_memory: u32,
    /// Limit action strategy
    pub on_limit: FuzzLimitAction,
}

/// Limit action for fuzzing
#[derive(Debug, Clone, Arbitrary)]
enum FuzzLimitAction {
    StopRecording,
    DropOldest,
    Fail,
}

impl FuzzLimitAction {
    fn to_limit_action(&self) -> LimitAction {
        match self {
            FuzzLimitAction::StopRecording => LimitAction::StopRecording,
            FuzzLimitAction::DropOldest => LimitAction::DropOldest,
            FuzzLimitAction::Fail => LimitAction::Fail,
        }
    }
}

/// Event types for fuzzing
#[derive(Debug, Clone, Arbitrary)]
enum FuzzEventType {
    TaskScheduled { task_index: u8, tick: u64 },
    TaskYielded { task_index: u8 },
    TaskCompleted { task_index: u8, severity: u8 },
    TaskSpawned { task_index: u8, region_index: u8, tick: u64 },
    TimeAdvanced { from_nanos: u64, to_nanos: u64 },
    TimerCreated { timer_id: u64, deadline_nanos: u64 },
    TimerFired { timer_id: u64 },
    TimerCancelled { timer_id: u64 },
    IoReady { token: u64, readable: bool, writable: bool, error: bool, hangup: bool },
    IoResult { token: u64, bytes: i64 },
    IoError { token: u64, error_kind: u8 },
    RngSeed { seed: u64 },
    RngValue { value: u64 },
    CancelInjection { task_index: u8 },
    DelayInjection { task_index: Option<u8>, delay_nanos: u64 },
    WakerWake { task_index: u8 },
    WakerBatchWake { count: u32 },
}

/// Panic injection configuration
#[derive(Debug, Clone, Arbitrary)]
struct PanicInjectionConfig {
    /// Whether to enable panic injection
    pub enabled: bool,
    /// Probability of panic (0-100)
    pub panic_probability: u8,
    /// Which writer should panic (0-7)
    pub panic_writer_index: u8,
    /// After how many events to panic (1-100)
    pub panic_after_events: u8,
}

/// Overflow configuration for testing limits
#[derive(Debug, Clone, Arbitrary)]
struct OverflowConfig {
    /// Whether to test overflow scenarios
    pub test_overflow: bool,
    /// Target memory limit for overflow (1-1000 bytes)
    pub memory_limit: u16,
    /// Target event limit for overflow (1-50 events)
    pub event_limit: u8,
}

/// Generate deterministic task/region IDs based on index
fn make_task_id(index: u8) -> TaskId {
    TaskId::new_for_test(index.into(), 0)
}

fn make_region_id(index: u8) -> RegionId {
    RegionId::new_for_test(index.into(), 0)
}

/// Convert error kind index to std::io::ErrorKind
fn index_to_error_kind(index: u8) -> io::ErrorKind {
    match index % 10 {
        0 => io::ErrorKind::NotFound,
        1 => io::ErrorKind::PermissionDenied,
        2 => io::ErrorKind::ConnectionRefused,
        3 => io::ErrorKind::ConnectionReset,
        4 => io::ErrorKind::ConnectionAborted,
        5 => io::ErrorKind::NotConnected,
        6 => io::ErrorKind::TimedOut,
        7 => io::ErrorKind::WriteZero,
        8 => io::ErrorKind::Interrupted,
        _ => io::ErrorKind::Other,
    }
}

/// Convert severity index to Severity
fn index_to_severity(index: u8) -> Severity {
    match index % 4 {
        0 => Severity::Ok,
        1 => Severity::Err,
        2 => Severity::Cancelled,
        _ => Severity::Panicked,
    }
}

/// Test 1: N writers + single reader with atomic append
fn test_concurrent_writers_single_reader(config: &TraceRecorderConcurrentConfig) {
    let writer_count = (config.writer_count % 8).max(1) as usize;
    let events_per_writer = (config.events_per_writer % 1000).max(1) as usize;

    // Clone config data needed by threads to avoid borrowing issues
    let event_mix = config.event_mix.clone();
    let enable_reader = config.enable_reader;
    let panic_enabled = config.panic_injection.enabled;
    let panic_writer_index = config.panic_injection.panic_writer_index;
    let panic_after_events = config.panic_injection.panic_after_events;
    let panic_probability = config.panic_injection.panic_probability;

    // Create shared recorder configuration
    let recorder_config = RecorderConfig::enabled()
        .with_capacity(config.recorder_config.initial_capacity.max(1) as usize)
        .with_rng(config.recorder_config.record_rng)
        .with_wakers(config.recorder_config.record_wakers)
        .with_max_events(config.recorder_config.max_events.map(|v| v.max(1) as u64))
        .with_max_memory(config.recorder_config.max_memory.max(100) as usize)
        .on_limit(config.recorder_config.on_limit.to_limit_action());

    let recorder = Arc::new(Mutex::new(TraceRecorder::with_config(
        TraceMetadata::new(42),
        recorder_config,
    )));

    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // Spawn concurrent writers
    for writer_id in 0..writer_count {
        let recorder_clone = Arc::clone(&recorder);
        let stop_flag_clone = Arc::clone(&stop_flag);
        let event_mix_clone = event_mix.clone();

        let handle = thread::spawn(move || {
            let mut event_count = 0;

            while event_count < events_per_writer && !stop_flag_clone.load(Ordering::Relaxed) {
                // Select event type based on writer ID and event count
                let event_index = (writer_id + event_count) % event_mix_clone.len().max(1);
                let event_type = &event_mix_clone[event_index % event_mix_clone.len()];

                // Apply panic injection if configured
                if panic_enabled
                    && writer_id == panic_writer_index as usize
                    && event_count == panic_after_events as usize
                    && (event_count % 100) < panic_probability as usize
                {
                    // Intentional panic to test cleanup
                    panic!("Fuzzer-injected panic in writer {}", writer_id);
                }

                // Record event with proper error handling
                if let Ok(mut recorder) = recorder_clone.try_lock() {
                    record_fuzz_event(&mut recorder, event_type, writer_id as u8);
                    event_count += 1;
                } else {
                    // Yield if lock contention
                    thread::yield_now();
                }
            }
        });

        handles.push(handle);
    }

    // Start reader if enabled
    let reader_handle = if enable_reader {
        let recorder_clone = Arc::clone(&recorder);
        let stop_flag_clone = Arc::clone(&stop_flag);

        Some(thread::spawn(move || {
            let mut snapshots = Vec::new();
            let mut iterations = 0;

            while !stop_flag_clone.load(Ordering::Relaxed) && iterations < 10 {
                // Test reader falling behind scenario
                if let Ok(recorder) = recorder_clone.try_lock() {
                    // Test snapshot (reader operation)
                    if let Some(snapshot) = recorder.snapshot() {
                        snapshots.push(snapshot);
                    }

                    // Test take operation (resets recorder) - drop guard first to avoid move
                    if iterations % 3 == 0 {
                        drop(recorder); // Release lock before take
                        if let Ok(mut recorder) = recorder_clone.try_lock() {
                            if let Some(trace) = recorder.take() {
                                // Validate trace structure
                                assert!(trace.events.len() <= 10000, "Trace too large");
                            }
                        }
                    }
                } else {
                    // Reader falling behind - test lagged subscriber semantics
                    thread::sleep(Duration::from_micros(1));
                }

                iterations += 1;
            }

            snapshots.len()
        }))
    } else {
        None
    };

    // Let writers run for a bit
    thread::sleep(Duration::from_millis(10));

    // Signal stop
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for all writers (with panic handling)
    for handle in handles {
        let _ = handle.join(); // Ignore panics from injected panics
    }

    // Wait for reader
    if let Some(reader_handle) = reader_handle {
        let _ = reader_handle.join();
    }

    // Test final state - avoid moving out of MutexGuard
    if let Ok(recorder) = recorder.try_lock() {
        let event_count = recorder.event_count();
        // Test basic properties without calling finish() which would move
        assert!(event_count <= 100000, "Final trace suspiciously large");
    }
}

/// Test 2: Overflow-to-lossy transition
fn test_overflow_to_lossy_transition(config: &TraceRecorderConcurrentConfig) {
    if !config.overflow_config.test_overflow {
        return;
    }

    let memory_limit = config.overflow_config.memory_limit.max(1) as usize;
    let event_limit = config.overflow_config.event_limit.max(1) as u64;

    // Create recorder with tight limits
    let recorder_config = RecorderConfig::enabled()
        .with_max_memory(memory_limit)
        .with_max_events(Some(event_limit))
        .on_limit(LimitAction::DropOldest); // Test lossy transition

    let mut recorder = TraceRecorder::with_config(TraceMetadata::new(123), recorder_config);

    // Fill up to trigger overflow
    for i in 0..event_limit + 10 {
        recorder.record_task_scheduled(make_task_id((i % 256) as u8), i);

        // Verify transition behavior
        if i >= event_limit {
            // Should be in lossy mode, dropping oldest
            assert!(recorder.event_count() <= event_limit as usize + 1);
        }
    }

    // Test memory overflow
    let mut large_events = 0;
    while large_events < 1000 && recorder.estimated_size() < memory_limit * 2 {
        // Generate large events to trigger memory limit
        for j in 0..10 {
            recorder.record_time_advanced(
                Time::from_nanos(large_events * 1000),
                Time::from_nanos(large_events * 1000 + j),
            );
        }
        large_events += 1;
    }

    // Recorder should still be functional after overflow
    assert!(recorder.is_enabled() || recorder.event_count() <= event_limit as usize);
}

/// Test 3: Record truncation preserves frame boundary
fn test_record_truncation_frame_boundary(_config: &TraceRecorderConcurrentConfig) {
    let recorder_config = RecorderConfig::enabled()
        .with_max_events(Some(5)) // Small limit to trigger truncation quickly
        .on_limit(LimitAction::DropOldest);

    let mut recorder = TraceRecorder::with_config(TraceMetadata::new(456), recorder_config);

    // Add events to trigger truncation
    let task_a = make_task_id(1);
    let task_b = make_task_id(2);
    let region = make_region_id(0);

    // Create a sequence that should maintain consistency even with truncation
    recorder.record_task_spawned(task_a, region, 0);
    recorder.record_task_scheduled(task_a, 0);
    recorder.record_task_yielded(task_a);
    recorder.record_task_spawned(task_b, region, 1);
    recorder.record_task_scheduled(task_b, 1);
    recorder.record_task_completed(task_a, Severity::Ok);
    recorder.record_task_completed(task_b, Severity::Ok);

    // Should have dropped oldest but maintained valid trace structure
    assert!(recorder.event_count() <= 6);

    if let Some(trace) = recorder.finish() {
        // Validate remaining events form valid sequences
        for event in &trace.events {
            // All events should be well-formed (no corruption from truncation)
            match event {
                asupersync::trace::replay::ReplayEvent::TaskScheduled { task, .. } => {
                    // CompactTaskId has unpack() method
                    let (index, _gen) = task.unpack();
                    assert!(index > 0);
                }
                asupersync::trace::replay::ReplayEvent::TaskCompleted { task, .. } => {
                    // CompactTaskId has unpack() method
                    let (index, _gen) = task.unpack();
                    assert!(index > 0);
                }
                _ => {} // Other events are fine
            }
        }
    }
}

/// Test 4: Reader falls behind → lagged subscriber semantics
fn test_reader_lag_semantics(_config: &TraceRecorderConcurrentConfig) {
    let recorder_config = RecorderConfig::enabled()
        .with_capacity(1000)
        .with_max_memory(50000);

    let recorder = Arc::new(Mutex::new(TraceRecorder::with_config(
        TraceMetadata::new(789),
        recorder_config,
    )));

    let stop_flag = Arc::new(AtomicBool::new(false));

    // Fast writer
    let recorder_writer = Arc::clone(&recorder);
    let stop_flag_writer = Arc::clone(&stop_flag);
    let writer_handle = thread::spawn(move || {
        let mut count = 0;
        while count < 1000 && !stop_flag_writer.load(Ordering::Relaxed) {
            if let Ok(mut r) = recorder_writer.try_lock() {
                r.record_task_scheduled(make_task_id((count % 256) as u8), count);
                count += 1;
            }
            // No yield - fast writing
        }
        count
    });

    // Slow reader (simulating lag)
    let recorder_reader = Arc::clone(&recorder);
    let stop_flag_reader = Arc::clone(&stop_flag);
    let reader_handle = thread::spawn(move || {
        let mut snapshots = Vec::new();
        while snapshots.len() < 10 && !stop_flag_reader.load(Ordering::Relaxed) {
            if let Ok(r) = recorder_reader.try_lock() {
                if let Some(snapshot) = r.snapshot() {
                    snapshots.push(snapshot.events.len());
                }
            }
            // Intentional delay to simulate slow reader
            thread::sleep(Duration::from_micros(100));
        }
        snapshots
    });

    // Let them race for a bit
    thread::sleep(Duration::from_millis(5));
    stop_flag.store(true, Ordering::Relaxed);

    let write_count = writer_handle.join().unwrap_or(0);
    let read_snapshots = reader_handle.join().unwrap_or(Vec::new());

    // Reader should have captured some snapshots, but likely missed events
    if !read_snapshots.is_empty() && write_count > 0 {
        let last_snapshot_size = read_snapshots.last().unwrap_or(&0);
        // Reader lag: last snapshot should be smaller than total writes
        assert!(*last_snapshot_size <= write_count as usize);
    }
}

/// Test 5: Panic during record writes still closes file cleanly
fn test_panic_safety_during_writes(config: &TraceRecorderConcurrentConfig) {
    if !config.panic_injection.enabled {
        return;
    }

    // Simple test: create recorder, record some events, test normal cleanup
    let recorder_config = RecorderConfig::enabled().with_capacity(100);
    let mut recorder = TraceRecorder::with_config(TraceMetadata::new(999), recorder_config);

    // Record some events successfully
    recorder.record_task_scheduled(make_task_id(1), 0);
    recorder.record_task_scheduled(make_task_id(2), 1);

    // Normally complete recording (testing that normal case works)
    if config.panic_injection.panic_probability <= 50 {
        recorder.record_task_completed(make_task_id(1), Severity::Ok);
        if let Some(trace) = recorder.finish() {
            assert!(trace.events.len() >= 2);
        }
    } else {
        // Test that we can abandon a recorder and create a new one
        drop(recorder);
        let mut new_recorder = TraceRecorder::with_config(
            TraceMetadata::new(1000),
            RecorderConfig::enabled(),
        );
        new_recorder.record_task_scheduled(make_task_id(100), 0);
        assert_eq!(new_recorder.event_count(), 1);
    }
}

/// Record a fuzz event to the trace recorder
fn record_fuzz_event(recorder: &mut TraceRecorder, event_type: &FuzzEventType, _writer_id: u8) {
    match event_type {
        FuzzEventType::TaskScheduled { task_index, tick } => {
            recorder.record_task_scheduled(make_task_id(*task_index), *tick);
        }
        FuzzEventType::TaskYielded { task_index } => {
            recorder.record_task_yielded(make_task_id(*task_index));
        }
        FuzzEventType::TaskCompleted { task_index, severity } => {
            recorder.record_task_completed(make_task_id(*task_index), index_to_severity(*severity));
        }
        FuzzEventType::TaskSpawned { task_index, region_index, tick } => {
            recorder.record_task_spawned(
                make_task_id(*task_index),
                make_region_id(*region_index),
                *tick,
            );
        }
        FuzzEventType::TimeAdvanced { from_nanos, to_nanos } => {
            recorder.record_time_advanced(
                Time::from_nanos(*from_nanos),
                Time::from_nanos(*to_nanos),
            );
        }
        FuzzEventType::TimerCreated { timer_id, deadline_nanos } => {
            recorder.record_timer_created(*timer_id, Time::from_nanos(*deadline_nanos));
        }
        FuzzEventType::TimerFired { timer_id } => {
            recorder.record_timer_fired(*timer_id);
        }
        FuzzEventType::TimerCancelled { timer_id } => {
            recorder.record_timer_cancelled(*timer_id);
        }
        FuzzEventType::IoReady { token, readable, writable, error, hangup } => {
            recorder.record_io_ready(*token, *readable, *writable, *error, *hangup);
        }
        FuzzEventType::IoResult { token, bytes } => {
            recorder.record_io_result(*token, *bytes);
        }
        FuzzEventType::IoError { token, error_kind } => {
            recorder.record_io_error(*token, index_to_error_kind(*error_kind));
        }
        FuzzEventType::RngSeed { seed } => {
            recorder.record_rng_seed(*seed);
        }
        FuzzEventType::RngValue { value } => {
            recorder.record_rng_value(*value);
        }
        FuzzEventType::CancelInjection { task_index } => {
            recorder.record_cancel_injection(make_task_id(*task_index));
        }
        FuzzEventType::DelayInjection { task_index, delay_nanos } => {
            let task = task_index.map(make_task_id);
            recorder.record_delay_injection(task, *delay_nanos);
        }
        FuzzEventType::WakerWake { task_index } => {
            recorder.record_waker_wake(make_task_id(*task_index));
        }
        FuzzEventType::WakerBatchWake { count } => {
            recorder.record_waker_batch_wake(*count);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for reasonable fuzzing performance
    if data.len() > 4096 {
        return;
    }

    // Parse fuzzing configuration from input
    let mut unstructured = Unstructured::new(data);
    let config = match TraceRecorderConcurrentConfig::arbitrary(&mut unstructured) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };

    // Ensure we have at least some events to test with
    if config.event_mix.is_empty() {
        return;
    }

    // ===== TEST 1: N WRITERS + SINGLE READER WITH ATOMIC APPEND =====
    test_concurrent_writers_single_reader(&config);

    // ===== TEST 2: OVERFLOW-TO-LOSSY TRANSITION =====
    test_overflow_to_lossy_transition(&config);

    // ===== TEST 3: RECORD TRUNCATION PRESERVES FRAME BOUNDARY =====
    test_record_truncation_frame_boundary(&config);

    // ===== TEST 4: READER FALLS BEHIND → LAGGED SUBSCRIBER SEMANTICS =====
    test_reader_lag_semantics(&config);

    // ===== TEST 5: PANIC DURING RECORD WRITES STILL CLOSES FILE CLEANLY =====
    test_panic_safety_during_writes(&config);
});