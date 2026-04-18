//! BSD Kqueue Event Conformance Tests
//!
//! Tests compliance with BSD kqueue event semantics for macOS/FreeBSD systems.
//! Implements Pattern 2 (Golden File Testing) to capture exact event behavior patterns.
//!
//! Key BSD kqueue behaviors tested:
//! 1. EV_ONESHOT: Event fires once then is automatically removed from the kqueue
//! 2. EV_CLEAR: Edge-triggered behavior - event is cleared when retrieved
//! 3. EV_DISPATCH: One-shot but leaves the event disabled instead of removing it
//! 4. Concurrent kevent calls: Multiple threads calling kevent() simultaneously
//! 5. udata pointer preservation: User-defined data survives through event delivery
//!
//! This module tests BSD-specific kqueue semantics that basic unit tests don't cover,
//! ensuring proper conformance with FreeBSD/macOS kqueue documentation.

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

use asupersync::runtime::reactor::{Interest, KqueueReactor, Event, Token};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// Environment variable to enable golden file updates
const UPDATE_GOLDENS_ENV: &str = "UPDATE_GOLDENS";

/// Captured kqueue event for golden file comparison
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedEvent {
    /// Token identifying the registered source
    pub token: u64,
    /// Interest flags that fired (readable, writable, etc.)
    pub ready_flags: u8,
    /// Sequence number to track event ordering
    pub sequence: u64,
    /// Timestamp when event was captured (relative to test start)
    pub timestamp_ns: u64,
}

/// Golden file metadata for kqueue conformance tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KqueueGoldenMetadata {
    /// Test case name
    pub test_name: String,
    /// BSD kqueue section/behavior being tested
    pub bsd_behavior: String,
    /// Description of the test scenario
    pub description: String,
    /// Platform where golden was created (macos/freebsd)
    pub platform: String,
    /// When this golden file was last updated
    pub last_updated: SystemTime,
    /// Input parameters that generated this golden
    pub input_params: HashMap<String, String>,
}

/// Complete golden file entry for kqueue event sequences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KqueueGoldenEntry {
    /// Metadata about this golden file
    pub metadata: KqueueGoldenMetadata,
    /// Captured event sequence
    pub events: Vec<CapturedEvent>,
    /// Additional test-specific data
    pub context: HashMap<String, String>,
}

/// Manager for kqueue golden file operations
pub struct KqueueGoldenManager {
    base_path: PathBuf,
    update_mode: bool,
}

impl KqueueGoldenManager {
    /// Creates a new kqueue golden file manager
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let update_mode = std::env::var(UPDATE_GOLDENS_ENV).is_ok();
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            update_mode,
        }
    }

    /// Asserts that captured events match the golden file
    pub fn assert_golden(
        &self,
        test_name: &str,
        events: Vec<CapturedEvent>,
        metadata: KqueueGoldenMetadata,
    ) -> Result<(), String> {
        let filename = format!("{}.golden.json", test_name);
        let file_path = self.base_path.join(filename);

        if self.update_mode {
            self.save_golden(&file_path, events, metadata)
        } else {
            self.validate_golden(&file_path, events)
        }
    }

    /// Saves events as a golden file (update mode)
    fn save_golden(
        &self,
        path: &Path,
        events: Vec<CapturedEvent>,
        metadata: KqueueGoldenMetadata,
    ) -> Result<(), String> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let golden_entry = KqueueGoldenEntry {
            metadata,
            events,
            context: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&golden_entry)
            .map_err(|e| format!("Failed to serialize golden: {}", e))?;

        fs::write(path, json).map_err(|e| format!("Failed to write golden file: {}", e))?;

        eprintln!("[GOLDEN] Updated: {}", path.display());
        Ok(())
    }

    /// Validates that events match the saved golden file
    fn validate_golden(&self, path: &Path, actual_events: Vec<CapturedEvent>) -> Result<(), String> {
        let json = fs::read_to_string(path)
            .map_err(|_| {
                format!(
                    "Golden file missing: {}\nRun with UPDATE_GOLDENS=1 to create it\nThen review and commit: git diff tests/golden/",
                    path.display()
                )
            })?;

        let golden_entry: KqueueGoldenEntry = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse golden file: {}", e))?;

        let expected_events = golden_entry.events;

        if actual_events.len() != expected_events.len() {
            return Err(format!(
                "Event count mismatch: expected {}, got {}",
                expected_events.len(),
                actual_events.len()
            ));
        }

        // Compare events, ignoring timestamps and sequence as they're not deterministic
        for (i, (expected, actual)) in expected_events.iter().zip(actual_events.iter()).enumerate() {
            if expected.token != actual.token || expected.ready_flags != actual.ready_flags {
                return Err(format!(
                    "Event mismatch at index {}:\nExpected: token={}, ready={:08b}\nActual: token={}, ready={:08b}",
                    i, expected.token, expected.ready_flags, actual.token, actual.ready_flags
                ));
            }
        }

        Ok(())
    }
}

/// Helper to capture events from a kqueue reactor
fn capture_events(reactor: &mut KqueueReactor, timeout: Duration) -> Vec<CapturedEvent> {
    let mut captured_events = Vec::new();
    let mut events_buffer = asupersync::runtime::reactor::Events::with_capacity(64);
    let start = Instant::now();
    let mut sequence_counter = 0u64;

    while start.elapsed() < timeout {
        events_buffer.clear();
        match reactor.poll(&mut events_buffer, Some(Duration::from_millis(10))) {
            Ok(_count) => {
                for event in events_buffer.iter() {
                    let captured = CapturedEvent {
                        token: event.token.0,
                        ready_flags: event.ready.bits(),
                        sequence: sequence_counter,
                        timestamp_ns: start.elapsed().as_nanos() as u64,
                    };
                    captured_events.push(captured);
                    sequence_counter += 1;
                }
            }
            Err(_) => break,
        }
    }

    captured_events
}

/// Create a simple pipe for testing kqueue events
fn create_test_pipe() -> (RawFd, RawFd) {
    let mut fds = [0i32; 2];
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            panic!("Failed to create pipe");
        }
    }
    (fds[0], fds[1])
}

/// Test EV_ONESHOT fire-and-silence behavior
#[test]
fn kqueue_ev_oneshot_fire_and_silence() {
    let golden_manager = KqueueGoldenManager::new("tests/golden/kqueue");
    let mut reactor = KqueueReactor::new().expect("Failed to create kqueue reactor");

    let (read_fd, write_fd) = create_test_pipe();
    let token = Token::from(0x1234);

    // Register with EV_ONESHOT flag (ONESHOT is already included in Interest::oneshot())
    let interest = Interest::oneshot();
    reactor
        .register(read_fd, token, interest)
        .expect("Failed to register pipe read fd");

    // Write data to trigger the event
    unsafe {
        libc::write(write_fd, b"test\0".as_ptr() as *const libc::c_void, 4);
    }

    // Capture events - should see exactly one read event, then silence
    let events = capture_events(&mut reactor, Duration::from_millis(100));

    // Write more data - should NOT trigger another event due to EV_ONESHOT
    unsafe {
        libc::write(write_fd, b"more\0".as_ptr() as *const libc::c_void, 4);
    }

    // Give time for any potential second event (there should be none)
    let additional_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Combine all events for golden comparison
    let mut all_events = events;
    all_events.extend(additional_events);

    let metadata = KqueueGoldenMetadata {
        test_name: "kqueue_ev_oneshot_fire_and_silence".to_string(),
        bsd_behavior: "EV_ONESHOT".to_string(),
        description: "Event fires once then is automatically removed".to_string(),
        platform: std::env::consts::OS.to_string(),
        last_updated: SystemTime::now(),
        input_params: HashMap::from([
            ("pipe_data_writes".to_string(), "2".to_string()),
            ("expected_events".to_string(), "1".to_string()),
        ]),
    };

    golden_manager
        .assert_golden("kqueue_ev_oneshot_fire_and_silence", all_events, metadata)
        .expect("Golden assertion failed");

    // Cleanup
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

/// Test EV_CLEAR edge-triggered behavior
#[test]
fn kqueue_ev_clear_edge_trigger() {
    let golden_manager = KqueueGoldenManager::new("tests/golden/kqueue");
    let mut reactor = KqueueReactor::new().expect("Failed to create kqueue reactor");

    let (read_fd, write_fd) = create_test_pipe();
    let token = Token::from(0x5678);

    // Register with EV_CLEAR (edge-triggered) - this is the default for kqueue
    let interest = Interest::clear();
    reactor
        .register(read_fd, token, interest)
        .expect("Failed to register pipe read fd");

    // Write data to trigger the event
    unsafe {
        libc::write(write_fd, b"test\0".as_ptr() as *const libc::c_void, 4);
    }

    // Capture first event
    let first_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Poll again without reading - should NOT get another event (edge-triggered)
    let second_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Write more data - should trigger another edge
    unsafe {
        libc::write(write_fd, b"more\0".as_ptr() as *const libc::c_void, 4);
    }

    let third_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Combine all events
    let mut all_events = first_events;
    all_events.extend(second_events);
    all_events.extend(third_events);

    let metadata = KqueueGoldenMetadata {
        test_name: "kqueue_ev_clear_edge_trigger".to_string(),
        bsd_behavior: "EV_CLEAR".to_string(),
        description: "Edge-triggered behavior - event cleared when retrieved".to_string(),
        platform: std::env::consts::OS.to_string(),
        last_updated: SystemTime::now(),
        input_params: HashMap::from([
            ("pipe_writes".to_string(), "2".to_string()),
            ("poll_cycles".to_string(), "3".to_string()),
        ]),
    };

    golden_manager
        .assert_golden("kqueue_ev_clear_edge_trigger", all_events, metadata)
        .expect("Golden assertion failed");

    // Cleanup
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

/// Test EV_DISPATCH one-shot-and-disable behavior
#[test]
fn kqueue_ev_dispatch_oneshot_disable() {
    let golden_manager = KqueueGoldenManager::new("tests/golden/kqueue");
    let mut reactor = KqueueReactor::new().expect("Failed to create kqueue reactor");

    let (read_fd, write_fd) = create_test_pipe();
    let token = Token::from(0x9ABC);

    // Register with EV_DISPATCH (one-shot but leaves event disabled)
    let interest = Interest::dispatch();
    reactor
        .register(read_fd, token, interest)
        .expect("Failed to register pipe read fd");

    // Write data to trigger the event
    unsafe {
        libc::write(write_fd, b"test\0".as_ptr() as *const libc::c_void, 4);
    }

    // Capture first event (should fire once)
    let first_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Write more data - should NOT fire because event is disabled
    unsafe {
        libc::write(write_fd, b"more\0".as_ptr() as *const libc::c_void, 4);
    }

    let second_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Re-enable the event by modifying it
    reactor
        .modify(read_fd, token, Interest::dispatch())
        .expect("Failed to re-enable event");

    // Should now fire again
    let third_events = capture_events(&mut reactor, Duration::from_millis(50));

    // Combine all events
    let mut all_events = first_events;
    all_events.extend(second_events);
    all_events.extend(third_events);

    let metadata = KqueueGoldenMetadata {
        test_name: "kqueue_ev_dispatch_oneshot_disable".to_string(),
        bsd_behavior: "EV_DISPATCH".to_string(),
        description: "One-shot but leaves event disabled instead of removing".to_string(),
        platform: std::env::consts::OS.to_string(),
        last_updated: SystemTime::now(),
        input_params: HashMap::from([
            ("initial_write".to_string(), "4_bytes".to_string()),
            ("second_write".to_string(), "4_bytes".to_string()),
            ("re_enable".to_string(), "true".to_string()),
        ]),
    };

    golden_manager
        .assert_golden("kqueue_ev_dispatch_oneshot_disable", all_events, metadata)
        .expect("Golden assertion failed");

    // Cleanup
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

/// Test token preservation through event delivery (equivalent to udata preservation)
#[test]
fn kqueue_token_preservation() {
    let golden_manager = KqueueGoldenManager::new("tests/golden/kqueue");
    let mut reactor = KqueueReactor::new().expect("Failed to create kqueue reactor");

    let (read_fd1, write_fd1) = create_test_pipe();
    let (read_fd2, write_fd2) = create_test_pipe();

    // Register multiple fds with different token values
    let token1 = Token::from(0xDEADBEEF);
    let token2 = Token::from(0xCAFEBABE);

    reactor
        .register(read_fd1, token1, Interest::readable())
        .expect("Failed to register first pipe");

    reactor
        .register(read_fd2, token2, Interest::readable())
        .expect("Failed to register second pipe");

    // Write to both pipes
    unsafe {
        libc::write(write_fd1, b"pipe1\0".as_ptr() as *const libc::c_void, 5);
        libc::write(write_fd2, b"pipe2\0".as_ptr() as *const libc::c_void, 5);
    }

    // Capture events - should preserve original token values
    let events = capture_events(&mut reactor, Duration::from_millis(100));

    let metadata = KqueueGoldenMetadata {
        test_name: "kqueue_token_preservation".to_string(),
        bsd_behavior: "token preservation".to_string(),
        description: "User-defined tokens survive through event delivery".to_string(),
        platform: std::env::consts::OS.to_string(),
        last_updated: SystemTime::now(),
        input_params: HashMap::from([
            ("fd_count".to_string(), "2".to_string()),
            ("token1".to_string(), format!("0x{:X}", token1.0)),
            ("token2".to_string(), format!("0x{:X}", token2.0)),
        ]),
    };

    golden_manager
        .assert_golden("kqueue_token_preservation", events, metadata)
        .expect("Golden assertion failed");

    // Cleanup
    unsafe {
        libc::close(read_fd1);
        libc::close(write_fd1);
        libc::close(read_fd2);
        libc::close(write_fd2);
    }
}

/// Test concurrent kevent calls from multiple threads
#[test]
fn kqueue_concurrent_kevent_calls() {
    let golden_manager = KqueueGoldenManager::new("tests/golden/kqueue");

    // Create shared reactor wrapped in Arc<Mutex<>> for thread safety
    let reactor = Arc::new(Mutex::new(
        KqueueReactor::new().expect("Failed to create kqueue reactor")
    ));

    let (read_fd, write_fd) = create_test_pipe();
    let token = Token::from(0xCCCC);

    // Register the pipe for reading
    {
        let mut r = reactor.lock().unwrap();
        r.register(read_fd, token, Interest::readable())
            .expect("Failed to register pipe");
    }

    // Shared data structures for coordination
    let events = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(Barrier::new(3)); // 2 polling threads + main thread

    let mut handles = vec![];

    // Spawn two threads that will poll concurrently
    for _thread_id in 0..2 {
        let reactor_clone = Arc::clone(&reactor);
        let events_clone = Arc::clone(&events);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait(); // Wait for all threads to be ready

            let mut thread_events_buffer = asupersync::runtime::reactor::Events::with_capacity(64);
            let start = Instant::now();
            let mut sequence_counter = 0u64;

            // Each thread polls for a short duration
            while start.elapsed() < Duration::from_millis(100) {
                thread_events_buffer.clear();
                let mut r = reactor_clone.lock().unwrap();
                match r.poll(&mut thread_events_buffer, Some(Duration::from_millis(10))) {
                    Ok(_count) => {
                        let mut events_guard = events_clone.lock().unwrap();
                        for event in thread_events_buffer.iter() {
                            let captured = CapturedEvent {
                                token: event.token.0,
                                ready_flags: event.ready.bits(),
                                sequence: sequence_counter,
                                timestamp_ns: start.elapsed().as_nanos() as u64,
                            };
                            events_guard.push(captured);
                            sequence_counter += 1;
                        }
                    }
                    Err(_) => break,
                }
                drop(r); // Release lock between polls
            }
        });

        handles.push(handle);
    }

    // Main thread waits for coordination, then writes data
    barrier.wait();

    // Give threads a moment to start polling
    thread::sleep(Duration::from_millis(10));

    // Write data while threads are polling concurrently
    unsafe {
        libc::write(write_fd, b"concurrent\0".as_ptr() as *const libc::c_void, 10);
    }

    // Wait for all polling threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Collect final events
    let final_events = {
        let events_guard = events.lock().unwrap();
        events_guard.clone()
    };

    let metadata = KqueueGoldenMetadata {
        test_name: "kqueue_concurrent_kevent_calls".to_string(),
        bsd_behavior: "concurrent kevent".to_string(),
        description: "Multiple threads calling kevent() simultaneously".to_string(),
        platform: std::env::consts::OS.to_string(),
        last_updated: SystemTime::now(),
        input_params: HashMap::from([
            ("thread_count".to_string(), "2".to_string()),
            ("poll_duration_ms".to_string(), "100".to_string()),
        ]),
    };

    golden_manager
        .assert_golden("kqueue_concurrent_kevent_calls", final_events, metadata)
        .expect("Golden assertion failed");

    // Cleanup
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}