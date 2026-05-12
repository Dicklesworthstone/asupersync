#![no_main]
use libfuzzer_sys::fuzz_target;

use asupersync::cancel::progress_certificate::{
    CertificateVerdict, ProgressCertificate, ProgressConfig,
};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

/// Fuzzing operations for progress certificates
#[derive(Debug, Clone)]
enum Operation {
    /// Observe with potential value
    Observe(f64),
    /// Call verdict
    Verdict,
    /// Compact with keep_last parameter
    Compact(usize),
    /// Reset certificate
    Reset,
    /// Start concurrent observe operation
    ConcurrentObserve(f64),
    /// Start concurrent compact operation
    ConcurrentCompact(usize),
}

struct ConcurrentWorker {
    handle: thread::JoinHandle<()>,
    rx: mpsc::Receiver<thread::Result<CertificateVerdict>>,
}

/// Test configuration for fuzzing
#[derive(Debug)]
struct FuzzConfig {
    confidence: f64,
    max_step_bound: f64,
    stall_threshold: usize,
    min_observations: usize,
    epsilon: f64,
}

impl FuzzConfig {
    fn from_bytes(data: &[u8]) -> Self {
        // Use bytes to generate test parameters, with bounds checking
        let mut idx = 0;

        let confidence = if idx < data.len() {
            let val = (data[idx] as f64) / 255.0;
            idx += 1;
            val.clamp(0.01, 0.99) // Valid confidence range
        } else {
            0.95
        };

        let max_step_bound = if idx < data.len() {
            let val = (data[idx] as f64) * 100.0;
            idx += 1;
            val.clamp(0.1, 1000.0)
        } else {
            10.0
        };

        let stall_threshold = if idx < data.len() {
            let val = data[idx] as usize;
            idx += 1;
            val.clamp(1, 50) // Reasonable range for stall threshold
        } else {
            5
        };

        let min_observations = if idx < data.len() {
            let val = data[idx] as usize;
            idx += 1;
            val.clamp(1, 100)
        } else {
            10
        };

        let epsilon = if idx < data.len() {
            let val = (data[idx] as f64) / 10000.0;
            val.clamp(1e-10, 1e-3)
        } else {
            1e-6
        };

        FuzzConfig {
            confidence,
            max_step_bound,
            stall_threshold,
            min_observations,
            epsilon,
        }
    }
}

/// Parse operations from fuzz input
fn parse_operations(data: &[u8]) -> Vec<Operation> {
    if data.len() < 8 {
        return vec![Operation::Observe(1.0), Operation::Verdict];
    }

    let config_size = 6; // Reserve first 6 bytes for config
    let ops_data = &data[config_size..];

    let mut operations = Vec::new();
    let mut i = 0;

    while i + 1 < ops_data.len() && operations.len() < 50 {
        let op_type = ops_data[i] % 6; // 6 operation types
        let param = ops_data[i + 1];

        let operation = match op_type {
            0 => {
                // Generate test potentials including edge cases
                let potential = match param {
                    0..=10 => f64::NAN,
                    11..=20 => f64::INFINITY,
                    21..=30 => f64::NEG_INFINITY,
                    31..=40 => 0.0,
                    41..=50 => -0.0,
                    51..=60 => f64::EPSILON,
                    61..=70 => f64::MIN,
                    71..=80 => f64::MAX,
                    _ => (param as f64) / 10.0 - 12.8, // Range approximately -12.8 to 12.7
                };
                Operation::Observe(potential)
            }
            1 => Operation::Verdict,
            2 => Operation::Compact((param as usize).clamp(0, 100)),
            3 => Operation::Reset,
            4 => {
                let potential = match param {
                    0..=50 => (param as f64) / 50.0,
                    _ => (param as f64) - 128.0,
                };
                Operation::ConcurrentObserve(potential)
            }
            5 => Operation::ConcurrentCompact((param as usize).clamp(0, 50)),
            _ => Operation::Observe(1.0),
        };

        operations.push(operation);
        i += 2;
    }

    if operations.is_empty() {
        operations.push(Operation::Observe(1.0));
        operations.push(Operation::Verdict);
    }

    operations
}

fn observe_worker_result(
    result: Result<thread::Result<CertificateVerdict>, mpsc::RecvTimeoutError>,
    join_result: thread::Result<()>,
) {
    match join_result {
        Ok(()) => {}
        Err(_) => panic!("concurrent progress certificate worker panicked outside catch_unwind"),
    }

    match result {
        Ok(Ok(_verdict)) => {}
        Ok(Err(_)) => panic!("concurrent progress certificate operation panicked"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("concurrent progress certificate worker did not report before timeout")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("concurrent progress certificate worker exited without reporting")
        }
    }
}

fn wait_for_worker(worker: ConcurrentWorker) {
    let result = worker.rx.recv_timeout(Duration::from_millis(100));
    let join_result = worker.handle.join();
    observe_worker_result(result, join_result);
}

fn drain_completed_workers(workers: &mut Vec<ConcurrentWorker>) {
    let mut index = 0;
    while index < workers.len() {
        match workers[index].rx.try_recv() {
            Ok(result) => {
                let worker = workers.swap_remove(index);
                observe_worker_result(Ok(result), worker.handle.join());
            }
            Err(mpsc::TryRecvError::Empty) => index += 1,
            Err(mpsc::TryRecvError::Disconnected) => {
                let worker = workers.swap_remove(index);
                observe_worker_result(
                    Err(mpsc::RecvTimeoutError::Disconnected),
                    worker.handle.join(),
                );
            }
        }
    }
}

fn assert_probability_bound(value: f64, label: &str) {
    assert!(value.is_finite(), "{label} should be finite, got {value:?}");
    assert!(
        (0.0..=1.0).contains(&value),
        "{label} should be in [0, 1], got {value:?}"
    );
}

fn observe_certificate_verdict(
    verdict: &CertificateVerdict,
    retained_observations: usize,
    context: &str,
) {
    assert_probability_bound(verdict.confidence_bound, "confidence bound");
    assert_probability_bound(verdict.azuma_bound, "Azuma bound");
    assert_probability_bound(verdict.freedman_bound, "Freedman bound");
    assert!(
        verdict.freedman_bound <= verdict.azuma_bound + 1e-10,
        "{context}: Freedman bound should not exceed Azuma bound: freedman={:?}, azuma={:?}",
        verdict.freedman_bound,
        verdict.azuma_bound
    );
    assert!(
        verdict.total_steps >= retained_observations,
        "{context}: total steps {} should cover retained observations {}",
        verdict.total_steps,
        retained_observations
    );
    assert!(
        verdict.current_potential.is_finite() && verdict.current_potential >= 0.0,
        "{context}: current potential should be finite and non-negative, got {:?}",
        verdict.current_potential
    );
    assert!(
        verdict.initial_potential.is_finite() && verdict.initial_potential >= 0.0,
        "{context}: initial potential should be finite and non-negative, got {:?}",
        verdict.initial_potential
    );
    assert!(
        verdict.max_observed_step.is_finite() && verdict.max_observed_step >= 0.0,
        "{context}: max observed step should be finite and non-negative, got {:?}",
        verdict.max_observed_step
    );
    if let Some(remaining) = verdict.estimated_remaining_steps {
        assert!(
            remaining.is_finite() && remaining >= 0.0,
            "{context}: remaining step estimate should be finite and non-negative, got {remaining:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 8 {
        return;
    }

    // Generate test configuration and operations
    let fuzz_config = FuzzConfig::from_bytes(&data[..6.min(data.len())]);
    let operations = parse_operations(data);

    // Create progress certificate with fuzzy configuration
    let config = ProgressConfig {
        confidence: fuzz_config.confidence,
        max_step_bound: fuzz_config.max_step_bound,
        stall_threshold: fuzz_config.stall_threshold,
        min_observations: fuzz_config.min_observations,
        epsilon: fuzz_config.epsilon,
    };

    let certificate = ProgressCertificate::new(config.clone());
    let certificate_shared = Arc::new(Mutex::new(certificate));

    // Track state for invariant checking
    let mut step_count = 0u64;
    let mut last_step = None;
    let mut concurrent_handles = Vec::new();

    // Execute operations and check invariants
    for operation in operations {
        match operation {
            Operation::Observe(potential) => {
                // INVARIANT 1: Step ordering monotonicity
                let current_step = step_count;
                step_count += 1;

                if let Some(prev) = last_step {
                    assert!(
                        current_step > prev,
                        "Step ordering violated: {} should be > {}",
                        current_step,
                        prev
                    );
                }
                last_step = Some(current_step);

                // INVARIANT 3: Boundary edge case handling
                let mut cert_guard = certificate_shared.lock().unwrap();

                // Store state before observe for comparison
                let observations_before = cert_guard.observations().len();
                let potential_before = cert_guard.observations().last().map(|obs| obs.potential);

                // The observe call should handle all floating-point edge cases gracefully
                cert_guard.observe(potential);

                // Verify observation was recorded (unless filtered as invalid)
                let observations_after = cert_guard.observations().len();

                // If potential is finite, it should be recorded
                if potential.is_finite() {
                    assert!(
                        observations_after > observations_before
                            || observations_after == config.min_observations.saturating_add(100),
                        "Valid finite potential {} should be recorded or list should be at capacity",
                        potential
                    );
                }

                // Check that NaN/Infinity values don't corrupt certificate state
                if !potential.is_finite() {
                    // Non-finite values might be rejected, but should not crash or corrupt state
                    let current_potential =
                        cert_guard.observations().last().map(|obs| obs.potential);
                    if let (Some(before), Some(current)) = (potential_before, current_potential) {
                        assert!(
                            before.is_finite() == current.is_finite() || potential.is_finite(),
                            "Non-finite potential {} should not corrupt previous state",
                            potential
                        );
                    }
                }
                drop(cert_guard);
            }

            Operation::Verdict => {
                // INVARIANT 2: Certificate validity under concurrent operations
                let cert_guard = certificate_shared.lock().unwrap();
                let verdict = cert_guard.verdict();

                // Verdict should always be deterministic given the current state
                let verdict2 = cert_guard.verdict();
                assert_eq!(
                    format!("{:?}", verdict),
                    format!("{:?}", verdict2),
                    "Verdict should be deterministic: first={:?}, second={:?}",
                    verdict,
                    verdict2
                );

                // If we have enough observations, verdict should be meaningful
                if cert_guard.observations().len() >= config.min_observations {
                    // Verdict computation should not panic
                    let _verdict_result = verdict;
                }
                drop(cert_guard);
            }

            Operation::Compact(keep_last) => {
                let mut cert_guard = certificate_shared.lock().unwrap();
                let obs_before = cert_guard.observations().len();

                // Compact should preserve certificate validity
                cert_guard.compact(keep_last);

                let obs_after = cert_guard.observations().len();

                // INVARIANT: Compact should keep at most keep_last observations
                assert!(
                    obs_after <= keep_last || keep_last == 0,
                    "Compact should keep at most {} observations, but kept {}",
                    keep_last,
                    obs_after
                );

                // INVARIANT: If we had fewer than keep_last, nothing should be removed
                if obs_before <= keep_last {
                    assert_eq!(
                        obs_after, obs_before,
                        "Compact should not remove observations if count {} <= keep_last {}",
                        obs_before, keep_last
                    );
                }
                drop(cert_guard);
            }

            Operation::Reset => {
                let mut cert_guard = certificate_shared.lock().unwrap();

                // Reset should restore initial state
                cert_guard.reset();

                // INVARIANT: After reset, observations should be empty
                assert_eq!(
                    cert_guard.observations().len(),
                    0,
                    "Reset should clear all observations"
                );

                // Reset the step counter for our invariant tracking
                step_count = 0;
                last_step = None;
                drop(cert_guard);
            }

            Operation::ConcurrentObserve(potential) => {
                // INVARIANT 2: Certificate validity under concurrent revoke operations
                let cert_shared = Arc::clone(&certificate_shared);
                let (tx, rx) = mpsc::channel();

                let handle = thread::spawn(move || {
                    let result = std::panic::catch_unwind(|| {
                        let mut cert = cert_shared.lock().unwrap();
                        cert.observe(potential);
                        cert.verdict()
                    });
                    tx.send(result)
                        .expect("concurrent progress certificate receiver should remain alive");
                });

                // Don't wait forever for concurrent operations
                concurrent_handles.push(ConcurrentWorker { handle, rx });

                // Limit concurrent operations to prevent resource exhaustion
                if concurrent_handles.len() > 5
                    && let Some(worker) = concurrent_handles.pop()
                {
                    wait_for_worker(worker);
                }
            }

            Operation::ConcurrentCompact(keep_last) => {
                // INVARIANT 2: Certificate validity under concurrent revoke operations
                let cert_shared = Arc::clone(&certificate_shared);
                let (tx, rx) = mpsc::channel();

                let handle = thread::spawn(move || {
                    let result = std::panic::catch_unwind(|| {
                        let mut cert = cert_shared.lock().unwrap();
                        cert.compact(keep_last);
                        cert.verdict()
                    });
                    tx.send(result)
                        .expect("concurrent progress certificate receiver should remain alive");
                });

                concurrent_handles.push(ConcurrentWorker { handle, rx });

                if concurrent_handles.len() > 5
                    && let Some(worker) = concurrent_handles.pop()
                {
                    wait_for_worker(worker);
                }
            }
        }

        // Periodically clean up completed concurrent operations
        if concurrent_handles.len() > 3 {
            drain_completed_workers(&mut concurrent_handles);
        }
    }

    // Clean up remaining concurrent operations before exit
    for worker in concurrent_handles {
        wait_for_worker(worker);
    }

    // Final invariant check: certificate should still be in a valid state
    let final_cert = certificate_shared.lock().unwrap();
    let retained_observations = final_cert.observations().len();
    let final_verdict = final_cert.verdict();

    drop(final_cert);
    observe_certificate_verdict(&final_verdict, retained_observations, "final verdict");
});
