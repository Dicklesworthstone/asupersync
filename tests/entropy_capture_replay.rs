//! Capability entropy replay through real task contexts, threads, and processes.
//!
//! Tests intentionally use only public test data when persisting tapes. No
//! captured OS entropy is written to disk. Fixture directories are retained.

#![cfg(feature = "test-internals")]

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::util::entropy_replay::{
    EntropyCaptureError, EntropyCaptureLimits, EntropyReplayCompletionError, EntropyRequest,
    EntropyTape, EntropyTapeDecodeLimits, RecordingEntropy,
};
use asupersync::util::{ArenaIndex, DetEntropy, EntropySource, OsEntropy};
use asupersync::{Budget, Cx, TaskId};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::time::Duration;

fn limits() -> EntropyCaptureLimits {
    EntropyCaptureLimits::new(4096, 65536, 256)
}

fn decode_limits() -> EntropyTapeDecodeLimits {
    EntropyTapeDecodeLimits::new(131072, limits(), 262144)
}

type Values = Vec<(usize, Vec<(u64, [u8; 13])>)>;

fn run_contexts(entropy: Arc<dyn EntropySource>, seed: u64) -> Values {
    let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(5000));
    lab.state.set_entropy_source(entropy);
    let region = lab.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(Vec::new()));
    for label in 0..8 {
        let output = Arc::clone(&output);
        let (task, _handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task must have its runtime context");
                let mut values = Vec::new();
                for _ in 0..3 {
                    let value = cx.random_u64();
                    yield_now().await;
                    let mut bytes = [0; 13];
                    cx.random_bytes(&mut bytes);
                    values.push((value, bytes));
                    yield_now().await;
                }
                output.lock().unwrap().push((label, values));
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
    }
    lab.run_until_quiescent();
    assert!(lab.is_quiescent(), "all recorded task contexts must drain");
    assert_eq!(lab.state.live_task_count(), 0);
    let mut values = output.lock().unwrap().clone();
    assert_eq!(
        values.len(),
        8,
        "a task panic cannot masquerade as a successful replay"
    );
    values.sort_by_key(|(label, _)| *label);
    values
}

#[test]
fn task_contexts_replay_actual_os_entropy_without_a_seed_or_provider_fallback() {
    let capture = Arc::new(RecordingEntropy::new(Arc::new(OsEntropy), limits()).unwrap());
    let expected = run_contexts(capture.clone(), 42);
    let tape = capture.finish().unwrap();
    assert_eq!(tape.bytes(), 8 * 3 * (8 + 13));
    assert!(
        tape.streams() >= 9,
        "the runtime must actually fork task-local providers"
    );
    // The entire source runtime and original OsEntropy wrapper are gone.
    drop(capture);
    let replay = tape.replay();
    let actual = run_contexts(Arc::new(replay.clone()), 777);
    assert_eq!(actual, expected);
    replay.verify_complete().unwrap();
}

#[test]
fn caught_context_divergence_cannot_turn_runtime_quiescence_into_replay_success() {
    fn scenario(entropy: Arc<dyn EntropySource>, changed: bool) -> bool {
        let mut lab = LabRuntime::new(LabConfig::new(19).max_steps(1000));
        lab.state.set_entropy_source(entropy);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let result = Arc::new(Mutex::new(None));
        let published = Arc::clone(&result);
        let (task, _handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let _ = cx.random_u64();
                let mut bytes = [0xa5; 13];
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    if changed {
                        cx.random_bytes(&mut bytes[..12]);
                    } else {
                        cx.random_bytes(&mut bytes);
                    }
                }));
                if changed {
                    assert_eq!(bytes, [0xa5; 13]);
                }
                *published.lock().unwrap() = Some(outcome.is_err());
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_quiescent();
        assert!(lab.is_quiescent());
        result.lock().unwrap().expect("task must publish a result")
    }
    let capture = Arc::new(RecordingEntropy::new(Arc::new(DetEntropy::new(3)), limits()).unwrap());
    assert!(!scenario(capture.clone(), false));
    let replay = capture.finish().unwrap().replay();
    assert!(scenario(Arc::new(replay.clone()), true));
    let error = replay
        .failure()
        .expect("the caught panic must leave a sticky refusal");
    assert_eq!(error.expected, Some(EntropyRequest::Bytes(13)));
    assert_eq!(error.actual, EntropyRequest::Bytes(12));
    assert!(matches!(
        replay.verify_complete(),
        Err(EntropyReplayCompletionError::Diverged(_))
    ));
}

#[test]
fn capture_finish_refuses_a_witnessed_inflight_provider_and_can_be_retried() {
    #[derive(Debug)]
    struct Parked {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl EntropySource for Parked {
        fn fill_bytes(&self, _: &mut [u8]) {
            panic!("unexpected byte call");
        }
        fn next_u64(&self) -> u64 {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            0x1234_5678_9abc_def0
        }
        fn fork(&self, _: TaskId) -> Arc<dyn EntropySource> {
            panic!("unexpected fork");
        }
        fn source_id(&self) -> &'static str {
            "parked-test"
        }
    }
    let (entered_tx, entered) = mpsc::sync_channel(1);
    let (release, release_rx) = mpsc::sync_channel(1);
    let capture = Arc::new(
        RecordingEntropy::new(
            Arc::new(Parked {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            limits(),
        )
        .unwrap(),
    );
    let worker_capture = Arc::clone(&capture);
    let worker = std::thread::spawn(move || worker_capture.next_u64());
    let witness = entered.recv_timeout(Duration::from_secs(5));
    let unfinished = capture.finish();
    // Always release and join before asserting, including against a broken
    // implementation that incorrectly lets finish succeed during the call.
    let _ = release.send(());
    let produced = worker.join().unwrap();
    witness.unwrap();
    assert!(matches!(
        unfinished,
        Err(EntropyCaptureError::InFlight { calls: 1 })
    ));
    let replay = capture.finish().unwrap().replay();
    assert_eq!(replay.try_next_u64().unwrap(), produced);
    replay.verify_complete().unwrap();
}

#[test]
fn provider_unwind_is_preserved_and_never_published_as_a_complete_capture() {
    #[derive(Debug)]
    struct Panics;
    impl EntropySource for Panics {
        fn fill_bytes(&self, _: &mut [u8]) {
            panic!("provider sentinel");
        }
        fn next_u64(&self) -> u64 {
            panic!("provider sentinel");
        }
        fn fork(&self, _: TaskId) -> Arc<dyn EntropySource> {
            panic!("provider sentinel");
        }
        fn source_id(&self) -> &'static str {
            "panicking-test"
        }
    }
    for request in 0..3 {
        let capture = RecordingEntropy::new(Arc::new(Panics), limits()).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| match request {
            0 => capture.fill_bytes(&mut [0; 7]),
            1 => {
                capture.next_u64();
            }
            _ => {
                capture.fork(TaskId::from_arena(ArenaIndex::new(1, 2)));
            }
        }));
        let panic = result.expect_err("the original provider must still panic");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"provider sentinel"));
        assert_eq!(
            capture.failure(),
            Some(EntropyCaptureError::InterruptedCall)
        );
        assert!(matches!(
            capture.finish(),
            Err(EntropyCaptureError::InterruptedCall)
        ));
    }
}

#[test]
fn provider_can_reenter_capture_inspection_without_a_bookkeeping_lock_deadlock() {
    struct Reentrant(Mutex<Weak<RecordingEntropy>>);
    impl std::fmt::Debug for Reentrant {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Reentrant")
        }
    }
    impl EntropySource for Reentrant {
        fn fill_bytes(&self, _: &mut [u8]) {
            panic!("unexpected byte call");
        }
        fn next_u64(&self) -> u64 {
            let capture = self.0.lock().unwrap().upgrade().unwrap();
            assert_eq!(capture.failure(), None);
            assert!(matches!(
                capture.finish(),
                Err(EntropyCaptureError::InFlight { calls: 1 })
            ));
            42
        }
        fn fork(&self, _: TaskId) -> Arc<dyn EntropySource> {
            panic!("unexpected fork");
        }
        fn source_id(&self) -> &'static str {
            "reentrant-test"
        }
    }
    let source = Arc::new(Reentrant(Mutex::new(Weak::new())));
    let capture = Arc::new(RecordingEntropy::new(source.clone(), limits()).unwrap());
    *source.0.lock().unwrap() = Arc::downgrade(&capture);
    let (done, completed) = mpsc::sync_channel(1);
    let worker_capture = Arc::clone(&capture);
    let worker = std::thread::spawn(move || {
        done.send(worker_capture.next_u64()).unwrap();
    });
    let value = completed
        .recv_timeout(Duration::from_secs(5))
        .expect("provider reentry must not deadlock on capture bookkeeping");
    worker.join().unwrap();
    let replay = capture.finish().unwrap().replay();
    assert_eq!(replay.next_u64(), value);
    replay.verify_complete().unwrap();
}

#[test]
fn concurrent_child_sources_replay_in_reverse_order_with_exact_values() {
    let capture = RecordingEntropy::new(Arc::new(DetEntropy::new(68)), limits()).unwrap();
    let mut workers = Vec::new();
    for index in 0..8 {
        let child = capture.fork(TaskId::from_arena(ArenaIndex::new(index, 9)));
        workers.push(std::thread::spawn(move || {
            (0..32).map(|_| child.next_u64()).collect::<Vec<_>>()
        }));
    }
    let expected: Vec<_> = workers
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    let replay = capture.finish().unwrap().replay();
    let children: Vec<_> = (0..8)
        .map(|index| {
            replay
                .try_fork(TaskId::from_arena(ArenaIndex::new(index, 9)))
                .unwrap()
        })
        .collect();
    for index in (0..8).rev() {
        let actual: Vec<_> = (0..32)
            .map(|_| children[index].try_next_u64().unwrap())
            .collect();
        assert_eq!(actual, expected[index]);
    }
    replay.verify_complete().unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn entropy_capture_survives_producer_process_exit_and_replays_context_calls() {
    use std::io::Write;
    use std::process::{Child, Command, Stdio};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    const CHILD_DIRECTORY: &str = "ASUPERSYNC_ENTROPY_TAPE_TEST_CHILD";
    const TEST_NAME: &str =
        "entropy_capture_survives_producer_process_exit_and_replays_context_calls";

    fn write_new(path: &std::path::Path, bytes: &[u8]) {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
        let directory = std::path::PathBuf::from(directory);
        // Deterministic, public test data only: never persist OS entropy here.
        let capture =
            Arc::new(RecordingEntropy::new(Arc::new(DetEntropy::new(44)), limits()).unwrap());
        let expected = run_contexts(capture.clone(), 57);
        let tape = capture.finish().unwrap();
        let bytes = tape
            .to_canonical_bytes(decode_limits().max_encoded_bytes)
            .unwrap();
        write_new(&directory.join("tape.bin"), bytes.as_ref());
        write_new(
            &directory.join("values.json"),
            &serde_json::to_vec(&expected).unwrap(),
        );
        return;
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "asupersync-entropy-replay-{}-{stamp}",
        std::process::id(),
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_DIRECTORY, &directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let began = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            began.elapsed() < Duration::from_secs(15),
            "producer process did not terminate"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    assert!(
        status.success(),
        "the producer must actually execute successfully"
    );
    let encoded = std::fs::read(directory.join("tape.bin")).unwrap();
    let expected: Values =
        serde_json::from_slice(&std::fs::read(directory.join("values.json")).unwrap()).unwrap();
    assert_eq!(
        expected.len(),
        8,
        "a zero-test subprocess cannot pass the witness"
    );
    let tape = EntropyTape::from_canonical_bytes(&encoded, decode_limits()).unwrap();
    let replay = tape.replay();
    let actual = run_contexts(Arc::new(replay.clone()), 999);
    assert_eq!(actual, expected);
    replay.verify_complete().unwrap();
    assert!(
        directory.join("tape.bin").exists(),
        "fixtures are retained, never auto-deleted"
    );
}
