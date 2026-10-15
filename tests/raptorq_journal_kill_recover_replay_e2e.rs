//! Process-level kill -> recover -> replay e2e for the crash-durable RaptorQ
//! trace journal (br-asupersync-raptorq-leverage-3bb2pl.2 AC6).
//!
//! AC6 asks for an e2e stage covering the full kill->recover->replay chain. The
//! deterministic in-process pieces are already pinned — torn-write boundary
//! recovery (AC1, `raptorq_journal_writer_io_contract.rs`) and recover->replay
//! round-trip (AC5) — so what this adds is the literal piece those reserve: a
//! REAL operating-system process that journals a trace, is then **SIGKILL**ed,
//! and whose durably-written symbol journal is recovered byte-exact and replayed
//! event-for-event from a different process.
//!
//! Mechanics: the test re-execs its own binary as a child (selected by an env
//! flag + an `--exact` filter so only this one test runs in the child). The
//! child records a deterministic trace, durably journals it (atomic write +
//! fsync per stripe/manifest/params), writes a `ready` marker, then spins. The
//! parent waits for the marker — so the journal is guaranteed durable — then
//! sends a real `SIGKILL` (`std::process::Child::kill`) and verifies the kill
//! happened (exit signal 9). It then recovers the latest epoch from disk,
//! confirms byte-exact recovery even after additionally losing a whole failure
//! domain (a lost stripe file), and drives the frankenlab replayer over the
//! recovered trace with zero divergence.
//!
//! Both processes build the identical deterministic fixture, so the parent knows
//! the expected bytes without the child shipping them out-of-band — recovery is
//! verified against an independently reconstructed ground truth.

#![allow(missing_docs)]

#[cfg(unix)]
mod kill_recover_replay {
    use asupersync::config::EncodingConfig;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::trace::raptorq_journal_writer::{
        DurableTraceJournal, DurableTraceJournalConfig, stripe_file_name,
    };
    use asupersync::trace::{ReplayEvent, ReplayTrace, TraceMetadata, TraceReplayer};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    /// Env var carrying the child's journal directory; its presence selects child
    /// mode when the test binary re-execs itself.
    const CHILD_DIR_ENV: &str = "ASUP_AC6_CHILD_JOURNAL_DIR";
    /// The single checkpoint epoch the child journals.
    const EPOCH: u64 = 42;
    const REPAIR_COUNT: usize = 10;
    const STRIPE_COUNT: usize = 3;
    /// Marker the child writes once the journal is fully durable on disk.
    const READY_MARKER: &str = "child-ready";

    /// The deterministic, varied recorded execution both processes agree on (a
    /// constant stream would round-trip trivially): interleaved virtual-time +
    /// timer events, same shape the AC5 round-trip uses.
    fn build_fixture_trace() -> ReplayTrace {
        let mut trace = ReplayTrace::new(
            TraceMetadata::new(0xA5A5_6C06).with_description("3bb2pl.2 AC6 kill/recover/replay"),
        );
        for i in 0..12u64 {
            trace.push(ReplayEvent::TimeAdvanced {
                from_nanos: i * 1_000,
                to_nanos: (i + 1) * 1_000,
            });
            trace.push(ReplayEvent::TimerCreated {
                timer_id: i,
                deadline_nanos: (i + 1) * 1_000 + 250,
            });
            trace.push(ReplayEvent::TimerFired { timer_id: i });
        }
        trace
    }

    fn journal_for(dir: PathBuf) -> DurableTraceJournal {
        DurableTraceJournal::new(DurableTraceJournalConfig {
            directory: dir,
            encoding: EncodingConfig::default(),
            repair_count: REPAIR_COUNT,
            stripe_count: STRIPE_COUNT,
        })
    }

    /// Child entry point: durably journal the fixture trace, signal readiness,
    /// then spin (bounded, so a dead parent never orphans us forever) waiting to
    /// be SIGKILLed. Never returns to the cargo-test harness — exits the process.
    fn run_child(dir: PathBuf) -> ! {
        let checkpoint = build_fixture_trace()
            .to_bytes()
            .expect("serialize fixture trace");

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("child runtime");
        let dir_for_task = dir.clone();
        runtime.block_on(runtime.handle().spawn(async move {
            journal_for(dir_for_task)
                .record_epoch(EPOCH, &checkpoint)
                .await
                .expect("child records durable trace epoch");
        }));

        // The epoch's stripes + manifest + params are now atomically written and
        // fsynced. Announce durability so the parent only kills us afterwards.
        std::fs::write(dir.join(READY_MARKER), b"ok").expect("write ready marker");

        // Spin waiting for the kill; bounded at ~60s so an absent parent cannot
        // leave an eternal orphan.
        for _ in 0..300 {
            std::thread::sleep(Duration::from_millis(200));
        }
        std::process::exit(0);
    }

    fn wait_for_marker(dir: &Path, timeout: Duration) -> bool {
        let start = Instant::now();
        let marker = dir.join(READY_MARKER);
        while start.elapsed() < timeout {
            if marker.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn sigkilled_process_journal_recovers_byte_exact_and_replays() {
        // ---- Child branch (re-exec): journal + spin until killed. ----
        if let Ok(dir) = std::env::var(CHILD_DIR_ENV) {
            run_child(PathBuf::from(dir));
        }

        // ---- Parent branch: spawn child, kill it, recover + replay. ----
        let dir = tempfile::tempdir().expect("journal tempdir");
        let dir_path = dir.path().to_path_buf();

        let exe = std::env::current_exe().expect("current test binary path");
        let mut child = std::process::Command::new(exe)
            // Run ONLY this test in the child so it hits the child branch and
            // nothing else from the binary executes. The path is module-qualified
            // because the test lives inside `mod kill_recover_replay`.
            .args([
                "kill_recover_replay::sigkilled_process_journal_recovers_byte_exact_and_replays",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD_DIR_ENV, &dir_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn child test process");

        // Wait until the child reports the journal is fully durable on disk.
        let durable = wait_for_marker(&dir_path, Duration::from_secs(60));
        if !durable {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child never durably journaled the trace within the timeout");
        }

        // Send a REAL SIGKILL to the live, mid-spin process.
        child.kill().expect("SIGKILL the child");
        let status = child.wait().expect("reap child");
        assert_eq!(
            status.signal(),
            Some(9),
            "child must have been terminated by SIGKILL (signal 9), got {status:?}"
        );

        // The fixture both processes agreed on is the ground truth.
        let expected = build_fixture_trace()
            .to_bytes()
            .expect("serialize fixture trace");
        let expected_events: Vec<ReplayEvent> = build_fixture_trace().iter().cloned().collect();
        assert!(
            expected_events.len() >= 12,
            "fixture must record a non-trivial trace"
        );

        // Recover + replay from the SIGKILLed process's on-disk journal.
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("parent runtime");
        let dir_for_task = dir_path.clone();
        let expected_for_task = expected.clone();
        let events_for_task = expected_events.clone();

        let (latest_epoch, recovered_after_loss, replayed_count, completed, divergence_caught) =
            runtime.block_on(runtime.handle().spawn(async move {
                let journal = journal_for(dir_for_task.clone());

                // Given only the directory, find + decode the newest checkpoint
                // the dead process left behind.
                let (epoch, recovered) = journal
                    .recover_latest()
                    .await
                    .expect("recover_latest after kill")
                    .expect("a recoverable epoch must survive the SIGKILL");
                assert_eq!(
                    recovered, expected_for_task,
                    "recovery from the killed process must be byte-exact"
                );

                // Crash hardening: even after ALSO losing a whole failure domain
                // (a stripe file), the epoch still recovers byte-exact.
                std::fs::remove_file(dir_for_task.join(stripe_file_name(epoch, 1)))
                    .expect("lose a stripe file");
                let recovered_after_loss = journal
                    .recover_epoch(epoch)
                    .await
                    .expect("recover after kill + lost failure domain");

                // The recovered bytes deserialize and replay event-for-event.
                let reconstructed = ReplayTrace::from_bytes(&recovered_after_loss)
                    .expect("recovered bytes form a valid trace");
                let mut replayer = TraceReplayer::new(reconstructed);
                for actual in &events_for_task {
                    replayer
                        .verify_and_advance(actual)
                        .expect("recovered trace replays without divergence");
                }
                let completed = replayer.is_completed();

                // Non-vacuity: a wrong event is actually CAUGHT as a divergence.
                let mut fresh = TraceReplayer::new(replayer.into_trace());
                let divergence_caught = fresh
                    .verify_and_advance(&ReplayEvent::TimerFired { timer_id: u64::MAX })
                    .is_err();

                (
                    epoch,
                    recovered_after_loss,
                    events_for_task.len(),
                    completed,
                    divergence_caught,
                )
            }));

        assert_eq!(
            latest_epoch, EPOCH,
            "recover_latest must find the journaled epoch"
        );
        assert_eq!(
            recovered_after_loss, expected,
            "recovery must stay byte-exact after kill + lost failure domain"
        );
        assert_eq!(
            replayed_count,
            expected_events.len(),
            "the replayer must process every recovered event"
        );
        assert!(completed, "replay must reach completion with no divergence");
        assert!(
            divergence_caught,
            "the replayer must actually verify events -- a wrong event must diverge"
        );
    }
}
