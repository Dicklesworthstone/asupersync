//! Scheduler perf-epic invariant floor under realistic mixed load
//! (br-asupersync-sched-hot-path-perf-bt4y5f.8, stage S2/S4 vehicle for
//! `scripts/run_sched_perf_e2e.sh`).
//!
//! The perf epic's promise is "faster WITHOUT losing a single
//! invariant". The benches measure the first half; this suite is the
//! standing proof of the second: a mixed workload (spawn storms +
//! cancellation waves + channel pressure + timers) on the PRODUCTION
//! runtime must reach clean quiescence — no live tasks, no draining
//! regions, no pending obligations (`Runtime::is_quiescent` reads all
//! three, including shard-C-resident obligations on sharded builds
//! since br-asupersync-m9wsza S4c-2c-iv) — across every live perf
//! config-flag combination (stage S4 matrix):
//! `{spawn_admission: Direct|Mailbox} x {state shape: Unified|Sharded}`.
//!
//! Fairness-envelope assertions (the documented
//! `PreemptionFairnessCertificate::invariant_holds` contract in
//! `src/runtime/scheduler/three_lane.rs`) are worker-local telemetry
//! and stay covered by the scheduler's own certificate tests; the e2e
//! script runs those by name in the same stage. Live-runtime
//! certificate aggregation is tracked separately (see the bead
//! comment) rather than silently approximated here.
//!
//! BREAKAGE REHEARSAL (bead AC5): setting
//! `ASUPERSYNC_SCHED_E2E_SABOTAGE=quiescence` makes the workload leave
//! a deliberately unjoined long sleeper behind and assert quiescence
//! immediately, which must FAIL with a pointed message. The e2e script
//! uses this env-injected control to prove the red path executes, then
//! reruns clean — no source bytes are ever modified.

use asupersync::runtime::{Runtime, RuntimeConfig};
use asupersync::time::{sleep, timeout, wall_now};
use std::time::Duration;

fn runtime_with(
    admission: asupersync::runtime::config::SpawnAdmissionMode,
    shape: asupersync::runtime::config::RuntimeStateShape,
) -> Runtime {
    let mut config = RuntimeConfig::default();
    config.worker_threads = 2;
    config.spawn_admission = admission;
    config.runtime_state_shape = shape;
    Runtime::with_config(config).expect("runtime constructs for matrix cell")
}

/// Drives the mixed workload and returns after every joined task
/// resolved. Cancellation waves are real protocol cancels: `timeout`
/// around a much longer sleep forces request -> drain -> finalize on
/// the production path.
fn drive_mixed_workload(runtime: &Runtime) {
    const SPAWN_STORM: usize = 64;
    const CHANNEL_MSGS: usize = 128;
    const CANCEL_WAVE: usize = 16;

    let sabotage_quiescence =
        std::env::var("ASUPERSYNC_SCHED_E2E_SABOTAGE").as_deref() == Ok("quiescence");

    runtime.block_on(async {
        // (1) Spawn storm: small compute tasks joined in spawn order.
        let mut storm = Vec::with_capacity(SPAWN_STORM);
        for i in 0..SPAWN_STORM {
            let handle = Runtime::current_handle()
                .expect("inside block_on")
                .spawn(async move { i.wrapping_mul(31) ^ (i << 3) });
            storm.push(handle);
        }

        // (2) Channel pressure: bounded mpsc, two-phase sends, one consumer.
        let (tx, mut rx) = asupersync::channel::mpsc::channel::<usize>(8);
        // Producer/consumer are fire-and-forget region-owned tasks
        // (`spawn_with_cx` returns unit); the post-drain quiescence
        // check below is what proves they completed and resolved
        // every reserve permit.
        Runtime::current_handle()
            .expect("inside block_on")
            .spawn_with_cx(move |cx| async move {
                for i in 0..CHANNEL_MSGS {
                    let permit = tx.reserve(&cx).await.expect("reserve under pressure");
                    permit.send(i);
                }
            });
        Runtime::current_handle()
            .expect("inside block_on")
            .spawn_with_cx(move |cx| async move {
                let mut got = 0usize;
                while got < CHANNEL_MSGS {
                    match rx.recv(&cx).await {
                        Ok(_) => got += 1,
                        Err(_) => break,
                    }
                }
            });

        // (3) Cancellation waves: timeouts force protocol cancels of
        // long sleepers; the elapsed error is the expected outcome.
        let mut waves = Vec::with_capacity(CANCEL_WAVE);
        for _ in 0..CANCEL_WAVE {
            waves.push(
                Runtime::current_handle()
                    .expect("inside block_on")
                    .spawn(async {
                        let long = sleep(wall_now(), Duration::from_secs(30));
                        timeout(wall_now(), Duration::from_millis(5), long).await
                    }),
            );
        }

        // (4) Timers: short sleeps interleaved with the rest.
        for _ in 0..8 {
            sleep(wall_now(), Duration::from_millis(1)).await;
        }

        // Join everything spawned above (JoinHandle implements Future).
        for handle in storm {
            let _ = handle.await;
        }
        for handle in waves {
            let _ = handle.await;
        }

        if sabotage_quiescence {
            // Deliberately leave an unjoined 10s sleeper live so the
            // post-drain quiescence assertion below MUST fail — the
            // e2e script's red-path control (bead AC5).
            let _leaked = Runtime::current_handle()
                .expect("inside block_on")
                .spawn(async {
                    sleep(wall_now(), Duration::from_secs(10)).await;
                });
        }
    });

    if sabotage_quiescence {
        assert!(
            runtime.is_quiescent(),
            "SABOTAGE CONTROL: runtime must NOT be quiescent while the \
             deliberately-leaked sleeper lives — if this assertion \
             message appears the control worked as intended \
             (br-asupersync-sched-hot-path-perf-bt4y5f.8 AC5)"
        );
    }
}

/// Post-drain floor: the runtime reaches full quiescence — no live
/// tasks, no draining regions, no pending obligations — within a
/// bounded deadline.
fn assert_invariant_floor(runtime: &Runtime, cell: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if runtime.is_quiescent() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "invariant floor violated in cell {cell}: runtime failed to \
             reach quiescence within 20s after the mixed workload \
             (live tasks, draining regions, or pending obligations \
             remain — see bt4y5f.8 S2)"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        runtime.draining_region_count(),
        0,
        "invariant floor violated in cell {cell}: draining regions \
         remain after quiescence"
    );
}

fn run_cell(
    admission: asupersync::runtime::config::SpawnAdmissionMode,
    shape: asupersync::runtime::config::RuntimeStateShape,
    cell: &str,
) {
    let runtime = runtime_with(admission, shape);
    drive_mixed_workload(&runtime);
    assert_invariant_floor(&runtime, cell);
}

use asupersync::runtime::config::{RuntimeStateShape, SpawnAdmissionMode};

#[test]
fn mixed_load_floor_direct_unified() {
    run_cell(
        SpawnAdmissionMode::Direct,
        RuntimeStateShape::Unified,
        "direct/unified",
    );
}

#[test]
fn mixed_load_floor_mailbox_unified() {
    run_cell(
        SpawnAdmissionMode::Mailbox,
        RuntimeStateShape::Unified,
        "mailbox/unified",
    );
}

#[test]
fn mixed_load_floor_direct_sharded() {
    run_cell(
        SpawnAdmissionMode::Direct,
        RuntimeStateShape::Sharded,
        "direct/sharded",
    );
}

#[test]
fn mixed_load_floor_mailbox_sharded() {
    run_cell(
        SpawnAdmissionMode::Mailbox,
        RuntimeStateShape::Sharded,
        "mailbox/sharded",
    );
}
