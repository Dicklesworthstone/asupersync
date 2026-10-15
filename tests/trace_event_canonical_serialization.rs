//! Canonical wire-format golden for `TraceEvent`.
//!
//! `TraceEvent` rides the wire between recorder, replayer, browser bridge
//! and distributed sheaf — any unintentional schema drift is a
//! cross-component breakage. This snapshot freezes the JSON shape across
//! every `TraceData` variant. Every event also round-trips through
//! `Deserialize` so a renamed field that happens to keep its JSON layout
//! still trips the assertion.
//!
//! Lives under `tests/` (not the `cfg(test)` module in `src/trace/event.rs`)
//! so it compiles into its own integration-test binary against the public
//! crate surface, independent of unrelated in-tree test modules.

use asupersync::monitor::DownReason;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::distributed::{LamportTime, LogicalTime};
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 1)
}
fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 1)
}
fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 1)
}

#[test]
fn trace_event_canonical_serialization_golden() {
    let events = vec![
        TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::UserTrace,
            TraceData::None,
        ),
        TraceEvent::spawn(2, Time::from_nanos(100), task(1), region(1)),
        TraceEvent::region_created(3, Time::from_nanos(200), region(2), Some(region(1))),
        TraceEvent::obligation_commit(
            4,
            Time::from_nanos(300),
            obligation(5),
            task(1),
            region(1),
            ObligationKind::Lease,
            1_500,
        ),
        TraceEvent::obligation_abort(
            5,
            Time::from_nanos(310),
            obligation(6),
            task(1),
            region(1),
            ObligationKind::SendPermit,
            2_500,
            ObligationAbortReason::Error,
        ),
        TraceEvent::cancel_request(
            6,
            Time::from_nanos(400),
            task(1),
            region(1),
            CancelReason::timeout(),
        ),
        TraceEvent::worker_cancel_requested(
            7,
            Time::from_nanos(500),
            "worker-canonical",
            42,
            7,
            0xDEAD_BEEF,
            task(1),
            region(1),
            obligation(2),
        ),
        TraceEvent::region_cancelled(
            8,
            Time::from_nanos(600),
            region(1),
            CancelReason::shutdown(),
        ),
        TraceEvent::time_advance(
            9,
            Time::from_nanos(700),
            Time::from_nanos(700),
            Time::from_nanos(800),
        ),
        TraceEvent::timer_scheduled(10, Time::from_nanos(800), 100, Time::from_nanos(900)),
        TraceEvent::timer_fired(11, Time::from_nanos(810), 100),
        TraceEvent::io_requested(12, Time::from_nanos(900), 7, 3),
        TraceEvent::io_ready(13, Time::from_nanos(1_000), 7, 1),
        TraceEvent::io_result(14, Time::from_nanos(1_100), 7, 4_096),
        TraceEvent::io_error(15, Time::from_nanos(1_200), 7, 5),
        TraceEvent::rng_seed(16, Time::from_nanos(1_300), 0x00C0_FFEE),
        TraceEvent::rng_value(17, Time::from_nanos(1_400), 42),
        TraceEvent::checkpoint(18, Time::from_nanos(1_500), 1_000, 5, 2),
        TraceEvent::new(
            19,
            Time::from_nanos(1_600),
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(2),
                region: region(1),
                idle_steps: 100,
                held: vec![(obligation(3), ObligationKind::SendPermit)],
            },
        ),
        TraceEvent::monitor_created(20, Time::from_nanos(1_700), 50, task(1), region(1), task(2)),
        TraceEvent::down_delivered(
            21,
            Time::from_nanos(1_800),
            50,
            task(1),
            task(2),
            Time::from_nanos(1_750),
            DownReason::Normal,
        ),
        TraceEvent::link_created(
            22,
            Time::from_nanos(1_900),
            60,
            task(1),
            region(1),
            task(2),
            region(2),
        ),
        TraceEvent::exit_delivered(
            23,
            Time::from_nanos(2_000),
            60,
            task(1),
            task(2),
            Time::from_nanos(1_950),
            DownReason::Normal,
        ),
        TraceEvent::user_trace(24, Time::from_nanos(2_100), "canonical-trace-marker"),
        TraceEvent::new(
            25,
            Time::from_nanos(2_200),
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".to_string(),
                task: Some(task(1)),
                detail: "injected 1ms delay".to_string(),
            },
        ),
        TraceEvent::poll(26, Time::from_nanos(2_300), task(1), region(1))
            .with_logical_time(LogicalTime::Lamport(LamportTime::from_raw(7))),
    ];

    for event in &events {
        let json = serde_json::to_value(event).expect("serialize trace event");
        let decoded: TraceEvent = serde_json::from_value(json).expect("deserialize trace event");
        assert_eq!(*event, decoded, "round-trip mismatch for {event:?}");
    }

    insta::assert_json_snapshot!("trace_event_canonical_serialization", events);
}
