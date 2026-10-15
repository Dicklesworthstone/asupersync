//! The third API-v2 on-ramp program: how you prove something is deterministic.
//!
//! `hello.rs` shows the entry point and `spawn_fanout.rs` shows structured
//! fan-out. This one shows the payoff: the same seed replays the same
//! execution, so a concurrency bug becomes a reproducible test failure instead
//! of a flake. Run it with `cargo run --example deterministic_test`.
//!
//! Kept deliberately short — it is an on-ramp, and
//! `scripts/run_api_v2_e2e.sh` gates its length so ceremony cannot creep back.
//! The rigorous version of these same claims, with full diagnostics, lives in
//! `tests/api_v2_integration.rs`; an example should teach, not audit.

use asupersync::lab::{LabRunReport, run_async_under_lab};
use asupersync::prelude::*;

fn main() {
    let (total, report) = fanout(7);
    assert_eq!(total, fanout(7).0, "same seed must replay identically");
    assert!(report.quiescent, "region close implies quiescence");
    assert!(report.invariant_violations.is_empty(), "nothing leaked");
    println!("deterministic: replayed {total} under seed 7, quiescent, 0 violations");
}

/// Sums a fan-out of 8 children under the deterministic lab runtime.
fn fanout(seed: u64) -> (u32, LabRunReport) {
    run_async_under_lab(seed, |cx| async move {
        let mut set = JoinSet::in_cx(&cx);
        for i in 0..8_u32 {
            set.spawn(&cx, move |_| async move { Ok::<_, ()>(i) })
                .expect("spawn");
        }
        let outcomes = set.join_all(&cx).await;
        outcomes.into_iter().map(|o| o.expect("member ok")).sum()
    })
}
