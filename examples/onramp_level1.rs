//! Level 1: make capabilities, outcomes, and budgets explicit.

use asupersync::{main, prelude::*};

#[main]
async fn main(cx: &Cx) {
    let service = Budget::new().with_poll_quota(64);
    let request = Budget::new().with_poll_quota(16);
    let effective = service.meet(request);
    assert_eq!(effective.remaining_polls(), 16);

    cx.checkpoint()
        .expect("budget and cancellation permit work");
    let outcome: Outcome<u32, Error> = Outcome::ok(42);
    assert_eq!(outcome.expect("work succeeds"), 42);
}
