//! Regression tests for race combinator panic precedence.

use asupersync::combinator::race::{RaceError, RaceWinner, race2_to_result};
use asupersync::types::Outcome;
use asupersync::types::outcome::PanicPayload;

#[test]
fn race2_loser_panic_swallowed() {
    let o1: Outcome<i32, &str> = Outcome::Ok(42);
    let o2: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("boom"));

    let result = race2_to_result(RaceWinner::First, o1, o2);
    assert!(
        matches!(result, Err(RaceError::Panicked(_))),
        "Expected Panicked, got {result:?}"
    );
}
