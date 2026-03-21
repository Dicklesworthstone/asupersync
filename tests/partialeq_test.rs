//! Compile-time PartialEq smoke test for `InvariantViolation`.

use asupersync::lab::runtime::InvariantViolation;

fn assert_partial_eq<T: PartialEq>() {}

fn main() {
    assert_partial_eq::<InvariantViolation>();
}
