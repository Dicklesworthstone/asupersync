//! Compile-time PartialEq smoke test for `InvariantViolation`.

use asupersync::lab::runtime::InvariantViolation;

fn assert_partial_eq<T: PartialEq>() {}

#[test]
fn test_partial_eq() {
    assert_partial_eq::<InvariantViolation>();
}
