pub mod budget;
pub mod channels;
pub mod io;
pub mod negative;
pub mod outcome;
pub mod runtime;

use crate::{ConformanceTest, RuntimeInterface};

/// Collect all conformance tests across categories.
pub fn all_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    let mut tests = Vec::new();
    tests.extend(runtime::all_tests::<RT>());
    tests.extend(channels::collect_tests::<RT>());
    tests.extend(outcome::all_tests::<RT>());
    tests.extend(budget::all_tests::<RT>());
    tests.extend(negative::all_tests::<RT>());
    tests.extend(io::all_tests::<RT>());
    tests
}
