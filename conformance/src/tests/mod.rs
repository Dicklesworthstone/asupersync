pub mod budget;
pub mod cancellation;
pub mod channels;
pub mod io;
pub mod negative;
pub mod obligation_no_leak;
pub mod outcome;
pub mod runtime;
pub mod structured_concurrency;

use crate::{ConformanceTest, RuntimeInterface};

/// Collect all conformance tests across categories.
pub fn all_tests<RT: RuntimeInterface + Sync>() -> Vec<ConformanceTest<RT>> {
    let mut tests = Vec::new();
    tests.extend(runtime::all_tests::<RT>());
    tests.extend(channels::collect_tests::<RT>());
    tests.extend(outcome::all_tests::<RT>());
    tests.extend(obligation_no_leak::all_tests::<RT>());
    tests.extend(budget::all_tests::<RT>());
    tests.extend(negative::all_tests::<RT>());
    tests.extend(io::all_tests::<RT>());
    tests.extend(cancellation::all_tests::<RT>());
    tests.extend(structured_concurrency::all_tests::<RT>());
    tests
}
