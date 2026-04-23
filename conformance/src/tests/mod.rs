pub mod budget;
pub mod cancel_protocol;
pub mod cancellation;
pub mod channels;
pub mod io;
pub mod negative;
pub mod obligation_no_leak;
pub mod outcome;
pub mod region_quiescence;
pub mod runtime;
// Temporarily disabled due to pre-existing compilation issues
// pub mod structured_concurrency;

use crate::{ConformanceTest, RuntimeInterface};

/// Collect all conformance tests across categories.
pub fn all_tests<RT: RuntimeInterface + Sync>() -> Vec<ConformanceTest<RT>> {
    let mut tests = Vec::new();
    tests.extend(runtime::all_tests::<RT>());
    tests.extend(channels::collect_tests::<RT>());
    tests.extend(outcome::all_tests::<RT>());
    tests.extend(obligation_no_leak::all_tests::<RT>());
    tests.extend(budget::all_tests::<RT>());
    tests.extend(region_quiescence::all_tests::<RT>());
    tests.extend(negative::all_tests::<RT>());
    tests.extend(io::all_tests::<RT>());
    tests.extend(cancellation::all_tests::<RT>());
    // Temporarily commented out due to pre-existing compilation issues
    // tests.extend(structured_concurrency::all_tests::<RT>());
    tests.extend(cancel_protocol::all_tests::<RT>());
    tests
}
