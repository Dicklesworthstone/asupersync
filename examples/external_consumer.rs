//! Simulates how an external crate might consume Asupersync's public API.

use asupersync::{Budget, Cx, LabConfig, LabRuntime, Outcome, Time};

fn main() {
    let _budget = Budget::INFINITE;
    let _deadline = Time::from_secs(1);

    let cx = Cx::for_testing();
    let _ = cx.is_cancel_requested();

    let outcome: Outcome<(), &'static str> = Outcome::ok(());
    let _ = outcome;

    let runtime = LabRuntime::new(LabConfig::new(7));
    let _ = (runtime.now(), runtime.steps());
}
