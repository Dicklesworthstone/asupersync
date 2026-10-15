//! Simulates how an external crate might consume Asupersync's public API.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, LabConfig, LabRuntime, Outcome, Time};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let budget = Budget::INFINITE;
    let deadline = Time::from_secs(1);
    let _ = (budget, deadline);

    let outcome: Outcome<(), &'static str> = Outcome::ok(());
    let _ = outcome;

    let runtime = LabRuntime::new(LabConfig::new(7));
    let _ = (runtime.now(), runtime.steps());

    let runtime = RuntimeBuilder::current_thread().build()?;
    let value = runtime.block_on(async {
        let handle = Runtime::current_handle().expect("block_on installs a runtime handle");
        handle.spawn(async { 21_u32 * 2 }).await
    });
    assert_eq!(value, 42);

    Ok(())
}
