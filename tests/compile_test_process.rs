//! Compile-only smoke test for process command API.

use asupersync::process::Command;
use asupersync::process::ProcessError;

fn run_command() -> Result<(), ProcessError> {
    let _output = Command::new("echo").arg("hello").output()?;
    Ok(())
}

#[test]
fn process_command_api_compiles() {
    run_command().expect("process command should run");
}
