#![allow(warnings)]
#![allow(clippy::all)]
//! Compile-only smoke test for process command API.

use asupersync::process::Command;
use asupersync::process::ProcessError;

fn run_command() -> Result<(), ProcessError> {
    let _output = Command::new("echo").arg("hello").output()?;
    Ok(())
}

fn run_command_async() -> Result<(), ProcessError> {
    futures_lite::future::block_on(async {
        let mut child = Command::new("echo").arg("hello").spawn()?;
        let _status = child.wait_async().await?;
        Ok::<(), ProcessError>(())
    })?;
    Ok(())
}

#[test]
fn process_command_api_compiles() {
    run_command().expect("process command should run");
    run_command_async().expect("async process command should run");
}

#[test]
fn process_output_async_echoes_stdout() {
    let output = futures_lite::future::block_on(async {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        cmd.output_async().await
    })
    .expect("output_async should succeed");

    assert!(output.status.success(), "echo should exit successfully");
    assert_eq!(output.stdout, b"hello\n");
}

#[test]
fn process_status_async_reports_nonzero_exit() {
    let status = futures_lite::future::block_on(async {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("exit 42");
        cmd.status_async().await
    })
    .expect("status_async should succeed");

    assert!(!status.success(), "exit 42 should not be success");
    assert_eq!(status.code(), Some(42));
}
