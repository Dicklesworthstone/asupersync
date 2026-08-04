//! Integration smoke tests for the process command APIs.

use asupersync::process::Command;
use asupersync::process::ExactImageCommand;
use asupersync::process::ProcessError;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use asupersync::process::{EXACT_IMAGE_SPAWN_POLICY_VERSION, ExactImageSpawnMechanism};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{Read, Write};

fn current_cx() -> asupersync::cx::Cx {
    asupersync::cx::Cx::current().unwrap_or_else(asupersync::cx::Cx::for_testing)
}

fn run_command() -> Result<(), ProcessError> {
    let _output = Command::new("echo").arg("hello").output()?;
    Ok(())
}

fn run_command_async() -> Result<(), ProcessError> {
    futures_lite::future::block_on(async {
        let mut child = Command::new("sh").arg("-c").arg(":").spawn()?;
        let cx = asupersync::cx::Cx::for_testing();
        let _status = child.wait_async(&cx).await?;
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
        let cx = current_cx();
        cmd.output_async(&cx).await
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
        let cx = current_cx();
        cmd.status_async(&cx).await
    })
    .expect("status_async should succeed");

    assert!(!status.success(), "exit 42 should not be success");
    assert_eq!(status.code(), Some(42));
}

#[test]
fn exact_image_refuses_relative_program() {
    let error = ExactImageCommand::new("relative-program")
        .spawn()
        .expect_err("relative exact-image path must be refused");
    assert!(
        matches!(error, ProcessError::InvalidConfiguration(_)),
        "unexpected exact-image refusal: {error}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exact_image_uses_private_pipes_and_exact_environment() {
    let mut command = ExactImageCommand::new("/usr/bin/env");
    command.env("ASUPERSYNC_EXACT_IMAGE_ONLY", "owned");
    let mut child = command.spawn().expect("spawn /usr/bin/env directly");

    assert_eq!(
        child.mechanism(),
        ExactImageSpawnMechanism::PosixSpawnAbsoluteProcessGroup
    );
    assert_eq!(
        child.mechanism().identity(),
        "posix_spawn.absolute_path.new_process_group"
    );
    assert_eq!(EXACT_IMAGE_SPAWN_POLICY_VERSION, 1);

    drop(child.take_stdin().expect("private exact-image stdin"));
    let mut stdout = child.take_stdout().expect("private exact-image stdout");
    let mut stderr = child.take_stderr().expect("private exact-image stderr");
    let status = child.wait().expect("wait for /usr/bin/env");
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    stdout
        .read_to_end(&mut stdout_bytes)
        .expect("read exact-image stdout");
    stderr
        .read_to_end(&mut stderr_bytes)
        .expect("read exact-image stderr");

    assert!(status.success(), "env failed: {stderr_bytes:?}");
    assert_eq!(
        stdout_bytes, b"ASUPERSYNC_EXACT_IMAGE_ONLY=owned\n",
        "child inherited or lost environment entries"
    );
    assert!(
        stderr_bytes.is_empty(),
        "unexpected stderr: {stderr_bytes:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exact_image_round_trips_stdin_without_shell_parsing() {
    let mut child = ExactImageCommand::new("/bin/cat")
        .spawn()
        .expect("spawn /bin/cat directly");
    let mut stdin = child.take_stdin().expect("private exact-image stdin");
    stdin
        .write_all(b"shell metacharacters stay data: $HOME; $(false)\n")
        .expect("write exact-image stdin");
    drop(stdin);

    let mut stdout = child.take_stdout().expect("private exact-image stdout");
    let mut stderr = child.take_stderr().expect("private exact-image stderr");
    let status = child.wait().expect("wait for /bin/cat");
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    stdout
        .read_to_end(&mut stdout_bytes)
        .expect("read exact-image stdout");
    stderr
        .read_to_end(&mut stderr_bytes)
        .expect("read exact-image stderr");

    assert!(status.success(), "cat failed: {stderr_bytes:?}");
    assert_eq!(
        stdout_bytes, b"shell metacharacters stay data: $HOME; $(false)\n",
        "stdin was not passed as opaque bytes"
    );
    assert!(
        stderr_bytes.is_empty(),
        "unexpected stderr: {stderr_bytes:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exact_image_never_interprets_executable_text_without_shebang() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/process/executable_text_no_shebang");
    let error = ExactImageCommand::new(fixture)
        .spawn()
        .expect_err("executable text without a shebang must not run");
    assert!(
        matches!(
            &error,
            ProcessError::Io(source) if source.raw_os_error() == Some(libc::ENOEXEC)
        ),
        "unexpected direct-spawn refusal: {error}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exact_image_tree_kill_reaps_the_process_group_leader() {
    let mut command = ExactImageCommand::new("/bin/sleep");
    command.arg("30");
    let mut child = command.spawn().expect("spawn /bin/sleep directly");
    let pid = nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).expect("exact-image child pid must fit i32"),
    );
    assert_eq!(
        nix::unistd::getpgid(Some(pid)).expect("read exact-image process group"),
        pid,
        "exact-image child must lead its isolated process group"
    );

    child
        .kill_process_tree()
        .expect("kill exact-image process tree");
    let status = child.wait().expect("reap exact-image process leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}
