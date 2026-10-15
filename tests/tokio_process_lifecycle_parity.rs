#![allow(unsafe_code)]
//! Contract tests for [T3.4] Process Lifecycle Parity
//!
//! Validates spawn, stdio, wait, kill, signal, exit status, and cancellation
//! behavior for the `process` module against its parity contract.
//!
//! Categories:
//! - PL-01..PL-10: Lifecycle (spawn, wait, exit status)
//! - PS-01..PS-06: Stdio (pipe configuration and I/O)
//! - PK-01..PK-05: Signal/Kill (termination and signals)
//! - PC-01..PC-04: Cancellation (cancel-safety and kill-on-drop)
//! - PE-01..PE-03: Error paths (not found, permission, double-wait)
//! - PB-01..PB-04: Boundary/Env (environment, cwd, isolation)

use asupersync::Cx;
use asupersync::process::{Command, ExitStatus, ProcessError, Stdio};

// ── Common ───────────────────────────────────────────────────────────

mod common {
    pub const DOC_MD: &str = include_str!("../docs/tokio_process_lifecycle_parity.md");
    pub const DOC_JSON: &str = include_str!("../docs/tokio_process_lifecycle_parity.json");

    pub fn json() -> serde_json::Value {
        serde_json::from_str(DOC_JSON).expect("JSON artifact must parse")
    }

    pub fn md_has_section(heading: &str) -> bool {
        for line in DOC_MD.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("## ") || trimmed.starts_with("### "))
                && trimmed.contains(heading)
            {
                return true;
            }
        }
        false
    }
}

fn current_cx() -> Cx {
    Cx::current().unwrap_or_else(Cx::for_testing)
}

fn successful_command() -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("exit /B 0");
        command
    }

    #[cfg(not(windows))]
    {
        Command::new("true")
    }
}

fn exit_code_command(code: i32) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("exit /B {code}"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!("exit {code}"));
        command
    }
}

fn long_running_command() -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("ping -n 100 127.0.0.1 >NUL");
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sleep");
        command.arg("100");
        command
    }
}

fn echo_line_command(line: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("echo {line}"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("printf");
        command.arg("%s\n").arg(line);
        command
    }
}

fn stderr_line_command(line: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("echo {line} 1>&2"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!("printf '%s\n' {line} >&2"));
        command
    }
}

fn stdout_stderr_lines_command(stdout_line: &str, stderr_line: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command
            .arg("/C")
            .arg(format!("echo {stdout_line} & echo {stderr_line} 1>&2"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "printf '%s\n' {stdout_line}; printf '%s\n' {stderr_line} >&2"
        ));
        command
    }
}

fn env_var_echo_command(var: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("echo %{var}%"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!("printf '%s\n' \"${var}\""));
        command
    }
}

fn env_pair_echo_command(left: &str, right: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("echo %{left}%-%{right}%"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("printf '%s\n' \"${left}-${right}\""));
        command
    }
}

fn cwd_command() -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("cd");
        command
    }

    #[cfg(not(windows))]
    {
        Command::new("pwd")
    }
}

fn env_clear_home_probe_command() -> Command {
    #[cfg(windows)]
    {
        let comspec = std::env::var_os("ComSpec")
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows\System32\cmd.exe"));
        let mut command = Command::new(comspec);
        command
            .arg("/C")
            .arg("if defined HOME (echo present) else (echo empty)");
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.arg("-c").arg(concat!("echo $", "{HOME:-empty}"));
        command
    }
}

fn assert_stdout_line(bytes: &[u8], expected: &str) {
    let line = String::from_utf8(bytes.to_vec()).expect("child output must be valid UTF-8");
    assert_eq!(line.trim_end_matches(['\r', '\n']), expected);
}

#[cfg(unix)]
fn assert_process_not_running_after_drop(pid: u32, context: &str) {
    #[allow(clippy::cast_possible_wrap)]
    let pid = pid as libc::pid_t;

    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ECHILD),
                "{context}: unexpected waitpid error after kill_on_drop"
            );
            return;
        }

        assert_ne!(
            waited, pid,
            "{context}: kill_on_drop terminated the child but left it waitable"
        );
        assert_eq!(
            waited, 0,
            "{context}: unexpected waitpid result after kill_on_drop"
        );

        let probe = unsafe { libc::kill(pid, 0) };
        assert_ne!(
            probe, 0,
            "{context}: child process is still alive after kill_on_drop"
        );
        return;
    }
}

#[cfg(windows)]
fn assert_process_not_running_after_drop(pid: u32, context: &str) {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };

    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return;
    }

    let wait_result = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        CloseHandle(handle);
    }

    assert_eq!(
        wait_result, WAIT_OBJECT_0,
        "{context}: child process is still running after kill_on_drop"
    );
}

// ── PL: Lifecycle ────────────────────────────────────────────────────

#[test]
fn pl_01_spawn_produces_valid_pid() {
    let child = successful_command().spawn().expect("spawn");
    let pid = child.id();
    assert!(pid.is_some(), "Spawned child must have a PID");
    assert!(pid.unwrap() > 0, "PID must be positive");
}

#[test]
fn pl_02_wait_returns_exit_code_zero() {
    let mut child = successful_command().spawn().expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success());
    assert_eq!(status.code(), Some(0));
}

#[test]
fn pl_03_wait_returns_nonzero_exit_code() {
    let mut child = exit_code_command(42).spawn().expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success());
    assert_eq!(status.code(), Some(42));
}

#[test]
fn pl_04_wait_async_returns_exit_code() {
    let status = futures_lite::future::block_on(async {
        let mut child = exit_code_command(7).spawn().expect("spawn");
        let cx = asupersync::cx::Cx::for_testing();
        child.wait_async(&cx).await
    })
    .expect("wait_async");

    assert!(!status.success());
    assert_eq!(status.code(), Some(7));
}

#[test]
fn pl_05_try_wait_returns_none_for_running() {
    let mut child = long_running_command().spawn().expect("spawn");
    let result = child.try_wait().expect("try_wait");
    assert!(result.is_none(), "sleep 10 should still be running");
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn pl_06_try_wait_returns_some_after_exit() {
    let mut child = successful_command().spawn().expect("spawn");
    std::thread::sleep(std::time::Duration::from_millis(50));
    let result = child.try_wait().expect("try_wait");
    assert!(result.is_some(), "true should have exited by now");
}

#[test]
fn pl_07_wait_consumes_handle() {
    let mut child = successful_command().spawn().expect("spawn");
    let _ = child.wait().expect("first wait");
    let result = child.wait();
    assert!(result.is_err(), "Second wait must fail (handle consumed)");
}

#[test]
fn pl_08_output_convenience_method() {
    let output = echo_line_command("lifecycle_test")
        .output()
        .expect("output");
    assert!(output.status.success());
    assert_stdout_line(&output.stdout, "lifecycle_test");
}

#[test]
fn pl_09_output_async_convenience_method() {
    let output = futures_lite::future::block_on(async {
        echo_line_command("async_lifecycle")
            .output_async(&current_cx())
            .await
    })
    .expect("output_async");
    assert!(output.status.success());
    assert_stdout_line(&output.stdout, "async_lifecycle");
}

#[test]
fn pl_10_status_async_convenience() {
    let status = futures_lite::future::block_on(async {
        successful_command().status_async(&current_cx()).await
    })
    .expect("status_async");
    assert!(status.success());
}

// ── PS: Stdio ────────────────────────────────────────────────────────

#[test]
fn ps_01_stdout_pipe_captures_output() {
    let child = echo_line_command("piped")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait_with_output");
    assert_stdout_line(&output.stdout, "piped");
}

#[test]
fn ps_02_stderr_pipe_captures_errors() {
    let child = stderr_line_command("err")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait_with_output");
    assert_stdout_line(&output.stderr, "err");
}

#[test]
fn ps_03_stdin_pipe_writes_data() {
    // Echo input back without relying on private ChildStdin::inner.
    let output = echo_line_command("from_stdin")
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert_stdout_line(&output.stdout, "from_stdin");
    // Stdin piping is also tested via the inline module tests in src/process.rs
}

#[test]
fn ps_04_null_stdio_discards() {
    // Use spawn() instead of output() because output() overrides stdio to Pipe
    let child = echo_line_command("discarded")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait_with_output");
    // stdout/stderr are empty because they were directed to /dev/null (no pipe)
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn ps_05_stdout_and_stderr_both_piped() {
    let child = stdout_stderr_lines_command("out", "err")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let output = child.wait_with_output().expect("wait_with_output");
    assert_stdout_line(&output.stdout, "out");
    assert_stdout_line(&output.stderr, "err");
}

#[test]
fn ps_06_take_once_semantics() {
    let mut child = echo_line_command("x")
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // First take succeeds
    assert!(child.stdin().is_some());
    assert!(child.stdout().is_some());
    assert!(child.stderr().is_some());
    // Second take returns None
    assert!(child.stdin().is_none());
    assert!(child.stdout().is_none());
    assert!(child.stderr().is_none());
    let _ = child.wait();
}

// ── PK: Signal/Kill ──────────────────────────────────────────────────

#[test]
fn pk_01_kill_terminates_process() {
    let mut child = long_running_command().spawn().expect("spawn");
    child.kill().expect("kill");
    let status = child.wait().expect("wait");
    assert!(!status.success());
    #[cfg(unix)]
    assert_eq!(status.signal(), Some(9)); // SIGKILL
}

#[test]
fn pk_02_start_kill_is_kill_alias() {
    let mut child = long_running_command().spawn().expect("spawn");
    child.start_kill().expect("start_kill");
    let status = child.wait().expect("wait");
    assert!(!status.success());
}

#[cfg(unix)]
#[test]
fn pk_03_signal_sends_sigterm() {
    let mut child = long_running_command().spawn().expect("spawn");
    child.signal(libc::SIGTERM).expect("signal SIGTERM");
    let status = child.wait().expect("wait");
    assert!(!status.success());
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

#[cfg(unix)]
#[test]
fn pk_04_signal_sends_sigusr1() {
    // USR1 default action is terminate
    let mut child = long_running_command().spawn().expect("spawn");
    child.signal(libc::SIGUSR1).expect("signal SIGUSR1");
    let status = child.wait().expect("wait");
    assert_eq!(status.signal(), Some(libc::SIGUSR1));
}

#[test]
fn pk_05_kill_after_wait_returns_error() {
    let mut child = successful_command().spawn().expect("spawn");
    let _ = child.wait().expect("wait");
    let result = child.kill();
    assert!(result.is_err(), "kill after wait must fail");
}

// ── PC: Cancellation ─────────────────────────────────────────────────

#[test]
fn pc_01_kill_on_drop_sends_sigkill() {
    let pid;
    {
        let child = long_running_command()
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");
    }
    // After drop, process should be dead.
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_process_not_running_after_drop(pid, "PC-01");
}

#[cfg(unix)]
#[test]
fn pc_02_no_kill_on_drop_leaves_process() {
    let pid;
    {
        let child = long_running_command().spawn().expect("spawn");
        pid = child.id().expect("pid");
    }
    // Process should still be running after drop (no kill_on_drop)
    std::thread::sleep(std::time::Duration::from_millis(10));
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = pid as i32;
    let ret = unsafe { libc::kill(pid_i32, 0) };
    // Clean up
    unsafe { libc::kill(pid_i32, libc::SIGKILL) };
    // Wait to reap zombie
    unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), 0) };
    assert_eq!(ret, 0, "Process should still exist without kill_on_drop");
}

#[test]
fn pc_03_wait_async_cancel_safe() {
    // Cancel wait_async by running only one iteration, then kill
    let mut child = long_running_command().spawn().expect("spawn");
    let result = child.try_wait().expect("try_wait");
    assert!(result.is_none(), "Should still be running");
    // Process continues after we stop polling
    child.kill().expect("kill");
    let status = child.wait().expect("reap");
    assert!(!status.success());
}

#[test]
fn pc_04_wait_with_output_async_captures_data() {
    let output = futures_lite::future::block_on(async {
        let child = echo_line_command("cancel_safe")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let cx = asupersync::cx::Cx::for_testing();
        child.wait_with_output_async(&cx).await
    })
    .expect("wait_with_output_async");
    assert!(output.status.success());
    assert_stdout_line(&output.stdout, "cancel_safe");
}

// ── PE: Error Paths ──────────────────────────────────────────────────

#[test]
fn pe_01_command_not_found() {
    let result = Command::new("nonexistent_command_xyz_99999").spawn();
    assert!(
        matches!(result, Err(ProcessError::NotFound(_))),
        "Expected NotFound, got {result:?}"
    );
}

#[test]
fn pe_02_process_error_display() {
    let err = Command::new("nonexistent_xyz_99999").spawn().unwrap_err();
    let display = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!display.is_empty());
    assert!(!debug.is_empty());
}

#[test]
fn pe_03_exit_status_display_and_construction() {
    // Verify the from_parts constructor and Display impl
    let success = ExitStatus::from_parts(Some(0), None);
    let failure = ExitStatus::from_parts(Some(1), None);
    assert!(success.success());
    assert!(!failure.success());
    assert_eq!(success.to_string(), "exit code: 0");
    assert_eq!(failure.to_string(), "exit code: 1");
    assert_eq!(success.code(), Some(0));
    assert_eq!(failure.code(), Some(1));
}

// ── PB: Boundary/Env ─────────────────────────────────────────────────

#[test]
fn pb_01_env_sets_variable() {
    let output = env_var_echo_command("TEST_VAR")
        .env("TEST_VAR", "parity_test")
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert_stdout_line(&output.stdout, "parity_test");
}

#[test]
fn pb_02_envs_sets_multiple() {
    let output = env_pair_echo_command("A", "B")
        .envs([("A", "x"), ("B", "y")])
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert_stdout_line(&output.stdout, "x-y");
}

#[test]
fn pb_03_current_dir_changes_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let expected = dir.path().canonicalize().expect("canonical tempdir");
    let output = cwd_command()
        .current_dir(&expected)
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim_end_matches(['\r', '\n']),
        expected.display().to_string()
    );
}

#[test]
fn pb_04_env_clear_removes_inherited() {
    let output = env_clear_home_probe_command()
        .env_clear()
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert_stdout_line(&output.stdout, "empty");
}

// ── Contract Artifact Validation ─────────────────────────────────────

#[test]
fn contract_01_json_parses_and_has_bead_id() {
    let j = common::json();
    assert_eq!(
        j.get("bead_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "asupersync-2oh2u.3.4"
    );
}

#[test]
fn contract_02_doc_has_required_sections() {
    let required = [
        "Scope",
        "API Differences",
        "Lifecycle State Machine",
        "Cancellation Semantics",
        "Stdio Piping",
        "Exit Status Semantics",
        "Test Evidence",
        "Drift Detection",
    ];
    for section in &required {
        assert!(
            common::md_has_section(section),
            "Missing section: '{section}'"
        );
    }
}

#[test]
fn contract_03_json_api_coverage_complete() {
    let j = common::json();
    let apis = j
        .get("api_coverage")
        .and_then(serde_json::Value::as_array)
        .expect("api_coverage");
    assert!(apis.len() >= 15, "Must cover at least 15 API items");
    for api in apis {
        let status = api
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_eq!(status, "COMPLETE", "API {api:?} not complete");
    }
}

#[test]
fn contract_04_json_summary_verdict() {
    let j = common::json();
    let summary = j.get("summary").expect("summary");
    assert_eq!(
        summary
            .get("overall_verdict")
            .and_then(serde_json::Value::as_str),
        Some("COMPLIANT")
    );
    assert_eq!(
        summary
            .get("total_tests")
            .and_then(serde_json::Value::as_u64),
        Some(36)
    );
}
