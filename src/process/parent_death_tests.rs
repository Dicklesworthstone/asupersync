#![cfg(all(test, target_os = "linux"))]
//! Parent-death signal regressions for `Command::parent_death_signal`.
//!
//! A helper process, this test binary re-executed on one ignored test, spawns
//! two `sleep` children through the public `Command`: one with a parent-death
//! signal and one without. The test then SIGKILLs the helper, so no `Drop`,
//! `kill_on_drop` or reaper hand-off runs in it. The guarded child must die;
//! the unguarded child is the control and must survive the same window.
//! Liveness is read from `/proc/<pid>/stat`: an exited zombie counts as dead.

use super::{Command, ProcessError, Stdio};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::io::{BufRead, BufReader, Write};
use std::process as std_process;
use std::thread;
use std::time::{Duration, Instant};

const HELPER_ENV: &str = "ASUPERSYNC_PARENT_DEATH_HELPER";
const HELPER_TEST: &str = "process::parent_death_tests::parent_death_helper_process";
const PIDS_PREFIX: &str = "PARENT_DEATH_PIDS ";
const DEADLINE: Duration = Duration::from_secs(10);

fn alive(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // The state follows the parenthesised command name, which may contain ')'.
    let state = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next());
    !matches!(state, None | Some("Z" | "X" | "x"))
}

fn spawn_sleep(signal: Option<i32>) -> u32 {
    let child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .parent_death_signal(signal)
        .spawn()
        .expect("spawn sleep child");
    child.id().expect("running child has a pid")
}

#[test]
#[ignore = "helper process for parent_death_signal_kills_the_child_of_a_sigkilled_parent"]
fn parent_death_helper_process() {
    if std::env::var_os(HELPER_ENV).is_none() {
        return;
    }
    eprintln!("parent_death helper: spawning children");
    let guarded = spawn_sleep(Some(libc::SIGKILL));
    let unguarded = spawn_sleep(None);
    eprintln!("parent_death helper: spawned guarded={guarded} unguarded={unguarded}");
    let mut stdout = std::io::stdout().lock();
    // libtest has already written "test <name> ... " without a newline.
    writeln!(stdout, "\n{PIDS_PREFIX}{guarded} {unguarded}").expect("report child pids");
    stdout.flush().expect("flush child pids");
    drop(stdout);
    // The signal follows the spawning thread, so keep it alive until the test
    // SIGKILLs this whole process.
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

struct Helper(std_process::Child);

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn parent_death_signal_kills_the_child_of_a_sigkilled_parent() {
    let binary = std::env::current_exe().expect("test binary path");
    let mut helper = Helper(
        std_process::Command::new(binary)
            .args([HELPER_TEST, "--exact", "--ignored", "--nocapture"])
            .args(["--test-threads=1"])
            .env(HELPER_ENV, "1")
            .stdin(std_process::Stdio::null())
            .stdout(std_process::Stdio::piped())
            .spawn()
            .expect("spawn helper process"),
    );
    let output = helper.0.stdout.take().expect("helper stdout");
    // Read on a thread so a helper that never reports cannot hang the test.
    let (report, reported) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let pids = BufReader::new(output)
            .lines()
            .map_while(Result::ok)
            .inspect(|line| eprintln!("parent_death helper stdout: {line}"))
            .find_map(|line| {
                let (_, pids) = line.split_once(PIDS_PREFIX)?;
                let (guarded, unguarded) = pids.trim().split_once(' ')?;
                Some((guarded.parse::<i32>().ok()?, unguarded.parse::<i32>().ok()?))
            });
        let _ = report.send(pids);
    });
    let (guarded, unguarded) = reported
        .recv_timeout(DEADLINE)
        .expect("helper did not report its children in time")
        .expect("helper exited before reporting its children");
    eprintln!("parent_death: helper reported guarded={guarded} unguarded={unguarded}");
    assert!(alive(guarded), "guarded child {guarded} not running");
    assert!(alive(unguarded), "unguarded child {unguarded} not running");

    let killed = Instant::now();
    helper.0.kill().expect("SIGKILL helper");
    helper.0.wait().expect("reap helper");
    eprintln!("parent_death: helper SIGKILLed and reaped");
    while alive(guarded) {
        assert!(
            killed.elapsed() < DEADLINE,
            "guarded child {guarded} outlived its SIGKILLed parent"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let guarded_died_ms = killed.elapsed().as_millis();
    // Give the control the same chance to be taken down by anything else.
    thread::sleep(Duration::from_millis(200));
    let control_alive = alive(unguarded);
    let _ = kill(Pid::from_raw(unguarded), Signal::SIGKILL);
    eprintln!(
        "{{\"test\":\"parent_death_signal\",\"guarded\":{guarded},\"unguarded\":{unguarded},\
         \"guarded_died_ms\":{guarded_died_ms},\"control_alive\":{control_alive}}}"
    );
    assert!(
        control_alive,
        "control child {unguarded} without the setting must outlive its parent"
    );
}

#[test]
fn non_positive_parent_death_signal_is_refused_before_spawning() {
    for signal in [0, -1] {
        let error = Command::new("true")
            .parent_death_signal(Some(signal))
            .spawn()
            .expect_err("a non-positive signal must be refused");
        assert!(
            matches!(error, ProcessError::InvalidConfiguration(_)),
            "signal {signal}: {error:?}"
        );
    }
}

#[test]
fn kernel_refusal_of_a_parent_death_signal_fails_spawn() {
    let error = Command::new("true")
        .parent_death_signal(Some(4096))
        .spawn()
        .expect_err("the kernel refuses an out-of-range signal");
    assert!(
        matches!(&error, ProcessError::Io(inner) if inner.raw_os_error() == Some(libc::EINVAL)),
        "{error:?}"
    );
}

#[test]
fn child_with_a_parent_death_signal_runs_normally() {
    let mut child = Command::new("true")
        .parent_death_signal(Some(libc::SIGTERM))
        .spawn()
        .expect("spawn with a parent-death signal");
    assert!(child.wait().expect("wait").success());
}
