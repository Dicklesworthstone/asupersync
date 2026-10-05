#![cfg(all(test, target_os = "linux"))]
//! Real Linux child-process regressions for br-asupersync-bi2462.114.
//!
//! A release-file handshake, not an assumed sleep duration, establishes that
//! the child is still alive when its handle is dropped. /proc disappearance
//! proves reaping: a merely exited zombie still has a /proc entry. Tests never
//! use waitpid(-1) or install a process-wide SIGCHLD handler.

use super::{Child, Command, Stdio};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::reactor::{Events, Interest, Reactor, Source, Token};
use crate::types::{Budget, RegionId, TaskId};
use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process as std_process;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(10);
const GATED_CHILD: &str = r#"
set -eu
: > "$1/ready"
n=0
while [ ! -f "$1/release" ]; do
    n=$((n + 1))
    [ "$n" -lt 2000 ] || exit 98
    sleep 0.01
done
: > "$1/finished"
exit 23
"#;

fn wait_for(description: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if predicate() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out: {description}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn exists(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("cannot inspect {}: {error}", path.display()),
    }
}

fn proc_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}"))
}

struct GatedChild {
    directory: tempfile::TempDir,
    child: Option<Child>,
    pid: u32,
}

impl GatedChild {
    fn spawn() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let child = Command::new("sh")
            .arg("-c")
            .arg(GATED_CHILD)
            .arg("asupersync-drop-reap-test")
            .arg(directory.path())
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .spawn()
            .unwrap();
        let pid = child.id().expect("fresh child must have a PID");
        let fixture = Self {
            directory,
            child: Some(child),
            pid,
        };
        wait_for("child reached the release gate", || {
            exists(&fixture.directory.path().join("ready"))
        });
        fixture.assert_running();
        fixture
    }

    fn abandon(&mut self) {
        drop(self.child.take().expect("child is dropped exactly once"));
    }

    fn assert_running(&self) {
        // While the gate is closed the script cannot have completed naturally.
        assert!(exists(&proc_path(self.pid)), "child exited before release");
        let stat = fs::read_to_string(proc_path(self.pid).join("stat")).unwrap();
        let (_, fields) = stat.rsplit_once(") ").expect("Linux proc stat format");
        assert_ne!(fields.as_bytes().first(), Some(&b'Z'), "child was killed");
        assert!(!exists(&self.directory.path().join("finished")));
    }

    fn release(&self) {
        fs::write(self.directory.path().join("release"), b"release\n").unwrap();
    }

    fn assert_finished_and_reaped(&self) {
        wait_for("child continued after its handle was dropped", || {
            exists(&self.directory.path().join("finished"))
        });
        wait_for("dropped child was reaped, not merely exited", || {
            !exists(&proc_path(self.pid))
        });
    }
}

impl Drop for GatedChild {
    fn drop(&mut self) {
        // Release the child even when an assertion failed. Keep its directory
        // alive through cleanup. The bounded script also has its own failsafe.
        let _ = fs::write(self.directory.path().join("release"), b"cleanup\n");
        let deadline = Instant::now() + DEADLINE;
        if let Some(child) = self.child.as_mut() {
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => return,
                    Ok(None) => {}
                }
                if Instant::now() >= deadline {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        // This is failure-path cleanup, AFTER the reaping assertion. It cannot
        // make a zombie-leaking implementation pass. It only waits for this
        // fixture's child, never an unrelated child's status.
        let Ok(raw_pid) = i32::try_from(self.pid) else {
            return;
        };
        loop {
            match waitpid(Pid::from_raw(raw_pid), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {}
                Ok(_) | Err(_) => return,
            }
            if Instant::now() >= deadline {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

struct OwnedStdChild(std_process::Child);

impl Drop for OwnedStdChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn dropped_live_child_continues_and_is_eventually_reaped() {
    let mut child = GatedChild::spawn();
    child.abandon();
    child.assert_running();
    child.release();
    child.assert_finished_and_reaped();
}

#[test]
fn long_running_child_does_not_delay_reaping_a_shorter_child() {
    let mut long = GatedChild::spawn();
    let mut short = GatedChild::spawn();
    long.abandon();
    short.abandon();
    short.release();
    short.assert_finished_and_reaped();
    long.assert_running();
    long.release();
    long.assert_finished_and_reaped();
}

#[test]
fn concurrent_drops_preserve_every_childs_reaping_owner() {
    thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| {
                // Each thread constructs and drops its own public handle;
                // the cleanup contract does not require Child to be Send.
                let mut child = GatedChild::spawn();
                child.abandon();
                child.assert_running();
                child.release();
                child.assert_finished_and_reaped();
            });
        }
    });
}

#[test]
fn reaper_does_not_consume_an_unrelated_std_childs_exit_status() {
    let mut independent = OwnedStdChild(
        std_process::Command::new("sh")
            .arg("-c")
            .arg("exit 37")
            .spawn()
            .unwrap(),
    );
    let pid = independent.0.id();
    wait_for("independently owned std child reached zombie state", || {
        let stat = fs::read_to_string(proc_path(pid).join("stat")).unwrap();
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    });

    let mut dropped = GatedChild::spawn();
    dropped.abandon();
    dropped.release();
    dropped.assert_finished_and_reaped();
    assert_eq!(independent.0.wait().unwrap().code(), Some(37));
}

#[test]
fn dropping_a_waited_child_preserves_other_child_statuses() {
    let mut independent = OwnedStdChild(
        std_process::Command::new("sh")
            .arg("-c")
            .arg("exit 37")
            .spawn()
            .unwrap(),
    );
    let mut child = Command::new("sh").arg("-c").arg("exit 7").spawn().unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(7));
    drop(child);
    assert_eq!(independent.0.wait().unwrap().code(), Some(37));
}

#[test]
fn dropping_a_child_after_try_wait_reuses_cached_status() {
    let mut child = Command::new("sh").arg("-c").arg("exit 11").spawn().unwrap();
    let pid = child.id().unwrap();
    wait_for("child returned a cached terminal status", || {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert_eq!(status.code(), Some(11));
                true
            }
            None => false,
        }
    });
    drop(child);
    assert!(!exists(&proc_path(pid)));
}

#[test]
fn kill_on_drop_still_terminates_and_reaps_the_child() {
    let child = Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    drop(child);
    wait_for("kill-on-drop child was reaped", || !exists(&proc_path(pid)));
}

/// Records, when a token is deregistered, whether the fd registered under it
/// is still the same open file (br-asupersync-reactor-audit-dofi11 LOW 2). The
/// /proc link target, not just the fd number, is compared, so an fd number
/// reused by a concurrent test cannot pass for the original pipe.
struct FdOpenAtDeregisterReactor {
    inner: crate::runtime::LabReactor,
    registered: Mutex<Vec<(Token, i32, Option<PathBuf>)>>,
    open_at_deregister: Mutex<Vec<(i32, bool)>>,
}

fn fd_target(fd: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

impl Reactor for FdOpenAtDeregisterReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        let fd = source.as_raw_fd();
        self.registered
            .lock()
            .unwrap()
            .push((token, fd, fd_target(fd)));
        self.inner.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        let entry = self
            .registered
            .lock()
            .unwrap()
            .iter()
            .find(|(registered, _, _)| *registered == token)
            .map(|(_, fd, target)| (*fd, target.clone()));
        if let Some((fd, target)) = entry {
            let open = target.is_some() && fd_target(fd) == target;
            self.open_at_deregister.lock().unwrap().push((fd, open));
        }
        self.inner.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        self.inner.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        self.inner.wake()
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

#[test]
fn child_pipes_leave_the_reactor_before_their_fd_closes() {
    let reactor = Arc::new(FdOpenAtDeregisterReactor {
        inner: crate::runtime::LabReactor::new(),
        registered: Mutex::new(Vec::new()),
        open_at_deregister: Mutex::new(Vec::new()),
    });
    let driver = crate::runtime::IoDriverHandle::new(reactor.clone());
    let cx = crate::cx::Cx::new_with_observability(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        Some(driver),
        None,
    );
    let _guard = crate::cx::Cx::set_current(Some(cx));

    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin().unwrap();
    let mut stdout = child.stdout().unwrap();
    let mut stderr = child.stderr().unwrap();
    let mut task_cx = Context::from_waker(Waker::noop());

    // Every pipe parks on the reactor: the child never writes, and it never
    // reads, so its stdin pipe fills.
    let mut byte = [0u8; 1];
    assert!(
        Pin::new(&mut stdout)
            .poll_read(&mut task_cx, &mut ReadBuf::new(&mut byte))
            .is_pending()
    );
    assert!(
        Pin::new(&mut stderr)
            .poll_read(&mut task_cx, &mut ReadBuf::new(&mut byte))
            .is_pending()
    );
    let chunk = [0u8; 4096];
    let mut parked = false;
    for _ in 0..1024 {
        match Pin::new(&mut stdin).poll_write(&mut task_cx, &chunk) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => panic!("write to the child's stdin: {err}"),
            Poll::Pending => {
                parked = true;
                break;
            }
        }
    }
    assert!(parked, "the child's stdin pipe never filled");
    assert_eq!(reactor.registered.lock().unwrap().len(), 3);

    drop(stdin);
    drop(stdout);
    drop(stderr);
    let seen = reactor.open_at_deregister.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        3,
        "every pipe leaves the reactor on drop: {seen:?}"
    );
    assert!(
        seen.iter().all(|&(_, open)| open),
        "a pipe closed its fd before leaving the reactor: {seen:?}"
    );

    child.kill().unwrap();
    child.wait().unwrap();
}
