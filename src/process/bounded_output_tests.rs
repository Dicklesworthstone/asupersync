//! Native subprocess coverage for bounded capture and cleanup ownership.

use super::{BoundedOutputError, CapturedOutputStream, OutputCaptureLimits};
use crate::cx::Cx;
use crate::process::{Child, Command, ProcessError, ProcessGroupMode, ProcessSignalTarget, Stdio};
use crate::runtime::RuntimeBuilder;
use std::future::{Future, poll_fn};
use std::path::Path;
use std::task::Poll;
use std::time::{Duration, Instant};

fn run_native(workers: usize, work: impl Future<Output = ()> + Send + 'static) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new()
            .worker_threads(workers)
            .build()
            .unwrap()
    };
    runtime.block_on(runtime.handle().spawn(async move {
        let mut work = std::pin::pin!(work);
        // Ordinary Sleep observes ambient cancellation. The watchdog must let
        // the operation finish its cancellation-resistant cleanup instead.
        let mut watchdog = std::pin::pin!(super::super::cancel_drain_delay(
            Duration::from_secs(15)
        ));
        poll_fn(|task| {
            if work.as_mut().poll(task).is_ready() {
                return Poll::Ready(());
            }
            assert!(
                watchdog.as_mut().poll(task).is_pending(),
                "bounded capture native watchdog expired"
            );
            Poll::Pending
        })
        .await;
    }));
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

fn piped_child(script: &str) -> Child {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::Null)
        .stdout(Stdio::Pipe)
        .stderr(Stdio::Pipe)
        .spawn()
        .unwrap()
}

fn assert_reaped(pid: u32) {
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "direct child {pid} must be reaped before capture returns"
    );
}

fn process_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(Instant::now() < deadline, "subprocess handshake timed out");
        crate::time::sleep(crate::time::wall_now(), Duration::from_millis(5)).await;
    }
}

#[test]
fn bounded_capture_accepts_zero_and_exact_limits() {
    for workers in [1, 2] {
        run_native(workers, async {
            let cx = Cx::current().expect("admitted native owner");
            let exact = Command::new("sh")
                .arg("-c")
                .arg("printf abcd; printf xyz >&2; exit 7")
                .output_bounded_async(&cx, OutputCaptureLimits::new(4, 3))
                .await
                .unwrap();
            assert_eq!(exact.stdout, b"abcd");
            assert_eq!(exact.stderr, b"xyz");
            assert_eq!(exact.status.code(), Some(7));

            let empty = Command::new("sh")
                .arg("-c")
                .arg("exit 0")
                .output_bounded_async(&cx, OutputCaptureLimits::new(0, 0))
                .await
                .unwrap();
            assert!(empty.status.success());
            assert!(empty.stdout.is_empty());
            assert!(empty.stderr.is_empty());
        });
    }
}

#[test]
fn bounded_capture_reports_each_overflow_and_reaps_before_return() {
    for workers in [1, 2] {
        run_native(workers, async {
            let cx = Cx::current().expect("admitted native owner");
            for (script, limits, stream, prefix) in [
                (
                    "printf abcde; exec sleep 30",
                    OutputCaptureLimits::new(4, 0),
                    CapturedOutputStream::Stdout,
                    b"abcd".as_slice(),
                ),
                (
                    "printf abcde >&2; exec sleep 30",
                    OutputCaptureLimits::new(0, 4),
                    CapturedOutputStream::Stderr,
                    b"abcd".as_slice(),
                ),
                (
                    "printf x; exec sleep 30",
                    OutputCaptureLimits::new(0, 0),
                    CapturedOutputStream::Stdout,
                    b"".as_slice(),
                ),
            ] {
                let child = piped_child(script);
                let pid = child.id().unwrap();
                let error = child
                    .wait_with_output_bounded_async(&cx, limits)
                    .await
                    .unwrap_err();
                let BoundedOutputError::LimitExceeded(error) = error else {
                    panic!("overflow must carry a completed limit receipt");
                };
                assert_eq!(error.stream, stream);
                assert_eq!(error.limits, limits);
                assert!(error.output.stdout.len() <= limits.stdout_bytes);
                assert!(error.output.stderr.len() <= limits.stderr_bytes);
                let retained = match stream {
                    CapturedOutputStream::Stdout => &error.output.stdout,
                    CapturedOutputStream::Stderr => &error.output.stderr,
                };
                assert_eq!(retained.as_slice(), prefix);
                assert_eq!(error.output.status.signal(), Some(libc::SIGKILL));
                assert_reaped(pid);
            }
        });
    }
}

#[test]
fn bounded_capture_drains_both_pipes_beyond_kernel_capacity() {
    for workers in [1, 2] {
        run_native(workers, async {
            let cx = Cx::current().expect("admitted native owner");
            let output = Command::new("sh")
                .arg("-c")
                .arg("head -c 131072 /dev/zero & head -c 131072 /dev/zero >&2 & wait")
                .process_group_mode(ProcessGroupMode::NewProcessGroup)
                .signal_target(ProcessSignalTarget::ProcessGroup)
                .output_bounded_async(&cx, OutputCaptureLimits::new(131_072, 131_072))
                .await
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout.len(), 131_072);
            assert_eq!(output.stderr.len(), 131_072);
            assert!(output.stdout.iter().all(|byte| *byte == 0));
            assert!(output.stderr.iter().all(|byte| *byte == 0));
        });
    }
}

fn assert_stdio_restored(command: &Command) {
    assert!(matches!(&command.stdin, Stdio::Pipe));
    assert!(matches!(&command.stdout, Stdio::Null));
    assert!(matches!(&command.stderr, Stdio::Inherit));
}

#[test]
fn bounded_command_refuses_precancelled_spawn_and_restores_stdio() {
    run_native(1, async {
        let directory = tempfile::tempdir().unwrap();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(": > \"$1/ran\"; printf ok")
            .arg("bounded-precancel")
            .arg(directory.path())
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Null)
            .stderr(Stdio::Inherit);
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        let result = command
            .output_bounded_async(&cancelled, OutputCaptureLimits::new(2, 0))
            .await;
        assert!(matches!(
            result,
            Err(BoundedOutputError::Process(ProcessError::Io(error)))
                if error.kind() == std::io::ErrorKind::Interrupted
        ));
        assert!(!directory.path().join("ran").exists());
        assert_stdio_restored(&command);

        let cx = Cx::current().expect("admitted native owner");
        let output = command
            .output_bounded_async(&cx, OutputCaptureLimits::new(2, 0))
            .await
            .unwrap();
        assert_eq!(output.stdout, b"ok");
        assert!(directory.path().join("ran").exists());
        assert_stdio_restored(&command);

        let mut missing = Command::new(directory.path().join("missing-executable"));
        missing
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Null)
            .stderr(Stdio::Inherit);
        assert!(matches!(
            missing
                .output_bounded_async(&cx, OutputCaptureLimits::new(2, 0))
                .await,
            Err(BoundedOutputError::Process(_))
        ));
        assert_stdio_restored(&missing);
    });
}

#[test]
fn bounded_capture_after_pipe_eof_has_no_cleanup_execution_timeout() {
    run_native(1, async {
        let cx = Cx::current().expect("admitted native owner");
        let output = Command::new("sh")
            .arg("-c")
            .arg("exec 1>&- 2>&-; sleep 0.6; exit 9")
            .process_group_mode(ProcessGroupMode::NewProcessGroup)
            .signal_target(ProcessSignalTarget::ProcessGroup)
            .output_bounded_async(&cx, OutputCaptureLimits::new(0, 0))
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(9));
    });
}

#[test]
fn bounded_capture_still_observes_cancellation_after_both_pipes_eof() {
    for workers in [1, 2] {
        run_native(workers, async {
            let directory = tempfile::tempdir().unwrap();
            let child = Command::new("sh")
                .arg("-c")
                .arg("exec 1>&- 2>&-; : > \"$1/ready\"; exec sleep 30")
                .arg("bounded-eof-cancel")
                .arg(directory.path())
                .stdin(Stdio::Null)
                .stdout(Stdio::Pipe)
                .stderr(Stdio::Pipe)
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let pid = child.id().unwrap();
            wait_until(|| directory.path().join("ready").exists()).await;
            let cx = Cx::current().expect("admitted native owner");
            let mut future =
                Box::pin(child.wait_with_output_bounded_async(&cx, OutputCaptureLimits::new(0, 0)));
            let mut pending_polls = 0;
            let result = poll_fn(|task| {
                let result = future.as_mut().poll(task);
                if result.is_pending() {
                    pending_polls += 1;
                    // The first poll consumes EOF and cooperatively yields.
                    // The second parks while waiting for the still-live child.
                    if pending_polls == 2 {
                        cx.set_cancel_requested(true);
                    }
                    if pending_polls <= 2 {
                        task.waker().wake_by_ref();
                    }
                }
                result
            })
            .await;
            assert!(pending_polls >= 2);
            assert!(matches!(
                result,
                Err(BoundedOutputError::Process(ProcessError::Io(error)))
                    if error.kind() == std::io::ErrorKind::Interrupted
            ));
            assert_reaped(pid);
        });
    }
}

#[test]
fn bounded_capture_drop_owns_cleanup_even_before_first_poll() {
    for workers in [1, 2] {
        run_native(workers, async {
            let cx = Cx::current().expect("admitted native owner");
            for poll_first in [false, true] {
                let child = piped_child("exec sleep 30");
                assert!(!child.kill_on_drop, "exercise the stronger capture ownership");
                let pid = child.id().unwrap();
                let mut future =
                    Box::pin(child.wait_with_output_bounded_async(&cx, OutputCaptureLimits::new(0, 0)));
                if poll_first {
                    poll_fn(|task| {
                        assert!(future.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                drop(future);
                wait_until(|| !Path::new(&format!("/proc/{pid}")).exists()).await;
            }
        });
    }
}

const GROUP_DESCENDANT: &str = r#"
sh -c '
    trap "" TERM
    printf "%s\n" "$$" > "$1/descendant"
    : > "$1/ready"
    while [ ! -f "$1/go" ]; do sleep 0.01; done
    printf XXXXX
    exec sleep 30
' bounded-descendant "$1" &
exit 0
"#;

#[test]
fn bounded_overflow_kills_descendant_before_reaping_exited_group_leader() {
    for workers in [1, 2] {
        run_native(workers, async {
            let directory = tempfile::tempdir().unwrap();
            let child = Command::new("sh")
                .arg("-c")
                .arg(GROUP_DESCENDANT)
                .arg("bounded-group-leader")
                .arg(directory.path())
                .stdin(Stdio::Null)
                .stdout(Stdio::Pipe)
                .stderr(Stdio::Pipe)
                .process_group_mode(ProcessGroupMode::NewProcessGroup)
                .signal_target(ProcessSignalTarget::ProcessGroup)
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let leader_pid = child.id().unwrap();
            wait_until(|| directory.path().join("ready").exists()).await;
            let descendant_pid: u32 =
                std::fs::read_to_string(directory.path().join("descendant"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
            // Reading procfs observes exit without releasing the leader's PID.
            // Calling try_wait here would destroy the identity being tested.
            wait_until(|| process_state(leader_pid) == Some('Z')).await;
            std::fs::write(directory.path().join("go"), b"go").unwrap();
            let cx = Cx::current().expect("admitted native owner");
            let error = child
                .wait_with_output_bounded_async(&cx, OutputCaptureLimits::new(1, 0))
                .await
                .unwrap_err();
            let BoundedOutputError::LimitExceeded(error) = error else {
                panic!("descendant overflow must produce a completed limit receipt");
            };
            assert_eq!(error.stream, CapturedOutputStream::Stdout);
            assert_eq!(error.output.stdout, b"X");
            assert!(error.output.stderr.is_empty());
            assert_eq!(error.output.status.code(), Some(0));
            assert_reaped(leader_pid);
            // An orphan may remain a zombie until the host's init reaps it.
            // The runtime owns and reaps the direct child, not arbitrary orphans.
            wait_until(|| matches!(process_state(descendant_pid), None | Some('Z'))).await;
        });
    }
}
