//! Real subprocess cancellation under an ambient native task context.
//!
//! The ready file proves the TERM handler is installed. Its delayed completion
//! distinguishes a real grace window from cancellation-shortened timer polls.

use super::{Command, ProcessError, Stdio};
use crate::cx::Cx;
use crate::runtime::RuntimeBuilder;
use std::future::{Future, poll_fn};
use std::time::{Duration, Instant};

const GRACEFUL_CHILD: &str = r#"
set -eu
trap 'sleep 0.08; : > "$1/finished"; exit 23' TERM
: > "$1/ready"
n=0
while [ "$n" -lt 1000 ]; do
    n=$((n + 1))
    sleep 0.01
done
exit 98
"#;

async fn cancel_after_pending<T>(
    cx: &Cx,
    future: impl Future<Output = Result<T, ProcessError>>,
) -> Result<T, ProcessError> {
    let mut future = std::pin::pin!(future);
    let mut parked = false;
    let result = poll_fn(|task| {
        let result = future.as_mut().poll(task);
        if result.is_pending() && !parked {
            parked = true;
            // Cancel the exact ambient owner only after the operation really
            // parked. Sleep's ordinary Future poll would now return immediately.
            cx.set_cancel_requested(true);
            task.waker().wake_by_ref();
        }
        result
    })
    .await;
    assert!(parked, "the live subprocess wait must first return Pending");
    assert!(cx.is_cancel_requested(), "cleanup must retain cancellation");
    result
}

fn cancellation_preserves_grace(workers: usize, collect_output: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(GRACEFUL_CHILD)
        .arg("asupersync-cancel-grace-test")
        .arg(directory.path())
        .stdin(Stdio::Null)
        .stdout(Stdio::Pipe)
        .stderr(Stdio::Pipe)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().expect("live child PID");
    let ready = directory.path().join("ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child failed before TERM setup"
        );
        assert!(
            Instant::now() < deadline,
            "child did not publish TERM readiness"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new()
            .worker_threads(workers)
            .build()
            .unwrap()
    };
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("admitted native owner");
        let work = async {
            let result = if collect_output {
                cancel_after_pending(&cx, child.wait_with_output_async(&cx))
                    .await
                    .map(|_| ())
            } else {
                let result = cancel_after_pending(&cx, child.wait_async(&cx)).await;
                assert!(
                    child.id().is_none(),
                    "cancel drain must consume the reaped child"
                );
                result.map(|_| ())
            };
            assert!(matches!(
                result,
                Err(ProcessError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted
            ));
            assert!(
                directory.path().join("finished").exists(),
                "cancelled timers must not skip the child's delayed TERM cleanup"
            );
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "wait must reap the exact child before returning cancellation"
            );
        };
        crate::time::timeout(cx.now(), Duration::from_secs(5), work)
            .await
            .expect("cancel/drain watchdog");
    }));
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn cancelled_native_wait_preserves_sigterm_grace_and_reaps() {
    for workers in [1, 2] {
        cancellation_preserves_grace(workers, false);
    }
}

#[test]
fn cancelled_native_output_wait_preserves_sigterm_grace_and_reaps() {
    for workers in [1, 2] {
        cancellation_preserves_grace(workers, true);
    }
}
