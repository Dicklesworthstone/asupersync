use asupersync_v044::Cx;
use asupersync_v044::channel::oneshot;
use asupersync_v044::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync_v044::sync::{LockError, Mutex, OwnedMutexGuard};
use std::future::Future;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

const EXPECT_OLD_POLICY_ENV: &str = "ASUPERSYNC_V044_EXPECT_OLD_CANCEL_JOIN";
const OLD_POLICY_SENTINEL: &str = "V044_CANCEL_COMPAT_OLD_POLICY_REJECTED";
const NEGATIVE_RED_SENTINEL: &str = "V044_CANCEL_COMPAT_NEGATIVE_RED";
const POSITIVE_GREEN_SENTINEL: &str = "V044_CANCEL_COMPAT_POSITIVE_GREEN";
const CASE_COUNT_SENTINEL: &str = "V044_CANCEL_COMPAT_CASES=3";

struct CancellationBlindLateValue {
    started: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}

impl Future for CancellationBlindLateValue {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.started.store(true, Ordering::Release);
        if self.released.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn exercise_published_v044_contract(expect_old_policy: bool) {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("published v0.4.4 must build its public native runtime");
    runtime.block_on(async {
        let root = Cx::current().expect("run_test must install a native runtime Cx");
        let mutex = Arc::new(Mutex::new(()));
        let holder_mutex = Arc::clone(&mutex);
        let (holder_started_tx, mut holder_started_rx) = oneshot::channel();
        let (release_holder_tx, mut release_holder_rx) = oneshot::channel();
        let mut holder = root
            .spawn(move |holder_cx| async move {
                let guard = OwnedMutexGuard::lock(holder_mutex, &holder_cx)
                    .await
                    .expect("holder must acquire the initially free mutex");
                holder_started_tx
                    .send_blocking(())
                    .expect("holder-start receiver must remain live");
                release_holder_rx
                    .recv(&holder_cx)
                    .await
                    .expect("holder release signal must remain live");
                drop(guard);
            })
            .expect("published v0.4.4 must admit the guard holder");

        holder_started_rx
            .recv(&root)
            .await
            .expect("holder must own the mutex before the cancelled child starts");

        let cancellation_acknowledged = Arc::new(AtomicBool::new(false));
        let cleanup_completed = Arc::new(AtomicBool::new(false));
        let child_mutex = Arc::clone(&mutex);
        let child_acknowledged = Arc::clone(&cancellation_acknowledged);
        let child_cleanup = Arc::clone(&cleanup_completed);
        let mut child = root
            .spawn(move |child_cx| async move {
                match OwnedMutexGuard::lock(child_mutex, &child_cx).await {
                    Err(LockError::Cancelled) => {
                        child_acknowledged.store(true, Ordering::Release);
                        // Cross an additional Pending after the public primitive
                        // reports cancellation. This is the cleanup phase whose
                        // returned value v0.4.3-compatible ordinary spawn must
                        // preserve.
                        yield_now().await;
                        child_cleanup.store(true, Ordering::Release);
                    }
                    Ok(guard) => {
                        drop(guard);
                        panic!("cancelled child unexpectedly acquired the held mutex");
                    }
                    Err(other) => panic!("unexpected mutex result: {other:?}"),
                }
            })
            .expect("published v0.4.4 must admit the downstream-shaped child");

        for _ in 0..512 {
            if mutex.waiters() == 1 {
                break;
            }
            yield_now().await;
        }
        assert_eq!(
            mutex.waiters(),
            1,
            "the downstream-shaped child must be genuinely parked before abort",
        );

        child.abort();
        let joined = child.join(&root).await;
        assert!(
            cancellation_acknowledged.load(Ordering::Acquire),
            "the child must observe and acknowledge cancellation before joining",
        );
        assert!(
            cleanup_completed.load(Ordering::Acquire),
            "the child must finish asynchronous cleanup before joining",
        );
        assert_eq!(
            mutex.waiters(),
            0,
            "terminal cleanup must unlink the parked waiter before holder release",
        );

        release_holder_tx
            .send_blocking(())
            .expect("holder must remain live until explicit release");
        assert_eq!(
            holder.join(&root).await,
            Ok(()),
            "holder must finish cleanly so the canary leaves no child task behind",
        );

        if expect_old_policy {
            assert!(
                matches!(joined, Err(JoinError::Cancelled(_))),
                "{OLD_POLICY_SENTINEL}: the stale downstream expectation must fail when an acknowledged child returns Ok(())",
            );
        } else {
            assert_eq!(
                joined,
                Ok(()),
                "ordinary Cx::spawn must preserve the value returned after cancellation acknowledgement and cleanup",
            );
        }

        let blind_started = Arc::new(AtomicBool::new(false));
        let blind_released = Arc::new(AtomicBool::new(false));
        let child_started = Arc::clone(&blind_started);
        let child_released = Arc::clone(&blind_released);
        let mut blind_child = root
            .spawn(move |_child_cx| CancellationBlindLateValue {
                started: child_started,
                released: child_released,
            })
            .expect("published v0.4.4 must admit the cancellation-blind control child");

        for _ in 0..512 {
            if blind_started.load(Ordering::Acquire) {
                break;
            }
            yield_now().await;
        }
        assert!(
            blind_started.load(Ordering::Acquire),
            "the cancellation-blind control must cross its first poll before abort",
        );
        blind_released.store(true, Ordering::Release);
        blind_child.abort();
        assert!(
            matches!(blind_child.join(&root).await, Err(JoinError::Cancelled(_))),
            "the cancellation-blind control must retain task-level JoinError::Cancelled attribution",
        );
    });
    assert!(
        runtime.is_quiescent(),
        "the published runtime must be quiescent after all child joins",
    );
}

fn main() {
    if std::env::var_os(EXPECT_OLD_POLICY_ENV).is_some() {
        exercise_published_v044_contract(true);
        return;
    }

    let planted_old_policy = Command::new(
        std::env::current_exe().expect("the canary executable path must remain available"),
    )
    .env(EXPECT_OLD_POLICY_ENV, "1")
    .output()
    .expect("the planted old-policy child process must start");
    let old_policy_stderr = String::from_utf8_lossy(&planted_old_policy.stderr);
    assert!(
        !planted_old_policy.status.success(),
        "the planted stale downstream expectation unexpectedly passed",
    );
    assert!(
        old_policy_stderr.contains(OLD_POLICY_SENTINEL),
        "the planted negative failed for the wrong reason: {old_policy_stderr}",
    );
    println!("{NEGATIVE_RED_SENTINEL}");

    exercise_published_v044_contract(false);
    println!(
        "{POSITIVE_GREEN_SENTINEL}: acknowledged=Ok(()) blind=Err(JoinError::Cancelled) waiters=0 cleanup=complete"
    );
    println!("{CASE_COUNT_SENTINEL}");
}
