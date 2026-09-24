#![forbid(unsafe_code)]
//! Process-wide ownership of Unix children abandoned without kill-on-drop.
//!
//! `Command::spawn` admits the reaper before creating an OS child. Dropping a
//! child only transfers its existing handle into the queue: it never starts a
//! thread, waits for process exit, or signals the process. The worker polls each
//! owned handle independently and sleeps when there is no useful work.

use parking_lot::{Condvar, Mutex};
use std::io;
use std::process::Child;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// A live abandoned child must not delay reaping any other child.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

static REAPER: LazyLock<Arc<Reaper>> = LazyLock::new(|| Arc::new(Reaper::default()));

#[derive(Default)]
struct Reaper {
    /// Serializes startup and leaves failed startup retryable. This lock is
    /// never taken by the worker or by a dropping child.
    started: Mutex<bool>,
    incoming: Mutex<Vec<Child>>,
    wake: Condvar,
}

/// Establish a reaping owner before any OS child is spawned.
///
/// A thread-creation failure is a spawn error, not a best-effort failure in
/// `Child::drop` after the process has already been created.
pub(super) fn ensure_started() -> io::Result<()> {
    REAPER.ensure_started_with(|reaper| {
        // One process-lifetime reaper; ownership outlives any runtime.
        std::thread::Builder::new()
            .name("asupersync-child-reaper".to_owned())
            .spawn(move || reaper.run())
            .map(drop)
    })
}

/// Reap an exited child now, or transfer ownership without waiting for its exit.
///
/// The public spawn path has already called `ensure_started`. The static queue
/// itself retains ownership even before the worker first observes this child.
pub(super) fn reap_or_enqueue(mut child: Child) {
    if !is_reaped(child.try_wait()) {
        REAPER.enqueue(child);
    }
}

impl Reaper {
    fn ensure_started_with(
        self: &Arc<Self>,
        launch: impl FnOnce(Arc<Self>) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut started = self.started.lock();
        if !*started {
            launch(Arc::clone(self))?;
            *started = true;
        }
        Ok(())
    }

    fn enqueue(&self, child: Child) {
        self.incoming.lock().push(child);
        self.wake.notify_one();
    }

    fn run(&self) {
        let mut pending = Vec::new();
        loop {
            {
                let mut incoming = self.incoming.lock();
                while pending.is_empty() && incoming.is_empty() {
                    self.wake.wait(&mut incoming);
                }
                pending.append(&mut incoming);
            }

            // Do not hold the queue lock during OS calls. `try_wait` consults
            // the owned child's cached status and never waits for another PID.
            // A live child or a transient error retains ownership for retry.
            pending.retain_mut(|child| !is_reaped(child.try_wait()));

            let mut incoming = self.incoming.lock();
            if !pending.is_empty() && incoming.is_empty() {
                // Atomic unlock-and-wait with the same mutex used by enqueue
                // prevents a missed notification between checking and sleeping.
                let _ = self.wake.wait_for(&mut incoming, POLL_INTERVAL);
            }
        }
    }
}

fn is_reaped(result: io::Result<Option<std::process::ExitStatus>>) -> bool {
    match result {
        Ok(Some(_)) => true,
        // An external explicit waiter or SIGCHLD policy may have consumed the
        // status. There is no remaining waitable child for this handle. Never
        // signal the PID, which could already have been reused.
        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => true,
        // In particular, EINTR is not permission to discard the child.
        Ok(None) | Err(_) => false,
    }
}

#[cfg(test)]
mod tests;
