//! Optional native readiness pump for runtimes whose task polls can occupy
//! every scheduler worker (asupersync-olysw5). No task execution or runtime
//! state lock belongs to this thread.

use crate::runtime::io_driver::IoDriverHandle;
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::time::TimerDriverHandle;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_POLL_WAIT: Duration = Duration::from_millis(250);
const MIN_RETRY_WAIT: Duration = Duration::from_millis(1);
const MAX_RETRY_WAIT: Duration = Duration::from_millis(10);

pub(super) fn run(
    io: IoDriverHandle,
    timers: Option<TimerDriverHandle>,
    shutdown: Arc<AtomicBool>,
) {
    let mut retry_wait = MIN_RETRY_WAIT;
    while !shutdown.load(Ordering::Acquire) {
        // Native host-infrastructure elapsed time only: this bounds retries
        // for an empty nonblocking backend. Task deadlines still come from
        // the injected TimerDriver; lab/browser runtimes never run this pump.
        let started = Instant::now();
        let turn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(timer) = &timers {
                // TimerDriver retires its timer entries before waking outside
                // the wheel lock. One hostile Waker cannot strand this pump.
                let _ = timer.process_timers();
            }
            if shutdown.load(Ordering::Acquire) {
                return (Ok(None), Duration::ZERO);
            }
            let timeout = timers
                .as_ref()
                .and_then(|timer| {
                    timer.next_deadline().map(|deadline| {
                        Duration::from_nanos(deadline.duration_since(timer.now()))
                    })
                })
                .map_or(MAX_POLL_WAIT, |wait| wait.min(MAX_POLL_WAIT));
            // Cloning the runtime's handle preserves its poll election. A
            // scheduler worker already driving I/O remains the sole poller.
            (io.try_turn_with(Some(timeout), |_, _| {}), timeout)
        }));

        let pause = match turn {
            Ok((Ok(Some(events)), timeout)) => {
                // A normal idle turn sleeps in the reactor and needs no extra
                // park. Also bound custom backends that return an empty batch
                // immediately without honoring their requested wait.
                let pause = if events == 0 {
                    retry_wait.min(timeout).saturating_sub(started.elapsed())
                } else {
                    Duration::ZERO
                };
                if pause.is_zero() {
                    retry_wait = MIN_RETRY_WAIT;
                } else {
                    retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT);
                }
                pause
            }
            Ok((Ok(None) | Err(_), _)) => {
                let pause = retry_wait;
                retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT);
                pause
            }
            Err(payload) => {
                // Panic payloads are user data too. Retire the ordinary case,
                // containing a destructor panic before the next bounded retry.
                if let Err(secondary) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
                {
                    std::mem::forget(secondary);
                }
                let pause = retry_wait;
                retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT);
                pause
            }
        };
        // Retire a caught payload before observing shutdown: a Waker can
        // request shutdown and panic in the same callback.
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if !pause.is_zero() {
            std::thread::park_timeout(pause);
        }
    }
}
