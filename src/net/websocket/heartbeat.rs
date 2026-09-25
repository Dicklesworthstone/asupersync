//! Connection-owned heartbeat state. Polling recv drives it; no detached task.

use super::WsError;
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::future::{Future, poll_fn};
use std::io;
use std::task::Poll;
use std::time::Duration;

#[derive(Default)]
pub(super) struct Heartbeat {
    clock: Option<TimerDriverHandle>,
    started: bool,
    interval: Option<Duration>,
    next_ping: Option<Time>,
    outstanding: Option<(Bytes, Time)>,
    pending_ping: Option<Bytes>,
    sequence: u64,
    failed: bool,
}

#[derive(Clone)]
pub(super) struct HeartbeatDeadline {
    at: Time,
    clock: Option<TimerDriverHandle>,
}

impl Heartbeat {
    fn now(&self) -> Time {
        self.clock.as_ref().map_or_else(
            || {
                let _ambient = Cx::set_current(None);
                crate::time::wall_now()
            },
            TimerDriverHandle::now,
        )
    }

    pub(super) fn failed(&self) -> bool {
        self.failed
    }

    pub(super) fn fail(&mut self) {
        self.failed = true;
    }

    pub(super) fn update(
        &mut self,
        cx: &Cx,
        interval: Option<Duration>,
        open: bool,
    ) -> Result<Option<Bytes>, WsError> {
        if self.failed {
            return Err(timeout_error());
        }
        if !open || interval.is_none() {
            self.interval = None;
            self.next_ping = None;
            self.outstanding = None;
            self.pending_ping = None;
            return Ok(None);
        }
        if !self.started {
            self.clock = cx.timer_driver();
            self.started = true;
        }
        let interval = interval
            .expect("enabled heartbeat")
            .max(Duration::from_millis(1));
        self.interval = Some(interval);
        let now = self.now();
        if let Some((_, deadline)) = &self.outstanding {
            if now >= *deadline {
                self.fail();
                return Err(timeout_error());
            }
            return Ok(self.pending_ping.clone());
        }
        let next = *self.next_ping.get_or_insert(now + interval);
        if now < next {
            return Ok(None);
        }
        self.sequence = self.sequence.wrapping_add(1);
        let mut payload = [0_u8; 16];
        payload[..8].copy_from_slice(b"asup-hb:");
        payload[8..].copy_from_slice(&self.sequence.to_be_bytes());
        let payload = Bytes::copy_from_slice(&payload);
        // Start the response allowance before writing. Backpressure must not
        // postpone the heartbeat deadline forever. The payload and deadline
        // survive cancellation of a borrowing recv future.
        self.outstanding = Some((payload.clone(), now + interval));
        self.pending_ping = Some(payload.clone());
        self.next_ping = None;
        Ok(Some(payload))
    }

    pub(super) fn received_pong(&mut self, payload: &[u8]) {
        if self.pending_ping.is_none()
            && self
                .outstanding
                .as_ref()
                .is_some_and(|(expected, deadline)| {
                    expected.as_ref() == payload && self.now() < *deadline
                })
        {
            self.outstanding = None;
            self.next_ping = self.interval.map(|interval| self.now() + interval);
        }
    }

    pub(super) fn ping_queued(&mut self) {
        self.pending_ping = None;
    }

    pub(super) fn deadline(&self) -> Option<HeartbeatDeadline> {
        let at = self
            .outstanding
            .as_ref()
            .map(|(_, deadline)| *deadline)
            .or(self.next_ping)?;
        Some(HeartbeatDeadline {
            at,
            clock: self.clock.clone(),
        })
    }

    pub(super) fn write_deadline(&self) -> Option<HeartbeatDeadline> {
        let at = if let Some((_, deadline)) = &self.outstanding {
            *deadline
        } else {
            // A pending automatic Pong can precede our first Ping. Its write
            // must still finish within the same interval + response allowance.
            self.next_ping? + self.interval?
        };
        Some(HeartbeatDeadline {
            at,
            clock: self.clock.clone(),
        })
    }
}

pub(super) fn timeout_error() -> WsError {
    WsError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "WebSocket heartbeat timed out",
    ))
}

/// Timer completion is distinct from I/O completion so an idle read can wake
/// to send its scheduled Ping. A dropped wait retains no timer registration;
/// its absolute deadline remains in the connection's Heartbeat.
pub(super) async fn wait_until<T, F>(
    cx: &Cx,
    deadline: Option<HeartbeatDeadline>,
    future: F,
) -> Result<Option<T>, WsError>
where
    F: Future<Output = Result<T, WsError>>,
{
    let mut future = std::pin::pin!(future);
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let wall_clock = deadline
        .as_ref()
        .is_some_and(|deadline| deadline.clock.is_none());
    let timer = deadline.map(|deadline| match deadline.clock {
        Some(clock) => Sleep::with_timer_driver(deadline.at, clock),
        None => Sleep::new(deadline.at),
    });
    let mut timer = std::pin::pin!(timer);
    poll_fn(|task| {
        // Timer cancellation checks and transport effects belong to the
        // explicit receiver context, never a different ambient caller.
        let _ambient = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
            return Poll::Ready(Err(WsError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled",
            ))));
        }
        if let Some(timer) = timer.as_mut().as_pin_mut() {
            // A capability-free first receive chose the process wall clock.
            // Keep that domain even if a later wait runs under another Cx.
            // Sleep then reuses the existing shared fallback timer; no
            // per-connection timer task or custom-clock polling thread exists.
            let _ambient = wall_clock.then(|| Cx::set_current(None));
            if timer.poll(task).is_ready() {
                return Poll::Ready(Ok(None));
            }
        }
        future.as_mut().poll(task).map(|result| result.map(Some))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::VirtualClock;
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::task::{Context, Waker};

    fn timed_cx(clock: &Arc<VirtualClock>) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(TimerDriverHandle::with_virtual_clock(Arc::clone(clock))),
            None,
        )
    }

    #[test]
    fn heartbeat_retains_wall_clock_under_foreign_ambient_and_resumed_context() {
        let explicit = Cx::for_testing();
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let interval = Duration::from_secs(60);
        let mut heartbeat = Heartbeat::default();
        let before = heartbeat.now();
        let _ambient = Cx::set_current(Some(foreign.clone()));
        assert!(
            heartbeat
                .update(&explicit, Some(interval), true)
                .unwrap()
                .is_none()
        );
        let after = heartbeat.now();
        let deadline = heartbeat.deadline().unwrap();
        assert!(deadline.at >= before + interval && deadline.at <= after + interval);
        assert!(
            heartbeat
                .update(&foreign, Some(interval), true)
                .unwrap()
                .is_none()
        );
        assert!(heartbeat.clock.is_none(), "first receive chose wall clock");
        let mut wait = std::pin::pin!(wait_until(
            &foreign,
            Some(deadline),
            std::future::pending::<Result<(), WsError>>()
        ));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "a foreign virtual clock cannot expire the retained wall deadline"
        );
    }

    #[test]
    fn zero_interval_uses_a_real_deadline_and_late_pong_cannot_rearm() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let _ambient = Cx::set_current(Some(foreign.clone()));
        let mut heartbeat = Heartbeat::default();
        assert!(
            heartbeat
                .update(&cx, Some(Duration::ZERO), true)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            heartbeat.deadline().unwrap().at,
            Time::from_nanos(1_000_000)
        );
        {
            let mut wait = std::pin::pin!(wait_until(
                &foreign,
                heartbeat.deadline(),
                std::future::pending::<Result<(), WsError>>()
            ));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            clock.advance(1_000_000);
            assert!(matches!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(None))
            ));
        }
        let payload = heartbeat
            .update(&foreign, Some(Duration::ZERO), true)
            .unwrap()
            .unwrap();
        heartbeat.ping_queued();
        heartbeat.received_pong(b"unrelated");
        clock.advance(1_000_000);
        heartbeat.received_pong(&payload);
        assert!(
            matches!(heartbeat.update(&cx, Some(Duration::ZERO), true), Err(WsError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "a matching Pong at the deadline is late, even after thread preemption"
        );
    }
}
