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
    /// When peer bytes last reached the read buffer. A Pong is judged by this
    /// arrival time, not by when the application next calls recv to decode it.
    last_read: Option<Time>,
    /// The read buffer held no complete frame when last decoded.
    drained: bool,
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

    /// `buffered` is whether the connection's read buffer holds undecoded bytes.
    pub(super) fn update(
        &mut self,
        cx: &Cx,
        interval: Option<Duration>,
        open: bool,
        buffered: bool,
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
                // The Pong may have been read in time, behind a message the
                // application took first: decode what arrived before the
                // deadline before declaring the peer dead.
                if buffered && !self.drained && self.last_read.is_some_and(|at| at < *deadline) {
                    return Ok(None);
                }
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
        // The frame was read no later than the last read into the buffer.
        let arrived = self.last_read.unwrap_or_else(|| self.now());
        if self.pending_ping.is_none()
            && self
                .outstanding
                .as_ref()
                .is_some_and(|(expected, deadline)| {
                    expected.as_ref() == payload && arrived < *deadline
                })
        {
            self.outstanding = None;
            self.drained = false;
            self.next_ping = self.interval.map(|interval| self.now() + interval);
        }
    }

    /// Records that peer bytes reached the read buffer now.
    pub(super) fn note_read(&mut self) {
        if self.started {
            self.last_read = Some(self.now());
        }
        self.drained = false;
    }

    /// Records that the read buffer holds no complete frame: nothing read in
    /// time is left to decode.
    pub(super) fn note_drained(&mut self) {
        self.drained = true;
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
#[path = "heartbeat_inline_tests.rs"]
mod tests;
