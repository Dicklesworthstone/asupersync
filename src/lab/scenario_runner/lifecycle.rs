//! Executable, opt-in host availability for supervised scenario workers.

use super::{FaultAction, FaultEvent, Participant, Scenario, Time, ValidationError};
use crate::cx::Cx;
use crate::time::{Sleep, sleep_until};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, Waker};

const MAX_WORK_MS: u64 = 60_000;
const MAX_STALL_MS: u64 = 60_000;

/// Explicit opt-in: legacy worker properties and fault behavior stay intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) host: String,
    pub(super) work_ms: u64,
    pub(super) crash_allowance: u64,
}

impl Plan {
    pub(super) fn parse(
        participant: &Participant,
        scenario: &Scenario,
    ) -> Result<Option<Self>, ValidationError> {
        let Some(value) = participant.properties.get("lifecycle") else {
            return Ok(None);
        };
        let error = |message: &str| ValidationError {
            field: format!("participants.{}.properties.lifecycle", participant.name),
            message: message.to_owned(),
        };
        let object = value
            .as_object()
            .ok_or_else(|| error("lifecycle must be an object with work_ms and optional host"))?;
        if object.keys().any(|key| key != "work_ms" && key != "host") {
            return Err(error("lifecycle accepts only work_ms and host"));
        }
        let work_ms = object
            .get("work_ms")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| (1..=MAX_WORK_MS).contains(value))
            .ok_or_else(|| error("lifecycle.work_ms must be an integer from 1 to 60000"))?;
        let host = match object.get("host") {
            None => participant.name.clone(),
            Some(value) => value
                .as_str()
                .filter(|host| scenario.participants.iter().any(|p| p.name == *host))
                .ok_or_else(|| error("lifecycle.host must name a declared participant"))?
                .to_owned(),
        };
        let mut crash_allowance = 0;
        for (index, fault) in scenario.faults.iter().enumerate() {
            if fault.args.get("host").and_then(serde_json::Value::as_str) != Some(host.as_str()) {
                continue;
            }
            if fault.action == FaultAction::HostCrash {
                crash_allowance += 1;
            }
            if fault.action == FaultAction::ProcessStall
                && fault
                    .args
                    .get("duration_ms")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|duration| duration > MAX_STALL_MS)
            {
                return Err(ValidationError {
                    field: format!("faults[{index}].args.duration_ms"),
                    message: "an executable worker stall must be at most 60000 milliseconds"
                        .to_owned(),
                });
            }
        }
        Ok(Some(Self {
            host,
            work_ms,
            crash_allowance,
        }))
    }
}

#[derive(Debug, Clone, Copy)]
struct Snapshot {
    online: bool,
    stalled_until: Option<Time>,
    crash_epoch: u64,
    active_nanos: u64,
}

#[derive(Debug)]
struct State {
    snapshot: Snapshot,
    last_time: Time,
    waiter: Option<(u64, Waker)>,
}

impl State {
    /// Account only time during which the host could do work. A bounded stall
    /// expires at its declared deadline even when no explicit resume is sent.
    fn advance(&mut self, now: Time) {
        if self.snapshot.online {
            let active_since = self
                .snapshot
                .stalled_until
                .map_or(self.last_time, |until| until.max(self.last_time));
            self.snapshot.active_nanos = self
                .snapshot
                .active_nanos
                .saturating_add(now.as_nanos().saturating_sub(active_since.as_nanos()));
            if self
                .snapshot
                .stalled_until
                .is_some_and(|until| until <= now)
            {
                self.snapshot.stalled_until = None;
            }
        }
        self.last_time = now.max(self.last_time);
    }
}

#[derive(Debug)]
pub(super) struct Control {
    pub(super) plan: Plan,
    state: Mutex<State>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkExit {
    Completed,
    Crashed,
    Cancelled,
    ClockExhausted,
}

impl Control {
    pub(super) fn new(plan: Plan, now: Time) -> Self {
        Self {
            plan,
            state: Mutex::new(State {
                snapshot: Snapshot {
                    online: true,
                    stalled_until: None,
                    crash_epoch: 0,
                    active_nanos: 0,
                },
                last_time: now,
                waiter: None,
            }),
        }
    }

    pub(super) fn apply(&self, fault: &FaultEvent, now: Time) {
        if fault.args.get("host").and_then(serde_json::Value::as_str)
            != Some(self.plan.host.as_str())
        {
            return;
        }
        let wake = {
            let mut state = self.state.lock();
            state.advance(now);
            match fault.action {
                FaultAction::HostCrash if state.snapshot.online => {
                    state.snapshot.online = false;
                    state.snapshot.stalled_until = None;
                    state.snapshot.crash_epoch += 1;
                }
                FaultAction::HostRestart if !state.snapshot.online => {
                    state.snapshot.online = true;
                }
                FaultAction::ProcessStall if state.snapshot.online => {
                    let duration = fault.args["duration_ms"].as_u64().unwrap_or(0);
                    state.snapshot.stalled_until = Some(Time::from_nanos(
                        now.as_nanos()
                            .saturating_add(duration.saturating_mul(1_000_000)),
                    ));
                }
                FaultAction::ProcessResume if state.snapshot.stalled_until.is_some() => {
                    state.snapshot.stalled_until = None;
                }
                _ => return,
            }
            state.waiter.take().map(|(_, waker)| waker)
        };
        // User-controlled wake callbacks never run while the control is locked.
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn observe(&self, now: Time, generation: u64, waker: &Waker) -> Snapshot {
        let new_waker = waker.clone();
        let (snapshot, retired) = {
            let mut state = self.state.lock();
            state.advance(now);
            let retired = state.waiter.replace((generation, new_waker));
            (state.snapshot, retired)
        };
        drop(retired);
        snapshot
    }

    /// Wait for a generation's active work. Crashes invalidate its progress;
    /// a replacement generation starts a new interval and can wait offline.
    pub(super) async fn work(self: &Arc<Self>, cx: &Cx, generation: u64) -> WorkExit {
        let started_at = cx.now();
        let initial = {
            let mut state = self.state.lock();
            state.advance(started_at);
            state.snapshot
        };
        let _registration = Registration {
            control: Arc::clone(self),
            generation,
        };
        let work_nanos = self.plan.work_ms * 1_000_000;
        let mut timer: Option<(Time, Pin<Box<Sleep>>)> = None;
        poll_fn(|task_cx| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(WorkExit::Cancelled);
            }
            let now = cx.now();
            let snapshot = self.observe(now, generation, task_cx.waker());
            if snapshot.crash_epoch != initial.crash_epoch {
                return Poll::Ready(WorkExit::Crashed);
            }
            if !snapshot.online {
                timer = None;
                return Poll::Pending;
            }
            let deadline = if let Some(until) = snapshot.stalled_until {
                until
            } else {
                let elapsed = snapshot.active_nanos.saturating_sub(initial.active_nanos);
                if elapsed >= work_nanos {
                    return Poll::Ready(WorkExit::Completed);
                }
                Time::from_nanos(now.as_nanos().saturating_add(work_nanos - elapsed))
            };
            if deadline <= now {
                return Poll::Ready(WorkExit::ClockExhausted);
            }
            if timer.as_ref().is_none_or(|(armed, _)| *armed != deadline) {
                timer = Some((deadline, Box::pin(sleep_until(deadline))));
            }
            if timer.as_mut().unwrap().1.as_mut().poll(task_cx).is_ready() {
                // A clock can advance during a timer poll. Reobserve on the
                // next scheduled poll instead of looping inside this one.
                task_cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
}

/// A cancelled or completed generation must not keep its scheduler waker.
struct Registration {
    control: Arc<Control>,
    generation: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let retired = {
            let mut state = self.control.state.lock();
            if state
                .waiter
                .as_ref()
                .is_some_and(|(generation, _)| *generation == self.generation)
            {
                state.waiter.take()
            } else {
                None
            }
        };
        drop(retired);
    }
}
