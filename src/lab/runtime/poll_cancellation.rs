//! One cooperative cancellation request at a validated scheduler boundary.
//!
//! The scenario campaign owns admission and bounded source capture. This
//! controller observes normal scheduling, checks the entire source prefix and
//! never substitutes a task choice. Divergence disables injection; it does not
//! prevent the fresh runtime from draining its actual workload.

use super::{ForcedDispatch, LabRuntime, compact_task_id};
use crate::trace::{TraceData, TraceEvent, TraceEventKind};
use crate::types::{CancelReason, TaskId};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::lab) enum PollCancellationResult {
    Requested,
    PrefixDiverged {
        poll_index: u64,
        expected: ForcedDispatch,
        actual: ForcedDispatch,
    },
    TargetNotReached {
        observed_polls: u64,
    },
    NotApplied,
}

#[derive(Debug)]
pub(in crate::lab) struct PollCancellationControl {
    source: Arc<[ForcedDispatch]>,
    target: usize,
    observed: usize,
    result: Option<PollCancellationResult>,
    target_terminal: bool,
}

impl PollCancellationControl {
    pub(in crate::lab) fn new(source: Arc<[ForcedDispatch]>, target: usize) -> Option<Self> {
        source.get(target)?;
        Some(Self {
            source,
            target,
            observed: 0,
            result: None,
            target_terminal: false,
        })
    }

    fn observe(&mut self, actual: ForcedDispatch) -> bool {
        if self.result.is_some() {
            return false;
        }
        let Some(&expected) = self.source.get(self.observed) else {
            self.result = Some(PollCancellationResult::NotApplied);
            return false;
        };
        if expected != actual {
            self.result = Some(PollCancellationResult::PrefixDiverged {
                poll_index: u64::try_from(self.observed)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
                expected,
                actual,
            });
            return false;
        }
        let inject = self.observed == self.target;
        self.observed += 1;
        inject
    }

    fn finish(self) -> PollCancellationResult {
        self.result
            .unwrap_or(PollCancellationResult::TargetNotReached {
                observed_polls: u64::try_from(self.observed).unwrap_or(u64::MAX),
            })
    }
}

impl LabRuntime {
    pub(in crate::lab) fn set_poll_cancellation(&mut self, control: PollCancellationControl) {
        debug_assert_eq!(self.steps, 0, "campaigns install before execution");
        self.poll_cancellation = Some(control);
    }

    pub(in crate::lab) fn finish_poll_cancellation(
        &mut self,
    ) -> Option<(PollCancellationResult, bool)> {
        self.poll_cancellation.take().map(|control| {
            let terminal = control.target_terminal;
            (control.finish(), terminal)
        })
    }

    pub(super) fn observe_poll_cancellation_completion(&mut self, task_id: TaskId) {
        let Some(control) = &mut self.poll_cancellation else {
            return;
        };
        if control.result == Some(PollCancellationResult::Requested)
            && control.source[control.target].task() == task_id.into()
            && self
                .state
                .task(task_id)
                .is_some_and(|task| task.state.is_terminal())
        {
            // Capture the full generation's terminal state before task_completed
            // recycles its record; absence afterward is not terminal evidence.
            control.target_terminal = true;
        }
    }

    pub(super) fn inject_poll_cancellation(&mut self, dispatch: ForcedDispatch) -> bool {
        let inject = self
            .poll_cancellation
            .as_mut()
            .is_some_and(|control| control.observe(dispatch));
        if !inject {
            return false;
        }
        let task_id = compact_task_id(dispatch.task());
        let old_state = self.state.task(task_id).and_then(|task| {
            // A pre-existing request does not exercise a new cancellation.
            (!task.state.is_terminal()
                && task.cancel_reason().is_none()
                && task.context_cancel_requested() != Some(true))
            .then(|| task.state.clone())
        });
        let Some(old_state) = old_state else {
            if let Some(control) = &mut self.poll_cancellation {
                control.result = Some(PollCancellationResult::NotApplied);
            }
            return false;
        };

        let reason = CancelReason::user("scenario poll-boundary cancellation");
        // Use the normal reason's cleanup budget, not chaos's zero budget.
        let (published, wakes) = self.state.cancel_task(task_id, &reason).into_parts();
        if let Some(control) = &mut self.poll_cancellation {
            control.result = Some(if published {
                PollCancellationResult::Requested
            } else {
                PollCancellationResult::NotApplied
            });
        }
        if published {
            if self.config.has_cancellation_oracle()
                && let Some(task) = self.state.task(task_id)
            {
                let effective = task.cancel_reason().cloned().unwrap_or(reason);
                let new_state = task.state.clone();
                self.oracles.cancellation_protocol.on_cancel_request(
                    task_id,
                    effective,
                    self.virtual_time,
                );
                self.oracles.cancellation_protocol.on_transition(
                    task_id,
                    &old_state,
                    &new_state,
                    self.virtual_time,
                );
            }
            self.replay_recorder.record_cancel_injection(task_id);
            self.state.record_trace_event(|seq| {
                TraceEvent::new(
                    seq,
                    self.virtual_time,
                    TraceEventKind::ChaosInjection,
                    TraceData::Chaos {
                        kind: "cancel".to_owned(),
                        task: Some(task_id),
                        detail: "scenario poll-boundary cancellation".to_owned(),
                    },
                )
            });
            // The selected task has already left its old queue. The existing
            // scheduler deduplicates the publication and subsequent wake effects.
            self.reschedule_after_chaos_skip(task_id);
        }
        wakes.dispatch();
        published
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::config::LabConfig;
    use crate::runtime::scheduler::DispatchLane;
    use crate::types::Budget;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn context_only_request_is_not_attributed_to_the_campaign() {
        let mut runtime = LabRuntime::new(LabConfig::new(7).max_steps(100));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let observed = Arc::new(AtomicBool::new(false));
        let witness = Arc::clone(&observed);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = crate::cx::Cx::current().expect("task context");
                witness.store(cx.checkpoint().is_err(), Ordering::Relaxed);
            })
            .unwrap();
        let cx = runtime
            .state
            .task(task)
            .unwrap()
            .cx
            .clone()
            .expect("linked context");
        cx.cancel_with_reason(CancelReason::user("pre-existing context request"));
        let record = runtime.state.task(task).unwrap();
        assert!(record.cancel_reason().is_none());
        assert_eq!(record.context_cancel_requested(), Some(true));

        runtime.scheduler.lock().schedule(task, 0);
        let dispatch = ForcedDispatch::from_checkpoint_parts(
            task.into(),
            0,
            DispatchLane::Ready,
            1,
            runtime.now().as_nanos(),
        );
        runtime
            .set_poll_cancellation(PollCancellationControl::new(Arc::from([dispatch]), 0).unwrap());
        runtime.run_until_quiescent();
        assert!(observed.load(Ordering::Relaxed));
        assert_eq!(
            runtime.finish_poll_cancellation(),
            Some((PollCancellationResult::NotApplied, false))
        );
    }
}
