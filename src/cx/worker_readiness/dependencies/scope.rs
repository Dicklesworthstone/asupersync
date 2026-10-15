//! A dependent operation owns a subtree, not the prerequisite workers.

use super::{DependencyError, DependencyLoss, ReadyDependencies, WorkerDependencies};
use super::super::Cancellation;
use crate::cx::{ChildRegionError, ChildRegionSpec, Cx};
use crate::record::task::TaskOutcome;
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::{Budget, CancelReason, Outcome, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

/// Explicit dependent-subtree authority and cooperative shutdown budget.
#[derive(Debug, Clone)]
pub struct DependencyScopeConfig {
    /// Child-region envelope, met with the caller's existing capability/budget.
    pub region: ChildRegionSpec,
    /// Existing cancellation/drain budget; not an arbitrary-future time bound.
    pub shutdown_budget: Budget,
}

impl DependencyScopeConfig {
    /// Inherit the caller's region envelope and select the drain budget explicitly.
    #[must_use]
    pub const fn new(shutdown_budget: Budget) -> Self {
        Self { region: ChildRegionSpec::inherit(), shutdown_budget }
    }
}

/// Refusal before the dependent region exists. The work factory was not invoked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DependencyScopeError {
    /// All-ready observation failed, without stopping any prerequisite.
    #[error("dependent startup: {0}")]
    Readiness(#[from] DependencyError),
    /// Runtime region admission failed.
    #[error("dependent region admission: {0}")]
    Region(#[from] ChildRegionError),
}

/// First observed reason to stop this operation, not a global first-cause clock.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DependencyStop {
    /// One selected generation left Ready; its replacement cannot repair this run.
    Lost(DependencyLoss),
    /// The caller acknowledged its own cancellation request.
    Cancelled(CancelReason),
    /// The observation mechanism failed, so unmonitored execution was refused.
    Observation(DependencyError),
}

impl DependencyStop {
    fn reason(&self) -> CancelReason {
        match self {
            Self::Cancelled(reason) => reason.clone(),
            Self::Lost(_) => CancelReason::user("worker dependency changed"),
            Self::Observation(_) => CancelReason::user("worker dependency observation failed"),
        }
    }
}

/// Public projection of the actual region-close receipt.
#[derive(Debug, Clone)]
pub struct DependencyRegionOutcome {
    /// Aggregated dependent-task/descendant outcome.
    pub outcome: TaskOutcome,
    /// Registered finalizer outcome, separately retained.
    pub cleanup_outcome: Option<TaskOutcome>,
}

/// Work, invalidation, and quiescence are separate results.
#[derive(Debug)]
#[must_use = "inspect the work outcome, stop reason, and actual region closure"]
pub struct DependencyScopeReport<T, E> {
    /// The dependent region, not any prerequisite's region.
    pub region: RegionId,
    /// Exact prerequisite generation vector selected for this run.
    pub readiness: ReadyDependencies,
    /// Whether the actual admitted task invoked the caller's work factory.
    pub invoked: bool,
    /// Immediate task submission refusal, if no handle was produced.
    pub spawn_error: Option<SpawnError>,
    /// Exact task terminal, containing the application's four-valued result.
    /// None means no work task was submitted, not successful work.
    pub work: Option<Result<Outcome<T, E>, JoinError>>,
    /// First dependency/caller/observation stop reason detected before body join.
    /// Caller cancellation during region close is recorded here if none preceded it.
    pub stop: Option<DependencyStop>,
    /// Actual caller cancellation, even if dependency loss was observed first.
    pub cancellation: Option<CancelReason>,
    /// A failed subtree-cancel command. Task abort was still attempted.
    pub cancellation_error: Option<ChildRegionError>,
    /// Err does not establish quiescence. No restart should be inferred from it.
    pub close: Result<DependencyRegionOutcome, ChildRegionError>,
}

impl<T, E> DependencyScopeReport<T, E> {
    /// Conservative aggregate success, not merely a successful work-task join.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.invoked && self.spawn_error.is_none()
            && matches!(&self.work, Some(Ok(Outcome::Ok(_))))
            && self.stop.is_none() && self.cancellation.is_none()
            && self.cancellation_error.is_none()
            && matches!(&self.close, Ok(close)
                if matches!(&close.outcome, Outcome::Ok(()) | Outcome::Cancelled(_))
                    && close.cleanup_outcome.as_ref().is_none_or(|value| value.is_ok()))
    }
}

struct WorkOwner<T> {
    task: TaskHandle<T>,
    joined: bool,
}

impl<T> Drop for WorkOwner<T> {
    fn drop(&mut self) {
        if !self.joined { self.task.abort(); }
    }
}

fn observe_cancel(cx: &Cx, cancellation: &mut Option<CancelReason>) -> bool {
    if cancellation.is_none() && cx.checkpoint().is_err() {
        *cancellation = Some(cx.cancel_reason().unwrap_or_else(CancelReason::shutdown));
        true
    } else {
        false
    }
}

impl WorkerDependencies {
    /// Await all prerequisites, then run work in an independently cancellable region.
    ///
    /// Invalidation stops the DEPENDENT subtree only, joins its work task, and
    /// closes its region before returning. Prerequisites and unrelated siblings
    /// are never cancelled. A replacement generation cannot silently substitute
    /// for one selected by this run. Call run again explicitly to select a new
    /// vector, or map the report through an existing managed restart policy.
    ///
    /// Readiness is rechecked after region admission and inside the actual task
    /// before constructing user work. It is not an atomic effect lease: a loss
    /// can race the final check, in which case cancellation follows observation.
    /// Monitoring ends at work-task join; region close then drains descendants.
    ///
    /// The caller's runtime task drives this future; there is no detached driver.
    /// Dropping it requests work cancellation and region close through owned
    /// guards. Only the enclosing region barrier establishes later quiescence in
    /// that case. Dropping the operation does NOT synchronously finish cleanup.
    /// Work must cooperate, acknowledge cancellation and complete its own async
    /// cleanup. Hard runtime abort and blocking callbacks remain outside this API.
    ///
    /// All-ready/region failures return Err before work admission. Once a region
    /// exists, even submission refusals return a report after attempting its
    /// close. No cancellation-aware result send can erase the observed work result.
    pub async fn run<T, E, F, Fut>(
        &self,
        cx: &Cx,
        config: DependencyScopeConfig,
        work: F,
    ) -> Result<DependencyScopeReport<T, E>, DependencyScopeError>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(Cx, ReadyDependencies) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<T, E>> + Send + 'static,
    {
        let selected = self.wait_ready(cx).await?;
        let region = cx.open_child_region(config.region).await?;
        let region_id = region.region_id();
        let invoked = Arc::new(AtomicBool::new(false));
        let mut cancellation = None;
        let mut cancellation_error = None;
        let mut stop = None;
        let mut spawn_error = None;
        let mut result = None;
        let mut registration = Cancellation { cx, token: None };

        if observe_cancel(cx, &mut cancellation) {
            stop = cancellation.clone().map(DependencyStop::Cancelled);
        } else if let Some(loss) = selected.first_lost() {
            stop = Some(DependencyStop::Lost(loss));
        }
        if stop.is_none() {
            let snapshot = selected.clone();
            let marker = Arc::clone(&invoked);
            let task = region.cx().spawn(move |child_cx| async move {
                if child_cx.checkpoint().is_err() {
                    return Outcome::Cancelled(child_cx.cancel_reason().unwrap_or_else(CancelReason::shutdown));
                }
                if snapshot.first_lost().is_some() {
                    return Outcome::Cancelled(CancelReason::user("worker dependency changed"));
                }
                marker.store(true, Ordering::Release);
                work(child_cx, snapshot).await
            });
            match task {
                Err(error) => spawn_error = Some(error),
                Ok(task) => {
                    let mut owner = WorkOwner { task, joined: false };
                    let mut lost = Some(Box::pin(selected.wait_lost(cx)));
                    result = Some(poll_fn(|task_cx| {
                        registration.token = Some(cx.refresh_cancel_waker(registration.token, task_cx.waker()));
                        let new_cancel = observe_cancel(cx, &mut cancellation);
                        let mut request = new_cancel.then(|| cancellation.as_ref().expect("observed cancellation").clone());
                        if stop.is_none() {
                            if new_cancel {
                                stop = cancellation.clone().map(DependencyStop::Cancelled);
                            } else if let Some(wait) = lost.as_mut() {
                                if let Poll::Ready(observed) = wait.as_mut().poll(task_cx) {
                                    let cause = match observed {
                                        Ok(loss) => DependencyStop::Lost(loss),
                                        Err(DependencyError::Cancelled) => {
                                            let reason = cx.cancel_reason().unwrap_or_else(CancelReason::shutdown);
                                            cancellation = Some(reason.clone());
                                            DependencyStop::Cancelled(reason)
                                        }
                                        Err(error) => DependencyStop::Observation(error),
                                    };
                                    request = Some(cause.reason());
                                    stop = Some(cause);
                                }
                            }
                        }
                        if stop.is_some() { lost = None; }
                        if let Some(reason) = request {
                            if let Err(error) = region.cancel_with_budget(reason, config.shutdown_budget) {
                                if cancellation_error.is_none() { cancellation_error = Some(error); }
                                owner.task.abort();
                            }
                        }
                        owner.task.poll_join(task_cx)
                    }).await);
                    owner.joined = true;
                    drop(lost);
                }
            }
        }

        // Retain cancellation observation while finalizers/descendants are
        // pending, not just while the work task is running. A task-only abort
        // during this phase must still acknowledge and publish the real report.
        let mut closing = std::pin::pin!(region.close_with_outcome());
        let close = poll_fn(|task_cx| {
            registration.token = Some(cx.refresh_cancel_waker(registration.token, task_cx.waker()));
            if observe_cancel(cx, &mut cancellation) && stop.is_none() {
                stop = cancellation.clone().map(DependencyStop::Cancelled);
            }
            closing.as_mut().poll(task_cx)
        }).await.map(|close| DependencyRegionOutcome {
            outcome: close.outcome, cleanup_outcome: close.cleanup_outcome,
        });
        Ok(DependencyScopeReport {
            region: region_id, readiness: selected, invoked: invoked.load(Ordering::Acquire),
            spawn_error, work: result, stop, cancellation, cancellation_error, close,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery)]
    use super::*;
    use crate::channel::oneshot;
    use crate::lab::{LabConfig, LabRuntime};
    use std::cell::Cell;

    fn run_case<F, Fut>(factory: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut lab = LabRuntime::new(LabConfig::new(0xde_9001).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
            factory(Cx::current().expect("registered test owner")).await;
        }).unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        join.try_join().unwrap().expect("dependency scenario completed");
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        if lab.state.region(root).is_some() {
            let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::shutdown(), None).into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
        }
        assert!(lab.state.region(root).is_none());
    }

    async fn parked<F: Future>(future: F, signal: oneshot::Sender<()>) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut signal = Some(signal);
        poll_fn(|task| {
            let result = future.as_mut().poll(task);
            if result.is_pending() {
                if let Some(signal) = signal.take() { signal.send_blocking(()).unwrap(); }
            }
            result
        }).await
    }

    #[test]
    fn detached_context_refuses_before_work_factory_invocation() {
        let cx = Cx::for_testing();
        let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
        let result = futures_lite::future::block_on(dependencies.run(
            &cx, DependencyScopeConfig::new(Budget::INFINITE),
            |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("not admitted") },
        ));
        assert!(matches!(result, Err(DependencyScopeError::Region(ChildRegionError::NoRuntimeGateway))));
    }

    #[test]
    fn successful_send_only_value_survives_task_join_and_region_close() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |body, snapshot| async move {
                    assert!(snapshot.is_empty());
                    assert_eq!(body.task_id(), Cx::current().unwrap().task_id());
                    crate::runtime::yield_now().await;
                    Outcome::<_, Cell<String>>::Ok(Cell::new(41))
                },
            ).await.unwrap();
            assert!(report.is_success());
            assert!(matches!(report.work, Some(Ok(Outcome::Ok(value))) if value.get() == 41));
        });
    }

    #[test]
    fn typed_application_failure_is_not_replaced_by_control_metadata() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |_, _| async { Outcome::<(), _>::Err(Cell::new(73u32)) },
            ).await.unwrap();
            assert!(!report.is_success());
            assert!(report.stop.is_none());
            assert!(report.close.is_ok());
            assert!(matches!(report.work, Some(Ok(Outcome::Err(error))) if error.get() == 73));
        });
    }

    #[test]
    fn work_factory_panic_still_reaches_the_region_close_barrier() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let report = dependencies.run(&cx, DependencyScopeConfig::new(Budget::INFINITE),
                |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("dependent factory sentinel") },
            ).await.unwrap();
            assert!(report.invoked);
            assert!(report.close.is_ok());
            assert!(!report.is_success());
            assert!(matches!(report.work, Some(Err(JoinError::Panicked(ref payload)))
                if payload.message() == "dependent factory sentinel"));
        });
    }

    #[test]
    fn caller_abort_during_descendant_close_preserves_completed_work_result() {
        run_case(|cx| async move {
            let dependencies = WorkerDependencies::new(Vec::new(), 0).unwrap();
            let (release, mut gate) = oneshot::channel::<()>();
            let (cleanup_parked, mut witness) = oneshot::channel();
            let mut controller = cx.spawn(move |driver| async move {
                dependencies.run(&driver, DependencyScopeConfig::new(Budget::INFINITE),
                    move |body, _| async move {
                        let (started, mut started_rx) = oneshot::channel();
                        let descendant = body.spawn(move |child| async move {
                            parked(child.cancelled(), started).await;
                            assert!(child.checkpoint().is_err());
                            parked(poll_fn(|task| gate.poll_recv_uninterruptible(task)), cleanup_parked)
                                .await.unwrap();
                        }).unwrap();
                        started_rx.recv(&body).await.unwrap();
                        drop(descendant); // The region, not this handle, owns the child.
                        Outcome::<_, ()>::Ok(42)
                    },
                ).await.unwrap()
            }).unwrap();
            witness.recv(&cx).await.unwrap();
            controller.abort();
            release.send_blocking(()).unwrap();
            let report = controller.join(&cx).await.unwrap();
            assert!(report.cancellation.is_some());
            assert!(matches!(report.stop, Some(DependencyStop::Cancelled(_))));
            assert!(matches!(report.work, Some(Ok(Outcome::Ok(42)))));
            assert!(report.close.is_ok());
            assert!(!report.is_success());
        });
    }
}
