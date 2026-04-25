//! Reproduction test for scheduling bugs in `spawn_registered`.

#![cfg(feature = "test-internals")]

#[cfg(test)]
mod tests {
    use asupersync::cx::Cx;
    use asupersync::runtime::RuntimeState;
    use asupersync::runtime::scheduler::ThreeLaneScheduler;
    use asupersync::sync::ContendedMutex;
    use asupersync::types::{Budget, TaskId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn spawn_registered_task_runs_after_explicit_scheduler_injection() {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        let root_region = state.lock().unwrap().create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::new_with_observability(
            root_region,
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
        );
        let scope = cx.scope();

        let inner_ran = Arc::new(AtomicBool::new(false));
        let inner_ran_clone = Arc::clone(&inner_ran);

        let handle = {
            let mut guard = state.lock().unwrap();
            scope.spawn_registered(&mut guard, &cx, |_| async move {
                inner_ran_clone.store(true, Ordering::SeqCst);
                42
            })
        }
        .expect("spawn_registered should store the task future");

        // `spawn_registered` stores the future in `RuntimeState`, but scheduling is explicit.
        // Inject the task into the scheduler so the worker can poll it.
        scheduler.spawn(handle.task_id(), 0);

        let mut worker = scheduler.take_workers().pop().unwrap();

        assert!(
            worker.run_once(),
            "explicitly injected spawn_registered task should be schedulable"
        );
        assert!(
            inner_ran.load(Ordering::SeqCst),
            "spawn_registered task should run when its stored future is scheduled"
        );
    }
}
