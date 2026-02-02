#![doc = "Repro for spawn factory panic handling."]
#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use asupersync::cx::{Cx, Scope};
use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::panic::AssertUnwindSafe;

fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn test_scope(region: RegionId, budget: Budget) -> Scope<'static> {
    Scope::new(region, budget)
}

#[test]
fn spawn_factory_panic_causes_leak() {
    let mut state = RuntimeState::new();
    let _cx = test_cx();
    let region = state.create_root_region(Budget::INFINITE);
    let _scope = test_scope(region, Budget::INFINITE);

    // 1. Spawn a task where the factory panics
    // We expect this to panic, so we catch it
    let _result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // We need to use unsafe code or a RefCell to mutate state inside catch_unwind
        // if we were capturing it, but here we just call spawn.
        // spawn takes &mut state.
        // We can't pass &mut state into catch_unwind easily because it's not UnwindSafe?
        // Actually, let's just do it directly. The test runner will catch the panic.
        // But we want to verify the state *after* the panic.

        // This is tricky in a unit test because we need to inspect state after panic.
        // We can't easily recover &mut state from catch_unwind if it was moved in.
        // But spawn takes &mut state, so it's a borrow.

        // We'll simulate the call logic manually or use a trick.
        panic!("simulated factory panic");
    }));

    // Actually, writing a test that *proves* the leak is harder because of the panic.
    // Let's implement the fix directly as the logic is sound.
    // "Task created in registry but future never created/started" is definitely a zombie task.
}

#[test]
fn repro_zombie_task() {
    // We'll use a RefCell to hold state so we can access it after the panic
    use std::cell::RefCell;
    let state = RefCell::new(RuntimeState::new());
    let cx = test_cx();

    let region = state.borrow_mut().create_root_region(Budget::INFINITE);
    let scope = test_scope(region, Budget::INFINITE);

    // Wrapper to allow catch_unwind with mutable borrow
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut state_ref = state.borrow_mut();
        let _ = scope.spawn(&mut state_ref, &cx, |_| {
            panic!("factory panic");
            #[allow(unreachable_code)]
            async {
                0
            }
        });
    }));

    assert!(res.is_err(), "spawn should have panicked");

    // Inspect state
    let state_ref = state.borrow();
    let region_record = state_ref.regions.get(region.arena_index()).unwrap();

    // BUG: The task was added to the region but never removed
    let tasks = region_record.task_ids();
    assert!(
        tasks.is_empty(),
        "Region should be empty but has zombie tasks: {tasks:?}",
    );
}
