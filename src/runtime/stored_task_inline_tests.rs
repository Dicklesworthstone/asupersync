    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn stored_task_polls_to_completion() {
        init_test("stored_task_polls_to_completion");
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let task = StoredTask::new(async move {
            completed_clone.store(true, Ordering::SeqCst);
            Outcome::Ok(())
        });

        let mut task = task;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Simple async block should complete immediately
        crate::test_section!("poll");
        let result = task.poll(&mut cx);
        let ready = matches!(result, Poll::Ready(Outcome::Ok(())));
        crate::assert_with_log!(ready, "poll should complete immediately", true, ready);
        let completed_value = completed.load(Ordering::SeqCst);
        crate::assert_with_log!(
            completed_value,
            "completion flag should be set",
            true,
            completed_value
        );
        crate::test_complete!("stored_task_polls_to_completion");
    }

    #[test]
    fn stored_task_debug() {
        init_test("stored_task_debug");
        let task = StoredTask::new(async { Outcome::Ok(()) });
        let debug = format!("{task:?}");
        let contains = debug.contains("StoredTask");
        crate::assert_with_log!(
            contains,
            "debug output should mention StoredTask",
            true,
            contains
        );
        crate::test_complete!("stored_task_debug");
    }

    #[test]
    fn any_stored_task_is_local_global() {
        init_test("any_stored_task_is_local_global");
        let task = AnyStoredTask::Global(StoredTask::new(async { Outcome::Ok(()) }));
        let local = task.is_local();
        crate::assert_with_log!(!local, "Global variant must not be local", false, local);
        crate::test_complete!("any_stored_task_is_local_global");
    }

    #[test]
    fn any_stored_task_is_local_local() {
        init_test("any_stored_task_is_local_local");
        let task = AnyStoredTask::Local(LocalStoredTask::new(async { Outcome::Ok(()) }));
        let local = task.is_local();
        crate::assert_with_log!(local, "Local variant must be local", true, local);
        crate::test_complete!("any_stored_task_is_local_local");
    }

    #[test]
    fn any_stored_task_is_local_stable_after_poll() {
        init_test("any_stored_task_is_local_stable_after_poll");
        let mut task = AnyStoredTask::Local(LocalStoredTask::new(async { Outcome::Ok(()) }));
        let before = task.is_local();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = task.poll(&mut cx);
        let after = task.is_local();
        crate::assert_with_log!(
            before == after,
            "is_local must be stable across poll",
            true,
            before == after
        );
        crate::test_complete!("any_stored_task_is_local_stable_after_poll");
    }

    #[test]
    fn any_stored_task_poll_count_tracks_inner_task_polls() {
        init_test("any_stored_task_poll_count_tracks_inner_task_polls");
        let mut task = AnyStoredTask::Local(LocalStoredTask::new(async { Outcome::Ok(()) }));
        let before = task.poll_count();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = task.poll(&mut cx);
        let after = task.poll_count();
        crate::assert_with_log!(
            before == 0 && after == 1,
            "AnyStoredTask must report the inner poll count",
            true,
            before == 0 && after == 1
        );
        crate::test_complete!("any_stored_task_poll_count_tracks_inner_task_polls");
    }

    #[test]
    fn stored_task_consumes_polls_remaining_after_poll() {
        init_test("stored_task_consumes_polls_remaining_after_poll");
        let mut task = StoredTask::new(async { Outcome::Ok(()) });
        task.set_polls_remaining(7);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = task.poll(&mut cx);
        crate::assert_with_log!(
            task.polls_remaining.is_none(),
            "polls_remaining should be consumed by poll",
            true,
            task.polls_remaining.is_none()
        );
        crate::test_complete!("stored_task_consumes_polls_remaining_after_poll");
    }

    #[test]
    fn local_stored_task_consumes_polls_remaining_after_poll() {
        init_test("local_stored_task_consumes_polls_remaining_after_poll");
        let mut task = LocalStoredTask::new(async { Outcome::Ok(()) });
        task.set_polls_remaining(11);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = task.poll(&mut cx);
        crate::assert_with_log!(
            task.polls_remaining.is_none(),
            "polls_remaining should be consumed by poll for local tasks",
            true,
            task.polls_remaining.is_none()
        );
        crate::test_complete!("local_stored_task_consumes_polls_remaining_after_poll");
    }
