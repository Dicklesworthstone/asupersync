    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::RegionLimits;
    use crate::runtime::RuntimeState;
    use crate::types::{
        CancelKind, CapabilityBudgetDimension, CapabilityBudgetRefusal, Outcome, Time,
    };
    use futures_lite::future::block_on;
    use std::sync::Arc;

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn test_scope(region: RegionId, budget: Budget) -> Scope<'static> {
        Scope::new(region, budget)
    }

    fn test_scope_with_capability_budget(
        region: RegionId,
        budget: Budget,
        capability_budget: CapabilityBudget,
    ) -> Scope<'static> {
        Scope::new_with_capability_budget(region, budget, capability_budget)
    }

    #[test]
    fn spawn_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope
            .create_stored_task(&mut state, &cx, |_| async { 42_i32 })
            .expect("should spawn async task");

        // Task should exist in state
        let task = state.task(handle.task_id());
        assert!(task.is_some());

        // Task should be owned by the region
        let task = task.expect("task should exist in state");
        assert_eq!(task.owner, region);
    }

    #[test]
    fn spawn_inherits_registry_and_remote_capabilities() {
        use crate::cx::registry::RegistryHandle;
        use crate::remote::{NodeId, RemoteCap};
        use std::task::Context;

        let mut state = RuntimeState::new();

        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let parent_registry_arc = registry_handle.as_arc();

        let cx = test_cx()
            .with_registry_handle(Some(registry_handle))
            .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin-test")));

        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let mut handle = scope
            .spawn_registered(&mut state, &cx, move |cx| async move {
                let child_registry = cx.registry_handle().expect("child must inherit registry");
                let child_registry_arc = child_registry.as_arc();
                let same_registry = Arc::ptr_eq(&child_registry_arc, &parent_registry_arc);

                let child_remote = cx.remote().expect("child must inherit remote cap");
                let origin = child_remote.local_node().as_str().to_owned();

                (same_registry, origin)
            })
            .expect("should spawn registered task for capability inheritance test");

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawn_registered must store the task");
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok((same_registry, origin))) => {
                assert!(
                    same_registry,
                    "child should observe the same RegistryCap instance"
                );
                assert_eq!(origin, "origin-test");
            }
            other => unreachable!("Expected Ready(Ok(_)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_inherits_runtime_timer_driver() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let clock = Arc::new(crate::time::VirtualClock::new());
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(clock));

        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .create_stored_task(&mut state, &cx, |cx| async move { cx.has_timer() })
            .expect("spawn should succeed");

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(has_timer)) => assert!(has_timer),
            other => unreachable!("Expected Ready(Ok(_)), got {other:?}"),
        }
    }

    #[test]
    fn create_task_record_uses_runtime_timer_driver_time() {
        let mut state = RuntimeState::new();
        let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_millis(
            11,
        )));
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(
            clock.clone(),
        ));

        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        clock.advance(Time::from_millis(7).as_nanos());
        let task_id = scope
            .create_task_record(&mut state)
            .expect("task record should be created");

        let task = state.task(task_id).expect("task record");
        assert_eq!(task.created_at, Time::from_millis(18));
        assert_eq!(task.id, task_id);
    }

    #[test]
    fn spawn_registered_stores_task() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // spawn_registered should both create and store the task
        let handle = scope
            .spawn_registered(&mut state, &cx, |_| async { 42_i32 })
            .expect("should spawn and register task");

        // Task record should exist
        let task = state.task(handle.task_id());
        assert!(task.is_some());
        assert_eq!(task.expect("task should exist in state").owner, region);

        // StoredTask should be registered (can be retrieved for polling)
        let stored = state.get_stored_future(handle.task_id());
        assert!(stored.is_some(), "spawn_registered should store the task");
    }

    #[test]
    fn spawn_registered_task_can_be_polled() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let mut handle = scope
            .spawn_registered(&mut state, &cx, |_| async { 42_i32 })
            .expect("should spawn registered task for polling test");

        // Get the stored future and poll it
        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state
            .get_stored_future(handle.task_id())
            .expect("should retrieve stored future for polling");
        let poll_result = stored.poll(&mut poll_cx);
        assert!(
            poll_result.is_ready(),
            "Simple async should complete in one poll"
        );

        // Join should now have the result
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 42),
            other => unreachable!("Expected Ready(Ok(42)), got {other:?}"),
        }
    }

    #[test]
    fn task_added_to_region() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope
            .create_stored_task(&mut state, &cx, |_| async { 42_i32 })
            .unwrap();

        // Check region has the task
        let region_record = state.region(region).unwrap();
        assert!(region_record.task_ids().contains(&handle.task_id()));
    }

    #[test]
    fn multiple_spawns_create_distinct_tasks() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle1, _) = scope
            .create_stored_task(&mut state, &cx, |_| async { 1_i32 })
            .unwrap();
        let (handle2, _) = scope
            .create_stored_task(&mut state, &cx, |_| async { 2_i32 })
            .unwrap();
        let (handle3, _) = scope
            .create_stored_task(&mut state, &cx, |_| async { 3_i32 })
            .unwrap();

        // All task IDs should be different
        assert_ne!(handle1.task_id(), handle2.task_id());
        assert_ne!(handle2.task_id(), handle3.task_id());
        assert_ne!(handle1.task_id(), handle3.task_id());

        // All tasks should be in the region
        let region_record = state.region(region).unwrap();
        assert!(region_record.task_ids().contains(&handle1.task_id()));
        assert!(region_record.task_ids().contains(&handle2.task_id()));
        assert!(region_record.task_ids().contains(&handle3.task_id()));
    }

    #[test]
    fn spawn_into_closing_region_should_fail() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Transition region to Closing
        let region_record = state.region_mut(region).expect("region");
        region_record.begin_close(None);

        // Attempt to spawn should fail
        let result = scope.create_stored_task(&mut state, &cx, |_| async { 42 });
        assert!(matches!(result, Err(SpawnError::RegionClosed(_))));
    }

    #[test]
    fn test_join_manual_poll() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task
        let (mut handle, mut stored_task) = scope
            .create_stored_task(&mut state, &cx, |_| async { 42_i32 })
            .unwrap();
        // The stored task is returned directly, not put in state by spawn_registered.

        // Create join future
        let mut join_fut = std::pin::pin!(handle.join(&cx));

        // Create waker context
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Poll join - should be pending
        assert!(join_fut.as_mut().poll(&mut ctx).is_pending());

        // Poll stored task - should complete and send result
        assert!(stored_task.poll(&mut ctx).is_ready());

        // Poll join - should be ready now
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 42),
            other => unreachable!("Expected Ready(Ok(42)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_abort_cancels_task() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task that checks for cancellation
        let (mut handle, mut stored_task) = scope
            .create_stored_task(&mut state, &cx, |cx| async move {
                // We expect to be cancelled immediately because abort() is called before we run
                if cx.checkpoint().is_err() {
                    return "cancelled";
                }
                "finished"
            })
            .unwrap();

        // Abort the task via handle
        handle.abort();

        // Drive the task
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Task should run, see cancellation, and return "cancelled"
        match stored_task.poll(&mut ctx) {
            Poll::Ready(crate::types::Outcome::Ok(())) => {}
            res => unreachable!("Task should have completed with Ok(()), got {res:?}"),
        }

        // Check result via handle
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, "cancelled"),
            Poll::Ready(Err(e)) => unreachable!("Task failed unexpectedly: {e}"),
            Poll::Pending => unreachable!("Join should be ready"),
        }
    }

    #[test]
    fn hedge_backup_spawn_failure_aborts_primary() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let limits = RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        };
        assert!(state.set_region_limits(region, limits));

        let result = block_on(scope.hedge(
            &mut state,
            &cx,
            std::time::Duration::ZERO,
            |_| async { 1_u8 },
            |_| async { 2_u8 },
        ));

        assert!(matches!(
            result,
            Err(JoinError::Cancelled(reason))
                if reason.kind == CancelKind::ResourceUnavailable
        ));

        let task_id = *state
            .region(region)
            .expect("region missing")
            .task_ids()
            .first()
            .expect("primary task should remain tracked");

        let task = state.task(task_id).expect("primary task record missing");
        let (cancel_requested, cancel_reason_kind) = {
            let inner = task
                .cx_inner
                .as_ref()
                .expect("primary task must have shared Cx inner")
                .read();
            (
                inner.cancel_requested,
                inner.cancel_reason.as_ref().map(|r| r.kind),
            )
        };

        assert!(
            cancel_requested,
            "primary task must be cancellation-requested when backup spawn fails"
        );
        assert_eq!(cancel_reason_kind, Some(CancelKind::ResourceUnavailable));
    }

    #[test]
    fn region_closes_empty_child() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child, _state| {
                let child_id = child.region_id();
                async move { Outcome::Ok(child_id) }
            },
        ))
        .expect("child region created");

        let child_id = match outcome {
            Outcome::Ok(id) => id,
            other => unreachable!("expected Outcome::Ok(child_id), got {other:?}"),
        };

        assert!(
            state.region(child_id).is_none(),
            "closed child region should be reclaimed from arena"
        );

        let parent_record = state.region(parent).expect("parent record missing");
        assert!(
            !parent_record.child_ids().contains(&child_id),
            "closed child should be removed from parent"
        );
    }

    #[test]
    fn region_budget_is_met_with_parent() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::with_deadline_at_secs(10));
        let scope = test_scope(parent, Budget::with_deadline_at_secs(10));

        let outcome = block_on(scope.region_with_budget(
            &mut state,
            &cx,
            Budget::with_deadline_at_secs(30),
            crate::types::policy::FailFast,
            |child, _state| {
                let child_id = child.region_id();
                let child_budget = child.budget();
                async move { Outcome::Ok((child_id, child_budget)) }
            },
        ))
        .expect("child region created");

        let (child_id, child_budget) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => unreachable!("expected Outcome::Ok(child_id), got {other:?}"),
        };

        assert_eq!(
            child_budget.deadline,
            Some(crate::types::Time::from_secs(10))
        );
        assert!(
            state.region(child_id).is_none(),
            "closed child region should be reclaimed from arena"
        );
    }

    #[test]
    fn region_admission_meets_region_scope_and_requested_envelopes() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region_with_capability_budget(
            Budget::with_deadline_at_secs(80)
                .with_poll_quota(80)
                .with_cost_quota(80)
                .with_priority(220),
            CapabilityBudget::new()
                .with_memory_bytes(2_048)
                .with_cpu_units(30)
                .with_io_bytes(2_000)
                .with_artifact_bytes(128)
                .with_cleanup_budget(Budget::new().with_poll_quota(80)),
        );
        let scope = test_scope_with_capability_budget(
            parent,
            Budget::with_deadline_at_secs(60)
                .with_poll_quota(90)
                .with_cost_quota(60)
                .with_priority(210),
            CapabilityBudget::new()
                .with_memory_bytes(1_024)
                .with_cpu_units(60)
                .with_io_bytes(3_000)
                .with_artifact_bytes(64)
                .with_cleanup_budget(Budget::new().with_poll_quota(40).with_cost_quota(30)),
        );
        let outcome = block_on(scope.region_with_budget_and_capability_budget(
            &mut state,
            &cx,
            Budget::with_deadline_at_secs(70)
                .with_poll_quota(40)
                .with_cost_quota(90)
                .with_priority(230),
            CapabilityBudget::new()
                .with_memory_bytes(4_096)
                .with_cpu_units(20)
                .with_io_bytes(1_000)
                .with_artifact_bytes(256)
                .with_cleanup_budget(Budget::new().with_poll_quota(60).with_cost_quota(20)),
            CapabilityBudgetRequirements::new()
                .require_memory_bytes()
                .require_cpu_units()
                .require_io_bytes()
                .require_artifact_bytes()
                .require_cleanup(),
            crate::types::policy::FailFast,
            |child, state| {
                let record = state.region(child.region_id()).expect("admitted child");
                assert_eq!(record.budget(), child.budget());
                assert_eq!(record.capability_budget(), child.capability_budget());
                std::future::ready(Outcome::Ok((child.budget(), child.capability_budget())))
            },
        ))
        .expect("combined envelopes admit the child");
        let Outcome::Ok((budget, capability_budget)) = outcome else {
            panic!("empty child must close successfully");
        };
        assert_eq!(
            budget,
            Budget::with_deadline_at_secs(60)
                .with_poll_quota(40)
                .with_cost_quota(60)
                .with_priority(230)
        );
        assert_eq!(
            capability_budget,
            CapabilityBudget::new()
                .with_memory_bytes(1_024)
                .with_cpu_units(20)
                .with_io_bytes(1_000)
                .with_artifact_bytes(64)
                .with_cleanup_budget(Budget::new().with_poll_quota(40).with_cost_quota(20))
        );
        assert!(state.region(parent).expect("parent").child_ids().is_empty());
    }

    #[test]
    fn region_cannot_replenish_exhausted_scope_scheduler_budget() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let exhausted = Budget::with_deadline_at_ns(0)
            .with_poll_quota(0)
            .with_cost_quota(0)
            .with_priority(u8::MAX);
        let scope = test_scope(parent, exhausted);
        let outcome = block_on(scope.region_with_budget(
            &mut state,
            &cx,
            Budget::INFINITE,
            crate::types::policy::FailFast,
            |child, _state| std::future::ready(Outcome::Ok(child.budget())),
        ))
        .expect("legacy admission retains the exhausted scheduler envelope");
        assert!(matches!(outcome, Outcome::Ok(budget) if budget == exhausted));
        assert!(state.region(parent).expect("parent").child_ids().is_empty());
    }

    #[test]
    fn region_with_priority_uses_requested_admission_priority() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        state
            .resource_monitor()
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                crate::runtime::resource_monitor::DegradationLevel::Moderate,
            );

        block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child, _state| {
                let child_id = child.region_id();
                async move { Outcome::Ok(child_id) }
            },
        ))
        .expect("normal child scope should be admitted at moderate pressure");

        let err = block_on(scope.region_with_priority(
            &mut state,
            &cx,
            RegionPriority::Low,
            crate::types::policy::FailFast,
            |_child, _state| async move { Outcome::Ok(()) },
        ))
        .expect_err("low-priority child scope should be rejected at moderate pressure");

        assert!(matches!(
            err,
            RegionCreateError::ResourcePressure {
                requested_priority: RegionPriority::Low,
                ..
            }
        ));
    }

    #[test]
    fn region_with_priority_registers_child_shedding_priority() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let outcome = block_on(scope.region_with_priority(
            &mut state,
            &cx,
            RegionPriority::Low,
            crate::types::policy::FailFast,
            |child, state| {
                let child_id = child.region_id();
                state
                    .resource_monitor()
                    .pressure()
                    .update_degradation_level(
                        crate::runtime::resource_monitor::ResourceType::Memory,
                        crate::runtime::resource_monitor::DegradationLevel::Heavy,
                    );
                let decision = state
                    .resource_monitor()
                    .engine()
                    .should_shed_region(child_id);
                async move { Outcome::Ok(decision) }
            },
        ))
        .expect("low-priority child scope should be admitted before pressure rises");

        assert!(matches!(
            outcome,
            Outcome::Ok(crate::runtime::resource_monitor::SheddingDecision::Pause)
        ));
    }

    #[test]
    fn region_capability_budget_is_met_with_parent() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent_budget = CapabilityBudget::new()
            .with_memory_bytes(1_024)
            .with_io_bytes(8_192);
        let parent =
            state.create_root_region_with_capability_budget(Budget::INFINITE, parent_budget);
        let scope = test_scope_with_capability_budget(parent, Budget::INFINITE, parent_budget);

        let outcome = block_on(
            scope.region_with_budget_and_capability_budget(
                &mut state,
                &cx,
                Budget::INFINITE,
                CapabilityBudget::new()
                    .with_memory_bytes(4_096)
                    .with_io_bytes(512),
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_io_bytes(),
                crate::types::policy::FailFast,
                |child, _state| {
                    let child_budget = child.capability_budget();
                    async move { Outcome::Ok(child_budget) }
                },
            ),
        )
        .expect("child region created");

        let child_budget = match outcome {
            Outcome::Ok(budget) => budget,
            other => unreachable!("expected Outcome::Ok(capability_budget), got {other:?}"),
        };

        assert_eq!(child_budget.memory_bytes, Some(1_024));
        assert_eq!(child_budget.io_bytes, Some(512));
    }

    #[test]
    fn region_capability_budget_required_absent_dimension_rejects() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let err = block_on(scope.region_with_budget_and_capability_budget(
            &mut state,
            &cx,
            Budget::INFINITE,
            CapabilityBudget::new(),
            CapabilityBudgetRequirements::new().require_artifact_bytes(),
            crate::types::policy::FailFast,
            |_child, _state| async move { Outcome::Ok(()) },
        ))
        .expect_err("missing required artifact budget must fail closed");

        assert!(matches!(
            err,
            RegionCreateError::CapabilityBudgetRefused {
                parent: refused_parent,
                reason: CapabilityBudgetRefusal::MissingRequired(
                    CapabilityBudgetDimension::ArtifactBytes
                ),
            } if refused_parent == parent
        ));
    }

    #[test]
    fn spawned_task_cx_inherits_scope_capability_budget() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let capability_budget = CapabilityBudget::new()
            .with_memory_bytes(4_096)
            .with_cpu_units(16);
        let region =
            state.create_root_region_with_capability_budget(Budget::INFINITE, capability_budget);
        let scope = test_scope_with_capability_budget(region, Budget::INFINITE, capability_budget);

        let (handle, _stored) = scope
            .create_stored_task(&mut state, &cx, |child_cx| async move {
                child_cx.capability_budget()
            })
            .expect("spawn should admit task");

        let task = state.task(handle.task_id()).expect("task record missing");
        let actual = task
            .cx_inner
            .as_ref()
            .expect("task cx inner missing")
            .read()
            .capability_budget;

        assert_eq!(actual, capability_budget);
    }

    #[test]
    fn region_spawns_tasks_in_child() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child, state| {
                let child_id = child.region_id();
                let (handle, mut stored) = child
                    .create_stored_task(state, &cx, |_| async { 7_i32 })
                    .expect("spawn in child");

                let parent_has = state
                    .region(parent)
                    .expect("parent record missing")
                    .task_ids()
                    .contains(&handle.task_id());
                let child_has = state
                    .region(child_id)
                    .expect("child record missing")
                    .task_ids()
                    .contains(&handle.task_id());

                let waker = std::task::Waker::noop().clone();
                let mut poll_cx = Context::from_waker(&waker);
                let poll_result = stored.poll(&mut poll_cx);
                if let Poll::Ready(outcome) = poll_result {
                    let task_outcome = match outcome {
                        Outcome::Ok(()) => Outcome::Ok(()),
                        Outcome::Panicked(payload) => Outcome::Panicked(payload),
                        other => unreachable!("unexpected task outcome: {other:?}"),
                    };
                    if let Some(task_record) = state.task_mut(handle.task_id()) {
                        task_record.complete(task_outcome);
                    }
                    let (_waiters, completion_observer) =
                        state.task_completed(handle.task_id()).into_parts();
                    completion_observer.dispatch();
                }

                std::future::ready(Outcome::Ok((child_id, parent_has, child_has)))
            },
        ))
        .expect("child region created");

        let (child_id, parent_has, child_has) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => unreachable!("expected Outcome::Ok(tuple), got {other:?}"),
        };

        assert!(!parent_has, "task should not be owned by parent region");
        assert!(child_has, "task should be owned by child region");

        let parent_record = state.region(parent).expect("parent record missing");
        assert!(
            !parent_record.child_ids().contains(&child_id),
            "closed child should be removed from parent"
        );
    }

    #[test]
    fn spawn_panic_propagates_as_panicked_error() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored_task) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("oops");
            })
            .unwrap();

        // Drive the task
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Polling stored task should return Ready(Panicked) even if it panics (caught inside)
        match stored_task.poll(&mut ctx) {
            Poll::Ready(crate::types::Outcome::Panicked(_)) => {}
            res => unreachable!("Task should have completed with Panicked, got {res:?}"),
        }

        // Check result via handle
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Err(JoinError::Panicked(p))) => {
                assert_eq!(p.message(), "oops");
            }
            res => unreachable!("Expected Panicked, got {res:?}"),
        }
    }

    #[test]
    fn spawn_registered_defers_synchronous_factory_panic_until_first_poll() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);
        let factory_called = Arc::new(AtomicBool::new(false));
        let factory_called_in_task = Arc::clone(&factory_called);

        let mut handle = scope
            .spawn_registered(&mut state, &cx, move |_| -> std::future::Ready<()> {
                factory_called_in_task.store(true, Ordering::SeqCst);
                panic!("synchronous scope factory panic");
            })
            .expect("factory construction must not run during registration");

        assert!(
            !factory_called.load(Ordering::SeqCst),
            "scope factory must stay lazy until the stored task is polled"
        );
        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawn_registered stores the lazy factory task");
        assert!(matches!(
            stored.poll(&mut poll_cx),
            Poll::Ready(Outcome::Panicked(_))
        ));
        assert!(factory_called.load(Ordering::SeqCst));

        let mut join = std::pin::pin!(handle.join(&cx));
        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(payload.message(), "synchronous scope factory panic");
            }
            other => panic!("synchronous factory panic must reach join: {other:?}"),
        }
    }

    #[test]
    fn join_all_success() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async { 1 })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| async { 2 })
            .unwrap();

        // Drive tasks to completion
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);
        assert!(t1.poll(&mut ctx).is_ready());
        assert!(t2.poll(&mut ctx).is_ready());

        let handles = vec![h1, h2];
        let mut fut = Box::pin(scope.join_all(&cx, handles));

        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(results) => {
                assert_eq!(results.len(), 2);
                assert_eq!(results[0].as_ref().unwrap(), &1);
                assert_eq!(results[1].as_ref().unwrap(), &2);
            }
            Poll::Pending => unreachable!("join_all should be ready"),
        }
    }

    #[test]
    fn race_all_aborted_task_is_drained() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Task 1: completes immediately
        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async { 1 })
            .unwrap();

        // Task 2: yields once, checking for cancellation
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |cx| async move {
                // Yield once to simulate running
                struct YieldOnce(bool);
                impl std::future::Future for YieldOnce {
                    type Output = ();
                    fn poll(
                        mut self: std::pin::Pin<&mut Self>,
                        cx: &mut std::task::Context<'_>,
                    ) -> std::task::Poll<()> {
                        if self.0 {
                            std::task::Poll::Ready(())
                        } else {
                            self.0 = true;
                            cx.waker().wake_by_ref();
                            std::task::Poll::Pending
                        }
                    }
                }
                YieldOnce(false).await;

                // Check cancellation
                if cx.checkpoint().is_err() {
                    return 0; // Cancelled
                }
                2
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Drive t1 to completion (winner)
        assert!(t1.poll(&mut ctx).is_ready());

        // Initialize race_all
        let handles = vec![h1, h2];
        let mut race_fut = Box::pin(scope.race_all(&cx, handles));

        // Poll race_all.
        // It sees h1 ready. Winner=0.
        // It aborts h2.
        // It awaits h2 drain.
        // h2 is still pending (hasn't run), so h2.join() returns Pending.
        // race_fut returns Pending.
        assert!(race_fut.as_mut().poll(&mut ctx).is_pending());

        // Now drive t2. It was aborted, so it should see cancellation if checked?
        // Wait, handle.abort() sets inner.cancel_requested.
        // But my t2 closure yields first.
        // So first poll of t2 -> YieldOnce returns Pending.
        assert!(t2.poll(&mut ctx).is_pending());

        // Poll race_fut again. Still waiting for h2 drain.
        assert!(race_fut.as_mut().poll(&mut ctx).is_pending());

        // Poll t2 again. YieldOnce finishes.
        // Then it hits checkpoint(). cancel_requested is true.
        // It returns 0 (simulated cancellation return).
        // Actually, normally tasks return Result or are wrapped.
        // Here spawn returns Result<i32>.
        // My closure returns i32.
        // So h2.join() will return Ok(0).
        // This counts as "drained".
        assert!(t2.poll(&mut ctx).is_ready());

        // Now poll race_fut. h2 drain complete.
        // Should return (1, 0).
        match race_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok((val, idx))) => {
                assert_eq!(val, 1);
                assert_eq!(idx, 0);
            }
            res => unreachable!("Expected Ready(Ok((1, 0))), got {res:?}"),
        }
    }

    #[test]
    fn ready_race_result_precedes_same_poll_owner_cancellation() {
        for all_handles in [false, true] {
            let mut state = RuntimeState::new();
            let cx = test_cx();
            let region = state.create_root_region(Budget::INFINITE);
            let scope = test_scope(region, Budget::INFINITE);
            let (h1, mut t1) = scope
                .create_stored_task(&mut state, &cx, |_| async { 7_u8 })
                .unwrap();
            let (h2, mut t2) = scope
                .create_stored_task(&mut state, &cx, |_| async { 7_u8 })
                .unwrap();
            let mut poll_cx = Context::from_waker(std::task::Waker::noop());
            assert!(t1.poll(&mut poll_cx).is_ready());
            assert!(t2.poll(&mut poll_cx).is_ready());
            cx.cancel_fast(CancelKind::User);
            let result = if all_handles {
                block_on(scope.race_all(&cx, vec![h1, h2])).map(|(value, _)| value)
            } else {
                block_on(scope.race(&cx, h1, h2))
            };
            assert_eq!(
                result.unwrap(),
                7,
                "a ready result must retain selection priority"
            );
        }
    }

    #[test]
    fn race_surfaces_loser_panic_even_if_winner_succeeds() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async { 1_i32 })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("loser panic");
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());

        let result = block_on(scope.race(&cx, h1, h2));
        assert!(
            matches!(result, Err(JoinError::Panicked(_))),
            "loser panic must dominate race result, got {result:?}"
        );
    }

    #[test]
    fn race_preserves_winner_panic_over_loser_panic() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("winner panic");
            })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| {
                let mut first_poll = true;
                std::future::poll_fn(move |poll_cx| {
                    if first_poll {
                        first_poll = false;
                        poll_cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        std::panic::panic_any("loser panic");
                    }
                })
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_pending());

        let result = block_on(scope.race(&cx, h1, h2));
        match result {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "winner panic");
            }
            other => unreachable!("winner panic must dominate race result, got {other:?}"),
        }
    }

    #[test]
    fn race_all_surfaces_simultaneous_loser_panic() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async { 1_i32 })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("simultaneous loser panic");
            })
            .unwrap();
        let (h3, mut t3) = scope
            .create_stored_task(&mut state, &cx, |_| async { 3_i32 })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());
        assert!(t3.poll(&mut poll_cx).is_ready());

        let result = block_on(scope.race_all(&cx, vec![h1, h2, h3]));
        assert!(
            matches!(result, Err(JoinError::Panicked(_))),
            "simultaneous loser panic must dominate race_all result, got {result:?}"
        );
    }

    #[test]
    fn race_all_preserves_winner_panic_over_loser_panic() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("winner panic");
            })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| {
                let mut first_poll = true;
                std::future::poll_fn(move |poll_cx| {
                    if first_poll {
                        first_poll = false;
                        poll_cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        std::panic::panic_any("loser panic");
                    }
                })
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_pending());

        let result = block_on(scope.race_all(&cx, vec![h1, h2]));
        match result {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "winner panic");
            }
            other => unreachable!("winner panic must dominate race_all result, got {other:?}"),
        }
    }

    #[test]
    fn race_all_empty_is_pending() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let fut = scope.race_all::<i32>(&cx, vec![]);
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        let pinned = std::pin::pin!(fut);
        let status = std::future::Future::poll(pinned, &mut poll_cx);
        assert!(status.is_pending());
    }

    // =============================================================================
    // CONFORMANCE TESTS: Structured Concurrency Invariants
    // =============================================================================
    //
    // These tests verify the core structured concurrency guarantees that must hold
    // for the spawn/join contract to be sound.

    #[test]
    fn conformance_spawn_creates_trackable_task() {
        // INVARIANT: Every spawned task creates a trackable record that belongs to the spawning region
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope
            .create_stored_task(&mut state, &cx, |_| async { 42_i32 })
            .unwrap();

        // Task must exist and be trackable
        let task_record = state
            .task(handle.task_id())
            .expect("spawned task must have a record");

        // Task must belong to the spawning region
        assert_eq!(
            task_record.owner, region,
            "spawned task must be owned by the spawning region"
        );

        // Region must track the task
        let region_record = state.region(region).expect("spawning region must exist");
        assert!(
            region_record.task_ids().contains(&handle.task_id()),
            "spawning region must track the spawned task"
        );
    }

    #[test]
    fn conformance_spawn_enforces_send_bounds() {
        // INVARIANT: spawn() enforces Send + 'static bounds for cross-worker task migration
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // This should compile - Send + 'static data
        let send_data = String::from("test");
        let (handle, _stored) = scope
            .create_stored_task(&mut state, &cx, move |_| async move {
                send_data.len() // Uses Send + 'static String
            })
            .unwrap();

        // Task record should reflect Send bounds
        let task_record = state
            .task(handle.task_id())
            .expect("Send task must have a record");
        assert_eq!(task_record.owner, region);

        // NOTE: Non-Send compile-time test examples are in module docstring
        // (compile_fail tests with Rc<T> and borrowed references)
    }

    #[test]
    fn conformance_join_awaits_task_completion() {
        // INVARIANT: TaskHandle.join() waits for task completion and returns the result

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .create_stored_task(&mut state, &cx, |_| async { 123_i32 })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Before task completion, join should be pending
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        assert!(
            join_fut.as_mut().poll(&mut poll_cx).is_pending(),
            "join must be pending before task completion"
        );

        // Complete the task
        assert!(
            stored.poll(&mut poll_cx).is_ready(),
            "test task must complete in one poll"
        );

        // After task completion, join should return the result
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok(result)) => {
                assert_eq!(result, 123, "join must return the task's result");
            }
            other => panic!("join must be Ready(Ok(123)) after task completion, got {other:?}"),
        }
    }

    #[test]
    fn conformance_child_region_task_isolation() {
        // INVARIANT: Tasks spawned in child regions belong to the child, not the parent

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent_region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent_region, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child_scope, state| {
                let child_region = child_scope.region_id();

                // Spawn task in child region
                let (handle, mut stored) = child_scope
                    .create_stored_task(state, &cx, |_| async { 456_i32 })
                    .expect("spawn in child region must succeed");

                // Verify task ownership invariants
                let task_record = state
                    .task(handle.task_id())
                    .expect("child task must have a record");
                let child_owns = task_record.owner == child_region;
                let parent_owns = task_record.owner == parent_region;

                // Verify region tracking invariants
                let parent_tracks = state
                    .region(parent_region)
                    .is_some_and(|r| r.task_ids().contains(&handle.task_id()));
                let child_tracks = state
                    .region(child_region)
                    .is_some_and(|r| r.task_ids().contains(&handle.task_id()));

                // Complete the task for clean shutdown
                let waker = std::task::Waker::noop().clone();
                let mut poll_cx = Context::from_waker(&waker);
                if let std::task::Poll::Ready(outcome) = stored.poll(&mut poll_cx) {
                    if let Some(task) = state.task_mut(handle.task_id()) {
                        task.complete(outcome.map_err(|_| {
                            crate::error::Error::new(crate::error::ErrorKind::Internal)
                        }));
                    }
                    let (_waiters, completion_observer) =
                        state.task_completed(handle.task_id()).into_parts();
                    completion_observer.dispatch();
                }

                std::future::ready(Outcome::Ok((
                    child_owns,
                    parent_owns,
                    child_tracks,
                    parent_tracks,
                )))
            },
        ))
        .expect("child region must complete");

        let (child_owns, parent_owns, child_tracks, parent_tracks) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => panic!("expected Ok(ownership_data), got {other:?}"),
        };

        assert!(
            child_owns,
            "task spawned in child region must be owned by child"
        );
        assert!(
            !parent_owns,
            "task spawned in child region must NOT be owned by parent"
        );
        assert!(child_tracks, "child region must track its spawned tasks");
        assert!(!parent_tracks, "parent region must NOT track child's tasks");
    }

    #[test]
    fn conformance_capability_inheritance() {
        // INVARIANT: Spawned tasks inherit capabilities from the parent Cx
        use crate::cx::macaroon::MacaroonToken;
        use crate::cx::registry::RegistryHandle;
        use crate::remote::{NodeId, RemoteCap};
        use crate::security::key::AuthKey;
        use crate::types::SystemPressure;
        use std::sync::Arc;
        use std::task::Context;

        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Setup parent Cx with capabilities
        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let parent_registry_arc = registry_handle.as_arc();
        let parent_io_cap: Arc<dyn crate::io::IoCap> =
            Arc::new(crate::io::LabIoCap::new_for_tests());
        let parent_pressure = Arc::new(SystemPressure::new());
        parent_pressure.set_headroom(0.25);
        let auth_key = AuthKey::from_seed(7);
        let token = MacaroonToken::mint(&auth_key, "scope:spawn", "cx/scope");

        let parent_cx = Cx::new_with_io(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::clone(&parent_io_cap)),
            None,
        )
        .with_registry_handle(Some(registry_handle))
        .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("test-node")))
        .with_pressure(Arc::clone(&parent_pressure))
        .with_macaroon(token);
        let parent_macaroon = parent_cx
            .macaroon_handle()
            .expect("parent must retain macaroon capability");

        let mut handle = scope
            .spawn_registered(&mut state, &parent_cx, move |child_cx| async move {
                // Verify registry inheritance
                let child_registry = child_cx
                    .registry_handle()
                    .expect("child must inherit registry capability");
                let same_registry = Arc::ptr_eq(&child_registry.as_arc(), &parent_registry_arc);

                // Verify remote capability inheritance
                let child_remote = child_cx
                    .remote()
                    .expect("child must inherit remote capability");
                let node_name = child_remote.local_node().as_str().to_owned();

                // Verify I/O capability inheritance
                let child_io_cap = child_cx
                    .io_cap_handle()
                    .expect("child must inherit I/O capability");
                let same_io_cap = Arc::ptr_eq(&child_io_cap, &parent_io_cap);

                // Verify system pressure inheritance
                let child_pressure = child_cx
                    .pressure_handle()
                    .expect("child must inherit system pressure");
                let same_pressure = Arc::ptr_eq(&child_pressure, &parent_pressure);

                // Verify macaroon inheritance
                let child_macaroon = child_cx
                    .macaroon_handle()
                    .expect("child must inherit macaroon capability");
                let same_macaroon = Arc::ptr_eq(&child_macaroon, &parent_macaroon);

                // Verify timer capability inheritance (if parent has it)
                let has_timer = child_cx.has_timer();

                (
                    same_registry,
                    node_name,
                    same_io_cap,
                    same_pressure,
                    same_macaroon,
                    has_timer,
                )
            })
            .unwrap();

        // Complete the task and verify results
        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawn_registered must store the task");
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&parent_cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok((
                same_registry,
                node_name,
                same_io_cap,
                same_pressure,
                same_macaroon,
                has_timer,
            ))) => {
                assert!(
                    same_registry,
                    "child must inherit exact same registry instance"
                );
                assert_eq!(
                    node_name, "test-node",
                    "child must inherit remote capability"
                );
                assert!(same_io_cap, "child must inherit exact same I/O capability");
                assert!(
                    same_pressure,
                    "child must inherit exact same system pressure handle"
                );
                assert!(
                    same_macaroon,
                    "child must inherit exact same macaroon capability"
                );
                assert_eq!(
                    has_timer,
                    parent_cx.has_timer(),
                    "child timer capability should stay consistent with the runtime-backed parent"
                );
            }
            other => panic!("capability inheritance test failed: {other:?}"),
        }
    }

    #[test]
    fn conformance_task_cancellation_propagation() {
        // INVARIANT: Cancelling a task via abort() propagates cancellation signal

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .create_stored_task(&mut state, &cx, |cx| async move {
                // Check cancellation status and respond accordingly
                if cx.checkpoint().is_err() {
                    "cancelled"
                } else {
                    "completed"
                }
            })
            .unwrap();

        // Abort the task before it runs
        handle.abort();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Task should complete and see the cancellation
        assert!(
            stored.poll(&mut poll_cx).is_ready(),
            "cancelled task must still complete"
        );

        // Join should return the cancellation-aware result
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok(result)) => {
                assert_eq!(
                    result, "cancelled",
                    "cancelled task must observe cancellation via checkpoint()"
                );
            }
            other => panic!("cancelled task join failed: {other:?}"),
        }
    }

    #[test]
    fn cancellation_blind_scope_completion_preserves_legacy_returned_value() {
        struct PendingThenReady(bool);

        impl Future for PendingThenReady {
            type Output = &'static str;

            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.0 {
                    Poll::Ready("late-success")
                } else {
                    self.0 = true;
                    Poll::Pending
                }
            }
        }

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);
        let (mut handle, mut stored) = scope
            .create_stored_task(&mut state, &cx, |_child_cx| PendingThenReady(false))
            .expect("create state-threaded scope task");
        let waker = std::task::Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        assert!(
            stored.poll(&mut poll_cx).is_pending(),
            "scope task must begin before abort",
        );
        handle.abort();
        assert!(
            stored.poll(&mut poll_cx).is_ready(),
            "abort must repoll the cancellation-blind scope task",
        );

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        assert_eq!(
            join_fut.as_mut().poll(&mut poll_cx),
            Poll::Ready(Ok("late-success")),
            "legacy Scope completion must preserve a returned value even without cancellation acknowledgement",
        );
    }

    #[test]
    fn metamorphic_nested_scope_cancellation_closes_descendants_without_spawn_leaks() {
        use std::task::{Context, Poll};

        fn run_ready_finalizer(state: &mut RuntimeState, poll_cx: &mut Context<'_>) {
            let mut scheduled = state.drain_ready_async_finalizers();
            assert_eq!(scheduled.len(), 1, "one LIFO finalizer should be ready");
            let (task_id, _priority, spawn_effects) =
                scheduled.pop().expect("ready finalizer task");
            spawn_effects.dispatch();
            let mut stored = state
                .remove_stored_future(task_id)
                .expect("ready finalizer must own a stored task");
            let outcome = match stored.poll(poll_cx) {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Cancelled(reason)) => Outcome::Cancelled(reason),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                Poll::Ready(Outcome::Err(())) => {
                    panic!("finalizer task must not resolve with unit error")
                }
                Poll::Pending => panic!("sync finalizer task must complete on its first poll"),
            };
            assert!(state.complete_task(task_id, outcome));
            let (waiters, observer) = state.task_completed(task_id).into_parts();
            assert!(waiters.is_empty());
            observer.dispatch();
        }

        struct YieldOnce(bool);

        impl std::future::Future for YieldOnce {
            type Output = ();

            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<()> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let root = state.create_root_region(Budget::INFINITE);
        let child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let grandchild = state
            .create_child_region(child, Budget::INFINITE)
            .expect("grandchild region");
        let child_scope = test_scope(child, Budget::INFINITE);
        let grandchild_scope = test_scope(grandchild, Budget::INFINITE);
        let finalizer_log = Arc::new(std::sync::Mutex::new(Vec::new()));

        let child_log = Arc::clone(&finalizer_log);
        assert!(
            child_scope.defer_sync(&mut state, move || {
                child_log
                    .lock()
                    .expect("child finalizer log poisoned")
                    .push("child");
            }),
            "child finalizer should register before cancellation"
        );

        let grandchild_log = Arc::clone(&finalizer_log);
        assert!(
            grandchild_scope.defer_sync(&mut state, move || {
                grandchild_log
                    .lock()
                    .expect("grandchild finalizer log poisoned")
                    .push("grandchild");
            }),
            "grandchild finalizer should register before cancellation"
        );

        let mut child_handle = child_scope
            .spawn_registered(&mut state, &cx, |task_cx| async move {
                YieldOnce(false).await;
                if task_cx.checkpoint().is_err() {
                    "child_cancelled"
                } else {
                    "child_completed"
                }
            })
            .expect("spawn child task");
        let child_task_id = child_handle.task_id();

        let mut grandchild_handle = grandchild_scope
            .spawn_registered(&mut state, &cx, |task_cx| async move {
                YieldOnce(false).await;
                if task_cx.checkpoint().is_err() {
                    "grandchild_cancelled"
                } else {
                    "grandchild_completed"
                }
            })
            .expect("spawn grandchild task");
        let grandchild_task_id = grandchild_handle.task_id();

        let cancel_reason = CancelReason::shutdown().with_region(root);
        let effects = state.cancel_request(root, &cancel_reason, None);
        let (cancelled, cancel_wakes) = effects.into_parts();
        assert!(
            cancelled
                .iter()
                .any(|(task_id, _)| *task_id == child_task_id),
            "parent cancellation must reach child task"
        );
        assert!(
            cancelled
                .iter()
                .any(|(task_id, _)| *task_id == grandchild_task_id),
            "parent cancellation must reach grandchild task"
        );
        cancel_wakes.dispatch();

        let grandchild_tasks_before_failed_spawn = state
            .region(grandchild)
            .expect("grandchild region missing")
            .task_count();
        let live_tasks_before_failed_spawn = state.live_task_count();
        let failed_spawn =
            grandchild_scope.create_stored_task(&mut state, &cx, |_| async { 99_u8 });
        let grandchild_tasks_after_failed_spawn = state
            .region(grandchild)
            .expect("grandchild region missing after failed spawn")
            .task_count();
        let live_tasks_after_failed_spawn = state.live_task_count();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        {
            let stored = state
                .get_stored_future(grandchild_task_id)
                .expect("grandchild stored task");
            let poll_result = stored.poll(&mut poll_cx);
            assert!(
                poll_result.is_pending(),
                "grandchild task should yield once before observing cancellation"
            );
        }
        {
            let stored = state
                .get_stored_future(grandchild_task_id)
                .expect("grandchild stored task");
            let poll_result = stored.poll(&mut poll_cx);
            let task_outcome = match poll_result {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                other => panic!(
                    "grandchild task should complete once cancellation is observed: {other:?}"
                ),
            };
            if let Some(task_record) = state.task_mut(grandchild_task_id) {
                task_record.complete(task_outcome);
            }
        }
        let (_waiters, completion_observer) = state.task_completed(grandchild_task_id).into_parts();
        completion_observer.dispatch();
        state.advance_region_state(grandchild);
        run_ready_finalizer(&mut state, &mut poll_cx);

        let mut grandchild_join_fut = std::pin::pin!(grandchild_handle.join(&cx));
        let grandchild_result = match grandchild_join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(result)) => result,
            other => panic!("grandchild cancellation join should succeed: {other:?}"),
        };

        {
            let stored = state
                .get_stored_future(child_task_id)
                .expect("child stored task");
            let poll_result = stored.poll(&mut poll_cx);
            assert!(
                poll_result.is_pending(),
                "child task should yield once before observing cancellation"
            );
        }
        {
            let stored = state
                .get_stored_future(child_task_id)
                .expect("child stored task");
            let poll_result = stored.poll(&mut poll_cx);
            let task_outcome = match poll_result {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                other => {
                    panic!("child task should complete once cancellation is observed: {other:?}")
                }
            };
            if let Some(task_record) = state.task_mut(child_task_id) {
                task_record.complete(task_outcome);
            }
        }
        let (_waiters, completion_observer) = state.task_completed(child_task_id).into_parts();
        completion_observer.dispatch();
        state.advance_region_state(child);
        run_ready_finalizer(&mut state, &mut poll_cx);

        let mut child_join_fut = std::pin::pin!(child_handle.join(&cx));
        let child_result = match child_join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(result)) => result,
            other => panic!("child cancellation join should succeed: {other:?}"),
        };

        assert_eq!(child_result, "child_cancelled");
        assert_eq!(grandchild_result, "grandchild_cancelled");
        assert!(
            matches!(failed_spawn, Err(SpawnError::RegionClosed(id)) if id == grandchild),
            "nested spawn after parent cancellation must fail against the closing grandchild region"
        );
        assert_eq!(
            grandchild_tasks_before_failed_spawn, grandchild_tasks_after_failed_spawn,
            "failed spawn after cancellation must not leak task membership into the grandchild region"
        );
        assert_eq!(
            live_tasks_before_failed_spawn, live_tasks_after_failed_spawn,
            "failed spawn after cancellation must not inflate runtime task count"
        );
        assert_eq!(
            *finalizer_log.lock().expect("finalizer log poisoned"), // ubs:ignore - test helper
            vec!["grandchild", "child"],
            "nested scope finalizers must run in reverse scope creation order"
        );
        assert!(
            state.region(grandchild).is_none(),
            "grandchild region should be reclaimed after close"
        );
        assert!(
            state.region(child).is_none(),
            "child region should be reclaimed after close"
        );
    }

    #[test]
    fn conformance_race_loser_drain_invariant() {
        // INVARIANT: In race operations, losers are cancelled and fully drained

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Winner: completes immediately
        let (winner_handle, mut winner_stored) = scope
            .create_stored_task(&mut state, &cx, |_| async { "winner" })
            .unwrap();

        // Loser: would run longer, must be cancelled and drained
        let (loser_handle, mut loser_stored) = scope
            .create_stored_task(&mut state, &cx, |cx| async move {
                // Simulate work that can be cancelled
                struct YieldOnce(bool);
                impl std::future::Future for YieldOnce {
                    type Output = ();
                    fn poll(
                        mut self: std::pin::Pin<&mut Self>,
                        cx: &mut std::task::Context<'_>,
                    ) -> std::task::Poll<()> {
                        if self.0 {
                            std::task::Poll::Ready(())
                        } else {
                            self.0 = true;
                            cx.waker().wake_by_ref();
                            std::task::Poll::Pending
                        }
                    }
                }
                YieldOnce(false).await;

                // Check if we were cancelled
                if cx.checkpoint().is_err() {
                    "loser_cancelled"
                } else {
                    "loser_completed"
                }
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Complete winner immediately
        assert!(winner_stored.poll(&mut poll_cx).is_ready());

        // Start the race
        let handles = vec![winner_handle, loser_handle];
        let mut race_fut = std::pin::pin!(scope.race_all(&cx, handles));

        // Race should be pending initially (waiting for loser drain)
        assert!(
            race_fut.as_mut().poll(&mut poll_cx).is_pending(),
            "race must wait for loser to be drained"
        );

        // Drive loser to first yield (it's now pending, but abort signal propagates)
        assert!(loser_stored.poll(&mut poll_cx).is_pending());

        // Still pending on race (loser not fully drained)
        assert!(race_fut.as_mut().poll(&mut poll_cx).is_pending());

        // Drive loser to completion (should see cancellation)
        assert!(loser_stored.poll(&mut poll_cx).is_ready());

        // Now race should complete with winner result
        match race_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok((result, winner_index))) => {
                assert_eq!(result, "winner", "race must return winner result");
                assert_eq!(winner_index, 0, "winner index must be correct");
            }
            other => panic!("race must complete after loser drain: {other:?}"),
        }
    }

    #[test]
    fn conformance_region_quiescence_on_empty() {
        // INVARIANT: Empty regions reach quiescence and can be closed immediately
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent_region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent_region, Budget::INFINITE);

        // Create and immediately close a child region with no spawned tasks
        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |_child_scope, _state| {
                // Don't spawn any tasks - region should be empty
                std::future::ready(Outcome::Ok("empty_region_completed"))
            },
        ))
        .expect("empty child region must complete");

        match outcome {
            Outcome::Ok(result) => {
                assert_eq!(
                    result, "empty_region_completed",
                    "empty region must reach quiescence immediately"
                );
            }
            other => panic!("empty region must complete successfully: {other:?}"),
        }

        // Child region should be cleaned up (no longer in parent's child list)
        let parent_record = state
            .region(parent_region)
            .expect("parent region must exist");
        assert!(
            parent_record.child_ids().is_empty(),
            "completed child region must be removed from parent"
        );
    }

    #[test]
    fn region_close_future_wakes_all_registered_waiters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl std::task::Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let notify = Arc::new(parking_lot::Mutex::new(
            crate::record::region::RegionCloseState {
                closed: false,
                waiters: Default::default(),
            },
        ));
        let wake_count_a = Arc::new(AtomicUsize::new(0));
        let wake_count_b = Arc::new(AtomicUsize::new(0));
        let waker_a = Waker::from(Arc::new(CountWaker(Arc::clone(&wake_count_a))));
        let waker_b = Waker::from(Arc::new(CountWaker(Arc::clone(&wake_count_b))));
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);
        let mut future_a = RegionCloseFuture {
            state: Arc::clone(&notify),
        };
        let mut future_b = RegionCloseFuture { state: notify };

        assert!(Pin::new(&mut future_a).poll(&mut cx_a).is_pending());
        assert!(Pin::new(&mut future_b).poll(&mut cx_b).is_pending());

        let waiters = {
            let mut state = future_a.state.lock();
            state.closed = true;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters {
            waker.wake();
        }

        assert_eq!(wake_count_a.load(Ordering::SeqCst), 1);
        assert_eq!(wake_count_b.load(Ordering::SeqCst), 1);
        assert!(Pin::new(&mut future_a).poll(&mut cx_a).is_ready());
        assert!(Pin::new(&mut future_b).poll(&mut cx_b).is_ready());
    }

    #[test]
    fn conformance_spawn_into_closed_region_fails() {
        // INVARIANT: Cannot spawn tasks into regions that have begun closing
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Close the region
        let region_record = state.region_mut(region).expect("region must exist");
        region_record.begin_close(None);

        // Attempt to spawn should fail
        let spawn_result = scope.create_stored_task(&mut state, &cx, |_| async { 42 });

        assert!(
            matches!(spawn_result, Err(SpawnError::RegionClosed(_))),
            "spawning into closed region must fail with RegionClosed error"
        );

        // State should remain consistent (no orphaned tasks)
        assert!(
            state.tasks_is_empty() || state.region(region).is_none_or(|r| r.task_ids().is_empty()),
            "failed spawn must not create orphaned tasks"
        );
    }

    #[test]
    fn conformance_join_multiple_tasks_preserves_results() {
        // INVARIANT: join_all preserves all task results in order

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn multiple tasks with different results
        let (h1, mut t1) = scope
            .create_stored_task(&mut state, &cx, |_| async { 100_i32 })
            .unwrap();
        let (h2, mut t2) = scope
            .create_stored_task(&mut state, &cx, |_| async { 200_i32 })
            .unwrap();
        let (h3, mut t3) = scope
            .create_stored_task(&mut state, &cx, |_| async { 300_i32 })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Complete all tasks
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());
        assert!(t3.poll(&mut poll_cx).is_ready());

        // Join all tasks
        let handles = vec![h1, h2, h3];
        let mut join_all_fut = std::pin::pin!(scope.join_all(&cx, handles));

        match join_all_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(results) => {
                assert_eq!(results.len(), 3, "join_all must return all results");

                // Results must be in the same order as handles
                assert_eq!(
                    results[0].as_ref().unwrap(),
                    &100,
                    "first task result must be preserved"
                );
                assert_eq!(
                    results[1].as_ref().unwrap(),
                    &200,
                    "second task result must be preserved"
                );
                assert_eq!(
                    results[2].as_ref().unwrap(),
                    &300,
                    "third task result must be preserved"
                );
            }
            other @ Poll::Pending => panic!("join_all must complete with all results: {other:?}"),
        }
    }

    #[test]
    fn conformance_panic_propagation_through_join() {
        // INVARIANT: Task panics are captured and propagated through join as JoinError::Panicked

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task that panics with a specific message
        let (mut handle, mut stored) = scope
            .create_stored_task(&mut state, &cx, |_| async {
                std::panic::panic_any("test_panic_message");
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Task execution should complete with Panicked outcome
        match stored.poll(&mut poll_cx) {
            Poll::Ready(crate::types::Outcome::Panicked(_)) => {
                // Expected: panic was caught and wrapped as Outcome::Panicked
            }
            other => panic!("panicking task must complete with Panicked outcome: {other:?}"),
        }

        // Join should propagate the panic as JoinError::Panicked
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "test_panic_message",
                    "join must preserve panic payload message"
                );
            }
            other => panic!("join of panicked task must return JoinError::Panicked: {other:?}"),
        }
    }

    /// Regression: region_with_budget factory panicking AFTER raw task creation
    /// returned — but BEFORE the StoredTask was scheduled — must not leave an
    /// orphan TaskRecord bound to the child region. Without the panic-catch
    /// rollback in `region_with_budget`, `region.task_count()` stays non-zero
    /// and `advance_region_state` can never transition Closing → Finalizing.
    ///
    /// Bead asupersync-c7s5de.
    #[test]
    fn region_factory_panic_after_spawn_cleans_up_orphan_task_records() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let tasks_before = state.tasks_iter().count();

        // Wrap the call in catch_unwind because the factory intentionally
        // panics after spawn — resume_unwind re-raises in region_with_budget.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope.region_with_budget(
                &mut state,
                &cx,
                Budget::INFINITE,
                crate::types::policy::FailFast,
                |child, state| {
                    // Spawn a task so a TaskRecord exists in Created state,
                    // bound to the child region.
                    let (_handle, _stored) = child
                        .create_stored_task(state, &cx, |_| async { 42_i32 })
                        .expect("spawn must succeed before the panic");
                    // Immediately panic — StoredTask is dropped unscheduled.
                    std::panic::panic_any("factory panic after spawn");
                    #[allow(unreachable_code)]
                    std::future::ready(Outcome::Ok(0_i32))
                },
            ))
        }));

        assert!(
            result.is_err(),
            "region_with_budget must re-raise the factory panic",
        );

        // Orphan TaskRecord(s) created inside the factory must have been
        // removed by the panic-catch rollback. The task count should be
        // back to its pre-call value.
        let tasks_after = state.tasks_iter().count();
        assert_eq!(
            tasks_after, tasks_before,
            "post-panic tasks_iter count must match pre-call count \
             (orphan TaskRecord not cleaned up: before={tasks_before} after={tasks_after})",
        );
    }

    #[test]
    fn spawn_error_to_cancel_reason_mapping_accuracy() {
        let region = RegionId::new_for_test(42, 0);

        let r1 = spawn_error_to_cancel_reason(SpawnError::RegionClosed(region));
        assert_eq!(r1.kind(), CancelKind::ParentCancelled);
        assert_eq!(r1.origin_region(), region);

        let r2 = spawn_error_to_cancel_reason(SpawnError::RegionNotFound(region));
        assert_eq!(r2.kind(), CancelKind::ParentCancelled);
        assert_eq!(r2.origin_region(), region);

        let r3 = spawn_error_to_cancel_reason(SpawnError::RuntimeUnavailable);
        assert_eq!(r3.kind(), CancelKind::ResourceUnavailable);

        let r4 = spawn_error_to_cancel_reason(SpawnError::RegionAtCapacity {
            region,
            limit: 10,
            live: 10,
        });
        assert_eq!(r4.kind(), CancelKind::ResourceUnavailable);
        assert_eq!(r4.origin_region(), region);

        let r5 = spawn_error_to_cancel_reason(SpawnError::AuthorizationDenied {
            region,
            cx_id: "test".to_string(),
        });
        assert_eq!(r5.kind(), CancelKind::ResourceUnavailable);
        assert_eq!(r5.origin_region(), region);

        let r6 = spawn_error_to_cancel_reason(SpawnError::LocalSchedulerUnavailable);
        assert_eq!(r6.kind(), CancelKind::ResourceUnavailable);

        let r7 = spawn_error_to_cancel_reason(SpawnError::NameRegistrationFailed {
            name: "svc".to_string(),
            reason: "dup".to_string(),
        });
        assert_eq!(r7.kind(), CancelKind::ResourceUnavailable);

        let r8 = spawn_error_to_cancel_reason(SpawnError::AdmissionSlotAlreadyReserved {
            task_id: TaskId::new_for_test(1, 0),
        });
        assert_eq!(r8.kind(), CancelKind::ResourceUnavailable);
    }
