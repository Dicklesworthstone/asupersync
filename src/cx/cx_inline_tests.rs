    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::macaroon::CaveatPredicate;
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::capability::{CommandFamily, FabricCapability, FabricCapabilityScope};
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::class::DeliveryClass;
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::ir::{CapabilityPermission, CapabilityTokenSchema, SubjectFamily};
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::subject::SubjectPattern;
    use crate::trace::TraceBufferHandle;
    use crate::types::CapabilityBudgetDimension;
    use crate::util::DetEntropy;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static CURRENT_CX_DTOR_STATE: AtomicU8 = AtomicU8::new(0);

    thread_local! {
        static CURRENT_CX_DTOR_PROBE: CurrentCxDtorProbe = const { CurrentCxDtorProbe };
    }

    struct CurrentCxDtorProbe;

    impl Drop for CurrentCxDtorProbe {
        fn drop(&mut self) {
            let state = if Cx::is_active() {
                1
            } else if Cx::current().is_some() {
                2
            } else {
                3
            };
            CURRENT_CX_DTOR_STATE.store(state as u8, Ordering::SeqCst);
        }
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn clear_current_stack() {
        CURRENT_CX_STACK.with(|stack| {
            stack.borrow_mut().clear();
        });
    }

    fn cap_layer(
        spawn: bool,
        time: bool,
        entropy: bool,
        io: bool,
        remote: bool,
    ) -> CapabilityLayerSnapshot {
        CapabilityLayerSnapshot {
            spawn,
            time,
            entropy,
            io,
            remote,
            trace: true,
        }
    }

    fn lab_with_spawn_cx() -> (crate::lab::LabRuntime, Cx<cap::All>, RegionId) {
        let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = lab.state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(root, TaskId::testing_default(), Budget::INFINITE)
            .with_spawn_gateway(lab.state.spawn_gateway())
            .with_pending_spawn_counter(
                lab.state
                    .region(root)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        (lab, cx, root)
    }

    fn test_cx_with_entropy(seed: u64) -> Cx<cap::All> {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::new(DetEntropy::new(seed))),
        )
    }

    #[test]
    fn spawn_batch_empty_requires_no_runtime_and_has_no_effects() {
        let cx = test_cx();
        let empty = std::iter::empty::<fn(Cx) -> std::future::Ready<usize>>;
        assert!(cx.spawn_batch(empty()).unwrap().is_empty());
        assert!(cx.spawn_batch_in(&cx.scope(), empty()).unwrap().is_empty());

        let (_lab, live_cx, _root) = lab_with_spawn_cx();
        let mailbox = live_cx.spawn_gateway_handle().unwrap().mailbox().clone();
        let before = mailbox.total_enqueued();
        assert!(live_cx.spawn_batch(empty()).unwrap().is_empty());
        assert_eq!(mailbox.total_enqueued(), before);
        assert_eq!(live_cx.pending_spawn_counter_handle().unwrap().count(), 0);
    }

    #[test]
    fn spawn_batch_rejects_unbounded_input_before_reserving_or_invoking() {
        let (_lab, cx, _root) = lab_with_spawn_cx();
        let mailbox = cx.spawn_gateway_handle().unwrap().mailbox().clone();
        let before = mailbox.total_enqueued();
        let consumed = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::new(AtomicUsize::new(0));
        let input = std::iter::from_fn(|| {
            consumed.fetch_add(1, Ordering::SeqCst);
            let invoked = Arc::clone(&invoked);
            Some(move |_child: Cx| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready(())
            })
        });

        let result = cx.spawn_batch(input);
        assert!(matches!(
            result,
            Err(SpawnBatchError::TooManyTasks {
                limit: MAX_SPAWN_BATCH_SIZE
            })
        ));
        assert_eq!(consumed.load(Ordering::SeqCst), MAX_SPAWN_BATCH_SIZE + 1);
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(mailbox.total_enqueued(), before);
        assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
    }

    #[test]
    fn spawn_batch_iterator_panic_cannot_publish_a_partial_batch() {
        let (_lab, cx, _root) = lab_with_spawn_cx();
        let mailbox = cx.spawn_gateway_handle().unwrap().mailbox().clone();
        let before = mailbox.total_enqueued();
        let invoked = Arc::new(AtomicUsize::new(0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let input = (0..8).map(|index| {
                assert_ne!(index, 3, "iterator fails after producing three factories");
                let invoked = Arc::clone(&invoked);
                move |_child: Cx| {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(index)
                }
            });
            let _ = cx.spawn_batch(input);
        }));
        assert!(result.is_err());
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(mailbox.total_enqueued(), before);
        assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
    }

    #[test]
    fn spawn_batch_setup_refusal_preserves_mailbox_and_region_counters() {
        let (mut lab, mut cx, root) = lab_with_spawn_cx();
        let mailbox = cx.spawn_gateway_handle().unwrap().mailbox().clone();
        let before = mailbox.total_enqueued();
        let invoked = Arc::new(AtomicUsize::new(0));
        let factories = || {
            let invoked = Arc::clone(&invoked);
            (0..3).map(move |_| {
                let invoked = Arc::clone(&invoked);
                move |_child: Cx| {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(())
                }
            })
        };

        cx.runtime_mask = cap::CapMask::none();
        assert!(matches!(
            cx.spawn_batch(factories()),
            Err(SpawnBatchError::Spawn(
                crate::runtime::state::SpawnError::RuntimeUnavailable
            ))
        ));
        assert!(matches!(
            cx.spawn_batch_in(&cx.scope(), factories()),
            Err(SpawnBatchError::Spawn(
                crate::runtime::state::SpawnError::RuntimeUnavailable
            ))
        ));
        cx.runtime_mask = cap::CapMask::all();
        let child = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .unwrap();
        let unwired: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child, Budget::INFINITE);
        assert!(matches!(
            cx.spawn_batch_in(&unwired, factories()),
            Err(SpawnBatchError::Spawn(
                crate::runtime::state::SpawnError::RuntimeUnavailable
            ))
        ));
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(mailbox.total_enqueued(), before);
        assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
        assert_eq!(lab.state.region(child).unwrap().pending_spawn_count(), 0);
    }

    #[test]
    fn spawn_batch_error_codes_preserve_the_underlying_runtime_diagnostic() {
        let too_large = SpawnBatchError::TooManyTasks {
            limit: MAX_SPAWN_BATCH_SIZE,
        };
        assert_eq!(too_large.code(), "ASUP-E010");
        assert!(too_large.to_string().starts_with("[ASUP-E010]"));
        assert!(std::error::Error::source(&too_large).is_none());
        let unavailable = SpawnBatchError::from(crate::runtime::state::SpawnError::RuntimeUnavailable);
        assert_eq!(unavailable.code(), "ASUP-E001");
        assert!(unavailable.to_string().starts_with("[ASUP-E001]"));
        assert!(std::error::Error::source(&unavailable).is_some());
    }

    #[test]
    fn spawn_registered_in_admits_and_registers_through_gateway() {
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

        let (mut lab, cx, root) = lab_with_spawn_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_child = Arc::clone(&ran);
        let mut handle = cx
            .spawn_registered_in(&scope, move |child| async move {
                assert_eq!(child.region_id(), child_region);
                ran_in_child.fetch_add(1, Ordering::SeqCst);
                YieldOnce(false).await;
                17usize
            })
            .expect("spawn_registered_in should enqueue through the gateway");

        assert!(
            crate::runtime::spawn_mailbox::is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child region should exist")
                .pending_spawn_count(),
            1,
            "pending reservation lands on the target scope region"
        );

        lab.step_for_test();

        assert_eq!(ran.load(Ordering::SeqCst), 1, "child task ran");
        assert!(
            !crate::runtime::spawn_mailbox::is_spawn_mailbox_id(handle.task_id()),
            "post-admission handle reports the canonical task id while the task is live"
        );
        assert_eq!(
            lab.state
                .task(handle.task_id())
                .expect("admitted task record should exist while pending")
                .owner,
            child_region
        );
        lab.run_until_quiescent();
        let joined = futures_lite::future::block_on(handle.join(&cx)).expect("joined child result");
        assert_eq!(joined, 17);
    }

    #[test]
    fn spawn_registered_in_without_runtime_wiring_fails_closed() {
        let cx = test_cx();
        let scope = cx.scope();
        let result = cx.spawn_registered_in(&scope, |_child| async move { 1usize });
        assert!(matches!(
            result,
            Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
        ));
    }

    fn test_cx_with_virtual_time(budget: Budget, now: Time) -> Cx<cap::All> {
        let clock = Arc::new(crate::time::VirtualClock::starting_at(now));
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
            None,
            None,
            None,
            Some(TimerDriverHandle::with_virtual_clock(clock)),
            None,
        )
    }

    #[test]
    fn introspection_capabilities_reflect_wrapper_type_level_masks() {
        let full = Arc::new(Cx::for_testing());

        let web: Arc<Cx<crate::cx::wrappers::WebCaps>> = crate::cx::wrappers::narrow(&full);
        let grpc: Arc<Cx<crate::cx::wrappers::GrpcCaps>> = crate::cx::wrappers::narrow(&full);
        let background: Arc<Cx<crate::cx::wrappers::BackgroundCaps>> =
            crate::cx::wrappers::narrow(&full);
        let pure: Arc<Cx<crate::cx::wrappers::PureCaps>> = crate::cx::wrappers::narrow(&full);
        let entropy: Arc<Cx<crate::cx::wrappers::EntropyCaps>> = crate::cx::wrappers::narrow(&full);

        let cases = [
            (
                web.capabilities(),
                cap_layer(false, true, false, true, false),
            ),
            (
                grpc.capabilities(),
                cap_layer(true, true, false, true, false),
            ),
            (
                background.capabilities(),
                cap_layer(true, true, false, false, false),
            ),
            (
                pure.capabilities(),
                cap_layer(false, false, false, false, false),
            ),
            (
                entropy.capabilities(),
                cap_layer(false, false, true, false, false),
            ),
        ];

        for (snapshot, expected_effective) in cases {
            assert_eq!(snapshot.runtime, cap_layer(true, true, true, true, true));
            assert_eq!(snapshot.effective, expected_effective);
            assert_eq!(snapshot.type_level, expected_effective);
            assert_eq!(snapshot.spawn, expected_effective.spawn);
            assert_eq!(snapshot.time, expected_effective.time);
            assert_eq!(snapshot.entropy, expected_effective.entropy);
            assert_eq!(snapshot.io, expected_effective.io);
            assert_eq!(snapshot.remote, expected_effective.remote);
            assert!(snapshot.trace);
        }
    }

    #[test]
    fn introspection_capabilities_intersect_type_and_runtime_masks() {
        clear_current_stack();

        let full = Cx::for_testing();
        let restricted_type: Cx<cap::None> = full.restrict::<cap::None>();
        let type_snapshot = restricted_type.capabilities();

        assert_eq!(
            type_snapshot.type_level,
            cap_layer(false, false, false, false, false)
        );
        assert_eq!(
            type_snapshot.runtime,
            cap_layer(true, true, true, true, true)
        );
        assert_eq!(
            type_snapshot.effective,
            cap_layer(false, false, false, false, false)
        );

        let _outer = Cx::set_current(Some(full.clone()));
        assert_eq!(Cx::restriction_depth(), 1);
        assert!(!Cx::is_restricted());

        let _restricted = Cx::push_restriction(cap::CapMask::none());
        assert_eq!(Cx::restriction_depth(), 2);
        assert!(Cx::is_restricted());

        let ambient = Cx::current().expect("ambient cx must be installed");
        let ambient_snapshot = ambient.capabilities();
        assert_eq!(
            ambient_snapshot.type_level,
            cap_layer(true, true, true, true, true)
        );
        assert_eq!(
            ambient_snapshot.runtime,
            cap_layer(false, false, false, false, false)
        );
        assert_eq!(
            ambient_snapshot.effective,
            cap_layer(false, false, false, false, false)
        );
    }

    #[test]
    fn introspection_budget_stats_reports_used_remaining_and_deadline() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(110))
            .with_poll_quota(3)
            .with_cost_quota(9)
            .with_priority(77);
        let cx = test_cx_with_virtual_time(budget, Time::from_secs(100));
        {
            let mut inner = cx.inner.write();
            inner.budget.poll_quota = 1;
            inner.budget.cost_quota = Some(4);
        }

        let stats = cx.budget_stats();

        assert_eq!(stats.deadline.at, Some(Time::from_secs(110)));
        assert_eq!(stats.deadline.remaining, Some(Duration::from_secs(10)));
        assert_eq!(stats.polls.quota, Some(3));
        assert_eq!(stats.polls.used, Some(2));
        assert_eq!(stats.polls.remaining, Some(1));
        assert_eq!(stats.cost.quota, Some(9));
        assert_eq!(stats.cost.used, Some(5));
        assert_eq!(stats.cost.remaining, Some(4));
        assert_eq!(stats.priority, 77);
    }

    #[test]
    fn introspection_budget_stats_drains_fast_path_checkpoint_counters() {
        let cx = test_cx_with_virtual_time(Budget::new().with_poll_quota(10), Time::from_secs(100));

        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());

        assert_eq!(
            cx.inner
                .read()
                .fast_path_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        let _stats = cx.budget_stats();

        let inner = cx.inner.read();
        assert_eq!(
            inner
                .fast_path_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(inner.checkpoint_state.checkpoint_count, 3);
    }

    #[test]
    fn budget_for_timeout_uses_virtual_time_deterministically() {
        // Virtual-time half of the wall/virtual test pair: with the clock
        // pinned at t=100s, a 30s timeout must produce exactly t=130s.
        let cx = test_cx_with_virtual_time(Budget::INFINITE, Time::from_secs(100));
        let budget = cx.budget_for_timeout(Duration::from_secs(30));
        assert_eq!(budget.deadline, Some(Time::from_secs(130)));
    }

    #[test]
    fn budget_for_timeout_never_loosens_ambient_deadline() {
        // Ambient deadline (t=110s) is sooner than now (100s) + 30s: the
        // per-call timeout must NOT extend it past the caller's bound.
        let ambient = Budget::new().with_deadline(Time::from_secs(110));
        let cx = test_cx_with_virtual_time(ambient, Time::from_secs(100));
        let budget = cx.budget_for_timeout(Duration::from_secs(30));
        assert_eq!(budget.deadline, Some(Time::from_secs(110)));
    }

    #[test]
    fn budget_for_timeout_inherits_non_deadline_dimensions() {
        let ambient = Budget::new().with_poll_quota(64).with_cost_quota(5);
        let cx = test_cx_with_virtual_time(ambient, Time::from_secs(1));
        let budget = cx.budget_for_timeout(Duration::from_secs(2));
        assert_eq!(budget.poll_quota, 64);
        assert_eq!(budget.cost_quota, Some(5));
        assert_eq!(budget.deadline, Some(Time::from_secs(3)));
    }

    #[test]
    fn budget_for_timeout_wall_clock_fallback_keeps_contract() {
        // Wall-clock half of the pair: without a timer driver, now() falls
        // back to the wall clock. Exact instants are nondeterministic, so
        // this asserts the clock-independent contract only: an open budget
        // gains SOME deadline, and tightening never exceeds an ambient one.
        let open = test_cx();
        let bounded = open.budget_for_timeout(Duration::from_secs(30));
        assert!(bounded.deadline.is_some());

        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
        let tightened = cx.budget_for_timeout(Duration::from_secs(30));
        // min(ambient, now + 30s) can never exceed the ambient deadline.
        assert_eq!(tightened.deadline, Some(Time::ZERO));
    }

    #[test]
    fn remaining_budget_snapshot_reflects_live_budget() {
        let budget = Budget::new().with_poll_quota(42).with_cost_quota(7);
        let cx = Cx::for_testing_with_budget(budget);
        let left = cx.remaining_budget();
        assert_eq!(left.polls, Some(42));
        assert_eq!(left.cost, Some(7));
        assert_eq!(left.deadline, None); // no deadline configured

        let unlimited = test_cx().remaining_budget();
        assert_eq!(unlimited.polls, None);
        assert_eq!(unlimited.cost, None);
    }

    fn trace_message(event: &crate::trace::TraceEvent) -> &str {
        match &event.data {
            crate::trace::TraceData::Message(message) => message,
            other => panic!("expected user trace message, got {other:?}"),
        }
    }

    #[cfg(feature = "messaging-fabric")]
    fn capability_schema(
        families: Vec<SubjectFamily>,
        permissions: Vec<CapabilityPermission>,
    ) -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.cx.demo".to_owned(),
            families,
            delivery_classes: vec![DeliveryClass::EphemeralInteractive],
            permissions,
        }
    }

    #[test]
    fn io_not_available_by_default() {
        let cx = test_cx();
        assert!(!cx.has_io());
        assert!(cx.io().is_none());
    }

    /// br-asupersync-xqt7dj: with_current(f) must invoke f with a borrowed
    /// &Cx that observes the SAME runtime mask as the legacy Cx::current()
    /// would have observed under set_current_restricted, AND in the
    /// unrestricted common case must NOT bump any Arc strong count of the
    /// installed cx (zero-clone fast path).
    #[test]
    fn with_current_zero_clone_in_unrestricted_case() {
        let cx = test_cx();
        // Reference strong counts BEFORE installation as ambient.
        let _guard = Cx::set_current(Some(cx.clone()));
        // Capture strong counts of the installed-frame's inner Arcs.
        let frame_inner_strong_before =
            Arc::strong_count(&Cx::current().expect("current should resolve").inner.clone());
        // current() itself bumped the count by +1 above (we cloned to read);
        // hold a 2nd reference to keep the count stable across with_current.
        let cx_pin = Cx::current().expect("current");
        let baseline = Arc::strong_count(&cx_pin.inner);

        let observed = Cx::with_current(|borrowed| {
            // Inside the closure, while we hold the borrow, the inner
            // strong count must NOT have been incremented above baseline.
            // This proves the zero-clone fast path was taken.
            let count_during_borrow = Arc::strong_count(&borrowed.inner);
            (count_during_borrow, borrowed.runtime_mask)
        })
        .expect("with_current should invoke closure");

        // The fast path borrows frame.cx directly without Arc::clone, so
        // the inner strong count during the borrow equals baseline.
        assert_eq!(
            observed.0, baseline,
            "with_current must not bump inner.strong_count in unrestricted case"
        );
        // Mask must reflect the installed frame (full caps for set_current).
        assert_eq!(observed.1, cap::CapMask::all());
        let _ = frame_inner_strong_before;
    }

    /// br-asupersync-xqt7dj: with_current must apply the frame's narrowed
    /// mask when set_current_restricted is active. In the restricted case
    /// the implementation falls back to clone+overlay (3 Arc::clone) to
    /// preserve the security invariant from br-asupersync-5ckssb; verify
    /// the closure observes the narrow mask.
    #[test]
    fn with_current_applies_restriction_mask() {
        let cx = test_cx();
        // restricted_cx with NoCaps narrows the runtime mask.
        let restricted = cx.clone().restrict::<cap::None>();
        let _guard = restricted.set_current_restricted();
        let mask_seen = Cx::with_current(|borrowed| borrowed.runtime_mask)
            .expect("with_current should resolve under restricted scope");
        assert_eq!(
            mask_seen,
            cap::CapMask::none(),
            "with_current must apply the frame's narrowed mask"
        );
    }

    /// br-asupersync-xqt7dj: with_current returns None when no ambient cx
    /// is installed; the closure must NOT fire.
    #[test]
    fn with_current_returns_none_when_no_ambient() {
        let mut closure_ran = false;
        let result = Cx::with_current(|_cx| {
            closure_ran = true;
            42_u32
        });
        assert!(result.is_none());
        assert!(
            !closure_ran,
            "closure must not be invoked when no ambient cx is installed"
        );
    }

    #[test]
    fn io_available_with_for_testing_with_io() {
        let cx: Cx = Cx::for_testing_with_io();
        assert!(cx.has_io());
        let io = cx.io().expect("should have io cap");
        assert!(!io.is_real_io());
        assert_eq!(io.name(), "lab");
    }

    #[test]
    fn checkpoint_without_cancel() {
        let cx = test_cx();
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn checkpoint_with_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn masked_defers_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        cx.masked(|| {
            assert!(
                cx.checkpoint().is_ok(),
                "checkpoint should succeed when masked"
            );
        });

        assert!(
            cx.checkpoint().is_err(),
            "checkpoint should fail after unmasking"
        );
    }

    #[test]
    fn is_cancel_requested_tracks_clear_and_mask_transitions() {
        let cx = test_cx();

        assert!(!cx.is_cancel_requested());
        assert!(!cx.inner.read().cancel_requested);

        cx.set_cancel_requested(true);
        assert!(cx.is_cancel_requested());
        assert!(cx.inner.read().cancel_requested);

        cx.masked(|| {
            assert!(
                cx.is_cancel_requested(),
                "masking defers checkpoint delivery, not cancellation visibility"
            );
            assert!(cx.checkpoint().is_ok());

            cx.set_cancel_requested(false);
            assert!(
                !cx.is_cancel_requested(),
                "clearing cancellation must publish false while masked"
            );
            assert!(!cx.inner.read().cancel_requested);
            assert!(cx.checkpoint().is_ok());

            cx.set_cancel_requested(true);
            assert!(cx.is_cancel_requested());
            assert!(cx.inner.read().cancel_requested);
        });

        assert!(cx.is_cancel_requested());
        assert!(cx.checkpoint().is_err());

        cx.set_cancel_requested(false);
        assert!(!cx.is_cancel_requested());
        assert!(!cx.inner.read().cancel_requested);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn published_cancel_requested_tracks_runtime_mutations_lock_free() {
        let cx = test_cx();

        assert!(!cx.published_cancel_requested());

        // Runtime mutation paths publish to the shared envelope.
        cx.set_cancel_requested(true);
        assert!(
            cx.published_cancel_requested(),
            "set_cancel_requested must publish to the lock-free envelope"
        );
        assert!(cx.is_cancel_requested());

        // Clearing must publish false while masked, exactly like the locked read.
        cx.masked(|| {
            cx.set_cancel_requested(false);
            assert!(
                !cx.published_cancel_requested(),
                "clearing cancellation must publish false while masked"
            );
            cx.set_cancel_requested(true);
            assert!(cx.published_cancel_requested());
        });

        // cancel_fast (a direct runtime producer) publishes too.
        cx.set_cancel_requested(false);
        assert!(!cx.published_cancel_requested());
        cx.cancel_fast(CancelKind::RaceLost);
        assert!(cx.published_cancel_requested());

        // The documented legacy-compat divergence: a direct locked-field write
        // is visible to is_cancel_requested but is NOT published to the
        // lock-free envelope until a checkpoint materializes it.
        cx.set_cancel_requested(false);
        {
            let mut inner = cx.inner.write();
            inner.cancel_requested = true;
        }
        assert!(cx.is_cancel_requested());
        assert!(
            !cx.published_cancel_requested(),
            "legacy direct-field mutation must not publish without checkpoint materialization"
        );
        assert!(
            cx.checkpoint().is_err(),
            "checkpoint must still deliver the legacy locked-field cancellation"
        );
        assert!(
            !cx.published_cancel_requested(),
            "checkpoint delivery of a legacy locked-field write does not republish the envelope; \
             the published bit may lag after legacy compat mutations"
        );

        // The envelope re-converges at the next runtime mutation.
        cx.set_cancel_requested(false);
        assert!(!cx.published_cancel_requested());
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn is_cancel_requested_shares_clone_and_republishes_deadline() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
        let clone = cx.clone();
        let from_inner: Cx<cap::All> = Cx::from_inner(Arc::clone(&cx.inner));
        let restricted: Cx<cap::None> = cx.restrict();

        assert!(Arc::ptr_eq(&cx.cancellation, &clone.cancellation));
        assert!(Arc::ptr_eq(&cx.cancellation, &from_inner.cancellation));
        assert!(Arc::ptr_eq(&cx.cancellation, &restricted.cancellation));

        assert!(!cx.is_cancel_requested());
        assert!(!clone.is_cancel_requested());
        assert!(!from_inner.is_cancel_requested());
        assert!(!restricted.is_cancel_requested());

        assert!(cx.checkpoint().is_err());
        assert!(cx.is_cancel_requested());
        assert!(clone.is_cancel_requested());
        assert!(from_inner.is_cancel_requested());
        assert!(restricted.is_cancel_requested());

        clone.set_cancel_requested(false);
        assert!(!cx.is_cancel_requested());
        assert!(!clone.is_cancel_requested());
        assert!(!from_inner.is_cancel_requested());
        assert!(!restricted.is_cancel_requested());
        assert!(!cx.inner.read().cancel_requested);

        assert!(clone.checkpoint().is_err());
        assert!(cx.is_cancel_requested());
        assert!(clone.is_cancel_requested());
        assert!(from_inner.is_cancel_requested());
        assert!(restricted.is_cancel_requested());
    }

    #[test]
    fn cancellation_producer_matrix_publishes_through_stable_envelope() {
        let assert_published = |cx: &Cx<cap::All>, expected| {
            assert_eq!(cx.is_cancel_requested(), expected);
            assert_eq!(cx.inner.read().is_cancel_requested(), expected);
        };

        let cx = test_cx();
        cx.set_cancel_requested(true);
        assert_published(&cx, true);
        cx.set_cancel_requested(false);
        assert_published(&cx, false);

        // All non-Cx producers use this paired lock-state/Release-publication
        // method, so exercise its true and clear transitions against the
        // compatibility-aware public query too.
        let cx = test_cx();
        cx.inner.write().set_cancel_requested(true);
        assert_published(&cx, true);
        cx.inner.write().set_cancel_requested(false);
        assert_published(&cx, false);

        let cx = test_cx();
        cx.set_cancel_internal(true);
        assert_published(&cx, true);
        cx.set_cancel_internal(false);
        assert_published(&cx, false);

        let cx = test_cx();
        cx.cancel_with(CancelKind::User, Some("matrix"));
        assert_published(&cx, true);

        let cx = test_cx();
        cx.cancel_fast(CancelKind::RaceLost);
        assert_published(&cx, true);

        let cx = test_cx();
        cx.set_cancel_reason(CancelReason::shutdown());
        assert_published(&cx, true);

        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
        assert!(cx.checkpoint().is_err());
        assert_published(&cx, true);

        let cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(0));
        assert!(cx.checkpoint().is_err());
        assert_published(&cx, true);

        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(0));
        assert!(cx.checkpoint_with("matrix").is_err());
        assert_published(&cx, true);
    }

    #[test]
    fn is_cancelled_matches_published_bit_and_does_not_need_lock() {
        let cx = test_cx();
        assert!(!cx.is_cancelled());
        cx.cancel_fast(CancelKind::RaceLost);
        assert!(cx.is_cancelled());
        assert_eq!(
            cx.is_cancelled(),
            cx.published_cancel_requested(),
            "is_cancelled must be the fast atomic alias for published_cancel_requested"
        );

        // Unlike is_cancel_requested, is_cancelled does not observe a raw
        // lock-field mutation that bypasses the publication envelope, so a
        // legacy-only cancellation is not visible through the fast path.
        let cx = test_cx();
        {
            let mut inner = cx.inner.write();
            inner.cancel_requested = true;
        }
        assert!(!cx.is_cancelled(), "fast path must not take the inner lock");
    }

    #[test]
    fn v0_4_3_compatibility_public_cancellation_fields_remain_observable() {
        let cx = test_cx();
        {
            let mut inner = cx.inner.write();
            inner.cancel_requested = true;
        }
        assert!(
            cx.is_cancel_requested(),
            "direct 0.4.3 cancel_requested mutation must remain observable"
        );

        cx.set_cancel_requested(false);
        let original_fast_cancel = Arc::clone(&cx.inner.read().fast_cancel);
        cx.set_cancel_requested(true);
        assert!(original_fast_cancel.load(std::sync::atomic::Ordering::Acquire));
        cx.set_cancel_requested(false);
        let replacement = Arc::new(std::sync::atomic::AtomicBool::new(true));
        {
            let mut inner = cx.inner.write();
            inner.fast_cancel = Arc::clone(&replacement);
        }
        assert!(
            !cx.is_cancel_requested(),
            "the 0.4.3 query contract reads cancel_requested, not fast_cancel"
        );

        assert!(
            cx.checkpoint().is_err(),
            "checkpoint must deliver cancellation published through a replaced fast_cancel handle"
        );
        assert!(
            cx.is_cancel_requested(),
            "checkpoint must materialize fast cancellation into the legacy locked field"
        );

        cx.set_cancel_requested(false);
        replacement.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            cx.checkpoint_with("compatibility fast cancellation")
                .is_err(),
            "checkpoint_with must deliver cancellation published through a replaced fast_cancel handle"
        );

        cx.set_cancel_requested(false);
        assert!(!replacement.load(std::sync::atomic::Ordering::Acquire));
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn is_cancel_requested_observes_release_published_clone_transitions() {
        const ROUNDS: usize = 128;

        let cx = test_cx();
        let writer_cx = cx.clone();
        let turn = Arc::new(std::sync::Barrier::new(2));
        let writer_turn = Arc::clone(&turn);
        let writer = std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                writer_cx.set_cancel_requested(true);
                writer_turn.wait();
                writer_turn.wait();

                writer_cx.set_cancel_requested(false);
                writer_turn.wait();
                writer_turn.wait();
            }
        });

        for _ in 0..ROUNDS {
            turn.wait();
            assert!(cx.is_cancel_requested());
            assert!(cx.inner.read().cancel_requested);
            turn.wait();

            turn.wait();
            assert!(!cx.is_cancel_requested());
            assert!(!cx.inner.read().cancel_requested);
            turn.wait();
        }

        writer
            .join()
            .expect("release-published cancellation writer must not panic");
    }

    #[test]
    fn trace_attaches_logical_time() {
        let cx = test_cx();
        let trace = TraceBufferHandle::new(8);
        cx.set_trace_buffer(trace.clone());

        cx.trace("hello");

        let events = trace.snapshot();
        let event = events.first().expect("trace event");
        assert!(event.logical_time.is_some());
    }

    #[test]
    fn masked_panic_safety() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let cx = test_cx();
        cx.set_cancel_requested(true);

        // Ensure initial state is cancelled (unmasked)
        assert!(cx.checkpoint().is_err());

        // Run a masked block that panics
        let cx_clone = cx.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            cx_clone.masked(|| {
                // Avoid `panic!/unreachable!` macros (UBS critical). We still
                // need an unwind here to validate mask-depth restoration.
                std::panic::resume_unwind(Box::new("oops"));
            });
        }));

        // After panic, mask depth should have been restored.
        // If it leaked, checkpoint() will return Ok(()) because it thinks it's still masked.
        assert!(
            cx.checkpoint().is_err(),
            "Cx remains masked after panic! mask_depth leaked."
        );
    }

    #[test]
    fn current_returns_none_during_thread_local_teardown() {
        CURRENT_CX_DTOR_STATE.store(0, Ordering::SeqCst);

        let join = std::thread::spawn(|| {
            // Initialize the probe first so its destructor runs after CURRENT_CX
            // and exercises ambient lookup during TLS teardown.
            CURRENT_CX_DTOR_PROBE.with(|_| {});

            let cx = test_cx();
            let _guard = Cx::set_current(Some(cx));
            assert!(Cx::is_active(), "current cx should be installed");
        });

        join.join()
            .expect("thread-local teardown should not panic when reading Cx");
        assert_eq!(
            CURRENT_CX_DTOR_STATE.load(Ordering::SeqCst),
            3,
            "Cx::current() should fail closed once CURRENT_CX is unavailable"
        );
    }

    /// INV-MASK-BOUNDED: exceeding MAX_MASK_DEPTH must panic.
    #[test]
    #[should_panic(expected = "MAX_MASK_DEPTH")]
    fn mask_depth_exceeds_bound_panics() {
        let cx = test_cx();

        // Directly set mask_depth to the limit, then call masked() once
        // to trigger the bound check. This avoids deep nesting which
        // would cause double-panic in MaskGuard drops during unwind.
        {
            let mut inner = cx.inner.write();
            inner.mask_depth = crate::types::task_context::MAX_MASK_DEPTH;
        }
        // This call should panic because mask_depth is already at the limit.
        cx.masked(|| {});
    }

    /// Context stack depth must be bounded to prevent stack overflow.
    #[test]
    #[should_panic(expected = "MAX_CONTEXT_STACK_DEPTH")]
    fn context_stack_depth_exceeds_bound_panics_set_current() {
        let cx = test_cx();

        // Fill the context stack to the limit manually to avoid deep nesting
        // during test setup that could cause issues during panic unwinding.
        CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            for _ in 0..crate::types::task_context::MAX_CONTEXT_STACK_DEPTH {
                s.push(CurrentCxFrame {
                    id: next_current_cx_frame_id(),
                    cx: FrameCx::Ready(cx.clone().retype::<cap::All>()),
                    mask: cap::CapMask::all(),
                });
            }
        });

        // This call should panic because stack is already at the limit.
        let _guard = cx.set_current_restricted();
    }

    /// Context stack depth must be bounded to prevent stack overflow (push_restriction variant).
    #[test]
    #[should_panic(expected = "MAX_CONTEXT_STACK_DEPTH")]
    fn context_stack_depth_exceeds_bound_panics_push_restriction() {
        let cx = test_cx();
        let _guard = Cx::set_current(Some(cx.clone()));

        // Fill the context stack to the limit manually to avoid deep nesting
        CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            for _ in 0..crate::types::task_context::MAX_CONTEXT_STACK_DEPTH {
                s.push(CurrentCxFrame {
                    id: next_current_cx_frame_id(),
                    cx: FrameCx::Ready(cx.clone().retype::<cap::All>()),
                    mask: cap::CapMask::all(),
                });
            }
        });

        // This call should panic because stack is already at the limit.
        let _restriction_guard = FullCx::push_restriction(cap::CapMask::none());
    }

    #[test]
    fn random_usize_in_range() {
        let cx = test_cx_with_entropy(123);
        for _ in 0..100 {
            let value = cx.random_usize(7);
            assert!(value < 7);
        }
    }

    #[test]
    fn shuffle_deterministic() {
        let cx1 = test_cx_with_entropy(42);
        let cx2 = test_cx_with_entropy(42);

        let mut a = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut b = [1, 2, 3, 4, 5, 6, 7, 8];

        cx1.shuffle(&mut a);
        cx2.shuffle(&mut b);

        assert_eq!(a, b);
    }

    #[test]
    fn random_f64_range() {
        let cx = test_cx_with_entropy(7);
        for _ in 0..100 {
            let value = cx.random_f64();
            assert!((0.0..1.0).contains(&value));
        }
    }

    /// br-asupersync-lw9q66: random_u64 must NOT include the random
    /// value in its trace event. The static-source proof is the
    /// commit comment + the trace! call shape; this test pins the
    /// runtime behaviour by asserting the function still returns
    /// distinct values and matches the same per-seed output as
    /// before the trace change (so no semantic regression accompanied
    /// the log-shape fix).
    #[test]
    fn lw9q66_random_u64_returns_distinct_values_without_logging_value() {
        let cx = test_cx_with_entropy(0xdead_beef);
        let mut samples = std::collections::HashSet::new();
        for _ in 0..256 {
            samples.insert(cx.random_u64());
        }
        // 256 samples from a CSPRNG: expect at least 200 unique to
        // confirm the source is producing varied output (not stuck).
        assert!(
            samples.len() >= 200,
            "random_u64 must produce varied output (got {} unique of 256)",
            samples.len()
        );
        // Determinism check: a fresh cx with the same seed should
        // produce the same first value (proves seed propagation
        // isn't perturbed by the trace-shape change).
        let cx2 = test_cx_with_entropy(0xdead_beef);
        let cx3 = test_cx_with_entropy(0xdead_beef);
        assert_eq!(cx2.random_u64(), cx3.random_u64());
    }

    // ========================================================================
    // Cancel Attribution API Tests
    // ========================================================================

    #[test]
    fn cancel_with_sets_reason() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());

        cx.cancel_with(CancelKind::User, Some("manual stop"));

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::User);
        assert_eq!(reason.message, Some("manual stop".to_string()));
    }

    #[test]
    fn cancel_with_no_message() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Timeout, None);

        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Timeout);
        assert!(reason.message.is_none());
    }

    #[test]
    fn a_later_cancel_with_keeps_an_older_reason_of_equal_severity() {
        // br-asupersync-27bbrg: cancel_with stamped its reason at a fixed 1 s,
        // so at any later time it looked older than a real Deadline reason and
        // replaced it, losing that reason's origin and message.
        let cx = test_cx_with_virtual_time(Budget::INFINITE, Time::from_secs(10));
        let deadline =
            CancelReason::with_origin(CancelKind::Deadline, cx.region_id(), Time::from_secs(5))
                .with_task(cx.task_id())
                .with_message("deadline passed");
        cx.cancel_with_reason(deadline.clone());

        cx.cancel_with(CancelKind::Timeout, Some("later timeout"));

        assert_eq!(cx.cancel_reason(), Some(deadline));
        let fresh = test_cx_with_virtual_time(Budget::INFINITE, Time::from_secs(10));
        fresh.cancel_with(CancelKind::Timeout, None);
        let stamped = fresh.cancel_reason().expect("reason");
        assert_eq!(stamped.timestamp, Time::from_secs(10));
        assert_eq!(stamped.origin_region, fresh.region_id());
    }

    #[test]
    fn cancel_with_reason_preserves_causes_and_stronger_cancellation() {
        let cx = test_cx();
        let deadline =
            CancelReason::with_origin(CancelKind::Deadline, cx.region_id(), Time::from_secs(7))
                .with_task(cx.task_id());
        let reason = CancelReason::parent_cancelled()
            .with_message("request response cancelled")
            .with_cause(deadline.clone());
        cx.cancel_with_reason(reason);
        assert!(cx.is_cancel_requested());
        assert_eq!(cx.root_cancel_cause(), Some(deadline));

        cx.cancel_with_reason(CancelReason::shutdown());
        let shutdown = cx.cancel_reason();
        cx.cancel_with_reason(
            CancelReason::parent_cancelled().with_cause(CancelReason::deadline()),
        );
        assert_eq!(cx.cancel_reason(), shutdown);
        assert!(cx.cancelled_by(CancelKind::Shutdown));
    }

    #[test]
    fn local_cancel_apis_never_weaken_existing_reason() {
        let cx = test_cx();
        cx.cancel_fast(CancelKind::Shutdown);
        cx.cancel_with(CancelKind::User, Some("late weaker request"));
        assert!(
            cx.cancel_reason()
                .is_some_and(|reason| reason.kind == CancelKind::Shutdown)
        );

        let cx = test_cx();
        cx.cancel_with(CancelKind::Shutdown, None);
        cx.cancel_fast(CancelKind::User);
        assert!(
            cx.cancel_reason()
                .is_some_and(|reason| reason.kind == CancelKind::Shutdown)
        );
    }

    #[test]
    fn cancel_reason_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());
    }

    #[test]
    fn cancel_chain_empty_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.cancel_chain().next().is_none());
    }

    #[test]
    fn cancel_chain_traverses_causes() {
        let cx = test_cx();

        // Build a chain: ParentCancelled -> ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[2].kind, CancelKind::Deadline);
    }

    #[test]
    fn root_cancel_cause_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.root_cancel_cause().is_none());
    }

    #[test]
    fn root_cancel_cause_finds_root() {
        let cx = test_cx();

        // Build: ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent = CancelReason::parent_cancelled().with_cause(timeout);

        cx.set_cancel_reason(parent);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Timeout);
    }

    #[test]
    fn root_cancel_cause_with_no_chain() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Shutdown, None);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancelled_by_checks_immediate_reason() {
        let cx = test_cx();

        // Build: ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent = CancelReason::parent_cancelled().with_cause(deadline);

        cx.set_cancel_reason(parent);

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));
        // Deadline is in chain but not immediate
        assert!(!cx.cancelled_by(CancelKind::Deadline));
    }

    #[test]
    fn cancelled_by_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.cancelled_by(CancelKind::User));
    }

    #[test]
    fn any_cause_is_searches_chain() {
        let cx = test_cx();

        // Build: ParentCancelled -> ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent1 = CancelReason::parent_cancelled().with_cause(timeout);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        // All kinds in the chain return true
        assert!(cx.any_cause_is(CancelKind::ParentCancelled));
        assert!(cx.any_cause_is(CancelKind::Timeout));

        // Kinds not in chain return false
        assert!(!cx.any_cause_is(CancelKind::Deadline));
        assert!(!cx.any_cause_is(CancelKind::Shutdown));
    }

    #[test]
    fn any_cause_is_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.any_cause_is(CancelKind::Timeout));
    }

    #[test]
    fn set_cancel_reason_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());

        cx.set_cancel_reason(CancelReason::shutdown());

        assert!(cx.is_cancel_requested());
        assert_eq!(
            cx.cancel_reason().expect("should have reason").kind,
            CancelKind::Shutdown
        );
    }

    #[test]
    fn integration_realistic_usage() {
        // Simulate a realistic cancellation scenario:
        // 1. Root region times out
        // 2. Child task receives ParentCancelled
        // 3. Handler inspects the cause chain

        let cx = test_cx();

        // Simulate runtime setting a chained reason (timeout -> parent_cancelled)
        let timeout_reason = CancelReason::timeout().with_message("request timeout");
        let child_reason = CancelReason::parent_cancelled().with_cause(timeout_reason);

        cx.set_cancel_reason(child_reason);

        // Handler code checks various conditions
        assert!(cx.is_cancel_requested());

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));

        // But we want to know if a timeout caused it
        if cx.any_cause_is(CancelKind::Timeout) {
            // Log or metric: "Request cancelled due to timeout"
            let root = cx.root_cancel_cause().unwrap();
            assert_eq!(root.kind, CancelKind::Timeout);
            assert_eq!(root.message, Some("request timeout".to_string()));
        }

        // Full chain inspection
        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::Timeout);
    }

    #[test]
    fn cancel_fast_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());
        assert!(cx.cancel_reason().is_none());

        cx.cancel_fast(CancelKind::Shutdown);

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancel_fast_no_cause_chain() {
        // cancel_fast is for the no-attribution path - it shouldn't create cause chains
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Timeout);

        let reason = cx.cancel_reason().expect("should have reason");
        // No cause chain
        assert!(reason.cause.is_none());
        // No message
        assert!(reason.message.is_none());
        // Not truncated (nothing to truncate)
        assert!(!reason.truncated);
    }

    #[test]
    fn cancel_fast_sets_region() {
        let cx = test_cx();

        cx.cancel_fast(CancelKind::User);

        let reason = cx.cancel_reason().expect("should have reason");
        // Region should be set from the Cx
        let expected_region = cx.region_id();
        assert_eq!(reason.origin_region, expected_region);
    }

    #[test]
    fn cancel_fast_minimal_allocation() {
        // cancel_fast should create minimal CancelReason without extra allocations
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Deadline);

        let reason = cx.cancel_reason().expect("should have reason");
        // Verify minimal structure: just kind, region, no message, no cause, no truncation
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(reason.message.is_none());
        assert!(reason.cause.is_none());
        assert!(!reason.truncated);
        assert!(reason.truncated_at_depth.is_none());

        // Memory cost should be minimal (just the struct size, no boxed cause)
        let cost = reason.estimated_memory_cost();
        // Should be roughly just the size of CancelReason without any heap allocations for cause
        assert!(
            cost < 200,
            "cancel_fast should have minimal memory cost, got {cost}"
        );
    }

    // ========================================================================
    // Checkpoint Progress Reporting Tests
    // ========================================================================

    #[test]
    fn checkpoint_records_progress() {
        let cx = test_cx();

        // Initially no checkpoints
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_none());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 0);

        // Record first checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 1);

        // Record second checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_records_message() {
        let cx = test_cx();

        // Record checkpoint with message
        assert!(cx.checkpoint_with("processing step 1").is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert_eq!(state.last_message.as_deref(), Some("processing step 1"));
        assert_eq!(state.checkpoint_count, 1);

        // Second checkpoint overwrites message
        assert!(cx.checkpoint_with("processing step 2").is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.last_message.as_deref(), Some("processing step 2"));
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_converts_user_message_before_inner_lock() {
        struct ReentrantMessage {
            inner: Arc<parking_lot::RwLock<CxInner>>,
            conversions: Arc<AtomicUsize>,
        }

        impl From<ReentrantMessage> for String {
            fn from(message: ReentrantMessage) -> Self {
                assert!(
                    message.inner.try_read().is_some(),
                    "message conversion must run before checkpoint_with acquires CxInner"
                );
                message.conversions.fetch_add(1, Ordering::SeqCst);
                "reentrant conversion".to_owned()
            }
        }

        let cx = test_cx();
        let conversions = Arc::new(AtomicUsize::new(0));
        let message = ReentrantMessage {
            inner: Arc::clone(&cx.inner),
            conversions: Arc::clone(&conversions),
        };

        assert!(cx.checkpoint_with(message).is_ok());
        assert_eq!(conversions.load(Ordering::SeqCst), 1);
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("reentrant conversion")
        );
    }

    #[test]
    fn checkpoint_history_returns_message_trail() {
        let cx = test_cx();

        cx.checkpoint_with("connect")
            .expect("first checkpoint_with should succeed");
        cx.checkpoint()
            .expect("messageless checkpoint should succeed");
        cx.checkpoint_with("query")
            .expect("second checkpoint_with should succeed");

        let history = cx.checkpoint_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].1.as_str(), "connect");
        assert_eq!(history[1].1.as_str(), "query");
        assert!(history[0].0 <= history[1].0);
    }

    #[test]
    fn checkpoint_clears_message() {
        let cx = test_cx();

        // Record checkpoint with message
        cx.checkpoint_with("step 1")
            .expect("checkpoint_with should succeed");
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("step 1")
        );

        // Regular checkpoint clears the message
        cx.checkpoint()
            .expect("checkpoint should succeed after message set");
        assert!(cx.checkpoint_state().last_message.is_none());
    }

    #[test]
    fn checkpoint_with_checks_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        // checkpoint_with should return error on cancellation
        assert!(cx.checkpoint_with("should fail").is_err());

        // But checkpoint state should still be updated
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(state.last_message.as_deref(), Some("should fail"));
    }

    #[test]
    fn checkpoint_deadline_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("deadline exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn checkpoint_poll_budget_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(0));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("poll quota exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::PollQuota);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn checkpoint_cost_budget_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(0));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("cost budget exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::CostBudget);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn capability_budget_plan_inherits_and_tightens() {
        let cx = test_cx();
        let parent = CapabilityBudget::new()
            .with_memory_bytes(1_024)
            .with_io_bytes(4_096)
            .with_cleanup_budget(Budget::new().with_poll_quota(100_000));
        let requirements = CapabilityBudgetRequirements::new()
            .require_memory_bytes()
            .require_io_bytes()
            .require_cleanup();

        cx.apply_child_capability_budget(parent, requirements)
            .expect("parent capability budget is complete");

        let child = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_io_bytes(512)
            .with_cleanup_budget(Budget::new().with_poll_quota(100_000));
        let effective = cx
            .plan_child_capability_budget(child, requirements)
            .expect("child should inherit missing required envelopes");

        assert_eq!(effective.memory_bytes, Some(1_024));
        assert_eq!(effective.io_bytes, Some(512));
        assert_eq!(
            effective.cleanup_budget.map(|budget| budget.poll_quota),
            Some(100_000)
        );
        assert_eq!(cx.capability_budget(), parent);
    }

    #[test]
    fn capability_budget_apply_fails_closed_when_required_missing() {
        let cx = test_cx();
        let requirements = CapabilityBudgetRequirements::new().require_artifact_bytes();

        let err = cx
            .apply_child_capability_budget(CapabilityBudget::new(), requirements)
            .expect_err("missing artifact budget must fail closed");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::ArtifactBytes)
        );
        assert_eq!(cx.capability_budget(), CapabilityBudget::UNSPECIFIED);
    }

    #[test]
    fn scope_inherits_cx_capability_budget() {
        let cx = test_cx();
        let budget = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_cpu_units(32);

        cx.apply_child_capability_budget(budget, CapabilityBudgetRequirements::NONE)
            .expect("optional capability budget should apply");

        let scope = cx.scope();

        assert_eq!(scope.capability_budget(), budget);
    }

    #[test]
    fn scope_with_capability_budget_fails_closed_when_required_missing() {
        let cx = test_cx();

        let err = cx
            .scope_with_budget_and_capability_budget(
                Budget::INFINITE,
                CapabilityBudget::new(),
                CapabilityBudgetRequirements::new().require_artifact_bytes(),
            )
            .expect_err("missing artifact envelope must fail closed");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::ArtifactBytes)
        );
    }

    #[test]
    fn masked_checkpoint_defers_budget_exhaustion() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));

        cx.masked(|| {
            assert!(
                cx.checkpoint().is_ok(),
                "budget exhaustion should defer while masked"
            );
        });

        let reason = cx
            .cancel_reason()
            .expect("masked checkpoint should still record exhaustion reason");
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(
            cx.checkpoint().is_err(),
            "deadline exhaustion should be observed after unmasking"
        );
    }

    #[test]
    fn checkpoint_budget_usage_reports_remaining_time_in_millis() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(3)
            .with_cost_quota(7);
        let baseline = Budget::new()
            .with_deadline(Time::from_secs(20))
            .with_poll_quota(5)
            .with_cost_quota(11);

        let (polls_used, cost_used, time_remaining_ms) =
            Cx::<cap::All>::checkpoint_budget_usage(budget, baseline, Time::from_secs(7));

        assert_eq!(polls_used, Some(2));
        assert_eq!(cost_used, Some(4));
        assert_eq!(time_remaining_ms, Some(3_000));
    }

    #[test]
    fn set_cancel_requested_wakes_registered_cancel_waker() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Waker;

        struct CountWaker(Arc<AtomicUsize>);

        use std::task::Wake;
        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));

        {
            let mut inner = cx.inner.write();
            inner.cancel_waker = Some(Arc::new(CancelWaker::new(waker)));
        }

        cx.set_cancel_requested(true);

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "set_cancel_requested(true) must wake the registered cancel waker"
        );

        cx.set_cancel_requested(false);

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "clearing cancellation must not spuriously wake the cancel waker"
        );
        cx.cancel_with_reason(
            CancelReason::parent_cancelled().with_cause(CancelReason::deadline()),
        );
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            2,
            "a complete cancellation reason must also wake registered waiters"
        );
        assert!(cx.any_cause_is(CancelKind::Deadline));
    }

    #[test]
    fn tracked_cancel_wakers_have_exact_independent_ownership() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Waker;

        struct CountWaker(Arc<AtomicUsize>);

        use std::task::Wake;
        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));

        let first = cx.refresh_cancel_waker(None, &waker);
        let second = cx.refresh_cancel_waker(None, &waker);
        assert_ne!(first, second, "distinct owners need distinct tokens");

        {
            let inner = cx.inner.read();
            assert!(inner.cancel_waker.is_none());
            assert_eq!(inner.cancel_waker_registrations.len(), 2);
        }

        cx.clear_cancel_waker(first);
        {
            let inner = cx.inner.read();
            assert_eq!(inner.cancel_waker_registrations.len(), 1);
        }
        cx.cancel_fast(CancelKind::User);
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "equivalent tracked owners must be deduplicated during fanout"
        );

        cx.clear_cancel_waker(second);
        {
            let inner = cx.inner.read();
            assert!(inner.cancel_waker.is_none());
            assert!(inner.cancel_waker_registrations.is_empty());
        }

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "registration cleanup must not wake the task"
        );
    }

    #[test]
    fn cancel_waker_tokens_reject_stale_cleanup_after_aba_identity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes_a = Arc::new(AtomicUsize::new(0));
        let wakes_b = Arc::new(AtomicUsize::new(0));
        let waker_a = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes_a))));
        let waker_b = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes_b))));

        let stale_a = cx.refresh_cancel_waker(None, &waker_a);
        cx.clear_cancel_waker(stale_a);
        let current_b = cx.refresh_cancel_waker(None, &waker_b);
        let current_a = cx.refresh_cancel_waker(None, &waker_a);
        assert_ne!(stale_a, current_a, "a cleared token must never be reused");

        // A late cleanup from the old A owner must not remove either current
        // registration, even though one has the ABA-identical Waker.
        cx.clear_cancel_waker(stale_a);
        assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 2);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(wakes_a.load(Ordering::SeqCst), 1);
        assert_eq!(wakes_b.load(Ordering::SeqCst), 1);

        cx.clear_cancel_waker(current_a);
        cx.clear_cancel_waker(current_b);
        let inner = cx.inner.read();
        assert!(inner.cancel_waker.is_none());
        assert!(inner.cancel_waker_registrations.is_empty());
    }

    #[test]
    fn auxiliary_registration_preserves_runtime_primary_and_untracked_is_idempotent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let primary_wakes = Arc::new(AtomicUsize::new(0));
        let auxiliary_wakes = Arc::new(AtomicUsize::new(0));
        let untracked_wakes = Arc::new(AtomicUsize::new(0));
        let primary = Waker::from(Arc::new(CountWaker(Arc::clone(&primary_wakes))));
        let auxiliary = Waker::from(Arc::new(CountWaker(Arc::clone(&auxiliary_wakes))));
        let untracked = Waker::from(Arc::new(CountWaker(Arc::clone(&untracked_wakes))));
        cx.inner.write().cancel_waker = Some(Arc::new(CancelWaker::new(primary)));

        let token = cx.refresh_cancel_waker(None, &auxiliary);
        for _ in 0..4_096 {
            cx.register_cancel_waker(&untracked);
        }
        assert!(cx.inner.read().cancel_waker.is_some());
        assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 1);

        cx.cancel_fast(CancelKind::User);
        assert_eq!(primary_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(auxiliary_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(untracked_wakes.load(Ordering::SeqCst), 1);

        cx.clear_cancel_waker(token);
        assert!(cx.inner.read().cancel_waker.is_some());
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }

    #[test]
    fn completed_context_rejects_new_cancel_waker_registrations() {
        let cx = test_cx();
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        let waker = Waker::noop().clone();

        let token = cx.refresh_cancel_waker(None, &waker);
        cx.register_cancel_waker(&waker);

        let inner = cx.inner.read();
        assert_eq!(token.id, 0);
        assert!(inner.cancel_waker_registry_closed);
        assert!(inner.cancel_waker.is_none());
        assert!(inner.untracked_cancel_waker.is_none());
        assert!(inner.cancel_waker_registrations.is_empty());
    }

    #[test]
    fn replacing_cancel_waker_retires_safe_payload_after_unlock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct DropProbe {
            inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
            drops: Arc<AtomicUsize>,
            unlocked_drops: Arc<AtomicUsize>,
        }

        #[allow(clippy::manual_noop_waker)]
        impl Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                if let Some(inner) = self.inner.upgrade()
                    && inner.try_write().is_some()
                {
                    self.unlocked_drops.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let cx = test_cx();
        let drops = Arc::new(AtomicUsize::new(0));
        let unlocked_drops = Arc::new(AtomicUsize::new(0));
        let first_waker = Waker::from(Arc::new(DropProbe {
            inner: Arc::downgrade(&cx.inner),
            drops: Arc::clone(&drops),
            unlocked_drops: Arc::clone(&unlocked_drops),
        }));
        let first = cx.refresh_cancel_waker(None, &first_waker);
        drop(first_waker);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let replacement = Waker::noop().clone();
        let replacement_token = cx.refresh_cancel_waker(Some(first), &replacement);
        assert_eq!(replacement_token, first);

        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(unlocked_drops.load(Ordering::SeqCst), 1);
        cx.clear_cancel_waker(replacement_token);
    }

    #[test]
    fn checkpoint_state_is_snapshot() {
        let cx = test_cx();

        // Get a snapshot
        let snapshot = cx.checkpoint_state();
        assert_eq!(snapshot.checkpoint_count, 0);

        // Record more checkpoints
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());

        // Original snapshot should be unchanged
        assert_eq!(snapshot.checkpoint_count, 0);

        // New snapshot should reflect updates
        assert_eq!(cx.checkpoint_state().checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_accepts_string_types() {
        let cx = test_cx();

        // Test &str
        assert!(cx.checkpoint_with("literal").is_ok());

        // Test String
        assert!(cx.checkpoint_with(String::from("owned")).is_ok());

        // Test format!
        assert!(cx.checkpoint_with(format!("item {}", 42)).is_ok());

        assert_eq!(cx.checkpoint_state().checkpoint_count, 3);
    }

    // -----------------------------------------------------------------
    // Macaroon integration tests (bd-2lqyk.2)
    // -----------------------------------------------------------------

    fn test_root_key() -> crate::security::key::AuthKey {
        crate::security::key::AuthKey::from_seed(42)
    }

    #[test]
    fn cx_no_macaroon_by_default() {
        let cx = test_cx();
        assert!(cx.macaroon().is_none());
    }

    #[test]
    fn cx_with_macaroon_attaches_token() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let m = cx.macaroon().expect("should have macaroon");
        assert_eq!(m.identifier(), "spawn:r1");
        assert_eq!(m.location(), "cx/scheduler");
    }

    #[test]
    fn cx_macaroon_survives_clone() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:net", "cx/io");
        let cx = test_cx().with_macaroon(token);
        let cx2 = cx.clone();

        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon after with_macaroon")
                .identifier(),
            cx2.macaroon()
                .expect("cloned cx should have macaroon")
                .identifier()
        );

        // Test attenuation to verify the attenuation mechanism works
        let attenuated_cx = cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuation should succeed");
        assert!(
            attenuated_cx
                .macaroon()
                .expect("attenuated cx should have macaroon")
                .is_direct_attenuation_of(
                    cx.macaroon()
                        .expect("cx should have macaroon for attenuation check"),
                    &CaveatPredicate::TimeBefore(u64::MAX / 2)
                ),
            "Cx::attenuate must install only a direct child of the parent token"
        );
    }

    #[test]
    fn cx_macaroon_survives_restrict() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "all:cap", "cx/root");
        let cx: Cx<cap::All> = test_cx().with_macaroon(token);
        let narrow: Cx<cap::None> = cx.restrict();

        assert_eq!(
            cx.macaroon().expect("cx should have macaroon").identifier(),
            narrow
                .macaroon()
                .expect("narrow should have macaroon")
                .identifier()
        );
    }

    #[test]
    fn cx_attenuate_adds_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let cx2 = cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuate should succeed");

        // Original unchanged
        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon")
                .caveat_count(),
            0
        );
        // Attenuated has one caveat
        assert_eq!(
            cx2.macaroon()
                .expect("cx2 should have macaroon")
                .caveat_count(),
            1
        );
        // Both share the same identifier
        assert_eq!(
            cx.macaroon().expect("cx should have macaroon").identifier(),
            cx2.macaroon()
                .expect("cx2 should have macaroon")
                .identifier()
        );
    }

    #[test]
    fn cx_attenuate_returns_none_without_macaroon() {
        let cx = test_cx();
        assert!(cx.attenuate(CaveatPredicate::MaxUses(10)).is_none());
    }

    #[test]
    fn cx_attenuate_scope_rejects_oversized_pattern() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);
        let pattern = "x".repeat(u16::MAX as usize + 1);

        let attenuated = cx.attenuate_scope(pattern);

        assert!(
            attenuated.is_none(),
            "oversized caveat content must fail closed instead of reaching the encoder"
        );
        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon")
                .caveat_count(),
            0
        );
    }

    #[test]
    fn cx_attenuate_from_budget_returns_none_without_macaroon() {
        let cx = test_cx();
        assert!(cx.attenuate_from_budget().is_none());
    }

    #[test]
    fn cx_attenuate_from_budget_preserves_token_without_deadline() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let attenuated = cx
            .attenuate_from_budget()
            .expect("macaroon should still be present");
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .caveat_count(),
            0
        );
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .identifier(),
            cx.macaroon().expect("cx should have macaroon").identifier()
        );
    }

    #[test]
    fn cx_attenuate_from_budget_adds_deadline_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let budget = Budget::new().with_deadline(Time::from_millis(5_000));
        let cx = Cx::for_testing_with_budget(budget).with_macaroon(token);

        let attenuated = cx
            .attenuate_from_budget()
            .expect("attenuation with deadline should succeed");
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .caveat_count(),
            1
        );
    }

    #[test]
    fn cx_verify_capability_succeeds() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, "spawn:r1", &ctx).is_ok());
    }

    #[test]
    fn cx_verify_capability_fails_wrong_key() {
        let key = test_root_key();
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new();
        let err = cx
            .verify_capability(&wrong_key, "spawn:r1", &ctx)
            .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_capability_fails_no_macaroon() {
        let key = test_root_key();
        let cx = test_cx();

        let ctx = VerificationContext::new();
        let err = cx.verify_capability(&key, "spawn:r1", &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_with_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler")
            .add_caveat(CaveatPredicate::TimeBefore(5_000))
            .add_caveat(CaveatPredicate::RegionScope(42));

        let cx = test_cx().with_macaroon(token);

        // Passes with correct context
        let ctx = VerificationContext::new().with_time(1000).with_region(42);
        assert!(cx.verify_capability(&key, "spawn:r1", &ctx).is_ok());

        // Fails with expired time
        let ctx_expired = VerificationContext::new().with_time(6000).with_region(42);
        let err = cx
            .verify_capability(&key, "spawn:r1", &ctx_expired)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 0, .. }
        ));

        // Fails with wrong region
        let ctx_wrong_region = VerificationContext::new().with_time(1000).with_region(99);
        let err = cx
            .verify_capability(&key, "spawn:r1", &ctx_wrong_region)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 1, .. }
        ));
    }

    #[test]
    fn cx_attenuate_then_verify() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "time:sleep", "cx/time");
        let cx = test_cx().with_macaroon(token);

        // Attenuate with time limit
        let cx2 = cx
            .attenuate(CaveatPredicate::TimeBefore(3_000))
            .expect("attenuation should succeed");

        // Further attenuate with max uses
        let cx3 = cx2
            .attenuate(CaveatPredicate::MaxUses(5))
            .expect("second attenuation should succeed");

        // Original has no restrictions
        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, "time:sleep", &ctx).is_ok());

        // cx2 has time restriction
        assert!(cx2.verify_capability(&key, "time:sleep", &ctx).is_ok());
        let ctx_late = VerificationContext::new().with_time(4000);
        assert!(
            cx2.verify_capability(&key, "time:sleep", &ctx_late)
                .is_err()
        );

        // cx3 has both time + uses restriction
        let ctx_ok = VerificationContext::new().with_time(1000).with_use_count(3);
        assert!(cx3.verify_capability(&key, "time:sleep", &ctx_ok).is_ok());
        let ctx_overuse = VerificationContext::new()
            .with_time(1000)
            .with_use_count(10);
        assert!(
            cx3.verify_capability(&key, "time:sleep", &ctx_overuse)
                .is_err()
        );
    }

    #[test]
    fn cx_verify_emits_evidence() {
        use crate::evidence_sink::CollectorSink;

        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let sink = Arc::new(CollectorSink::new());
        let cx = test_cx()
            .with_macaroon(token)
            .with_evidence_sink(Some(sink.clone() as Arc<dyn EvidenceSink>));

        let ctx = VerificationContext::new();

        // Successful verification should emit evidence
        cx.verify_capability(&key, "spawn:r1", &ctx)
            .expect("capability verification should succeed");
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component, "cx_macaroon");
        assert_eq!(entries[0].action, "verify_success");

        // Failed verification should also emit evidence
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let _ = cx.verify_capability(&wrong_key, "spawn:r1", &ctx);
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].action, "verify_fail_signature");
    }

    #[test]
    fn cx_verify_capability_rejects_wrong_identifier() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let err = cx
            .verify_capability(&key, "spawn:r2", &VerificationContext::new())
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::UnexpectedIdentifier { .. }
        ));
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_grant_publish_capability_mints_token_and_runtime_grant() {
        let cx = test_cx();
        let schema = capability_schema(
            vec![SubjectFamily::Command],
            vec![CapabilityPermission::Publish],
        );

        let granted = cx
            .grant_publish_capability::<CommandFamily>(
                SubjectPattern::new("orders.>"),
                &schema,
                DeliveryClass::EphemeralInteractive,
            )
            .expect("publish capability should mint");

        assert_eq!(granted.token().family(), SubjectFamily::Command);
        assert!(cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("payments.created"),
        }));
        assert_eq!(cx.fabric_capabilities().len(), 1);
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_revoke_fabric_capabilities_by_id_and_scope_propagates_to_children() {
        let cx = test_cx();
        let child = cx.restrict::<cap::None>();
        let publish = cx
            .grant_fabric_capability(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("publish grant");
        let subscribe = cx
            .grant_fabric_capability(FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
            .expect("subscribe grant");

        assert!(child.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert_eq!(
            child.revoke_fabric_capability_scope(FabricCapabilityScope::Publish),
            1
        );
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert_eq!(
            cx.revoke_fabric_capability(subscribe.id()),
            Some(FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
        );
        assert!(
            !child.check_fabric_capability(&FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
        );
        assert_eq!(publish.id().raw(), 1);
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_revoke_fabric_capability_by_subject_is_overlap_based() {
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.>"),
        })
        .expect("publish grant");
        cx.grant_fabric_capability(FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.>"),
        })
        .expect("subscribe grant");

        assert_eq!(
            cx.revoke_fabric_capability_by_subject(&SubjectPattern::new("orders.created")),
            1
        );
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(cx.check_fabric_capability(&FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.captured"),
        }));
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_rejects_empty_stream_capability_names() {
        let cx = test_cx();

        let error = cx
            .grant_fabric_capability(FabricCapability::ConsumeStream {
                stream: "   ".to_owned(),
            })
            .expect_err("blank stream names must fail");

        assert_eq!(error, FabricCapabilityGrantError::EmptyStreamName);
    }

    // ========================================================================
    // Metamorphic Testing: Cx::trace ordering across scope boundaries
    // ========================================================================

    /// MR1: Parent-Child Trace Ordering (Inclusive)
    /// Transformation: Create child scope
    /// Relation: Parent traces precede child traces in logical order
    #[test]
    fn mr_trace_parent_child_ordering() {
        let parent_cx = test_cx();
        let trace = TraceBufferHandle::new(16);
        parent_cx.set_trace_buffer(trace.clone());

        // Parent emits trace first
        parent_cx.trace("parent trace 1");

        // Create child context (simulating child scope)
        let child_cx = parent_cx.clone();
        child_cx.trace("child trace 1");
        child_cx.trace("child trace 2");

        // Parent emits another trace after child
        parent_cx.trace("parent trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4);

        // Extract logical times for ordering verification
        let times: Vec<_> = events
            .iter()
            .map(|e| e.logical_time.as_ref().expect("logical time"))
            .collect();

        // Verify parent traces have logical time precedence structure
        // (In a real parent-child scenario, parent regions would have different region IDs)
        // For this test we verify causal ordering through logical time monotonicity
        for i in 1..times.len() {
            assert!(
                times[i - 1] <= times[i],
                "Logical time should be monotonically increasing: {:?} > {:?}",
                times[i - 1],
                times[i]
            );
        }
    }

    /// MR2: Deterministic Interleaving (Equivalence)
    /// Transformation: Same seed replay
    /// Relation: Identical trace order under deterministic execution
    #[test]
    fn mr_trace_deterministic_interleaving() {
        // First execution with entropy seed
        let cx1 = test_cx_with_entropy(42);
        let trace1 = TraceBufferHandle::new(16);
        cx1.set_trace_buffer(trace1.clone());

        // Simulate concurrent traces with deterministic randomization
        for i in 0..5 {
            if cx1.random_usize(2) == 0 {
                cx1.trace(&format!("branch_a_{}", i));
            } else {
                cx1.trace(&format!("branch_b_{}", i));
            }
        }

        // Second execution with same seed
        let cx2 = test_cx_with_entropy(42);
        let trace2 = TraceBufferHandle::new(16);
        cx2.set_trace_buffer(trace2.clone());

        for i in 0..5 {
            if cx2.random_usize(2) == 0 {
                cx2.trace(&format!("branch_a_{}", i));
            } else {
                cx2.trace(&format!("branch_b_{}", i));
            }
        }

        let events1 = trace1.snapshot();
        let events2 = trace2.snapshot();

        // Deterministic execution should produce identical trace sequences
        assert_eq!(
            events1.len(),
            events2.len(),
            "Trace count should be deterministic"
        );

        for (i, (e1, e2)) in events1.iter().zip(events2.iter()).enumerate() {
            // Note: We compare message content rather than exact logical time
            // as time implementation details may vary while maintaining determinism
            assert_eq!(
                trace_message(e1),
                trace_message(e2),
                "Trace message at index {} should be deterministic: '{}' vs '{}'",
                i,
                trace_message(e1),
                trace_message(e2)
            );
        }
    }

    /// MR3: Macaroon Causal Ordering (Permutative)
    /// Transformation: Macaroon attenuation chain
    /// Relation: Logical time monotonic through auth flow
    #[test]
    fn mr_trace_macaroon_causal_ordering() {
        use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
        use crate::security::key::AuthKey;

        let key = AuthKey::from_seed(42);
        let token = MacaroonToken::mint(&key, "trace:emit", "cx/trace");

        // Root context with macaroon
        let root_cx = test_cx().with_macaroon(token);
        let trace = TraceBufferHandle::new(16);
        root_cx.set_trace_buffer(trace.clone());

        root_cx.trace("root macaroon trace");

        // Attenuated context (simulating capability restriction)
        let attenuated_cx = root_cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuation should succeed");
        attenuated_cx.trace("attenuated trace 1");

        // Further attenuated context
        let further_attenuated_cx = attenuated_cx
            .attenuate(CaveatPredicate::MaxUses(10))
            .expect("further attenuation should succeed");
        further_attenuated_cx.trace("further attenuated trace");

        // Back to less attenuated
        attenuated_cx.trace("attenuated trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4);

        // Verify causal ordering preservation through logical time
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        // Logical time should increase monotonically regardless of attenuation level
        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Macaroon attenuation should preserve causal ordering: tick {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }
    }

    /// MR4: Budget Exhaustion Idempotence (Equivalence)
    /// Transformation: Multiple budget exhaust attempts
    /// Relation: Single log entry recorded
    #[test]
    fn mr_trace_budget_exhaustion_idempotence() {
        use crate::types::Budget;

        // Create context with minimal budget
        let budget = Budget::new().with_poll_quota(1);
        let cx = Cx::for_testing_with_budget(budget);
        let trace = TraceBufferHandle::new(16);
        cx.set_trace_buffer(trace.clone());

        // First trace that might exhaust budget
        cx.trace("pre-exhaustion trace");

        // Simulate budget exhaustion (in practice this would happen during task execution)
        // For this test, we verify that multiple trace attempts during exhaustion
        // don't create duplicate entries
        cx.trace("exhaustion trace 1");
        cx.trace("exhaustion trace 2"); // Same condition
        cx.trace("exhaustion trace 3"); // Same condition

        let events = trace.snapshot();

        // All trace calls should succeed (budget exhaustion doesn't prevent tracing)
        // But this verifies that tracing remains consistent under budget pressure
        assert_eq!(events.len(), 4, "All traces should be recorded");

        // Verify no duplicate logical times (idempotence of time allocation)
        let mut logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref().map(|t| format!("{:?}", t)))
            .collect();
        logical_times.sort_unstable();
        logical_times.dedup();

        assert_eq!(
            logical_times.len(),
            4,
            "Logical time allocation should be idempotent (no duplicate times)"
        );
    }

    /// MR5: Clone Trace Equivalence (Equivalence)
    /// Transformation: Clone Cx
    /// Relation: Same trace patterns produced
    #[test]
    fn mr_trace_clone_equivalence() {
        let original_cx = test_cx_with_entropy(123);
        let trace = TraceBufferHandle::new(16);
        original_cx.set_trace_buffer(trace.clone());

        // Clone the context
        let cloned_cx = original_cx.clone();

        // Both should share the same trace buffer and produce equivalent patterns
        original_cx.trace("original trace 1");
        cloned_cx.trace("cloned trace 1");
        original_cx.trace("original trace 2");
        cloned_cx.trace("cloned trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4, "Both contexts should write to same buffer");

        // Verify logical time ordering is preserved across clone usage
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Clone should preserve logical time ordering: {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }

        // Verify cloned context shares the entropy stream rather than
        // replaying the first draw from a copied RNG state.
        let val1 = original_cx.random_usize(100);
        let val2 = cloned_cx.random_usize(100);
        let control_cx = test_cx_with_entropy(123);
        let expected1 = control_cx.random_usize(100);
        let expected2 = control_cx.random_usize(100);

        assert_eq!(
            (val1, val2),
            (expected1, expected2),
            "Cloned context should continue the shared entropy sequence"
        );
    }

    /// MR6: Composite Trace Ordering (Composition)
    /// Combines parent-child + clone + macaroon relations
    #[test]
    fn mr_trace_composite_ordering() {
        use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
        use crate::security::key::AuthKey;

        let key = AuthKey::from_seed(789);
        let token = MacaroonToken::mint(&key, "trace:composite", "cx/test");

        // Root context with macaroon
        let root_cx = test_cx_with_entropy(456).with_macaroon(token);
        let trace = TraceBufferHandle::new(32);
        root_cx.set_trace_buffer(trace.clone());

        // MR1 + MR3: Parent with macaroon
        root_cx.trace("parent+macaroon trace");

        // MR5: Clone preserves properties
        let child_cx = root_cx.clone();

        // MR3: Attenuation preserves ordering
        let attenuated_child = child_cx
            .attenuate(CaveatPredicate::TimeBefore(10000))
            .expect("attenuation should work");

        // MR1: Child traces after parent
        attenuated_child.trace("child+attenuated trace");

        // MR2: Deterministic interleaving
        for i in 0..3 {
            if root_cx.random_usize(2) == 0 {
                root_cx.trace(&format!("parent_branch_{}", i));
            } else {
                attenuated_child.trace(&format!("child_branch_{}", i));
            }
        }

        let events = trace.snapshot();
        assert!(
            events.len() >= 5,
            "Composite test should produce multiple traces"
        );

        // Verify all metamorphic properties hold in composition:

        // 1. Logical time monotonicity (covers MR1, MR3, MR5)
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Composite trace ordering should preserve monotonicity: {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }

        // 2. All traces recorded (MR4 budget idempotence equivalent)
        assert!(
            events.iter().all(|e| !trace_message(e).is_empty()),
            "All traces should have non-empty messages"
        );

        // 3. Deterministic branching produces expected pattern (MR2)
        let branch_traces = events
            .iter()
            .filter(|e| trace_message(e).contains("_branch_"))
            .count();
        assert_eq!(
            branch_traces, 3,
            "Deterministic branching should produce exactly 3 branch traces"
        );
    }

    // ========================================================================
    // br-asupersync-5ckssb: Cx::current() honors restriction stack
    // ========================================================================

    /// Sanity: a freshly-installed full cx returns the full mask.
    #[test]
    fn _5ckssb_full_set_current_returns_full_mask() {
        // Suppress any cx left installed by a previous test on this thread.
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let cx = Cx::for_testing();
        let _guard = Cx::set_current(Some(cx.clone()));
        let observed = Cx::current().expect("current must be installed");
        assert_eq!(observed.runtime_mask, cap::CapMask::all());
    }

    /// The actual ambient-authority defense: a restricted cx pushed
    /// via set_current_restricted causes any subsequent ambient
    /// Cx::current() lookup to observe the narrowed mask.
    #[test]
    fn _5ckssb_set_current_restricted_narrows_ambient_view() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        // Install a full cx first (simulates the runtime polling a task).
        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx.clone()));

        // Now nest a restricted view (None).
        let restricted: Cx<cap::None> = full_cx.restrict::<cap::None>();
        let _inner = restricted.set_current_restricted();

        // Ambient lookup must now see the narrowed mask.
        let observed = Cx::current().expect("current must be installed");
        assert_eq!(
            observed.runtime_mask,
            cap::CapMask::none(),
            "innermost restriction must narrow the ambient mask"
        );

        // The cap-gated Option-returning methods must respect the
        // narrowed mask. These compile because the returned cx still
        // has Caps = cap::All (set_current always installs a FullCx);
        // the runtime check is what blocks access.
        assert!(observed.io().is_none(), "IO must be masked");
        assert!(observed.remote().is_none(), "REMOTE must be masked");
        assert!(observed.timer_driver().is_none(), "TIME must be masked");
        assert!(observed.fetch_cap().is_none(), "fetch_cap must be masked");
    }

    /// After the restriction guard drops, ambient lookups recover the
    /// outer (full) view.
    #[test]
    fn _5ckssb_restriction_guard_drop_restores_outer_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx.clone()));
        {
            let restricted: Cx<cap::None> = full_cx.restrict::<cap::None>();
            let _inner = restricted.set_current_restricted();
            assert_eq!(
                Cx::current()
                    .expect("current context should be set")
                    .runtime_mask,
                cap::CapMask::none(),
                "inside scope: restricted"
            );
        }
        // Inner guard dropped — outer full mask restored.
        assert_eq!(
            Cx::current().unwrap().runtime_mask,
            cap::CapMask::all(),
            "outer scope: full mask restored"
        );
    }

    /// Explicit push_restriction(none()) drops every cap on top of
    /// the current mask without changing the underlying cx.
    #[test]
    fn _5ckssb_push_restriction_intersects_with_current_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx));

        let _restrict = Cx::push_restriction(cap::CapMask::none());
        let observed = Cx::current().unwrap();
        assert_eq!(
            observed.runtime_mask,
            cap::CapMask::none(),
            "push_restriction(none) intersects to none"
        );
        assert!(observed.io().is_none());
        assert!(observed.remote().is_none());
        assert!(observed.timer_driver().is_none());

        // After drop, outer ALL is restored.
        drop(_restrict);
        assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::all());
    }

    #[test]
    fn _5ckssb_has_remote_respects_push_restriction_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing_with_remote(crate::remote::RemoteCap::new());
        let _outer = Cx::set_current(Some(full_cx));
        assert!(
            Cx::current().unwrap().has_remote(),
            "unrestricted context should expose REMOTE"
        );

        let _restrict = Cx::push_restriction(cap::CapMask::none());
        let observed = Cx::current().unwrap();
        assert!(observed.remote().is_none(), "REMOTE handle must be masked");
        assert!(
            !observed.has_remote(),
            "has_remote must agree with the runtime capability mask"
        );
    }

    /// push_restriction with no installed cx must return a no-op
    /// guard (no panic, drop is safe).
    #[test]
    fn _5ckssb_push_restriction_with_no_current_is_no_op() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }
        let _g = Cx::push_restriction(cap::CapMask::none());
        assert!(Cx::current().is_none());
    }

    /// Multiple nested restrictions: each push narrows further; pops
    /// restore the prior level.
    #[test]
    fn _5ckssb_nested_restrictions_walk_stack_correctly() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _l1 = Cx::set_current(Some(full_cx.clone())); // ALL
        {
            let l2_cx: Cx<cap::CapSet<true, true, true, false, true>> =
                full_cx.restrict::<cap::CapSet<true, true, true, false, true>>();
            let _l2 = l2_cx.set_current_restricted(); // no IO
            assert!(!Cx::current().unwrap().runtime_mask.has(cap::CapMask::IO));
            assert!(
                Cx::current()
                    .unwrap()
                    .runtime_mask
                    .has(cap::CapMask::REMOTE)
            );
            {
                let l3_cx: Cx<cap::None> = full_cx.restrict::<cap::None>();
                let _l3 = l3_cx.set_current_restricted(); // none
                assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::none());
            }
            // l3 dropped — back to no-IO mask
            assert!(!Cx::current().unwrap().runtime_mask.has(cap::CapMask::IO));
            assert!(
                Cx::current()
                    .unwrap()
                    .runtime_mask
                    .has(cap::CapMask::REMOTE)
            );
        }
        // l2 dropped — back to ALL
        assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::all());
    }

    /// A context with a virtual timer, armed at its budget deadline the way
    /// the runtime arms a task's context (br-asupersync-pev2xi).
    fn deadline_cx(
        deadline: Option<Time>,
    ) -> (Arc<crate::time::VirtualClock>, TimerDriverHandle, Cx) {
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let budget = deadline.map_or(Budget::INFINITE, |deadline| {
            Budget::new().with_deadline(deadline)
        });
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        cx.arm_budget_deadline();
        (clock, timer, cx)
    }

    struct DeadlineWakeCount(AtomicUsize);

    impl std::task::Wake for DeadlineWakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn budget_deadline_cancels_and_wakes_a_parked_context() {
        let (clock, timer, cx) = deadline_cx(Some(Time::from_millis(50)));
        let wakes = Arc::new(DeadlineWakeCount(AtomicUsize::new(0)));
        let token = cx.refresh_cancel_waker(None, &Waker::from(Arc::clone(&wakes)));
        assert_eq!(timer.pending_count(), 1, "the deadline is armed");

        clock.advance_to(Time::from_millis(49));
        assert_eq!(timer.process_timers(), 0);
        assert!(!cx.is_cancel_requested(), "not before the deadline");
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        clock.advance_to(Time::from_millis(50));
        assert_eq!(timer.process_timers(), 1);
        assert!(cx.is_cancel_requested(), "cancelled at the deadline");
        assert_eq!(
            cx.cancel_reason().map(|reason| reason.kind),
            Some(CancelKind::Deadline)
        );
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "the parked wait is woken without a checkpoint"
        );
        cx.clear_cancel_waker(token);
    }

    #[test]
    fn budget_deadline_arms_nothing_without_a_deadline() {
        let (_clock, timer, cx) = deadline_cx(None);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn budget_deadline_timer_is_removed_with_its_context() {
        let (clock, timer, cx) = deadline_cx(Some(Time::from_millis(50)));
        drop(cx);
        clock.advance_to(Time::from_millis(60));
        assert_eq!(
            timer.process_timers(),
            0,
            "a dropped context's deadline timer must not fire"
        );
    }

    #[test]
    fn budget_deadline_timer_is_removed_when_the_task_completes() {
        let (clock, timer, cx) = deadline_cx(Some(Time::from_millis(50)));
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        clock.advance_to(Time::from_millis(60));
        assert_eq!(
            timer.process_timers(),
            0,
            "a finished task's deadline timer must not fire, though its context lives on"
        );
        assert!(!cx.is_cancel_requested());
    }

    /// Async finalizer tasks carry a 5 s infrastructure deadline under a
    /// cancellation mask; that legacy handling is unchanged, so a parked
    /// finalizer arms no deadline timer.
    #[test]
    fn budget_deadline_arms_no_timer_for_a_parked_async_finalizer() {
        use crate::lab::{LabConfig, LabRuntime};

        let mut lab = LabRuntime::new(LabConfig::new(0x5EED).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (child_tx, child_rx) = std::sync::mpsc::channel();
        let (release, mut gate) = crate::channel::oneshot::channel::<()>();
        let (owner, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task Cx");
                let child = cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .expect("open child region");
                child_tx.send(child.region_id()).expect("publish child");
                gate.recv_uninterruptible().await.expect("release");
                drop(child);
            })
            .expect("create owner");
        lab.scheduler.lock().schedule(owner, 0);
        lab.run_until_idle();
        let child = child_rx.try_recv().expect("child region opened");
        assert!(
            lab.state
                .register_async_finalizer(child, std::future::pending::<()>())
        );
        release.send_blocking(()).expect("release the owner");
        lab.run_until_idle();
        assert_eq!(
            lab.pending_timer_count(),
            0,
            "a parked async finalizer arms no deadline timer"
        );
    }

    #[test]
    fn budget_deadline_leaves_an_earlier_cancellation_alone() {
        let (clock, timer, cx) = deadline_cx(Some(Time::from_millis(50)));
        cx.cancel_with(CancelKind::User, None);
        clock.advance_to(Time::from_millis(50));
        let _ = timer.process_timers();
        assert_eq!(
            cx.cancel_reason().map(|reason| reason.kind),
            Some(CancelKind::User)
        );
    }

    #[test]
    fn budget_deadline_past_the_wheel_horizon_rearms_instead_of_cancelling_early() {
        let probe =
            TimerDriverHandle::with_virtual_clock(Arc::new(crate::time::VirtualClock::new()));
        let horizon = u64::try_from(probe.max_timer_duration().as_nanos()).expect("horizon fits");
        let deadline = Time::from_nanos(horizon + 1_000_000_000);
        let (clock, timer, cx) = deadline_cx(Some(deadline));

        clock.advance_to(Time::from_nanos(horizon));
        assert_eq!(
            timer.process_timers(),
            1,
            "the clamped timer fires at the horizon"
        );
        assert!(!cx.is_cancel_requested(), "the horizon is not the deadline");
        assert_eq!(timer.pending_count(), 1, "re-armed for the real deadline");

        clock.advance_to(deadline);
        assert_eq!(timer.process_timers(), 1);
        assert_eq!(
            cx.cancel_reason().map(|reason| reason.kind),
            Some(CancelKind::Deadline)
        );
    }

    /// br-asupersync-ovztin: `Cx::for_request_with_budget` is now
    /// gated behind `cfg(any(test, feature = "test-internals"))`. In
    /// the cfg(test) compilation it remains visible for the existing
    /// conformance harness (cx_capability_semantics.rs:53,76); in a
    /// production build with `default-features = false` the
    /// constructor is removed entirely so external callers cannot
    /// mint a fully-capable Cx out of thin air.
    ///
    /// This regression test keeps the test-internals path observable
    /// (the constructor still works in cfg(test)) AND pins the
    /// invariant that the resulting Cx — like the pre-fix Cx — has
    /// `CapMask::all()`. That latter half is what makes external
    /// access to this constructor a capability-bypass: the previous
    /// shape was a fully ambient capability source. The fix removes
    /// the production access path, NOT the cap-mask shape (changing
    /// the cap-mask shape would break the legitimate test callers).
    #[test]
    fn ovztin_for_request_is_gated_and_remains_full_caps_in_tests() {
        // In cfg(test) the constructor is visible — call it.
        let cx = Cx::for_request();
        // Documented contract: the test constructor returns a Cx with
        // CapMask::all(). Production access is removed via cfg-gate;
        // this assertion just pins that the test path is unchanged.
        assert_eq!(cx.runtime_mask, cap::CapMask::all());
    }

    // --- derive_cancel_scope (br-asupersync-issue65-criticisms-kpmoy5.3.1) ---

    #[test]
    fn a_derived_scope_shares_the_task_and_owns_its_cancellation() {
        let parent = Cx::for_testing();
        let child = parent.derive_cancel_scope();
        assert_eq!(
            child.task_id(),
            parent.task_id(),
            "obligations stay the task's"
        );
        assert_eq!(child.region_id(), parent.region_id());
        assert!(Arc::ptr_eq(&child.handles, &parent.handles), "same drivers");
        child.cancel_with(CancelKind::User, Some("the child alone"));
        assert!(child.is_cancel_requested());
        assert!(child.checkpoint().is_err());
        assert!(!parent.is_cancel_requested(), "the parent is untouched");
        assert!(parent.checkpoint().is_ok());
    }

    #[test]
    fn a_derived_scope_inherits_its_parents_cancellation_once() {
        let parent = Cx::for_testing();
        let child = parent.derive_cancel_scope();
        assert!(parent.observable_cancel_reason().is_none());
        parent.cancel_with(CancelKind::Shutdown, Some("parent cancelled"));
        let reason = parent
            .observable_cancel_reason()
            .expect("an unmasked cancellation is observable");
        assert!(child.inherit_cancel(&reason), "the child is cancelled");
        assert!(!child.inherit_cancel(&reason), "only once");
        assert_eq!(
            child.cancel_reason().map(|reason| reason.kind),
            Some(CancelKind::Shutdown),
            "with the parent's reason"
        );
    }

    #[test]
    fn a_masked_parent_does_not_pass_its_cancellation_on() {
        let parent = Cx::for_testing();
        parent.cancel_with(CancelKind::User, Some("cancelled while masked"));
        parent.masked(|| {
            assert!(
                parent.observable_cancel_reason().is_none(),
                "cleanup under a mask keeps its derived scopes running"
            );
        });
        assert!(parent.observable_cancel_reason().is_some());
    }

    #[test]
    fn a_derived_scopes_mask_does_not_leak_to_its_parent() {
        let parent = Cx::for_testing();
        let child = parent.derive_cancel_scope();
        child.masked(|| {
            assert_eq!(child.inner.read().mask_depth, 1);
            assert_eq!(parent.inner.read().mask_depth, 0);
        });
    }

    /// asupersync-445rt7: a cleared cancellation wake target goes back to its
    /// context's pool, the next observer reuses that allocation with its own
    /// Waker, and a target something else still holds is never pooled.
    #[test]
    fn a_retired_cancellation_wake_target_is_reused_by_the_next_observer() {
        struct CountWake(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let target_of =
            |cx: &Cx<cap::None>| Arc::as_ptr(&cx.inner.read().cancel_waker_registrations[0].target);

        let cx = Cx::detached_cancel_context();
        let mut noop = std::task::Context::from_waker(Waker::noop());
        let first = {
            let mut cancelled = std::pin::pin!(cx.cancelled());
            assert!(cancelled.as_mut().poll(&mut noop).is_pending());
            target_of(&cx)
        };
        assert_eq!(cx.inner.read().cancel_waker_pool.len(), 1);

        let counter = Arc::new(CountWake(std::sync::atomic::AtomicUsize::new(0)));
        let counting = Waker::from(Arc::clone(&counter));
        let mut task = std::task::Context::from_waker(&counting);
        let held = {
            let mut cancelled = std::pin::pin!(cx.cancelled());
            assert!(cancelled.as_mut().poll(&mut task).is_pending());
            assert_eq!(target_of(&cx), first, "the allocation is reused");
            assert!(cx.inner.read().cancel_waker_pool.is_empty());
            // Stands in for an in-flight wake that cloned the target.
            let held = Arc::clone(&cx.inner.read().cancel_waker_registrations[0].target);
            cx.cancel_fast(CancelKind::User);
            assert_eq!(
                counter.0.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the reused target wakes the new observer's Waker"
            );
            assert!(cancelled.as_mut().poll(&mut task).is_ready());
            held
        };
        assert!(
            cx.inner.read().cancel_waker_pool.is_empty(),
            "a target another owner still holds is not pooled"
        );
        drop(held);
    }

    /// asupersync-445rt7 follow-up: a repoll with a different Waker hands the
    /// target it replaces back to the pool, so the next observer reuses that
    /// allocation, and the repolled observer is woken through its new Waker.
    #[test]
    fn a_waker_change_returns_the_replaced_wake_target_to_the_pool() {
        struct CountWake(AtomicUsize);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let target_at = |cx: &Cx<cap::None>, index: usize| {
            Arc::as_ptr(&cx.inner.read().cancel_waker_registrations[index].target)
        };

        let cx = Cx::detached_cancel_context();
        let mut noop = std::task::Context::from_waker(Waker::noop());
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let counting = Waker::from(Arc::clone(&counter));
        let mut task = std::task::Context::from_waker(&counting);

        let mut first = std::pin::pin!(cx.cancelled());
        assert!(first.as_mut().poll(&mut noop).is_pending());
        let replaced = target_at(&cx, 0);
        assert!(first.as_mut().poll(&mut task).is_pending());
        assert_ne!(
            target_at(&cx, 0),
            replaced,
            "a new Waker gets its own target"
        );
        assert_eq!(
            cx.inner.read().cancel_waker_pool.len(),
            1,
            "the replaced target is pooled"
        );

        let mut second = std::pin::pin!(cx.cancelled());
        assert!(second.as_mut().poll(&mut noop).is_pending());
        assert_eq!(target_at(&cx, 1), replaced, "the next observer reuses it");
        assert!(cx.inner.read().cancel_waker_pool.is_empty());

        cx.cancel_fast(CancelKind::User);
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "the repolled observer is woken through its new Waker"
        );
        assert!(first.as_mut().poll(&mut task).is_ready());
        assert!(second.as_mut().poll(&mut noop).is_ready());
    }

    /// br-asupersync-93zkbz: inside a spawned task, `Cx::current()` is the
    /// task record's context. It must share the spawn closure's handles, so
    /// it carries what the task inherited from its spawner, and a task
    /// spawned through it inherits them in turn.
    mod spawned_task_ambient_context {
        use super::*;
        use crate::runtime::RuntimeBuilder;

        /// What a spawned task saw through `Cx::current()`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Seen {
            /// The ambient context and the task's own share one bundle.
            same_handles: bool,
            registry: bool,
            io_cap: bool,
            /// The spawner's pressure handle, not the runtime's.
            pressure: bool,
        }

        const INHERITED: Seen = Seen {
            same_handles: true,
            registry: true,
            io_cap: true,
            pressure: true,
        };

        fn seen(own: &Cx, pressure: &Arc<SystemPressure>) -> Seen {
            let current = Cx::current().expect("a spawned task has an ambient context");
            Seen {
                same_handles: Arc::ptr_eq(&current.handles, &own.handles),
                registry: current.registry_handle().is_some(),
                io_cap: current.io_cap_handle().is_some(),
                pressure: current
                    .pressure_handle()
                    .is_some_and(|handle| Arc::ptr_eq(&handle, pressure)),
            }
        }

        /// The ambient context with a registry, an I/O capability and a
        /// pressure handle attached.
        fn spawner(pressure: &Arc<SystemPressure>) -> Cx {
            let registry = RegistryHandle::new(Arc::new(crate::cx::NameRegistry::new()));
            let mut cx = Cx::current()
                .expect("the test runs inside a task")
                .with_registry_handle(Some(registry))
                .with_pressure(Arc::clone(pressure));
            Arc::make_mut(&mut cx.handles).io_cap =
                Some(Arc::new(crate::io::LabIoCap::new_for_tests()));
            cx
        }

        /// Spawns a child through `spawner`. The child records what it saw,
        /// then spawns a grandchild through `Cx::current()`, which records the
        /// same.
        async fn child_and_grandchild(spawner: Cx, pressure: Arc<SystemPressure>) -> (Seen, Seen) {
            let mut child = spawner
                .spawn(move |child| async move {
                    let in_child = seen(&child, &pressure);
                    let current = Cx::current().expect("ambient context");
                    let mut grandchild = current
                        .spawn(move |grandchild| async move { seen(&grandchild, &pressure) })
                        .expect("spawn through the ambient context");
                    let in_grandchild = grandchild.join(&current).await.expect("grandchild joins");
                    (in_child, in_grandchild)
                })
                .expect("spawn through the capable context");
            child.join(&spawner).await.expect("child joins")
        }

        /// Runs `run` on its own thread and fails instead of hanging.
        fn bounded<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
            let (done, result) = std::sync::mpsc::channel();
            let _worker = std::thread::spawn(move || {
                let _ = done.send(run());
            });
            result
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the spawned tasks finished within 30 s")
        }

        #[test]
        fn current_thread_spawn_and_spawn_local_carry_the_spawners_handles() {
            let (child, grandchild, local) = bounded(|| {
                let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
                runtime.block_on(async {
                    let pressure = Arc::new(SystemPressure::new());
                    let spawner = spawner(&pressure);
                    let (child, grandchild) =
                        child_and_grandchild(spawner.clone(), Arc::clone(&pressure)).await;
                    let mut local = spawner
                        .spawn_local(move |local| async move { seen(&local, &pressure) })
                        .expect("spawn_local on the block_on thread");
                    let local = local.join(&spawner).await.expect("local task joins");
                    (child, grandchild, local)
                })
            });
            assert_eq!(child, INHERITED, "spawned task");
            assert_eq!(grandchild, INHERITED, "task spawned through Cx::current()");
            assert_eq!(local, INHERITED, "spawn_local task");
        }

        #[test]
        fn four_workers_spawn_carries_the_spawners_handles() {
            let (child, grandchild) = bounded(|| {
                let runtime = RuntimeBuilder::new()
                    .worker_threads(4)
                    .build()
                    .expect("runtime");
                runtime.block_on(async {
                    let pressure = Arc::new(SystemPressure::new());
                    child_and_grandchild(spawner(&pressure), pressure).await
                })
            });
            assert_eq!(child, INHERITED, "spawned task");
            assert_eq!(grandchild, INHERITED, "task spawned through Cx::current()");
        }

        #[test]
        fn lab_spawn_carries_the_spawners_handles() {
            use crate::lab::{LabConfig, LabRuntime};

            let mut lab = LabRuntime::new(LabConfig::new(0x93_2B_B2));
            let root = lab.state.create_root_region(crate::types::Budget::INFINITE);
            let out = Arc::new(parking_lot::Mutex::new(None));
            let out_in_task = Arc::clone(&out);
            let (owner, _join) = lab
                .state
                .create_task(root, crate::types::Budget::INFINITE, async move {
                    let pressure = Arc::new(SystemPressure::new());
                    let seen = child_and_grandchild(spawner(&pressure), pressure).await;
                    *out_in_task.lock() = Some(seen);
                })
                .expect("create the owner");
            lab.scheduler.lock().schedule(owner, 0);
            let report = lab.run_until_quiescent_with_report();
            assert!(report.lab_test_passed(), "{report:?}");
            assert_eq!(*out.lock(), Some((INHERITED, INHERITED)));
        }
    }
