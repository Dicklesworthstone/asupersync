    use super::*;
    use crate::link::{ExitPolicy, LinkSlot};
    use std::sync::Arc;

    fn tid(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn rid(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    /// Tasks in `tasks` are live, all in region 1.
    fn live(tasks: &[u32]) -> impl Fn(TaskId) -> Option<RegionId> + '_ {
        move |task| tasks.iter().any(|&i| tid(i) == task).then(|| rid(1))
    }

    fn established<R: Copy, N>(slot: &WatchSlot<R, N>) -> Option<Result<R, WatchError>> {
        slot.inner.lock().established
    }

    fn monitor(
        watches: &mut TaskWatches,
        watcher: u32,
        target: u32,
        alive: &[u32],
    ) -> Arc<MonitorSlot> {
        let slot = Arc::new(MonitorSlot::default());
        let applied = watches.apply(
            WatchCommand::Monitor {
                watcher: tid(watcher).into(),
                watcher_region: rid(1),
                target: tid(target).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(alive),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        slot
    }

    fn link(
        watches: &mut TaskWatches,
        task: u32,
        peer: u32,
        task_policy: ExitPolicy,
        alive: &[u32],
    ) -> Arc<LinkSlot> {
        let slot = Arc::new(LinkSlot::default());
        let applied = watches.apply(
            WatchCommand::Link {
                task: tid(task).into(),
                task_region: rid(1),
                task_policy,
                peer: tid(peer).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(alive),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        slot
    }

    fn panicked() -> Outcome<(), crate::error::Error> {
        Outcome::Panicked(PanicPayload::new("boom"))
    }

    #[test]
    fn a_monitor_fires_one_down_with_the_outcome_reason_and_is_retired() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        let (monitor_ref, monitored) = established(&slot)
            .expect("applied")
            .expect("target is live");
        assert_eq!(monitored, tid(2));

        let effects = watches
            .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
            .expect("a monitored exit has effects");
        assert_eq!(effects.downs.len(), 1);
        assert!(effects.cancels.is_empty());
        effects.dispatch();
        let down = slot.notice().expect("DOWN delivered");
        assert_eq!(down.monitored, tid(2));
        assert_eq!(down.monitor_ref, monitor_ref);
        assert!(down.reason.is_panicked());
        assert!(watches.is_empty(), "the fired monitor is retired");
        assert!(
            watches
                .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none(),
            "a retired monitor never fires twice"
        );
    }

    #[test]
    fn each_outcome_maps_to_its_down_reason() {
        let cases: Vec<(Outcome<(), crate::error::Error>, fn(&DownReason) -> bool)> = vec![
            (Outcome::Ok(()), DownReason::is_normal),
            (
                Outcome::Err(crate::error::Error::new(crate::error::ErrorKind::Internal)),
                DownReason::is_error,
            ),
            (
                Outcome::Cancelled(CancelReason::user("stop")),
                DownReason::is_cancelled,
            ),
            (panicked(), DownReason::is_panicked),
        ];
        for (outcome, expected) in cases {
            let mut watches = TaskWatches::default();
            let slot = monitor(&mut watches, 1, 2, &[1, 2]);
            watches
                .on_task_completed(tid(2), Some(&outcome), Time::ZERO, None)
                .expect("effects")
                .dispatch();
            let down = slot.notice().expect("DOWN delivered");
            assert!(expected(&down.reason), "{outcome:?} gave {:?}", down.reason);
        }
    }

    #[test]
    fn monitoring_a_task_that_is_not_live_fails_not_found() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 9, &[1]);
        assert_eq!(established(&slot), Some(Err(WatchError::NotFound)));
        assert!(watches.is_empty());
    }

    #[test]
    fn demonitor_before_exit_means_no_down() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        let (monitor_ref, _) = established(&slot).expect("applied").expect("live");
        let applied = watches.apply(WatchCommand::Demonitor { monitor_ref }, live(&[1, 2]));
        assert!(matches!(applied, WatchApply::Done(None)));
        assert!(watches.is_empty());
        assert!(
            watches
                .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
                .is_none()
        );
        assert!(slot.notice().is_none());
    }

    #[test]
    fn a_watcher_that_finishes_first_takes_its_monitors_with_it() {
        let mut watches = TaskWatches::default();
        let slot = monitor(&mut watches, 1, 2, &[1, 2]);
        assert!(
            watches
                .on_task_completed(tid(1), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none()
        );
        assert!(watches.is_empty(), "no monitor outlives its watcher");
        assert!(
            watches
                .on_task_completed(tid(2), Some(&panicked()), Time::ZERO, None)
                .is_none()
        );
        assert!(slot.notice().is_none());
    }

    #[test]
    fn an_abandoned_opening_is_never_registered() {
        let mut watches = TaskWatches::default();
        let slot = Arc::new(MonitorSlot::default());
        assert_eq!(slot.abandon(), None);
        let applied = watches.apply(
            WatchCommand::Monitor {
                watcher: tid(1).into(),
                watcher_region: rid(1),
                target: tid(2).into(),
                slot: Arc::clone(&slot),
                attempts: 0,
            },
            live(&[1, 2]),
        );
        assert!(matches!(applied, WatchApply::Done(None)));
        assert!(watches.is_empty());
        assert_eq!(established(&slot), None);
    }

    #[test]
    fn several_monitors_on_one_task_fire_in_monitor_ref_order() {
        let mut watches = TaskWatches::default();
        let slots = [
            monitor(&mut watches, 1, 3, &[1, 2, 3]),
            monitor(&mut watches, 2, 3, &[1, 2, 3]),
            monitor(&mut watches, 1, 3, &[1, 2, 3]),
        ];
        let effects = watches
            .on_task_completed(tid(3), Some(&Outcome::Ok(())), Time::ZERO, None)
            .expect("effects");
        let refs: Vec<MonitorRef> = effects
            .downs
            .iter()
            .map(|(_, _, d)| d.monitor_ref)
            .collect();
        let watchers: Vec<TaskId> = effects
            .down_deliveries()
            .map(|(watcher, monitored, _)| {
                assert_eq!(monitored, tid(3));
                watcher
            })
            .collect();
        assert_eq!(
            watchers,
            vec![tid(1), tid(2), tid(1)],
            "watchers follow the refs"
        );
        let mut sorted = refs.clone();
        sorted.sort();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs, sorted, "DOWN-ORDER: ascending monitor refs");
        effects.dispatch();
        for slot in &slots {
            assert!(slot.notice().expect("DOWN delivered").reason.is_normal());
        }
    }

    #[test]
    fn an_abnormal_exit_cancels_a_propagating_peer_from_either_side() {
        for (finishing, other) in [(2, 1), (1, 2)] {
            let mut watches = TaskWatches::default();
            let _slot = link(&mut watches, 1, 2, ExitPolicy::Propagate, &[1, 2]);
            let effects = watches
                .on_task_completed(tid(finishing), Some(&panicked()), Time::ZERO, None)
                .expect("effects");
            assert_eq!(effects.cancels.len(), 1);
            assert_eq!(effects.cancels[0].0, tid(other));
            assert_eq!(
                effects.cancels[0].1.kind,
                crate::types::cancel::CancelKind::LinkedExit
            );
            assert!(effects.exits.is_empty());
            assert!(watches.is_empty(), "the link ends with the task");
        }
    }

    #[test]
    fn a_normal_exit_only_removes_a_propagating_link() {
        let mut watches = TaskWatches::default();
        let _slot = link(&mut watches, 1, 2, ExitPolicy::Propagate, &[1, 2]);
        assert!(
            watches
                .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
                .is_none()
        );
        assert!(watches.is_empty());
    }

    #[test]
    fn a_trapping_task_receives_its_peer_exit_and_still_propagates_its_own() {
        // Abnormal peer exit: delivered, nobody cancelled.
        let mut watches = TaskWatches::default();
        let slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        let (link_ref, peer) = established(&slot).expect("applied").expect("live");
        assert_eq!(peer, tid(2));
        let effects = watches
            .on_task_completed(
                tid(2),
                Some(&Outcome::Cancelled(CancelReason::user("stop"))),
                Time::ZERO,
                None,
            )
            .expect("effects");
        assert!(effects.cancels.is_empty());
        effects.dispatch();
        let signal = slot.notice().expect("exit delivered");
        assert_eq!(signal.from, tid(2));
        assert_eq!(signal.link_ref, link_ref);
        assert!(signal.reason.is_cancelled());

        // Normal peer exit: a trapping task hears about it too.
        let mut watches = TaskWatches::default();
        let slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        watches
            .on_task_completed(tid(2), Some(&Outcome::Ok(())), Time::ZERO, None)
            .expect("effects")
            .dispatch();
        assert!(slot.notice().expect("exit delivered").reason.is_normal());

        // The trapping task's own abnormal exit still cancels its peer.
        let mut watches = TaskWatches::default();
        let _slot = link(&mut watches, 1, 2, ExitPolicy::Trap, &[1, 2]);
        let effects = watches
            .on_task_completed(tid(1), Some(&panicked()), Time::ZERO, None)
            .expect("effects");
        assert_eq!(effects.cancels.len(), 1);
        assert_eq!(effects.cancels[0].0, tid(2));
    }

    #[test]
    fn a_watch_on_an_unadmitted_spawn_retries_until_admitted_or_denied() {
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let admitted = Arc::new(
            crate::runtime::spawn_mailbox::AdmittedTaskSlot::new()
                .with_retirement_barrier(Arc::clone(&barrier)),
        );
        let provisional =
            TaskId::new_for_test(7, crate::runtime::spawn_mailbox::SPAWN_ID_GENERATION_TAG);
        let target = WatchTarget {
            id: provisional,
            admitted: Some(admitted),
        };
        let slot = Arc::new(MonitorSlot::default());
        let mut watches = TaskWatches::default();
        let command = WatchCommand::Monitor {
            watcher: tid(1).into(),
            watcher_region: rid(1),
            target,
            slot: Arc::clone(&slot),
            attempts: 0,
        };
        // Not admitted, barrier pending: retried well past the unbarriered cap.
        let mut command = command;
        for _ in 0..(MAX_UNBARRIERED_WATCH_ATTEMPTS + 8) {
            command = match watches.apply(command, live(&[1])) {
                WatchApply::Retry(next) => next,
                WatchApply::Done(_) => panic!("a pending admission must be retried"),
            };
        }
        assert_eq!(established(&slot), None);
        // Denied: the barrier opens without an admission, so the target is gone.
        barrier.open_and_wake();
        assert!(matches!(
            watches.apply(command, live(&[1])),
            WatchApply::Done(None)
        ));
        assert_eq!(established(&slot), Some(Err(WatchError::NotFound)));
        assert!(watches.is_empty());
    }

    /// A natively spawned GenServer holds its monitors and links through its
    /// spawn handle: the watch waits for the spawn's admission and is held by
    /// the admitted id; a denied or finished holder cannot hold one.
    #[test]
    fn a_watch_held_through_a_spawn_handle_waits_for_its_admission() {
        use crate::runtime::spawn_mailbox::{
            AdmittedTask, AdmittedTaskSlot, SPAWN_ID_GENERATION_TAG,
        };
        use crate::runtime::task_handle::RetirementBarrier;
        let holder = |slot: &Arc<AdmittedTaskSlot>| WatchTarget {
            id: TaskId::new_for_test(9, SPAWN_ID_GENERATION_TAG),
            admitted: Some(Arc::clone(slot)),
        };
        let mut watches = TaskWatches::default();

        // Monitor: retried while unadmitted, then held by the admitted id.
        let barrier = RetirementBarrier::pending();
        let admitted =
            Arc::new(AdmittedTaskSlot::new().with_retirement_barrier(Arc::clone(&barrier)));
        let slot = Arc::new(MonitorSlot::default());
        let command = WatchCommand::Monitor {
            watcher: holder(&admitted),
            watcher_region: rid(1),
            target: tid(2).into(),
            slot: Arc::clone(&slot),
            attempts: 0,
        };
        let WatchApply::Retry(command) = watches.apply(command, live(&[1, 2])) else {
            panic!("a watch whose holder is unadmitted must be retried");
        };
        assert_eq!(established(&slot), None);
        assert!(
            admitted
                .set(AdmittedTask::pending(tid(1), std::sync::Weak::new()))
                .is_ok()
        );
        assert!(matches!(
            watches.apply(command, live(&[1, 2])),
            WatchApply::Done(None)
        ));
        let (monitor_ref, monitored) = established(&slot).expect("applied").expect("established");
        assert_eq!(monitored, tid(2));
        assert_eq!(
            watches.monitors.watchers_of(tid(2)),
            vec![(monitor_ref, tid(1))]
        );

        // Link: the holder's spawn is denied while the request waits.
        let barrier = RetirementBarrier::pending();
        let denied =
            Arc::new(AdmittedTaskSlot::new().with_retirement_barrier(Arc::clone(&barrier)));
        let slot = Arc::new(LinkSlot::default());
        let command = WatchCommand::Link {
            task: holder(&denied),
            task_region: rid(1),
            task_policy: ExitPolicy::Propagate,
            peer: tid(2).into(),
            slot: Arc::clone(&slot),
            attempts: 0,
        };
        let WatchApply::Retry(command) = watches.apply(command, live(&[1, 2])) else {
            panic!("a link whose holder is unadmitted must be retried");
        };
        barrier.open_and_wake();
        assert!(matches!(
            watches.apply(command, live(&[1, 2])),
            WatchApply::Done(None)
        ));
        assert_eq!(established(&slot), Some(Err(WatchError::WatcherNotFound)));

        // Link: the holder was admitted but already finished.
        let finished = Arc::new(AdmittedTaskSlot::new());
        assert!(
            finished
                .set(AdmittedTask::pending(tid(3), std::sync::Weak::new()))
                .is_ok()
        );
        let slot = Arc::new(LinkSlot::default());
        let command = WatchCommand::Link {
            task: holder(&finished),
            task_region: rid(1),
            task_policy: ExitPolicy::Propagate,
            peer: tid(2).into(),
            slot: Arc::clone(&slot),
            attempts: 0,
        };
        assert!(matches!(
            watches.apply(command, live(&[1, 2])),
            WatchApply::Done(None)
        ));
        assert_eq!(established(&slot), Some(Err(WatchError::WatcherNotFound)));
        assert!(watches.links.is_empty() && watches.link_slots.is_empty());
    }

    #[test]
    fn monitor_set_watcher_index_stays_consistent() {
        let mut set = MonitorSet::new();
        let a = set.establish(tid(1), rid(1), tid(5));
        let b = set.establish(tid(1), rid(1), tid(6));
        let c = set.establish(tid(2), rid(2), tid(5));
        assert!(set.demonitor(b));
        assert_eq!(set.remove_watcher(tid(1)), vec![a]);
        assert_eq!(set.watchers_of(tid(5)), vec![(c, tid(2))]);
        assert_eq!(set.remove_monitored(tid(5)), vec![c]);
        assert!(set.is_empty());
        assert!(set.remove_watcher(tid(2)).is_empty());
        assert!(set.cleanup_region(rid(2)).is_empty());
    }
