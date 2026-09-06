#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::actor::Actor;
use asupersync::cx::Cx;
use asupersync::supervision::{
    BackoffStrategy, RestartConfig, RestartTracker, RestartTrackerConfig, StormMonitorConfig,
};
use asupersync::types::Budget;
use asupersync::types::policy::FailFast;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[test]
fn test_backoff_handles_invalid_multiplier() {
    // Negative multiplier should fallback to safe default (2.0) or handle gracefully
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: -5.0,
    };
    // Should not panic
    let delay = backoff.delay_for_attempt(1);
    assert!(delay.is_some());

    // NaN multiplier
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: f64::NAN,
    };
    // Should not panic
    let delay = backoff.delay_for_attempt(1);
    assert!(delay.is_some());

    // Infinite multiplier
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: f64::INFINITY,
    };
    // Should cap at max or fallback
    let delay = backoff.delay_for_attempt(10).unwrap();
    assert!(delay <= Duration::from_secs(10));
}

#[test]
fn supervised_actor_panic_restarts_under_restart_strategy() {
    #[derive(Debug)]
    struct PanicOnMessage {
        handled: u32,
        final_handled: Arc<AtomicU32>,
    }

    impl Actor for PanicOnMessage {
        type Message = u32;

        fn handle(&mut self, _cx: &Cx, msg: u32) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            assert!(msg != 999, "intentional supervision regression panic");
            self.handled += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.final_handled.store(self.handled, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = asupersync::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

    let factory_calls = Arc::new(AtomicU32::new(0));
    let factory_calls_for_actor = Arc::clone(&factory_calls);
    let final_handled = Arc::new(AtomicU32::new(u32::MAX));
    let final_handled_for_actor = Arc::clone(&final_handled);
    let strategy = asupersync::supervision::SupervisionStrategy::Restart(
        asupersync::supervision::RestartConfig::new(3, Duration::from_secs(60))
            .with_backoff(asupersync::supervision::BackoffStrategy::None),
    );

    let (mut handle, stored) = scope
        .spawn_supervised_actor(
            &mut runtime.state,
            &cx,
            move || {
                factory_calls_for_actor.fetch_add(1, Ordering::SeqCst);
                PanicOnMessage {
                    handled: 0,
                    final_handled: Arc::clone(&final_handled_for_actor),
                }
            },
            strategy,
            8,
        )
        .expect("spawn supervised actor");
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    handle.try_send(999).expect("enqueue panic message");
    handle.try_send(1).expect("enqueue post-restart message");
    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_idle();
    handle.abort();
    runtime.run_until_quiescent();

    let join = futures_lite::future::block_on(handle.join(&cx));
    let actor = join.expect("aborting the restarted actor should still return final state");
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        2,
        "panic must trigger exactly one supervised restart"
    );
    assert_eq!(
        actor.handled, 1,
        "restarted actor should keep the queued post-crash work"
    );
    assert_eq!(
        final_handled.load(Ordering::SeqCst),
        1,
        "restarted actor should handle queued work before abort"
    );
}

#[test]
fn explicit_storm_monitor_rate_is_preserved_across_builder_order() {
    let explicit_monitor = StormMonitorConfig {
        alpha: 0.01,
        expected_rate: StormMonitorConfig::default().expected_rate,
        min_observations: 1,
        tolerance: 1.2,
    };

    let build_tracker = |threshold_first: bool| {
        let config = if threshold_first {
            RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                .with_storm_detection(2.0)
                .with_storm_monitor(explicit_monitor)
        } else {
            RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                .with_storm_monitor(explicit_monitor)
                .with_storm_detection(2.0)
        };
        let mut tracker = RestartTracker::new(config);
        tracker.record(0);
        tracker
            .storm_snapshot()
            .expect("storm monitor enabled")
            .e_value
    };

    let threshold_then_monitor = build_tracker(true);
    let monitor_then_threshold = build_tracker(false);

    assert!(
        threshold_then_monitor > 1.0,
        "explicit expected_rate must not be overwritten by threshold inference"
    );
    assert!(
        (threshold_then_monitor - monitor_then_threshold).abs() < f64::EPSILON,
        "builder order must not change explicit storm monitor behavior"
    );
}

// Public consumer coverage for bi2462.35. These callbacks own real async
// cleanup; they do not claim registration of native runtime region finalizers.
mod managed_public {
    use asupersync::channel::mpsc;
    use asupersync::cx::{Cx, Scope};
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::runtime::{RuntimeBuilder, RuntimeState, SpawnError};
    use asupersync::supervision::{
        BackoffStrategy, ChildSpec, EscalationPolicy, ManagedChildBinding, ManagedGeneration,
        ManagedRestartMode, ManagedSupervisor, ManagedSupervisorHandle, RestartPolicy,
        SupervisionConfig, SupervisorBuilder,
    };
    use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
    use asupersync::types::{Budget, CancelReason, Outcome, TaskId, policy::FailFast};
    use std::collections::BTreeSet;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Poll, Waker};
    use std::time::Duration;

    const NAMES: [&str; 4] = ["a", "b", "c", "d"];
    type Snapshot = Box<dyn Fn() -> Vec<TraceEvent> + Send + Sync>;

    fn legacy_start(
        _: &Scope<'static, FailFast>,
        _: &mut RuntimeState,
        _: &Cx,
    ) -> Result<TaskId, SpawnError> {
        panic!("public managed journey must never call legacy ChildStart")
    }

    fn bind(
        bindings: Vec<ManagedChildBinding<&'static str>>,
        config: SupervisionConfig,
    ) -> ManagedSupervisor<&'static str> {
        let mut builder =
            SupervisorBuilder::new("public-managed").with_restart_policy(config.restart_policy);
        for name in NAMES.iter().take(bindings.len()) {
            builder = builder.child(
                ChildSpec::new(*name, legacy_start)
                    .with_shutdown_budget(Budget::new().with_poll_quota(10_000)),
            );
        }
        builder
            .compile()
            .unwrap()
            .bind_managed(bindings, config)
            .unwrap()
    }

    fn config(policy: RestartPolicy, restarts: u32) -> SupervisionConfig {
        SupervisionConfig::new(restarts, Duration::from_secs(60))
            .with_restart_policy(policy)
            .with_backoff(BackoffStrategy::None)
    }

    // An ordinary user cleanup future with an owned waker. Observations are
    // emitted only after a genuine Pending registration. No simulated task,
    // deadline, cancellation acknowledgement, or finalizer is introduced here.
    #[derive(Debug, Default)]
    struct Gate(Mutex<(bool, Option<Waker>)>);

    impl Gate {
        fn release(&self) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                assert!(!state.0, "cleanup release must be unique");
                state.0 = true;
                state.1.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
        }

        async fn wait(&self, mut on_pending: impl FnMut()) {
            let mut observed = false;
            poll_fn(|poll_cx| {
                {
                    let mut state = self.0.lock().unwrap();
                    if state.0 {
                        return Poll::Ready(());
                    }
                    state.1 = Some(poll_cx.waker().clone());
                }
                if !observed {
                    observed = true;
                    on_pending();
                }
                Poll::Pending
            })
            .await;
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Action {
        Started,
        Work(u32),
        Failed,
        CleanupPending,
        Cleaned,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Observation {
        child: usize,
        generation: ManagedGeneration,
        action: Action,
    }

    #[derive(Debug)]
    enum Command {
        Work(u32),
        Error,
        Panic,
        Finish,
    }

    #[derive(Debug)]
    struct Ready {
        child: usize,
        generation: ManagedGeneration,
        mailbox: mpsc::Sender<Command>,
        cleanup: Arc<Gate>,
    }

    #[derive(Debug)]
    enum Event {
        Ready(Ready),
        Observed(Observation),
    }

    #[derive(Clone)]
    struct Events {
        sender: mpsc::Sender<Event>,
        log: Arc<Mutex<Vec<Observation>>>,
    }

    impl Events {
        fn observe(&self, child: usize, generation: ManagedGeneration, action: Action) {
            let observed = Observation {
                child,
                generation,
                action,
            };
            self.log.lock().unwrap().push(observed);
            self.sender.try_send(Event::Observed(observed)).unwrap();
        }
    }

    fn events() -> (Events, mpsc::Receiver<Event>) {
        let (sender, receiver) = mpsc::channel(128);
        (
            Events {
                sender,
                log: Arc::new(Mutex::new(Vec::new())),
            },
            receiver,
        )
    }

    fn worker(
        index: usize,
        mode: ManagedRestartMode,
        events: Events,
        interdependent: Option<Arc<Gate>>,
        cancel_on_start: Option<Cx>,
    ) -> ManagedChildBinding<&'static str> {
        ManagedChildBinding::new(
            NAMES[index],
            mode,
            move |cx: Cx, generation: ManagedGeneration| {
                let events = events.clone();
                let witness = interdependent.clone();
                if let Some(controller) = &cancel_on_start {
                    controller.cancel_with(
                        asupersync::types::CancelKind::User,
                        Some("cancellation inside actual managed factory"),
                    );
                }
                async move {
                    let (sender, mut receiver) = mpsc::channel(2);
                    let cleanup = Arc::new(Gate::default());
                    events.log.lock().unwrap().push(Observation {
                        child: index,
                        generation,
                        action: Action::Started,
                    });
                    events
                        .sender
                        .try_send(Event::Ready(Ready {
                            child: index,
                            generation,
                            mailbox: sender,
                            cleanup: Arc::clone(&cleanup),
                        }))
                        .unwrap();
                    loop {
                        match receiver.recv(&cx).await {
                            Ok(Command::Work(value)) => {
                                events.observe(index, generation, Action::Work(value))
                            }
                            Ok(Command::Error) => {
                                events.observe(index, generation, Action::Failed);
                                return Outcome::Err("controlled mailbox failure");
                            }
                            Ok(Command::Panic) => {
                                events.observe(index, generation, Action::Failed);
                                panic!("actual public managed child poll panic");
                            }
                            Ok(Command::Finish) => return Outcome::Ok(()),
                            Err(mpsc::RecvError::Cancelled) => {
                                let reason = cx.cancel_reason().expect("real child cancellation");
                                if index == 2 && generation.number == 1 {
                                    if let Some(witness) = &witness {
                                        witness
                                            .wait(|| {
                                                events.observe(
                                                    index,
                                                    generation,
                                                    Action::CleanupPending,
                                                )
                                            })
                                            .await;
                                    }
                                }
                                cleanup
                                    .wait(|| {
                                        events.observe(index, generation, Action::CleanupPending)
                                    })
                                    .await;
                                events.observe(index, generation, Action::Cleaned);
                                if index == 3 && generation.number == 1 {
                                    if let Some(witness) = &witness {
                                        witness.release();
                                    }
                                }
                                return Outcome::Cancelled(reason);
                            }
                            Err(error) => panic!("unexpected public mailbox close: {error:?}"),
                        }
                    }
                }
            },
        )
    }

    async fn next_event(
        cx: &Cx,
        handle: &mut ManagedSupervisorHandle<&'static str>,
        events: &mut mpsc::Receiver<Event>,
    ) -> Event {
        let mut joined = Box::pin(handle.join());
        let mut received = Box::pin(events.recv(cx));
        poll_fn(|poll_cx| {
            assert!(
                joined.as_mut().poll(poll_cx).is_pending(),
                "managed controller completed before its required work/cleanup witness"
            );
            received.as_mut().poll(poll_cx).map(Result::unwrap)
        })
        .await
    }

    async fn ready_set(
        cx: &Cx,
        handle: &mut ManagedSupervisorHandle<&'static str>,
        events: &mut mpsc::Receiver<Event>,
        expected: &[usize],
    ) -> Vec<Ready> {
        let mut ready = Vec::new();
        while ready.len() < expected.len() {
            match next_event(cx, handle, events).await {
                Event::Ready(value) => ready.push(value),
                Event::Observed(value) => panic!("unexpected event while starting: {value:?}"),
            }
        }
        ready.sort_by_key(|value| value.child);
        assert_eq!(
            ready.iter().map(|value| value.child).collect::<Vec<_>>(),
            expected
        );
        ready
    }

    async fn perform_work(
        cx: &Cx,
        handle: &mut ManagedSupervisorHandle<&'static str>,
        events: &mut mpsc::Receiver<Event>,
        ready: &[Ready],
        offset: u32,
    ) {
        // Each acknowledgement is awaited before the next command: the
        // independent expected payload sequence is not scheduler-dependent.
        for child in ready {
            let value = offset + u32::try_from(child.child).unwrap();
            child.mailbox.try_send(Command::Work(value)).unwrap();
            match next_event(cx, handle, events).await {
                Event::Observed(actual) => assert_eq!(
                    actual,
                    Observation {
                        child: child.child,
                        generation: child.generation,
                        action: Action::Work(value),
                    }
                ),
                Event::Ready(_) => panic!("unsolicited replacement during successful work"),
            }
        }
    }

    fn verify_completion_claim(
        log: &[Observation],
        required: &[ManagedGeneration],
        claims_complete: bool,
    ) -> Result<(), &'static str> {
        if required.is_empty() {
            return Err("zero_selected_generations");
        }
        if claims_complete
            && required.iter().any(|generation| {
                !log.iter().any(|entry| {
                    entry.generation == *generation
                        && matches!(entry.action, Action::Cleaned | Action::Failed)
                })
            })
        {
            return Err("premature_generation_completion");
        }
        Ok(())
    }

    fn terminal_witnesses(log: &[Observation], trace: &[TraceEvent]) {
        let starts: Vec<_> = log
            .iter()
            .filter(|entry| entry.action == Action::Started)
            .collect();
        assert!(!starts.is_empty());
        let ids: BTreeSet<_> = starts.iter().map(|entry| entry.generation.task).collect();
        assert_eq!(
            ids.len(),
            starts.len(),
            "every generation owns a distinct actual TaskId"
        );
        for entry in starts {
            assert_eq!(
                trace
                    .iter()
                    .filter(|event| event.kind == TraceEventKind::Complete
                        && matches!(event.data, TraceData::Task { task, region }
                    if task == entry.generation.task && region == entry.generation.region))
                    .count(),
                1,
                "missing/duplicated actual terminal for {entry:?}"
            );
        }
    }

    async fn restart_sets(
        cx: Cx,
        snapshot: &Snapshot,
        policy: RestartPolicy,
        panic_child: bool,
    ) -> serde_json::Value {
        let (events, mut receiver) = events();
        let interdependent =
            (policy != RestartPolicy::OneForOne).then(|| Arc::new(Gate::default()));
        let bindings = (0..4)
            .map(|index| {
                worker(
                    index,
                    ManagedRestartMode::Transient,
                    events.clone(),
                    interdependent.clone(),
                    None,
                )
            })
            .collect();
        let mut handle = bind(bindings, config(policy, 3)).spawn(&cx).unwrap();
        let mut current = ready_set(&cx, &mut handle, &mut receiver, &[0, 1, 2, 3]).await;
        perform_work(&cx, &mut handle, &mut receiver, &current, 100).await;
        let originals: Vec<_> = current.iter().map(|child| child.generation).collect();
        let old_mailbox = current[1].mailbox.clone();
        let affected: &[usize] = match policy {
            RestartPolicy::OneForOne => &[1],
            RestartPolicy::OneForAll => &[0, 1, 2, 3],
            RestartPolicy::RestForOne => &[1, 2, 3],
        };
        current[1]
            .mailbox
            .try_send(if panic_child {
                Command::Panic
            } else {
                Command::Error
            })
            .unwrap();
        let mut pending = BTreeSet::new();
        let mut failed = false;
        let mut replacements = Vec::new();
        while !failed || pending.len() + 1 < affected.len() {
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Observed(entry) if entry.action == Action::Failed => {
                    assert_eq!(entry.generation, originals[1]);
                    assert!(!failed);
                    failed = true;
                }
                Event::Observed(entry) if entry.action == Action::CleanupPending => {
                    assert!(affected.contains(&entry.child));
                    assert_eq!(entry.generation, originals[entry.child]);
                    assert!(pending.insert(entry.child));
                }
                Event::Ready(_) => panic!("replacement admitted before held cleanup drained"),
                Event::Observed(other) => panic!("unexpected held-cleanup event {other:?}"),
            }
        }
        if affected.len() > 1 {
            let selected: Vec<_> = affected.iter().map(|index| originals[*index]).collect();
            let held = events.log.lock().unwrap();
            assert_eq!(
                verify_completion_claim(&held, &selected, true),
                Err("premature_generation_completion")
            );
            assert_eq!(
                verify_completion_claim(&held, &[], true),
                Err("zero_selected_generations")
            );
            drop(held);
            for index in affected.iter().copied().filter(|index| *index != 1) {
                current[index].cleanup.release();
            }
        }
        let mut cleaned = BTreeSet::new();
        while replacements.len() < affected.len() {
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Observed(entry) if entry.action == Action::Cleaned => {
                    assert!(affected.contains(&entry.child));
                    assert_eq!(entry.generation, originals[entry.child]);
                    assert!(cleaned.insert(entry.child));
                }
                Event::Ready(ready) => {
                    assert_eq!(
                        cleaned.len() + 1,
                        affected.len(),
                        "all affected cleanup precedes any replacement"
                    );
                    replacements.push(ready);
                }
                Event::Observed(other) => panic!("unexpected drain event {other:?}"),
            }
        }
        replacements.sort_by_key(|child| child.child);
        assert_eq!(
            replacements
                .iter()
                .map(|child| child.child)
                .collect::<Vec<_>>(),
            affected
        );
        for replacement in replacements {
            assert_eq!(replacement.generation.number, 2);
            assert_ne!(
                replacement.generation.task,
                originals[replacement.child].task
            );
            assert_ne!(
                replacement.generation.region,
                originals[replacement.child].region
            );
            let index = replacement.child;
            current[index] = replacement;
        }
        for (index, child) in current.iter().enumerate() {
            assert_eq!(
                child.generation.number,
                if affected.contains(&index) { 2 } else { 1 }
            );
            if !affected.contains(&index) {
                assert_eq!(child.generation, originals[index]);
            }
        }
        assert!(
            matches!(
                old_mailbox.try_send(Command::Error),
                Err(mpsc::SendError::Closed(Command::Error))
            ),
            "a late command addressed to the retired generation cannot fail its replacement"
        );
        perform_work(&cx, &mut handle, &mut receiver, &current, 200).await;
        handle.abort();
        let mut stopped = BTreeSet::new();
        while stopped.len() < current.len() {
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Observed(entry) if entry.action == Action::CleanupPending => {
                    assert_eq!(entry.generation, current[entry.child].generation);
                    assert!(stopped.insert(entry.child));
                }
                Event::Observed(other) => panic!("unexpected shutdown event {other:?}"),
                Event::Ready(_) => panic!("parent cancellation resurrected a generation"),
            }
        }
        for child in &current {
            child.cleanup.release();
        }
        let report = handle.join().await.unwrap();
        assert!(report.outcome.is_cancelled(), "{report:?}");
        assert_eq!(
            (report.started, report.joined),
            (4 + affected.len() as u64, 4 + affected.len() as u64)
        );
        assert_eq!(report.restart_batches, 1);
        assert_eq!(report.escalations, 0);
        assert_eq!(report.children.len(), 4);
        let log = events.log.lock().unwrap().clone();
        let selected: Vec<_> = current.iter().map(|child| child.generation).collect();
        assert_eq!(verify_completion_claim(&log, &selected, true), Ok(()));
        terminal_witnesses(&log, &snapshot());
        let payloads: Vec<_> = log
            .iter()
            .filter_map(|entry| match entry.action {
                Action::Work(value) => Some(value),
                _ => None,
            })
            .collect();
        assert_eq!(payloads, vec![100, 101, 102, 103, 200, 201, 202, 203]);
        if affected.len() > 1 {
            let position = |index| {
                log.iter()
                    .position(|entry| {
                        entry.child == index
                            && entry.generation == originals[index]
                            && entry.action == Action::Cleaned
                    })
                    .unwrap()
            };
            assert!(
                position(3) < position(2),
                "c really awaited d's cleanup witness"
            );
        }
        serde_json::json!({"scenario":"public_restart_sets", "policy":format!("{policy:?}"),
            "actual_panic":panic_child,"affected":affected,"started":report.started,
            "joined":report.joined,"restart_batches":report.restart_batches,
            "mailbox_capacity":2,"payloads":payloads,"generations":format!("{log:?}"),
            "cleanup_evidence":"task_owned_async_cleanup","actual_terminal_witnesses":report.joined})
    }

    async fn restart_mode(
        cx: Cx,
        snapshot: &Snapshot,
        mode: ManagedRestartMode,
        terminal: u8,
    ) -> serde_json::Value {
        let (events, mut receiver) = events();
        let binding = worker(0, mode, events.clone(), None, None);
        let mut handle = bind(vec![binding], config(RestartPolicy::OneForOne, 1))
            .spawn(&cx)
            .unwrap();
        let initial = ready_set(&cx, &mut handle, &mut receiver, &[0]).await;
        perform_work(&cx, &mut handle, &mut receiver, &initial, 300).await;
        initial[0]
            .mailbox
            .try_send(match terminal {
                0 => Command::Finish,
                1 => Command::Error,
                2 => Command::Panic,
                _ => unreachable!(),
            })
            .unwrap();
        let restarted = mode == ManagedRestartMode::Permanent
            || (mode == ManagedRestartMode::Transient && terminal != 0);
        if restarted {
            let replacement = loop {
                match next_event(&cx, &mut handle, &mut receiver).await {
                    Event::Ready(child) => break child,
                    Event::Observed(entry) => assert_eq!(entry.action, Action::Failed),
                }
            };
            assert_eq!(replacement.generation.number, 2);
            assert_ne!(replacement.generation.task, initial[0].generation.task);
            perform_work(
                &cx,
                &mut handle,
                &mut receiver,
                std::slice::from_ref(&replacement),
                400,
            )
            .await;
            handle.abort();
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Observed(entry) => {
                    assert_eq!(entry.generation, replacement.generation);
                    assert_eq!(entry.action, Action::CleanupPending);
                }
                Event::Ready(_) => panic!("unexpected third generation"),
            }
            replacement.cleanup.release();
        }
        let report = handle.join().await.unwrap();
        assert_eq!(
            (report.started, report.joined),
            (1 + u64::from(restarted), 1 + u64::from(restarted))
        );
        assert_eq!(report.restart_batches, u64::from(restarted));
        assert_eq!(report.children.len(), 1);
        let child = &report.children[0];
        if !restarted {
            match terminal {
                0 => assert!(child.outcome.is_ok(), "{report:?}"),
                1 => assert!(matches!(
                    child.outcome,
                    Outcome::Err("controlled mailbox failure")
                )),
                2 => assert!(matches!(child.outcome, Outcome::Panicked(_))),
                _ => unreachable!(),
            }
        }
        assert!(child.region_outcome.is_some());
        let log = events.log.lock().unwrap().clone();
        terminal_witnesses(&log, &snapshot());
        serde_json::json!({"scenario":"public_restart_mode","mode":format!("{mode:?}"),
            "terminal":terminal,"started":report.started,"joined":report.joined,
            "restart_batches":report.restart_batches,"typed_outcome":format!("{:?}", child.outcome),
            "actual_task_outcome":format!("{:?}", child.task_outcome),"events":format!("{log:?}")})
    }

    async fn cancellation_during_start(cx: Cx, snapshot: &Snapshot) -> serde_json::Value {
        let (events, mut receiver) = events();
        let observed = events.clone();
        let mut controller = cx
            .spawn(move |controller| async move {
                let bindings = vec![
                    worker(
                        0,
                        ManagedRestartMode::Permanent,
                        observed.clone(),
                        None,
                        Some(controller.clone()),
                    ),
                    worker(1, ManagedRestartMode::Permanent, observed, None, None),
                ];
                bind(bindings, config(RestartPolicy::OneForAll, 3))
                    .run(&controller)
                    .await
            })
            .unwrap();
        let mut child = None;
        loop {
            let mut next = Box::pin(receiver.recv(&cx));
            let event = poll_fn(|poll_cx| {
                assert!(
                    controller.poll_join(poll_cx).is_pending(),
                    "start cancellation returned before cleanup"
                );
                next.as_mut().poll(poll_cx).map(Result::unwrap)
            })
            .await;
            match event {
                Event::Ready(ready) => {
                    assert_eq!(ready.child, 0);
                    assert!(child.replace(ready).is_none());
                }
                Event::Observed(entry) => {
                    assert_eq!(entry.action, Action::CleanupPending);
                    assert_eq!(entry.generation, child.as_ref().unwrap().generation);
                    break;
                }
            }
        }
        let child = child.unwrap();
        let held = events.log.lock().unwrap().clone();
        assert_eq!(
            held.iter()
                .filter(|event| event.action == Action::Started)
                .count(),
            1
        );
        assert_eq!(
            verify_completion_claim(&held, &[child.generation], true),
            Err("premature_generation_completion")
        );
        child.cleanup.release();
        let report = controller.join(&cx).await.unwrap();
        assert!(report.outcome.is_cancelled(), "{report:?}");
        assert_eq!(
            (report.started, report.joined, report.restart_batches),
            (1, 1, 0)
        );
        terminal_witnesses(&events.log.lock().unwrap(), &snapshot());
        serde_json::json!({"scenario":"public_cancel_during_factory","started":1,"joined":1,
            "never_started_child":"b","cleanup_crossed_pending":true,"report":format!("{report:?}")})
    }

    async fn cancellation_during_backoff(cx: Cx, snapshot: &Snapshot) -> serde_json::Value {
        let (events, mut receiver) = events();
        let binding = worker(0, ManagedRestartMode::Transient, events.clone(), None, None);
        let mut handle = bind(
            vec![binding],
            config(RestartPolicy::OneForOne, 3)
                .with_backoff(BackoffStrategy::Fixed(Duration::from_secs(300))),
        )
        .spawn(&cx)
        .unwrap();
        let ready = ready_set(&cx, &mut handle, &mut receiver, &[0]).await;
        perform_work(&cx, &mut handle, &mut receiver, &ready, 500).await;
        let timer = cx.timer_driver().expect("actual owned runtime clock");
        assert!(timer.next_deadline().is_none());
        ready[0].mailbox.try_send(Command::Error).unwrap();
        match next_event(&cx, &mut handle, &mut receiver).await {
            Event::Observed(entry) => assert_eq!(entry.action, Action::Failed),
            Event::Ready(_) => panic!("backoff allowed immediate replacement"),
        }
        // The runtime's real timer registration, not a planning delay field,
        // proves the backoff is parked. There were no timers before this
        // failure, and the delay exceeds the whole native-run watchdog.
        let mut observed_backoff = false;
        for _ in 0..4096 {
            let trace = snapshot();
            observed_backoff = trace.iter().any(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(event.data, TraceData::Task { task, region }
                    if task == ready[0].generation.task && region == ready[0].generation.region)
            }) && timer
                .next_deadline()
                .is_some_and(|deadline| deadline > cx.now());
            if observed_backoff {
                break;
            }
            asupersync::runtime::yield_now().await;
        }
        assert!(observed_backoff, "actual managed backoff never parked");
        handle.abort();
        let report = handle.join().await.unwrap();
        assert!(report.outcome.is_cancelled(), "{report:?}");
        assert_eq!(
            (report.started, report.joined, report.restart_batches),
            (1, 1, 0)
        );
        assert!(matches!(
            report.children[0].outcome,
            Outcome::Err("controlled mailbox failure")
        ));
        terminal_witnesses(&events.log.lock().unwrap(), &snapshot());
        serde_json::json!({"scenario":"public_cancel_during_actual_backoff","delay_seconds":300,
            "started":1,"joined":1,"restart_batches":0,"actual_sleep_witness":true})
    }

    async fn shared_intensity(cx: Cx, snapshot: &Snapshot) -> serde_json::Value {
        // The observer remains outside the parent region that escalation
        // cancels. Both managed controller and its real sibling are inside it.
        let parent = cx
            .open_child_region(asupersync::cx::ChildRegionSpec::inherit())
            .await
            .unwrap();
        let (ready_sender, mut ready_receiver) = asupersync::channel::oneshot::channel();
        let (keep_open, mut sibling_receiver) = mpsc::channel::<()>(1);
        let mut sibling = parent
            .cx()
            .spawn(move |child| async move {
                let identity = (child.task_id(), child.region_id());
                let mut receiving = Box::pin(sibling_receiver.recv(&child));
                let mut ready_sender = Some(ready_sender);
                let result = poll_fn(|poll_cx| {
                    let result = receiving.as_mut().poll(poll_cx);
                    if result.is_pending() {
                        if let Some(sender) = ready_sender.take() {
                            sender.send_blocking(identity).unwrap();
                        }
                    }
                    result
                })
                .await;
                assert_eq!(result, Err(mpsc::RecvError::Cancelled));
                child
                    .cancel_reason()
                    .expect("actual parent escalation reaches a parked sibling")
            })
            .unwrap();
        let (sibling_task, sibling_region) = ready_receiver.recv(&cx).await.unwrap();
        assert_eq!(sibling_region, parent.region_id());
        assert_eq!(keep_open.telemetry_snapshot(3500).recv_waiter_count, 1);
        let (events, mut receiver) = events();
        let bindings = (0..2)
            .map(|index| {
                worker(
                    index,
                    ManagedRestartMode::Transient,
                    events.clone(),
                    None,
                    None,
                )
            })
            .collect();
        let mut handle = bind(
            bindings,
            config(RestartPolicy::OneForOne, 1).with_escalation(EscalationPolicy::Escalate),
        )
        .spawn(parent.cx())
        .unwrap();
        let ready = ready_set(&cx, &mut handle, &mut receiver, &[0, 1]).await;
        perform_work(&cx, &mut handle, &mut receiver, &ready, 600).await;
        // Publish both real failures without awaiting any restart. The single
        // shared policy admits one replacement across these two child names.
        ready[0].mailbox.try_send(Command::Error).unwrap();
        ready[1].mailbox.try_send(Command::Error).unwrap();
        let mut failed = BTreeSet::new();
        let mut replacement = None;
        let mut cleanup_pending = false;
        while failed.len() != 2 || !cleanup_pending {
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Ready(child) => {
                    assert_eq!(child.generation.number, 2);
                    assert!(
                        replacement.replace(child).is_none(),
                        "shared quota admits exactly one replacement"
                    );
                }
                Event::Observed(entry) if entry.action == Action::Failed => {
                    assert_eq!(entry.generation.number, 1);
                    assert!(failed.insert(entry.child));
                }
                Event::Observed(entry) if entry.action == Action::CleanupPending => {
                    assert_eq!(entry.generation, replacement.as_ref().unwrap().generation);
                    assert!(!cleanup_pending);
                    cleanup_pending = true;
                }
                Event::Observed(other) => panic!("unexpected intensity event {other:?}"),
            }
        }
        let reason = sibling.join(&cx).await.unwrap();
        assert_eq!(reason.kind, asupersync::types::CancelKind::FailFast);
        assert!(
            ready
                .iter()
                .any(|child| reason.origin_task == Some(child.generation.task))
        );
        assert_eq!(keep_open.telemetry_snapshot(3500).recv_waiter_count, 0);
        let replacement = replacement.unwrap();
        assert_eq!(
            verify_completion_claim(&events.log.lock().unwrap(), &[replacement.generation], true),
            Err("premature_generation_completion")
        );
        replacement.cleanup.release();
        let report = handle.join().await.unwrap();
        assert_eq!(
            (
                report.started,
                report.joined,
                report.restart_batches,
                report.escalations
            ),
            (3, 3, 1, 1)
        );
        assert!(
            matches!(
                report.outcome,
                Outcome::Err(asupersync::supervision::ManagedSupervisorError::RestartLimit { .. })
            ),
            "{report:?}"
        );
        parent.close().await.unwrap();
        let trace = snapshot();
        terminal_witnesses(&events.log.lock().unwrap(), &trace);
        assert_eq!(trace.iter().filter(|event| event.kind == TraceEventKind::Complete &&
            matches!(event.data, TraceData::Task { task, region } if task == sibling_task && region == sibling_region)).count(), 1);
        let escalations = trace.iter().filter(|event| matches!(&event.data,
            TraceData::Message(message) if message.contains("action=parent_escalated") &&
                ready.iter().any(|child| message.contains(&format!("task={:?}", child.generation.task))))).count();
        assert_eq!(escalations, 1);
        serde_json::json!({"scenario":"public_shared_intensity_actual_parent_escalation",
            "started":3,"joined":3,"restart_batches":1,"escalations":1,
            "parent_sibling":format!("{sibling_task:?}"),"parent_reason":format!("{reason:?}"),
            "events":format!("{:?}", events.log.lock().unwrap())})
    }

    async fn journeys(cx: Cx, snapshot: Snapshot) -> Vec<serde_json::Value> {
        let mut results = Vec::new();
        for policy in [
            RestartPolicy::OneForOne,
            RestartPolicy::OneForAll,
            RestartPolicy::RestForOne,
        ] {
            for panic_child in [false, true] {
                results.push(restart_sets(cx.clone(), &snapshot, policy, panic_child).await);
            }
        }
        for mode in [
            ManagedRestartMode::Permanent,
            ManagedRestartMode::Transient,
            ManagedRestartMode::Temporary,
        ] {
            for terminal in 0..3 {
                results.push(restart_mode(cx.clone(), &snapshot, mode, terminal).await);
            }
        }
        results.push(cancellation_during_start(cx.clone(), &snapshot).await);
        results.push(cancellation_during_backoff(cx.clone(), &snapshot).await);
        results.push(shared_intensity(cx, &snapshot).await);
        assert_eq!(results.len(), 18);
        results
    }

    #[test]
    fn public_managed_supervisor_seeded_lab_work_and_cleanup() {
        for seed in [0x3501, 0x3502, 0x3503] {
            let mut lab = LabRuntime::new(
                LabConfig::new(seed)
                    .max_steps(200_000)
                    .trace_capacity(200_000),
            );
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trace = lab.state.trace_handle();
            let coordinator: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
                Box::pin(async move {
                    journeys(Cx::current().unwrap(), Box::new(move || trace.snapshot())).await
                });
            let (task, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            let reports = joined
                .try_join()
                .unwrap()
                .expect("all managed public journeys completed");
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.leak_count(), 0);
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            let (tasks, wakes) = lab
                .state
                .cancel_request(
                    root,
                    &CancelReason::user("public supervisor journeys done"),
                    None,
                )
                .into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ASUPERSYNC_MANAGED_SUPERVISOR {}",
                serde_json::json!({
                "backend":"lab","seed":seed,"journeys":reports,"live_tasks":0,
                "pending_obligations":0,"leaks":0,"evidence":"scheduled cancellation, not OS signal injection"})
            );
        }
    }

    fn native(sharded: bool) {
        let runtime = if sharded {
            RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .build()
        .unwrap();
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(
            runtime.config().runtime_state_shape,
            if sharded {
                asupersync::runtime::config::RuntimeStateShape::Sharded
            } else {
                asupersync::runtime::config::RuntimeStateShape::Unified
            }
        );
        let observer = runtime.handle();
        let coordinator: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
            Box::pin(async move {
                journeys(
                    Cx::current().unwrap(),
                    Box::new(move || observer.trace_snapshot().unwrap()),
                )
                .await
            });
        let reports = runtime.block_on(runtime.handle().spawn(coordinator));
        runtime.block_on(async {
            for _ in 0..4096 {
                if runtime.is_quiescent() {
                    break;
                }
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(runtime.is_quiescent());
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        eprintln!(
            "ASUPERSYNC_MANAGED_SUPERVISOR {}",
            serde_json::json!({
            "backend":if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
            "journeys":reports,"live_tasks":0,"leaks":0,"shutdown_completed":true})
        );
    }

    #[test]
    fn public_managed_supervisor_native_work_and_cleanup() {
        for sharded in [false, true] {
            let (sent, received) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| native(sharded));
                let _ = sent.send(result);
            });
            let result = received
                .recv_timeout(Duration::from_secs(60))
                .expect("whole native supervisor journey timed out; no cleanup success is implied");
            worker
                .join()
                .expect("owned native watchdog worker terminated");
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    }

    #[cfg(unix)]
    async fn signalled_journey(
        cx: Cx,
        snapshot: Snapshot,
        external: Arc<Gate>,
    ) -> serde_json::Value {
        use std::io::Write;
        let mut signal = asupersync::signal::sigterm().expect("native SIGTERM subscription");
        let (events, mut receiver) = events();
        let witness = Arc::new(Gate::default());
        let bindings = (0..4)
            .map(|index| {
                worker(
                    index,
                    ManagedRestartMode::Permanent,
                    events.clone(),
                    Some(Arc::clone(&witness)),
                    None,
                )
            })
            .collect();
        let mut handle = bind(bindings, config(RestartPolicy::OneForAll, 3))
            .spawn(&cx)
            .unwrap();
        let ready = ready_set(&cx, &mut handle, &mut receiver, &[0, 1, 2, 3]).await;
        perform_work(&cx, &mut handle, &mut receiver, &ready, 700).await;
        let mut signal_wait = Box::pin(signal.recv());
        let mut announced = false;
        let received = poll_fn(|poll_cx| {
            let result = signal_wait.as_mut().poll(poll_cx);
            if result.is_pending() && !announced {
                announced = true;
                println!(
                    "ASUPERSYNC_SUPERVISOR_SIGTERM_READY pid={}",
                    std::process::id()
                );
                std::io::stdout().flush().unwrap();
            }
            result
        })
        .await;
        assert!(
            announced,
            "parent sends only after the actual signal wait is Pending"
        );
        assert_eq!(received, Some(()));
        handle.abort();
        let mut pending = BTreeSet::new();
        while pending.len() != 4 {
            match next_event(&cx, &mut handle, &mut receiver).await {
                Event::Observed(entry) => {
                    assert_eq!(entry.action, Action::CleanupPending);
                    assert_eq!(entry.generation, ready[entry.child].generation);
                    assert!(pending.insert(entry.child));
                }
                Event::Ready(_) => panic!("SIGTERM must not restart any generation"),
            }
        }
        let selected: Vec<_> = ready.iter().map(|child| child.generation).collect();
        assert_eq!(
            verify_completion_claim(&events.log.lock().unwrap(), &selected, true),
            Err("premature_generation_completion")
        );
        assert_eq!(
            verify_completion_claim(&events.log.lock().unwrap(), &[], true),
            Err("zero_selected_generations")
        );
        // The external parent controls release: receiving SIGTERM alone cannot
        // satisfy the report/exit claim while real owned cleanup is suspended.
        external
            .wait(|| {
                println!("ASUPERSYNC_SUPERVISOR_SIGTERM_CLEANUP_PENDING selected=4");
                std::io::stdout().flush().unwrap();
            })
            .await;
        for child in &ready {
            child.cleanup.release();
        }
        let report = handle.join().await.unwrap();
        assert!(report.outcome.is_cancelled(), "{report:?}");
        assert_eq!(
            (
                report.started,
                report.joined,
                report.restart_batches,
                report.escalations
            ),
            (4, 4, 0, 0)
        );
        let log = events.log.lock().unwrap().clone();
        assert_eq!(verify_completion_claim(&log, &selected, true), Ok(()));
        terminal_witnesses(&log, &snapshot());
        let cleaned = |index| {
            log.iter()
                .position(|entry| entry.child == index && entry.action == Action::Cleaned)
                .unwrap()
        };
        assert!(
            cleaned(3) < cleaned(2),
            "dependent cleanup waits for the actual sibling witness"
        );
        for child in &ready {
            let telemetry = child.mailbox.telemetry_snapshot(3500);
            assert_eq!(telemetry.queued_messages, 0);
            assert_eq!(telemetry.recv_waiter_count, 0);
        }
        let payloads: Vec<_> = log
            .iter()
            .filter_map(|entry| match entry.action {
                Action::Work(value) => Some(value),
                _ => None,
            })
            .collect();
        assert_eq!(payloads, vec![700, 701, 702, 703]);
        serde_json::json!({"signal":"actual_process_SIGTERM","selected":4,"started":4,"joined":4,
            "restart_batches":0,"payloads":payloads,"events":format!("{log:?}"),
            "cleanup":"task_owned_async_Pending_then_external_release",
            "negative_controls":["zero_selected_generations","premature_generation_completion"]})
    }

    #[cfg(unix)]
    fn signal_child(sharded: bool) {
        use std::io::BufRead;
        let external = Arc::new(Gate::default());
        let release = Arc::clone(&external);
        let input = std::thread::spawn(move || {
            let mut line = String::new();
            assert!(std::io::stdin().lock().read_line(&mut line).unwrap() > 0);
            assert_eq!(line, "release\n");
            release.release();
        });
        let runtime = if sharded {
            RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .build()
        .unwrap();
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        let observer = runtime.handle();
        let coordinator: Pin<Box<dyn Future<Output = serde_json::Value> + Send>> =
            Box::pin(async move {
                signalled_journey(
                    Cx::current().unwrap(),
                    Box::new(move || observer.trace_snapshot().unwrap()),
                    external,
                )
                .await
            });
        let report = runtime.block_on(runtime.handle().spawn(coordinator));
        input.join().expect("owned release reader terminated");
        runtime.block_on(async {
            for _ in 0..4096 {
                if runtime.is_quiescent() {
                    break;
                }
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(runtime.is_quiescent());
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        println!(
            "ASUPERSYNC_SUPERVISOR_SIGTERM_COMPLETE {}",
            serde_json::json!({
            "backend":if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
            "journey":report,"runtime_shutdown":true,"live_tasks":0,"leaks":0})
        );
    }

    #[cfg(unix)]
    struct OwnedSignalChild(std::process::Child);

    #[cfg(unix)]
    impl Drop for OwnedSignalChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                // This guard owns only the process launched by this test. A
                // forced timeout termination is failure, never drain evidence.
                if let Err(error) = self.0.kill() {
                    eprintln!("owned SIGTERM test cleanup kill: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("owned SIGTERM test cleanup wait: {error}");
                }
            }
        }
    }

    #[cfg(unix)]
    const SIGNAL_CHILD_MARKER: &str = "ASUPERSYNC_MANAGED_SIGTERM_OWNED_CHILD";

    #[cfg(unix)]
    const SIGNAL_TEST: &str = "managed_public::public_managed_supervisor_owned_sigterm_shutdown";

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    enum SignalRunRefusal {
        ZeroSelectedTests,
        MissingSelectionReceipt,
        MissingDrainReceipt,
    }

    #[cfg(unix)]
    fn run_owned_signal_subprocess(
        mode: &str,
        exact_filter: &str,
    ) -> Result<serde_json::Value, SignalRunRefusal> {
        use std::io::{BufRead, Write};
        use std::process::{Command as ProcessCommand, Stdio};
        let mut child = OwnedSignalChild(
            ProcessCommand::new(std::env::current_exe().unwrap())
                .args(["--exact", exact_filter, "--nocapture", "--test-threads=1"])
                .env(SIGNAL_CHILD_MARKER, mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("launch exact owned test subprocess"),
        );
        let pid = child.0.id();
        let stdout = child.0.stdout.take().unwrap();
        let mut stdin = child.0.stdin.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if sent.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        let mut ready = false;
        let mut held = false;
        let mut complete = None;
        let mut harness_pass = false;
        let mut zero_selected = false;
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("whole SIGTERM subprocess watchdog elapsed");
            let line = match received.recv_timeout(remaining) {
                Ok(line) => line.expect("owned child stdout read"),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    panic!("owned SIGTERM child stalled; no success")
                }
            };
            eprintln!("SIGTERM_CHILD backend={mode} pid={pid} {line}");
            if line.contains("ASUPERSYNC_SUPERVISOR_SIGTERM_READY") {
                assert!(!ready);
                ready = true;
                assert!(line.contains(&format!("pid={pid}")));
                assert!(child.0.try_wait().unwrap().is_none());
                let status = ProcessCommand::new("/bin/kill")
                    .args(["-TERM", &pid.to_string()])
                    .status()
                    .expect("deliver real SIGTERM to the owned child only");
                assert!(status.success());
            }
            if line.contains("ASUPERSYNC_SUPERVISOR_SIGTERM_CLEANUP_PENDING") {
                assert!(ready && !held);
                held = true;
                assert!(line.contains("selected=4"));
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "early child exit cannot pass the cleanup claim"
                );
                stdin.write_all(b"release\n").unwrap();
                stdin.flush().unwrap();
            }
            if let Some((_, json)) = line.split_once("ASUPERSYNC_SUPERVISOR_SIGTERM_COMPLETE ") {
                assert!(held && complete.is_none());
                let report: serde_json::Value = serde_json::from_str(json).unwrap();
                assert_eq!(report["runtime_shutdown"], true);
                assert_eq!(report["journey"]["selected"], 4);
                assert_eq!(report["journey"]["joined"], 4);
                assert_eq!(
                    report["journey"]["payloads"],
                    serde_json::json!([700, 701, 702, 703])
                );
                complete = Some(report);
            }
            if line.contains("test result: ok. 1 passed; 0 failed; 0 ignored;") {
                harness_pass = true;
            }
            if line.contains("test result: ok. 0 passed; 0 failed; 0 ignored;") {
                zero_selected = true;
            }
        }
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child did not exit after its report"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        reader.join().expect("owned stdout reader terminated");
        // The same gate judges real positive and planted negative subprocesses
        // only after their actual harness output and terminal status exist.
        if zero_selected {
            return Err(SignalRunRefusal::ZeroSelectedTests);
        }
        if !harness_pass {
            return Err(SignalRunRefusal::MissingSelectionReceipt);
        }
        if !(ready && held && complete.is_some()) {
            return Err(SignalRunRefusal::MissingDrainReceipt);
        }
        Ok(complete.unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn public_managed_supervisor_owned_sigterm_shutdown() {
        if let Ok(mode) = std::env::var(SIGNAL_CHILD_MARKER) {
            match mode.as_str() {
                "current" | "sharded" => signal_child(mode == "sharded"),
                "early_exit" => {
                    // This selected test exits normally before creating a
                    // runtime. Its successful harness status must be rejected
                    // by the very same gate as the two real SIGTERM journeys.
                    println!("ASUPERSYNC_SUPERVISOR_NEGATIVE_EARLY_EXIT no_runtime_or_drain");
                }
                _ => panic!("unknown owned SIGTERM subprocess mode"),
            }
            return;
        }
        for mode in ["current", "sharded"] {
            run_owned_signal_subprocess(mode, SIGNAL_TEST)
                .expect("selected real SIGTERM journey drained and exited");
        }
        assert_eq!(
            run_owned_signal_subprocess(
                "current",
                "managed_public::definitely_missing_managed_supervisor_case",
            ),
            Err(SignalRunRefusal::ZeroSelectedTests),
            "actual zero-test libtest success must not pass the journey gate"
        );
        assert_eq!(
            run_owned_signal_subprocess("early_exit", SIGNAL_TEST),
            Err(SignalRunRefusal::MissingDrainReceipt),
            "actual selected-but-early test success must not pass the journey gate"
        );
        println!(
            "ASUPERSYNC_SUPERVISOR_HARNESS_NEGATIVES {}",
            serde_json::json!({"zero_filter":"ZeroSelectedTests",
                "early_exit":"MissingDrainReceipt","actual_terminal_subprocesses":2})
        );
    }
}
