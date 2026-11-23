use super::*;

fn topic(name: &str) -> KafkaNewTopic {
    KafkaNewTopic::new(name, 3, 1).unwrap()
}

fn success(name: &str) -> KafkaTopicAdminResult {
    KafkaTopicAdminResult {
        topic: name.to_owned(),
        result: Ok(()),
    }
}

#[test]
fn kafka_admin_validates_names_counts_configuration_and_batch_bytes() {
    for name in ["", ".", "..", "a/b", "white space", "nul\0name", "é"] {
        assert!(KafkaNewTopic::new(name, 1, 1).is_err());
    }
    assert!(KafkaNewTopic::new("x".repeat(250), 1, 1).is_err());
    assert!(KafkaNewTopic::new("x".repeat(249), i32::MAX, i16::MAX.into()).is_ok());
    for (partitions, replication) in [(0, 1), (-1, 1), (1, 0), (1, -1), (1, 32768)] {
        assert!(KafkaNewTopic::new("topic", partitions, replication).is_err());
    }
    for (key, value) in [("", "value"), ("nul\0key", "value"), ("key", "nul\0value")] {
        assert!(topic("topic").with_config(key, value).is_err());
    }
    assert!(topic("topic").with_config("key", "s".repeat(4097)).is_err());
    let mut specification = topic("topic");
    for index in 0..MAX_TOPIC_CONFIGS {
        specification = specification
            .with_config(format!("property-{index}"), "private-config-value")
            .unwrap();
    }
    assert!(!format!("{specification:?}").contains("private-config-value"));
    specification = specification
        .with_config("property-0", "replacement")
        .unwrap();
    assert_eq!(specification.configuration.len(), MAX_TOPIC_CONFIGS);
    assert!(specification.with_config("extra", "value").is_err());

    assert!(validate_batch(std::iter::empty()).is_err());
    assert!(validate_batch([("duplicate", 9), ("duplicate", 9)]).is_err());
    assert!(validate_batch([("topic", MAX_REQUEST_BYTES)]).is_ok());
    assert!(validate_batch([("topic", MAX_REQUEST_BYTES + 1)]).is_err());
    assert!(validate_batch([("one", MAX_REQUEST_BYTES), ("two", usize::MAX)]).is_err());
    let names: Vec<_> = (0..=MAX_TOPICS).map(|index| format!("topic-{index}")).collect();
    assert!(
        validate_batch(
            names[..MAX_TOPICS]
                .iter()
                .map(|name| (name.as_str(), name.len()))
        )
        .is_ok()
    );
    assert!(validate_batch(names.iter().map(|name| (name.as_str(), name.len()))).is_err());

    let large = (0..16).fold(topic("topic"), |topic, index| {
        topic
            .with_config(format!("property-{index}"), "x".repeat(4096))
            .unwrap()
    });
    let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
    assert!(matches!(
        admin.create_topics(&Cx::for_testing(), &[large]),
        Err(KafkaAdminError::InvalidInput(_))
    ));
    assert_eq!(admin.in_flight(), 0);
}

#[test]
fn kafka_admin_rejects_unrepresentable_timeouts_and_concurrency() {
    for timeout in [
        Duration::ZERO,
        Duration::from_nanos(999_999),
        Duration::MAX,
        Duration::from_millis(i32::MAX as u64 + 1),
    ] {
        let config = ProducerConfig {
            request_timeout: timeout,
            ..ProducerConfig::default()
        };
        assert!(matches!(
            KafkaAdmin::new(config),
            Err(KafkaAdminError::InvalidInput(_))
        ));
    }
    for timeout in [Duration::from_millis(1), Duration::from_millis(i32::MAX as u64)] {
        let config = ProducerConfig {
            request_timeout: timeout,
            ..ProducerConfig::default()
        };
        assert!(KafkaAdmin::new(config).is_ok());
    }
    assert!(
        KafkaAdmin::with_max_in_flight(
            ProducerConfig::default(),
            NonZeroUsize::new(MAX_IN_FLIGHT + 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn kafka_admin_reports_partial_broker_failure_in_caller_order() {
    let expected = vec!["created".to_owned(), "refused".to_owned()];
    let refusal = KafkaTopicAdminResult {
        topic: "refused".to_owned(),
        result: Err(KafkaTopicBrokerError {
            code: 36,
            name: "TopicAlreadyExists".to_owned(),
        }),
    };
    let report = normalize_report(&expected, vec![refusal.clone(), success("created")]).unwrap();
    assert!(!report.all_succeeded());
    assert_eq!(report.topics()[0].topic(), "created");
    assert!(report.topics()[0].result().is_ok());
    assert_eq!(report.topics()[1], refusal);
    let error = report.topics()[1].result().unwrap_err();
    assert_eq!(error.code(), 36);
    assert_eq!(error.name(), "TopicAlreadyExists");
    for malformed in [
        vec![],
        vec![success("created")],
        vec![success("created"), success("created")],
        vec![success("created"), success("unexpected")],
        vec![success("created"), success("refused"), success("extra")],
    ] {
        assert!(
            normalize_report(&expected, malformed)
                .unwrap_err()
                .outcome_unknown()
        );
    }
}

#[test]
#[cfg(not(feature = "kafka"))]
fn kafka_admin_without_feature_never_uses_the_deterministic_broker() {
    let config = ProducerConfig::default().allow_deterministic_broker_for_testing(true);
    let admin = KafkaAdmin::new(config).unwrap();
    let cx = Cx::for_testing();
    assert!(matches!(
        admin.create_topics(&cx, &[topic("create")]),
        Err(KafkaAdminError::Client(KafkaError::FeatureDisabled))
    ));
    assert!(matches!(
        admin.delete_topics(&cx, &["delete"]),
        Err(KafkaAdminError::Client(KafkaError::FeatureDisabled))
    ));
    assert_eq!(admin.in_flight(), 0);
}

#[test]
fn kafka_admin_admission_refusal_releases_its_slot() {
    let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
    let result = admin.submit_with(
        &Cx::for_testing(),
        AdminRequest::Delete(vec!["topic".into()]),
        |_, _, _| panic!("a driverless caller cannot run an admin job"),
    );
    assert!(matches!(result, Err(KafkaAdminError::Admission(_))));
    assert_eq!(admin.in_flight(), 0);
}

#[test]
fn kafka_admin_refuses_cancelled_and_io_denied_contexts_before_admission() {
    let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(crate::types::CancelKind::User, Some("before admin submission"));
    assert!(matches!(
        admin.submit_with(
            &cancelled,
            AdminRequest::Delete(vec!["topic".into()]),
            |_, _, _| panic!("cancelled admission must not reach the executor")
        ),
        Err(KafkaAdminError::Client(KafkaError::Cancelled))
    ));
    let mut denied = Cx::for_testing();
    denied.runtime_mask = <crate::cx::cap::CapSet<true, true, true, false, true>
        as crate::cx::cap::CapSetRuntimeMask>::MASK;
    assert!(matches!(
        admin.submit_with(
            &denied,
            AdminRequest::Delete(vec!["topic".into()]),
            |_, _, _| panic!("I/O denial must not reach the executor")
        ),
        Err(KafkaAdminError::Client(KafkaError::Config(_)))
    ));
    assert_eq!(admin.in_flight(), 0);
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
    use crate::types::{Budget, CancelKind};
    use std::future::{Future, poll_fn};
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Instant;

    fn bounded(test: impl FnOnce() + Send + 'static) {
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(40))
            .expect("native admin lifecycle must complete");
        worker.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn runtime(workers: usize) -> Runtime {
        let builder = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        };
        builder.blocking_threads(1, 1).build().unwrap()
    }

    fn drained(runtime: &Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
        assert_eq!(report.pending_spawns, 0);
    }

    fn complete(request: AdminRequest) -> Result<KafkaAdminReport, KafkaAdminError> {
        let names = request.names();
        let reports = names.iter().map(|name| success(name)).collect();
        normalize_report(&names, reports)
    }

    #[test]
    fn kafka_admin_cancelled_wait_retains_report_and_shared_admission() {
        bounded(|| {
            for workers in [1, 2] {
                let runtime = runtime(workers);
                let owner = runtime.request_cx_with_budget(Budget::INFINITE);
                let admin = KafkaAdmin::with_max_in_flight(
                    ProducerConfig::default(),
                    NonZeroUsize::new(1).unwrap(),
                )
                .unwrap();
                let clone = admin.clone();
                let (started, mut start) = oneshot::channel();
                let (release, released) = mpsc::channel();
                let calls = Arc::new(AtomicUsize::new(0));
                let called = Arc::clone(&calls);
                let mut operation = admin
                    .submit_with(
                        &owner,
                        AdminRequest::Create(vec![topic("created"), topic("second")]),
                        move |_, _, request| {
                            called.fetch_add(1, Ordering::SeqCst);
                            started.send_blocking(()).unwrap();
                            released.recv_timeout(Duration::from_secs(10)).unwrap();
                            complete(request)
                        },
                    )
                    .unwrap();
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    start.recv(&cx).await.unwrap();
                });
                assert_eq!(clone.in_flight(), 1);
                assert!(matches!(
                    clone.submit_with(
                        &owner,
                        AdminRequest::Delete(vec!["busy".into()]),
                        |_, _, request| complete(request)
                    ),
                    Err(KafkaAdminError::Busy { limit: 1 })
                ));
                // Dropping a borrowing join must leave the same mutation and
                // its receipt available for another observation attempt.
                runtime.block_on(async {
                    let mut waiting = std::pin::pin!(operation.join());
                    poll_fn(|context| {
                        assert!(waiting.as_mut().poll(context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                });
                let observer = Cx::for_testing();
                observer.cancel_with(CancelKind::User, Some("stop observing the admin request"));
                assert!(matches!(
                    runtime.block_on(operation.join_cancellable(&observer)),
                    Err(JoinError::Cancelled(_))
                ));
                assert!(!operation.is_finished());
                assert_eq!(admin.in_flight(), 1);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                release.send(()).unwrap();
                let report = runtime.block_on(operation.join()).unwrap().unwrap();
                assert!(report.all_succeeded());
                assert_eq!(
                    report
                        .topics()
                        .iter()
                        .map(|topic| topic.topic())
                        .collect::<Vec<_>>(),
                    ["created", "second"]
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(admin.in_flight(), 0);
                let mut next = clone
                    .submit_with(
                        &owner,
                        AdminRequest::Delete(vec!["next".into()]),
                        |_, _, request| complete(request),
                    )
                    .unwrap();
                assert!(runtime.block_on(next.join()).unwrap().unwrap().all_succeeded());
                drained(&runtime);
            }
        });
    }

    #[test]
    fn kafka_admin_queued_cancellation_prevents_submission_and_releases_capacity() {
        bounded(|| {
            for workers in [1, 2] {
                let runtime = runtime(workers);
                let owner = runtime.request_cx_with_budget(Budget::INFINITE);
                let (occupied, wait_occupied) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let holding = runtime
                    .spawn_blocking(move || {
                        occupied.send(()).unwrap();
                        released.recv_timeout(Duration::from_secs(10)).unwrap();
                    })
                    .unwrap();
                wait_occupied.recv_timeout(Duration::from_secs(5)).unwrap();
                let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let called = Arc::clone(&calls);
                let mut operation = admin
                    .submit_with(
                        &owner,
                        AdminRequest::Delete(vec!["topic".into()]),
                        move |_, _, request| {
                            called.fetch_add(1, Ordering::SeqCst);
                            complete(request)
                        },
                    )
                    .unwrap();
                let pool = runtime.blocking_handle().unwrap();
                runtime.block_on(async {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while pool.pending_count() == 0 {
                        assert!(
                            Instant::now() < deadline,
                            "admin job must reach the pool queue"
                        );
                        yield_now().await;
                    }
                });
                operation.abort();
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(admin.in_flight(), 1);
                release.send(()).unwrap();
                assert!(matches!(
                    runtime.block_on(operation.join()),
                    Err(JoinError::Cancelled(_))
                ));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(admin.in_flight(), 0);
                assert!(holding.wait_timeout(Duration::from_secs(1)));
                drained(&runtime);
            }
        });
    }

    #[test]
    fn kafka_admin_drop_keeps_running_work_owned_until_native_retirement() {
        bounded(|| {
            let runtime = runtime(2);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
            let (started, mut start) = oneshot::channel();
            let (release, released) = mpsc::channel();
            let operation = admin
                .submit_with(
                    &owner,
                    AdminRequest::Delete(vec!["topic".into()]),
                    move |_, _, request| {
                        started.send_blocking(()).unwrap();
                        released.recv_timeout(Duration::from_secs(10)).unwrap();
                        complete(request)
                    },
                )
                .unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                start.recv(&cx).await.unwrap();
            });
            drop(operation);
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut);
            assert!(report.live_tasks > 0);
            assert_eq!(admin.in_flight(), 1);
            release.send(()).unwrap();
            drained(&runtime);
            assert_eq!(admin.in_flight(), 0);
        });
    }

    #[test]
    fn kafka_admin_error_and_panic_retire_admission_slots() {
        bounded(|| {
            let runtime = runtime(2);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let admin = KafkaAdmin::new(ProducerConfig::default()).unwrap();
            let mut failed = admin
                .submit_with(
                    &owner,
                    AdminRequest::Delete(vec!["topic".into()]),
                    |_, _, _| {
                        Err(KafkaAdminError::OutcomeUnknown(KafkaError::Broker(
                            "bounded failure".into(),
                        )))
                    },
                )
                .unwrap();
            assert!(
                runtime
                    .block_on(failed.join())
                    .unwrap()
                    .unwrap_err()
                    .outcome_unknown()
            );
            assert_eq!(admin.in_flight(), 0);
            let mut panicked = admin
                .submit_with(
                    &owner,
                    AdminRequest::Delete(vec!["topic".into()]),
                    |_, _, _| panic!("native worker test panic"),
                )
                .unwrap();
            assert!(matches!(
                runtime.block_on(panicked.join()),
                Err(JoinError::Panicked(_))
            ));
            assert_eq!(admin.in_flight(), 0);
            drained(&runtime);
        });
    }

    #[test]
    #[cfg(feature = "kafka")]
    fn kafka_admin_native_configuration_failure_is_redacted_and_drained() {
        bounded(|| {
            let runtime = runtime(2);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let config = ProducerConfig::default()
                .with_property("asupersync.invalid.admin.property", "secret-admin-value");
            let admin = KafkaAdmin::new(config).unwrap();
            let mut operation = admin
                .create_topics(&owner, &[topic("never-submitted")])
                .unwrap();
            let error = runtime.block_on(operation.join()).unwrap().unwrap_err();
            assert!(matches!(error, KafkaAdminError::Client(_)));
            assert!(!error.outcome_unknown());
            assert!(!format!("{error:?}").contains("secret-admin-value"));
            assert_eq!(admin.in_flight(), 0);
            drained(&runtime);
        });
    }
}
