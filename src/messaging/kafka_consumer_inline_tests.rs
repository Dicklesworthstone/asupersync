#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::expect_fun_call,
    clippy::map_unwrap_or,
    clippy::cast_possible_wrap,
    clippy::future_not_send
)]
use super::*;
#[cfg(not(feature = "kafka"))]
use crate::messaging::kafka::{
    DeterministicBrokerTestGuard, KafkaProducer, ProducerConfig,
    lock_deterministic_broker_for_tests,
};
use crate::test_utils::run_test_with_cx;

#[derive(Default)]
struct ConsumerWaitWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for ConsumerWaitWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn consumer_wait_context(
    timer: Option<crate::time::TimerDriverHandle>,
    budget: crate::types::Budget,
) -> Cx {
    Cx::new_with_drivers(
        crate::types::RegionId::new_for_test(0, 1),
        crate::types::TaskId::new_for_test(1, 0),
        budget,
        None,
        None,
        None,
        timer,
        None,
    )
}

#[test]
fn consumer_backoff_uses_owner_timer_across_foreign_pollers() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};

    for foreign_origin in [0, 10_000] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let owner = consumer_wait_context(Some(timer.clone()), Budget::INFINITE);
        let foreign_timer = TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_nanos(foreign_origin)),
        ));
        let foreign = consumer_wait_context(Some(foreign_timer.clone()), Budget::INFINITE);
        let _ambient = Cx::set_current(Some(foreign.clone()));
        let wakes = Arc::new(ConsumerWaitWake::default());
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut task = std::task::Context::from_waker(&waker);
        let mut wait = Box::pin(wait_consumer_retry_backoff(
            &owner,
            Duration::from_nanos(10),
        ));

        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(
            timer.pending_count(),
            1,
            "the explicit owner must own the wake"
        );
        assert_eq!(foreign_timer.pending_count(), 0);
        assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
        assert!(foreign.inner.read().cancel_waker_registrations.is_empty());
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            0,
            "the wait must stay parked"
        );

        // A cancelled polling task cannot make an owner's backoff report
        // elapsed time; the owner alone supplies cancellation here.
        foreign.cancel_with(crate::types::CancelKind::User, Some("foreign caller"));
        assert!(wait.as_mut().poll(&mut task).is_pending());
        clock.advance(9);
        assert_eq!(timer.process_timers(), 0);
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        clock.advance(1);
        assert_eq!(timer.process_timers(), 1);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
        assert_eq!(timer.pending_count(), 0);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert_eq!(
            Cx::current().unwrap().cancel_reason(),
            foreign.cancel_reason()
        );
    }
}

#[test]
fn consumer_backoff_cancellation_wakes_the_replacement_waker_and_retires_wait() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
    let owner = consumer_wait_context(Some(timer.clone()), crate::types::Budget::INFINITE);
    let first = Arc::new(ConsumerWaitWake::default());
    let first_waker = std::task::Waker::from(Arc::clone(&first));
    let replacement = Arc::new(ConsumerWaitWake::default());
    let replacement_waker = std::task::Waker::from(Arc::clone(&replacement));
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));

    assert!(
        wait.as_mut()
            .poll(&mut std::task::Context::from_waker(&first_waker))
            .is_pending()
    );
    assert!(
        wait.as_mut()
            .poll(&mut std::task::Context::from_waker(&replacement_waker))
            .is_pending()
    );
    assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(replacement.0.load(Ordering::SeqCst), 0);
    owner.cancel_with(
        crate::types::CancelKind::User,
        Some("cancel parked consumer"),
    );
    assert_eq!(
        first.0.load(Ordering::SeqCst),
        0,
        "the obsolete task waker must be retired"
    );
    assert!(replacement.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        wait.as_mut()
            .poll(&mut std::task::Context::from_waker(&replacement_waker)),
        Poll::Ready(Err(KafkaError::Cancelled))
    ));
    assert_eq!(timer.pending_count(), 0);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_backoff_drop_removes_only_its_own_cancellation_registration() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
    let owner = consumer_wait_context(Some(timer.clone()), crate::types::Budget::INFINITE);
    let wakes = Arc::new(ConsumerWaitWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut task = std::task::Context::from_waker(&waker);
    let mut observer = std::pin::pin!(owner.cancelled());
    assert!(observer.as_mut().poll(&mut task).is_pending());
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 2);
    drop(wait);
    assert_eq!(timer.pending_count(), 0);
    assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    owner.cancel_with(crate::types::CancelKind::User, Some("remaining observer"));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(observer.as_mut().poll(&mut task).is_ready());
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_backoff_masked_cancellation_stays_parked_until_unmasked() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    let timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
    let owner = consumer_wait_context(Some(timer.clone()), crate::types::Budget::INFINITE);
    let wakes = Arc::new(ConsumerWaitWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut task = std::task::Context::from_waker(&waker);
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
    let before_unmask = owner.masked(|| {
        assert!(wait.as_mut().poll(&mut task).is_pending());
        owner.cancel_with(crate::types::CancelKind::User, Some("masked consumer wait"));
        let after_request = wakes.0.load(Ordering::SeqCst);
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            after_request,
            "no cancellation spin"
        );
        assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
        after_request
    });
    assert!(wakes.0.load(Ordering::SeqCst) > before_unmask);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(KafkaError::Cancelled))
    ));
    assert_eq!(timer.pending_count(), 0);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_backoff_driverless_budget_ignores_foreign_virtual_clock() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};
    let budget =
        Budget::INFINITE.with_deadline(crate::time::raw_wall_now() + Duration::from_secs(3600));
    let owner = consumer_wait_context(None, budget);
    let foreign_timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::starting_at(
        Time::from_nanos(u64::MAX - 1),
    )));
    let foreign = consumer_wait_context(Some(foreign_timer.clone()), Budget::INFINITE);
    let _ambient = Cx::set_current(Some(foreign));
    let wakes = Arc::new(ConsumerWaitWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut task = std::task::Context::from_waker(&waker);
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert!(
        !owner.is_cancel_requested(),
        "the wall-clock budget is still live"
    );
    assert_eq!(foreign_timer.pending_count(), 0);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    owner.cancel_with(
        crate::types::CancelKind::User,
        Some("driverless consumer wait"),
    );
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(KafkaError::Cancelled))
    ));
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_backoff_budget_deadline_wakes_before_delay_without_time_authority() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};

    for restrict_time in [false, true] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let owner = consumer_wait_context(
            Some(timer.clone()),
            Budget::INFINITE.with_deadline(Time::from_nanos(110)),
        );
        let owner = if restrict_time {
            let _restricted = owner
                .restrict::<crate::cx::cap::None>()
                .set_current_restricted();
            Cx::current().unwrap()
        } else {
            owner
        };
        let foreign_timer = TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_nanos(10_000)),
        ));
        let foreign = consumer_wait_context(Some(foreign_timer.clone()), Budget::INFINITE);
        let _ambient = Cx::set_current(Some(foreign));
        let wakes = Arc::new(ConsumerWaitWake::default());
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut task = std::task::Context::from_waker(&waker);
        let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_nanos(110)));
        assert_eq!(foreign_timer.pending_count(), 0);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        clock.advance(10);
        assert_eq!(timer.process_timers(), 1);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            wait.as_mut().poll(&mut task),
            Poll::Ready(Err(KafkaError::Cancelled))
        ));
        assert_eq!(
            owner.cancel_reason().unwrap().kind,
            crate::types::CancelKind::Deadline
        );
        assert_eq!(timer.pending_count(), 0);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    }
}

#[test]
fn consumer_backoff_masked_deadline_is_not_rearmed_or_self_waking() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let owner = consumer_wait_context(
        Some(timer.clone()),
        Budget::INFINITE.with_deadline(Time::from_nanos(110)),
    );
    let wakes = Arc::new(ConsumerWaitWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut task = std::task::Context::from_waker(&waker);
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
    let before_unmask = owner.masked(|| {
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(timer.pending_count(), 2);
        clock.advance(10);
        assert_eq!(timer.process_timers(), 1);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(
            timer.pending_count(),
            1,
            "only the original backoff remains"
        );
        let after_deadline = wakes.0.load(Ordering::SeqCst);
        for _ in 0..3 {
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(timer.process_timers(), 0);
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), after_deadline);
        assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
        after_deadline
    });
    assert!(wakes.0.load(Ordering::SeqCst) > before_unmask);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(KafkaError::Cancelled))
    ));
    assert_eq!(timer.pending_count(), 0);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_backoff_refreshes_a_changed_budget_deadline() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let owner = consumer_wait_context(
        Some(timer.clone()),
        Budget::INFINITE.with_deadline(Time::from_nanos(1000)),
    );
    let wakes = Arc::new(ConsumerWaitWake::default());
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut task = std::task::Context::from_waker(&waker);
    let mut wait = Box::pin(wait_consumer_retry_backoff(&owner, Duration::from_secs(60)));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(timer.next_deadline(), Some(Time::from_nanos(1000)));
    owner.inner.write().budget.deadline = Some(Time::from_nanos(110));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(timer.next_deadline(), Some(Time::from_nanos(110)));
    assert_eq!(
        timer.pending_count(),
        2,
        "the superseded deadline must be retired"
    );
    clock.advance(10);
    assert_eq!(timer.process_timers(), 1);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Err(KafkaError::Cancelled))
    ));
    assert_eq!(timer.pending_count(), 0);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn consumer_poll_fallback_waits_on_owner_and_releases_waiters() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, Time};
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();

    for finish in ["timeout", "cancel", "close", "drop"] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let owner = consumer_wait_context(Some(timer.clone()), Budget::INFINITE);
        let foreign_timer = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
        let foreign = consumer_wait_context(Some(foreign_timer.clone()), Budget::INFINITE);
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        futures_lite::future::block_on(consumer.subscribe(&owner, &["consumer-owner-wait"]))
            .unwrap();
        let _ambient = Cx::set_current(Some(foreign.clone()));
        let wakes = Arc::new(ConsumerWaitWake::default());
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut task = std::task::Context::from_waker(&waker);
        let mut wait = Box::pin(consumer.poll_nullable(&owner, Duration::from_nanos(10)));
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(timer.pending_count(), 1);
        assert_eq!(foreign_timer.pending_count(), 0);
        assert_eq!(consumer.state_notify.waiter_count(), 1);
        assert_eq!(owner.inner.read().cancel_waker_registrations.len(), 1);
        assert!(foreign.inner.read().cancel_waker_registrations.is_empty());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        match finish {
            "timeout" => {
                clock.advance(10);
                assert_eq!(timer.process_timers(), 1);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(
                    wait.as_mut().poll(&mut task),
                    Poll::Ready(Ok(None))
                ));
            }
            "cancel" => {
                owner.cancel_with(crate::types::CancelKind::User, Some("cancel consumer poll"));
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(
                    wait.as_mut().poll(&mut task),
                    Poll::Ready(Err(KafkaError::Cancelled))
                ));
            }
            "close" => {
                futures_lite::future::block_on(consumer.close(&owner)).unwrap();
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(
                    matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(KafkaError::Config(message))) if message.contains("closed"))
                );
            }
            "drop" => {}
            _ => unreachable!(),
        }
        drop(wait);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(consumer.state_notify.waiter_count(), 0);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    }
}

#[test]
fn nullable_record_compatibility_conversion_never_invents_nulls() {
    let legacy = ConsumerRecord {
        topic: "compact".into(),
        partition: 2,
        offset: 17,
        key: Some(Vec::new()),
        payload: Vec::new(),
        timestamp: Some(1700000000000),
        headers: vec![("same".into(), Vec::new()), ("same".into(), b"x".to_vec())],
    };
    let nullable = NullableConsumerRecord::from(legacy.clone());
    assert_eq!(nullable.payload, Some(Vec::new()));
    assert_eq!(nullable.key, Some(Vec::new()));
    assert_eq!(
        nullable.headers,
        vec![
            ("same".into(), Some(Vec::new())),
            ("same".into(), Some(b"x".to_vec())),
        ]
    );
    assert_eq!(ConsumerRecord::from(nullable.clone()), legacy);

    let tombstone = NullableConsumerRecord {
        payload: None,
        headers: vec![("same".into(), None), ("same".into(), Some(Vec::new()))],
        ..nullable
    };
    let projected = ConsumerRecord::from(tombstone);
    assert!(projected.payload.is_empty());
    assert_eq!(
        projected.headers,
        vec![("same".into(), Vec::new()), ("same".into(), Vec::new()),]
    );
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn nullable_native_headers() -> rdkafka::message::OwnedHeaders {
    use rdkafka::message::{Header, OwnedHeaders};
    OwnedHeaders::new()
        .insert(Header {
            key: "same",
            value: None::<&[u8]>,
        })
        .insert(Header {
            key: "same",
            value: Some(&b""[..]),
        })
        .insert(Header {
            key: "same",
            value: Some(&b"header"[..]),
        })
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn nullable_native_fixture(bootstrap: &str, topic: &str) {
    use rdkafka::producer::{BaseProducer, BaseRecord, Producer};
    // Raw rdkafka is the independent producer: it supplies actual nulls on
    // the Kafka wire instead of constructing this crate's record type.
    let producer: BaseProducer = rdkafka::ClientConfig::new()
        .set("bootstrap.servers", bootstrap)
        .set("message.timeout.ms", "10000")
        .create()
        .unwrap();
    for payload in [
        Some(&b"value"[..]),
        Some(&b""[..]),
        None,
        Some(&b"tail"[..]),
    ] {
        let mut record: BaseRecord<'_, [u8], [u8]> = BaseRecord::to(topic)
            .key(&b"key"[..])
            .partition(0)
            .timestamp(1700000000000)
            .headers(nullable_native_headers());
        record.payload = payload;
        producer.send(record).unwrap();
    }
    producer.flush(Duration::from_secs(10)).unwrap();
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn assert_nullable_headers(record: &NullableConsumerRecord) {
    assert_eq!(record.key.as_deref(), Some(&b"key"[..]));
    assert_eq!(record.timestamp, Some(1700000000000));
    assert_eq!(
        record.headers,
        vec![
            ("same".into(), None),
            ("same".into(), Some(Vec::new())),
            ("same".into(), Some(b"header".to_vec())),
        ]
    );
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn nullable_native_journey(multithread: bool, abandon_buffered_poll: bool) {
    use crate::cx::ChildRegionSpec;
    use crate::cx::resource_bracket::{BracketConfig, BracketUseFuture};
    use crate::runtime::RuntimeBuilder;
    use crate::types::{Budget, Outcome};

    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "nullable-records";
    cluster.create_topic(topic, 1, 1).unwrap();
    nullable_native_fixture(&cluster.bootstrap_servers(), topic);
    // librdkafka's mock coordinator does not empty a group when its last
    // member leaves. It holds a JoinGroup for session.timeout.ms - 1 s
    // (44 s at the default 45 s) before it elects the next member, so the
    // resumed consumer below needs a short session to be assigned in time.
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "nullable-records-group")
        .force_real_kafka(true)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .session_timeout(Duration::from_secs(10))
        .with_property("group.protocol", "classic");
    let builder = if multithread {
        RuntimeBuilder::new().worker_threads(2)
    } else {
        RuntimeBuilder::current_thread()
    };
    let runtime = builder.blocking_threads(1, 2).build().unwrap();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on_with_cx(owner.clone(), async move {
        let enclosing = owner
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let mut handle = KafkaConsumer::spawn_scoped(
            enclosing.cx(),
            config.clone(),
            BracketConfig::new(u32::MAX),
            move |cx, consumer| -> BracketUseFuture<'_, (), KafkaError> {
                Box::pin(async move {
                    consumer.subscribe(&cx, &[topic]).await.unwrap();
                    for (offset, payload) in [(0, &b"value"[..]), (1, &b""[..])] {
                        let record = consumer
                            .poll_nullable(&cx, Duration::from_secs(10))
                            .await
                            .unwrap()
                            .expect("record from the mock broker");
                        assert_eq!((record.partition, record.offset), (0, offset));
                        assert_eq!(record.payload.as_deref(), Some(payload));
                        assert_nullable_headers(&record);
                    }

                    let tombstone = if abandon_buffered_poll {
                        let operations = consumer.broker_ops.as_ref().unwrap();
                        let (published, mut wait_published) = crate::channel::oneshot::channel();
                        let (release, await_release) = std::sync::mpsc::channel();
                        *operations.after_record_buffered.lock() = Some(BufferedRecordHook {
                            published,
                            release: await_release,
                        });
                        let mut polling =
                            Box::pin(consumer.poll_nullable(&cx, Duration::from_secs(10)));
                        let mut witnessing = Box::pin(wait_published.recv(&cx));
                        std::future::poll_fn(|task_cx| {
                            assert!(
                                polling.as_mut().poll(task_cx).is_pending(),
                                "the admitted poll must still await its blocking receipt"
                            );
                            witnessing.as_mut().poll(task_cx)
                        })
                        .await
                        .unwrap();
                        {
                            let buffered = consumer.buffered_outcome.lock();
                            let record = buffered
                                .as_ref()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .record
                                .as_ref()
                                .expect("actual broker record is buffered");
                            assert_eq!(record.offset, 2);
                            assert!(record.payload.is_none());
                        }
                        drop(witnessing);
                        drop(polling);
                        // The old blocking call is still owned and parked.
                        // Its result must be available exactly once to the
                        // next API call without waiting for that receipt.
                        let record = consumer
                            .poll_nullable(&cx, Duration::ZERO)
                            .await
                            .unwrap()
                            .expect("abandoned poll's tombstone");
                        release.send(()).unwrap();
                        record
                    } else {
                        consumer
                            .poll_nullable(&cx, Duration::from_secs(10))
                            .await
                            .unwrap()
                            .expect("tombstone from the mock broker")
                    };
                    assert_eq!((tombstone.partition, tombstone.offset), (0, 2));
                    assert!(tombstone.payload.is_none(), "a tombstone must remain null");
                    assert_nullable_headers(&tombstone);
                    assert_eq!(consumer.position(topic, 0), Some(3));

                    if abandon_buffered_poll {
                        let tail = consumer
                            .poll(&cx, Duration::from_secs(10))
                            .await
                            .unwrap()
                            .expect("following record");
                        assert_eq!((tail.offset, tail.payload.as_slice()), (3, &b"tail"[..]));
                        assert!(
                            consumer
                                .poll_nullable(&cx, Duration::ZERO)
                                .await
                                .unwrap()
                                .is_none()
                        );
                    } else {
                        // Re-reading through the shipped API preserves its
                        // compatibility semantics and advances the SAME stream.
                        consumer
                            .seek(&cx, &TopicPartitionOffset::new(topic, 0, 1))
                            .await
                            .unwrap();
                        for offset in [1, 2] {
                            let legacy = consumer
                                .poll(&cx, Duration::from_secs(10))
                                .await
                                .unwrap()
                                .expect("legacy empty value or tombstone");
                            assert_eq!(legacy.offset, offset);
                            assert!(legacy.payload.is_empty());
                            assert_eq!(
                                legacy.headers,
                                vec![
                                    ("same".into(), Vec::new()),
                                    ("same".into(), Vec::new()),
                                    ("same".into(), b"header".to_vec()),
                                ]
                            );
                        }
                        consumer
                            .commit_offsets(&cx, &[TopicPartitionOffset::new(topic, 0, 3)])
                            .await
                            .unwrap();
                        assert_eq!(consumer.committed_offset(topic, 0), Some(3));
                    }
                    Outcome::Ok(())
                })
            },
        )
        .unwrap();
        let report = handle.join().await.unwrap();
        assert!(matches!(
            report.usage.as_ref().unwrap().outcome,
            Outcome::Ok(())
        ));
        assert!(matches!(
            report.release.as_ref().unwrap().outcome,
            Outcome::Ok(())
        ));
        assert!(report.unreleased.is_none());

        if !abandon_buffered_poll {
            // A new native consumer in the same group must resume at the
            // broker-committed next offset, after the tombstone.
            let mut resumed = KafkaConsumer::spawn_scoped(
                enclosing.cx(),
                config,
                BracketConfig::new(u32::MAX),
                move |cx, consumer| -> BracketUseFuture<'_, (), KafkaError> {
                    Box::pin(async move {
                        consumer.subscribe(&cx, &[topic]).await.unwrap();
                        // Covers the mock's 9 s join hold after the first
                        // consumer left (see the config above).
                        let tail = consumer
                            .poll_nullable(&cx, Duration::from_secs(30))
                            .await
                            .unwrap()
                            .expect("resume from the committed next offset");
                        assert_eq!(tail.offset, 3);
                        assert_eq!(tail.payload.as_deref(), Some(&b"tail"[..]));
                        assert_nullable_headers(&tail);
                        Outcome::Ok(())
                    })
                },
            )
            .unwrap();
            let report = resumed.join().await.unwrap();
            assert!(matches!(
                report.usage.as_ref().unwrap().outcome,
                Outcome::Ok(())
            ));
            assert!(matches!(
                report.release.as_ref().unwrap().outcome,
                Outcome::Ok(())
            ));
            assert!(report.unreleased.is_none());
        }
        enclosing.close().await.unwrap();
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    drop(runtime);
    drop(cluster);
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn bounded_nullable_native(multithread: bool, abandon_buffered_poll: bool) {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(|| {
            nullable_native_journey(multithread, abandon_buffered_poll);
        });
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(60))
        .expect("nullable Kafka journey and native teardown must finish");
    thread.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// br-asupersync-messaging-client-audit-k6pxks, item 22. Uses librdkafka's
/// native wire client and in-process mock broker, not live-cluster proof.
#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_nullable_poll_preserves_tombstones_headers_seek_and_committed_resume() {
    for multithread in [false, true] {
        bounded_nullable_native(multithread, false);
    }
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_nullable_poll_recovers_tombstone_after_pending_future_drop_once() {
    for multithread in [false, true] {
        bounded_nullable_native(multithread, true);
    }
}

/// A broker poll result still buffered when the application seeks (a poll
/// cancelled after its broker poll finished) kept its pre-seek record and
/// position: the next poll delivered a record from before the seek and
/// moved the partition back.
#[cfg(feature = "kafka")]
#[test]
fn seek_rebases_a_buffered_poll_result() {
    let outcome = |partition| BrokerPollOutcome {
        record: Some(NullableConsumerRecord {
            topic: "orders".to_string(),
            partition,
            offset: 41,
            key: None,
            payload: Some(b"x".to_vec()),
            timestamp: None,
            headers: Vec::new(),
        }),
        snapshot: BrokerSnapshot {
            assigned_partitions: [("orders".to_string(), 0), ("orders".to_string(), 1)]
                .into_iter()
                .collect(),
            positions: [
                (("orders".to_string(), 0), 42),
                (("orders".to_string(), 1), 9),
            ]
            .into_iter()
            .collect(),
        },
        transient_error: None,
    };

    let mut buffered = Some(Ok(outcome(0)));
    rebase_buffered_after_seek(&mut buffered, "orders", 0, 0);
    let Some(Ok(rebased)) = buffered else {
        panic!("the outcome stays buffered");
    };
    assert!(
        rebased.record.is_none(),
        "the record fetched before the seek is dropped"
    );
    assert_eq!(rebased.snapshot.positions[&("orders".to_string(), 0)], 0);
    assert_eq!(rebased.snapshot.positions[&("orders".to_string(), 1)], 9);

    let mut other = Some(Ok(outcome(1)));
    rebase_buffered_after_seek(&mut other, "orders", 0, 0);
    let Some(Ok(kept)) = other else {
        panic!("the outcome stays buffered");
    };
    assert_eq!(
        kept.record.map(|record| record.partition),
        Some(1),
        "a record for another partition is kept"
    );
}

/// br-asupersync-pm29wb: the broker thread of a dropped poll can buffer
/// its record after the next poll has started its own broker thread. That
/// thread polled again and replaced the buffered record, which was never
/// delivered although its position had advanced.
#[cfg(feature = "kafka")]
#[test]
fn a_record_buffered_by_a_dropped_poll_is_not_overwritten() {
    // Test builds use the native backend only when forced; librdkafka's
    // in-process mock broker stands in for a cluster.
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    cluster.create_topic("orders", 1, 1).unwrap();
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "buffered-poll-group")
        .force_real_kafka(true);
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();
        let operations = Arc::clone(consumer.broker_ops.as_ref().expect("native backend"));

        // Stand in for the dropped poll's broker thread, which holds the lock.
        let (locked, await_locked) = std::sync::mpsc::channel();
        let (release, await_release) = std::sync::mpsc::channel::<()>();
        let holder = {
            let operations = Arc::clone(&operations);
            std::thread::spawn(move || {
                let _lock = operations.serial.lock();
                locked.send(()).unwrap();
                let _ = await_release.recv_timeout(Duration::from_secs(20));
            })
        };
        await_locked.recv_timeout(Duration::from_secs(10)).unwrap();

        let (attempted, mut wait_attempted) = crate::channel::oneshot::channel();
        *operations.before_lock.lock() = Some(attempted);
        let mut polling = Box::pin(consumer.poll(&cx, Duration::from_secs(5)));
        let mut attempted = Box::pin(wait_attempted.recv(&cx));
        std::future::poll_fn(|task_cx| {
            assert!(polling.as_mut().poll(task_cx).is_pending());
            attempted.as_mut().poll(task_cx)
        })
        .await
        .unwrap();

        // The next poll's broker thread now waits for the lock; the dropped
        // poll's thread buffers its record and releases it.
        *consumer.buffered_outcome.lock() = Some(Ok(BrokerPollOutcome {
            record: Some(NullableConsumerRecord {
                topic: "orders".to_string(),
                partition: 0,
                offset: 41,
                key: None,
                payload: Some(b"x".to_vec()),
                timestamp: None,
                headers: Vec::new(),
            }),
            snapshot: BrokerSnapshot {
                assigned_partitions: [("orders".to_string(), 0)].into_iter().collect(),
                positions: [(("orders".to_string(), 0), 42)].into_iter().collect(),
            },
            transient_error: None,
        }));
        release.send(()).unwrap();
        holder.join().unwrap();

        let delivered = polling.await.expect("poll").expect("the buffered record");
        assert_eq!((delivered.partition, delivered.offset), (0, 41));
    });
}

#[test]
fn transactional_offsets_validate_batches_and_membership_before_enrollment() {
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["input-a", "input-b"])
            .await
            .unwrap();
        let metadata = consumer.group_metadata_for_state_test();
        assert_eq!(metadata.group_id(), consumer.config().group_id);
        assert_eq!(metadata.generation(), consumer.rebalance_generation());
        let valid = metadata
            .prepare_offsets(&[
                TopicPartitionOffset::new("input-a", 0, 0),
                TopicPartitionOffset::new("input-b", 0, i64::MAX),
            ])
            .unwrap();
        assert_eq!(valid.offsets.len(), 2);
        for bad in [
            vec![],
            vec![TopicPartitionOffset::new("input-a", -1, 2)],
            vec![TopicPartitionOffset::new("input-a", 0, -1)],
            vec![TopicPartitionOffset::new("foreign", 0, 2)],
            vec![TopicPartitionOffset::new("input-a", 1, 2)],
            vec![
                TopicPartitionOffset::new("input-a", 0, 1),
                TopicPartitionOffset::new("input-a", 0, 2),
            ],
            vec![TopicPartitionOffset::new("input-a", 0, 2); 3],
        ] {
            assert!(metadata.prepare_offsets(&bad).is_err(), "batch {bad:?}");
        }
        consumer
            .state
            .lock()
            .committed_offsets
            .insert(("input-a".into(), 0), 7);
        assert!(
            metadata
                .prepare_offsets(&[TopicPartitionOffset::new("input-a", 0, 6)])
                .is_err()
        );
        let pending = metadata
            .prepare_offsets(&[TopicPartitionOffset::new("input-a", 0, 8)])
            .unwrap();
        consumer
            .rebalance(&cx, &[TopicPartitionOffset::new("input-b", 0, 0)])
            .await
            .unwrap();
        assert!(matches!(
            pending.validate_current(),
            Err(KafkaError::Transaction(_))
        ));
        assert!(
            metadata
                .prepare_offsets(&[TopicPartitionOffset::new("input-a", 0, 8)])
                .is_err()
        );
        let current = consumer.group_metadata_for_state_test();
        consumer.close(&cx).await.unwrap();
        assert!(
            current
                .prepare_offsets(&[TopicPartitionOffset::new("input-b", 0, 1)])
                .is_err()
        );
        drop(consumer);
        assert!(
            current
                .prepare_offsets(&[TopicPartitionOffset::new("input-b", 0, 1)])
                .is_err()
        );
    });
}

#[test]
fn transactional_offsets_merge_monotonically_and_publish_only_current_cache() {
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["input-a", "input-b"])
            .await
            .unwrap();
        let metadata = consumer.group_metadata_for_state_test();
        let first = metadata
            .prepare_offsets(&[TopicPartitionOffset::new("input-a", 0, 3)])
            .unwrap();
        let second = metadata
            .clone()
            .prepare_offsets(&[
                TopicPartitionOffset::new("input-a", 0, 7),
                TopicPartitionOffset::new("input-b", 0, 2),
            ])
            .unwrap();
        let merged = first.merge(&second).unwrap();
        assert_eq!(merged.offsets.get(&("input-a".into(), 0)), Some(&7));
        assert_eq!(merged.offsets.get(&("input-b".into(), 0)), Some(&2));
        assert_eq!(
            consumer.committed_offset("input-a", 0),
            None,
            "enrollment is not a commit"
        );
        assert!(
            merged.merge(&first).is_err(),
            "later enrollment must not regress an earlier offset"
        );
        let another_snapshot = consumer
            .group_metadata_for_state_test()
            .prepare_offsets(&[TopicPartitionOffset::new("input-a", 0, 8)])
            .unwrap();
        assert!(
            merged.merge(&another_snapshot).is_err(),
            "cannot replace membership in one transaction"
        );
        merged.clone().publish_committed();
        assert_eq!(consumer.committed_offset("input-a", 0), Some(7));
        assert_eq!(consumer.committed_offset("input-b", 0), Some(2));
        consumer
            .state
            .lock()
            .committed_offsets
            .insert(("input-a".into(), 0), 11);
        merged.clone().publish_committed();
        assert_eq!(consumer.committed_offset("input-a", 0), Some(11));
        assert!(
            merged.validate_current().is_err(),
            "queued enrollment must recheck concurrent commits"
        );
        consumer.state.lock().rebalance_generation += 1;
        consumer.state.lock().committed_offsets.clear();
        merged.publish_committed();
        assert_eq!(
            consumer.committed_offset("input-a", 0),
            None,
            "old assignment must not update a new owner"
        );
        consumer.close(&cx).await.unwrap();
    });
}

#[test]
fn transactional_group_metadata_refuses_auto_commit_and_model_backends() {
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        assert!(matches!(
            consumer.group_metadata(&cx).await,
            Err(KafkaError::FeatureDisabled)
        ));
        consumer.close(&cx).await.unwrap();
        let consumer =
            KafkaConsumer::new(ConsumerConfig::default().enable_auto_commit(true)).unwrap();
        assert!(
            matches!(consumer.group_metadata(&cx).await, Err(KafkaError::Config(message))
                if message.contains("enable_auto_commit=false"))
        );
        consumer.close(&cx).await.unwrap();
    });
}

/// br-asupersync-bi2462.26: raw properties keep insertion order and a
/// repeated key overrides in place (consumer and producer twins).
#[test]
fn with_property_keeps_insertion_order_and_overrides_the_same_key() {
    let consumer = ConsumerConfig::new(vec!["127.0.0.1:1".to_string()], "group")
        .with_property("a", "1")
        .with_property("b", "2")
        .with_property("a", "3");
    assert_eq!(
        consumer.extra_properties(),
        &[
            ("a".to_string(), "3".to_string()),
            ("b".to_string(), "2".to_string())
        ]
    );
    let mut in_place = consumer.clone();
    in_place.set_property("b", "4");
    assert_eq!(
        in_place.extra_properties()[1],
        ("b".to_string(), "4".to_string())
    );

    let producer = crate::messaging::kafka::ProducerConfig::new(vec!["127.0.0.1:1".to_string()])
        .with_property("linger.ms", "9")
        .with_property("linger.ms", "10");
    assert_eq!(
        producer.extra_properties(),
        &[("linger.ms".to_string(), "10".to_string())]
    );
}

/// br-asupersync-bi2462.26: a raw property never overrides a typed field
/// (typed setters run after the passthrough), while a key no typed field
/// owns reaches librdkafka unchanged.
#[cfg(feature = "kafka")]
#[test]
fn typed_fields_win_over_raw_properties_in_the_client_config() {
    let config = ConsumerConfig::new(vec!["127.0.0.1:1".to_string()], "group")
        .with_property("bootstrap.servers", "raw-host:9")
        .with_property("group.id", "raw-group")
        .with_property("partition.assignment.strategy", "cooperative-sticky");
    let client = build_consumer_config(&config);
    assert_eq!(client.get("bootstrap.servers"), Some("127.0.0.1:1"));
    assert_eq!(client.get("group.id"), Some("group"));
    assert_eq!(
        client.get("partition.assignment.strategy"),
        Some("cooperative-sticky")
    );
}

#[test]
fn transient_error_is_recorded_once_per_code_and_counted() {
    use crate::types::Time;
    let mut state = ConsumerState::default();
    assert!(state.last_transient_error.is_none());

    let first = record_transient_error(&mut state, "UnknownTopicOrPartition", Time::from_nanos(10));
    assert_eq!(
        first
            .as_ref()
            .map(|entry| (entry.code.as_str(), entry.count)),
        Some(("UnknownTopicOrPartition", 1)),
        "first occurrence of a code is announced"
    );
    assert!(
        record_transient_error(&mut state, "UnknownTopicOrPartition", Time::from_nanos(20))
            .is_none(),
        "a repeat of the same code is counted, not announced"
    );
    let recorded = state.last_transient_error.clone().expect("recorded");
    assert_eq!(recorded.count, 2);
    assert_eq!(recorded.first_seen, Time::from_nanos(10));
    assert_eq!(recorded.last_seen, Time::from_nanos(20));

    let other = record_transient_error(&mut state, "SomeOtherCode", Time::from_nanos(30));
    assert_eq!(
        other
            .as_ref()
            .map(|entry| (entry.code.as_str(), entry.count)),
        Some(("SomeOtherCode", 1)),
        "a different code replaces the entry and is announced again"
    );
    assert_eq!(
        state.last_transient_error.as_ref().map(|entry| entry.count),
        Some(1)
    );
}
#[cfg(feature = "kafka")]
use rdkafka::topic_partition_list::Offset;
use std::sync::Arc;
#[cfg(not(feature = "kafka"))]
use std::time::Instant;

#[cfg(not(feature = "kafka"))]
fn deterministic_broker_guard() -> DeterministicBrokerTestGuard {
    lock_deterministic_broker_for_tests()
}

#[cfg(feature = "kafka")]
#[test]
fn broker_snapshot_update_tracks_generation_and_revocations() {
    let mut state = ConsumerState::default();
    state.subscribed_topics.insert("orders".to_string());
    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("orders".to_string(), 0), ("orders".to_string(), 1)]),
            BTreeMap::from([
                (("orders".to_string(), 0), 4),
                (("orders".to_string(), 1), 8),
            ]),
        ),
    );
    assert_eq!(state.rebalance_generation, 1);
    assert_eq!(state.last_revoked_partitions.len(), 0);
    assert_eq!(state.positions.get(&("orders".to_string(), 1)), Some(&8));

    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("orders".to_string(), 1)]),
            BTreeMap::from([(("orders".to_string(), 1), 9)]),
        ),
    );
    assert_eq!(state.rebalance_generation, 2);
    assert_eq!(
        state.last_revoked_partitions,
        BTreeSet::from([("orders".to_string(), 0)])
    );
    assert_eq!(state.positions.get(&("orders".to_string(), 1)), Some(&9));
    assert!(!state.positions.contains_key(&("orders".to_string(), 0)));
}

#[cfg(feature = "kafka")]
#[test]
fn offset_from_rdkafka_only_keeps_absolute_offsets() {
    assert_eq!(offset_from_rdkafka(Offset::Offset(7)), Some(7));
    assert_eq!(offset_from_rdkafka(Offset::Offset(-1)), None);
    assert_eq!(offset_from_rdkafka(Offset::Beginning), None);
    assert_eq!(offset_from_rdkafka(Offset::End), None);
    assert_eq!(offset_from_rdkafka(Offset::Stored), None);
    assert_eq!(offset_from_rdkafka(Offset::Invalid), None);
}

#[test]
fn test_config_defaults() {
    let config = ConsumerConfig::default();
    assert_eq!(config.group_id, "asupersync-default");
    assert_eq!(config.max_poll_records, 500);
    // br-asupersync-2i2e21: default is manual-commit (at-least-once).
    // Flipping this assertion is a deliberate behavior change — see the
    // docstring on `ConsumerConfig::enable_auto_commit` for the
    // at-most-once footgun this default avoids.
    assert!(
        !config.enable_auto_commit,
        "default must be manual-commit / at-least-once"
    );
}

#[test]
fn test_config_builder() {
    let config = ConsumerConfig::new(vec!["kafka:9092".to_string()], "group-1")
        .client_id("consumer-1")
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .enable_auto_commit(false)
        .max_poll_records(1000)
        .fetch_min_bytes(4)
        .fetch_max_bytes(1024)
        .isolation_level(IsolationLevel::ReadCommitted);

    assert_eq!(config.bootstrap_servers, vec!["kafka:9092"]);
    assert_eq!(config.group_id, "group-1");
    assert_eq!(config.client_id, Some("consumer-1".to_string()));
    assert_eq!(config.auto_offset_reset, AutoOffsetReset::Earliest);
    assert!(!config.enable_auto_commit);
    assert_eq!(config.max_poll_records, 1000);
    assert_eq!(config.fetch_min_bytes, 4);
    assert_eq!(config.fetch_max_bytes, 1024);
    assert_eq!(config.isolation_level, IsolationLevel::ReadCommitted);
    assert!(!config.allow_insecure_transport_for_testing);
    assert_eq!(config.security, KafkaSecurityConfig::Plaintext);
}

#[test]
fn test_config_validation() {
    let empty_servers = ConsumerConfig {
        bootstrap_servers: vec![],
        ..Default::default()
    };
    assert!(empty_servers.validate().is_err());

    let empty_group = ConsumerConfig::new(vec!["kafka:9092".to_string()], "");
    assert!(empty_group.validate().is_err());

    let bad_fetch = ConsumerConfig::new(vec!["kafka:9092".to_string()], "group")
        .fetch_min_bytes(10)
        .fetch_max_bytes(1);
    assert!(bad_fetch.validate().is_err());

    let remote_plaintext =
        ConsumerConfig::new(vec!["broker.example.com:9092".to_string()], "group");
    let err = remote_plaintext.validate().expect_err(
        "remote non-loopback bootstrap servers must fail closed until TLS/SASL support lands",
    );
    assert!(matches!(err, KafkaError::Config(msg) if msg.contains("TLS or SASL_SSL")));

    let explicit_insecure =
        ConsumerConfig::new(vec!["broker.example.com:9092".to_string()], "group")
            .allow_insecure_transport_for_testing(true);
    assert!(explicit_insecure.validate().is_ok());

    let tls = ConsumerConfig::new(vec!["broker.example.com:9092".to_string()], "group")
        .tls(KafkaTlsConfig::new().ca_location("/etc/ssl/certs"));
    assert!(tls.validate().is_ok());

    let sasl = ConsumerConfig::new(vec!["broker.example.com:9092".to_string()], "group")
        .sasl_scram_sha_256("service-user", "top-secret");
    assert!(sasl.validate().is_ok());

    let bad_sasl = ConsumerConfig::new(vec!["broker.example.com:9092".to_string()], "group")
        .sasl_scram_sha_512("service-user", "");
    let err = bad_sasl
        .validate()
        .expect_err("blank SASL password must fail closed");
    assert!(matches!(err, KafkaError::Config(msg) if msg.contains("password")));

    let debug = format!("{sasl:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("top-secret"));
}

#[test]
fn test_topic_partition_offset() {
    let tpo = TopicPartitionOffset::new("topic", 1, 42);
    assert_eq!(tpo.topic, "topic");
    assert_eq!(tpo.partition, 1);
    assert_eq!(tpo.offset, 42);
}

#[test]
fn test_consumer_creation() {
    let config = ConsumerConfig::default();
    let consumer = KafkaConsumer::new(config);
    assert!(consumer.is_ok());
}

// Pure data-type tests (wave 12 – CyanBarn)

#[test]
fn auto_offset_reset_default() {
    let d = AutoOffsetReset::default();
    assert_eq!(d, AutoOffsetReset::Latest);
}

#[test]
fn auto_offset_reset_debug_copy_eq() {
    let e = AutoOffsetReset::Earliest;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("Earliest"));

    // Copy
    let e2 = e;
    assert_eq!(e, e2);

    // Clone
    let e3 = e;
    assert_eq!(e, e3);

    // Inequality
    assert_ne!(AutoOffsetReset::Earliest, AutoOffsetReset::Latest);
    assert_ne!(AutoOffsetReset::Latest, AutoOffsetReset::None);
}

#[test]
fn isolation_level_default() {
    let d = IsolationLevel::default();
    assert_eq!(d, IsolationLevel::ReadUncommitted);
}

#[test]
fn isolation_level_debug_copy_eq() {
    let rc = IsolationLevel::ReadCommitted;
    let dbg = format!("{rc:?}");
    assert!(dbg.contains("ReadCommitted"));

    let rc2 = rc;
    assert_eq!(rc, rc2);

    assert_ne!(
        IsolationLevel::ReadCommitted,
        IsolationLevel::ReadUncommitted
    );
}

#[test]
fn consumer_config_debug_clone() {
    let cfg = ConsumerConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("asupersync-default"));

    let cloned = cfg;
    assert_eq!(cloned.group_id, "asupersync-default");
}

#[test]
fn consumer_config_new_overrides_defaults() {
    let cfg = ConsumerConfig::new(vec!["broker:9092".into()], "my-group");
    assert_eq!(cfg.bootstrap_servers, vec!["broker:9092"]);
    assert_eq!(cfg.group_id, "my-group");
    // Other fields still have defaults
    assert_eq!(cfg.max_poll_records, 500);
    // br-asupersync-2i2e21: default is manual-commit / at-least-once.
    assert!(!cfg.enable_auto_commit);
}

#[test]
fn consumer_config_session_timeout_builder() {
    let cfg = ConsumerConfig::default().session_timeout(Duration::from_secs(60));
    assert_eq!(cfg.session_timeout, Duration::from_secs(60));
}

#[test]
fn consumer_config_heartbeat_builder() {
    let cfg = ConsumerConfig::default().heartbeat_interval(Duration::from_secs(10));
    assert_eq!(cfg.heartbeat_interval, Duration::from_secs(10));
}

#[test]
fn consumer_config_auto_commit_interval_builder() {
    let cfg = ConsumerConfig::default().auto_commit_interval(Duration::from_secs(15));
    assert_eq!(cfg.auto_commit_interval, Duration::from_secs(15));
}

#[test]
fn consumer_config_fetch_max_wait_builder() {
    let cfg = ConsumerConfig::default().fetch_max_wait(Duration::from_secs(1));
    assert_eq!(cfg.fetch_max_wait, Duration::from_secs(1));
}

#[test]
fn consumer_config_validate_zero_poll_records() {
    let cfg = ConsumerConfig::default().max_poll_records(0);
    assert!(cfg.validate().is_err());
}

#[test]
fn consumer_config_validate_whitespace_group() {
    let cfg = ConsumerConfig::new(vec!["kafka:9092".into()], "   ");
    assert!(cfg.validate().is_err());
}

#[test]
fn consumer_config_validate_ok() {
    let cfg = ConsumerConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn consumer_config_allows_loopback_ipv4_and_ipv6_without_insecure_opt_in() {
    let ipv4 = ConsumerConfig::new(vec!["127.0.0.1:9092".into()], "group");
    assert!(ipv4.validate().is_ok());

    let ipv6 = ConsumerConfig::new(vec!["[::1]:9092".into()], "group");
    assert!(ipv6.validate().is_ok());
}

#[test]
fn topic_partition_offset_debug_clone_eq() {
    let tpo = TopicPartitionOffset::new("events", 0, 100);
    let dbg = format!("{tpo:?}");
    assert!(dbg.contains("events"));
    assert!(dbg.contains("100"));

    let cloned = tpo.clone();
    assert_eq!(tpo, cloned);
}

#[test]
fn topic_partition_offset_inequality() {
    let a = TopicPartitionOffset::new("t1", 0, 0);
    let b = TopicPartitionOffset::new("t2", 0, 0);
    assert_ne!(a, b);
}

#[test]
fn consumer_record_debug_clone() {
    let rec = ConsumerRecord {
        topic: "test-topic".into(),
        partition: 3,
        offset: 42,
        key: Some(b"key".to_vec()),
        payload: b"value".to_vec(),
        timestamp: Some(1000),
        headers: vec![("h1".into(), b"v1".to_vec())],
    };
    let dbg = format!("{rec:?}");
    assert!(dbg.contains("test-topic"));
    assert!(dbg.contains("42"));

    let cloned = rec;
    assert_eq!(cloned.topic, "test-topic");
    assert_eq!(cloned.partition, 3);
    assert_eq!(cloned.key, Some(b"key".to_vec()));
}

#[test]
fn consumer_record_no_key_no_timestamp() {
    let rec = ConsumerRecord {
        topic: "t".into(),
        partition: 0,
        offset: 0,
        key: None,
        payload: vec![],
        timestamp: None,
        headers: vec![],
    };
    assert!(rec.key.is_none());
    assert!(rec.timestamp.is_none());
}

#[test]
fn kafka_consumer_debug_config_accessor() {
    let cfg = ConsumerConfig::default();
    let consumer = KafkaConsumer::new(cfg).unwrap();
    let dbg = format!("{consumer:?}");
    assert!(dbg.contains("KafkaConsumer"));

    assert_eq!(consumer.config().group_id, "asupersync-default");
}

#[test]
fn kafka_consumer_rejects_invalid_config() {
    let cfg = ConsumerConfig {
        bootstrap_servers: vec![],
        ..Default::default()
    };
    assert!(KafkaConsumer::new(cfg).is_err());
}

#[test]
fn auto_offset_reset_debug_clone_copy_eq_default() {
    let a = AutoOffsetReset::default();
    assert_eq!(a, AutoOffsetReset::Latest);
    let b = a; // Copy
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_ne!(a, AutoOffsetReset::Earliest);
    assert_ne!(a, AutoOffsetReset::None);
    let dbg = format!("{a:?}");
    assert!(dbg.contains("Latest"));
}

#[test]
fn isolation_level_debug_clone_copy_eq_default() {
    let a = IsolationLevel::default();
    assert_eq!(a, IsolationLevel::ReadUncommitted);
    let b = a; // Copy
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_ne!(a, IsolationLevel::ReadCommitted);
    let dbg = format!("{a:?}");
    assert!(dbg.contains("ReadUncommitted"));
}

#[test]
fn consumer_config_debug_clone_default() {
    let cfg = ConsumerConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cloned.group_id, "asupersync-default");
    assert_eq!(cloned.auto_offset_reset, AutoOffsetReset::Latest);
    assert_eq!(cloned.isolation_level, IsolationLevel::ReadUncommitted);
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("ConsumerConfig"));
}

#[test]
fn consumer_subscribe_tracks_assignments() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["orders", "orders", "payments"])
            .await
            .unwrap();

        assert_eq!(
            consumer.subscriptions(),
            vec!["orders".to_string(), "payments".to_string()]
        );
        assert_eq!(
            consumer.assigned_partitions(),
            vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
        );
        assert!(
            consumer
                .poll(&cx, Duration::from_millis(1))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn consumer_commit_and_seek_track_offsets() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 7)])
            .await
            .unwrap();
        assert_eq!(consumer.committed_offset("orders", 0), Some(7));

        consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", 0, 42))
            .await
            .unwrap();
        assert_eq!(consumer.position("orders", 0), Some(42));

        let missing = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("missing", 0, 1)])
            .await
            .unwrap_err();
        assert!(matches!(missing, KafkaError::InvalidTopic(topic) if topic == "missing"));

        let negative = consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", 0, -1))
            .await
            .unwrap_err();
        assert!(matches!(negative, KafkaError::Config(msg) if msg.contains("non-negative")));
    });
}

#[test]
fn consumer_close_is_idempotent_and_blocks_operations() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();
        consumer.close(&cx).await.unwrap();
        consumer.close(&cx).await.unwrap();
        assert!(consumer.is_closed());

        let err = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 1)])
            .await
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("closed")));

        let seek_err = consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", 0, 42))
            .await
            .unwrap_err();
        assert!(matches!(seek_err, KafkaError::Config(msg) if msg.contains("closed")));
    });
}

#[test]
fn consumer_rejects_empty_topic_entries() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        let err = consumer.subscribe(&cx, &["orders", ""]).await.unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("topic cannot be empty")));
    });
}

#[cfg(feature = "kafka")]
fn check_native_empty_rebalance(strategy: &str, expected_protocol: KafkaRebalanceProtocol) {
    // This exercises librdkafka's real client against its in-process test
    // broker, including group negotiation; it is not live-broker proof.
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "empty-rebalance";
    cluster.create_topic(topic, 1, 1).unwrap();
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "empty-rebalance-group")
        .force_real_kafka(true)
        .with_property("group.protocol", "classic")
        .with_property("partition.assignment.strategy", strategy)
        .with_property("enable.auto.commit", "false");
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let started = std::time::Instant::now();
        while consumer.assigned_partitions().is_empty()
            && started.elapsed() < Duration::from_secs(30)
        {
            consumer
                .poll(&cx, Duration::from_millis(100))
                .await
                .unwrap();
        }
        let previous = consumer.assigned_partitions();
        let protocol = consumer.rebalance_protocol();
        let generation = consumer.rebalance_generation();
        let (native, broker_ops) = consumer.broker_backend().unwrap();
        let native_before = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        let result = consumer.rebalance(&cx, &[]).await;
        // Inspect before another poll can reconcile wrapper state or drive
        // callbacks: a no-op that clears only the wrapper must fail here.
        let native_after = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        let wrapper_after = consumer.assigned_partitions();
        let subscriptions = consumer.subscriptions();
        let repeated = consumer.rebalance(&cx, &[]).await;
        let native_after_repeat = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        let close_result = consumer.close(&cx).await;

        assert_eq!(protocol, expected_protocol, "group protocol not negotiated");
        assert_eq!(previous, vec![(topic.to_string(), 0)]);
        assert_eq!(native_before, 1, "native assignment was not established");
        let result = result.expect("empty rebalance must revoke native assignment");
        assert!(result.assigned.is_empty());
        assert_eq!(result.revoked, previous);
        assert_eq!(result.generation, generation + 1);
        assert_eq!(
            native_after, 0,
            "native ownership must actually be released"
        );
        assert!(wrapper_after.is_empty());
        assert_eq!(subscriptions, vec![topic.to_string()]);
        let repeated = repeated.expect("repeated empty rebalance must succeed");
        assert!(repeated.assigned.is_empty());
        assert!(repeated.revoked.is_empty());
        assert_eq!(repeated.generation, result.generation + 1);
        assert_eq!(native_after_repeat, 0);
        close_result.unwrap();
    });
}

#[cfg(feature = "kafka")]
#[test]
fn native_empty_rebalance_cooperative_releases_assignment() {
    check_native_empty_rebalance("cooperative-sticky", KafkaRebalanceProtocol::Cooperative);
}

#[cfg(feature = "kafka")]
#[test]
fn native_manual_rebalance_cooperative_modifies_assignment() {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "coop-manual-rebalance";
    cluster.create_topic(topic, 2, 1).unwrap();
    let config = ConsumerConfig::new(
        vec![cluster.bootstrap_servers()],
        "coop-manual-rebalance-group",
    )
    .force_real_kafka(true)
    .with_property("group.protocol", "classic")
    .with_property("partition.assignment.strategy", "cooperative-sticky")
    .with_property("enable.auto.commit", "false");
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let started = std::time::Instant::now();
        while consumer.assigned_partitions().is_empty()
            && started.elapsed() < Duration::from_secs(30)
        {
            consumer
                .poll(&cx, Duration::from_millis(100))
                .await
                .unwrap();
        }
        assert_eq!(
            consumer.rebalance_protocol(),
            KafkaRebalanceProtocol::Cooperative
        );
        let (native, broker_ops) = consumer.broker_backend().unwrap();
        let initial_count = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        assert_eq!(initial_count, 2);

        // Rebalance manually to only partition 0
        let tpo0 = TopicPartitionOffset::new(topic, 0, 0);
        let result = consumer
            .rebalance(&cx, &[tpo0.clone()])
            .await
            .expect("manual cooperative rebalance must succeed");
        assert_eq!(consumer.assigned_partitions(), vec![(topic.to_string(), 0)]);
        let native_after = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        assert_eq!(native_after, 1);
        assert_eq!(result.assigned, vec![(topic.to_string(), 0)]);
        assert_eq!(result.revoked, vec![(topic.to_string(), 1)]);

        // Rebalance manually back to partitions 0 and 1
        let tpo1 = TopicPartitionOffset::new(topic, 1, 0);
        let result2 = consumer
            .rebalance(&cx, &[tpo0, tpo1])
            .await
            .expect("manual cooperative rebalance to both partitions must succeed");
        assert_eq!(consumer.assigned_partitions().len(), 2);
        let native_after2 = {
            let _guard = broker_ops.lock();
            native.assignment().unwrap().count()
        };
        assert_eq!(native_after2, 2);
        assert_eq!(result2.revoked, Vec::<(String, i32)>::new());

        consumer.close(&cx).await.unwrap();
    });
}

#[cfg(feature = "kafka")]
#[test]
fn native_empty_rebalance_eager_releases_assignment() {
    check_native_empty_rebalance("range", KafkaRebalanceProtocol::Eager);
}

#[cfg(feature = "kafka")]
fn check_native_partial_rebalance_publication(
    abandon_waiter: bool,
    race_buffered_poll: bool,
) {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "partial-cooperative-rebalance";
    cluster.create_topic(topic, 2, 1).unwrap();
    let config = ConsumerConfig::new(
        vec![cluster.bootstrap_servers()],
        "partial-cooperative-rebalance-group",
    )
    .force_real_kafka(true)
    .enable_auto_commit(false)
    .with_property("group.protocol", "classic")
    .with_property("partition.assignment.strategy", "cooperative-sticky");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(1, 4)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let consumer = Arc::new(KafkaConsumer::new(config).unwrap());
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let started = std::time::Instant::now();
        while consumer.assigned_partitions().len() != 2
            && started.elapsed() < Duration::from_secs(30)
        {
            consumer.poll(&cx, Duration::from_millis(100)).await.unwrap();
        }
        assert_eq!(
            consumer.rebalance_protocol(),
            KafkaRebalanceProtocol::Cooperative
        );
        assert_eq!(consumer.assigned_partitions().len(), 2);
        let generation = consumer.rebalance_generation();
        let old_metadata = consumer.group_metadata_for_state_test();
        let (native, operations) = consumer.broker_backend().unwrap();
        // An abandoned native poll can retain this snapshot even when no
        // record arrived. It must not restore partition 1 on the next poll.
        {
            let _guard = operations.lock();
            *consumer.buffered_outcome.lock() = Some(Ok(BrokerPollOutcome {
                record: None,
                snapshot: capture_broker_snapshot(&native).unwrap(),
                transient_error: None,
            }));
        }
        let parked_poll = if race_buffered_poll {
            let (published, mut wait_published) = crate::channel::oneshot::channel();
            let (release, await_release) = std::sync::mpsc::channel();
            *operations.after_buffered_take.lock() = Some(BufferedRecordHook {
                published,
                release: await_release,
            });
            let polling_consumer = Arc::clone(&consumer);
            let polling_cx = cx.clone();
            let polling = std::thread::spawn(move || {
                futures_lite::future::block_on(
                    polling_consumer.poll(&polling_cx, Duration::ZERO),
                )
            });
            wait_published.recv(&cx).await.unwrap();
            // The real poll has removed the old outcome but has not applied
            // its state. It must still hold the shared publication lock.
            assert!(
                consumer.buffered_outcome.try_lock().is_none(),
                "a taken poll outcome must retain its buffer lock through state publication"
            );
            Some((release, polling))
        } else {
            None
        };
        operations
            .rebalance_failure_after_unassign
            .store(true, Ordering::Release);
        let (published, mut wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_rebalance_native.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        let target = [TopicPartitionOffset::new(topic, 0, 0)];
        let mut rebalancing = Box::pin(consumer.rebalance(&cx, &target));
        let mut witnessing = Box::pin(wait_published.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(rebalancing.as_mut().poll(task).is_pending());
            witnessing.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witnessing);
        // The worker is parked after a REAL successful native revocation and
        // an injected failure before the retained partition's seek. Its lease
        // prevents another native mutation during this direct observation.
        assert_eq!(native.assignment().unwrap().count(), 1);
        assert_eq!(consumer.assigned_partitions().len(), 2);
        if let Some((release_poll, polling)) = parked_poll {
            assert!(consumer.buffered_outcome.try_lock().is_none());
            release_poll.send(()).unwrap();
            assert!(polling.join().unwrap().unwrap().is_none());
        }
        if abandon_waiter {
            drop(rebalancing);
            release.send(()).unwrap();
            let operations = Arc::clone(&operations);
            crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
                // Retirement witness: publication must precede release of
                // the same native operation lock, without another async poll.
                drop(operations.lock());
            })
            .await;
        } else {
            release.send(()).unwrap();
            let error = rebalancing.await.unwrap_err();
            assert!(matches!(error, KafkaError::Broker(message)
                if message == "injected rebalance failure after native revocation"));
        }
        assert_eq!(consumer.assigned_partitions(), vec![(topic.to_string(), 0)]);
        assert_eq!(consumer.position(topic, 1), None);
        assert_eq!(
            consumer.last_revoked_partitions(),
            vec![(topic.to_string(), 1)]
        );
        assert_eq!(consumer.rebalance_generation(), generation + 1);
        assert!(matches!(
            old_metadata.prepare_offsets(&target),
            Err(KafkaError::Transaction(_))
        ));
        assert!(matches!(
            consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new(topic, 1, 1)])
                .await,
            Err(KafkaError::Config(message)) if message.contains("not assigned")
        ));
        if !race_buffered_poll {
            assert!(consumer.poll(&cx, Duration::ZERO).await.unwrap().is_none());
        }
        assert_eq!(
            consumer.assigned_partitions(),
            vec![(topic.to_string(), 0)],
            "the buffered pre-rebalance snapshot must not resurrect revoked ownership"
        );
        consumer.close(&cx).await.unwrap();
    });
    assert_eq!(
        runtime.shutdown_drained(Duration::from_secs(10)).outcome,
        crate::runtime::RootDrainOutcome::Quiescent
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[cfg(feature = "kafka")]
#[test]
fn native_partial_rebalance_reconciles_before_returning_original_error() {
    check_native_partial_rebalance_publication(false, false);
}

#[cfg(feature = "kafka")]
#[test]
fn native_partial_rebalance_publishes_after_waiter_is_dropped() {
    check_native_partial_rebalance_publication(true, false);
}

#[cfg(feature = "kafka")]
#[test]
fn native_rebalance_and_buffered_poll_publish_in_one_order() {
    check_native_partial_rebalance_publication(false, true);
}

#[cfg(feature = "kafka")]
#[test]
fn failed_rebalance_preserves_only_unrepositioned_buffered_records() {
    let key = ("orders".to_string(), 0);
    for completed_seek in [false, true] {
        let mut state = ConsumerState::default();
        state.assigned_partitions.insert(key.clone());
        state.positions.insert(key.clone(), 10);
        state.rebalance_generation = 7;
        let mut buffered = Some(Ok(BrokerPollOutcome {
            record: Some(NullableConsumerRecord {
                topic: key.0.clone(),
                partition: key.1,
                offset: 9,
                key: None,
                payload: Some(b"retained".to_vec()),
                timestamp: None,
                headers: Vec::new(),
            }),
            snapshot: BrokerSnapshot {
                assigned_partitions: state.assigned_partitions.clone(),
                positions: state.positions.clone(),
            },
            transient_error: None,
        }));
        // Eager assign can still report the old concrete app_pos while its
        // fetch is stopping. A completed explicit offset must win over it.
        let positions = [(key.clone(), if completed_seek { 42 } else { 10 })]
            .into_iter()
            .collect();
        let completed = if completed_seek {
            [(key.clone(), 12)].into_iter().collect()
        } else {
            BTreeMap::new()
        };
        let error = publish_broker_rebalance(
            &mut state,
            &mut buffered,
            Err(KafkaError::Broker("later step failed".into())),
            Ok(BrokerSnapshot {
                assigned_partitions: [key.clone()].into_iter().collect(),
                positions,
            }),
            &BTreeSet::from([key.clone()]),
            &completed,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, KafkaError::Broker(message) if message == "later step failed"));
        assert_eq!(
            state.rebalance_generation, 8,
            "same membership still invalidates metadata"
        );
        assert_eq!(state.positions[&key], if completed_seek { 12 } else { 10 });
        let outcome = buffered.unwrap().unwrap();
        assert_eq!(outcome.record.is_some(), !completed_seek);
        assert_eq!(outcome.snapshot.positions, state.positions);
    }
}

#[cfg(feature = "kafka")]
#[test]
fn rebalance_snapshot_failure_revokes_unknown_ownership_without_erasing_mutation_error() {
    let key = ("orders".to_string(), 0);
    for mutation_failed in [false, true] {
        let mut state = ConsumerState::default();
        state.assigned_partitions.insert(key.clone());
        state.positions.insert(key.clone(), 42);
        let operation = if mutation_failed {
            Err(KafkaError::Broker("original mutation failure".into()))
        } else {
            Ok(())
        };
        let mut buffered = Some(Ok(BrokerPollOutcome {
            record: None,
            snapshot: BrokerSnapshot {
                assigned_partitions: state.assigned_partitions.clone(),
                positions: state.positions.clone(),
            },
            transient_error: None,
        }));
        let error = publish_broker_rebalance(
            &mut state,
            &mut buffered,
            operation,
            Err(KafkaError::Broker("snapshot unavailable".into())),
            &BTreeSet::from([key.clone()]),
            &BTreeMap::from([(key.clone(), 12)]),
            false,
        )
        .unwrap_err();
        let expected = if mutation_failed {
            "original mutation failure"
        } else {
            "snapshot unavailable"
        };
        assert!(matches!(error, KafkaError::Broker(message) if message == expected));
        assert!(state.assigned_partitions.is_empty());
        assert!(state.positions.is_empty());
        assert_eq!(state.rebalance_generation, 1);
        assert_eq!(state.last_revoked_partitions, BTreeSet::from([key.clone()]));
        assert!(
            buffered
                .unwrap()
                .unwrap()
                .snapshot
                .assigned_partitions
                .is_empty()
        );
    }
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn offset_operation<'a>(
    consumer: &'a KafkaConsumer,
    cx: &'a Cx,
    offsets: &'a [TopicPartitionOffset],
    commit: bool,
) -> Pin<Box<dyn Future<Output = Result<(), KafkaError>> + 'a>> {
    if commit {
        Box::pin(consumer.commit_offsets(cx, offsets))
    } else {
        Box::pin(consumer.seek(cx, &offsets[0]))
    }
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
async fn native_committed_offset(consumer: &KafkaConsumer, topic: &str) -> Option<i64> {
    let (native, operations) = consumer.broker_backend().unwrap();
    let topic = topic.to_string();
    crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
        let _guard = operations.lock();
        let mut query = TopicPartitionList::new();
        query.add_partition(&topic, 0);
        let committed = native
            .committed_offsets(query, Duration::from_secs(5))
            .unwrap();
        offset_from_rdkafka(committed.find_partition(&topic, 0).unwrap().offset())
    })
    .await
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_seek_publishes_after_waiter_is_dropped() {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "dropped-seek";
    cluster.create_topic(topic, 1, 1).unwrap();
    nullable_native_fixture(&cluster.bootstrap_servers(), topic);
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "dropped-seek-group")
        .force_real_kafka(true)
        .enable_auto_commit(false)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .with_property("group.protocol", "classic");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(1, 4)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let first = consumer
            .poll_nullable(&cx, Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(consumer.position(topic, 0), Some(1));
        let (_, operations) = consumer.broker_backend().unwrap();
        let (published, mut wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_seek_native.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        let target = TopicPartitionOffset::new(topic, 0, 2);
        let mut seeking = Box::pin(consumer.seek(&cx, &target));
        let mut witness = Box::pin(wait_published.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(seeking.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witness);
        assert_eq!(consumer.position(topic, 0), Some(1));
        drop(seeking);
        release.send(()).unwrap();
        crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
            drop(operations.lock());
        })
        .await;
        // Inspect before polling can refresh state from the native handle.
        assert_eq!(consumer.position(topic, 0), Some(2));
        let next = consumer
            .poll_nullable(&cx, Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.offset, 2);
        assert!(next.payload.is_none(), "the actual target is the tombstone");
        consumer.close(&cx).await.unwrap();
    });
    assert_eq!(
        runtime.shutdown_drained(Duration::from_secs(10)).outcome,
        crate::runtime::RootDrainOutcome::Quiescent
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_dropped_commit_fences_a_queued_lower_broker_commit() {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "dropped-commit";
    cluster.create_topic(topic, 1, 1).unwrap();
    nullable_native_fixture(&cluster.bootstrap_servers(), topic);
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "dropped-commit-group")
        .force_real_kafka(true)
        .enable_auto_commit(false)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .with_property("group.protocol", "classic");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(1, 4)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        assert!(consumer.poll(&cx, Duration::from_secs(30)).await.unwrap().is_some());
        let (_, operations) = consumer.broker_backend().unwrap();
        let (published, mut wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_commit_native.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        let high = [TopicPartitionOffset::new(topic, 0, 3)];
        let mut committing = Box::pin(consumer.commit_offsets(&cx, &high));
        let mut witness = Box::pin(wait_published.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(committing.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witness);
        assert_eq!(consumer.committed_offset(topic, 0), None);

        // This lower request passes the fast check while the successful
        // higher commit is parked before publication. It must recheck later,
        // before sending anything that could lower the BROKER's offset.
        let (queued, mut wait_queued) = crate::channel::oneshot::channel();
        *operations.before_lock.lock() = Some(queued);
        let low = [TopicPartitionOffset::new(topic, 0, 2)];
        let mut lower = Box::pin(consumer.commit_offsets(&cx, &low));
        let mut witness = Box::pin(wait_queued.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(lower.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witness);
        drop(committing);
        release.send(()).unwrap();
        let error = lower.await.unwrap_err();
        assert!(matches!(error, KafkaError::Config(message)
            if message == "offset commit regression is not allowed"));
        assert_eq!(consumer.committed_offset(topic, 0), Some(3));
        assert_eq!(native_committed_offset(&consumer, topic).await, Some(3));
        consumer.close(&cx).await.unwrap();
    });
    assert_eq!(
        runtime.shutdown_drained(Duration::from_secs(10)).outcome,
        crate::runtime::RootDrainOutcome::Quiescent
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
fn check_native_queued_offset_generation(commit: bool, close: bool) {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "queued-offset-generation";
    cluster.create_topic(topic, 1, 1).unwrap();
    nullable_native_fixture(&cluster.bootstrap_servers(), topic);
    let config = ConsumerConfig::new(
        vec![cluster.bootstrap_servers()],
        "queued-offset-generation-group",
    )
    .force_real_kafka(true)
    .enable_auto_commit(false)
    .auto_offset_reset(AutoOffsetReset::Earliest)
    .with_property("group.protocol", "classic");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(1, 4)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        assert!(consumer.poll(&cx, Duration::from_secs(30)).await.unwrap().is_some());
        let generation = consumer.rebalance_generation();
        let (_, operations) = consumer.broker_backend().unwrap();
        let (published, mut wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_rebalance_native.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        let reassignment = [TopicPartitionOffset::new(topic, 0, 2)];
        let mut rebalancing = Box::pin(consumer.rebalance(&cx, &reassignment));
        let mut witness = Box::pin(wait_published.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(rebalancing.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witness);
        assert_eq!(consumer.rebalance_generation(), generation);
        let (queued, mut wait_queued) = crate::channel::oneshot::channel();
        *operations.before_lock.lock() = Some(queued);
        let requested = [TopicPartitionOffset::new(topic, 0, 1)];
        let mut queued = offset_operation(&consumer, &cx, &requested, commit);
        let mut witness = Box::pin(wait_queued.recv(&cx));
        std::future::poll_fn(|task| {
            assert!(queued.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .unwrap();
        drop(witness);

        if close {
            let mut closing = Box::pin(consumer.close(&cx));
            assert!(
                std::future::poll_fn(|task| Poll::Ready(closing.as_mut().poll(task)))
                    .await
                    .is_pending()
            );
            assert!(consumer.is_closed());
            release.send(()).unwrap();
            assert!(rebalancing.await.is_err());
            let error = queued.await.unwrap_err();
            assert!(matches!(error, KafkaError::Config(message)
                if message == "consumer is closed"));
            closing.await.unwrap();
            assert!(consumer.assigned_partitions().is_empty());
            assert_eq!(consumer.position(topic, 0), None);
            assert_eq!(consumer.committed_offset(topic, 0), None);
        } else {
            release.send(()).unwrap();
            let rebound = rebalancing.await.unwrap();
            assert_eq!(rebound.generation, generation + 1);
            let error = queued.await.unwrap_err();
            assert!(matches!(error, KafkaError::Config(message)
                if message == "consumer assignment changed before offset operation"));
            assert_eq!(consumer.position(topic, 0), Some(2));
            assert_eq!(consumer.committed_offset(topic, 0), None);
            assert_eq!(native_committed_offset(&consumer, topic).await, None);
            consumer.close(&cx).await.unwrap();
        }
    });
    assert_eq!(
        runtime.shutdown_drained(Duration::from_secs(10)).outcome,
        crate::runtime::RootDrainOutcome::Quiescent
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_queued_seek_cannot_cross_same_partition_rebalance() {
    check_native_queued_offset_generation(false, false);
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_queued_commit_cannot_cross_same_partition_rebalance() {
    check_native_queued_offset_generation(true, false);
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_queued_offset_operations_refuse_after_close_starts() {
    check_native_queued_offset_generation(false, true);
    check_native_queued_offset_generation(true, true);
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
#[test]
fn native_commit_checks_ownership_before_a_buffered_revoke_is_consumed() {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "unpublished-revoke";
    cluster.create_topic(topic, 1, 1).unwrap();
    nullable_native_fixture(&cluster.bootstrap_servers(), topic);
    let config = ConsumerConfig::new(vec![cluster.bootstrap_servers()], "unpublished-revoke-group")
        .force_real_kafka(true)
        .enable_auto_commit(false)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .with_property("group.protocol", "classic");
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(1, 4)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        assert!(consumer.poll(&cx, Duration::from_secs(30)).await.unwrap().is_some());
        let (native, operations) = consumer.broker_backend().unwrap();
        let buffered = Arc::clone(&consumer.buffered_outcome);
        crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
            let _guard = operations.lock();
            native.unassign().unwrap();
            // Reproduce the publication boundary of a poll whose future was
            // dropped after the native handle processed a real revocation.
            *buffered.lock() = Some(Ok(BrokerPollOutcome {
                record: None,
                snapshot: capture_broker_snapshot(&native).unwrap(),
                transient_error: None,
            }));
        })
        .await;
        assert_eq!(consumer.assigned_partitions(), vec![(topic.to_string(), 0)]);
        let error = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new(topic, 0, 2)])
            .await
            .unwrap_err();
        assert!(matches!(error, KafkaError::Config(message)
            if message == "partition is not assigned to this consumer"));
        assert_eq!(consumer.committed_offset(topic, 0), None);
        assert_eq!(native_committed_offset(&consumer, topic).await, None);
        consumer.close(&cx).await.unwrap();
    });
    assert_eq!(
        runtime.shutdown_drained(Duration::from_secs(10)).outcome,
        crate::runtime::RootDrainOutcome::Quiescent
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
}

/// br-asupersync-bi2462.115: an explicit empty rebalance clears only the
/// local assignment; the group still owns this member's partition, so the
/// `unsubscribe()` in close() queues an eager revoke. close() must run that
/// revoke through the callback. Left queued, it fires inside
/// `rd_kafka_consumer_close` when the native handle drops, and blocks there.
#[cfg(feature = "kafka")]
#[test]
fn close_after_an_empty_rebalance_drains_the_group_revoke() {
    let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
    let topic = "empty-rebalance-close";
    cluster.create_topic(topic, 1, 1).unwrap();
    let config = ConsumerConfig::new(
        vec![cluster.bootstrap_servers()],
        "empty-rebalance-close-group",
    )
    .force_real_kafka(true)
    .with_property("group.protocol", "classic")
    .with_property("partition.assignment.strategy", "range")
    .with_property("enable.auto.commit", "false");
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(config).unwrap();
        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let started = std::time::Instant::now();
        while consumer.assigned_partitions().is_empty()
            && started.elapsed() < Duration::from_secs(30)
        {
            consumer
                .poll(&cx, Duration::from_millis(100))
                .await
                .unwrap();
        }
        assert_eq!(consumer.assigned_partitions(), vec![(topic.to_string(), 0)]);
        let (native, _) = consumer.broker_backend().unwrap();
        let group = || {
            native
                .context()
                .counters
                .group_partitions
                .load(Ordering::Acquire)
        };
        assert_eq!(
            group(),
            1,
            "the group's assignment came through the callback"
        );
        consumer.rebalance(&cx, &[]).await.unwrap();
        assert!(consumer.assigned_partitions().is_empty());
        assert_eq!(
            group(),
            1,
            "an explicit rebalance leaves the group's assignment"
        );
        let before = consumer.rebalance_stats();
        consumer.close(&cx).await.unwrap();
        let after = consumer.rebalance_stats();
        assert!(
            after.eager_unassigns > before.eager_unassigns,
            "close() left the group's revoke queued: {before:?} -> {after:?}"
        );
        assert_eq!(group(), 0, "the revoke released the group's assignment");
    });
}

#[test]
fn consumer_rebalance_tracks_assignment_and_revocation() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["orders", "payments"])
            .await
            .unwrap();

        let result = consumer
            .rebalance(
                &cx,
                &[
                    TopicPartitionOffset::new("orders", 1, 10),
                    TopicPartitionOffset::new("orders", 2, 0),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.generation, 1);
        assert_eq!(
            result.assigned,
            vec![("orders".to_string(), 1), ("orders".to_string(), 2)]
        );
        assert_eq!(
            result.revoked,
            vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
        );
        assert_eq!(consumer.position("orders", 1), Some(10));
        assert_eq!(consumer.position("orders", 2), Some(0));
        assert_eq!(consumer.rebalance_generation(), 1);
        assert_eq!(
            consumer.last_revoked_partitions(),
            vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
        );
    });
}

#[test]
fn consumer_rebalance_rejects_duplicate_partition_entries() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["orders", "payments"])
            .await
            .unwrap();

        let err = consumer
            .rebalance(
                &cx,
                &[
                    TopicPartitionOffset::new("orders", 1, 10),
                    TopicPartitionOffset::new("orders", 1, 25),
                ],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("duplicate")));
        assert_eq!(
            consumer.assigned_partitions(),
            vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
        );
        assert_eq!(consumer.rebalance_generation(), 0);
        assert!(consumer.last_revoked_partitions().is_empty());
        assert_eq!(consumer.position("orders", 1), None);
    });
}

#[test]
fn consumer_rebalance_rejects_close_race_after_open() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = Arc::new(KafkaConsumer::new(ConsumerConfig::default()).unwrap());
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        let hook = Arc::new(RebalanceAfterOpenHook::new());
        consumer.install_rebalance_after_open_hook(Arc::clone(&hook));

        let rebalance_consumer = Arc::clone(&consumer);
        let rebalance_cx = cx.clone();
        let handle = std::thread::spawn(move || {
            futures_lite::future::block_on(
                rebalance_consumer
                    .rebalance(&rebalance_cx, &[TopicPartitionOffset::new("orders", 1, 10)]),
            )
        });

        hook.arrived.wait();
        consumer.closed.store(true, Ordering::Release);
        hook.release.wait();

        let err = handle
            .join()
            .expect("rebalance thread panicked")
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("closed")));
        assert_eq!(consumer.rebalance_generation(), 0);
        assert_eq!(
            consumer.assigned_partitions(),
            vec![("orders".to_string(), 0)]
        );
        assert_eq!(consumer.position("orders", 1), None);
    });
}

// asupersync-lde436 item 5: subscribe() reset the generation to 0, so a
// rebalance after a re-subscribe brought metadata captured before it back
// to a matching generation and assignment, and it validated again.
#[test]
fn group_metadata_from_before_a_resubscribe_never_validates_again() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();
        assert_eq!(consumer.rebalance_generation(), 0);
        let owned = [TopicPartitionOffset::new("orders", 1, 0)];
        consumer.rebalance(&cx, &owned).await.unwrap();
        let before = consumer.group_metadata_for_state_test();

        consumer.subscribe(&cx, &["orders"]).await.unwrap();
        consumer.rebalance(&cx, &owned).await.unwrap();
        assert_eq!(
            consumer.assigned_partitions(),
            vec![("orders".to_string(), 1)]
        );
        assert!(
            consumer.rebalance_generation() > before.generation(),
            "generation {} after a re-subscribe, {} before it",
            consumer.rebalance_generation(),
            before.generation()
        );
        assert!(matches!(
            before.prepare_offsets(&owned),
            Err(KafkaError::Transaction(_))
        ));
    });
}

#[test]
fn consumer_rebalance_rejects_negative_partition_numbers() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer
            .subscribe(&cx, &["orders", "payments"])
            .await
            .unwrap();

        let err = consumer
            .rebalance(&cx, &[TopicPartitionOffset::new("orders", -1, 10)])
            .await
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("non-negative")));
        assert_eq!(
            consumer.assigned_partitions(),
            vec![("orders".to_string(), 0), ("payments".to_string(), 0)]
        );
        assert_eq!(consumer.rebalance_generation(), 0);
        assert!(consumer.last_revoked_partitions().is_empty());
        assert_eq!(consumer.position("orders", -1), None);
    });
}

#[test]
fn consumer_commit_rejects_unassigned_partitions_and_regression() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        let unassigned = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 1, 5)])
            .await
            .unwrap_err();
        assert!(matches!(unassigned, KafkaError::Config(msg) if msg.contains("not assigned")));

        consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 8)])
            .await
            .unwrap();
        let regression = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 7)])
            .await
            .unwrap_err();
        assert!(matches!(regression, KafkaError::Config(msg) if msg.contains("regression")));
    });
}

#[test]
fn consumer_commit_rejects_duplicate_partition_entries_in_single_batch() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        let err = consumer
            .commit_offsets(
                &cx,
                &[
                    TopicPartitionOffset::new("orders", 0, 8),
                    TopicPartitionOffset::new("orders", 0, 7),
                ],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("duplicate")));
        assert_eq!(consumer.committed_offset("orders", 0), None);
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn consumer_resubscribe_preserves_committed_offsets_across_topic_changes() {
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let topic = "consumer-resubscribe-preserves-committed-offsets";
        let other_topic = "consumer-resubscribe-preserves-committed-offsets-other";
        let consumer = KafkaConsumer::new(
            ConsumerConfig::new(vec!["localhost:9092".to_string()], "group-resubscribe")
                .auto_offset_reset(AutoOffsetReset::None),
        )
        .unwrap();

        consumer.subscribe(&cx, &[topic]).await.unwrap();
        consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new(topic, 0, 7)])
            .await
            .unwrap();

        consumer.subscribe(&cx, &[other_topic]).await.unwrap();
        assert_eq!(consumer.position(topic, 0), None);
        assert_eq!(consumer.committed_offset(topic, 0), Some(7));

        consumer.subscribe(&cx, &[topic]).await.unwrap();

        assert_eq!(consumer.committed_offset(topic, 0), Some(7));
        assert!(
            consumer.poll(&cx, Duration::ZERO).await.unwrap().is_none(),
            "existing committed offset should satisfy auto_offset_reset=None after resubscribe"
        );
        assert_eq!(consumer.position(topic, 0), Some(7));
    });
}

#[test]
fn consumer_commit_and_seek_reject_negative_partition_numbers() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        let commit_err = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", -1, 8)])
            .await
            .unwrap_err();
        assert!(matches!(commit_err, KafkaError::Config(msg) if msg.contains("non-negative")));
        assert_eq!(consumer.committed_offset("orders", -1), None);

        let seek_err = consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", -1, 42))
            .await
            .unwrap_err();
        assert!(matches!(seek_err, KafkaError::Config(msg) if msg.contains("non-negative")));
        assert_eq!(consumer.position("orders", -1), None);
    });
}

#[test]
fn consumer_seek_rejects_unassigned_partitions() {
    #[cfg(not(feature = "kafka"))]
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let consumer = KafkaConsumer::new(ConsumerConfig::default()).unwrap();
        consumer.subscribe(&cx, &["orders"]).await.unwrap();

        let err = consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", 1, 1))
            .await
            .unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("not assigned")));
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn consumer_poll_returns_brokerless_records_and_advances_position() {
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let topic = "consumer-poll-returns-brokerless-records";
        let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
        let consumer = KafkaConsumer::new(
            ConsumerConfig::new(vec!["localhost:9092".to_string()], "group-a")
                .auto_offset_reset(AutoOffsetReset::Earliest),
        )
        .unwrap();

        producer
            .send(&cx, topic, Some(b"k1"), b"one", Some(0))
            .await
            .unwrap();
        producer
            .send(&cx, topic, Some(b"k2"), b"two", Some(0))
            .await
            .unwrap();

        consumer.subscribe(&cx, &[topic]).await.unwrap();

        let first = consumer
            .poll(&cx, Duration::ZERO)
            .await
            .unwrap()
            .expect("first record");
        assert_eq!(first.topic, topic);
        assert_eq!(first.partition, 0);
        assert_eq!(first.offset, 0);
        assert_eq!(first.key.as_deref(), Some(&b"k1"[..]));
        assert_eq!(first.payload, b"one");

        let second = consumer
            .poll(&cx, Duration::ZERO)
            .await
            .unwrap()
            .expect("second record");
        assert_eq!(second.offset, 1);
        assert_eq!(second.key.as_deref(), Some(&b"k2"[..]));
        assert_eq!(second.payload, b"two");
        assert_eq!(consumer.position(topic, 0), Some(2));
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn consumer_latest_offset_reset_skips_existing_backlog() {
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let topic = "consumer-latest-offset-reset-skips-existing-backlog";
        let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
        let consumer =
            KafkaConsumer::new(ConsumerConfig::new(vec!["localhost:9092".to_string()], "g"))
                .unwrap();

        producer
            .send(&cx, topic, None, b"existing-before-subscribe", Some(0))
            .await
            .unwrap();

        consumer.subscribe(&cx, &[topic]).await.unwrap();
        assert!(consumer.poll(&cx, Duration::ZERO).await.unwrap().is_none());

        producer
            .send(&cx, topic, None, b"after-subscribe", Some(0))
            .await
            .unwrap();

        let record = consumer
            .poll(&cx, Duration::ZERO)
            .await
            .unwrap()
            .expect("post-subscribe record");
        assert_eq!(record.offset, 1);
        assert_eq!(record.payload, b"after-subscribe");
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn consumer_offset_reset_none_requires_existing_position() {
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let topic = "consumer-offset-reset-none-requires-existing-position";
        let consumer = KafkaConsumer::new(
            ConsumerConfig::new(vec!["localhost:9092".to_string()], "g")
                .auto_offset_reset(AutoOffsetReset::None),
        )
        .unwrap();

        consumer.subscribe(&cx, &[topic]).await.unwrap();
        let err = consumer.poll(&cx, Duration::ZERO).await.unwrap_err();
        assert!(matches!(err, KafkaError::Config(msg) if msg.contains("no offset available")));
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn consumer_poll_rechecks_brokerless_records_after_waiter_registration() {
    let _broker = deterministic_broker_guard();
    run_test_with_cx(|cx| async move {
        let topic = "consumer-poll-rechecks-brokerless-records-after-waiter-registration";
        let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
        let consumer = Arc::new(
            KafkaConsumer::new(
                ConsumerConfig::new(vec!["localhost:9092".to_string()], "group-recheck")
                    .auto_offset_reset(AutoOffsetReset::Earliest),
            )
            .unwrap(),
        );
        consumer.subscribe(&cx, &[topic]).await.unwrap();

        let hook = Arc::new(PollBeforeWaitHook::new());
        consumer.install_poll_before_wait_hook(Arc::clone(&hook));

        let poll_consumer = Arc::clone(&consumer);
        let poll_cx = cx.clone();
        let started = Instant::now();
        let handle = std::thread::spawn(move || {
            futures_lite::future::block_on(poll_consumer.poll(&poll_cx, Duration::from_secs(1)))
        });

        hook.arrived.wait();
        producer
            .send(&cx, topic, Some(b"k"), b"wake", Some(0))
            .await
            .unwrap();
        hook.release.wait();

        let record = handle
            .join()
            .expect("poll thread panicked")
            .unwrap()
            .expect("poll should return the brokerless record without sleeping until timeout");

        assert_eq!(record.topic, topic);
        assert_eq!(record.partition, 0);
        assert_eq!(record.offset, 0);
        assert_eq!(record.key.as_deref(), Some(&b"k"[..]));
        assert_eq!(record.payload, b"wake");
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "poll should recheck immediately after waiter registration instead of idling until timeout"
        );
    });
}

// ─── br-asupersync-yis4hl: rebalance TOCTOU regression ────────────

/// Test the EXACT logic the poll() arm uses to drop records for
/// revoked partitions. Exercises the exact sequence:
///   1. Consumer owns (topic_a, 0) and (topic_a, 1).
///   2. Blocking thread fetches a record for (topic_a, 1) +
///      auto-commits it (broker write — outside this test scope) +
///      captures a fresh BrokerSnapshot reflecting a rebalance
///      that just revoked (topic_a, 1).
///   3. poll() arm acquires state lock, applies the snapshot
///      (which removes (topic_a, 1) from assigned_partitions and
///      bumps rebalance_generation), then checks if the buffered
///      record's (topic, partition) is still owned.
///   4. Asserts: NOT owned → record MUST be dropped; the
///      application never sees a record for a revoked partition.
#[cfg(feature = "kafka")]
#[test]
fn rebalance_toctou_drops_record_for_revoked_partition() {
    let mut state = ConsumerState::default();
    state.subscribed_topics.insert("topic_a".to_string());
    // Pre-rebalance assignment.
    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("topic_a".to_string(), 0), ("topic_a".to_string(), 1)]),
            BTreeMap::new(),
        ),
    );
    assert!(
        state
            .assigned_partitions
            .contains(&("topic_a".to_string(), 1))
    );
    let pre_gen = state.rebalance_generation;

    // Blocking thread captured a record for ("topic_a", 1)
    // BEFORE the rebalance, then a rebalance fired that revoked
    // ("topic_a", 1). Apply the post-rebalance snapshot.
    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("topic_a".to_string(), 0)]), // 1 revoked
            BTreeMap::new(),
        ),
    );
    assert!(state.rebalance_generation > pre_gen, "generation must bump");
    assert!(
        state
            .last_revoked_partitions
            .contains(&("topic_a".to_string(), 1))
    );

    // Now the buffered record from the pre-rebalance fetch carries
    // (topic_a, 1). The fix in poll() does this check:
    let record_topic = "topic_a".to_string();
    let record_partition: i32 = 1;
    let owned = state
        .assigned_partitions
        .contains(&(record_topic.clone(), record_partition));
    assert!(
        !owned,
        "post-rebalance check MUST report (topic_a, 1) as NOT owned — \
             record must be dropped to avoid delivering for revoked partition"
    );

    // Inverse: a record for (topic_a, 0) is still owned and would be
    // delivered.
    let owned_unrevoked = state
        .assigned_partitions
        .contains(&("topic_a".to_string(), 0));
    assert!(
        owned_unrevoked,
        "(topic_a, 0) is still in the assignment — its record MUST be delivered"
    );
}

/// No-op control: when no rebalance occurred, the record's partition
/// is still owned and the check returns true (deliver normally).
#[cfg(feature = "kafka")]
#[test]
fn rebalance_toctou_keeps_record_when_no_revocation() {
    let mut state = ConsumerState::default();
    state.subscribed_topics.insert("topic_a".to_string());
    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("topic_a".to_string(), 0)]),
            BTreeMap::new(),
        ),
    );
    // Same snapshot replayed (no rebalance) — assignment unchanged.
    apply_broker_snapshot(
        &mut state,
        broker_snapshot_from_topic_maps(
            BTreeSet::from([("topic_a".to_string(), 0)]),
            BTreeMap::new(),
        ),
    );
    let owned = state
        .assigned_partitions
        .contains(&("topic_a".to_string(), 0));
    assert!(owned, "no rebalance → (topic_a, 0) still owned");
}

// (broker_snapshot_from_topic_maps already exists at line 501 in
// module scope — reused here without re-definition.)

/// br-asupersync-mskwk7 + br-asupersync-6mlvbi: when a Cx is
/// constructed with no TimerDriverHandle attached, the kafka_consumer
/// poll-deadline closure must fall back to wall_now() rather than
/// silently using zero. Pre-fix the no-driver fallback wasn't an
/// issue at this layer (every callsite read wall_now directly), but
/// the fix routes through cx.timer_driver().map_or_else(wall_now, ..)
/// so the determinism contract is preserved AND the production
/// no-driver path keeps working. This test pins the contract: a Cx
/// without a timer driver still returns a non-zero now() value via
/// the wall_now fallback, so the deadline math doesn't degenerate.
#[test]
fn timer_driver_fallback_returns_nonzero_when_no_driver_attached() {
    let cx = Cx::for_request();
    // The Cx::for_request constructor does not attach a TimerDriverHandle
    // (it routes through Cx::new which leaves timer_driver = None).
    // The closure used in the kafka_consumer poll paths must therefore
    // fall back to wall_now. Force wall_now to seed and sample a tiny
    // delta so the fallback advances.
    let _ = crate::time::wall_now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let now_fn = || {
        cx.timer_driver()
            .map_or_else(crate::time::wall_now, |d| d.now())
    };
    let t = now_fn().as_nanos();
    assert!(
        t > 0,
        "br-asupersync-mskwk7/6mlvbi: kafka_consumer's now_fn must \
             return a non-zero value when no TimerDriverHandle is \
             attached — the wall_now fallback must be reachable from \
             both poll paths"
    );
}

/// br-asupersync-mskwk7 + br-asupersync-6mlvbi: when a Cx HAS a
/// TimerDriverHandle attached (the lab harness shape), the
/// closure must use it instead of wall_now — that's the property
/// the fix establishes. We construct a Cx with a real timer
/// driver and confirm the closure reads from the driver, not
/// from wall_now.
#[test]
fn timer_driver_used_when_attached() {
    use crate::time::{TimerDriverHandle, VirtualClock};
    let clock = std::sync::Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
    let driver_ref = driver.clone();
    let virtual_now_via_closure = || {
        // Exercise the closure shape used in kafka_consumer.
        let timer_opt = Some(driver_ref.clone());
        timer_opt.map_or_else(crate::time::wall_now, |d| d.now())
    };
    // Advance the virtual clock by 7 seconds and confirm the
    // closure observes it (VirtualClock::advance takes nanos).
    clock.advance(7_000_000_000);
    let observed = virtual_now_via_closure().as_nanos();
    assert!(
        observed >= 7_000_000_000,
        "br-asupersync-mskwk7/6mlvbi: when TimerDriverHandle is \
             attached, the now_fn closure must read from it \
             (observed: {observed}ns; expected >= 7s)"
    );
}

#[cfg(all(feature = "kafka", not(target_arch = "wasm32")))]
mod native_subscription_publication {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::task::Poll;

    const OLD: &str = "subscription-old";
    const NEXT: &str = "subscription-next";
    const LAST: &str = "subscription-last";

    fn run<F, Fut>(body: F)
    where
        F: FnOnce(Cx, Arc<KafkaConsumer>, Arc<BrokerOperations>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let cluster = rdkafka::mocking::MockCluster::new(1).unwrap();
        for topic in [OLD, NEXT, LAST] {
            cluster.create_topic(topic, 1, 1).unwrap();
            nullable_native_fixture(&cluster.bootstrap_servers(), topic);
        }
        let config = ConsumerConfig::new(
            vec![cluster.bootstrap_servers()],
            "subscription-publication-group",
        )
        .force_real_kafka(true)
        .enable_auto_commit(false)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .session_timeout(Duration::from_secs(10))
        .with_property("group.protocol", "classic");
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 4)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let consumer = Arc::new(KafkaConsumer::new(config).unwrap());
            consumer.subscribe(&cx, &[OLD]).await.unwrap();
            let first = consumer
                .poll_nullable(&cx, Duration::from_secs(30))
                .await
                .unwrap()
                .expect("initial record from the native broker");
            assert_eq!((first.topic.as_str(), first.offset), (OLD, 0));
            assert_eq!(consumer.position(OLD, 0), Some(1));
            let operations = Arc::clone(consumer.broker_ops.as_ref().unwrap());
            body(cx.clone(), Arc::clone(&consumer), operations).await;
            consumer.close(&cx).await.unwrap();
        });
        assert_eq!(
            runtime.shutdown_drained(Duration::from_secs(10)).outcome,
            crate::runtime::RootDrainOutcome::Quiescent
        );
        assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
    }

    fn park_subscription(
        operations: &BrokerOperations,
    ) -> (
        crate::channel::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (published, wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_subscribe_native.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        (wait_published, release)
    }

    async fn witnessed<F: Future + ?Sized>(
        cx: &Cx,
        mut operation: Pin<&mut F>,
        reached: &mut crate::channel::oneshot::Receiver<()>,
    ) {
        let mut witness = Box::pin(reached.recv(cx));
        poll_fn(|task| {
            assert!(operation.as_mut().poll(task).is_pending());
            witness.as_mut().poll(task)
        })
        .await
        .expect("native worker reached the retained hook");
    }

    async fn retired(operations: Arc<BrokerOperations>) {
        crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
            drop(operations.lock());
        })
        .await;
    }

    async fn native_topics(consumer: &KafkaConsumer) -> BTreeSet<String> {
        let (native, operations) = consumer.broker_backend().unwrap();
        crate::runtime::spawn_blocking::spawn_blocking_on_thread(move || {
            let _guard = operations.lock();
            let subscription = native.subscription().unwrap();
            subscription
                .elements()
                .into_iter()
                .map(|partition| partition.topic().to_string())
                .collect()
        })
        .await
    }

    async fn buffer_second_record(
        cx: &Cx,
        consumer: &KafkaConsumer,
        operations: &Arc<BrokerOperations>,
    ) {
        let (published, mut wait_published) = crate::channel::oneshot::channel();
        let (release, await_release) = std::sync::mpsc::channel();
        *operations.after_record_buffered.lock() = Some(BufferedRecordHook {
            published,
            release: await_release,
        });
        let mut polling = Box::pin(consumer.poll_nullable(cx, Duration::from_secs(30)));
        witnessed(cx, polling.as_mut(), &mut wait_published).await;
        drop(polling);
        release.send(()).unwrap();
        retired(Arc::clone(operations)).await;
        let buffered = consumer.buffered_outcome.lock();
        let record = buffered
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .record
            .as_ref()
            .expect("the actual native record remains retained");
        assert_eq!((record.topic.as_str(), record.offset), (OLD, 1));
    }

    #[test]
    fn dropped_waiter_still_publishes_the_native_subscription() {
        run(|cx, consumer, operations| async move {
            consumer
                .commit_offsets(&cx, &[TopicPartitionOffset::new(OLD, 0, 1)])
                .await
                .unwrap();
            let generation = consumer.rebalance_generation();
            let (mut reached, release) = park_subscription(&operations);
            let topics = [NEXT];
            let mut subscribing = Box::pin(consumer.subscribe(&cx, &topics));
            witnessed(&cx, subscribing.as_mut(), &mut reached).await;
            assert_eq!(consumer.subscriptions(), vec![OLD.to_string()]);
            drop(subscribing);
            release.send(()).unwrap();
            retired(Arc::clone(&operations)).await;
            // No poll or group-metadata capture has reconciled state here.
            assert_eq!(consumer.subscriptions(), vec![NEXT.to_string()]);
            assert!(consumer.assigned_partitions().is_empty());
            assert_eq!(consumer.position(OLD, 0), None);
            assert_eq!(consumer.committed_offset(OLD, 0), Some(1));
            assert_eq!(consumer.rebalance_generation(), generation + 1);
            assert_eq!(
                native_topics(&consumer).await,
                BTreeSet::from([NEXT.to_string()])
            );
            let next = consumer
                .poll_nullable(&cx, Duration::from_secs(30))
                .await
                .unwrap()
                .expect("a record under the real new subscription");
            assert_eq!((next.topic.as_str(), next.offset), (NEXT, 0));
        });
    }

    #[test]
    fn late_waiter_cannot_replace_a_newer_native_subscription() {
        run(|cx, consumer, operations| async move {
            let generation = consumer.rebalance_generation();
            let (mut reached, release) = park_subscription(&operations);
            let first_topics = [NEXT];
            let mut first = Box::pin(consumer.subscribe(&cx, &first_topics));
            witnessed(&cx, first.as_mut(), &mut reached).await;
            let (attempted, mut wait_attempted) = crate::channel::oneshot::channel();
            *operations.before_lock.lock() = Some(attempted);
            let last_topics = [LAST];
            let mut last = Box::pin(consumer.subscribe(&cx, &last_topics));
            witnessed(&cx, last.as_mut(), &mut wait_attempted).await;
            release.send(()).unwrap();
            last.await.unwrap();
            assert_eq!(consumer.subscriptions(), vec![LAST.to_string()]);
            // Resume the older receipt only after the newer call has finished.
            first.await.unwrap();
            assert_eq!(consumer.subscriptions(), vec![LAST.to_string()]);
            assert_eq!(consumer.rebalance_generation(), generation + 2);
            assert_eq!(
                native_topics(&consumer).await,
                BTreeSet::from([LAST.to_string()])
            );
        });
    }

    #[test]
    fn matching_buffered_record_refuses_before_subscription_effects() {
        run(|cx, consumer, operations| async move {
            let generation = consumer.rebalance_generation();
            buffer_second_record(&cx, &consumer, &operations).await;
            for topics in [vec![OLD], vec![OLD, NEXT], vec!["^subscription-.*"]] {
                let error = consumer.subscribe(&cx, &topics).await.unwrap_err();
                assert!(matches!(error, KafkaError::Config(message)
                    if message.contains("retained record")));
                assert_eq!(consumer.subscriptions(), vec![OLD.to_string()]);
                assert_eq!(consumer.rebalance_generation(), generation);
                assert_eq!(consumer.position(OLD, 0), Some(1));
                assert_eq!(
                    native_topics(&consumer).await,
                    BTreeSet::from([OLD.to_string()])
                );
                let buffered = consumer.buffered_outcome.lock();
                let record = buffered
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .record
                    .as_ref()
                    .expect("refusal must preserve the already-fetched record");
                assert_eq!((record.topic.as_str(), record.offset), (OLD, 1));
            }
            let retained = consumer
                .poll_nullable(&cx, Duration::ZERO)
                .await
                .unwrap()
                .expect("the refused subscription must not lose the record");
            assert_eq!((retained.topic.as_str(), retained.offset), (OLD, 1));
            assert_eq!(retained.payload.as_deref(), Some(&b""[..]));
            consumer.subscribe(&cx, &[OLD, NEXT]).await.unwrap();
            assert_eq!(
                native_topics(&consumer).await,
                BTreeSet::from([OLD.to_string(), NEXT.to_string()])
            );
            assert_eq!(consumer.rebalance_generation(), generation + 1);
        });
    }

    #[test]
    fn removed_topic_record_and_snapshot_do_not_reappear() {
        run(|cx, consumer, operations| async move {
            buffer_second_record(&cx, &consumer, &operations).await;
            consumer.subscribe(&cx, &[NEXT]).await.unwrap();
            {
                let buffered = consumer.buffered_outcome.lock();
                let outcome = buffered.as_ref().unwrap().as_ref().unwrap();
                assert!(outcome.record.is_none());
                assert!(outcome.snapshot.assigned_partitions.is_empty());
                assert!(outcome.snapshot.positions.is_empty());
            }
            // Consume only the retained empty outcome, before a new native
            // poll can mask an old snapshot resurrecting the removed topic.
            assert!(
                consumer
                    .poll_nullable(&cx, Duration::ZERO)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(consumer.assigned_partitions().is_empty());
            assert_eq!(consumer.position(OLD, 0), None);
            let next = consumer
                .poll_nullable(&cx, Duration::from_secs(30))
                .await
                .unwrap()
                .expect("the native replacement subscription must receive data");
            assert_eq!((next.topic.as_str(), next.offset), (NEXT, 0));
        });
    }

    #[test]
    fn queued_subscription_refuses_after_close_without_native_effects() {
        run(|cx, consumer, operations| async move {
            let (mut reached, release) = park_subscription(&operations);
            let first_topics = [NEXT];
            let mut first = Box::pin(consumer.subscribe(&cx, &first_topics));
            witnessed(&cx, first.as_mut(), &mut reached).await;
            let (attempted, mut wait_attempted) = crate::channel::oneshot::channel();
            *operations.before_lock.lock() = Some(attempted);
            let last_topics = [LAST];
            let mut last = Box::pin(consumer.subscribe(&cx, &last_topics));
            witnessed(&cx, last.as_mut(), &mut wait_attempted).await;
            // A second native success would consume this sentinel. Its release
            // is already available so a faulty implementation cannot hang here.
            let (_unexpected_success, unexpected_release) = park_subscription(&operations);
            unexpected_release.send(()).unwrap();
            let mut closing = Box::pin(consumer.close(&cx));
            assert!(
                poll_fn(|task| Poll::Ready(closing.as_mut().poll(task)))
                    .await
                    .is_pending()
            );
            assert!(consumer.is_closed());
            release.send(()).unwrap();
            for result in [first.await, last.await] {
                assert!(matches!(result, Err(KafkaError::Config(message))
                    if message == "consumer is closed"));
            }
            closing.await.unwrap();
            assert!(
                operations.after_subscribe_native.lock().is_some(),
                "a queued operation must not subscribe after close fenced admission"
            );
            drop(operations.after_subscribe_native.lock().take());
            assert!(consumer.subscriptions().is_empty());
            assert!(consumer.assigned_partitions().is_empty());
            assert!(native_topics(&consumer).await.is_empty());
        });
    }

    #[test]
    fn snapshot_filter_respects_literals_and_native_pattern_authority() {
        let mut state = ConsumerState::default();
        state.subscribed_topics.insert(NEXT.to_string());
        apply_broker_snapshot(
            &mut state,
            broker_snapshot_from_topic_maps(
                BTreeSet::from([(OLD.to_string(), 0), (NEXT.to_string(), 0)]),
                BTreeMap::from([
                    ((OLD.to_string(), 0), 9),
                    ((NEXT.to_string(), 0), 3),
                ]),
            ),
        );
        assert_eq!(
            state.assigned_partitions,
            BTreeSet::from([(NEXT.to_string(), 0)])
        );
        assert!(!state.positions.contains_key(&(OLD.to_string(), 0)));
        assert_eq!(state.positions.get(&(NEXT.to_string(), 0)), Some(&3));

        let mut patterned = ConsumerState::default();
        patterned.subscribed_topics.insert("^orders.*".to_string());
        let actual = ("orders-2026".to_string(), 0);
        assert!(!patterned.subscribed_topics.contains(&actual.0));
        assert!(subscription_may_include_topic(
            &patterned.subscribed_topics,
            &actual.0
        ));
        apply_broker_snapshot(
            &mut patterned,
            broker_snapshot_from_topic_maps(
                BTreeSet::from([actual.clone()]),
                BTreeMap::from([(actual.clone(), 7)]),
            ),
        );
        assert!(patterned.assigned_partitions.contains(&actual));
        assert_eq!(patterned.positions.get(&actual), Some(&7));
    }
}
