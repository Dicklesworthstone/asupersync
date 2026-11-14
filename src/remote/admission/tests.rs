use super::*;

#[test]
fn borrowed_preflight_matches_existing_strict_wire_bytes() {
    let cx = Cx::for_testing();
    let registry = ComputationSchemaRegistry::new();
    let hello = RemotePeerHello::new(
        NodeId::new("origin\n\"雪"),
        RemoteProtocolVersion::V3,
        registry.fingerprint(),
    );
    let input = (0_u8..=255).collect::<Vec<_>>();
    let request = SpawnRequest {
        remote_task_id: RemoteTaskId::from_raw(u64::MAX),
        computation: ComputationName::new("escaped\n\"computation"),
        input: RemoteInput::new(input.clone()),
        lease: Duration::new(u64::MAX, 999_999_999),
        idempotency_key: IdempotencyKey::from_raw(u128::MAX),
        budget: Some(cx.budget()),
        origin_node: hello.peer_node().clone(),
        origin_region: cx.region_id(),
        origin_task: cx.task_id(),
    };
    let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request).unwrap();
    let borrowed = BorrowedRequest {
        hello: &hello,
        remote_task_id: u64::MAX,
        computation: request.computation.as_str(),
        input: &input,
        lease_secs: u64::MAX,
        lease_subsec_nanos: 999_999_999,
        idempotency_key_high: u64::MAX,
        idempotency_key_low: u64::MAX,
        budget: request.budget.map(Into::into),
        origin_region: cx.region_id(),
        origin_task: cx.task_id(),
    };
    let expected = serde_json::to_vec(&wire).unwrap();
    assert_eq!(serde_json::to_vec(&borrowed).unwrap(), expected);
    assert_eq!(
        count_frame(&borrowed, expected.len()).unwrap(),
        expected.len()
    );
    assert!(count_frame(&borrowed, expected.len() - 1).is_err());
    assert!(count_frame(&borrowed, 0).is_err());
    eprintln!(
        "{}",
        serde_json::json!({"bead":"asupersync-bi2462.77", "case":"strict_wire_preflight",
        "encoded_bytes":expected.len(), "exact_limit":"accepted", "one_below":"refused"})
    );
}

#[test]
fn admission_credit_waits_for_every_buffer_owner() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let peer = NodeId::new("pinned-test-peer");
        let executor = RemoteExecutor::new_queued(
            RemoteAdmissionLimits {
                max_peers: 1,
                max_in_flight: 1,
                max_input_bytes: 1024,
            },
            [(
                peer.clone(),
                RemotePeerLimits {
                    max_in_flight: 1,
                    max_input_bytes: 1024,
                    max_request_bytes: 1024,
                },
            )],
            RemoteQueueLimits {
                max_waiters: 1,
                max_input_bytes: 1024,
                max_waiters_per_peer: 1,
                max_input_bytes_per_peer: 1024,
            },
        )
        .unwrap();
        let reservation = executor
            .reserve(&cx, &peer, 1024, Duration::from_secs(1))
            .await
            .unwrap();
        let credit = Arc::new(NativeRemoteCredit {
            _reservation: reservation,
        });
        let receiver_owner = Arc::clone(&credit);
        let driver_owner = credit;
        drop(receiver_owner);
        assert_eq!(
            executor.usage().in_flight,
            1,
            "dropping a live handle cannot release its driver's credit"
        );
        drop(driver_owner);
        assert_eq!(executor.usage().in_flight, 0);
        assert_eq!(executor.usage().input_bytes, 0);

        let credit = Arc::new(NativeRemoteCredit {
            _reservation: executor
                .reserve(&cx, &peer, 1024, Duration::from_secs(1))
                .await
                .unwrap(),
        });
        let unread_result = Arc::clone(&credit);
        drop(credit);
        assert_eq!(
            executor.usage().input_bytes,
            1024,
            "an unread terminal result retains admission"
        );
        drop(unread_result);
        assert_eq!(executor.usage().input_bytes, 0);
    });
}

#[test]
fn attenuated_commit_refuses_before_native_registration_and_releases_credit() {
    use crate::tls::{Certificate, CertificatePin, CertificatePinSet, TlsConnectorBuilder};

    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    let handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let certificate =
            Certificate::from_pem(include_bytes!("../../../tests/fixtures/tls/server.crt"))
                .unwrap()
                .remove(0);
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&certificate)
            .with_certificate_pins(
                CertificatePinSet::new()
                    .with_pin(CertificatePin::compute_spki_sha256(&certificate).unwrap()),
            )
            .build()
            .unwrap();
        let client = RemoteComputationClient::new(
            "127.0.0.1:1".parse().unwrap(),
            "localhost",
            connector,
            RemoteComputationClientConfig::new()
                .with_wire_limits(RemoteServiceWireLimits::new(4096)),
        )
        .unwrap();
        let node = NodeId::new("peer");
        let origin = NodeId::new("origin");
        let hello = RemotePeerHello::new(
            origin.clone(),
            RemoteProtocolVersion::V3,
            ComputationSchemaRegistry::new().fingerprint(),
        );
        let charge = 16 * (4096 + 4) + 256 * 1024;
        let admitted = AdmittedNativeRemoteRuntime::new(
            handle,
            origin,
            [(
                NativeRemoteRoute::new(node.clone(), hello, client),
                NativeRemotePeerAdmissionLimits {
                    max_in_flight: 1,
                    max_buffer_bytes: charge,
                    max_input_bytes: 1,
                },
            )],
            NativeRemoteAdmissionLimits {
                max_routes: 1,
                max_in_flight: 1,
                max_buffer_bytes: charge,
                max_waiters: 0,
                max_waiters_per_peer: 0,
            },
            NativeRemoteRuntimeConfig::new().with_max_in_flight(1),
        )
        .unwrap();
        let restricted = {
            type LocalCaps = crate::cx::cap::CapSet<true, true, true, true, false>;
            let _guard = cx.restrict::<LocalCaps>().set_current_restricted();
            Cx::current().unwrap()
        };
        assert!(cx.capabilities().remote);
        assert!(restricted.capabilities().io);
        assert!(!restricted.capabilities().remote);
        assert!(cx.remote().is_none(), "the domain supplies route authority");

        let reservation = admitted
            .reserve(&cx, &node, 1, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(admitted.usage().in_flight, 1);
        assert_eq!(admitted.peer_usage(&node).unwrap().buffer_bytes, charge);
        assert!(matches!(
            reservation.commit(
                &restricted,
                &ComputationName::new("echo"),
                &[7],
                Duration::from_secs(1),
            ),
            Err(NativeRemoteAdmissionError::Remote(RemoteError::NoCapability))
        ));
        assert_eq!(admitted.usage(), NativeRemoteAdmissionUsage::default());
        assert_eq!(
            admitted.peer_usage(&node),
            Some(NativeRemoteAdmissionUsage::default())
        );
        {
            let state = admitted.domain.runtime.shared.state.lock();
            assert!(
                state.tasks.is_empty(),
                "no native result channel was registered"
            );
            assert!(state.active.is_empty(), "no native driver was admitted");
        }
        let reused = admitted
            .reserve(&cx, &node, 1, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(admitted.usage().buffer_bytes, charge);
        drop(reused);
        assert_eq!(admitted.usage(), NativeRemoteAdmissionUsage::default());
    });
}

#[test]
fn discarded_factory_and_unpolled_driver_retire_native_admission() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let peer = NodeId::new("peer");
        let executor = RemoteExecutor::new_queued(
            RemoteAdmissionLimits { max_peers: 1, max_in_flight: 1, max_input_bytes: 1024 },
            [(peer.clone(), RemotePeerLimits { max_in_flight: 1, max_input_bytes: 1024, max_request_bytes: 1024 })],
            RemoteQueueLimits { max_waiters: 1, max_input_bytes: 1024, max_waiters_per_peer: 1, max_input_bytes_per_peer: 1024 },
        ).unwrap();
        let cert = crate::tls::Certificate::from_pem(include_bytes!("../../../tests/fixtures/tls/server.crt")).unwrap().remove(0);
        let client = RemoteComputationClient::new("127.0.0.1:1".parse().unwrap(), "localhost",
            crate::tls::TlsConnectorBuilder::new().add_root_certificate(&cert).build().unwrap(),
            RemoteComputationClientConfig::new()).unwrap();
        for construct_future in [false, true] {
            let shared = Arc::new(NativeRemoteShared { max_in_flight: 1, drain_timeout: Duration::from_secs(1),
                automatic_lease_renewal: true, state: Mutex::new(NativeRemoteState::new()), retirement_notify: None });
            let task = RemoteTaskId::next();
            let (sender, mut receiver) = oneshot::channel();
            shared.register(task, sender);
            let control_receiver = shared.admit(task).unwrap();
            let registry = ComputationSchemaRegistry::new();
            let request = SpawnRequest { remote_task_id: task, computation: ComputationName::new("echo"),
                input: RemoteInput::new(vec![1, 2, 3]), lease: Duration::from_secs(1), idempotency_key: IdempotencyKey::from_raw(1),
                budget: None, origin_node: NodeId::new("origin"), origin_region: cx.region_id(), origin_task: cx.task_id() };
            let credit = Arc::new(NativeRemoteCredit { _reservation: executor.reserve(&cx, &peer, 1024,
                Duration::from_secs(1)).await.unwrap() });
            let guard = NativeRemoteDriverGuard::new(Arc::clone(&shared), task, Some(credit));
            let publication = NativeRemotePublishedRequest {
                wire: RemoteServiceWireRequest::from_spawn_request(RemotePeerHello::new(NodeId::new("origin"),
                    RemoteProtocolVersion::V3, registry.fingerprint()), &request).unwrap(),
                origin: None,
                client: client.clone(), control: shared.control(task).unwrap(), control_receiver,
                guard,
            };
            assert_eq!(shared.state.lock().active.len(), 1);
            assert_eq!(executor.usage().in_flight, 1);
            let factory = move || async move { drop(publication); };
            if construct_future { drop(factory()); } else { drop(factory); }
            assert!(shared.state.lock().active.is_empty());
            assert_eq!(executor.usage().in_flight, 0);
            assert!(matches!(receiver.try_recv(), Ok(Err(RemoteError::TransportError(message)))
                if message == "native remote driver ended before terminal publication"));
            assert!(shared.state.lock().tasks[&task].driver_cx.is_none());
            eprintln!("{}", serde_json::json!({"bead":"asupersync-bi2462.77", "case":"unpolled_publication_drop",
                "constructed_future":construct_future, "active":shared.state.lock().active.len(),
                "charged_bytes":executor.usage().input_bytes, "terminal":"TransportError"}));
        }
    });
}

/// br-asupersync-96btkn: a handle dropped as its driver completes leaves no
/// task entry behind. Here the driver completes inside the drop's own cancel
/// request, while the handle's result receiver is still alive: the result is
/// delivered, so the driver keeps the entry, and the runtime retires it when
/// the handle reports its drop.
#[test]
fn a_handle_dropped_as_its_driver_completes_leaves_no_task_entry() {
    struct CompletesOnCancel(Arc<NativeRemoteShared>);

    impl fmt::Debug for CompletesOnCancel {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("CompletesOnCancel")
        }
    }

    impl RemoteRuntime for CompletesOnCancel {
        fn send_message(
            &self,
            _destination: &NodeId,
            envelope: MessageEnvelope<RemoteMessage>,
        ) -> Result<(), RemoteError> {
            if let RemoteMessage::CancelRequest(request) = envelope.payload {
                let task = request.remote_task_id;
                self.0
                    .complete(task, Ok(RemoteOutcome::Success(Vec::new())), None);
                let _ = self.0.request_cancel(task, request.reason);
            }
            Ok(())
        }

        fn register_task(
            &self,
            task_id: RemoteTaskId,
            tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
        ) {
            self.0.register(task_id, tx);
        }

        fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
            self.0
                .state
                .lock()
                .tasks
                .get(&task_id)
                .map(|entry| entry.state)
        }

        fn clear_task_state(&self, task_id: RemoteTaskId) {
            self.0.state.lock().tasks.remove(&task_id);
        }

        fn unregister_task(&self, task_id: RemoteTaskId) {
            self.0.roll_back_admission(task_id);
        }

        fn handle_dropped(&self, task_id: RemoteTaskId) {
            self.0.release_dropped_handle(task_id);
        }
    }

    let cx = Cx::for_testing();
    let shared = Arc::new(NativeRemoteShared {
        max_in_flight: 1,
        drain_timeout: Duration::from_secs(1),
        automatic_lease_renewal: true,
        state: Mutex::new(NativeRemoteState::new()),
        retirement_notify: None,
    });
    let runtime: Arc<dyn RemoteRuntime> = Arc::new(CompletesOnCancel(Arc::clone(&shared)));
    let task = RemoteTaskId::next();
    let (sender, receiver) = oneshot::channel();
    runtime.register_task(task, sender);
    let _control = shared.admit(task).unwrap();
    shared.set_running(task);
    drop(RemoteHandle {
        remote_task_id: task,
        local_task_id: None,
        origin_node: NodeId::new("origin"),
        node: NodeId::new("peer"),
        computation: ComputationName::new("echo"),
        owner_region: cx.region_id(),
        runtime: Some(runtime),
        receiver,
        sender_clock: cx.logical_clock_handle(),
        lease: Duration::from_secs(1),
        state: RemoteTaskState::Running,
        completed: false,
    });
    let state = shared.state.lock();
    assert!(state.active.is_empty());
    assert!(
        state.tasks.is_empty(),
        "the dropped handle's task entry was left behind"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetirementObservation {
    active: usize,
    charged: usize,
    bytes: usize,
}

struct RetirementWaker {
    shared: Arc<NativeRemoteShared>,
    executor: RemoteExecutor,
    observations: Arc<Mutex<Vec<RetirementObservation>>>,
    panic_after_observe: bool,
}

impl RetirementWaker {
    fn observe(&self) {
        let active = self
            .shared
            .state
            .try_lock()
            .expect("retirement callbacks must run outside the native state lock")
            .active
            .len();
        let usage = self.executor.usage();
        self.observations.lock().push(RetirementObservation {
            active,
            charged: usage.in_flight,
            bytes: usage.input_bytes,
        });
        assert!(
            !self.panic_after_observe,
            "injected admission-release wake panic"
        );
    }
}

impl std::task::Wake for RetirementWaker {
    fn wake(self: Arc<Self>) {
        self.observe();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.observe();
    }
}

fn retirement_executor(peer: &NodeId) -> RemoteExecutor {
    RemoteExecutor::new_queued(
        RemoteAdmissionLimits {
            max_peers: 1,
            max_in_flight: 1,
            max_input_bytes: 1024,
        },
        [(
            peer.clone(),
            RemotePeerLimits {
                max_in_flight: 1,
                max_input_bytes: 1024,
                max_request_bytes: 1024,
            },
        )],
        RemoteQueueLimits {
            max_waiters: 1,
            max_input_bytes: 1024,
            max_waiters_per_peer: 1,
            max_input_bytes_per_peer: 1024,
        },
    )
    .unwrap()
}

#[test]
fn terminal_delivery_and_admission_release_precede_driver_retirement() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for keep_receiver in [false, true] {
            let peer = NodeId::new("peer");
            let executor = retirement_executor(&peer);
            let retired = Arc::new(crate::sync::Notify::new());
            let shared = Arc::new(NativeRemoteShared {
                max_in_flight: 1, drain_timeout: Duration::from_secs(1),
                automatic_lease_renewal: true, state: Mutex::new(NativeRemoteState::new()),
                retirement_notify: Some(Arc::clone(&retired)),
            });
            let task = RemoteTaskId::next();
            let (sender, receiver) = oneshot::channel();
            let mut receiver = Some(receiver);
            shared.register(task, sender);
            let _control = shared.admit(task).unwrap();
            let credit = Arc::new(NativeRemoteCredit {
                _reservation: executor.reserve(&cx, &peer, 1024, Duration::from_secs(1)).await.unwrap(),
            });
            let receiver_credit = keep_receiver.then(|| Arc::clone(&credit));
            if !keep_receiver { drop(receiver.take()); }
            let delivery = Arc::new(Mutex::new(Vec::new()));
            let delivery_waker = Waker::from(Arc::new(RetirementWaker {
                shared: Arc::clone(&shared), executor: executor.clone(),
                observations: Arc::clone(&delivery), panic_after_observe: false,
            }));
            let mut result_wait = receiver.as_mut().map(|receiver| Box::pin(receiver.recv_uninterruptible()));
            if let Some(waiter) = &mut result_wait {
                assert!(waiter.as_mut().poll(&mut Context::from_waker(&delivery_waker)).is_pending());
            }
            let observations = Arc::new(Mutex::new(Vec::new()));
            let retirement_waker = Waker::from(Arc::new(RetirementWaker {
                shared: Arc::clone(&shared), executor: executor.clone(),
                observations: Arc::clone(&observations), panic_after_observe: false,
            }));
            let mut retired_wait = Box::pin(retired.notified());
            assert!(retired_wait.as_mut().poll(&mut Context::from_waker(&retirement_waker)).is_pending());
            let mut driver = NativeRemoteDriverGuard::new(Arc::clone(&shared), task, Some(credit));
            driver.finish(Ok(RemoteOutcome::Success(vec![7; 128])));
            drop(driver);
            assert_eq!(*observations.lock(), vec![RetirementObservation {
                active: 0, charged: usize::from(keep_receiver),
                bytes: if keep_receiver { 1024 } else { 0 },
            }], "close must never observe a retired driver that still owns credit");
            if keep_receiver {
                assert_eq!(*delivery.lock(), vec![RetirementObservation {
                    active: 1, charged: 1, bytes: 1024,
                }], "the result is transferred before final driver release");
            }
            drop(result_wait);
            if let Some(receiver) = &mut receiver {
                assert!(matches!(receiver.try_recv(), Ok(Ok(RemoteOutcome::Success(bytes))) if bytes == [7; 128]));
            }
            drop(receiver);
            drop(receiver_credit);
            shared.release_dropped_handle(task);
            assert!(shared.state.lock().tasks.is_empty());
            assert_eq!(executor.usage().input_bytes, 0);
            assert_eq!(executor.usage().in_flight, 0);
            eprintln!("{}", serde_json::json!({"bead":"asupersync-96btkn",
                "case":"retirement_after_credit", "unread_receiver":keep_receiver,
                "remaining_bytes":executor.usage().input_bytes,
                "remaining_active":shared.state.lock().active.len()}));
        }
    });
}

#[test]
fn a_panicking_credit_release_cannot_strand_native_driver_retirement() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let peer = NodeId::new("peer");
        let executor = retirement_executor(&peer);
        let retired = Arc::new(crate::sync::Notify::new());
        let shared = Arc::new(NativeRemoteShared {
            max_in_flight: 1,
            drain_timeout: Duration::from_secs(1),
            automatic_lease_renewal: true,
            state: Mutex::new(NativeRemoteState::new()),
            retirement_notify: Some(Arc::clone(&retired)),
        });
        let task = RemoteTaskId::next();
        let (sender, receiver) = oneshot::channel();
        shared.register(task, sender);
        let _control = shared.admit(task).unwrap();
        drop(receiver);
        let credit = Arc::new(NativeRemoteCredit {
            _reservation: executor
                .reserve(&cx, &peer, 1024, Duration::from_secs(1))
                .await
                .unwrap(),
        });
        let released = Arc::new(Mutex::new(Vec::new()));
        let release_waker = Waker::from(Arc::new(RetirementWaker {
            shared: Arc::clone(&shared),
            executor: executor.clone(),
            observations: Arc::clone(&released),
            panic_after_observe: true,
        }));
        let mut queued = Box::pin(executor.reserve(&cx, &peer, 1024, Duration::from_secs(5)));
        assert!(
            queued
                .as_mut()
                .poll(&mut Context::from_waker(&release_waker))
                .is_pending()
        );
        let observations = Arc::new(Mutex::new(Vec::new()));
        let retirement_waker = Waker::from(Arc::new(RetirementWaker {
            shared: Arc::clone(&shared),
            executor: executor.clone(),
            observations: Arc::clone(&observations),
            panic_after_observe: false,
        }));
        let mut retired_wait = Box::pin(retired.notified());
        assert!(
            retired_wait
                .as_mut()
                .poll(&mut Context::from_waker(&retirement_waker))
                .is_pending()
        );
        let drained = Arc::new(Mutex::new(Vec::new()));
        let drain_wakers = [true, false].map(|panic_after_observe| {
            Waker::from(Arc::new(RetirementWaker {
                shared: Arc::clone(&shared),
                executor: executor.clone(),
                observations: Arc::clone(&drained),
                panic_after_observe,
            }))
        });
        let mut drains = [
            shared.begin_drain(true).2.unwrap(),
            shared.begin_drain(true).2.unwrap(),
        ];
        let mut drain_waiters = drains
            .iter_mut()
            .map(|receiver| Box::pin(receiver.recv_uninterruptible()))
            .collect::<Vec<_>>();
        for (waiter, waker) in drain_waiters.iter_mut().zip(&drain_wakers) {
            assert!(
                waiter
                    .as_mut()
                    .poll(&mut Context::from_waker(waker))
                    .is_pending()
            );
        }
        let mut driver = NativeRemoteDriverGuard::new(Arc::clone(&shared), task, Some(credit));
        driver.finish(Ok(RemoteOutcome::Success(vec![7; 128])));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(driver)));
        assert!(
            unwind.is_err(),
            "the planted release callback actually panicked"
        );
        assert_eq!(
            *released.lock(),
            vec![RetirementObservation {
                active: 1,
                charged: 0,
                bytes: 0
            }]
        );
        assert_eq!(
            *observations.lock(),
            vec![RetirementObservation {
                active: 0,
                charged: 0,
                bytes: 0
            }]
        );
        assert_eq!(
            *drained.lock(),
            vec![
                RetirementObservation {
                    active: 0,
                    charged: 0,
                    bytes: 0
                };
                2
            ],
            "a panicking drain receiver must not strand later receivers or the domain notifier"
        );
        for (waiter, waker) in drain_waiters.iter_mut().zip(&drain_wakers) {
            assert!(matches!(
                waiter.as_mut().poll(&mut Context::from_waker(waker)),
                std::task::Poll::Ready(Ok(()))
            ));
        }
        assert!(shared.state.lock().active.is_empty());
        assert!(shared.state.lock().tasks.is_empty());
        drop(queued);
        assert_eq!(executor.queue_usage().waiters, 0);
        assert_eq!(executor.usage().in_flight, 0);
    });
}
