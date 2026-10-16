    use super::*;
    use crate::distributed::ComputationSchemaRegistry;
    use crate::remote::{NodeId, RemoteProtocolVersion};
    use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use crate::util::ArenaIndex;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn transport(cx: Cx) -> RemoteSymbolTransport {
        RemoteSymbolTransport {
            cx, hello: RemotePeerHello::new(NodeId::new("origin"), RemoteProtocolVersion::V1,
                ComputationSchemaRegistry::new().fingerprint()),
            routes: Arc::new(BTreeMap::new()), auth_key: Arc::new(AuthKey::from_seed(42)),
            limits: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16, max_payload_bytes: 2048, max_decoded_bytes: 8192 },
            admission: Arc::new(super::super::admission::Admission::new(1)), chunk_bytes: Some(128),
        }
    }

    fn timed_cx(id: u32, budget: Budget, timer: TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(RegionId::from_arena(ArenaIndex::new(id, 0)),
            TaskId::from_arena(ArenaIndex::new(id, 0)), budget, None, None, None, Some(timer), None)
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }


    #[test]
    fn explicit_attempt_refuses_whole_batch_transport_before_route_or_admission() {
        let mut transport = transport(Cx::for_testing());
        transport.chunk_bytes = None;
        let mut sending = Box::pin(transport.send_symbols_with_attempt("missing", Vec::new(), 17));
        let result = sending.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(result, Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert_eq!(transport.in_flight(), 0);
    }

    #[test]
    fn whole_transfer_timer_and_inner_polls_use_owner_despite_foreign_ambient_clock() {
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
        let owner = timed_cx(1, Budget::INFINITE.with_deadline(Time::from_nanos(100)),
            TimerDriverHandle::new(Arc::clone(&driver)));
        let foreign_clock = Arc::new(VirtualClock::new());
        foreign_clock.advance(1000);
        let foreign = timed_cx(2, Budget::INFINITE, TimerDriverHandle::with_virtual_clock(foreign_clock));
        let transport = transport(owner.clone());
        let polls = AtomicUsize::new(0);
        let inner = poll_fn(|_| {
            assert_eq!(Cx::current().unwrap().task_id(), owner.task_id());
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending::<Result<(), RemoteSymbolError>>
        });
        let wake = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut operation = Box::pin(transport.with_owner_deadline(inner));
        let _foreign = Cx::set_current(Some(foreign.clone()));
        assert!(operation.as_mut().poll(&mut task).is_pending(), "foreign clock must not expire the owner");
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        clock.advance(100);
        driver.process_timers();
        assert!(wake.0.load(Ordering::SeqCst) > 0, "owner timer must wake the parked operation");
        assert!(matches!(operation.as_mut().poll(&mut task), Poll::Ready(Err(RemoteSymbolError::Deadline))));
        assert_eq!(Cx::current().unwrap().task_id(), foreign.task_id());
    }

    #[test]
    fn declared_owner_deadline_without_owner_timer_refuses_before_inner_dispatch() {
        let owner = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX)));
        let transport = transport(owner);
        let dispatched = AtomicBool::new(false);
        let mut operation = Box::pin(transport.with_owner_deadline(async {
            dispatched.store(true, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(operation.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(RemoteSymbolError::Configuration))));
        assert!(!dispatched.load(Ordering::SeqCst));
    }
