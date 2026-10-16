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

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "windows"
    ))]
    fn create_reactor_factory() {
        init_test("create_reactor_factory");
        let reactor = create_reactor().expect("failed to create reactor");
        let snapshot = reactor.capability_snapshot();
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        assert_ne!(snapshot.backend(), IoReactorBackend::Injected);
        for capability in IoUringCapability::ALL {
            assert_eq!(
                snapshot.decision(capability),
                IoUringCapabilityDecision::not_requested(capability)
            );
        }
        crate::test_complete!("create_reactor_factory");
    }

    #[test]
    fn io_uring_capability_ids_and_fallback_ids_are_stable() {
        assert_eq!(IoReactorBackend::Unavailable.as_str(), "unavailable");
        assert_eq!(
            IoUringCapability::ALL.map(IoUringCapability::id),
            [
                "URING-CAP-FIXED-BUFFERS",
                "URING-CAP-PROVIDED-GROUPS",
                "URING-CAP-MAPPED-BUFFER-RING",
                "URING-CAP-MULTISHOT-ACCEPT",
                "URING-CAP-MULTISHOT-RECV",
                "URING-CAP-SQPOLL",
            ]
        );
        assert_eq!(IoUringFallbackReason::None.id(), "URING-FB-NONE");
        assert_eq!(
            IoUringFallbackReason::NotRequested.id(),
            "URING-FB-NOT-REQUESTED"
        );
        assert_eq!(
            IoUringFallbackReason::FeatureDisabled.id(),
            "URING-FB-FEATURE-DISABLED"
        );
        assert_eq!(
            IoUringFallbackReason::TargetUnsupported.id(),
            "URING-FB-TARGET-UNSUPPORTED"
        );
        assert_eq!(IoUringFallbackReason::ForcedOff.id(), "URING-FB-FORCED-OFF");
        assert_eq!(
            IoUringFallbackReason::RingCreate.id(),
            "URING-FB-RING-CREATE"
        );
        assert_eq!(
            IoUringFallbackReason::ReactorUnavailable.id(),
            "URING-FB-REACTOR-UNAVAILABLE"
        );
        assert_eq!(
            IoUringFallbackReason::OperationUnsupported.id(),
            "URING-FB-OP-UNSUPPORTED"
        );
        assert_eq!(
            IoUringFallbackReason::Permission.id(),
            "URING-FB-PERMISSION"
        );
        assert_eq!(IoUringFallbackReason::Resource.id(), "URING-FB-RESOURCE");
        assert_eq!(
            IoUringFallbackReason::ProbeError.id(),
            "URING-FB-PROBE-ERROR"
        );
        assert_eq!(
            IoUringFallbackReason::Dependency.id(),
            "URING-FB-DEPENDENCY"
        );
        assert_eq!(IoUringFallbackReason::NoWin.id(), "URING-FB-NO-WIN");
        assert_eq!(IoUringFallbackReason::Unknown.id(), "URING-FB-UNKNOWN");
    }

    #[test]
    fn terminal_reactor_snapshot_preserves_policy_without_probing() {
        let policy = IoUringCapabilityPolicy::new()
            .with_requested(IoUringCapability::FixedBuffers, true)
            .with_requested(IoUringCapability::SqPoll, true)
            .with_forced_off(IoUringCapability::SqPoll, true);

        let snapshot = IoReactorCapabilitySnapshot::reactor_unavailable(policy);
        assert_eq!(snapshot.backend(), IoReactorBackend::Unavailable);
        assert_eq!(
            snapshot.selection_fallback(),
            Some(IoUringFallbackReason::ReactorUnavailable)
        );

        let requested = snapshot.decision(IoUringCapability::FixedBuffers);
        assert!(requested.requested());
        assert_eq!(requested.supported(), IoUringSupportState::NotProbed);
        assert!(!requested.active());
        assert_eq!(
            requested.fallback_reason(),
            IoUringFallbackReason::ReactorUnavailable
        );

        let forced_off = snapshot.decision(IoUringCapability::SqPoll);
        assert!(forced_off.requested());
        assert_eq!(forced_off.supported(), IoUringSupportState::NotProbed);
        assert!(!forced_off.active());
        assert_eq!(
            forced_off.fallback_reason(),
            IoUringFallbackReason::ForcedOff
        );

        let unrequested = snapshot.decision(IoUringCapability::MultishotAccept);
        assert!(!unrequested.requested());
        assert_eq!(unrequested.supported(), IoUringSupportState::NotProbed);
        assert!(!unrequested.active());
        assert_eq!(
            unrequested.fallback_reason(),
            IoUringFallbackReason::NotRequested
        );
    }

    #[test]
    fn io_uring_capability_decision_fails_inconsistent_tuples_closed() {
        let capability = IoUringCapability::FixedBuffers;
        let valid = IoUringCapabilityDecision::new(
            capability,
            true,
            IoUringSupportState::Supported,
            true,
            IoUringFallbackReason::None,
        );
        assert!(valid.active());
        assert_eq!(valid.fallback_reason(), IoUringFallbackReason::None);

        let invalid = IoUringCapabilityDecision::new(
            capability,
            false,
            IoUringSupportState::Supported,
            true,
            IoUringFallbackReason::None,
        );
        assert_eq!(invalid.capability(), capability);
        assert!(!invalid.requested());
        assert_eq!(invalid.supported(), IoUringSupportState::Supported);
        assert!(!invalid.active());
        assert_eq!(invalid.fallback_reason(), IoUringFallbackReason::Unknown);
    }

    #[test]
    fn io_uring_capability_policy_precedence_is_deterministic() {
        let requested = IoUringCapability::FixedBuffers;
        let unrequested = IoUringCapability::ProvidedGroups;
        let policy = IoUringCapabilityPolicy::new()
            .with_requested(requested, true)
            .with_forced_off(requested, true);

        let forced = policy.decide(requested, Some(IoUringProbeOutcome::Supported));
        assert!(forced.requested());
        assert_eq!(forced.supported(), IoUringSupportState::NotProbed);
        assert!(!forced.active());
        assert_eq!(forced.fallback_reason(), IoUringFallbackReason::ForcedOff);

        let skipped = policy.decide(unrequested, Some(IoUringProbeOutcome::Supported));
        assert_eq!(
            skipped,
            IoUringCapabilityDecision::not_requested(unrequested)
        );

        let active = IoUringCapabilityPolicy::new()
            .with_requested(requested, true)
            .decide(requested, Some(IoUringProbeOutcome::Supported));
        assert!(active.active());
        assert_eq!(active.fallback_reason(), IoUringFallbackReason::None);

        let dependent = IoUringCapability::MultishotRecv;
        let dependency_blocked = IoUringCapabilityPolicy::new()
            .with_requested(dependent, true)
            .decide(dependent, Some(IoUringProbeOutcome::Dependency));
        assert!(dependency_blocked.requested());
        assert_eq!(
            dependency_blocked.supported(),
            IoUringSupportState::NotProbed
        );
        assert!(!dependency_blocked.active());
        assert_eq!(
            dependency_blocked.fallback_reason(),
            IoUringFallbackReason::Dependency
        );
    }

    // Event tests
    #[test]
    fn event_new() {
        init_test("event_new");
        let event = Event::new(Token::new(42), Interest::READABLE | Interest::WRITABLE);
        crate::assert_with_log!(event.token.0 == 42, "token id", 42usize, event.token.0);
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_new");
    }

    #[test]
    fn event_readable() {
        init_test("event_readable");
        let event = Event::readable(Token::new(1));
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_readable");
    }

    #[test]
    fn event_writable() {
        init_test("event_writable");
        let event = Event::writable(Token::new(2));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_writable");
    }

    #[test]
    fn event_errored() {
        init_test("event_errored");
        let event = Event::errored(Token::new(3));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_errored");
    }

    #[test]
    fn event_hangup() {
        init_test("event_hangup");
        let event = Event::hangup(Token::new(4));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_hangup");
    }

    #[test]
    fn event_combined_flags() {
        init_test("event_combined_flags");
        let event = Event::new(
            Token::new(5),
            Interest::READABLE | Interest::ERROR | Interest::HUP,
        );
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_combined_flags");
    }

    // Events container tests
    #[test]
    fn events_with_capacity() {
        init_test("events_with_capacity");
        let events = Events::with_capacity(64);
        crate::assert_with_log!(
            events.capacity() == 64,
            "capacity",
            64usize,
            events.capacity()
        );
        crate::assert_with_log!(events.is_empty(), "len", 0usize, events.len());
        crate::assert_with_log!(events.is_empty(), "is_empty", true, events.is_empty());
        crate::test_complete!("events_with_capacity");
    }

    #[test]
    fn events_push_and_iterate() {
        init_test("events_push_and_iterate");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));
        events.push(Event::errored(Token::new(3)));

        crate::assert_with_log!(events.len() == 3, "len", 3usize, events.len());
        crate::assert_with_log!(!events.is_empty(), "not empty", false, events.is_empty());

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3],
            "tokens order",
            vec![1, 2, 3],
            tokens
        );
        crate::test_complete!("events_push_and_iterate");
    }

    #[test]
    fn events_clear() {
        init_test("events_clear");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));

        crate::assert_with_log!(events.len() == 2, "len before clear", 2usize, events.len());
        events.clear();
        crate::assert_with_log!(events.is_empty(), "len after clear", 0usize, events.len());
        crate::assert_with_log!(
            events.is_empty(),
            "empty after clear",
            true,
            events.is_empty()
        );
        // Capacity is maintained
        crate::assert_with_log!(
            events.capacity() == 10,
            "capacity maintained",
            10usize,
            events.capacity()
        );
        crate::test_complete!("events_clear");
    }

    #[test]
    fn events_grow_beyond_capacity() {
        init_test("events_grow_beyond_capacity");
        let mut events = Events::with_capacity(3);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));
        events.push(Event::readable(Token::new(3)));
        // These should be retained (growing the vector)
        events.push(Event::readable(Token::new(4)));
        events.push(Event::readable(Token::new(5)));

        crate::assert_with_log!(events.len() == 5, "len grew", 5usize, events.len());

        // Capacity should track actual backing storage growth.
        crate::assert_with_log!(
            events.capacity() >= events.len(),
            "capacity tracks growth",
            true,
            events.capacity()
        );

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3, 4, 5],
            "all tokens retained",
            vec![1, 2, 3, 4, 5],
            tokens
        );
        crate::test_complete!("events_grow_beyond_capacity");
    }

    #[test]
    fn events_into_iter_ref() {
        init_test("events_into_iter_ref");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let mut count = 0;
        for event in &events {
            let ok = event.is_readable() || event.is_writable();
            crate::assert_with_log!(ok, "event readable or writable", true, ok);
            count += 1;
        }
        crate::assert_with_log!(count == 2, "iter count", 2usize, count);
        crate::test_complete!("events_into_iter_ref");
    }

    #[test]
    fn events_into_iter_owned() {
        init_test("events_into_iter_owned");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let collected: Vec<Event> = events.into_iter().collect();
        crate::assert_with_log!(
            collected.len() == 2,
            "collected len",
            2usize,
            collected.len()
        );
        crate::assert_with_log!(
            collected[0].is_readable(),
            "first readable",
            true,
            collected[0].is_readable()
        );
        crate::assert_with_log!(
            collected[1].is_writable(),
            "second writable",
            true,
            collected[1].is_writable()
        );
        crate::test_complete!("events_into_iter_owned");
    }

    #[test]
    fn events_zero_capacity() {
        init_test("events_zero_capacity");
        let mut events = Events::with_capacity(0);
        crate::assert_with_log!(
            events.capacity() == 0,
            "capacity zero",
            0usize,
            events.capacity()
        );
        crate::assert_with_log!(events.is_empty(), "len zero", 0usize, events.len());

        // Should grow dynamically despite initial capacity of 0
        events.push(Event::readable(Token::new(1)));
        crate::assert_with_log!(events.len() == 1, "len grew", 1usize, events.len());
        crate::test_complete!("events_zero_capacity");
    }

    // Token tests
    #[test]
    fn token_new() {
        init_test("token_new");
        let token = Token::new(123);
        crate::assert_with_log!(token.0 == 123, "token id", 123usize, token.0);
        crate::test_complete!("token_new");
    }

    #[test]
    fn token_equality() {
        init_test("token_equality");
        let t1 = Token::new(1);
        let t2 = Token::new(1);
        let t3 = Token::new(2);

        crate::assert_with_log!(t1 == t2, "t1 == t2", t2, t1);
        crate::assert_with_log!(t1 != t3, "t1 != t3", true, t1 != t3);
        crate::test_complete!("token_equality");
    }

    #[test]
    fn token_ordering() {
        init_test("token_ordering");
        let t1 = Token::new(1);
        let t2 = Token::new(2);

        crate::assert_with_log!(t1 < t2, "t1 < t2", true, t1 < t2);
        crate::assert_with_log!(t2 > t1, "t2 > t1", true, t2 > t1);
        crate::test_complete!("token_ordering");
    }

    // ============================================================
    // Cross-reactor trait compliance tests
    //
    // Verify that all Reactor implementations satisfy the same
    // behavioral contract through the trait interface.
    // ============================================================

    /// Compile-time assertion that a reactor type is Send + Sync + Reactor.
    fn assert_reactor_trait_bounds<R: Reactor + Send + Sync>() {}

    #[test]
    fn reactor_trait_bounds_epoll() {
        init_test("reactor_trait_bounds_epoll");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_reactor_trait_bounds::<super::EpollReactor>();
        crate::test_complete!("reactor_trait_bounds_epoll");
    }

    #[test]
    fn reactor_trait_bounds_lab() {
        init_test("reactor_trait_bounds_lab");
        assert_reactor_trait_bounds::<super::LabReactor>();
        crate::test_complete!("reactor_trait_bounds_lab");
    }

    #[test]
    fn reactor_trait_bounds_browser() {
        init_test("reactor_trait_bounds_browser");
        assert_reactor_trait_bounds::<super::BrowserReactor>();
        crate::test_complete!("reactor_trait_bounds_browser");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn reactor_trait_bounds_io_uring() {
        init_test("reactor_trait_bounds_io_uring");
        assert_reactor_trait_bounds::<super::IoUringReactor>();
        crate::test_complete!("reactor_trait_bounds_io_uring");
    }

    /// Run a common compliance check against any Reactor implementation.
    /// Verifies: starts empty, registration_count, is_empty, wake succeeds.
    fn compliance_check_empty_state(reactor: &dyn Reactor, name: &str) {
        crate::assert_with_log!(
            reactor.is_empty(),
            &format!("{name} starts empty"),
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            &format!("{name} starts with zero registrations"),
            0usize,
            reactor.registration_count()
        );
    }

    fn compliance_check_wake(reactor: &dyn Reactor, name: &str) {
        let result = reactor.wake();
        crate::assert_with_log!(
            result.is_ok(),
            &format!("{name} wake succeeds"),
            true,
            result.is_ok()
        );
    }

    fn compliance_check_poll_nonblocking(reactor: &dyn Reactor, name: &str) {
        let mut events = Events::with_capacity(16);
        let result = reactor.poll(&mut events, Some(std::time::Duration::ZERO));
        crate::assert_with_log!(
            result.is_ok(),
            &format!("{name} non-blocking poll succeeds"),
            true,
            result.is_ok()
        );
        crate::assert_with_log!(
            events.is_empty(),
            &format!("{name} no events on empty reactor"),
            true,
            events.is_empty()
        );
    }

    fn compliance_check_deregister_unknown(reactor: &dyn Reactor, name: &str) {
        let result = reactor.deregister(Token::new(99999));
        crate::assert_with_log!(
            result.is_err(),
            &format!("{name} deregister unknown token fails"),
            true,
            result.is_err()
        );
        let kind = result.expect_err("checked above").kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            &format!("{name} deregister unknown token reports NotFound"),
            io::ErrorKind::NotFound,
            kind
        );
    }

    fn compliance_check_modify_unknown(reactor: &dyn Reactor, name: &str) {
        let result = reactor.modify(Token::new(99999), Interest::READABLE);
        crate::assert_with_log!(
            result.is_err(),
            &format!("{name} modify unknown token fails"),
            true,
            result.is_err()
        );
        let kind = result.expect_err("checked above").kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            &format!("{name} modify unknown token reports NotFound"),
            io::ErrorKind::NotFound,
            kind
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cross_reactor_compliance_epoll() {
        init_test("cross_reactor_compliance_epoll");
        let reactor = super::EpollReactor::new().expect("failed to create epoll reactor");
        let name = "EpollReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_epoll");
    }

    #[test]
    fn cross_reactor_compliance_lab() {
        init_test("cross_reactor_compliance_lab");
        let reactor = super::LabReactor::new();
        let name = "LabReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_lab");
    }

    #[test]
    fn cross_reactor_compliance_browser() {
        init_test("cross_reactor_compliance_browser");
        let reactor = super::BrowserReactor::default();
        let name = "BrowserReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_browser");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cross_reactor_compliance_io_uring() {
        init_test("cross_reactor_compliance_io_uring");
        let reactor = match super::IoUringReactor::new() {
            Ok(r) => r,
            Err(e) => {
                // io_uring may not be available on older kernels
                eprintln!("Skipping io_uring compliance test: {e}");
                return;
            }
        };
        let name = "IoUringReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_io_uring");
    }

    /// Verify that Reactor trait objects work correctly (dyn dispatch).
    #[test]
    fn reactor_as_trait_object() {
        init_test("reactor_as_trait_object");
        let lab = super::LabReactor::new();
        let reactor: &dyn Reactor = &lab;

        crate::assert_with_log!(
            reactor.is_empty(),
            "trait object is_empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "trait object registration_count",
            0usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            reactor.wake().is_ok(),
            "trait object wake",
            true,
            reactor.wake().is_ok()
        );

        crate::test_complete!("reactor_as_trait_object");
    }

    /// Verify that Arc<Reactor> works for shared reactor access.
    #[test]
    fn reactor_arc_shared_access() {
        init_test("reactor_arc_shared_access");
        let reactor = std::sync::Arc::new(super::LabReactor::new());
        let reactor_clone = std::sync::Arc::clone(&reactor);

        crate::assert_with_log!(
            reactor.is_empty(),
            "arc reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor_clone.is_empty(),
            "arc clone reactor empty",
            true,
            reactor_clone.is_empty()
        );

        // Wake from clone
        crate::assert_with_log!(
            reactor_clone.wake().is_ok(),
            "wake from arc clone",
            true,
            reactor_clone.wake().is_ok()
        );

        crate::test_complete!("reactor_arc_shared_access");
    }

    #[test]
    fn token_debug_clone_copy_hash_ord_eq() {
        use std::collections::HashSet;
        let t = Token::new(42);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("42"), "{dbg}");
        let copied: Token = t;
        let cloned = t;
        assert_eq!(copied, cloned);
        assert!(Token::new(1) < Token::new(2));

        let mut set = HashSet::new();
        set.insert(Token::new(1));
        set.insert(Token::new(2));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn event_debug_clone_copy_eq() {
        let e = Event::new(Token::new(1), Interest::READABLE);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Event"), "{dbg}");
        let copied: Event = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        assert_ne!(e, Event::new(Token::new(2), Interest::WRITABLE));
    }
