    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::contract::TimeoutOverride;
    use super::*;
    use crate::trace::{TraceBufferHandle, TraceData, TraceEventKind};
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use franken_kernel::SchemaVersion;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn path(segments: &[&str]) -> SessionPath {
        let mut path = SessionPath::root();
        for segment in segments {
            path = path.child(*segment);
        }
        path
    }

    fn test_cx_with_trace() -> (Cx, TraceBufferHandle) {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 1)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        );
        let trace = TraceBufferHandle::new(32);
        cx.set_trace_buffer(trace.clone());
        (cx, trace)
    }

    fn request_reply_contract() -> ProtocolContract {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        )
    }

    fn reservation_handoff_contract() -> ProtocolContract {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");
        let handoff = MessageType::new("handoff", caller.clone(), steward.clone(), "Delegate");

        ProtocolContract::new(
            "reservation_handoff",
            SchemaVersion::new(1, 0, 1),
            vec![caller, steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        super::super::contract::SessionBranch::new(
                            "granted",
                            SessionType::receive(
                                granted,
                                SessionType::send(handoff, SessionType::End),
                            ),
                        ),
                        super::super::contract::SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        )
    }

    fn compensating_request_reply_contract() -> ProtocolContract {
        let mut contract = request_reply_contract();
        contract.timeout_law.default_timeout = Some(Duration::from_secs(1));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract
            .compensation_paths
            .push(super::super::contract::CompensationPath::new(
                "rollback-request",
                path(&["send:get_user"]),
                vec![path(&["send:get_user", "receive:user", "end"])],
            ));
        contract
    }

    #[test]
    fn valid_trace_is_accepted_and_roles_complete() {
        init_test("valid_trace_is_accepted_and_roles_complete");
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        let request_send = monitor
            .observe(&client, Some(&request), None)
            .expect("client send request");
        assert_eq!(request_send.path, path(&["send:get_user"]));
        assert_eq!(
            request_send.expectation,
            ConformanceExpectation::Send {
                message: request.clone()
            }
        );

        monitor
            .observe(&server, Some(&request), None)
            .expect("server receive request");
        monitor
            .observe(&server, Some(&response), None)
            .expect("server send response");
        monitor
            .observe(&client, Some(&response), None)
            .expect("client receive response");

        assert!(monitor.is_role_complete(&client));
        assert!(monitor.is_role_complete(&server));
        assert!(monitor.is_complete());
        assert_eq!(monitor.history().len(), 4);

        crate::test_complete!("valid_trace_is_accepted_and_roles_complete");
    }

    #[test]
    fn invalid_branch_is_rejected_with_candidate_paths() {
        init_test("invalid_branch_is_rejected_with_candidate_paths");
        let contract = reservation_handoff_contract();
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");

        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        monitor
            .observe(&caller, Some(&reserve), None)
            .expect("caller send reserve");
        monitor
            .observe(&steward, Some(&reserve), None)
            .expect("steward receive reserve");

        let err = monitor
            .observe(&caller, None, Some(&Label::from("queued")))
            .expect_err("unexpected label should fail");
        assert!(
            matches!(
                err.as_ref(),
                ConformanceViolation::UnexpectedObservation { .. }
            ),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::UnexpectedObservation {
            expected, evidence, ..
        } = err.as_ref()
        {
            assert_eq!(
                expected,
                &ConformanceExpectation::ObserveBranch {
                    labels: vec![Label::from("granted"), Label::from("denied")],
                }
            );
            assert_eq!(
                evidence.candidate_paths,
                vec![
                    path(&["send:reserve", "branch:steward:granted"]),
                    path(&["send:reserve", "branch:steward:denied"]),
                ]
            );
        }

        crate::test_complete!("invalid_branch_is_rejected_with_candidate_paths");
    }

    #[test]
    fn timeout_is_detected_from_timeout_law() {
        init_test("timeout_is_detected_from_timeout_law");
        let contract = compensating_request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");

        let mut monitor = ConformanceMonitor::new_at(&contract, Time::ZERO).expect("monitor");
        monitor
            .observe_at(&client, Some(&request), None, Time::ZERO)
            .expect("client request");

        let err = monitor
            .check_timeout(Time::from_secs(2))
            .expect_err("server receive should time out after 1s default");
        assert!(
            matches!(err.as_ref(), ConformanceViolation::Timeout { .. }),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::Timeout {
            role,
            expected,
            evidence,
            ..
        } = err.as_ref()
        {
            assert_eq!(role, &server);
            assert_eq!(
                expected,
                &ConformanceExpectation::Receive { message: request }
            );
            assert_eq!(evidence.path, Some(path(&["send:get_user"])));
            assert_eq!(evidence.timeout, Some(Duration::from_secs(1)));
        }

        crate::test_complete!("timeout_is_detected_from_timeout_law");
    }

    #[test]
    fn compensation_paths_are_emitted_in_violation_evidence() {
        init_test("compensation_paths_are_emitted_in_violation_evidence");
        let contract = compensating_request_reply_contract();
        let monitor = ConformanceMonitor::new(&contract).expect("monitor");

        let err = monitor
            .check_timeout(Time::from_secs(2))
            .expect_err("initial send should time out");
        assert!(
            matches!(err.as_ref(), ConformanceViolation::Timeout { .. }),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::Timeout { evidence, .. } = err.as_ref() {
            assert_eq!(evidence.path, Some(path(&["send:get_user"])));
            assert!(
                evidence
                    .compensation_paths
                    .iter()
                    .any(|branch| branch.name == "rollback-request"),
                "expected rollback-request compensation in evidence"
            );
        }

        crate::test_complete!("compensation_paths_are_emitted_in_violation_evidence");
    }

    #[test]
    fn lab_runtime_oracle_reports_timeout() {
        init_test("lab_runtime_oracle_reports_timeout");
        let contract = compensating_request_reply_contract();
        let mut runtime = LabRuntime::with_seed(7);
        let mut oracle = ConformanceOracle::new_at(&contract, runtime.now()).expect("oracle");

        runtime.advance_time(1_500_000_000);
        let err = oracle
            .check_lab(&runtime)
            .expect_err("oracle should report timeout");
        assert!(matches!(err.as_ref(), ConformanceViolation::Timeout { .. }));
        assert_eq!(oracle.violations().len(), 1);

        crate::test_complete!("lab_runtime_oracle_reports_timeout");
    }

    #[test]
    fn observe_with_cx_logs_conformance_check_event() {
        init_test("observe_with_cx_logs_conformance_check_event");
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server, "GetUser");

        let (cx, trace) = test_cx_with_trace();
        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        monitor
            .observe_with_cx(&cx, &client, Some(&request), None)
            .expect("logged check");

        let saw_conformance_event = trace.snapshot().iter().any(|event| {
            event.kind == TraceEventKind::UserTrace
                && matches!(&event.data, TraceData::Message(message) if message == "conformance_check")
        });
        assert!(
            saw_conformance_event,
            "expected conformance_check trace event"
        );

        crate::test_complete!("observe_with_cx_logs_conformance_check_event");
    }

    #[test]
    fn degenerate_recurse_to_self_does_not_loop() {
        init_test("degenerate_recurse_to_self_does_not_loop");
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        // Build a contract whose body is RecursePoint("L", Recurse("L"))
        // — a degenerate empty loop.  This passes validation but previously
        // caused normalize() to spin forever.
        let request = MessageType::new("ping", client.clone(), server.clone(), "Ping");
        let contract = ProtocolContract::new(
            "degenerate",
            SchemaVersion::new(0, 0, 1),
            vec![client.clone(), server],
            GlobalSessionType::new(SessionType::send(
                request.clone(),
                SessionType::recurse_point("L", SessionType::recurse("L")),
            )),
        );
        // Construction must not hang.
        let monitor = ConformanceMonitor::new(&contract).expect("monitor should not loop");
        // After the first send, both roles should reach a synthetic End
        // because the degenerate recursion is treated as completion.
        let mut monitor = monitor;
        monitor
            .observe(&client, Some(&request), None)
            .expect("client send");
        assert!(
            monitor.is_role_complete(&client),
            "client should be complete after degenerate recursion resolves to End"
        );
        crate::test_complete!("degenerate_recurse_to_self_does_not_loop");
    }
