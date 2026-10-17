    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use franken_kernel::SchemaVersion;

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

    fn streaming_contract() -> ProtocolContract {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        ProtocolContract::new(
            "streaming",
            SchemaVersion::new(1, 1, 0),
            vec![producer, consumer.clone()],
            GlobalSessionType::new(SessionType::send(
                open,
                SessionType::recurse_point(
                    "stream_loop",
                    SessionType::choice(
                        consumer,
                        vec![
                            super::super::contract::SessionBranch::new(
                                "chunk",
                                SessionType::receive(chunk, SessionType::recurse("stream_loop")),
                            ),
                            super::super::contract::SessionBranch::new(
                                "done",
                                SessionType::receive(close, SessionType::End),
                            ),
                        ],
                    ),
                ),
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

    #[test]
    fn request_reply_projection_is_dual() {
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");

        let client_local = project_contract(&contract, &client).expect("client projection");
        let server_local = project_contract(&contract, &server).expect("server projection");

        assert!(matches!(client_local, LocalSessionType::Send { .. }));
        assert!(matches!(server_local, LocalSessionType::Receive { .. }));
        assert!(is_dual(&client_local, &server_local));
    }

    #[test]
    fn choice_projection_maps_decider_to_choice_and_peer_to_branch() {
        let contract = streaming_contract();
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");

        let producer_local = project_contract(&contract, &producer).expect("producer projection");
        let consumer_local = project_contract(&contract, &consumer).expect("consumer projection");

        assert!(is_dual(&producer_local, &consumer_local));

        let LocalSessionType::Send { next, .. } = producer_local else {
            panic!("producer should send the opening frame");
        };
        let LocalSessionType::RecursePoint { body, .. } = *next else {
            panic!("producer should enter the projected recursion point");
        };
        assert!(matches!(*body, LocalSessionType::Branch { .. }));

        let LocalSessionType::Receive { next, .. } = consumer_local else {
            panic!("consumer should receive the opening frame");
        };
        let LocalSessionType::RecursePoint { body, .. } = *next else {
            panic!("consumer should enter the projected recursion point");
        };
        assert!(matches!(*body, LocalSessionType::Choice { .. }));
    }

    #[test]
    fn branch_projection_maps_controller_to_choice_and_peer_to_branch() {
        let contract = reservation_handoff_contract();
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");

        let caller_local = project_contract(&contract, &caller).expect("caller projection");
        let steward_local = project_contract(&contract, &steward).expect("steward projection");

        assert!(is_dual(&caller_local, &steward_local));

        let LocalSessionType::Send { next, .. } = caller_local else {
            panic!("caller should send the reservation");
        };
        assert!(matches!(*next, LocalSessionType::Branch { .. }));

        let LocalSessionType::Receive { next, .. } = steward_local else {
            panic!("steward should receive the reservation");
        };
        assert!(matches!(*next, LocalSessionType::Choice { .. }));
    }

    #[test]
    fn projection_rejects_unknown_role() {
        let contract = request_reply_contract();
        let err = project_contract(&contract, &RoleName::from("outsider")).unwrap_err();
        assert_eq!(
            err,
            ProjectionError::UnknownRole(RoleName::from("outsider"))
        );
    }

    #[test]
    fn projection_rejects_invalid_role_count() {
        let contract = ProtocolContract::new(
            "bad_roles",
            SchemaVersion::new(1, 0, 0),
            vec![RoleName::from("client")],
            GlobalSessionType::new(SessionType::send(
                MessageType::new("ping", "client", "server", "Ping"),
                SessionType::End,
            )),
        );

        let err = project(
            &contract.global_type,
            &contract.roles,
            &RoleName::from("client"),
        )
        .unwrap_err();
        assert_eq!(err, ProjectionError::UnsupportedRoleCount { actual: 1 });
    }

    #[test]
    fn duality_rejects_mismatched_branch_labels() {
        let left =
            LocalSessionType::choice(vec![LocalSessionBranch::new("ok", LocalSessionType::End)]);
        let right =
            LocalSessionType::branch(vec![LocalSessionBranch::new("nope", LocalSessionType::End)]);

        assert!(!is_dual(&left, &right));
    }

    #[test]
    fn project_pair_returns_dual_locals() {
        let contract = request_reply_contract();
        let (left, right) = project_pair(&contract).expect("project pair");
        assert!(is_dual(&left, &right));
    }
