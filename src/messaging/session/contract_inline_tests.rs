    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    #[test]
    fn request_reply_contract_validates_and_roundtrips() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut contract = ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.evidence_checkpoints.push(EvidenceCheckpoint::new(
            "request-enqueued",
            path(&["send:get_user"]),
        ));
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract.compensation_paths.push(CompensationPath::new(
            "cancel-request",
            path(&["send:get_user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));
        contract.cutoff_paths.push(CutoffPath::new(
            "reply-cutoff",
            path(&["send:get_user", "receive:user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));

        contract.validate().unwrap();

        let json = serde_json::to_string(&contract).unwrap();
        let decoded: ProtocolContract = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, contract);
    }

    #[test]
    fn streaming_protocol_with_choice_and_recursion_validates() {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        let contract = ProtocolContract {
            name: "streaming".to_owned(),
            version: SchemaVersion::new(1, 1, 0),
            roles: vec![producer, consumer.clone()],
            global_type: GlobalSessionType::new(SessionType::send(
                open,
                SessionType::recurse_point(
                    "stream_loop",
                    SessionType::choice(
                        consumer,
                        vec![
                            SessionBranch::new(
                                "chunk",
                                SessionType::receive(chunk, SessionType::recurse("stream_loop")),
                            ),
                            SessionBranch::new(
                                "done",
                                SessionType::receive(close, SessionType::End),
                            ),
                        ],
                    ),
                ),
            )),
            evidence_checkpoints: vec![EvidenceCheckpoint::new(
                "chunk-ack",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
            )],
            timeout_law: TimeoutLaw {
                default_timeout: Some(Duration::from_secs(10)),
                per_step: vec![TimeoutOverride::new(
                    path(&[
                        "send:open_stream",
                        "recurse-point:stream_loop",
                        "choice:consumer:done",
                        "receive:close",
                    ]),
                    Duration::from_secs(1),
                )],
            },
            compensation_paths: vec![CompensationPath::new(
                "rollback-stream",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
                vec![path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                    "end",
                ])],
            )],
            cutoff_paths: vec![CutoffPath::new(
                "graceful-stop",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                ]),
                vec![path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                    "end",
                ])],
            )],
        };

        contract.validate().unwrap();
    }

    #[test]
    fn reservation_handoff_protocol_with_branch_validates() {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");
        let handoff = MessageType::new("handoff", caller.clone(), steward.clone(), "Delegate");

        let contract = ProtocolContract::new(
            "reservation_handoff",
            SchemaVersion::new(1, 0, 1),
            vec![caller, steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        SessionBranch::new(
                            "granted",
                            SessionType::receive(
                                granted,
                                SessionType::send(handoff, SessionType::End),
                            ),
                        ),
                        SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        );

        contract.validate().unwrap();
    }

    #[test]
    fn undefined_recursion_label_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");

        let contract = ProtocolContract::new(
            "bad_loop",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::recurse("missing_loop"),
            )),
        );

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UndefinedRecursionLabel {
                path: path(&["send:request"]),
                label: Label::from("missing_loop"),
            })
        );
    }

    #[test]
    fn unknown_evidence_path_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "bad_evidence",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract
            .evidence_checkpoints
            .push(EvidenceCheckpoint::new("missing", path(&["send:nope"])));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownEvidencePath {
                name: "missing".to_owned(),
                path: path(&["send:nope"]),
            })
        );
    }

    #[test]
    fn root_evidence_path_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_evidence",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract
            .evidence_checkpoints
            .push(EvidenceCheckpoint::new("root", SessionPath::root()));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownEvidencePath {
                name: "root".to_owned(),
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn root_timeout_override_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_timeout",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            SessionPath::root(),
            Duration::from_secs(1),
        ));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownTimeoutPath {
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn root_compensation_trigger_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_compensation",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.compensation_paths.push(CompensationPath::new(
            "rollback",
            SessionPath::root(),
            vec![path(&["send:request", "receive:response", "end"])],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::UnknownCompensationTrigger {
                    name: "rollback".to_owned(),
                    path: SessionPath::root(),
                }
            )
        );
    }

    #[test]
    fn root_cutoff_step_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_cutoff",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.cutoff_paths.push(CutoffPath::new(
            "graceful",
            path(&["send:request"]),
            vec![SessionPath::root()],
        ));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownCutoffStep {
                name: "graceful".to_owned(),
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn compensation_path_must_progress_forward() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "unordered_compensation",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.compensation_paths.push(CompensationPath::new(
            "rollback",
            path(&["send:request"]),
            vec![
                path(&["send:request", "receive:response", "end"]),
                path(&["send:request", "receive:response"]),
            ],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::InvalidCompensationSequenceOrder {
                    name: "rollback".to_owned(),
                    previous: path(&["send:request", "receive:response", "end"]),
                    path: path(&["send:request", "receive:response"]),
                }
            )
        );
    }

    #[test]
    fn cutoff_path_must_progress_forward() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "unordered_cutoff",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.cutoff_paths.push(CutoffPath::new(
            "graceful",
            path(&["send:request"]),
            vec![
                path(&["send:request", "receive:response", "end"]),
                path(&["send:request", "receive:response"]),
            ],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::InvalidCutoffSequenceOrder {
                    name: "graceful".to_owned(),
                    previous: path(&["send:request", "receive:response", "end"]),
                    path: path(&["send:request", "receive:response"]),
                }
            )
        );
    }
