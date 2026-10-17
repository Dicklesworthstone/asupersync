    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::contract::{GlobalSessionType, SessionBranch};
    use super::*;

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    fn request_reply_contract() -> ProtocolContract {
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
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract
            .evidence_checkpoints
            .push(super::super::contract::EvidenceCheckpoint::new(
                "request-enqueued",
                path(&["send:get_user"]),
            ));
        contract
    }

    fn streaming_contract() -> ProtocolContract {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        ProtocolContract {
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
            evidence_checkpoints: vec![super::super::contract::EvidenceCheckpoint::new(
                "chunk-ack",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
            )],
            timeout_law: super::super::contract::TimeoutLaw {
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
        }
    }

    fn reservation_handoff_contract(version: SchemaVersion) -> ProtocolContract {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");

        ProtocolContract::new(
            "reservation_handoff",
            version,
            vec![caller, steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        SessionBranch::new(
                            "granted",
                            SessionType::receive(granted, SessionType::End),
                        ),
                        SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        )
    }

    #[test]
    fn synthesizes_request_reply_handler_scaffolds() {
        let contract = request_reply_contract();
        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let client = RoleName::from("client");
        let server = RoleName::from("server");

        assert_eq!(scaffold.obligations.len(), 2);

        let client_handler = scaffold.handler_for(&client).expect("client handler");
        let request_path = path(&["send:get_user"]);
        let response_path = path(&["send:get_user", "receive:user"]);
        let request_step = client_handler.step(&request_path).expect("request step");
        let response_step = client_handler.step(&response_path).expect("response step");

        assert!(matches!(
            request_step.action,
            SynthesizedAction::Emit { .. }
        ));
        assert_eq!(
            request_step.register_obligations,
            vec!["transition:root/send:get_user".to_owned()]
        );
        assert_eq!(
            request_step.evidence_checkpoints,
            vec!["request-enqueued".to_owned()]
        );
        assert_eq!(request_step.error_branches.len(), 1);

        assert!(matches!(
            response_step.action,
            SynthesizedAction::Consume { .. }
        ));
        assert_eq!(
            response_step.complete_obligations,
            vec!["transition:root/send:get_user/receive:user".to_owned()]
        );
        assert_eq!(
            response_step.error_branches,
            vec![SynthesizedErrorBranch {
                name: "timeout:root/send:get_user/receive:user".to_owned(),
                kind: SynthesizedErrorBranchKind::Timeout {
                    timeout: Duration::from_secs(2),
                },
            }]
        );

        let server_handler = scaffold.handler_for(&server).expect("server handler");
        assert_eq!(
            server_handler
                .step(&request_path)
                .expect("server receive request")
                .complete_obligations,
            vec!["transition:root/send:get_user".to_owned()]
        );
        assert_eq!(
            server_handler
                .step(&response_path)
                .expect("server emit response")
                .register_obligations,
            vec!["transition:root/send:get_user/receive:user".to_owned()]
        );
    }

    #[test]
    fn synthesizes_streaming_protocol_with_error_branches() {
        let contract = streaming_contract();
        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let consumer = RoleName::from("consumer");
        let handler = scaffold.handler_for(&consumer).expect("consumer handler");
        let chunk_choice_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:chunk",
        ]);
        let chunk_receive_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:chunk",
            "receive:chunk",
        ]);
        let done_choice_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:done",
        ]);

        assert!(matches!(
            handler
                .step(&chunk_choice_path)
                .expect("chunk choice")
                .action,
            SynthesizedAction::ChooseBranch { .. }
        ));
        assert!(matches!(
            handler
                .step(&chunk_receive_path)
                .expect("chunk receive")
                .action,
            SynthesizedAction::Consume { .. }
        ));
        assert!(
            handler
                .step(&chunk_receive_path)
                .expect("chunk receive")
                .evidence_checkpoints
                .contains(&"chunk-ack".to_owned())
        );
        assert!(
            handler
                .step(&chunk_receive_path)
                .expect("chunk receive")
                .error_branches
                .iter()
                .any(|branch| matches!(
                    branch.kind,
                    SynthesizedErrorBranchKind::Compensation {
                        stage: RecoveryHookStage::Trigger,
                        ..
                    }
                ))
        );
        assert!(
            handler
                .step(&done_choice_path)
                .expect("done choice")
                .error_branches
                .iter()
                .any(|branch| matches!(
                    branch.kind,
                    SynthesizedErrorBranchKind::Cutoff {
                        stage: RecoveryHookStage::Trigger,
                        ..
                    }
                ))
        );
    }

    #[test]
    fn synthesizes_saga_compensation_hooks_from_recovery_paths() {
        let mut contract = request_reply_contract();
        contract.compensation_paths.push(CompensationPath::new(
            "rollback-request",
            path(&["send:get_user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));

        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let client_handler = scaffold
            .handler_for(&RoleName::from("client"))
            .expect("client handler");
        let request_step = client_handler
            .step(&path(&["send:get_user"]))
            .expect("request step");

        assert!(request_step.error_branches.iter().any(|branch| matches!(
            branch.kind,
            SynthesizedErrorBranchKind::Compensation {
                stage: RecoveryHookStage::Trigger,
                ..
            }
        )));
    }

    #[test]
    fn evolved_protocol_adapter_accepts_added_branch_and_metadata() {
        let previous = reservation_handoff_contract(SchemaVersion::new(1, 0, 0));
        let mut next = reservation_handoff_contract(SchemaVersion::new(1, 1, 0));
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let queued = MessageType::new("queued", steward.clone(), caller, "Queued");

        if let SessionType::Send { next, .. } = &mut next.global_type.root
            && let SessionType::Branch { branches, .. } = next.as_mut()
        {
            branches.push(SessionBranch::new(
                "queued",
                SessionType::receive(queued, SessionType::End),
            ));
        }
        next.evidence_checkpoints
            .push(super::super::contract::EvidenceCheckpoint::new(
                "reserve-sent",
                path(&["send:reserve"]),
            ));

        let adapter = adapt_protocol_evolution(&previous, &next).expect("compatible");

        assert_eq!(adapter.contract_name, "reservation_handoff");
        assert_eq!(
            adapter.added_branches,
            vec![AddedBranchPath {
                parent: path(&["send:reserve"]),
                controller: steward,
                label: Label::from("queued"),
            }]
        );
        assert_eq!(
            adapter.added_evidence_checkpoints,
            vec!["reserve-sent".to_owned()]
        );
    }
