    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationAbortReason;
    use crate::util::ArenaIndex;
    use franken_kernel::SchemaVersion;

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    fn task_id(slot: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(slot, 0))
    }

    fn region_id(slot: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(slot, 0))
    }

    fn request_reply_contract() -> ProtocolContract {
        let client = super::super::contract::RoleName::from("client");
        let server = super::super::contract::RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut contract = ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            super::super::contract::GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract
            .timeout_law
            .per_step
            .push(super::super::contract::TimeoutOverride::new(
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
        contract
    }

    fn streaming_contract() -> ProtocolContract {
        let producer = super::super::contract::RoleName::from("producer");
        let consumer = super::super::contract::RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", consumer.clone(), producer.clone(), "Chunk");
        let close = MessageType::new("close", consumer.clone(), producer.clone(), "Close");

        ProtocolContract {
            name: "streaming".to_owned(),
            version: SchemaVersion::new(1, 1, 0),
            roles: vec![producer, consumer.clone()],
            global_type: super::super::contract::GlobalSessionType::new(SessionType::send(
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
            evidence_checkpoints: Vec::new(),
            timeout_law: super::super::contract::TimeoutLaw {
                default_timeout: Some(Duration::from_secs(10)),
                per_step: vec![super::super::contract::TimeoutOverride::new(
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

    #[test]
    fn derives_request_reply_timeout_and_recovery_obligations() {
        let derived = DerivedObligations::from_contract(&request_reply_contract())
            .expect("request/reply contract should derive");

        assert_eq!(derived.contract_name, "user_lookup");
        assert_eq!(derived.obligations.len(), 5);

        let reply = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Reply)
            .expect("reply obligation should exist");
        assert_eq!(reply.ledger_kind(), ObligationKind::Ack);
        assert_eq!(reply.trigger, path(&["send:get_user"]));
        assert_eq!(reply.steps, vec![path(&["send:get_user", "receive:user"])]);
        assert_eq!(
            reply
                .message
                .as_ref()
                .expect("reply obligation keeps message")
                .name,
            "get_user"
        );

        let send_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger == path(&["send:get_user"])
            })
            .expect("default send timeout should exist");
        assert_eq!(send_timeout.timeout, Some(Duration::from_secs(5)));
        assert_eq!(send_timeout.ledger_kind(), ObligationKind::Lease);

        let receive_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger == path(&["send:get_user", "receive:user"])
            })
            .expect("receive override should exist");
        assert_eq!(receive_timeout.timeout, Some(Duration::from_secs(2)));

        let compensation = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Compensation)
            .expect("compensation obligation should exist");
        assert_eq!(compensation.ledger_kind(), ObligationKind::SendPermit);
        assert_eq!(compensation.trigger, path(&["send:get_user"]));
        assert_eq!(
            compensation.steps,
            vec![path(&["send:get_user", "receive:user", "end"])]
        );

        let cutoff = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Cutoff)
            .expect("cutoff obligation should exist");
        assert_eq!(cutoff.ledger_kind(), ObligationKind::SendPermit);
        assert_eq!(cutoff.trigger, path(&["send:get_user", "receive:user"]));
    }

    #[test]
    fn derives_streaming_reply_targets_and_saga_paths() {
        let derived = DerivedObligations::from_contract(&streaming_contract())
            .expect("streaming contract should derive");

        let reply = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Reply
                    && obligation.trigger == path(&["send:open_stream"])
            })
            .expect("open_stream should derive a reply obligation");
        assert_eq!(
            reply.steps,
            vec![
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                ]),
            ]
        );

        let receive_close_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger
                        == path(&[
                            "send:open_stream",
                            "recurse-point:stream_loop",
                            "choice:consumer:done",
                            "receive:close",
                        ])
            })
            .expect("receive:close timeout should exist");
        assert_eq!(receive_close_timeout.timeout, Some(Duration::from_secs(1)));

        let compensation = derived
            .obligations
            .iter()
            .find(|obligation| obligation.name.starts_with("compensation:rollback-stream@"))
            .expect("stream compensation should exist");
        assert_eq!(
            compensation.trigger,
            path(&[
                "send:open_stream",
                "recurse-point:stream_loop",
                "choice:consumer:chunk",
                "receive:chunk",
            ])
        );

        let cutoff = derived
            .obligations
            .iter()
            .find(|obligation| obligation.name.starts_with("cutoff:graceful-stop@"))
            .expect("stream cutoff should exist");
        assert_eq!(
            cutoff.steps,
            vec![path(&[
                "send:open_stream",
                "recurse-point:stream_loop",
                "choice:consumer:done",
                "receive:close",
                "end",
            ])]
        );
    }

    #[test]
    fn derived_obligations_reserve_cleanly_in_runtime_ledger() {
        let derived = DerivedObligations::from_contract(&request_reply_contract())
            .expect("request/reply contract should derive");

        let mut ledger = ObligationLedger::new();
        let tokens = derived.reserve_all_in_ledger(
            &mut ledger,
            task_id(1),
            region_id(7),
            Time::from_nanos(0),
        );

        assert_eq!(tokens.len(), derived.obligations.len());
        assert_eq!(ledger.stats().pending, derived.obligations.len() as u64);
        assert!(
            tokens
                .iter()
                .zip(&derived.obligations)
                .all(|(token, obligation)| token.kind() == obligation.ledger_kind())
        );

        for (index, token) in tokens.into_iter().enumerate() {
            ledger.abort(
                token,
                Time::from_nanos((index + 1) as u64),
                ObligationAbortReason::Explicit,
            );
        }

        assert_eq!(ledger.stats().pending, 0);
        assert_eq!(
            ledger.stats().total_aborted,
            derived.obligations.len() as u64
        );
    }

    #[test]
    fn description_includes_message_timeout_and_steps() {
        let obligation = DerivedObligation {
            name: "reply:get_user@send:get_user".to_owned(),
            class: DerivedObligationClass::Reply,
            trigger: path(&["send:get_user"]),
            steps: vec![
                path(&["send:get_user", "receive:user"]),
                path(&["send:get_user", "receive:user", "end"]),
            ],
            timeout: Some(Duration::from_millis(1500)),
            message: Some(MessageType::new(
                "get_user",
                super::super::contract::RoleName::from("client"),
                super::super::contract::RoleName::from("server"),
                "GetUser",
            )),
        };

        let description = obligation.description();
        assert!(description.starts_with("reply obligation triggered at "));
        assert!(description.contains("for client->server:get_user"));
        assert!(description.contains("with timeout=1500ms"));
        assert!(description.contains("steps=["));
        assert!(description.contains("receive:user"));
        assert!(description.contains("end"));
    }
