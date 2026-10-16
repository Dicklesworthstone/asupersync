    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;

    // -- SendPermit protocol --

    #[test]
    fn send_permit_commit_path() {
        let (sender, receiver) = send_permit::new_session::<String>(1);

        // Sender: Reserve → Send → End.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left(); // choose Send
        let sender = sender.send("hello".to_string());
        let proof = sender.close();
        assert_eq!(proof.channel_id, 1);
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Receiver: Reserve → offer → recv → End.
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (msg, ch) = ch.recv("hello".to_string());
                assert_eq!(msg, "hello");
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Left branch"),
        }
    }

    #[test]
    fn send_permit_abort_path() {
        let (sender, receiver) = send_permit::new_session::<String>(2);

        // Sender: Reserve → Abort → End.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_right(); // choose Abort
        let sender = sender.send(send_permit::AbortMsg);
        let proof = sender.close();
        assert_eq!(proof.channel_id, 2);

        // Receiver: Reserve → offer → Abort → End.
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(send_permit::AbortMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Right branch"),
        }
    }

    // -- Two-phase commit protocol --

    #[test]
    fn two_phase_commit_path() {
        let (initiator, executor) = two_phase::new_session(3, ObligationKind::SendPermit);

        // Initiator: Reserve → Commit → End.
        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::SendPermit,
        };
        let initiator = initiator.send(reserve_msg.clone());
        let initiator = initiator.select_left(); // Commit
        let initiator = initiator.send(two_phase::CommitMsg);
        let proof = initiator.close();
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Executor: Reserve → offer → Commit → End.
        let (msg, executor) = executor.recv(reserve_msg);
        assert_eq!(msg.kind, ObligationKind::SendPermit);
        match executor.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(two_phase::CommitMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Commit"),
        }
    }

    #[test]
    fn two_phase_abort_path() {
        let (initiator, executor) = two_phase::new_session(4, ObligationKind::Lease);

        // Initiator: Reserve → Abort → End.
        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::Lease,
        };
        let initiator = initiator.send(reserve_msg.clone());
        let initiator = initiator.select_right(); // Abort
        let abort_msg = two_phase::AbortMsg {
            reason: "timeout".to_string(),
        };
        let initiator = initiator.send(abort_msg);
        let proof = initiator.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Executor side.
        let (_, executor) = executor.recv(reserve_msg);
        match executor.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (msg, ch) = ch.recv(two_phase::AbortMsg {
                    reason: "timeout".to_string(),
                });
                assert_eq!(msg.reason, "timeout");
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Abort"),
        }
    }

    // -- Lease protocol --

    #[test]
    fn lease_acquire_and_release() {
        let (holder, resource) = lease::new_session(5);

        // Holder: Acquire → Release → End.
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_right(); // Release
        let holder = holder.send(lease::ReleaseMsg);
        let proof = holder.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Resource: Acquire → offer → Release → End.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    #[test]
    fn lease_acquire_renew_release() {
        let (holder, resource) = lease::new_session(6);

        // Holder: Acquire → Renew → (new loop) → Release → End.
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_left(); // Renew
        let holder = holder.send(lease::RenewMsg);
        let _proof_renew = holder.close();

        // After renew, create a new loop iteration.
        let (holder2, resource2) = lease::renew_loop(6);
        let holder2 = holder2.select_right(); // Release
        let holder2 = holder2.send(lease::ReleaseMsg);
        let proof = holder2.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Resource side: Acquire → Renew.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew"),
        }

        // Resource loop 2: Release.
        match resource2.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    #[test]
    fn session_protocol_adoption_specs_cover_priority_families() {
        let specs = session_protocol_adoption_specs();
        let ids = specs
            .iter()
            .map(|spec| spec.protocol_id)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["send_permit", "lease", "two_phase"]);
        assert!(
            specs.iter().all(|spec| !spec.typed_entrypoint.is_empty()),
            "typed entrypoints must be explicit"
        );
        assert!(
            specs.iter().all(|spec| !spec.dynamic_surface.is_empty()),
            "dynamic coexistence surfaces must be explicit"
        );
    }

    #[test]
    fn session_protocol_adoption_specs_document_oracles_and_migration_surfaces() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                !spec.runtime_oracles.is_empty(),
                "runtime oracles must remain explicit for {}",
                spec.protocol_id
            );
            assert!(
                spec.runtime_oracles
                    .iter()
                    .all(|surface| surface.starts_with("src/")),
                "runtime oracles must point at concrete source files for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces.len() >= 2,
                "migration surfaces must include existing and planned coverage for {}",
                spec.protocol_id
            );
            assert!(
                !spec.initial_rollout_scope.is_empty(),
                "initial rollout scope must be documented for {}",
                spec.protocol_id
            );
            assert!(
                !spec.avoid_for_now.is_empty(),
                "deferred surfaces must be documented for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .iter()
                    .all(|surface| !surface.contains("planned")),
                "migration surfaces must point at concrete live paths for {}",
                spec.protocol_id
            );
        }
    }

    #[test]
    fn session_protocol_adoption_specs_keep_diagnostics_fields_stable() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                spec.diagnostics_fields.contains(&"channel_id"),
                "channel_id must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.diagnostics_fields.contains(&"trace_id"),
                "trace_id must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.diagnostics_fields.contains(&"protocol"),
                "protocol field must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.compile_time_constraints.len() >= 3,
                "compile-time guarantees must stay substantive for {}",
                spec.protocol_id
            );
            assert!(
                spec.transitions.len() >= 3,
                "state transitions must stay explicit for {}",
                spec.protocol_id
            );
        }
    }

    #[test]
    fn session_protocol_adoption_specs_reference_current_validation_surfaces() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                spec.migration_test_surfaces
                    .contains(&DOC_COMPILE_FAIL_SURFACE),
                "compile-fail doctest surface must stay wired for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .contains(&MIGRATION_INTEGRATION_SURFACE),
                "typed/dynamic migration surface must stay wired for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .contains(&MIGRATION_GUIDE_SURFACE),
                "migration guide surface must stay wired for {}",
                spec.protocol_id
            );
        }
    }

    // -- SessionProof --

    #[test]
    fn session_proof_fields() {
        let (sender, _receiver) = send_permit::new_session::<u32>(42);

        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(100_u32);
        let proof = sender.close();

        assert_eq!(proof.channel_id, 42);
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Prevent receiver drop bomb.
        _receiver.disarm_for_test();
    }

    // -- Drop bomb verification --

    #[test]
    #[should_panic(expected = "SESSION LEAKED")]
    fn drop_mid_protocol_panics() {
        let (sender, receiver) = send_permit::new_session::<u32>(99);

        // Disarm receiver first to avoid double-panic during unwinding.
        receiver.disarm_for_test();

        // Sender starts but doesn't finish — drop should panic.
        let sender = sender.send(send_permit::ReserveMsg);
        drop(sender); // PANIC: session leaked
    }

    // -- Chan transition preserves metadata --

    #[test]
    fn transition_preserves_channel_id() {
        let (sender, _receiver) = two_phase::new_session(77, ObligationKind::IoOp);
        assert_eq!(sender.channel_id(), 77);
        assert_eq!(sender.obligation_kind(), ObligationKind::IoOp);

        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::IoOp,
        };
        let sender = sender.send(reserve_msg);
        let sender = sender.select_left();
        let sender = sender.send(two_phase::CommitMsg);
        let proof = sender.close();
        assert_eq!(proof.channel_id, 77);

        _receiver.disarm_for_test();
    }

    // -- Duality invariant --

    /// Invariant: `new_session` produces dual endpoints sharing the same
    /// channel_id and obligation_kind.
    #[test]
    fn send_permit_dual_channels_share_identity() {
        let (sender, receiver) = send_permit::new_session::<u32>(100);

        let ids_match = sender.channel_id() == receiver.channel_id();
        assert!(ids_match, "channel_id must match across endpoints");

        let kinds_match = sender.obligation_kind() == receiver.obligation_kind();
        assert!(kinds_match, "obligation_kind must match across endpoints");

        assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);

        // Drive both to End to avoid drop bombs.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(42_u32);
        let _proof = sender.close();

        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(42_u32);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    // -- Delegation invariant --

    /// Invariant: delegation channel pair preserves metadata and both
    /// endpoints share the same channel_id and obligation_kind.
    #[test]
    fn delegation_pair_preserves_metadata() {
        use delegation::new_delegation;

        let (delegator_ch, delegatee_ch) = new_delegation::<Initiator, two_phase::InitiatorSession>(
            201,
            ObligationKind::SendPermit,
        );

        assert_eq!(delegator_ch.channel_id(), 201);
        assert_eq!(delegator_ch.obligation_kind(), ObligationKind::SendPermit);
        assert_eq!(delegatee_ch.channel_id(), 201);
        assert_eq!(delegatee_ch.obligation_kind(), ObligationKind::SendPermit);

        // Disarm drop bombs — delegation is typestate-only encoding; the
        // actual Chan<R,S> value cannot pass through send() without triggering
        // the inner drop bomb, so we verify metadata and type-level correctness.
        delegator_ch.disarm_for_test();
        delegatee_ch.disarm_for_test();
    }

    // -- Multi-renew lease invariant --

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn branch_debug_copy_eq() {
        let left = Branch::Left;
        let right = Branch::Right;

        let dbg = format!("{left:?}");
        assert!(dbg.contains("Left"));

        // Copy
        let left2 = left;
        assert_eq!(left, left2);

        // Inequality
        assert_ne!(left, right);

        // Clone
        let right2 = right;
        assert_eq!(right, right2);
    }

    #[test]
    fn session_proof_debug() {
        let proof = SessionProof {
            channel_id: 42,
            obligation_kind: ObligationKind::SendPermit,
        };
        let dbg = format!("{proof:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("SendPermit"));
    }

    #[test]
    fn two_phase_reserve_msg_debug_clone() {
        let msg = two_phase::ReserveMsg {
            kind: ObligationKind::Lease,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Lease"));

        let cloned = msg;
        assert_eq!(cloned.kind, ObligationKind::Lease);
    }

    #[test]
    fn two_phase_abort_msg_debug_clone() {
        let msg = two_phase::AbortMsg {
            reason: "budget_exhausted".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("budget_exhausted"));

        let cloned = msg;
        assert_eq!(cloned.reason, "budget_exhausted");
    }

    #[test]
    fn selected_left_variant() {
        let s: Selected<u32, &str> = Selected::Left(42);
        match s {
            Selected::Left(v) => assert_eq!(v, 42),
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    #[test]
    fn selected_right_variant() {
        let s: Selected<u32, &str> = Selected::Right("hello");
        match s {
            Selected::Right(v) => assert_eq!(v, "hello"),
            Selected::Left(_) => panic!("expected Right"),
        }
    }

    #[test]
    fn chan_accessors() {
        let (sender, receiver) = send_permit::new_session::<u32>(55);
        assert_eq!(sender.channel_id(), 55);
        assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);
        assert_eq!(receiver.channel_id(), 55);
        assert_eq!(receiver.obligation_kind(), ObligationKind::SendPermit);

        // Drive both to End
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(0_u32);
        let _ = sender.close();
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(0_u32);
                let _ = ch.close();
            }
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    #[test]
    fn lease_new_session_obligation_kind() {
        let (holder, resource) = lease::new_session(99);
        assert_eq!(holder.obligation_kind(), ObligationKind::Lease);
        assert_eq!(resource.obligation_kind(), ObligationKind::Lease);

        // Drive to End
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_right();
        let holder = holder.send(lease::ReleaseMsg);
        let _ = holder.close();

        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _ = ch.close();
            }
            Selected::Left(_) => panic!("expected Right"),
        }
    }

    /// Invariant: lease protocol supports multiple renew cycles before release,
    /// each creating a fresh loop iteration.
    #[test]
    fn lease_multiple_renew_cycles() {
        let (holder, resource) = lease::new_session(300);

        // Holder: Acquire.
        let holder = holder.send(lease::AcquireMsg);

        // First loop: choose Renew.
        let holder = holder.select_left();
        let holder = holder.send(lease::RenewMsg);
        let _proof1 = holder.close();

        // Resource side first loop.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew"),
        }

        // Second loop iteration.
        let (holder2, resource2) = lease::renew_loop(300);
        let holder2 = holder2.select_left(); // Renew again
        let holder2 = holder2.send(lease::RenewMsg);
        let _proof2 = holder2.close();

        match resource2.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew 2"),
        }

        // Third loop: finally Release.
        let (holder3, resource3) = lease::renew_loop(300);
        let holder3 = holder3.select_right(); // Release
        let holder3 = holder3.send(lease::ReleaseMsg);
        let proof = holder3.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        match resource3.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    // =================================================================
    // Transport-backed session tests (G2 — bead v2ofj7.7.2)
    // =================================================================

    #[test]
    fn transport_backed_send_permit_happy_path() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(100, ObligationKind::SendPermit, 4);

        assert!(sender.is_transport_backed());
        assert!(receiver.is_transport_backed());

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            // Initiator: Send ReserveMsg
            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();

            // Responder: Recv ReserveMsg
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            // Initiator: Select Send branch (left)
            let sender = sender.select_left_async(&cx).await.unwrap();

            // Responder: Offer and receive branch choice
            let receiver = match receiver.offer_async(&cx).await.unwrap() {
                Selected::Left(ch) => ch,
                Selected::Right(_) => panic!("expected Left (Send) branch"),
            };

            // Initiator: Send the payload
            let sender = sender.send_async(&cx, 42_u64).await.unwrap();

            // Responder: Recv the payload
            let (value, receiver) = receiver.recv_async(&cx).await.unwrap();
            assert_eq!(value, 42_u64);

            // Both sides close
            let proof_s = sender.close();
            let proof_r = receiver.close();
            assert_eq!(proof_s.channel_id, 100);
            assert_eq!(proof_r.channel_id, 100);
            assert_eq!(proof_s.obligation_kind, ObligationKind::SendPermit);
        });
    }

    #[test]
    fn transport_backed_send_permit_abort_path() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(200, ObligationKind::SendPermit, 4);

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            // Initiator: Select Abort branch (right)
            let sender = sender.select_right_async(&cx).await.unwrap();

            let receiver = match receiver.offer_async(&cx).await.unwrap() {
                Selected::Right(ch) => ch,
                Selected::Left(_) => panic!("expected Right (Abort) branch"),
            };

            let sender = sender.send_async(&cx, send_permit::AbortMsg).await.unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            let proof_s = sender.close();
            let proof_r = receiver.close();
            assert_eq!(proof_s.obligation_kind, ObligationKind::SendPermit);
            assert_eq!(proof_r.obligation_kind, ObligationKind::SendPermit);
        });
    }

    #[test]
    fn transport_backed_peer_drop_returns_closed() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(300, ObligationKind::SendPermit, 4);

        // Drop the receiver immediately
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let result = sender.send_async(&cx, send_permit::ReserveMsg).await;
            match result {
                Err(SessionError::Closed) => {} // expected
                Err(other) => panic!("expected Closed, got {other}"),
                Ok(ch) => {
                    ch.disarm_for_test();
                    panic!("expected error, got Ok");
                }
            }
        });
    }

    #[test]
    fn transport_backed_send_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(301, ObligationKind::SendPermit, 4);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed send cancelled",
            ));

            let result = sender.send_async(&cx, send_permit::ReserveMsg).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_send_async_unpolled_future_drop_does_not_panic() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(3011, ObligationKind::SendPermit, 4);
        let cx = Cx::for_testing();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let future = sender.send_async(&cx, send_permit::ReserveMsg);
            drop(future);
        }));

        receiver.disarm_for_test();
        assert!(
            result.is_ok(),
            "dropping an unpolled send_async future must not trip the session leak drop bomb"
        );
    }

    #[test]
    fn transport_backed_recv_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(302, ObligationKind::SendPermit, 4);
        sender.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed recv cancelled",
            ));

            let result = receiver.recv_async(&cx).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_recv_async_unpolled_future_drop_does_not_panic() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(3021, ObligationKind::SendPermit, 4);
        let cx = Cx::for_testing();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let future = receiver.recv_async(&cx);
            drop(future);
        }));

        sender.disarm_for_test();
        assert!(
            result.is_ok(),
            "dropping an unpolled recv_async future must not trip the session leak drop bomb"
        );
    }

    #[test]
    fn transport_backed_select_async_cancelled_cx_returns_cancelled() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let cancelled_cx = Cx::for_testing();
            cancelled_cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed select cancelled",
            ));

            let (sender_left, receiver_left) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(303, ObligationKind::SendPermit, 4);
            let sender_left = sender_left
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_left) = receiver_left.recv_async(&cx).await.unwrap();
            let left_result = sender_left.select_left_async(&cancelled_cx).await;
            receiver_left.disarm_for_test();
            assert!(matches!(left_result, Err(SessionError::Cancelled)));

            let (sender_right, receiver_right) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(304, ObligationKind::SendPermit, 4);
            let sender_right = sender_right
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_right) = receiver_right.recv_async(&cx).await.unwrap();
            let right_result = sender_right.select_right_async(&cancelled_cx).await;
            receiver_right.disarm_for_test();
            assert!(matches!(right_result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_select_async_unpolled_future_drop_does_not_panic() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let (sender_left, receiver_left) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3031, ObligationKind::SendPermit, 4);
            let sender_left = sender_left
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_left) = receiver_left.recv_async(&cx).await.unwrap();

            let left_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = sender_left.select_left_async(&cx);
                drop(future);
            }));
            receiver_left.disarm_for_test();
            assert!(
                left_result.is_ok(),
                "dropping an unpolled select_left_async future must not panic"
            );

            let (sender_right, receiver_right) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3032, ObligationKind::SendPermit, 4);
            let sender_right = sender_right
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_right) = receiver_right.recv_async(&cx).await.unwrap();

            let right_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = sender_right.select_right_async(&cx);
                drop(future);
            }));
            receiver_right.disarm_for_test();
            assert!(
                right_result.is_ok(),
                "dropping an unpolled select_right_async future must not panic"
            );
        });
    }

    #[test]
    fn transport_backed_offer_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(305, ObligationKind::SendPermit, 4);

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();
            sender.disarm_for_test();

            let cancelled_cx = Cx::for_testing();
            cancelled_cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed offer cancelled",
            ));

            let result = receiver.offer_async(&cancelled_cx).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_offer_async_unpolled_future_drop_does_not_panic() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let (sender, receiver) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3051, ObligationKind::SendPermit, 4);

            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = receiver.offer_async(&cx);
                drop(future);
            }));

            sender.disarm_for_test();
            assert!(
                result.is_ok(),
                "dropping an unpolled offer_async future must not trip the session leak drop bomb"
            );
        });
    }

    #[test]
    fn transport_backed_recv_offer_and_select_peer_drop_return_closed() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let (sender_recv, receiver_recv) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(306, ObligationKind::SendPermit, 4);
            sender_recv.disarm_for_test();
            let recv_result = receiver_recv.recv_async(&cx).await;
            assert!(matches!(recv_result, Err(SessionError::Closed)));

            let (sender_offer, receiver_offer) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(307, ObligationKind::SendPermit, 4);
            let sender_offer = sender_offer
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_offer) = receiver_offer.recv_async(&cx).await.unwrap();
            sender_offer.disarm_for_test();
            let offer_result = receiver_offer.offer_async(&cx).await;
            assert!(matches!(offer_result, Err(SessionError::Closed)));

            let (sender_select, receiver_select) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(308, ObligationKind::SendPermit, 4);
            let sender_select = sender_select
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_select) = receiver_select.recv_async(&cx).await.unwrap();
            receiver_select.disarm_for_test();
            let select_result = sender_select.select_left_async(&cx).await;
            assert!(matches!(select_result, Err(SessionError::Closed)));
        });
    }

    #[test]
    fn select_left_async_fails_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(309);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender.send(send_permit::ReserveMsg);
            let result = sender.select_left_async(&cx).await;
            assert_eq!(result.map(|_| ()), Err(SessionError::NoTransport));
        });
    }

    #[test]
    fn select_right_async_fails_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(310);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender.send(send_permit::ReserveMsg);
            let result = sender.select_right_async(&cx).await;
            assert_eq!(result.map(|_| ()), Err(SessionError::NoTransport));
        });
    }

    #[test]
    fn recv_async_fails_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(311);
        sender.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let result = receiver.recv_async(&cx).await;
            assert_eq!(result.map(|_| ()), Err(SessionError::NoTransport));
        });
    }

    #[test]
    fn send_async_fails_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(312);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender.send(send_permit::ReserveMsg);
            let sender = sender.select_left();
            let result = sender.send_async(&cx, 7).await;
            assert_eq!(result.map(|_| ()), Err(SessionError::NoTransport));
        });
    }

    #[test]
    fn offer_async_fails_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(313);
        sender.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
            let result = receiver.offer_async(&cx).await;
            assert_eq!(result.map(|_| ()), Err(SessionError::NoTransport));
        });
    }

    #[test]
    fn transport_backed_is_transport_backed_flag() {
        let (pure_s, pure_r) = send_permit::new_session::<u32>(1);
        assert!(!pure_s.is_transport_backed());
        assert!(!pure_r.is_transport_backed());
        pure_s.disarm_for_test();
        pure_r.disarm_for_test();

        let (trans_s, trans_r) = new_transport_pair::<
            send_permit::InitiatorSession<u32>,
            send_permit::ResponderSession<u32>,
        >(2, ObligationKind::SendPermit, 4);
        assert!(trans_s.is_transport_backed());
        assert!(trans_r.is_transport_backed());
        trans_s.disarm_for_test();
        trans_r.disarm_for_test();
    }

    #[test]
    fn session_error_display() {
        assert_eq!(SessionError::Cancelled.to_string(), "session cancelled");
        assert_eq!(SessionError::Closed.to_string(), "session peer closed");
        assert_eq!(
            SessionError::ProtocolViolation {
                expected: "u64",
                actual: "String"
            }
            .to_string(),
            "protocol violation: expected u64, got String"
        );
    }

    /// br-asupersync-wue53y: when an async session transition consumes
    /// the linear channel via an Err arm (peer disconnect / cancel /
    /// NoTransport / ProtocolViolation), the silent-consume audit
    /// counter must increment so the abort is observable in
    /// production logs/metrics. The pre-fix shape returned the Err
    /// silently — the channel was consumed, no Chan came back, and
    /// Drop did not fire because `closed` was already pre-disarmed.
    /// This test pins the audit-trail contract.
    #[test]
    fn wue53y_err_arm_increments_silent_consume_counter() {
        let before = silent_session_consume_count();

        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(900, ObligationKind::SendPermit, 4);

        // Disarm the receiver so we don't take a stale-Chan panic;
        // we're testing the sender-side Err arm in isolation.
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            // Drop the receiver's transport BEFORE the sender polls
            // by completing its Drop (already happened — disarm_for_test
            // dropped it). The sender's send_async will now observe
            // peer-disconnect → SessionError::Closed.
            let result = sender.send_async(&cx, send_permit::ReserveMsg).await;
            let err = match result {
                Err(err) => err,
                Ok(_) => panic!("peer disconnect must surface as Err"),
            };
            assert!(
                matches!(err, SessionError::Closed | SessionError::Cancelled),
                "unexpected error variant: {err:?}"
            );
        });

        let after = silent_session_consume_count();
        assert!(
            after > before,
            "br-asupersync-wue53y: silent-consume counter must \
             increment on Err arm (before={before}, after={after})"
        );
    }
