    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // --- Compile-time duality checks via assert_type_eq ---

    fn assert_dual<S: Session>()
    where
        S::Dual: Session<Dual = S>,
    {
        // If this compiles, duality is involutive for S
    }

    #[test]
    fn duality_end() {
        fn _check() -> Dual<End> {
            End
        }

        init_test("duality_end");

        assert_dual::<End>();
        // Dual<End> = End

        crate::test_complete!("duality_end");
    }

    #[test]
    fn duality_send_recv() {
        init_test("duality_send_recv");

        // Dual<Send<T, End>> = Recv<T, End>
        assert_dual::<Send<String, End>>();
        assert_dual::<Recv<String, End>>();

        // Dual<Send<u64, Recv<bool, End>>> = Recv<u64, Send<bool, End>>
        assert_dual::<Send<u64, Recv<bool, End>>>();

        crate::test_complete!("duality_send_recv");
    }

    #[test]
    fn duality_choose_offer() {
        init_test("duality_choose_offer");

        // Dual<Choose<A, B>> = Offer<Dual<A>, Dual<B>>
        assert_dual::<Choose<End, End>>();
        assert_dual::<Offer<End, End>>();
        assert_dual::<Choose<Send<u8, End>, Recv<u8, End>>>();

        crate::test_complete!("duality_choose_offer");
    }

    #[test]
    fn duality_is_involutive() {
        // Dual<Dual<S>> = S for all S
        // This is enforced by the Session trait bound: Dual: Session<Dual = Self>
        // The fact that these compile proves involution:
        fn _roundtrip_end(_: Dual<Dual<End>>) -> End {
            End
        }

        fn _roundtrip_send(_: Dual<Dual<Send<u32, End>>>) -> Send<u32, End> {
            Send {
                _phantom: PhantomData,
            }
        }

        init_test("duality_is_involutive");

        crate::test_complete!("duality_is_involutive");
    }

    #[test]
    fn duality_complex_protocol() {
        // ATM-like protocol:
        // Client: Send<Card, Recv<Pin, Choose<
        //           Send<Amount, Recv<Cash, End>>,   -- withdraw
        //           Recv<Balance, End>                -- check balance
        //         >>>
        type Card = u64;
        type Pin = u32;
        type Amount = u64;
        type Cash = u64;
        type Balance = u64;

        type ClientProtocol =
            Send<Card, Recv<Pin, Choose<Send<Amount, Recv<Cash, End>>, Recv<Balance, End>>>>;

        // Server (dual):
        // Recv<Card, Send<Pin, Offer<
        //   Recv<Amount, Send<Cash, End>>,
        //   Send<Balance, End>
        // >>>
        type ServerProtocol = Dual<ClientProtocol>;

        // Verify the dual structure compiles correctly
        fn _accept_server(_: ServerProtocol) {}

        init_test("duality_complex_protocol");

        assert_dual::<ClientProtocol>();
        assert_dual::<ServerProtocol>();

        crate::test_complete!("duality_complex_protocol");
    }

    #[test]
    fn channel_creates_dual_endpoints() {
        type P = Send<u32, Recv<bool, End>>;

        init_test("channel_creates_dual_endpoints");
        let (_client, _server) = channel::<P>();

        // _client: Endpoint<Send<u32, Recv<bool, End>>>
        // _server: Endpoint<Recv<u32, Send<bool, End>>>

        crate::test_complete!("channel_creates_dual_endpoints");
    }

    #[test]
    fn endpoint_close_at_end() {
        init_test("endpoint_close_at_end");

        let (ep1, ep2) = channel::<End>();
        ep1.close();
        ep2.close();

        crate::test_complete!("endpoint_close_at_end");
    }

    #[test]
    fn branch_enum() {
        init_test("branch_enum");

        let left = Branch::Left;
        let right = Branch::Right;
        assert_ne!(left, right);
        assert_eq!(left, Branch::Left);
        assert_eq!(right, Branch::Right);

        crate::test_complete!("branch_enum");
    }

    // --- E2E protocol tests (lab runtime) ---

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// E2E: Simple request-response protocol over session-typed endpoints.
    #[test]
    fn session_send_recv_e2e() {
        // Protocol: Send<u64, Recv<u64, End>>
        type ClientP = Send<u64, Recv<u64, End>>;

        init_test("session_send_recv_e2e");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        let (client_ep, server_ep) = channel::<ClientP>();

        let client_result = Arc::new(AtomicU64::new(0));
        let server_result = Arc::new(AtomicU64::new(0));
        let cr = client_result.clone();
        let sr = server_result.clone();

        // Client task: send 42, receive response
        let (client_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                let ep = client_ep.send(&cx, 42).await.expect("client send");
                let (response, ep) = ep.recv(&cx).await.expect("client recv");
                cr.store(response, Ordering::Relaxed);
                ep.close();
            })
            .unwrap();

        // Server task: receive request, send response (value * 2)
        let (server_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                let (request, ep) = server_ep.recv(&cx).await.expect("server recv");
                sr.store(request, Ordering::Relaxed);
                let ep = ep.send(&cx, request * 2).await.expect("server send");
                ep.close();
            })
            .unwrap();

        runtime.scheduler.lock().schedule(client_id, 0);
        runtime.scheduler.lock().schedule(server_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(
            server_result.load(Ordering::Relaxed),
            42,
            "server received 42"
        );
        assert_eq!(
            client_result.load(Ordering::Relaxed),
            84,
            "client received 84"
        );

        crate::test_complete!("session_send_recv_e2e");
    }

    /// E2E: Choose/Offer protocol — client chooses left branch.
    #[test]
    fn session_choose_offer_e2e() {
        // Protocol: Choose<Send<u64, End>, Recv<u64, End>>
        type ClientP = Choose<Send<u64, End>, Recv<u64, End>>;

        init_test("session_choose_offer_e2e");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        let (client_ep, server_ep) = channel::<ClientP>();

        let left_taken = Arc::new(AtomicBool::new(false));
        let value_sent = Arc::new(AtomicU64::new(0));
        let lt = left_taken.clone();
        let vs = value_sent.clone();

        // Client: choose left branch, send a value
        let (client_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                let ep = client_ep.choose_left(&cx).await.expect("choose left");
                let ep = ep.send(&cx, 99).await.expect("send on left");
                ep.close();
            })
            .unwrap();

        // Server: offer both branches, handle whichever the client picks
        let (server_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                match server_ep.offer(&cx).await.expect("offer") {
                    Offered::Left(ep) => {
                        lt.store(true, Ordering::Relaxed);
                        let (val, ep) = ep.recv(&cx).await.expect("recv on left");
                        vs.store(val, Ordering::Relaxed);
                        ep.close();
                    }
                    Offered::Right(ep) => {
                        // Server's right branch: Send<u64, End>
                        let ep = ep.send(&cx, 0).await.unwrap();
                        ep.close();
                    }
                }
            })
            .unwrap();

        runtime.scheduler.lock().schedule(client_id, 0);
        runtime.scheduler.lock().schedule(server_id, 0);
        runtime.run_until_quiescent();

        assert!(
            left_taken.load(Ordering::Relaxed),
            "server took left branch"
        );
        assert_eq!(value_sent.load(Ordering::Relaxed), 99, "server received 99");

        crate::test_complete!("session_choose_offer_e2e");
    }

    /// E2E: Deterministic session execution — same seed, same result.
    #[test]
    fn session_deterministic() {
        fn run_protocol(seed: u64) -> u64 {
            type P = Send<u64, Recv<u64, End>>;

            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime
                .state
                .create_root_region(crate::types::Budget::INFINITE);
            let (client_ep, server_ep) = channel::<P>();

            let result = Arc::new(AtomicU64::new(0));
            let r = result.clone();

            let (cid, _) = runtime
                .state
                .create_task(region, crate::types::Budget::INFINITE, async move {
                    let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                    let ep = client_ep.send(&cx, 7).await.unwrap();
                    let (val, ep) = ep.recv(&cx).await.unwrap();
                    r.store(val, Ordering::Relaxed);
                    ep.close();
                })
                .unwrap();

            let (sid, _) = runtime
                .state
                .create_task(region, crate::types::Budget::INFINITE, async move {
                    let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
                    let (v, ep) = server_ep.recv(&cx).await.unwrap();
                    let ep = ep.send(&cx, v + 100).await.unwrap();
                    ep.close();
                })
                .unwrap();

            runtime.scheduler.lock().schedule(cid, 0);
            runtime.scheduler.lock().schedule(sid, 0);
            runtime.run_until_quiescent();

            result.load(Ordering::Relaxed)
        }

        init_test("session_deterministic");

        let r1 = run_protocol(0xCAFE);
        let r2 = run_protocol(0xCAFE);
        assert_eq!(r1, r2, "deterministic replay");
        assert_eq!(r1, 107, "7 + 100 = 107");

        crate::test_complete!("session_deterministic");
    }

    // Pure data-type tests (wave 36 – CyanBarn)

    #[test]
    fn session_error_debug() {
        let e1 = SessionError::Disconnected;
        let e2 = SessionError::TypeMismatch;
        let e3 = SessionError::Cancelled;

        let dbg1 = format!("{e1:?}");
        let dbg2 = format!("{e2:?}");
        let dbg3 = format!("{e3:?}");

        assert!(dbg1.contains("Disconnected"));
        assert!(dbg2.contains("TypeMismatch"));
        assert!(dbg3.contains("Cancelled"));
    }

    #[test]
    fn branch_debug_copy() {
        let left = Branch::Left;
        let right = Branch::Right;

        let dbg_l = format!("{left:?}");
        let dbg_r = format!("{right:?}");
        assert!(dbg_l.contains("Left"));
        assert!(dbg_r.contains("Right"));

        // Copy semantics
        let left2 = left;
        assert_eq!(left, left2);

        // Clone
        let right2 = right;
        assert_eq!(right, right2);
    }

    #[test]
    fn session_send_surfaces_cancellation() {
        init_test("session_send_surfaces_cancellation");

        let cx = crate::cx::Cx::for_testing();
        cx.set_cancel_reason(crate::types::CancelReason::user("session send cancelled"));

        let (client, _server) = channel::<Send<u64, End>>();
        let result = futures_lite::future::block_on(client.send(&cx, 42));

        assert!(
            matches!(result, Outcome::Err(SessionError::Cancelled)),
            "cancelled send should surface SessionError::Cancelled"
        );

        crate::test_complete!("session_send_surfaces_cancellation");
    }

    #[test]
    fn session_choice_surfaces_cancellation() {
        init_test("session_choice_surfaces_cancellation");

        let cx = crate::cx::Cx::for_testing();
        cx.set_cancel_reason(crate::types::CancelReason::user("session choose cancelled"));

        let (left_ep, _left_peer) = channel::<Choose<End, End>>();
        let left_result = futures_lite::future::block_on(left_ep.choose_left(&cx));
        assert!(
            matches!(left_result, Outcome::Err(SessionError::Cancelled)),
            "cancelled choose_left should surface SessionError::Cancelled"
        );

        let (right_ep, _right_peer) = channel::<Choose<End, End>>();
        let right_result = futures_lite::future::block_on(right_ep.choose_right(&cx));
        assert!(
            matches!(right_result, Outcome::Err(SessionError::Cancelled)),
            "cancelled choose_right should surface SessionError::Cancelled"
        );

        crate::test_complete!("session_choice_surfaces_cancellation");
    }
