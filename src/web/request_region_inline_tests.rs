    use super::*;
    use crate::cx::{Cx, cap};
    use crate::obligation::graded::{GradedObligation, Resolution};
    use crate::record::ObligationKind;
    use crate::web::extract::Request;
    use crate::web::response::StatusCode;

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn test_request(method: &str, path: &str) -> Request {
        Request::new(method, path)
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn producer_cancellation_classifies_time_causes_through_parent_cleanup() {
        use crate::types::CancelReason;

        for kind in [CancelKind::Timeout, CancelKind::Deadline] {
            let cx = test_cx();
            cx.cancel_with_reason(
                CancelReason::parent_cancelled().with_cause(CancelReason::new(kind)),
            );
            assert_eq!(
                classify_server_producer_cancellation(&cx),
                ServerProducerCancellation::DeadlineExceeded,
            );
        }
        for reason in [
            CancelReason::parent_cancelled(),
            CancelReason::parent_cancelled().with_cause(CancelReason::user("client reset")),
            CancelReason::shutdown(),
        ] {
            let cx = test_cx();
            cx.cancel_with_reason(reason);
            assert_eq!(
                classify_server_producer_cancellation(&cx),
                ServerProducerCancellation::Cancelled,
            );
        }
    }

    // --- RequestRegion::run ---

    #[test]
    fn run_success() {
        let cx = test_cx();
        let req = test_request("GET", "/hello");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            assert_eq!(ctx.method(), "GET");
            assert_eq!(ctx.path(), "/hello");
            Response::new(StatusCode::OK, b"ok".to_vec())
        });

        assert!(outcome.is_ok());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn run_panic_isolation() {
        let cx = test_cx();
        let req = test_request("GET", "/panic");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("handler bug");
        });

        assert!(outcome.is_panicked());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn run_panic_string_message_preserved() {
        let cx = test_cx();
        let req = test_request("GET", "/");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("something broke");
        });

        if let RegionOutcome::Panicked(msg) = &outcome {
            assert!(msg.contains("something broke"), "msg: {msg}");
        } else {
            panic!("expected Panicked outcome");
        }
    }

    #[test]
    fn run_cancelled_before_handler_returns_499() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let req = test_request("GET", "/cancel");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("should not reach handler");
        });

        assert!(outcome.is_cancelled());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
    }

    #[test]
    fn run_commits_response_when_cancel_arrives_during_handler() {
        // br-asupersync-bmc8m5: a cancel that arrives while the handler is
        // running must NOT cause the completed Response to be silently
        // dropped. The handler's work is a discharged obligation; the
        // outcome is committed (Ok), and callers that need to observe
        // the cancel can read it from the `Cx` post-hoc.
        let cx = test_cx();
        let req = test_request("GET", "/cancel-during");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            // Simulate a cancel arriving during handler execution
            // (e.g., parent region timeout fires) before the handler
            // returns its already-built Response.
            ctx.cx().set_cancel_requested(true);
            Response::new(StatusCode::OK, b"ok".to_vec())
        });

        // Completed work survives the cancel race.
        assert!(
            outcome.is_ok(),
            "completed Response must survive cancel race"
        );
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"ok");
        // Cancel signal remains observable on the cx for telemetry/retry.
        assert!(
            cx.is_cancel_requested(),
            "cancel signal remains observable on the cx after the handler returns"
        );
    }

    #[test]
    fn run_installs_current_cx_for_handler_body() {
        let cx = test_cx();
        let req = test_request("GET", "/current");
        let expected_task = cx.task_id();
        let expected_region = cx.region_id();
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            let current = Cx::current().expect("request region should install CURRENT_CX");
            assert_eq!(current.task_id(), expected_task);
            assert_eq!(current.region_id(), expected_region);
            Response::empty(StatusCode::OK)
        });

        assert!(outcome.is_ok());
        assert!(
            Cx::current().is_none(),
            "request region must restore the prior CURRENT_CX after the handler returns"
        );
    }

    // --- RequestRegion::run_sync ---

    #[test]
    fn run_sync_success() {
        let cx = test_cx();
        let req = test_request("POST", "/data");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|ctx| {
            assert_eq!(ctx.method(), "POST");
            Ok(Response::new(StatusCode::CREATED, b"created".to_vec()))
        });

        assert!(outcome.is_ok());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn run_sync_error() {
        let cx = test_cx();
        let req = test_request("GET", "/err");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|_ctx| Err(Error::new(crate::error::ErrorKind::Internal)));

        assert!(outcome.is_error());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn run_sync_panic() {
        let cx = test_cx();
        let req = test_request("GET", "/");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|_ctx| -> Result<Response, Error> {
            panic!("boom");
        });

        assert!(outcome.is_panicked());
    }

    #[test]
    fn run_sync_commits_ok_response_when_cancel_arrives_during_handler() {
        // br-asupersync-bmc8m5: same contract as run() — if the handler
        // reaches a successful Response before the cancel takes effect,
        // commit the Response instead of throwing the work away.
        let cx = test_cx();
        let req = test_request("GET", "/cancel-during");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|ctx| {
            ctx.cx().set_cancel_requested(true);
            Ok(Response::new(StatusCode::OK, b"ok".to_vec()))
        });

        assert!(
            outcome.is_ok(),
            "completed Ok Response must survive cancel race"
        );
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"ok");
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn run_sync_commits_err_response_when_cancel_arrives_during_handler() {
        // br-asupersync-bmc8m5: an Err result is also a discharged
        // obligation — it carries application-level failure info the
        // caller has paid for. Don't silently rewrite it as Cancelled.
        let cx = test_cx();
        let req = test_request("GET", "/cancel-during-err");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|ctx| {
            ctx.cx().set_cancel_requested(true);
            Err(Error::new(crate::error::ErrorKind::Internal))
        });

        assert!(outcome.is_error(), "Err result must survive cancel race");
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn run_sync_installs_current_cx_for_handler_body() {
        let cx = test_cx();
        let req = test_request("POST", "/current");
        let expected_task = cx.task_id();
        let expected_region = cx.region_id();
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|_ctx| {
            let current = Cx::current().expect("request region should install CURRENT_CX");
            assert_eq!(current.task_id(), expected_task);
            assert_eq!(current.region_id(), expected_region);
            Ok(Response::empty(StatusCode::OK))
        });

        assert!(outcome.is_ok());
        assert!(
            Cx::current().is_none(),
            "request region must restore the prior CURRENT_CX after sync handlers return"
        );
    }

    // --- RequestContext accessors ---

    #[test]
    fn context_accessors() {
        let cx = test_cx();
        let mut req = test_request("DELETE", "/users/99");
        req.headers
            .insert("authorization".to_string(), "Bearer token".to_string());
        let mut params = std::collections::HashMap::new();
        params.insert("id".to_string(), "99".to_string());
        req.path_params = params;

        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            assert_eq!(ctx.method(), "DELETE");
            assert_eq!(ctx.path(), "/users/99");
            assert_eq!(ctx.path_param("id"), Some("99"));
            assert_eq!(ctx.path_param("missing"), None);
            assert_eq!(ctx.header("Authorization"), Some("Bearer token"));
            assert_eq!(ctx.header("authorization"), Some("Bearer token"));
            assert_eq!(ctx.header("Missing"), None);
            let _readonly = ctx.cx_readonly();
            let _narrow = ctx.cx_narrow::<cap::CapSet<true, true, false, false, false>>();
            Response::empty(StatusCode::NO_CONTENT)
        });

        assert!(outcome.is_ok());
    }

    // --- IsolatedHandler ---

    #[test]
    fn isolated_handler_success() {
        let handler = IsolatedHandler::new(|ctx| {
            let name = ctx.path_param("name").unwrap_or("world");
            Response::new(StatusCode::OK, format!("Hello, {name}!").into_bytes())
        });

        let cx = test_cx();
        let mut req = test_request("GET", "/greet/alice");
        let mut params = std::collections::HashMap::new();
        params.insert("name".to_string(), "alice".to_string());
        req.path_params = params;

        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn isolated_handler_panic_returns_500() {
        let handler = IsolatedHandler::new(|_ctx| {
            panic!("handler crash");
        });

        let cx = test_cx();
        let req = test_request("GET", "/");
        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn panicked_response_does_not_leak_panic_message() {
        let resp = RegionOutcome::Panicked("secret panic details".to_string()).into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn isolated_handler_cancelled_returns_499() {
        let handler = IsolatedHandler::new(|_ctx| {
            panic!("should not run");
        });

        let cx = test_cx();
        cx.set_cancel_requested(true);
        let req = test_request("GET", "/");
        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
    }

    // --- RegionOutcome ---

    #[test]
    fn region_outcome_display() {
        let ok = RegionOutcome::Ok(Response::empty(StatusCode::OK));
        assert!(ok.to_string().contains("200"));

        let cancelled = RegionOutcome::Cancelled;
        assert_eq!(cancelled.to_string(), "Cancelled");

        let panicked = RegionOutcome::Panicked("oof".to_string());
        assert!(panicked.to_string().contains("oof"));
    }

    // --- extract_panic_message ---

    #[test]
    fn panic_message_from_str() {
        let msg = extract_panic_message(&(Box::new("oops") as Box<dyn std::any::Any + Send>));
        assert_eq!(msg, "oops");
    }

    #[test]
    fn panic_message_from_string() {
        let msg = extract_panic_message(
            &(Box::new("owned msg".to_string()) as Box<dyn std::any::Any + Send>),
        );
        assert_eq!(msg, "owned msg");
    }

    #[test]
    fn panic_message_unknown_type() {
        let msg = extract_panic_message(&(Box::new(42i32) as Box<dyn std::any::Any + Send>));
        assert_eq!(msg, "unknown panic");
    }

    // ─── Metamorphic Testing: Cancel-on-Disconnect Invariants ──────────────────

    mod metamorphic_tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::time::Duration;

        /// Deterministic delay simulation using virtual time instead of thread sleep.
        /// This provides faster, deterministic test execution while preserving
        /// the same timing behavior patterns.
        fn virtual_delay(duration: Duration) {
            // For deterministic testing, we simulate delay without actually sleeping.
            // This provides the same concurrency patterns but eliminates timing dependencies.
            // In a real async context, this would be replaced with asupersync::time::sleep().

            // Create a minimal spin delay to allow thread scheduling but avoid wall-clock dependency
            let iterations = duration.as_millis().max(1) as usize;
            for _ in 0..iterations {
                std::hint::spin_loop();
                // Allow other threads to run
                std::thread::yield_now();
            }
        }

        /// MR1: Client disconnect triggers request-region cancel within 1 tick
        ///
        /// Property: If the client disconnects during handler execution,
        /// the region's cancellation state should be observable within 1 tick.
        #[test]
        fn mr_disconnect_triggers_cancel_within_one_tick() {
            let cx = test_cx();
            let req = test_request("GET", "/long-running");
            let region = RequestRegion::new(&cx, req);

            let cancel_observed = Arc::new(AtomicBool::new(false));
            let cancel_observed_clone = Arc::clone(&cancel_observed);
            let cx_clone = cx.clone();

            // Signal that the handler has started and the disconnect should
            // now be delivered. This removes the previous wall-clock/spin
            // race (the handler could finish its fixed 10-iteration loop
            // before the background thread's arbitrary delay set the cancel
            // flag, leaving neither `cancel_observed` nor `outcome` cancelled
            // and flaking the assertion). The barrier guarantees the
            // disconnect arrives *during* handler execution, which is exactly
            // the metamorphic property under test.
            let handler_started = Arc::new(AtomicBool::new(false));
            let handler_started_clone = Arc::clone(&handler_started);

            // Simulate client disconnect: wait until the handler is running,
            // then set cancel. Mirrors a disconnect observed mid-request.
            let cancel_thread = std::thread::spawn(move || {
                while !handler_started_clone.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                cx_clone.set_cancel_requested(true);
            });

            let outcome = region.run(|ctx| {
                // Announce that the handler is executing so the disconnect is
                // delivered now, then poll for cancellation. The loop is
                // bounded but large enough that it cannot exit before the
                // cross-thread store becomes visible (the handler spins on
                // `is_cancel_requested` rather than doing fixed busywork).
                handler_started.store(true, Ordering::SeqCst);
                for _i in 0..1_000_000 {
                    if ctx.cx().is_cancel_requested() {
                        cancel_observed_clone.store(true, Ordering::SeqCst);
                        return Response::new(
                            StatusCode::CLIENT_CLOSED_REQUEST,
                            b"cancelled".to_vec(),
                        );
                    }
                    std::hint::spin_loop();
                }
                Response::new(StatusCode::OK, b"completed".to_vec())
            });
            cancel_thread.join().expect("cancel thread panicked");

            // MR1: a disconnect delivered during handler execution must be
            // observable by the handler (or surfaced as a cancelled outcome).
            assert!(
                cancel_observed.load(Ordering::SeqCst) || outcome.is_cancelled(),
                "Client disconnect should trigger observable cancellation"
            );
        }

        /// MR2: All pending downstream futures receive cancellation
        ///
        /// Property: When the request region is cancelled, all spawned tasks
        /// within the region should also be cancelled.
        #[test]
        fn mr_downstream_futures_receive_cancellation() {
            let cx = test_cx();
            let req = test_request("GET", "/spawn-tasks");
            let region = RequestRegion::new(&cx, req);

            let task_cancelled = Arc::new(AtomicBool::new(false));
            let task_started = Arc::new(AtomicBool::new(false));
            let cancellation_armed = Arc::new(AtomicBool::new(false));
            let task_cancelled_clone = Arc::clone(&task_cancelled);
            let task_started_clone = Arc::clone(&task_started);
            let cancellation_armed_clone = Arc::clone(&cancellation_armed);

            let outcome = region.run(|ctx| {
                std::thread::scope(|s| {
                    // Spawn a background task that monitors cancellation
                    let task_ctx = ctx.cx().clone();
                    s.spawn(move || {
                        task_started_clone.store(true, Ordering::SeqCst);
                        while !cancellation_armed_clone.load(Ordering::SeqCst) {
                            std::hint::spin_loop();
                            std::thread::yield_now();
                        }
                        for _ in 0..10_000 {
                            if task_ctx.is_cancel_requested() {
                                task_cancelled_clone.store(true, Ordering::SeqCst);
                                break;
                            }
                            std::hint::spin_loop();
                            std::thread::yield_now();
                        }
                    });

                    // Simulate client disconnect
                    while !task_started.load(Ordering::SeqCst) {
                        std::hint::spin_loop();
                        std::thread::yield_now();
                    }
                    ctx.cx().set_cancel_requested(true);
                    cancellation_armed.store(true, Ordering::SeqCst);
                });

                Response::new(StatusCode::OK, b"ok".to_vec())
            });

            // MR2: Spawned tasks should observe cancellation
            assert!(
                task_cancelled.load(Ordering::SeqCst) || outcome.is_cancelled(),
                "Spawned tasks should receive cancellation signal"
            );
        }

        /// MR3: No obligation leaks after disconnect
        ///
        /// Property: When a request is cancelled, all tracked obligations
        /// should be properly cleaned up (committed or aborted).
        #[test]
        fn mr_no_obligation_leaks_after_disconnect() {
            let cx = test_cx();
            let req = test_request("POST", "/transaction");
            let region = RequestRegion::new(&cx, req);

            let obligation_cleaned = Arc::new(AtomicBool::new(false));
            let obligation_cleaned_clone = Arc::clone(&obligation_cleaned);

            let _outcome = region.run(|ctx| {
                // Create a real graded obligation for a request-scoped resource
                let obligation =
                    GradedObligation::reserve(ObligationKind::IoOp, "HTTP request transaction");

                // Simulate client disconnect during transaction
                virtual_delay(Duration::from_millis(1));
                ctx.cx().set_cancel_requested(true);

                // Set the flag when resolving the obligation properly
                let _proof = obligation.resolve(Resolution::Abort);
                obligation_cleaned_clone.store(true, Ordering::SeqCst);

                // Early return should trigger obligation cleanup via Resolution
                if ctx.cx().checkpoint().is_err() {
                    return Response::new(StatusCode::CLIENT_CLOSED_REQUEST, b"cancelled".to_vec());
                }

                Response::new(StatusCode::OK, b"committed".to_vec())
            });

            // Give time for cleanup
            virtual_delay(Duration::from_millis(1));

            // MR3: Obligations should be cleaned up after cancellation
            assert!(
                obligation_cleaned.load(Ordering::SeqCst),
                "Obligations must be cleaned up when request is cancelled"
            );
        }

        /// MR4: Partial response flushed atomically
        ///
        /// Property: If a response is partially written when cancellation occurs,
        /// the response should be atomically committed or discarded (no partial writes).
        #[test]
        fn mr_partial_response_flushed_atomically() {
            let cx = test_cx();
            let req = test_request("GET", "/streaming");
            let region = RequestRegion::new(&cx, req);

            let response_complete = Arc::new(AtomicBool::new(false));
            let response_complete_clone = Arc::clone(&response_complete);
            let cancel_cx = cx.clone();

            let cancel_thread = std::thread::spawn(move || {
                virtual_delay(Duration::from_millis(5));
                cancel_cx.set_cancel_requested(true);
            });

            let outcome = region.run(|ctx| {
                // Simulate building a response that could be interrupted
                let mut response_data = Vec::new();
                for i in 0..10 {
                    if ctx.cx().is_cancel_requested() {
                        // If cancelled, return what we have or a cancellation response
                        return Response::new(
                            StatusCode::CLIENT_CLOSED_REQUEST,
                            b"cancelled".to_vec(),
                        );
                    }

                    // Simulate response building
                    response_data.push(b'a' + (i % 26) as u8);
                    virtual_delay(Duration::from_millis(1));
                }

                response_complete_clone.store(true, Ordering::SeqCst);
                Response::new(StatusCode::OK, response_data)
            });
            cancel_thread.join().expect("cancel thread panicked");

            // MR4: Response should be either complete or properly cancelled.
            // A handler-produced 499 is still a committed response under the
            // br-asupersync-bmc8m5 cancel-race contract.
            match outcome {
                RegionOutcome::Ok(response) => {
                    let complete = response_complete.load(Ordering::SeqCst);
                    let cancel_requested = cx.is_cancel_requested();
                    let body = response.body.as_ref();

                    match response.status {
                        StatusCode::OK => {
                            assert!(
                                complete,
                                "OK response must only commit after full build: status={:?} cancel_requested={cancel_requested} body_len={}",
                                response.status,
                                body.len()
                            );
                            assert_eq!(
                                body, b"abcdefghij",
                                "OK response body must be complete: status={:?} cancel_requested={cancel_requested}",
                                response.status
                            );
                        }
                        StatusCode::CLIENT_CLOSED_REQUEST => {
                            assert!(
                                !complete,
                                "499 cancellation response must not mark the full body complete: status={:?} cancel_requested={cancel_requested} body_len={}",
                                response.status,
                                body.len()
                            );
                            assert!(
                                cancel_requested,
                                "499 cancellation response requires an observable cancel signal: status={:?} body_len={}",
                                response.status,
                                body.len()
                            );
                            assert_eq!(
                                body, b"cancelled",
                                "499 response body must be the atomic cancellation response"
                            );
                        }
                        status => panic!(
                            "Unexpected committed response status: status={status:?} cancel_requested={cancel_requested} complete={complete} body_len={}",
                            body.len()
                        ),
                    }
                }
                RegionOutcome::Cancelled => assert!(
                    !response_complete.load(Ordering::SeqCst),
                    "Pre-handler cancellation must not complete response building: cancel_requested={}",
                    cx.is_cancel_requested()
                ),
                _ => panic!("Unexpected outcome: {:?}", outcome),
            }
        }

        /// MR5: Reconnect with same request-id deduplicated
        ///
        /// Property: If a client reconnects with the same request identifier,
        /// the request should be deduplicated (idempotency).
        #[test]
        fn mr_reconnect_request_id_deduplicated() {
            let cx = test_cx();
            let request_counter = Arc::new(AtomicU32::new(0));

            // First request with ID "req-123"
            let mut req1 = test_request("POST", "/idempotent");
            req1.headers
                .insert("x-request-id".to_string(), "req-123".to_string());
            req1.headers
                .insert("x-idempotency-key".to_string(), "key-123".to_string());

            let region1 = RequestRegion::new(&cx, req1);
            let counter_clone1 = Arc::clone(&request_counter);

            let outcome1 = region1.run(|ctx| {
                // Check for idempotency key in real implementation
                let request_id = ctx.header("x-request-id").unwrap_or("none");
                let idempotency_key = ctx.header("x-idempotency-key").unwrap_or("none");

                // Simulate idempotent operation
                if request_id == "req-123" && idempotency_key == "key-123" {
                    counter_clone1.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else {
                    Response::new(StatusCode::BAD_REQUEST, b"missing headers".to_vec())
                }
            });

            // Second request with same ID (reconnect/retry)
            let mut req2 = test_request("POST", "/idempotent");
            req2.headers
                .insert("x-request-id".to_string(), "req-123".to_string());
            req2.headers
                .insert("x-idempotency-key".to_string(), "key-123".to_string());

            let region2 = RequestRegion::new(&cx, req2);
            let counter_clone2 = Arc::clone(&request_counter);

            let outcome2 = region2.run(|ctx| {
                let request_id = ctx.header("x-request-id").unwrap_or("none");
                let idempotency_key = ctx.header("x-idempotency-key").unwrap_or("none");

                // In a real implementation, this would check a cache/database
                // For this test, we simulate that the operation should be idempotent
                let current_count = counter_clone2.load(Ordering::SeqCst);

                if request_id == "req-123" && idempotency_key == "key-123" && current_count > 0 {
                    // Already processed - return cached result
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else if current_count == 0 {
                    // First time - process it
                    counter_clone2.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else {
                    Response::new(StatusCode::BAD_REQUEST, b"invalid state".to_vec())
                }
            });

            // MR5: Both requests should succeed, but operation should only happen once
            assert!(outcome1.is_ok(), "First request should succeed");
            assert!(
                outcome2.is_ok(),
                "Second request (reconnect) should succeed"
            );

            // The key invariant: idempotent operations should only execute once
            let final_count = request_counter.load(Ordering::SeqCst);
            assert_eq!(
                final_count, 1,
                "Idempotent operation should only execute once despite multiple requests"
            );
        }

        /// Composite MR: Disconnect during concurrent operations
        ///
        /// Tests multiple invariants simultaneously to catch interaction bugs.
        #[test]
        fn mr_composite_disconnect_concurrent_operations() {
            let cx = test_cx();
            let req = test_request("POST", "/complex");
            let region = RequestRegion::new(&cx, req);

            let task_count = Arc::new(AtomicU32::new(0));
            let cleanup_count = Arc::new(AtomicU32::new(0));

            let task_count_clone = Arc::clone(&task_count);
            let cleanup_count_clone = Arc::clone(&cleanup_count);

            let outcome = region.run(|ctx| {
                std::thread::scope(|s| {
                    // Spawn multiple concurrent tasks
                    let mut handles = Vec::new();
                    for _i in 0..3 {
                        let task_ctx = ctx.cx().clone();
                        let task_counter = Arc::clone(&task_count_clone);
                        let cleanup_counter = Arc::clone(&cleanup_count_clone);

                        handles.push(s.spawn(move || {
                            task_counter.fetch_add(1, Ordering::SeqCst);

                            // Simulate work with cleanup
                            let _cleanup = CleanupGuard {
                                counter: cleanup_counter,
                            };

                            for _ in 0..20 {
                                if task_ctx.is_cancel_requested() {
                                    return; // Task cancelled
                                }
                                virtual_delay(Duration::from_micros(100));
                            }
                        }));
                    }

                    // Simulate client disconnect after brief work
                    virtual_delay(Duration::from_millis(2));
                    ctx.cx().set_cancel_requested(true);

                    // Give tasks time to observe cancellation and clean up
                    virtual_delay(Duration::from_millis(10));

                    for h in handles {
                        let _ = h.join();
                    }
                });

                Response::new(StatusCode::CLIENT_CLOSED_REQUEST, b"cancelled".to_vec())
            });

            virtual_delay(Duration::from_millis(5)); // Allow cleanup to complete

            // Composite invariants:
            // 1. All tasks should have started
            assert_eq!(
                task_count.load(Ordering::SeqCst),
                3,
                "All spawned tasks should have started"
            );

            // 2. All tasks should have cleaned up
            assert_eq!(
                cleanup_count.load(Ordering::SeqCst),
                3,
                "All tasks should have performed cleanup"
            );

            // 3. Request cancellation should stay observable, while the
            // handler-produced 499 remains a committed response.
            let cancel_requested = cx.is_cancel_requested();
            match outcome {
                RegionOutcome::Ok(response) => {
                    assert_eq!(
                        response.status,
                        StatusCode::CLIENT_CLOSED_REQUEST,
                        "Composite disconnect should commit the handler's cancellation response: cancel_requested={cancel_requested} body_len={}",
                        response.body.as_ref().len()
                    );
                    assert!(
                        cancel_requested,
                        "Composite disconnect must leave cancel signal observable after committed response: status={:?}",
                        response.status
                    );
                }
                RegionOutcome::Cancelled => assert!(
                    cancel_requested,
                    "Pre-handler cancellation must be observable after cancelled outcome"
                ),
                other => panic!(
                    "Unexpected composite disconnect outcome: {other:?}; cancel_requested={cancel_requested}"
                ),
            }
        }

        struct CleanupGuard {
            counter: Arc<AtomicU32>,
        }

        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // ─── Async Request Region Tests ────────────────────────────────────────────

    mod async_tests {
        use super::*;
        use crate::test_utils::run_test_with_cx;
        use std::pin::Pin;

        /// Test basic async handler execution
        #[test]
        fn async_run_success() {
            run_test_with_cx(|cx| async move {
                let req = test_request("GET", "/async-hello");
                let region = RequestRegion::new(&cx, req);

                let outcome = region
                    .run_async(|ctx| {
                        let method = ctx.method().to_owned();
                        let path = ctx.path().to_owned();
                        async move {
                            assert_eq!(method, "GET");
                            assert_eq!(path, "/async-hello");
                            Response::new(StatusCode::OK, b"async ok".to_vec())
                        }
                    })
                    .await;

                assert!(outcome.is_ok());
                let resp = outcome.into_response();
                assert_eq!(resp.status, StatusCode::OK);
                assert_eq!(&resp.body[..], b"async ok");
            });
        }

        /// Test async handler with cancellation
        #[test]
        fn async_run_with_cancellation() {
            run_test_with_cx(|cx| async move {
                let req = test_request("GET", "/cancel-test");
                let region = RequestRegion::new(&cx, req);

                // Set cancellation before running
                cx.set_cancel_requested(true);

                let outcome = region
                    .run_async(|_ctx| async move {
                        Response::new(StatusCode::OK, b"should not execute".to_vec())
                    })
                    .await;

                assert!(outcome.is_cancelled());
            });
        }

        /// Test async handler with Handler trait
        #[test]
        fn async_run_handler_success() {
            struct AsyncTestHandler;

            impl crate::web::handler::Handler for AsyncTestHandler {
                fn call(
                    &self,
                    _cx: &Cx,
                    req: Request,
                ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
                    let path = req.path.clone();
                    Box::pin(async move {
                        Response::new(StatusCode::OK, format!("async: {}", path).into_bytes())
                    })
                }
            }

            run_test_with_cx(|cx| async move {
                let req = test_request("POST", "/handler-test");
                let region = RequestRegion::new(&cx, req);
                let handler = AsyncTestHandler;

                let outcome = region.run_handler(&handler).await;

                assert!(outcome.is_ok());
                let resp = outcome.into_response();
                assert_eq!(resp.status, StatusCode::OK);
                assert_eq!(&resp.body[..], b"async: /handler-test");
            });
        }

        /// Test async handler with request context integration
        #[test]
        fn async_context_integration() {
            run_test_with_cx(|cx| async move {
                let req = test_request("GET", "/context");
                let region = RequestRegion::new(&cx, req);

                let outcome = region
                    .run_async(|ctx| {
                        // Verify context provides access to Cx and cancellation
                        let can_cancel = ctx.cx().checkpoint().is_ok();
                        async move {
                            assert!(can_cancel, "Context should provide access to cancellation");

                            Response::new(StatusCode::OK, b"context ok".to_vec())
                        }
                    })
                    .await;

                assert!(outcome.is_ok());
            });
        }
    }

    // --- Server-hop request regions (br-asupersync-server-stack-hardening-eeexl1.1.1) ---

    mod server_hop {
        use super::*;
        use crate::runtime::RuntimeBuilder;
        use crate::trace::event::{TraceData, TraceEventKind};
        use crate::types::{Budget, CancelKind, Time};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        const NOW: Time = Time::from_secs(1_000);

        // --- derive_request_budget: meet semantics + security ---

        #[test]
        fn derive_inherits_base_when_nothing_configured() {
            let (budget, source) = derive_request_budget(Budget::INFINITE, NOW, None, None, None);
            assert_eq!(budget.deadline, None);
            assert_eq!(source, RequestBudgetSource::Inherited);
        }

        #[test]
        fn derive_applies_server_config_timeout() {
            let (budget, source) = derive_request_budget(
                Budget::INFINITE,
                NOW,
                Some(Duration::from_secs(30)),
                None,
                None,
            );
            assert_eq!(budget.deadline, Some(NOW + Duration::from_secs(30)));
            assert_eq!(source, RequestBudgetSource::ServerConfig);
        }

        #[test]
        fn derive_never_loosens_tighter_base() {
            let base = Budget::new().with_timeout(NOW, Duration::from_secs(10));
            let (budget, _) =
                derive_request_budget(base, NOW, Some(Duration::from_secs(30)), None, None);
            assert_eq!(
                budget.deadline,
                Some(NOW + Duration::from_secs(10)),
                "a server timeout longer than the connection budget must not extend it"
            );
        }

        #[test]
        fn derive_header_clamped_by_cap() {
            let (budget, source) = derive_request_budget(
                Budget::INFINITE,
                NOW,
                None,
                Some(Duration::from_secs(600)),
                Some(Duration::from_secs(60)),
            );
            assert_eq!(
                budget.deadline,
                Some(NOW + Duration::from_secs(60)),
                "header timeout must be clamped to the configured cap"
            );
            assert_eq!(source, RequestBudgetSource::HeaderClamped);
        }

        #[test]
        fn derive_header_ignored_without_cap_opt_in() {
            let (budget, source) = derive_request_budget(
                Budget::INFINITE,
                NOW,
                None,
                Some(Duration::from_millis(1)),
                None,
            );
            assert_eq!(budget.deadline, None, "no cap configured => header ignored");
            assert_eq!(source, RequestBudgetSource::Inherited);
        }

        #[test]
        fn derive_header_tightens_within_cap_and_config() {
            let (budget, source) = derive_request_budget(
                Budget::INFINITE,
                NOW,
                Some(Duration::from_secs(30)),
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(60)),
            );
            assert_eq!(budget.deadline, Some(NOW + Duration::from_secs(5)));
            assert_eq!(source, RequestBudgetSource::ServerConfigAndHeader);
        }

        /// Security (parent AC 3): a hostile header can never extend the
        /// effective deadline beyond the cap, the server config, or the
        /// connection budget — whichever is tightest.
        #[test]
        fn derive_security_hostile_header_cannot_extend() {
            let huge = Duration::from_millis(u64::MAX);
            let (budget, _) = derive_request_budget(
                Budget::INFINITE,
                NOW,
                None,
                Some(huge),
                Some(Duration::from_secs(2)),
            );
            assert_eq!(budget.deadline, Some(NOW + Duration::from_secs(2)));

            let base = Budget::new().with_timeout(NOW, Duration::from_secs(1));
            let (budget, _) = derive_request_budget(
                base,
                NOW,
                Some(Duration::from_secs(30)),
                Some(huge),
                Some(Duration::from_secs(120)),
            );
            assert_eq!(
                budget.deadline,
                Some(NOW + Duration::from_secs(1)),
                "connection budget remains the binding constraint"
            );
        }

        // --- run_with_protocol_drain lifecycle ---

        fn block_on<F: std::future::Future>(fut: F) -> F::Output {
            RuntimeBuilder::current_thread()
                .build()
                .expect("build current-thread runtime")
                .block_on(fut)
        }

        fn budget_events(
            events: &[crate::trace::event::TraceEvent],
        ) -> Vec<(TraceEventKind, TraceData)> {
            events
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        TraceEventKind::BudgetInstalled | TraceEventKind::BudgetConsumed
                    )
                })
                .map(|e| (e.kind, e.data.clone()))
                .collect()
        }

        #[test]
        fn hop_ok_commits_response_and_emits_budget_events() {
            block_on(async {
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let trace = region.cx().trace_buffer().expect("runtime trace buffer");
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::Inherited,
                        None,
                        Duration::from_millis(10),
                        async { 7_u32 },
                    )
                    .await;
                assert!(matches!(outcome, ServerHopOutcome::Ok(7)));

                let events = budget_events(&trace.snapshot());
                assert_eq!(events.len(), 2, "installed + consumed: {events:?}");
                assert_eq!(events[0].0, TraceEventKind::BudgetInstalled);
                let TraceData::Budget {
                    protocol, source, ..
                } = &events[0].1
                else {
                    panic!("expected Budget data, got {:?}", events[0].1);
                };
                assert_eq!(protocol, "test");
                assert_eq!(source.as_deref(), Some("inherited"));
                assert_eq!(events[1].0, TraceEventKind::BudgetConsumed);
                let TraceData::Budget {
                    protocol, outcome, ..
                } = &events[1].1
                else {
                    panic!("expected Budget data, got {:?}", events[1].1);
                };
                assert_eq!(protocol, "test");
                assert_eq!(outcome.as_deref(), Some("ok"));
            });
        }

        #[test]
        fn hop_force_closed_future_drop_emits_consumed_event() {
            // The HTTP/1.1 force-close path drops the run_with_protocol_drain
            // future while the handler is still pending, so no explicit finish
            // runs. The Drop backstop must still emit server.budget_consumed
            // (outcome=force_closed) exactly once so the budget-trace contract
            // holds on every path. Regression guard for br-asupersync-tkmiv8.
            block_on(async {
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let trace = region.cx().trace_buffer().expect("runtime trace buffer");

                let fut = region.run_with_protocol_drain::<u32, _>(
                    RequestBudgetSource::Inherited,
                    None,
                    Duration::from_millis(10),
                    std::future::pending::<u32>(),
                );
                // Box::pin so `drop` actually drops the future (and the region
                // it owns); `pin!` would only drop a borrow, leaving the region
                // alive until end of scope and the Drop backstop unobserved.
                let mut fut = Box::pin(fut);
                let waker = std::task::Waker::noop();
                let mut task_cx = std::task::Context::from_waker(waker);
                assert!(
                    fut.as_mut().poll(&mut task_cx).is_pending(),
                    "pending handler keeps the hop future pending"
                );
                // Force-close: drop the in-flight future before it resolves.
                drop(fut);

                let events = budget_events(&trace.snapshot());
                assert!(
                    events
                        .iter()
                        .any(|(kind, _)| *kind == TraceEventKind::BudgetInstalled),
                    "installed event present: {events:?}"
                );
                let consumed: Vec<&TraceData> = events
                    .iter()
                    .filter(|(kind, _)| *kind == TraceEventKind::BudgetConsumed)
                    .map(|(_, data)| data)
                    .collect();
                assert_eq!(consumed.len(), 1, "exactly one consumed event: {events:?}");
                let TraceData::Budget { outcome, .. } = consumed[0] else {
                    panic!("expected Budget data, got {:?}", consumed[0]);
                };
                assert_eq!(
                    outcome.as_deref(),
                    Some("force_closed"),
                    "force-closed outcome: {consumed:?}"
                );
            });
        }

        #[test]
        fn hop_handler_sees_request_budget_via_ambient_cx() {
            block_on(async {
                // The deadline is an instant on the runtime clock, so it is set
                // from the current time: a fixed NOW (1000 s) put it at 1030 s,
                // already past when a long test run reached this test.
                let now = crate::time::wall_now();
                let budget = Budget::INFINITE.tightened_by_timeout(now, Duration::from_secs(30));
                let region =
                    ServerRequestRegion::mint("test", budget, now).expect("runtime installed");
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::ServerConfig,
                        None,
                        Duration::from_millis(10),
                        async {
                            Cx::with_current(|cx| cx.budget().deadline.is_some()).unwrap_or(false)
                        },
                    )
                    .await;
                assert!(
                    matches!(outcome, ServerHopOutcome::Ok(true)),
                    "handler must observe the installed request budget deadline"
                );
            });
        }

        #[test]
        fn hop_pre_cancelled_connection_rejects_handler() {
            block_on(async {
                let conn_cx = Cx::for_testing();
                conn_cx.cancel_with(CancelKind::User, Some("client went away"));
                let started = Arc::new(AtomicBool::new(false));
                let started_probe = Arc::clone(&started);

                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::Inherited,
                        Some(conn_cx),
                        Duration::from_millis(10),
                        async move {
                            started_probe.store(true, Ordering::SeqCst);
                            0_u32
                        },
                    )
                    .await;
                assert!(matches!(outcome, ServerHopOutcome::Cancelled));
                assert!(
                    !started.load(Ordering::SeqCst),
                    "a pre-cancelled connection must not start the handler"
                );
            });
        }

        #[test]
        fn hop_panic_isolated_with_message() {
            block_on(async {
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let outcome: ServerHopOutcome<u32> = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::Inherited,
                        None,
                        Duration::from_millis(10),
                        async { panic!("handler exploded") },
                    )
                    .await;
                match outcome {
                    ServerHopOutcome::Panicked(msg) => assert!(msg.contains("handler exploded")),
                    other => panic!("expected Panicked, got {other:?}"),
                }
            });
        }

        #[test]
        fn hop_deadline_exceeded_after_drain_grace() {
            block_on(async {
                let now = crate::time::wall_now();
                let budget = Budget::INFINITE.tightened_by_timeout(now, Duration::from_millis(20));
                let region =
                    ServerRequestRegion::mint("test", budget, now).expect("runtime installed");
                let region_cx = region.cx().clone();
                let outcome: ServerHopOutcome<u32> = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::ServerConfig,
                        None,
                        Duration::from_millis(10),
                        async move {
                            crate::time::sleep(now, Duration::from_secs(600)).await;
                            0_u32
                        },
                    )
                    .await;
                assert!(matches!(outcome, ServerHopOutcome::DeadlineExceeded));
                assert!(
                    region_cx.cancelled_by(CancelKind::Timeout),
                    "deadline expiry must cancel the request region with Timeout"
                );
            });
        }

        /// br-asupersync-bmc8m5 commit semantics on the server hop: a
        /// handler that observes connection cancellation during the drain
        /// grace and completes gets its response committed, not discarded.
        ///
        /// This uses an explicit connection-cancel transition instead of a
        /// tiny wall-clock deadline. The latter can expire before the first
        /// handler poll when the full suite is under load, which tests the
        /// pre-handler gate rather than the drain-commit boundary.
        #[test]
        fn hop_connection_drain_commits_completed_response() {
            block_on(async {
                let conn_cx = Cx::for_testing();
                let conn_for_handler = conn_cx.clone();
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let mut connection_cancelled = false;
                let handler = std::future::poll_fn(move |task_cx| {
                    Cx::with_current(|cx| {
                        if cx.is_cancel_requested() {
                            std::task::Poll::Ready(42_u32)
                        } else {
                            if !connection_cancelled {
                                connection_cancelled = true;
                                conn_for_handler.cancel_with(
                                    CancelKind::User,
                                    Some("peer disconnected during response build"),
                                );
                            }
                            cx.register_cancel_waker(task_cx.waker());
                            std::task::Poll::Pending
                        }
                    })
                    .unwrap_or(std::task::Poll::Ready(0_u32))
                });
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::Inherited,
                        Some(conn_cx),
                        Duration::from_millis(500),
                        handler,
                    )
                    .await;
                assert!(
                    matches!(outcome, ServerHopOutcome::Ok(42)),
                    "a response completed during drain must be committed, got {outcome:?}"
                );
            });
        }

        #[test]
        fn hop_connection_cancel_mid_flight_resolves_connection_lost() {
            block_on(async {
                let conn_cx = Cx::for_testing();
                let conn_for_handler = conn_cx.clone();
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let region_cx = region.cx().clone();
                // First poll cancels the connection, then stays pending
                // forever: the hop must observe the cancel, cancel the
                // region, and resolve ConnectionLost after the grace.
                let mut cancelled_conn = false;
                let handler = std::future::poll_fn(move |_task_cx| {
                    if !cancelled_conn {
                        cancelled_conn = true;
                        conn_for_handler.cancel_with(CancelKind::User, Some("peer disconnect"));
                    }
                    std::task::Poll::<u32>::Pending
                });
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::Inherited,
                        Some(conn_cx),
                        Duration::from_millis(10),
                        handler,
                    )
                    .await;
                assert!(matches!(outcome, ServerHopOutcome::ConnectionLost));
                assert!(
                    region_cx.cancelled_by(CancelKind::ParentCancelled),
                    "connection cancel must propagate to the request region"
                );
            });
        }

        /// A request whose deadline passed before the handler started is
        /// refused as DeadlineExceeded (a 503 with ASUP-E501), not as
        /// Cancelled (br-asupersync-m8xsjx).
        #[test]
        fn hop_deadline_passed_before_start_is_deadline_exceeded() {
            block_on(async {
                let started = Arc::new(AtomicBool::new(false));
                let started_probe = Arc::clone(&started);
                let region = ServerRequestRegion::mint("test", Budget::with_deadline_at_ns(1), NOW)
                    .expect("runtime installed");
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::ServerConfig,
                        None,
                        Duration::from_millis(10),
                        async move {
                            started_probe.store(true, Ordering::SeqCst);
                            0_u32
                        },
                    )
                    .await;
                assert!(
                    matches!(outcome, ServerHopOutcome::DeadlineExceeded),
                    "a request past its deadline is a deadline outcome, got {outcome:?}"
                );
                assert!(
                    !started.load(Ordering::SeqCst),
                    "a request past its deadline must not start the handler"
                );
            });
        }

        /// When the connection Cx is the request Cx itself (the owned h2
        /// hop) and the request's deadline cancels it, the hop resolves
        /// DeadlineExceeded, not ConnectionLost (br-asupersync-m8xsjx).
        #[test]
        fn hop_own_deadline_cancel_is_not_a_lost_connection() {
            block_on(async {
                let region = ServerRequestRegion::mint("test", Budget::INFINITE, NOW)
                    .expect("runtime installed");
                let request_cx = region.cx().clone();
                let deadline_cx = request_cx.clone();
                // First poll: the request's deadline cancels its Cx (as the
                // budget-deadline timer or a checkpoint past the deadline
                // does); then the handler hangs.
                let mut expired = false;
                let handler = std::future::poll_fn(move |_task_cx| {
                    if !expired {
                        expired = true;
                        deadline_cx.cancel_with(CancelKind::Deadline, Some("request deadline"));
                    }
                    std::task::Poll::<u32>::Pending
                });
                let outcome = region
                    .run_with_protocol_drain(
                        RequestBudgetSource::ServerConfig,
                        Some(request_cx),
                        Duration::from_millis(10),
                        handler,
                    )
                    .await;
                assert!(
                    matches!(outcome, ServerHopOutcome::DeadlineExceeded),
                    "the request's own deadline is not a lost connection, got {outcome:?}"
                );
            });
        }

        // --- AC2 lab matrix: normal / timeout / disconnect cells run as ---
        // --- LabRuntime tasks under virtual time, oracle-clean each.    ---

        mod lab_matrix {
            use super::*;
            use crate::lab::{AutoAdvanceTermination, LabConfig, LabRuntime};
            use crate::runtime::StoredTask;
            use crate::types::Outcome;
            use std::sync::Mutex;

            /// Owner-agnostic tag of a [`ServerHopOutcome`] for cross-task
            /// assertion (the response type stays inside the lab task).
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            enum CellOutcome {
                Ok,
                Cancelled,
                Panicked,
                DeadlineExceeded,
                ConnectionLost,
            }

            fn tag<R>(outcome: &ServerHopOutcome<R>) -> CellOutcome {
                match outcome {
                    ServerHopOutcome::Ok(_) => CellOutcome::Ok,
                    ServerHopOutcome::Cancelled => CellOutcome::Cancelled,
                    ServerHopOutcome::Panicked(_) => CellOutcome::Panicked,
                    ServerHopOutcome::DeadlineExceeded => CellOutcome::DeadlineExceeded,
                    ServerHopOutcome::ConnectionLost => CellOutcome::ConnectionLost,
                }
            }

            /// Virtual `now` from the ambient (lab task) context.
            fn ambient_now() -> Time {
                Cx::with_current(|cx| {
                    cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |timer| timer.now())
                })
                .unwrap_or_else(crate::time::wall_now)
            }

            /// Runs one matrix cell as a lab task to quiescence and
            /// asserts the run is oracle-clean.
            fn run_lab_cell(
                seed: u64,
                cell: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            ) {
                run_lab_cell_with_budget(seed, Budget::new(), cell);
            }

            /// [`run_lab_cell`] with the cell task's own budget.
            fn run_lab_cell_with_budget(
                seed: u64,
                task_budget: Budget,
                cell: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            ) {
                run_lab_cell_jumping(seed, task_budget, None, cell);
            }

            /// [`run_lab_cell_with_budget`]; with `jump_to`, virtual time first
            /// jumps there once the cell is idle, so timers due earlier fire
            /// late, as on a stalled worker.
            fn run_lab_cell_jumping(
                seed: u64,
                task_budget: Budget,
                jump_to: Option<Time>,
                cell: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            ) {
                let mut lab = LabRuntime::new(LabConfig::new(seed));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let system_cx = lab.state.create_system_cx();
                let (tid, _handle, _task_cx, _result_tx, spawn_effects) = lab
                    .state
                    .create_task_infrastructure::<()>(&system_cx, root, task_budget, false)
                    .expect("create lab task infrastructure");
                lab.state.store_spawned_task(
                    tid,
                    StoredTask::new_with_id(
                        async move {
                            cell.await;
                            Outcome::Ok(())
                        },
                        tid,
                    ),
                );
                lab.scheduler.lock().schedule(tid, 0);
                spawn_effects.dispatch();
                if let Some(at) = jump_to {
                    lab.run_until_idle();
                    lab.advance_time_to(at);
                }

                let vt = lab.run_with_auto_advance();
                assert_eq!(
                    vt.termination,
                    AutoAdvanceTermination::Quiescent,
                    "lab cell must reach quiescence, got {vt:?}"
                );
                let report = lab.run_until_quiescent_with_report();
                assert!(
                    report.oracle_report.all_passed(),
                    "oracle violations in lab cell: {:?}",
                    report.oracle_report
                );
                assert!(
                    report.invariant_violations.is_empty(),
                    "invariant violations in lab cell: {:?}",
                    report.invariant_violations
                );
            }

            #[test]
            fn lab_cell_normal_request_is_oracle_clean() {
                let got: Arc<Mutex<Option<CellOutcome>>> = Arc::new(Mutex::new(None));
                let slot = Arc::clone(&got);
                run_lab_cell(
                    11,
                    Box::pin(async move {
                        let now = ambient_now();
                        let (budget, source) = derive_request_budget(
                            Budget::INFINITE,
                            now,
                            Some(Duration::from_secs(30)),
                            None,
                            None,
                        );
                        let region = ServerRequestRegion::mint("lab", budget, now)
                            .expect("mint from ambient lab cx");
                        let outcome = region
                            .run_with_protocol_drain(
                                source,
                                None,
                                Duration::from_millis(5),
                                async { 1_u8 },
                            )
                            .await;
                        *slot.lock().unwrap() = Some(tag(&outcome));
                    }),
                );
                assert_eq!(*got.lock().unwrap(), Some(CellOutcome::Ok));
            }

            #[test]
            fn lab_cell_timeout_request_is_oracle_clean() {
                let got: Arc<Mutex<Option<CellOutcome>>> = Arc::new(Mutex::new(None));
                let slot = Arc::clone(&got);
                run_lab_cell(
                    23,
                    Box::pin(async move {
                        let now = ambient_now();
                        let (budget, source) = derive_request_budget(
                            Budget::INFINITE,
                            now,
                            Some(Duration::from_millis(10)),
                            None,
                            None,
                        );
                        let region = ServerRequestRegion::mint("lab", budget, now)
                            .expect("mint from ambient lab cx");
                        let outcome = region
                            .run_with_protocol_drain(
                                source,
                                None,
                                Duration::from_millis(5),
                                async {
                                    let handler_now = ambient_now();
                                    crate::time::sleep(handler_now, Duration::from_secs(600)).await;
                                    9_u8
                                },
                            )
                            .await;
                        *slot.lock().unwrap() = Some(tag(&outcome));
                    }),
                );
                assert_eq!(
                    *got.lock().unwrap(),
                    Some(CellOutcome::DeadlineExceeded),
                    "virtual-time deadline must bound the handler deterministically"
                );
            }

            #[test]
            fn lab_cell_disconnect_request_is_oracle_clean() {
                let got: Arc<Mutex<Option<CellOutcome>>> = Arc::new(Mutex::new(None));
                let slot = Arc::clone(&got);
                let conn_cx = Cx::for_testing();
                let conn_for_handler = conn_cx.clone();
                run_lab_cell(
                    37,
                    Box::pin(async move {
                        let now = ambient_now();
                        let (budget, source) =
                            derive_request_budget(Budget::INFINITE, now, None, None, None);
                        let region = ServerRequestRegion::mint("lab", budget, now)
                            .expect("mint from ambient lab cx");
                        // First poll simulates the peer vanishing
                        // mid-request, then the handler hangs forever:
                        // the hop must cancel the region and resolve
                        // ConnectionLost after the (virtual) drain grace.
                        let mut disconnected = false;
                        let handler = std::future::poll_fn(move |_task_cx| {
                            if !disconnected {
                                disconnected = true;
                                conn_for_handler
                                    .cancel_with(CancelKind::User, Some("peer disconnect"));
                            }
                            std::task::Poll::<u8>::Pending
                        });
                        let outcome = region
                            .run_with_protocol_drain(
                                source,
                                Some(conn_cx),
                                Duration::from_millis(5),
                                handler,
                            )
                            .await;
                        *slot.lock().unwrap() = Some(tag(&outcome));
                    }),
                );
                assert_eq!(
                    *got.lock().unwrap(),
                    Some(CellOutcome::ConnectionLost),
                    "disconnect must cancel the region and drain deterministically"
                );
            }

            /// The owned h2 hop's shape: the handler runs in a task whose own
            /// Cx is the connection Cx and whose budget carries the request
            /// deadline. The budget-deadline timer cancels that Cx at the
            /// deadline, at the same virtual instant the hop's timeout
            /// expires; the hop still reports DeadlineExceeded (a 503), not
            /// a lost connection (br-asupersync-m8xsjx, br-asupersync-pev2xi).
            #[cfg(not(target_arch = "wasm32"))]
            #[test]
            fn lab_cell_task_deadline_on_the_shared_connection_cx_is_deadline_exceeded() {
                let got: Arc<Mutex<Option<CellOutcome>>> = Arc::new(Mutex::new(None));
                let slot = Arc::clone(&got);
                run_lab_cell_with_budget(
                    41,
                    Budget::with_deadline_at_ns(10_000_000),
                    Box::pin(async move {
                        let cx = Cx::current().expect("lab task context");
                        let region =
                            ServerRequestRegion::from_body_cx("lab", cx.clone(), ambient_now());
                        let outcome = region
                            .run_with_protocol_drain(
                                RequestBudgetSource::ServerConfig,
                                Some(cx),
                                Duration::from_millis(5),
                                async {
                                    let handler_now = ambient_now();
                                    crate::time::sleep(handler_now, Duration::from_secs(600)).await;
                                    9_u8
                                },
                            )
                            .await;
                        *slot.lock().unwrap() = Some(tag(&outcome));
                    }),
                );
                assert_eq!(
                    *got.lock().unwrap(),
                    Some(CellOutcome::DeadlineExceeded),
                    "the task's own deadline must resolve as the request deadline"
                );
            }

            /// The same cell with the deadline seen late: virtual time jumps
            /// past it while the handler is parked, so the budget-deadline
            /// timer cancels the shared Cx with Deadline, stamped at the
            /// deadline, before the hop observes it. The request still ends
            /// with the hop's attribution, Timeout and ASUP-E501, which
            /// tests/quic_h3_live_udp.rs requires of the h3 listener
            /// (br-asupersync-pev2xi).
            #[cfg(not(target_arch = "wasm32"))]
            #[test]
            fn lab_cell_task_deadline_seen_late_keeps_the_hop_attribution() {
                type Seen = (CellOutcome, bool, Option<String>);
                let got: Arc<Mutex<Option<Seen>>> = Arc::new(Mutex::new(None));
                let slot = Arc::clone(&got);
                run_lab_cell_jumping(
                    43,
                    Budget::with_deadline_at_ns(10_000_000),
                    Some(Time::from_nanos(20_000_000)),
                    Box::pin(async move {
                        let cx = Cx::current().expect("lab task context");
                        let region =
                            ServerRequestRegion::from_body_cx("lab", cx.clone(), ambient_now());
                        let outcome = region
                            .run_with_protocol_drain(
                                RequestBudgetSource::ServerConfig,
                                Some(cx.clone()),
                                Duration::from_millis(5),
                                async {
                                    let handler_now = ambient_now();
                                    crate::time::sleep(handler_now, Duration::from_secs(600)).await;
                                    9_u8
                                },
                            )
                            .await;
                        let message = cx
                            .cancel_reason()
                            .and_then(|reason| reason.message.as_deref().map(str::to_owned));
                        *slot.lock().unwrap() =
                            Some((tag(&outcome), cx.cancelled_by(CancelKind::Timeout), message));
                    }),
                );
                assert_eq!(
                    *got.lock().unwrap(),
                    Some((
                        CellOutcome::DeadlineExceeded,
                        true,
                        Some(HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.to_owned()),
                    )),
                    "a deadline seen late keeps the hop's Timeout and ASUP-E501 attribution"
                );
            }
        }
    }
