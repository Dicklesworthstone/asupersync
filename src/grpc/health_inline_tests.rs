    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_json_snapshot;
    use serde_json::json;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn health_response_snapshot(service: &HealthService, query: &str) -> serde_json::Value {
        let request = if query.is_empty() {
            HealthCheckRequest::server()
        } else {
            HealthCheckRequest::new(query)
        };
        let response = service
            .check(&request)
            .expect("health snapshot queries should succeed");

        json!({
            "query": request.service,
            "status_code": response.status as i32,
            "status_text": response.status.to_string(),
        })
    }

    #[derive(Default)]
    struct CountingWake {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: &Arc<CountingWake>) -> Waker {
        Waker::from(counter.clone())
    }

    fn authed_health_request(service: &str) -> Request<HealthCheckRequest> {
        let mut request = Request::new(HealthCheckRequest::new(service));
        let inserted = request
            .metadata_mut()
            .insert("authorization", "Bearer test-token");
        crate::assert_with_log!(inserted, "test auth metadata inserted", true, inserted);
        request
    }

    fn bearer_token_health_service() -> HealthService {
        HealthService::with_auth_mode(HealthAuthMode::bearer_token("test-token"))
    }

    fn health_auth_token_request(
        service: &str,
        key: &str,
        value: &str,
    ) -> Request<HealthCheckRequest> {
        let mut request = Request::new(HealthCheckRequest::new(service));
        let inserted = request.metadata_mut().insert(key, value);
        crate::assert_with_log!(inserted, "test auth metadata inserted", true, inserted);
        request
    }

    #[test]
    fn serving_status_from_i32() {
        init_test("serving_status_from_i32");
        crate::assert_with_log!(
            ServingStatus::from_i32(0) == Some(ServingStatus::Unknown),
            "0",
            Some(ServingStatus::Unknown),
            ServingStatus::from_i32(0)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(1) == Some(ServingStatus::Serving),
            "1",
            Some(ServingStatus::Serving),
            ServingStatus::from_i32(1)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(2) == Some(ServingStatus::NotServing),
            "2",
            Some(ServingStatus::NotServing),
            ServingStatus::from_i32(2)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(3) == Some(ServingStatus::ServiceUnknown),
            "3",
            Some(ServingStatus::ServiceUnknown),
            ServingStatus::from_i32(3)
        );
        let none = ServingStatus::from_i32(4).is_none();
        crate::assert_with_log!(none, "4 none", true, none);
        crate::test_complete!("serving_status_from_i32");
    }

    #[test]
    fn serving_status_is_healthy() {
        init_test("serving_status_is_healthy");
        let unknown = ServingStatus::Unknown.is_healthy();
        crate::assert_with_log!(!unknown, "unknown healthy", false, unknown);
        let serving = ServingStatus::Serving.is_healthy();
        crate::assert_with_log!(serving, "serving healthy", true, serving);
        let not_serving = ServingStatus::NotServing.is_healthy();
        crate::assert_with_log!(!not_serving, "not serving healthy", false, not_serving);
        let service_unknown = ServingStatus::ServiceUnknown.is_healthy();
        crate::assert_with_log!(
            !service_unknown,
            "service unknown healthy",
            false,
            service_unknown
        );
        crate::test_complete!("serving_status_is_healthy");
    }

    #[test]
    fn serving_status_display() {
        init_test("serving_status_display");
        let serving = ServingStatus::Serving.to_string();
        crate::assert_with_log!(serving == "SERVING", "serving", "SERVING", serving);
        let not_serving = ServingStatus::NotServing.to_string();
        crate::assert_with_log!(
            not_serving == "NOT_SERVING",
            "not serving",
            "NOT_SERVING",
            not_serving
        );
        crate::test_complete!("serving_status_display");
    }

    #[test]
    fn health_service_set_and_get() {
        init_test("health_service_set_and_get");
        let service = HealthService::new();

        service.set_status("test.Service", ServingStatus::Serving);
        let status = service.get_status("test.Service");
        crate::assert_with_log!(
            status == Some(ServingStatus::Serving),
            "serving",
            Some(ServingStatus::Serving),
            status
        );

        service.set_status("test.Service", ServingStatus::NotServing);
        let status = service.get_status("test.Service");
        crate::assert_with_log!(
            status == Some(ServingStatus::NotServing),
            "not serving",
            Some(ServingStatus::NotServing),
            status
        );
        crate::test_complete!("health_service_set_and_get");
    }

    #[test]
    fn health_service_is_serving() {
        init_test("health_service_is_serving");
        let service = HealthService::new();

        let unknown = service.is_serving("unknown");
        crate::assert_with_log!(!unknown, "unknown not serving", false, unknown);

        service.set_status("test", ServingStatus::Serving);
        let serving = service.is_serving("test");
        crate::assert_with_log!(serving, "test serving", true, serving);

        service.set_status("test", ServingStatus::NotServing);
        let serving = service.is_serving("test");
        crate::assert_with_log!(!serving, "test not serving", false, serving);
        crate::test_complete!("health_service_is_serving");
    }

    #[test]
    fn health_service_check() {
        init_test("health_service_check");
        let service = HealthService::new();
        service.set_status("test.Service", ServingStatus::Serving);

        let req = HealthCheckRequest::new("test.Service");
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "serving",
            ServingStatus::Serving,
            resp.status
        );

        let req = HealthCheckRequest::new("unknown.Service");
        let err = service.check(&req).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == super::super::status::Code::PermissionDenied,
            "unknown service is hidden from enumeration",
            super::super::status::Code::PermissionDenied,
            code
        );
        crate::test_complete!("health_service_check");
    }

    #[test]
    fn health_service_server_status() {
        init_test("health_service_server_status");
        let service = HealthService::new();

        // No services registered
        let req = HealthCheckRequest::server();
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::ServiceUnknown,
            "service unknown",
            ServingStatus::ServiceUnknown,
            resp.status
        );

        // Add a healthy service
        service.set_status("test", ServingStatus::Serving);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "serving",
            ServingStatus::Serving,
            resp.status
        );

        // Add an unhealthy service
        service.set_status("test2", ServingStatus::NotServing);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::NotServing,
            "not serving",
            ServingStatus::NotServing,
            resp.status
        );

        // Explicit server status overrides
        service.set_server_status(ServingStatus::Serving);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "server serving",
            ServingStatus::Serving,
            resp.status
        );
        crate::test_complete!("health_service_server_status");
    }

    #[test]
    fn health_check_response_statuses_snapshot() {
        init_test("health_check_response_statuses_snapshot");
        let service = HealthService::new();
        service.set_server_status(ServingStatus::Unknown);
        service.set_status("svc.serving", ServingStatus::Serving);
        service.set_status("svc.not_serving", ServingStatus::NotServing);
        service.set_status("svc.unknown", ServingStatus::Unknown);

        let snapshot = json!({
            "server": health_response_snapshot(&service, ""),
            "service_queries": [
                health_response_snapshot(&service, "svc.serving"),
                health_response_snapshot(&service, "svc.not_serving"),
                health_response_snapshot(&service, "svc.unknown"),
            ],
        });

        assert_json_snapshot!("health_check_response_statuses", snapshot);
        crate::test_complete!("health_check_response_statuses_snapshot");
    }

    #[test]
    fn health_service_clear() {
        init_test("health_service_clear");
        let service = HealthService::new();
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::Serving);

        service.clear_status("a");
        let a_none = service.get_status("a").is_none();
        crate::assert_with_log!(a_none, "a cleared", true, a_none);
        let b_some = service.get_status("b").is_some();
        crate::assert_with_log!(b_some, "b still set", true, b_some);

        service.clear();
        let b_none = service.get_status("b").is_none();
        crate::assert_with_log!(b_none, "b cleared", true, b_none);
        crate::test_complete!("health_service_clear");
    }

    #[test]
    fn health_auth_mode_default_requires_auth_for_async_endpoints() {
        init_test("health_auth_mode_default_requires_auth_for_async_endpoints");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check_err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("default auth mode must reject unauthenticated Check");
        let watch_err = futures_lite::future::block_on(service.watch_async(&request))
            .expect_err("default auth mode must reject unauthenticated Watch");

        crate::assert_with_log!(
            check_err.code() == super::super::status::Code::Unauthenticated,
            "default check code",
            super::super::status::Code::Unauthenticated,
            check_err.code()
        );
        crate::assert_with_log!(
            watch_err.code() == super::super::status::Code::Unauthenticated,
            "default watch code",
            super::super::status::Code::Unauthenticated,
            watch_err.code()
        );
        crate::assert_with_log!(
            check_err.message() == "health check endpoint requires configured authentication",
            "default check message",
            "health check endpoint requires configured authentication",
            check_err.message()
        );
        crate::assert_with_log!(
            watch_err.message() == "health check endpoint requires configured authentication",
            "default watch message",
            "health check endpoint requires configured authentication",
            watch_err.message()
        );

        let arbitrary_bearer = authed_health_request("svc");
        let token_err = futures_lite::future::block_on(service.check_async(&arbitrary_bearer))
            .expect_err("default RequireAuth must not accept arbitrary bearer tokens");
        crate::assert_with_log!(
            token_err.message() == "health check endpoint requires configured authentication",
            "default arbitrary bearer message",
            "health check endpoint requires configured authentication",
            token_err.message()
        );
        crate::test_complete!("health_auth_mode_default_requires_auth_for_async_endpoints");
    }

    #[test]
    fn health_auth_mode_bearer_token_requires_exact_secret() {
        init_test("health_auth_mode_bearer_token_requires_exact_secret");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let allowed = authed_health_request("svc");
        let check = futures_lite::future::block_on(service.check_async(&allowed))
            .expect("configured bearer token must allow Check");
        let allowed_status = check.into_inner().status;
        crate::assert_with_log!(
            allowed_status == ServingStatus::Serving,
            "configured bearer token check status",
            ServingStatus::Serving,
            allowed_status
        );

        let wrong = health_auth_token_request("svc", "authorization", "Bearer wrong-token");
        let err = futures_lite::future::block_on(service.watch_async(&wrong))
            .expect_err("wrong bearer token must fail closed");
        crate::assert_with_log!(
            err.message() == "invalid bearer token",
            "wrong bearer token rejected",
            "invalid bearer token",
            err.message()
        );
        crate::test_complete!("health_auth_mode_bearer_token_requires_exact_secret");
    }

    #[test]
    fn health_auth_mode_none_allows_async_check_and_watch_without_metadata() {
        init_test("health_auth_mode_none_allows_async_check_and_watch_without_metadata");
        let service = HealthService::with_auth_mode(HealthAuthMode::None);
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check = futures_lite::future::block_on(service.check_async(&request))
            .expect("auth mode None must allow Check without metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "none auth check status",
            ServingStatus::Serving,
            check_status
        );

        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("auth mode None must allow Watch without metadata");
        let mut stream = response.into_inner();
        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "none auth watch first item",
            true,
            format!("{first:?}")
        );
        crate::test_complete!(
            "health_auth_mode_none_allows_async_check_and_watch_without_metadata"
        );
    }

    #[test]
    fn health_auth_mode_custom_validator_controls_check_and_watch() {
        init_test("health_auth_mode_custom_validator_controls_check_and_watch");
        let validator_calls = Arc::new(AtomicUsize::new(0));
        let validator_calls_for_closure = Arc::clone(&validator_calls);
        let service = HealthService::with_auth_mode(HealthAuthMode::Custom(Arc::new(
            move |metadata: &Metadata, method: &str| {
                validator_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                let Some(super::super::streaming::MetadataValue::Ascii(token)) =
                    metadata.get("x-health-token")
                else {
                    return Err(Status::permission_denied(format!("{method} denied")));
                };
                if token == "allow" {
                    Ok(())
                } else {
                    Err(Status::permission_denied(format!("{method} denied")))
                }
            },
        )));
        service.set_status("svc", ServingStatus::Serving);

        let allowed = health_auth_token_request("svc", "x-health-token", "allow");
        let check = futures_lite::future::block_on(service.check_async(&allowed))
            .expect("custom validator must allow matching Check metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "custom auth check status",
            ServingStatus::Serving,
            check_status
        );

        let denied = health_auth_token_request("svc", "x-health-token", "deny");
        let watch_err = futures_lite::future::block_on(service.watch_async(&denied))
            .expect_err("custom validator must reject denied Watch metadata");
        crate::assert_with_log!(
            watch_err.code() == super::super::status::Code::PermissionDenied,
            "custom watch code",
            super::super::status::Code::PermissionDenied,
            watch_err.code()
        );
        crate::assert_with_log!(
            watch_err.message() == "Watch denied",
            "custom watch message",
            "Watch denied",
            watch_err.message()
        );
        crate::assert_with_log!(
            validator_calls.load(Ordering::SeqCst) == 2,
            "custom validator called once per async endpoint",
            2,
            validator_calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("health_auth_mode_custom_validator_controls_check_and_watch");
    }

    #[test]
    fn health_auth_mode_builder_propagates_configured_mode() {
        init_test("health_auth_mode_builder_propagates_configured_mode");
        let service = HealthServiceBuilder::new()
            .auth_mode(HealthAuthMode::None)
            .add("svc", ServingStatus::Serving)
            .build();

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check = futures_lite::future::block_on(service.check_async(&request))
            .expect("builder auth mode None must allow Check without metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "builder none auth check status",
            ServingStatus::Serving,
            check_status
        );
        crate::test_complete!("health_auth_mode_builder_propagates_configured_mode");
    }

    #[test]
    fn health_version_only_tracks_real_changes() {
        init_test("health_version_only_tracks_real_changes");
        let service = HealthService::new();

        let v0 = service.version();
        service.clear();
        crate::assert_with_log!(
            service.version() == v0,
            "clear empty is no-op",
            v0,
            service.version()
        );
        service.clear_status("missing");
        crate::assert_with_log!(
            service.version() == v0,
            "clear missing is no-op",
            v0,
            service.version()
        );

        service.set_status("svc", ServingStatus::Serving);
        let v1 = service.version();
        crate::assert_with_log!(v1 > v0, "initial set increments", true, v1 > v0);

        service.set_status("svc", ServingStatus::Serving);
        crate::assert_with_log!(
            service.version() == v1,
            "idempotent set does not increment",
            v1,
            service.version()
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            service.version() > v1,
            "real status transition increments",
            true,
            service.version() > v1
        );
        crate::test_complete!("health_version_only_tracks_real_changes");
    }

    #[test]
    fn health_watcher_ignores_unrelated_service_changes() {
        init_test("health_watcher_ignores_unrelated_service_changes");
        let service = HealthService::new();
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::Serving);

        let mut watcher_a = service.watch("a");
        let mut watcher_b = service.watch("b");

        service.set_status("a", ServingStatus::NotServing);

        let changed_a = watcher_a.changed();
        crate::assert_with_log!(changed_a, "watcher a sees change", true, changed_a);

        let changed_b = watcher_b.changed();
        crate::assert_with_log!(
            !changed_b,
            "watcher b ignores unrelated change",
            false,
            changed_b
        );
        crate::assert_with_log!(
            watcher_b.status() == ServingStatus::Serving,
            "watcher b status unchanged",
            ServingStatus::Serving,
            watcher_b.status()
        );
        crate::test_complete!("health_watcher_ignores_unrelated_service_changes");
    }

    #[test]
    fn health_watcher_unknown_service_reports_service_unknown() {
        init_test("health_watcher_unknown_service_reports_service_unknown");
        let service = HealthService::new();
        let mut watcher = service.watch("missing");

        crate::assert_with_log!(
            watcher.status() == ServingStatus::ServiceUnknown,
            "unknown service reports watch sentinel",
            ServingStatus::ServiceUnknown,
            watcher.status()
        );
        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(!changed, "initial unknown poll is stable", false, changed);
        crate::assert_with_log!(
            status == ServingStatus::ServiceUnknown,
            "poll_status reports service unknown",
            ServingStatus::ServiceUnknown,
            status
        );

        service.set_status("missing", ServingStatus::Serving);
        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(changed, "registration is observed", true, changed);
        crate::assert_with_log!(
            status == ServingStatus::Serving,
            "watcher sees serving after registration",
            ServingStatus::Serving,
            status
        );
        crate::test_complete!("health_watcher_unknown_service_reports_service_unknown");
    }

    #[test]
    fn health_watcher_reports_named_service_transient_round_trip() {
        init_test("health_watcher_reports_named_service_transient_round_trip");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let mut changed_watcher = service.watch("svc");
        let mut poll_watcher = service.watch("svc");

        service.set_status("svc", ServingStatus::NotServing);
        service.set_status("svc", ServingStatus::Serving);

        let changed = changed_watcher.changed();
        crate::assert_with_log!(
            changed,
            "changed() observes transient round trip",
            true,
            changed
        );
        crate::assert_with_log!(
            changed_watcher.status() == ServingStatus::Serving,
            "effective status returns to serving",
            ServingStatus::Serving,
            changed_watcher.status()
        );

        let (poll_changed, polled_status) = poll_watcher.poll_status();
        crate::assert_with_log!(
            poll_changed,
            "poll_status observes transient round trip",
            true,
            poll_changed
        );
        crate::assert_with_log!(
            polled_status == ServingStatus::Serving,
            "poll_status reports current effective status",
            ServingStatus::Serving,
            polled_status
        );
        crate::test_complete!("health_watcher_reports_named_service_transient_round_trip");
    }

    #[test]
    fn health_watcher_reports_server_transient_round_trip() {
        init_test("health_watcher_reports_server_transient_round_trip");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let mut watcher = service.watch("");

        service.set_status("svc", ServingStatus::NotServing);
        service.set_status("svc", ServingStatus::Serving);

        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(
            changed,
            "server watcher observes aggregate transient round trip",
            true,
            changed
        );
        crate::assert_with_log!(
            status == ServingStatus::Serving,
            "server watcher reports recovered aggregate status",
            ServingStatus::Serving,
            status
        );
        crate::test_complete!("health_watcher_reports_server_transient_round_trip");
    }

    #[test]
    fn health_watch_initial_snapshot_is_atomic_for_named_services() {
        init_test("health_watch_initial_snapshot_is_atomic_for_named_services");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let version_guard = service.watch_versions.write();
        let watch_service = service.clone();
        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let watcher = watch_service.watch("svc");
            watcher_tx.send(watcher).unwrap();
        });

        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut status_lock_held = false;
        while std::time::Instant::now() < wait_deadline {
            if service.statuses.try_write().is_none() {
                status_lock_held = true;
                break;
            }
            std::thread::yield_now();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        crate::assert_with_log!(
            status_lock_held,
            "watch constructor must hold statuses lock until version snapshot completes",
            true,
            status_lock_held
        );

        drop(version_guard);
        let mut watcher = watcher_rx.recv().unwrap();
        handle.join().unwrap();

        crate::assert_with_log!(
            watcher.status() == ServingStatus::Serving,
            "initial status snapshot preserved",
            ServingStatus::Serving,
            watcher.status()
        );

        service.set_status("svc", ServingStatus::NotServing);
        let changed = watcher.changed();
        crate::assert_with_log!(
            changed,
            "watcher still observes later transition",
            true,
            changed
        );
        crate::assert_with_log!(
            watcher.status() == ServingStatus::NotServing,
            "watcher reports new status after transition",
            ServingStatus::NotServing,
            watcher.status()
        );
        crate::test_complete!("health_watch_initial_snapshot_is_atomic_for_named_services");
    }

    #[test]
    fn health_watch_async_emits_initial_status_and_wakes_on_change() {
        init_test("health_watch_async_emits_initial_status_and_wakes_on_change");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "initial watch snapshot is emitted immediately",
            true,
            first_ok
        );

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        let pending = matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        );
        crate::assert_with_log!(
            pending,
            "stream waits for the next health transition",
            true,
            pending
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 1,
            "status change wakes pending async watch",
            1,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        let next = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let next_ok = matches!(
            next,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            }))
        );
        crate::assert_with_log!(
            next_ok,
            "watch stream emits changed status after wake",
            true,
            next_ok
        );
        crate::test_complete!("health_watch_async_emits_initial_status_and_wakes_on_change");
    }

    /// GRPC-DIFF-HWATCH-HALFCLOSE: grpc-go keeps Health/Watch open after the
    /// client sends its single request message and half-closes the send side.
    /// The server stream must stay pending for future updates instead of
    /// terminating when no more client request bytes can arrive.
    #[test]
    fn differential_health_watch_send_half_close_semantics_vs_grpc_go() {
        init_test("differential_health_watch_send_half_close_semantics_vs_grpc_go");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        drop(request);
        let mut stream = response.into_inner();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "grpc-go: initial watch snapshot is emitted before half-close matters",
            true,
            first_ok
        );

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        let pending_after_half_close = matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        );
        crate::assert_with_log!(
            pending_after_half_close,
            "grpc-go: send-half-close must not terminate Health/Watch",
            true,
            pending_after_half_close
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 1,
            "grpc-go: pending Watch keeps exactly one waiter after half-close",
            1,
            waiter_count
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 1,
            "grpc-go: status transition wakes half-closed watch",
            1,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        let next = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let next_ok = matches!(
            next,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            }))
        );
        crate::assert_with_log!(
            next_ok,
            "grpc-go: half-closed watch still emits later status changes",
            true,
            next_ok
        );

        crate::test_complete!("differential_health_watch_send_half_close_semantics_vs_grpc_go");
    }

    #[test]
    fn health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter() {
        init_test("health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));

        let check_err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("grpc-health-probe style Check must fail closed without auth");
        let watch_err = futures_lite::future::block_on(service.watch_async(&request))
            .expect_err("Watch must enforce the same auth gate before constructing a stream");

        crate::assert_with_log!(
            watch_err.code() == check_err.code(),
            "watch auth code matches check auth code",
            check_err.code(),
            watch_err.code()
        );
        crate::assert_with_log!(
            watch_err.message() == check_err.message(),
            "watch auth message matches check auth message",
            check_err.message(),
            watch_err.message()
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 0,
            "unauthenticated watch must not register any streaming waiter state",
            0,
            waiter_count
        );
        crate::test_complete!(
            "health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter"
        );
    }

    #[test]
    fn health_check_async_rejects_empty_bearer_token() {
        init_test("health_check_async_rejects_empty_bearer_token");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let mut request = Request::new(HealthCheckRequest::new("svc"));
        let inserted = request.metadata_mut().insert("authorization", "Bearer ");
        crate::assert_with_log!(inserted, "empty bearer metadata inserted", true, inserted);

        let err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("empty bearer tokens must fail closed");
        crate::assert_with_log!(
            err.message() == "empty bearer token",
            "empty bearer token rejected",
            "empty bearer token",
            err.message()
        );
        crate::test_complete!("health_check_async_rejects_empty_bearer_token");
    }

    #[test]
    fn health_watch_async_drop_unregisters_pending_waiter() {
        init_test("health_watch_async_drop_unregisters_pending_waiter");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let _ = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        ));

        let waiter_count_before_drop = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count_before_drop == 1,
            "pending watch registers exactly one waiter",
            1,
            waiter_count_before_drop
        );

        drop(stream);

        let waiter_count_after_drop = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count_after_drop == 0,
            "dropping a pending watch unregisters waiter state",
            0,
            waiter_count_after_drop
        );
        crate::test_complete!("health_watch_async_drop_unregisters_pending_waiter");
    }

    #[test]
    fn health_watch_async_rechecks_after_waiter_registration() {
        init_test("health_watch_async_rechecks_after_waiter_registration");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let _ = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);

        let poll = stream.poll_next_with_hook(&mut cx, |stream| {
            stream
                .watcher
                .service
                .set_status("svc", ServingStatus::NotServing);
        });

        let changed = matches!(
            poll,
            Poll::Ready(Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            })))
        );
        crate::assert_with_log!(
            changed,
            "watch stream must not miss transition between status check and waiter registration",
            true,
            format!("{poll:?}")
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 0,
            "caught transition clears waiter registration instead of parking forever",
            0,
            waiter_count
        );
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 0,
            "recheck path resolves inline without depending on an out-of-band wake",
            0,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        crate::test_complete!("health_watch_async_rechecks_after_waiter_registration");
    }

    #[test]
    fn health_service_services() {
        init_test("health_service_services");
        let service = HealthService::new();
        service.set_status("b", ServingStatus::NotServing);
        service.set_status("a", ServingStatus::Serving);

        let services = service.services();
        crate::assert_with_log!(
            services == vec!["a".to_string(), "b".to_string()],
            "services are returned in deterministic sorted order",
            vec!["a".to_string(), "b".to_string()],
            services
        );
        crate::test_complete!("health_service_services");
    }

    #[test]
    fn health_reporter() {
        init_test("health_reporter");
        let service = HealthService::new();
        {
            let reporter = HealthReporter::new(service.clone(), "my.Service");
            reporter.set_serving();
            let status = reporter.status();
            crate::assert_with_log!(
                status == ServingStatus::Serving,
                "serving",
                ServingStatus::Serving,
                status
            );
            let serving = service.is_serving("my.Service");
            crate::assert_with_log!(serving, "service serving", true, serving);
        }
        // Service status cleared on drop
        let none = service.get_status("my.Service").is_none();
        crate::assert_with_log!(none, "cleared on drop", true, none);
        crate::test_complete!("health_reporter");
    }

    #[test]
    fn health_reporter_only_final_drop_clears_shared_service_status() {
        init_test("health_reporter_only_final_drop_clears_shared_service_status");
        let service = HealthService::new();
        let reporter_a = HealthReporter::new(service.clone(), "shared.Service");
        let reporter_b = HealthReporter::new(service.clone(), "shared.Service");

        reporter_a.set_serving();
        let version_after_set = service.version();

        drop(reporter_a);
        crate::assert_with_log!(
            service.get_status("shared.Service") == Some(ServingStatus::Serving),
            "first drop preserves shared registration",
            Some(ServingStatus::Serving),
            service.get_status("shared.Service")
        );
        crate::assert_with_log!(
            service.version() == version_after_set,
            "non-final drop does not clear or bump version",
            version_after_set,
            service.version()
        );

        reporter_b.set_not_serving();
        crate::assert_with_log!(
            service.get_status("shared.Service") == Some(ServingStatus::NotServing),
            "remaining reporter still controls shared service state",
            Some(ServingStatus::NotServing),
            service.get_status("shared.Service")
        );

        drop(reporter_b);
        crate::assert_with_log!(
            service.get_status("shared.Service").is_none(),
            "final drop clears shared registration",
            true,
            service.get_status("shared.Service").is_none()
        );
        crate::test_complete!("health_reporter_only_final_drop_clears_shared_service_status");
    }

    #[test]
    fn health_reporter_final_drop_does_not_clear_replacement_reporter_status() {
        init_test("health_reporter_final_drop_does_not_clear_replacement_reporter_status");
        let service = HealthService::new();
        let reporter = HealthReporter::new(service.clone(), "race.Service");
        reporter.set_serving();
        let _reporter = std::mem::ManuallyDrop::new(reporter);

        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (created_tx, created_rx) = std::sync::mpsc::channel();
        let service_for_thread = service.clone();
        let handle = std::thread::spawn(move || {
            attempt_rx.recv().unwrap();
            let replacement = HealthReporter::new(service_for_thread.clone(), "race.Service");
            replacement.set_not_serving();
            created_tx.send(()).unwrap();
            replacement
        });

        service.release_reporter_and_maybe_clear_status_with_hook("race.Service", || {
            attempt_tx.send(()).unwrap();
            std::thread::yield_now();
        });

        created_rx.recv().unwrap();
        crate::assert_with_log!(
            service.get_status("race.Service") == Some(ServingStatus::NotServing),
            "replacement reporter survives final-drop clear window",
            Some(ServingStatus::NotServing),
            service.get_status("race.Service")
        );

        let replacement = handle.join().unwrap();
        drop(replacement);
        crate::assert_with_log!(
            service.get_status("race.Service").is_none(),
            "replacement final drop still clears registration",
            true,
            service.get_status("race.Service").is_none()
        );
        crate::test_complete!(
            "health_reporter_final_drop_does_not_clear_replacement_reporter_status"
        );
    }

    #[test]
    fn health_service_builder() {
        init_test("health_service_builder");
        let service = HealthServiceBuilder::new()
            .add("explicit", ServingStatus::NotServing)
            .add_serving(["a", "b", "c"])
            .build();

        let explicit = service.get_status("explicit");
        crate::assert_with_log!(
            explicit == Some(ServingStatus::NotServing),
            "explicit",
            Some(ServingStatus::NotServing),
            explicit
        );
        let a = service.get_status("a");
        crate::assert_with_log!(
            a == Some(ServingStatus::Serving),
            "a",
            Some(ServingStatus::Serving),
            a
        );
        let b = service.get_status("b");
        crate::assert_with_log!(
            b == Some(ServingStatus::Serving),
            "b",
            Some(ServingStatus::Serving),
            b
        );
        let c = service.get_status("c");
        crate::assert_with_log!(
            c == Some(ServingStatus::Serving),
            "c",
            Some(ServingStatus::Serving),
            c
        );
        crate::test_complete!("health_service_builder");
    }

    #[test]
    fn health_service_named_service() {
        init_test("health_service_named_service");
        let name = HealthService::NAME;
        crate::assert_with_log!(
            name == "grpc.health.v1.Health",
            "name",
            "grpc.health.v1.Health",
            name
        );
        crate::test_complete!("health_service_named_service");
    }

    #[test]
    fn health_service_descriptor() {
        init_test("health_service_descriptor");
        let service = HealthService::new();
        let desc = service.descriptor();
        crate::assert_with_log!(desc.name == "Health", "name", "Health", desc.name);
        crate::assert_with_log!(
            desc.package == "grpc.health.v1",
            "package",
            "grpc.health.v1",
            desc.package
        );
        let len = desc.methods.len();
        crate::assert_with_log!(len == 2, "methods len", 2, len);
        crate::test_complete!("health_service_descriptor");
    }

    #[test]
    fn health_service_method_names() {
        init_test("health_service_method_names");
        let service = HealthService::new();
        let names = service.method_names();
        let has_check = names.contains(&"Check");
        crate::assert_with_log!(has_check, "has Check", true, has_check);
        let has_watch = names.contains(&"Watch");
        crate::assert_with_log!(has_watch, "has Watch", true, has_watch);
        crate::test_complete!("health_service_method_names");
    }

    #[test]
    fn health_check_request_constructors() {
        init_test("health_check_request_constructors");
        let req = HealthCheckRequest::new("my.Service");
        crate::assert_with_log!(
            req.service == "my.Service",
            "service",
            "my.Service",
            req.service
        );

        let req = HealthCheckRequest::server();
        crate::assert_with_log!(req.service.is_empty(), "service", "", req.service);
        crate::test_complete!("health_check_request_constructors");
    }

    #[test]
    fn health_service_clone() {
        init_test("health_service_clone");
        let service1 = HealthService::new();
        let service2 = service1.clone();

        service1.set_status("test", ServingStatus::Serving);
        let status = service2.get_status("test");
        crate::assert_with_log!(
            status == Some(ServingStatus::Serving),
            "serving",
            Some(ServingStatus::Serving),
            status
        );
        crate::test_complete!("health_service_clone");
    }

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn serving_status_debug_clone_copy_eq_hash_default() {
        use std::collections::HashSet;

        let def = ServingStatus::default();
        assert_eq!(def, ServingStatus::Unknown);

        let statuses = [
            ServingStatus::Unknown,
            ServingStatus::Serving,
            ServingStatus::NotServing,
            ServingStatus::ServiceUnknown,
        ];
        for s in &statuses {
            let copied = *s;
            let cloned = *s;
            assert_eq!(copied, cloned);
            assert!(!format!("{s:?}").is_empty());
        }

        let mut set = HashSet::new();
        for s in &statuses {
            set.insert(*s);
        }
        assert_eq!(set.len(), 4);
        set.insert(ServingStatus::Serving);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn health_check_request_debug_clone_default() {
        let def = HealthCheckRequest::default();
        assert!(def.service.is_empty());
        let dbg = format!("{def:?}");
        assert!(dbg.contains("HealthCheckRequest"), "{dbg}");
        let cloned = def;
        assert_eq!(cloned.service, "");
    }

    #[test]
    fn health_check_response_debug_clone_default() {
        let def = HealthCheckResponse::default();
        assert_eq!(def.status, ServingStatus::Unknown);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("HealthCheckResponse"), "{dbg}");
        let resp = HealthCheckResponse::new(ServingStatus::Serving);
        let cloned = resp;
        assert_eq!(cloned.status, ServingStatus::Serving);
    }
