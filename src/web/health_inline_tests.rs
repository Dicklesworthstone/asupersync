    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::handler::Handler;
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    trait SyncHandlerExt {
        fn call_sync(&self, req: super::super::extract::Request) -> Response;
    }

    impl<H: Handler> SyncHandlerExt for H {
        fn call_sync(&self, req: super::super::extract::Request) -> Response {
            futures_lite::future::block_on(Handler::call(self, &crate::Cx::for_testing(), req))
        }
    }

    // ================================================================
    // HealthStatus
    // ================================================================

    #[test]
    fn health_status_healthy() {
        let s = HealthStatus::Healthy;
        assert!(s.is_healthy());
        assert!(s.is_operational());
        assert_eq!(s.as_str(), "healthy");
        assert_eq!(s.detail(), None);
        assert_eq!(s.to_string(), "healthy");
    }

    #[test]
    fn health_status_degraded() {
        let s = HealthStatus::Degraded("slow".into());
        assert!(!s.is_healthy());
        assert!(s.is_operational());
        assert_eq!(s.as_str(), "degraded");
        assert_eq!(s.detail(), Some("slow"));
        assert_eq!(s.to_string(), "degraded: slow");
    }

    #[test]
    fn health_status_unhealthy() {
        let s = HealthStatus::Unhealthy("down".into());
        assert!(!s.is_healthy());
        assert!(!s.is_operational());
        assert_eq!(s.as_str(), "unhealthy");
        assert_eq!(s.detail(), Some("down"));
        assert_eq!(s.to_string(), "unhealthy: down");
    }

    // ================================================================
    // HealthResponse serialization
    // ================================================================

    #[test]
    fn health_response_healthy_json() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        assert_eq!(resp.to_json(), r#"{"status":"healthy"}"#);
    }

    #[test]
    fn health_response_with_checks_json() {
        let mut checks = BTreeMap::new();
        checks.insert("db".to_string(), HealthStatus::Healthy);
        checks.insert(
            "cache".to_string(),
            HealthStatus::Degraded("high latency".into()),
        );

        let resp = HealthResponse {
            status: HealthStatus::Degraded("one or more checks degraded".into()),
            checks,
        };
        let json = resp.to_json();
        assert!(json.contains(r#""status":"degraded""#));
        assert!(json.contains(r#""detail":"one or more checks degraded""#));
        assert!(json.contains(r#""db":{"status":"healthy"}"#));
        assert!(json.contains(r#""cache":{"status":"degraded","detail":"high latency"}"#));
    }

    #[test]
    fn health_response_top_level_detail_json() {
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("error: \"bad\"\nretry".into()),
            checks: BTreeMap::new(),
        };
        assert_eq!(
            resp.to_json(),
            r#"{"status":"unhealthy","detail":"error: \"bad\"\nretry"}"#
        );
    }

    #[test]
    fn health_response_probe_json_redacts_detail_and_checks() {
        let mut checks = BTreeMap::new();
        checks.insert(
            "database".to_string(),
            HealthStatus::Unhealthy("connection refused".into()),
        );
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("one or more checks unhealthy".into()),
            checks,
        };

        assert_eq!(resp.to_probe_json(), r#"{"status":"unhealthy"}"#);
    }

    #[test]
    fn health_response_json_escaping() {
        let mut checks = BTreeMap::new();
        checks.insert(
            "test".to_string(),
            HealthStatus::Unhealthy("error: \"bad\"".into()),
        );

        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("fail".into()),
            checks,
        };
        let json = resp.to_json();
        assert!(json.contains(r#""detail":"fail""#));
        assert!(json.contains(r#"\"bad\""#));
    }

    // ================================================================
    // HealthResponse IntoResponse
    // ================================================================

    #[test]
    fn health_response_into_response_healthy() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        assert_eq!(http.status, StatusCode::OK);
        assert_eq!(
            http.headers.get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn health_response_into_response_unhealthy() {
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("fail".into()),
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        assert_eq!(http.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn health_response_into_response_degraded() {
        let resp = HealthResponse {
            status: HealthStatus::Degraded("slow".into()),
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        // Degraded is still operational → 200 OK.
        assert_eq!(http.status, StatusCode::OK);
    }

    // ================================================================
    // HealthCheck system
    // ================================================================

    #[test]
    fn health_check_no_checks() {
        let hc = HealthCheck::new();
        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.checks.is_empty());
    }

    #[test]
    fn health_check_all_healthy() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Healthy)
            .check("cache", || HealthStatus::Healthy);

        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.checks.len(), 2);
    }

    #[test]
    fn health_check_one_degraded() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Healthy)
            .check("cache", || HealthStatus::Degraded("slow".into()));

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Degraded(_)));
        assert_eq!(result.checks.get("cache").unwrap().as_str(), "degraded");
    }

    #[test]
    fn health_check_one_unhealthy() {
        let hc = HealthCheck::new()
            .check("db", || {
                HealthStatus::Unhealthy("connection refused".into())
            })
            .check("cache", || HealthStatus::Healthy);

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Unhealthy(_)));
    }

    #[test]
    fn health_check_unhealthy_overrides_degraded() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Degraded("slow".into()))
            .check("cache", || HealthStatus::Unhealthy("down".into()));

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Unhealthy(_)));
    }

    #[test]
    fn health_check_callbacks_run_without_registry_lock() {
        let observed_unlocked = Arc::new(AtomicBool::new(false));
        let hc = HealthCheck::new();
        let probe = hc.clone();
        let observed = Arc::clone(&observed_unlocked);

        let hc = hc.check("registry", move || {
            let lock_available = probe.inner.checks.try_lock().is_some();
            observed.store(lock_available, Ordering::SeqCst);
            if lock_available {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy("registry lock held during callback".into())
            }
        });

        let result = hc.run_checks();
        assert!(
            observed_unlocked.load(Ordering::SeqCst),
            "health checks must not execute while the registry mutex is held"
        );
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    // ================================================================
    // Readiness control
    // ================================================================

    #[test]
    fn health_check_readiness_default() {
        let hc = HealthCheck::new();
        assert!(hc.is_ready());
    }

    #[test]
    fn health_check_set_ready() {
        let hc = HealthCheck::new();
        hc.set_ready(false);
        assert!(!hc.is_ready());

        hc.set_ready(true);
        assert!(hc.is_ready());
    }

    #[test]
    fn health_check_clone_shares_state() {
        let hc = HealthCheck::new();
        let hc2 = hc.clone();
        hc.set_ready(false);
        assert!(!hc2.is_ready());
    }

    // ================================================================
    // Handler integration
    // ================================================================

    #[test]
    fn liveness_handler_returns_200() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        let handler = hc.liveness_handler();

        let req = super::super::extract::Request::new("GET", "/healthz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("healthy"));
    }

    #[test]
    fn liveness_handler_unhealthy_returns_503() {
        let hc = HealthCheck::new().check("db", || {
            HealthStatus::Unhealthy("connection refused".into())
        });
        let handler = hc.liveness_handler();

        let req = super::super::extract::Request::new("GET", "/healthz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, r#"{"status":"unhealthy"}"#);
        assert!(!body.contains("connection refused"));
        assert!(!body.contains("db"));
    }

    #[test]
    fn readiness_handler_ready() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Healthy)
            .check("cache", || HealthStatus::Degraded("high latency".into()));
        let handler = hc.readiness_handler();

        let req = super::super::extract::Request::new("GET", "/readyz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, r#"{"status":"degraded"}"#);
        assert!(!body.contains("high latency"));
        assert!(!body.contains("cache"));
    }

    #[test]
    fn readiness_handler_not_ready() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        hc.set_ready(false);
        let handler = hc.readiness_handler();

        let req = super::super::extract::Request::new("GET", "/readyz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("not_ready"));
    }

    #[test]
    fn startup_handler_started() {
        let hc = HealthCheck::new();
        let handler = hc.startup_handler();

        let req = super::super::extract::Request::new("GET", "/startupz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("started"));
    }

    #[test]
    fn startup_handler_not_started() {
        let hc = HealthCheck::new();
        hc.set_ready(false);
        let handler = hc.startup_handler();

        let req = super::super::extract::Request::new("GET", "/startupz");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("starting"));
    }

    // ================================================================
    // Data type coverage
    // ================================================================

    #[test]
    fn health_status_debug_clone_eq() {
        let s = HealthStatus::Healthy;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Healthy"));
        let cloned = s.clone();
        assert_eq!(s, cloned);

        let d1 = HealthStatus::Degraded("a".into());
        let d2 = HealthStatus::Degraded("b".into());
        assert_ne!(d1, d2);
    }

    #[test]
    fn health_response_debug_clone() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("HealthResponse"));
    }

    #[test]
    fn health_check_debug() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        let dbg = format!("{hc:?}");
        assert!(dbg.contains("HealthCheck"));
        assert!(dbg.contains("db"));
    }

    #[test]
    fn health_check_default() {
        let hc = HealthCheck::default();
        assert!(hc.is_ready());
        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
    }
