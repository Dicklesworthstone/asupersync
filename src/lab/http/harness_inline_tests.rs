    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;
    use crate::web::router::get;

    fn scrub_trace_display(output: &str) -> String {
        output
            .lines()
            .map(|line| {
                if let Some(prefix) = line.split_once("(t=").map(|(prefix, _)| prefix) {
                    format!("{prefix}(t=[MS])")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn test_router() -> Router {
        Router::new()
            .route("/health", get(FnHandler::new(|| "ok")))
            .route("/users", get(FnHandler::new(|| "[]")))
            .route(
                "/fail",
                get(FnHandler::new(|| StatusCode::INTERNAL_SERVER_ERROR)),
            )
    }

    #[test]
    fn harness_basic_request() {
        let mut harness = TestHarness::with_seed(42, test_router());

        let resp = harness.get("/health");
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(harness.trace().len(), 1);
    }

    #[test]
    fn harness_trace_records_details() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/users");

        let trace = harness.trace();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].method, "GET");
        assert_eq!(trace[0].path, "/health");
        assert_eq!(trace[0].status, 200);
        assert_eq!(trace[1].path, "/users");
    }

    #[test]
    fn harness_assert_all_success() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/users");

        harness.assert_all_success(); // Should not panic.
    }

    #[test]
    #[should_panic(expected = "returned 500")]
    fn harness_assert_all_success_fails_on_error() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/fail");

        harness.assert_all_success(); // Should panic.
    }

    #[test]
    fn harness_request_count() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/health");
        harness.get("/users");

        harness.assert_request_count(3);
    }

    #[test]
    fn harness_batch_deterministic() {
        let router = Router::new()
            .route("/a", get(FnHandler::new(|| "a")))
            .route("/b", get(FnHandler::new(|| "b")))
            .route("/c", get(FnHandler::new(|| "c")));

        let mut h1 = TestHarness::with_seed(99, router);

        let router2 = Router::new()
            .route("/a", get(FnHandler::new(|| "a")))
            .route("/b", get(FnHandler::new(|| "b")))
            .route("/c", get(FnHandler::new(|| "c")));

        let mut h2 = TestHarness::with_seed(99, router2);

        let batch1 = h1.get_batch(&["/a", "/b", "/c"]);
        let batch2 = h2.get_batch(&["/a", "/b", "/c"]);

        // Same seed → same responses
        assert_eq!(batch1.len(), batch2.len());
        for (r1, r2) in batch1.iter().zip(batch2.iter()) {
            assert_eq!(r1.status, r2.status);
            assert_eq!(r1.body, r2.body);
        }
    }

    #[test]
    fn harness_client_records_trace() {
        let mut harness = TestHarness::with_seed(42, test_router());

        let resp = harness.client().get("/health");

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(harness.trace().len(), 1);
        assert_eq!(harness.trace()[0].path, "/health");
    }

    #[test]
    fn harness_client_batch_is_traced_and_seeded() {
        let router = Router::new()
            .route("/a", get(FnHandler::new(|| "a")))
            .route("/b", get(FnHandler::new(|| "b")))
            .route("/c", get(FnHandler::new(|| "c")));

        let mut h1 = TestHarness::with_seed(99, router);

        let router2 = Router::new()
            .route("/a", get(FnHandler::new(|| "a")))
            .route("/b", get(FnHandler::new(|| "b")))
            .route("/c", get(FnHandler::new(|| "c")));

        let mut h2 = TestHarness::with_seed(99, router2);

        let batch1 = h1.client().get_batch(&["/a", "/b", "/c"]);
        let batch2 = h2.client().get_batch(&["/a", "/b", "/c"]);

        assert_eq!(batch1.len(), batch2.len());
        for (r1, r2) in batch1.iter().zip(batch2.iter()) {
            assert_eq!(r1.status, r2.status);
            assert_eq!(r1.body, r2.body);
        }

        let trace_paths_1: Vec<&str> = h1.trace().iter().map(|entry| entry.path.as_str()).collect();
        let trace_paths_2: Vec<&str> = h2.trace().iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(trace_paths_1, trace_paths_2);
        assert_eq!(trace_paths_1.len(), 3);
    }

    #[test]
    fn harness_trace_filtering() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/users");
        harness.get("/fail");

        let trace = harness.trace();
        let trace_2xx = RequestTrace {
            entries: trace.to_vec(),
        };
        let successes = trace_2xx.by_status_class(2);
        assert_eq!(successes.len(), 2);

        let trace_5xx = RequestTrace {
            entries: trace.to_vec(),
        };
        let errors = trace_5xx.by_status_class(5);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn harness_trace_by_path() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/users");

        let trace = harness.trace();
        let trace_health = RequestTrace {
            entries: trace.to_vec(),
        };
        let health = trace_health.by_path_prefix("/health");
        assert_eq!(health.len(), 1);
    }

    #[test]
    fn harness_clear_trace() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        assert_eq!(harness.trace().len(), 1);

        harness.clear_trace();
        assert_eq!(harness.trace().len(), 0);
    }

    #[test]
    fn harness_virtual_time() {
        let mut harness = TestHarness::with_seed(42, test_router());

        let t0 = harness.now();
        harness.get("/health");

        harness.advance_time(1_000_000_000); // 1 second
        let t1 = harness.now();

        harness.get("/users");

        // First request at t0, second at t1
        let trace = harness.trace();
        assert_eq!(trace[0].virtual_time, t0);
        assert_eq!(trace[1].virtual_time, t1);
        assert!(t1 > t0);
    }

    #[test]
    fn harness_trace_display() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/fail");

        let trace_str = format!(
            "{}",
            RequestTrace {
                entries: harness.trace().to_vec()
            }
        );
        assert!(trace_str.contains("GET /health"));
        assert!(trace_str.contains("500"));
    }

    #[test]
    fn harness_trace_display_snapshot_scrubbed() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.advance_time(250_000_000);
        harness.get("/fail");

        let trace_display = format!(
            "{}",
            RequestTrace {
                entries: harness.trace().to_vec()
            }
        );

        insta::assert_snapshot!(
            "harness_trace_display_scrubbed",
            scrub_trace_display(&trace_display)
        );
    }

    #[test]
    fn trace_success_and_error_counts() {
        let mut harness = TestHarness::with_seed(42, test_router());

        harness.get("/health");
        harness.get("/users");
        harness.get("/fail");
        harness.get("/missing"); // 404

        let trace = RequestTrace {
            entries: harness.trace().to_vec(),
        };
        assert_eq!(trace.success_count(), 2);
        assert_eq!(trace.error_count(), 2); // 500 + 404
    }
