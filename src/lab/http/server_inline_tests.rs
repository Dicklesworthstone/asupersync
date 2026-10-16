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

    #[test]
    fn server_handles_request() {
        let router = Router::new().route("/hello", get(FnHandler::new(|| "world")));
        let server = VirtualServer::new(router);

        let resp = server.handle(Request::new("GET", "/hello"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(server.request_count(), 1);
    }

    #[test]
    fn server_404_for_unknown_route() {
        let router = Router::new();
        let server = VirtualServer::new(router);

        let resp = server.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn server_counts_requests() {
        let router = Router::new().route("/", get(FnHandler::new(|| "ok")));
        let server = VirtualServer::new(router);

        for _ in 0..5 {
            server.handle(Request::new("GET", "/"));
        }
        assert_eq!(server.request_count(), 5);
    }

    #[test]
    fn server_handle_at_returns_time() {
        let router = Router::new().route("/", get(FnHandler::new(|| "ok")));
        let server = VirtualServer::new(router);

        let now = Time::from_millis(1000);
        let (resp, time) = server.handle_at(Request::new("GET", "/"), now);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(time, now);
    }
