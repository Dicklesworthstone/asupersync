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
    use crate::web::router::{Router, get, post};

    fn test_server() -> VirtualServer {
        let router = Router::new()
            .route("/hello", get(FnHandler::new(|| "world")))
            .route("/echo", post(FnHandler::new(|| StatusCode::CREATED)));
        VirtualServer::new(router)
    }

    #[test]
    fn client_get() {
        let server = test_server();
        let client = VirtualClient::new(&server);

        let resp = client.get("/hello");
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn client_post() {
        let server = test_server();
        let client = VirtualClient::new(&server);

        let resp = client.post("/echo", b"data".to_vec());
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn client_delete() {
        let server = test_server();
        let client = VirtualClient::new(&server);

        let resp = client.delete("/hello");
        // GET-only route → 405
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn client_get_batch_deterministic() {
        let router = Router::new()
            .route("/a", get(FnHandler::new(|| "a")))
            .route("/b", get(FnHandler::new(|| "b")))
            .route("/c", get(FnHandler::new(|| "c")));
        let server = VirtualServer::new(router);
        let client = VirtualClient::new(&server);

        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);

        let batch1 = client.get_batch(&["/a", "/b", "/c"], &mut rng1);
        let batch2 = client.get_batch(&["/a", "/b", "/c"], &mut rng2);

        // Same seed → same results
        assert_eq!(batch1.len(), batch2.len());
        for (r1, r2) in batch1.iter().zip(batch2.iter()) {
            assert_eq!(r1.status, r2.status);
            assert_eq!(r1.body, r2.body);
        }

        // Server processed all requests
        assert_eq!(server.request_count(), 6);
    }

    #[test]
    fn client_request_builder() {
        let server = test_server();
        let client = VirtualClient::new(&server);

        let resp = client
            .request("GET", "/hello")
            .header("x-custom", "value")
            .send();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn client_request_builder_json() {
        let server = test_server();
        let client = VirtualClient::new(&server);

        let resp = client
            .request("POST", "/echo")
            .json(r#"{"key":"value"}"#)
            .send();
        assert_eq!(resp.status, StatusCode::CREATED);
    }
