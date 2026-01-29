//! Virtual HTTP client for lab runtime testing.

use std::collections::HashMap;

use crate::bytes::Bytes;
use crate::util::DetRng;
use crate::web::extract::Request;
use crate::web::response::Response;

use super::server::VirtualServer;

/// A virtual HTTP client that dispatches requests to a [`VirtualServer`].
///
/// Supports deterministic concurrent request batching: when multiple
/// requests are issued as a batch, the execution order is determined by
/// the provided [`DetRng`], ensuring reproducibility.
///
/// # Example
///
/// ```ignore
/// let client = VirtualClient::new(&server);
///
/// // Single request
/// let resp = client.get("/health");
///
/// // Concurrent batch (order determined by seed)
/// let resps = client.get_batch(&["/a", "/b", "/c"]);
/// ```
pub struct VirtualClient<'a> {
    server: &'a VirtualServer,
}

impl<'a> VirtualClient<'a> {
    /// Create a client bound to a virtual server.
    #[must_use]
    pub fn new(server: &'a VirtualServer) -> Self {
        Self { server }
    }

    /// Send a GET request.
    pub fn get(&self, path: &str) -> Response {
        self.server.handle(Request::new("GET", path))
    }

    /// Send a POST request with a body.
    pub fn post(&self, path: &str, body: impl Into<Bytes>) -> Response {
        let mut req = Request::new("POST", path);
        req.body = body.into();
        req.headers.insert(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        );
        self.server.handle(req)
    }

    /// Send a POST request with a JSON body.
    pub fn post_json(&self, path: &str, json: &str) -> Response {
        let mut req = Request::new("POST", path);
        req.body = Bytes::from(json.to_string());
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        self.server.handle(req)
    }

    /// Send a PUT request with a body.
    pub fn put(&self, path: &str, body: impl Into<Bytes>) -> Response {
        let mut req = Request::new("PUT", path);
        req.body = body.into();
        self.server.handle(req)
    }

    /// Send a DELETE request.
    pub fn delete(&self, path: &str) -> Response {
        self.server.handle(Request::new("DELETE", path))
    }

    /// Send a batch of GET requests in deterministic order.
    ///
    /// The `rng` controls the execution order, simulating concurrent
    /// request arrival. Same seed → same ordering → same results.
    pub fn get_batch(&self, paths: &[&str], rng: &mut DetRng) -> Vec<Response> {
        let mut indices: Vec<usize> = (0..paths.len()).collect();
        rng.shuffle(&mut indices);

        let mut responses = vec![None; paths.len()];
        for &idx in &indices {
            responses[idx] = Some(self.get(paths[idx]));
        }
        responses.into_iter().map(|r| r.unwrap()).collect()
    }

    /// Send a custom request built with [`RequestBuilder`].
    pub fn send(&self, req: Request) -> Response {
        self.server.handle(req)
    }

    /// Create a request builder for a custom request.
    #[must_use]
    pub fn request(&'a self, method: &str, path: &str) -> RequestBuilder<'a> {
        RequestBuilder {
            client: self,
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: Bytes::new(),
        }
    }
}

/// Builder for constructing custom requests.
pub struct RequestBuilder<'a> {
    client: &'a VirtualClient<'a>,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Bytes,
}

impl<'a> RequestBuilder<'a> {
    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the request body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Set a JSON body and content-type header.
    #[must_use]
    pub fn json(mut self, json: &str) -> Self {
        self.body = Bytes::from(json.to_string());
        self.headers
            .insert("content-type".to_string(), "application/json".to_string());
        self
    }

    /// Send the request and return the response.
    pub fn send(self) -> Response {
        let mut req = Request::new(&self.method, &self.path);
        req.headers = self.headers;
        req.body = self.body;
        self.client.send(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;
    use crate::web::router::{get, post, Router};

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
}
