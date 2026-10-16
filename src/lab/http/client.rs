//! Virtual HTTP client for lab runtime testing.

use std::collections::HashMap;

use crate::Cx;
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
    #[must_use]
    pub fn get(&self, path: &str) -> Response {
        self.server.handle(Request::new("GET", path))
    }

    /// Send a GET request with an explicit capability context.
    pub async fn get_with_cx(&self, cx: &Cx, path: &str) -> Response {
        self.server
            .handle_with_cx(cx, Request::new("GET", path))
            .await
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
    #[must_use]
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
    #[must_use]
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
        responses
            .into_iter()
            .map(|r| r.expect("response should be present"))
            .collect()
    }

    /// Send a custom request built with [`RequestBuilder`].
    #[must_use]
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

impl RequestBuilder<'_> {
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
    #[must_use]
    pub fn send(self) -> Response {
        let mut req = Request::new(&self.method, &self.path);
        req.headers = self.headers;
        req.body = self.body;
        self.client.send(req)
    }
}

#[cfg(test)]
#[path = "client_inline_tests.rs"]
mod tests;
