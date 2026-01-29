//! Request extractors.
//!
//! Extractors pull typed data from incoming HTTP requests. Each extractor
//! implements [`FromRequest`] or [`FromRequestParts`] and can be used as a
//! handler parameter.
//!
//! # Built-in Extractors
//!
//! - [`Path<T>`]: URL path parameters
//! - [`Query<T>`]: Query string parameters
//! - [`Json<T>`]: JSON request body
//! - [`Form<T>`]: URL-encoded form body
//! - [`State<T>`]: Shared application state
//! - [`RawBody`]: Raw request body bytes

use std::collections::HashMap;
use std::fmt;

use crate::bytes::Bytes;

// ─── Request Type ────────────────────────────────────────────────────────────

/// An incoming HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request path (e.g., "/users/42").
    pub path: String,
    /// Query string (everything after '?'), if present.
    pub query: Option<String>,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request body bytes.
    pub body: Bytes,
    /// Path parameters extracted by the router (e.g., `{ "id": "42" }`).
    pub path_params: HashMap<String, String>,
    /// Extensions for middleware-injected state.
    pub extensions: Extensions,
}

impl Request {
    /// Create a new request (primarily for testing).
    #[must_use]
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: None,
            headers: HashMap::new(),
            body: Bytes::new(),
            path_params: HashMap::new(),
            extensions: Extensions::new(),
        }
    }

    /// Set the query string.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Set the request body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set path parameters (used internally by the router).
    #[must_use]
    pub fn with_path_params(mut self, params: HashMap<String, String>) -> Self {
        self.path_params = params;
        self
    }
}

// ─── Extensions ──────────────────────────────────────────────────────────────

/// Type-erased extension map for middleware-injected data.
///
/// Allows middleware to inject arbitrary typed state into requests.
#[derive(Debug, Clone, Default)]
pub struct Extensions {
    // Simplified: use a HashMap<TypeId, Box<dyn Any>> in production.
    // For Phase 0, we use a string-keyed map.
    data: HashMap<String, String>,
}

impl Extensions {
    /// Create an empty extensions map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a value by key.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(String::as_str)
    }
}

// ─── Extraction Error ────────────────────────────────────────────────────────

/// Error returned when extraction fails.
#[derive(Debug, Clone)]
pub struct ExtractionError {
    /// Human-readable description.
    pub message: String,
    /// Suggested HTTP status code for the error response.
    pub status: super::response::StatusCode,
}

impl ExtractionError {
    /// Create a new extraction error.
    #[must_use]
    pub fn new(status: super::response::StatusCode, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }

    /// Create a 400 Bad Request extraction error.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(super::response::StatusCode::BAD_REQUEST, message)
    }

    /// Create a 422 Unprocessable Entity extraction error.
    #[must_use]
    pub fn unprocessable(message: impl Into<String>) -> Self {
        Self::new(super::response::StatusCode::UNPROCESSABLE_ENTITY, message)
    }
}

impl fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status, self.message)
    }
}

impl std::error::Error for ExtractionError {}

impl super::response::IntoResponse for ExtractionError {
    fn into_response(self) -> super::response::Response {
        super::response::Response::new(self.status, Bytes::copy_from_slice(self.message.as_bytes()))
            .header("content-type", "text/plain; charset=utf-8")
    }
}

// ─── FromRequest / FromRequestParts ──────────────────────────────────────────

/// Extract a value from request parts (headers, path, query).
///
/// Extractors implementing this trait can be used without consuming the body.
pub trait FromRequestParts: Sized {
    /// Attempt to extract from request parts.
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError>;
}

/// Extract a value from the full request (may consume the body).
///
/// Only one body-consuming extractor can be used per handler.
pub trait FromRequest: Sized {
    /// Attempt to extract from the request.
    fn from_request(req: Request) -> Result<Self, ExtractionError>;
}

// Blanket: anything that implements FromRequestParts also implements FromRequest.
impl<T: FromRequestParts> FromRequest for T {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        Self::from_request_parts(&req)
    }
}

// ─── Path<T> ─────────────────────────────────────────────────────────────────

/// Extract path parameters.
///
/// For a single parameter, `Path<String>` extracts the first path param.
/// For named parameters, use `Path<HashMap<String, String>>`.
///
/// ```ignore
/// async fn get_user(Path(id): Path<String>) -> String {
///     format!("User {id}")
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Path<T>(pub T);

impl FromRequestParts for Path<String> {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        req.path_params
            .values()
            .next()
            .cloned()
            .map(Path)
            .ok_or_else(|| ExtractionError::bad_request("no path parameters found"))
    }
}

#[allow(clippy::implicit_hasher)]
impl FromRequestParts for Path<HashMap<String, String>> {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        Ok(Self(req.path_params.clone()))
    }
}

// ─── Query<T> ────────────────────────────────────────────────────────────────

/// Extract query string parameters.
///
/// Deserializes the query string using `serde_urlencoded`.
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct Pagination { page: u32, per_page: u32 }
///
/// async fn list(Query(p): Query<Pagination>) -> String {
///     format!("Page {} ({} per page)", p.page, p.per_page)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Query<T>(pub T);

#[allow(clippy::implicit_hasher)]
impl FromRequestParts for Query<HashMap<String, String>> {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let qs = req.query.as_deref().unwrap_or("");
        Ok(Self(parse_urlencoded(qs)))
    }
}

/// Parse a URL-encoded string into key-value pairs.
fn parse_urlencoded(input: &str) -> HashMap<String, String> {
    input
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

/// Simple percent-decoding (handles %XX and + as space).
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'+' => result.push(' '),
            b'%' => {
                let hi = chars.next().and_then(hex_val);
                let lo = chars.next().and_then(hex_val);
                if let (Some(h), Some(l)) = (hi, lo) {
                    result.push((h << 4 | l) as char);
                } else {
                    result.push('%');
                }
            }
            _ => result.push(b as char),
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Json<T> ─────────────────────────────────────────────────────────────────

/// Extract JSON request body.
///
/// Deserializes the request body as JSON.
///
/// ```ignore
/// async fn create_user(Json(user): Json<CreateUser>) -> StatusCode {
///     // ...
///     StatusCode::CREATED
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl<T: serde::de::DeserializeOwned> FromRequest for Json<T> {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        let content_type = req.headers.get("content-type").map(String::as_str);
        if let Some(ct) = content_type {
            if !ct.contains("application/json") {
                return Err(ExtractionError::new(
                    super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    format!("expected application/json, got {ct}"),
                ));
            }
        }

        serde_json::from_slice(req.body.as_ref())
            .map(Json)
            .map_err(|e| ExtractionError::unprocessable(format!("invalid JSON: {e}")))
    }
}

// ─── Form<T> ─────────────────────────────────────────────────────────────────

/// Extract URL-encoded form data from the request body.
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct Login { username: String, password: String }
///
/// async fn login(Form(data): Form<Login>) -> Redirect {
///     // ...
///     Redirect::to("/dashboard")
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Form<T>(pub T);

#[allow(clippy::implicit_hasher)]
impl FromRequest for Form<HashMap<String, String>> {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        let body_str = std::str::from_utf8(req.body.as_ref())
            .map_err(|e| ExtractionError::bad_request(format!("invalid UTF-8 body: {e}")))?;

        Ok(Self(parse_urlencoded(body_str)))
    }
}

// ─── State<T> ────────────────────────────────────────────────────────────────

/// Extract shared application state.
///
/// State must be injected via `Router::with_state()`. The state is stored
/// in the request extensions by the router.
///
/// ```ignore
/// #[derive(Clone)]
/// struct AppState { db: DbPool }
///
/// async fn handler(State(state): State<AppState>) -> String {
///     // use state.db
///     "ok".into()
/// }
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .with_state(AppState { db });
/// ```
#[derive(Debug, Clone)]
pub struct State<T>(pub T);

// State extraction requires the router to inject state into extensions.
// Phase 0: State<String> extraction from extensions for demonstration.
impl FromRequestParts for State<String> {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        req.extensions
            .get("state")
            .map(|s| Self(s.to_string()))
            .ok_or_else(|| {
                ExtractionError::new(
                    super::response::StatusCode::INTERNAL_SERVER_ERROR,
                    "state not configured",
                )
            })
    }
}

// ─── RawBody ─────────────────────────────────────────────────────────────────

/// Extract the raw request body as bytes.
#[derive(Debug, Clone)]
pub struct RawBody(pub Bytes);

impl FromRequest for RawBody {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        Ok(Self(req.body))
    }
}

// ─── HeaderMap Extractor ─────────────────────────────────────────────────────

#[allow(clippy::implicit_hasher)]
impl FromRequestParts for HashMap<String, String> {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        Ok(req.headers.clone())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_extraction() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42").with_path_params(params);

        let Path(id) = Path::<String>::from_request_parts(&req).unwrap();
        assert_eq!(id, "42");
    }

    #[test]
    fn query_extraction() {
        let req = Request::new("GET", "/items").with_query("page=3&sort=name");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(params.get("page").unwrap(), "3");
        assert_eq!(params.get("sort").unwrap(), "name");
    }

    #[test]
    fn json_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Input {
            name: String,
        }

        let req = Request::new("POST", "/users")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"{\"name\":\"alice\"}"));

        let Json(input) = Json::<Input>::from_request(req).unwrap();
        assert_eq!(input.name, "alice");
    }

    #[test]
    fn json_wrong_content_type() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            #[allow(dead_code)]
            name: String,
        }

        let req = Request::new("POST", "/users")
            .with_header("content-type", "text/plain")
            .with_body(Bytes::from_static(b"{\"name\":\"alice\"}"));

        let result = Json::<Input>::from_request(req);
        assert!(result.is_err());
    }

    #[test]
    fn form_extraction() {
        let req =
            Request::new("POST", "/login").with_body(Bytes::from_static(b"user=alice&pass=secret"));

        let Form(data) = Form::<HashMap<String, String>>::from_request(req).unwrap();
        assert_eq!(data.get("user").unwrap(), "alice");
        assert_eq!(data.get("pass").unwrap(), "secret");
    }

    #[test]
    fn raw_body_extraction() {
        let req = Request::new("POST", "/upload").with_body(Bytes::from_static(b"raw data"));

        let RawBody(body) = RawBody::from_request(req).unwrap();
        assert_eq!(body.as_ref(), b"raw data");
    }

    #[test]
    fn headers_extraction() {
        let req = Request::new("GET", "/").with_header("x-request-id", "abc123");

        let headers = HashMap::<String, String>::from_request_parts(&req).unwrap();
        assert_eq!(headers.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn missing_path_params() {
        let req = Request::new("GET", "/");
        let result = Path::<String>::from_request_parts(&req);
        assert!(result.is_err());
    }
}
