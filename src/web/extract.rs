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
//! - [`Cookie`]: Raw `Cookie` request header
//! - [`CookieJar`]: Parsed request cookies
//! - [`State<T>`]: Shared application state
//! - [`RawBody`]: Raw request body bytes

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::bytes::Bytes;
use serde::de::DeserializeOwned;

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
            headers: HashMap::with_capacity(8),
            body: Bytes::new(),
            path_params: HashMap::with_capacity(2),
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
    ///
    /// Header names are normalized to lowercase so the lightweight web stack
    /// can treat them case-insensitively.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    /// Returns a header value using HTTP's case-insensitive matching rules.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        if let Some(value) = self.headers.get(name) {
            return Some(value.as_str());
        }

        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
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
#[derive(Clone, Default)]
pub struct Extensions {
    string_data: HashMap<String, String>,
    typed_data: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions")
            .field("string_keys", &self.string_data.keys().collect::<Vec<_>>())
            .field("typed_count", &self.typed_data.len())
            .finish()
    }
}

impl Extensions {
    /// Create an empty extensions map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a value by key.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.string_data.insert(key.into(), value.into());
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.string_data.get(key).map(String::as_str)
    }

    /// Insert a typed value.
    pub fn insert_typed<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.typed_data.insert(TypeId::of::<T>(), Arc::new(value));
    }

    /// Get a typed value.
    #[must_use]
    pub fn get_typed<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.typed_data
            .get(&TypeId::of::<T>())
            .and_then(|value| value.as_ref().downcast_ref::<T>())
    }

    /// Get a cloned typed value.
    #[must_use]
    pub fn get_typed_cloned<T>(&self) -> Option<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        self.get_typed::<T>().cloned()
    }

    /// Merge data from another extension map.
    pub(crate) fn extend_from(&mut self, other: &Self) {
        self.string_data.extend(other.string_data.clone());
        self.typed_data.extend(
            other
                .typed_data
                .iter()
                .map(|(type_id, value)| (*type_id, Arc::clone(value))),
        );
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
/// For a single parameter, primitive/owned types can be extracted directly
/// (for example `Path<u64>` or `Path<String>`). For named parameters, extract
/// into a `Deserialize` type (for example a struct or `HashMap<String, String>`).
///
/// ```ignore
/// async fn get_user(Path(id): Path<String>) -> String {
///     format!("User {id}")
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Path<T>(pub T);

impl<T> FromRequestParts for Path<T>
where
    T: DeserializeOwned,
{
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        if req.path_params.is_empty() {
            return Err(ExtractionError::bad_request("no path parameters found"));
        }

        if req.path_params.len() == 1
            && let Some(first) = req.path_params.values().next()
            && let Some(value) = deserialize_single_value::<T>(first)
        {
            return Ok(Self(value));
        }

        deserialize_from_string_map(&req.path_params, "path parameters").map(Self)
    }
}

// ─── Query<T> ────────────────────────────────────────────────────────────────

/// Extract query string parameters.
///
/// Deserializes query pairs into typed values.
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

impl<T> FromRequestParts for Query<T>
where
    T: DeserializeOwned,
{
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let qs = req.query.as_deref().unwrap_or("");
        let parsed = parse_urlencoded(qs);

        if parsed.len() == 1
            && let Some(first) = parsed.values().next()
            && let Some(value) = deserialize_single_value::<T>(first)
        {
            return Ok(Self(value));
        }

        deserialize_from_string_map(&parsed, "query parameters").map(Self)
    }
}

fn deserialize_single_value<T>(raw: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    if let Ok(parsed) = serde_json::from_value::<T>(serde_json::Value::String(raw.to_string())) {
        return Some(parsed);
    }

    serde_json::from_value::<T>(coerce_json_scalar(raw)).ok()
}

#[allow(clippy::implicit_hasher)]
fn deserialize_from_string_map<T>(
    values: &HashMap<String, String>,
    context: &str,
) -> Result<T, ExtractionError>
where
    T: DeserializeOwned,
{
    let as_strings = serde_json::Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    );
    if let Ok(parsed) = serde_json::from_value::<T>(as_strings) {
        return Ok(parsed);
    }

    let as_coerced = serde_json::Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), coerce_json_scalar(value)))
            .collect(),
    );
    serde_json::from_value::<T>(as_coerced)
        .map_err(|e| ExtractionError::bad_request(format!("invalid {context}: {e}")))
}

fn coerce_json_scalar(raw: &str) -> serde_json::Value {
    if let Ok(boolean) = raw.parse::<bool>() {
        return serde_json::Value::Bool(boolean);
    }
    if let Ok(integer) = raw.parse::<i64>() {
        return serde_json::Value::Number(integer.into());
    }
    if let Ok(unsigned) = raw.parse::<u64>() {
        return serde_json::Value::Number(unsigned.into());
    }
    if let Ok(float) = raw.parse::<f64>()
        && let Some(number) = serde_json::Number::from_f64(float)
    {
        return serde_json::Value::Number(number);
    }
    serde_json::Value::String(raw.to_string())
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
    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                output.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 < input.len() {
                    let hi = hex_val(input[i + 1]);
                    let lo = hex_val(input[i + 2]);
                    if let (Some(h), Some(l)) = (hi, lo) {
                        output.push(h << 4 | l);
                        i += 3;
                    } else {
                        output.push(b'%');
                        i += 1;
                    }
                } else {
                    output.push(b'%');
                    i += 1;
                }
            }
            b => {
                output.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(output).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Cookie / CookieJar ─────────────────────────────────────────────────────

/// Extract the raw `Cookie` request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie(pub String);

impl FromRequestParts for Cookie {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        header_value_ci(req, "cookie")
            .map(|value| Self(value.to_string()))
            .ok_or_else(|| ExtractionError::bad_request("missing Cookie header"))
    }
}

/// Parsed request cookies.
///
/// `CookieJar` is extracted from the `Cookie` header and provides convenient
/// accessors for cookie lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieJar {
    cookies: HashMap<String, String>,
}

impl CookieJar {
    /// Returns the cookie value for `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }

    /// Returns true when a cookie with `name` exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.cookies.contains_key(name)
    }

    /// Returns the number of cookies in the jar.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Returns true when no cookies are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Iterates over cookie key/value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.cookies
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

impl FromRequestParts for CookieJar {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let cookies = header_value_ci(req, "cookie")
            .map(parse_cookie_header)
            .unwrap_or_default();
        Ok(Self { cookies })
    }
}

fn header_value_ci<'a>(req: &'a Request, header_name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(header_name))
        .map(|(_, value)| value.as_str())
}

fn matches_content_type_media_type(content_type: &str, expected: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

fn matches_json_content_type(content_type: &str) -> bool {
    let Some(media_type) = content_type.split(';').next() else {
        return false;
    };
    let Some((ty, subtype)) = media_type.trim().split_once('/') else {
        return false;
    };
    if !ty.trim().eq_ignore_ascii_case("application") {
        return false;
    }

    let subtype = subtype.trim();
    subtype.eq_ignore_ascii_case("json")
        || subtype.rsplit_once('+').is_some_and(|(prefix, suffix)| {
            !prefix.trim().is_empty() && suffix.eq_ignore_ascii_case("json")
        })
}

#[allow(clippy::implicit_hasher)]
fn parse_cookie_header(raw: &str) -> HashMap<String, String> {
    let mut parsed = HashMap::new();
    for segment in raw.split(';') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value = value.trim().trim_matches('"').to_string();
        parsed.insert(name.to_string(), value);
    }
    parsed
}

// ─── BodyLimits ──────────────────────────────────────────────────────────────

/// Default maximum JSON body size (10 MiB).
const DEFAULT_MAX_JSON_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default maximum form body size (2 MiB).
const DEFAULT_MAX_FORM_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Configurable body size limits for request extractors.
///
/// Middleware can inject this into request extensions to override the default
/// limits on a per-route or per-server basis. Extractors (`Json`, `Form`)
/// check for this type in extensions and fall back to defaults if absent.
///
/// # Example
///
/// ```ignore
/// // Server-wide: allow 50 MiB JSON bodies
/// let limits = BodyLimits::new()
///     .max_json_body_size(50 * 1024 * 1024);
/// // Inject via middleware into request.extensions.insert_typed(limits)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BodyLimits {
    /// Maximum JSON body size in bytes.
    pub max_json_body_size: usize,
    /// Maximum form body size in bytes.
    pub max_form_body_size: usize,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_json_body_size: DEFAULT_MAX_JSON_BODY_SIZE,
            max_form_body_size: DEFAULT_MAX_FORM_BODY_SIZE,
        }
    }
}

impl BodyLimits {
    /// Create body limits with defaults (10 MiB JSON, 2 MiB form).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum JSON body size.
    #[must_use]
    pub fn max_json_body_size(mut self, bytes: usize) -> Self {
        self.max_json_body_size = bytes;
        self
    }

    /// Set the maximum form body size.
    #[must_use]
    pub fn max_form_body_size(mut self, bytes: usize) -> Self {
        self.max_form_body_size = bytes;
        self
    }
}

// ─── Json<T> ─────────────────────────────────────────────────────────────────

/// Extract JSON request body.
///
/// Deserializes the request body as JSON.
///
/// The body size limit defaults to 10 MiB but can be overridden by injecting
/// [`BodyLimits`] into the request extensions via middleware.
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
        let limit = req
            .extensions
            .get_typed::<BodyLimits>()
            .map_or(DEFAULT_MAX_JSON_BODY_SIZE, |l| l.max_json_body_size);
        if req.body.len() > limit {
            return Err(ExtractionError::new(
                super::response::StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "JSON body too large: {} bytes (limit {})",
                    req.body.len(),
                    limit
                ),
            ));
        }

        if let Some(ct) = header_value_ci(&req, "content-type") {
            if !matches_json_content_type(ct) {
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
impl<T: DeserializeOwned> FromRequest for Form<T> {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        let limit = req
            .extensions
            .get_typed::<BodyLimits>()
            .map_or(DEFAULT_MAX_FORM_BODY_SIZE, |l| l.max_form_body_size);
        if req.body.len() > limit {
            return Err(ExtractionError::new(
                super::response::StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "form body too large: {} bytes (limit {})",
                    req.body.len(),
                    limit
                ),
            ));
        }

        if let Some(ct) = header_value_ci(&req, "content-type") {
            if !matches_content_type_media_type(ct, "application/x-www-form-urlencoded") {
                return Err(ExtractionError::new(
                    super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    format!("expected application/x-www-form-urlencoded, got {ct}"),
                ));
            }
        }

        let body_str = std::str::from_utf8(req.body.as_ref())
            .map_err(|e| ExtractionError::bad_request(format!("invalid UTF-8 body: {e}")))?;

        let parsed = parse_urlencoded(body_str);

        if parsed.len() == 1
            && let Some(first) = parsed.values().next()
            && let Some(value) = deserialize_single_value::<T>(first)
        {
            return Ok(Self(value));
        }

        deserialize_from_string_map(&parsed, "form data").map(Self)
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

impl<T> FromRequestParts for State<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        req.extensions
            .get_typed_cloned::<T>()
            .map(Self)
            .ok_or_else(|| {
                ExtractionError::new(
                    super::response::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("state not configured for {}", std::any::type_name::<T>()),
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
    fn path_typed_numeric_extraction() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42").with_path_params(params);

        let Path(id) = Path::<u64>::from_request_parts(&req).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn path_typed_struct_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Params {
            user_id: u64,
            post_id: u32,
        }

        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "7".to_string());
        params.insert("post_id".to_string(), "11".to_string());
        let req = Request::new("GET", "/users/7/posts/11").with_path_params(params);

        let Path(extracted) = Path::<Params>::from_request_parts(&req).unwrap();
        assert_eq!(
            extracted,
            Params {
                user_id: 7,
                post_id: 11
            }
        );
    }

    #[test]
    fn path_typed_deserialization_error() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "not-a-number".to_string());
        let req = Request::new("GET", "/users/not-a-number").with_path_params(params);

        let err = Path::<u64>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid path parameters"));
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
        let req = Request::new("POST", "/login")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"user=alice&pass=secret"));

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
    fn request_header_lookup_is_case_insensitive() {
        let mut req = Request::new("GET", "/").with_header("X-Trace-Id", "trace-123");
        req.headers
            .insert("Authorization".to_string(), "Bearer token".to_string());

        assert_eq!(req.header("x-trace-id"), Some("trace-123"));
        assert_eq!(req.header("X-TRACE-ID"), Some("trace-123"));
        assert_eq!(req.header("authorization"), Some("Bearer token"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Bearer token"));
        assert_eq!(req.header("missing"), None);
    }

    #[test]
    fn missing_path_params() {
        let req = Request::new("GET", "/");
        let result = Path::<String>::from_request_parts(&req);
        assert!(result.is_err());
    }

    #[test]
    fn percent_decode_preserves_invalid_sequences() {
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("x%G1"), "x%G1");
        assert_eq!(percent_decode("x%1G"), "x%1G");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%A"), "%A");
        assert_eq!(percent_decode("%%41"), "%A"); // first % invalid, then valid %41
    }

    #[test]
    fn request_debug_clone() {
        let r = Request::new("GET", "/api/v1");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Request"));
        assert!(dbg.contains("GET"));

        let r2 = r;
        assert_eq!(r2.method, "GET");
        assert_eq!(r2.path, "/api/v1");
    }

    #[test]
    fn extensions_debug_clone_default() {
        let e = Extensions::default();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Extensions"));

        let e2 = e;
        assert!(e2.get("missing").is_none());
    }

    #[test]
    fn extraction_error_debug_clone() {
        let e = ExtractionError::bad_request("missing field");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ExtractionError"));
        assert!(dbg.contains("missing field"));

        let e2 = e;
        assert_eq!(e2.message, "missing field");
    }

    #[test]
    fn typed_state_extraction() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            name: String,
        }

        let mut req = Request::new("GET", "/");
        req.extensions.insert_typed(AppState {
            name: "alpha".to_string(),
        });

        let State(state) = State::<AppState>::from_request_parts(&req).unwrap();
        assert_eq!(
            state,
            AppState {
                name: "alpha".to_string()
            }
        );
    }

    #[test]
    fn typed_state_missing_returns_error() {
        #[derive(Clone, Debug)]
        struct AppState;

        let req = Request::new("GET", "/");
        let err = State::<AppState>::from_request_parts(&req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(err.message.contains("state not configured"));
    }

    #[test]
    fn form_body_too_large() {
        let oversized = vec![b'a'; DEFAULT_MAX_FORM_BODY_SIZE + 1];
        let req = Request::new("POST", "/form").with_body(Bytes::from(oversized));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn json_body_too_large() {
        let oversized = vec![b'a'; DEFAULT_MAX_JSON_BODY_SIZE + 1];
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(oversized));
        let result = Json::<serde_json::Value>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn json_content_type_header_name_case_insensitive() {
        let req = Request::new("POST", "/data")
            .with_header("Content-Type", "application/json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn json_content_type_allows_parameters_but_rejects_substring_tricks() {
        let with_charset = Request::new("POST", "/data")
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(with_charset).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));

        let structured_suffix = Request::new("POST", "/data")
            .with_header("content-type", "application/cloudevents+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(structured_suffix).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));

        let misleading = Request::new("POST", "/data")
            .with_header("content-type", "text/plain; note=application/json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(misleading).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let wrong_top_level = Request::new("POST", "/data")
            .with_header("content-type", "text/cloudevents+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(wrong_top_level).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let empty_structured_prefix = Request::new("POST", "/data")
            .with_header("content-type", "application/+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(empty_structured_prefix).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn json_missing_content_type_still_parses_valid_json() {
        let req = Request::new("POST", "/data").with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn form_wrong_content_type() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "text/plain")
            .with_body(Bytes::from_static(b"user=alice"));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn form_content_type_header_name_case_insensitive() {
        let req = Request::new("POST", "/form")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"user=alice&role=admin"));
        let Form(values) = Form::<HashMap<String, String>>::from_request(req).unwrap();
        assert_eq!(values.get("user").map(String::as_str), Some("alice"));
        assert_eq!(values.get("role").map(String::as_str), Some("admin"));
    }

    #[test]
    fn form_content_type_allows_parameters_but_rejects_substring_tricks() {
        let with_charset = Request::new("POST", "/form")
            .with_header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .with_body(Bytes::from_static(b"user=alice&role=admin"));
        let Form(values) = Form::<HashMap<String, String>>::from_request(with_charset).unwrap();
        assert_eq!(values.get("user").map(String::as_str), Some("alice"));
        assert_eq!(values.get("role").map(String::as_str), Some("admin"));

        let misleading = Request::new("POST", "/form")
            .with_header(
                "content-type",
                "application/x-www-form-urlencoded-bogus; charset=utf-8",
            )
            .with_body(Bytes::from_static(b"user=alice"));
        let err = Form::<HashMap<String, String>>::from_request(misleading).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn form_missing_content_type_still_parses_urlencoded_body() {
        let req = Request::new("POST", "/form").with_body(Bytes::from_static(b"user=alice"));
        let Form(values) = Form::<HashMap<String, String>>::from_request(req).unwrap();
        assert_eq!(values.get("user").map(String::as_str), Some("alice"));
    }

    #[test]
    fn form_invalid_utf8() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"\xff\xfe"));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn json_invalid_body() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"not json"));
        let result = Json::<serde_json::Value>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn query_empty_string() {
        let req = Request::new("GET", "/items");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn query_percent_encoded_values() {
        let req = Request::new("GET", "/search").with_query("q=hello+world&tag=%23rust");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(params.get("q").unwrap(), "hello world");
        assert_eq!(params.get("tag").unwrap(), "#rust");
    }

    #[test]
    fn query_typed_struct_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Pagination {
            page: u32,
            per_page: u16,
            active: bool,
        }

        let req = Request::new("GET", "/items").with_query("page=3&per_page=25&active=true");
        let Query(pagination) = Query::<Pagination>::from_request_parts(&req).unwrap();
        assert_eq!(
            pagination,
            Pagination {
                page: 3,
                per_page: 25,
                active: true
            }
        );
    }

    #[test]
    fn query_typed_scalar_extraction() {
        let req = Request::new("GET", "/items").with_query("value=17");
        let Query(value) = Query::<u32>::from_request_parts(&req).unwrap();
        assert_eq!(value, 17);
    }

    #[test]
    fn query_typed_deserialization_error() {
        let req = Request::new("GET", "/items").with_query("page=abc");
        let err = Query::<u32>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid query parameters"));
    }

    #[test]
    fn path_multiple_params() {
        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "42".to_string());
        params.insert("post_id".to_string(), "7".to_string());
        let req = Request::new("GET", "/users/42/posts/7").with_path_params(params.clone());

        let Path(extracted) = Path::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(extracted, params);
    }

    #[test]
    fn raw_body_empty() {
        let req = Request::new("POST", "/upload");
        let RawBody(body) = RawBody::from_request(req).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn cookie_extraction_raw_header() {
        let req = Request::new("GET", "/").with_header("Cookie", "session=abc; theme=dark");
        let Cookie(raw) = Cookie::from_request_parts(&req).unwrap();
        assert_eq!(raw, "session=abc; theme=dark");
    }

    #[test]
    fn cookie_extraction_missing_header_is_error() {
        let req = Request::new("GET", "/");
        let err = Cookie::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cookie_jar_parses_cookie_pairs() {
        let req = Request::new("GET", "/").with_header("cookie", "session=abc; theme=dark; id=42");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("session"), Some("abc"));
        assert_eq!(jar.get("theme"), Some("dark"));
        assert_eq!(jar.get("id"), Some("42"));
        assert_eq!(jar.len(), 3);
    }

    #[test]
    fn cookie_jar_last_duplicate_wins() {
        let req = Request::new("GET", "/").with_header("cookie", "token=old; token=new");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("token"), Some("new"));
    }

    #[test]
    fn cookie_jar_ignores_malformed_segments() {
        let req = Request::new("GET", "/").with_header(
            "cookie",
            "good=1; malformed; =missing_name; spaced = ok ; quoted=\"v\"",
        );
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("good"), Some("1"));
        assert_eq!(jar.get("spaced"), Some("ok"));
        assert_eq!(jar.get("quoted"), Some("v"));
        assert!(!jar.contains("malformed"));
    }

    #[test]
    fn cookie_jar_missing_header_is_empty() {
        let req = Request::new("GET", "/");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert!(jar.is_empty());
    }

    #[test]
    fn extraction_error_into_response() {
        use crate::web::response::IntoResponse;
        let err = ExtractionError::bad_request("missing field");
        let resp = err.into_response();
        assert_eq!(resp.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers.get("content-type").map(String::as_str),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn extensions_extend_preserves_string_and_typed_values() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            id: u32,
        }

        let mut base = Extensions::new();
        base.insert("trace_id", "abc");
        base.insert_typed(AppState { id: 7 });

        let mut req_extensions = Extensions::new();
        req_extensions.insert("request_id", "r-1");
        req_extensions.extend_from(&base);

        assert_eq!(req_extensions.get("trace_id"), Some("abc"));
        assert_eq!(req_extensions.get("request_id"), Some("r-1"));
        assert_eq!(
            req_extensions.get_typed_cloned::<AppState>(),
            Some(AppState { id: 7 })
        );
    }

    #[test]
    fn extensions_hold_multiple_typed_values_and_override_same_type() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            id: u32,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        struct FeatureFlags {
            experimental: bool,
        }

        let mut extensions = Extensions::new();
        extensions.insert_typed(AppState { id: 1 });
        extensions.insert_typed(FeatureFlags { experimental: true });
        // Same TypeId should be replaced by the most recent insert.
        extensions.insert_typed(AppState { id: 2 });

        assert_eq!(
            extensions.get_typed_cloned::<AppState>(),
            Some(AppState { id: 2 })
        );
        assert_eq!(
            extensions.get_typed_cloned::<FeatureFlags>(),
            Some(FeatureFlags { experimental: true })
        );
    }

    // ── Scalar-guard regression tests ────────────────────────────────────

    #[test]
    fn path_scalar_with_multiple_params_falls_through_to_struct() {
        // Before the len()==1 guard, Path<u32> with 2+ params would
        // nondeterministically pick whichever value HashMap yielded first.
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct PostRef {
            user_id: u32,
            post_id: u32,
        }

        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "42".to_string());
        params.insert("post_id".to_string(), "7".to_string());
        let req = Request::new("GET", "/users/42/posts/7").with_path_params(params);

        // Scalar extraction must NOT succeed — falls through to struct deser.
        assert!(Path::<u32>::from_request_parts(&req).is_err());

        // Struct extraction succeeds deterministically.
        let Path(post_ref) = Path::<PostRef>::from_request_parts(&req).unwrap();
        assert_eq!(
            post_ref,
            PostRef {
                user_id: 42,
                post_id: 7
            }
        );
    }

    #[test]
    fn query_scalar_with_multiple_params_falls_through_to_struct() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Pagination {
            page: u32,
            per_page: u32,
        }

        let req = Request::new("GET", "/items").with_query("page=3&per_page=25");

        // Scalar extraction must NOT succeed with 2 query params.
        assert!(Query::<u32>::from_request_parts(&req).is_err());

        // Struct extraction works correctly.
        let Query(pg) = Query::<Pagination>::from_request_parts(&req).unwrap();
        assert_eq!(
            pg,
            Pagination {
                page: 3,
                per_page: 25
            }
        );
    }
}
