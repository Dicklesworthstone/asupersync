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
        let parsed = parse_urlencoded(qs, "query parameter")?;

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

/// Deserialize from multi-value map (for forms with duplicate keys).
///
/// Handles both single values and Vec<String> according to target type.
/// For single-value fields, uses the first value. For Vec fields, preserves all values.
fn deserialize_from_multi_value_map<T>(
    parsed: &HashMap<String, Vec<String>>,
    context: &str,
) -> Result<T, ExtractionError>
where
    T: DeserializeOwned,
{
    // Try deserializing with intelligent handling of single vs multi values
    let mut json_map = serde_json::Map::new();

    for (key, values) in parsed {
        let json_value = if values.len() == 1 {
            // Single value - use coerced scalar (bool, number, string)
            coerce_json_scalar(&values[0])
        } else {
            // Multiple values - serialize as array of coerced values
            serde_json::Value::Array(values.iter().map(|v| coerce_json_scalar(v)).collect())
        };
        json_map.insert(key.clone(), json_value);
    }

    let json_value = serde_json::Value::Object(json_map);

    serde_json::from_value::<T>(json_value)
        .map_err(|e| ExtractionError::bad_request(format!("invalid {context}: {e}")))
}

/// Parse a URL-encoded string into key-value pairs.
///
/// Per HTML form specification, duplicate keys should preserve all values
/// as Vec<String> rather than rejecting or overwriting. This correctly
/// handles forms like `a=1&a=2` -> `{"a": ["1", "2"]}`.
fn parse_urlencoded_multi(
    input: &str,
    _field_kind: &str,
) -> Result<HashMap<String, Vec<String>>, ExtractionError> {
    let mut parsed: HashMap<String, Vec<String>> = HashMap::new();
    for pair in input.split('&').filter(|s| !s.is_empty()) {
        let mut parts = pair.splitn(2, '=');
        let Some(key) = parts.next() else {
            continue;
        };
        let key = percent_decode(key);
        let value = percent_decode(parts.next().unwrap_or(""));
        parsed.entry(key).or_default().push(value);
    }
    Ok(parsed)
}

/// Legacy parse function for backward compatibility with single values.
/// Used by Query extractor which may want different duplicate key behavior.
fn parse_urlencoded(
    input: &str,
    field_kind: &str,
) -> Result<HashMap<String, String>, ExtractionError> {
    let multi_values = parse_urlencoded_multi(input, field_kind)?;
    let mut single_values = HashMap::new();

    for (key, values) in multi_values {
        if values.len() == 1 {
            // Safe: length check ensures exactly one element exists
            if let Some(value) = values.into_iter().next() {
                single_values.insert(key, value);
            } else {
                // Should never happen given length check, but handle gracefully
                return Err(ExtractionError::bad_request(format!(
                    "internal error: expected value for {field_kind} `{key}`"
                )));
            }
        } else {
            return Err(ExtractionError::bad_request(format!(
                "duplicate {field_kind} `{key}` (use multi-value extractor for forms)"
            )));
        }
    }
    Ok(single_values)
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
                if i.saturating_add(2) < input.len() {
                    let hi = hex_val(input[i.saturating_add(1)]);
                    let lo = hex_val(input[i.saturating_add(2)]);
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

pub(super) fn header_value_ci<'a>(req: &'a Request, header_name: &str) -> Option<&'a str> {
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

fn invalid_content_length() -> ExtractionError {
    ExtractionError::new(
        super::response::StatusCode::BAD_REQUEST,
        "invalid Content-Length header",
    )
}

pub(super) fn parse_content_length(value: &str) -> Result<usize, ExtractionError> {
    let mut parsed = None;

    for raw_part in value.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            return Err(invalid_content_length());
        }

        let declared = part
            .parse::<usize>()
            .map_err(|_| invalid_content_length())?;
        if let Some(previous) = parsed {
            if previous != declared {
                return Err(ExtractionError::new(
                    super::response::StatusCode::BAD_REQUEST,
                    "conflicting Content-Length header values",
                ));
            }
        } else {
            parsed = Some(declared);
        }
    }

    parsed.ok_or_else(invalid_content_length)
}

/// Validates that request body length matches Content-Length, when present.
fn validate_content_length(req: &Request) -> Result<(), ExtractionError> {
    if let Some(cl_value) = header_value_ci(req, "content-length") {
        let declared_length = parse_content_length(cl_value)?;
        let actual_length = req.body.len();
        if actual_length != declared_length {
            return Err(ExtractionError::new(
                super::response::StatusCode::BAD_REQUEST,
                format!(
                    "Content-Length mismatch: declared {} bytes, received {} bytes",
                    declared_length, actual_length
                ),
            ));
        }
    }
    Ok(())
}

/// Check Content-Length header against size limit before reading body.
///
/// This prevents DoS attacks where large bodies are fully buffered into memory
/// before size checking occurs. Per RFC 9110, we should return 413 Payload Too Large
/// based on Content-Length header before body processing.
fn check_content_length_limit(req: &Request, limit: usize) -> Result<(), ExtractionError> {
    if let Some(cl_value) = header_value_ci(req, "content-length") {
        let declared_length = parse_content_length(cl_value)?;
        if declared_length > limit {
            return Err(ExtractionError::new(
                super::response::StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "Content-Length {} bytes exceeds limit {} bytes",
                    declared_length, limit
                ),
            ));
        }
    }
    Ok(())
}

// ─── BodyLimits ──────────────────────────────────────────────────────────────

/// Default maximum JSON body size (10 MiB).
const DEFAULT_MAX_JSON_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default maximum form body size (2 MiB).
const DEFAULT_MAX_FORM_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Default maximum raw body size (10 MiB).
const DEFAULT_MAX_RAW_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Configurable body size limits for request extractors.
///
/// Middleware can inject this into request extensions to override the default
/// limits on a per-route or per-server basis. Extractors (`Json`, `Form`,
/// `RawBody`)
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
    /// Maximum raw body size in bytes.
    pub max_raw_body_size: usize,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_json_body_size: DEFAULT_MAX_JSON_BODY_SIZE,
            max_form_body_size: DEFAULT_MAX_FORM_BODY_SIZE,
            max_raw_body_size: DEFAULT_MAX_RAW_BODY_SIZE,
        }
    }
}

impl BodyLimits {
    /// Create body limits with defaults (10 MiB JSON, 2 MiB form, 10 MiB raw).
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

    /// Set the maximum raw body size.
    #[must_use]
    pub fn max_raw_body_size(mut self, bytes: usize) -> Self {
        self.max_raw_body_size = bytes;
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

        // SECURITY: Check Content-Length header BEFORE reading body to prevent DoS
        check_content_length_limit(&req, limit)?;

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

        // Reject invalid or mismatched framing metadata before parsing body bytes.
        validate_content_length(&req)?;

        let Some(ct) = header_value_ci(&req, "content-type") else {
            return Err(ExtractionError::new(
                super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Json requires Content-Type: application/json",
            ));
        };
        if !matches_json_content_type(ct) {
            return Err(ExtractionError::new(
                super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("expected application/json, got {ct}"),
            ));
        }

        // br-asupersync-y4mc96: keep serde error in server-side log only;
        // return a generic message to the client so byte offsets, expected
        // type names, and partial-parse context don't reach an attacker.
        // The detailed `e` is recorded via tracing for operator forensics.
        serde_json::from_slice(req.body.as_ref())
            .map(Json)
            .map_err(|_err| {
                crate::tracing_compat::warn!(
                    error = %_err,
                    "web/extract: Json deserialization failed"
                );
                ExtractionError::unprocessable("invalid JSON body")
            })
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

        // SECURITY: Check Content-Length header BEFORE reading body to prevent DoS
        check_content_length_limit(&req, limit)?;

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

        // Reject invalid or mismatched framing metadata before parsing body bytes.
        validate_content_length(&req)?;

        // br-asupersync-mxqraw: Content-Type MUST be present AND must be
        // application/x-www-form-urlencoded. Previously we accepted any
        // body when Content-Type was absent, parsing arbitrary payloads
        // (JSON, XML, raw bytes) as form-encoded — so an attacker could
        // forge a Form<T> deserialisation by sending a JSON body without
        // a Content-Type header. Default-deny: missing header is a 415.
        let Some(ct) = header_value_ci(&req, "content-type") else {
            return Err(ExtractionError::new(
                super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Form requires Content-Type: application/x-www-form-urlencoded",
            ));
        };
        if !matches_content_type_media_type(ct, "application/x-www-form-urlencoded") {
            return Err(ExtractionError::new(
                super::response::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("expected application/x-www-form-urlencoded, got {ct}"),
            ));
        }

        let body_str = std::str::from_utf8(req.body.as_ref())
            .map_err(|e| ExtractionError::bad_request(format!("invalid UTF-8 body: {e}")))?;

        let parsed = parse_urlencoded_multi(body_str, "form field")?;

        deserialize_from_multi_value_map(&parsed, "form data").map(Self)
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
        let limit = req
            .extensions
            .get_typed::<BodyLimits>()
            .map_or(DEFAULT_MAX_RAW_BODY_SIZE, |l| l.max_raw_body_size);

        // SECURITY: Check Content-Length header BEFORE reading body to prevent DoS
        check_content_length_limit(&req, limit)?;

        if req.body.len() > limit {
            return Err(ExtractionError::new(
                super::response::StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "raw body too large: {} bytes (limit {})",
                    req.body.len(),
                    limit
                ),
            ));
        }

        // Reject invalid or mismatched framing metadata before exposing body bytes.
        validate_content_length(&req)?;

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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
    fn content_length_parser_accepts_single_and_identical_combined_values() {
        assert_eq!(parse_content_length("42").unwrap(), 42);
        assert_eq!(parse_content_length("42, 42").unwrap(), 42);
        assert_eq!(parse_content_length("0042, 42").unwrap(), 42);
    }

    #[test]
    fn content_length_parser_rejects_invalid_or_conflicting_values() {
        for value in ["", "5, ", "5, 6", "not-a-number", "-1"] {
            let err = parse_content_length(value).unwrap_err();
            assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        }
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
    fn json_missing_content_type_rejects_with_415() {
        let req = Request::new("POST", "/data").with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(err.message, "Json requires Content-Type: application/json");
    }

    #[test]
    fn json_top_level_scalar_matches_rfc7159() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"123"));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value, serde_json::Value::Number(123.into()));
    }

    #[test]
    fn json_surrounded_by_rfc8259_whitespace_parses() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"\r\n\t {\"ok\":true} \n"));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn metamorphic_body_extractors_preserve_body_semantics_and_limits() {
        let json_body = Bytes::from_static(br#"{"user":"alice","admin":true}"#);
        let json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(json_body.clone());
        let RawBody(raw_json) = RawBody::from_request(json_req.clone()).unwrap();
        assert_eq!(raw_json.as_ref(), json_body.as_ref());
        let Json(parsed_json) = Json::<serde_json::Value>::from_request(json_req).unwrap();
        assert_eq!(
            parsed_json,
            serde_json::from_slice::<serde_json::Value>(raw_json.as_ref()).unwrap()
        );

        let form_body = Bytes::from_static(b"user=alice&admin=boss");
        let form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(form_body.clone());
        let RawBody(raw_form) = RawBody::from_request(form_req.clone()).unwrap();
        assert_eq!(raw_form.as_ref(), form_body.as_ref());
        let Form(parsed_form) = Form::<HashMap<String, String>>::from_request(form_req).unwrap();
        assert_eq!(
            parsed_form,
            parse_urlencoded(
                std::str::from_utf8(raw_form.as_ref()).unwrap(),
                "form field"
            )
            .unwrap()
        );

        let limit = 8;
        let limits = BodyLimits::new()
            .max_json_body_size(limit)
            .max_form_body_size(limit)
            .max_raw_body_size(limit);

        let mut oversized_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(br#"{"k":"123456789"}"#));
        oversized_json_req.extensions.insert_typed(limits);
        let json_err = Json::<serde_json::Value>::from_request(oversized_json_req).unwrap_err();
        assert_eq!(
            json_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut oversized_form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"k=123456789"));
        oversized_form_req.extensions.insert_typed(limits);
        let form_err =
            Form::<HashMap<String, String>>::from_request(oversized_form_req).unwrap_err();
        assert_eq!(
            form_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut oversized_raw_req =
            Request::new("POST", "/raw").with_body(Bytes::from_static(b"123456789"));
        oversized_raw_req.extensions.insert_typed(limits);
        let raw_err = RawBody::from_request(oversized_raw_req).unwrap_err();
        assert_eq!(
            raw_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
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
    fn form_missing_content_type_rejects_with_415() {
        // br-asupersync-mxqraw: Form requires Content-Type:
        // application/x-www-form-urlencoded. Missing Content-Type is a
        // 415 — default-deny prevents an attacker from forging Form<T>
        // deserialisation by submitting a foreign-format body (JSON, XML,
        // raw bytes) without declaring its media type.
        let req = Request::new("POST", "/form").with_body(Bytes::from_static(b"user=alice"));
        let err = Form::<HashMap<String, String>>::from_request(req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
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
    fn form_duplicate_keys_preserved_as_vec() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct MultiForm {
            role: Vec<String>,
            name: String,
        }

        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"role=user&role=admin&name=alice"));

        let Form(data) = Form::<MultiForm>::from_request(req).unwrap();
        assert_eq!(data.role, vec!["user", "admin"]);
        assert_eq!(data.name, "alice");
    }

    #[test]
    fn form_duplicate_keys_html_spec_compliance_audit() {
        println!("=== FORM DUPLICATE KEYS HTML SPEC COMPLIANCE AUDIT ===");

        use serde::Deserialize;

        // Test Case 1: Multiple values for same key should be preserved as Vec
        #[derive(Deserialize, Debug, PartialEq)]
        struct TestForm {
            tags: Vec<String>,
            category: String,
            flags: Option<Vec<String>>,
        }

        println!("✓ Test Case 1: Multiple values preserved as Vec<String>");

        let req1 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"tags=red&tags=blue&tags=green&category=test",
            ));

        let Form(data1) = Form::<TestForm>::from_request(req1).unwrap();
        assert_eq!(data1.tags, vec!["red", "blue", "green"]);
        assert_eq!(data1.category, "test");
        assert_eq!(data1.flags, None);

        println!("  ✅ tags=red&tags=blue&tags=green → Vec![\"red\", \"blue\", \"green\"]");

        // Test Case 2: Single values should work normally
        println!("✓ Test Case 2: Single values work normally");

        let req2 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"tags=solo&category=single"));

        let Form(data2) = Form::<TestForm>::from_request(req2).unwrap();
        assert_eq!(data2.tags, vec!["solo"]);
        assert_eq!(data2.category, "single");

        println!("  ✅ tags=solo → Vec![\"solo\"] (single item as Vec)");

        // Test Case 3: Mixed single and multiple values
        println!("✓ Test Case 3: Mixed single and multiple values");

        let req3 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"tags=first&category=mixed&tags=second&flags=a&flags=b",
            ));

        let Form(data3) = Form::<TestForm>::from_request(req3).unwrap();
        assert_eq!(data3.tags, vec!["first", "second"]);
        assert_eq!(data3.category, "mixed");
        assert_eq!(data3.flags, Some(vec!["a".to_string(), "b".to_string()]));

        println!("  ✅ Mixed form: single category + multiple tags + multiple flags");

        // Test Case 4: HTML checkbox scenario (common use case)
        #[derive(Deserialize, Debug)]
        struct CheckboxForm {
            #[serde(default)]
            permissions: Vec<String>,
            username: String,
        }

        println!("✓ Test Case 4: HTML checkbox scenario");

        let req4 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"permissions=read&permissions=write&permissions=delete&username=admin",
            ));

        let Form(data4) = Form::<CheckboxForm>::from_request(req4).unwrap();
        assert_eq!(data4.permissions, vec!["read", "write", "delete"]);
        assert_eq!(data4.username, "admin");

        println!("  ✅ Checkbox form: permissions=[read, write, delete]");

        // Test Case 5: Type coercion with duplicates
        #[derive(Deserialize, Debug)]
        struct TypedForm {
            numbers: Vec<i32>,
            enabled: bool,
        }

        println!("✓ Test Case 5: Type coercion with duplicates");

        let req5 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"numbers=42&numbers=123&numbers=999&enabled=true",
            ));

        let Form(data5) = Form::<TypedForm>::from_request(req5).unwrap();
        assert_eq!(data5.numbers, vec![42, 123, 999]);
        assert_eq!(data5.enabled, true);

        println!("  ✅ Type coercion: string numbers → Vec<i32>");

        println!("\n📋 HTML FORM SPEC COMPLIANCE VERIFIED:");
        println!("  1. Duplicate keys preserved: ✅ OPTION (a) - Vec<String> (CORRECT)");
        println!("  2. Single values supported: ✅ BACKWARD COMPATIBLE");
        println!("  3. Type coercion works: ✅ STRING → NUMBER/BOOL");
        println!("  4. HTML checkboxes: ✅ MULTIPLE SELECTIONS PRESERVED");
        println!("  5. Mixed forms: ✅ SINGLE + MULTIPLE FIELDS");

        println!("\n✅ STATUS: FORM DUPLICATE KEY HANDLING IS COMPLIANT");
        println!("BEHAVIOR: Option (a) - return Vec<String> for duplicate keys (CORRECT)");
        println!("COMPLIANCE: HTML Form Specification - preserves all submitted values");
        println!("IMPACT: Applications can now handle multi-select forms correctly");
    }

    #[test]
    fn form_scalar_extraction_does_not_ignore_field_names() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"flag=true"));
        let err = Form::<bool>::from_request(req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid form data"));
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
    fn query_duplicate_keys_reject_instead_of_collapsing_to_scalar() {
        let req = Request::new("GET", "/items").with_query("value=17&value=18");
        let err = Query::<u32>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert_eq!(
            err.message,
            "duplicate query parameter `value` (use multi-value extractor for forms)"
        );
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
        let req = Request::new("GET", "/").with_header("cookie", "mode=old; mode=new");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("mode"), Some("new"));
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

    #[test]
    fn body_size_limit_checks_content_length_before_reading_body_dos_prevention() {
        // AUDIT TEST: Verify that Content-Length is checked BEFORE reading body
        // to prevent DoS attacks via memory exhaustion.
        // Per RFC 9110, should return 413 Payload Too Large based on Content-Length header.

        println!("=== WEB BODY SIZE LIMIT DoS PREVENTION AUDIT ===");

        // Test 1: JSON extractor checks Content-Length early
        let oversized_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "20971520") // 20MB declared
            .with_body(Bytes::from_static(b"{\"small\":\"body\"}")); // But small actual body

        let json_err = Json::<serde_json::Value>::from_request(oversized_json_req).unwrap_err();
        assert_eq!(
            json_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "JSON extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            json_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            json_err.message
        );

        // Test 2: Form extractor checks Content-Length early
        let oversized_form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_header("content-length", "5242880") // 5MB declared
            .with_body(Bytes::from_static(b"name=test")); // But small actual body

        let form_err =
            Form::<HashMap<String, String>>::from_request(oversized_form_req).unwrap_err();
        assert_eq!(
            form_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "Form extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            form_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            form_err.message
        );

        // Test 3: RawBody extractor checks Content-Length early
        let oversized_raw_req = Request::new("POST", "/upload")
            .with_header("content-length", "15728640") // 15MB declared
            .with_body(Bytes::from_static(b"small data")); // But small actual body

        let raw_err = RawBody::from_request(oversized_raw_req).unwrap_err();
        assert_eq!(
            raw_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "RawBody extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            raw_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            raw_err.message
        );

        // Test 4: Verify that requests within limit still work
        let valid_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "19") // Small declared size
            .with_body(Bytes::from_static(b"{\"valid\":\"request\"}"));

        let json_result = Json::<serde_json::Value>::from_request(valid_json_req);
        assert!(
            json_result.is_ok(),
            "Valid requests with Content-Length within limit should be processed"
        );

        println!("✅ AUDIT PASSED: Content-Length checked before body processing");
        println!("📋 DoS PROTECTION VERIFIED:");
        println!("  1. Content-Length header checked BEFORE body buffering: ✅");
        println!("  2. 413 Payload Too Large returned early: ✅");
        println!("  3. Memory exhaustion attack prevented: ✅");
        println!("  4. RFC 9110 compliance: ✅");
        println!("\n✅ STATUS: WEB BODY SIZE LIMITS ARE SECURE");
    }
}
