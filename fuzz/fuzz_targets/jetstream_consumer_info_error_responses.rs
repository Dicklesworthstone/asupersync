#![no_main]

//! Structure-aware fuzz target for JetStream ConsumerInfo error responses.
//!
//! Focuses on `$JS.API.CONSUMER.INFO.*`-shaped envelopes that carry an `error`
//! object, with wrapper fields and nested metadata that may shadow the same
//! keys (`code`, `err_code`, `description`). The parser oracle is the
//! `fuzz_parse_api_error()` helper from `src/messaging/jetstream.rs`.

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{JsError, fuzz_parse_api_error};
use libfuzzer_sys::fuzz_target;

const MAX_STRING_LEN: usize = 256;
const MAX_JSON_BYTES: usize = 16 * 1024;

#[derive(Arbitrary, Debug, Clone)]
struct ConsumerInfoErrorFuzz {
    error: ErrorObject,
    wrapper: ConsumerInfoWrapper,
    shadow: ShadowFields,
}

#[derive(Arbitrary, Debug, Clone)]
struct ErrorObject {
    code: NumericField,
    err_code: NumericField,
    description: StringField,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConsumerInfoWrapper {
    stream: String,
    consumer: String,
    include_type: bool,
    include_created: bool,
    include_state: bool,
    include_config: bool,
    include_num_pending: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct ShadowFields {
    top_level_code: Option<u32>,
    top_level_err_code: Option<u32>,
    top_level_description: Option<String>,
    state_code: Option<u32>,
    state_description: Option<String>,
    config_description: Option<String>,
}

#[derive(Arbitrary, Debug, Clone)]
enum NumericField {
    Missing,
    Number(u32),
    Quoted(String),
    Null,
}

#[derive(Arbitrary, Debug, Clone)]
enum StringField {
    Missing,
    Text(String),
    Escaped(String),
    Number(u64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorFingerprint {
    Api { code: u32, description: String },
    StreamNotFound(String),
    ConsumerNotFound { stream: String, consumer: String },
    NotAcked,
    AlreadyAcknowledged,
    InvalidConfig(String),
    ParseError(String),
    Nats(String),
}

impl ConsumerInfoErrorFuzz {
    fn too_large(&self) -> bool {
        self.wrapper.stream.len() > MAX_STRING_LEN
            || self.wrapper.consumer.len() > MAX_STRING_LEN
            || self
                .shadow
                .top_level_description
                .as_ref()
                .is_some_and(|s| s.len() > MAX_STRING_LEN)
            || self
                .shadow
                .state_description
                .as_ref()
                .is_some_and(|s| s.len() > MAX_STRING_LEN)
            || self
                .shadow
                .config_description
                .as_ref()
                .is_some_and(|s| s.len() > MAX_STRING_LEN)
            || self.error.too_large()
    }

    fn bare_error_response(&self) -> String {
        format!("{{\"error\":{}}}", self.error.render())
    }

    fn consumer_info_response(&self, error_first: bool) -> String {
        let mut fields = Vec::new();

        if let Some(code) = self.shadow.top_level_code {
            fields.push(format!("\"code\":{code}"));
        }
        if let Some(err_code) = self.shadow.top_level_err_code {
            fields.push(format!("\"err_code\":{err_code}"));
        }
        if let Some(description) = &self.shadow.top_level_description {
            fields.push(format!("\"description\":\"{}\"", json_escape(description)));
        }
        if self.wrapper.include_type {
            fields.push("\"type\":\"io.nats.jetstream.api.v1.consumer_info_response\"".to_string());
        }
        fields.push(format!(
            "\"stream_name\":\"{}\"",
            json_escape(&self.wrapper.stream)
        ));
        fields.push(format!(
            "\"name\":\"{}\"",
            json_escape(&self.wrapper.consumer)
        ));
        if self.wrapper.include_created {
            fields.push("\"created\":\"2026-04-28T21:00:00Z\"".to_string());
        }
        if self.wrapper.include_num_pending {
            fields.push("\"num_pending\":42".to_string());
        }
        if self.wrapper.include_state {
            let mut state_fields = vec![
                "\"ack_floor\":7".to_string(),
                "\"delivered\":11".to_string(),
            ];
            if let Some(code) = self.shadow.state_code {
                state_fields.push(format!("\"code\":{code}"));
            }
            if let Some(description) = &self.shadow.state_description {
                state_fields.push(format!("\"description\":\"{}\"", json_escape(description)));
            }
            fields.push(format!("\"state\":{{{}}}", state_fields.join(",")));
        }
        if self.wrapper.include_config {
            let mut config_fields = vec![
                "\"ack_policy\":\"explicit\"".to_string(),
                "\"max_deliver\":5".to_string(),
            ];
            if let Some(description) = &self.shadow.config_description {
                config_fields.push(format!("\"description\":\"{}\"", json_escape(description)));
            }
            fields.push(format!("\"config\":{{{}}}", config_fields.join(",")));
        }

        let error_field = format!("\"error\":{}", self.error.render());
        if error_first {
            fields.insert(0, error_field);
        } else {
            fields.push(error_field);
        }

        format!("{{{}}}", fields.join(","))
    }
}

impl ErrorObject {
    fn too_large(&self) -> bool {
        self.code.too_large() || self.err_code.too_large() || self.description.too_large()
    }

    fn render(&self) -> String {
        let mut fields = Vec::new();
        if let Some(field) = self.code.render("code") {
            fields.push(field);
        }
        if let Some(field) = self.err_code.render("err_code") {
            fields.push(field);
        }
        if let Some(field) = self.description.render("description") {
            fields.push(field);
        }
        format!("{{{}}}", fields.join(","))
    }

    fn expected_fingerprint(&self) -> ErrorFingerprint {
        let description = self
            .description
            .string_value()
            .unwrap_or_else(|| "unknown error".to_string());
        if self.err_code.numeric_value() == Some(10059) {
            ErrorFingerprint::StreamNotFound(description)
        } else {
            ErrorFingerprint::Api {
                code: self.code.numeric_value().unwrap_or(0),
                description,
            }
        }
    }
}

impl NumericField {
    fn too_large(&self) -> bool {
        matches!(self, Self::Quoted(s) if s.len() > MAX_STRING_LEN)
    }

    fn render(&self, key: &str) -> Option<String> {
        match self {
            Self::Missing => None,
            Self::Number(value) => Some(format!("\"{key}\":{value}")),
            Self::Quoted(value) => Some(format!("\"{key}\":\"{}\"", json_escape(value))),
            Self::Null => Some(format!("\"{key}\":null")),
        }
    }

    fn numeric_value(&self) -> Option<u32> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }
}

impl StringField {
    fn too_large(&self) -> bool {
        matches!(self, Self::Text(s) | Self::Escaped(s) if s.len() > MAX_STRING_LEN)
    }

    fn render(&self, key: &str) -> Option<String> {
        match self {
            Self::Missing => None,
            Self::Text(value) | Self::Escaped(value) => {
                Some(format!("\"{key}\":\"{}\"", json_escape(value)))
            }
            Self::Number(value) => Some(format!("\"{key}\":{value}")),
            Self::Bool(value) => Some(format!("\"{key}\":{value}")),
            Self::Null => Some(format!("\"{key}\":null")),
        }
    }

    fn string_value(&self) -> Option<String> {
        match self {
            Self::Text(value) | Self::Escaped(value) => Some(value.clone()),
            _ => None,
        }
    }
}

impl From<JsError> for ErrorFingerprint {
    fn from(err: JsError) -> Self {
        match err {
            JsError::Api { code, description } => Self::Api { code, description },
            JsError::StreamNotFound(name) => Self::StreamNotFound(name),
            JsError::ConsumerNotFound { stream, consumer } => {
                Self::ConsumerNotFound { stream, consumer }
            }
            JsError::NotAcked => Self::NotAcked,
            JsError::AlreadyAcknowledged => Self::AlreadyAcknowledged,
            JsError::InvalidConfig(msg) => Self::InvalidConfig(msg),
            JsError::ParseError(msg) => Self::ParseError(msg),
            JsError::Nats(err) => Self::Nats(err.to_string()),
        }
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

fuzz_target!(|input: ConsumerInfoErrorFuzz| {
    if input.too_large() {
        return;
    }

    let bare = input.bare_error_response();
    let wrapped_error_first = input.consumer_info_response(true);
    let wrapped_error_last = input.consumer_info_response(false);

    if [
        bare.len(),
        wrapped_error_first.len(),
        wrapped_error_last.len(),
    ]
    .into_iter()
    .any(|len| len > MAX_JSON_BYTES)
    {
        return;
    }

    let expected = input.error.expected_fingerprint();
    let bare_actual = ErrorFingerprint::from(fuzz_parse_api_error(&bare));
    let first_actual = ErrorFingerprint::from(fuzz_parse_api_error(&wrapped_error_first));
    let last_actual = ErrorFingerprint::from(fuzz_parse_api_error(&wrapped_error_last));

    assert_eq!(bare_actual, expected, "bare error envelope drifted");
    assert_eq!(
        first_actual, expected,
        "error-first ConsumerInfo wrapper changed error classification"
    );
    assert_eq!(
        last_actual, expected,
        "wrapper-only shadow fields changed ConsumerInfo error classification"
    );
});
