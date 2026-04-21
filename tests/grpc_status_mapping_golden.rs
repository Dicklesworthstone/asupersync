//! Golden snapshots for canonical gRPC status codes on the HTTP/2 wire.

use base64::Engine as _;
use asupersync::grpc::status::{Code, Status};
use insta::assert_json_snapshot;
use serde_json::{Value, json};

const CANONICAL_STATUS_CODES: &[Code] = &[
    Code::Ok,
    Code::Cancelled,
    Code::Unknown,
    Code::InvalidArgument,
    Code::DeadlineExceeded,
    Code::NotFound,
    Code::AlreadyExists,
    Code::PermissionDenied,
    Code::ResourceExhausted,
    Code::FailedPrecondition,
    Code::Aborted,
    Code::OutOfRange,
    Code::Unimplemented,
    Code::Internal,
    Code::Unavailable,
    Code::DataLoss,
    Code::Unauthenticated,
];

fn fixture_status(code: Code) -> Status {
    match code {
        Code::Ok => Status::ok(),
        Code::Cancelled => Status::cancelled("caller cancelled request"),
        Code::Unknown => Status::unknown("opaque upstream failure"),
        Code::InvalidArgument => Status::invalid_argument("field `name` is invalid"),
        Code::DeadlineExceeded => Status::deadline_exceeded("deadline exceeded after 30s"),
        Code::NotFound => Status::not_found("widget/123 missing"),
        Code::AlreadyExists => Status::already_exists("widget/123 already exists"),
        Code::PermissionDenied => Status::permission_denied("missing write scope"),
        Code::ResourceExhausted => Status::resource_exhausted("quota exhausted"),
        Code::FailedPrecondition => Status::failed_precondition("system not ready"),
        Code::Aborted => Status::aborted("transaction aborted"),
        Code::OutOfRange => Status::out_of_range("page index out of range"),
        Code::Unimplemented => Status::unimplemented("method not implemented"),
        Code::Internal => Status::internal("internal invariant broken"),
        Code::Unavailable => Status::unavailable("service draining"),
        Code::DataLoss => Status::data_loss("checksum mismatch"),
        Code::Unauthenticated => Status::unauthenticated("bearer token missing"),
    }
}

fn escape_grpc_message(message: &str) -> String {
    let mut escaped = String::with_capacity(message.len());
    for c in message.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn wire_snapshot(status: &Status) -> Value {
    json!({
        "http_status": 200,
        "content_type": "application/grpc",
        "trailers": {
            "grpc-status": status.code().as_i32().to_string(),
            "grpc-message": escape_grpc_message(status.message()),
            "grpc-status-details-bin": status.details().map(|details| {
                base64::engine::general_purpose::STANDARD.encode(details)
            }),
        },
    })
}

#[test]
fn status_code_http_mapping() {
    let snapshot: Vec<Value> = CANONICAL_STATUS_CODES
        .iter()
        .copied()
        .map(|code| {
            let status = fixture_status(code);
            json!({
                "grpc_code": code.as_i32(),
                "grpc_name": code.as_str(),
                "wire": wire_snapshot(&status),
            })
        })
        .collect();

    assert_json_snapshot!("status_code_http_mapping", snapshot);
}
