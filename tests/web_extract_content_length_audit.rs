//! Regression tests for web request body extractor Content-Length validation.

use asupersync::bytes::Bytes;
use asupersync::web::extract::{ExtractionError, Form, FromRequest, Json, RawBody, Request};
use asupersync::web::response::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct TestPayload {
    name: String,
    value: i32,
}

fn assert_bad_request(err: ExtractionError, expected_message: &str) {
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
        err.message.contains(expected_message),
        "expected error message to contain `{expected_message}`, got `{}`",
        err.message
    );
}

fn assert_content_length_mismatch(err: ExtractionError, declared: usize, actual: usize) {
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
        err.message.contains("Content-Length mismatch"),
        "expected Content-Length mismatch error, got `{}`",
        err.message
    );
    assert!(
        err.message.contains(&format!("declared {declared}")),
        "mismatch should include declared length, got `{}`",
        err.message
    );
    assert!(
        err.message.contains(&format!("received {actual}")),
        "mismatch should include actual length, got `{}`",
        err.message
    );
}

#[test]
fn json_extractor_rejects_content_length_mismatch() {
    let json_payload = r#"{"name":"test","value":42}"#;
    let actual_length = json_payload.len();
    let declared_length = 100;

    let req = Request::new("POST", "/api/test")
        .with_header("content-type", "application/json")
        .with_header("content-length", declared_length.to_string())
        .with_body(Bytes::from(json_payload));

    let err = Json::<TestPayload>::from_request(req).unwrap_err();
    assert_content_length_mismatch(err, declared_length, actual_length);
}

#[test]
fn form_extractor_rejects_content_length_mismatch() {
    let form_data = "name=test&value=42";
    let actual_length = form_data.len();
    let declared_length = 50;

    let req = Request::new("POST", "/form/submit")
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_header("content-length", declared_length.to_string())
        .with_body(Bytes::from(form_data));

    let err = Form::<HashMap<String, String>>::from_request(req).unwrap_err();
    assert_content_length_mismatch(err, declared_length, actual_length);
}

#[test]
fn raw_body_extractor_rejects_content_length_mismatch() {
    let raw_data = b"some raw binary data";
    let actual_length = raw_data.len();
    let declared_length = 5;

    let req = Request::new("POST", "/upload")
        .with_header("content-length", declared_length.to_string())
        .with_body(Bytes::from_static(raw_data));

    let err = RawBody::from_request(req).unwrap_err();
    assert_content_length_mismatch(err, declared_length, actual_length);
}

#[test]
fn extractors_accept_matching_content_length() {
    let json_payload = r#"{"name":"valid","value":123}"#;
    let req = Request::new("POST", "/api/valid")
        .with_header("content-type", "application/json")
        .with_header("content-length", json_payload.len().to_string())
        .with_body(Bytes::from(json_payload));

    let Json(payload) = Json::<TestPayload>::from_request(req).unwrap();
    assert_eq!(
        payload,
        TestPayload {
            name: "valid".to_string(),
            value: 123
        }
    );

    let form_data = "name=valid&value=123";
    let req = Request::new("POST", "/form/valid")
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_header("content-length", form_data.len().to_string())
        .with_body(Bytes::from(form_data));

    let Form(form) = Form::<HashMap<String, String>>::from_request(req).unwrap();
    assert_eq!(form.get("name").map(String::as_str), Some("valid"));
    assert_eq!(form.get("value").map(String::as_str), Some("123"));

    let raw_data = b"valid raw data";
    let req = Request::new("POST", "/upload/valid")
        .with_header("content-length", raw_data.len().to_string())
        .with_body(Bytes::from_static(raw_data));

    let RawBody(body) = RawBody::from_request(req).unwrap();
    assert_eq!(body.as_ref(), raw_data);
}

#[test]
fn extractors_accept_missing_content_length_header() {
    let json_payload = r#"{"name":"no_header","value":456}"#;
    let req = Request::new("POST", "/api/no_header")
        .with_header("content-type", "application/json")
        .with_body(Bytes::from(json_payload));

    let Json(payload) = Json::<TestPayload>::from_request(req).unwrap();
    assert_eq!(payload.name, "no_header");

    let form_data = "name=no_header&value=456";
    let req = Request::new("POST", "/form/no_header")
        .with_header("content-type", "application/x-www-form-urlencoded")
        .with_body(Bytes::from(form_data));

    let Form(form) = Form::<HashMap<String, String>>::from_request(req).unwrap();
    assert_eq!(form.get("name").map(String::as_str), Some("no_header"));

    let raw_data = b"no header raw data";
    let req = Request::new("POST", "/upload/no_header").with_body(Bytes::from_static(raw_data));

    let RawBody(body) = RawBody::from_request(req).unwrap();
    assert_eq!(body.as_ref(), raw_data);
}

#[test]
fn extractor_rejects_invalid_content_length_header() {
    let json_payload = r#"{"name":"test","value":789}"#;
    let req = Request::new("POST", "/api/invalid")
        .with_header("content-type", "application/json")
        .with_header("content-length", "not_a_number")
        .with_body(Bytes::from(json_payload));

    let err = Json::<TestPayload>::from_request(req).unwrap_err();
    assert_bad_request(err, "invalid Content-Length header");
}

#[test]
fn extractor_accepts_identical_combined_content_length_values() {
    let json_payload = r#"{"name":"duplicated","value":7}"#;
    let req = Request::new("POST", "/api/combined")
        .with_header("content-type", "application/json")
        .with_header(
            "content-length",
            format!("{}, {}", json_payload.len(), json_payload.len()),
        )
        .with_body(Bytes::from(json_payload));

    let Json(payload) = Json::<TestPayload>::from_request(req).unwrap();
    assert_eq!(payload.name, "duplicated");
    assert_eq!(payload.value, 7);
}

#[test]
fn extractor_rejects_conflicting_combined_content_length_values() {
    let raw_data = b"abcde";
    let req = Request::new("POST", "/upload/conflict")
        .with_header("content-length", "5, 6")
        .with_body(Bytes::from_static(raw_data));

    let err = RawBody::from_request(req).unwrap_err();
    assert_bad_request(err, "conflicting Content-Length header values");
}

#[test]
fn extractor_rejects_empty_combined_content_length_member() {
    let raw_data = b"abcde";
    let req = Request::new("POST", "/upload/empty-member")
        .with_header("content-length", "5, ")
        .with_body(Bytes::from_static(raw_data));

    let err = RawBody::from_request(req).unwrap_err();
    assert_bad_request(err, "invalid Content-Length header");
}

#[test]
fn raw_body_accepts_zero_content_length_with_empty_body() {
    let req = Request::new("POST", "/empty")
        .with_header("content-length", "0")
        .with_body(Bytes::new());

    let RawBody(body) = RawBody::from_request(req).unwrap();
    assert!(body.is_empty());
}
