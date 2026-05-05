//! Live gRPC deadline conformance tests.
//!
//! These tests pin the current public gRPC server deadline contract:
//! `grpc-timeout` parsing, default timeout fallback, deadline propagation
//! through `CallContextWithCx`, child-timeout attenuation, and
//! `DEADLINE_EXCEEDED` classification.

use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::grpc::{
    CallContext, Code, Metadata, MetadataValue, Response, Status, format_grpc_timeout,
    parse_grpc_timeout,
};

fn metadata_with_timeout(timeout: &str) -> Metadata {
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", timeout));
    metadata
}

fn ascii_metadata_value<'a>(metadata: &'a Metadata, key: &str) -> Option<&'a str> {
    match metadata.get(key) {
        Some(MetadataValue::Ascii(value)) => Some(value.as_str()),
        Some(MetadataValue::Binary(_)) | None => None,
    }
}

struct DeadlineLog<'a> {
    scenario_id: &'a str,
    metadata_in: &'a str,
    metadata_out: &'a str,
    virtual_now: &'a str,
    deadline: &'a str,
    expected_status: Code,
    actual_status: Code,
    health_state: &'a str,
    cancellation_observed: bool,
    verdict: &'a str,
    first_failure: &'a str,
}

fn log_deadline_event(case: DeadlineLog<'_>) {
    println!(
        "bead_id=asupersync-pfvsch suite_id=grpc_deadline scenario_id={} grpc_method=/grpc.test.Deadline/Unary metadata_in={} metadata_out={} virtual_now={} deadline={} expected_status={:?} actual_status={:?} health_state={} cancellation_observed={} verdict={} first_failure={}",
        case.scenario_id,
        case.metadata_in,
        case.metadata_out,
        case.virtual_now,
        case.deadline,
        case.expected_status,
        case.actual_status,
        case.health_state,
        case.cancellation_observed,
        case.verdict,
        case.first_failure
    );
}

#[test]
fn grpc_timeout_units_round_trip_and_reject_malformed_values() {
    let valid = [
        ("100m", Duration::from_millis(100)),
        ("10S", Duration::from_secs(10)),
        ("1M", Duration::from_secs(60)),
        ("2H", Duration::from_secs(7_200)),
        ("500u", Duration::from_micros(500)),
        ("1000n", Duration::from_nanos(1_000)),
        ("0n", Duration::ZERO),
        ("99999999H", Duration::from_secs(99_999_999 * 3_600)),
    ];

    for (wire, expected) in valid {
        assert_eq!(parse_grpc_timeout(wire), Some(expected), "{wire}");
        let formatted = format_grpc_timeout(expected);
        assert_eq!(
            parse_grpc_timeout(&formatted),
            Some(expected),
            "formatted timeout {formatted} must preserve {wire}"
        );
    }

    for malformed in ["", "S", "100000000S", "1s", "1X", " 1S", "１S"] {
        assert_eq!(
            parse_grpc_timeout(malformed),
            None,
            "malformed timeout must fail closed: {malformed:?}"
        );
    }
}

#[test]
fn call_context_applies_explicit_default_and_invalid_timeout_contracts() {
    let now = Instant::now();

    let explicit = CallContext::from_metadata_at(
        metadata_with_timeout("5S"),
        Some(Duration::from_secs(30)),
        Some("127.0.0.1:50051".to_string()),
        now,
    );
    assert_eq!(explicit.deadline(), Some(now + Duration::from_secs(5)));
    assert_eq!(explicit.peer_addr(), Some("127.0.0.1:50051"));
    assert!(!explicit.is_expired_at(now));
    assert_eq!(explicit.remaining_at(now), Some(Duration::from_secs(5)));
    assert!(explicit.is_expired_at(now + Duration::from_secs(5)));

    let defaulted =
        CallContext::from_metadata_at(Metadata::new(), Some(Duration::from_secs(30)), None, now);
    assert_eq!(defaulted.deadline(), Some(now + Duration::from_secs(30)));

    let invalid = CallContext::from_metadata_at(
        metadata_with_timeout("invalid"),
        Some(Duration::from_secs(30)),
        None,
        now,
    );
    assert_eq!(
        invalid.deadline(),
        None,
        "present but malformed grpc-timeout must not fall back to server default"
    );
}

#[test]
fn call_context_with_cx_preserves_deadline_metadata_and_capability_context() {
    let now = Instant::now();
    let call = CallContext::from_metadata_at(metadata_with_timeout("750m"), None, None, now);
    let cx = Cx::for_testing();
    let wrapped = call.with_cx(&cx);

    assert_eq!(wrapped.deadline(), Some(now + Duration::from_millis(750)));
    assert!(wrapped.metadata().get("grpc-timeout").is_some());
    assert_eq!(wrapped.cx().task_id(), cx.task_id());
    assert_eq!(wrapped.call().deadline(), call.deadline());
}

#[test]
fn parent_deadline_attenuates_outbound_child_timeout() {
    let now = Instant::now();
    let parent = CallContext::from_metadata_at(metadata_with_timeout("10S"), None, None, now);

    let mut longer_child = metadata_with_timeout("15S");
    assert!(parent.propagate_timeout_to_at(&mut longer_child, now));
    assert_eq!(
        ascii_metadata_value(&longer_child, "grpc-timeout"),
        Some("10S"),
        "child timeout longer than parent must be clamped"
    );

    let mut shorter_child = metadata_with_timeout("5S");
    assert!(parent.propagate_timeout_to_at(&mut shorter_child, now));
    assert_eq!(
        ascii_metadata_value(&shorter_child, "grpc-timeout"),
        Some("5S"),
        "child timeout shorter than parent must be preserved"
    );

    let no_deadline = CallContext::new();
    let mut metadata = Metadata::new();
    assert!(!no_deadline.propagate_timeout_to_at(&mut metadata, now));
    assert!(metadata.get("grpc-timeout").is_none());
}

#[test]
fn expired_deadline_surfaces_zero_timeout_and_deadline_exceeded_status() {
    let now = Instant::now();
    let call = CallContext::from_metadata_at(metadata_with_timeout("0n"), None, None, now);
    assert_eq!(call.deadline(), Some(now));
    assert!(call.is_expired_at(now));
    assert_eq!(call.timeout_header_value_at(now), Some("0n".to_string()));

    let response: Result<Response<&'static str>, Status> = if call.is_expired_at(now) {
        Err(Status::deadline_exceeded(
            "handler processing exceeded deadline",
        ))
    } else {
        Ok(Response::new("ok"))
    };
    let status = response.expect_err("zero timeout must fail fast");
    assert_eq!(status.code(), Code::DeadlineExceeded);
    log_deadline_event(DeadlineLog {
        scenario_id: "zero-timeout-fails-fast",
        metadata_in: "grpc-timeout:0n",
        metadata_out: "grpc-timeout:0n",
        virtual_now: "0ns",
        deadline: "0ns",
        expected_status: Code::DeadlineExceeded,
        actual_status: status.code(),
        health_state: "not_applicable",
        cancellation_observed: true,
        verdict: "pass",
        first_failure: "",
    });
}

#[test]
fn deadline_conformance_runner_logs_success_failure_and_propagation_matrix() {
    let now = Instant::now();

    let success = CallContext::from_metadata_at(metadata_with_timeout("5S"), None, None, now);
    let handler_end = now + Duration::from_millis(250);
    let success_response: Result<Response<&'static str>, Status> =
        if success.is_expired_at(handler_end) {
            Err(Status::deadline_exceeded(
                "handler processing exceeded deadline",
            ))
        } else {
            Ok(Response::new("ok"))
        };
    let success_status = match &success_response {
        Ok(_) => Code::Ok,
        Err(status) => status.code(),
    };
    assert_eq!(success_status, Code::Ok);

    let mut outbound = metadata_with_timeout("30S");
    assert!(success.propagate_timeout_to_at(&mut outbound, now + Duration::from_secs(1)));
    assert_eq!(ascii_metadata_value(&outbound, "grpc-timeout"), Some("4S"));
    log_deadline_event(DeadlineLog {
        scenario_id: "success-propagates-tighter-parent-timeout",
        metadata_in: "grpc-timeout:5S",
        metadata_out: "grpc-timeout:4S",
        virtual_now: "1s",
        deadline: "5s",
        expected_status: Code::Ok,
        actual_status: success_status,
        health_state: "not_applicable",
        cancellation_observed: false,
        verdict: "pass",
        first_failure: "",
    });

    let expired = CallContext::from_metadata_at(metadata_with_timeout("1m"), None, None, now);
    let handler_end = now + Duration::from_millis(2);
    let expired_response: Result<Response<&'static str>, Status> =
        if expired.is_expired_at(handler_end) {
            Err(Status::deadline_exceeded(
                "handler processing exceeded deadline",
            ))
        } else {
            Ok(Response::new("late"))
        };
    let expired_status = expired_response
        .expect_err("handler past deadline must fail")
        .code();
    assert_eq!(expired_status, Code::DeadlineExceeded);
    log_deadline_event(DeadlineLog {
        scenario_id: "failure-deadline-exceeded-after-virtual-work",
        metadata_in: "grpc-timeout:1m",
        metadata_out: "grpc-timeout:0n",
        virtual_now: "2ms",
        deadline: "1ms",
        expected_status: Code::DeadlineExceeded,
        actual_status: expired_status,
        health_state: "not_applicable",
        cancellation_observed: true,
        verdict: "pass",
        first_failure: "",
    });
}
