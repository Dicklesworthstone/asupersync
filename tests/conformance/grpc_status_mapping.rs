use asupersync::grpc::status::TransportErrorKind;
use asupersync::grpc::{Code, GrpcError, Status};

const CANONICAL_GRPC_STATUS_CODES: &[(Code, i32, &str)] = &[
    (Code::Ok, 0, "OK"),
    (Code::Cancelled, 1, "CANCELLED"),
    (Code::Unknown, 2, "UNKNOWN"),
    (Code::InvalidArgument, 3, "INVALID_ARGUMENT"),
    (Code::DeadlineExceeded, 4, "DEADLINE_EXCEEDED"),
    (Code::NotFound, 5, "NOT_FOUND"),
    (Code::AlreadyExists, 6, "ALREADY_EXISTS"),
    (Code::PermissionDenied, 7, "PERMISSION_DENIED"),
    (Code::ResourceExhausted, 8, "RESOURCE_EXHAUSTED"),
    (Code::FailedPrecondition, 9, "FAILED_PRECONDITION"),
    (Code::Aborted, 10, "ABORTED"),
    (Code::OutOfRange, 11, "OUT_OF_RANGE"),
    (Code::Unimplemented, 12, "UNIMPLEMENTED"),
    (Code::Internal, 13, "INTERNAL"),
    (Code::Unavailable, 14, "UNAVAILABLE"),
    (Code::DataLoss, 15, "DATA_LOSS"),
    (Code::Unauthenticated, 16, "UNAUTHENTICATED"),
];

#[test]
fn canonical_status_code_table_matches_grpc_wire_values() {
    assert_eq!(
        CANONICAL_GRPC_STATUS_CODES.len(),
        17,
        "gRPC defines exactly 17 canonical status codes"
    );

    for &(code, wire_value, name) in CANONICAL_GRPC_STATUS_CODES {
        assert_eq!(code.as_i32(), wire_value, "{name} wire value drifted");
        assert_eq!(code.as_str(), name, "{name} canonical name drifted");
        assert_eq!(
            code.to_string(),
            name,
            "{name} Display output must stay canonical"
        );
        assert_eq!(
            Code::from_i32(wire_value),
            code,
            "{name} must round-trip from its wire value"
        );
    }

    let wire_values = CANONICAL_GRPC_STATUS_CODES
        .iter()
        .map(|&(_, wire_value, _)| wire_value)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        wire_values,
        (0..=16).collect::<std::collections::BTreeSet<_>>(),
        "canonical gRPC status table must cover every wire value from 0 through 16 exactly once"
    );
}

#[test]
fn invalid_status_wire_values_map_to_unknown() {
    for invalid_code in [-1, 17, 18, 99, 255, 1000, i32::MIN, i32::MAX] {
        let decoded = Code::from_i32(invalid_code);
        assert_eq!(
            decoded,
            Code::Unknown,
            "invalid gRPC wire code {invalid_code} must decode to UNKNOWN"
        );
        assert_eq!(decoded.as_i32(), 2, "UNKNOWN wire value must remain 2");
    }
}

#[test]
fn grpc_error_conditions_map_to_canonical_status_codes() {
    let cases = [
        (
            GrpcError::transport_kind(TransportErrorKind::Timeout, "deadline expired"),
            Code::DeadlineExceeded,
        ),
        (
            GrpcError::transport_kind(TransportErrorKind::ConnectFailed, "connection refused"),
            Code::Unavailable,
        ),
        (
            GrpcError::transport_kind(TransportErrorKind::ResetByPeer, "stream reset"),
            Code::Unavailable,
        ),
        (
            GrpcError::transport_kind(TransportErrorKind::ProtocolViolation, "bad HTTP/2 preface"),
            Code::Internal,
        ),
        (GrpcError::MessageTooLarge, Code::ResourceExhausted),
        (
            GrpcError::invalid_message("bad varint prefix"),
            Code::InvalidArgument,
        ),
        (
            GrpcError::compression("gzip footer mismatch"),
            Code::Internal,
        ),
    ];

    for (error, expected_code) in cases {
        let status = error.into_status();
        assert_eq!(
            status.code(),
            expected_code,
            "unexpected status mapping for {:?}",
            expected_code
        );
    }
}

#[test]
fn bare_transport_errors_default_to_unavailable_even_if_message_mentions_timeout() {
    let status =
        GrpcError::transport("message text says timeout but kind is unclassified").into_status();

    assert_eq!(
        status.code(),
        Code::Unavailable,
        "substring-matching timeout text must not silently promote to DEADLINE_EXCEEDED"
    );
}

#[test]
fn cancelled_and_deadline_statuses_remain_distinct() {
    let cancelled = Status::cancelled("caller cancelled");
    let deadline = Status::deadline_exceeded("deadline elapsed");

    assert_eq!(cancelled.code(), Code::Cancelled);
    assert_eq!(deadline.code(), Code::DeadlineExceeded);
    assert_ne!(
        cancelled.code().as_i32(),
        deadline.code().as_i32(),
        "CANCELLED and DEADLINE_EXCEEDED must remain distinct wire codes"
    );
}

#[test]
fn io_error_kinds_follow_the_same_transport_status_matrix() {
    let cases = [
        (std::io::ErrorKind::TimedOut, Code::DeadlineExceeded),
        (std::io::ErrorKind::ConnectionRefused, Code::Unavailable),
        (std::io::ErrorKind::ConnectionReset, Code::Unavailable),
        (std::io::ErrorKind::InvalidData, Code::Internal),
    ];

    for (io_kind, expected_code) in cases {
        let transport_kind = TransportErrorKind::from_io_error_kind(io_kind);
        let status =
            GrpcError::transport_kind(transport_kind, format!("{io_kind:?}")).into_status();
        assert_eq!(status.code(), expected_code);
    }
}
