use asupersync::grpc::status::TransportErrorKind;
use asupersync::grpc::{Code, GrpcError, Status};

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
