//! Audit + regression test for `src/grpc/status.rs` error→Status
//! mapping determinism (tick #180).
//!
//! Operator's question: "verify error→Status mapping deterministic."
//!
//! Audit findings:
//!
//!   (a) **TransportErrorKind taxonomy is a closed enum**
//!       (status.rs:311-328) replacing the earlier substring-
//!       based classification (br-asupersync-9gg21l). The
//!       earlier pattern scanned free-form error text for
//!       "timeout"/"timed out"/"deadline exceeded"/"http 504"
//!       — peer-controlled or os-controlled error strings
//!       could MISCLASSIFY the status code. Now the mapping
//!       is driven by a typed kind, fully deterministic.
//!
//!   (b) **`from_io_error_kind` is a pure function over
//!       `std::io::ErrorKind`** (status.rs:338-358). Same
//!       input always produces the same output:
//!         * TimedOut → Timeout
//!         * ConnectionRefused/NotFound/AddrNotAvailable/
//!           NetworkDown/NetworkUnreachable/HostUnreachable →
//!           ConnectFailed
//!         * AddrInUse → ProtocolViolation (local bind config
//!           failure, NOT peer reachability)
//!         * ConnectionReset/ConnectionAborted/BrokenPipe/
//!           NotConnected/UnexpectedEof → ResetByPeer
//!         * InvalidData → ProtocolViolation
//!         * _ → Other
//!
//!   (c) **`GrpcError::into_status` is exhaustive over all
//!       GrpcError variants** (status.rs:427-444):
//!         * Status(s) → s (passthrough)
//!         * Transport(kind, msg) → mapped via the
//!           TransportErrorKind table (Timeout→DeadlineExceeded,
//!           ProtocolViolation→Internal, others→Unavailable)
//!         * Protocol(msg) → Status::internal(format!("protocol
//!           error: {msg}"))
//!         * MessageTooLarge → Status::resource_exhausted(...)
//!         * InvalidMessage(msg) → Status::invalid_argument(msg)
//!         * Compression(msg) → Status::internal(format!(
//!           "compression error: {msg}"))
//!
//!   (d) **`#[non_exhaustive]` on TransportErrorKind**
//!       (status.rs:312, br-asupersync-co6rye) — future taxonomy
//!       growth (TlsHandshakeFailed, LocalConfigError) is
//!       non-breaking for downstream callers that match on
//!       this enum.
//!
//!   (e) **No thread-local state, no time-of-day branching, no
//!       randomness** — the mapping is a pure function.
//!
//! Regression tests below pin (a)+(b)+(c) at the public API
//! surface.

use asupersync::grpc::Status;
use asupersync::grpc::status::{Code, GrpcError, TransportErrorKind};

#[test]
fn transport_error_kind_to_status_code_table() {
    // Pin (a): the canonical TransportErrorKind → gRPC Code
    // mapping. Locking down the table so a regression that
    // shifted any kind to a different code (e.g. switching
    // ProtocolViolation from Internal to Unavailable) would
    // break this test.
    let cases = [
        (TransportErrorKind::Timeout, Code::DeadlineExceeded),
        (TransportErrorKind::ConnectFailed, Code::Unavailable),
        (TransportErrorKind::ResetByPeer, Code::Unavailable),
        (TransportErrorKind::ProtocolViolation, Code::Internal),
        (TransportErrorKind::Other, Code::Unavailable),
    ];
    for (kind, expected_code) in cases {
        let err = GrpcError::transport_kind(kind, "test message");
        let status = err.into_status();
        assert_eq!(
            status.code(),
            expected_code,
            "TransportErrorKind::{kind:?} must map to Code::{expected_code:?}",
        );
    }
}

#[test]
fn io_error_kind_to_transport_kind_table() {
    // Pin (b): the canonical std::io::ErrorKind →
    // TransportErrorKind classification. The audit-critical
    // property: peer-reachable failures map to Unavailable
    // (retryable); local-bind failures map to Internal
    // (non-retryable); deadline elapsed maps to
    // DeadlineExceeded (terminal).
    use std::io::ErrorKind as Ek;
    let cases = [
        (Ek::TimedOut, TransportErrorKind::Timeout),
        (Ek::ConnectionRefused, TransportErrorKind::ConnectFailed),
        (Ek::NotFound, TransportErrorKind::ConnectFailed),
        (Ek::AddrNotAvailable, TransportErrorKind::ConnectFailed),
        (Ek::NetworkDown, TransportErrorKind::ConnectFailed),
        (Ek::NetworkUnreachable, TransportErrorKind::ConnectFailed),
        (Ek::HostUnreachable, TransportErrorKind::ConnectFailed),
        // AddrInUse is local config — NOT peer reachability.
        (Ek::AddrInUse, TransportErrorKind::ProtocolViolation),
        (Ek::ConnectionReset, TransportErrorKind::ResetByPeer),
        (Ek::ConnectionAborted, TransportErrorKind::ResetByPeer),
        (Ek::BrokenPipe, TransportErrorKind::ResetByPeer),
        (Ek::NotConnected, TransportErrorKind::ResetByPeer),
        (Ek::UnexpectedEof, TransportErrorKind::ResetByPeer),
        (Ek::InvalidData, TransportErrorKind::ProtocolViolation),
        (Ek::Other, TransportErrorKind::Other),
    ];
    for (io_kind, expected_kind) in cases {
        let actual = TransportErrorKind::from_io_error_kind(io_kind);
        assert_eq!(
            actual, expected_kind,
            "io::ErrorKind::{io_kind:?} must classify as TransportErrorKind::{expected_kind:?}; \
             got {actual:?}",
        );
    }
}

#[test]
fn from_io_error_kind_is_pure_no_state() {
    // Pin (e): the classification function is pure — calling
    // it twice with the same input produces the same output,
    // independent of any global state. Loop-call to verify no
    // hidden caching / RNG / time dependence.
    use std::io::ErrorKind as Ek;
    for _ in 0..32 {
        assert_eq!(
            TransportErrorKind::from_io_error_kind(Ek::TimedOut),
            TransportErrorKind::Timeout,
        );
        assert_eq!(
            TransportErrorKind::from_io_error_kind(Ek::ConnectionRefused),
            TransportErrorKind::ConnectFailed,
        );
        assert_eq!(
            TransportErrorKind::from_io_error_kind(Ek::AddrInUse),
            TransportErrorKind::ProtocolViolation,
        );
    }
}

#[test]
fn into_status_passes_through_status_variant_unchanged() {
    // Pin (c) Status(s) arm: GrpcError::Status(s) → s
    // unchanged. The pre-constructed status passes through
    // without re-mapping.
    let original = Status::deadline_exceeded("explicit deadline");
    let err: GrpcError = original.clone().into();
    let recovered = err.into_status();
    assert_eq!(recovered.code(), original.code());
    assert_eq!(recovered.message(), original.message());
}

#[test]
fn into_status_protocol_variant_maps_to_internal() {
    // Pin (c) Protocol arm.
    let err = GrpcError::protocol("malformed frame");
    let status = err.into_status();
    assert_eq!(
        status.code(),
        Code::Internal,
        "Protocol error → Internal (gRPC clients should not retry)",
    );
    assert!(
        status.message().contains("protocol error: malformed frame"),
        "Internal status message must include the protocol-error context; \
         got {:?}",
        status.message(),
    );
}

#[test]
fn into_status_message_too_large_maps_to_resource_exhausted() {
    // Pin (c) MessageTooLarge arm. Audit-critical: the wire-
    // protocol oversize signal MUST map to ResourceExhausted
    // so clients understand the failure as a quota/cap issue
    // rather than an internal bug.
    let err = GrpcError::MessageTooLarge;
    let status = err.into_status();
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), "message too large");
}

#[test]
fn into_status_invalid_message_maps_to_invalid_argument() {
    // Pin (c) InvalidMessage arm.
    let err = GrpcError::InvalidMessage("missing required field".to_string());
    let status = err.into_status();
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "InvalidMessage → InvalidArgument (client-side fix)",
    );
    assert!(status.message().contains("missing required field"));
}

#[test]
fn into_status_compression_maps_to_internal_with_context() {
    // Pin (c) Compression arm. Audit-critical: a compression
    // error indicates the codec / negotiation got out of
    // sync — that's a server-side internal problem, not a
    // client-input issue.
    let err = GrpcError::Compression("decompressor not configured".to_string());
    let status = err.into_status();
    assert_eq!(status.code(), Code::Internal);
    assert!(
        status
            .message()
            .contains("compression error: decompressor not configured"),
        "Internal status message must surface compression error context; \
         got {:?}",
        status.message(),
    );
}

#[test]
fn round_trip_io_error_classification_independent_of_message_text() {
    // Pin (a) audit-critical: the message TEXT does not
    // influence the classification. We construct two errors
    // with DIFFERENT messages but same ErrorKind — they map
    // to the same Status code. A regression to substring-
    // search-based classification (the pre-fix vulnerability)
    // would break this pin.
    use std::io::Error as IoError;
    use std::io::ErrorKind as Ek;

    // Two TimedOut errors with adversarial messages.
    let err1: GrpcError = IoError::new(Ek::TimedOut, "deadline exceeded").into();
    let err2: GrpcError = IoError::new(Ek::TimedOut, "Unavailable: server says retry me").into();

    let status1 = err1.into_status();
    let status2 = err2.into_status();
    assert_eq!(
        status1.code(),
        status2.code(),
        "Status code must be determined by io::ErrorKind, NOT by message \
         text. Both TimedOut errors must map to the same Code regardless \
         of message content (br-asupersync-9gg21l).",
    );
    assert_eq!(status1.code(), Code::DeadlineExceeded);
}

#[test]
fn status_code_is_deterministic_across_invocations() {
    // Pin (e) determinism: 100 invocations of the same
    // mapping all produce the same result. No flakiness.
    use std::io::Error as IoError;
    use std::io::ErrorKind as Ek;

    let codes: Vec<Code> = (0..100)
        .map(|_| {
            let err: GrpcError = IoError::new(Ek::ConnectionReset, "peer gone").into();
            err.into_status().code()
        })
        .collect();
    assert!(
        codes.iter().all(|c| *c == Code::Unavailable),
        "100 invocations must all map ConnectionReset to Unavailable",
    );
}

#[test]
fn into_status_with_empty_message_still_maps_correctly() {
    // Boundary pin: an empty error message doesn't perturb the
    // classification.
    let err = GrpcError::transport_kind(TransportErrorKind::Timeout, "");
    let status = err.into_status();
    assert_eq!(status.code(), Code::DeadlineExceeded);
}
