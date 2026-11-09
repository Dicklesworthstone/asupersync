use super::retry_delay;
use crate::bytes::Bytes;
use crate::grpc::{Code, Status};
use std::time::Duration;

const RETRY_TYPE: &[u8] = b"type.googleapis.com/google.rpc.RetryInfo";

// Independent wire fixtures deliberately do not use the production protobuf
// encoder or parser. All lengths and tags below are emitted by these helpers.
fn append_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn scalar(number: u32, value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    append_varint(&mut output, u64::from(number) << 3);
    append_varint(&mut output, value);
    output
}

fn bytes_field(number: u32, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    append_varint(&mut output, (u64::from(number) << 3) | 2);
    append_varint(&mut output, value.len() as u64);
    output.extend_from_slice(value);
    output
}

fn any(type_url: &[u8], value: &[u8]) -> Vec<u8> {
    [bytes_field(1, type_url), bytes_field(2, value)].concat()
}

fn retry_info(seconds: u64, nanos: u64) -> Vec<u8> {
    bytes_field(1, &[scalar(1, seconds), scalar(2, nanos)].concat())
}

fn envelope(code: u64, details: &[Vec<u8>]) -> Vec<u8> {
    let mut output = scalar(1, code);
    for detail in details {
        output.extend_from_slice(&bytes_field(3, detail));
    }
    output
}

fn status(code: Code, envelope: Vec<u8>) -> Status {
    Status::with_details(
        code,
        "peer-controlled status message",
        Bytes::from(envelope),
    )
}

fn exhausted(info: &[u8]) -> Status {
    status(
        Code::ResourceExhausted,
        envelope(8, &[any(RETRY_TYPE, info)]),
    )
}

#[test]
fn hand_encoded_collector_status_yields_the_expected_delay() {
    // Status(code=8, details=[Any(type_url="x/google.rpc.RetryInfo",
    // value=RetryInfo(retry_delay=Duration(seconds=2)))])
    let wire = b"\x08\x08\x1a\x1e\x0a\x16x/google.rpc.RetryInfo\x12\x04\x0a\x02\x08\x02";
    let result = retry_delay(&status(Code::ResourceExhausted, wire.to_vec()));
    assert_eq!(result, Ok(Some(Duration::from_secs(2))));
}

#[test]
fn absent_empty_and_unrelated_details_do_not_authorize_resource_retry() {
    assert_eq!(retry_delay(&Status::resource_exhausted("full")), Ok(None));
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, Vec::new())),
        Ok(None)
    );
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, scalar(1, 8))),
        Ok(None)
    );
    let opaque = any(b"https://collector.invalid/example.Other", b"\xff\xff\xff");
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, envelope(8, &[opaque]))),
        Ok(None)
    );
}

#[test]
fn present_empty_retry_info_is_a_valid_zero_delay_hint() {
    for detail in [
        bytes_field(1, RETRY_TYPE),
        any(RETRY_TYPE, &[]),
        any(RETRY_TYPE, &bytes_field(1, &[])),
        any(RETRY_TYPE, &retry_info(0, 0)),
    ] {
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, envelope(8, &[detail]))),
            Ok(Some(Duration::ZERO))
        );
    }
}

#[test]
fn envelope_code_must_match_the_non_ok_native_status() {
    let detail = any(RETRY_TYPE, &retry_info(1, 0));
    for malformed in [
        envelope(14, std::slice::from_ref(&detail)),
        envelope(0, std::slice::from_ref(&detail)),
        envelope(u64::MAX, std::slice::from_ref(&detail)),
        envelope((1_u64 << 32) + 8, std::slice::from_ref(&detail)),
        bytes_field(3, &detail),
    ] {
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, malformed)),
            Err(())
        );
    }
    assert_eq!(retry_delay(&status(Code::Ok, scalar(1, 0))), Err(()));
    assert_eq!(
        retry_delay(&status(Code::Unavailable, envelope(14, &[detail]))),
        Ok(Some(Duration::from_secs(1)))
    );
}

#[test]
fn duration_bounds_and_field_order_preserve_nanosecond_precision() {
    for (seconds, nanos) in [(0, 1), (3, 999_999_999), (315_576_000_000, 999_999_999)] {
        let duration = [scalar(2, u64::from(nanos)), scalar(1, seconds)].concat();
        let detail = [
            bytes_field(2, &bytes_field(1, &duration)),
            bytes_field(1, RETRY_TYPE),
        ]
        .concat();
        let wire = [bytes_field(3, &detail), scalar(1, 8)].concat();
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, wire)),
            Ok(Some(Duration::new(seconds, nanos)))
        );
    }
    // Non-minimal but valid varints retain their protobuf meaning.
    let detail = any(RETRY_TYPE, b"\x0a\x03\x08\x82\x00");
    let wire = [vec![0x08, 0x88, 0x00], bytes_field(3, &detail)].concat();
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, wire)),
        Ok(Some(Duration::from_secs(2)))
    );
}

#[test]
fn negative_overflowing_and_unnormalized_durations_are_refused() {
    for (seconds, nanos) in [
        (u64::MAX, 0),
        (315_576_000_001, 0),
        (0, 1_000_000_000),
        (0, u64::MAX),
        (0, u64::from(u32::MAX)),
        (0, (1_u64 << 32) + 1),
    ] {
        assert_eq!(
            retry_delay(&exhausted(&retry_info(seconds, nanos))),
            Err(())
        );
    }
}

#[test]
fn duplicate_singular_fields_and_competing_hints_are_refused() {
    let good_info = retry_info(2, 0);
    let good_any = any(RETRY_TYPE, &good_info);
    let same_hint_twice = envelope(8, &[good_any.clone(), good_any.clone()]);
    let different_hints = envelope(8, &[good_any.clone(), any(RETRY_TYPE, &retry_info(5, 0))]);
    let duplicate_code = [envelope(8, std::slice::from_ref(&good_any)), scalar(1, 8)].concat();
    let duplicate_message = [
        envelope(8, std::slice::from_ref(&good_any)),
        bytes_field(2, b"first"),
        bytes_field(2, b"second"),
    ]
    .concat();
    let duplicate_type = [good_any.clone(), bytes_field(1, RETRY_TYPE)].concat();
    let duplicate_value = [good_any, bytes_field(2, &good_info)].concat();
    let duplicate_delay = [good_info.clone(), good_info].concat();
    let duplicate_seconds = bytes_field(1, &[scalar(1, 1), scalar(1, 2)].concat());
    let duplicate_nanos = bytes_field(1, &[scalar(2, 1), scalar(2, 1)].concat());

    for malformed in [
        same_hint_twice,
        different_hints,
        duplicate_code,
        duplicate_message,
        envelope(8, &[duplicate_type]),
        envelope(8, &[duplicate_value]),
        envelope(8, &[any(RETRY_TYPE, &duplicate_delay)]),
        envelope(8, &[any(RETRY_TYPE, &duplicate_seconds)]),
        envelope(8, &[any(RETRY_TYPE, &duplicate_nanos)]),
    ] {
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, malformed)),
            Err(())
        );
    }
}

#[test]
fn type_matching_uses_the_exact_final_url_component() {
    for name in [
        b"google.rpc.RetryInfo".as_slice(),
        b"x/google.rpc.RetryInfoSuffix",
        b"x/google.rpc.retryinfo",
        b"x/google.rpc.RetryInfo?query",
        b"x/google.rpc.RetryInfo/Other",
    ] {
        let wire = envelope(8, &[any(name, &retry_info(4, 0))]);
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, wire)),
            Ok(None)
        );
    }
    for name in [
        b"/google.rpc.RetryInfo".as_slice(),
        b"https://does-not-resolve.invalid/types/google.rpc.RetryInfo",
    ] {
        let wire = envelope(8, &[any(name, &retry_info(4, 0))]);
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, wire)),
            Ok(Some(Duration::from_secs(4)))
        );
    }
}

#[test]
fn unknown_fields_and_opaque_any_values_cannot_inject_a_hint() {
    let injected = envelope(8, &[any(RETRY_TYPE, &retry_info(1, 0))]);
    let mut group = vec![0x4b]; // Unknown field9 start-group.
    group.extend_from_slice(&injected);
    group.push(0x4c);
    let wire = [
        envelope(8, &[any(b"x/Other", &injected), any(b"x/Other", b"\xff")]),
        group,
        vec![0x55, 1, 2, 3, 4],             // Unknown field10 fixed32.
        vec![0x59, 1, 2, 3, 4, 5, 6, 7, 8], // Unknown field11 fixed64.
    ]
    .concat();
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, wire)),
        Ok(None)
    );

    let wire = envelope(
        8,
        &[
            any(b"x/Other", b"\xff\xff"),
            any(RETRY_TYPE, &retry_info(3, 0)),
            any(b"x/Other", b"\x00"),
        ],
    );
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, wire)),
        Ok(Some(Duration::from_secs(3)))
    );
}

#[test]
fn malformed_known_values_and_trailing_bytes_never_release_a_hint() {
    let good = envelope(8, &[any(RETRY_TYPE, &retry_info(2, 0))]);
    let invalid_type = any(b"\xff/google.rpc.RetryInfo", &[]);
    let invalid_value = [bytes_field(1, RETRY_TYPE), scalar(2, 1)].concat();
    let invalid_code = [bytes_field(1, &[8]), bytes_field(3, &any(RETRY_TYPE, &[]))].concat();
    for malformed in [
        [good.clone(), vec![0]].concat(),
        [good.clone(), vec![0x1a, 0x03, 0x08]].concat(),
        [good.clone(), bytes_field(2, b"\xff")].concat(),
        [good, bytes_field(3, &invalid_type)].concat(),
        envelope(8, &[invalid_value]),
        envelope(8, &[any(RETRY_TYPE, &scalar(1, 5))]),
        envelope(
            8,
            &[any(RETRY_TYPE, &bytes_field(1, &bytes_field(1, &[1])))],
        ),
        envelope(8, &[any(RETRY_TYPE, &[0x0a, 0x03, 0x08])]),
        invalid_code,
    ] {
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, malformed)),
            Err(())
        );
    }
}

#[test]
fn type_urls_are_bounded_even_for_unknown_any_types() {
    let suffix = b"/google.rpc.RetryInfo";
    let mut url = vec![b'x'; 1024 - suffix.len()];
    url.extend_from_slice(suffix);
    assert_eq!(
        retry_delay(&status(
            Code::ResourceExhausted,
            envelope(8, &[any(&url, &[])])
        )),
        Ok(Some(Duration::ZERO))
    );
    url.insert(0, b'x');
    for oversized in [url, vec![b'x'; 1025]] {
        assert_eq!(
            retry_delay(&status(
                Code::ResourceExhausted,
                envelope(8, &[any(&oversized, &[])])
            )),
            Err(())
        );
    }
}

#[test]
fn field_budget_is_aggregate_across_all_nested_details() {
    // The code and recognized hint contain six fields. The opaque Any adds
    // three wrappers, so247 unknown fields reaches the shared256-field cap.
    let known = any(RETRY_TYPE, &bytes_field(1, &scalar(1, 2)));
    for (extra_fields, expected) in [(247, Ok(Some(Duration::from_secs(2)))), (248, Err(()))] {
        let mut other = any(b"x/Other", &[]);
        for _ in 0..extra_fields {
            other.extend_from_slice(&scalar(9, 0));
        }
        let wire = envelope(8, &[known.clone(), other]);
        assert_eq!(
            retry_delay(&status(Code::ResourceExhausted, wire)),
            expected
        );
    }
}

#[test]
fn details_limit_refuses_a_potentially_truncated_valid_prefix() {
    let prefix = envelope(8, &[any(RETRY_TYPE, &retry_info(2, 0))]);
    let padded = |length: usize| {
        let mut wire = prefix.clone();
        // The padding field uses one tag byte and a three-byte length.
        wire.extend_from_slice(&bytes_field(9, &vec![0; length - prefix.len() - 4]));
        assert_eq!(wire.len(), length);
        wire
    };
    let below = status(Code::ResourceExhausted, padded(65_535));
    assert_eq!(retry_delay(&below), Ok(Some(Duration::from_secs(2))));
    let at_cap = status(Code::ResourceExhausted, padded(65_536));
    assert_eq!(retry_delay(&at_cap), Err(()));

    let mut too_large = padded(65_536);
    too_large.extend_from_slice(&bytes_field(3, &any(RETRY_TYPE, &retry_info(9, 0))));
    let truncated = status(Code::ResourceExhausted, too_large);
    assert_eq!(truncated.details().expect("details").len(), 65_536);
    assert_eq!(retry_delay(&truncated), Err(()));
}

#[test]
fn unknown_group_depth_shares_the_known_message_depth_budget() {
    for (depth, valid) in [(5, true), (6, false)] {
        let mut duration = scalar(1, 2);
        duration.extend(std::iter::repeat_n(0x4b, depth));
        duration.extend(std::iter::repeat_n(0x4c, depth));
        // Status -> Any -> RetryInfo -> Duration already consumes depth3.
        let result = retry_delay(&exhausted(&bytes_field(1, &duration)));
        assert_eq!(
            result,
            if valid {
                Ok(Some(Duration::from_secs(2)))
            } else {
                Err(())
            }
        );
    }
    let unterminated = [scalar(1, 8), vec![0x4b, 0x08, 0x08]].concat();
    assert_eq!(
        retry_delay(&status(Code::ResourceExhausted, unterminated)),
        Err(())
    );
}

#[test]
fn returned_values_do_not_retain_peer_diagnostics_or_urls() {
    let secret = "credential-and-payload-secret";
    let url = format!("https://{secret}.invalid/google.rpc.RetryInfo");
    let wire = [
        envelope(14, &[any(url.as_bytes(), &retry_info(1, 2))]),
        bytes_field(2, secret.as_bytes()),
    ]
    .concat();
    let peer = Status::with_details(Code::Unavailable, secret, Bytes::from(wire));
    let accepted = retry_delay(&peer);
    assert_eq!(accepted, Ok(Some(Duration::new(1, 2))));
    assert!(!format!("{accepted:?}").contains(secret));

    let malformed = envelope(14, &[any(url.as_bytes(), &[0xff])]);
    let peer = Status::with_details(Code::Unavailable, secret, Bytes::from(malformed));
    let refused = retry_delay(&peer);
    assert_eq!(refused, Err(()));
    assert_eq!(format!("{refused:?}"), "Err(())");
}
