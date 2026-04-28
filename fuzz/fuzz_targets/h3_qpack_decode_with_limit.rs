//! br-asupersync-dbp8lb: focused fuzz target for the HTTP/3 QPACK
//! field-section size-limit decoders in `src/http/h3_native.rs`.
//!
//! Existing QPACK fuzzers drive the generic field-section parser, string
//! decoder, prefixed integers, and broad integration paths. This target
//! covers the missing policy seam at:
//!   * `qpack_decode_request_field_section_with_limit`
//!   * `qpack_decode_response_field_section_with_limit`
//!
//! It builds valid static-only request/response field sections, computes the
//! exact decoded header size from the same QPACK plan, and asserts:
//!   * decode succeeds with no limit,
//!   * decode succeeds with the exact decoded-size limit,
//!   * decode succeeds with any larger limit,
//!   * decode rejects `exact_size - 1` with the documented QPACK policy error.
//!
//! The harness also checks that static-only wire decodes identically under
//! `StaticOnly` and `DynamicTableAllowed`, so limit enforcement does not drift
//! across QPACK modes when no dynamic references are present.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{
    H3NativeError, H3PseudoHeaders, H3QpackMode, H3RequestHead, H3ResponseHead, QpackFieldPlan,
    qpack_decode_request_field_section_with_limit, qpack_decode_response_field_section_with_limit,
    qpack_encode_field_section, qpack_plan_to_header_fields, qpack_static_plan_for_request,
    qpack_static_plan_for_response,
};
use libfuzzer_sys::fuzz_target;

const MAX_HEADERS: usize = 6;
const MAX_COMPONENT_BYTES: usize = 24;
const LIMIT_ERROR: &str = "decoded field section exceeds maximum size limit";
const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];
const STATUSES: &[u16] = &[200, 201, 204, 301, 302, 400, 404, 418, 500, 503];

#[derive(Arbitrary, Debug)]
struct HeaderInput {
    name_suffix: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct RequestInput {
    method_case: u8,
    scheme_https: bool,
    authority: Vec<u8>,
    path: Vec<u8>,
    headers: Vec<HeaderInput>,
}

#[derive(Arbitrary, Debug)]
struct ResponseInput {
    status_case: u8,
    headers: Vec<HeaderInput>,
}

#[derive(Arbitrary, Debug)]
enum Surface {
    Request(RequestInput),
    Response(ResponseInput),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    surface: Surface,
    limit_slack: u8,
}

fuzz_target!(|input: FuzzInput| match input.surface {
    Surface::Request(request) => fuzz_request(request, input.limit_slack),
    Surface::Response(response) => fuzz_response(response, input.limit_slack),
});

fn fuzz_request(input: RequestInput, limit_slack: u8) {
    let request = build_request_head(input);
    let plan = qpack_static_plan_for_request(&request);
    let wire = qpack_encode_field_section(&plan).expect("encode valid request field section");
    let decoded_size = decoded_field_section_size(&plan);
    let higher_limit = decoded_size + 1 + u64::from(limit_slack % 16);

    let static_result =
        qpack_decode_request_field_section_with_limit(&wire, H3QpackMode::StaticOnly, None, None)
            .expect("decode request without limit");
    let dynamic_result = qpack_decode_request_field_section_with_limit(
        &wire,
        H3QpackMode::DynamicTableAllowed,
        None,
        None,
    )
    .expect("decode request without limit under dynamic mode");
    assert_eq!(
        static_result, dynamic_result,
        "static-only request wire should decode identically under both QPACK modes"
    );

    for mode in [H3QpackMode::StaticOnly, H3QpackMode::DynamicTableAllowed] {
        let exact =
            qpack_decode_request_field_section_with_limit(&wire, mode, None, Some(decoded_size))
                .expect("decode request at exact size limit");
        assert_eq!(exact, static_result);

        let higher =
            qpack_decode_request_field_section_with_limit(&wire, mode, None, Some(higher_limit))
                .expect("decode request above size limit");
        assert_eq!(higher, static_result);

        let err = qpack_decode_request_field_section_with_limit(
            &wire,
            mode,
            None,
            Some(decoded_size - 1),
        )
        .expect_err("request exact-minus-one limit must reject");
        assert_eq!(err, H3NativeError::QpackPolicy(LIMIT_ERROR));
    }
}

fn fuzz_response(input: ResponseInput, limit_slack: u8) {
    let response = build_response_head(input);
    let plan = qpack_static_plan_for_response(&response);
    let wire = qpack_encode_field_section(&plan).expect("encode valid response field section");
    let decoded_size = decoded_field_section_size(&plan);
    let higher_limit = decoded_size + 1 + u64::from(limit_slack % 16);

    let static_result =
        qpack_decode_response_field_section_with_limit(&wire, H3QpackMode::StaticOnly, None, None)
            .expect("decode response without limit");
    let dynamic_result = qpack_decode_response_field_section_with_limit(
        &wire,
        H3QpackMode::DynamicTableAllowed,
        None,
        None,
    )
    .expect("decode response without limit under dynamic mode");
    assert_eq!(
        static_result, dynamic_result,
        "static-only response wire should decode identically under both QPACK modes"
    );

    for mode in [H3QpackMode::StaticOnly, H3QpackMode::DynamicTableAllowed] {
        let exact =
            qpack_decode_response_field_section_with_limit(&wire, mode, None, Some(decoded_size))
                .expect("decode response at exact size limit");
        assert_eq!(exact, static_result);

        let higher =
            qpack_decode_response_field_section_with_limit(&wire, mode, None, Some(higher_limit))
                .expect("decode response above size limit");
        assert_eq!(higher, static_result);

        let err = qpack_decode_response_field_section_with_limit(
            &wire,
            mode,
            None,
            Some(decoded_size - 1),
        )
        .expect_err("response exact-minus-one limit must reject");
        assert_eq!(err, H3NativeError::QpackPolicy(LIMIT_ERROR));
    }
}

fn build_request_head(input: RequestInput) -> H3RequestHead {
    let method = METHODS[usize::from(input.method_case) % METHODS.len()].to_string();
    let scheme = if input.scheme_https { "https" } else { "http" }.to_string();
    let pseudo = H3PseudoHeaders {
        method: Some(method),
        scheme: Some(scheme),
        authority: Some(sanitize_authority(&input.authority)),
        path: Some(sanitize_path(&input.path)),
        status: None,
        protocol: None,
    };
    let headers = sanitize_headers(&input.headers);
    H3RequestHead::new(pseudo, headers).expect("sanitized request head should be valid")
}

fn build_response_head(input: ResponseInput) -> H3ResponseHead {
    let status = STATUSES[usize::from(input.status_case) % STATUSES.len()];
    let headers = sanitize_headers(&input.headers);
    H3ResponseHead::new(status, headers).expect("sanitized response head should be valid")
}

fn sanitize_headers(inputs: &[HeaderInput]) -> Vec<(String, String)> {
    inputs
        .iter()
        .take(MAX_HEADERS)
        .enumerate()
        .map(|(idx, header)| {
            let suffix = sanitize_token_fragment(&header.name_suffix);
            let name = if suffix.is_empty() {
                format!("x-fuzz-{idx}")
            } else {
                format!("x-fuzz-{idx}-{suffix}")
            };
            let value = sanitize_value(&header.value);
            (name, value)
        })
        .collect()
}

fn sanitize_token_fragment(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_COMPONENT_BYTES)
        .map(|byte| match byte % 4 {
            0 => char::from(b'a' + (byte % 26)),
            1 => char::from(b'0' + (byte % 10)),
            2 => '-',
            _ => char::from(b'a' + ((byte / 2) % 26)),
        })
        .collect()
}

fn sanitize_value(bytes: &[u8]) -> String {
    let value: String = bytes
        .iter()
        .take(MAX_COMPONENT_BYTES)
        .map(|byte| char::from(32 + (byte % 95)))
        .filter(|ch| *ch != '\r' && *ch != '\n')
        .collect();
    if value.is_empty() {
        "v".to_string()
    } else {
        value
    }
}

fn sanitize_path(bytes: &[u8]) -> String {
    let tail: String = bytes
        .iter()
        .take(MAX_COMPONENT_BYTES)
        .map(|byte| match byte % 5 {
            0 => char::from(b'a' + (byte % 26)),
            1 => char::from(b'0' + (byte % 10)),
            2 => '-',
            3 => '.',
            _ => '_',
        })
        .collect();
    if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{tail}")
    }
}

fn sanitize_authority(bytes: &[u8]) -> String {
    let label: String = bytes
        .iter()
        .take(MAX_COMPONENT_BYTES)
        .map(|byte| match byte % 3 {
            0 => char::from(b'a' + (byte % 26)),
            1 => char::from(b'0' + (byte % 10)),
            _ => '-',
        })
        .collect();
    let trimmed = label.trim_matches('-');
    let host = if trimmed.is_empty() {
        "fuzz".to_string()
    } else {
        trimmed.to_string()
    };
    format!("{host}.example")
}

fn decoded_field_section_size(plan: &[QpackFieldPlan]) -> u64 {
    let fields = qpack_plan_to_header_fields(plan, None).expect("static plan should resolve");
    fields.into_iter().fold(0u64, |acc, (name, value)| {
        acc + u64::try_from(name.len()).expect("name len fits u64")
            + u64::try_from(value.len()).expect("value len fits u64")
    })
}
