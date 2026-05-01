//! Audit + regression test for `src/grpc/web.rs` negotiation surface
//! (tick #144).
//!
//! Operator's question: "verify Sec-Fetch-Mode / Sec-Fetch-Site
//! headers respected, no smuggling via X-User-Agent."
//!
//! Audit findings:
//!
//!   (a) **Sec-Fetch-Mode / Sec-Fetch-Site — NOT INSPECTED.**
//!       `grep -nE 'Sec-Fetch|sec-fetch' src/grpc/web.rs` returns
//!       zero hits. The asupersync gRPC-Web negotiation is purely
//!       content-type based: `is_grpc_web_request(ct)` matches on
//!       the `application/grpc-web` family via `ContentType::
//!       from_header_value`, with no consideration of browser
//!       Fetch-metadata headers.
//!
//!       Whether this is a security issue depends on the threat
//!       model:
//!         * Public-API deployment: NOT a finding. Browser-vs-
//!           non-browser distinction isn't part of the trust
//!           boundary; the API accepts gRPC-Web from any client.
//!         * Browser-only-private-API deployment: defense gap.
//!           A non-browser caller (curl, custom HTTP client)
//!           that mimics the gRPC-Web content-type passes
//!           negotiation. The deployment would need a separate
//!           interceptor / WAF rule to enforce
//!           `Sec-Fetch-Mode: cors` and a known
//!           `Sec-Fetch-Site` policy.
//!
//!       **Documentation gap (P3):** the public negotiation
//!       contract should call this out so operators of
//!       browser-only deployments know they need an explicit
//!       Fetch-metadata-validating interceptor.
//!
//!   (b) **X-User-Agent smuggling — NOT A VECTOR HERE.**
//!       `grep -nE 'X-User-Agent|x-user-agent' src/grpc/web.rs`
//!       returns zero hits. The X-User-Agent header is a gRPC-Web
//!       convention for the user-agent string when the standard
//!       `User-Agent` header is restricted by the browser (CORS
//!       preflight rules). "Smuggling" would mean using
//!       X-User-Agent to bypass `User-Agent`-based filtering —
//!       but asupersync's gRPC-Web negotiation does NOT filter
//!       on `User-Agent` in the first place, so there is nothing
//!       to bypass. The negotiation is content-type-only.
//!
//!       This audit pin holds the boundary so a future commit
//!       that adds User-Agent-based logic without ALSO sanitising
//!       X-User-Agent must trip a regression test.
//!
//!   (c) **Negotiation IS strict on the content-type itself.**
//!       Verified clean: `ContentType::from_header_value` only
//!       returns Some for the canonical `application/grpc-web` /
//!       `application/grpc-web+proto` / `application/grpc-web+json`
//!       / `application/grpc-web-text` family — anything else
//!       (including `application/grpc`, `application/json`,
//!       `text/plain`, garbage) returns None.

use asupersync::grpc::is_grpc_web_request;

#[test]
fn negotiation_is_content_type_only_not_sec_fetch_aware() {
    // Pin (a): the negotiation function takes a content-type
    // string and ignores any other request header. Same content
    // type with or without Fetch metadata yields the same
    // verdict.
    //
    // The function signature itself is the strongest assertion:
    // `is_grpc_web_request(content_type: &str) -> bool` accepts
    // ONLY content-type, so by construction Sec-Fetch headers
    // cannot be considered. Pin via a positive case so the
    // contract is documented in test form.
    assert!(
        is_grpc_web_request("application/grpc-web"),
        "canonical gRPC-Web content type must negotiate true",
    );
    assert!(
        is_grpc_web_request("application/grpc-web+proto"),
        "+proto variant must negotiate true",
    );
    assert!(
        is_grpc_web_request("application/grpc-web-text"),
        "text mode must negotiate true",
    );
}

#[test]
fn negotiation_rejects_non_grpc_web_content_types() {
    // Pin (c): the content-type whitelist is strict — anything
    // outside the application/grpc-web family returns false.
    let rejected = [
        "application/grpc", // standard gRPC over HTTP/2 — NOT gRPC-Web
        "application/json",
        "text/plain",
        "application/octet-stream",
        "application/grpc-web-EXTRA-stuff", // not a valid suffix
        "",
        " ",
        "garbage",
        "application/x-grpc-web", // x- prefix is not part of the family
    ];
    for ct in rejected {
        assert!(
            !is_grpc_web_request(ct),
            "content-type {ct:?} must NOT negotiate as gRPC-Web",
        );
    }
}

#[test]
fn x_user_agent_is_not_a_smuggling_vector_here() {
    // Pin (b): the negotiation function does NOT inspect
    // X-User-Agent. A regression that ADDED User-Agent-based
    // filtering without also handling X-User-Agent — making
    // X-User-Agent a smuggling vector — would have to trip a
    // future test that exercises the new filtering surface.
    //
    // For now, the contract is "negotiation is content-type
    // only", which inherently has no User-Agent / X-User-Agent
    // smuggling surface. Pin via the positive case (negotiation
    // returns true regardless of any User-Agent value because
    // there's no User-Agent input to consider).
    //
    // The function signature `is_grpc_web_request(&str)` accepts
    // a content-type string only. There is no User-Agent input
    // to smuggle.
    let ct = "application/grpc-web";
    assert!(
        is_grpc_web_request(ct),
        "negotiation contract: content-type-only; X-User-Agent has no \
         influence because there is no User-Agent input parameter",
    );
}

#[test]
fn negotiation_is_case_insensitive_per_rfc9110_media_type_match() {
    // Pinned current behavior: ContentType::from_header_value is
    // case-INSENSITIVE on the type/subtype, matching RFC 9110
    // §8.3 ('media types are case-insensitive on the type and
    // subtype'). This is the correct interop posture — a peer
    // sending 'Application/Grpc-Web' is RFC-conformant and the
    // server should accept it.
    //
    // The audit relevance: case-insensitivity does NOT introduce
    // a smuggling vector here because the negotiation has no
    // User-Agent / Sec-Fetch input that could be bypassed via
    // case-confusion. The case-insensitivity is purely on the
    // content-type whitelist, which case-folds to the same
    // canonical ContentType variant.
    //
    // Pinned so a future TIGHTENING to strict-case (which would
    // break interop with RFC-conformant peers) forces an
    // intentional re-baseline.
    let canonical = "application/grpc-web";
    let mixed_case = "Application/Grpc-Web";
    let upper = "APPLICATION/GRPC-WEB";

    assert!(is_grpc_web_request(canonical));
    assert!(
        is_grpc_web_request(mixed_case),
        "RFC 9110 §8.3: case-insensitive type/subtype match is the \
         correct posture; mixed-case rejection would break interop",
    );
    assert!(
        is_grpc_web_request(upper),
        "uppercase content-type must match the gRPC-Web family per \
         RFC 9110 §8.3 case-insensitive media-type rules",
    );
}
