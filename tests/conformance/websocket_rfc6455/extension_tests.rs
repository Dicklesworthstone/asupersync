#![allow(warnings)]
#![allow(clippy::all)]
//! Extension conformance tests (RFC 6455 §4.1, §5.2, §9.1; RFC 7692 §6).
//!
//! Rejection of RSV1/RSV2/RSV3 when no extension is negotiated is already
//! asserted on the production codec by `framing_tests::test_reserved_bits`
//! (RFC6455-5.2-RESERVED-BITS), so it is not repeated here. This module
//! covers the other side:
//!
//! - always: the client fails the connection when the server selects an
//!   extension it did not request, at handshake validation and when a live
//!   connection is built from an agreed extension list;
//! - with the `compression` feature only (the sole production codec
//!   configuration that gives RSV1 a meaning): RSV1 is accepted on a
//!   negotiated permessage-deflate data frame, and still refused on control
//!   frames, on non-first fragments and for RSV2/RSV3. The production RSV1
//!   path is reachable only through `WebSocket::from_upgraded_with_extensions`
//!   (`FrameCodec::enable_permessage_deflate` is crate-private), so these
//!   cases use the live client over the in-memory transport.

use super::fragmentation_tests::{
    LiveClient, client_receiving, deliver_and_shutdown, recv_once, virtual_pair,
};
use super::*;
use asupersync::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    ClientHandshake, HandshakeError, HttpResponse, Message, WebSocket, WebSocketConfig, WsError,
    WsUrl,
};
use asupersync::util::{EntropySource, OsEntropy};
use std::collections::BTreeMap;
use std::sync::Arc;

/// RFC 6455 §1.3 sample key and its Sec-WebSocket-Accept value.
const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// A permessage-deflate agreement the production client supports.
const PMD_AGREED: &str = "permessage-deflate; server_no_context_takeover";

/// Run all extension conformance tests.
#[allow(dead_code)]
pub fn run_extension_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_unrequested_extension_rejected());
    results.push(test_live_extension_agreement());
    #[cfg(feature = "compression")]
    results.push(test_rsv1_accepted_with_permessage_deflate());
    #[cfg(feature = "compression")]
    results.push(test_reserved_bits_outside_permessage_deflate_scope());

    results
}

/// A 101 response for `SAMPLE_KEY`, optionally selecting `extension`.
fn upgrade_response(extension: Option<&str>) -> Result<HttpResponse, String> {
    let mut raw = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {SAMPLE_ACCEPT}\r\n"
    );
    if let Some(extension) = extension {
        raw.push_str(&format!("Sec-WebSocket-Extensions: {extension}\r\n"));
    }
    raw.push_str("\r\n");
    HttpResponse::parse(raw.as_bytes()).map_err(|e| format!("101 response should parse: {e}"))
}

/// A client handshake for `SAMPLE_KEY` that requested `extensions`.
fn client_requesting(extensions: &[&str]) -> Result<ClientHandshake, String> {
    let url =
        WsUrl::parse("ws://example.com/chat").map_err(|e| format!("url parse failed: {e}"))?;
    Ok(ClientHandshake::new_for_test(
        url,
        SAMPLE_KEY.to_string(),
        vec![],
        extensions.iter().map(|e| e.to_string()).collect(),
        BTreeMap::new(),
    ))
}

/// Builds a client connection from an agreed extension list over the
/// in-memory transport; the peer has already sent `wire` and shut down.
fn client_with_extensions(
    agreed: &[String],
    wire: &[u8],
) -> Result<(Result<LiveClient, HandshakeError>, VirtualTcpStream), String> {
    let (client_io, mut peer) = virtual_pair()?;
    deliver_and_shutdown(&mut peer, wire)?;
    let entropy: Arc<dyn EntropySource> = Arc::new(OsEntropy);
    let config = WebSocketConfig::new().ping_interval(None);
    let ws = WebSocket::from_upgraded_with_extensions(client_io, config, agreed, entropy);
    Ok((ws, peer))
}

/// RFC 6455 §4.1 (and §9.1): if the server's response "indicates the use of an
/// extension that was not present in the client's handshake ... the client
/// MUST _Fail the WebSocket Connection_."
#[allow(dead_code)]
fn test_unrequested_extension_rejected() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let nothing_requested: &[&str] = &[];
        let rejections: [(&[&str], &str); 2] = [
            (nothing_requested, "permessage-deflate"),
            (&["permessage-deflate"], "x-unrequested"),
        ];
        for (requested, selected) in rejections {
            let handshake = client_requesting(requested)?;
            match handshake.validate_response(&upgrade_response(Some(selected))?) {
                Err(HandshakeError::ExtensionMismatch { .. }) => {}
                other => {
                    return Err(format!(
                        "client requesting {requested:?} must reject a server selecting {selected:?}, got {other:?}"
                    ));
                }
            }
        }

        // Controls: the same responses pass when nothing unrequested is
        // selected, so the rejections above are due to the extension.
        client_requesting(&[])?
            .validate_response(&upgrade_response(None)?)
            .map_err(|e| format!("response without extensions must validate: {e}"))?;
        client_requesting(&["permessage-deflate"])?
            .validate_response(&upgrade_response(Some(PMD_AGREED))?)
            .map_err(|e| {
                format!("response selecting the requested extension must validate: {e}")
            })?;
        Ok(())
    });

    create_test_result(
        "RFC6455-9.1-EXT-NOT-REQUESTED",
        "Client MUST fail the connection when the server selects an unrequested extension",
        TestCategory::Extensions,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §4.1/§9.1 at connection construction: an agreed extension the
/// client never offered must not yield a connection; no agreement yields a
/// plain connection; permessage-deflate yields a compressing connection only
/// when the implementation is compiled in (otherwise it must fail closed).
#[allow(dead_code)]
fn test_live_extension_agreement() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let (unknown, _peer_unknown) = client_with_extensions(&["x-unrequested".to_string()], &[])?;
        match unknown {
            Err(HandshakeError::ExtensionMismatch { .. }) => {}
            Err(other) => {
                return Err(format!(
                    "unrequested extension must fail with ExtensionMismatch, got {other}"
                ));
            }
            Ok(_) => {
                return Err("a connection was built with an unrequested extension".to_string());
            }
        }

        let none: Vec<String> = Vec::new();
        let (plain, _peer_plain) = client_with_extensions(&none, &[])?;
        match plain {
            Ok(ws) if !ws.compression_enabled() => {}
            Ok(_) => {
                return Err("no agreed extension must not enable permessage-deflate".to_string());
            }
            Err(e) => return Err(format!("an empty agreement must be accepted: {e}")),
        }

        let (deflate, _peer_deflate) = client_with_extensions(&[PMD_AGREED.to_string()], &[])?;
        match (cfg!(feature = "compression"), deflate) {
            (true, Ok(ws)) if ws.compression_enabled() => {}
            (true, Ok(_)) => {
                return Err("agreed permessage-deflate must enable compression".to_string());
            }
            (true, Err(e)) => {
                return Err(format!(
                    "agreed permessage-deflate must be accepted with the compression feature: {e}"
                ));
            }
            (false, Err(HandshakeError::ExtensionMismatch { .. })) => {}
            (false, Err(other)) => {
                return Err(format!(
                    "without the compression feature permessage-deflate must fail with ExtensionMismatch, got {other}"
                ));
            }
            (false, Ok(_)) => {
                return Err(
                    "permessage-deflate was accepted although the compression feature is disabled"
                        .to_string(),
                );
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-9.1-EXT-LIVE-AGREEMENT",
        "Live connection accepts only extensions it requested and implements",
        TestCategory::Extensions,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7692 §7.2.3.1: "Hello" compressed in one frame with RSV1 set.
#[cfg(feature = "compression")]
const RFC7692_COMPRESSED_HELLO: [u8; 9] = [0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

/// RFC 6455 §5.2: RSV1 MUST be 0 "unless an extension is negotiated that
/// defines meanings for non-zero values"; RFC 7692 §6 gives RSV1 that meaning.
/// With permessage-deflate negotiated, the RFC 7692 example frame decodes to
/// "Hello"; the same bytes on a connection without the agreement must fail.
#[cfg(feature = "compression")]
#[allow(dead_code)]
fn test_rsv1_accepted_with_permessage_deflate() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let cx = Cx::for_testing();

        let (deflate, _peer) =
            client_with_extensions(&[PMD_AGREED.to_string()], &RFC7692_COMPRESSED_HELLO)?;
        let mut ws =
            deflate.map_err(|e| format!("agreed permessage-deflate must be accepted: {e}"))?;
        if !ws.compression_enabled() {
            return Err("agreed permessage-deflate must enable compression".to_string());
        }
        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Text(text))) if text == "Hello" => {}
            other => {
                return Err(format!(
                    "RSV1 frame on a permessage-deflate connection must decode to \"Hello\", got {other:?}"
                ));
            }
        }

        let (mut plain, _plain_peer) = client_receiving(&RFC7692_COMPRESSED_HELLO)?;
        match recv_once(&mut plain, &cx) {
            Err(WsError::ReservedBitsSet) => {}
            other => {
                return Err(format!(
                    "the same RSV1 frame without the agreement must fail, got {other:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-RSV1-PMD-ACCEPT",
        "RSV1 is accepted only when permessage-deflate is negotiated",
        TestCategory::Extensions,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7692 §6: "An endpoint MUST NOT set the 'Per-Message Compressed' bit of
/// control frames and non-first fragments of a data message. An endpoint
/// receiving such a frame MUST _Fail the WebSocket Connection_." RSV2/RSV3
/// have no meaning under permessage-deflate and still fail (RFC 6455 §5.2).
#[cfg(feature = "compression")]
#[allow(dead_code)]
fn test_reserved_bits_outside_permessage_deflate_scope() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let cases: [(&str, &[u8]); 4] = [
            ("RSV1 on a Ping", &[0xC9, 0x00]),
            (
                "RSV1 on a non-first fragment",
                &[0x01, 0x01, b'a', 0xC0, 0x01, b'b'],
            ),
            ("RSV2 on a Text frame", &[0xA1, 0x00]),
            ("RSV3 on a Text frame", &[0x91, 0x00]),
        ];
        let cx = Cx::for_testing();

        for (label, wire) in cases {
            let (deflate, _peer) = client_with_extensions(&[PMD_AGREED.to_string()], wire)?;
            let mut ws = deflate
                .map_err(|e| format!("{label}: agreed permessage-deflate must be accepted: {e}"))?;
            match recv_once(&mut ws, &cx) {
                Err(WsError::ReservedBitsSet) => {}
                other => {
                    return Err(format!(
                        "{label} must fail a permessage-deflate connection, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.2-RSV-PMD-SCOPE",
        "Reserved bits outside the permessage-deflate RSV1 scope MUST fail",
        TestCategory::Extensions,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
