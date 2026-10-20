//! Policy composition and response semantics before incoming-body ownership.

use super::{
    BodyKind, Http1Config, Http1StreamingConfig, Method, RequestHead, Response, Version,
    admit_streaming_request_head,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn head(method: Method, uri: &str) -> RequestHead {
    RequestHead {
        method,
        uri: uri.to_string(),
        version: Version::Http11,
        headers: Vec::new(),
    }
}

fn is_closed(response: &Response) -> bool {
    let values: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.as_str())
        .collect();
    values == ["close"]
}

#[test]
fn route_ceiling_is_local_and_cannot_overflow_or_loosen_the_transport() {
    let config = Arc::new(
        Http1StreamingConfig::from(Http1Config::default().max_body_size(10))
            .incoming_body_queue(2, 7)
            .unread_body_drain(4, 6, Duration::from_secs(3))
            .with_request_body_policy(|head| {
                Ok(Some(if head.uri == "/tiny" { 3 } else { u64::MAX }))
            }),
    );
    let tiny =
        admit_streaming_request_head(&config, &head(Method::Post, "/tiny"), BodyKind::Chunked)
            .unwrap();
    assert_eq!(tiny.max_body_size, 3);
    assert_eq!(tiny.incoming_body_frame_capacity, 2);
    assert_eq!(tiny.incoming_body_queued_bytes, 7);
    assert_eq!(tiny.unread_body_drain_frames, 4);
    assert_eq!(tiny.unread_body_drain_bytes, 6);
    assert_eq!(tiny.unread_body_drain_timeout, Duration::from_secs(3));
    assert_eq!(config.max_body_size, 10);

    let next = admit_streaming_request_head(
        &config,
        &head(Method::Post, "/large"),
        BodyKind::ContentLength(10),
    )
    .unwrap();
    assert_eq!(next.max_body_size, 10);
    assert!(Arc::ptr_eq(&config, &next));
    for (uri, length) in [("/tiny", 4), ("/large", 11)] {
        let refused = admit_streaming_request_head(
            &config,
            &head(Method::Post, uri),
            BodyKind::ContentLength(length),
        )
        .unwrap_err();
        assert_eq!(refused.status, 413);
        assert!(is_closed(&refused));
        assert!(
            String::from_utf8(refused.body)
                .unwrap()
                .contains("ASUP-E505")
        );
    }
}

#[test]
fn composed_hooks_meet_limits_and_preserve_an_earlier_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let first = Arc::clone(&calls);
    let second = Arc::clone(&calls);
    let third = Arc::clone(&calls);
    let config = Arc::new(
        Http1StreamingConfig::from(Http1Config::default().max_body_size(32))
            .with_request_body_policy(move |_| {
                assert_eq!(first.fetch_add(1, Ordering::SeqCst), 0);
                Ok(Some(12))
            })
            .with_request_body_policy(move |_| {
                assert_eq!(second.fetch_add(1, Ordering::SeqCst), 1);
                Ok(None)
            })
            .with_request_body_policy(move |_| {
                assert_eq!(third.fetch_add(1, Ordering::SeqCst), 2);
                Ok(Some(4))
            }),
    );
    let admitted =
        admit_streaming_request_head(&config, &head(Method::Post, "/"), BodyKind::Chunked).unwrap();
    assert_eq!(admitted.max_body_size, 4);
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    let later_calls = Arc::new(AtomicUsize::new(0));
    let later = Arc::clone(&later_calls);
    let config = Arc::new(
        Http1StreamingConfig::default()
            .with_request_body_policy(|_| {
                Err(Response::new(403, "Forbidden", b"denied".to_vec())
                    .with_header("x-policy", "outer")
                    .with_header("connection", "keep-alive")
                    .with_header("Connection", "upgrade"))
            })
            .with_request_body_policy(move |_| {
                later.fetch_add(1, Ordering::SeqCst);
                Ok(Some(0))
            }),
    );
    let refusal = admit_streaming_request_head(&config, &head(Method::Post, "/"), BodyKind::Empty)
        .unwrap_err();
    assert_eq!(refusal.status, 403);
    assert_eq!(refusal.body, b"denied");
    assert!(
        refusal
            .headers
            .iter()
            .any(|(name, value)| name == "x-policy" && value == "outer")
    );
    assert!(is_closed(&refusal));
    assert_eq!(later_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn panics_interim_responses_and_invalid_lengths_fail_closed() {
    let configs = [
        Http1StreamingConfig::default().with_request_body_policy(|_| panic!("policy failed")),
        Http1StreamingConfig::default()
            .with_request_body_policy(|_| Err(Response::new(100, "Continue", Vec::new()))),
        Http1StreamingConfig::default().with_request_body_policy(|_| {
            Err(Response::new(101, "Switching Protocols", Vec::new()))
        }),
        Http1StreamingConfig::default().with_request_body_policy(|_| {
            Err(Response::new(403, "Forbidden", Vec::new()).with_header("content-length", "10"))
        }),
    ];
    for config in configs {
        let mut request = head(Method::Post, "/");
        request.version = Version::Http10;
        let refusal =
            admit_streaming_request_head(&Arc::new(config), &request, BodyKind::Empty).unwrap_err();
        assert_eq!(refusal.status, 500);
        assert_eq!(refusal.version, Version::Http10);
        assert!(is_closed(&refusal));
    }
}

#[test]
fn custom_head_refusal_preserves_get_representation_metadata() {
    let config = Arc::new(
        Http1StreamingConfig::default().with_request_body_policy(|_| {
            Err(Response::new(403, "Forbidden", Vec::new()).with_header("content-length", "123"))
        }),
    );
    let refusal = admit_streaming_request_head(&config, &head(Method::Head, "/"), BodyKind::Empty)
        .unwrap_err();
    assert_eq!(refusal.status, 403);
    assert!(refusal.body.is_empty());
    assert!(
        refusal
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "123")
    );
    assert!(is_closed(&refusal));

    let config = Arc::new(
        Http1StreamingConfig::default().with_request_body_policy(|_| {
            let mut response = Response::new(403, "Forbidden", b"denied".to_vec())
                .with_header("transfer-encoding", "chunked")
                .with_header("trailer", "x-checksum");
            response
                .trailers
                .push(("x-checksum".to_string(), "checked".to_string()));
            Err(response)
        }),
    );
    let refusal = admit_streaming_request_head(&config, &head(Method::Head, "/"), BodyKind::Empty)
        .unwrap_err();
    assert_eq!(refusal.status, 403);
    assert!(refusal.body.is_empty());
    assert!(refusal.trailers.is_empty());
    assert!(refusal.headers.iter().all(|(name, _)| {
        !name.eq_ignore_ascii_case("transfer-encoding") && !name.eq_ignore_ascii_case("trailer")
    }));
    assert!(
        refusal
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "6")
    );
    assert!(is_closed(&refusal));
}
