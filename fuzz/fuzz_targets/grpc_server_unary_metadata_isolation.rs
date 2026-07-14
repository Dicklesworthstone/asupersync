#![no_main]

//! Cargo-fuzz target for unary-handler metadata isolation across
//! "concurrent" calls.
//!
//! Operator note (tick #134): the operator's request says "Arbitrary
//! concurrent unary calls, assert: each gets independent Cx, no
//! metadata leak between calls." The Cx half requires an async
//! runtime, which a libfuzzer-driven sync harness doesn't have.
//! This target drives sequential shared-instance metadata reuse through the
//! sync portions of the dispatch surface (`enforce_metadata_size_limit` plus
//! each interceptor's `intercept_request`). It does not exercise data races,
//! concurrent scheduling, or independent `Cx` construction. A regression where, e.g., a
//! TracingInterceptor accidentally cached the previous call's
//! x-request-id in a non-atomic location and reused it on the
//! next call would surface here.
//!
//! Properties asserted per fuzz iteration:
//!
//!   1. **No panic** on any sequence of arbitrary requests.
//!
//!   2. **Per-call metadata isolation.** Running N requests
//!      through the same shared interceptor chain MUST leave each
//!      request's metadata distinct to that call. Specifically:
//!      after intercept_request runs on requests A and B in
//!      order, none of B's metadata values may equal a value that
//!      was ONLY in A's pre-call metadata (and vice versa) —
//!      barring deliberately-shared values like the static auth
//!      token.
//!
//!   3. **TracingInterceptor uniqueness.** The TracingInterceptor
//!      is the only interceptor in the chain that has shared
//!      state across calls (the AtomicU64 request-id counter). Its
//!      contract is that EVERY call gets a unique x-request-id;
//!      drift here (two calls observing the same id) is a leak
//!      that would corrupt trace correlation across the wire.
//!
//!   4. **enforce_metadata_size_limit is referentially
//!      transparent.** The same Metadata input MUST produce the
//!      same Result output regardless of how many calls preceded.
//!      A regression where the function maintained hidden state
//!      (e.g. a dedup cache keyed on metadata content) would
//!      surface as the second identical call returning a
//!      different Result.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_server_unary_metadata_isolation -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::server::{Interceptor, enforce_metadata_size_limit};
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request};
use asupersync::grpc::{
    BearerAuthInterceptor, InterceptorLayer, LoggingInterceptor, TracingInterceptor,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

const MAX_CALLS: usize = 32;
const MAX_KV_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct CallSpec {
    /// Per-call user-supplied metadata. Each call gets its own
    /// metadata independent of any other call's metadata.
    headers: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    calls: Vec<CallSpec>,
}

fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn expected_metadata_key(key: &str) -> Option<String> {
    let normalized = key.to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if normalized.ends_with("-bin") {
        return None;
    }

    normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'))
        .then_some(normalized)
}

fn expected_ascii_value_is_valid(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

fn assert_metadata_insert_observation(
    metadata: &Metadata,
    before_len: usize,
    key: &str,
    value: &str,
    inserted: bool,
) {
    let after_len = metadata.len();
    if !inserted {
        assert_eq!(
            after_len,
            before_len,
            "Metadata::insert rejected an entry but mutated metadata: \
             raw_key_len={}, before_len={before_len}, after_len={after_len}",
            key.len(),
        );
        assert!(
            expected_metadata_key(key).is_none() || !expected_ascii_value_is_valid(value),
            "Metadata::insert rejected a locally valid metadata entry: \
             raw_key={key:?}, raw_value={value:?}",
        );
        return;
    }

    assert_eq!(
        after_len,
        before_len + 1,
        "Metadata::insert accepted an entry without appending exactly one entry: \
         raw_key_len={}, before_len={before_len}, after_len={after_len}",
        key.len(),
    );
    let expected_key = expected_metadata_key(key).expect("accepted metadata key must normalize");
    assert!(
        expected_ascii_value_is_valid(value),
        "Metadata::insert accepted an invalid ASCII metadata value: {value:?}",
    );
    let (stored_key, stored_value) = metadata
        .iter()
        .last()
        .expect("accepted metadata entry must be observable");
    assert_eq!(
        stored_key, expected_key,
        "accepted key normalization drifted"
    );
    match stored_value {
        MetadataValue::Ascii(stored) => assert_eq!(
            stored, value,
            "accepted metadata value changed during insertion",
        ),
        MetadataValue::Binary(_) => panic!("Metadata::insert stored an ASCII value as binary"),
    }
}

fn build_request(spec: &CallSpec) -> Request<Bytes> {
    let mut metadata = Metadata::new();
    for (key, value) in &spec.headers {
        let key = truncate(key, MAX_KV_LEN);
        let value = truncate(value, MAX_KV_LEN);
        let before_len = metadata.len();
        let inserted = metadata.insert(key.as_str(), value.as_str());
        assert_metadata_insert_observation(&metadata, before_len, &key, &value, inserted);
    }
    Request::with_metadata(Bytes::new(), metadata)
}

fn ascii_value(metadata: &Metadata, key: &str) -> Option<String> {
    match metadata.get(key) {
        Some(MetadataValue::Ascii(v)) => Some(v.clone()),
        _ => None,
    }
}

fuzz_target!(|input: FuzzInput| {
    if input.calls.len() > MAX_CALLS {
        return;
    }

    // Shared interceptor chain — the same instance runs across all
    // "concurrent" calls (in practice serialized within this fuzz
    // target's single thread, but the shared-state surface is the
    // same that real concurrent calls exercise).
    let chain = InterceptorLayer::new()
        .layer(TracingInterceptor::new())
        .layer(LoggingInterceptor::new())
        .layer(BearerAuthInterceptor::new("static-token"));

    // Snapshot the per-call metadata BEFORE running the chain so we
    // can compare post-call values against pre-call values from
    // OTHER calls.
    let pre_call_metadata: Vec<Metadata> = input
        .calls
        .iter()
        .map(|spec| build_request(spec).metadata().clone())
        .collect();

    // Run each call through the chain. Capture the resulting
    // Request to inspect its metadata afterwards.
    let mut post_call_requests: Vec<Request<Bytes>> = Vec::with_capacity(input.calls.len());
    for spec in &input.calls {
        let mut req = build_request(spec);

        // Property 4: enforce_metadata_size_limit is referentially
        // transparent. Two calls with the same Metadata produce the
        // same Result regardless of order.
        let size_check = enforce_metadata_size_limit(req.metadata(), 8 * 1024);
        // Sanity: the same call repeated via clone produces the same
        // result.
        let size_check_repeat = enforce_metadata_size_limit(req.metadata(), 8 * 1024);
        match (&size_check, &size_check_repeat) {
            (Ok(()), Ok(())) | (Err(_), Err(_)) => {}
            _ => panic!("enforce_metadata_size_limit is non-referentially-transparent"),
        }

        // Run the interceptor chain. This concrete chain is
        // Tracing + Logging + BearerAuth, and every layer should
        // accept every request; observing the result catches future
        // interceptor drift before metadata checks inspect a
        // partially-processed request.
        assert!(
            chain.intercept_request(&mut req).is_ok(),
            "metadata isolation fuzz chain unexpectedly rejected a request",
        );
        post_call_requests.push(req);
    }

    // Property 3: TracingInterceptor produced a UNIQUE x-request-id
    // per call. Collect every emitted id and assert no duplicates.
    let mut request_ids: HashSet<String> = HashSet::new();
    for req in &post_call_requests {
        if let Some(id) = ascii_value(req.metadata(), "x-request-id") {
            assert!(
                request_ids.insert(id.clone()),
                "TracingInterceptor emitted duplicate x-request-id={id} — \
                 cross-call collision means trace correlation is corrupted",
            );
        }
    }

    // Property 2: per-call metadata isolation. For every PAIR
    // (call_i, call_j), call_j's metadata MUST NOT contain a value
    // that came from call_i's pre-call metadata UNLESS that value
    // was independently present in call_j's own pre-call metadata
    // (legitimate same-content overlap by pure chance).
    //
    // The cleanest expression: for each post-call request, every
    // ASCII value present in its metadata that was NOT in its own
    // pre-call metadata MUST be (a) a header the interceptor chain
    // legitimately injected (Bearer / x-request-id / x-logged), or
    // (b) absent from EVERY OTHER call's pre-call metadata.
    let interceptor_injected: HashSet<&str> = ["authorization", "x-request-id", "x-logged"]
        .iter()
        .copied()
        .collect();

    for (i, post) in post_call_requests.iter().enumerate() {
        let pre_i = &pre_call_metadata[i];
        for (key, value) in post.metadata().iter() {
            // Skip interceptor-injected keys — those are NOT a leak.
            if interceptor_injected.contains(key) {
                continue;
            }
            let MetadataValue::Ascii(post_val) = value else {
                continue;
            };
            // If the value was already in this call's pre-call
            // metadata, it's not a leak.
            if matches!(pre_i.get(key), Some(MetadataValue::Ascii(v)) if v == post_val) {
                continue;
            }
            // Otherwise: the value appeared in this call's metadata
            // but did NOT come from this call's pre-call metadata
            // and is NOT an interceptor-injected key. Check that
            // the value did NOT come from any OTHER call's pre-
            // call metadata — that would be a cross-call leak.
            for (j, pre_j) in pre_call_metadata.iter().enumerate() {
                if i == j {
                    continue;
                }
                if matches!(pre_j.get(key), Some(MetadataValue::Ascii(v)) if v == post_val) {
                    panic!(
                        "cross-call metadata leak: call {i} observed key={key:?} \
                         value={post_val:?} that came from call {j}'s pre-call metadata; \
                         this is a request-scope isolation violation",
                    );
                }
            }
        }
    }
});
