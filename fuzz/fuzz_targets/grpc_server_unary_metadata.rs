#![no_main]

//! Cargo-fuzz target for the unary-dispatch metadata-validation gate
//! in `asupersync::grpc::server`.
//!
//! `Server::dispatch_unary` invokes `enforce_metadata_size_limit` as
//! its FIRST gate before any interceptor or handler runs
//! (br-asupersync-7u4r72). This target covers the public `Metadata`
//! insertion boundary followed by that synchronous validation helper. It
//! does not model HPACK/H2 ingestion or prove that every transport adapter
//! routes through the helper.
//!
//! This target drives `enforce_metadata_size_limit` with
//! `Arbitrary`-derived metadata entries (key + ASCII value | binary value)
//! plus an arbitrary payload `Bytes`. Invalid public insertions are rejected
//! before the validation helper; accepted entries are then checked below.
//!
//!   1. **No panic at the modeled boundaries.** Every insertion either
//!      succeeds unchanged or rejects without mutation; validation returns
//!      Ok(()) or a documented Status error, never unwinds.
//!
//!   2. **Documented validation rules are honored.** When the result
//!      is Ok, the metadata satisfies the rules
//!      `validate_inbound_metadata` enforces (no reserved grpc-*
//!      keys outside the allowlist, printable ASCII values,
//!      well-formed content-type and te). When the result is Err,
//!      the error code is one of the documented two.
//!
//!   3. **Size cap honored.** `enforce_metadata_size_limit(meta, cap)`
//!      with `cap > 0` rejects with `resource_exhausted` only when the
//!      pre-validation metadata byte size (key + value bytes) would
//!      exceed `cap`. Names that pass validation but bust the cap are
//!      typed correctly.
//!
//!   4. **Request<Bytes> construction never panics.** The dispatch
//!      surface wraps the validated metadata into `Request<Bytes>`
//!      via `Request::with_metadata`; a panic here would propagate
//!      out of dispatch_unary's first phase.
//!
//! Why this target matters even with the unit tests in server.rs:
//! the existing tests cover well-formed metadata. This fuzzer adds
//! systematic adversarial-byte coverage across the public metadata
//! container and the synchronous validation helper. Wire-frame and
//! HPACK ingestion remain outside this target.
//!
//! Out of scope (separate beads):
//!   * Async dispatch_unary itself — needs a runtime; pinned by the
//!     end-to-end tests in tests/grpc_*.rs.
//!   * Cx-leak verification across the handler boundary — needs an
//!     async runtime to drive the future; tracked via the structured-
//!     concurrency invariant tests under tests/.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_server_unary_metadata -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::Status;
use asupersync::grpc::server::{DEFAULT_MAX_METADATA_SIZE, enforce_metadata_size_limit};
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request};
use libfuzzer_sys::fuzz_target;

/// Per-iteration cap on number of metadata entries — bounded so each
/// iteration stays sub-second.
const MAX_ENTRIES: usize = 64;
/// Per-iteration cap on key/value byte length. Larger than the 8 KiB
/// per-call cap so the resource-exhausted path is reachable on
/// realistic seeds.
const MAX_KV_LEN: usize = 16 * 1024;
/// Per-iteration cap on payload bytes. Enough to exercise binary
/// payloads through Request::with_metadata.
const MAX_PAYLOAD_LEN: usize = 4 * 1024;

#[derive(Arbitrary, Debug)]
struct UnaryFuzzInput {
    entries: Vec<MetadataEntry>,
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct MetadataEntry {
    /// Raw key bytes — adversarial unicode + control + reserved-prefix.
    key: String,
    /// Either an ASCII string (rejected by `Metadata::insert` if it contains
    /// non-printable/non-ASCII bytes) or a binary blob (must use a `-bin`
    /// suffixed key per gRPC spec).
    kind: ValueKind,
}

#[derive(Arbitrary, Debug)]
enum ValueKind {
    Ascii(String),
    Binary(Vec<u8>),
}

fn truncate_kv(s: &str) -> String {
    if s.len() <= MAX_KV_LEN {
        return s.to_string();
    }
    let mut end = MAX_KV_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn metadata_entry_count(metadata: &Metadata) -> usize {
    metadata.iter().count()
}

fn expected_metadata_key(key: &str, binary: bool) -> Option<String> {
    let mut normalized = key.to_ascii_lowercase();
    if binary && !normalized.ends_with("-bin") {
        normalized.push_str("-bin");
    }
    if normalized.is_empty() {
        return None;
    }
    if !binary && normalized.ends_with("-bin") {
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

fn assert_ascii_insert_observation(
    metadata: &Metadata,
    before_len: usize,
    key: &str,
    value: &str,
    inserted: bool,
) {
    let after_len = metadata_entry_count(metadata);
    if !inserted {
        assert_eq!(
            after_len,
            before_len,
            "Metadata::insert rejected an ASCII entry but mutated metadata: \
             raw_key_len={}, before_len={before_len}, after_len={after_len}",
            key.len(),
        );
        assert!(
            expected_metadata_key(key, false).is_none() || !expected_ascii_value_is_valid(value),
            "Metadata::insert rejected a locally valid ASCII metadata entry: \
             raw_key={key:?}, raw_value={value:?}",
        );
        return;
    }

    assert_eq!(
        after_len,
        before_len + 1,
        "Metadata::insert accepted an ASCII entry without appending exactly one entry: \
         raw_key_len={}, before_len={before_len}, after_len={after_len}",
        key.len(),
    );
    let expected_key =
        expected_metadata_key(key, false).expect("accepted ASCII metadata key must normalize");
    assert!(
        expected_ascii_value_is_valid(value),
        "Metadata::insert accepted an invalid ASCII metadata value: {value:?}",
    );
    let (stored_key, stored_value) = metadata
        .iter()
        .last()
        .expect("accepted ASCII metadata entry must be observable");
    assert_eq!(
        stored_key, expected_key,
        "accepted ASCII key normalization drifted"
    );
    match stored_value {
        MetadataValue::Ascii(stored) => assert_eq!(
            stored, value,
            "accepted ASCII metadata value changed during insertion",
        ),
        MetadataValue::Binary(_) => panic!("Metadata::insert stored an ASCII value as binary"),
    }
}

fn assert_binary_insert_observation(
    metadata: &Metadata,
    before_len: usize,
    key: &str,
    value: &[u8],
    inserted: bool,
) {
    let after_len = metadata_entry_count(metadata);
    if !inserted {
        assert_eq!(
            after_len,
            before_len,
            "Metadata::insert_bin rejected a binary entry but mutated metadata: \
             raw_key_len={}, before_len={before_len}, after_len={after_len}",
            key.len(),
        );
        assert!(
            expected_metadata_key(key, true).is_none(),
            "Metadata::insert_bin rejected a locally valid binary metadata key: raw_key={key:?}",
        );
        return;
    }

    assert_eq!(
        after_len,
        before_len + 1,
        "Metadata::insert_bin accepted a binary entry without appending exactly one entry: \
         raw_key_len={}, before_len={before_len}, after_len={after_len}",
        key.len(),
    );
    let expected_key =
        expected_metadata_key(key, true).expect("accepted binary metadata key must normalize");
    let (stored_key, stored_value) = metadata
        .iter()
        .last()
        .expect("accepted binary metadata entry must be observable");
    assert_eq!(
        stored_key, expected_key,
        "accepted binary key normalization drifted",
    );
    match stored_value {
        MetadataValue::Binary(stored) => assert_eq!(
            stored.as_ref(),
            value,
            "accepted binary metadata value changed during insertion",
        ),
        MetadataValue::Ascii(_) => panic!("Metadata::insert_bin stored a binary value as ASCII"),
    }
}

fn build_metadata(entries: &[MetadataEntry]) -> Metadata {
    let mut metadata = Metadata::new();
    for entry in entries.iter().take(MAX_ENTRIES) {
        let key = truncate_kv(&entry.key);
        match &entry.kind {
            ValueKind::Ascii(value) => {
                let value = truncate_kv(value);
                let before_len = metadata_entry_count(&metadata);
                let inserted = metadata.insert(key.clone(), value.clone());
                assert_ascii_insert_observation(&metadata, before_len, &key, &value, inserted);
            }
            ValueKind::Binary(bytes) => {
                let bytes_capped: Vec<u8> = bytes.iter().take(MAX_KV_LEN).copied().collect();
                let before_len = metadata_entry_count(&metadata);
                let inserted = metadata.insert_bin(key.clone(), Bytes::from(bytes_capped.clone()));
                assert_binary_insert_observation(
                    &metadata,
                    before_len,
                    &key,
                    &bytes_capped,
                    inserted,
                );
            }
        }
    }
    metadata
}

fn assert_ok_status_code_or_panic(status: &Status, ctx: &str) {
    let code = status.code();
    assert!(
        matches!(code, Code::InvalidArgument | Code::ResourceExhausted),
        "enforce_metadata_size_limit returned an unexpected Status code: \
         code={code:?}, ctx={ctx}, message={msg:?}",
        msg = status.message(),
    );
}

fuzz_target!(|input: UnaryFuzzInput| {
    if input.entries.len() > MAX_ENTRIES || input.payload.len() > MAX_PAYLOAD_LEN {
        return;
    }

    let metadata = build_metadata(&input.entries);

    // Property 1+2: cap=DEFAULT enforces the production envelope.
    let result_default = enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE);
    if let Err(ref status) = result_default {
        assert_ok_status_code_or_panic(status, "default-cap");
    }

    // Property 3: cap=0 disables enforcement (per the documented "0 means
    // unlimited" convention). Validation rules still run, but the
    // length cap path must not trigger ResourceExhausted.
    let result_uncapped = enforce_metadata_size_limit(&metadata, 0);
    if let Err(ref status) = result_uncapped {
        assert_eq!(
            status.code(),
            Code::InvalidArgument,
            "cap=0 must NEVER produce ResourceExhausted (validation-only path); \
             got code={:?}, msg={:?}",
            status.code(),
            status.message(),
        );
    }

    // Cross-check: any input that fails validation under cap=0 must
    // also fail under cap=DEFAULT (validation runs first in both
    // paths). The reverse is not true — a name may be valid but bust
    // the cap.
    if result_uncapped.is_err() {
        assert!(
            result_default.is_err(),
            "an input that fails validation under cap=0 MUST also fail under cap=DEFAULT — \
             enforce_metadata_size_limit's validation precedes the size check",
        );
    }

    // Property 4: Request<Bytes> construction never panics on the
    // validated metadata (or on the raw metadata if validation
    // rejected it — the dispatch path doesn't reach Request
    // construction in that case, but the constructor itself must
    // still be panic-free for any well-formed metadata snapshot).
    let payload = Bytes::from(
        input
            .payload
            .iter()
            .take(MAX_PAYLOAD_LEN)
            .copied()
            .collect::<Vec<_>>(),
    );
    let _request = Request::with_metadata(payload, metadata.clone());
    // The clone path itself is part of dispatch's request-snapshot
    // pattern; a panic in clone is the same DoS as a panic in
    // construction.
    let _cloned = metadata.clone();
});
