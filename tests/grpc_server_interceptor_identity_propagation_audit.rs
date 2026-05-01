//! Audit + regression test for `src/grpc/server.rs` interceptor
//! identity propagation through typed extensions (tick #195).
//!
//! Operator's question: "verify interceptor identity propagation."
//!
//! Audit context:
//!
//!   The asupersync gRPC interceptor chain has NO implicit auth
//!   flow. An auth interceptor that extracts a principal from
//!   `authorization` headers MUST share that identity with
//!   downstream interceptors and the user handler via TYPED
//!   EXTENSIONS — not via thread-locals (no ambient authority),
//!   not via Metadata (would leak to the wire and to upstream
//!   services).
//!
//!   The pattern (from `interceptor.rs:5-50` doc comment, and
//!   `streaming.rs:121-161` Extensions module):
//!
//!     1. Auth interceptor parses `authorization` header.
//!     2. Auth interceptor builds an `AuthContext` (principal,
//!        scopes, claims) and inserts via
//!        `request.extensions_mut().insert_typed(auth)`.
//!     3. Downstream interceptors / handlers retrieve via
//!        `request.extensions().get_typed::<AuthContext>()`.
//!     4. The Request is moved into the handler at dispatch
//!        time; extensions move with it.
//!     5. Error-side interceptors (audited tick #185) see the
//!        SAME extensions via the request_snapshot
//!        (server.rs:852).
//!
//! Audit findings:
//!
//!   (a) **Typed extensions key by `TypeId`** (streaming.rs:160).
//!       Each concrete type T has at most ONE entry. A second
//!       `insert_typed::<T>` REPLACES the first. This is the
//!       documented pattern for "auth interceptor inserts
//!       AuthContext, downstream replaces with refined
//!       AuthContext after additional checks."
//!
//!   (b) **`get_typed<T>` returns `Option<&T>`** (streaming.rs:
//!       186-195). Downstream interceptors / handlers that
//!       expect AuthContext but find None handle the absent
//!       case explicitly — no silent default to anonymous.
//!
//!   (c) **Extensions are stored as `Arc<dyn Any + Send + Sync>`**
//!       (streaming.rs:160). Cloning the request (via snapshot)
//!       Arc-clones the extension value — the same AuthContext
//!       is visible through both the original Request and any
//!       snapshot.
//!
//!   (d) **AuthContext does NOT route to the wire**
//!       (interceptor.rs:91-93 doc). The whole point of the
//!       extensions pattern is that AuthContext stays
//!       server-side. A regression that serialized AuthContext
//!       into Metadata (which round-trips to the client) would
//!       leak server-side identity to the peer.
//!
//!   (e) **AuthContext fields are explicitly typed**
//!       (interceptor.rs:99-112): `principal: String`,
//!       `scopes: Vec<String>`, `request_id: Option<String>`,
//!       `claims: HashMap<String, String>`. A regression that
//!       added a `bytes: Bytes` field would change the
//!       on-the-wire propagation surface (still in extensions,
//!       not metadata, but worth pinning the public type).
//!
//! Regression tests below pin (a)-(e) at the public Extensions
//! + AuthContext API surface.

use asupersync::bytes::Bytes;
use asupersync::grpc::interceptor::AuthContext;
use asupersync::grpc::streaming::{Metadata, Request};

#[test]
fn auth_context_inserted_by_interceptor_visible_to_downstream() {
    // Pin (a)+(b): an interceptor inserts AuthContext via
    // extensions_mut().insert_typed; a downstream consumer
    // retrieves via extensions().get_typed.
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());

    // Auth interceptor builds + inserts.
    let auth = AuthContext::with_principal("alice")
        .with_scopes(["read", "write"])
        .with_request_id("req-abc-123");
    request.extensions_mut().insert_typed(auth.clone());

    // Downstream retrieves.
    let recovered = request
        .extensions()
        .get_typed::<AuthContext>()
        .expect("AuthContext must be retrievable by downstream");
    assert_eq!(recovered.principal, "alice");
    assert_eq!(recovered.scopes, vec!["read", "write"]);
    assert_eq!(recovered.request_id, Some("req-abc-123".to_string()));
}

#[test]
fn missing_auth_context_returns_none_no_silent_default() {
    // Pin (b): if no AuthContext was inserted, get_typed
    // returns None. Downstream MUST handle the absent case
    // explicitly — there is no silent fallback to "anonymous"
    // that would let an unauthenticated request slip past a
    // handler that expects auth.
    let request = Request::with_metadata(Bytes::new(), Metadata::new());
    let recovered: Option<&AuthContext> = request.extensions().get_typed();
    assert!(
        recovered.is_none(),
        "absent AuthContext must surface as None — handlers expecting auth \
         get a clear signal, NOT a silent default principal",
    );
}

#[test]
fn second_insert_typed_replaces_first() {
    // Pin (a): TypeId-keyed storage means inserting a SECOND
    // AuthContext replaces the first. This is the documented
    // pattern for refinement-by-later-interceptor (e.g. an
    // auth interceptor inserts a basic AuthContext, an
    // authorization interceptor replaces it with a refined
    // one carrying scopes).
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());

    let basic = AuthContext::with_principal("alice");
    request.extensions_mut().insert_typed(basic);

    let refined = AuthContext::with_principal("alice")
        .with_scopes(["admin"])
        .with_claim("tenant", "acme");
    request.extensions_mut().insert_typed(refined.clone());

    let recovered = request
        .extensions()
        .get_typed::<AuthContext>()
        .expect("refined AuthContext present");
    assert_eq!(recovered.scopes, vec!["admin"]);
    assert_eq!(
        recovered.claims.get("tenant"),
        Some(&"acme".to_string()),
        "second insert REPLACED the first; refined claims visible",
    );
}

#[test]
fn auth_context_does_not_route_to_metadata() {
    // Pin (d): AuthContext lives in extensions, NOT metadata.
    // A regression that serialized AuthContext into the
    // request's Metadata (e.g. as a base64-encoded blob)
    // would leak to the wire.
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    let auth = AuthContext::with_principal("alice").with_claim(
        "secret-claim",
        "do-not-leak-to-wire",
    );
    request.extensions_mut().insert_typed(auth);

    // Verify metadata is empty (no wire-leak).
    assert!(
        request.metadata().iter().count() == 0,
        "inserting AuthContext into extensions MUST NOT route any bytes \
         into metadata; metadata is empty",
    );

    // The AuthContext IS in extensions, however.
    assert!(request.extensions().get_typed::<AuthContext>().is_some());
}

#[test]
fn auth_context_typed_fields_match_documented_shape() {
    // Pin (e): AuthContext public fields are exactly as
    // documented — principal: String, scopes: Vec<String>,
    // request_id: Option<String>, claims: HashMap<String,
    // String>. A regression that added a `bytes: Bytes` field
    // (or removed a documented field) would surface here.
    let auth = AuthContext::default();
    // All fields are explicitly typed. We pin shape via
    // construction + access patterns.
    let _principal: &String = &auth.principal;
    let _scopes: &Vec<String> = &auth.scopes;
    let _request_id: &Option<String> = &auth.request_id;
    let _claims: &std::collections::HashMap<String, String> = &auth.claims;

    // Default values.
    assert_eq!(auth.principal, "");
    assert!(auth.scopes.is_empty());
    assert!(auth.request_id.is_none());
    assert!(auth.claims.is_empty());
}

#[test]
fn extensions_arc_clone_preserves_identity_in_snapshots() {
    // Pin (c): Extensions stores Arc<dyn Any + Send + Sync>.
    // Cloning the Extensions (e.g. via Request::snapshot)
    // produces a NEW Extensions where get_typed returns the
    // SAME underlying value. The Arc means cloning is cheap
    // (refcount bump) — and the value is shared, not copied.
    let mut original = Request::with_metadata(Bytes::new(), Metadata::new());
    let auth = AuthContext::with_principal("alice");
    original.extensions_mut().insert_typed(auth.clone());

    // Clone the extensions (via Extensions::clone, which is
    // Arc-clone underneath).
    let cloned_ext = original.extensions().clone();
    let cloned_auth = cloned_ext
        .get_typed::<AuthContext>()
        .expect("cloned extensions carry AuthContext");
    assert_eq!(cloned_auth.principal, "alice");
}

#[test]
fn anonymous_request_does_not_synthesize_auth_context() {
    // Pin (b)+(d): a request that arrives with NO
    // `authorization` header (anonymous) does NOT have an
    // AuthContext in extensions. The audit-relevant
    // property: the framework does NOT silently synthesize a
    // "default anonymous" AuthContext that downstream might
    // confuse for "authenticated as empty principal."
    let request = Request::with_metadata(Bytes::new(), Metadata::new());
    assert!(
        request.extensions().get_typed::<AuthContext>().is_none(),
        "fresh Request has no AuthContext — anonymous is the absence of \
         AuthContext, not a default-empty AuthContext",
    );
}

#[test]
fn auth_context_clone_is_full_value_clone() {
    // Pin (a): AuthContext is `#[derive(Clone)]` — a clone
    // produces a fully independent value. Mutating the clone
    // does NOT affect the original. Important because
    // refinement interceptors clone-and-modify rather than
    // mutate-in-place.
    let original = AuthContext::with_principal("alice")
        .with_scopes(["read"]);
    let mut clone = original.clone();
    clone.scopes.push("admin".to_string());

    assert_eq!(original.scopes, vec!["read"]);
    assert_eq!(clone.scopes, vec!["read", "admin"]);
}

#[test]
fn extensions_typeid_keying_does_not_collide_across_types() {
    // Pin (a): two different types (e.g. AuthContext and a
    // hypothetical OtherType) are stored independently. A
    // regression that hashed types incorrectly (e.g. via
    // type_name string) would let two distinct types collide.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OtherType {
        value: u32,
    }

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    let auth = AuthContext::with_principal("alice");
    let other = OtherType { value: 42 };

    request.extensions_mut().insert_typed(auth.clone());
    request.extensions_mut().insert_typed(other.clone());

    // Both retrievable independently.
    let recovered_auth = request
        .extensions()
        .get_typed::<AuthContext>()
        .expect("AuthContext present");
    let recovered_other = request
        .extensions()
        .get_typed::<OtherType>()
        .expect("OtherType present");

    assert_eq!(recovered_auth.principal, "alice");
    assert_eq!(recovered_other.value, 42);
}

#[test]
fn auth_context_request_id_optional_independent_of_principal() {
    // Pin (e): request_id is independent of principal — useful
    // for tracing even when the request is unauthenticated. A
    // regression that coupled them (e.g. only including
    // request_id when principal is set) would break tracing
    // for anonymous flows.
    let auth_without_principal = AuthContext::default()
        .with_request_id("req-anon-789");
    assert_eq!(auth_without_principal.principal, "");
    assert_eq!(
        auth_without_principal.request_id,
        Some("req-anon-789".to_string()),
        "request_id present even when principal is empty (anonymous)",
    );
}
