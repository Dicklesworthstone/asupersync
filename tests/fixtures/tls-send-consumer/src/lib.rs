//! Downstream compiler coverage for GH #86.
//!
//! Deliberately no recursion_limit attribute, HTTP imports, test-internals,
//! unsafe auto-trait implementations, or boxing before the Send obligation.
//! Cargo compiles this as a separate crate, not as part of asupersync's lib.
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::spawn_mailbox::SpawnRequest;
use std::future::{Future, pending};

fn require_send<T: Send>() {}
fn require_send_sync<T: Send + Sync>() {}
fn require_send_closure<F: FnOnce() + Send + 'static>(_: F) {}

/// Exercise the reported long auto-trait path, not just Cx in isolation.
pub fn assert_runtime_send_contracts() {
    require_send::<SpawnRequest>();
    require_send_sync::<Cx>();
}

/// Keep the whole context alive across suspension. Moving only one of its
/// fields into the future would not test the context's structural type graph.
pub fn cx_capturing_future(cx: Cx) -> impl Future<Output = ()> + Send + 'static {
    async move {
        pending::<()>().await;
        drop(cx);
    }
}

/// Also reach Cx indirectly through the spawn/admission/mailbox graph that
/// exposed the extra rustls depth in the reporter's compiler notes.
pub fn spawn_request_capturing_future(
    request: SpawnRequest,
) -> impl Future<Output = ()> + Send + 'static {
    async move {
        pending::<()>().await;
        drop(request);
    }
}

/// A blocking-pool-style closure must be Send before any runtime type erasure.
/// This is a compile contract; the deliberately pending futures are not run.
pub fn assert_capturing_closure_is_send(cx: Cx, request: SpawnRequest) {
    require_send_closure(move || {
        drop(cx_capturing_future(cx));
        drop(spawn_request_capturing_future(request));
    });
}

#[test]
fn public_runtime_types_are_send() {
    assert_runtime_send_contracts();
}
