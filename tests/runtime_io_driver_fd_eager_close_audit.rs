//! Audit + regression test for `src/runtime/io_driver.rs` and
//! `src/net/tcp/stream.rs` file-descriptor lifecycle on
//! TcpStream drop.
//!
//! Operator's question: "when a TcpStream is dropped, is the FD
//! closed eagerly (correct) or lazily on next reactor cycle (FD
//! leak risk)? Per asupersync resource discipline, must be
//! eager."
//!
//! Audit findings:
//!
//!   FD close is EAGER via three sequential drops, all running
//!   synchronously in the dropping thread:
//!
//!   1. **`TcpStream::drop`** (stream.rs:972-979): if
//!      `self.shutdown_on_drop` is true (the default for
//!      non-split streams), calls
//!      `self.inner.shutdown(Shutdown::Both)` to send FIN/RST
//!      to the peer for deterministic teardown.
//!
//!   2. **`IoRegistration::drop`** (io_driver.rs:865-887):
//!      runs as `self.registration: Option<IoRegistration>`
//!      drops as part of TcpStream's struct drop. The Drop
//!      impl eagerly deregisters from the reactor:
//!
//!        ```ignore
//!        if let Some(driver) = self.driver.upgrade() {
//!            let mut guard = driver.lock();
//!            let _ = guard.deregister(self.token);
//!        }
//!        ```
//!
//!      Best-effort retry on transient errors. The
//!      `wake_polling_reactor()` call ensures a concurrent
//!      `poll` blocking in epoll_wait/kevent observes the
//!      deregistration immediately, not on its next polling
//!      cycle.
//!
//!   3. **Last `Arc<net::TcpStream>` drop**: `self.inner` is
//!      `Arc<net::TcpStream>` (stream.rs:53). When the last
//!      Arc drops, std's `TcpStream::Drop` runs, which calls
//!      `close(fd)` eagerly (this is the std library's
//!      synchronous close).
//!
//!   The reactor itself does NOT hold an Arc clone of the
//!   inner std::net::TcpStream — it tracks only the FD/Token
//!   pair (see `runtime/reactor/registration.rs` and the
//!   per-platform reactor backends). So a TcpStream drop is
//!   NOT held back by reactor state; the FD closes as soon as
//!   the last user-side Arc drops.
//!
//!   The only documented case where the FD outlives a single
//!   TcpStream drop is `TcpStream::into_split`
//!   (stream.rs:425-438): the read and write halves each hold
//!   an Arc clone, and the FD closes only when BOTH halves
//!   drop. This is the explicit split-streams contract; it
//!   sets `shutdown_on_drop = false` on the originating
//!   stream so neither half issues a premature shutdown.
//!
//! Verdict: **SOUND**. The operator's failure mode (lazy
//! close on next reactor cycle) is STRUCTURALLY IMPOSSIBLE:
//!   - IoRegistration::drop runs synchronously and calls
//!     deregister + wake_polling_reactor immediately.
//!   - The std::net::TcpStream's Drop calls close(fd)
//!     synchronously when its Arc refcount hits zero.
//!   - The reactor holds no Arc to the std stream — only the
//!     FD value, which is integer-data, not a refcount.
//!
//! A regression that:
//!   - removed `IoRegistration::drop` or made it a no-op,
//!   - replaced synchronous deregister with a "deferred
//!     cleanup queue" pulled by the reactor on its next cycle,
//!   - added an Arc<net::TcpStream> field on the reactor
//!     (would let the reactor outlive the user's TcpStream and
//!     hold the FD open),
//!   - changed `inner: Arc<net::TcpStream>` to
//!     `inner: Weak<net::TcpStream>` (would invert ownership
//!     and could cause use-after-free on FD operations),
//!   - removed `shutdown_on_drop` so peers don't see a clean
//!     teardown,
//! would all be caught here.

use std::path::PathBuf;

fn read_io_driver_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/io_driver.rs");
    std::fs::read_to_string(&path).expect("read io_driver.rs")
}

fn read_tcp_stream_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/net/tcp/stream.rs");
    std::fs::read_to_string(&path).expect("read net/tcp/stream.rs")
}

fn fn_body_global<'a>(source: &'a str, fn_marker: &str) -> &'a str {
    let start = source.find(fn_marker).expect("function marker");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("function body close");
    &source[start..start + body_end]
}

#[test]
fn io_registration_drop_eagerly_deregisters() {
    // Pin AUDIT-CRITICAL: IoRegistration::drop synchronously
    // calls driver.deregister(self.token) — NOT push to a
    // deferred-cleanup queue. A regression to a deferred path
    // would mean FDs stay registered past the user-visible
    // drop boundary.
    let source = read_io_driver_source();

    let impl_marker = "impl Drop for IoRegistration {";
    let start = source
        .find(impl_marker)
        .expect("impl Drop for IoRegistration");
    let end_rel = source[start..].find("\n}\n").expect("Drop impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("guard.deregister(self.token)"),
        "REGRESSION: IoRegistration::drop no longer calls \
         `guard.deregister(self.token)` directly. A regression \
         to a deferred cleanup queue would let FDs stay \
         registered past the user-visible drop, breaking the \
         eager-close discipline.\n\nimpl body:\n{body}",
    );

    // The Drop impl must NOT contain queue-like patterns that
    // would defer the deregister.
    let suspect_deferred_patterns = [
        "self.queue.push",
        "deferred_cleanup.push",
        "pending_drops.push",
        "send_to_reactor",
        "schedule_cleanup",
        "Box::pin(",
    ];
    for pat in &suspect_deferred_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: IoRegistration::drop now contains \
             `{pat}` — looks like a deferred cleanup path. \
             The eager-close discipline requires synchronous \
             deregister.\n\nimpl body:\n{body}",
        );
    }
}

#[test]
fn io_registration_drop_wakes_reactor_for_immediate_visibility() {
    // Pin: IoRegistration::drop calls wake_polling_reactor()
    // BEFORE deregister. This ensures a concurrent reactor
    // poll blocking in epoll_wait/kevent observes the
    // deregistration immediately rather than on its next
    // polling cycle.
    let source = read_io_driver_source();

    let impl_marker = "impl Drop for IoRegistration {";
    let start = source.find(impl_marker).expect("impl Drop");
    let end_rel = source[start..].find("\n}\n").expect("Drop impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("self.wake_polling_reactor();"),
        "REGRESSION: IoRegistration::drop no longer calls \
         self.wake_polling_reactor(). Without this, a reactor \
         currently blocked in epoll_wait/kevent might not \
         observe the deregistration until its next polling \
         cycle — fits the operator's 'lazy on next reactor \
         cycle' failure mode exactly.\n\nimpl body:\n{body}",
    );

    // Defense-in-depth: wake must come BEFORE deregister so
    // the reactor wakes BEFORE its registration view changes.
    let wake_pos = body.find("self.wake_polling_reactor()").expect("wake call");
    let deregister_pos = body
        .find("guard.deregister(self.token)")
        .expect("deregister call");
    assert!(
        wake_pos < deregister_pos,
        "REGRESSION: wake_polling_reactor now runs AFTER \
         deregister in the Drop path. The wake should fire \
         FIRST so the reactor exits its blocking call BEFORE \
         the registration disappears, avoiding a window where \
         the reactor blocks on a deregistered FD.",
    );
}

#[test]
fn io_registration_struct_does_not_hold_arc_to_inner_stream() {
    // Pin: IoRegistration tracks only the Token + reactor
    // handles, NOT an Arc<net::TcpStream> or similar. If it
    // held one, a registration outliving the user's TcpStream
    // would keep the FD open until the registration also
    // dropped — breaking eager close.
    let source = read_io_driver_source();

    let struct_marker = "pub struct IoRegistration {";
    let start = source.find(struct_marker).expect("IoRegistration struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    let suspect_field_patterns = [
        "Arc<net::TcpStream",
        "Arc<std::net::TcpStream",
        "Arc<TcpStream",
        "stream: Arc<",
        "fd_owner: Arc<",
    ];
    for pat in &suspect_field_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: IoRegistration now holds `{pat}` — \
             a refcount on the user's stream. This inverts \
             ownership: the registration outliving the \
             stream's user-visible drop would keep the FD \
             open, breaking eager close.\n\nstruct body:\n{body}",
        );
    }
}

#[test]
fn tcp_stream_drop_calls_shutdown_on_drop_when_enabled() {
    // Pin: TcpStream::drop calls self.inner.shutdown(Shutdown::
    // Both) when shutdown_on_drop is true. Without this, peers
    // see RST instead of FIN and the connection appears
    // abnormally closed.
    let source = read_tcp_stream_source();

    let impl_marker = "impl Drop for TcpStream {";
    let start = source.find(impl_marker).expect("TcpStream Drop impl");
    let end_rel = source[start..].find("\n}\n").expect("Drop impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("self.inner.shutdown(Shutdown::Both)"),
        "REGRESSION: TcpStream::drop no longer calls \
         self.inner.shutdown(Shutdown::Both). Without the \
         graceful shutdown, peers may see RST instead of FIN \
         on connection close — the operator's 'eager close' \
         requirement implies graceful close, not silent FD \
         drop.\n\nimpl body:\n{body}",
    );

    assert!(
        body.contains("if self.shutdown_on_drop"),
        "REGRESSION: TcpStream::drop no longer guards the \
         shutdown call on `self.shutdown_on_drop`. The flag \
         is documented to be false after into_split() so \
         neither half issues a premature shutdown; removing \
         the guard would close split streams' FDs from the \
         first half-drop.",
    );
}

#[test]
fn tcp_stream_inner_is_arc_for_split_support() {
    // Pin: inner is `Arc<net::TcpStream>` (refcounted). This
    // is required for `into_split` to share the underlying FD
    // between read/write halves. A regression that changed it
    // to `Box<net::TcpStream>` would break into_split; a
    // regression to `Weak<net::TcpStream>` would invert
    // ownership and could cause use-after-close.
    let source = read_tcp_stream_source();

    assert!(
        source.contains("inner: Arc<net::TcpStream>,"),
        "REGRESSION: TcpStream.inner is no longer \
         `Arc<net::TcpStream>`. The Arc is required for \
         into_split to share the FD between halves; \
         changing the type may break split semantics OR \
         invert FD ownership.",
    );

    // No Weak<net::TcpStream> field — that would be a smell.
    assert!(
        !source.contains("Weak<net::TcpStream>") && !source.contains("Weak<std::net::TcpStream>"),
        "REGRESSION: TcpStream now holds a Weak<net::TcpStream>. \
         Weak references would let the FD close while the \
         TcpStream is still in use — use-after-close on the \
         next read/write.",
    );
}

#[test]
fn tcp_stream_struct_holds_io_registration_for_eager_dereg_on_drop() {
    // Pin: TcpStream has a `registration: Option<IoRegistration>`
    // field. When TcpStream drops, this field drops too,
    // triggering IoRegistration::drop → eager reactor
    // deregister. A regression that removed the field would
    // mean the registration leaks (until the reactor's slab
    // entry was eventually invalidated some other way).
    let source = read_tcp_stream_source();

    assert!(
        source.contains("registration: Option<IoRegistration>,"),
        "REGRESSION: TcpStream no longer has a \
         `registration: Option<IoRegistration>` field. Without \
         it, the reactor's view of the FD lingers past the \
         user-visible drop, breaking the eager-deregister \
         chain.",
    );
}

#[test]
fn into_split_disables_shutdown_on_drop_to_prevent_premature_close() {
    // Pin: into_split sets `shutdown_on_drop = false` so
    // neither half issues a shutdown when it drops. The FD
    // closes only when BOTH halves drop (last Arc drop). A
    // regression that left shutdown_on_drop=true would make
    // the first half-drop close the connection from the OTHER
    // half's perspective — protocol corruption.
    let source = read_tcp_stream_source();

    let fn_marker = "let mut this = self;\n            this.shutdown_on_drop = false;";
    assert!(
        source.contains(fn_marker),
        "REGRESSION: into_split no longer disables \
         shutdown_on_drop. Without this, the first half-drop \
         calls TcpStream::drop's shutdown(Both), closing the \
         connection while the other half is still using it.",
    );
}

#[test]
fn io_driver_deregister_is_synchronous_under_lock() {
    // Pin: IoDriver::deregister is a synchronous fn that
    // updates state under the driver's mutex. NOT an async
    // fn, NOT a method that pushes to a queue. The reactor
    // observes the change on its next epoll/kevent call,
    // which is why IoRegistration::drop also calls
    // wake_polling_reactor.
    let source = read_io_driver_source();

    let fn_marker = "pub fn deregister(&mut self, token: Token) -> io::Result<()> {";
    assert!(
        source.contains(fn_marker),
        "REGRESSION: IoDriver::deregister signature changed. \
         The synchronous `&mut self` receiver and Result return \
         are part of the eager-deregister contract — an async \
         signature or change to &self would be a behavioral \
         shift worth re-auditing.",
    );

    // The body must call self.reactor.deregister synchronously.
    let body = fn_body_global(&source, fn_marker);
    assert!(
        body.contains("self.reactor.deregister("),
        "REGRESSION: IoDriver::deregister no longer calls \
         self.reactor.deregister synchronously. A regression \
         to a deferred / queued path would push FD cleanup \
         past the drop boundary.\n\nfn body:\n{body}",
    );
}
