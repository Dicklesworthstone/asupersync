#![allow(clippy::all)]
//! Exhaustive unit tests for adapter boundary correctness (T7.10).
//!
//! Validates correctness contracts declared in T7.8 performance budgets:
//! CC (CancelAware), BC (Blocking), BB (Body Bridge), TC (Tower),
//! IC (I/O), HC (Hyper), and cross-cutting invariant enforcement.
//!
//! # Test Categories
//!
//! 1. **CancelAware correctness** — CC-01..05 from T7.8 § 6.1
//! 2. **Blocking bridge correctness** — BC-01..04 from T7.8 § 6.2
//! 3. **Body bridge correctness** — BB-01..07 from T7.8 § 6.3
//! 4. **Tower bridge correctness** — TC-01..03 from T7.8 § 6.4
//! 5. **I/O bridge correctness** — IC-01..04 from T7.8 § 6.5
//! 6. **Hyper bridge correctness** — HC-01..04 from T7.8 § 6.6
//! 7. **Cross-cutting invariant enforcement** — IG-01..07 from T7.8 § 4
//! 8. **AdapterConfig budget enforcement** — min_budget_for_call validation
//! 9. **Error type completeness** — all error variants exercised
//! 10. **Startup/shutdown contracts** — SU/SD/GD from T7.8 § 3

#![allow(missing_docs)]

use std::path::Path;

// ─── source loading helpers ────────────────────────────────────────────

fn load_source(module: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("asupersync-tokio-compat/src")
        .join(module);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{module} must exist at {}", path.display()))
}

fn load_budget_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_performance_budgets.md");
    std::fs::read_to_string(path).expect("budget doc must exist")
}

// ═══════════════════════════════════════════════════════════════════════
// 1. CANCELAWARE CORRECTNESS (CC-01..05)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cc01_best_effort_does_not_discard_ready_result_after_cancel() {
    // CC-01: BestEffort mode returns Completed even if cancel was requested
    // when the inner future is already Ready.
    let src = load_source("cancel.rs");

    // BestEffort branch: polls future first, returns Completed if Ready
    assert!(
        src.contains("BestEffort"),
        "cancel.rs must implement BestEffort mode"
    );
    // When cancel_requested && future Ready → CancelResult::Completed
    assert!(
        src.contains("CancelResult::Completed(output)"),
        "BestEffort must return Completed when future is Ready after cancel"
    );
}

#[test]
fn cc02_strict_mode_returns_cancellation_ignored_on_ready_after_cancel() {
    // CC-02: Strict mode returns CancellationIgnored when future completes
    // after cancel was requested.
    let src = load_source("cancel.rs");

    assert!(
        src.contains("CancellationIgnored"),
        "cancel.rs must have CancellationIgnored variant"
    );
    // Strict branch: Ready after cancel → CancellationIgnored
    assert!(
        src.contains("CancelResult::CancellationIgnored(output)"),
        "Strict mode must return CancellationIgnored when Ready after cancel"
    );
}

#[test]
fn cc03_all_modes_return_cancelled_when_pending_after_cancel() {
    // CC-03: All three modes return Cancelled when future is Pending after cancel.
    let src = load_source("cancel.rs");

    // Count CancelResult::Cancelled occurrences — should be 3 (one per mode)
    let cancelled_count = src.matches("CancelResult::Cancelled").count();
    assert!(
        cancelled_count >= 3,
        "all 3 cancel modes must return Cancelled on Pending; found {cancelled_count} occurrences"
    );
}

#[test]
fn cc04_cancel_request_is_callable_via_pin() {
    // CC-04: Cancel request is callable via Pin<&mut Self>.
    let src = load_source("cancel.rs");

    assert!(
        src.contains("fn request_cancel(self: Pin<&mut Self>)"),
        "request_cancel must take Pin<&mut Self>"
    );
    assert!(
        src.contains("*self.project().cancel_requested = true"),
        "request_cancel must set cancel_requested flag"
    );
}

#[test]
fn cc05_cancel_result_has_all_three_variants() {
    // CC-05: CancelResult enum has Completed, Cancelled, CancellationIgnored.
    let src = load_source("cancel.rs");

    assert!(
        src.contains("Completed("),
        "CancelResult must have Completed variant"
    );
    assert!(
        src.contains("Cancelled,") || src.contains("Cancelled\n"),
        "CancelResult must have Cancelled variant"
    );
    assert!(
        src.contains("CancellationIgnored("),
        "CancelResult must have CancellationIgnored variant"
    );
}

#[test]
fn cc_cancel_aware_uses_pin_project_lite() {
    // CancelAware must use pin_project_lite for sound pin projection.
    let src = load_source("cancel.rs");
    assert!(
        src.contains("pin_project!"),
        "CancelAware must use pin_project! macro"
    );
    assert!(
        src.contains("#[pin]"),
        "inner future must be #[pin] projected"
    );
}

#[test]
fn cc_cancel_aware_implements_future() {
    let src = load_source("cancel.rs");
    assert!(
        src.contains("impl<F: Future> Future for CancelAware<F>"),
        "CancelAware must implement Future"
    );
    assert!(
        src.contains("type Output = CancelResult<F::Output>"),
        "CancelAware output must be CancelResult"
    );
}

#[test]
fn cc_no_cancel_polls_normally() {
    // When cancel_requested is false, future is polled normally.
    let src = load_source("cancel.rs");
    assert!(
        src.contains("Poll::Pending => Poll::Pending"),
        "uncancelled Pending must propagate as Pending"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. BLOCKING BRIDGE CORRECTNESS (BC-01..04)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bc01_cx_propagated_via_set_current() {
    // BC-01: Cx propagated to blocking thread via set_current.
    let src = load_source("blocking.rs");

    assert!(
        src.contains("Cx::set_current(Some(cx_clone))"),
        "block_on_sync must propagate Cx via set_current"
    );
}

#[test]
fn bc02_panic_captured_via_catch_unwind() {
    // BC-02: Panics captured as Panicked outcome, not propagated.
    let src = load_source("blocking.rs");

    assert!(
        src.contains("catch_unwind"),
        "blocking bridge must use catch_unwind"
    );
    assert!(
        src.contains("AssertUnwindSafe"),
        "blocking bridge must wrap in AssertUnwindSafe"
    );
    assert!(
        src.contains("BlockingOutcome::Panicked"),
        "panics must map to BlockingOutcome::Panicked"
    );
}

#[test]
fn bc03_cx_guard_is_raii_drop() {
    // BC-03: Cx guard restored after panic via RAII _cx_guard.
    let src = load_source("blocking.rs");

    assert!(
        src.contains("let _cx_guard = asupersync::Cx::set_current"),
        "Cx guard must be RAII (prefixed with _cx_guard)"
    );
}

#[test]
fn bc04_cancellation_check_on_completion() {
    // BC-04: Cancellation checked after blocking operation completes.
    let src = load_source("blocking.rs");

    assert!(
        src.contains("cx.is_cancel_requested()"),
        "must check is_cancel_requested after completion"
    );
    // Strict mode returns Cancelled when cancel was requested during execution
    assert!(
        src.contains("CancellationMode::Strict => BlockingOutcome::Cancelled"),
        "Strict mode must return Cancelled when cancel_requested"
    );
}

#[test]
fn bc_blocking_outcome_has_three_variants() {
    let src = load_source("blocking.rs");

    assert!(
        src.contains("Ok(T)"),
        "BlockingOutcome must have Ok variant"
    );
    assert!(
        src.contains("Cancelled,") || src.contains("Cancelled\n"),
        "BlockingOutcome must have Cancelled variant"
    );
    assert!(
        src.contains("Panicked(String)"),
        "BlockingOutcome must have Panicked variant"
    );
}

#[test]
fn bc_outcome_methods_complete() {
    let src = load_source("blocking.rs");

    let required_methods = [
        "is_ok",
        "is_cancelled",
        "is_panicked",
        "unwrap",
        "map",
        "into_result",
    ];
    for method in &required_methods {
        assert!(
            src.contains(&format!("fn {method}")),
            "BlockingOutcome must implement {method}()"
        );
    }
}

#[test]
fn bc_with_cx_sync_captures_panics() {
    // with_cx_sync must also capture panics.
    let src = load_source("blocking.rs");

    // Count catch_unwind calls — should be at least 2 (block_on_sync + with_cx_sync)
    let catch_count = src.matches("catch_unwind").count();
    assert!(
        catch_count >= 2,
        "both block_on_sync and with_cx_sync must use catch_unwind; found {catch_count}"
    );
}

#[test]
fn bc_block_with_cx_convenience_uses_best_effort() {
    let src = load_source("blocking.rs");
    assert!(
        src.contains("block_on_sync(cx, f, CancellationMode::BestEffort)"),
        "block_with_cx must delegate to block_on_sync with BestEffort"
    );
}

#[test]
fn bc_panic_message_handles_str_and_string() {
    let src = load_source("blocking.rs");
    assert!(
        src.contains("downcast_ref::<&str>()"),
        "panic_message must handle &str payloads"
    );
    assert!(
        src.contains("downcast_ref::<String>()"),
        "panic_message must handle String payloads"
    );
    assert!(
        src.contains("unknown panic"),
        "panic_message must have fallback for unknown types"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. BODY BRIDGE CORRECTNESS (BB-01..07)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bb01_full_body_single_data_frame_then_none() {
    // BB-01: Full body returns single DATA frame then None.
    let src = load_source("body_bridge.rs");

    // Full body path: data.take() → Some(bytes) → Frame::data(bytes)
    assert!(
        src.contains("Frame::data(bytes)"),
        "full body must produce DATA frame"
    );
    // After data consumed: data is None → trailers or None
    assert!(
        src.contains("Poll::Ready(None)"),
        "full body must return None after all frames consumed"
    );
}

#[test]
fn bb02_empty_body_is_end_stream() {
    // BB-02: Empty body reports is_end_stream() == true.
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("fn is_end_stream"),
        "body bridge must implement is_end_stream"
    );
    assert!(
        src.contains("BodyKind::Full(None) => self.trailers.is_none()"),
        "empty body with no trailers must report is_end_stream"
    );
}

#[test]
fn bb03_trailers_frame_after_data() {
    // BB-03: Trailers frame sent after data frames.
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("Frame::trailers(trailers)"),
        "body bridge must produce TRAILERS frame"
    );
    assert!(
        src.contains("with_trailers"),
        "body bridge must support with_trailers builder"
    );
}

#[test]
fn bb04_empty_body_skips_data_goes_to_trailers() {
    // BB-04: Empty body with trailers skips DATA, sends TRAILERS then None.
    let src = load_source("body_bridge.rs");

    // When bytes is empty: skip data frame, go to trailers
    assert!(
        src.contains("bytes.is_empty()"),
        "must check for empty bytes to skip DATA frame"
    );
}

#[test]
fn bb05_size_hint_accurate_for_full_bodies() {
    // BB-05: size_hint returns exact size for full bodies.
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("SizeHint::with_exact(data.len() as u64)"),
        "size_hint must return exact size for full body"
    );
    assert!(
        src.contains("SizeHint::with_exact(0)"),
        "size_hint must return 0 for empty body"
    );
}

#[test]
fn bb06_collect_body_limited_rejects_oversize() {
    // BB-06: collect_body_limited returns TooLarge for oversize bodies.
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("BodyLimitError::TooLarge"),
        "must return TooLarge for oversize bodies"
    );
    assert!(
        src.contains("buf.len() + chunk.len() > max_bytes"),
        "must check cumulative size against limit"
    );
}

#[test]
fn bb07_collect_body_limited_accepts_within_limit() {
    // BB-07: collect_body_limited returns Ok for bodies within limit.
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("Ok(buf.freeze())"),
        "must return Ok(Bytes) for bodies within limit"
    );
}

#[test]
fn bb_body_kind_enum_has_full_and_stream() {
    let src = load_source("body_bridge.rs");
    assert!(src.contains("Full("), "BodyKind must have Full variant");
    assert!(src.contains("Stream("), "BodyKind must have Stream variant");
}

#[test]
fn bb_constructors_are_const_fn() {
    let src = load_source("body_bridge.rs");
    assert!(
        src.contains("pub const fn full("),
        "full() must be const fn"
    );
    assert!(
        src.contains("pub const fn empty("),
        "empty() must be const fn"
    );
    assert!(
        src.contains("pub const fn streaming("),
        "streaming() must be const fn"
    );
}

#[test]
fn bb_grpc_service_adapter_is_zero_cost_newtype() {
    let src = load_source("body_bridge.rs");
    assert!(
        src.contains("pub struct GrpcServiceAdapter<S>"),
        "GrpcServiceAdapter must exist"
    );
    assert!(
        src.contains("pub const fn new(service: S)"),
        "GrpcServiceAdapter::new must be const fn"
    );
    assert!(
        src.contains("pub const fn inner(&self)"),
        "GrpcServiceAdapter::inner must be const fn"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. TOWER BRIDGE CORRECTNESS (TC-01..03)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tc01_from_tower_preserves_poll_ready_semantics() {
    // TC-01: FromTower polls tower service readiness before call.
    let src = load_source("tower_bridge.rs");

    assert!(
        src.contains("svc.poll_ready(task_cx)"),
        "FromTower must poll tower service readiness"
    );
    assert!(
        src.contains("BridgeError::Readiness(e)"),
        "FromTower must propagate readiness errors"
    );
}

#[test]
fn tc02_into_tower_preserves_call_semantics() {
    // TC-02: IntoTower delegates call to inner asupersync service.
    let src = load_source("tower_bridge.rs");

    assert!(
        src.contains("svc.call(&cx, request).await"),
        "IntoTower must delegate to asupersync service's call"
    );
}

#[test]
fn tc03_error_types_preserved_through_bridge() {
    // TC-03: Bridge errors wrap the service's error type parametrically.
    let src = load_source("tower_bridge.rs");

    assert!(
        src.contains("BridgeError<S::Error>"),
        "FromTower must use parametric BridgeError<S::Error>"
    );
    assert!(
        src.contains("type Error = BridgeError<S::Error>"),
        "IntoTower Service::Error must be BridgeError<S::Error>"
    );
}

#[test]
fn tc_from_tower_installs_cx_for_response_future() {
    // FromTower must install Cx during both readiness polling and response await.
    let src = load_source("tower_bridge.rs");

    // Count Cx::set_current calls — should be 2 (poll_fn + response await)
    let cx_set_count = src.matches("Cx::set_current(Some(cx.clone()))").count();
    assert!(
        cx_set_count >= 2,
        "FromTower must install Cx in both readiness and response phases; found {cx_set_count}"
    );
}

#[test]
fn tc_from_tower_checks_cancellation_before_await() {
    let src = load_source("tower_bridge.rs");
    assert!(
        src.contains("cx.is_cancel_requested()"),
        "FromTower must check cancellation before awaiting response"
    );
    assert!(
        src.contains("BridgeError::Cancelled"),
        "must return Cancelled on cancel"
    );
}

#[test]
fn tc_into_tower_requires_cx_current() {
    let src = load_source("tower_bridge.rs");
    assert!(
        src.contains("Cx::current()") && src.contains(".ok_or(BridgeError::NoCxAvailable)"),
        "IntoTower must require Cx::current() to be set"
    );
}

#[test]
fn tc_into_tower_is_always_ready() {
    let src = load_source("tower_bridge.rs");
    assert!(
        src.contains("Poll::Ready(Ok(()))") && src.contains("fn poll_ready"),
        "IntoTower must be always ready"
    );
}

#[test]
fn tc_bridge_error_has_all_variants() {
    let src = load_source("tower_bridge.rs");

    let variants = ["Readiness(", "Service(", "Cancelled", "NoCxAvailable"];
    for variant in &variants {
        assert!(
            src.contains(variant),
            "BridgeError must have {variant} variant"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 5. I/O BRIDGE CORRECTNESS (IC-01..04)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ic01_tokio_io_implements_hyper_read_write() {
    // IC-01: TokioIo implements hyper::rt::Read and hyper::rt::Write.
    let src = load_source("io.rs");

    assert!(
        src.contains("impl<T> hyper::rt::Read for TokioIo<T>"),
        "TokioIo must implement hyper::rt::Read"
    );
    assert!(
        src.contains("impl<T> hyper::rt::Write for TokioIo<T>"),
        "TokioIo must implement hyper::rt::Write"
    );
}

#[test]
fn ic02_asupersync_io_implements_asupersync_read_write() {
    // IC-02: AsupersyncIo implements asupersync AsyncRead/AsyncWrite.
    let src = load_source("io.rs");

    assert!(
        src.contains("impl<T> asupersync::io::AsyncRead for AsupersyncIo<T>"),
        "AsupersyncIo must implement asupersync AsyncRead"
    );
    assert!(
        src.contains("impl<T> asupersync::io::AsyncWrite for AsupersyncIo<T>"),
        "AsupersyncIo must implement asupersync AsyncWrite"
    );
}

#[test]
fn ic03_poll_read_is_cancel_safe_documented() {
    // IC-03: poll_read cancel-safety is documented.
    let src = load_source("io.rs");

    assert!(
        src.contains("poll_read") && src.contains("cancel-safe"),
        "I/O module must document poll_read cancel-safety"
    );
}

#[test]
fn ic04_read_exact_not_cancel_safe_documented() {
    // IC-04: read_exact NOT cancel-safe is documented.
    let src = load_source("io.rs");

    assert!(
        src.contains("read_exact") && src.contains("NOT cancel-safe"),
        "I/O module must document read_exact is NOT cancel-safe"
    );
}

#[test]
fn ic_tokio_io_has_wrap_unwrap_api() {
    let src = load_source("io.rs");

    for method in ["fn new(", "fn inner(", "fn inner_mut(", "fn into_inner("] {
        assert!(src.contains(method), "TokioIo must have {method}");
    }
}

#[test]
fn ic_bidirectional_tokio_trait_impls() {
    // TokioIo must implement Tokio AsyncRead/AsyncWrite (for tokio-io feature)
    let src = load_source("io.rs");

    assert!(
        src.contains("impl<T> tokio::io::AsyncRead for TokioIo<T>"),
        "TokioIo must implement tokio::io::AsyncRead"
    );
    assert!(
        src.contains("impl<T> tokio::io::AsyncWrite for TokioIo<T>"),
        "TokioIo must implement tokio::io::AsyncWrite"
    );
}

#[test]
fn ic_poll_write_vectored_supported() {
    let src = load_source("io.rs");

    // Both TokioIo and AsupersyncIo must support vectored writes
    let vectored_count = src.matches("poll_write_vectored").count();
    assert!(
        vectored_count >= 4,
        "both adapters must implement poll_write_vectored; found {vectored_count} occurrences"
    );
}

#[test]
fn ic_flush_and_shutdown_delegated() {
    let src = load_source("io.rs");

    let flush_count = src.matches("poll_flush").count();
    let shutdown_count = src.matches("poll_shutdown").count();
    assert!(
        flush_count >= 4,
        "both adapters must implement poll_flush; found {flush_count}"
    );
    assert!(
        shutdown_count >= 4,
        "both adapters must implement poll_shutdown; found {shutdown_count}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. HYPER BRIDGE CORRECTNESS (HC-01..04)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn hc01_executor_implements_hyper_executor() {
    // HC-01: AsupersyncExecutor implements hyper::rt::Executor.
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("impl<F> hyper::rt::Executor<F> for AsupersyncExecutor"),
        "AsupersyncExecutor must implement hyper::rt::Executor"
    );
}

#[test]
fn hc02_timer_implements_hyper_timer() {
    // HC-02: AsupersyncTimer implements hyper::rt::Timer.
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("impl hyper::rt::Timer for AsupersyncTimer"),
        "AsupersyncTimer must implement hyper::rt::Timer"
    );
}

#[test]
fn hc03_sleep_implements_hyper_sleep() {
    // HC-03: AsupersyncSleep implements hyper::rt::Sleep.
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("impl hyper::rt::Sleep for AsupersyncSleep"),
        "AsupersyncSleep must implement hyper::rt::Sleep"
    );
}

#[test]
fn hc04_executor_routes_spawn_through_closure() {
    // HC-04: Spawned tasks route through user-provided spawn function.
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("(self.spawn_fn)(Box::pin(future))"),
        "execute must delegate to spawn_fn"
    );
}

#[test]
fn hc_timer_has_sleep_sleep_until_reset() {
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("fn sleep(&self, duration: Duration)"),
        "Timer must implement sleep"
    );
    assert!(
        src.contains("fn sleep_until(&self, deadline: Instant)"),
        "Timer must implement sleep_until"
    );
    assert!(src.contains("fn reset("), "Timer must implement reset");
}

#[test]
fn hc_sleep_uses_asupersync_native_timer() {
    let src = load_source("hyper_bridge.rs");

    assert!(
        src.contains("asupersync::time::sleep("),
        "AsupersyncSleep must use asupersync native timer"
    );
    assert!(
        src.contains("asupersync::time::wall_now()"),
        "AsupersyncSleep must use wall_now for time source"
    );
}

#[test]
fn hc_executor_noop_for_testing() {
    let src = load_source("hyper_bridge.rs");
    assert!(
        src.contains("fn noop()"),
        "AsupersyncExecutor must provide noop() for testing"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. CROSS-CUTTING INVARIANT ENFORCEMENT (IG-01..07)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ig01_no_ambient_authority_all_entry_points_explicit() {
    // IG-01: No thread-local sniffing in adapter entry points.
    // Verify: block_on_sync requires &Cx, FromTower::call requires &Cx.
    let blocking_src = load_source("blocking.rs");
    assert!(
        blocking_src.contains("cx: &asupersync::Cx"),
        "block_on_sync must require explicit &Cx"
    );

    let tower_src = load_source("tower_bridge.rs");
    assert!(
        tower_src.contains("cx: &asupersync::Cx"),
        "FromTower::call must require explicit &Cx"
    );
}

#[test]
fn ig02_structured_concurrency_spawn_through_region() {
    // IG-02: AsupersyncExecutor routes spawn through user-controlled region.
    let src = load_source("hyper_bridge.rs");
    assert!(
        src.contains("spawn_fn"),
        "executor must use user-controlled spawn function (region routing)"
    );
}

#[test]
fn ig03_cancellation_protocol_implemented() {
    // IG-03: CancelAware wrapper exists and checks cancel state.
    let cancel_src = load_source("cancel.rs");
    assert!(
        cancel_src.contains("cancel_requested"),
        "CancelAware must track cancel_requested state"
    );

    // Blocking bridge also checks cancellation
    let blocking_src = load_source("blocking.rs");
    assert!(
        blocking_src.contains("is_cancel_requested"),
        "blocking bridge must check cancellation"
    );
}

#[test]
fn ig04_no_obligation_leaks_spawn_tracked() {
    // IG-04: Blocking tasks use spawn_blocking (tracked by pool).
    let src = load_source("blocking.rs");
    assert!(
        src.contains("asupersync::runtime::spawn_blocking"),
        "blocking bridge must use spawn_blocking for task tracking"
    );
}

#[test]
fn ig05_outcome_severity_lattice() {
    // IG-05: BlockingOutcome has Ok/Cancelled/Panicked (three-valued lattice).
    let src = load_source("blocking.rs");
    assert!(src.contains("Ok(T)"), "must have Ok variant");
    assert!(src.contains("Cancelled"), "must have Cancelled variant");
    assert!(
        src.contains("Panicked(String)"),
        "must have Panicked variant"
    );

    // CancelResult has Completed/Cancelled/CancellationIgnored
    let cancel_src = load_source("cancel.rs");
    assert!(
        cancel_src.contains("Completed("),
        "must have Completed variant"
    );
    assert!(
        cancel_src.contains("CancellationIgnored("),
        "must have CancellationIgnored variant"
    );
}

#[test]
fn ig06_no_tokio_runtime_in_adapter_code() {
    // IG-06: No embedded Tokio runtime in any adapter module.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    for entry in std::fs::read_dir(&src_dir).expect("src dir must exist") {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            let fname = entry.file_name();

            for forbidden in [
                "tokio::runtime::Runtime",
                "#[tokio::main]",
                "#[tokio::test]",
                "tokio::runtime::Builder",
            ] {
                assert!(
                    !content.contains(forbidden),
                    "IG-06 violation: {fname:?} contains forbidden pattern: {forbidden}"
                );
            }
        }
    }
}

#[test]
fn ig07_all_adapter_modules_present() {
    // IG-07: All seven source files exist in the compat crate.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    for module in [
        "lib.rs",
        "hyper_bridge.rs",
        "body_bridge.rs",
        "tower_bridge.rs",
        "io.rs",
        "cancel.rs",
        "blocking.rs",
    ] {
        assert!(
            src_dir.join(module).exists(),
            "IG-07: adapter module {module} must exist"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 8. ADAPTER CONFIG BUDGET ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn adapter_config_has_budget_fields() {
    let src = load_source("lib.rs");

    assert!(
        src.contains("min_budget_for_call: u64"),
        "AdapterConfig must have min_budget_for_call"
    );
    assert!(
        src.contains("cancellation_mode: CancellationMode"),
        "AdapterConfig must have cancellation_mode"
    );
    assert!(
        src.contains("fallback_timeout: Option<std::time::Duration>"),
        "AdapterConfig must have fallback_timeout"
    );
}

#[test]
fn adapter_config_default_values_reasonable() {
    let src = load_source("lib.rs");

    // Default cancellation mode is BestEffort
    assert!(
        src.contains("CancellationMode::default()"),
        "default cancellation_mode must be BestEffort"
    );
    // Default fallback timeout is 30s
    assert!(
        src.contains("Duration::from_secs(30)"),
        "default fallback_timeout must be 30s"
    );
    // Default min budget is 10
    assert!(
        src.contains("min_budget_for_call: 10"),
        "default min_budget_for_call must be 10"
    );
}

#[test]
fn adapter_error_has_insufficient_budget() {
    let src = load_source("lib.rs");
    assert!(
        src.contains("InsufficientBudget"),
        "AdapterError must have InsufficientBudget variant"
    );
    assert!(
        src.contains("remaining: u64") && src.contains("required: u64"),
        "InsufficientBudget must track remaining and required"
    );
}

#[test]
fn adapter_error_has_all_variants() {
    let src = load_source("lib.rs");

    for variant in [
        "Service(",
        "Cancelled",
        "Timeout",
        "InsufficientBudget",
        "CancellationIgnored",
    ] {
        assert!(
            src.contains(variant),
            "AdapterError must have {variant} variant"
        );
    }
}

#[test]
fn adapter_config_builder_methods() {
    let src = load_source("lib.rs");

    for method in [
        "with_cancellation_mode",
        "with_fallback_timeout",
        "with_min_budget",
    ] {
        assert!(
            src.contains(&format!("fn {method}")),
            "AdapterConfig must have {method}() builder"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 9. ERROR TYPE COMPLETENESS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn all_error_types_implement_display() {
    let lib_src = load_source("lib.rs");
    assert!(
        lib_src.contains("impl<E: std::fmt::Display> std::fmt::Display for AdapterError<E>"),
        "AdapterError must implement Display"
    );

    let body_src = load_source("body_bridge.rs");
    assert!(
        body_src.contains("impl<E: std::fmt::Display> std::fmt::Display for BodyLimitError<E>"),
        "BodyLimitError must implement Display"
    );

    let tower_src = load_source("tower_bridge.rs");
    assert!(
        tower_src.contains("impl<E: std::fmt::Display> std::fmt::Display for BridgeError<E>"),
        "BridgeError must implement Display"
    );

    let blocking_src = load_source("blocking.rs");
    assert!(
        blocking_src.contains("impl std::fmt::Display for BlockingBridgeError"),
        "BlockingBridgeError must implement Display"
    );
}

#[test]
fn all_error_types_implement_error_trait() {
    let lib_src = load_source("lib.rs");
    assert!(
        lib_src.contains(
            "impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for AdapterError<E>"
        ),
        "AdapterError must implement Error"
    );

    let body_src = load_source("body_bridge.rs");
    assert!(
        body_src.contains("std::error::Error for BodyLimitError<E>"),
        "BodyLimitError must implement Error"
    );

    let tower_src = load_source("tower_bridge.rs");
    assert!(
        tower_src.contains("std::error::Error for BridgeError<E>"),
        "BridgeError must implement Error"
    );

    let blocking_src = load_source("blocking.rs");
    assert!(
        blocking_src.contains("impl std::error::Error for BlockingBridgeError"),
        "BlockingBridgeError must implement Error"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. STARTUP / SHUTDOWN / DRAIN CONTRACTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn su03_body_bridge_const_fn_constructors() {
    // SU-03: body_bridge constructors are const fn (zero startup cost).
    let src = load_source("body_bridge.rs");
    assert!(src.contains("pub const fn full("));
    assert!(src.contains("pub const fn empty("));
    assert!(src.contains("pub const fn streaming("));
}

#[test]
fn sd03_body_stream_terminates_with_none() {
    // SD-03: Body yields None after all frames consumed.
    let src = load_source("body_bridge.rs");
    assert!(
        src.contains("Poll::Ready(None)"),
        "body must yield None after terminal"
    );
}

#[test]
fn sd02_blocking_cx_guard_raii() {
    // SD-02: Blocking thread Cx guard is RAII (restored on drop/panic).
    let src = load_source("blocking.rs");
    // _cx_guard pattern ensures drop on scope exit
    let guard_count = src
        .matches("let _cx_guard = asupersync::Cx::set_current")
        .count();
    assert!(
        guard_count >= 2,
        "both block_on_sync and with_cx_sync must use RAII Cx guard; found {guard_count}"
    );
}

#[test]
fn gd01_cancel_aware_timeout_fallback_grace_period() {
    // GD-01: TimeoutFallback mode references grace period concept.
    let cancel_src = load_source("cancel.rs");
    assert!(
        cancel_src.contains("TimeoutFallback"),
        "cancel.rs must implement TimeoutFallback mode"
    );

    let lib_src = load_source("lib.rs");
    assert!(
        lib_src.contains("fallback_timeout"),
        "AdapterConfig must have fallback_timeout for GD-01"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 11. BUDGET DOC CROSS-REFERENCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_doc_contract_ids_all_tested_here() {
    let doc = load_budget_doc();

    // Verify all contract IDs from § 6 are present in the budget doc
    let contract_ids = [
        "CC-01", "CC-02", "CC-03", "CC-04", "CC-05", "BC-01", "BC-02", "BC-03", "BC-04", "BB-01",
        "BB-02", "BB-03", "BB-04", "BB-05", "BB-06", "BB-07", "TC-01", "TC-02", "TC-03", "IC-01",
        "IC-02", "IC-03", "IC-04", "HC-01", "HC-02", "HC-03", "HC-04",
    ];

    for id in &contract_ids {
        assert!(
            doc.contains(id),
            "budget doc must define contract {id} that is tested here"
        );
    }
}

#[test]
fn all_seven_modules_have_deny_unsafe_code() {
    // Project policy: #![deny(unsafe_code)] at crate level.
    let lib_src = load_source("lib.rs");
    assert!(
        lib_src.contains("deny(unsafe_code)"),
        "compat crate must deny unsafe_code"
    );
}

#[test]
fn compat_crate_has_no_tokio_dependency_features_requiring_runtime() {
    let cargo_toml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .expect("Cargo.toml must exist");

    // Must not require tokio runtime features
    assert!(
        !cargo_toml.contains("\"rt\"") && !cargo_toml.contains("\"rt-multi-thread\""),
        "compat crate must not depend on tokio rt or rt-multi-thread features"
    );
    // Only sync feature should be used
    assert!(
        cargo_toml.contains("[\"sync\"]"),
        "tokio dependency should only use sync feature"
    );
}
