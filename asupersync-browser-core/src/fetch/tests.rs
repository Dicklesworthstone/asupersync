//! Actual dispatcher admission/lifecycle and shared byte-accounting tests.
//! No native test pretends to perform browser network I/O.
use super::state::{BodyBudget, error_outcome, prepare};
use super::*;
use asupersync::types::{WasmAbiOutcomeEnvelope, WasmAbiValue, WasmHandleRef, WasmScopeEnterRequest, WasmTaskSpawnRequest};
use std::future::Future;
use std::task::{Context, Waker};

const ORIGIN: &str = "https://api.example.test";

struct Owners { runtime: WasmHandleRef, scope: WasmHandleRef }
impl Owners {
    fn new() -> Self {
        crate::reset_dispatcher_for_tests();
        let runtime = serde_json::from_str(&crate::runtime_create_impl(Some(serde_json::json!({
            "fetchAuthority": { "allowedOrigins": [ORIGIN], "allowedMethods": ["GET", "POST"], "allowCredentials": false }
        }).to_string())).unwrap()).unwrap();
        let scope = crate::with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
            parent: runtime, label: None,
        }, None)).unwrap();
        Self { runtime, scope }
    }
    fn request(&self) -> WasmFetchRequest {
        WasmFetchRequest { scope: self.scope, url: format!("{ORIGIN}/data"), method: "GET".into(), credentials: false, body: None }
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        if crate::dispatcher_handle_is_live(&self.runtime) {
            crate::runtime_close_impl(serde_json::to_string(&self.runtime).unwrap(), None).unwrap();
        }
    }
}
fn limits() -> FetchBytesLimits { FetchBytesLimits::new(4, 8, 3) }
fn live() -> usize {
    crate::DISPATCHER.with(|d| d.borrow().handles().memory_report().live_handles)
}
fn status(code: u16) -> WasmAbiOutcomeEnvelope {
    WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::U64(u64::from(code)) }
}

#[test]
fn admission_inherits_exact_scope_authority_and_drop_releases_a_pinned_handle() {
    let owners = Owners::new();
    let baseline = live();
    let (_, lease) = prepare(owners.request(), limits(), None).unwrap();
    assert!(lease.check_active().is_ok());
    assert_eq!(live(), baseline + 1);
    let handle = lease.handle();
    crate::DISPATCHER.with(|d| assert!(d.borrow().handles().get(&handle).unwrap().pinned));
    drop(lease);
    assert_eq!(live(), baseline);
    assert!(!crate::dispatcher_handle_is_live(&handle));
}

#[test]
fn initial_origin_method_and_credential_denials_do_not_allocate_handles() {
    let owners = Owners::new();
    let baseline = live();
    let mut origin = owners.request();
    origin.url = "https://unauthorized.example.test/secret?token=private".into();
    let mut method = owners.request();
    method.method = "DELETE".into();
    let mut credentials = owners.request();
    credentials.credentials = true;
    for request in [origin, method, credentials] {
        assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::CapabilityDenied));
        assert_eq!(live(), baseline);
    }
}

#[test]
fn detached_runtime_has_no_ambient_fetch_authority() {
    let owners = Owners::new();
    let runtime = crate::with_dispatcher(|d| d.runtime_create(None)).unwrap();
    let mut request = owners.request();
    request.scope = runtime;
    let baseline = live();
    assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::CapabilityDenied));
    assert_eq!(live(), baseline);
    crate::runtime_close_impl(serde_json::to_string(&runtime).unwrap(), None).unwrap();
}

#[test]
fn invalid_url_method_and_get_body_are_refused_before_admission() {
    let owners = Owners::new();
    let baseline = live();
    for url in ["file:///private", "https://user:password@api.example.test/data", "", "/relative"] {
        let mut request = owners.request();
        request.url = url.into();
        assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::InvalidRequest));
    }
    let mut request = owners.request();
    request.method = "not a method".into();
    assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::InvalidRequest));
    let mut request = owners.request();
    request.body = Some(Vec::new());
    assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::InvalidRequest));
    assert_eq!(live(), baseline);
}

#[test]
fn request_limit_is_inclusive_and_checked_before_any_handle_is_allocated() {
    let owners = Owners::new();
    let baseline = live();
    let mut request = owners.request();
    request.method = " post ".into();
    request.body = Some(vec![1, 2, 3, 4]);
    let (normalized, lease) = prepare(request.clone(), limits(), None).unwrap();
    assert_eq!(normalized.method, "POST");
    assert_eq!(normalized.body, request.body);
    drop(lease);
    request.body.as_mut().unwrap().push(5);
    assert_eq!(prepare(request, limits(), None).err(), Some(FetchBytesError::RequestLimit { limit: 4 }));
    assert_eq!(live(), baseline);
}

#[test]
fn wrong_handle_kind_and_abi_version_refuse_admission() {
    let owners = Owners::new();
    let task = crate::with_dispatcher(|d| d.task_spawn(&WasmTaskSpawnRequest {
        scope: owners.scope, label: None, cancel_kind: None,
    }, None)).unwrap();
    let mut wrong_owner = owners.request();
    wrong_owner.scope = task;
    let baseline = live();
    assert_eq!(prepare(wrong_owner, limits(), None).err(), Some(FetchBytesError::OwnerUnavailable));
    assert_eq!(prepare(owners.request(), limits(), Some(WasmAbiVersion { major: u16::MAX, minor: 0 })).err(),
        Some(FetchBytesError::IncompatibleAbi));
    assert_eq!(live(), baseline);
}

#[test]
fn owner_close_invalidates_lease_and_stale_drop_cannot_release_a_replacement() {
    let owners = Owners::new();
    let (_, lease) = prepare(owners.request(), limits(), None).unwrap();
    let old = lease.handle();
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert_eq!(lease.check_active(), Err(FetchBytesError::Cancelled));
    let scope = crate::with_dispatcher(|d| d.scope_enter(&WasmScopeEnterRequest {
        parent: owners.runtime, label: None,
    }, None)).unwrap();
    let mut request = owners.request();
    request.scope = scope;
    let (_, replacement) = prepare(request, limits(), None).unwrap();
    assert_ne!(old, replacement.handle());
    let baseline = live();
    drop(lease);
    assert_eq!(live(), baseline);
    assert!(replacement.check_active().is_ok());
}

#[test]
fn complete_publication_releases_once_and_stale_success_is_refused() {
    let owners = Owners::new();
    let (_, mut lease) = prepare(owners.request(), limits(), None).unwrap();
    let handle = lease.handle();
    lease.publish(status(404)).unwrap();
    assert!(!crate::dispatcher_handle_is_live(&handle));
    assert_eq!(lease.publish(status(200)), Err(FetchBytesError::Publication));
    let (_, mut cancelling) = prepare(owners.request(), limits(), None).unwrap();
    crate::with_dispatcher(|d| d.apply_abort(&cancelling.handle())).unwrap();
    assert_eq!(cancelling.publish(status(200)), Err(FetchBytesError::Cancelled));
    cancelling.publish(error_outcome(FetchBytesError::Cancelled)).unwrap();
    let (_, mut stale) = prepare(owners.request(), limits(), None).unwrap();
    crate::scope_close_impl(serde_json::to_string(&owners.scope).unwrap(), None).unwrap();
    assert_eq!(stale.publish(status(200)), Err(FetchBytesError::Cancelled));
}

#[test]
fn zero_limits_are_real_refusals_not_unlimited_sentinels() {
    let owners = Owners::new();
    let zero = FetchBytesLimits::new(0, 0, 0);
    let (_, lease) = prepare(owners.request(), zero, None).unwrap();
    let mut body = Vec::new();
    let mut budget = BodyBudget::new(zero);
    assert_eq!(budget.reserve_chunk(&mut body, 0), Ok(0..0));
    assert_eq!(budget.reserve_chunk(&mut body, 1), Err(FetchBytesError::ResponseLimit { limit: 0 }));
    assert_eq!(budget.begin_read(), Err(FetchBytesError::ReadLimit { limit: 0 }));
    drop(lease);
}

#[test]
fn chunk_limit_is_checked_before_allocation_or_prefix_mutation() {
    let budget = BodyBudget::new(limits());
    let mut body = vec![1, 2, 3];
    let destination = budget.reserve_chunk(&mut body, 5).unwrap();
    body[destination].copy_from_slice(&[4, 5, 6, 7, 8]);
    assert_eq!(body, [1, 2, 3, 4, 5, 6, 7, 8]);
    let capacity = body.capacity();
    assert_eq!(budget.reserve_chunk(&mut body, 1), Err(FetchBytesError::ResponseLimit { limit: 8 }));
    assert_eq!(body.capacity(), capacity);
    assert_eq!(body, [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn empty_chunks_and_the_eof_call_share_the_finite_read_budget() {
    let mut budget = BodyBudget::new(FetchBytesLimits::new(0, 8, 2));
    let mut body = Vec::new();
    budget.begin_read().unwrap();
    assert_eq!(budget.reserve_chunk(&mut body, 0), Ok(0..0));
    budget.begin_read().unwrap();
    assert_eq!(budget.reserve_chunk(&mut body, 0), Ok(0..0));
    assert_eq!(budget.begin_read(), Err(FetchBytesError::ReadLimit { limit: 2 }));
    assert!(body.is_empty());
}

#[test]
fn length_overflow_refuses_without_saturation_or_allocation() {
    let budget = BodyBudget::new(FetchBytesLimits::new(0, usize::MAX, 1));
    assert_eq!(budget.checked_end(usize::MAX, 1), Err(FetchBytesError::LengthOverflow));
    assert_eq!(budget.checked_end(usize::MAX - 1, 1), Ok(usize::MAX));
}

#[test]
fn chunk_segmentation_preserves_bytes_and_does_not_change_the_byte_limit() {
    for split in 0..=8 {
        let budget = BodyBudget::new(limits());
        let mut body = Vec::new();
        let bytes = [0, 1, 2, 3, 4, 5, 6, 7];
        for chunk in [&bytes[..split], &bytes[split..]] {
            let destination = budget.reserve_chunk(&mut body, chunk.len()).unwrap();
            body[destination].copy_from_slice(chunk);
        }
        assert_eq!(body, bytes);
        assert!(matches!(budget.reserve_chunk(&mut body, 1), Err(FetchBytesError::ResponseLimit { .. })));
    }
}

#[test]
fn diagnostics_do_not_include_response_payloads_or_host_exception_strings() {
    let response = FetchBytesResponse { status: 500, body: b"secret session token".to_vec() };
    let debug = format!("{response:?}");
    assert!(debug.contains("500"));
    assert!(!debug.contains("secret"));
    assert!(matches!(error_outcome(FetchBytesError::Cancelled), WasmAbiOutcomeEnvelope::Cancelled { .. }));
    assert!(matches!(error_outcome(FetchBytesError::ResponseLimit { limit: 8 }), WasmAbiOutcomeEnvelope::Err { .. }));
}

#[test]
fn native_entry_point_does_not_fabricate_a_network_result_or_admit_a_handle() {
    let owners = Owners::new();
    let baseline = live();
    let mut future = Box::pin(fetch_bytes(owners.request(), limits(), None));
    let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    assert_eq!(result, std::task::Poll::Ready(Err(FetchBytesError::UnsupportedHost)));
    assert_eq!(live(), baseline);
}
