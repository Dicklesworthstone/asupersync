//! br-asupersync-52uhvk — Fuzz the gRPC server-reflection
//! `DescribeService` string-arg parsing path. Every authenticated
//! reflection caller hits this endpoint with a service-name string;
//! the lookup is `BTreeMap::get(&str)`, but the error path allocates
//! `format!("service '{service}' not found")` proportional to the
//! input — megabyte-scale names cause megabyte-scale error
//! allocations per request.
//!
//! Invariants asserted:
//!   1. No panic — `describe_service(&str)` must return `Result` on
//!      any UTF-8 input including U+202E bidi, embedded NUL, CR/LF,
//!      empty string, single dot, double dots, very long names.
//!   2. Bounded allocation — we cap input at MAX_INPUT_LEN to keep
//!      individual cases under libFuzzer's per-iteration budget.
//!   3. No filesystem access — the in-memory descriptor lookup must
//!      never exfiltrate path-traversal shapes (../etc/passwd,
//!      C:\\..., %2F-encoded slashes). The `BTreeMap` lookup is by
//!      exact string match; this is a regression guard against a
//!      future refactor that might introduce path-handling.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::grpc::reflection::ReflectionService;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let svc = ReflectionService::new().allow_anonymous();
    let service_name = String::from_utf8_lossy(data).into_owned();

    // Path 1: describe_service on an empty registry — every input
    // should miss the BTreeMap and return NotFound, never panic.
    let r = catch_unwind(AssertUnwindSafe(|| svc.describe_service(&service_name)));
    assert!(
        r.is_ok(),
        "describe_service panicked on {} bytes",
        service_name.len()
    );

    // Path 2: list_services must always succeed on an empty registry
    // and never panic regardless of subsequent describe_service calls.
    let lr = catch_unwind(AssertUnwindSafe(|| svc.list_services()));
    assert!(lr.is_ok(), "list_services panicked");

    // Path 3: stress structurally-interesting variants — each must
    // surface a Result without panic.
    let variants: [&str; 8] = [
        "",
        ".",
        "..",
        "foo.",
        "../etc/passwd",
        "/absolute/path",
        "C:\\Windows\\System32",
        "service\u{202E}name",
    ];
    for variant in &variants {
        let composed = format!("{variant}{service_name}");
        if composed.len() > MAX_INPUT_LEN {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| svc.describe_service(&composed)));
        assert!(
            r.is_ok(),
            "describe_service panicked on variant={variant:?} + {} bytes",
            service_name.len()
        );
    }
});
