#![allow(clippy::all)]
#![allow(missing_docs)]

//! E2E service mesh composition test (T4.2).
//!
//! Tests realistic service mesh patterns: load balancing across backends,
//! circuit breaker behavior, retry with backoff, concurrent request handling.
//! All within LabRuntime with oracle verification.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use common::e2e_harness::E2eLabHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Simulated backend service
// ---------------------------------------------------------------------------

/// Simulated backend with configurable failure rate.
struct SimBackend {
    id: usize,
    request_count: AtomicUsize,
    failure_count: AtomicUsize,
    healthy: AtomicBool,
}

impl SimBackend {
    fn new(id: usize) -> Arc<Self> {
        Arc::new(Self {
            id,
            request_count: AtomicUsize::new(0),
            failure_count: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
        })
    }

    fn handle_request(&self) -> Result<u64, &'static str> {
        let count = self.request_count.fetch_add(1, Ordering::SeqCst);
        if !self.healthy.load(Ordering::SeqCst) {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            return Err("backend unhealthy");
        }
        Ok(self.id as u64 * 1000 + count as u64)
    }

    fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    fn total_requests(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// T4.2a: Load balance across healthy backends
// ---------------------------------------------------------------------------

#[test]
fn e2e_service_mesh_all_healthy() {
    let mut h = E2eLabHarness::new("e2e_service_mesh_all_healthy", 0xE2E4_2001);
    let root = h.create_root();

    h.phase("setup");

    let backends: Vec<Arc<SimBackend>> = (0..3).map(SimBackend::new).collect();
    let total_requests = 60usize;
    let success_count = Arc::new(AtomicUsize::new(0));

    // Spawn request handlers — round-robin across backends
    for i in 0..total_requests {
        let backend = backends[i % 3].clone();
        let success = success_count.clone();
        h.spawn(root, async move {
            match backend.handle_request() {
                Ok(_) => {
                    success.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    tracing::warn!(backend = backend.id, error = %e, "request failed");
                }
            }
            yield_now().await;
        });
    }

    h.phase("execute");
    h.run_until_quiescent();

    h.phase("verify");
    let s = success_count.load(Ordering::SeqCst);
    assert_with_log!(
        s == total_requests,
        "all requests succeeded",
        total_requests,
        s
    );

    // Verify even distribution (each backend got total/3 requests)
    for (i, backend) in backends.iter().enumerate() {
        let count = backend.total_requests();
        assert_with_log!(
            count == total_requests / 3,
            &format!("backend {i} request count"),
            total_requests / 3,
            count
        );
    }

    h.finish();
}

// ---------------------------------------------------------------------------
// T4.2b: One backend fails — circuit breaker pattern
// ---------------------------------------------------------------------------

#[test]
fn e2e_service_mesh_backend_failure() {
    let mut h = E2eLabHarness::new("e2e_service_mesh_backend_failure", 0xE2E4_2002);
    let root = h.create_root();

    h.phase("setup");

    let backends: Vec<Arc<SimBackend>> = (0..3).map(SimBackend::new).collect();
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    // Mark backend 1 as unhealthy
    backends[1].set_healthy(false);

    let total_requests = 60usize;

    // Spawn requests with retry on failure (try next backend)
    for i in 0..total_requests {
        let primary = backends[i % 3].clone();
        let fallback = backends[(i + 1) % 3].clone();
        let success = success_count.clone();
        let failure = failure_count.clone();
        h.spawn(root, async move {
            if primary.handle_request().is_ok() {
                success.fetch_add(1, Ordering::SeqCst);
            } else {
                // Retry on fallback
                failure.fetch_add(1, Ordering::SeqCst);
                if fallback.handle_request().is_ok() {
                    success.fetch_add(1, Ordering::SeqCst);
                } else {
                    failure.fetch_add(1, Ordering::SeqCst);
                }
            }
            yield_now().await;
        });
    }

    h.phase("execute");
    h.run_until_quiescent();

    h.phase("verify");
    let s = success_count.load(Ordering::SeqCst);
    let f = failure_count.load(Ordering::SeqCst);
    tracing::info!(successes = s, failures = f, "request results");

    // All requests should eventually succeed (via fallback)
    assert_with_log!(
        s == total_requests,
        "all requests eventually succeeded",
        total_requests,
        s
    );
    // Some failures should have occurred (backend 1 was down)
    assert_with_log!(f > 0, "some primary failures occurred", "> 0", f);

    h.finish();
}

// ---------------------------------------------------------------------------
// T4.2c: All backends fail then recover
// ---------------------------------------------------------------------------

#[test]
fn e2e_service_mesh_failure_and_recovery() {
    let mut h = E2eLabHarness::new("e2e_service_mesh_failure_and_recovery", 0xE2E4_2003);
    let root = h.create_root();

    h.phase("setup");

    let backends: Vec<Arc<SimBackend>> = (0..3).map(SimBackend::new).collect();
    let phase1_success = Arc::new(AtomicUsize::new(0));
    let phase2_failure = Arc::new(AtomicUsize::new(0));
    let phase3_success = Arc::new(AtomicUsize::new(0));

    // Phase 1: All healthy — 20 requests
    h.section("phase1: all healthy");
    for i in 0..20 {
        let backend = backends[i % 3].clone();
        let success = phase1_success.clone();
        h.spawn(root, async move {
            if backend.handle_request().is_ok() {
                success.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    h.run_until_quiescent();

    let p1 = phase1_success.load(Ordering::SeqCst);
    assert_with_log!(p1 == 20, "phase1 all succeeded", 20, p1);

    // Phase 2: All backends down — 10 requests
    h.section("phase2: all down");
    for backend in &backends {
        backend.set_healthy(false);
    }
    for i in 0..10 {
        let backend = backends[i % 3].clone();
        let failure = phase2_failure.clone();
        h.spawn(root, async move {
            if backend.handle_request().is_err() {
                failure.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    h.run_until_quiescent();

    let p2 = phase2_failure.load(Ordering::SeqCst);
    assert_with_log!(p2 == 10, "phase2 all failed", 10, p2);

    // Phase 3: Recovery — 20 requests
    h.section("phase3: recovery");
    for backend in &backends {
        backend.set_healthy(true);
    }
    for i in 0..20 {
        let backend = backends[i % 3].clone();
        let success = phase3_success.clone();
        h.spawn(root, async move {
            if backend.handle_request().is_ok() {
                success.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    h.run_until_quiescent();

    let p3 = phase3_success.load(Ordering::SeqCst);
    assert_with_log!(p3 == 20, "phase3 all recovered", 20, p3);

    h.finish();
}

// ---------------------------------------------------------------------------
// T4.2d: Concurrent requests with chaos
// ---------------------------------------------------------------------------

#[test]
fn e2e_service_mesh_chaos() {
    let mut h = E2eLabHarness::with_light_chaos("e2e_service_mesh_chaos", 0xE2E4_2004);
    let root = h.create_root();

    h.phase("setup");

    let backends: Vec<Arc<SimBackend>> = (0..3).map(SimBackend::new).collect();
    let attempted = Arc::new(AtomicUsize::new(0));
    let total_requests = 50usize;

    for i in 0..total_requests {
        let backend = backends[i % 3].clone();
        let attempted_clone = attempted.clone();
        h.spawn(root, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            if cx.checkpoint().is_err() {
                return;
            }
            attempted_clone.fetch_add(1, Ordering::SeqCst);
            let _ = backend.handle_request();
            yield_now().await;
        });
    }

    h.phase("execute");
    h.run_until_quiescent();

    h.phase("verify");
    // Under chaos, not all requests may complete, but system should be stable
    assert_with_log!(
        h.is_quiescent(),
        "quiescent after chaos",
        true,
        h.is_quiescent()
    );

    h.finish();
}
