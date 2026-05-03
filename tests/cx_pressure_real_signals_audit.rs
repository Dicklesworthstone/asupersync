//! Audit + regression test for `Cx::pressure()` metric
//! semantics — verify the value comes from REAL OS signals,
//! not a constant or stub.
//!
//! Operator's question: "Cx::pressure() returns 0.0..=1.0
//! indicating 'how full' the runtime is. Verify the metric
//! is computed from real signals (queue depth, worker
//! busy-fraction). If returning constant or stub value,
//! file bead. If correctly computed, pin behavior."
//!
//! Audit findings:
//!
//!   `Cx::pressure() -> Option<&SystemPressure>` returns the
//!   atomic pressure handle attached to the Cx. The
//!   underlying `SystemPressure.headroom()` value is
//!   computed from **REAL platform-specific OS signals** by
//!   `ResourceMonitor` — NOT a constant or stub. Note the
//!   semantic inversion: `headroom()` returns 0.0–1.0 where
//!   **1.0 = full capacity (normal)** and **0.0 = no
//!   capacity (emergency)**. The operator's "how full"
//!   framing is technically inverted from headroom; apps
//!   that want "fullness" compute `1.0 - headroom`.
//!
//!   Real-signal sources (resource_monitor.rs:1116-1144):
//!
//!   1. **Memory** (resource_monitor.rs:1157):
//!      `platform::process_rss_bytes()` reads
//!        - Linux: VmRSS from `/proc/self/status`
//!        - macOS/BSD: `getrusage(RUSAGE_SELF).ru_maxrss`
//!      Max via `RLIMIT_AS` (or `/proc/meminfo`'s `MemTotal`
//!      when rlimit is `RLIM_INFINITY`).
//!
//!   2. **File descriptors** (resource_monitor.rs:1183):
//!      real platform read of FD count + ulimit.
//!
//!   3. **CPU load** (resource_monitor.rs:1209):
//!      `/proc/loadavg` (Linux first column = 1-minute load
//!      average) or `libc::getloadavg(loads, 3)` (macOS/BSD).
//!
//!   4. **Network connections** (resource_monitor.rs:1228):
//!      real platform read of socket counts.
//!
//!   The signal flow:
//!
//!   - `SystemResourceCollector::collect_now()` reads the
//!     four signals (resource_monitor.rs:1116).
//!   - Each measurement is fed into
//!     `ResourcePressure::update_measurement` which stores
//!     the raw measurement.
//!   - `update_degradation_level` per-resource maps the
//!     measurement into a 5-band level (None/Light/Moderate/
//:     Heavy/Emergency).
//!   - The COMPOSITE level is the max() across all 4
//!     resource axes (resource_monitor.rs:402-410).
//!   - `system_pressure.set_headroom(max_level.to_headroom())`
//:     publishes the headroom (resource_monitor.rs:380):
//!       None=1.0, Light=0.75, Moderate=0.5, Heavy=0.25,
//!       Emergency=0.0.
//!   - `Cx::pressure()` returns the Arc<SystemPressure> handle
//:     so callers can read the headroom via atomic load.
//!
//!   The signal is updated periodically by the collector
//!   thread (default `collection_interval: Duration::from_secs(1)`).
//!   Between collections, the atomic value is the last
//!   real measurement — stale by at most 1s by default.
//!
//! Verdict: **SOUND**. The headroom is computed from real
//! OS-level signals (VmRSS, FD count, loadavg, network
//! connections) — NOT a constant or stub. The five-band
//! mapping is deterministic and matches the public
//! SystemPressure.degradation_level() / level_label API.
//!
//! Note on the operator's framing: the operator says
//! "queue depth, worker busy-fraction" as example signals.
//! The current implementation uses OS-level signals (RSS,
//! FDs, loadavg, network) instead. This is by design —
//! asupersync's resource pressure is OS-resource-driven,
//! not scheduler-internal. Per-region admission caps
//! (RegionLimits.max_tasks) provide the scheduler-internal
//! capacity check separately. Both are exposed; the
//! operator's framing conflates two distinct backpressure
//! signals.
//!
//! No bead filed. The headroom is real, not stub.
//!
//! A regression that:
//!   - changed SystemResourceCollector::collect_now to
//:     return constant measurements without OS reads (would
//!     turn the headroom into a stub),
//!   - removed the `/proc/loadavg` read on Linux (would
//!     lose the CPU-load signal),
//!   - removed the getloadavg / process_rss_bytes platform
//:     reads (would lose the cross-platform real-signal
//!     mechanism),
//!   - changed the composite level from max() to a constant
//!     None (would silently report no pressure regardless
//!     of actual resource exhaustion),
//!   - changed the to_headroom mapping (would shift the
//!     five-band semantic without notifying callers that
//:     compose Cx::pressure with should_degrade(threshold)),
//!   - removed update_degradation_level's set_headroom
//!     call (would freeze SystemPressure at its initial
//!     value — effectively a stub even though OS signals
//!     are still being read),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_pressure_returns_optional_system_pressure_handle() {
    // Pin (link 0): Cx::pressure() returns the
    // Option<&SystemPressure> handle. Without it, app code
    // can't observe the runtime pressure at all.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn pressure(&self) -> Option<&SystemPressure> {"),
        "REGRESSION: Cx::pressure signature changed. Apps \
         lose the documented backpressure handle.",
    );
}

#[test]
fn system_resource_collector_collect_now_reads_four_real_signals() {
    // Pin (link 1+2+3+4): collect_now reads four real OS
    // signals (memory, FD, CPU load, network). All four
    // gated by `if let Ok(...)` so partial-platform support
    // (e.g., Windows missing /proc) gracefully omits the
    // measurement.
    let source = read("src/runtime/resource_monitor.rs");

    let fn_marker = "pub fn collect_now(&self) -> Result<(), ResourceMonitorError> {";
    let start = source.find(fn_marker).expect("collect_now fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("collect_now close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.collect_memory_usage()"),
        "REGRESSION: collect_now no longer reads memory \
         usage. The headroom no longer reflects memory \
         pressure — backpressure on memory-bound workloads \
         is silently invisible.",
    );

    assert!(
        body.contains("self.collect_fd_usage()"),
        "REGRESSION: collect_now no longer reads FD usage. \
         FD-bound workloads (many sockets) silently exhaust \
         without pressure signal.",
    );

    assert!(
        body.contains("self.collect_cpu_load()"),
        "REGRESSION: collect_now no longer reads CPU load. \
         CPU-bound workloads silently saturate without \
         pressure signal — the OS's load-average signal \
         is the canonical capacity indicator.",
    );

    assert!(
        body.contains("self.collect_network_usage()"),
        "REGRESSION: collect_now no longer reads network \
         usage. Network-bound workloads silently saturate.",
    );

    // Each successful read must update the corresponding
    // ResourcePressure measurement.
    assert!(
        body.contains("self.pressure\n                .update_measurement(ResourceType::Memory")
            && body.contains("update_measurement(ResourceType::FileDescriptors")
            && body.contains("update_measurement(ResourceType::CpuLoad")
            && body.contains("update_measurement(ResourceType::NetworkConnections"),
        "REGRESSION: collect_now no longer feeds measurements \
         into ResourcePressure. The signals are read but \
         not published — headroom stays stub-like at \
         initial value.",
    );
}

#[test]
fn collect_memory_usage_reads_real_platform_rss() {
    // Pin (link 1): collect_memory_usage uses
    // platform::process_rss_bytes — a REAL platform read
    // (Linux /proc/self/status; macOS getrusage). NOT a
    // constant.
    let source = read("src/runtime/resource_monitor.rs");

    let fn_marker = "fn collect_memory_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {";
    let start = source.find(fn_marker).expect("collect_memory_usage fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("collect_memory_usage close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("platform::process_rss_bytes()"),
        "REGRESSION: collect_memory_usage no longer calls \
         platform::process_rss_bytes. Either the platform \
         abstraction is gone or memory is now a constant — \
         headroom no longer tracks real RSS.",
    );

    assert!(
        body.contains("platform::memory_max_bytes()"),
        "REGRESSION: collect_memory_usage no longer reads \
         the memory limit (RLIMIT_AS / MemTotal). Without a \
         denominator, the % usage can't be computed — \
         headroom reverts to constant.",
    );
}

#[test]
fn collect_cpu_load_reads_loadavg_from_os() {
    // Pin (link 3): collect_cpu_load reads /proc/loadavg
    // (Linux) or getloadavg (macOS/BSD). NOT a constant.
    let source = read("src/runtime/resource_monitor.rs");

    // The /proc/loadavg path is the canonical Linux read.
    assert!(
        source.contains("\"/proc/loadavg\""),
        "REGRESSION: /proc/loadavg path is gone from \
         resource_monitor.rs. Linux CPU-load signal is lost \
         — headroom no longer reflects system load.",
    );

    // The getloadavg libc call is the canonical macOS/BSD
    // read.
    assert!(
        source.contains("libc::getloadavg(loads.as_mut_ptr(), 3)"),
        "REGRESSION: libc::getloadavg call is gone. macOS/\
         BSD lose their CPU-load signal — headroom on \
         non-Linux is now stub.",
    );
}

#[test]
fn update_degradation_level_publishes_max_to_system_pressure_headroom() {
    // Pin (signal flow): update_degradation_level uses the
    // MAX degradation level across all resources to compute
    // composite headroom. This is what makes any one
    // resource exhaustion drive the overall pressure signal.
    let source = read("src/runtime/resource_monitor.rs");

    let fn_marker = "pub fn update_degradation_level(&self, resource_type: ResourceType, level: DegradationLevel) {";
    let start = source.find(fn_marker).expect("update_degradation_level fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("update_degradation_level close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("levels\n            .values()\n            .max()")
            || body.contains(".values().max()"),
        "REGRESSION: update_degradation_level no longer \
         takes max() across resource types. Either it uses \
         min/avg (which would mask any single resource's \
         exhaustion) or the composite is now constant — \
         headroom doesn't reflect any one resource's \
         pressure.",
    );

    assert!(
        body.contains("self.system_pressure.set_headroom(max_level.to_headroom());"),
        "REGRESSION: update_degradation_level no longer \
         calls set_headroom on system_pressure. The \
         atomic pressure handle that Cx::pressure() returns \
         is frozen at its initial value — effectively a \
         stub even though OS signals are still being read.",
    );
}

#[test]
fn degradation_level_to_headroom_uses_documented_five_band_mapping() {
    // Pin (semantic contract): the to_headroom mapping is
    // None=1.0, Light=0.75, Moderate=0.5, Heavy=0.25,
    // Emergency=0.0. These five bands match the public
    // SystemPressure.degradation_level / level_label API.
    let source = read("src/runtime/resource_monitor.rs");

    let fn_marker = "pub fn to_headroom(self) -> f32 {";
    let start = source.find(fn_marker).expect("to_headroom fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("to_headroom close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("Self::None => 1.0,")
            && body.contains("Self::Light => 0.75,")
            && body.contains("Self::Moderate => 0.5,")
            && body.contains("Self::Heavy => 0.25,")
            && body.contains("Self::Emergency => 0.0,"),
        "REGRESSION: to_headroom mapping changed. The \
         five-band semantic is part of the public contract \
         — apps using SystemPressure::should_degrade(0.25) \
         expect the Heavy threshold to land at exactly \
         0.25. Drifting these constants silently changes \
         backpressure decision points.",
    );
}

#[test]
fn composite_degradation_level_takes_max_across_resource_types() {
    // Pin (signal-flow contract): composite_degradation_level
    // returns max() across all degradation_levels — any
    // one resource's exhaustion drives the composite.
    let source = read("src/runtime/resource_monitor.rs");

    let fn_marker = "pub fn composite_degradation_level(&self) -> DegradationLevel {";
    let start = source.find(fn_marker).expect("composite_degradation_level fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("composite_degradation_level close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("levels\n            .values()\n            .max()")
            || body.contains(".values().max()"),
        "REGRESSION: composite_degradation_level no longer \
         takes max(). Either it averages (masks exhaustion) \
         or it returns a constant (stub).",
    );
}

#[test]
fn monitor_config_collection_interval_default_is_one_second() {
    // Pin (signal freshness): the default collection interval
    // is 1 second. Without periodic collection, the headroom
    // value would freeze at startup — effectively a stub.
    let source = read("src/runtime/resource_monitor.rs");

    assert!(
        source.contains("collection_interval: Duration::from_secs(1),"),
        "REGRESSION: MonitorConfig default collection_interval \
         changed from 1s. Either the interval is too long \
         (headroom is silently stale by minutes) or the \
         collector is disabled (effective stub).",
    );
}

#[test]
fn system_pressure_headroom_loaded_via_atomic_for_lock_free_query() {
    // Pin (read path): SystemPressure::headroom uses
    // atomic load — apps can call this from the hot path
    // without contention. The atomic is the storage that
    // bridges the collector thread to user threads.
    let source = read("src/types/pressure.rs");

    assert!(
        source.contains("self.headroom_bits.load(Ordering::Relaxed)"),
        "REGRESSION: SystemPressure::headroom no longer uses \
         atomic load. Either a lock has been added (hot-path \
         contention) or the read is non-atomic (data race).",
    );
}

#[test]
fn system_pressure_set_headroom_writes_via_atomic_store() {
    // Pin (write path): set_headroom uses atomic store. The
    // collector thread publishes via this; user threads
    // observe via Acquire-load. Without atomic, the
    // collector-side write is a data race.
    let source = read("src/types/pressure.rs");

    let fn_marker = "pub fn set_headroom(&self, headroom: f32) {";
    let start = source.find(fn_marker).expect("set_headroom fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("set_headroom close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.headroom_bits\n            .store(clamped.to_bits(), Ordering::Relaxed);")
            || body.contains(".store(clamped.to_bits(), Ordering::Relaxed);"),
        "REGRESSION: set_headroom no longer publishes via \
         atomic store. Either a lock is involved (collector-\
         side contention) or the write is non-atomic (data \
         race with reader threads).",
    );
}

#[test]
fn no_constant_or_stub_headroom_returned_from_pressure() {
    // Pin (anti-stub): the source must NOT contain code that
    // returns a constant headroom value (e.g., always 1.0 or
    // always 0.5). A grep for suspicious patterns finds
    // none in the production path.
    let source = read("src/types/pressure.rs");

    let suspect_constant_returns = [
        "pub fn headroom(&self) -> f32 {\n        1.0",
        "pub fn headroom(&self) -> f32 {\n        0.5",
        "pub fn headroom(&self) -> f32 {\n        return 1.0;",
        "// TODO: implement real pressure",
        "// stub: always returns 1.0",
    ];
    for pat in &suspect_constant_returns {
        assert!(
            !source.contains(pat),
            "REGRESSION: SystemPressure::headroom now returns \
             a constant (`{pat}`). The headroom is a stub \
             — backpressure decisions are uniformly stale, \
             defeating the OS-signal-driven design.",
        );
    }

    // Also check the resource_monitor for the same pattern.
    let monitor_source = read("src/runtime/resource_monitor.rs");
    let suspect_monitor_stubs = [
        "// stub implementation",
        "fn collect_now(&self) -> Result<(), ResourceMonitorError> {\n        Ok(())\n    }",
    ];
    for pat in &suspect_monitor_stubs {
        assert!(
            !monitor_source.contains(pat),
            "REGRESSION: collect_now is now a stub (`{pat}`) — \
             OS signals are no longer read; headroom \
             frozen at initial value.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_has_capacity_backpressure_query_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
