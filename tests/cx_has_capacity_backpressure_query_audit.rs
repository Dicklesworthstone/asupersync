//! Audit + regression test for application-facing capacity /
//! backpressure query APIs.
//!
//! Operator's question: "is there a way for application code
//! to query 'can I spawn another N tasks safely' before
//! spawning (correct: backpressure-aware) or do we just
//! spawn-and-pray (DoS risk)?"
//!
//! Audit findings:
//!
//!   asupersync exposes **multiple** backpressure-aware
//!   query APIs on `Cx` and the runtime state. Application
//!   code can check capacity at three layers (hardware
//!   pressure, region admission limits, current usage)
//!   before spawning. There is no spawn-and-pray pathway
//!   except by user choice. The chain:
//!
//!   1. **`Cx::pressure() -> Option<&SystemPressure>`**
//!      (cx/cx.rs:791): the application-facing handle to
//!      the runtime's resource monitor. Returns None if no
//!      pressure handle was attached at runtime construction
//!      (e.g., minimal lab-runtime configurations).
//!
//!   2. **`SystemPressure::headroom() -> f32`** (types/
//!      pressure.rs:62): returns 0.0–1.0 with five-band
//!      semantics:
//!        - 1.0 — full headroom (normal)
//!        - 0.75 — light degradation
//!        - 0.5 — moderate degradation
//!        - 0.25 — heavy degradation
//!        - 0.0 — emergency degradation
//!      Atomic load with Relaxed ordering — lock-free, can
//!      be called arbitrarily often without contention.
//!
//!   3. **`SystemPressure::should_degrade(threshold) -> bool`**
//!      (pressure.rs:79): boolean check against a caller-
//!      provided threshold. The user-facing
//!      "can I spawn another N tasks?" check looks like:
//!      ```ignore
//!      if cx.pressure().is_some_and(|p| p.should_degrade(0.25)) {
//!          // skip / shed / queue
//!      } else {
//!          // safe to spawn
//!      }
//!      ```
//!
//!   4. **`SystemPressure::degradation_level() -> u8`**
//!      (pressure.rs:97): returns 0–4 (Normal / Light /
//!      Moderate / Heavy / Emergency). Lets the user pick
//!      a threshold matching their workload's tolerance.
//!
//!   5. **`RegionLimits.max_tasks: Option<usize>`** (record/
//!      region.rs:209): hard admission cap per region.
//!      Spawn requests beyond this return
//!      `SpawnError::RegionAtCapacity { region, limit, live }`
//!      — backpressure surfaced as a typed error, not a
//!      panic.
//!
//!   6. **`RegionLimits.max_subregions: Option<usize>`**
//!      (record/region.rs): hard admission cap on per-parent
//!      child-region creation. `create_child_region` returns
//!      `RegionCreateError::ParentAtCapacity { region, limit, live, ... }`
//!      when exceeded.
//!
//!   7. **`RegionRecord::task_count() -> usize`** (region.rs:
//!      518): current per-region task count without cloning
//!      the task list. Combined with `RegionLimits.max_tasks`,
//!      lets app code compute remaining capacity:
//!      `limit - current = N safe spawns`.
//!
//!   8. **`RuntimeState::region_limits(region) -> Option<RegionLimits>`**
//!      (state.rs:1465): query the current limit for a
//!      region. Pairs with `region.task_count()` for the
//!      "can I spawn N more?" check.
//!
//!   9. **`RuntimeState::live_task_count() -> usize`** (state.rs:
//!      2338): global task count across all regions. Useful
//!      for global backpressure decisions (e.g., reject new
//!      requests if total live tasks > N).
//!
//!  10. **`RuntimeState::check_resource_pressure_for_region(priority)`**
//!      (state.rs:3761): runtime-side pre-create check that
//!      composes resource_monitor pressure with the
//!      region's RegionPriority. Returns
//!      `Err(RegionCreateError::ResourcePressure)` when the
//!      runtime would shed the region. Application code
//!      doesn't call this directly — `create_child_region`
//!      invokes it internally — but the public effect is
//!      that backpressure is enforced at admission, not
//!      after the fact.
//!
//!  11. **`RegionState::can_spawn() -> bool`** (region.rs:127):
//!      state predicate — returns true ONLY when the region
//!      is `Open`. A region in Closing / Draining /
//!      Finalizing / Closed rejects new spawns at the
//!      structural level, independent of capacity.
//!
//!  12. **Spawn returns Result with RegionAtCapacity**
//:      (cx/scope.rs SpawnError): the spawn API returns
//!      `Result<(TaskHandle<...>, StoredTask), SpawnError>`.
//!      The Err arm carries enough information for the
//!      application to retry, queue, or shed:
//!        - `SpawnError::RegionClosed(region)` — region not
//!          accepting new work.
//!        - `SpawnError::RegionAtCapacity { region, limit,
//!          live }` — capacity hit.
//!        - `SpawnError::ResourcePressure { ... }` —
//!          runtime backpressure.
//!
//! Verdict: **SOUND**. Application code has rich
//! backpressure introspection at three layers:
//!   - Hardware: cx.pressure() + SystemPressure methods.
//!   - Region admission: RegionLimits + region.task_count
//!     + state.region_limits.
//!   - Current usage: state.live_task_count + region state
//!     predicates.
//! The spawn API also surfaces backpressure as a typed
//! Err (RegionAtCapacity / ResourcePressure / RegionClosed)
//! — so even spawn-without-pre-check produces actionable
//! error information rather than a runtime panic.
//!
//! No bead filed. The framing "spawn-and-pray" is incorrect:
//! spawn() returns Result with structured backpressure
//! error variants. The "feature missing" interpretation
//! would be wrong.
//!
//! A regression that:
//!   - removed Cx::pressure() (would lose the application-
//!     facing pressure query — apps would need to thread
//!     SystemPressure manually),
//!   - changed pressure() to return SystemPressure by VALUE
//!     instead of &SystemPressure (would force atomic load
//:     into the public method — losing the option to skip
//!     the check entirely if pressure unavailable),
//!   - removed should_degrade / degradation_level methods
//!     (would force apps to compute their own band from
//!     headroom — fragile, easy to drift from runtime
//!     constants),
//!   - removed max_tasks from RegionLimits (would lose hard
//:     admission caps — apps couldn't enforce per-region
//!     bounds),
//!   - removed RegionAtCapacity from SpawnError (would lose
//!     the typed backpressure error — apps would have to
//!     parse string error messages),
//!   - changed spawn to panic on capacity exhaustion
//!     instead of returning Err (would break the Result
//!     contract — apps lose graceful-degradation hooks),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_pressure_method_returns_optional_system_pressure_handle() {
    // Pin (link 1): Cx::pressure() returns Option<&SystemPressure>.
    // The Option lets minimal/lab configurations omit the
    // pressure handle without breaking app code.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn pressure(&self) -> Option<&SystemPressure> {"),
        "REGRESSION: Cx::pressure signature changed. The \
         Option<&SystemPressure> contract lets app code \
         gracefully handle the no-pressure case (e.g., lab \
         runtime). A change to require the handle would \
         break existing apps; a change to return by value \
         would force an atomic load on every call.",
    );

    // The body must access the pressure handle from
    // self.handles.pressure (Arc<SystemPressure> stored
    // there).
    let fn_marker = "pub fn pressure(&self) -> Option<&SystemPressure> {";
    let start = source.find(fn_marker).expect("pressure fn");
    let body_end = source[start..].find("\n    }\n").expect("pressure close");
    let body = &source[start..start + body_end];
    assert!(
        body.contains("self.handles.pressure.as_deref()"),
        "REGRESSION: Cx::pressure no longer reads from \
         self.handles.pressure. The pressure handle storage \
         pattern is broken — apps may see stale or \
         missing pressure data.",
    );
}

#[test]
fn system_pressure_headroom_returns_f32_via_atomic_load() {
    // Pin (link 2): SystemPressure::headroom() returns f32
    // 0.0-1.0 via atomic load. The atomic + Relaxed ordering
    // is what makes the query lock-free (apps can call
    // arbitrarily often).
    let source = read("src/types/pressure.rs");

    assert!(
        source.contains("pub fn headroom(&self) -> f32 {"),
        "REGRESSION: SystemPressure::headroom signature \
         changed. The fp32 return is the documented \
         contract — apps depend on the 0.0-1.0 scale.",
    );

    let fn_marker = "pub fn headroom(&self) -> f32 {";
    let start = source.find(fn_marker).expect("headroom fn");
    let body_end = source[start..].find("\n    }\n").expect("headroom close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.headroom_bits.load(Ordering::Relaxed)"),
        "REGRESSION: headroom() no longer uses atomic load \
         with Relaxed ordering. A lock or stronger ordering \
         would make the query expensive — backpressure \
         polling becomes contention-prone.",
    );
}

#[test]
fn system_pressure_should_degrade_provides_threshold_check() {
    // Pin (link 3): should_degrade(threshold) is the
    // boolean primitive for "should I shed?". Without it,
    // apps would compose headroom < threshold themselves —
    // working but verbose.
    let source = read("src/types/pressure.rs");

    assert!(
        source.contains("pub fn should_degrade(&self, threshold: f32) -> bool {"),
        "REGRESSION: SystemPressure::should_degrade signature \
         changed. The boolean threshold-check is the \
         documented backpressure primitive — apps using it \
         break.",
    );
}

#[test]
fn system_pressure_degradation_level_returns_five_band_u8() {
    // Pin (link 4): degradation_level() returns 0-4 with
    // five-band semantics matching the runtime resource
    // monitor. This is the public severity signal.
    let source = read("src/types/pressure.rs");

    assert!(
        source.contains("pub fn degradation_level(&self) -> u8 {"),
        "REGRESSION: degradation_level signature changed. \
         The u8 0-4 band is the public severity scale; \
         apps that match on it break.",
    );

    // Verify the five-band thresholds (0.875 / 0.625 /
    // 0.375 / 0.125) — these MUST mirror the runtime's
    // resource-monitor cuts to maintain the
    // SystemPressure-as-public-pressure-signal contract.
    let source_str = read("src/types/pressure.rs");
    assert!(
        source_str.contains("> 0.875")
            && source_str.contains("> 0.625")
            && source_str.contains("> 0.375")
            && source_str.contains("> 0.125"),
        "REGRESSION: degradation_level thresholds (0.875 / \
         0.625 / 0.375 / 0.125) changed. These cuts must \
         match runtime::resource_monitor::DegradationLevel \
         to maintain the pressure-clone contract. Drifting \
         them silently changes the public severity signal.",
    );
}

#[test]
fn region_limits_max_tasks_provides_hard_admission_cap() {
    // Pin (link 5): RegionLimits has max_tasks: Option<usize>
    // for hard per-region admission caps. Without it, apps
    // can't bound per-region task fan-out.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("pub max_tasks: Option<usize>,"),
        "REGRESSION: RegionLimits.max_tasks field is gone. \
         Apps lose the hard per-region admission cap — \
         spawn-and-pray for per-region sizing.",
    );

    // RegionLimits::unlimited() exists for opt-out.
    assert!(
        source.contains("max_tasks: None,"),
        "REGRESSION: RegionLimits::unlimited() no longer \
         sets max_tasks: None. Apps that opt out of caps \
         lose the documented escape hatch.",
    );
}

#[test]
fn spawn_error_includes_region_at_capacity_variant_for_typed_backpressure() {
    // Pin (link 12): SpawnError has RegionAtCapacity variant
    // carrying region/limit/live for actionable error
    // information. Without typed errors, apps would parse
    // strings.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("RegionAtCapacity {")
            && source.contains("limit,")
            && source.contains("live,"),
        "REGRESSION: SpawnError::RegionAtCapacity variant or \
         its limit/live fields are gone. Apps lose the \
         typed backpressure error and must parse string \
         representations — fragile.",
    );

    // RegionClosed variant exists for closed-region error.
    assert!(
        source.contains("RegionClosed("),
        "REGRESSION: SpawnError::RegionClosed variant is \
         gone. Apps can't distinguish 'no capacity' from \
         'region not accepting work' — different actions \
         (retry vs abandon) get conflated.",
    );
}

#[test]
fn spawn_returns_result_for_graceful_backpressure_handling() {
    // Pin (link 12): Scope::spawn returns Result<...,
    // SpawnError>. Without Result, apps would have no path
    // to gracefully handle capacity exhaustion.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("Result<(TaskHandle<Fut::Output>, StoredTask), SpawnError>"),
        "REGRESSION: Scope::spawn return type changed from \
         Result. Apps that expect to handle capacity errors \
         break — and a panicking spawn destroys the \
         graceful-degradation contract.",
    );
}

#[test]
fn region_record_task_count_returns_current_usage_for_capacity_query() {
    // Pin (link 7): RegionRecord::task_count() returns
    // usize without cloning. Combined with max_tasks, lets
    // apps compute remaining capacity = limit - current.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("pub fn task_count(&self) -> usize {"),
        "REGRESSION: RegionRecord::task_count signature \
         changed or removed. Apps can no longer query \
         per-region usage — 'can I spawn N more?' check \
         degrades.",
    );
}

#[test]
fn runtime_state_region_limits_provides_per_region_cap_query() {
    // Pin (link 8): RuntimeState::region_limits(region)
    // returns Option<RegionLimits>. Apps pair this with
    // task_count to compute remaining capacity.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn region_limits(&self, region: RegionId) -> Option<RegionLimits> {"),
        "REGRESSION: RuntimeState::region_limits signature \
         changed. Apps can no longer query the current \
         RegionLimits — 'can I spawn N more?' check breaks.",
    );
}

#[test]
fn runtime_state_live_task_count_provides_global_capacity_query() {
    // Pin (link 9): RuntimeState::live_task_count returns
    // global task count across all regions. Useful for
    // global backpressure decisions.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn live_task_count(&self) -> usize {"),
        "REGRESSION: RuntimeState::live_task_count signature \
         changed. Apps can no longer query global task \
         count — global backpressure decisions break.",
    );
}

#[test]
fn check_resource_pressure_enforces_admission_at_create_child_region() {
    // Pin (link 10): create_child_region calls
    // check_resource_pressure_for_region BEFORE creating
    // the region. This is the runtime-side enforcement
    // that backpressure is checked at admission, not
    // after the fact.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn create_child_region(";
    let start = source.find(fn_marker).expect("create_child_region fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("create_child_region close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.check_resource_pressure_for_region("),
        "REGRESSION: create_child_region no longer calls \
         check_resource_pressure_for_region. Backpressure \
         enforcement happens AFTER region creation — \
         pathway for unbounded region fan-out under \
         resource pressure.",
    );
}

#[test]
fn region_state_can_spawn_predicate_gates_at_state_level() {
    // Pin (link 11): RegionState::can_spawn returns true
    // ONLY for Open. Closing / Draining / Finalizing /
    // Closed regions reject spawns at the structural
    // level — independent of capacity.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("pub const fn can_spawn(self) -> bool {"),
        "REGRESSION: RegionState::can_spawn predicate is \
         gone. The structural-state gate that prevents \
         spawning in Closing/Draining regions is lost — \
         pathway for spawning into a region that's \
         already closing.",
    );
}

#[test]
fn region_create_error_carries_resource_pressure_variant() {
    // Pin (link 6+10): RegionCreateError (defined in
    // src/runtime/region_table.rs) has a ResourcePressure
    // variant so apps can distinguish capacity errors from
    // runtime-pressure errors.
    let source = read("src/runtime/region_table.rs");

    assert!(
        source.contains("pub enum RegionCreateError {"),
        "REGRESSION: RegionCreateError enum is gone or moved \
         from src/runtime/region_table.rs. The typed \
         creation-error contract is lost.",
    );

    assert!(
        source.contains("ResourcePressure {"),
        "REGRESSION: RegionCreateError::ResourcePressure \
         variant is gone. Apps can't distinguish \
         capacity-cap rejection from runtime-pressure \
         rejection — different mitigations conflated.",
    );

    assert!(
        source.contains("ParentAtCapacity {"),
        "REGRESSION: RegionCreateError::ParentAtCapacity \
         variant is gone. Apps lose the typed parent-cap \
         error.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_spawn_during_cancellation_audit.rs",
        "tests/scheduler_spawn_send_bounds_compile_time_audit.rs",
        "tests/cx_spawn_local_vs_spawn_distinction_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
