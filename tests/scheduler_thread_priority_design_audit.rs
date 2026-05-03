//! Audit + regression test for thread-priority configuration
//! and Linux SCHED_FIFO real-time scheduling.
//!
//! Operator's question: "when configured for real-time
//! priority, do we attempt SCHED_FIFO (correct: deadline-
//! bounded) and fall back gracefully if not permitted?"
//!
//! Audit findings:
//!
//!   asupersync **DELIBERATELY DOES NOT use OS-level
//!   real-time scheduling**. There is no SCHED_FIFO,
//!   sched_setscheduler, setpriority, or nice-value
//!   manipulation anywhere in src/. Worker threads spawn
//!   via plain `std::thread::Builder::new().name(...).
//!   stack_size(...).spawn(...)` (runtime/builder.rs:333)
//!   at OS-default priority. This is **SOUND BY DESIGN**
//!   for six concrete reasons:
//!
//!   1. **Cross-platform**: SCHED_FIFO is Linux-specific.
//!      asupersync supports Linux + macOS + Windows + WASM.
//!      A Linux-RT-only deadline mechanism would silently
//!      degrade on other platforms — and the deadline-aware
//!      contract must hold on every platform.
//!
//!   2. **Permission requirements**: SCHED_FIFO requires
//!      `CAP_SYS_NICE` or root. Standard server / container
//!      / CI deployments do NOT grant these by default. A
//!      runtime that depended on SCHED_FIFO would need
//!      either fallback paths (defeating the bound) or
//!      hard-fail at startup (defeating portability).
//!
//!   3. **`#![deny(unsafe_code)]` discipline** (per AGENTS.md):
//!      `libc::sched_setscheduler` requires `unsafe`. Adding
//!      it would require a per-function `#[allow(unsafe_code)]`
//!      and a documented carve-out — the project's audit
//!      record (audit_index.jsonl) shows zero unsafe code in
//!      the runtime/scheduler/ tree, by deliberate choice.
//!
//!   4. **System-stability hazard**: A SCHED_FIFO thread
//!      that spins (e.g., a tight checkpoint loop — see
//!      tests/scheduler_checkpoint_tight_loop_dos_audit.rs)
//!      starves ALL other processes on the system, including
//!      init/systemd/the kernel's own watchdog. asupersync's
//!      cooperative-yield contract becomes a load-bearing
//!      kernel-stability invariant under SCHED_FIFO — a
//!      bug that previously surfaced as a slow task becomes
//!      an OS hang.
//!
//!   5. **Deadline-aware behavior is achieved cooperatively**:
//!      asupersync's deadline guarantees come from FIVE
//!      MECHANISMS already audited and pinned:
//!        a. Cooperative budget (poll_quota / cost_quota /
//!           deadline) — bounds task runtime.
//!        b. Lyapunov governor — anticipates deadline
//!           pressure and switches to MeetDeadlines
//!           SchedulingSuggestion.
//!        c. EDF lane priority — Timed > Cancel > Ready
//!           under MeetDeadlines (three_lane.rs:3401).
//!        d. Multi-worker dispatch — free workers pick up
//!           EDF tasks in parallel.
//!        e. timed_fairness_limit — bounded EDF-vs-FIFO
//!           interleaving even under sustained pressure.
//!      None of these depend on OS thread priority.
//!
//!   6. **User extension point exists**: if a specific
//!      deployment wants OS-level RT priority, the runtime
//!      provides `RuntimeBuilder::on_thread_start(|| { ... })`
//!      (runtime/builder.rs:2446). User code can call
//!      `libc::sched_setscheduler` from this callback —
//!      with their own `#[allow(unsafe_code)]` and their
//!      own privilege management. asupersync neither
//!      requires nor blocks the choice.
//!
//! Verdict: **SOUND BY DESIGN**. The framing of the
//! operator's question contains a category error: asupersync's
//! deadline-aware spec does NOT depend on OS RT scheduling.
//! Pinning a SCHED_FIFO attempt would actually be a
//! REGRESSION — it would (a) only work on Linux, (b)
//! require unprivileged-fallback complexity, (c) introduce
//! unsafe code, (d) create system-stability hazards.
//!
//! What the audit DOES pin:
//!   - No OS RT scheduling code anywhere in src/ (forbid
//!     a regression that adds SCHED_FIFO without explicit
//!     design discussion).
//!   - Worker threads spawn via plain
//!     std::thread::Builder with no priority manipulation.
//!   - The on_thread_start / on_thread_stop callbacks
//!     exist as the user-extension point for those who
//!     genuinely need OS RT priority.
//!   - Cross-references to the cooperative-deadline-mechanism
//!     audits that DO carry the deadline-aware contract.
//!
//! A regression that:
//!   - added a `with_realtime_priority(SchedFifo)` method
//!     to RuntimeBuilder that called libc::sched_setscheduler
//!     (would introduce unsafe code, OS-stability hazards,
//!     and cross-platform divergence — needs explicit
//!     design discussion before merge),
//!   - added a default-on SCHED_FIFO attempt at startup
//!     (would hard-fail under unprivileged deployments — a
//!     widely-deployed app would break for many users),
//!   - removed the on_thread_start callback (would lose
//!     the user-extension point — users who genuinely need
//!     OS RT priority lose the opt-in mechanism),
//!   - replaced the std::thread::Builder.spawn with a
//!     SchedPolicy-aware spawn that silently swallowed
//!     errors (would mask permission failures and produce
//!     confusing behavior — RT was requested but not
//!     applied),
//! would all be caught by the structural pins below.

use std::ffi::OsStr;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn collect_rs_files(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension() == Some(OsStr::new("rs")) {
            out.push(path);
        }
    }
}

#[test]
fn no_sched_setscheduler_or_sched_fifo_anywhere_in_src() {
    // Pin (link 1+2+3+4): there must be no OS RT scheduling
    // call anywhere in src/. The deadline-aware contract is
    // cooperative — adding OS RT would conflict with the
    // design's portability, security, and stability goals.
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);

    let suspect_os_rt = [
        "sched_setscheduler",
        "SCHED_FIFO",
        "SCHED_RR",
        "sched_setattr",
        "pthread_setschedparam",
        "SetThreadPriority(",
    ];

    let mut findings = Vec::new();
    for path in files {
        let path_str = path.display().to_string();
        // Skip test code (the `tests/` directory may legitimately mention
        // these patterns in audit assertions like this one).
        if path_str.contains("/tests/")
            || path_str.contains("_tests.rs")
            || path_str.contains("/test_")
            || path_str.contains("_audit.rs")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pat in &suspect_os_rt {
            if content.contains(pat) {
                for (line_no, line) in content.lines().enumerate() {
                    if line.contains(pat) {
                        let trimmed = line.trim_start();
                        // Skip comments / docstrings.
                        if trimmed.starts_with("//")
                            || trimmed.starts_with("///")
                            || trimmed.starts_with("//!")
                        {
                            continue;
                        }
                        findings.push(format!(
                            "{path_str}:{line_no}: pattern `{pat}` — {line}",
                            line_no = line_no + 1,
                        ));
                    }
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: src/ now contains OS RT scheduling \
         calls. asupersync's deadline-aware contract is \
         cooperative; adding SCHED_FIFO / sched_setscheduler \
         would introduce cross-platform divergence, require \
         unsafe code (violating #![deny(unsafe_code)]), and \
         create OS-stability hazards. If RT is genuinely \
         needed, route it through RuntimeBuilder::\
         on_thread_start so users opt in explicitly. \
         Findings:\n  {findings}",
        findings = findings.join("\n  "),
    );
}

#[test]
fn no_setpriority_or_nice_value_calls_in_src() {
    // Pin: also forbid the lower-impact setpriority / nice
    // calls. Even SCHED_OTHER nice-value tweaks require
    // CAP_SYS_NICE for negative values — and silently change
    // behavior for users on non-Linux platforms.
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);

    let suspect_nice = [
        "libc::setpriority(",
        "libc::PRIO_PROCESS",
        "libc::PRIO_PGRP",
        "nix::sys::resource::setpriority",
    ];

    let mut findings = Vec::new();
    for path in files {
        let path_str = path.display().to_string();
        if path_str.contains("/tests/")
            || path_str.contains("_tests.rs")
            || path_str.contains("/test_")
            || path_str.contains("_audit.rs")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pat in &suspect_nice {
            if content.contains(pat) {
                findings.push(format!("{path_str}: pattern `{pat}`"));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: src/ now contains setpriority/nice \
         calls. The deadline-aware contract is cooperative \
         — even SCHED_OTHER nice tweaks add OS-coupling \
         that breaks cross-platform parity. Route through \
         on_thread_start. Findings:\n  {findings}",
        findings = findings.join("\n  "),
    );
}

#[test]
fn worker_threads_spawn_via_plain_std_thread_builder() {
    // Pin (link 4+6): the worker spawn site uses plain
    // std::thread::Builder with .name() and .stack_size()
    // only. No priority-setting wrapper.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("let mut builder = std::thread::Builder::new().name(name);"),
        "REGRESSION: worker spawn no longer uses plain \
         std::thread::Builder::new().name(name). If a \
         priority-setting wrapper has been added, it must be \
         documented and tested per the design discussion.",
    );

    // Forbid threading-with-priority crates.
    let suspect_priority_crates = [
        "thread_priority::",
        "ThreadPriority::",
        "thread_priority::set_current_thread_priority",
    ];
    for pat in &suspect_priority_crates {
        assert!(
            !source.contains(pat),
            "REGRESSION: builder.rs now uses a thread-priority \
             crate (`{pat}`). Routing through on_thread_start \
             keeps the runtime portable; baking it into \
             builder couples the runtime to a specific OS RT \
             behavior.",
        );
    }
}

#[test]
fn on_thread_start_callback_exists_as_user_extension_point() {
    // Pin (link 6): RuntimeBuilder::on_thread_start exists
    // as the documented extension point for users who need
    // OS RT priority. Removing it would lose the only
    // legitimate path for users to opt into RT scheduling
    // themselves.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn on_thread_start<F>(mut self, f: F) -> Self"),
        "REGRESSION: RuntimeBuilder::on_thread_start callback \
         is gone. Users who genuinely need OS RT priority \
         have lost their opt-in mechanism — and can no \
         longer call libc::sched_setscheduler from the \
         worker thread under their own privilege management.",
    );

    // The Send + Sync + 'static bounds make the callback
    // safe to invoke on every worker.
    assert!(
        source.contains("F: Fn() + Send + Sync + 'static,"),
        "REGRESSION: on_thread_start callback bounds changed. \
         Without Send + Sync + 'static, the callback can't \
         be invoked from every worker thread.",
    );

    // The callback IS invoked at worker start (not just
    // declared).
    assert!(
        source.contains("if let Some(callback) = on_start.as_ref() {")
            && source.contains("callback();"),
        "REGRESSION: on_thread_start callback is no longer \
         invoked at worker startup. The extension point is \
         silently dead — users who set the callback see no \
         effect.",
    );
}

#[test]
fn on_thread_stop_callback_exists_for_lifecycle_symmetry() {
    // Pin (audit hygiene): on_thread_stop is the symmetric
    // teardown extension point. Without it, users who
    // applied OS RT priority via on_thread_start cannot
    // restore default priority on worker exit — leading to
    // priority-leak warnings on some kernels.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("pub fn on_thread_stop<F>(mut self, f: F) -> Self"),
        "REGRESSION: RuntimeBuilder::on_thread_stop callback \
         is gone. Users can't pair their on_thread_start \
         priority change with a teardown — asymmetric \
         lifecycle hooks.",
    );

    assert!(
        source.contains("if let Some(callback) = on_stop.as_ref() {"),
        "REGRESSION: on_thread_stop callback is no longer \
         invoked on worker exit. The teardown extension is \
         silently dead.",
    );
}

#[test]
fn no_unsafe_code_in_runtime_scheduler_tree() {
    // Pin (link 3): the runtime/scheduler/ subtree has no
    // #[allow(unsafe_code)] declarations. SCHED_FIFO would
    // require one — ensuring the carve-out is absent is
    // the clearest signal that the design intent holds.
    let scheduler_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/runtime/scheduler");
    let mut files = Vec::new();
    collect_rs_files(&scheduler_dir, &mut files);

    let mut findings = Vec::new();
    for path in files {
        let path_str = path.display().to_string();
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Look for #[allow(unsafe_code)] OR #![allow(unsafe_code)].
        if content.contains("#[allow(unsafe_code)]")
            || content.contains("#![allow(unsafe_code)]")
        {
            findings.push(path_str);
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: runtime/scheduler/ subtree now contains \
         #[allow(unsafe_code)]. SCHED_FIFO / sched_setscheduler \
         require unsafe code — adding such a carve-out \
         signals a deviation from the cooperative-only \
         design intent. Files: {findings:?}",
    );
}

#[test]
fn deadline_aware_mechanisms_are_cooperative_not_os_rt() {
    // Pin (link 5): cross-reference the cooperative
    // deadline-aware mechanism audits. These are what
    // actually carry the deadline-aware contract — not OS
    // RT scheduling.
    let cooperative_audits = [
        ("tests/scheduler_three_lane_edf_vs_fifo_deadline_pressure_audit.rs",
         "Lyapunov governor + MeetDeadlines + EDF lane priority"),
        ("tests/runtime_budget_carry_forward_across_yields_audit.rs",
         "cooperative budget carry-forward"),
        ("tests/scheduler_edf_concurrent_insert_heap_invariant_audit.rs",
         "EDF heap correctness"),
        ("tests/scheduler_cooperative_budget_yield_audit.rs",
         "cooperative budget yield contract"),
    ];

    for (audit, mechanism) in &cooperative_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: cooperative deadline audit `{audit}` \
             (covering `{mechanism}`) is missing. The \
             deadline-aware contract depends on this \
             mechanism; without the audit, a regression in \
             the cooperative path could be missed and the \
             audit chain that justifies 'no OS RT needed' is \
             incomplete.",
        );
    }
}

#[test]
fn thread_name_prefix_default_is_documented_for_observability() {
    // Pin (audit hygiene): the thread name prefix
    // (`asupersync-worker` by default) gives observers a
    // clear signal in `ps`, `top`, and Linux thread
    // dumps. This is the primary OS-side observability
    // mechanism — replacing OS RT priority diagnostics with
    // semantic thread names.
    let source = read("src/runtime/builder.rs");

    assert!(
        source.contains("\"asupersync-worker\"") || source.contains("asupersync-worker"),
        "REGRESSION: default thread name prefix \
         `asupersync-worker` is gone or changed. OS-side \
         thread observability is the primary mechanism that \
         compensates for not using OS RT scheduling — losing \
         the consistent name makes `ps`/`top` debugging \
         harder.",
    );

    assert!(
        source.contains("pub fn thread_name_prefix(mut self, prefix: impl Into<String>) -> Self"),
        "REGRESSION: thread_name_prefix builder method is \
         gone. Users can no longer customize the thread \
         name — multi-runtime deployments lose the ability \
         to distinguish workers in OS tooling.",
    );
}

#[test]
fn no_default_priority_attempt_in_worker_spawn_path() {
    // Pin (link 2): the worker-spawn path does NOT make a
    // default attempt to elevate priority. Such an attempt
    // would (a) hard-fail under unprivileged deployments,
    // (b) require fallback complexity that defeats the
    // bound. The cooperative deadline mechanisms are the
    // ONLY priority enforcement.
    let source = read("src/runtime/builder.rs");

    let suspect_default_attempts = [
        "set_realtime_priority",
        "try_set_sched_fifo",
        "elevate_priority_if_capable",
        "default_realtime_priority",
    ];
    for pat in &suspect_default_attempts {
        assert!(
            !source.contains(pat),
            "REGRESSION: builder.rs now attempts a default \
             priority elevation (`{pat}`). Even with a \
             fallback, the attempt itself signals a design \
             change toward OS-coupling. If genuinely needed, \
             route through on_thread_start as opt-in.",
        );
    }
}

#[test]
fn cargo_toml_has_no_thread_priority_dependency() {
    // Pin: a regression that added `thread-priority` or
    // similar OS-RT-coupling crates to Cargo.toml would
    // signal an upstream design change toward OS RT.
    let source = read("Cargo.toml");

    let suspect_deps = [
        "thread-priority =",
        "thread_priority =",
        "rt-priority =",
        "sched-priority =",
    ];
    for pat in &suspect_deps {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cargo.toml now depends on `{pat}`. \
             A thread-priority crate dependency signals a \
             design change toward OS RT scheduling — needs \
             explicit discussion. The cooperative deadline \
             mechanisms are sufficient for the deadline-\
             aware contract.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_three_lane_edf_vs_fifo_deadline_pressure_audit.rs",
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
        "tests/scheduler_checkpoint_tight_loop_dos_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
