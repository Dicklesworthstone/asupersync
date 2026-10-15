//! Behavioral proof that a lab trace can be exported to TLA+ and model-checked
//! with TLC (br-asupersync-gap-lean-tla-receipts-48ukyp).
//!
//! `LabRunReport::export_tla` had no callers and no exported trace had ever
//! been fed to TLC. This test runs a small deterministic scenario on
//! `LabRuntime`, exports the captured trace as a TLA+ behavior module, writes
//! a TLC configuration that checks the module's three invariants, and runs
//! TLC on it.
//!
//! TLC is Java software. The test looks for the jar in
//! `ASUPERSYNC_TLA2TOOLS_JAR` and `java` in `ASUPERSYNC_JAVA` (default:
//! `java` on `PATH`). Without the jar it prints a skip reason and returns,
//! except under `CI=true`, where a missing TLC is a failure: the CI job that
//! installs Java and the jar must actually run the checker.
//!
//! What green proves:
//! - the export produces a module TLC parses, with `snapshot_count() ==
//!   events + 1` states;
//! - TLC checks `NoObligationLeaks`, `QuiescenceOnClose`, and
//!   `ObligationLinearity` over the concrete behavior and reports
//!   "No error has been found";
//! - planted negative: the same module plus an invariant the recorded
//!   behavior breaks (`PlantedFalse`: no task ever completes) makes TLC
//!   report "Invariant PlantedFalse is violated" and exit nonzero (TLC exit
//!   status 12, safety violation).
//!
//! No-claim: TLC checks the recorded concrete behavior only (one trace); it is
//! not a parametric model check of the runtime.

use std::path::{Path, PathBuf};
use std::process::Command;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::TraceEvent;
use asupersync::types::Budget;

const INVARIANTS: [&str; 3] = [
    "NoObligationLeaks",
    "QuiescenceOnClose",
    "ObligationLinearity",
];

fn tlc_config() -> String {
    let mut cfg = String::from("SPECIFICATION Spec\n");
    for invariant in INVARIANTS {
        cfg.push_str("INVARIANT ");
        cfg.push_str(invariant);
        cfg.push('\n');
    }
    cfg
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "asupersync_tla_tlc_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

struct TlcRun {
    status: std::process::ExitStatus,
    output: String,
}

fn run_tlc(java: &str, jar: &Path, dir: &Path, module: &str) -> TlcRun {
    let out = Command::new(java)
        .current_dir(dir)
        .args(["-XX:+UseSerialGC", "-cp"])
        .arg(jar)
        // `-deadlock` turns off deadlock detection: a recorded behavior is a
        // finite state sequence whose last state has no successor, which TLC
        // would otherwise report as a deadlock (exit status 11).
        .args([
            "tlc2.TLC",
            "-workers",
            "1",
            "-deadlock",
            "-config",
            &format!("{module}.cfg"),
            &format!("{module}.tla"),
        ])
        .output()
        .expect("spawn java for TLC");
    let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(&out.stderr));
    TlcRun {
        status: out.status,
        output,
    }
}

/// A two-task scenario: both tasks yield once, then complete.
fn lab_trace(seed: u64) -> (Vec<TraceEvent>, asupersync::lab::LabRunReport) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    for _ in 0..2 {
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                asupersync::runtime::yield_now().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
    }
    runtime.run_until_quiescent();
    let events: Vec<TraceEvent> = runtime.trace().snapshot();
    let report = runtime.report();
    (events, report)
}

#[test]
fn lab_trace_exports_to_tla_and_tlc_checks_the_invariants() {
    let (events, report) = lab_trace(7);
    assert!(
        events.len() >= 4,
        "two spawned tasks must leave at least spawn/complete events: {}",
        events.len()
    );

    let module = report
        .export_tla(&events, "LabTraceBehavior")
        .expect("non-empty trace exports a module");
    assert_eq!(module.name, "LabTraceBehavior");
    assert!(module.source.contains("Init =="));
    assert!(module.source.contains("Next =="));
    for invariant in INVARIANTS {
        assert!(
            module.source.contains(&format!("{invariant} ==")),
            "module must define {invariant}"
        );
    }
    let exporter = asupersync::trace::tla_export::TlaExporter::from_trace(&events);
    assert_eq!(
        exporter.snapshot_count(),
        events.len() + 1,
        "one state per event plus the initial state"
    );

    let dir = scratch_dir();
    std::fs::write(dir.join("LabTraceBehavior.tla"), &module.source).expect("write module");
    std::fs::write(dir.join("LabTraceBehavior.cfg"), tlc_config()).expect("write cfg");
    eprintln!("exported TLA+ module to {}", dir.display());

    let Some(jar) = std::env::var_os("ASUPERSYNC_TLA2TOOLS_JAR").map(PathBuf::from) else {
        let in_ci = std::env::var("CI").map(|v| v == "true").unwrap_or(false);
        assert!(
            !in_ci,
            "CI=true but ASUPERSYNC_TLA2TOOLS_JAR is unset; the TLC job must install tla2tools.jar"
        );
        eprintln!(
            "SKIP TLC: ASUPERSYNC_TLA2TOOLS_JAR not set (module written to {})",
            dir.display()
        );
        return;
    };
    assert!(
        jar.is_file(),
        "ASUPERSYNC_TLA2TOOLS_JAR must point at tla2tools.jar: {jar:?}"
    );
    let java = std::env::var("ASUPERSYNC_JAVA").unwrap_or_else(|_| "java".to_string());

    let run = run_tlc(&java, &jar, &dir, "LabTraceBehavior");
    assert!(
        run.status.success(),
        "TLC must accept the exported behavior; output:\n{}",
        run.output
    );
    assert!(
        run.output
            .contains("Model checking completed. No error has been found."),
        "TLC must report a clean check; output:\n{}",
        run.output
    );
    assert!(
        run.output.contains("distinct states found"),
        "TLC must report the state count; output:\n{}",
        run.output
    );

    // Planted negative: add an invariant that the recorded behavior really
    // breaks ("no task ever completes"; both tasks complete). TLC must report
    // the violation and exit nonzero, proving invariants are really checked
    // against the recorded states rather than passing vacuously.
    let broken = module
        .source
        .replace(
            "---- MODULE LabTraceBehavior ----",
            "---- MODULE LabTraceBroken ----",
        )
        .replace(
            "\n====\n",
            "\nPlantedFalse == \\A t \\in DOMAIN tasks: tasks[t][1] /= \"Completed\"\n====\n",
        );
    assert_ne!(broken, module.source, "the planted mutation must apply");
    std::fs::write(dir.join("LabTraceBroken.tla"), broken).expect("write broken module");
    std::fs::write(
        dir.join("LabTraceBroken.cfg"),
        format!("{}INVARIANT PlantedFalse\n", tlc_config()),
    )
    .expect("write broken cfg");
    let broken_run = run_tlc(&java, &jar, &dir, "LabTraceBroken");
    assert!(
        !broken_run.status.success(),
        "TLC must fail on the planted invariant violation; output:\n{}",
        broken_run.output
    );
    assert!(
        broken_run
            .output
            .contains("Invariant PlantedFalse is violated"),
        "TLC must name the violated invariant; output:\n{}",
        broken_run.output
    );
}

#[test]
fn empty_trace_exports_no_module_planted_negative() {
    let mut runtime = LabRuntime::new(LabConfig::new(1));
    let report = runtime.report();
    assert!(report.export_tla(&[], "Empty").is_none());
}
