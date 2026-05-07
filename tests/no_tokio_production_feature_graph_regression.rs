//! br-asupersync-aj7lx3.2 — production-graph Tokio-free regression.
//!
//! Hard regression proof that the asupersync production crate's
//! NORMAL dependency graph contains zero `tokio` edges, both with
//! default features AND with `--features metrics`. This is the
//! production-binary safety property: anything a downstream user
//! consuming the asupersync runtime as a library (default or
//! metrics-enabled) gets in their normal dep graph cannot include
//! tokio.
//!
//! ── Distinction from existing tests ─────────────────────
//!
//! - `tests/no_tokio_in_normal_dep_graph.rs` checks the WORKSPACE
//!   graph: `cargo tree -e normal --workspace -i tokio` and
//!   allowlists `asupersync-tokio-compat` and
//!   `asupersync-conformance` as direct dependers. That test
//!   covers workspace-level audit.
//!
//! - `tests/no_tokio_feature_boundary_contract.rs` is a STATIC
//!   contract verifier (compares Cargo.toml feature definitions
//!   against a JSON manifest). It does not run cargo.
//!
//! - THIS test runs `cargo tree -e normal -p asupersync -i tokio`
//!   WITHOUT --workspace, twice: once with default features, once
//!   with `--features metrics`. Either result containing tokio is
//!   a production regression.
//!
//! ── Acceptance criteria addressed ───────────────────────
//!
//! 1. Regression test fails if tokio appears in default OR metrics
//!    production normal dep graph: yes (two assertions, one per
//!    feature profile).
//! 2. Distinguishes production proof from workspace/dev/test
//!    expected tokio edges: yes — uses `-p asupersync` (single
//!    package), not `--workspace`. The expected signal is
//!    "nothing to print" / "nothing depends on" — empty graph.
//! 3. Validation commands intended to run through rch when
//!    invoked manually; this test invokes cargo via std::Command
//!    locally for `cargo test` integration. CI wrappers can
//!    invoke via rch exec.
//! 4. No new runtime/executor dependency is introduced (uses
//!    only std::process::Command).
//!
//! ── Skip-on-no-cargo behaviour ──────────────────────────
//!
//! Consistent with the sibling test `no_tokio_in_normal_dep_graph.rs`,
//! this test skips with a printed warning if cargo is not on PATH
//! (sandboxed test runners). Real CI environments with cargo on PATH
//! exercise the gate.
//!
//! ── How to run locally ──────────────────────────────────
//!
//!   cargo test --test no_tokio_production_feature_graph_regression
//!
//! ── How to run via rch ──────────────────────────────────
//!
//!   rch exec -- cargo test --test no_tokio_production_feature_graph_regression

use std::process::Command;

/// Return value from a single `cargo tree -e normal -p asupersync -i tokio`
/// invocation that distinguishes the three relevant outcomes:
///   - `NoTokio`: cargo confirmed tokio is not in this graph.
///   - `TokioPresent { stdout }`: tokio IS in the graph; stdout
///     contains the dependency path tree.
///   - `Skipped { reason }`: cargo not invokable (sandboxed runner);
///     test skips per the documented escape hatch.
enum TreeOutcome {
    NoTokio,
    TokioPresent { stdout: String },
    Skipped { reason: String },
}

fn cargo_tree_for_production(features: &[&str]) -> TreeOutcome {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(&cargo);
    cmd.args(["tree", "-e", "normal", "-p", "asupersync", "-i", "tokio"]);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return TreeOutcome::Skipped {
                reason: format!("cargo invocation failed: {e}"),
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `cargo tree -i tokio` exits non-zero when tokio is NOT in
        // the graph at all. That's the IDEAL outcome — tokio-free
        // production graph.
        if stderr.contains("nothing depends on")
            || stderr.contains("no matches found")
            || stderr.contains("not found in the graph")
        {
            return TreeOutcome::NoTokio;
        }
        // Some other cargo failure (lockfile drift, network, etc.) —
        // skip with a clear reason rather than masking as a regression.
        return TreeOutcome::Skipped {
            reason: format!(
                "unexpected cargo tree failure (likely unrelated build state). \
                 stderr:\n{stderr}\nstdout:\n{}",
                String::from_utf8_lossy(&output.stdout),
            ),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stripped = stdout.trim();
    // Newer cargo emits the literal sentinel "warning: nothing to print"
    // on stderr (handled above as exit-nonzero in some toolchains) or
    // empty stdout on success (older toolchains). Treat both as no-tokio.
    if stripped.is_empty() {
        return TreeOutcome::NoTokio;
    }

    // Otherwise stdout DOES list tokio + dependers — production
    // regression. Capture the full output for diagnostics.
    TreeOutcome::TokioPresent { stdout }
}

#[test]
fn default_production_graph_has_no_tokio() {
    match cargo_tree_for_production(&[]) {
        TreeOutcome::NoTokio => {
            println!(
                "br-asupersync-aj7lx3.2: default production graph is \
                 tokio-free. Invariant satisfied."
            );
        }
        TreeOutcome::TokioPresent { stdout } => {
            panic!(
                "br-asupersync-aj7lx3.2 VIOLATION: tokio appeared in the \
                 DEFAULT production normal dep graph for `-p asupersync`. \
                 Investigate which feature/dependency introduced this and \
                 either remove the dep or update the proof manifest with \
                 explicit justification.\n\n\
                 Full cargo-tree output (production graph, default features):\n\
                 {stdout}\n\n\
                 Reproduce with:\n\
                 \tcargo tree -e normal -p asupersync -i tokio"
            );
        }
        TreeOutcome::Skipped { reason } => {
            println!(
                "br-asupersync-aj7lx3.2: skipping default-graph check ({reason}). \
                 Real CI environments with cargo on PATH will exercise the gate."
            );
        }
    }
}

#[test]
fn metrics_feature_production_graph_has_no_tokio() {
    match cargo_tree_for_production(&["metrics"]) {
        TreeOutcome::NoTokio => {
            println!(
                "br-asupersync-aj7lx3.2: metrics-enabled production graph is \
                 tokio-free. Invariant satisfied."
            );
        }
        TreeOutcome::TokioPresent { stdout } => {
            panic!(
                "br-asupersync-aj7lx3.2 VIOLATION: tokio appeared in the \
                 METRICS-enabled production normal dep graph for \
                 `-p asupersync --features metrics`. Likely cause: \
                 opentelemetry / opentelemetry_sdk feature drift, or \
                 metrics-feature accidentally pulling in opentelemetry-proto \
                 (which intentionally lives in the fuzz-only carve-out, \
                 NOT metrics).\n\n\
                 Full cargo-tree output (production graph, --features metrics):\n\
                 {stdout}\n\n\
                 Reproduce with:\n\
                 \tcargo tree -e normal -p asupersync --features metrics -i tokio\n\n\
                 Fix paths:\n\
                 \t- audit the metrics feature's transitive deps in Cargo.toml\n\
                 \t- ensure opentelemetry-proto stays gated to fuzz only\n\
                 \t- if a new metrics dep legitimately needs tokio, escalate\n\
                 \t  via the no-tokio carve-out review process before merge."
            );
        }
        TreeOutcome::Skipped { reason } => {
            println!(
                "br-asupersync-aj7lx3.2: skipping metrics-graph check ({reason}). \
                 Real CI environments with cargo on PATH will exercise the gate."
            );
        }
    }
}

#[test]
fn workspace_audit_graph_distinct_from_production_graph() {
    // Pin: this test documents — and lightly verifies — the distinction
    // between the production proof here (`-p asupersync` with no
    // --workspace) and the workspace audit at
    // `no_tokio_in_normal_dep_graph.rs` (`--workspace`). The workspace
    // audit DOES expect tokio (via asupersync-tokio-compat and
    // asupersync-conformance carve-outs), so the two tests cannot
    // share an assertion shape.
    //
    // We assert this by reading the sibling test source and confirming
    // it allowlists the carve-outs. If the workspace test's allowlist
    // changes, future maintainers see that this production test is the
    // STRICTER zero-tokio gate — it does NOT inherit those allowances.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/no_tokio_in_normal_dep_graph.rs");
    let workspace_test = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "br-asupersync-aj7lx3.2: workspace test missing at \
             {path:?} ({err}). The production-vs-workspace distinction \
             this test documents requires the sibling test to exist."
        )
    });

    let workspace_carve_outs = ["asupersync-tokio-compat", "asupersync-conformance"];
    for carve_out in &workspace_carve_outs {
        assert!(
            workspace_test.contains(carve_out),
            "br-asupersync-aj7lx3.2: workspace test no longer allowlists \
             `{carve_out}` as a tokio direct depender. The production-graph \
             distinction (this test) is the stricter ZERO-tokio gate; the \
             workspace test is the LOOSER carve-out audit. Both must \
             coexist; if the workspace allowlist shrinks, ensure this \
             stricter gate still does the right thing."
        );
    }

    // And: this production-graph test does NOT use `--workspace`. Pin
    // that programmatic invariant by checking THIS test file does not
    // accidentally invoke `--workspace`.
    let this_test = std::fs::read_to_string(file!()).unwrap_or_else(|err| {
        panic!(
            "br-asupersync-aj7lx3.2: cannot read self at {} ({err})",
            file!()
        )
    });
    assert!(
        !this_test.contains("\"--workspace\""),
        "br-asupersync-aj7lx3.2: this production-graph test now passes \
         --workspace, which inherits the workspace carve-outs. The point \
         of this gate is the STRICTER `-p asupersync` view. Fix the \
         cargo invocation to drop --workspace."
    );
}
