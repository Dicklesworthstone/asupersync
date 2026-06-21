//! br-asupersync-g7a0a9 invariant gate.
//!
//! Enforces that `tokio` only appears in the asupersync workspace's
//! `cargo tree -e normal` output via the documented carve-outs:
//!
//!   1. `asupersync-tokio-compat` — opt-in tokio compat shim.
//!   2. `asupersync-conformance` — RFC vendor-comparison harness.
//!   3. Protocol/test satellites that are already documented in AGENTS.md's
//!      full-workspace audit carve-out (`h2`, `hyper`, `tonic`,
//!      `tokio-util`, `opentelemetry_sdk`, and related adapters).
//!
//! Any other path through which `tokio` enters the normal-edge dep
//! graph is a regression of the project's "no tokio in the runtime"
//! invariant (AGENTS.md §"Async Runtime: THIS IS IT") and must be
//! either removed or explicitly added to this allowlist.
//!
//! Why this lives in tests/ rather than build.rs:
//!   - The check needs the `cargo` binary at runtime (build.rs runs
//!     before cargo metadata is fully resolved for the workspace).
//!   - Failing as a test means CI surfaces the violation as a normal
//!     test failure rather than a fatal build error.
//!
//! How to run: `cargo test --test no_tokio_in_normal_dep_graph`
//!
//! Skipping in environments without cargo on PATH: the test exits
//! with a `println!` warning rather than failing — this keeps fuzz /
//! sandboxed test runners that strip $PATH from spuriously breaking
//! CI. Real CI runners with cargo on PATH will exercise the gate.

use std::process::Command;

#[test]
fn tokio_only_reaches_workspace_via_documented_carve_outs() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let output = Command::new(&cargo)
        .args(["tree", "-e", "normal", "--workspace", "-i", "tokio"])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            // Cargo not on PATH (sandboxed runner). Don't fail —
            // real CI environments will exercise the gate.
            println!(
                "br-asupersync-g7a0a9: skipping check (cargo invocation \
                 failed: {e}). The gate runs on CI with cargo on PATH."
            );
            return;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `cargo tree -i tokio` exits non-zero when tokio is NOT in
        // the dep graph at all. That's actually the IDEAL outcome —
        // pass the test cleanly.
        if stderr.contains("nothing depends on")
            || stderr.contains("no matches found")
            || stderr.contains("not found in the graph")
        {
            println!(
                "br-asupersync-g7a0a9: tokio is not in the normal-edge \
                 dep graph at all. Invariant fully satisfied."
            );
            return;
        }
        panic!(
            "br-asupersync-g7a0a9: cargo tree failed unexpectedly. \
             stderr:\n{stderr}\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Allow-list of crates that may legitimately depend on tokio
    // DIRECTLY (i.e., have a normal-edge dep on `tokio` in their
    // own Cargo.toml). Transitive consumers of these crates are
    // fine — they're inheriting through the carve-out.
    const ALLOWED_DIRECT_DEPENDERS: &[&str] = &[
        "asupersync-tokio-compat",
        "asupersync-conformance",
        "h2",
        "hyper",
        "hyper-timeout",
        "hyper-util",
        "opentelemetry_sdk",
        "tokio-stream",
        "tokio-util",
        "tonic",
        "tower",
    ];

    // Parse `cargo tree -i tokio` output. The format is:
    //
    //   tokio v1.52.1
    //   ├── direct_depender_1 v...
    //   │   └── transitive ...
    //   └── direct_depender_2 v...
    //
    // Direct dependers are the lines whose tree-art prefix is
    // exactly `├── ` or `└── ` (no preceding `│` columns). Anything
    // with deeper nesting (`│   ├──`, `│   │   └──`, etc.) is a
    // transitive consumer of an already-listed direct depender and
    // is fine — the carve-out covers them.
    let offenders: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            // Direct-child markers: a line that begins with `├── ` or
            // `└── ` followed immediately by the crate name. Lines
            // that have any deeper indentation contain `│` columns
            // before the marker.
            line.starts_with("├── ") || line.starts_with("└── ")
        })
        .filter(|line| {
            // Strip the marker and check against the allow list.
            let crate_part = line.trim_start_matches(['├', '└', '─', ' ']).trim();
            !ALLOWED_DIRECT_DEPENDERS
                .iter()
                .any(|allowed| crate_part.starts_with(allowed))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "br-asupersync-g7a0a9 VIOLATION: tokio reached the normal-edge \
         dep graph through an UNDOCUMENTED direct depender. Allowed \
         direct dependers are {ALLOWED_DIRECT_DEPENDERS:?}. Offending \
         top-level dependers from `cargo tree -e normal --workspace -i \
         tokio`:\n{}\n\nFull cargo tree output:\n{stdout}",
        offenders.join("\n"),
    );
}
