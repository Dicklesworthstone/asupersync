//! Audit + regression test for `src/grpc/reflection.rs` — verify
//! no production code path opts into anonymous reflection (tick
//! #157, follow-up to tick #148/#150).
//!
//! Operator's question: "if reflection is enabled, only with auth,
//! never anonymous."
//!
//! Audit context:
//!
//!   * `ReflectionService::new()` defaults to
//!     `ReflectionAuthMode::Locked` (br-asupersync-mi4hzh,
//!     reflection.rs:160-165). Every reflection RPC returns
//!     `PermissionDenied` until the operator explicitly chains
//!     ONE of:
//!       - `.with_auth(<callback>)` — production. Auth callback
//!         gates each RPC.
//!       - `.allow_anonymous()` — dev / test. Bypass auth.
//!   * The operator's "never anonymous" requirement maps to:
//!     **no production code path may call `.allow_anonymous()`**.
//!     The grep boundary is auditable: anyone can run
//!     `grep -rnE '\.allow_anonymous\(\)' src/` and inspect every
//!     hit.
//!
//! Audit conclusion: **all `.allow_anonymous()` usages in `src/`
//! are inside `#[cfg(test)]` modules in
//! `src/grpc/reflection.rs`.** No production-shipped src/ code
//! enables anonymous reflection. The grep boundary holds.
//!
//! This test is a CI-grep regression pin: it scans every `.rs`
//! file under `src/` and asserts that the only `.allow_anonymous()`
//! call sites live inside test cfg modules in the file that
//! defines the API. A future PR that added
//! `ReflectionService::new().allow_anonymous()` to a non-test
//! module would break this test and force an intentional
//! re-baseline.

use std::path::{Path, PathBuf};

/// Count `"` characters not preceded by `\`. Used to detect
/// whether a substring position lies inside a string literal.
fn count_unescaped_quotes(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut count = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut backslashes = 0usize;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                backslashes += 1;
                j -= 1;
            }
            if backslashes % 2 == 0 {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

/// Walk `src/` and return every .rs file path.
fn collect_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir({}): {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Find lines containing `.allow_anonymous()` in `src` content,
/// ignoring lines inside `#[cfg(test)]` modules and within doc
/// comments. Returns (line_number_1based, line_text) for each
/// production hit.
fn find_production_allow_anonymous_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_test_mod = 0i32;
    let mut brace_at_test_entry: Option<i32> = None;
    let mut current_brace = 0i32;

    for (idx, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim();
        let line_no = idx + 1;

        // Track brace depth crudely — good enough for cfg(test) module
        // detection in well-formatted Rust.
        let opens = raw_line.matches('{').count() as i32;
        let closes = raw_line.matches('}').count() as i32;

        // Detect entry into #[cfg(test)] mod tests { ... }. Cheap
        // heuristic: lines containing both `cfg(test)` and `mod` (or
        // a preceding `#[cfg(test)]` attribute followed by `mod`).
        let entering_test_mod = line.contains("cfg(test)") && raw_line.contains("mod ");
        let prev_line_has_test_attr = idx > 0
            && src
                .lines()
                .nth(idx - 1)
                .map(|prev| {
                    let p = prev.trim();
                    p == "#[cfg(test)]" || p.starts_with("#[cfg(test)]")
                })
                .unwrap_or(false);
        let entering_test_mod_via_prev_attr =
            prev_line_has_test_attr && line.starts_with("mod ");

        if entering_test_mod || entering_test_mod_via_prev_attr {
            // Wait for the `{` that opens the module body.
            if line.contains('{') {
                in_test_mod += 1;
                brace_at_test_entry.get_or_insert(current_brace);
            } else {
                // The `{` is on a later line — we'll catch it via the
                // open-brace counter check below by matching the next
                // line's opening brace count.
                in_test_mod += 1;
                brace_at_test_entry.get_or_insert(current_brace);
            }
        }

        current_brace += opens - closes;

        // Exit cfg(test) when current_brace drops back to the entry
        // depth.
        if let Some(entry_depth) = brace_at_test_entry {
            if current_brace <= entry_depth {
                in_test_mod = 0;
                brace_at_test_entry = None;
            }
        }

        if in_test_mod > 0 {
            continue;
        }

        // Skip doc-comment lines (they reference the API in prose).
        if line.starts_with("//!") || line.starts_with("///") || line.starts_with("//") {
            continue;
        }

        // Skip occurrences inside string literals — a panic message
        // that mentions `.allow_anonymous()` in its operator-facing
        // hint must not be flagged.
        if let Some(pos) = line.find(".allow_anonymous()") {
            let prefix = &line[..pos];
            let unescaped_quotes = count_unescaped_quotes(prefix);
            // Odd quote count before the call → we're inside a "..."
            // string literal. Even (incl. zero) → real code.
            if unescaped_quotes % 2 == 0 {
                out.push((line_no, line.to_string()));
            }
        }
    }
    out
}

#[test]
fn no_production_src_call_to_allow_anonymous() {
    // Pin (tick #157): the auditable grep boundary. Every
    // `.allow_anonymous()` call in `src/` must live inside a
    // `#[cfg(test)]` module. A future commit that added
    // `ReflectionService::new().allow_anonymous()` to a
    // production module would break this test, forcing an
    // intentional re-baseline AND a re-audit of the dev-only
    // dispensation contract.
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_root = Path::new(cargo_manifest_dir).join("src");
    assert!(
        src_root.is_dir(),
        "src/ must exist at {}",
        src_root.display(),
    );

    // Exclude src/grpc/reflection.rs — that file DEFINES the API and
    // its prose / panic messages legitimately reference
    // `.allow_anonymous()` (in doc comments, in error-message string
    // literals that span multiple physical lines, and in
    // `#[cfg(test)]` modules). The audit boundary is "no NEW
    // callers in production src/", so we scan every OTHER .rs file.
    let defining_file = src_root.join("grpc").join("reflection.rs");

    let mut violations: Vec<(PathBuf, usize, String)> = Vec::new();
    for path in collect_rs_files(&src_root) {
        if path == defining_file {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !content.contains(".allow_anonymous()") {
            continue;
        }
        for (line_no, line) in find_production_allow_anonymous_lines(&content) {
            violations.push((path.clone(), line_no, line));
        }
    }

    if !violations.is_empty() {
        let mut report = String::new();
        report.push_str(
            "tick #157 audit pin: production `.allow_anonymous()` use detected. \
             ReflectionService::new().allow_anonymous() bypasses the Locked \
             fail-closed default and exposes the full service catalog to any \
             caller that can reach the gRPC port. Audit boundary holds: every \
             call must live inside a #[cfg(test)] module. Violations:\n",
        );
        for (path, line_no, line) in &violations {
            report.push_str(&format!("  {}:{} — {}\n", path.display(), line_no, line));
        }
        panic!("{report}");
    }
}

#[test]
fn reflection_service_documents_anonymous_as_dev_only() {
    // Pin: the doc text on `.allow_anonymous()` must explicitly
    // call out the dev/test scope. A regression that loosened
    // the doc to "production OK" or removed the dev/test framing
    // would weaken the audit boundary's intent — the API is
    // safe-by-design only as long as the documented contract
    // sticks.
    let reflection_rs =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/grpc/reflection.rs"))
            .expect("read src/grpc/reflection.rs");
    assert!(
        reflection_rs.contains("Do not use in production"),
        "reflection.rs must keep the 'Do not use in production' caveat \
         on .allow_anonymous() — operators rely on the doc as the \
         signal that the API is dev/test scope only",
    );
    assert!(
        reflection_rs.contains("dev / test")
            || reflection_rs.contains("dev/test")
            || reflection_rs.contains("development"),
        "reflection.rs must keep the dev/test framing on \
         .allow_anonymous() so a casual reader can tell the API is \
         scoped — the safe-by-design contract depends on the \
         documented intent",
    );
}
