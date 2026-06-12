#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const LEDGER_PATH: &str = "artifacts/unsafe_boundary_ledger_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const LANE_ID: &str = "unsafe-boundary-ledger-contract";
const GUARANTEE_ID: &str = "unsafe-boundary-ledger-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_unsafe_boundary_ledger_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test unsafe_boundary_ledger_contract -- --nocapture";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SiteKind {
    AllowUnsafeCode,
    UnsafeBlock,
    UnsafeFn,
    UnsafeImpl,
    UnsafeTrait,
}

impl SiteKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AllowUnsafeCode => "allow_unsafe_code",
            Self::UnsafeBlock => "unsafe_block",
            Self::UnsafeFn => "unsafe_fn",
            Self::UnsafeImpl => "unsafe_impl",
            Self::UnsafeTrait => "unsafe_trait",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "allow_unsafe_code" => Some(Self::AllowUnsafeCode),
            "unsafe_block" => Some(Self::UnsafeBlock),
            "unsafe_fn" => Some(Self::UnsafeFn),
            "unsafe_impl" => Some(Self::UnsafeImpl),
            "unsafe_trait" => Some(Self::UnsafeTrait),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Locator {
    path: String,
    kind: SiteKind,
    line: usize,
}

#[derive(Clone, Debug)]
struct ScanHit {
    locator: Locator,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn rust_source_paths() -> Vec<String> {
    let mut paths = Vec::new();
    collect_rust_source_paths(&repo_path(""), &mut paths);
    paths.sort();
    paths.dedup();
    paths
}

fn collect_rust_source_paths(dir: &Path, paths: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|err| panic!("read dir {dir:?}: {err}"));
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| panic!("read dir entry in {dir:?}: {err}"));
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|err| panic!("read file type for {path:?}: {err}"));

        if file_type.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            collect_rust_source_paths(&path, paths);
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
        {
            let relative = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or_else(|err| panic!("strip repo prefix for {path:?}: {err}"))
                .to_string_lossy()
                .replace('\\', "/");
            paths.push(relative);
        }
    }
}

fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".beads" | ".git" | "target" | "node_modules" | ".pytest_cache" | ".ruff_cache"
    ) || name.starts_with(".rch-target")
        || name.starts_with("rch_target")
}

fn scan_workspace_sources() -> (
    BTreeSet<String>,
    BTreeMap<String, String>,
    BTreeSet<Locator>,
) {
    let mut source_by_path = BTreeMap::new();
    let mut scanned = BTreeSet::new();
    let paths = rust_source_paths();
    let path_set = paths.iter().cloned().collect::<BTreeSet<_>>();

    for path in paths {
        let source = read_repo_file(&path);
        for hit in scan_source(&path, &source) {
            scanned.insert(hit.locator);
        }
        source_by_path.insert(path, source);
    }

    (path_set, source_by_path, scanned)
}

fn scan_source(path: &str, source: &str) -> Vec<ScanHit> {
    let masked = mask_comments_and_literals(source);
    let mut hits = Vec::new();

    for (line_index, masked_line) in masked.lines().enumerate() {
        let line = line_index + 1;

        if contains_allow_unsafe_code(masked_line) {
            hits.push(ScanHit {
                locator: Locator {
                    path: path.to_string(),
                    kind: SiteKind::AllowUnsafeCode,
                    line,
                },
            });
        }

        for kind in unsafe_kinds_on_line(masked_line) {
            hits.push(ScanHit {
                locator: Locator {
                    path: path.to_string(),
                    kind,
                    line,
                },
            });
        }
    }

    hits.sort_by(|left, right| left.locator.cmp(&right.locator));
    hits.dedup_by(|left, right| left.locator == right.locator);
    hits
}

fn contains_allow_unsafe_code(line: &str) -> bool {
    let compact = line
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    compact.contains("allow(unsafe_code")
}

fn unsafe_kinds_on_line(line: &str) -> BTreeSet<SiteKind> {
    let mut kinds = BTreeSet::new();
    let mut offset = 0;

    while let Some(relative) = line[offset..].find("unsafe") {
        let start = offset + relative;
        let end = start + "unsafe".len();
        if !is_keyword_boundary(line, start, end) {
            offset = end;
            continue;
        }

        let tail = &line[end..];
        let trimmed = tail.trim_start();
        if trimmed.starts_with('{') {
            kinds.insert(SiteKind::UnsafeBlock);
        } else if starts_with_keyword(trimmed, "fn") {
            kinds.insert(SiteKind::UnsafeFn);
        } else if starts_with_keyword(trimmed, "impl") {
            kinds.insert(SiteKind::UnsafeImpl);
        } else if starts_with_keyword(trimmed, "trait") {
            kinds.insert(SiteKind::UnsafeTrait);
        }
        offset = end;
    }

    kinds
}

fn starts_with_keyword(text: &str, keyword: &str) -> bool {
    text.starts_with(keyword)
        && text[keyword.len()..]
            .chars()
            .next()
            .is_none_or(|ch| !is_ident_char(ch))
}

fn is_keyword_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_ident_char(ch));
    let after = text[end..]
        .chars()
        .next()
        .is_none_or(|ch| !is_ident_char(ch));
    before && after
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[derive(Clone, Copy)]
enum MaskMode {
    Code,
    LineComment,
    BlockComment(usize),
    String { escaped: bool },
    Char { escaped: bool },
    RawString { hashes: usize },
}

fn mask_comments_and_literals(source: &str) -> String {
    let chars = source.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(source.len());
    let mut mode = MaskMode::Code;
    let mut index = 0;

    while index < chars.len() {
        match mode {
            MaskMode::Code => {
                if starts_with(&chars, index, &['/', '/']) {
                    push_spaces(&mut output, 2);
                    index += 2;
                    mode = MaskMode::LineComment;
                } else if starts_with(&chars, index, &['/', '*']) {
                    push_spaces(&mut output, 2);
                    index += 2;
                    mode = MaskMode::BlockComment(1);
                } else if let Some((prefix_len, hashes)) = raw_string_start(&chars, index) {
                    push_spaces(&mut output, prefix_len);
                    index += prefix_len;
                    mode = MaskMode::RawString { hashes };
                } else if chars[index] == '"' {
                    push_masked_char(&mut output, chars[index]);
                    index += 1;
                    mode = MaskMode::String { escaped: false };
                } else if chars[index] == '\'' && is_char_literal_start(&chars, index) {
                    push_masked_char(&mut output, chars[index]);
                    index += 1;
                    mode = MaskMode::Char { escaped: false };
                } else {
                    output.push(chars[index]);
                    index += 1;
                }
            }
            MaskMode::LineComment => {
                let ch = chars[index];
                push_masked_char(&mut output, ch);
                index += 1;
                if ch == '\n' {
                    mode = MaskMode::Code;
                }
            }
            MaskMode::BlockComment(depth) => {
                if starts_with(&chars, index, &['/', '*']) {
                    push_spaces(&mut output, 2);
                    index += 2;
                    mode = MaskMode::BlockComment(depth + 1);
                } else if starts_with(&chars, index, &['*', '/']) {
                    push_spaces(&mut output, 2);
                    index += 2;
                    mode = if depth == 1 {
                        MaskMode::Code
                    } else {
                        MaskMode::BlockComment(depth - 1)
                    };
                } else {
                    push_masked_char(&mut output, chars[index]);
                    index += 1;
                }
            }
            MaskMode::String { escaped } => {
                let ch = chars[index];
                push_masked_char(&mut output, ch);
                index += 1;
                mode = if escaped {
                    MaskMode::String { escaped: false }
                } else if ch == '\\' {
                    MaskMode::String { escaped: true }
                } else if ch == '"' {
                    MaskMode::Code
                } else {
                    MaskMode::String { escaped: false }
                };
            }
            MaskMode::Char { escaped } => {
                let ch = chars[index];
                push_masked_char(&mut output, ch);
                index += 1;
                mode = if escaped {
                    MaskMode::Char { escaped: false }
                } else if ch == '\\' {
                    MaskMode::Char { escaped: true }
                } else if ch == '\'' || ch == '\n' {
                    MaskMode::Code
                } else {
                    MaskMode::Char { escaped: false }
                };
            }
            MaskMode::RawString { hashes } => {
                if raw_string_end(&chars, index, hashes) {
                    push_spaces(&mut output, hashes + 1);
                    index += hashes + 1;
                    mode = MaskMode::Code;
                } else {
                    push_masked_char(&mut output, chars[index]);
                    index += 1;
                }
            }
        }
    }

    output
}

fn starts_with(chars: &[char], index: usize, pattern: &[char]) -> bool {
    chars
        .get(index..index + pattern.len())
        .is_some_and(|candidate| candidate == pattern)
}

fn raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if chars.get(cursor) == Some(&'b') || chars.get(cursor) == Some(&'c') {
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;

    let mut hashes = 0;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'"') {
        return None;
    }

    Some((cursor - index + 1, hashes))
}

fn raw_string_end(chars: &[char], index: usize, hashes: usize) -> bool {
    chars.get(index) == Some(&'"')
        && (0..hashes).all(|hash_index| chars.get(index + 1 + hash_index) == Some(&'#'))
}

fn is_char_literal_start(chars: &[char], index: usize) -> bool {
    let Some(next) = chars.get(index + 1) else {
        return false;
    };
    !(*next == '_' || next.is_ascii_alphabetic())
}

fn push_spaces(output: &mut String, count: usize) {
    for _ in 0..count {
        output.push(' ');
    }
}

fn push_masked_char(output: &mut String, ch: char) {
    if ch == '\n' {
        output.push('\n');
    } else {
        output.push(' ');
    }
}

fn ledger_locators(
    ledger: &Value,
    scanned_paths: &BTreeSet<String>,
) -> (BTreeSet<Locator>, BTreeMap<Locator, String>) {
    let mut locators = BTreeSet::new();
    let mut owner_by_locator = BTreeMap::new();
    let mut site_ids = BTreeSet::new();

    for site in array(ledger, "sites") {
        let site_id = string(site, "site_id").to_string();
        assert!(
            site_ids.insert(site_id.clone()),
            "duplicate site_id {site_id}"
        );

        let path = string(site, "path");
        assert!(
            scanned_paths.contains(path),
            "{site_id}: ledger path does not resolve to tracked Rust source: {path}"
        );
        for required in [
            "category",
            "scope",
            "feature_or_platform_gate",
            "why_safe_rust_is_insufficient",
            "safety_invariant",
            "expected_evidence",
        ] {
            string(site, required);
        }
        assert_ne!(
            string(site, "category"),
            "other",
            "{site_id}: category other"
        );
        assert!(
            !array(site, "explicit_no_claims").is_empty(),
            "{site_id}: explicit_no_claims must be nonempty"
        );

        let operation_locators = array(site, "operation_locators");
        assert!(
            !operation_locators.is_empty(),
            "{site_id}: operation_locators must be nonempty"
        );
        let mut row_has_allow = false;
        let mut row_has_child_operation = false;
        for operation in operation_locators {
            let kind = SiteKind::from_str(string(operation, "kind")).unwrap_or_else(|| {
                panic!(
                    "{}: unknown operation kind {}",
                    site_id,
                    string(operation, "kind")
                )
            });
            let line = operation
                .get("line")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{site_id}: operation line must be u64"))
                as usize;
            assert!(line > 0, "{site_id}: operation line must be positive");
            string(operation, "pattern");

            row_has_allow |= kind == SiteKind::AllowUnsafeCode;
            row_has_child_operation |= kind != SiteKind::AllowUnsafeCode;

            let locator = Locator {
                path: path.to_string(),
                kind,
                line,
            };
            assert!(
                locators.insert(locator.clone()),
                "{site_id}: duplicate locator {}:{}:{}",
                locator.path,
                locator.line,
                locator.kind.as_str()
            );
            owner_by_locator.insert(locator, site_id.clone());
        }

        if row_has_allow && !row_has_child_operation {
            assert!(
                site.get("unsafe_operation_child_sites")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty()),
                "{site_id}: broad allow_unsafe_code row must either list contained unsafe operation_locators or carry unsafe_operation_child_sites"
            );
        }
    }

    (locators, owner_by_locator)
}

fn compare_locators(
    scanned: &BTreeSet<Locator>,
    ledger: &BTreeSet<Locator>,
    owner_by_locator: &BTreeMap<Locator, String>,
    source_by_path: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut diagnostics = Vec::new();

    for locator in scanned.difference(ledger) {
        diagnostics.push(format!(
            "unledgered unsafe site: path={} line={} kind={} nearby={} suggested_site_id={}",
            locator.path,
            locator.line,
            locator.kind.as_str(),
            nearby_context(source_by_path.get(&locator.path), locator.line),
            suggested_site_id(locator)
        ));
    }

    for locator in ledger.difference(scanned) {
        let site_id = owner_by_locator
            .get(locator)
            .map_or("<unknown-site>", String::as_str);
        diagnostics.push(format!(
            "stale unsafe ledger row: site_id={} path={} line={} kind={} nearby={} suggested_action=update-or-remove-ledger-locator",
            site_id,
            locator.path,
            locator.line,
            locator.kind.as_str(),
            nearby_context(source_by_path.get(&locator.path), locator.line)
        ));
    }

    diagnostics
}

fn nearby_context(source: Option<&String>, line: usize) -> String {
    let Some(source) = source else {
        return "source-unavailable".to_string();
    };
    let lines = source.lines().collect::<Vec<_>>();
    let end = line.saturating_sub(1).min(lines.len());
    let start = end.saturating_sub(30);

    for candidate in lines[start..end].iter().rev() {
        let trimmed = candidate.trim();
        if trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub(crate) fn ")
            || trimmed.starts_with("unsafe fn ")
            || trimmed.starts_with("pub unsafe fn ")
            || trimmed.starts_with("impl")
            || trimmed.starts_with("mod ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("trait ")
        {
            return trimmed.to_string();
        }
    }

    "module-root".to_string()
}

fn suggested_site_id(locator: &Locator) -> String {
    let mut slug = String::from("unsafe-");
    for ch in locator.path.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    if !slug.ends_with('-') {
        slug.push('-');
    }
    slug.push_str(locator.kind.as_str());
    slug.push('-');
    slug.push_str(&locator.line.to_string());
    slug.trim_end_matches('-').to_string()
}

fn validate_summary(ledger: &Value, locators: &BTreeSet<Locator>) {
    let summary = ledger.get("summary").expect("ledger summary");
    assert_eq!(
        summary.get("operation_count").and_then(Value::as_u64),
        Some(locators.len() as u64),
        "summary.operation_count must match operation_locators"
    );
    assert_eq!(
        summary.get("boundary_rows").and_then(Value::as_u64),
        Some(array(ledger, "sites").len() as u64),
        "summary.boundary_rows must match sites"
    );

    let mut kind_counts = BTreeMap::new();
    for locator in locators {
        *kind_counts.entry(locator.kind.as_str()).or_insert(0_u64) += 1;
    }
    for (kind, expected) in kind_counts {
        assert_eq!(
            summary
                .get("operation_kind_counts")
                .and_then(|counts| counts.get(kind))
                .and_then(Value::as_u64),
            Some(expected),
            "summary.operation_kind_counts.{kind} drifted"
        );
    }
}

fn validate_category_evidence_policy(ledger: &Value) {
    let categories = object(ledger, "categories");
    let category_evidence = object(ledger, "category_evidence");
    let category_keys = categories.keys().cloned().collect::<BTreeSet<_>>();
    let evidence_keys = category_evidence.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        category_keys, evidence_keys,
        "category_evidence keys must exactly match categories keys"
    );

    for (category, evidence) in category_evidence {
        for key in ["required_evidence", "review_workflow", "explicit_no_claims"] {
            let values = array(evidence, key);
            assert!(!values.is_empty(), "{category}: {key} must be nonempty");
            for value in values {
                assert!(
                    value.as_str().is_some_and(|text| !text.trim().is_empty()),
                    "{category}: {key} entries must be nonempty strings"
                );
            }
        }
    }

    for site in array(ledger, "sites") {
        let site_id = string(site, "site_id");
        let category = string(site, "category");
        assert!(
            category_evidence.contains_key(category),
            "{site_id}: category {category} must have category_evidence"
        );
        assert!(
            string(site, "expected_evidence").contains("Category-specific evidence"),
            "{site_id}: expected_evidence must point reviewers at the category policy"
        );
    }
}

fn lane_by_id<'a>(manifest: &'a Value, lane_id: &str) -> &'a Value {
    array(manifest, "lanes")
        .iter()
        .find(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        .unwrap_or_else(|| panic!("missing manifest lane {lane_id}"))
}

fn guarantee_by_id<'a>(manifest: &'a Value, guarantee_id: &str) -> &'a Value {
    array(manifest, "guarantees")
        .iter()
        .find(|guarantee| {
            guarantee.get("guarantee_id").and_then(Value::as_str) == Some(guarantee_id)
        })
        .unwrap_or_else(|| panic!("missing manifest guarantee {guarantee_id}"))
}

#[test]
fn unsafe_boundary_ledger_matches_source_locators() {
    let ledger = json(LEDGER_PATH);
    let (source_paths, source_by_path, scanned) = scan_workspace_sources();
    let (ledger_locators, owner_by_locator) = ledger_locators(&ledger, &source_paths);

    validate_summary(&ledger, &ledger_locators);
    validate_category_evidence_policy(&ledger);
    let diagnostics = compare_locators(
        &scanned,
        &ledger_locators,
        &owner_by_locator,
        &source_by_path,
    );
    assert!(
        diagnostics.is_empty(),
        "unsafe boundary ledger drift:\n{}",
        diagnostics.join("\n")
    );
}

#[test]
fn scanner_ignores_comments_strings_and_detects_macro_bodies() {
    let source = r#"
fn sample() {
    let _text = "unsafe { string literal } #[allow(unsafe_code)]";
    // unsafe fn hidden() {}
    /* unsafe impl Hidden {} */
    macro_rules! active {
        () => { unsafe { core::ptr::read_volatile(&0) } };
    }
    #[allow(unsafe_code)]
    unsafe { core::ptr::read_volatile(&0) };
}
"#;
    let hits = scan_source("synthetic.rs", source)
        .into_iter()
        .map(|hit| hit.locator)
        .collect::<BTreeSet<_>>();

    assert!(hits.contains(&Locator {
        path: "synthetic.rs".to_string(),
        kind: SiteKind::UnsafeBlock,
        line: 7,
    }));
    assert!(hits.contains(&Locator {
        path: "synthetic.rs".to_string(),
        kind: SiteKind::AllowUnsafeCode,
        line: 9,
    }));
    assert!(hits.contains(&Locator {
        path: "synthetic.rs".to_string(),
        kind: SiteKind::UnsafeBlock,
        line: 10,
    }));
    assert_eq!(
        hits.len(),
        3,
        "comments and string literals must not create unsafe ledger hits"
    );
}

#[test]
fn diagnostics_cover_unledgered_and_stale_rows() {
    let source = "mod demo {\n    fn nearby() {\n        unsafe { core::ptr::read_volatile(&0) };\n    }\n}\n";
    let scanned = scan_source("synthetic.rs", source)
        .into_iter()
        .map(|hit| hit.locator)
        .collect::<BTreeSet<_>>();
    let stale = Locator {
        path: "synthetic.rs".to_string(),
        kind: SiteKind::UnsafeFn,
        line: 99,
    };
    let ledger = BTreeSet::from([stale.clone()]);
    let owner_by_locator = BTreeMap::from([(stale, "unsafe-synthetic-stale".to_string())]);
    let source_by_path = BTreeMap::from([("synthetic.rs".to_string(), source.to_string())]);

    let diagnostics = compare_locators(&scanned, &ledger, &owner_by_locator, &source_by_path);
    let joined = diagnostics.join("\n");
    assert!(joined.contains("unledgered unsafe site"));
    assert!(joined.contains("stale unsafe ledger row"));
    assert!(joined.contains("path=synthetic.rs"));
    assert!(joined.contains("line=3"));
    assert!(joined.contains("kind=unsafe_block"));
    assert!(joined.contains("nearby=fn nearby() {"));
    assert!(joined.contains("suggested_site_id=unsafe-synthetic-rs-unsafe_block-3"));
}

#[test]
fn manifest_and_status_rows_wire_the_contract_lane() {
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lane = lane_by_id(&manifest, LANE_ID);
    let guarantee = guarantee_by_id(&manifest, GUARANTEE_ID);

    assert_eq!(string(lane, "command"), PROOF_COMMAND);
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert!(string_set(lane, "source_paths").contains(LEDGER_PATH));
    assert!(string_set(lane, "source_paths").contains("tests/unsafe_boundary_ledger_contract.rs"));
    assert!(string(lane, "explicit_not_covered").contains("does not prove unsafe correctness"));
    assert!(string(lane, "explicit_not_covered").contains("does not execute platform FFI"));
    assert!(string_set(lane, "guarantee_ids").contains(GUARANTEE_ID));
    assert!(string_set(guarantee, "lane_ids").contains(LANE_ID));
    assert!(string_set(&lane["proof_reuse_policy"], "allowed_claim_scopes").contains(GUARANTEE_ID));

    let claim = array(&snapshot, "claim_categories")
        .iter()
        .find(|entry| entry.get("claim_id").and_then(Value::as_str) == Some(GUARANTEE_ID))
        .unwrap_or_else(|| panic!("missing proof-status claim {GUARANTEE_ID}"));
    assert_eq!(string(claim, "proof_evidence_status"), "rerun-required");
    assert!(string_set(claim, "manifest_lane_ids").contains(LANE_ID));
    assert!(string_set(claim, "manifest_guarantee_ids").contains(GUARANTEE_ID));
    assert_eq!(
        array(claim, "proof_commands")[0].as_str(),
        Some(PROOF_COMMAND)
    );
    assert!(string(claim, "notes").contains("does not prove unsafe correctness"));
}

#[test]
fn docs_publish_unsafe_review_workflow_policy() {
    let docs = read_repo_file("docs/unsafe_boundary_ledger.md");
    let readme = read_repo_file("README.md");
    let agents = read_repo_file("AGENTS.md");

    for required in [
        "category_evidence",
        "category-specific evidence",
        "breakage rehearsal",
        "RCH_REQUIRE_REMOTE=1 rch exec",
    ] {
        assert!(
            docs.contains(required),
            "unsafe ledger docs must mention {required}"
        );
    }

    for required in [
        "artifacts/unsafe_boundary_ledger_v1.json",
        "docs/unsafe_boundary_ledger.md",
        "category-specific evidence",
        "unsafe-boundary-ledger-contract",
    ] {
        assert!(
            readme.contains(required),
            "README unsafe policy must mention {required}"
        );
        assert!(
            agents.contains(required),
            "AGENTS unsafe policy must mention {required}"
        );
    }
}
