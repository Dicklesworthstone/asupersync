//! Doctor-oriented CLI primitives.
//!
//! This module provides deterministic workspace scanning utilities used by
//! `doctor_asupersync` surfaces.

use super::Outputtable;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Deterministic workspace scan report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceScanReport {
    /// Root path used for the scan.
    pub root: String,
    /// Manifest path used as the scan entrypoint.
    pub workspace_manifest: String,
    /// Workspace members discovered in deterministic order.
    pub members: Vec<WorkspaceMember>,
    /// Capability-flow edges from member crate to runtime surface.
    pub capability_edges: Vec<CapabilityEdge>,
    /// Non-fatal scan warnings.
    pub warnings: Vec<String>,
}

impl Outputtable for WorkspaceScanReport {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Root: {}", self.root));
        lines.push(format!("Manifest: {}", self.workspace_manifest));
        lines.push(format!("Members: {}", self.members.len()));
        lines.push(format!("Capability edges: {}", self.capability_edges.len()));
        if !self.warnings.is_empty() {
            lines.push(format!("Warnings: {}", self.warnings.len()));
        }
        for member in &self.members {
            lines.push(format!(
                "- {} ({}) [{}]",
                member.name,
                member.relative_path,
                member.capability_surfaces.join(", "),
            ));
        }
        for warning in &self.warnings {
            lines.push(format!("warning: {warning}"));
        }
        lines.join("\n")
    }
}

/// Deterministic summary of one workspace member.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceMember {
    /// Cargo package name (or fallback name).
    pub name: String,
    /// Path relative to scan root.
    pub relative_path: String,
    /// Manifest path relative to scan root.
    pub manifest_path: String,
    /// Number of Rust files scanned under `src/`.
    pub rust_file_count: usize,
    /// Runtime/capability surfaces referenced by this member.
    pub capability_surfaces: Vec<String>,
}

/// Deterministic capability-flow edge.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityEdge {
    /// Workspace member package name.
    pub member: String,
    /// Runtime surface label.
    pub surface: String,
    /// Number of files that referenced this surface.
    pub evidence_count: usize,
    /// Sample relative source files containing references.
    pub sample_files: Vec<String>,
}

#[derive(Debug, Clone)]
struct MemberScan {
    member: WorkspaceMember,
    evidence: BTreeMap<String, BTreeSet<String>>,
}

const MAX_SAMPLE_FILES: usize = 3;
const SURFACE_MARKERS: [(&str, &[&str]); 12] = [
    (
        "cx",
        &["&Cx", "asupersync::Cx", "Cx::", "use asupersync::Cx"],
    ),
    ("scope", &["Scope", "scope!(", ".region("]),
    (
        "runtime",
        &["RuntimeBuilder", "runtime::", "asupersync::runtime"],
    ),
    (
        "channel",
        &["channel::", "asupersync::channel", "mpsc::", "oneshot::"],
    ),
    (
        "sync",
        &[
            "sync::Mutex",
            "sync::RwLock",
            "sync::Semaphore",
            "asupersync::sync",
        ],
    ),
    (
        "lab",
        &["LabRuntime", "LabConfig", "asupersync::lab", "lab::"],
    ),
    (
        "trace",
        &[
            "ReplayEvent",
            "TraceWriter",
            "TraceReader",
            "asupersync::trace",
        ],
    ),
    (
        "net",
        &["asupersync::net", "TcpStream", "TcpListener", "UdpSocket"],
    ),
    ("io", &["asupersync::io", "AsyncRead", "AsyncWrite"]),
    (
        "http",
        &[
            "asupersync::http",
            "http::",
            "Request::new(",
            "Response::new(",
        ],
    ),
    (
        "cancel",
        &["CancelReason", "CancelKind", "asupersync::cancel"],
    ),
    (
        "obligation",
        &[
            "Obligation",
            "asupersync::obligation",
            "reserve(",
            "commit(",
        ],
    ),
];

/// Scan a Cargo workspace and summarize capability-flow references.
///
/// The report is deterministic: members, surfaces, and sample paths are all
/// emitted in sorted order.
///
/// # Errors
///
/// Returns `io::Error` if the root manifest cannot be read or if directory
/// traversal fails.
pub fn scan_workspace(root: &Path) -> io::Result<WorkspaceScanReport> {
    let root = root.to_path_buf();
    let manifest_path = root.join("Cargo.toml");
    let manifest_text = fs::read_to_string(&manifest_path)?;

    let mut warnings = Vec::new();
    let workspace_members = parse_workspace_string_array(&manifest_text, "members");
    let workspace_excludes = parse_workspace_string_array(&manifest_text, "exclude");

    let mut member_dirs = BTreeSet::new();
    if workspace_members.is_empty() {
        member_dirs.insert(root.clone());
    } else {
        for pattern in &workspace_members {
            for path in expand_member_pattern(&root, pattern, &mut warnings)? {
                member_dirs.insert(path);
            }
        }
    }

    let mut excluded_dirs = BTreeSet::new();
    for pattern in &workspace_excludes {
        for path in expand_member_pattern(&root, pattern, &mut warnings)? {
            excluded_dirs.insert(path);
        }
    }

    let mut member_scans = Vec::new();
    for member_dir in member_dirs {
        if excluded_dirs.contains(&member_dir) {
            continue;
        }
        match scan_member(&root, &member_dir)? {
            Some(scan) => member_scans.push(scan),
            None => {
                warnings.push(format!(
                    "member missing Cargo.toml: {}",
                    relative_to(&root, &member_dir),
                ));
            }
        }
    }

    member_scans.sort_by(|a, b| a.member.relative_path.cmp(&b.member.relative_path));

    let mut members = Vec::with_capacity(member_scans.len());
    let mut edges = Vec::new();
    for scan in member_scans {
        for (surface, files) in &scan.evidence {
            let sample_files = files
                .iter()
                .take(MAX_SAMPLE_FILES)
                .cloned()
                .collect::<Vec<_>>();
            edges.push(CapabilityEdge {
                member: scan.member.name.clone(),
                surface: surface.clone(),
                evidence_count: files.len(),
                sample_files,
            });
        }
        members.push(scan.member);
    }

    edges.sort_by(|a, b| {
        a.member
            .cmp(&b.member)
            .then_with(|| a.surface.cmp(&b.surface))
    });

    Ok(WorkspaceScanReport {
        root: root.display().to_string(),
        workspace_manifest: manifest_path.display().to_string(),
        members,
        capability_edges: edges,
        warnings,
    })
}

fn scan_member(root: &Path, member_dir: &Path) -> io::Result<Option<MemberScan>> {
    let manifest_path = member_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest_text = fs::read_to_string(&manifest_path)?;
    let package_name = parse_package_name(&manifest_text).unwrap_or_else(|| {
        member_dir
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(|| "unknown".to_string(), ToString::to_string)
    });

    let source_root = member_dir.join("src");
    let rust_files = collect_rust_files(&source_root)?;
    let mut evidence: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for file in rust_files {
        let source = fs::read_to_string(&file)?;
        let matched_surfaces = detect_surfaces(&source);
        if matched_surfaces.is_empty() {
            continue;
        }
        let relative_file = relative_to(root, &file);
        for surface in matched_surfaces {
            evidence
                .entry(surface.to_string())
                .or_default()
                .insert(relative_file.clone());
        }
    }

    let member = WorkspaceMember {
        name: package_name,
        relative_path: relative_to(root, member_dir),
        manifest_path: relative_to(root, &manifest_path),
        rust_file_count: collect_rust_files(&source_root)?.len(),
        capability_surfaces: evidence.keys().cloned().collect(),
    };

    Ok(Some(MemberScan { member, evidence }))
}

fn parse_workspace_string_array(manifest: &str, key: &str) -> Vec<String> {
    let mut in_workspace = false;
    let mut collecting = false;
    let mut buffer = String::new();
    let mut values = Vec::new();
    let prefix = format!("{key} =");

    for line in manifest.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            if collecting {
                values.extend(parse_string_array_literal(&buffer));
                buffer.clear();
                collecting = false;
            }
            in_workspace = trimmed == "[workspace]";
            continue;
        }

        if !in_workspace {
            continue;
        }

        if !collecting && trimmed.starts_with(&prefix) {
            collecting = true;
            if let Some((_, rhs)) = trimmed.split_once('=') {
                buffer.push_str(rhs.trim_start());
                buffer.push('\n');
            }
            if trimmed.contains(']') {
                values.extend(parse_string_array_literal(&buffer));
                buffer.clear();
                collecting = false;
            }
            continue;
        }

        if collecting {
            buffer.push_str(trimmed);
            buffer.push('\n');
            if trimmed.contains(']') {
                values.extend(parse_string_array_literal(&buffer));
                buffer.clear();
                collecting = false;
            }
        }
    }

    if collecting {
        values.extend(parse_string_array_literal(&buffer));
    }

    values
}

fn parse_string_array_literal(text: &str) -> Vec<String> {
    let limit = text.find(']').unwrap_or(text.len());
    let slice = &text[..limit];
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for ch in slice.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => {
                if in_string {
                    values.push(current.clone());
                    current.clear();
                    in_string = false;
                } else {
                    in_string = true;
                }
            }
            _ if in_string => current.push(ch),
            _ => {}
        }
    }

    values
}

fn parse_package_name(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if !in_package || !trimmed.starts_with("name =") {
            continue;
        }
        let parsed = parse_string_array_literal(trimmed);
        if let Some(name) = parsed.first() {
            return Some(name.clone());
        }
    }
    None
}

fn expand_member_pattern(
    root: &Path,
    pattern: &str,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<PathBuf>> {
    if !pattern.contains('*') {
        return Ok(vec![root.join(pattern)]);
    }

    if let Some(base) = pattern.strip_suffix("/*") {
        let base_dir = root.join(base);
        if !base_dir.is_dir() {
            warnings.push(format!("wildcard base missing: {}", base_dir.display()));
            return Ok(Vec::new());
        }
        let mut dirs = Vec::new();
        for entry in fs::read_dir(base_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
        }
        dirs.sort();
        return Ok(dirs);
    }

    warnings.push(format!(
        "unsupported workspace member glob pattern: {pattern}"
    ));
    Ok(Vec::new())
}

fn collect_rust_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)?.collect::<Result<Vec<_>, io::Error>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn detect_surfaces(source: &str) -> BTreeSet<&'static str> {
    let mut surfaces = BTreeSet::new();
    for (surface, markers) in SURFACE_MARKERS {
        if markers.iter().any(|marker| source.contains(marker)) {
            surfaces.insert(surface);
        }
    }
    surfaces
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directories");
        }
        fs::write(path, content).expect("write file");
    }

    #[test]
    fn scan_workspace_discovers_members_and_surfaces() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a", "crate_b"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_a/src/lib.rs"),
            "use asupersync::{Cx, Scope};\nuse asupersync::channel::mpsc;\n",
        );
        write_file(
            &root.join("crate_b/Cargo.toml"),
            r#"[package]
name = "crate_b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_b/src/lib.rs"),
            "use asupersync::runtime::RuntimeBuilder;\nuse asupersync::lab::LabRuntime;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "crate_a");
        assert_eq!(report.members[1].name, "crate_b");
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "cx")
        );
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "runtime")
        );
    }

    #[test]
    fn scan_workspace_supports_simple_wildcard_members() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/*"]
"#,
        );
        write_file(
            &root.join("crates/a/Cargo.toml"),
            r#"[package]
name = "a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crates/a/src/lib.rs"), "use asupersync::Cx;\n");
        write_file(
            &root.join("crates/b/Cargo.toml"),
            r#"[package]
name = "b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crates/b/src/lib.rs"),
            "use asupersync::trace::ReplayEvent;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "a");
        assert_eq!(report.members[1].name, "b");
    }

    #[test]
    fn scan_workspace_reports_missing_member_manifest() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["missing_member"]
"#,
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert!(report.members.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("missing Cargo.toml"))
        );
    }

    #[test]
    fn scan_workspace_falls_back_to_single_package_root() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[package]
name = "root_pkg"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("src/lib.rs"),
            "use asupersync::{Cx, Budget, Outcome};\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 1);
        assert_eq!(report.members[0].name, "root_pkg");
        assert!(
            report.members[0]
                .capability_surfaces
                .iter()
                .any(|surface| surface == "cx")
        );
    }
}
