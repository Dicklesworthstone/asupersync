//! JSONL exporter for offline replay of [`EvidenceLedger`] entries (bd-qaaxt.2).
//!
//! Writes one JSON object per line to an append-only file, enabling efficient
//! offline replay and analysis of runtime decisions.
//!
//! # Features
//!
//! - Append-only semantics — existing lines are never modified.
//! - Schema version header — first line is a version record.
//! - Configurable rotation by size.
//! - Buffered I/O for throughput.
//!
//! # Example
//!
//! ```no_run
//! use franken_evidence::{EvidenceLedgerBuilder, export::JsonlExporter};
//! use std::path::PathBuf;
//!
//! let mut exporter = JsonlExporter::open(PathBuf::from("/tmp/evidence.jsonl")).unwrap();
//!
//! let entry = EvidenceLedgerBuilder::new()
//!     .ts_unix_ms(1700000000000)
//!     .component("scheduler")
//!     .action("preempt")
//!     .posterior(vec![0.7, 0.2, 0.1])
//!     .chosen_expected_loss(0.05)
//!     .calibration_score(0.92)
//!     .build()
//!     .unwrap();
//!
//! exporter.append(&entry).unwrap();
//! exporter.flush().unwrap();
//! ```

use crate::EvidenceLedger;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Schema version written as the first line of each JSONL file.
const SCHEMA_VERSION: &str = "1.0.0";

/// Default maximum file size before rotation (100 MB).
const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// JSONL exporter for [`EvidenceLedger`] entries.
///
/// Opens a file in append mode and writes one JSON line per entry.
/// The first line of each new file is a schema version header.
pub struct JsonlExporter {
    writer: BufWriter<File>,
    path: PathBuf,
    bytes_written: u64,
    entries_written: u64,
    max_bytes: u64,
}

/// Configuration for [`JsonlExporter`].
#[derive(Clone, Debug)]
pub struct ExporterConfig {
    /// Maximum file size in bytes before rotation. Set to 0 to disable rotation.
    pub max_bytes: u64,
    /// Buffer capacity for the writer.
    pub buf_capacity: usize,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            buf_capacity: 8192,
        }
    }
}

impl JsonlExporter {
    /// Open a JSONL file for appending, writing a schema header if the file is new/empty.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        Self::open_with_config(path, &ExporterConfig::default())
    }

    /// Open with explicit configuration.
    pub fn open_with_config(path: PathBuf, config: &ExporterConfig) -> io::Result<Self> {
        let existing_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut writer = BufWriter::with_capacity(config.buf_capacity, file);

        let mut bytes_written = existing_size;

        // Write schema header if file is empty.
        if existing_size == 0 {
            let header =
                format!("{{\"_schema\":\"EvidenceLedger\",\"_version\":\"{SCHEMA_VERSION}\"}}\n");
            writer.write_all(header.as_bytes())?;
            bytes_written += header.len() as u64;
        }

        Ok(Self {
            writer,
            path,
            bytes_written,
            entries_written: 0,
            max_bytes: config.max_bytes,
        })
    }

    /// Append a single entry as a JSONL line.
    ///
    /// Returns the number of bytes written (including the newline).
    pub fn append(&mut self, entry: &EvidenceLedger) -> io::Result<u64> {
        // Check rotation before writing.
        if self.max_bytes > 0 && self.bytes_written >= self.max_bytes {
            self.rotate()?;
        }

        let json = serde_json::to_string(entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let line = format!("{json}\n");
        let line_bytes = line.len() as u64;

        self.writer.write_all(line.as_bytes())?;
        self.bytes_written += line_bytes;
        self.entries_written += 1;

        Ok(line_bytes)
    }

    /// Flush buffered data to disk.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Number of entries written since this exporter was opened.
    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }

    /// Approximate bytes written to the current file.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Path to the current output file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rotate the file: close current, rename to timestamped name, open fresh.
    fn rotate(&mut self) -> io::Result<()> {
        self.writer.flush()?;

        // Generate rotated filename: path.YYYYMMDD_HHMMSS.jsonl
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let rotated_name = format!(
            "{}.{secs}.jsonl",
            self.path.file_stem().unwrap_or_default().to_string_lossy()
        );
        let rotated_path = self.path.with_file_name(rotated_name);

        // Rename current file.
        fs::rename(&self.path, &rotated_path)?;

        // Open fresh file with header.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = BufWriter::new(file);

        let header =
            format!("{{\"_schema\":\"EvidenceLedger\",\"_version\":\"{SCHEMA_VERSION}\"}}\n");
        self.writer.write_all(header.as_bytes())?;
        self.bytes_written = header.len() as u64;

        Ok(())
    }
}

/// Read and validate a JSONL file, returning parsed entries (skipping the header).
///
/// Partial/corrupt lines at the end of the file are silently skipped
/// (crash recovery).
pub fn read_jsonl(path: &Path) -> io::Result<Vec<EvidenceLedger>> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip schema header lines.
        if line.contains("\"_schema\"") {
            continue;
        }
        // Attempt to parse; skip corrupt/partial lines (crash recovery).
        if let Ok(entry) = serde_json::from_str::<EvidenceLedger>(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceLedgerBuilder;

    fn test_entry(component: &str) -> EvidenceLedger {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_000)
            .component(component)
            .action("act")
            .posterior(vec![0.6, 0.4])
            .chosen_expected_loss(0.1)
            .calibration_score(0.85)
            .build()
            .unwrap()
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut exporter = JsonlExporter::open(path.clone()).unwrap();
        exporter.append(&test_entry("alpha")).unwrap();
        exporter.append(&test_entry("beta")).unwrap();
        exporter.flush().unwrap();

        assert_eq!(exporter.entries_written(), 2);

        let entries = read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component, "alpha");
        assert_eq!(entries[1].component, "beta");
    }

    #[test]
    fn schema_header_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut exporter = JsonlExporter::open(path.clone()).unwrap();
        exporter.flush().unwrap();
        drop(exporter);

        let content = fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert!(first_line.contains("\"_schema\""));
        assert!(first_line.contains(SCHEMA_VERSION));
    }

    #[test]
    fn append_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        // First session: write one entry.
        {
            let mut exporter = JsonlExporter::open(path.clone()).unwrap();
            exporter.append(&test_entry("first")).unwrap();
            exporter.flush().unwrap();
        }

        // Second session: append another entry (no duplicate header).
        {
            let mut exporter = JsonlExporter::open(path.clone()).unwrap();
            exporter.append(&test_entry("second")).unwrap();
            exporter.flush().unwrap();
        }

        let content = fs::read_to_string(&path).unwrap();
        let header_count = content
            .lines()
            .filter(|l| l.contains("\"_schema\""))
            .count();
        assert_eq!(header_count, 1, "should have exactly one schema header");

        let entries = read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn crash_recovery_skips_partial_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        // Write valid data then simulate a crash by appending partial JSON.
        {
            let mut exporter = JsonlExporter::open(path.clone()).unwrap();
            exporter.append(&test_entry("valid")).unwrap();
            exporter.flush().unwrap();
        }

        // Append partial/corrupt line.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "{{\"ts\":123,\"c\":\"broken").unwrap();

        let entries = read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 1, "should skip corrupt line");
        assert_eq!(entries[0].component, "valid");
    }

    #[test]
    fn rotation_by_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");

        let config = ExporterConfig {
            max_bytes: 200, // Very small to trigger rotation quickly.
            buf_capacity: 64,
        };
        let mut exporter = JsonlExporter::open_with_config(path.clone(), &config).unwrap();

        // Write entries until rotation occurs.
        for i in 0..20 {
            exporter.append(&test_entry(&format!("entry{i}"))).unwrap();
        }
        exporter.flush().unwrap();

        // Check that rotated files exist.
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            files.len() > 1,
            "should have rotated files, got {}",
            files.len()
        );

        // Current file should have a schema header.
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"_schema\""));
    }

    #[test]
    fn bytes_written_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut exporter = JsonlExporter::open(path).unwrap();
        let header_bytes = exporter.bytes_written();
        assert!(header_bytes > 0);

        let entry_bytes = exporter.append(&test_entry("x")).unwrap();
        assert!(entry_bytes > 0);
        assert_eq!(exporter.bytes_written(), header_bytes + entry_bytes);
    }
}
