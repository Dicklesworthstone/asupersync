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
use std::sync::Arc;

/// Schema version written as the first line of each JSONL file.
const SCHEMA_VERSION: &str = "1.0.0";

/// Default maximum file size before rotation (100 MB).
const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// br-asupersync-ies02a — Pluggable clock used for rotation filenames.
///
/// `JsonlExporter::rotate` previously called
/// `std::time::SystemTime::now()` directly, which broke deterministic
/// replay under `LabRuntime::VirtualClock`: the same evidence batch
/// rotated to a different filename in different runs because the
/// timestamp baked into the rotated path was wall-clock time. Callers
/// running deterministic tests can now supply a `RotationClock` whose
/// `now_secs()` returns a virtual / counter-driven time; the default
/// implementation `WallClock` preserves the original production
/// behaviour.
pub trait RotationClock: Send + Sync {
    /// Returns "now" in seconds since some reference epoch. Used solely
    /// to build the rotated filename — uniqueness is required, monotonicity
    /// is preferred, and the absolute value's meaning is opaque to the
    /// exporter.
    fn now_secs(&self) -> u64;
}

/// Default `RotationClock` that reads `SystemTime::now()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WallClock;

impl RotationClock for WallClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl<F: Fn() -> u64 + Send + Sync> RotationClock for F {
    fn now_secs(&self) -> u64 {
        (self)()
    }
}

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
    /// br-asupersync-ies02a — Clock used for rotation filenames.
    clock: Arc<dyn RotationClock>,
}

/// Configuration for [`JsonlExporter`].
#[derive(Clone)]
pub struct ExporterConfig {
    /// Maximum file size in bytes before rotation. Set to 0 to disable rotation.
    pub max_bytes: u64,
    /// Buffer capacity for the writer.
    pub buf_capacity: usize,
    /// br-asupersync-ies02a — Clock used to build rotated filenames.
    /// Defaults to [`WallClock`] (reads `SystemTime::now()`); deterministic
    /// tests should supply a virtual clock so rotated paths are stable
    /// across runs.
    pub clock: Arc<dyn RotationClock>,
}

impl std::fmt::Debug for ExporterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExporterConfig")
            .field("max_bytes", &self.max_bytes)
            .field("buf_capacity", &self.buf_capacity)
            .field("clock", &"<dyn RotationClock>")
            .finish()
    }
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            buf_capacity: 8192,
            clock: Arc::new(WallClock),
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
        let existing_size = fs::metadata(&path).map_or(0, |m| m.len());
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
            clock: Arc::clone(&config.clock),
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
    ///
    /// br-asupersync-ies02a — uses the configured `RotationClock` rather
    /// than `SystemTime::now()` so deterministic tests can pin the
    /// rotated filename across runs.
    fn rotate(&mut self) -> io::Result<()> {
        self.writer.flush()?;

        // Generate rotated filename: path.<secs>.jsonl
        let secs = self.clock.now_secs();
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
        // Attempt to parse and validate; skip corrupt/partial/invalid lines
        // (crash recovery + schema guardrail).
        if let Ok(entry) = serde_json::from_str::<EvidenceLedger>(line)
            && entry.is_valid()
        {
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
    fn read_jsonl_skips_parsed_but_invalid_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.jsonl");

        {
            let mut exporter = JsonlExporter::open(path.clone()).unwrap();
            exporter.append(&test_entry("valid")).unwrap();
            exporter.flush().unwrap();
        }

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            r#"{{"ts":2,"c":"broken","a":"chosen","p":[1.0],"el":{{"other":0.1}},"cel":0.1,"cal":0.8,"fb":false,"tf":[]}}"#
        )
        .unwrap();

        let entries = read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 1, "should skip invalid but parseable line");
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

    /// br-asupersync-ies02a — Rotation uses the configured `RotationClock`
    /// rather than `SystemTime::now()`. Pinning the clock to a fixed
    /// value makes the rotated filename deterministic across runs.
    #[test]
    fn rotation_uses_configured_clock() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");

        // Fixed-instant clock: every rotation lands on the same second.
        let config = ExporterConfig {
            max_bytes: 64,
            buf_capacity: 8192,
            clock: Arc::new(|| 1_700_000_000u64),
        };
        let mut exporter = JsonlExporter::open_with_config(path.clone(), &config).unwrap();

        // Write enough entries to force at least one rotation.
        for i in 0..32 {
            exporter
                .append(&test_entry(&format!("payload-{i}")))
                .unwrap();
        }
        exporter.flush().unwrap();

        // The deterministic clock fixes the rotated filename. Search the
        // directory for `evidence.1700000000.jsonl`.
        let expected_rotated = dir.path().join("evidence.1700000000.jsonl");
        assert!(
            expected_rotated.exists(),
            "expected deterministic rotated filename {:?}",
            expected_rotated
        );
    }

    /// br-asupersync-ies02a — Default config still uses `WallClock`
    /// (preserves prior production behaviour).
    #[test]
    fn default_config_uses_wall_clock() {
        let cfg = ExporterConfig::default();
        // WallClock returns a "large" current-epoch second — well above
        // 1 billion (any plausible UNIX epoch second since ~Sept 2001).
        let now = cfg.clock.now_secs();
        assert!(now > 1_000_000_000, "default clock returned {now}");
    }
}
