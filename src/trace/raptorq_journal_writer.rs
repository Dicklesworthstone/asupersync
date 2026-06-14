//! RaptorQ encode side of the crash-durable trace journal
//! (br-asupersync-raptorq-leverage-3bb2pl.2).
//!
//! This bridges the runtime's RaptorQ [`EncodingPipeline`] to the pure journal
//! serializer in [`super::raptorq_journal`]: a checkpoint's bytes are encoded
//! into source + repair symbols, grouped per source block, and handed to
//! [`serialize_epoch`] to produce per-stripe journal bytes plus the matching
//! [`EpochManifest`]. The actual striped file I/O and blocking-pool scheduling
//! remain the caller's responsibility — this is the encode→serialize core.

use crate::config::EncodingConfig;
use crate::encoding::{EncodingError, EncodingPipeline};
use crate::trace::raptorq_journal::{
    BlockSymbols, EpochManifest, JOURNAL_FLAG_CHECKPOINT_BOUNDARY, latest_complete_epoch,
    scan_frames, serialize_epoch,
};
use crate::types::ObjectId;
use crate::types::resource::{PoolConfig, SymbolPool};
use std::collections::BTreeMap;

/// Encode `data` for checkpoint `epoch` into one [`BlockSymbols`] per RaptorQ
/// source block (carrying both source and repair symbols), in deterministic
/// source-block order.
///
/// `source_symbol_count` per block is the count of source symbols emitted for
/// that block (the K' needed to decode it). `repair_count` is the number of
/// repair symbols requested per block — extra symbols that let the block survive
/// losing stripes.
///
/// # Errors
///
/// Returns the [`EncodingError`] from the pipeline if encoding fails (e.g., an
/// invalid object/block plan).
pub fn encode_checkpoint_blocks(
    epoch: u64,
    data: &[u8],
    config: EncodingConfig,
    repair_count: usize,
) -> Result<Vec<BlockSymbols>, EncodingError> {
    let symbol_size = u32::from(config.symbol_size);
    let mut pipeline = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));
    let object_id = ObjectId::new(epoch, 0);

    // BTree keyed by source block number for deterministic block ordering;
    // value is (symbols, source-symbol count).
    let mut by_block: BTreeMap<u8, (Vec<(u32, Vec<u8>)>, u32)> = BTreeMap::new();
    for result in pipeline.encode_with_repair(object_id, data, repair_count) {
        let symbol = result?;
        let id = symbol.id();
        let is_source = symbol.kind().is_source();
        let entry = by_block.entry(id.sbn()).or_default();
        entry.0.push((id.esi(), symbol.symbol().data().to_vec()));
        if is_source {
            entry.1 += 1;
        }
    }

    Ok(by_block
        .into_iter()
        .map(|(sbn, (symbols, source_symbol_count))| BlockSymbols {
            source_block_number: u32::from(sbn),
            source_symbol_count,
            symbol_size,
            symbols,
        })
        .collect())
}

/// Encode and serialize a whole checkpoint epoch into `stripe_count` per-stripe
/// journal byte streams plus the [`EpochManifest`].
///
/// Ready for a striped writer to flush each stream to a distinct failure domain.
///
/// Returns `Ok(None)` if `stripe_count` is zero.
///
/// # Errors
///
/// Returns the [`EncodingError`] from [`encode_checkpoint_blocks`].
pub fn encode_and_serialize_epoch(
    epoch: u64,
    data: &[u8],
    config: EncodingConfig,
    repair_count: usize,
    stripe_count: usize,
    flags: u16,
) -> Result<Option<(Vec<Vec<u8>>, EpochManifest)>, EncodingError> {
    let blocks = encode_checkpoint_blocks(epoch, data, config, repair_count)?;
    Ok(serialize_epoch(epoch, stripe_count, flags, &blocks))
}

/// File name for stripe `index` of `epoch` within a journal directory.
#[must_use]
pub fn stripe_file_name(epoch: u64, index: usize) -> String {
    format!("epoch-{epoch}-stripe-{index}.rqj")
}

/// Durably write each stripe of an epoch to its own file in `dir`, one file per
/// failure domain, returning the written paths in stripe order.
///
/// Each stripe is written with [`crate::fs::write_atomic`] (temp file →
/// `sync_all` → rename → parent-dir `sync_all`), so a crash mid-write never
/// leaves a torn stripe file in place — the previous stripe content (if any)
/// survives and the new content lands atomically. For maximum failure-domain
/// isolation a caller can point `dir` at a per-stripe mount; the file-per-stripe
/// layout keeps that a pure deployment choice.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if the directory or any stripe file
/// cannot be created or synced.
pub async fn write_epoch_stripes(
    dir: &std::path::Path,
    epoch: u64,
    stripes: &[Vec<u8>],
) -> std::io::Result<Vec<std::path::PathBuf>> {
    crate::fs::create_dir_all(dir).await?;
    let mut paths = Vec::with_capacity(stripes.len());
    for (index, bytes) in stripes.iter().enumerate() {
        let path = dir.join(stripe_file_name(epoch, index));
        crate::fs::write_atomic(&path, bytes).await?;
        paths.push(path);
    }
    Ok(paths)
}

/// Read and concatenate the surviving stripe files for `epoch` from `dir`,
/// skipping any stripe whose file is missing (a lost failure domain).
///
/// The concatenated bytes feed [`super::raptorq_journal::scan_frames`]; recovery
/// then succeeds as long as enough symbols survived (see
/// [`super::raptorq_journal::latest_complete_epoch`]). A missing stripe is the
/// expected crash case and is silently skipped; any other I/O error propagates.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] for any read failure other than a
/// missing stripe file.
pub async fn read_epoch_stripes(
    dir: &std::path::Path,
    epoch: u64,
    stripe_count: usize,
) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for index in 0..stripe_count {
        let path = dir.join(stripe_file_name(epoch, index));
        match crate::fs::read(&path).await {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

/// File name for an epoch's persisted manifest record within a journal directory.
#[must_use]
pub fn manifest_file_name(epoch: u64) -> String {
    format!("epoch-{epoch}-manifest.rqm")
}

/// Durably persist an epoch's [`EpochManifest`] record (CRC-protected, atomic +
/// fsync) so recovery can detect a wholly-missing source block from disk alone.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if the directory or manifest file
/// cannot be created or synced.
pub async fn write_epoch_manifest(
    dir: &std::path::Path,
    manifest: EpochManifest,
) -> std::io::Result<std::path::PathBuf> {
    crate::fs::create_dir_all(dir).await?;
    let path = dir.join(manifest_file_name(manifest.epoch));
    crate::fs::write_atomic(&path, &manifest.encode()).await?;
    Ok(path)
}

/// Read an epoch's persisted [`EpochManifest`], returning `None` if its file is
/// absent (so recovery can fall back to symbol-only judgement).
///
/// # Errors
///
/// Returns [`std::io::Error`] for a read failure other than a missing file, or
/// `InvalidData` if the record is corrupt / mis-versioned.
pub async fn read_epoch_manifest(
    dir: &std::path::Path,
    epoch: u64,
) -> std::io::Result<Option<EpochManifest>> {
    let path = dir.join(manifest_file_name(epoch));
    match crate::fs::read(&path).await {
        Ok(bytes) => EpochManifest::decode(&bytes)
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Error from a [`DurableTraceJournal`] operation.
#[derive(Debug)]
pub enum DurableJournalError {
    /// RaptorQ encoding failed.
    Encoding(EncodingError),
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// The journal was configured with zero stripes.
    NoStripes,
}

impl core::fmt::Display for DurableJournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "durable journal encode error: {error}"),
            Self::Io(error) => write!(f, "durable journal I/O error: {error}"),
            Self::NoStripes => f.write_str("durable journal configured with zero stripes"),
        }
    }
}

impl std::error::Error for DurableJournalError {}

impl From<EncodingError> for DurableJournalError {
    fn from(error: EncodingError) -> Self {
        Self::Encoding(error)
    }
}

impl From<std::io::Error> for DurableJournalError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Configuration for a [`DurableTraceJournal`].
#[derive(Debug, Clone)]
pub struct DurableTraceJournalConfig {
    /// Directory the stripe and manifest files live in.
    pub directory: std::path::PathBuf,
    /// RaptorQ encoding configuration.
    pub encoding: EncodingConfig,
    /// Repair symbols per source block (redundancy for stripe loss).
    pub repair_count: usize,
    /// Number of stripe files (failure domains) to spread each epoch across.
    pub stripe_count: usize,
}

/// Cohesive handle over the crash-durable RaptorQ trace journal: encode, stripe,
/// and durably persist a checkpoint epoch, and ask whether a persisted epoch
/// still recovers from the surviving stripes.
///
/// This is the API a trace recorder holds — it bundles the configuration so the
/// recorder's checkpoint hook is a single [`DurableTraceJournal::record_epoch`]
/// call, while staying decoupled from the recorder (callers pass the checkpoint
/// bytes directly, keeping the journal independently testable).
#[derive(Debug, Clone)]
pub struct DurableTraceJournal {
    config: DurableTraceJournalConfig,
}

impl DurableTraceJournal {
    /// Build a journal handle from its configuration.
    #[must_use]
    pub fn new(config: DurableTraceJournalConfig) -> Self {
        Self { config }
    }

    /// The journal's configuration.
    #[must_use]
    pub fn config(&self) -> &DurableTraceJournalConfig {
        &self.config
    }

    /// Encode, stripe, and durably persist a checkpoint `epoch`'s bytes (stripe
    /// files + manifest), returning the persisted [`EpochManifest`].
    ///
    /// # Errors
    ///
    /// Returns [`DurableJournalError`] if encoding fails, the configuration has
    /// zero stripes, or a filesystem write fails.
    pub async fn record_epoch(
        &self,
        epoch: u64,
        data: &[u8],
    ) -> Result<EpochManifest, DurableJournalError> {
        let (stripes, manifest) = encode_and_serialize_epoch(
            epoch,
            data,
            self.config.encoding.clone(),
            self.config.repair_count,
            self.config.stripe_count,
            JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
        )?
        .ok_or(DurableJournalError::NoStripes)?;
        write_epoch_stripes(&self.config.directory, epoch, &stripes).await?;
        write_epoch_manifest(&self.config.directory, manifest).await?;
        Ok(manifest)
    }

    /// Whether `epoch` still fully recovers from the surviving stripe files,
    /// judged against its persisted manifest.
    ///
    /// Returns `false` if the epoch's manifest file is absent (recovery cannot be
    /// confirmed without the declared block count).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] for a read failure other than a
    /// missing file.
    pub async fn epoch_recoverable(&self, epoch: u64) -> std::io::Result<bool> {
        let Some(manifest) = read_epoch_manifest(&self.config.directory, epoch).await? else {
            return Ok(false);
        };
        let survivors =
            read_epoch_stripes(&self.config.directory, epoch, self.config.stripe_count).await?;
        let (frames, _) = scan_frames(&survivors);
        Ok(latest_complete_epoch(&frames, &[manifest]) == Some(epoch))
    }

    /// Every recorded epoch (one with a persisted manifest) in the journal
    /// directory, ascending. Empty if the directory does not exist yet.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] for a directory read failure
    /// other than the directory being absent.
    pub async fn recorded_epochs(&self) -> std::io::Result<Vec<u64>> {
        discover_epochs(&self.config.directory).await
    }

    /// The highest recorded epoch that still fully recovers from its surviving
    /// stripe files on disk — the latest checkpoint a recovery tool can restore.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] for a directory or stripe read
    /// failure.
    pub async fn latest_recoverable_epoch(&self) -> std::io::Result<Option<u64>> {
        let mut epochs = discover_epochs(&self.config.directory).await?;
        epochs.sort_unstable_by(|left, right| right.cmp(left)); // descending
        for epoch in epochs {
            if self.epoch_recoverable(epoch).await? {
                return Ok(Some(epoch));
            }
        }
        Ok(None)
    }
}

/// Parse the epoch number out of a `epoch-<N>-manifest.rqm` file name.
fn parse_manifest_epoch(file_name: &str) -> Option<u64> {
    file_name
        .strip_prefix("epoch-")?
        .strip_suffix("-manifest.rqm")?
        .parse::<u64>()
        .ok()
}

/// Discover every epoch with a persisted manifest record in `dir`, ascending.
///
/// A missing directory yields an empty list (nothing recorded yet) rather than
/// an error, so a fresh recovery target is handled cleanly.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] for a read failure other than the
/// directory being absent.
pub async fn discover_epochs(dir: &std::path::Path) -> std::io::Result<Vec<u64>> {
    let mut entries = match crate::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut epochs = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(epoch) = parse_manifest_epoch(&name.to_string_lossy()) {
            epochs.push(epoch);
        }
    }
    epochs.sort_unstable();
    Ok(epochs)
}
