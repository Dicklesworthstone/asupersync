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
use crate::trace::raptorq_journal::{BlockSymbols, EpochManifest, serialize_epoch};
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
