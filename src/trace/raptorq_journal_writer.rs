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
/// journal byte streams plus the [`EpochManifest`], ready for a striped writer
/// to flush each stream to a distinct failure domain.
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
