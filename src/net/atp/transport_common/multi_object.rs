//! Transport-agnostic split planning for huge ATP entries.
//!
//! ATP-RQ source block numbers are one byte, so one encoded object can carry at
//! most 256 source blocks. For large single files, the safe path is to split the
//! logical file into ordered RaptorQ objects, keep each object's K bounded by
//! the configured block size, then verify the whole file after reassembly.

/// ATP-RQ's one-byte source-block number limit.
pub const ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT: u32 = 256;

/// The ATP-RQ default block cap used by current senders.
pub const ATP_RQ_DEFAULT_MULTI_OBJECT_BLOCK_SIZE: u64 = 8 * 1024 * 1024;

/// Split planner configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiObjectSplitConfig {
    /// Maximum source blocks carried by one encoded object.
    pub max_source_blocks_per_object: u32,
    /// Maximum bytes in one source block.
    pub max_block_size: u64,
}

impl MultiObjectSplitConfig {
    /// Build a planner config for the given block size and the ATP-RQ SBN cap.
    pub const fn new(max_block_size: u64) -> Self {
        Self {
            max_source_blocks_per_object: ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT,
            max_block_size,
        }
    }

    /// Maximum bytes one encoded object may carry.
    pub fn object_byte_limit(self) -> Result<u64, MultiObjectSplitError> {
        if self.max_source_blocks_per_object == 0 {
            return Err(MultiObjectSplitError::InvalidSourceBlockLimit {
                max_source_blocks_per_object: self.max_source_blocks_per_object,
            });
        }
        if self.max_source_blocks_per_object > ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT {
            return Err(MultiObjectSplitError::InvalidSourceBlockLimit {
                max_source_blocks_per_object: self.max_source_blocks_per_object,
            });
        }
        if self.max_block_size == 0 {
            return Err(MultiObjectSplitError::ZeroMaxBlockSize);
        }

        u64::from(self.max_source_blocks_per_object)
            .checked_mul(self.max_block_size)
            .ok_or(MultiObjectSplitError::ObjectByteLimitOverflow {
                max_source_blocks_per_object: self.max_source_blocks_per_object,
                max_block_size: self.max_block_size,
            })
    }
}

impl Default for MultiObjectSplitConfig {
    fn default() -> Self {
        Self::new(ATP_RQ_DEFAULT_MULTI_OBJECT_BLOCK_SIZE)
    }
}

/// One encoded object covering a byte range of a logical entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiObjectShard {
    /// Zero-based shard ordinal within the logical entry.
    pub shard_index: u32,
    /// Byte offset in the logical entry.
    pub logical_offset: u64,
    /// Number of logical entry bytes carried by this shard.
    pub len: u64,
    /// Source block cap used when encoding this shard.
    pub max_block_size: u64,
    /// Number of source blocks needed by this shard.
    pub source_block_count: u32,
}

impl MultiObjectShard {
    /// Exclusive end offset in the logical entry.
    pub fn logical_end(&self) -> u64 {
        self.logical_offset.saturating_add(self.len)
    }

    /// Whether this shard is the zero-content placeholder for an empty entry.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Ordered split plan for one logical entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiObjectPlan {
    /// Original logical entry size.
    pub logical_size: u64,
    /// Maximum bytes allowed in any non-empty shard.
    pub max_object_bytes: u64,
    /// Ordered shards to transfer and reassemble.
    pub shards: Vec<MultiObjectShard>,
}

impl MultiObjectPlan {
    /// Number of encoded objects in the plan.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Whether the logical entry requires more than one encoded object.
    pub fn is_split(&self) -> bool {
        self.shards.len() > 1
    }

    /// Sum of shard lengths; this must equal `logical_size`.
    pub fn planned_bytes(&self) -> u64 {
        self.shards
            .iter()
            .fold(0u64, |acc, shard| acc.saturating_add(shard.len))
    }
}

/// Errors from [`plan_multi_object_split`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultiObjectSplitError {
    /// The configured block size cannot encode data.
    #[error("multi-object split max_block_size must be non-zero")]
    ZeroMaxBlockSize,
    /// The source-block limit is incompatible with ATP-RQ's u8 SBN field.
    #[error(
        "multi-object split source-block limit must be in 1..=256, got {max_source_blocks_per_object}"
    )]
    InvalidSourceBlockLimit {
        /// Configured source-block ceiling.
        max_source_blocks_per_object: u32,
    },
    /// The object byte limit overflowed u64.
    #[error(
        "multi-object split object byte limit overflow: {max_source_blocks_per_object} blocks * {max_block_size} bytes"
    )]
    ObjectByteLimitOverflow {
        /// Configured source-block ceiling.
        max_source_blocks_per_object: u32,
        /// Configured block size.
        max_block_size: u64,
    },
    /// The logical entry would require too many ordered shards.
    #[error("multi-object split would produce too many shards: {shard_count}")]
    TooManyShards {
        /// Required shard count.
        shard_count: u64,
    },
}

/// Plan a fail-closed multi-object split for one logical entry.
///
/// The returned shards are contiguous, non-overlapping, and preserve byte order.
/// Non-empty shards are capped at `max_source_blocks_per_object *
/// max_block_size`, and their `source_block_count` never exceeds the ATP-RQ SBN
/// limit. Empty entries produce one zero-length shard so manifests can retain
/// the entry even though no source symbols need to be sent.
pub fn plan_multi_object_split(
    logical_size: u64,
    config: MultiObjectSplitConfig,
) -> Result<MultiObjectPlan, MultiObjectSplitError> {
    let max_object_bytes = config.object_byte_limit()?;
    if logical_size == 0 {
        return Ok(MultiObjectPlan {
            logical_size,
            max_object_bytes,
            shards: vec![MultiObjectShard {
                shard_index: 0,
                logical_offset: 0,
                len: 0,
                max_block_size: config.max_block_size,
                source_block_count: 0,
            }],
        });
    }

    let required_shards = logical_size.div_ceil(max_object_bytes);
    if required_shards > u64::from(u32::MAX) {
        return Err(MultiObjectSplitError::TooManyShards {
            shard_count: required_shards,
        });
    }

    let mut shards = Vec::with_capacity(usize::try_from(required_shards.min(1024)).unwrap_or(0));
    let mut logical_offset = 0u64;
    while logical_offset < logical_size {
        let remaining = logical_size - logical_offset;
        let len = remaining.min(max_object_bytes);
        let source_block_count =
            u32::try_from(len.div_ceil(config.max_block_size)).map_err(|_| {
                MultiObjectSplitError::TooManyShards {
                    shard_count: required_shards,
                }
            })?;
        debug_assert!(source_block_count <= config.max_source_blocks_per_object);

        shards.push(MultiObjectShard {
            shard_index: u32::try_from(shards.len()).map_err(|_| {
                MultiObjectSplitError::TooManyShards {
                    shard_count: required_shards,
                }
            })?,
            logical_offset,
            len,
            max_block_size: config.max_block_size,
            source_block_count,
        });
        logical_offset += len;
    }

    Ok(MultiObjectPlan {
        logical_size,
        max_object_bytes,
        shards,
    })
}

#[cfg(test)]
#[path = "multi_object_inline_tests.rs"]
mod tests;
