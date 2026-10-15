//! Deterministic Slepian-Wolf syndrome foundation for ATP delta regions.
//!
//! B-8.11 builds on the B-8.10 chunk/sub-chunk delta path: first localize the
//! changed byte region with the existing content-addressed chunks, then send a
//! sparse GF(256) syndrome for that region.  This first slice is intentionally
//! a small, testable foundation: shape/rate types, deterministic rateless row
//! generation, syndrome encoding, and belief-propagation style peeling decoders
//! seeded from the receiver's old bytes.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::atp::delta::{
    CasChunkRef, ContentAddressedChunkStore, DeltaResyncPlan, PersistentChunkManifest,
};
use crate::raptorq::gf256::Gf256;

/// Schema marker for the first B-8.11 syndrome foundation.
pub const ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA: &str = "asupersync.atp.slepian-wolf.syndrome.v1";

/// Linear-code shape for a changed byte region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdpcShape {
    /// Number of source symbols in the changed byte region.
    pub n: usize,
    /// Side-information symbols expected to be known before syndrome decode.
    pub k: usize,
    /// Minimum-distance design hint for the sparse parity schedule.
    pub d: usize,
}

impl LdpcShape {
    /// Build a validated `[n, k, d]` shape.
    pub fn new(n: usize, k: usize, d: usize) -> Result<Self, SlepianWolfError> {
        if n == 0 {
            return Err(SlepianWolfError::InvalidShape {
                n,
                k,
                d,
                reason: "n must be non-zero",
            });
        }
        if k > n {
            return Err(SlepianWolfError::InvalidShape {
                n,
                k,
                d,
                reason: "k must be <= n",
            });
        }
        if d == 0 {
            return Err(SlepianWolfError::InvalidShape {
                n,
                k,
                d,
                reason: "d must be non-zero",
            });
        }
        Ok(Self { n, k, d })
    }

    /// Number of syndrome symbols at the `[n, k, d]` design rate.
    #[must_use]
    pub const fn design_syndrome_symbols(self) -> usize {
        self.n - self.k
    }

    /// Code rate `k / n`.
    #[must_use]
    pub fn rate(self) -> LdpcRate {
        LdpcRate {
            information_symbols: self.k,
            source_symbols: self.n,
        }
    }
}

/// Exact rational code rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdpcRate {
    /// Numerator.
    pub information_symbols: usize,
    /// Denominator.
    pub source_symbols: usize,
}

impl LdpcRate {
    /// Rate as an `f64` for reports and admission heuristics.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.information_symbols as f64 / self.source_symbols as f64
    }
}

/// Deterministic rateless sparse syndrome schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatelessLdpcConfig {
    /// Region code shape.
    pub shape: LdpcShape,
    /// Stable seed used to derive sparse parity rows.
    pub seed: u64,
    /// Minimum non-bootstrap row degree.
    pub min_degree: usize,
    /// Maximum non-bootstrap row degree.
    pub max_degree: usize,
}

impl RatelessLdpcConfig {
    /// Build a deterministic rateless schedule.
    pub fn new(
        shape: LdpcShape,
        seed: u64,
        min_degree: usize,
        max_degree: usize,
    ) -> Result<Self, SlepianWolfError> {
        if min_degree == 0 || max_degree == 0 || min_degree > max_degree {
            return Err(SlepianWolfError::InvalidDegreeWindow {
                min_degree,
                max_degree,
            });
        }
        Ok(Self {
            shape,
            seed,
            min_degree,
            max_degree,
        })
    }

    /// Deterministic foundation default for a region.
    pub fn foundation(shape: LdpcShape, seed: u64) -> Result<Self, SlepianWolfError> {
        let min_degree = shape.d.clamp(1, shape.n);
        let max_degree = min_degree.saturating_add(2).min(shape.n);
        Self::new(shape, seed, min_degree, max_degree)
    }
}

/// Byte region localized from positional old/new chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlepianWolfChangedRegion {
    /// Sender chunk index that contains this region.
    pub chunk_index: u32,
    /// Logical byte offset of the first changed byte.
    pub byte_offset: u64,
    /// Old receiver bytes for this localized region.
    pub old_bytes: Vec<u8>,
    /// New sender bytes for this localized region.
    pub new_bytes: Vec<u8>,
}

impl SlepianWolfChangedRegion {
    /// Number of new source symbols in this region.
    #[must_use]
    pub fn source_symbols(&self) -> usize {
        self.new_bytes.len()
    }

    /// Positions whose old side information differs from the new source bytes.
    ///
    /// This helper is for deterministic harnesses and offline floor reports.
    /// A production decoder should obtain uncertainty from negotiated priors or
    /// reliability metadata rather than comparing against the sender's bytes.
    #[must_use]
    pub fn truth_uncertain_indices(&self) -> Vec<usize> {
        self.old_bytes
            .iter()
            .zip(self.new_bytes.iter())
            .enumerate()
            .filter_map(|(idx, (old, new))| (old != new).then_some(idx))
            .collect()
    }
}

/// One sparse GF(256) matrix coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdpcTap {
    /// Source-symbol column.
    pub index: usize,
    /// Non-zero GF(256) coefficient.
    pub coefficient: Gf256,
}

/// One rateless syndrome row `value = sum(tap.coefficient * source[tap.index])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyndromeSymbol {
    /// Rateless row identifier.
    pub id: u64,
    /// Sparse parity-check taps.
    pub taps: Vec<LdpcTap>,
    /// Encoded GF(256) syndrome byte.
    pub value: Gf256,
}

/// Encoded syndrome frame for one changed region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatelessSyndrome {
    /// Stable schema marker.
    pub schema: &'static str,
    /// Code shape.
    pub shape: LdpcShape,
    /// Seed used to derive rows.
    pub seed: u64,
    /// Minimum non-bootstrap row degree used to derive sparse taps.
    pub min_degree: usize,
    /// Maximum non-bootstrap row degree used to derive sparse taps.
    pub max_degree: usize,
    /// Emitted syndrome rows.
    pub symbols: Vec<SyndromeSymbol>,
}

impl RatelessSyndrome {
    /// Wire bytes for syndrome values when taps are derived from `(seed, id)`.
    ///
    /// The in-memory frame keeps taps for deterministic tests and local decode,
    /// but the sender does not need to serialize them: row ids are contiguous
    /// and coefficients are reproducible from the frame seed.
    #[must_use]
    pub fn encoded_value_bytes(&self) -> usize {
        self.symbols.len()
    }

    /// Number of non-zero syndrome values in this frame.
    #[must_use]
    pub fn syndrome_weight(&self) -> usize {
        self.symbols
            .iter()
            .filter(|symbol| !symbol.value.is_zero())
            .count()
    }

    /// Syndrome-value bytes emitted versus the zero-error side-information
    /// floor implied by this `[n, k, d]` shape.
    #[must_use]
    pub fn floor_gap_report(&self) -> SyndromeFloorGapReport {
        SyndromeFloorGapReport::new(self.shape.n, self.shape.k, self.encoded_value_bytes())
    }

    /// Convert this syndrome to a compact sidecar-free wire frame.
    ///
    /// Taps are intentionally omitted: the receiver reconstructs them from
    /// `(shape, seed, degree window, row id)`, so only syndrome values cross
    /// the wire.
    pub fn to_compact_wire_frame(&self) -> Result<CompactRatelessSyndromeFrame, SlepianWolfError> {
        let first_symbol_id = self.symbols.first().map_or(0, |symbol| symbol.id);
        let mut values = Vec::with_capacity(self.symbols.len());
        for (offset, symbol) in self.symbols.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?;
            let expected = first_symbol_id.checked_add(offset).ok_or(
                SlepianWolfError::SyndromeSymbolIdOverflow {
                    first_symbol_id,
                    offset,
                },
            )?;
            if symbol.id != expected {
                return Err(SlepianWolfError::NonContiguousSyndromeRows {
                    expected,
                    actual: symbol.id,
                });
            }
            values.push(symbol.value.raw());
        }

        Ok(CompactRatelessSyndromeFrame {
            schema: ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA.to_string(),
            n: u64::try_from(self.shape.n)
                .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?,
            k: u64::try_from(self.shape.k)
                .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?,
            d: u64::try_from(self.shape.d)
                .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?,
            seed: self.seed,
            min_degree: u64::try_from(self.min_degree)
                .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?,
            max_degree: u64::try_from(self.max_degree)
                .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?,
            first_symbol_id,
            values,
        })
    }
}

/// Compact serde-ready syndrome frame.
///
/// This is the B-8.11 non-interactive wire shape: no receiver signature
/// sidecar and no serialized sparse matrix, just deterministic row metadata
/// plus raw syndrome values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRatelessSyndromeFrame {
    /// Stable schema marker.
    pub schema: String,
    /// Number of source symbols.
    pub n: u64,
    /// Information symbols.
    pub k: u64,
    /// Minimum-distance design hint.
    pub d: u64,
    /// Seed used to derive rows.
    pub seed: u64,
    /// Minimum non-bootstrap row degree.
    pub min_degree: u64,
    /// Maximum non-bootstrap row degree.
    pub max_degree: u64,
    /// First row id represented by `values`.
    pub first_symbol_id: u64,
    /// Raw GF(256) syndrome values.
    pub values: Vec<u8>,
}

impl CompactRatelessSyndromeFrame {
    /// Rehydrate this compact frame into the in-memory syndrome representation.
    pub fn into_rateless_syndrome(self) -> Result<RatelessSyndrome, SlepianWolfError> {
        if self.schema != ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA {
            return Err(SlepianWolfError::UnsupportedWireSchema {
                schema: self.schema,
            });
        }

        let shape = LdpcShape::new(
            usize_from_wire("n", self.n)?,
            usize_from_wire("k", self.k)?,
            usize_from_wire("d", self.d)?,
        )?;
        let config = RatelessLdpcConfig::new(
            shape,
            self.seed,
            usize_from_wire("min_degree", self.min_degree)?,
            usize_from_wire("max_degree", self.max_degree)?,
        )?;

        let mut symbols = Vec::with_capacity(self.values.len());
        for (offset, value) in self.values.into_iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?;
            let id = self.first_symbol_id.checked_add(offset).ok_or(
                SlepianWolfError::SyndromeSymbolIdOverflow {
                    first_symbol_id: self.first_symbol_id,
                    offset,
                },
            )?;
            let taps = derive_ldpc_taps(config, id);
            symbols.push(SyndromeSymbol {
                id,
                taps,
                value: Gf256::new(value),
            });
        }

        Ok(RatelessSyndrome {
            schema: ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA,
            shape,
            seed: self.seed,
            min_degree: config.min_degree,
            max_degree: config.max_degree,
            symbols,
        })
    }
}

/// Byte-symbol floor/gap accounting for a Slepian-Wolf syndrome frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyndromeFloorGapReport {
    /// Source byte-symbols represented by the coded region.
    pub source_symbols: usize,
    /// Byte-symbols assumed known from receiver side information.
    pub side_info_symbols: usize,
    /// Zero-error byte-symbol floor, `source_symbols - side_info_symbols`.
    pub floor_bytes: usize,
    /// Syndrome value bytes actually emitted.
    pub syndrome_value_bytes: usize,
    /// Bytes above the floor. Saturates at zero when a frame is below the floor
    /// due to an intentionally partial rateless window.
    pub gap_bytes: usize,
    /// `gap_bytes / floor_bytes` in per-mille units; `None` for a zero floor.
    pub gap_over_floor_per_mille: Option<u64>,
}

impl SyndromeFloorGapReport {
    /// Build deterministic syndrome accounting from source/side-info counts.
    #[must_use]
    pub fn new(
        source_symbols: usize,
        side_info_symbols: usize,
        syndrome_value_bytes: usize,
    ) -> Self {
        let side_info_symbols = side_info_symbols.min(source_symbols);
        let floor_bytes = source_symbols - side_info_symbols;
        let gap_bytes = syndrome_value_bytes.saturating_sub(floor_bytes);
        let gap_over_floor_per_mille = if floor_bytes == 0 {
            None
        } else {
            Some(saturating_per_mille(gap_bytes, floor_bytes))
        };
        Self {
            source_symbols,
            side_info_symbols,
            floor_bytes,
            syndrome_value_bytes,
            gap_bytes,
            gap_over_floor_per_mille,
        }
    }
}

/// Belief-propagation / peeling progress metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpDecodeReport {
    /// Whether all source symbols were recovered.
    pub converged: bool,
    /// Number of peeling passes executed for the converged window.
    pub iterations: usize,
    /// Syndrome rows consumed when decoding stopped.
    pub used_symbols: usize,
    /// Additional rows pulled after the initial window.
    pub pulled_symbols: usize,
    /// Failed windows that made no complete decode before pulling more rows.
    pub stalled_windows: usize,
    /// Source symbols known at stop time.
    pub known_symbols: usize,
    /// Non-zero syndrome values in the consumed window.
    pub syndrome_weight: usize,
}

/// Successful BP decode output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpDecodeResult {
    /// Recovered new region bytes.
    pub bytes: Vec<u8>,
    /// Convergence report.
    pub report: BpDecodeReport,
}

/// Sidecar-free syndrome payload for one sender chunk missing at the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingChunkSyndrome {
    /// Sender chunk represented by this syndrome frame.
    pub chunk: CasChunkRef,
    /// Number of source bytes in the sender chunk.
    pub source_symbols: usize,
    /// Receiver side-information bytes assumed by this first slice.
    pub side_info_symbols: usize,
    /// Initial contiguous syndrome rows a receiver should try before pulling
    /// more rateless rows.
    pub initial_symbols: usize,
    /// Deterministic syndrome frame.
    pub frame: RatelessSyndrome,
}

impl MissingChunkSyndrome {
    /// Wire bytes for this frame's syndrome values.
    #[must_use]
    pub fn encoded_value_bytes(&self) -> usize {
        self.frame.encoded_value_bytes()
    }

    /// Syndrome-value bytes emitted versus this chunk's side-information floor.
    #[must_use]
    pub fn floor_gap_report(&self) -> SyndromeFloorGapReport {
        SyndromeFloorGapReport::new(
            self.source_symbols,
            self.side_info_symbols,
            self.encoded_value_bytes(),
        )
    }
}

/// Sender-side Slepian-Wolf package that does not require receiver signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarFreeSyndromePlan {
    /// Stable schema marker.
    pub schema: &'static str,
    /// Per-missing-chunk syndrome frames.
    pub chunks: Vec<MissingChunkSyndrome>,
    /// Actual syndrome value bytes emitted by `chunks`.
    pub payload_bytes: u64,
    /// Whole missing chunk bytes represented before syndrome coding.
    pub whole_chunk_bytes: u64,
    /// Receiver sidecar/signature bytes required by this package.
    pub receiver_sidecar_bytes: u64,
}

impl SidecarFreeSyndromePlan {
    /// This package can be sent without receiver-side subchunk signatures.
    #[must_use]
    pub const fn is_sidecar_free(&self) -> bool {
        self.receiver_sidecar_bytes == 0
    }

    /// Aggregate syndrome-value bytes emitted versus the package floor.
    #[must_use]
    pub fn floor_gap_report(&self) -> SyndromeFloorGapReport {
        let source_symbols = self
            .chunks
            .iter()
            .map(|chunk| chunk.source_symbols)
            .sum::<usize>();
        let side_info_symbols = self
            .chunks
            .iter()
            .map(|chunk| chunk.side_info_symbols)
            .sum::<usize>();
        SyndromeFloorGapReport::new(
            source_symbols,
            side_info_symbols,
            u64_to_saturating_usize(self.payload_bytes),
        )
    }
}

/// B-8.11 deterministic foundation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlepianWolfError {
    /// Invalid `[n, k, d]` shape.
    InvalidShape {
        n: usize,
        k: usize,
        d: usize,
        reason: &'static str,
    },
    /// Invalid rateless row-degree window.
    InvalidDegreeWindow {
        min_degree: usize,
        max_degree: usize,
    },
    /// Source bytes did not match the configured shape.
    SourceLengthMismatch { expected: usize, actual: usize },
    /// Old side information did not match the configured shape.
    SideInfoLengthMismatch { expected: usize, actual: usize },
    /// An uncertainty index is outside the region.
    UncertainIndexOutOfRange { index: usize, len: usize },
    /// Sender or receiver CAS did not contain the manifest chunk bytes.
    MissingChunk { side: ChunkSide, chunk_index: u32 },
    /// Stored chunk bytes did not match the manifest size.
    ChunkSizeMismatch {
        side: ChunkSide,
        chunk_index: u32,
        expected: u64,
        actual: usize,
    },
    /// A consumed syndrome row contradicts the known side information.
    SyndromeContradiction { symbol_id: u64 },
    /// BP could not recover all symbols from the available rows.
    DecodeStalled {
        known_symbols: usize,
        source_symbols: usize,
        used_symbols: usize,
    },
    /// Syndrome payload accounting overflowed.
    SyndromePayloadSizeOverflow,
    /// Wire frame used an unsupported schema marker.
    UnsupportedWireSchema { schema: String },
    /// Wire shape value cannot be represented on this target.
    WireShapeValueOutOfRange { field: &'static str, value: u64 },
    /// Compact wire frames require contiguous row ids.
    NonContiguousSyndromeRows { expected: u64, actual: u64 },
    /// Row id arithmetic overflowed while decoding a compact frame.
    SyndromeSymbolIdOverflow { first_symbol_id: u64, offset: u64 },
}

impl fmt::Display for SlepianWolfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShape { n, k, d, reason } => {
                write!(f, "invalid LDPC shape [n={n}, k={k}, d={d}]: {reason}")
            }
            Self::InvalidDegreeWindow {
                min_degree,
                max_degree,
            } => write!(
                f,
                "invalid LDPC degree window: min={min_degree}, max={max_degree}"
            ),
            Self::SourceLengthMismatch { expected, actual } => write!(
                f,
                "source length {actual} does not match LDPC shape n={expected}"
            ),
            Self::SideInfoLengthMismatch { expected, actual } => write!(
                f,
                "side-information length {actual} does not match LDPC shape n={expected}"
            ),
            Self::UncertainIndexOutOfRange { index, len } => {
                write!(
                    f,
                    "uncertain source index {index} is outside region len {len}"
                )
            }
            Self::MissingChunk { side, chunk_index } => {
                write!(f, "missing {side} chunk bytes for chunk {chunk_index}")
            }
            Self::ChunkSizeMismatch {
                side,
                chunk_index,
                expected,
                actual,
            } => write!(
                f,
                "{side} chunk {chunk_index} size mismatch: expected {expected}, got {actual}"
            ),
            Self::SyndromeContradiction { symbol_id } => {
                write!(
                    f,
                    "syndrome row {symbol_id} contradicts known side information"
                )
            }
            Self::DecodeStalled {
                known_symbols,
                source_symbols,
                used_symbols,
            } => write!(
                f,
                "BP decode stalled after {used_symbols} syndrome rows: {known_symbols}/{source_symbols} symbols known"
            ),
            Self::SyndromePayloadSizeOverflow => {
                f.write_str("Slepian-Wolf syndrome payload size overflowed")
            }
            Self::UnsupportedWireSchema { schema } => {
                write!(f, "unsupported Slepian-Wolf syndrome schema: {schema}")
            }
            Self::WireShapeValueOutOfRange { field, value } => write!(
                f,
                "Slepian-Wolf wire shape field {field}={value} is out of range"
            ),
            Self::NonContiguousSyndromeRows { expected, actual } => write!(
                f,
                "compact syndrome rows must be contiguous: expected row {expected}, got {actual}"
            ),
            Self::SyndromeSymbolIdOverflow {
                first_symbol_id,
                offset,
            } => write!(
                f,
                "syndrome row id overflow from first row {first_symbol_id} and offset {offset}"
            ),
        }
    }
}

impl std::error::Error for SlepianWolfError {}

/// Which side of a changed-region localization failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkSide {
    /// Sender/new side.
    Sender,
    /// Receiver/old side.
    Receiver,
}

impl fmt::Display for ChunkSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sender => f.write_str("sender"),
            Self::Receiver => f.write_str("receiver"),
        }
    }
}

/// Localize same-position changed chunks into byte regions.
pub fn localize_manifest_changed_regions(
    sender: &PersistentChunkManifest,
    sender_store: &ContentAddressedChunkStore,
    receiver: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
) -> Result<Vec<SlepianWolfChangedRegion>, SlepianWolfError> {
    let mut regions = Vec::new();
    for sender_chunk in &sender.chunks {
        let Some(receiver_chunk) = receiver.chunks.get(sender_chunk.index as usize) else {
            continue;
        };
        if sender_chunk.content_id == receiver_chunk.content_id {
            continue;
        }

        let new_chunk = checked_chunk_payload(
            sender_store,
            &sender_chunk.content_id,
            sender_chunk.index,
            sender_chunk.size_bytes,
            ChunkSide::Sender,
        )?;
        let old_chunk = checked_chunk_payload(
            receiver_store,
            &receiver_chunk.content_id,
            receiver_chunk.index,
            receiver_chunk.size_bytes,
            ChunkSide::Receiver,
        )?;
        if let Some((relative_offset, old_bytes, new_bytes)) =
            localize_changed_bytes(old_chunk, new_chunk)
        {
            regions.push(SlepianWolfChangedRegion {
                chunk_index: sender_chunk.index,
                byte_offset: sender_chunk.byte_offset + relative_offset as u64,
                old_bytes,
                new_bytes,
            });
        }
    }
    Ok(regions)
}

/// Trim equal prefix/suffix bytes from an old/new region pair.
#[must_use]
pub fn localize_changed_bytes(old: &[u8], new: &[u8]) -> Option<(usize, Vec<u8>, Vec<u8>)> {
    if old == new {
        return None;
    }

    let min_len = old.len().min(new.len());
    let mut prefix = 0usize;
    while prefix < min_len && old[prefix] == new[prefix] {
        prefix += 1;
    }

    let mut suffix = 0usize;
    while suffix < min_len.saturating_sub(prefix)
        && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
    {
        suffix += 1;
    }

    Some((
        prefix,
        old[prefix..old.len() - suffix].to_vec(),
        new[prefix..new.len() - suffix].to_vec(),
    ))
}

/// Encode `source` into `symbol_count` deterministic rateless syndrome rows.
pub fn encode_rateless_syndrome(
    source: &[u8],
    config: RatelessLdpcConfig,
    symbol_count: usize,
) -> Result<RatelessSyndrome, SlepianWolfError> {
    if source.len() != config.shape.n {
        return Err(SlepianWolfError::SourceLengthMismatch {
            expected: config.shape.n,
            actual: source.len(),
        });
    }

    let mut symbols = Vec::with_capacity(symbol_count);
    for id in 0..symbol_count {
        let id = u64::try_from(id).map_err(|_| SlepianWolfError::InvalidShape {
            n: config.shape.n,
            k: config.shape.k,
            d: config.shape.d,
            reason: "symbol id exceeds u64",
        })?;
        let taps = derive_ldpc_taps(config, id);
        let value = evaluate_symbol(source, &taps);
        symbols.push(SyndromeSymbol { id, taps, value });
    }

    Ok(RatelessSyndrome {
        schema: ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA,
        shape: config.shape,
        seed: config.seed,
        min_degree: config.min_degree,
        max_degree: config.max_degree,
        symbols,
    })
}

/// Encode missing sender chunks as sidecar-free Slepian-Wolf syndrome frames.
///
/// This is the non-interactive append-tail lever: for chunks absent from the
/// receiver manifest/CAS, the sender can emit systematic syndrome values derived
/// only from its local CAS. The receiver needs no subchunk signature sidecar; it
/// decodes with every byte marked uncertain and verifies the final manifest.
pub fn encode_missing_chunk_syndrome_plan(
    base_plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
    seed: u64,
    rateless_margin_symbols: usize,
) -> Result<SidecarFreeSyndromePlan, SlepianWolfError> {
    let mut chunks = Vec::with_capacity(base_plan.missing_chunks.len());
    let mut payload_bytes = 0u64;

    for chunk in &base_plan.missing_chunks {
        let payload = checked_chunk_payload(
            sender_store,
            &chunk.content_id,
            chunk.index,
            chunk.size_bytes,
            ChunkSide::Sender,
        )?;
        let shape = LdpcShape::new(payload.len(), 0, 1)?;
        let config = RatelessLdpcConfig::foundation(shape, syndrome_chunk_seed(seed, chunk))?;
        let initial_symbols = shape.design_syndrome_symbols();
        let symbol_count = initial_symbols
            .checked_add(rateless_margin_symbols)
            .ok_or(SlepianWolfError::SyndromePayloadSizeOverflow)?;
        let frame = encode_rateless_syndrome(payload, config, symbol_count)?;
        let encoded_value_bytes = u64::try_from(frame.encoded_value_bytes())
            .map_err(|_| SlepianWolfError::SyndromePayloadSizeOverflow)?;
        payload_bytes = payload_bytes
            .checked_add(encoded_value_bytes)
            .ok_or(SlepianWolfError::SyndromePayloadSizeOverflow)?;
        chunks.push(MissingChunkSyndrome {
            chunk: chunk.clone(),
            source_symbols: payload.len(),
            side_info_symbols: 0,
            initial_symbols,
            frame,
        });
    }

    Ok(SidecarFreeSyndromePlan {
        schema: ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA,
        chunks,
        payload_bytes,
        whole_chunk_bytes: base_plan.missing_bytes,
        receiver_sidecar_bytes: 0,
    })
}

/// Decode a rateless syndrome, pulling more rows when BP stalls.
///
/// This explicit-erasure entry point is useful when a harness or future
/// reliability model already knows which old side-information positions are
/// uncertain. Use [`decode_with_old_file_side_information`] when the receiver
/// has only the old region bytes and no uncertainty sidecar.
pub fn decode_with_side_information(
    frame: &RatelessSyndrome,
    old_side_info: &[u8],
    uncertain_indices: &[usize],
    initial_symbols: usize,
) -> Result<BpDecodeResult, SlepianWolfError> {
    if old_side_info.len() != frame.shape.n {
        return Err(SlepianWolfError::SideInfoLengthMismatch {
            expected: frame.shape.n,
            actual: old_side_info.len(),
        });
    }
    validate_uncertain_indices(uncertain_indices, frame.shape.n)?;

    let mut used_symbols = initial_symbols.min(frame.symbols.len());
    let mut stalled_windows = 0usize;
    loop {
        let attempt =
            attempt_peeling_decode(frame, old_side_info, uncertain_indices, used_symbols)?;
        if let Some(bytes) = attempt.bytes {
            let report = BpDecodeReport {
                converged: true,
                iterations: attempt.iterations,
                used_symbols,
                pulled_symbols: used_symbols.saturating_sub(initial_symbols),
                stalled_windows,
                known_symbols: frame.shape.n,
                syndrome_weight: syndrome_weight(&frame.symbols[..used_symbols]),
            };
            return Ok(BpDecodeResult { bytes, report });
        }
        if used_symbols == frame.symbols.len() {
            return Err(SlepianWolfError::DecodeStalled {
                known_symbols: attempt.known_symbols,
                source_symbols: frame.shape.n,
                used_symbols,
            });
        }
        stalled_windows += 1;
        used_symbols += 1;
    }
}

/// Decode a rateless syndrome from only receiver old-file side information.
///
/// The receiver starts with its old byte region as the prior and solves the
/// sparse delta vector `new ^ old` from syndrome residuals. The first rows of
/// the deterministic schedule are singleton bootstrap checks, so unchanged
/// bytes are proven as zero deltas and changed bytes are recovered without a
/// receiver signature sidecar. Additional rateless rows are pulled until BP
/// peels every delta or fails closed.
pub fn decode_with_old_file_side_information(
    frame: &RatelessSyndrome,
    old_side_info: &[u8],
    initial_symbols: usize,
) -> Result<BpDecodeResult, SlepianWolfError> {
    if old_side_info.len() != frame.shape.n {
        return Err(SlepianWolfError::SideInfoLengthMismatch {
            expected: frame.shape.n,
            actual: old_side_info.len(),
        });
    }

    let mut used_symbols = initial_symbols.min(frame.symbols.len());
    let mut stalled_windows = 0usize;
    loop {
        let attempt = attempt_side_info_delta_decode(frame, old_side_info, used_symbols)?;
        if let Some(bytes) = attempt.bytes {
            let report = BpDecodeReport {
                converged: true,
                iterations: attempt.iterations,
                used_symbols,
                pulled_symbols: used_symbols.saturating_sub(initial_symbols),
                stalled_windows,
                known_symbols: frame.shape.n,
                syndrome_weight: syndrome_weight(&frame.symbols[..used_symbols]),
            };
            return Ok(BpDecodeResult { bytes, report });
        }
        if used_symbols == frame.symbols.len() {
            return Err(SlepianWolfError::DecodeStalled {
                known_symbols: attempt.known_symbols,
                source_symbols: frame.shape.n,
                used_symbols,
            });
        }
        stalled_windows += 1;
        used_symbols += 1;
    }
}

/// Decode a missing-chunk syndrome with no receiver side information.
pub fn decode_missing_chunk_syndrome(
    frame: &RatelessSyndrome,
    initial_symbols: usize,
) -> Result<BpDecodeResult, SlepianWolfError> {
    let old_side_info = vec![0u8; frame.shape.n];
    decode_with_old_file_side_information(frame, &old_side_info, initial_symbols)
}

fn syndrome_chunk_seed(seed: u64, chunk: &CasChunkRef) -> u64 {
    seed ^ u64::from(chunk.index).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ chunk.byte_offset.rotate_left(17)
        ^ chunk.size_bytes.rotate_left(31)
}

fn checked_chunk_payload<'a>(
    store: &'a ContentAddressedChunkStore,
    content_id: &crate::atp::object::ContentId,
    chunk_index: u32,
    expected_size: u64,
    side: ChunkSide,
) -> Result<&'a [u8], SlepianWolfError> {
    let Some(payload) = store.get(content_id) else {
        return Err(SlepianWolfError::MissingChunk { side, chunk_index });
    };
    if payload.len() as u64 != expected_size {
        return Err(SlepianWolfError::ChunkSizeMismatch {
            side,
            chunk_index,
            expected: expected_size,
            actual: payload.len(),
        });
    }
    Ok(payload)
}

fn usize_from_wire(field: &'static str, value: u64) -> Result<usize, SlepianWolfError> {
    usize::try_from(value).map_err(|_| SlepianWolfError::WireShapeValueOutOfRange { field, value })
}

fn derive_ldpc_taps(config: RatelessLdpcConfig, symbol_id: u64) -> Vec<LdpcTap> {
    let n = config.shape.n;
    if symbol_id < n as u64 {
        return vec![LdpcTap {
            index: symbol_id as usize,
            coefficient: Gf256::ONE,
        }];
    }

    let degree_span = config
        .max_degree
        .saturating_sub(config.min_degree)
        .saturating_add(1);
    let mut rng = config.seed ^ symbol_id.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let degree = config
        .min_degree
        .saturating_add((splitmix64(&mut rng) as usize) % degree_span)
        .min(n);

    let mut used = BTreeSet::new();
    let mut taps = Vec::with_capacity(degree);
    while taps.len() < degree {
        let index = (splitmix64(&mut rng) as usize) % n;
        if !used.insert(index) {
            continue;
        }
        let coefficient = nonzero_coefficient(splitmix64(&mut rng));
        taps.push(LdpcTap { index, coefficient });
    }
    taps.sort_by_key(|tap| tap.index);
    taps
}

fn evaluate_symbol(source: &[u8], taps: &[LdpcTap]) -> Gf256 {
    taps.iter().fold(Gf256::ZERO, |acc, tap| {
        acc + tap.coefficient * Gf256::new(source[tap.index])
    })
}

#[derive(Debug)]
struct DecodeAttempt {
    bytes: Option<Vec<u8>>,
    iterations: usize,
    known_symbols: usize,
}

fn attempt_peeling_decode(
    frame: &RatelessSyndrome,
    old_side_info: &[u8],
    uncertain_indices: &[usize],
    used_symbols: usize,
) -> Result<DecodeAttempt, SlepianWolfError> {
    let mut values = old_side_info
        .iter()
        .copied()
        .map(|byte| Some(Gf256::new(byte)))
        .collect::<Vec<_>>();
    for &index in uncertain_indices {
        values[index] = None;
    }

    let mut iterations = 0usize;
    loop {
        let mut progressed = false;
        iterations += 1;

        for symbol in &frame.symbols[..used_symbols] {
            let mut residual = symbol.value;
            let mut unknown = None::<LdpcTap>;
            let mut unknown_count = 0usize;

            for tap in &symbol.taps {
                match values[tap.index] {
                    Some(value) => residual = residual - tap.coefficient * value,
                    None => {
                        unknown = Some(*tap);
                        unknown_count += 1;
                    }
                }
            }

            match (unknown_count, unknown) {
                (0, _) if !residual.is_zero() => {
                    return Err(SlepianWolfError::SyndromeContradiction {
                        symbol_id: symbol.id,
                    });
                }
                (1, Some(tap)) => {
                    values[tap.index] = Some(residual / tap.coefficient);
                    progressed = true;
                }
                _ => {}
            }
        }

        if let Some(bytes) = collect_decoded_bytes(&values) {
            return Ok(DecodeAttempt {
                bytes: Some(bytes),
                iterations,
                known_symbols: values.len(),
            });
        }
        if !progressed {
            return Ok(DecodeAttempt {
                bytes: None,
                iterations,
                known_symbols: values.iter().filter(|value| value.is_some()).count(),
            });
        }
    }
}

fn attempt_side_info_delta_decode(
    frame: &RatelessSyndrome,
    old_side_info: &[u8],
    used_symbols: usize,
) -> Result<DecodeAttempt, SlepianWolfError> {
    let old_values = old_side_info
        .iter()
        .copied()
        .map(Gf256::new)
        .collect::<Vec<_>>();
    let mut deltas = vec![None::<Gf256>; frame.shape.n];
    let mut iterations = 0usize;

    loop {
        let mut progressed = false;
        iterations += 1;

        for symbol in &frame.symbols[..used_symbols] {
            let mut residual = symbol.value;
            let mut unknown = None::<LdpcTap>;
            let mut unknown_count = 0usize;

            for tap in &symbol.taps {
                residual = residual - tap.coefficient * old_values[tap.index];
                match deltas[tap.index] {
                    Some(delta) => residual = residual - tap.coefficient * delta,
                    None => {
                        unknown = Some(*tap);
                        unknown_count += 1;
                    }
                }
            }

            match (unknown_count, unknown) {
                (0, _) if !residual.is_zero() => {
                    return Err(SlepianWolfError::SyndromeContradiction {
                        symbol_id: symbol.id,
                    });
                }
                (1, Some(tap)) => {
                    deltas[tap.index] = Some(residual / tap.coefficient);
                    progressed = true;
                }
                _ => {}
            }
        }

        if let Some(bytes) = collect_side_info_decoded_bytes(&old_values, &deltas) {
            return Ok(DecodeAttempt {
                bytes: Some(bytes),
                iterations,
                known_symbols: deltas.len(),
            });
        }
        if !progressed {
            return Ok(DecodeAttempt {
                bytes: None,
                iterations,
                known_symbols: deltas.iter().filter(|delta| delta.is_some()).count(),
            });
        }
    }
}

fn collect_decoded_bytes(values: &[Option<Gf256>]) -> Option<Vec<u8>> {
    values
        .iter()
        .copied()
        .map(|value| value.map(Gf256::raw))
        .collect()
}

fn collect_side_info_decoded_bytes(old: &[Gf256], deltas: &[Option<Gf256>]) -> Option<Vec<u8>> {
    old.iter()
        .copied()
        .zip(deltas.iter().copied())
        .map(|(old, delta)| delta.map(|delta| (old + delta).raw()))
        .collect()
}

fn validate_uncertain_indices(indices: &[usize], len: usize) -> Result<(), SlepianWolfError> {
    for &index in indices {
        if index >= len {
            return Err(SlepianWolfError::UncertainIndexOutOfRange { index, len });
        }
    }
    Ok(())
}

fn syndrome_weight(symbols: &[SyndromeSymbol]) -> usize {
    symbols
        .iter()
        .filter(|symbol| !symbol.value.is_zero())
        .count()
}

fn saturating_per_mille(numerator: usize, denominator: usize) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let value = (numerator as u128)
        .saturating_mul(1000)
        .saturating_div(denominator as u128);
    value.min(u128::from(u64::MAX)) as u64
}

fn u64_to_saturating_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn nonzero_coefficient(word: u64) -> Gf256 {
    let byte = (word as u8).wrapping_add(1);
    if byte == 0 {
        Gf256::ONE
    } else {
        Gf256::new(byte)
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::delta::{
        ContentAddressedChunkStore, PersistentChunkManifest,
        plan_incremental_resync_from_verified_receiver_manifest,
    };
    use proptest::prelude::*;

    const SMALL_APPEND_LIKE_DELTA_BYTES: usize = 4 * 1024;
    const COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES: usize = 14 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct SyndromeSidecarMeasurement {
        append_delta_bytes: usize,
        syndrome_value_bytes: usize,
        receiver_sidecar_baseline_bytes: usize,
    }

    impl SyndromeSidecarMeasurement {
        fn syndrome_minus_sidecar_bytes(self) -> usize {
            self.syndrome_value_bytes
                .saturating_sub(self.receiver_sidecar_baseline_bytes)
        }

        fn sidecar_minus_syndrome_bytes(self) -> usize {
            self.receiver_sidecar_baseline_bytes
                .saturating_sub(self.syndrome_value_bytes)
        }

        fn syndrome_to_sidecar_ratio_milli(self) -> usize {
            self.syndrome_value_bytes * 1000 / self.receiver_sidecar_baseline_bytes
        }
    }

    fn deterministic_append_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|idx| ((idx * 19 + idx / 7 + 3) % 251) as u8)
            .collect()
    }

    fn small_append_like_syndrome_sidecar_measurement() -> SyndromeSidecarMeasurement {
        let append = deterministic_append_payload(SMALL_APPEND_LIKE_DELTA_BYTES);
        let shape = LdpcShape::new(append.len(), 0, 1).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0x51de_cafe).expect("config");
        let frame =
            encode_rateless_syndrome(&append, config, shape.n).expect("small append syndrome");

        SyndromeSidecarMeasurement {
            append_delta_bytes: append.len(),
            syndrome_value_bytes: frame.encoded_value_bytes(),
            receiver_sidecar_baseline_bytes: COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES,
        }
    }

    #[test]
    fn localize_chunks_then_rateless_syndrome_decode_round_trips() {
        let old = b"AAabcdefgZZ".to_vec();
        let new = b"AAxbcydZgZZ".to_vec();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender_report = sender_store
            .ingest_ordered_chunks([new.as_slice()])
            .expect("sender ingest");
        let receiver_report = receiver_store
            .ingest_ordered_chunks([old.as_slice()])
            .expect("receiver ingest");
        let sender_manifest =
            PersistentChunkManifest::new("tree", sender_report.chunks).expect("sender manifest");
        let receiver_manifest = PersistentChunkManifest::new("tree", receiver_report.chunks)
            .expect("receiver manifest");

        let regions = localize_manifest_changed_regions(
            &sender_manifest,
            &sender_store,
            &receiver_manifest,
            &receiver_store,
        )
        .expect("changed regions");
        assert_eq!(regions.len(), 1);

        let region = &regions[0];
        assert_eq!(region.byte_offset, 2);
        assert_eq!(region.old_bytes, b"abcdef");
        assert_eq!(region.new_bytes, b"xbcydZ");
        let uncertain = region.truth_uncertain_indices();
        assert_eq!(uncertain, vec![0, 3, 4, 5]);

        let shape = LdpcShape::new(
            region.source_symbols(),
            region.source_symbols() - uncertain.len(),
            3,
        )
        .expect("shape");
        assert_eq!(shape.design_syndrome_symbols(), uncertain.len());
        assert_eq!(shape.rate().as_f64(), 2.0 / 6.0);

        let config = RatelessLdpcConfig::foundation(shape, 0x51ed_1d0c).expect("config");
        let frame = encode_rateless_syndrome(&region.new_bytes, config, shape.n).expect("syndrome");
        assert_eq!(frame.schema, ATP_SLEPIAN_WOLF_SYNDROME_SCHEMA);
        assert!(frame.syndrome_weight() > 0);
        assert_eq!(
            frame.floor_gap_report(),
            SyndromeFloorGapReport {
                source_symbols: 6,
                side_info_symbols: 2,
                floor_bytes: 4,
                syndrome_value_bytes: 6,
                gap_bytes: 2,
                gap_over_floor_per_mille: Some(500),
            }
        );

        let decoded = decode_with_side_information(&frame, &region.old_bytes, &uncertain, 1)
            .expect("bp decode");
        assert_eq!(decoded.bytes, region.new_bytes);
        assert!(decoded.report.converged);
        assert_eq!(decoded.report.used_symbols, 6);
        assert_eq!(decoded.report.pulled_symbols, 5);
        assert!(decoded.report.stalled_windows > 0);
        assert_eq!(decoded.report.known_symbols, region.source_symbols());
        assert!(decoded.report.syndrome_weight > 0);
    }

    #[test]
    fn bp_decode_old_file_side_info_recovers_sparse_edits_without_uncertainty_sidecar() {
        let old = b"0123456789abcdef".to_vec();
        let mut new = old.clone();
        new[0] = b'X';
        new[7] = b'Y';
        new[15] = b'Z';

        let changed_symbols = old
            .iter()
            .zip(new.iter())
            .filter(|(old, new)| old != new)
            .count();
        let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0xdec0_de01).expect("config");
        let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

        let decoded =
            decode_with_old_file_side_information(&frame, &old, shape.design_syndrome_symbols())
                .expect("old-file side-info BP decode");

        assert_eq!(decoded.bytes, new);
        assert!(decoded.report.converged);
        assert_eq!(decoded.report.used_symbols, shape.n);
        assert_eq!(
            decoded.report.pulled_symbols,
            shape.n - shape.design_syndrome_symbols()
        );
        assert!(decoded.report.stalled_windows > 0);
        assert_eq!(decoded.report.known_symbols, shape.n);
        assert!(decoded.report.syndrome_weight > 0);
    }

    #[test]
    fn sidecar_free_missing_append_syndrome_beats_rsync_target() {
        let base = vec![0x31; 5 * 1024 * 1024];
        let append = deterministic_append_payload(64 * 1024);

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender_report = sender_store
            .ingest_ordered_chunks([base.as_slice(), append.as_slice()])
            .expect("sender ingest");
        let receiver_report = receiver_store
            .ingest_ordered_chunks([base.as_slice()])
            .expect("receiver ingest");
        let sender_manifest =
            PersistentChunkManifest::new("tree", sender_report.chunks).expect("sender manifest");
        let receiver_manifest = PersistentChunkManifest::new("tree", receiver_report.chunks)
            .expect("receiver manifest");

        let delta_plan = plan_incremental_resync_from_verified_receiver_manifest(
            &sender_manifest,
            Some(&receiver_manifest),
        );
        assert_eq!(delta_plan.missing_chunks.len(), 1);
        assert_eq!(delta_plan.missing_bytes, append.len() as u64);

        let syndrome_plan =
            encode_missing_chunk_syndrome_plan(&delta_plan, &sender_store, 0x51de_cafe, 0)
                .expect("syndrome plan");

        assert!(syndrome_plan.is_sidecar_free());
        assert_eq!(syndrome_plan.payload_bytes, append.len() as u64);
        assert_eq!(syndrome_plan.whole_chunk_bytes, append.len() as u64);
        assert!(syndrome_plan.payload_bytes < 96 * 1024);
        assert_eq!(
            syndrome_plan.floor_gap_report(),
            SyndromeFloorGapReport {
                source_symbols: append.len(),
                side_info_symbols: 0,
                floor_bytes: append.len(),
                syndrome_value_bytes: append.len(),
                gap_bytes: 0,
                gap_over_floor_per_mille: Some(0),
            }
        );

        let chunk = &syndrome_plan.chunks[0];
        assert_eq!(chunk.side_info_symbols, 0);
        assert_eq!(chunk.initial_symbols, append.len());
        assert_eq!(chunk.encoded_value_bytes(), append.len());
        assert_eq!(chunk.floor_gap_report(), syndrome_plan.floor_gap_report());
        let decoded = decode_missing_chunk_syndrome(&chunk.frame, chunk.initial_symbols)
            .expect("missing chunk decode");
        assert_eq!(decoded.bytes, append);
    }

    #[test]
    fn small_append_like_syndrome_measurement_beats_compact_sidecar_baseline() {
        let measurement = small_append_like_syndrome_sidecar_measurement();

        assert_eq!(
            measurement.append_delta_bytes,
            SMALL_APPEND_LIKE_DELTA_BYTES
        );
        assert_eq!(measurement.syndrome_value_bytes, 4_096);
        assert_eq!(
            measurement.receiver_sidecar_baseline_bytes,
            COMPACT_RECEIVER_SIDECAR_BASELINE_BYTES
        );
        assert_eq!(measurement.syndrome_minus_sidecar_bytes(), 0);
        assert_eq!(measurement.sidecar_minus_syndrome_bytes(), 10_240);
        assert_eq!(measurement.syndrome_to_sidecar_ratio_milli(), 285);
    }

    #[test]
    fn old_file_side_info_decode_reports_stall_when_rows_are_exhausted() {
        let source = b"wxyz";
        let old = b"abcd";
        let shape = LdpcShape::new(4, 0, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 7).expect("config");
        let frame = encode_rateless_syndrome(source, config, 2).expect("syndrome");
        let err = decode_with_old_file_side_information(&frame, old, 1)
            .expect_err("not enough rows to decode all side-info deltas");

        assert_eq!(
            err,
            SlepianWolfError::DecodeStalled {
                known_symbols: 2,
                source_symbols: 4,
                used_symbols: 2,
            }
        );
    }

    #[test]
    fn bp_decode_reports_stall_when_syndrome_window_is_exhausted() {
        let source = b"wxyz";
        let old = b"abcd";
        let shape = LdpcShape::new(4, 0, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 7).expect("config");
        let frame = encode_rateless_syndrome(source, config, 2).expect("syndrome");
        let err = decode_with_side_information(&frame, old, &[0, 1, 2, 3], 1)
            .expect_err("not enough rows to decode all erasures");

        assert_eq!(
            err,
            SlepianWolfError::DecodeStalled {
                known_symbols: 2,
                source_symbols: 4,
                used_symbols: 2,
            }
        );
    }

    #[test]
    fn compact_syndrome_wire_frame_round_trips_without_serialized_taps() {
        let old = b"same-prefix-012345".to_vec();
        let mut new = old.clone();
        new[3] = b'X';
        new[14] = b'Y';

        let changed_symbols = old
            .iter()
            .zip(new.iter())
            .filter(|(old, new)| old != new)
            .count();
        let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0xfeed_51de).expect("config");
        let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

        let wire = frame.to_compact_wire_frame().expect("compact wire frame");
        assert_eq!(wire.values.len(), frame.symbols.len());
        let wire_json = serde_json::to_string(&wire).expect("serialize compact frame");
        assert!(!wire_json.contains("taps"));

        let decoded_wire: CompactRatelessSyndromeFrame =
            serde_json::from_str(&wire_json).expect("deserialize compact frame");
        let restored = decoded_wire
            .into_rateless_syndrome()
            .expect("restore syndrome");
        assert_eq!(restored.shape, frame.shape);
        assert_eq!(restored.seed, frame.seed);
        assert_eq!(restored.min_degree, frame.min_degree);
        assert_eq!(restored.max_degree, frame.max_degree);
        assert_eq!(restored.symbols, frame.symbols);

        let decoded =
            decode_with_old_file_side_information(&restored, &old, shape.design_syndrome_symbols())
                .expect("compact syndrome decodes");
        assert_eq!(decoded.bytes, new);
    }

    #[test]
    fn compact_syndrome_wire_frame_rejects_non_contiguous_rows() {
        let shape = LdpcShape::new(4, 0, 1).expect("shape");
        let config = RatelessLdpcConfig::foundation(shape, 0x51de).expect("config");
        let mut frame = encode_rateless_syndrome(b"abcd", config, 4).expect("syndrome");
        frame.symbols[1].id = 3;

        assert_eq!(
            frame.to_compact_wire_frame(),
            Err(SlepianWolfError::NonContiguousSyndromeRows {
                expected: 1,
                actual: 3,
            })
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..ProptestConfig::default()
        })]

        #[test]
        fn bp_decode_old_file_side_info_converges_for_random_sparse_edits(
            cells in proptest::collection::vec((any::<u8>(), any::<u8>(), any::<bool>()), 1..65),
            seed in any::<u64>(),
        ) {
            let old = cells.iter().map(|(byte, _, _)| *byte).collect::<Vec<_>>();
            let new = cells
                .iter()
                .map(|(old, raw_delta, should_change)| {
                    if *should_change {
                        *old ^ (*raw_delta | 1)
                    } else {
                        *old
                    }
                })
                .collect::<Vec<_>>();
            let changed_symbols = old
                .iter()
                .zip(new.iter())
                .filter(|(old, new)| old != new)
                .count();
            let shape = LdpcShape::new(new.len(), new.len() - changed_symbols, 3).expect("shape");
            let config = RatelessLdpcConfig::foundation(shape, seed).expect("config");
            let frame = encode_rateless_syndrome(&new, config, shape.n).expect("syndrome");

            let decoded =
                decode_with_old_file_side_information(&frame, &old, shape.design_syndrome_symbols())
                    .expect("old-file side-info BP decode");

            prop_assert_eq!(decoded.bytes, new);
            prop_assert!(decoded.report.converged);
            prop_assert_eq!(decoded.report.known_symbols, shape.n);
            prop_assert!(decoded.report.used_symbols <= shape.n);
            prop_assert_eq!(
                decoded.report.pulled_symbols,
                decoded.report.used_symbols.saturating_sub(shape.design_syndrome_symbols())
            );
        }
    }
}
