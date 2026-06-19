//! Deterministic Slepian-Wolf syndrome foundation for ATP delta regions.
//!
//! B-8.11 builds on the B-8.10 chunk/sub-chunk delta path: first localize the
//! changed byte region with the existing content-addressed chunks, then send a
//! sparse GF(256) syndrome for that region.  This first slice is intentionally
//! a small, testable foundation: shape/rate types, deterministic rateless row
//! generation, syndrome encoding, and a belief-propagation style erasure
//! peeling decoder seeded from the receiver's old bytes.

use std::collections::BTreeSet;
use std::fmt;

use crate::atp::delta::{ContentAddressedChunkStore, PersistentChunkManifest};
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
    /// Emitted syndrome rows.
    pub symbols: Vec<SyndromeSymbol>,
}

impl RatelessSyndrome {
    /// Number of non-zero syndrome values in this frame.
    #[must_use]
    pub fn syndrome_weight(&self) -> usize {
        self.symbols
            .iter()
            .filter(|symbol| !symbol.value.is_zero())
            .count()
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
        symbols,
    })
}

/// Decode a rateless syndrome, pulling more rows when BP stalls.
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

fn collect_decoded_bytes(values: &[Option<Gf256>]) -> Option<Vec<u8>> {
    values
        .iter()
        .copied()
        .map(|value| value.map(Gf256::raw))
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
    use crate::atp::delta::{ContentAddressedChunkStore, PersistentChunkManifest};

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
}
