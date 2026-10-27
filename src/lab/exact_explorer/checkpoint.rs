//! Bounded, portable frontiers for exact schedule campaigns.
//!
//! Checkpoints contain choices and historical counters, never closures or
//! authority to execute code. Their checksum detects corruption, not forgery.
//! Loading a checkpoint does not verify its claimed earlier runs. Resumption
//! requires the caller's matching workload key and execution configuration and
//! checks every saved enabled set against the live scheduler before polling.
//!
//! Decode admission covers encoded bytes and requested prefix/decision/dispatch
//! vector storage, excluding allocator overhead. Shape, counts, exact length
//! and checksum are validated before allocating any of those vectors.

use super::{ExactScheduleDecision, ExactSchedulePrefix, ExactScheduleWorkloadKey, ForcedDispatch};
use crate::runtime::scheduler::DispatchLane;
use crate::trace::replay::CompactTaskId;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const MAGIC: [u8; 8] = *b"ASUPEXP\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 124;
const CHECKSUM_BYTES: usize = 32;
const DISPATCH_BYTES: usize = 29;
const CHECKSUM_DOMAIN: &[u8] = b"asupersync.lab.exact-exploration-checkpoint.v1\0";

/// Cumulative history retained when completed run reports are released.
///
/// These counters describe the producing process's observations. Decoding them
/// does not independently establish that the historical executions occurred.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExactScheduleProgress {
    /// Executions attempted across all batches.
    pub runs: u64,
    /// Executions that reached supported, replayable quiescence.
    pub completed: u64,
    /// Executions that did not reach supported, replayable quiescence.
    pub incomplete: u64,
    /// Executions that did not satisfy the lab test contract.
    pub failed: u64,
    /// Alternative prefixes lost because a campaign's queue was full.
    pub omitted: u64,
}

/// A resumable breadth-first frontier bound to a workload and execution config.
///
/// Completed runs are not retained. Save the canonical bytes and later load
/// them with explicit admission bounds, then pass this checkpoint to
/// [`super::ExactScheduleExplorer::resume`] with the same workload key. The
/// caller owns persistence; this module performs no filesystem I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactScheduleCheckpoint {
    pub(super) workload: ExactScheduleWorkloadKey,
    pub(super) seed: u64,
    pub(super) config_hash: u64,
    pub(super) pending: VecDeque<ExactSchedulePrefix>,
    pub(super) progress: ExactScheduleProgress,
}

/// Explicit admission bounds for checkpoint encoding and decoding.
///
/// Counts are totals across the entire frontier. Zero admits only an empty
/// corresponding collection. The decoded byte bound covers requested vector
/// storage, not allocator overhead or the caller's input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactScheduleCheckpointLimits {
    /// Maximum complete encoded checkpoint, including its checksum.
    pub max_encoded_bytes: usize,
    /// Maximum pending prefixes.
    pub max_prefixes: usize,
    /// Maximum combined decisions in all pending prefixes.
    pub max_decisions: usize,
    /// Maximum combined enabled dispatches in all decisions.
    pub max_dispatches: usize,
    /// Maximum requested decoded prefix, decision and dispatch storage.
    pub max_decoded_bytes: usize,
}

/// Malformed, corrupted or over-budget checkpoint data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExactScheduleCheckpointError {
    /// Unknown magic or format version.
    #[error("unrecognized exact exploration checkpoint format")]
    Format,
    /// Truncated bytes, trailing bytes or inconsistent declared counts.
    #[error("exact exploration checkpoint length or counts disagree")]
    Length,
    /// Checked count conversion or size arithmetic overflowed.
    #[error("exact exploration checkpoint size overflow")]
    Overflow,
    /// The encoded byte admission was exceeded.
    #[error("exact exploration checkpoint encoded byte limit exceeded")]
    ByteLimit,
    /// The pending-prefix admission was exceeded.
    #[error("exact exploration checkpoint prefix limit exceeded")]
    PrefixLimit,
    /// The aggregate decision admission was exceeded.
    #[error("exact exploration checkpoint decision limit exceeded")]
    DecisionLimit,
    /// The aggregate enabled-dispatch admission was exceeded.
    #[error("exact exploration checkpoint dispatch limit exceeded")]
    DispatchLimit,
    /// Requested decoded vector storage exceeded admission.
    #[error("exact exploration checkpoint decoded storage limit exceeded")]
    DecodedLimit,
    /// The checksum did not match the complete checkpoint.
    #[error("exact exploration checkpoint checksum mismatch")]
    Checksum,
    /// Invalid progress, choice, ordering or prefix identity.
    #[error("invalid exact exploration checkpoint shape")]
    Shape,
    /// Bounded vector allocation failed.
    #[error("could not allocate exact exploration checkpoint storage")]
    Allocation,
}

type Error = ExactScheduleCheckpointError;

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn encoded_len(prefixes: usize, decisions: usize, dispatches: usize) -> Result<usize, Error> {
    prefixes
        .checked_mul(8)
        .and_then(|n| decisions.checked_mul(16).and_then(|m| n.checked_add(m)))
        .and_then(|n| {
            dispatches
                .checked_mul(DISPATCH_BYTES)
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(HEADER_BYTES + CHECKSUM_BYTES))
        .ok_or(Error::Overflow)
}

fn check_limits(
    prefixes: usize,
    decisions: usize,
    dispatches: usize,
    limits: ExactScheduleCheckpointLimits,
) -> Result<usize, Error> {
    if prefixes > limits.max_prefixes {
        return Err(Error::PrefixLimit);
    }
    if decisions > limits.max_decisions {
        return Err(Error::DecisionLimit);
    }
    if dispatches > limits.max_dispatches {
        return Err(Error::DispatchLimit);
    }
    let decoded = prefixes
        .checked_mul(std::mem::size_of::<ExactSchedulePrefix>())
        .and_then(|n| {
            decisions
                .checked_mul(std::mem::size_of::<ExactScheduleDecision>())
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| {
            dispatches
                .checked_mul(std::mem::size_of::<ForcedDispatch>())
                .and_then(|m| n.checked_add(m))
        })
        .ok_or(Error::Overflow)?;
    if decoded > limits.max_decoded_bytes {
        return Err(Error::DecodedLimit);
    }
    let encoded = encoded_len(prefixes, decisions, dispatches)?;
    if encoded > limits.max_encoded_bytes {
        return Err(Error::ByteLimit);
    }
    Ok(encoded)
}

fn check_progress(progress: ExactScheduleProgress, prefixes: usize) -> Result<(), Error> {
    if progress.completed.checked_add(progress.incomplete) != Some(progress.runs)
        || progress.failed > progress.runs
        || (progress.runs == 0 && (prefixes != 1 || progress.omitted != 0))
    {
        return Err(Error::Shape);
    }
    Ok(())
}

fn check_choice(
    choice: ForcedDispatch,
    previous: Option<ForcedDispatch>,
    previous_step: u64,
    previous_nanos: u64,
) -> Result<(), Error> {
    if choice.worker() != 0
        || choice.lane() == DispatchLane::Stolen
        || choice.at_step() <= previous_step
        || choice.at_nanos() < previous_nanos
    {
        return Err(Error::Shape);
    }
    if let Some(last) = previous
        && (choice.task().unpack() <= last.task().unpack()
            || choice.lane() != last.lane()
            || choice.at_step() != last.at_step()
            || choice.at_nanos() != last.at_nanos())
    {
        return Err(Error::Shape);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::Overflow)?;
        let slice = self.bytes.get(self.offset..end).ok_or(Error::Length)?;
        let mut value = [0; N];
        value.copy_from_slice(slice);
        self.offset = end;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| Error::Overflow)
    }

    fn dispatch(&mut self) -> Result<ForcedDispatch, Error> {
        let task = CompactTaskId(self.u64()?);
        let worker = u32::from_le_bytes(self.array()?);
        let lane = match self.array::<1>()?[0] {
            0 => DispatchLane::Cancel,
            1 => DispatchLane::Timed,
            2 => DispatchLane::Ready,
            _ => return Err(Error::Shape),
        };
        let step = self.u64()?;
        let nanos = self.u64()?;
        Ok(ForcedDispatch::from_checkpoint_parts(
            task, worker, lane, step, nanos,
        ))
    }
}

fn put_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    let count = u64::try_from(count).map_err(|_| Error::Overflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

impl ExactScheduleCheckpoint {
    /// Caller-supplied identity of the workload code and fixture inputs.
    #[must_use]
    pub const fn workload(&self) -> ExactScheduleWorkloadKey {
        self.workload
    }

    /// Cumulative progress, independent of retained batch reports.
    #[must_use]
    pub const fn progress(&self) -> ExactScheduleProgress {
        self.progress
    }

    /// Number of exact prefixes waiting for another batch.
    #[must_use]
    pub fn pending_prefix_count(&self) -> usize {
        self.pending.len()
    }

    /// Remaining prefixes in their deterministic breadth-first order.
    pub fn pending_prefixes(&self) -> impl ExactSizeIterator<Item = &ExactSchedulePrefix> {
        self.pending.iter()
    }

    /// Encodes the exact frontier and cumulative progress with an integrity hash.
    ///
    /// No completed traces are included. All count and byte admission occurs
    /// before allocating the output. The hash is not an authentication scheme.
    ///
    /// # Errors
    /// Refuses invalid shape, insufficient admission, overflow or allocation failure.
    pub fn to_canonical_bytes(
        &self,
        limits: ExactScheduleCheckpointLimits,
    ) -> Result<Vec<u8>, Error> {
        check_progress(self.progress, self.pending.len())?;
        let mut decisions = 0usize;
        let mut dispatches = 0usize;
        for prefix in &self.pending {
            if prefix.seed != self.seed
                || prefix.config_hash != self.config_hash
                || (prefix.decisions.is_empty() != (self.progress.runs == 0))
            {
                return Err(Error::Shape);
            }
            decisions = decisions
                .checked_add(prefix.decisions.len())
                .ok_or(Error::Overflow)?;
            let mut previous_step = 0;
            let mut previous_nanos = 0;
            for decision in &prefix.decisions {
                if decision.selected >= decision.enabled.len() {
                    return Err(Error::Shape);
                }
                dispatches = dispatches
                    .checked_add(decision.enabled.len())
                    .ok_or(Error::Overflow)?;
                let mut previous = None;
                for &choice in &decision.enabled {
                    check_choice(choice, previous, previous_step, previous_nanos)?;
                    previous = Some(choice);
                }
                let selected = decision.selected();
                previous_step = selected.at_step();
                previous_nanos = selected.at_nanos();
            }
        }
        let len = check_limits(self.pending.len(), decisions, dispatches, limits)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.workload.0);
        bytes.extend_from_slice(&self.seed.to_le_bytes());
        bytes.extend_from_slice(&self.config_hash.to_le_bytes());
        for count in [
            self.progress.runs,
            self.progress.completed,
            self.progress.incomplete,
            self.progress.failed,
            self.progress.omitted,
        ] {
            bytes.extend_from_slice(&count.to_le_bytes());
        }
        put_count(&mut bytes, self.pending.len())?;
        put_count(&mut bytes, decisions)?;
        put_count(&mut bytes, dispatches)?;
        for prefix in &self.pending {
            put_count(&mut bytes, prefix.decisions.len())?;
            for decision in &prefix.decisions {
                put_count(&mut bytes, decision.selected)?;
                put_count(&mut bytes, decision.enabled.len())?;
                for choice in &decision.enabled {
                    bytes.extend_from_slice(&choice.task().0.to_le_bytes());
                    bytes.extend_from_slice(&choice.worker().to_le_bytes());
                    bytes.push(match choice.lane() {
                        DispatchLane::Cancel => 0,
                        DispatchLane::Timed => 1,
                        DispatchLane::Ready => 2,
                        DispatchLane::Stolen => return Err(Error::Shape),
                    });
                    bytes.extend_from_slice(&choice.at_step().to_le_bytes());
                    bytes.extend_from_slice(&choice.at_nanos().to_le_bytes());
                }
            }
        }
        let hash = checksum(&bytes);
        bytes.extend_from_slice(&hash);
        debug_assert_eq!(bytes.len(), len);
        Ok(bytes)
    }

    /// Decodes an unverified checkpoint within explicit aggregate storage limits.
    ///
    /// Exact length, checksum, every nested count and canonical choice ordering
    /// are checked before any frontier allocation. Execution compatibility is
    /// subsequently checked by [`super::ExactScheduleExplorer::resume`].
    ///
    /// # Errors
    /// Refuses unsupported, corrupt, malformed, noncanonical or over-budget data.
    pub fn try_from_canonical_bytes(
        bytes: &[u8],
        limits: ExactScheduleCheckpointLimits,
    ) -> Result<Self, Error> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(Error::ByteLimit);
        }
        if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
            return Err(Error::Length);
        }
        let payload_end = bytes.len() - CHECKSUM_BYTES;
        let mut reader = Reader {
            bytes: &bytes[..payload_end],
            offset: 0,
        };
        if reader.array::<8>()? != MAGIC || u32::from_le_bytes(reader.array()?) != VERSION {
            return Err(Error::Format);
        }
        let workload = ExactScheduleWorkloadKey(reader.array()?);
        let seed = reader.u64()?;
        let config_hash = reader.u64()?;
        let progress = ExactScheduleProgress {
            runs: reader.u64()?,
            completed: reader.u64()?,
            incomplete: reader.u64()?,
            failed: reader.u64()?,
            omitted: reader.u64()?,
        };
        let prefixes = reader.count()?;
        let decisions = reader.count()?;
        let dispatches = reader.count()?;
        if check_limits(prefixes, decisions, dispatches, limits)? != bytes.len() {
            return Err(Error::Length);
        }
        if bytes[payload_end..] != checksum(&bytes[..payload_end]) {
            return Err(Error::Checksum);
        }
        check_progress(progress, prefixes)?;

        // Scan all nested declarations and choices before allocating any vectors.
        let mut seen_decisions = 0usize;
        let mut seen_dispatches = 0usize;
        for _ in 0..prefixes {
            let count = reader.count()?;
            if (count == 0) != (progress.runs == 0) {
                return Err(Error::Shape);
            }
            seen_decisions = seen_decisions.checked_add(count).ok_or(Error::Overflow)?;
            if seen_decisions > decisions {
                return Err(Error::Length);
            }
            let mut previous_step = 0;
            let mut previous_nanos = 0;
            for _ in 0..count {
                let selected = reader.count()?;
                let enabled = reader.count()?;
                if selected >= enabled {
                    return Err(Error::Shape);
                }
                seen_dispatches = seen_dispatches
                    .checked_add(enabled)
                    .ok_or(Error::Overflow)?;
                if seen_dispatches > dispatches {
                    return Err(Error::Length);
                }
                let mut previous = None;
                for _ in 0..enabled {
                    let choice = reader.dispatch()?;
                    check_choice(choice, previous, previous_step, previous_nanos)?;
                    previous = Some(choice);
                }
                let last = previous.ok_or(Error::Shape)?;
                previous_step = last.at_step();
                previous_nanos = last.at_nanos();
            }
        }
        if reader.offset != payload_end
            || seen_decisions != decisions
            || seen_dispatches != dispatches
        {
            return Err(Error::Length);
        }

        reader.offset = HEADER_BYTES;
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(prefixes)
            .map_err(|_| Error::Allocation)?;
        for _ in 0..prefixes {
            let count = reader.count()?;
            let mut prefix = ExactSchedulePrefix {
                seed,
                config_hash,
                decisions: Vec::new(),
            };
            prefix
                .decisions
                .try_reserve_exact(count)
                .map_err(|_| Error::Allocation)?;
            for _ in 0..count {
                let selected = reader.count()?;
                let count = reader.count()?;
                let mut enabled = Vec::new();
                enabled
                    .try_reserve_exact(count)
                    .map_err(|_| Error::Allocation)?;
                for _ in 0..count {
                    enabled.push(reader.dispatch()?);
                }
                prefix
                    .decisions
                    .push(ExactScheduleDecision { enabled, selected });
            }
            pending.push_back(prefix);
        }
        Ok(Self {
            workload,
            seed,
            config_hash,
            pending,
            progress,
        })
    }
}
