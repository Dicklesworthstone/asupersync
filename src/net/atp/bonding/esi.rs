//! Channel bonding Phase A2 — static ESI residue partitioning.
//!
//! Donor `i` of `N` owns every ESI where `esi % N == i`, spanning both
//! systematic source symbols (`esi < K`) and repair symbols (`esi >= K`) for
//! each source block. This gives donors a zero-negotiation, disjoint assignment:
//! distinct ESIs name distinct useful symbols, while two donors emitting the
//! same ESI only produce duplicate waste.

use core::fmt;

/// Validated ESI residue-class assignment for one donor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsiPartition {
    donor_index: u32,
    donor_count: u32,
}

impl EsiPartition {
    /// Build a partition for donor `donor_index` among `donor_count` donors.
    ///
    /// # Errors
    ///
    /// Returns [`EsiPartitionError`] for zero donors or an out-of-range donor.
    pub fn new(donor_index: u32, donor_count: u32) -> Result<Self, EsiPartitionError> {
        if donor_count == 0 {
            return Err(EsiPartitionError::ZeroDonors);
        }
        if donor_index >= donor_count {
            return Err(EsiPartitionError::DonorIndexOutOfRange {
                donor_index,
                donor_count,
            });
        }

        Ok(Self {
            donor_index,
            donor_count,
        })
    }

    /// Return this donor's zero-based index.
    #[must_use]
    pub const fn donor_index(self) -> u32 {
        self.donor_index
    }

    /// Return the total number of donors in this partition.
    #[must_use]
    pub const fn donor_count(self) -> u32 {
        self.donor_count
    }

    /// Map a donor-local emission sequence to the global ESI it owns.
    #[must_use]
    pub fn esi_for_sequence(self, sequence: u32) -> Option<u32> {
        sequence
            .checked_mul(self.donor_count)
            .and_then(|base| base.checked_add(self.donor_index))
    }

    /// Return true when `esi` belongs to this donor's residue class.
    #[must_use]
    pub fn owns_esi(self, esi: u32) -> bool {
        esi % self.donor_count == self.donor_index
    }

    /// Iterate this donor's ESI stream: `i, i+N, i+2N, ...`.
    #[must_use]
    pub const fn stream(self) -> DonorEsiStream {
        DonorEsiStream {
            partition: self,
            next_sequence: Some(0),
        }
    }
}

/// Error returned by static ESI partition construction or arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EsiPartitionError {
    /// A bonded transfer must have at least one donor.
    ZeroDonors,
    /// The donor index must be in `0..donor_count`.
    DonorIndexOutOfRange { donor_index: u32, donor_count: u32 },
    /// The requested donor-local sequence cannot fit in the `u32` ESI space.
    SequenceOverflow {
        donor_index: u32,
        donor_count: u32,
        sequence: u32,
    },
}

impl fmt::Display for EsiPartitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDonors => f.write_str("channel bonding ESI partition has zero donors"),
            Self::DonorIndexOutOfRange {
                donor_index,
                donor_count,
            } => write!(
                f,
                "channel bonding donor index {donor_index} is outside 0..{donor_count}"
            ),
            Self::SequenceOverflow {
                donor_index,
                donor_count,
                sequence,
            } => write!(
                f,
                "channel bonding donor {donor_index}/{donor_count} sequence {sequence} exceeds u32 ESI space"
            ),
        }
    }
}

impl std::error::Error for EsiPartitionError {}

/// Return the global ESI emitted by donor `donor_index` at local `sequence`.
///
/// # Errors
///
/// Returns [`EsiPartitionError`] when the partition is invalid or the arithmetic
/// would overflow `u32`.
pub fn esi_for_donor(
    donor_index: u32,
    donor_count: u32,
    sequence: u32,
) -> Result<u32, EsiPartitionError> {
    let partition = EsiPartition::new(donor_index, donor_count)?;
    partition
        .esi_for_sequence(sequence)
        .ok_or(EsiPartitionError::SequenceOverflow {
            donor_index,
            donor_count,
            sequence,
        })
}

/// Return true when `esi` belongs to donor `donor_index` of `donor_count`.
///
/// # Errors
///
/// Returns [`EsiPartitionError`] when the partition is invalid.
pub fn owns_esi(donor_index: u32, donor_count: u32, esi: u32) -> Result<bool, EsiPartitionError> {
    Ok(EsiPartition::new(donor_index, donor_count)?.owns_esi(esi))
}

/// Return an iterator over donor `donor_index`'s assigned ESIs.
///
/// # Errors
///
/// Returns [`EsiPartitionError`] when the partition is invalid.
pub fn donor_esi_stream(
    donor_index: u32,
    donor_count: u32,
) -> Result<DonorEsiStream, EsiPartitionError> {
    Ok(EsiPartition::new(donor_index, donor_count)?.stream())
}

/// Iterator over one donor's global ESI sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DonorEsiStream {
    partition: EsiPartition,
    next_sequence: Option<u32>,
}

impl Iterator for DonorEsiStream {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let sequence = self.next_sequence?;
        match self.partition.esi_for_sequence(sequence) {
            Some(esi) => {
                self.next_sequence = sequence.checked_add(1);
                Some(esi)
            }
            None => {
                self.next_sequence = None;
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "esi_inline_tests.rs"]
mod tests;
