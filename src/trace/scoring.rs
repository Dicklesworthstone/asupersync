//! Topological novelty scoring for exploration prioritization.
//!
//! Turns persistent homology output (persistence pairs from the square
//! complex) into a deterministic priority score for DPOR exploration nodes.
//!
//! # Scoring Model
//!
//! Each exploration node (seed/backtrack point) is scored by analyzing the
//! H1 persistence of its trace's commutation complex:
//!
//! - **Novelty (primary):** number of new homology classes not seen in
//!   previously explored traces.
//! - **Persistence sum (secondary):** sum of `(death - birth)` intervals,
//!   weighted by persistence length. Longer-lived cycles indicate more
//!   structurally significant scheduling freedom.
//! - **Tie-break (tertiary):** stable deterministic ordering by fingerprint.
//!
//! # Evidence Ledger
//!
//! The [`EvidenceLedger`] records which persistence classes contributed to
//! the score, their birth/death intervals, and provides human-readable
//! explanations for why one node outranks another.

use crate::trace::gf2::{BoundaryMatrix, PersistencePairs};
use crate::util::DetHasher;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::hash::{Hash, Hasher};

/// A deterministic priority score for an exploration node.
///
/// Ordered by `(novelty, persistence_sum, fingerprint)` descending for
/// novelty and persistence, ascending for fingerprint (tie-break).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologicalScore {
    /// Number of new homology classes (higher = more novel).
    pub novelty: u32,
    /// Sum of persistence intervals (higher = more structurally significant).
    pub persistence_sum: u64,
    /// Deterministic tie-break fingerprint (lower = earlier in canonical order).
    pub fingerprint: u64,
}

impl TopologicalScore {
    /// Creates a zero score with the given fingerprint.
    #[must_use]
    pub const fn zero(fingerprint: u64) -> Self {
        Self {
            novelty: 0,
            persistence_sum: 0,
            fingerprint,
        }
    }
}

impl Ord for TopologicalScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.novelty
            .cmp(&other.novelty)
            .then(self.persistence_sum.cmp(&other.persistence_sum))
            // Lower fingerprint wins ties (ascending = stable canonical order)
            .then(other.fingerprint.cmp(&self.fingerprint))
    }
}

impl PartialOrd for TopologicalScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A canonical identifier for a persistence class.
///
/// Two classes are "the same" if they have the same birth and death
/// column indices in the reduced boundary matrix. This is deterministic
/// because our reduction algorithm uses stable left-to-right pivoting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId {
    /// Birth column index in the boundary matrix.
    pub birth: usize,
    /// Death column index (or `usize::MAX` for unpaired/infinite classes).
    pub death: usize,
}

impl ClassId {
    /// Returns the persistence interval length, or `None` for infinite classes.
    #[must_use]
    pub const fn persistence(&self) -> Option<u64> {
        if self.death == usize::MAX {
            None
        } else {
            Some(self.death.saturating_sub(self.birth) as u64)
        }
    }
}

/// Evidence entry explaining why a class contributes to the score.
#[derive(Debug, Clone)]
pub struct EvidenceEntry {
    /// The persistence class.
    pub class: ClassId,
    /// Whether this class is novel (not seen before).
    pub is_novel: bool,
    /// Persistence interval length (None = infinite).
    pub persistence: Option<u64>,
}

/// An evidence ledger recording which classes contributed to a score.
#[derive(Debug, Clone)]
pub struct EvidenceLedger {
    /// All evidence entries for this scoring.
    pub entries: Vec<EvidenceEntry>,
    /// The computed score.
    pub score: TopologicalScore,
}

impl EvidenceLedger {
    /// Returns a human-readable summary of why this score was assigned.
    #[must_use]
    pub fn summary(&self) -> String {
        let novel_count = self.entries.iter().filter(|e| e.is_novel).count();
        let total = self.entries.len();
        let finite_count = self.entries.iter().filter_map(|e| e.persistence).count();

        let mut s = format!(
            "score: novelty={}, persistence_sum={}, fingerprint={:#018x}\n",
            self.score.novelty, self.score.persistence_sum, self.score.fingerprint
        );
        let _ = writeln!(
            &mut s,
            "classes: {total} total, {novel_count} novel, {finite_count} finite"
        );
        for e in &self.entries {
            let tag = if e.is_novel { "NEW" } else { "old" };
            let pers = e
                .persistence
                .map_or_else(|| "pers=∞".to_string(), |p| format!("pers={p}"));
            let _ = writeln!(
                &mut s,
                "  [{tag}] birth={}, death={}, {pers}",
                e.class.birth,
                if e.class.death == usize::MAX {
                    "∞".to_string()
                } else {
                    e.class.death.to_string()
                },
            );
        }
        s
    }
}

/// Compute a topological novelty score from persistence pairs.
///
/// # Parameters
///
/// - `pairs`: persistence pairs from reducing the boundary matrix.
/// - `seen_classes`: set of previously observed class identifiers.
///   Updated in-place with newly discovered classes.
/// - `fingerprint`: deterministic tie-break value (e.g., hash of seed).
///
/// # Returns
///
/// An [`EvidenceLedger`] containing the score and per-class evidence.
#[must_use]
pub fn score_persistence(
    pairs: &PersistencePairs,
    seen_classes: &mut BTreeSet<ClassId>,
    fingerprint: u64,
) -> EvidenceLedger {
    let mut entries = Vec::new();
    let mut novelty = 0u32;
    let mut persistence_sum = 0u64;

    // Score paired classes (finite persistence)
    for &(birth, death) in &pairs.pairs {
        let class = ClassId { birth, death };
        let is_novel = seen_classes.insert(class);
        let persistence = class.persistence();

        if is_novel {
            novelty += 1;
        }
        if let Some(p) = persistence {
            persistence_sum = persistence_sum.saturating_add(p);
        }

        entries.push(EvidenceEntry {
            class,
            is_novel,
            persistence,
        });
    }

    // Score unpaired classes (infinite persistence)
    for &birth in &pairs.unpaired {
        let class = ClassId {
            birth,
            death: usize::MAX,
        };
        let is_novel = seen_classes.insert(class);

        if is_novel {
            novelty += 1;
        }
        // Infinite classes don't contribute to persistence_sum
        // (they persist forever — not a scheduling choice that can be resolved)

        entries.push(EvidenceEntry {
            class,
            is_novel,
            persistence: None,
        });
    }

    let score = TopologicalScore {
        novelty,
        persistence_sum,
        fingerprint,
    };

    EvidenceLedger { entries, score }
}

/// Compute a deterministic fingerprint for a seed value.
#[must_use]
pub fn seed_fingerprint(seed: u64) -> u64 {
    let mut h = DetHasher::for_lab();
    seed.hash(&mut h);
    h.finish()
}

/// Convenience: score a boundary matrix end-to-end.
///
/// Reduces the matrix, extracts persistence pairs, and scores them.
#[must_use]
pub fn score_boundary_matrix(
    matrix: &BoundaryMatrix,
    seen_classes: &mut BTreeSet<ClassId>,
    fingerprint: u64,
) -> EvidenceLedger {
    let reduced = matrix.reduce();
    let pairs = reduced.persistence_pairs();
    score_persistence(&pairs, seen_classes, fingerprint)
}

#[cfg(test)]
#[path = "scoring_inline_tests.rs"]
mod tests;
