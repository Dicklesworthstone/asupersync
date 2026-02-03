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
use std::collections::HashSet;
use std::fmt::Write;
use std::hash::{DefaultHasher, Hash, Hasher};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            Some((self.death - self.birth) as u64)
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
pub fn score_persistence<S: std::hash::BuildHasher>(
    pairs: &PersistencePairs,
    seen_classes: &mut HashSet<ClassId, S>,
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
    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    h.finish()
}

/// Convenience: score a boundary matrix end-to-end.
///
/// Reduces the matrix, extracts persistence pairs, and scores them.
#[must_use]
pub fn score_boundary_matrix<S: std::hash::BuildHasher>(
    matrix: &BoundaryMatrix,
    seen_classes: &mut HashSet<ClassId, S>,
    fingerprint: u64,
) -> EvidenceLedger {
    let reduced = matrix.reduce();
    let pairs = reduced.persistence_pairs();
    score_persistence(&pairs, seen_classes, fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::gf2::BoundaryMatrix;

    #[test]
    fn score_empty() {
        let pairs = PersistencePairs {
            pairs: vec![],
            unpaired: vec![],
        };
        let mut seen = HashSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 42);
        assert_eq!(ledger.score.novelty, 0);
        assert_eq!(ledger.score.persistence_sum, 0);
        assert_eq!(ledger.score.fingerprint, 42);
        assert!(ledger.entries.is_empty());
    }

    #[test]
    fn score_novel_classes() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5), (1, 8)],
            unpaired: vec![3],
        };
        let mut seen = HashSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 100);

        assert_eq!(ledger.score.novelty, 3); // all new
        assert_eq!(ledger.score.persistence_sum, 5 + 7); // (5-0) + (8-1)
        assert_eq!(ledger.entries.len(), 3);
        assert!(ledger.entries.iter().all(|e| e.is_novel));
    }

    #[test]
    fn score_repeated_classes_not_novel() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5)],
            unpaired: vec![],
        };
        let mut seen = HashSet::new();

        let l1 = score_persistence(&pairs, &mut seen, 1);
        assert_eq!(l1.score.novelty, 1);

        // Same class again — not novel
        let l2 = score_persistence(&pairs, &mut seen, 2);
        assert_eq!(l2.score.novelty, 0);
        assert_eq!(l2.score.persistence_sum, 5); // persistence still counted
        assert!(!l2.entries[0].is_novel);
    }

    #[test]
    fn score_ordering() {
        let high = TopologicalScore {
            novelty: 2,
            persistence_sum: 10,
            fingerprint: 100,
        };
        let low = TopologicalScore {
            novelty: 1,
            persistence_sum: 50,
            fingerprint: 1,
        };
        // Higher novelty wins
        assert!(high > low);

        let a = TopologicalScore {
            novelty: 1,
            persistence_sum: 20,
            fingerprint: 5,
        };
        let b = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 1,
        };
        // Same novelty, higher persistence wins
        assert!(a > b);

        let x = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 5,
        };
        let y = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 10,
        };
        // Same novelty+persistence, lower fingerprint wins
        assert!(x > y);
    }

    #[test]
    fn score_determinism() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 3), (2, 7)],
            unpaired: vec![5],
        };

        let mut seen1 = HashSet::new();
        let mut seen2 = HashSet::new();

        let l1 = score_persistence(&pairs, &mut seen1, 42);
        let l2 = score_persistence(&pairs, &mut seen2, 42);

        assert_eq!(l1.score, l2.score);
    }

    #[test]
    fn evidence_ledger_summary_format() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5)],
            unpaired: vec![3],
        };
        let mut seen = HashSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 0xFF);

        let summary = ledger.summary();
        assert!(summary.contains("novelty=2"));
        assert!(summary.contains("NEW"));
        assert!(summary.contains("pers=5"));
        assert!(summary.contains("pers=∞"));
    }

    #[test]
    fn score_boundary_matrix_end_to_end() {
        // Build a simple complex: triangle with filled face
        // v0, v1, v2, e01, e02, e12, t012
        let mut d = BoundaryMatrix::zeros(7, 7);
        // e01 (col 3): v0 + v1
        d.set(0, 3);
        d.set(1, 3);
        // e02 (col 4): v0 + v2
        d.set(0, 4);
        d.set(2, 4);
        // e12 (col 5): v1 + v2
        d.set(1, 5);
        d.set(2, 5);
        // t012 (col 6): e01 + e02 + e12
        d.set(3, 6);
        d.set(4, 6);
        d.set(5, 6);

        let mut seen = HashSet::new();
        let ledger = score_boundary_matrix(&d, &mut seen, 0);

        // Filled triangle: β0=1, β1=0 (cycle killed by face)
        // Should have pairs and the score should be deterministic
        assert!(ledger.score.novelty > 0 || !ledger.entries.is_empty());
    }

    #[test]
    fn seed_fingerprint_deterministic() {
        assert_eq!(seed_fingerprint(42), seed_fingerprint(42));
        assert_ne!(seed_fingerprint(42), seed_fingerprint(43));
    }

    #[test]
    fn class_id_persistence() {
        let finite = ClassId {
            birth: 3,
            death: 10,
        };
        assert_eq!(finite.persistence(), Some(7));

        let infinite = ClassId {
            birth: 3,
            death: usize::MAX,
        };
        assert_eq!(infinite.persistence(), None);
    }
}
