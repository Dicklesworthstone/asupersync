//! Assignment of symbols to replicas for balanced distribution.
//!
//! Determines which symbols each replica receives based on the chosen
//! [`AssignmentStrategy`].

use crate::record::distributed_region::ReplicaInfo;
use crate::types::symbol::Symbol;

// ---------------------------------------------------------------------------
// AssignmentStrategy
// ---------------------------------------------------------------------------

/// Strategy for assigning symbols to replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentStrategy {
    /// Each replica gets all symbols (full replication).
    Full,
    /// Symbols are striped across replicas (each gets a subset).
    Striped,
    /// Each replica gets at least K symbols (minimum for decode).
    MinimumK,
    /// Custom assignment based on replica capacity.
    Weighted,
}

// ---------------------------------------------------------------------------
// SymbolAssigner
// ---------------------------------------------------------------------------

/// Assigns symbols to replicas based on strategy.
#[derive(Debug)]
pub struct SymbolAssigner {
    strategy: AssignmentStrategy,
}

impl SymbolAssigner {
    /// Creates a new assigner with the given strategy.
    #[must_use]
    pub const fn new(strategy: AssignmentStrategy) -> Self {
        Self { strategy }
    }

    /// Returns the assignment strategy.
    #[must_use]
    pub const fn strategy(&self) -> AssignmentStrategy {
        self.strategy
    }

    /// Computes symbol assignments for the given replicas.
    ///
    /// # Arguments
    ///
    /// * `symbols` - The symbols to distribute
    /// * `replicas` - Target replicas
    /// * `k` - Source symbol count (minimum for decode)
    #[must_use]
    pub fn assign(
        &self,
        symbols: &[Symbol],
        replicas: &[ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        if replicas.is_empty() || symbols.is_empty() {
            return Vec::new();
        }

        match self.strategy {
            AssignmentStrategy::Full | AssignmentStrategy::Weighted => {
                Self::assign_full(symbols, replicas, k)
            }
            AssignmentStrategy::Striped => Self::assign_striped(symbols, replicas, k),
            AssignmentStrategy::MinimumK => Self::assign_minimum_k(symbols, replicas, k),
        }
    }

    /// Full replication: every replica gets all symbols.
    fn assign_full(symbols: &[Symbol], replicas: &[ReplicaInfo], k: u16) -> Vec<ReplicaAssignment> {
        let all_indices: Vec<usize> = (0..symbols.len()).collect();
        replicas
            .iter()
            .map(|r| ReplicaAssignment {
                replica_id: r.id.clone(),
                symbol_indices: all_indices.clone(),
                can_decode: symbols.len() >= k as usize,
            })
            .collect()
    }

    /// Striped: symbols are distributed round-robin across replicas.
    fn assign_striped(
        symbols: &[Symbol],
        replicas: &[ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let n = replicas.len();
        let mut assignments: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (i, _) in symbols.iter().enumerate() {
            assignments[i % n].push(i);
        }

        replicas
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let indices = &assignments[i];
                ReplicaAssignment {
                    replica_id: r.id.clone(),
                    symbol_indices: indices.clone(),
                    can_decode: indices.len() >= k as usize,
                }
            })
            .collect()
    }

    /// MinimumK: each replica gets at least K symbols to enable independent decoding.
    fn assign_minimum_k(
        symbols: &[Symbol],
        replicas: &[ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let k_usize = k as usize;

        replicas
            .iter()
            .enumerate()
            .map(|(replica_idx, r)| {
                // Give each replica K symbols starting at a rotated offset.
                let mut indices = Vec::with_capacity(k_usize);
                for j in 0..std::cmp::min(k_usize, symbols.len()) {
                    let idx = (replica_idx * k_usize / replicas.len() + j) % symbols.len();
                    if !indices.contains(&idx) {
                        indices.push(idx);
                    }
                }

                // If we don't have K yet due to small symbol count or
                // deduplication, fill from the beginning.
                let mut fill = 0;
                while indices.len() < k_usize && fill < symbols.len() {
                    if !indices.contains(&fill) {
                        indices.push(fill);
                    }
                    fill += 1;
                }

                ReplicaAssignment {
                    replica_id: r.id.clone(),
                    can_decode: indices.len() >= k_usize,
                    symbol_indices: indices,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ReplicaAssignment
// ---------------------------------------------------------------------------

/// Assignment of symbols to a specific replica.
#[derive(Debug, Clone)]
pub struct ReplicaAssignment {
    /// Target replica identifier.
    pub replica_id: String,
    /// Symbol indices to send.
    pub symbol_indices: Vec<usize>,
    /// Whether this replica can decode independently.
    pub can_decode: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_replicas(count: usize) -> Vec<ReplicaInfo> {
        (0..count)
            .map(|i| ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .collect()
    }

    fn create_test_symbols(count: usize) -> Vec<Symbol> {
        (0..count)
            .map(|i| Symbol::new_for_test(1, 0, i as u32, &[0u8; 128]))
            .collect()
    }

    #[test]
    fn full_assignment_all_replicas_get_all() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 5);

        assert_eq!(assignments.len(), 3);
        for assignment in &assignments {
            assert_eq!(assignment.symbol_indices.len(), 10);
            assert!(assignment.can_decode);
        }
    }

    #[test]
    fn striped_assignment_distributes_evenly() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let symbols = create_test_symbols(9);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 5);

        // Each replica should get 3 symbols (9 / 3).
        for assignment in &assignments {
            assert_eq!(assignment.symbol_indices.len(), 3);
        }
    }

    #[test]
    fn striped_no_overlap() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let symbols = create_test_symbols(12);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 4);

        // Collect all assigned indices.
        let mut all: Vec<usize> = Vec::new();
        for a in &assignments {
            all.extend_from_slice(&a.symbol_indices);
        }
        all.sort_unstable();
        all.dedup();

        assert_eq!(all.len(), 12, "all symbols should be assigned exactly once");
    }

    #[test]
    fn minimum_k_assignment() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(15);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 10);

        for assignment in &assignments {
            assert!(
                assignment.symbol_indices.len() >= 10,
                "replica {} got {} symbols, need >= 10",
                assignment.replica_id,
                assignment.symbol_indices.len()
            );
            assert!(assignment.can_decode);
        }
    }

    #[test]
    fn empty_symbols_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols: Vec<Symbol> = vec![];
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn empty_replicas_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(10);
        let replicas: Vec<ReplicaInfo> = vec![];

        let assignments = assigner.assign(&symbols, &replicas, 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn weighted_defaults_to_full() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(2);

        let assignments = assigner.assign(&symbols, &replicas, 3);

        assert_eq!(assignments.len(), 2);
        for assignment in &assignments {
            assert_eq!(assignment.symbol_indices.len(), 5);
        }
    }

    // ========== Edge case tests (bd-3k9o) ==========

    #[test]
    fn full_more_replicas_than_symbols() {
        // 3 symbols, 10 replicas — every replica gets all 3
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(3);
        let replicas = create_test_replicas(10);

        let assignments = assigner.assign(&symbols, &replicas, 2);

        assert_eq!(assignments.len(), 10);
        for a in &assignments {
            assert_eq!(a.symbol_indices.len(), 3);
            assert!(a.can_decode);
        }
    }

    #[test]
    fn full_single_symbol() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(1);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 1);

        for a in &assignments {
            assert_eq!(a.symbol_indices.len(), 1);
            assert!(a.can_decode);
        }
    }

    #[test]
    fn full_k_greater_than_symbol_count() {
        // k=10 but only 5 symbols — can_decode should be false
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(2);

        let assignments = assigner.assign(&symbols, &replicas, 10);

        for a in &assignments {
            assert_eq!(a.symbol_indices.len(), 5);
            assert!(!a.can_decode);
        }
    }

    #[test]
    fn striped_uneven_distribution() {
        // 10 symbols across 3 replicas: 4, 4, 2 (or 4, 3, 3)
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 3);

        let total: usize = assignments.iter().map(|a| a.symbol_indices.len()).sum();
        assert_eq!(total, 10, "all symbols assigned");

        // No replica should get 0 or all
        for a in &assignments {
            assert!(!a.symbol_indices.is_empty());
            assert!(a.symbol_indices.len() <= 4);
        }
    }

    #[test]
    fn striped_single_replica() {
        // Single replica gets all symbols via striping
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(1);

        let assignments = assigner.assign(&symbols, &replicas, 3);

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].symbol_indices.len(), 5);
        assert!(assignments[0].can_decode);
    }

    #[test]
    fn striped_more_replicas_than_symbols() {
        // 3 symbols, 5 replicas — some replicas get 0 or 1 symbol
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let symbols = create_test_symbols(3);
        let replicas = create_test_replicas(5);

        let assignments = assigner.assign(&symbols, &replicas, 2);

        let total: usize = assignments.iter().map(|a| a.symbol_indices.len()).sum();
        assert_eq!(total, 3);

        // Replicas 0,1,2 get one symbol each, replicas 3,4 get none
        let nonempty = assignments
            .iter()
            .filter(|a| !a.symbol_indices.is_empty())
            .count();
        assert_eq!(nonempty, 3);
    }

    #[test]
    fn minimum_k_single_replica() {
        // Single replica should get at least K symbols
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas(1);

        let assignments = assigner.assign(&symbols, &replicas, 5);

        assert_eq!(assignments.len(), 1);
        assert!(assignments[0].symbol_indices.len() >= 5);
        assert!(assignments[0].can_decode);
    }

    #[test]
    fn minimum_k_k_equals_symbol_count() {
        // k == total symbols: every replica gets all
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(3);

        let assignments = assigner.assign(&symbols, &replicas, 5);

        for a in &assignments {
            assert_eq!(a.symbol_indices.len(), 5);
            assert!(a.can_decode);
        }
    }

    #[test]
    fn minimum_k_k_greater_than_symbols() {
        // k=10 but only 5 symbols — can't reach K, can_decode false
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(2);

        let assignments = assigner.assign(&symbols, &replicas, 10);

        for a in &assignments {
            assert!(!a.can_decode);
        }
    }

    #[test]
    fn minimum_k_no_duplicate_indices() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(20);
        let replicas = create_test_replicas(4);

        let assignments = assigner.assign(&symbols, &replicas, 8);

        for a in &assignments {
            let mut sorted = a.symbol_indices.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                a.symbol_indices.len(),
                "no duplicate indices for replica {}",
                a.replica_id
            );
        }
    }

    #[test]
    fn strategy_accessor() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        assert_eq!(assigner.strategy(), AssignmentStrategy::Striped);
    }

    #[test]
    fn both_empty_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let assignments = assigner.assign(&[], &[], 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn full_k_zero() {
        // k=0: every replica can decode (0 symbols needed)
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(2);

        let assignments = assigner.assign(&symbols, &replicas, 0);

        for a in &assignments {
            assert!(a.can_decode);
        }
    }
}
