//! Assignment of symbols to replicas for balanced distribution.
//!
//! Determines which symbols each replica receives based on the chosen
//! [`AssignmentStrategy`].

use crate::record::distributed_region::ReplicaInfo;
use crate::security::SecurityContext;
use crate::types::symbol::Symbol;
use std::collections::BTreeSet;

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
    /// Symbols are distributed once, biased toward replicas with lower current
    /// `symbol_count`.
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
    #[inline]
    #[must_use]
    pub const fn new(strategy: AssignmentStrategy) -> Self {
        Self { strategy }
    }

    /// Returns the assignment strategy.
    #[inline]
    #[must_use]
    pub const fn strategy(&self) -> AssignmentStrategy {
        self.strategy
    }

    /// Computes symbol assignments for the given replicas.
    ///
    /// asupersync-j18rga: Now validates replica authorization before assignment
    /// to prevent unauthorized nodes from participating in symbol distribution.
    ///
    /// # Arguments
    ///
    /// * `symbols` - The symbols to distribute
    /// * `replicas` - Target replicas (will be filtered for authorization)
    /// * `security_context` - Security context for replica authorization
    /// * `region_id` - Optional region identifier for scoped authorization
    /// * `k` - Source symbol count (minimum for decode)
    ///
    /// # Returns
    ///
    /// Symbol assignments only for authorized replicas. Unauthorized replicas
    /// are silently filtered out to prevent information leakage.
    #[must_use]
    pub fn assign(
        &self,
        symbols: &[Symbol],
        replicas: &[ReplicaInfo],
        security_context: &SecurityContext,
        region_id: Option<&str>,
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        if replicas.is_empty() || symbols.is_empty() {
            return Vec::new();
        }

        // asupersync-j18rga: Filter replicas to only include authorized ones
        let authorized_replicas: Vec<&ReplicaInfo> = replicas
            .iter()
            .filter(|replica| security_context.is_replica_authorized(&replica.id, region_id))
            .collect();

        if authorized_replicas.is_empty() {
            // No authorized replicas - return empty assignments
            return Vec::new();
        }

        match self.strategy {
            AssignmentStrategy::Full => Self::assign_full(symbols, &authorized_replicas, k),
            AssignmentStrategy::Striped => Self::assign_striped(symbols, &authorized_replicas, k),
            AssignmentStrategy::MinimumK => {
                Self::assign_minimum_k(symbols, &authorized_replicas, k)
            }
            AssignmentStrategy::Weighted => Self::assign_weighted(symbols, &authorized_replicas, k),
        }
    }

    /// Full replication: every replica gets all symbols.
    fn assign_full(
        symbols: &[Symbol],
        replicas: &[&ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let k_usize = k as usize;
        let all_indices: Vec<usize> = (0..symbols.len()).collect();
        replicas
            .iter()
            .map(|r| ReplicaAssignment::from_indices(r, all_indices.clone(), k_usize))
            .collect()
    }

    /// Striped: symbols are distributed round-robin across replicas.
    fn assign_striped(
        symbols: &[Symbol],
        replicas: &[&ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let k_usize = k as usize;
        let n = replicas.len();
        let mut assignments: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (i, _) in symbols.iter().enumerate() {
            assignments[i % n].push(i);
        }

        replicas
            .iter()
            .enumerate()
            .map(|(i, r)| ReplicaAssignment::from_indices(r, assignments[i].clone(), k_usize)) // ubs:ignore - i < replicas.len() == assignments.len()
            .collect()
    }

    /// MinimumK: each replica gets at least K symbols to enable independent decoding.
    ///
    /// br-asupersync-45xcbm: dedup uses `BTreeSet<usize>` rather than
    /// `Vec::contains`. The previous implementation called `Vec::contains`
    /// inside two loops that each ran up to `K` (or `symbols.len()`)
    /// iterations, giving O(K^2) (or O(symbols.len()^2)) per replica
    /// and O(R · K^2) per assignment call. With K bounded by RaptorQ's
    /// K' (~56403) and R bounded only by service config, an attacker
    /// who can drive snapshot redistribution (e.g., via the bridge
    /// path) could pin the assignment thread for tens of seconds —
    /// a SaaS-grade algorithmic-complexity DoS.
    ///
    /// `BTreeSet` makes dedup O(log K) per insert and preserves
    /// deterministic iteration order (sorted by index), which keeps
    /// the assignment replay-stable. The intermediate set is
    /// `collect()`ed into the final `Vec<usize>` once at the end of
    /// the per-replica computation; downstream code that consumes
    /// `symbol_indices` sees the same `Vec<usize>` shape it always
    /// did, just sorted instead of insertion-ordered.
    ///
    /// The change to sorted-by-default ordering is intentional and is
    /// the simplest replay-stable variant: any caller that depended
    /// on the previous insertion order was relying on an undocumented
    /// invariant of the deduplication path; the new order is total
    /// and deterministic.
    fn assign_minimum_k(
        symbols: &[Symbol],
        replicas: &[&ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let k_usize = k as usize;

        replicas
            .iter()
            .enumerate()
            .map(|(replica_idx, r)| {
                // Give each replica K symbols starting at a rotated offset.
                let mut indices: BTreeSet<usize> = BTreeSet::new();
                let symbol_len = symbols.len();
                if symbol_len > 0 {
                    for j in 0..std::cmp::min(k_usize, symbol_len) {
                        let idx =
                            (replica_idx * symbol_len / replicas.len().max(1) + j) % symbol_len;
                        indices.insert(idx);
                    }

                    // If we don't have K yet due to small symbol count
                    // or deduplication, fill from the beginning.
                    let mut fill = 0;
                    while indices.len() < k_usize && fill < symbol_len {
                        indices.insert(fill);
                        fill += 1;
                    }
                }

                let symbol_indices: Vec<usize> = indices.into_iter().collect();
                ReplicaAssignment::from_indices(r, symbol_indices, k_usize)
            })
            .collect()
    }

    /// Weighted: assign each symbol exactly once, preferring replicas that
    /// currently hold fewer symbols.
    fn assign_weighted(
        symbols: &[Symbol],
        replicas: &[&ReplicaInfo],
        k: u16,
    ) -> Vec<ReplicaAssignment> {
        let mut assignments: Vec<Vec<usize>> = vec![Vec::new(); replicas.len()];
        let mut assigned_counts = vec![0_u64; replicas.len()];

        for (symbol_idx, _) in symbols.iter().enumerate() {
            let mut best_idx = 0usize;
            let mut best_projected_total =
                u64::from(replicas[best_idx].symbol_count) + assigned_counts[best_idx];
            for candidate_idx in 1..replicas.len() {
                let candidate_projected_total = u64::from(replicas[candidate_idx].symbol_count)
                    + assigned_counts[candidate_idx];

                if candidate_projected_total < best_projected_total
                    || (candidate_projected_total == best_projected_total
                        && assigned_counts[candidate_idx] < assigned_counts[best_idx])
                {
                    best_idx = candidate_idx;
                    best_projected_total = candidate_projected_total;
                }
            }

            assignments[best_idx].push(symbol_idx);
            assigned_counts[best_idx] += 1;
        }

        replicas
            .iter()
            .enumerate()
            .map(|(replica_idx, replica)| {
                ReplicaAssignment::from_indices(
                    replica,
                    assignments[replica_idx].clone(),
                    k as usize,
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ReplicaAssignment
// ---------------------------------------------------------------------------

/// Assignment of symbols to a specific replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaAssignment {
    /// Target replica identifier.
    pub replica_id: String,
    /// Symbol indices to send.
    pub symbol_indices: Vec<usize>,
    /// Whether this replica can decode independently.
    pub can_decode: bool,
}

impl ReplicaAssignment {
    fn from_indices(replica: &ReplicaInfo, symbol_indices: Vec<usize>, k_usize: usize) -> Self {
        Self {
            replica_id: replica.id.clone(),
            can_decode: symbol_indices.len() >= k_usize,
            symbol_indices,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn create_test_replicas(count: usize) -> Vec<ReplicaInfo> {
        (0..count)
            .map(|i| ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .collect()
    }

    fn create_test_replicas_with_symbol_counts(symbol_counts: &[u32]) -> Vec<ReplicaInfo> {
        symbol_counts
            .iter()
            .enumerate()
            .map(|(i, &symbol_count)| {
                let mut replica = ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}"));
                replica.symbol_count = symbol_count;
                replica
            })
            .collect()
    }

    fn create_test_symbols(count: usize) -> Vec<Symbol> {
        (0..count)
            .map(|i| Symbol::new_for_test(1, 0, i as u32, &[0u8; 128]))
            .collect()
    }

    trait AuthorizedAssignForTests {
        fn assign_authorized(
            &self,
            symbols: &[Symbol],
            replicas: &[ReplicaInfo],
            k: u16,
        ) -> Vec<ReplicaAssignment>;
    }

    impl AuthorizedAssignForTests for SymbolAssigner {
        fn assign_authorized(
            &self,
            symbols: &[Symbol],
            replicas: &[ReplicaInfo],
            k: u16,
        ) -> Vec<ReplicaAssignment> {
            let mut security_context = SecurityContext::for_testing(42);
            for replica in replicas {
                security_context
                    .authorize_replica(&replica.id, None)
                    .expect("test replica identifiers should be authorizable");
            }
            SymbolAssigner::assign(self, symbols, replicas, &security_context, None, k)
        }
    }

    #[test]
    fn full_assignment_all_replicas_get_all() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas(3);
        let security_context = SecurityContext::for_testing(42);

        let assignments = assigner.assign(&symbols, &replicas, &security_context, None, 5);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 5);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 4);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 10);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn empty_replicas_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(10);
        let replicas: Vec<ReplicaInfo> = vec![];

        let assignments = assigner.assign_authorized(&symbols, &replicas, 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn weighted_prefers_less_loaded_replicas() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(18);
        let replicas = create_test_replicas_with_symbol_counts(&[0, 4, 9]);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 3);

        let counts: Vec<_> = assignments
            .iter()
            .map(|assignment| assignment.symbol_indices.len())
            .collect();
        assert_eq!(counts.iter().sum::<usize>(), symbols.len());
        assert!(
            counts[0] > counts[1],
            "lighter replica should get more symbols"
        );
        assert!(
            counts[1] > counts[2],
            "heaviest replica should get the fewest symbols"
        );

        let mut all_indices: Vec<_> = assignments
            .iter()
            .flat_map(|assignment| assignment.symbol_indices.iter().copied())
            .collect();
        all_indices.sort_unstable();
        all_indices.dedup();
        assert_eq!(
            all_indices.len(),
            symbols.len(),
            "weighted assignment must not duplicate symbols"
        );
    }

    #[test]
    fn weighted_equal_loads_balance_like_striping() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas_with_symbol_counts(&[2, 2, 2]);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 3);

        let counts: Vec<_> = assignments
            .iter()
            .map(|assignment| assignment.symbol_indices.len())
            .collect();
        let min = counts.iter().copied().min().unwrap_or(0);
        let max = counts.iter().copied().max().unwrap_or(0);
        assert_eq!(counts.iter().sum::<usize>(), symbols.len());
        assert!(
            max - min <= 1,
            "equal loads should distribute nearly evenly, got {counts:?}"
        );
    }

    #[test]
    fn metamorphic_weighted_equal_loads_match_striped_assignment() {
        let weighted = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let striped = SymbolAssigner::new(AssignmentStrategy::Striped);
        let replicas = create_test_replicas_with_symbol_counts(&[7, 7, 7, 7]);

        for symbol_count in [1_usize, 2, 3, 4, 7, 11, 17] {
            let symbols = create_test_symbols(symbol_count);
            let weighted_plan = weighted.assign_authorized(&symbols, &replicas, 99);
            let striped_plan = striped.assign_authorized(&symbols, &replicas, 99);

            assert_eq!(
                weighted_plan, striped_plan,
                "with equal existing loads, weighted assignment should reduce to striped \
                 round-robin for {symbol_count} symbols"
            );
        }
    }

    #[test]
    fn weighted_avoids_heavier_replica_until_projected_loads_match() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(2);
        let replicas = create_test_replicas_with_symbol_counts(&[0, 100]);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 1);
        let counts: Vec<_> = assignments
            .iter()
            .map(|assignment| assignment.symbol_indices.len())
            .collect();

        assert_eq!(counts, vec![2, 0]);
    }

    #[test]
    fn weighted_handles_near_u32_max_existing_symbol_counts() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(3);
        let replicas = create_test_replicas_with_symbol_counts(&[u32::MAX, u32::MAX - 1]);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 2);

        assert_eq!(assignments[0].symbol_indices, vec![1]);
        assert_eq!(assignments[1].symbol_indices, vec![0, 2]);

        let mut assigned_once: Vec<_> = assignments
            .iter()
            .flat_map(|assignment| assignment.symbol_indices.iter().copied())
            .collect();
        assigned_once.sort_unstable();
        assert_eq!(assigned_once, vec![0, 1, 2]);
    }

    #[test]
    fn metamorphic_weighted_assignment_invariant_under_uniform_load_shift() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let symbols = create_test_symbols(37);

        let baseline_replicas = create_test_replicas_with_symbol_counts(&[0, 3, 9, 3]);
        let shifted_replicas =
            create_test_replicas_with_symbol_counts(&[10_000, 10_003, 10_009, 10_003]);

        let baseline = assigner.assign_authorized(&symbols, &baseline_replicas, 4);
        let shifted = assigner.assign_authorized(&symbols, &shifted_replicas, 4);

        assert_eq!(
            baseline, shifted,
            "weighted assignment should depend on relative projected load; adding \
             the same constant to every replica must not change the plan"
        );
    }

    // ========== Edge case tests (bd-3k9o) ==========

    #[test]
    fn full_more_replicas_than_symbols() {
        // 3 symbols, 10 replicas — every replica gets all 3
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(3);
        let replicas = create_test_replicas(10);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 2);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 1);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 10);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 3);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 3);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 2);

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
    fn striped_assignment_preserves_existing_residue_classes_when_symbols_extend() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let replicas = create_test_replicas(4);
        let base_symbols = create_test_symbols(11);
        let extended_symbols = create_test_symbols(base_symbols.len() + replicas.len() * 2);

        let base_plan = assigner.assign_authorized(&base_symbols, &replicas, 99);
        let extended_plan = assigner.assign_authorized(&extended_symbols, &replicas, 99);

        assert_eq!(base_plan.len(), extended_plan.len());
        for (replica_idx, (base, extended)) in base_plan.iter().zip(&extended_plan).enumerate() {
            assert_eq!(base.replica_id, extended.replica_id);

            let preserved_indices: Vec<_> = extended
                .symbol_indices
                .iter()
                .copied()
                .filter(|&idx| idx < base_symbols.len())
                .collect();
            assert_eq!(
                preserved_indices, base.symbol_indices,
                "extending symbols must not reshuffle existing striped assignments"
            );

            let appended_indices: Vec<_> = extended
                .symbol_indices
                .iter()
                .copied()
                .filter(|&idx| idx >= base_symbols.len())
                .collect();
            assert_eq!(
                appended_indices.len(),
                2,
                "two complete replica periods should add two symbols per replica"
            );

            for idx in &extended.symbol_indices {
                assert_eq!(
                    idx % replicas.len(),
                    replica_idx,
                    "striped assignment must keep replica residue classes stable"
                );
            }
        }
    }

    #[test]
    fn minimum_k_single_replica() {
        // Single replica should get at least K symbols
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(10);
        let replicas = create_test_replicas(1);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 5);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 5);

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

        let assignments = assigner.assign_authorized(&symbols, &replicas, 10);

        for a in &assignments {
            assert!(!a.can_decode);
        }
    }

    #[test]
    fn minimum_k_no_duplicate_indices() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let symbols = create_test_symbols(20);
        let replicas = create_test_replicas(4);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 8);

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

    // ========== Replica Authorization Tests (asupersync-j18rga) ==========

    #[test]
    fn replica_authorization_filters_unauthorized_replicas() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(5);
        let security_context = SecurityContext::for_testing(42);

        // Mix of authorized and unauthorized replica IDs
        let mut replicas = vec![
            ReplicaInfo::new("replica-auth-1", "addr1"), // authorized
            ReplicaInfo::new("node-auth-2", "addr2"),    // authorized
            ReplicaInfo::new("r3", "addr3"),             // authorized
            ReplicaInfo::new("invalid-test", "addr4"),   // unauthorized (contains "test")
            ReplicaInfo::new("rogue-replica", "addr5"),  // unauthorized (not authorized)
            ReplicaInfo::new("", "addr6"),               // unauthorized (empty ID)
        ];

        let assignments = assigner.assign(&symbols, &replicas, &security_context, None, 3);

        // Should only get assignments for the 3 authorized replicas
        assert_eq!(assignments.len(), 3);

        let replica_ids: Vec<_> = assignments.iter().map(|a| &a.replica_id).collect();
        assert!(replica_ids.contains(&&"replica-auth-1".to_string()));
        assert!(replica_ids.contains(&&"node-auth-2".to_string()));
        assert!(replica_ids.contains(&&"r3".to_string()));

        // Unauthorized replicas should not appear in assignments
        assert!(!replica_ids.contains(&&"invalid-test".to_string()));
        assert!(!replica_ids.contains(&&"rogue-replica".to_string()));
        assert!(!replica_ids.contains(&&"".to_string()));
    }

    #[test]
    fn all_unauthorized_replicas_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(5);
        let security_context = SecurityContext::for_testing(42);

        // All unauthorized replicas
        let replicas = vec![
            ReplicaInfo::new("test-replica", "addr1"), // contains "test"
            ReplicaInfo::new("rogue-node", "addr2"),   // not authorized
            ReplicaInfo::new("", "addr3"),             // empty ID
        ];

        let assignments = assigner.assign(&symbols, &replicas, &security_context, None, 3);

        // Should return empty since no replicas are authorized
        assert!(assignments.is_empty());
    }

    #[test]
    fn replica_authorization_preserves_assignment_strategy_semantics() {
        let symbols = create_test_symbols(12);
        let security_context = SecurityContext::for_testing(42);

        // All authorized replicas
        let replicas = vec![
            ReplicaInfo::new("replica-1", "addr1"),
            ReplicaInfo::new("replica-2", "addr2"),
            ReplicaInfo::new("replica-3", "addr3"),
        ];

        // Test that striped assignment still works correctly with authorization
        let striped = SymbolAssigner::new(AssignmentStrategy::Striped);
        let assignments = striped.assign(&symbols, &replicas, &security_context, None, 4);

        // Collect all assigned indices to verify complete assignment
        let mut all: Vec<usize> = Vec::new();
        for a in &assignments {
            all.extend_from_slice(&a.symbol_indices);
        }
        all.sort_unstable();
        all.dedup();

        assert_eq!(all.len(), 12, "all symbols should be assigned exactly once");
        assert_eq!(
            assignments.len(),
            3,
            "all authorized replicas should get assignments"
        );
    }

    #[test]
    fn both_empty_returns_empty() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let security_context = SecurityContext::for_testing(42);
        let assignments = assigner.assign(&[], &[], &security_context, None, 5);
        assert!(assignments.is_empty());
    }

    #[test]
    fn full_k_zero() {
        // k=0: every replica can decode (0 symbols needed)
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let symbols = create_test_symbols(5);
        let replicas = create_test_replicas(2);

        let assignments = assigner.assign_authorized(&symbols, &replicas, 0);

        for a in &assignments {
            assert!(a.can_decode);
        }
    }

    #[test]
    fn assignment_strategy_conformance_matrix() {
        let symbols = create_test_symbols(8);
        let replicas = create_test_replicas(3);
        let expected_all_indices: Vec<_> = (0..symbols.len()).collect();

        for strategy in [
            AssignmentStrategy::Full,
            AssignmentStrategy::Striped,
            AssignmentStrategy::MinimumK,
            AssignmentStrategy::Weighted,
        ] {
            let plan = SymbolAssigner::new(strategy).assign_authorized(&symbols, &replicas, 4);
            assert_eq!(
                plan.len(),
                replicas.len(),
                "{strategy:?}: one assignment per replica"
            );

            for assignment in &plan {
                assert!(
                    assignment
                        .symbol_indices
                        .iter()
                        .all(|&idx| idx < symbols.len()),
                    "{strategy:?}: assigned indices must stay within the symbol set"
                );

                let mut per_replica = assignment.symbol_indices.clone();
                per_replica.sort_unstable();
                per_replica.dedup();
                assert_eq!(
                    per_replica.len(),
                    assignment.symbol_indices.len(),
                    "{strategy:?}: per-replica assignments must not duplicate indices"
                );
            }

            match strategy {
                AssignmentStrategy::Full => {
                    for assignment in &plan {
                        assert_eq!(assignment.symbol_indices, expected_all_indices);
                        assert!(
                            assignment.can_decode,
                            "full replication with 8 symbols and k=4 must decode everywhere"
                        );
                    }
                }
                AssignmentStrategy::Striped => {
                    let mut assigned_once: Vec<_> = plan
                        .iter()
                        .flat_map(|assignment| assignment.symbol_indices.iter().copied())
                        .collect();
                    assigned_once.sort_unstable();
                    assert_eq!(
                        assigned_once, expected_all_indices,
                        "striping must assign every symbol exactly once"
                    );
                    assert!(
                        plan.iter().all(|assignment| !assignment.can_decode),
                        "8 symbols striped over 3 replicas stays below k=4 per replica"
                    );
                }
                AssignmentStrategy::MinimumK => {
                    for assignment in &plan {
                        assert_eq!(assignment.symbol_indices.len(), 4);
                        assert!(
                            assignment.can_decode,
                            "minimum-k must provide k symbols per replica"
                        );
                    }
                }
                AssignmentStrategy::Weighted => {
                    let mut assigned_once: Vec<_> = plan
                        .iter()
                        .flat_map(|assignment| assignment.symbol_indices.iter().copied())
                        .collect();
                    assigned_once.sort_unstable();
                    assert_eq!(
                        assigned_once, expected_all_indices,
                        "weighted assignment must assign every symbol exactly once"
                    );
                }
            }
        }
    }

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn assignment_strategy_debug_clone_copy_eq() {
        let s = AssignmentStrategy::Striped;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Striped"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, AssignmentStrategy::Full);
    }

    #[test]
    fn replica_assignment_debug_clone() {
        let ra = ReplicaAssignment {
            replica_id: "r0".to_string(),
            symbol_indices: vec![0, 1, 2],
            can_decode: true,
        };
        let dbg = format!("{ra:?}");
        assert!(dbg.contains("ReplicaAssignment"), "{dbg}");
        let cloned = ra;
        assert_eq!(cloned.replica_id, "r0");
        assert_eq!(cloned.symbol_indices, [0, 1, 2]);
    }

    // ---- Golden plan snapshots (bead asupersync-a64jii) --------------------
    //
    // The four AssignmentStrategy variants produce deterministic routing
    // plans. Their outputs feed downstream quorum / distribution logic, so
    // silent regressions (off-by-one in round-robin, rotation-offset drift
    // in MinimumK, tie-break change in Weighted) would propagate without
    // being caught by the existing property-style tests above.
    //
    // The fixtures below fix a canonical asymmetric input — 3 replicas with
    // prior symbol_count [10, 5, 20] so Weighted's load-balancing is visible,
    // 8 symbols, k=4 — and snapshot the entire Vec<ReplicaAssignment> Debug
    // output via insta. To intentionally update a plan:
    //   UPDATE_SNAPSHOTS=1 cargo test -p asupersync --lib distributed::assignment::tests::golden_
    //   cargo insta review
    //   git diff src/distributed/snapshots/
    //
    // Each strategy gets its own #[test] so a plan change shows up in only
    // one snapshot, making review localized.

    fn golden_replicas() -> Vec<ReplicaInfo> {
        create_test_replicas_with_symbol_counts(&[10, 5, 20])
    }

    fn golden_symbols() -> Vec<Symbol> {
        create_test_symbols(8)
    }

    const GOLDEN_K: u16 = 4;

    #[test]
    fn golden_plan_full_strategy() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
        let plan = assigner.assign_authorized(&golden_symbols(), &golden_replicas(), GOLDEN_K);
        insta::assert_debug_snapshot!(plan);
    }

    #[test]
    fn golden_plan_striped_strategy() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Striped);
        let plan = assigner.assign_authorized(&golden_symbols(), &golden_replicas(), GOLDEN_K);
        insta::assert_debug_snapshot!(plan);
    }

    #[test]
    fn golden_plan_minimum_k_strategy() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let plan = assigner.assign_authorized(&golden_symbols(), &golden_replicas(), GOLDEN_K);
        insta::assert_debug_snapshot!(plan);
    }

    #[test]
    fn golden_plan_weighted_strategy() {
        let assigner = SymbolAssigner::new(AssignmentStrategy::Weighted);
        let plan = assigner.assign_authorized(&golden_symbols(), &golden_replicas(), GOLDEN_K);
        insta::assert_debug_snapshot!(plan);
    }

    // ================================================================
    // br-asupersync-45xcbm — algorithmic-complexity DoS regression
    // ================================================================

    /// Replay-determinism: every replica's `symbol_indices` is sorted
    /// (BTreeSet's natural iteration order). The previous Vec-based
    /// implementation produced an insertion-ordered list whose order
    /// happened to match index-ascending in practice but was not a
    /// documented invariant. Lock the new explicit invariant here.
    #[test]
    fn assign_minimum_k_returns_sorted_indices() {
        let symbols = create_test_symbols(64);
        let replicas = create_test_replicas(4);
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let plan = assigner.assign_authorized(&symbols, &replicas, 16);

        for assignment in &plan {
            let mut sorted = assignment.symbol_indices.clone();
            sorted.sort_unstable();
            assert_eq!(
                assignment.symbol_indices, sorted,
                "br-45xcbm: symbol_indices must be sorted (BTreeSet iteration order)"
            );
        }
    }

    /// Determinism: identical input produces byte-identical output
    /// across repeated calls (no ambient hashing or thread-state
    /// leakage in the dedup path).
    #[test]
    fn assign_minimum_k_is_deterministic_across_calls() {
        let symbols = create_test_symbols(256);
        let replicas = create_test_replicas(8);
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let p1 = assigner.assign_authorized(&symbols, &replicas, 64);
        for _ in 0..8 {
            let pn = assigner.assign_authorized(&symbols, &replicas, 64);
            assert_eq!(p1, pn, "assign_minimum_k must be deterministic");
        }
    }

    /// br-asupersync-45xcbm: K = 10_000 must complete quickly with the
    /// BTreeSet-based dedup. The previous Vec::contains O(K^2) path
    /// would take seconds for this shape; the BTreeSet path completes
    /// in well under one second on commodity hardware.
    ///
    /// We assert a generous wall-clock bound (5 seconds) — the point
    /// of this test is to fail loudly if a future refactor reverts
    /// to O(K^2). Under the new code this completes in ~milliseconds.
    #[test]
    fn assign_minimum_k_handles_k_10000_quickly() {
        let k: u16 = 10_000;
        let symbols = create_test_symbols(k as usize);
        let replicas = create_test_replicas(8);
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);

        let started = std::time::Instant::now();
        let plan = assigner.assign_authorized(&symbols, &replicas, k);
        let elapsed = started.elapsed();

        assert_eq!(plan.len(), 8);
        for assignment in &plan {
            assert!(
                assignment.can_decode,
                "every replica must hold at least K={k} symbols"
            );
            assert_eq!(
                assignment.symbol_indices.len(),
                k as usize,
                "each replica receives exactly K symbols"
            );
        }
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "assign_minimum_k(K=10000) must complete in under 5s; took {elapsed:?} \
             (regression: did dedup revert to O(K^2)?)"
        );
    }

    /// Edge case: K equals symbol count. The fill-up branch should
    /// not fire (every replica's rotated window already covers all
    /// symbols modulo dedup), and the resulting assignment must be
    /// the identity set 0..symbols.len() for every replica.
    #[test]
    fn assign_minimum_k_when_k_equals_symbol_count() {
        let symbols = create_test_symbols(32);
        let replicas = create_test_replicas(2);
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let plan = assigner.assign_authorized(&symbols, &replicas, 32);
        for assignment in &plan {
            assert_eq!(assignment.symbol_indices.len(), 32);
            // Sorted 0..32 by BTreeSet invariant.
            for (i, idx) in assignment.symbol_indices.iter().enumerate() {
                assert_eq!(*idx, i);
            }
        }
    }

    /// Edge case: zero-symbol input. The function must not panic on
    /// modulo-by-zero or empty-iteration paths; every replica gets
    /// an empty `symbol_indices` and `can_decode = false` (since
    /// 0 < K for any non-zero K).
    #[test]
    fn assign_minimum_k_handles_empty_symbols() {
        let symbols: Vec<Symbol> = Vec::new();
        let replicas = create_test_replicas(3);
        let assigner = SymbolAssigner::new(AssignmentStrategy::MinimumK);
        let plan = assigner.assign_authorized(&symbols, &replicas, 4);
        for assignment in &plan {
            assert!(assignment.symbol_indices.is_empty());
            assert!(!assignment.can_decode);
        }
    }
}
