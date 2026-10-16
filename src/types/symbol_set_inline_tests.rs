    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::Symbol;

    fn test_symbol(sbn: u8, esi: u32, data_len: usize) -> Symbol {
        Symbol::new_source_for_test(1, sbn, esi, &vec![0u8; data_len])
    }

    fn test_repair_symbol(sbn: u8, esi: u32, data_len: usize) -> Symbol {
        Symbol::new_repair_for_test(1, sbn, esi, &vec![0u8; data_len])
    }

    #[test]
    fn insert_and_duplicate() {
        let mut set = SymbolSet::new();
        let symbol = test_symbol(0, 0, 4);
        assert!(matches!(
            set.insert(symbol.clone()),
            InsertResult::Inserted { .. }
        ));
        assert!(matches!(set.insert(symbol), InsertResult::Duplicate));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn threshold_tracking() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_config(config);
        assert!(!set.threshold_reached(0));

        let _ = set.insert(test_symbol(0, 0, 4));
        assert!(!set.threshold_reached(0));

        set.set_block_k(0, 1);
        assert!(set.threshold_reached(0));
    }

    #[test]
    fn repair_symbols_increment_repair_progress() {
        let mut set = SymbolSet::new();
        let symbol = test_repair_symbol(0, 99, 4);

        let InsertResult::Inserted { block_progress, .. } = set.insert(symbol) else {
            panic!("repair symbol should insert");
        };

        assert_eq!(block_progress.source_symbols, 0);
        assert_eq!(block_progress.repair_symbols, 1);
    }

    #[test]
    fn block_limit_enforced() {
        let config = ThresholdConfig::new(1.0, 0, 1);
        let mut set = SymbolSet::with_config(config);
        assert!(matches!(
            set.insert(test_symbol(1, 0, 1)),
            InsertResult::Inserted { .. }
        ));
        assert!(matches!(
            set.insert(test_symbol(1, 1, 1)),
            InsertResult::BlockLimitReached { sbn: 1 }
        ));
    }

    #[test]
    fn memory_budget_enforced() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_memory_budget(config, 8);
        let large = test_symbol(0, 0, 128);
        assert!(matches!(
            set.insert(large),
            InsertResult::MemoryLimitReached
        ));
    }

    #[test]
    fn clear_block_removes_only_block() {
        let mut set = SymbolSet::new();
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(1, 0, 4));
        assert_eq!(set.len(), 2);

        set.clear_block(0);
        assert_eq!(set.len(), 1);
        assert!(set.symbols_for_block(0).next().is_none());
        assert!(set.symbols_for_block(1).next().is_some());
    }

    /// Invariant: remove decrements counts and frees memory.
    #[test]
    fn remove_decrements_counts_and_memory() {
        let mut set = SymbolSet::new();
        let sym = test_symbol(0, 0, 16);
        let id = sym.id();
        let _ = set.insert(sym);
        assert_eq!(set.len(), 1);
        let mem_before = set.memory_usage();
        assert!(mem_before > 0);

        let removed = set.remove(&id);
        assert!(removed.is_some());
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        assert_eq!(set.memory_usage(), 0);
    }

    /// Invariant: ConcurrentSymbolSet basic insert and threshold operations work.
    #[test]
    fn concurrent_symbol_set_insert_and_threshold() {
        let css = ConcurrentSymbolSet::new();
        let sym = test_symbol(0, 0, 4);
        assert!(matches!(css.insert(sym), InsertResult::Inserted { .. }));
        assert!(!css.threshold_reached(0));

        css.set_block_k(0, 1);
        assert!(css.threshold_reached(0));
    }

    /// Invariant: ready_blocks returns only blocks that have reached threshold.
    #[test]
    fn ready_blocks_returns_threshold_blocks() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_config(config);
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(1, 0, 4));
        set.set_block_k(0, 1); // block 0 ready
        // block 1 not ready (no K set)

        let ready = set.ready_blocks();
        assert_eq!(ready.len(), 1);
        assert!(ready.contains(&0));
    }

    #[test]
    fn ready_blocks_are_sorted() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_config(config);
        let _ = set.insert(test_symbol(2, 0, 4));
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(1, 0, 4));

        assert!(set.set_block_k(2, 1));
        assert!(set.set_block_k(0, 1));
        assert!(set.set_block_k(1, 1));

        assert_eq!(set.ready_blocks(), vec![0, 1, 2]);
    }

    /// Invariant: clear resets all symbol state.
    #[test]
    fn clear_resets_all_state() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_memory_budget(config, 4096);
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(0, 1, 4));
        set.set_block_k(0, 2);
        assert_eq!(set.len(), 2);
        assert!(set.memory_usage() > 0);

        set.clear();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.memory_usage(), 0);
        assert!(!set.threshold_reached(0));
    }

    /// Invariant: block_progress returns correct source/repair counts.
    #[test]
    fn block_progress_tracking() {
        let mut set = SymbolSet::new();
        assert!(set.block_progress(0).is_none());

        let _ = set.insert(test_symbol(0, 0, 4)); // source (esi < K when K set)
        let progress = set.block_progress(0).unwrap();
        assert_eq!(
            progress.total(),
            progress.source_symbols + progress.repair_symbols
        );
        assert_eq!(progress.sbn, 0);
    }

    #[test]
    fn iter_and_drain_symbols() {
        let mut set = SymbolSet::new();
        let _ = set.insert(test_symbol(0, 0, 4));
        let _ = set.insert(test_symbol(0, 1, 4));

        assert_eq!(set.iter().count(), 2);
        assert_eq!(set.len(), 2);

        let drained = set.drain().count();
        assert_eq!(drained, 2);
        assert!(set.is_empty());
        assert_eq!(set.memory_usage(), 0);
    }

    #[test]
    fn zero_k_never_reaches_threshold() {
        let config = ThresholdConfig::new(1.0, 0, 0);
        let mut set = SymbolSet::with_config(config);
        let _ = set.insert(test_symbol(0, 0, 4));
        assert!(!set.set_block_k(0, 0));
        assert!(!set.threshold_reached(0));
    }

    #[test]
    fn threshold_calculation_saturates_min_overhead() {
        let config = ThresholdConfig::new(1.0, usize::MAX, 0);
        let mut set = SymbolSet::with_config(config);
        let _ = set.insert(test_symbol(0, 0, 4));
        assert!(!set.set_block_k(0, 2));
        assert!(!set.threshold_reached(0));
    }

    #[test]
    fn threshold_reached_when_minimum_extra_dominates_without_double_counting() {
        // Config: factor=1.05 → ceil(10*1.05)=11, min_overhead=3 → K+3=13
        // threshold = max(11, 13) = 13
        // Use fewer than K source symbols to avoid the source_symbols >= K
        // short-circuit, then fill the rest with repair symbols.
        let config = ThresholdConfig::new(1.05, 3, 0);
        let mut set = SymbolSet::with_config(config);
        assert!(!set.set_block_k(0, 10));

        // Insert 5 source + 7 repair = 12 total (threshold = 13)
        for esi in 0..5 {
            let _ = set.insert(test_symbol(0, esi, 4));
        }
        for esi in 5..12 {
            let _ = set.insert(test_repair_symbol(0, esi, 4));
        }
        assert!(!set.threshold_reached(0));

        // Insert 1 more repair symbol (total = 13, threshold = 13)
        let _ = set.insert(test_repair_symbol(0, 12, 4));
        assert!(set.threshold_reached(0));
    }

    #[test]
    fn threshold_reached_when_factor_dominates_without_extra_increment() {
        // Config: factor=1.5 → ceil(10*1.5)=15, min_overhead=1 → K+1=11
        // threshold = max(15, 11) = 15
        let config = ThresholdConfig::new(1.5, 1, 0);
        let mut set = SymbolSet::with_config(config);
        assert!(!set.set_block_k(0, 10));

        // Insert 5 source + 9 repair = 14 total (threshold = 15)
        for esi in 0..5 {
            let _ = set.insert(test_symbol(0, esi, 4));
        }
        for esi in 5..14 {
            let _ = set.insert(test_repair_symbol(0, esi, 4));
        }
        assert!(!set.threshold_reached(0));

        // Insert 1 more repair symbol (total = 15, threshold = 15)
        let _ = set.insert(test_repair_symbol(0, 14, 4));
        assert!(set.threshold_reached(0));
    }

    #[test]
    fn threshold_does_not_reach_with_infinite_overhead_before_all_sources_arrive() {
        // With infinite factor the threshold is never reached (line 375-376 returns false).
        // Use only repair symbols beyond K to avoid source_symbols >= K short-circuit.
        let config = ThresholdConfig::new(f64::INFINITY, 0, 0);
        let mut set = SymbolSet::with_config(config);
        assert!(!set.set_block_k(0, 10));

        // Insert 9 source symbols (< K, so source check doesn't trigger)
        for esi in 0..9 {
            let _ = set.insert(test_symbol(0, esi, 4));
        }
        // Insert 56 repair symbols (total = 65, but infinite threshold)
        for esi in 9..65 {
            let _ = set.insert(test_repair_symbol(0, esi, 4));
        }

        assert!(!set.threshold_reached(0));
    }

    // =========================================================================
    // Wave 56 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn threshold_config_debug_clone_copy() {
        let cfg = ThresholdConfig::new(1.02, 0, 0);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("ThresholdConfig"), "{dbg}");
        let copied = cfg;
        let cloned = cfg;
        assert!((copied.overhead_factor - cloned.overhead_factor).abs() < f64::EPSILON);
    }

    #[test]
    fn insert_result_debug_clone() {
        let mut set = SymbolSet::new();
        let result = set.insert(test_symbol(0, 0, 4));
        let dbg = format!("{result:?}");
        assert!(dbg.contains("Insert"), "{dbg}");
        let cloned = result;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }
