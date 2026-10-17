    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn object_id_conversions() {
        let id = ObjectId::new(0x1234_5678_9abc_def0, 0xfed_cba9_8765_4321);
        assert_eq!(id.high(), 0x1234_5678_9abc_def0);
        assert_eq!(id.low(), 0xfed_cba9_8765_4321);

        let from_u128 = ObjectId::from_u128(id.as_u128());
        assert_eq!(id, from_u128);
    }

    #[test]
    fn object_id_nil() {
        let nil = ObjectId::NIL;
        assert_eq!(nil.high(), 0);
        assert_eq!(nil.low(), 0);
        assert_eq!(nil.as_u128(), 0);
    }

    #[test]
    fn object_id_test_constructor() {
        let id = ObjectId::new_for_test(42);
        assert_eq!(id.high(), 0);
        assert_eq!(id.low(), 42);
    }

    #[test]
    fn symbol_id_creation() {
        let object_id = ObjectId::new_for_test(1);
        let symbol_id = SymbolId::new(object_id, 0, 5);

        assert_eq!(symbol_id.object_id(), object_id);
        assert_eq!(symbol_id.sbn(), 0);
        assert_eq!(symbol_id.esi(), 5);
    }

    #[test]
    fn symbol_id_source_vs_repair() {
        let symbol_id = SymbolId::new_for_test(1, 0, 5);

        // With 10 source symbols, ESI 5 is a source symbol
        assert!(symbol_id.is_source(10));
        assert!(!symbol_id.is_repair(10));

        // With 5 source symbols, ESI 5 is a repair symbol
        assert!(!symbol_id.is_source(5));
        assert!(symbol_id.is_repair(5));
    }

    #[test]
    fn symbol_creation_and_data() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let data = vec![1, 2, 3, 4, 5];
        let symbol = Symbol::new(id, data.clone(), SymbolKind::Source);

        assert_eq!(symbol.id(), id);
        assert_eq!(symbol.kind(), SymbolKind::Source);
        assert_eq!(symbol.data(), &data[..]);
        assert_eq!(symbol.len(), 5);
        assert!(!symbol.is_empty());
    }

    #[test]
    fn symbol_from_slice() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let data = [10, 20, 30];
        let symbol = Symbol::from_slice(id, &data, SymbolKind::Repair);

        assert_eq!(symbol.data(), &data[..]);
        assert_eq!(symbol.kind(), SymbolKind::Repair);
    }

    #[test]
    fn symbol_empty() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::empty(id, 100, SymbolKind::Source);

        assert_eq!(symbol.len(), 100);
        assert!(symbol.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn symbol_into_data() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let original_data = vec![1, 2, 3];
        let symbol = Symbol::new(id, original_data.clone(), SymbolKind::Source);

        let recovered = symbol.into_data();
        assert_eq!(recovered, original_data);
    }

    #[test]
    fn symbol_kind_checks() {
        assert!(SymbolKind::Source.is_source());
        assert!(!SymbolKind::Source.is_repair());
        assert!(!SymbolKind::Repair.is_source());
        assert!(SymbolKind::Repair.is_repair());
    }

    #[test]
    fn object_params_calculations() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            10000, // 10KB object
            1280,  // symbol size
            1,     // 1 source block
            8,     // 8 symbols per block
        );

        assert_eq!(params.min_symbols_for_decode(), 8);
        assert_eq!(params.total_source_symbols(), 8);
    }

    #[test]
    fn object_params_multi_block() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            327_680, // 4 full blocks * 64 symbols/block * 1280 bytes
            1280,
            4,  // 4 source blocks
            64, // 64 symbols per block
        );

        assert_eq!(params.min_symbols_for_decode(), 256);
        assert_eq!(params.total_source_symbols(), 256);
    }

    #[test]
    fn object_params_can_represent_full_256_block_contract() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            327_680, // 256 blocks * 1 symbol/block * 1280 bytes
            1280,
            256,
            1,
        );

        assert_eq!(params.source_blocks, 256);
        assert_eq!(params.min_symbols_for_decode(), 256);
        assert_eq!(params.total_source_symbols(), 256);
    }

    #[test]
    fn object_params_partial_last_block_does_not_overcount_total_symbols() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            326_400, // 255 symbols worth of payload at 1280 bytes each
            1280,
            4,
            64,
        );

        assert_eq!(params.min_symbols_for_decode(), 255);
        assert_eq!(params.total_source_symbols(), 255);
    }

    #[test]
    fn display_formatting() {
        let object_id = ObjectId::new(0x1234_5678_0000_0000, 0);
        assert!(format!("{object_id}").contains("Obj-"));

        let symbol_id = SymbolId::new(object_id, 1, 42);
        let display = format!("{symbol_id}");
        assert!(display.contains(":1:42"));

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let display = format!("{symbol}");
        assert!(display.contains("3 bytes"));
    }

    // =========================================================================
    // Wave 31: Data-type trait coverage
    // =========================================================================

    #[test]
    fn object_id_ord() {
        let a = ObjectId::new(0, 1);
        let b = ObjectId::new(0, 2);
        let c = ObjectId::new(1, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn object_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ObjectId::new_for_test(1));
        set.insert(ObjectId::new_for_test(2));
        set.insert(ObjectId::new_for_test(1));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn symbol_id_ord_hash() {
        use std::collections::HashSet;
        let a = SymbolId::new_for_test(1, 0, 0);
        let b = SymbolId::new_for_test(1, 0, 1);
        assert!(a < b);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(a);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn symbol_kind_clone_copy_hash_display() {
        use std::collections::HashSet;
        let src = SymbolKind::Source;
        let rep = SymbolKind::Repair;
        let cloned = src; // Copy
        assert_eq!(cloned, src);
        assert_eq!(format!("{src}"), "source");
        assert_eq!(format!("{rep}"), "repair");
        let mut set = HashSet::new();
        set.insert(src);
        set.insert(rep);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn symbol_clone_hash() {
        use std::collections::HashSet;
        let sym = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let cloned = sym.clone();
        assert_eq!(sym, cloned);
        let mut set = HashSet::new();
        set.insert(sym);
        set.insert(cloned);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn symbol_data_mut() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let mut symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        symbol.data_mut()[0] = 99;
        assert_eq!(symbol.data()[0], 99);
    }

    #[test]
    fn symbol_empty_is_empty() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::empty(id, 0, SymbolKind::Source);
        assert!(symbol.is_empty());
        assert_eq!(symbol.len(), 0);
    }

    #[test]
    fn symbol_convenience_accessors() {
        let sym = Symbol::new_for_test(42, 3, 7, &[10, 20]);
        assert_eq!(sym.object_id(), ObjectId::new_for_test(42));
        assert_eq!(sym.sbn(), 3);
        assert_eq!(sym.esi(), 7);
    }

    #[test]
    fn symbol_test_constructor_defaults_to_source() {
        let sym = Symbol::new_for_test(42, 3, 7, &[10, 20]);
        assert_eq!(sym.kind(), SymbolKind::Source);
    }

    #[test]
    fn symbol_repair_test_constructor_preserves_repair_kind() {
        let sym = Symbol::new_repair_for_test(42, 3, 7, &[10, 20]);
        assert_eq!(sym.kind(), SymbolKind::Repair);
    }

    #[test]
    fn object_params_clone_copy_display() {
        let params = ObjectParams::new_for_test(1, 5000);
        let cloned = params;
        let copied = params; // Copy
        assert_eq!(cloned, copied);
        let display = format!("{params}");
        assert!(display.contains("ObjectParams"));
        assert!(display.contains("5000"));
    }

    #[test]
    fn debug_formatting() {
        let object_id = ObjectId::new_for_test(42);
        let debug = format!("{object_id:?}");
        assert!(debug.contains("ObjectId"));

        let symbol_id = SymbolId::new_for_test(1, 2, 3);
        let debug = format!("{symbol_id:?}");
        assert!(debug.contains("SymbolId"));
        assert!(debug.contains("sbn=2"));
        assert!(debug.contains("esi=3"));
    }
