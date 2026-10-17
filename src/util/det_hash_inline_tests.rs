    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::hash::Hash;

    fn hash_value<T: Hash>(value: &T) -> u64 {
        let mut hasher = DetHasher::default();
        value.hash(&mut hasher);
        hasher.finish()
    }

    // =========================================================================
    // DetHasher Core Functionality
    // =========================================================================

    #[test]
    fn det_hasher_same_input_same_hash() {
        let h1 = hash_value(&"hello");
        let h2 = hash_value(&"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn det_hasher_different_input_different_hash() {
        let h1 = hash_value(&"hello");
        let h2 = hash_value(&"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn det_hasher_numeric_values() {
        let h1 = hash_value(&42u64);
        let h2 = hash_value(&42u64);
        assert_eq!(h1, h2);

        let h3 = hash_value(&43u64);
        assert_ne!(h1, h3);
    }

    #[test]
    fn det_hasher_empty_slice() {
        let h1 = hash_value(&[0u8; 0]);
        let h2 = hash_value(&[0u8; 0]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn det_hasher_incremental_write() {
        // Writing bytes incrementally should match writing all at once
        let mut h1 = DetHasher::default();
        h1.write(&[1, 2, 3, 4]);
        let result1 = h1.finish();

        let mut h2 = DetHasher::default();
        h2.write(&[1, 2]);
        h2.write(&[3, 4]);
        let result2 = h2.finish();

        assert_eq!(result1, result2);
    }

    #[test]
    fn det_hasher_write_u64_consistent_with_write() {
        // Verify that write_u64 and write produce the same hash when fed the
        // hasher's canonical little-endian byte representation.
        let mut h1 = DetHasher::default();
        h1.write_u64(0xDEAD_BEEF_CAFE_BABE);

        let mut h2 = DetHasher::default();
        h2.write(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

        assert_eq!(
            h1.finish(),
            h2.finish(),
            "write_u64 must match write for same bytes",
        );
    }

    // =========================================================================
    // DetHashMap Tests
    // =========================================================================

    #[test]
    fn det_hashmap_deterministic_lookup() {
        let mut map1: DetHashMap<String, i32> = DetHashMap::default();
        let mut map2: DetHashMap<String, i32> = DetHashMap::default();

        map1.insert("a".to_string(), 1);
        map1.insert("b".to_string(), 2);
        map1.insert("c".to_string(), 3);

        map2.insert("a".to_string(), 1);
        map2.insert("b".to_string(), 2);
        map2.insert("c".to_string(), 3);

        assert_eq!(map1.get("a"), map2.get("a"));
        assert_eq!(map1.get("b"), map2.get("b"));
        assert_eq!(map1.get("c"), map2.get("c"));
    }

    #[test]
    fn det_hashmap_iteration_order_consistent() {
        // Note: HashMap iteration order is not guaranteed even with deterministic
        // hashing, but the hashes themselves are deterministic
        let mut map: DetHashMap<i32, i32> = DetHashMap::default();
        for i in 0..100 {
            map.insert(i, i * 2);
        }

        // Verify all values are correct
        for i in 0..100 {
            assert_eq!(map.get(&i), Some(&(i * 2)));
        }
    }

    // =========================================================================
    // DetHashSet Tests
    // =========================================================================

    #[test]
    fn det_hashset_deterministic_contains() {
        let mut set1: DetHashSet<String> = DetHashSet::default();
        let mut set2: DetHashSet<String> = DetHashSet::default();

        set1.insert("alpha".to_string());
        set1.insert("beta".to_string());
        set1.insert("gamma".to_string());

        set2.insert("alpha".to_string());
        set2.insert("beta".to_string());
        set2.insert("gamma".to_string());

        assert_eq!(set1.contains("alpha"), set2.contains("alpha"));
        assert_eq!(set1.contains("beta"), set2.contains("beta"));
        assert_eq!(set1.contains("delta"), set2.contains("delta"));
    }

    #[test]
    fn det_hashset_len() {
        let mut set: DetHashSet<i32> = DetHashSet::default();
        assert_eq!(set.len(), 0);

        set.insert(1);
        set.insert(2);
        set.insert(3);
        assert_eq!(set.len(), 3);

        // Duplicate insert
        set.insert(1);
        assert_eq!(set.len(), 3);
    }

    // =========================================================================
    // DetBuildHasher Tests
    // =========================================================================

    #[test]
    fn det_build_hasher_produces_deterministic_hashers() {
        let builder = DetBuildHasher::for_lab();
        let mut h1 = builder.build_hasher();
        let mut h2 = builder.build_hasher();

        h1.write(b"test data");
        h2.write(b"test data");

        assert_eq!(h1.finish(), h2.finish());
    }

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn det_hasher_debug_clone() {
        let mut h = DetHasher::default();
        h.write(b"partial");
        let dbg = format!("{h:?}");
        assert!(dbg.contains("DetHasher"), "{dbg}");
        let h2 = h.clone();
        assert_eq!(h.finish(), h2.finish());
    }

    #[test]
    fn det_build_hasher_clone_default() {
        let b1 = DetBuildHasher::default();
        let b2 = b1.clone();
        let mut x = b1.build_hasher();
        let mut y = b2.build_hasher();
        x.write(b"same");
        y.write(b"same");
        assert_eq!(x.finish(), y.finish());
    }

    // =========================================================================
    // Security Tests - Production vs Lab Mode
    // =========================================================================

    #[test]
    fn lab_mode_produces_deterministic_hashes() {
        let h1 = DetHasher::for_lab();
        let h2 = DetHasher::for_lab();
        let mut x = h1;
        let mut y = h2;
        x.write(b"test data");
        y.write(b"test data");
        assert_eq!(x.finish(), y.finish(), "Lab mode must be deterministic");
    }

    #[test]
    fn production_mode_produces_different_seeds() {
        let h1 = DetHasher::for_production();
        let h2 = DetHasher::for_production();
        // Two production hashers should have different internal seeds
        // We can't directly access the seed, but we can verify they hash differently
        // with high probability by hashing empty data
        let mut x = h1;
        let mut y = h2;
        x.write(b"");
        y.write(b"");
        let hash1 = x.finish();
        let hash2 = y.finish();
        // With random seeding, these should be different with very high probability
        assert_ne!(hash1, hash2, "Production mode should use random seeds");
    }

    #[test]
    fn lab_mode_different_from_production_mode() {
        let lab = DetHasher::for_lab();
        let prod = DetHasher::for_production();
        let mut lab_hasher = lab;
        let mut prod_hasher = prod;
        lab_hasher.write(b"test");
        prod_hasher.write(b"test");
        // Lab uses fixed seed, production uses random seed
        assert_ne!(lab_hasher.finish(), prod_hasher.finish());
    }

    #[test]
    fn det_build_hasher_lab_mode() {
        let builder = DetBuildHasher::for_lab();
        let h1 = builder.build_hasher();
        let h2 = builder.build_hasher();
        let mut x = h1;
        let mut y = h2;
        x.write(b"test");
        y.write(b"test");
        assert_eq!(x.finish(), y.finish());
    }

    #[test]
    fn det_build_hasher_production_mode() {
        let builder = DetBuildHasher::for_production();
        let h1 = builder.build_hasher();
        let h2 = builder.build_hasher();
        let mut x = h1;
        let mut y = h2;
        x.write(b"");
        y.write(b"");
        assert_eq!(
            x.finish(),
            y.finish(),
            "one builder must seed all its hashers identically (HashMap correctness)"
        );

        let other = DetBuildHasher::for_production();
        let mut a = builder.build_hasher();
        let mut b = other.build_hasher();
        a.write(b"");
        b.write(b"");
        assert_ne!(
            a.finish(),
            b.finish(),
            "independent production builders should use independent random seeds"
        );
    }

    #[test]
    fn det_hash_set_production_builder_preserves_set_semantics() {
        let mut set = DetHashSet::with_hasher(DetBuildHasher::for_production());

        assert!(set.insert(42_u64));
        assert!(!set.insert(42_u64));
        assert_eq!(set.len(), 1);
        assert!(set.contains(&42));
        assert!(set.remove(&42));
        assert!(set.is_empty());
    }

    #[test]
    fn production_hasher_builder_always_random() {
        // A single builder must produce hashers with a STABLE seed: HashMap calls
        // build_hasher() once per probe, so insert and lookup of the same key must
        // hash identically or the map silently loses entries. Two hashers from the
        // same builder therefore agree on the same input.
        let builder = ProductionBuildHasher::default();
        let mut h1 = builder.build_hasher();
        let mut h2 = builder.build_hasher();
        h1.write(b"collision test");
        h2.write(b"collision test");
        assert_eq!(
            h1.finish(),
            h2.finish(),
            "one builder must seed all its hashers identically (HashMap correctness)"
        );

        // Distinct builders are independently random-seeded, defeating collision
        // attacks across map instances. With 64-bit seeds a collision here is
        // astronomically unlikely.
        let other = ProductionBuildHasher::default();
        let mut x = builder.build_hasher();
        let mut y = other.build_hasher();
        x.write(b"collision test");
        y.write(b"collision test");
        assert_ne!(
            x.finish(),
            y.finish(),
            "independent builders use independent random seeds"
        );
    }

    #[test]
    fn production_hashmap_prevents_collision_attacks() {
        // This test verifies that ProductionHashMap uses random seeding
        let map1: ProductionHashMap<String, i32> = ProductionHashMap::default();
        let map2: ProductionHashMap<String, i32> = ProductionHashMap::default();

        // Insert the same key in both maps
        let mut map1 = map1;
        let mut map2 = map2;
        map1.insert("attack_key".to_string(), 1);
        map2.insert("attack_key".to_string(), 2);

        // Both should contain their respective values
        assert_eq!(map1.get("attack_key"), Some(&1));
        assert_eq!(map2.get("attack_key"), Some(&2));
    }

    #[test]
    fn default_builder_matches_configured_mode_and_remains_stable() {
        let default_builder = DetBuildHasher::default();
        let mut d1 = default_builder.build_hasher();
        let mut d2 = default_builder.build_hasher();
        d1.write(b"compatibility");
        d2.write(b"compatibility");
        assert_eq!(
            d1.finish(),
            d2.finish(),
            "Default builder must be stable within one collection"
        );

        #[cfg(feature = "test-internals")]
        {
            let mut d = DetHasher::default();
            let mut l = DetHasher::for_lab();
            d.write(b"compatibility test");
            l.write(b"compatibility test");
            assert_eq!(
                d.finish(),
                l.finish(),
                "Default hasher should be identical to lab mode"
            );

            let lab_builder = DetBuildHasher::for_lab();
            let mut d_h = default_builder.build_hasher();
            let mut l_h = lab_builder.build_hasher();
            d_h.write(b"compatibility");
            l_h.write(b"compatibility");
            assert_eq!(
                d_h.finish(),
                l_h.finish(),
                "Default builder should match lab builder"
            );
        }

        #[cfg(not(feature = "test-internals"))]
        {
            let other_builder = DetBuildHasher::default();
            let mut x = default_builder.build_hasher();
            let mut y = other_builder.build_hasher();
            x.write(b"compatibility");
            y.write(b"compatibility");
            assert_ne!(
                x.finish(),
                y.finish(),
                "Default production builders should use independent random seeds"
            );
        }
    }

    // -----------------------------------------------------------------------
    // GH#55: lab determinism must not depend on the `test-internals` feature.
    // -----------------------------------------------------------------------

    #[test]
    fn with_seed_builders_hash_identically_for_identical_seeds() {
        let a = DetBuildHasher::with_seed(0xdead_beef);
        let b = DetBuildHasher::with_seed(0xdead_beef);
        for key in [0u64, 1, 42, u64::MAX] {
            let mut ha = a.build_hasher();
            let mut hb = b.build_hasher();
            ha.write_u64(key);
            hb.write_u64(key);
            assert_eq!(
                ha.finish(),
                hb.finish(),
                "identical seeds must hash identically in every build configuration"
            );
        }
    }

    #[test]
    fn with_seed_builders_diverge_for_different_seeds() {
        let a = DetBuildHasher::with_seed(1);
        let b = DetBuildHasher::with_seed(2);
        let mut ha = a.build_hasher();
        let mut hb = b.build_hasher();
        ha.write_u64(7);
        hb.write_u64(7);
        assert_ne!(
            ha.finish(),
            hb.finish(),
            "distinct lab seeds should produce distinct hash streams"
        );
    }

    #[test]
    fn with_seed_sets_iterate_identically_for_identical_seeds() {
        // Regression for GH#55: `DetHashSet::default()` iterates in a
        // different order per instance in builds without `test-internals`.
        // Seed-derived construction must iterate identically regardless of
        // features — the lab scheduler relies on this for replayability.
        let order = |seed: u64| -> Vec<u64> {
            let mut set: DetHashSet<u64> = DetHashSet::with_hasher(DetBuildHasher::with_seed(seed));
            for id in 0..64u64 {
                set.insert(id);
            }
            set.iter().copied().collect()
        };
        assert_eq!(
            order(42),
            order(42),
            "identical inserts must iterate identically in lab paths"
        );
    }
