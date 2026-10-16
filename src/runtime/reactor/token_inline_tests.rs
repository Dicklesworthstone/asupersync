    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;

    fn test_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn token_pack_unpack() {
        init_test("token_pack_unpack");
        let token = SlabToken::new(42, 7);
        let packed = token.to_usize();
        let unpacked = SlabToken::from_usize(packed);

        crate::assert_with_log!(token == unpacked, "token round-trip", token, unpacked);
        crate::assert_with_log!(
            unpacked.index() == 42,
            "index round-trip",
            42u32,
            unpacked.index()
        );
        crate::assert_with_log!(
            unpacked.generation() == 7,
            "generation round-trip",
            7u32,
            unpacked.generation()
        );
        crate::test_complete!("token_pack_unpack");
    }

    #[test]
    fn token_pack_unpack_max_values() {
        init_test("token_pack_unpack_max_values");
        #[cfg(target_pointer_width = "64")]
        let max_index = u32::MAX - 1;
        #[cfg(target_pointer_width = "32")]
        let max_index = SlabToken::MAX_INDEX;

        let token = SlabToken::new(max_index, SlabToken::MAX_GENERATION);
        let packed = token.to_usize();
        let unpacked = SlabToken::from_usize(packed);

        crate::assert_with_log!(token == unpacked, "max token round-trip", token, unpacked);
        crate::test_complete!("token_pack_unpack_max_values");
    }

    #[test]
    fn slab_insert_and_get() {
        init_test("slab_insert_and_get");
        let mut slab = TokenSlab::new();
        let waker = test_waker();

        let token = slab.insert(waker);

        crate::assert_with_log!(slab.len() == 1, "len after insert", 1usize, slab.len());
        crate::assert_with_log!(!slab.is_empty(), "slab not empty", false, slab.is_empty());
        let contains = slab.contains(token);
        crate::assert_with_log!(contains, "slab contains token", true, contains);
        let get_some = slab.get(token).is_some();
        crate::assert_with_log!(get_some, "slab get returns", true, get_some);
        crate::test_complete!("slab_insert_and_get");
    }

    #[test]
    fn slab_remove() {
        init_test("slab_remove");
        let mut slab = TokenSlab::new();
        let waker = test_waker();

        let token = slab.insert(waker);
        let removed = slab.remove(token);

        crate::assert_with_log!(
            removed.is_some(),
            "remove returns some",
            true,
            removed.is_some()
        );
        crate::assert_with_log!(slab.is_empty(), "len after remove", 0usize, slab.len());
        crate::assert_with_log!(
            slab.is_empty(),
            "slab empty after remove",
            true,
            slab.is_empty()
        );
        let contains = slab.contains(token);
        crate::assert_with_log!(!contains, "token removed", false, contains);
        let get_none = slab.get(token).is_none();
        crate::assert_with_log!(get_none, "get returns none", true, get_none);
        crate::test_complete!("slab_remove");
    }

    #[test]
    fn slab_generation_prevents_aba() {
        init_test("slab_generation_prevents_aba");
        let mut slab = TokenSlab::new();

        // Insert first waker.
        let token1 = slab.insert(test_waker());
        crate::assert_with_log!(
            token1.generation() == 0,
            "initial generation",
            0u32,
            token1.generation()
        );

        // Remove it.
        slab.remove(token1);

        // Insert second waker (reuses the slot).
        let token2 = slab.insert(test_waker());
        crate::assert_with_log!(
            token2.index() == token1.index(),
            "slot reused",
            token1.index(),
            token2.index()
        );
        crate::assert_with_log!(
            token2.generation() == 1,
            "generation incremented",
            1u32,
            token2.generation()
        );

        // Old token should not work.
        let contains_old = slab.contains(token1);
        crate::assert_with_log!(!contains_old, "old token invalid", false, contains_old);
        let old_get = slab.get(token1).is_none();
        crate::assert_with_log!(old_get, "old token get none", true, old_get);

        // New token should work.
        let contains_new = slab.contains(token2);
        crate::assert_with_log!(contains_new, "new token valid", true, contains_new);
        let new_get = slab.get(token2).is_some();
        crate::assert_with_log!(new_get, "new token get some", true, new_get);
        crate::test_complete!("slab_generation_prevents_aba");
    }

    #[test]
    fn slab_reuses_free_slots() {
        init_test("slab_reuses_free_slots");
        let mut slab = TokenSlab::new();

        // Insert three wakers.
        let t1 = slab.insert(test_waker());
        let t2 = slab.insert(test_waker());
        let t3 = slab.insert(test_waker());

        crate::assert_with_log!(slab.len() == 3, "len after inserts", 3usize, slab.len());

        // Remove the middle one.
        slab.remove(t2);
        crate::assert_with_log!(slab.len() == 2, "len after remove", 2usize, slab.len());

        // Insert a new one - should reuse t2's slot.
        let t4 = slab.insert(test_waker());
        crate::assert_with_log!(
            t4.index() == t2.index(),
            "reused slot index",
            t2.index(),
            t4.index()
        );
        crate::assert_with_log!(
            t4.generation() != t2.generation(),
            "generation advanced",
            true,
            t4.generation() != t2.generation()
        );

        // Old tokens still work.
        let contains_t1 = slab.contains(t1);
        let contains_t3 = slab.contains(t3);
        let contains_t4 = slab.contains(t4);
        let contains_t2 = slab.contains(t2);
        crate::assert_with_log!(contains_t1, "t1 still valid", true, contains_t1);
        crate::assert_with_log!(contains_t3, "t3 still valid", true, contains_t3);
        crate::assert_with_log!(contains_t4, "t4 valid", true, contains_t4);
        crate::assert_with_log!(!contains_t2, "t2 invalidated", false, contains_t2);
        crate::test_complete!("slab_reuses_free_slots");
    }

    #[test]
    fn slab_multiple_inserts_removes() {
        init_test("slab_multiple_inserts_removes");
        let mut slab = TokenSlab::new();
        let mut tokens = Vec::new();

        // Insert many wakers.
        for _ in 0..100 {
            tokens.push(slab.insert(test_waker()));
        }
        crate::assert_with_log!(slab.len() == 100, "len after inserts", 100usize, slab.len());

        // Remove every other one.
        for i in (0..100).step_by(2) {
            slab.remove(tokens[i]);
        }
        crate::assert_with_log!(slab.len() == 50, "len after removes", 50usize, slab.len());

        // Insert more.
        for _ in 0..25 {
            tokens.push(slab.insert(test_waker()));
        }
        crate::assert_with_log!(slab.len() == 75, "len after reinserts", 75usize, slab.len());
        crate::test_complete!("slab_multiple_inserts_removes");
    }

    #[test]
    fn slab_get_invalid_index() {
        init_test("slab_get_invalid_index");
        let slab: TokenSlab = TokenSlab::new();
        let token = SlabToken::new(999, 0);

        let contains = slab.contains(token);
        crate::assert_with_log!(!contains, "invalid token not contained", false, contains);
        let get_none = slab.get(token).is_none();
        crate::assert_with_log!(get_none, "invalid token get none", true, get_none);
        crate::test_complete!("slab_get_invalid_index");
    }

    #[test]
    fn slab_remove_invalid_index_preserves_state() {
        init_test("slab_remove_invalid_index_preserves_state");
        let mut slab = TokenSlab::new();
        let token = slab.insert(test_waker());
        let invalid = SlabToken::new(token.index() + 10, token.generation());

        let removed = slab.remove(invalid);
        crate::assert_with_log!(
            removed.is_none(),
            "invalid-index remove returns none",
            true,
            removed.is_none()
        );
        crate::assert_with_log!(
            slab.len() == 1,
            "invalid-index remove keeps len",
            1usize,
            slab.len()
        );
        let contains = slab.contains(token);
        crate::assert_with_log!(contains, "original token still valid", true, contains);

        let removed_original = slab.remove(token);
        crate::assert_with_log!(
            removed_original.is_some(),
            "original remove still succeeds",
            true,
            removed_original.is_some()
        );
        crate::assert_with_log!(
            slab.is_empty(),
            "slab empty after original remove",
            true,
            slab.is_empty()
        );
        crate::test_complete!("slab_remove_invalid_index_preserves_state");
    }

    #[test]
    fn slab_remove_invalid_generation() {
        init_test("slab_remove_invalid_generation");
        let mut slab = TokenSlab::new();

        let token = slab.insert(test_waker());
        let stale_token = SlabToken::new(token.index(), token.generation() + 1);

        // Remove with wrong generation should fail.
        let removed = slab.remove(stale_token).is_none();
        crate::assert_with_log!(removed, "stale remove fails", true, removed);
        // Original token should still work.
        let contains = slab.contains(token);
        crate::assert_with_log!(contains, "original token still valid", true, contains);
        crate::test_complete!("slab_remove_invalid_generation");
    }

    #[test]
    fn slab_double_remove() {
        init_test("slab_double_remove");
        let mut slab = TokenSlab::new();

        let token = slab.insert(test_waker());
        let removed1 = slab.remove(token);
        let removed2 = slab.remove(token);

        crate::assert_with_log!(
            removed1.is_some(),
            "first remove succeeds",
            true,
            removed1.is_some()
        );
        crate::assert_with_log!(
            removed2.is_none(),
            "second remove fails",
            true,
            removed2.is_none()
        );
        crate::test_complete!("slab_double_remove");
    }

    #[test]
    fn slab_clear() {
        init_test("slab_clear");
        let mut slab = TokenSlab::new();

        for _ in 0..10 {
            slab.insert(test_waker());
        }
        crate::assert_with_log!(slab.len() == 10, "len before clear", 10usize, slab.len());

        slab.clear();
        crate::assert_with_log!(slab.is_empty(), "len after clear", 0usize, slab.len());
        crate::assert_with_log!(
            slab.is_empty(),
            "slab empty after clear",
            true,
            slab.is_empty()
        );
        crate::test_complete!("slab_clear");
    }

    #[test]
    fn slab_retain() {
        init_test("slab_retain");
        let mut slab = TokenSlab::new();

        let tokens: Vec<_> = (0..10).map(|_| slab.insert(test_waker())).collect();
        crate::assert_with_log!(slab.len() == 10, "len before retain", 10usize, slab.len());

        // Keep only even indices.
        slab.retain(|token, _| token.index() % 2 == 0);
        crate::assert_with_log!(slab.len() == 5, "len after retain", 5usize, slab.len());

        // Verify even tokens are retained, odd are removed.
        for (i, token) in tokens.iter().enumerate() {
            let contains = slab.contains(*token);
            if i % 2 == 0 {
                crate::assert_with_log!(contains, "even token retained", true, contains);
            } else {
                crate::assert_with_log!(!contains, "odd token removed", false, contains);
            }
        }
        crate::test_complete!("slab_retain");
    }

    #[test]
    fn slab_iter() {
        init_test("slab_iter");
        let mut slab = TokenSlab::new();

        let tokens: Vec<_> = (0..5).map(|_| slab.insert(test_waker())).collect();

        // Remove one.
        slab.remove(tokens[2]);

        // Iterate - should see 4 entries.
        let iter_tokens: Vec<_> = slab.iter().map(|(t, _)| t).collect();
        crate::assert_with_log!(
            iter_tokens.len() == 4,
            "iter length",
            4usize,
            iter_tokens.len()
        );
        let contains_0 = iter_tokens.contains(&tokens[0]);
        let contains_1 = iter_tokens.contains(&tokens[1]);
        let contains_2 = iter_tokens.contains(&tokens[2]);
        let contains_3 = iter_tokens.contains(&tokens[3]);
        let contains_4 = iter_tokens.contains(&tokens[4]);
        crate::assert_with_log!(contains_0, "iter contains token 0", true, contains_0);
        crate::assert_with_log!(contains_1, "iter contains token 1", true, contains_1);
        crate::assert_with_log!(!contains_2, "iter omits removed", false, contains_2);
        crate::assert_with_log!(contains_3, "iter contains token 3", true, contains_3);
        crate::assert_with_log!(contains_4, "iter contains token 4", true, contains_4);
        crate::test_complete!("slab_iter");
    }

    #[test]
    fn slab_with_capacity() {
        init_test("slab_with_capacity");
        let slab: TokenSlab = TokenSlab::with_capacity(100);
        crate::assert_with_log!(
            slab.capacity() >= 100,
            "capacity at least requested",
            true,
            slab.capacity() >= 100
        );
        crate::assert_with_log!(slab.is_empty(), "slab starts empty", true, slab.is_empty());
        crate::test_complete!("slab_with_capacity");
    }

    #[test]
    fn slab_supports_non_waker_payloads() {
        init_test("slab_supports_non_waker_payloads");
        let mut slab = TokenSlab::<u64>::new();
        let token = slab.insert(42);
        let stored = slab.get(token).copied();
        let removed = slab.remove(token);

        crate::assert_with_log!(stored == Some(42), "generic get", Some(42), stored);
        crate::assert_with_log!(removed == Some(42), "generic remove", Some(42), removed);
        crate::assert_with_log!(slab.is_empty(), "generic slab empty", true, slab.is_empty());
        crate::test_complete!("slab_supports_non_waker_payloads");
    }

    #[test]
    fn token_invalid() {
        init_test("token_invalid");
        let token = SlabToken::invalid();
        crate::assert_with_log!(
            token.index() == u32::MAX,
            "invalid index",
            u32::MAX,
            token.index()
        );
        crate::assert_with_log!(
            token.generation() == u32::MAX,
            "invalid generation",
            u32::MAX,
            token.generation()
        );
        crate::test_complete!("token_invalid");
    }

    #[test]
    fn slab_get_mut() {
        init_test("slab_get_mut");
        let mut slab = TokenSlab::new();

        let token = slab.insert(test_waker());

        // Get mutable reference.
        let has_mut = slab.get_mut(token).is_some();
        crate::assert_with_log!(has_mut, "get_mut succeeds", true, has_mut);

        // Remove and try again.
        slab.remove(token);
        let has_mut_after = slab.get_mut(token).is_none();
        crate::assert_with_log!(has_mut_after, "get_mut after remove", true, has_mut_after);
        crate::test_complete!("slab_get_mut");
    }

    #[test]
    fn slab_clear_invalidates_stale_tokens() {
        init_test("slab_clear_invalidates_stale_tokens");
        let mut slab = TokenSlab::new();

        let stale = slab.insert(test_waker());
        slab.clear();

        let contains_stale = slab.contains(stale);
        crate::assert_with_log!(
            !contains_stale,
            "stale token invalid after clear",
            false,
            contains_stale
        );

        let fresh = slab.insert(test_waker());
        crate::assert_with_log!(
            fresh.index() == stale.index(),
            "slot reused after clear",
            stale.index(),
            fresh.index()
        );
        crate::assert_with_log!(
            fresh.generation() != stale.generation(),
            "generation advanced across clear",
            true,
            fresh.generation() != stale.generation()
        );
        crate::assert_with_log!(
            slab.get(stale).is_none(),
            "old token still rejected after reuse",
            true,
            slab.get(stale).is_none()
        );
        crate::test_complete!("slab_clear_invalidates_stale_tokens");
    }

    #[test]
    fn slab_clear_already_empty_keeps_stale_tokens_invalid() {
        init_test("slab_clear_already_empty_keeps_stale_tokens_invalid");
        let mut slab = TokenSlab::new();

        let stale = slab.insert(test_waker());
        slab.remove(stale);
        slab.clear();

        crate::assert_with_log!(
            slab.get(stale).is_none(),
            "removed token remains stale after empty clear",
            true,
            slab.get(stale).is_none()
        );

        let fresh = slab.insert(test_waker());
        crate::assert_with_log!(
            slab.contains(fresh),
            "fresh token after empty clear is live",
            true,
            slab.contains(fresh)
        );
        crate::assert_with_log!(
            fresh != stale,
            "empty clear does not reuse stale token generation",
            true,
            fresh != stale
        );
        crate::test_complete!("slab_clear_already_empty_keeps_stale_tokens_invalid");
    }

    #[test]
    fn token_default() {
        init_test("token_default");
        let token = SlabToken::default();
        crate::assert_with_log!(
            token == SlabToken::invalid(),
            "default is invalid",
            SlabToken::invalid(),
            token
        );
        crate::test_complete!("token_default");
    }

    #[test]
    fn slab_token_debug_clone_copy_hash() {
        use std::collections::HashSet;

        let t = SlabToken::from_usize(42);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("SlabToken"));

        let t2 = t;
        assert_eq!(t, t2);

        // Copy
        let t3 = t;
        assert_eq!(t, t3);

        // Hash
        let mut set = HashSet::new();
        set.insert(t);
        set.insert(SlabToken::from_usize(99));
        assert_eq!(set.len(), 2);
        assert!(set.contains(&t));
    }

    /// br-asupersync-rtiu1s — On any platform, MAX_GENERATION is at
    /// least 2^16 - 1 = 65,535. The 32-bit packing was previously
    /// 24 bits index + 8 bits generation (MAX_GENERATION = 0xFF =
    /// 255), which wrapped after 256 reuse cycles per slot — an ABA
    /// collision in any long-running reactor. The fix splits the
    /// 32-bit usize as 16+16, raising the wrap point to 65,536.
    #[test]
    fn max_generation_supports_at_least_2_to_16_cycles() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(SlabToken::MAX_GENERATION, u32::MAX);

        #[cfg(target_pointer_width = "32")]
        assert_eq!(SlabToken::MAX_GENERATION, 0xFFFF);
    }

    /// br-asupersync-rtiu1s — Pack/unpack round-trip preserves
    /// generation values across the 256→65535 range. The previous 8-bit
    /// 32-bit packing would silently truncate any generation > 255 to
    /// 255 mod 256 == the same generation value as one issued 256
    /// cycles earlier.
    #[test]
    fn pack_unpack_preserves_high_generation_values() {
        for g in [0u32, 1, 255, 256, 1024, 4096, 65_535] {
            let token = SlabToken::new(42, g);
            let round = SlabToken::from_usize(token.to_usize());
            assert_eq!(
                round.generation(),
                g,
                "br-asupersync-rtiu1s: generation {g} not preserved through pack/unpack"
            );
            assert_eq!(round.index(), 42);
        }
    }

    /// br-asupersync-rtiu1s — Two tokens that differ only in the
    /// generation byte beyond the 8-bit boundary now hash and compare
    /// distinctly. With the prior packing, generations 0 and 256 had
    /// the same packed representation on 32-bit, so a stale token from
    /// the first allocation would compare equal to a fresh token after
    /// 256 reuses.
    #[test]
    fn high_bit_generation_does_not_collide_with_low() {
        let low = SlabToken::new(7, 0);
        let high = SlabToken::new(7, 256);
        // Direct comparison (struct level): they differ.
        assert_ne!(low, high);
        // Packed representation: must also differ. Pre-fix, on 32-bit
        // these collided.
        assert_ne!(
            low.to_usize(),
            high.to_usize(),
            "br-asupersync-rtiu1s: gen=0 and gen=256 must pack to distinct usize"
        );
    }
