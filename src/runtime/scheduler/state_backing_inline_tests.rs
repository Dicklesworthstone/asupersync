    use super::*;
    use crate::types::Budget;

    /// Verifies the trait's existence + dispatch shape via the
    /// unified RuntimeState impl. This is intentionally minimal — the
    /// real coverage is the existing scheduler test suite, which keeps
    /// exercising RuntimeState directly until 30atgp.3 routes through
    /// the trait.
    #[test]
    fn unified_runtime_state_implements_backing_trait() {
        let mut state = RuntimeState::new();
        let _root = state.create_root_region(Budget::INFINITE);

        // Dispatch via the trait. If this compiles + runs, the trait is
        // properly implemented for RuntimeState.
        fn assert_impl<B: RuntimeStateBacking>(_b: &B) {}
        assert_impl(&state);

        // current_time pass-through.
        let now_via_trait = RuntimeStateBacking::current_time(&state);
        assert_eq!(now_via_trait, state.now);
    }

    /// Sanity: drain_ready_async_finalizers via the trait yields the
    /// same SmallVec the direct method does (both empty on a fresh
    /// RuntimeState).
    #[test]
    fn drain_ready_async_finalizers_via_trait_matches_direct() {
        let mut state = RuntimeState::new();
        let trait_drained: SmallVec<[(TaskId, u8, TaskSpawnEffects); 2]> =
            RuntimeStateBacking::drain_ready_async_finalizers(&mut state);
        assert!(trait_drained.is_empty());
        let direct_drained = state.drain_ready_async_finalizers();
        assert!(direct_drained.is_empty());
    }
