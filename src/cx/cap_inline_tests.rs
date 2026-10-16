    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // Helper: assert a type satisfies SubsetOf at compile time.
    fn assert_subset<Sub: SubsetOf<Super>, Super>() {}

    // Helper: assert a marker trait at compile time.
    fn assert_has_spawn<C: HasSpawn>() {}
    fn assert_has_time<C: HasTime>() {}
    fn assert_has_random<C: HasRandom>() {}
    fn assert_has_io<C: HasIo>() {}
    fn assert_has_remote<C: HasRemote>() {}

    // --- Reflexivity ---

    #[test]
    fn subset_reflexive_all() {
        assert_subset::<All, All>();
    }

    #[test]
    fn subset_reflexive_none() {
        assert_subset::<None, None>();
    }

    #[test]
    fn subset_reflexive_mixed() {
        // CapSet<true, false, true, false, true> ⊆ itself
        assert_subset::<
            CapSet<true, false, true, false, true>,
            CapSet<true, false, true, false, true>,
        >();
    }

    // --- Bottom and top ---

    #[test]
    fn none_subset_of_all() {
        assert_subset::<None, All>();
    }

    #[test]
    fn none_subset_of_any() {
        assert_subset::<None, CapSet<false, true, false, false, true>>();
        assert_subset::<None, CapSet<true, false, false, false, false>>();
    }

    #[test]
    fn any_subset_of_all() {
        assert_subset::<CapSet<true, false, true, false, true>, All>();
        assert_subset::<CapSet<false, false, false, true, false>, All>();
    }

    // --- Intermediate narrowing (framework wrapper types) ---

    #[test]
    fn background_subset_of_grpc() {
        // Background = <true, true, false, false, false>
        // Grpc       = <true, true, false, true, false>
        // Background ⊆ Grpc (Background drops IO)
        type BackgroundCaps = CapSet<true, true, false, false, false>;
        type GrpcCaps = CapSet<true, true, false, true, false>;
        assert_subset::<BackgroundCaps, GrpcCaps>();
    }

    #[test]
    fn web_subset_of_all() {
        // Web = <false, true, false, true, false>
        type WebCaps = CapSet<false, true, false, true, false>;
        assert_subset::<WebCaps, All>();
    }

    #[test]
    fn pure_subset_of_web() {
        // Pure = None = <false, false, false, false, false>
        // Web  = <false, true, false, true, false>
        type WebCaps = CapSet<false, true, false, true, false>;
        assert_subset::<None, WebCaps>();
    }

    #[test]
    fn single_cap_subset_of_multi() {
        // <false, true, false, false, false> ⊆ <true, true, false, true, false>
        assert_subset::<
            CapSet<false, true, false, false, false>,
            CapSet<true, true, false, true, false>,
        >();
    }

    // --- Transitivity (demonstrated, not mechanized) ---

    #[test]
    fn transitive_none_background_grpc() {
        type BackgroundCaps = CapSet<true, true, false, false, false>;
        type GrpcCaps = CapSet<true, true, false, true, false>;
        // None ⊆ Background ⊆ Grpc, therefore None ⊆ Grpc
        assert_subset::<None, BackgroundCaps>();
        assert_subset::<BackgroundCaps, GrpcCaps>();
        assert_subset::<None, GrpcCaps>();
    }

    // --- Marker traits ---

    #[test]
    fn all_has_every_capability() {
        assert_has_spawn::<All>();
        assert_has_time::<All>();
        assert_has_random::<All>();
        assert_has_io::<All>();
        assert_has_remote::<All>();
    }

    #[test]
    fn partial_caps_have_correct_markers() {
        // <true, true, false, true, false> has Spawn+Time+Io but not Random/Remote
        assert_has_spawn::<CapSet<true, true, false, true, false>>();
        assert_has_time::<CapSet<true, true, false, true, false>>();
        assert_has_io::<CapSet<true, true, false, true, false>>();
    }

    // --- ZST property ---

    #[test]
    fn capset_is_zero_sized() {
        assert_eq!(std::mem::size_of::<All>(), 0);
        assert_eq!(std::mem::size_of::<None>(), 0);
        assert_eq!(
            std::mem::size_of::<CapSet<true, false, true, false, true>>(),
            0
        );
    }

    // --- Compile-fail doctests for anti-forgery are on HasSpawn and SubsetOf above ---

    // =========================================================================
    // Wave 54 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn capset_debug_clone_copy_default() {
        let all = All::default();
        let dbg = format!("{all:?}");
        assert!(dbg.contains("CapSet"), "{dbg}");
        let copied = all;
        let cloned = all;
        // ZST so all instances are identical
        let _ = (copied, cloned);

        let none = None::default();
        let dbg_none = format!("{none:?}");
        assert!(dbg_none.contains("CapSet"), "{dbg_none}");
    }

    #[test]
    fn default_implementations_correct() {
        // All::default() should have all capabilities
        let all = All::default();
        assert_has_spawn::<All>();
        assert_has_time::<All>();
        assert_has_random::<All>();
        assert_has_io::<All>();
        assert_has_remote::<All>();

        // Verify the type is actually All, not None
        let _: All = all; // This should compile

        // None::default() should have no capabilities
        let none = None::default();
        let _: None = none; // This should compile

        // Verify they are different types at compile-time
        fn verify_all_has_spawn(_: impl HasSpawn) {}
        verify_all_has_spawn(all); // Should compile
        // verify_all_has_spawn(none); // Should NOT compile
    }
