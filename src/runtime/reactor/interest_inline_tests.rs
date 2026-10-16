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

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn interest_constants() {
        init_test("interest_constants");
        crate::test_section!("bits");
        crate::assert_with_log!(
            Interest::NONE.bits() == 0,
            "NONE bits",
            0,
            Interest::NONE.bits()
        );
        crate::assert_with_log!(
            Interest::READABLE.bits() == 1,
            "READABLE bits",
            1,
            Interest::READABLE.bits()
        );
        crate::assert_with_log!(
            Interest::WRITABLE.bits() == 2,
            "WRITABLE bits",
            2,
            Interest::WRITABLE.bits()
        );
        crate::assert_with_log!(
            Interest::ERROR.bits() == 4,
            "ERROR bits",
            4,
            Interest::ERROR.bits()
        );
        crate::assert_with_log!(
            Interest::HUP.bits() == 8,
            "HUP bits",
            8,
            Interest::HUP.bits()
        );
        crate::assert_with_log!(
            Interest::PRIORITY.bits() == 16,
            "PRIORITY bits",
            16,
            Interest::PRIORITY.bits()
        );
        crate::assert_with_log!(
            Interest::ONESHOT.bits() == 32,
            "ONESHOT bits",
            32,
            Interest::ONESHOT.bits()
        );
        crate::assert_with_log!(
            Interest::EDGE_TRIGGERED.bits() == 64,
            "EDGE_TRIGGERED bits",
            64,
            Interest::EDGE_TRIGGERED.bits()
        );
        crate::assert_with_log!(
            Interest::DISPATCH.bits() == 128,
            "DISPATCH bits",
            128,
            Interest::DISPATCH.bits()
        );
        crate::test_complete!("interest_constants");
    }

    #[test]
    fn interest_combining() {
        init_test("interest_combining");
        let interest = Interest::READABLE | Interest::WRITABLE;
        crate::assert_with_log!(
            interest.is_readable(),
            "combined interest is readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "combined interest is writable",
            true,
            interest.is_writable()
        );
        crate::assert_with_log!(
            !interest.is_error(),
            "combined interest excludes error",
            false,
            interest.is_error()
        );
        crate::assert_with_log!(
            interest == Interest::both(),
            "combined interest equals both()",
            Interest::both(),
            interest
        );
        crate::test_complete!("interest_combining");
    }

    #[test]
    fn interest_contains() {
        init_test("interest_contains");
        let interest = Interest::READABLE | Interest::WRITABLE | Interest::ERROR;
        crate::assert_with_log!(
            interest.contains(Interest::READABLE),
            "contains READABLE",
            true,
            interest.contains(Interest::READABLE)
        );
        crate::assert_with_log!(
            interest.contains(Interest::WRITABLE),
            "contains WRITABLE",
            true,
            interest.contains(Interest::WRITABLE)
        );
        crate::assert_with_log!(
            interest.contains(Interest::ERROR),
            "contains ERROR",
            true,
            interest.contains(Interest::ERROR)
        );
        crate::assert_with_log!(
            interest.contains(Interest::both()),
            "contains both()",
            true,
            interest.contains(Interest::both())
        );
        crate::assert_with_log!(
            !interest.contains(Interest::HUP),
            "does not contain HUP",
            false,
            interest.contains(Interest::HUP)
        );
        crate::test_complete!("interest_contains");
    }

    #[test]
    fn interest_add_remove() {
        init_test("interest_add_remove");
        let mut interest = Interest::READABLE;
        interest = interest.add(Interest::WRITABLE);
        crate::assert_with_log!(
            interest.is_readable(),
            "readable retained after add",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "writable set after add",
            true,
            interest.is_writable()
        );

        interest = interest.remove(Interest::READABLE);
        crate::assert_with_log!(
            !interest.is_readable(),
            "readable removed",
            false,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "writable remains",
            true,
            interest.is_writable()
        );
        crate::test_complete!("interest_add_remove");
    }

    #[test]
    fn interest_bit_operators() {
        init_test("interest_bit_operators");
        // BitOr
        let interest = Interest::READABLE | Interest::WRITABLE;
        crate::assert_with_log!(interest.bits() == 3, "bitor bits", 3, interest.bits());

        // BitAnd
        let masked = interest & Interest::READABLE;
        crate::assert_with_log!(
            masked.is_readable(),
            "bitand keeps readable",
            true,
            masked.is_readable()
        );
        crate::assert_with_log!(
            !masked.is_writable(),
            "bitand clears writable",
            false,
            masked.is_writable()
        );

        // BitOrAssign
        let mut interest = Interest::READABLE;
        interest |= Interest::WRITABLE;
        crate::assert_with_log!(
            interest.is_writable(),
            "bitorassign sets writable",
            true,
            interest.is_writable()
        );

        // BitAndAssign
        interest &= Interest::READABLE;
        crate::assert_with_log!(
            !interest.is_writable(),
            "bitandassign clears writable",
            false,
            interest.is_writable()
        );

        // Not
        let not_readable = !Interest::READABLE;
        crate::assert_with_log!(
            !not_readable.is_readable(),
            "not clears readable",
            false,
            not_readable.is_readable()
        );
        crate::assert_with_log!(
            (not_readable.bits() & !Interest::ALL.bits()) == 0,
            "not keeps only defined bits",
            0,
            not_readable.bits() & !Interest::ALL.bits()
        );
        crate::test_complete!("interest_bit_operators");
    }

    #[test]
    fn interest_not_masks_undefined_bits() {
        init_test("interest_not_masks_undefined_bits");
        let unknown = Interest::from_bits(1 << 7);
        let inverted = !unknown;

        crate::assert_with_log!(
            (inverted.bits() & !Interest::ALL.bits()) == 0,
            "inverted mask excludes undefined bits",
            0,
            inverted.bits() & !Interest::ALL.bits()
        );
        crate::assert_with_log!(
            !inverted.is_empty(),
            "inverting unknown raw bits yields defined set complement",
            true,
            !inverted.is_empty()
        );
        crate::test_complete!("interest_not_masks_undefined_bits");
    }

    #[test]
    fn interest_not_none_equals_all() {
        init_test("interest_not_none_equals_all");
        let inverted_none = !Interest::NONE;
        crate::assert_with_log!(
            inverted_none == Interest::ALL,
            "inverting NONE yields all defined flags",
            Interest::ALL,
            inverted_none
        );
        crate::test_complete!("interest_not_none_equals_all");
    }

    #[test]
    fn interest_socket() {
        init_test("interest_socket");
        let socket = Interest::SOCKET;
        crate::assert_with_log!(
            socket.is_readable(),
            "socket readable",
            true,
            socket.is_readable()
        );
        crate::assert_with_log!(
            socket.is_writable(),
            "socket writable",
            true,
            socket.is_writable()
        );
        crate::assert_with_log!(socket.is_error(), "socket error", true, socket.is_error());
        crate::assert_with_log!(socket.is_hup(), "socket hup", true, socket.is_hup());
        crate::assert_with_log!(
            !socket.is_priority(),
            "socket priority unset",
            false,
            socket.is_priority()
        );
        crate::test_complete!("interest_socket");
    }

    #[test]
    fn interest_modes() {
        init_test("interest_modes");
        let interest = Interest::READABLE
            .with_oneshot()
            .with_edge_triggered()
            .with_dispatch();
        crate::assert_with_log!(
            interest.is_readable(),
            "modes keep readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_oneshot(),
            "oneshot set",
            true,
            interest.is_oneshot()
        );
        crate::assert_with_log!(
            interest.is_edge_triggered(),
            "edge-triggered set",
            true,
            interest.is_edge_triggered()
        );
        crate::assert_with_log!(
            interest.is_dispatch(),
            "dispatch set",
            true,
            interest.is_dispatch()
        );
        crate::test_complete!("interest_modes");
    }

    #[test]
    fn interest_dispatch_helpers() {
        init_test("interest_dispatch_helpers");

        // Test dispatch helper method
        let dispatch_interest = Interest::dispatch();
        crate::assert_with_log!(
            dispatch_interest.is_readable(),
            "dispatch() includes readable",
            true,
            dispatch_interest.is_readable()
        );
        crate::assert_with_log!(
            dispatch_interest.is_dispatch(),
            "dispatch() includes dispatch",
            true,
            dispatch_interest.is_dispatch()
        );

        // Test oneshot helper method
        let oneshot_interest = Interest::oneshot();
        crate::assert_with_log!(
            oneshot_interest.is_readable(),
            "oneshot() includes readable",
            true,
            oneshot_interest.is_readable()
        );
        crate::assert_with_log!(
            oneshot_interest.is_oneshot(),
            "oneshot() includes oneshot",
            true,
            oneshot_interest.is_oneshot()
        );

        // Test clear helper method
        let clear_interest = Interest::clear();
        crate::assert_with_log!(
            clear_interest.is_readable(),
            "clear() includes readable",
            true,
            clear_interest.is_readable()
        );
        crate::assert_with_log!(
            clear_interest.is_edge_triggered(),
            "clear() includes edge_triggered",
            true,
            clear_interest.is_edge_triggered()
        );

        crate::test_complete!("interest_dispatch_helpers");
    }

    #[test]
    fn interest_from_bits() {
        init_test("interest_from_bits");
        let interest = Interest::from_bits(0b011);
        crate::assert_with_log!(
            interest.is_readable(),
            "from_bits readable",
            true,
            interest.is_readable()
        );
        crate::assert_with_log!(
            interest.is_writable(),
            "from_bits writable",
            true,
            interest.is_writable()
        );
        crate::assert_with_log!(
            !interest.is_error(),
            "from_bits excludes error",
            false,
            interest.is_error()
        );
        crate::test_complete!("interest_from_bits");
    }

    #[test]
    fn interest_empty() {
        init_test("interest_empty");
        crate::assert_with_log!(
            Interest::NONE.is_empty(),
            "NONE is empty",
            true,
            Interest::NONE.is_empty()
        );
        crate::assert_with_log!(
            Interest::empty().is_empty(),
            "empty is empty",
            true,
            Interest::empty().is_empty()
        );
        crate::assert_with_log!(
            !Interest::READABLE.is_empty(),
            "READABLE not empty",
            false,
            Interest::READABLE.is_empty()
        );
        crate::test_complete!("interest_empty");
    }

    #[test]
    fn interest_default() {
        init_test("interest_default");
        crate::assert_with_log!(
            Interest::default() == Interest::NONE,
            "default is NONE",
            Interest::NONE,
            Interest::default()
        );
        crate::test_complete!("interest_default");
    }

    #[test]
    fn interest_display() {
        init_test("interest_display");
        let none_display = format!("{}", Interest::NONE);
        crate::assert_with_log!(none_display == "NONE", "NONE display", "NONE", none_display);
        let readable_display = format!("{}", Interest::READABLE);
        crate::assert_with_log!(
            readable_display == "READABLE",
            "READABLE display",
            "READABLE",
            readable_display
        );
        let both_display = format!("{}", Interest::READABLE | Interest::WRITABLE);
        crate::assert_with_log!(
            both_display == "READABLE | WRITABLE",
            "combined display",
            "READABLE | WRITABLE",
            both_display
        );
        crate::test_complete!("interest_display");
    }

    #[test]
    fn interest_helpers() {
        init_test("interest_helpers");
        crate::assert_with_log!(
            Interest::readable() == Interest::READABLE,
            "readable helper",
            Interest::READABLE,
            Interest::readable()
        );
        crate::assert_with_log!(
            Interest::writable() == Interest::WRITABLE,
            "writable helper",
            Interest::WRITABLE,
            Interest::writable()
        );
        crate::assert_with_log!(
            Interest::both() == (Interest::READABLE | Interest::WRITABLE),
            "both helper",
            Interest::READABLE | Interest::WRITABLE,
            Interest::both()
        );
        crate::test_complete!("interest_helpers");
    }

    #[test]
    fn interest_debug_clone_copy_hash_default_eq() {
        use std::collections::HashSet;
        let i = Interest::READABLE;
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Interest"), "{dbg}");
        let copied: Interest = i;
        let cloned = i;
        assert_eq!(copied, cloned);
        assert_eq!(Interest::default(), Interest(0));

        let mut set = HashSet::new();
        set.insert(Interest::READABLE);
        set.insert(Interest::WRITABLE);
        set.insert(Interest::both());
        assert_eq!(set.len(), 3);
    }
