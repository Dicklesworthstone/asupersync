    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_ancillary_new() {
        init_test("test_ancillary_new");
        let ancillary = SocketAncillary::new(128);

        crate::assert_with_log!(
            ancillary.capacity() == 128,
            "capacity",
            128,
            ancillary.capacity()
        );
        crate::assert_with_log!(ancillary.is_empty(), "is_empty", true, ancillary.is_empty());
        crate::assert_with_log!(
            !ancillary.is_truncated(),
            "truncated",
            false,
            ancillary.is_truncated()
        );
        crate::test_complete!("test_ancillary_new");
    }

    #[test]
    fn test_add_fds() {
        init_test("test_add_fds");
        let mut ancillary = SocketAncillary::new(128);

        // Add deterministic test fds; this unit test does not send them.
        let fds = [3, 4, 5];
        let added = ancillary.add_fds(&fds);

        crate::assert_with_log!(added, "added", true, added);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );
        crate::test_complete!("test_add_fds");
    }

    #[test]
    fn test_add_fds_too_small_buffer() {
        init_test("test_add_fds_too_small");
        // Capacity only affects receive; send-side queueing is unbounded here.
        let mut ancillary = SocketAncillary::new(4);

        let fds = [3, 4, 5];
        let added = ancillary.add_fds(&fds);

        crate::assert_with_log!(added, "added", true, added);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );
        crate::test_complete!("test_add_fds_too_small");
    }

    #[test]
    fn test_clear() {
        init_test("test_ancillary_clear");
        let mut ancillary = SocketAncillary::new(128);

        ancillary.add_fds(&[3, 4]);
        crate::assert_with_log!(
            !ancillary.is_empty(),
            "not empty",
            false,
            ancillary.is_empty()
        );

        ancillary.clear();
        crate::assert_with_log!(
            ancillary.is_empty(),
            "empty after clear",
            true,
            ancillary.is_empty()
        );
        crate::test_complete!("test_ancillary_clear");
    }

    #[test]
    fn test_ancillary_space_for_fds() {
        init_test("test_ancillary_space_for_fds");

        let space0 = ancillary_space_for_fds(0);
        crate::assert_with_log!(space0 == 0, "space for 0", 0, space0);

        let space1 = ancillary_space_for_fds(1);
        crate::assert_with_log!(space1 > 0, "space for 1 > 0", true, space1 > 0);

        let space3 = ancillary_space_for_fds(3);
        crate::assert_with_log!(space3 > space1, "space for 3 > 1", true, space3 > space1);

        crate::test_complete!("test_ancillary_space_for_fds");
    }

    #[test]
    fn test_prepare_for_recv_exposes_full_buffer_len() {
        init_test("test_prepare_for_recv_exposes_full_buffer_len");
        let mut ancillary = SocketAncillary::new(128);
        let recv_buf = ancillary.prepare_for_recv();
        crate::assert_with_log!(recv_buf.len() == 128, "recv buf len", 128, recv_buf.len());
        crate::test_complete!("test_prepare_for_recv_exposes_full_buffer_len");
    }

    #[test]
    fn received_scm_rights_iterator_is_ordered_and_one_shot() {
        init_test("received_scm_rights_iterator_is_ordered_and_one_shot");
        let mut ancillary = SocketAncillary::new(128);
        ancillary.push_received_fds(&[7, 8, 9]);

        let mut messages = ancillary.messages();
        let Some(message) = messages.next() else {
            crate::assert_with_log!(false, "SCM_RIGHTS message present", true, false);
            return;
        };
        let AncillaryMessage::ScmRights(mut rights) = message;

        crate::assert_with_log!(
            rights.size_hint() == (3, Some(3)),
            "exact size hint before iteration",
            (3, Some(3)),
            rights.size_hint()
        );
        let first = rights.next();
        crate::assert_with_log!(first == Some(7), "first fd", Some(7), first);
        let second = rights.next();
        crate::assert_with_log!(second == Some(8), "second fd", Some(8), second);
        let third = rights.next();
        crate::assert_with_log!(third == Some(9), "third fd", Some(9), third);
        let exhausted = rights.next();
        crate::assert_with_log!(
            exhausted.is_none(),
            "rights exhausted",
            Option::<RawFd>::None,
            exhausted
        );
        let extra_message = messages.next();
        crate::assert_with_log!(
            extra_message.is_none(),
            "ancillary message iterator yields once",
            true,
            extra_message.is_none()
        );
        crate::test_complete!("received_scm_rights_iterator_is_ordered_and_one_shot");
    }

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn socket_ancillary_debug_default() {
        let anc = SocketAncillary::default();
        let dbg = format!("{anc:?}");
        assert!(dbg.contains("SocketAncillary"), "{dbg}");
        assert_eq!(anc.capacity(), 0);
        assert!(anc.is_empty());
    }

    #[test]
    fn ancillary_messages_debug() {
        let anc = SocketAncillary::new(0);
        let msgs = anc.messages();
        let dbg = format!("{msgs:?}");
        assert!(dbg.contains("AncillaryMessages"), "{dbg}");
    }
