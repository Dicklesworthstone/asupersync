    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;
    use std::future::Future;
    use std::pin::Pin;

    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_ready<F: Future>(mut fut: Pin<&mut F>) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
        }
        panic!("future did not resolve"); // ubs:ignore - test logic
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn commit_writes_data() {
        init_test("commit_writes_data");
        let mut output = Vec::new();
        let result = {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"hello ");
            permit.stage(b"world");

            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 11, "staged_len", 11, staged_len);
            let empty = permit.is_empty();
            crate::assert_with_log!(!empty, "not empty", false, empty);

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "commit ok", true, ok);
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
        crate::test_complete!("commit_writes_data");
    }

    #[test]
    fn metamorphic_chunked_staging_matches_single_stage_commit() {
        init_test("metamorphic_chunked_staging_matches_single_stage_commit");
        let payload = b"alpha\nbeta\0gamma delta";

        let mut single_output = Vec::new();
        let single_result = {
            let mut permit = WritePermit::new(&mut single_output);
            permit.stage(payload);

            let staged_len = permit.staged_len();
            crate::assert_with_log!(
                staged_len == payload.len(),
                "single staged_len",
                payload.len(),
                staged_len
            );

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };
        let single_ok = single_result.is_ok();
        crate::assert_with_log!(single_ok, "single commit ok", true, single_ok);

        for split_at in 0..=payload.len() {
            let mut chunked_output = Vec::new();
            let chunked_result = {
                let mut permit = WritePermit::new(&mut chunked_output);
                permit.stage(&payload[..split_at]);
                permit.stage(&payload[split_at..]);

                let staged_len = permit.staged_len();
                crate::assert_with_log!(
                    staged_len == payload.len(),
                    "chunked staged_len",
                    payload.len(),
                    staged_len
                );

                let mut fut = Box::pin(permit.commit());
                poll_ready(fut.as_mut())
            };
            let chunked_ok = chunked_result.is_ok();
            crate::assert_with_log!(chunked_ok, "chunked commit ok", true, chunked_ok);
            crate::assert_with_log!(
                chunked_output == single_output,
                "chunked output matches single-stage output",
                single_output.as_slice(),
                chunked_output.as_slice()
            );
        }

        crate::test_complete!("metamorphic_chunked_staging_matches_single_stage_commit");
    }

    #[test]
    fn abort_discards_data() {
        init_test("abort_discards_data");
        let mut output = Vec::new();
        {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"this should be discarded");
            permit.abort();
        }
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("abort_discards_data");
    }

    #[test]
    fn drop_discards_data() {
        init_test("drop_discards_data");
        let mut output = Vec::new();
        {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"this should be discarded");
            // permit is dropped here
        }
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("drop_discards_data");
    }

    #[test]
    fn clear_removes_staged_data() {
        init_test("clear_removes_staged_data");
        let mut output = Vec::new();
        let result = {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"hello");
            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 5, "staged_len", 5, staged_len);

            permit.clear();
            let empty = permit.is_empty();
            crate::assert_with_log!(empty, "empty", true, empty);
            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 0, "staged_len", 0, staged_len);

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "commit ok", true, ok);
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("clear_removes_staged_data");
    }

    #[test]
    fn clear_allows_restage_before_commit() {
        init_test("clear_allows_restage_before_commit");
        let mut output = Vec::new();
        let result = {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"discarded");
            permit.clear();
            permit.stage(b"kept");

            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 4, "staged_len", 4, staged_len);
            let empty = permit.is_empty();
            crate::assert_with_log!(!empty, "not empty", false, empty);

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "commit ok", true, ok);
        crate::assert_with_log!(output == b"kept", "output", b"kept", output);
        crate::test_complete!("clear_allows_restage_before_commit");
    }

    proptest! {
        #[test]
        fn write_permit_metamorphic_clear_resets_staged_prefix(
            discarded in prop::collection::vec(any::<u8>(), 0..128),
            retained in prop::collection::vec(any::<u8>(), 0..128),
            split_at in 0usize..128,
        ) {
            let split_at = split_at.min(retained.len());

            let mut cleared_output = Vec::new();
            let cleared_result = {
                let mut permit = WritePermit::new(&mut cleared_output);
                permit.stage(&discarded);
                prop_assert_eq!(
                    permit.staged_len(),
                    discarded.len(),
                    "initial staging must account for all discarded bytes",
                );

                permit.clear();
                prop_assert!(permit.is_empty(), "clear must empty staged data");
                prop_assert_eq!(permit.staged_len(), 0, "clear must reset staged length");

                permit.stage(&retained[..split_at]);
                permit.stage(&retained[split_at..]);
                prop_assert_eq!(
                    permit.staged_len(),
                    retained.len(),
                    "restaging in chunks after clear must account for retained bytes only",
                );

                let mut fut = Box::pin(permit.commit());
                poll_ready(fut.as_mut())
            };
            prop_assert!(cleared_result.is_ok(), "cleared permit commit should succeed");

            let mut fresh_output = Vec::new();
            let fresh_result = {
                let mut permit = WritePermit::new(&mut fresh_output);
                permit.stage(&retained);
                prop_assert_eq!(
                    permit.staged_len(),
                    retained.len(),
                    "fresh permit must account for retained bytes",
                );

                let mut fut = Box::pin(permit.commit());
                poll_ready(fut.as_mut())
            };
            prop_assert!(fresh_result.is_ok(), "fresh permit commit should succeed");

            prop_assert_eq!(
                cleared_output.as_slice(),
                fresh_output.as_slice(),
                "clear plus restage must commit the same bytes as a fresh permit",
            );
            prop_assert_eq!(
                cleared_output.as_slice(),
                retained.as_slice(),
                "discarded staged bytes must not leak into committed output",
            );
        }
    }

    #[test]
    fn with_capacity_preallocates() {
        init_test("with_capacity_preallocates");
        let mut output = Vec::new();
        let permit = WritePermit::with_capacity(&mut output, 1024);
        let empty = permit.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        crate::test_complete!("with_capacity_preallocates");
    }
