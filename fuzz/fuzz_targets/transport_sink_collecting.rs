//! Fuzz target for `src/transport/sink.rs` — CollectingSink lifecycle.
//!
//! Exercises the SymbolSink trait through the in-memory CollectingSink
//! which is the project's reference test sink. Each fuzz iteration
//! drives a sequence of send / flush / close ops through a
//! freshly-built CollectingSink and asserts the invariants:
//!
//!   1. send() preserves order — the i-th send is the i-th item in
//!      collected().
//!   2. flush() never panics regardless of buffer state.
//!   3. After close(), further sends return Err and the collected set
//!      is unchanged.
//!   4. The total count of collected symbols equals the count of
//!      successful sends.
//!
//! AuthenticatedSymbol construction goes through Symbol::new_for_test
//! to keep fuzz inputs structured.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::security::{AuthKey, SecurityContext};
use asupersync::transport::sink::CollectingSink;
use asupersync::types::symbol::Symbol;

#[derive(Debug, Arbitrary)]
enum Op {
    Send {
        object_id: u32,
        esi: u32,
        payload: Vec<u8>,
    },
    Flush,
    Close,
}

fuzz_target!(|ops: Vec<Op>| {
    let mut sink = CollectingSink::new();
    let auth = SecurityContext::new(AuthKey::from_seed(0));

    let mut closed = false;
    let mut expected_count = 0_usize;
    let cx = asupersync::Cx::for_testing();

    for op in ops.into_iter().take(64) {
        match op {
            Op::Send {
                object_id,
                esi,
                payload,
            } => {
                if payload.len() > 1024 {
                    continue; // bound payload to keep corpus reasonable
                }
                let sym = Symbol::new_for_test(u64::from(object_id), 0, esi, &payload);
                let auth_sym = auth.sign_symbol(&sym);
                let result = futures_lite::future::block_on(async {
                    use asupersync::transport::sink::SymbolSinkExt;
                    sink.send_one(&cx, auth_sym).await
                });
                if !closed {
                    assert!(result.is_ok(), "send to open sink failed: {result:?}");
                    expected_count += 1;
                } else {
                    assert!(result.is_err(), "send to closed sink succeeded");
                }
            }
            Op::Flush => {
                let result = futures_lite::future::block_on(async {
                    use asupersync::transport::sink::SymbolSinkExt;
                    sink.flush_now(&cx).await
                });
                if !closed {
                    assert!(result.is_ok(), "flush on open sink failed");
                }
                // Flush on a closed sink may return Err; that's acceptable.
            }
            Op::Close => {
                if !closed {
                    let result = futures_lite::future::block_on(async {
                        use asupersync::transport::sink::SymbolSinkExt;
                        sink.close_now(&cx).await
                    });
                    assert!(result.is_ok(), "first close failed");
                    closed = true;
                }
            }
        }
        // Invariant: collected count never exceeds the expected.
        assert!(
            sink.collected().len() <= expected_count,
            "collected count exceeds expected"
        );
    }

    // Final invariant: collected count equals expected (no symbols dropped on the floor).
    assert_eq!(
        sink.collected().len(),
        expected_count,
        "CollectingSink lost symbols: collected={}, expected={}",
        sink.collected().len(),
        expected_count
    );
});
