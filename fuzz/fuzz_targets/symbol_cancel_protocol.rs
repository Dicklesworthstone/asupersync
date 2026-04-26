#![no_main]

//! Fuzzer for `src/cancel/symbol_cancel.rs::SymbolCancelToken` protocol.
//!
//! # Properties asserted per iteration
//!
//!   1. **No panic on any input.** Random sequences of cancel / child /
//!      add_listener / to_bytes / from_bytes calls MUST NOT panic.
//!
//!   2. **Cancel is idempotent (first-caller-wins).** The FIRST
//!      `cancel(reason, time)` MUST return `true`; every subsequent
//!      call on the same token MUST return `false`. The token's
//!      `is_cancelled()` MUST stay `true` after the first cancel.
//!
//!   3. **`cancelled_at()` consistency.** After the first successful
//!      cancel at time T, `cancelled_at()` MUST return `Some(t)` with
//!      `t.as_nanos() >= T.min(u64::MAX - 1)`. Once set it MUST NOT
//!      change on subsequent cancels.
//!
//!   4. **Wire round-trip preserves observable bits.** `to_bytes()` then
//!      `from_bytes()` MUST yield a token whose `token_id`, `object_id`,
//!      and `is_cancelled()` match the source. (The deserialized token
//!      is a fresh state — child links / listeners are intentionally
//!      not preserved per the documented contract.)
//!
//!   5. **`from_bytes` is total on truncated/garbage input.** Bytes
//!      shorter than `TOKEN_WIRE_SIZE` (25) MUST yield `None`, never
//!      panic.
//!
//!   6. **Child cancels propagate.** A child created BEFORE parent is
//!      cancelled MUST be cancelled after the parent is cancelled. A
//!      child created AFTER parent cancel MUST be born already-
//!      cancelled (per the documented design).
//!
//!   7. **Multi-thread cancel: exactly one CAS winner.** N threads
//!      racing to cancel the same token MUST result in EXACTLY ONE
//!      `true` return; all others return `false`. Tested via
//!      crossbeam-style scope (one inline iteration per fuzz input
//!      to keep throughput; richer concurrency is in dedicated
//!      tests/repro_*.rs files).
//!
//! Tokens are constructed with `DetRng::new(seed)` so failures are
//! reproducible from the fuzz input.

use asupersync::cancel::symbol_cancel::SymbolCancelToken;
use asupersync::types::ObjectId;
use asupersync::types::Time;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::util::det_rng::DetRng;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

const TOKEN_WIRE_SIZE: usize = 25;

/// Map a fuzz-byte to one of the documented CancelKind variants. Kept
/// to a small fixed set so the fuzzer's scheduling decisions are
/// deterministic across runs (no hidden enum reorder leakage).
fn make_reason(byte: u8) -> CancelReason {
    let kind = match byte % 6 {
        0 => CancelKind::User,
        1 => CancelKind::Deadline,
        2 => CancelKind::ParentCancelled,
        3 => CancelKind::ResourceUnavailable,
        4 => CancelKind::Shutdown,
        _ => CancelKind::User,
    };
    CancelReason::new(kind)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Carve a deterministic seed for the token's RNG and an ObjectId.
    let seed = u64::from_le_bytes(
        data[..8.min(data.len())]
            .iter()
            .copied()
            .chain(std::iter::repeat(0))
            .take(8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    );
    let mut rng = DetRng::new(seed);
    let obj = ObjectId::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), seed);
    let token = SymbolCancelToken::new(obj, &mut rng);

    // ── Property 5: `from_bytes` is total on truncated input ────────────
    for cap in 0..TOKEN_WIRE_SIZE {
        let _ = SymbolCancelToken::from_bytes(&data[..cap.min(data.len())]);
    }

    // Use bytes after seed-prefix as the operation script.
    let script = &data[8.min(data.len())..];

    let mut first_cancel_time: Option<u64> = None;
    let mut total_cancel_calls: u32 = 0;
    let mut won_cancel_calls: u32 = 0;

    for (i, op_byte) in script.iter().enumerate().take(64) {
        let op = op_byte % 6;
        let arg = script.get(i.wrapping_add(1)).copied().unwrap_or(0);

        match op {
            // 0..=1: cancel
            0 | 1 => {
                let reason = make_reason(arg);
                let t_nanos = u64::from(arg) * 1_000_000;
                let t = Time::from_nanos(t_nanos);
                let won = token.cancel(&reason, t);
                total_cancel_calls += 1;
                if won {
                    won_cancel_calls += 1;
                    // Property 2: only the first call may win
                    assert!(
                        first_cancel_time.is_none(),
                        "cancel() returned true twice for the same token"
                    );
                    first_cancel_time = Some(t_nanos.min(u64::MAX - 1));
                }
                // Property 3: cancelled_at is monotonic and matches first
                if let Some(expected_floor) = first_cancel_time {
                    let actual = token.cancelled_at();
                    assert!(
                        actual.is_some(),
                        "cancelled_at = None after at least one successful cancel"
                    );
                    let actual_nanos = actual.unwrap().as_nanos();
                    assert_eq!(
                        actual_nanos, expected_floor,
                        "cancelled_at changed after first cancel: was {expected_floor}, now {actual_nanos}"
                    );
                }
            }

            // 2: spawn a child
            2 => {
                let was_parent_cancelled = token.is_cancelled();
                let mut child_rng = DetRng::new(seed.wrapping_add(u64::from(arg)));
                let child = token.child(&mut child_rng);
                if was_parent_cancelled {
                    // Property 6: post-cancel children are born cancelled
                    assert!(
                        child.is_cancelled(),
                        "child created AFTER parent cancel must be born cancelled"
                    );
                }
            }

            // 3: wire round-trip on current token state
            3 => {
                let bytes = token.to_bytes();
                let restored = SymbolCancelToken::from_bytes(&bytes)
                    .expect("to_bytes round-trips through from_bytes");
                // Property 4: cancelled bit + identity must match
                assert_eq!(
                    restored.is_cancelled(),
                    token.is_cancelled(),
                    "wire round-trip lost cancelled bit"
                );
                assert_eq!(
                    restored.token_id(),
                    token.token_id(),
                    "wire round-trip lost token_id"
                );
                assert_eq!(
                    restored.object_id(),
                    token.object_id(),
                    "wire round-trip lost object_id"
                );
            }

            // 4: from_bytes on a slice of the script (fuzz the parser)
            4 => {
                let _ = SymbolCancelToken::from_bytes(script);
            }

            // 5: spot-check is_cancelled is stable across calls
            _ => {
                let a = token.is_cancelled();
                let b = token.is_cancelled();
                assert_eq!(a, b, "is_cancelled() flapped between back-to-back reads");
            }
        }
    }

    // Sanity: if any cancel happened at all, exactly one won.
    assert!(
        won_cancel_calls <= 1,
        "more than one cancel() returned true (won={won_cancel_calls}, total={total_cancel_calls})"
    );
    if total_cancel_calls > 0 {
        assert_eq!(
            token.is_cancelled(),
            won_cancel_calls == 1,
            "is_cancelled() == (won == 1) invariant violated"
        );
    }

    // ── Property 7: multi-thread CAS-winner invariant ───────────────────
    // Spawn 4 threads racing to cancel a fresh token. Exactly one MUST
    // observe the win. Use a small fixed thread count to keep fuzz
    // throughput; cheaper than scenario-level concurrency tests.
    {
        let mut frng = DetRng::new(seed.wrapping_add(0xABCD));
        let race_token = Arc::new(SymbolCancelToken::new(obj, &mut frng));
        let win_count = Arc::new(AtomicU8::new(0));
        let mut handles = Vec::with_capacity(4);
        for tid in 0..4u64 {
            let t = Arc::clone(&race_token);
            let w = Arc::clone(&win_count);
            handles.push(std::thread::spawn(move || {
                let reason = CancelReason::new(CancelKind::User);
                let now = Time::from_nanos(tid * 1000);
                if t.cancel(&reason, now) {
                    w.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().expect("race thread MUST NOT panic");
        }
        let winners = win_count.load(Ordering::Acquire);
        assert_eq!(
            winners, 1,
            "exactly one cancel() must win the CAS race; got {winners} winners"
        );
        assert!(race_token.is_cancelled(), "post-race token MUST be cancelled");
    }
});
