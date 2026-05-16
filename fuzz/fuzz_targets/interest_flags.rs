//! Fuzz target for reactor Interest flag operations.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_interest_flags
//! ```

#![no_main]

use asupersync::runtime::reactor::Interest;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const DEFINED_FLAGS: [(Interest, u8); 8] = [
    (Interest::READABLE, 1 << 0),
    (Interest::WRITABLE, 1 << 1),
    (Interest::ERROR, 1 << 2),
    (Interest::HUP, 1 << 3),
    (Interest::PRIORITY, 1 << 4),
    (Interest::ONESHOT, 1 << 5),
    (Interest::EDGE_TRIGGERED, 1 << 6),
    (Interest::DISPATCH, 1 << 7),
];

static FIXED_ORACLES: OnceLock<()> = OnceLock::new();

fn assert_fixed_oracles() {
    assert_eq!(Interest::NONE.bits(), 0);
    assert_eq!(Interest::empty(), Interest::NONE);
    assert_eq!(Interest::ALL.bits(), u8::MAX);
    assert_eq!(Interest::SOCKET.bits(), 0b0000_1111);
    assert_eq!(Interest::both().bits(), 0b0000_0011);
    assert_eq!(Interest::oneshot().bits(), 0b0010_0001);
    assert_eq!(Interest::clear().bits(), 0b0100_0001);
    assert_eq!(Interest::dispatch().bits(), 0b1000_0001);
    assert_eq!((!Interest::NONE).bits(), Interest::ALL.bits());
    assert_eq!((!Interest::ALL).bits(), 0);

    for (flag, bit) in DEFINED_FLAGS {
        assert_eq!(flag.bits(), bit);
        assert!(Interest::ALL.contains(flag));
    }
}

fn assert_interest_matches_model(bits: u8) {
    let interest = Interest::from_bits(bits);
    assert_eq!(interest.bits(), bits);
    assert_eq!(interest.is_empty(), bits == 0);
    assert_eq!(
        interest.is_readable(),
        bits & Interest::READABLE.bits() != 0
    );
    assert_eq!(
        interest.is_writable(),
        bits & Interest::WRITABLE.bits() != 0
    );
    assert_eq!(interest.is_error(), bits & Interest::ERROR.bits() != 0);
    assert_eq!(interest.is_hup(), bits & Interest::HUP.bits() != 0);
    assert_eq!(
        interest.is_priority(),
        bits & Interest::PRIORITY.bits() != 0
    );
    assert_eq!(interest.is_oneshot(), bits & Interest::ONESHOT.bits() != 0);
    assert_eq!(
        interest.is_edge_triggered(),
        bits & Interest::EDGE_TRIGGERED.bits() != 0
    );
    assert_eq!(
        interest.is_dispatch(),
        bits & Interest::DISPATCH.bits() != 0
    );

    for (flag, bit) in DEFINED_FLAGS {
        assert_eq!(interest.contains(flag), bits & bit == bit);
    }
}

fn assert_pairwise_operations(a_bits: u8, b_bits: u8) {
    let a = Interest::from_bits(a_bits);
    let b = Interest::from_bits(b_bits);

    assert_eq!(a.add(b).bits(), a_bits | b_bits);
    assert_eq!((a | b).bits(), a_bits | b_bits);
    assert_eq!((a & b).bits(), a_bits & b_bits);
    assert_eq!(a.remove(b).bits(), a_bits & !b_bits);
    assert_eq!((!a).bits(), !a_bits & Interest::ALL.bits());
    assert_eq!(a.contains(b), a_bits & b_bits == b_bits);

    let mut union = a;
    union |= b;
    assert_eq!(union.bits(), a_bits | b_bits);

    let mut intersection = a;
    intersection &= b;
    assert_eq!(intersection.bits(), a_bits & b_bits);

    assert_eq!(a.with_oneshot().bits(), a_bits | Interest::ONESHOT.bits());
    assert_eq!(
        a.with_edge_triggered().bits(),
        a_bits | Interest::EDGE_TRIGGERED.bits()
    );
    assert_eq!(a.with_dispatch().bits(), a_bits | Interest::DISPATCH.bits());
}

fuzz_target!(|data: &[u8]| {
    FIXED_ORACLES.get_or_init(assert_fixed_oracles);

    if data.is_empty() {
        return;
    }

    assert_interest_matches_model(data[0]);

    for window in data.windows(2) {
        assert_interest_matches_model(window[0]);
        assert_interest_matches_model(window[1]);
        assert_pairwise_operations(window[0], window[1]);
    }
});
