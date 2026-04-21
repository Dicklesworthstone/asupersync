#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::raptorq::gf256::Gf256;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const MAX_CASES: usize = 256;
const REDUCTION_POLY: u8 = 0x1D;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_LEN {
        return;
    }

    for chunk in data.chunks_exact(4).take(MAX_CASES) {
        assert_scalar_contracts(chunk[0], chunk[1], chunk[2], chunk[3]);
    }
});

fn assert_scalar_contracts(a: u8, b: u8, c: u8, exp: u8) {
    let ga = Gf256::new(a);
    let gb = Gf256::new(b);
    let gc = Gf256::new(c);

    assert_eq!(ga.add(gb).raw(), a ^ b, "GF256 add must be XOR");
    assert_eq!(ga.sub(gb).raw(), a ^ b, "GF256 sub must equal XOR");

    let mul = ga.mul_field(gb);
    assert_eq!(mul.raw(), reference_mul(a, b), "mul_field mismatch");
    assert_eq!(mul.raw(), gb.mul_field(ga).raw(), "mul_field must commute");
    assert_eq!(
        ga.mul_field(Gf256::ZERO).raw(),
        0,
        "multiply by zero must return zero"
    );
    assert_eq!(
        ga.mul_field(Gf256::ONE).raw(),
        a,
        "multiply by one must be identity"
    );

    assert_eq!(
        ga.mul_field(gb).mul_field(gc).raw(),
        ga.mul_field(gb.mul_field(gc)).raw(),
        "mul_field must associate"
    );
    assert_eq!(
        ga.mul_field(gb.add(gc)).raw(),
        ga.mul_field(gb).add(ga.mul_field(gc)).raw(),
        "mul_field must distribute over add"
    );

    assert_eq!(ga.pow(exp).raw(), reference_pow(a, exp), "pow mismatch");
    assert_eq!(ga.pow(0).raw(), Gf256::ONE.raw(), "x^0 must be one");
    if a == 0 {
        assert_eq!(ga.pow(1).raw(), 0, "zero^1 must remain zero");
    } else {
        assert_eq!(ga.pow(255).raw(), 1, "nonzero x^255 must equal one");
        assert_eq!(
            ga.pow(254).raw(),
            reference_inv(a).unwrap_or_default(),
            "x^254 must match inverse"
        );
    }

    if a == 0 {
        let inverse = catch_unwind(AssertUnwindSafe(|| ga.inv()));
        assert!(inverse.is_err(), "inverting zero must panic");
    } else if let Some(expected_inv) = reference_inv(a) {
        let inverse = ga.inv();
        assert_eq!(inverse.raw(), expected_inv, "inverse mismatch");
        assert_eq!(
            ga.mul_field(inverse).raw(),
            1,
            "value times inverse must equal one"
        );
    }

    if b == 0 {
        let division = catch_unwind(AssertUnwindSafe(|| ga.div_field(gb)));
        assert!(division.is_err(), "division by zero must panic");
    } else if let Some(expected_div) = reference_div(a, b) {
        let division = ga.div_field(gb);
        assert_eq!(division.raw(), expected_div, "division mismatch");
        assert_eq!(
            division.mul_field(gb).raw(),
            a,
            "division round-trip must recover numerator"
        );
    }
}

fn reference_mul(mut lhs: u8, mut rhs: u8) -> u8 {
    let mut acc = 0u8;

    while rhs != 0 {
        if rhs & 1 != 0 {
            acc ^= lhs;
        }

        let carry = lhs & 0x80 != 0;
        lhs <<= 1;
        if carry {
            lhs ^= REDUCTION_POLY;
        }
        rhs >>= 1;
    }

    acc
}

fn reference_pow(base: u8, exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    if base == 0 {
        return 0;
    }

    let mut acc = 1u8;
    let mut i = 0u8;
    while i < exp {
        acc = reference_mul(acc, base);
        i = i.wrapping_add(1);
    }
    acc
}

fn reference_inv(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }

    (1..=u8::MAX).find(|&candidate| reference_mul(value, candidate) == 1)
}

fn reference_div(lhs: u8, rhs: u8) -> Option<u8> {
    reference_inv(rhs).map(|inverse| reference_mul(lhs, inverse))
}
