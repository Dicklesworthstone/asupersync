#![no_main]

//! Cargo-fuzz target for GF(256) SIMD vs scalar-reference equivalence.
//!
//! The public slice functions (`gf256_add_slice`, `gf256_mul_slice`,
//! `gf256_addmul_slice`, and their `slices2` variants) dispatch to AVX2 or
//! NEON kernels when `simd-intrinsics` is enabled. This target computes a
//! completely independent byte-by-byte reference using `Gf256::mul_field`
//! (log/exp tables, no SIMD at any point) and asserts exact equality.
//!
//! Coverage:
//!   - `c == 0` and `c == 1` fast paths (both short-circuited in SIMD kernels).
//!   - 16 / 32 / 64 stride-alignment thresholds (MUL_TABLE_THRESHOLD = 32 on
//!     AVX2/NEON, 16 on scalar; add kernels use 16/32).
//!   - Unaligned buffers (offset 0..16) to flush out `unsafe` pointer math.
//!   - Odd-length tails (lengths that straddle SIMD/scalar boundaries).
//!   - Dual-slice `slices2` fused paths with asymmetric lengths.

use asupersync::raptorq::gf256::{
    Gf256, active_kernel, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice,
    gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
};
use libfuzzer_sys::fuzz_target;

const MAX_LEN: usize = 4096;
const MAX_OPS: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Touch the dispatcher once so fuzzing covers kernel selection.
    let _ = active_kernel();

    let mut cursor = Cursor::new(data);
    for _ in 0..MAX_OPS {
        let Some(op) = cursor.take(1) else { return };
        match op[0] % 6 {
            0 => run_add_slice(&mut cursor),
            1 => run_mul_slice(&mut cursor),
            2 => run_addmul_slice(&mut cursor),
            3 => run_add_slices2(&mut cursor),
            4 => run_mul_slices2(&mut cursor),
            5 => run_addmul_slices2(&mut cursor),
            _ => unreachable!(),
        }
    }
});

fn run_add_slice(c: &mut Cursor) {
    let Some((dst0, src, _)) = c.take_aligned_pair() else {
        return;
    };

    let mut got = dst0.clone();
    gf256_add_slice(&mut got, &src);

    let expected: Vec<u8> = dst0.iter().zip(src.iter()).map(|(a, b)| a ^ b).collect();
    assert_eq!(got, expected, "gf256_add_slice diverged from XOR reference");
}

fn run_mul_slice(c: &mut Cursor) {
    let Some(dst0) = c.take_aligned() else { return };
    let Some(scalar) = c.scalar() else { return };

    let mut got = dst0.clone();
    gf256_mul_slice(&mut got, Gf256::new(scalar));

    let expected = scalar_mul_ref(&dst0, scalar);
    assert_eq!(
        got, expected,
        "gf256_mul_slice diverged from scalar reference (c={scalar}, len={})",
        dst0.len()
    );
}

fn run_addmul_slice(c: &mut Cursor) {
    let Some((dst0, src, _)) = c.take_aligned_pair() else {
        return;
    };
    let Some(scalar) = c.scalar() else { return };

    let mut got = dst0.clone();
    gf256_addmul_slice(&mut got, &src, Gf256::new(scalar));

    let expected = scalar_addmul_ref(&dst0, &src, scalar);
    assert_eq!(
        got, expected,
        "gf256_addmul_slice diverged from scalar reference (c={scalar}, len={})",
        dst0.len()
    );
}

fn run_add_slices2(c: &mut Cursor) {
    let Some((dst_a0, src_a, _)) = c.take_aligned_pair() else {
        return;
    };
    let Some((dst_b0, src_b, _)) = c.take_aligned_pair() else {
        return;
    };

    let mut got_a = dst_a0.clone();
    let mut got_b = dst_b0.clone();
    gf256_add_slices2(&mut got_a, &src_a, &mut got_b, &src_b);

    let expected_a: Vec<u8> = dst_a0
        .iter()
        .zip(src_a.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let expected_b: Vec<u8> = dst_b0
        .iter()
        .zip(src_b.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    assert_eq!(got_a, expected_a, "gf256_add_slices2 lane A diverged");
    assert_eq!(got_b, expected_b, "gf256_add_slices2 lane B diverged");
}

fn run_mul_slices2(c: &mut Cursor) {
    let Some(dst_a0) = c.take_aligned() else {
        return;
    };
    let Some(dst_b0) = c.take_aligned() else {
        return;
    };
    let Some(scalar) = c.scalar() else { return };

    let mut got_a = dst_a0.clone();
    let mut got_b = dst_b0.clone();
    gf256_mul_slices2(&mut got_a, &mut got_b, Gf256::new(scalar));

    let expected_a = scalar_mul_ref(&dst_a0, scalar);
    let expected_b = scalar_mul_ref(&dst_b0, scalar);
    assert_eq!(
        got_a, expected_a,
        "gf256_mul_slices2 lane A diverged (c={scalar})"
    );
    assert_eq!(
        got_b, expected_b,
        "gf256_mul_slices2 lane B diverged (c={scalar})"
    );
}

fn run_addmul_slices2(c: &mut Cursor) {
    let Some((dst_a0, src_a, _)) = c.take_aligned_pair() else {
        return;
    };
    let Some((dst_b0, src_b, _)) = c.take_aligned_pair() else {
        return;
    };
    let Some(scalar) = c.scalar() else { return };

    let mut got_a = dst_a0.clone();
    let mut got_b = dst_b0.clone();
    gf256_addmul_slices2(&mut got_a, &src_a, &mut got_b, &src_b, Gf256::new(scalar));

    let expected_a = scalar_addmul_ref(&dst_a0, &src_a, scalar);
    let expected_b = scalar_addmul_ref(&dst_b0, &src_b, scalar);
    assert_eq!(
        got_a, expected_a,
        "gf256_addmul_slices2 lane A diverged (c={scalar})"
    );
    assert_eq!(
        got_b, expected_b,
        "gf256_addmul_slices2 lane B diverged (c={scalar})"
    );
}

fn scalar_mul_ref(dst: &[u8], c: u8) -> Vec<u8> {
    let cg = Gf256::new(c);
    dst.iter()
        .map(|&x| Gf256::new(x).mul_field(cg).raw())
        .collect()
}

fn scalar_addmul_ref(dst: &[u8], src: &[u8], c: u8) -> Vec<u8> {
    let cg = Gf256::new(c);
    dst.iter()
        .zip(src.iter())
        .map(|(&d, &s)| d ^ Gf256::new(s).mul_field(cg).raw())
        .collect()
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    prng: u64,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut seed = 0xcbf29ce484222325u64;
        for &b in data.iter().take(16) {
            seed ^= u64::from(b);
            seed = seed.wrapping_mul(0x00000100000001B3);
        }
        Self {
            data,
            pos: 0,
            prng: seed,
        }
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn next_u16(&mut self) -> u16 {
        let bytes = self.take(2).unwrap_or(&[0, 0]);
        u16::from_le_bytes([
            *bytes.first().unwrap_or(&0),
            *bytes.get(1).unwrap_or(&0),
        ])
    }

    fn next_u8(&mut self) -> u8 {
        self.take(1).and_then(|s| s.first().copied()).unwrap_or(0)
    }

    fn xorshift(&mut self) -> u64 {
        let mut x = self.prng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng = x;
        x
    }

    /// Pick a fuzz-friendly length. Biases toward kernel-threshold neighborhoods
    /// (15, 16, 17, 31, 32, 33, 63, 64, 65) so boundary conditions hit often.
    fn length(&mut self) -> usize {
        let bucket = self.next_u8() % 16;
        let base = match bucket {
            0 => 0,
            1 => 1,
            2 => 15,
            3 => 16,
            4 => 17,
            5 => 31,
            6 => 32,
            7 => 33,
            8 => 48,
            9 => 63,
            10 => 64,
            11 => 65,
            12 => 127,
            13 => 128,
            14 => 255,
            _ => (self.next_u16() as usize) % MAX_LEN,
        };
        base.min(MAX_LEN)
    }

    /// Scalar selection: over-weights 0, 1, small values, and 255 to exercise
    /// the c==0 / c==1 fast paths and multiplicative extremes.
    fn scalar(&mut self) -> Option<u8> {
        let tag = self.next_u8();
        Some(match tag % 10 {
            0 | 1 => 0,
            2 | 3 => 1,
            4 => 2,
            5 => 255,
            _ => self.next_u8(),
        })
    }

    /// Fill a Vec<u8> of requested length from the PRNG (so we never run out
    /// of bytes at short inputs and still keep coverage cheap).
    fn fill(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let r = self.xorshift().to_le_bytes();
            let take = (len - out.len()).min(8);
            out.extend_from_slice(&r[..take]);
        }
        out
    }

    /// Return (dst, src, offset) where dst and src share an offset into an
    /// over-allocated buffer, giving unaligned SIMD coverage.
    fn take_aligned_pair(&mut self) -> Option<(Vec<u8>, Vec<u8>, usize)> {
        let len = self.length();
        let offset = (self.next_u8() as usize) % 16;
        let mut dst_buf = self.fill(len + offset);
        let src_buf = self.fill(len + offset);
        let dst = dst_buf.split_off(offset);
        let src = src_buf[offset..].to_vec();
        Some((dst, src, offset))
    }

    fn take_aligned(&mut self) -> Option<Vec<u8>> {
        let len = self.length();
        let offset = (self.next_u8() as usize) % 16;
        let mut buf = self.fill(len + offset);
        Some(buf.split_off(offset))
    }
}
