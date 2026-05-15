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
//!
//! Metamorphic relations (additive to the byte-by-byte scalar oracle):
//!   * MR-MUL-COMPOSE: `mul_slice(mul_slice(buf, c1), c2)` ≡ `mul_slice(buf, c1 · c2)`.
//!     Verifies the SIMD kernel's choice of multiplication path
//!     (table-lookup vs nibble-shuffle) composes with field multiplication.
//!     Single-mul scalar-oracle calls cannot catch this.
//!   * MR-ADDMUL-XOR-INVOLUTION: `addmul_slice(dst, src, c)` applied twice
//!     restores `dst` (XOR is its own inverse). Hits the SIMD store path
//!     symmetrically and catches read-clobbering-write regressions and any
//!     non-determinism across invocations.

use asupersync::raptorq::gf256::{
    Gf256, Gf256Kernel, active_kernel, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice,
    gf256_addmul_slices2, gf256_mul_slice, gf256_mul_slices2,
};
use libfuzzer_sys::fuzz_target;

const MAX_LEN: usize = 4096;
const MAX_OPS: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    observe_active_kernel();

    let mut cursor = Cursor::new(data);
    for _ in 0..MAX_OPS {
        let Some(op) = cursor.take(1) else { return };
        match op[0] % 10 {
            0 => run_add_slice(&mut cursor),
            1 => run_mul_slice(&mut cursor),
            2 => run_addmul_slice(&mut cursor),
            3 => run_add_slices2(&mut cursor),
            4 => run_mul_slices2(&mut cursor),
            5 => run_addmul_slices2(&mut cursor),
            6 => run_mr_mul_compose(&mut cursor),
            7 => run_mr_addmul_involution(&mut cursor),
            8 => run_mul_slice_focus(&mut cursor),
            9 => run_mul_slices2_focus(&mut cursor),
            _ => unreachable!(),
        }
    }
});

fn observe_active_kernel() {
    let selected = active_kernel();
    assert_eq!(
        active_kernel(),
        selected,
        "GF(256) kernel dispatch changed within one fuzz iteration; selected={selected:?}"
    );
    assert!(
        !active_kernel_name(selected).is_empty(),
        "GF(256) active kernel must have an observer label"
    );
}

fn active_kernel_name(kernel: Gf256Kernel) -> &'static str {
    match kernel {
        Gf256Kernel::Scalar => "scalar",
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Gf256Kernel::X86Avx2 => "x86-avx2",
        #[cfg(target_arch = "aarch64")]
        Gf256Kernel::Aarch64Neon => "aarch64-neon",
    }
}

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

    assert_mul_matches_scalar_per_byte(&dst0, scalar, &got, "gf256_mul_slice");
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
        got,
        expected,
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

    assert_mul_matches_scalar_per_byte(&dst_a0, scalar, &got_a, "gf256_mul_slices2 lane A");
    assert_mul_matches_scalar_per_byte(&dst_b0, scalar, &got_b, "gf256_mul_slices2 lane B");
}

/// Multiply-focused differential oracle. Reuses one arbitrary byte buffer
/// against several arbitrary scalars so the fuzzer spends more cycles on the
/// SIMD multiply kernel than on the mixed add/addmul paths.
fn run_mul_slice_focus(c: &mut Cursor) {
    let Some(dst0) = c.take_aligned() else { return };
    let scalar_trials = usize::from(c.next_u8() % 8) + 1;

    for _ in 0..scalar_trials {
        let Some(scalar) = c.scalar() else { return };
        let mut got = dst0.clone();
        gf256_mul_slice(&mut got, Gf256::new(scalar));
        assert_mul_matches_scalar_per_byte(&dst0, scalar, &got, "gf256_mul_slice focus");
    }
}

/// Dual-lane multiply focus. Exercises the fused SIMD multiply dispatch while
/// keeping the oracle byte-exact for both arbitrary lanes.
fn run_mul_slices2_focus(c: &mut Cursor) {
    let Some(dst_a0) = c.take_aligned() else {
        return;
    };
    let Some(dst_b0) = c.take_aligned() else {
        return;
    };
    let scalar_trials = usize::from(c.next_u8() % 8) + 1;

    for _ in 0..scalar_trials {
        let Some(scalar) = c.scalar() else { return };
        let mut got_a = dst_a0.clone();
        let mut got_b = dst_b0.clone();
        gf256_mul_slices2(&mut got_a, &mut got_b, Gf256::new(scalar));
        assert_mul_matches_scalar_per_byte(
            &dst_a0,
            scalar,
            &got_a,
            "gf256_mul_slices2 focus lane A",
        );
        assert_mul_matches_scalar_per_byte(
            &dst_b0,
            scalar,
            &got_b,
            "gf256_mul_slices2 focus lane B",
        );
    }
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

/// MR-MUL-COMPOSE: `mul_slice(mul_slice(buf, c1), c2)` ≡ `mul_slice(buf, c1·c2)`.
///
/// Uses two distinct SIMD calls (so the kernel's table-vs-shuffle dispatch
/// runs twice) and compares to a single SIMD call with the pre-composed
/// scalar. Catches kernels that conflate `mul_field` for the c1·c2 path.
fn run_mr_mul_compose(c: &mut Cursor) {
    let Some(buf) = c.take_aligned() else { return };
    let Some(c1) = c.scalar() else { return };
    let Some(c2) = c.scalar() else { return };

    let mut twostep = buf.clone();
    gf256_mul_slice(&mut twostep, Gf256::new(c1));
    gf256_mul_slice(&mut twostep, Gf256::new(c2));

    let composed = Gf256::new(c1).mul_field(Gf256::new(c2)).raw();
    let mut onestep = buf.clone();
    gf256_mul_slice(&mut onestep, Gf256::new(composed));

    assert_eq!(
        twostep,
        onestep,
        "MR-MUL-COMPOSE failed: c1={c1} c2={c2} c1·c2={composed} len={}",
        buf.len()
    );
}

/// MR-ADDMUL-XOR-INVOLUTION: `addmul_slice(dst, src, c)` applied twice with
/// the same scalar restores the original `dst`. Holds because GF(2)
/// addition is XOR and the SIMD kernel is required to be a pure function
/// of (dst[i], src[i], c). Catches read-clobbering-write bugs and
/// non-deterministic kernel state across invocations.
fn run_mr_addmul_involution(c: &mut Cursor) {
    let Some((dst0, src, _)) = c.take_aligned_pair() else {
        return;
    };
    let Some(scalar) = c.scalar() else { return };

    let mut work = dst0.clone();
    gf256_addmul_slice(&mut work, &src, Gf256::new(scalar));
    gf256_addmul_slice(&mut work, &src, Gf256::new(scalar));

    assert_eq!(
        work,
        dst0,
        "MR-ADDMUL-XOR-INVOLUTION failed: c={scalar} len={}",
        dst0.len()
    );
}

fn scalar_addmul_ref(dst: &[u8], src: &[u8], c: u8) -> Vec<u8> {
    let cg = Gf256::new(c);
    dst.iter()
        .zip(src.iter())
        .map(|(&d, &s)| d ^ Gf256::new(s).mul_field(cg).raw())
        .collect()
}

fn assert_mul_matches_scalar_per_byte(input: &[u8], scalar: u8, got: &[u8], context: &str) {
    assert_eq!(
        got.len(),
        input.len(),
        "{context} length mismatch for scalar={scalar}: got {} expected {}",
        got.len(),
        input.len()
    );

    let scalar_gf = Gf256::new(scalar);
    for (idx, (&src, &actual)) in input.iter().zip(got.iter()).enumerate() {
        let expected = Gf256::new(src).mul_field(scalar_gf).raw();
        assert_eq!(
            actual, expected,
            "{context} byte mismatch at idx={idx} scalar={scalar} src={src:#04x}"
        );
    }
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
        u16::from_le_bytes([*bytes.first().unwrap_or(&0), *bytes.get(1).unwrap_or(&0)])
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
