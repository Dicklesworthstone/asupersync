//! GF(256) finite-field arithmetic for RaptorQ encoding/decoding.
//!
//! Implements the Galois field GF(2^8) used by RFC 6330 (RaptorQ) with the
//! irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x1D over GF(2)).
//!
//! # Representation
//!
//! Elements are stored as `u8` values where each bit represents a coefficient
//! of a degree-7 polynomial over GF(2). Addition is XOR; multiplication uses
//! precomputed log/exp (antilog) tables for O(1) operations.
//!
//! # Determinism
//!
//! All operations are deterministic and platform-independent. Table generation
//! is `const`-evaluated at compile time.
//!
//! # Kernel Dispatch
//!
//! Bulk slice operations dispatch through a deterministic kernel selector:
//! - x86/x86_64 with AVX2 support -> `Gf256Kernel::X86Avx2`
//! - aarch64 with NEON support -> `Gf256Kernel::Aarch64Neon`
//! - otherwise -> `Gf256Kernel::Scalar`
//!
//! # Feature Detection and Build Flags
//!
//! - Runtime detection:
//!   - x86/x86_64 uses `is_x86_feature_detected!("avx2")`
//!   - aarch64 uses `is_aarch64_feature_detected!("neon")`
//! - Compile-time gating:
//!   - AVX2 implementation is compiled only on `target_arch = "x86" | "x86_64"`
//!   - NEON implementation is compiled only on `target_arch = "aarch64"`
//! - Scalar fallback:
//!   - always compiled and selected when feature checks fail or ISA code is unavailable.
//! - Determinism:
//!   - dispatch decision is memoized in `OnceLock`, so kernel selection is stable
//!     for process lifetime.

#![cfg_attr(
    feature = "simd-intrinsics",
    allow(unsafe_code, clippy::cast_ptr_alignment, clippy::ptr_as_ptr)
)]

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8, vst1q_u8,
};
#[cfg(all(feature = "simd-intrinsics", target_arch = "x86"))]
use core::arch::x86::{
    __m128i, __m256i, _mm256_and_si256, _mm256_broadcastsi128_si256, _mm256_loadu_si256,
    _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16, _mm256_storeu_si256,
    _mm256_xor_si256, _mm_loadu_si128,
};
#[cfg(all(feature = "simd-intrinsics", target_arch = "x86_64"))]
use core::arch::x86_64::{
    __m128i, __m256i, _mm256_and_si256, _mm256_broadcastsi128_si256, _mm256_loadu_si256,
    _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16, _mm256_storeu_si256,
    _mm256_xor_si256, _mm_loadu_si128,
};

/// The irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1.
///
/// Represented as 0x1D (the low 8 bits after subtracting x^8).
/// Full polynomial is 0x11D but we only need the reduction mask.
const POLY: u16 = 0x1D;

/// A primitive element (generator) of GF(256). The value 2 (i.e. x)
/// generates the full multiplicative group of order 255.
const GENERATOR: u16 = 0x02;

/// Logarithm table: `LOG[a]` = discrete log base `GENERATOR` of `a`.
///
/// `LOG[0]` is unused (log of zero is undefined); set to 0 by convention.
static LOG: [u8; 256] = build_log_table();

/// Exponential (antilog) table: `EXP[i]` = `GENERATOR^i mod POLY`.
///
/// Extended to 512 entries so that `EXP[a + b]` works without modular
/// reduction for any `a, b < 255`.
static EXP: [u8; 512] = build_exp_table();

// ============================================================================
// Table generation (const)
// ============================================================================

const fn build_exp_table() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        table[i] = val as u8;
        table[i + 255] = val as u8; // mirror for mod-free lookup
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= 0x100 | POLY;
        }
        i += 1;
    }
    // EXP[255] = EXP[0] = 1 (wraps), already set by mirror
    table[255] = 1;
    table[510] = 1;
    table
}

const fn build_log_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u16 = 1;
    let mut i = 0u8;
    // We loop 255 times (exponents 0..254) to fill log for all non-zero elements.
    loop {
        table[val as usize] = i;
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= 0x100 | POLY;
        }
        if i == 254 {
            break;
        }
        i += 1;
    }
    table
}

const fn gf256_mul_const(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    let mut i = 0u8;
    while i < 8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= POLY as u8;
        }
        b >>= 1;
        i += 1;
    }
    acc
}

#[allow(clippy::large_stack_arrays)]
const fn build_mul_tables() -> [[u8; 256]; 256] {
    let mut tables = [[0u8; 256]; 256];
    let mut c = 0usize;
    while c < 256 {
        let mut x = 0usize;
        while x < 256 {
            tables[c][x] = gf256_mul_const(x as u8, c as u8);
            x += 1;
        }
        c += 1;
    }
    tables
}

static MUL_TABLES: [[u8; 256]; 256] = build_mul_tables();

#[cfg(feature = "simd-intrinsics")]
use std::simd::prelude::*;

/// Precomputed nibble-decomposed multiplication tables for SIMD (Halevi-Shacham).
///
/// For a scalar `c`, stores `lo[i] = c * i` for `i in 0..16` and
/// `hi[i] = c * (i << 4)` for `i in 0..16`. This enables 16-byte-at-a-time
/// multiplication via `c * x = lo[x & 0x0F] ^ hi[x >> 4]`, where each lookup
/// is a single SIMD shuffle (`swizzle_dyn` → PSHUFB on x86).
#[cfg(feature = "simd-intrinsics")]
struct NibbleTables {
    lo: Simd<u8, 16>,
    hi: Simd<u8, 16>,
}

#[cfg(feature = "simd-intrinsics")]
impl NibbleTables {
    #[inline]
    fn for_scalar(c: Gf256) -> Self {
        let t = &MUL_TABLES[c.0 as usize];
        Self {
            lo: Simd::from_array([
                t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11], t[12],
                t[13], t[14], t[15],
            ]),
            hi: Simd::from_array([
                t[0x00], t[0x10], t[0x20], t[0x30], t[0x40], t[0x50], t[0x60], t[0x70], t[0x80],
                t[0x90], t[0xA0], t[0xB0], t[0xC0], t[0xD0], t[0xE0], t[0xF0],
            ]),
        }
    }

    /// Multiply 16 bytes by the precomputed scalar via nibble decomposition.
    #[inline]
    fn mul16(&self, x: Simd<u8, 16>) -> Simd<u8, 16> {
        let mask_lo = Simd::splat(0x0F);
        let lo_nibbles = x & mask_lo;
        let hi_nibbles = (x >> 4) & mask_lo;
        self.lo.swizzle_dyn(lo_nibbles) ^ self.hi.swizzle_dyn(hi_nibbles)
    }
}

#[cfg(not(feature = "simd-intrinsics"))]
struct NibbleTables;

#[cfg(not(feature = "simd-intrinsics"))]
impl NibbleTables {
    #[inline]
    fn for_scalar(_c: Gf256) -> Self {
        Self
    }
}

/// Runtime-selected kernel family for bulk GF(256) operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gf256Kernel {
    /// Portable fallback used everywhere.
    Scalar,
    /// x86/x86_64 AVX2-capable lane (requires `simd-intrinsics` feature).
    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    X86Avx2,
    /// aarch64 NEON-capable lane (requires `simd-intrinsics` feature).
    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    Aarch64Neon,
}

type AddSliceKernel = fn(&mut [u8], &[u8]);
type MulSliceKernel = fn(&mut [u8], Gf256);
type AddMulSliceKernel = fn(&mut [u8], &[u8], Gf256);

#[derive(Clone, Copy)]
struct Gf256Dispatch {
    kind: Gf256Kernel,
    add_slice: AddSliceKernel,
    mul_slice: MulSliceKernel,
    addmul_slice: AddMulSliceKernel,
}

static DISPATCH: std::sync::OnceLock<Gf256Dispatch> = std::sync::OnceLock::new();
static DUAL_POLICY: std::sync::OnceLock<DualKernelPolicy> = std::sync::OnceLock::new();

fn dispatch() -> &'static Gf256Dispatch {
    DISPATCH.get_or_init(detect_dispatch)
}

fn detect_dispatch() -> Gf256Dispatch {
    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return Gf256Dispatch {
                kind: Gf256Kernel::X86Avx2,
                add_slice: gf256_add_slice_x86_avx2,
                mul_slice: gf256_mul_slice_x86_avx2,
                addmul_slice: gf256_addmul_slice_x86_avx2,
            };
        }
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return Gf256Dispatch {
                kind: Gf256Kernel::Aarch64Neon,
                add_slice: gf256_add_slice_aarch64_neon,
                mul_slice: gf256_mul_slice_aarch64_neon,
                addmul_slice: gf256_addmul_slice_aarch64_neon,
            };
        }
    }

    Gf256Dispatch {
        kind: Gf256Kernel::Scalar,
        add_slice: gf256_add_slice_scalar,
        mul_slice: gf256_mul_slice_scalar,
        addmul_slice: gf256_addmul_slice_scalar,
    }
}

/// Deterministic policy for dual-slice fused kernels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DualKernelOverride {
    Auto,
    ForceSequential,
    ForceFused,
}

#[derive(Clone, Copy, Debug)]
struct DualKernelPolicy {
    mode: DualKernelOverride,
    mul_min_total: usize,
    mul_max_total: usize,
    addmul_min_total: usize,
    addmul_max_total: usize,
    max_lane_ratio: usize,
}

fn dual_policy() -> &'static DualKernelPolicy {
    DUAL_POLICY.get_or_init(detect_dual_policy)
}

fn detect_dual_policy() -> DualKernelPolicy {
    let mode = match std::env::var("ASUPERSYNC_GF256_DUAL_POLICY")
        .ok()
        .as_deref()
    {
        Some("off" | "sequential") => DualKernelOverride::ForceSequential,
        Some("fused" | "force_fused") => DualKernelOverride::ForceFused,
        _ => DualKernelOverride::Auto,
    };

    let mut policy = match dispatch().kind {
        Gf256Kernel::Scalar => DualKernelPolicy {
            mode,
            mul_min_total: usize::MAX,
            mul_max_total: 0,
            addmul_min_total: usize::MAX,
            addmul_max_total: 0,
            max_lane_ratio: 1,
        },
        #[cfg(all(
            feature = "simd-intrinsics",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        Gf256Kernel::X86Avx2 => DualKernelPolicy {
            mode,
            // Conservative default: prefer fused dual mul on medium-size windows
            // and disable on large windows where some workers regress.
            mul_min_total: 8 * 1024,
            mul_max_total: 24 * 1024,
            // Addmul has thinner margins; keep fused window narrower.
            addmul_min_total: 8 * 1024,
            addmul_max_total: 16 * 1024,
            max_lane_ratio: 8,
        },
        #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
        Gf256Kernel::Aarch64Neon => DualKernelPolicy {
            mode,
            mul_min_total: 8 * 1024,
            mul_max_total: 24 * 1024,
            addmul_min_total: 8 * 1024,
            addmul_max_total: 16 * 1024,
            max_lane_ratio: 8,
        },
    };

    if let Some(v) = parse_usize_env("ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL") {
        policy.mul_min_total = v;
    }
    if let Some(v) = parse_usize_env("ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL") {
        policy.mul_max_total = v;
    }
    if let Some(v) = parse_usize_env("ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL") {
        policy.addmul_min_total = v;
    }
    if let Some(v) = parse_usize_env("ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL") {
        policy.addmul_max_total = v;
    }
    if let Some(v) = parse_usize_env("ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO") {
        policy.max_lane_ratio = v.max(1);
    }

    policy
}

fn parse_usize_env(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.parse::<usize>().ok()
}

#[inline]
fn lane_ratio_within(len_a: usize, len_b: usize, max_ratio: usize) -> bool {
    let lo = len_a.min(len_b);
    let hi = len_a.max(len_b);
    lo > 0 && lo.saturating_mul(max_ratio) >= hi
}

#[inline]
fn in_window(total: usize, min_total: usize, max_total: usize) -> bool {
    min_total <= max_total && (min_total..=max_total).contains(&total)
}

#[inline]
fn should_use_dual_mul_fused(len_a: usize, len_b: usize) -> bool {
    let policy = dual_policy();
    match policy.mode {
        DualKernelOverride::ForceSequential => false,
        DualKernelOverride::ForceFused => true,
        DualKernelOverride::Auto => {
            let total = len_a.saturating_add(len_b);
            in_window(total, policy.mul_min_total, policy.mul_max_total)
                && lane_ratio_within(len_a, len_b, policy.max_lane_ratio)
        }
    }
}

#[inline]
fn should_use_dual_addmul_fused(len_a: usize, len_b: usize) -> bool {
    let policy = dual_policy();
    match policy.mode {
        DualKernelOverride::ForceSequential => false,
        DualKernelOverride::ForceFused => true,
        DualKernelOverride::Auto => {
            let total = len_a.saturating_add(len_b);
            in_window(total, policy.addmul_min_total, policy.addmul_max_total)
                && lane_ratio_within(len_a, len_b, policy.max_lane_ratio)
        }
    }
}

/// Returns the active runtime-selected GF(256) bulk kernel family.
#[must_use]
pub fn active_kernel() -> Gf256Kernel {
    dispatch().kind
}

// ============================================================================
// Field element wrapper
// ============================================================================

/// An element of GF(256).
///
/// Wraps a `u8` and provides field arithmetic operations. All operations
/// are constant-time with respect to the element value (table lookups).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Gf256(pub u8);

impl Gf256 {
    /// The additive identity (zero element).
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity (one element).
    pub const ONE: Self = Self(1);

    /// The primitive element (generator of the multiplicative group).
    pub const ALPHA: Self = Self(GENERATOR as u8);

    /// Creates a field element from a raw byte.
    #[inline]
    #[must_use]
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    /// Returns the raw byte value.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns true if this is the zero element.
    #[inline]
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Field addition (XOR).
    #[inline]
    #[must_use]
    pub const fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    /// Field subtraction (same as addition in characteristic 2).
    #[inline]
    #[must_use]
    pub const fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }

    /// Field multiplication using log/exp tables.
    ///
    /// Returns `ZERO` if either operand is zero.
    #[inline]
    #[must_use]
    pub fn mul_field(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 {
            return Self::ZERO;
        }
        let log_sum = LOG[self.0 as usize] as usize + LOG[rhs.0 as usize] as usize;
        Self(EXP[log_sum])
    }

    /// Multiplicative inverse.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (zero has no multiplicative inverse).
    #[inline]
    #[must_use]
    pub fn inv(self) -> Self {
        assert!(!self.is_zero(), "cannot invert zero in GF(256)");
        // inv(a) = a^254 = EXP[255 - LOG[a]]
        let log_a = LOG[self.0 as usize] as usize;
        Self(EXP[255 - log_a])
    }

    /// Field division: `self / rhs`.
    ///
    /// # Panics
    ///
    /// Panics if `rhs` is zero.
    #[inline]
    #[must_use]
    pub fn div_field(self, rhs: Self) -> Self {
        self.mul_field(rhs.inv())
    }

    /// Exponentiation: `self^exp` using the log/exp tables.
    ///
    /// Returns `ONE` for any base raised to the zero power.
    /// Returns `ZERO` for zero raised to any positive power.
    #[must_use]
    pub fn pow(self, exp: u8) -> Self {
        if exp == 0 {
            return Self::ONE;
        }
        if self.is_zero() {
            return Self::ZERO;
        }
        let log_a = u32::from(LOG[self.0 as usize]);
        let log_result = (log_a * u32::from(exp)) % 255;
        Self(EXP[log_result as usize])
    }
}

impl std::fmt::Debug for Gf256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GF({})", self.0)
    }
}

impl std::fmt::Display for Gf256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for Gf256 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::add(self, rhs)
    }
}

impl std::ops::Sub for Gf256 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::sub(self, rhs)
    }
}

impl std::ops::Mul for Gf256 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::mul_field(self, rhs)
    }
}

impl std::ops::Div for Gf256 {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        Self::div_field(self, rhs)
    }
}

impl std::ops::AddAssign for Gf256 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = Self::add(*self, rhs);
    }
}

impl std::ops::MulAssign for Gf256 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul_field(*self, rhs);
    }
}

// ============================================================================
// Bulk operations on byte slices (symbol-level XOR + scale)
// ============================================================================

/// XOR `src` into `dst` element-wise: `dst[i] ^= src[i]`.
///
/// Uses 32-byte-wide XOR (4×u64) for throughput on bulk data, falling back
/// to 8-byte and scalar loops for the tail.
///
/// # Panics
///
/// Panics if `src.len() != dst.len()`.
#[inline]
pub fn gf256_add_slice(dst: &mut [u8], src: &[u8]) {
    (dispatch().add_slice)(dst, src);
}

fn gf256_add_slice_scalar(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");

    // Wide path: 32 bytes (4×u64) per iteration.
    let mut d_chunks = dst.chunks_exact_mut(32);
    let mut s_chunks = src.chunks_exact(32);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let mut d_words = [
            u64::from_ne_bytes(d_chunk[0..8].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[8..16].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[16..24].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[24..32].try_into().unwrap()),
        ];
        let s_words = [
            u64::from_ne_bytes(s_chunk[0..8].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[8..16].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[16..24].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[24..32].try_into().unwrap()),
        ];
        d_words[0] ^= s_words[0];
        d_words[1] ^= s_words[1];
        d_words[2] ^= s_words[2];
        d_words[3] ^= s_words[3];
        d_chunk[0..8].copy_from_slice(&d_words[0].to_ne_bytes());
        d_chunk[8..16].copy_from_slice(&d_words[1].to_ne_bytes());
        d_chunk[16..24].copy_from_slice(&d_words[2].to_ne_bytes());
        d_chunk[24..32].copy_from_slice(&d_words[3].to_ne_bytes());
    }

    // 8-byte tail.
    let d_rem = d_chunks.into_remainder();
    let s_rem = s_chunks.remainder();
    let mut d8 = d_rem.chunks_exact_mut(8);
    let mut s8 = s_rem.chunks_exact(8);
    for (d_chunk, s_chunk) in d8.by_ref().zip(s8.by_ref()) {
        let d_arr: [u8; 8] = d_chunk.try_into().unwrap();
        let s_arr: [u8; 8] = s_chunk.try_into().unwrap();
        let result = u64::from_ne_bytes(d_arr) ^ u64::from_ne_bytes(s_arr);
        d_chunk.copy_from_slice(&result.to_ne_bytes());
    }

    // Scalar tail.
    for (d, s) in d8.into_remainder().iter_mut().zip(s8.remainder()) {
        *d ^= s;
    }
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
fn gf256_add_slice_x86_avx2(dst: &mut [u8], src: &[u8]) {
    // Dispatch scaffold: AVX2 lane currently reuses scalar core.
    gf256_add_slice_scalar(dst, src);
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
fn gf256_add_slice_aarch64_neon(dst: &mut [u8], src: &[u8]) {
    // Dispatch scaffold: NEON lane currently reuses scalar core.
    gf256_add_slice_scalar(dst, src);
}

/// Minimum slice length to amortise building a 256-byte multiplication table.
///
/// The table build is 255 lookups; above this threshold the per-element
/// savings from single-lookup (vs. branch + double-lookup) outweigh the
/// up-front cost.
const MUL_TABLE_THRESHOLD: usize = 64;

#[inline]
fn mul_table_for(c: Gf256) -> &'static [u8; 256] {
    &MUL_TABLES[c.0 as usize]
}

#[cfg(feature = "simd-intrinsics")]
const fn build_mul_nibble_tables() -> ([[u8; 16]; 256], [[u8; 16]; 256]) {
    let mut low = [[0u8; 16]; 256];
    let mut high = [[0u8; 16]; 256];
    let mut c = 0usize;
    while c < 256 {
        let mut i = 0usize;
        while i < 16 {
            low[c][i] = gf256_mul_const(i as u8, c as u8);
            high[c][i] = gf256_mul_const((i as u8) << 4, c as u8);
            i += 1;
        }
        c += 1;
    }
    (low, high)
}

#[cfg(feature = "simd-intrinsics")]
static MUL_NIBBLE_TABLES: ([[u8; 16]; 256], [[u8; 16]; 256]) = build_mul_nibble_tables();

#[cfg(feature = "simd-intrinsics")]
#[inline]
fn mul_nibble_tables(c: Gf256) -> (&'static [u8; 16], &'static [u8; 16]) {
    (
        &MUL_NIBBLE_TABLES.0[c.0 as usize],
        &MUL_NIBBLE_TABLES.1[c.0 as usize],
    )
}

/// Multiply every element of `dst` by scalar `c` in GF(256).
///
/// For slices >= `MUL_TABLE_THRESHOLD` bytes, a pre-built 256-entry table
/// replaces per-element branch+double-lookup with a single table lookup.
///
/// If `c` is zero, the entire slice is zeroed. If `c` is one, this is a no-op.
#[inline]
pub fn gf256_mul_slice(dst: &mut [u8], c: Gf256) {
    (dispatch().mul_slice)(dst, c);
}

/// Multiply two slices by the same scalar in one fused dispatch.
///
/// This superkernel amortizes table/nibble derivation and ISA dispatch across
/// both slices: `dst_a[i] *= c` and `dst_b[i] *= c`.
#[inline]
pub fn gf256_mul_slices2(dst_a: &mut [u8], dst_b: &mut [u8], c: Gf256) {
    if c.is_zero() {
        dst_a.fill(0);
        dst_b.fill(0);
        return;
    }
    if c == Gf256::ONE {
        return;
    }
    if !should_use_dual_mul_fused(dst_a.len(), dst_b.len()) {
        gf256_mul_slice(dst_a, c);
        gf256_mul_slice(dst_b, c);
        return;
    }

    let table = mul_table_for(c);
    #[cfg(feature = "simd-intrinsics")]
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    if matches!(dispatch().kind, Gf256Kernel::X86Avx2) && std::is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 support is checked above and pointers remain within
        // bounds of the provided slices.
        unsafe {
            gf256_mul_slice_x86_avx2_impl_tables(dst_a, low_tbl_arr, high_tbl_arr, table);
            gf256_mul_slice_x86_avx2_impl_tables(dst_b, low_tbl_arr, high_tbl_arr, table);
        }
        return;
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    if matches!(dispatch().kind, Gf256Kernel::Aarch64Neon)
        && std::arch::is_aarch64_feature_detected!("neon")
    {
        // SAFETY: NEON support is checked above and pointers remain within
        // bounds of the provided slices.
        unsafe {
            gf256_mul_slice_aarch64_neon_impl_tables(dst_a, low_tbl_arr, high_tbl_arr, table);
            gf256_mul_slice_aarch64_neon_impl_tables(dst_b, low_tbl_arr, high_tbl_arr, table);
        }
        return;
    }

    let nib = NibbleTables::for_scalar(c);
    mul_with_table_wide(dst_a, &nib, table);
    mul_with_table_wide(dst_b, &nib, table);
}

fn gf256_mul_slice_scalar(dst: &mut [u8], c: Gf256) {
    if c.is_zero() {
        dst.fill(0);
        return;
    }
    if c == Gf256::ONE {
        return;
    }
    if dst.len() >= MUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        let table = mul_table_for(c);
        mul_with_table_wide(dst, &nib, table);
    } else {
        let log_c = LOG[c.0 as usize] as usize;
        for d in dst.iter_mut() {
            if *d != 0 {
                *d = EXP[LOG[*d as usize] as usize + log_c];
            }
        }
    }
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
fn gf256_mul_slice_x86_avx2(dst: &mut [u8], c: Gf256) {
    if c.is_zero() {
        dst.fill(0);
        return;
    }
    if c == Gf256::ONE {
        return;
    }
    if dst.len() < 32 {
        gf256_mul_slice_scalar(dst, c);
        return;
    }
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: CPU feature is checked at runtime above, and the function
        // only reads/writes within `dst` bounds.
        unsafe {
            gf256_mul_slice_x86_avx2_impl(dst, c);
        }
    } else {
        gf256_mul_slice_scalar(dst, c);
    }
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
fn gf256_mul_slice_aarch64_neon(dst: &mut [u8], c: Gf256) {
    if c.is_zero() {
        dst.fill(0);
        return;
    }
    if c == Gf256::ONE {
        return;
    }
    if dst.len() < 16 {
        gf256_mul_slice_scalar(dst, c);
        return;
    }
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: CPU feature is checked at runtime above, and the function
        // only reads/writes within `dst` bounds.
        unsafe {
            gf256_mul_slice_aarch64_neon_impl(dst, c);
        }
    } else {
        gf256_mul_slice_scalar(dst, c);
    }
}

/// SIMD inner loop for `gf256_mul_slice`: processes 16 bytes per iteration
/// via Halevi-Shacham nibble decomposition (`swizzle_dyn` → PSHUFB on x86).
///
/// Falls back to scalar table lookups for the remainder (< 16 bytes).
#[cfg(feature = "simd-intrinsics")]
fn mul_with_table_wide(dst: &mut [u8], nib: &NibbleTables, table: &[u8; 256]) {
    let mut chunks = dst.chunks_exact_mut(16);
    for chunk in chunks.by_ref() {
        let x = Simd::<u8, 16>::from_slice(chunk);
        let result = nib.mul16(x);
        chunk.copy_from_slice(result.as_array());
    }
    for d in chunks.into_remainder() {
        *d = table[*d as usize];
    }
}

#[cfg(not(feature = "simd-intrinsics"))]
fn mul_with_table_wide(dst: &mut [u8], _nib: &NibbleTables, table: &[u8; 256]) {
    for d in dst.iter_mut() {
        *d = table[*d as usize];
    }
}

/// Scalar inner loop for `gf256_mul_slice` (retained for test comparison).
#[cfg(test)]
fn mul_with_table_scalar(dst: &mut [u8], table: &[u8; 256]) {
    let mut chunks = dst.chunks_exact_mut(8);
    for chunk in chunks.by_ref() {
        let t = [
            table[chunk[0] as usize],
            table[chunk[1] as usize],
            table[chunk[2] as usize],
            table[chunk[3] as usize],
            table[chunk[4] as usize],
            table[chunk[5] as usize],
            table[chunk[6] as usize],
            table[chunk[7] as usize],
        ];
        chunk.copy_from_slice(&t);
    }
    for d in chunks.into_remainder() {
        *d = table[*d as usize];
    }
}

/// SIMD inner loop for `gf256_addmul_slice`: processes 16 bytes per iteration
/// via Halevi-Shacham nibble decomposition, XORing the products into `dst`.
///
/// Falls back to scalar table lookups for the remainder (< 16 bytes).
#[cfg(feature = "simd-intrinsics")]
fn addmul_with_table_wide(dst: &mut [u8], src: &[u8], nib: &NibbleTables, table: &[u8; 256]) {
    let mut d_chunks = dst.chunks_exact_mut(16);
    let mut s_chunks = src.chunks_exact(16);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let s = Simd::<u8, 16>::from_slice(s_chunk);
        let d = Simd::<u8, 16>::from_slice(d_chunk);
        let result = d ^ nib.mul16(s);
        d_chunk.copy_from_slice(result.as_array());
    }
    for (d, s) in d_chunks
        .into_remainder()
        .iter_mut()
        .zip(s_chunks.remainder())
    {
        *d ^= table[*s as usize];
    }
}

#[cfg(not(feature = "simd-intrinsics"))]
fn addmul_with_table_wide(dst: &mut [u8], src: &[u8], _nib: &NibbleTables, table: &[u8; 256]) {
    for (d, s) in dst.iter_mut().zip(src.iter().copied()) {
        *d ^= table[s as usize];
    }
}

/// Scalar inner loop for `gf256_addmul_slice` (retained for test comparison).
#[cfg(test)]
fn addmul_with_table_scalar(dst: &mut [u8], src: &[u8], table: &[u8; 256]) {
    let mut d_chunks = dst.chunks_exact_mut(8);
    let mut s_chunks = src.chunks_exact(8);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let t = [
            table[s_chunk[0] as usize],
            table[s_chunk[1] as usize],
            table[s_chunk[2] as usize],
            table[s_chunk[3] as usize],
            table[s_chunk[4] as usize],
            table[s_chunk[5] as usize],
            table[s_chunk[6] as usize],
            table[s_chunk[7] as usize],
        ];
        let d_arr: [u8; 8] = d_chunk[..].try_into().unwrap();
        let result = u64::from_ne_bytes(d_arr) ^ u64::from_ne_bytes(t);
        d_chunk.copy_from_slice(&result.to_ne_bytes());
    }
    for (d, s) in d_chunks
        .into_remainder()
        .iter_mut()
        .zip(s_chunks.remainder())
    {
        *d ^= table[*s as usize];
    }
}

/// Multiply-accumulate: `dst[i] += c * src[i]` in GF(256).
///
/// For slices >= 64 bytes the hot path builds a 256-entry multiplication
/// table and processes 8 bytes at a time via `u64` wide-XOR
/// (`addmul_with_table_wide`). Smaller slices fall back to scalar
/// log/exp lookups.
///
/// # Panics
///
/// Panics if `src.len() != dst.len()`.
#[inline]
pub fn gf256_addmul_slice(dst: &mut [u8], src: &[u8], c: Gf256) {
    (dispatch().addmul_slice)(dst, src, c);
}

/// Multiply-accumulate two independent pairs using one fused scalar path.
///
/// Applies:
/// - `dst_a[i] += c * src_a[i]`
/// - `dst_b[i] += c * src_b[i]`
///
/// with shared kernel setup for both pairs.
///
/// # Panics
///
/// Panics if `dst_a.len() != src_a.len()` or `dst_b.len() != src_b.len()`.
#[inline]
pub fn gf256_addmul_slices2(
    dst_a: &mut [u8],
    src_a: &[u8],
    dst_b: &mut [u8],
    src_b: &[u8],
    c: Gf256,
) {
    assert_eq!(dst_a.len(), src_a.len(), "slice length mismatch");
    assert_eq!(dst_b.len(), src_b.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice(dst_a, src_a);
        gf256_add_slice(dst_b, src_b);
        return;
    }
    if !should_use_dual_addmul_fused(dst_a.len(), dst_b.len()) {
        gf256_addmul_slice(dst_a, src_a, c);
        gf256_addmul_slice(dst_b, src_b, c);
        return;
    }

    let table = mul_table_for(c);
    #[cfg(feature = "simd-intrinsics")]
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    if matches!(dispatch().kind, Gf256Kernel::X86Avx2) && std::is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 support is checked above and both pairs are length-checked.
        unsafe {
            gf256_addmul_slice_x86_avx2_impl_tables(dst_a, src_a, low_tbl_arr, high_tbl_arr, table);
            gf256_addmul_slice_x86_avx2_impl_tables(dst_b, src_b, low_tbl_arr, high_tbl_arr, table);
        }
        return;
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    if matches!(dispatch().kind, Gf256Kernel::Aarch64Neon)
        && std::arch::is_aarch64_feature_detected!("neon")
    {
        // SAFETY: NEON support is checked above and both pairs are length-checked.
        unsafe {
            gf256_addmul_slice_aarch64_neon_impl_tables(
                dst_a,
                src_a,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
            gf256_addmul_slice_aarch64_neon_impl_tables(
                dst_b,
                src_b,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
        }
        return;
    }

    let nib = NibbleTables::for_scalar(c);
    addmul_with_table_wide(dst_a, src_a, &nib, table);
    addmul_with_table_wide(dst_b, src_b, &nib, table);
}

fn gf256_addmul_slice_scalar(dst: &mut [u8], src: &[u8], c: Gf256) {
    const ADDMUL_TABLE_THRESHOLD: usize = 64;

    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice_scalar(dst, src);
        return;
    }
    if src.len() >= ADDMUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        let table = mul_table_for(c);
        addmul_with_table_wide(dst, src, &nib, table);
        return;
    }
    let log_c = LOG[c.0 as usize] as usize;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        if *s != 0 {
            *d ^= EXP[LOG[*s as usize] as usize + log_c];
        }
    }
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
fn gf256_addmul_slice_x86_avx2(dst: &mut [u8], src: &[u8], c: Gf256) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice_x86_avx2(dst, src);
        return;
    }
    if src.len() < 32 {
        gf256_addmul_slice_scalar(dst, src, c);
        return;
    }
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: CPU feature is checked at runtime above, and both slices are
        // length-checked to match before vectorized processing.
        unsafe {
            gf256_addmul_slice_x86_avx2_impl(dst, src, c);
        }
    } else {
        gf256_addmul_slice_scalar(dst, src, c);
    }
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
fn gf256_addmul_slice_aarch64_neon(dst: &mut [u8], src: &[u8], c: Gf256) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice_aarch64_neon(dst, src);
        return;
    }
    if src.len() < 16 {
        gf256_addmul_slice_scalar(dst, src, c);
        return;
    }
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: CPU feature is checked at runtime above, and both slices are
        // length-checked to match before vectorized processing.
        unsafe {
            gf256_addmul_slice_aarch64_neon_impl(dst, src, c);
        }
    } else {
        gf256_addmul_slice_scalar(dst, src, c);
    }
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "avx2")]
unsafe fn gf256_mul_slice_x86_avx2_impl(dst: &mut [u8], c: Gf256) {
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
    gf256_mul_slice_x86_avx2_impl_tables(dst, low_tbl_arr, high_tbl_arr, mul_table_for(c));
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "avx2")]
unsafe fn gf256_mul_slice_x86_avx2_impl_tables(
    dst: &mut [u8],
    low_tbl_arr: &[u8; 16],
    high_tbl_arr: &[u8; 16],
    table: &[u8; 256],
) {
    // SAFETY: caller guarantees AVX2 support.
    let low_tbl_128 = unsafe { _mm_loadu_si128(low_tbl_arr.as_ptr().cast::<__m128i>()) };
    let high_tbl_128 = unsafe { _mm_loadu_si128(high_tbl_arr.as_ptr().cast::<__m128i>()) };
    let low_tbl_256 = _mm256_broadcastsi128_si256(low_tbl_128);
    let high_tbl_256 = _mm256_broadcastsi128_si256(high_tbl_128);
    let nibble_mask = _mm256_set1_epi8(0x0f_i8);

    let mut i = 0usize;
    while i + 32 <= dst.len() {
        let ptr = unsafe { dst.as_mut_ptr().add(i) };
        // SAFETY: pointer range is in-bounds and unaligned loads/stores are used.
        let input = unsafe { _mm256_loadu_si256(ptr.cast::<__m256i>()) };
        let low_nibbles = _mm256_and_si256(input, nibble_mask);
        let high_nibbles = _mm256_and_si256(_mm256_srli_epi16(input, 4), nibble_mask);
        let low_mul = _mm256_shuffle_epi8(low_tbl_256, low_nibbles);
        let high_mul = _mm256_shuffle_epi8(high_tbl_256, high_nibbles);
        let result = _mm256_xor_si256(low_mul, high_mul);
        unsafe { _mm256_storeu_si256(ptr.cast::<__m256i>(), result) };
        i += 32;
    }

    for d in &mut dst[i..] {
        *d = table[*d as usize];
    }
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "avx2")]
unsafe fn gf256_addmul_slice_x86_avx2_impl(dst: &mut [u8], src: &[u8], c: Gf256) {
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
    gf256_addmul_slice_x86_avx2_impl_tables(dst, src, low_tbl_arr, high_tbl_arr, mul_table_for(c));
}

#[cfg(all(
    feature = "simd-intrinsics",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "avx2")]
unsafe fn gf256_addmul_slice_x86_avx2_impl_tables(
    dst: &mut [u8],
    src: &[u8],
    low_tbl_arr: &[u8; 16],
    high_tbl_arr: &[u8; 16],
    table: &[u8; 256],
) {
    // SAFETY: caller guarantees AVX2 support and matching lengths.
    let low_tbl_128 = unsafe { _mm_loadu_si128(low_tbl_arr.as_ptr().cast::<__m128i>()) };
    let high_tbl_128 = unsafe { _mm_loadu_si128(high_tbl_arr.as_ptr().cast::<__m128i>()) };
    let low_tbl_256 = _mm256_broadcastsi128_si256(low_tbl_128);
    let high_tbl_256 = _mm256_broadcastsi128_si256(high_tbl_128);
    let nibble_mask = _mm256_set1_epi8(0x0f_i8);

    let mut i = 0usize;
    while i + 32 <= src.len() {
        let src_ptr = unsafe { src.as_ptr().add(i) };
        let dst_ptr = unsafe { dst.as_mut_ptr().add(i) };
        // SAFETY: pointer ranges are in-bounds and unaligned loads/stores are used.
        let src_v = unsafe { _mm256_loadu_si256(src_ptr.cast::<__m256i>()) };
        let dst_v = unsafe { _mm256_loadu_si256(dst_ptr.cast::<__m256i>()) };
        let low_nibbles = _mm256_and_si256(src_v, nibble_mask);
        let high_nibbles = _mm256_and_si256(_mm256_srli_epi16(src_v, 4), nibble_mask);
        let low_mul = _mm256_shuffle_epi8(low_tbl_256, low_nibbles);
        let high_mul = _mm256_shuffle_epi8(high_tbl_256, high_nibbles);
        let product = _mm256_xor_si256(low_mul, high_mul);
        let result = _mm256_xor_si256(dst_v, product);
        unsafe { _mm256_storeu_si256(dst_ptr.cast::<__m256i>(), result) };
        i += 32;
    }

    for (d, s) in dst[i..].iter_mut().zip(src[i..].iter()) {
        *d ^= table[*s as usize];
    }
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
unsafe fn gf256_mul_slice_aarch64_neon_impl(dst: &mut [u8], c: Gf256) {
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
    gf256_mul_slice_aarch64_neon_impl_tables(dst, low_tbl_arr, high_tbl_arr, mul_table_for(c));
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
unsafe fn gf256_mul_slice_aarch64_neon_impl_tables(
    dst: &mut [u8],
    low_tbl_arr: &[u8; 16],
    high_tbl_arr: &[u8; 16],
    table: &[u8; 256],
) {
    // SAFETY: caller guarantees NEON support.
    let low_tbl: uint8x16_t = unsafe { vld1q_u8(low_tbl_arr.as_ptr()) };
    let high_tbl: uint8x16_t = unsafe { vld1q_u8(high_tbl_arr.as_ptr()) };
    let nibble_mask = vdupq_n_u8(0x0f);

    let mut i = 0usize;
    while i + 16 <= dst.len() {
        let ptr = unsafe { dst.as_mut_ptr().add(i) };
        let input = unsafe { vld1q_u8(ptr) };
        let low_nibbles = vandq_u8(input, nibble_mask);
        let high_nibbles = vandq_u8(vshrq_n_u8(input, 4), nibble_mask);
        let low_mul = vqtbl1q_u8(low_tbl, low_nibbles);
        let high_mul = vqtbl1q_u8(high_tbl, high_nibbles);
        let result = veorq_u8(low_mul, high_mul);
        unsafe { vst1q_u8(ptr, result) };
        i += 16;
    }

    for d in &mut dst[i..] {
        *d = table[*d as usize];
    }
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
unsafe fn gf256_addmul_slice_aarch64_neon_impl(dst: &mut [u8], src: &[u8], c: Gf256) {
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
    gf256_addmul_slice_aarch64_neon_impl_tables(
        dst,
        src,
        low_tbl_arr,
        high_tbl_arr,
        mul_table_for(c),
    );
}

#[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
unsafe fn gf256_addmul_slice_aarch64_neon_impl_tables(
    dst: &mut [u8],
    src: &[u8],
    low_tbl_arr: &[u8; 16],
    high_tbl_arr: &[u8; 16],
    table: &[u8; 256],
) {
    // SAFETY: caller guarantees NEON support and matching lengths.
    let low_tbl: uint8x16_t = unsafe { vld1q_u8(low_tbl_arr.as_ptr()) };
    let high_tbl: uint8x16_t = unsafe { vld1q_u8(high_tbl_arr.as_ptr()) };
    let nibble_mask = vdupq_n_u8(0x0f);

    let mut i = 0usize;
    while i + 16 <= src.len() {
        let src_ptr = unsafe { src.as_ptr().add(i) };
        let dst_ptr = unsafe { dst.as_mut_ptr().add(i) };
        let src_v = unsafe { vld1q_u8(src_ptr) };
        let dst_v = unsafe { vld1q_u8(dst_ptr) };
        let low_nibbles = vandq_u8(src_v, nibble_mask);
        let high_nibbles = vandq_u8(vshrq_n_u8(src_v, 4), nibble_mask);
        let low_mul = vqtbl1q_u8(low_tbl, low_nibbles);
        let high_mul = vqtbl1q_u8(high_tbl, high_nibbles);
        let product = veorq_u8(low_mul, high_mul);
        let result = veorq_u8(dst_v, product);
        unsafe { vst1q_u8(dst_ptr, result) };
        i += 16;
    }

    for (d, s) in dst[i..].iter_mut().zip(src[i..].iter()) {
        *d ^= table[*s as usize];
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        format!(
            "scenario_id={scenario_id} seed={seed} parameter_set={parameter_set} replay_ref={replay_ref}"
        )
    }

    // -- Table sanity --

    #[test]
    fn exp_table_generates_all_nonzero() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "exp_table_generates_all_nonzero",
            replay_ref,
        );
        let mut visited = [false; 256];
        for (i, &v) in EXP.iter().enumerate().take(255) {
            assert!(!visited[v as usize], "duplicate EXP[{i}] = {v}; {context}");
            visited[v as usize] = true;
        }
        // Zero should not appear in EXP[0..255]
        assert!(
            !visited[0],
            "zero should not be generated by EXP table; {context}"
        );
    }

    #[test]
    fn log_exp_roundtrip() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "log_exp_roundtrip", replay_ref);
        for a in 1u16..=255 {
            let log_a = LOG[a as usize];
            assert_eq!(
                EXP[log_a as usize], a as u8,
                "roundtrip failed for {a}; {context}"
            );
        }
    }

    #[test]
    fn exp_wraps_at_255() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "exp_wraps_at_255", replay_ref);
        // EXP[i] == EXP[i + 255] for i in 0..255
        for i in 0..255 {
            assert_eq!(EXP[i], EXP[i + 255], "mirror mismatch at {i}; {context}");
        }
    }

    // -- Field axioms --

    #[test]
    fn additive_identity() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "additive_identity", replay_ref);
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + Gf256::ZERO, fa, "{context}");
            assert_eq!(Gf256::ZERO + fa, fa, "{context}");
        }
    }

    #[test]
    fn additive_inverse() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "additive_inverse", replay_ref);
        // In GF(2^n), every element is its own additive inverse.
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + fa, Gf256::ZERO, "{context}");
        }
    }

    #[test]
    fn multiplicative_identity() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplicative_identity",
            replay_ref,
        );
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa * Gf256::ONE, fa, "{context}");
            assert_eq!(Gf256::ONE * fa, fa, "{context}");
        }
    }

    #[test]
    fn multiplicative_inverse_all_nonzero() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplicative_inverse_all_nonzero",
            replay_ref,
        );
        for a in 1u8..=255 {
            let fa = Gf256(a);
            let inv = fa.inv();
            assert_eq!(
                fa * inv,
                Gf256::ONE,
                "a={a}, inv={}, product={}; {context}",
                inv.0,
                (fa * inv).0
            );
            assert_eq!(inv * fa, Gf256::ONE, "{context}");
        }
    }

    #[test]
    #[should_panic(expected = "cannot invert zero")]
    fn inverse_of_zero_panics() {
        let _ = Gf256::ZERO.inv();
    }

    #[test]
    fn multiplication_commutative() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplication_commutative",
            replay_ref,
        );
        // Spot check: all pairs would be 65k, so test a representative sample.
        for a in (0u8..=255).step_by(7) {
            for b in (0u8..=255).step_by(11) {
                let fa = Gf256(a);
                let fb = Gf256(b);
                assert_eq!(
                    fa * fb,
                    fb * fa,
                    "commutativity failed: {a} * {b}; {context}"
                );
            }
        }
    }

    #[test]
    fn multiplication_associative() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplication_associative",
            replay_ref,
        );
        let triples = [
            (3u8, 7, 11),
            (0, 100, 200),
            (1, 255, 128),
            (37, 42, 199),
            (255, 255, 255),
        ];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                (fa * fb) * fc,
                fa * (fb * fc),
                "associativity failed: {a} * {b} * {c}; {context}"
            );
        }
    }

    #[test]
    fn distributive_law() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "distributive_law", replay_ref);
        let triples = [(3u8, 7, 11), (100, 200, 50), (255, 1, 0), (37, 42, 199)];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                fa * (fb + fc),
                fa * fb + fa * fc,
                "distributive law failed: {a} * ({b} + {c}); {context}"
            );
        }
    }

    #[test]
    fn zero_annihilates() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "zero_annihilates", replay_ref);
        for a in 0u8..=255 {
            assert_eq!(Gf256(a) * Gf256::ZERO, Gf256::ZERO, "{context}");
        }
    }

    // -- Exponentiation --

    #[test]
    fn pow_basic() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "pow_basic", replay_ref);
        let g = Gf256::ALPHA; // generator = 2
        assert_eq!(g.pow(0), Gf256::ONE, "{context}");
        assert_eq!(g.pow(1), g, "{context}");
        // g^8 should equal the reduction of x^8 = x^4 + x^3 + x^2 + 1 = 0x1D = 29
        assert_eq!(g.pow(8), Gf256(POLY as u8), "{context}");
    }

    #[test]
    fn pow_fermats_little() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "pow_fermats_little", replay_ref);
        // a^255 = 1 for all nonzero a in GF(256)
        for a in 1u8..=255 {
            assert_eq!(
                Gf256(a).pow(255),
                Gf256::ONE,
                "Fermat's little theorem failed for {a}; {context}"
            );
        }
    }

    // -- Division --

    #[test]
    fn division_is_mul_inverse() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "division_is_mul_inverse",
            replay_ref,
        );
        let pairs = [(6u8, 3), (255, 1), (100, 200), (42, 37)];
        for (a, b) in pairs {
            let fa = Gf256(a);
            let fb = Gf256(b);
            assert_eq!(fa / fb, fa * fb.inv(), "{context}");
        }
    }

    #[test]
    fn div_self_is_one() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "div_self_is_one", replay_ref);
        for a in 1u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa / fa, Gf256::ONE, "{context}");
        }
    }

    // -- Bulk slice operations --

    #[test]
    fn add_slice_xors() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "add_slice_xors", replay_ref);
        let mut dst = vec![0x00, 0xFF, 0xAA];
        let src = vec![0xFF, 0xFF, 0x55];
        gf256_add_slice(&mut dst, &src);
        assert_eq!(dst, vec![0xFF, 0x00, 0xFF], "{context}");
    }

    #[test]
    fn mul_slice_by_one_is_noop() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_by_one_is_noop",
            replay_ref,
        );
        let original = vec![1, 2, 3, 100, 255];
        let mut data = original.clone();
        gf256_mul_slice(&mut data, Gf256::ONE);
        assert_eq!(data, original, "{context}");
    }

    #[test]
    fn mul_slice_by_zero_clears() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_by_zero_clears",
            replay_ref,
        );
        let mut data = vec![1, 2, 3, 100, 255];
        gf256_mul_slice(&mut data, Gf256::ZERO);
        assert_eq!(data, vec![0, 0, 0, 0, 0], "{context}");
    }

    #[test]
    fn mul_slice_large_inputs() {
        // Exercise the `mul_with_table_wide` path (>= MUL_TABLE_THRESHOLD bytes).
        const LEN: usize = 64 + 7; // 71 bytes: crosses the 64-byte threshold
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_large_inputs",
            replay_ref,
        );
        let original: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let expected: Vec<u8> = original.iter().map(|&s| (Gf256(s) * c).0).collect();
        let mut data = original;
        gf256_mul_slice(&mut data, c);
        assert_eq!(data, expected, "{context}");
    }

    #[test]
    fn addmul_slice_correctness() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slice_correctness",
            replay_ref,
        );
        let src = vec![1u8, 2, 3, 0, 255];
        let c = Gf256(7);
        let mut dst = vec![0u8; 5];
        gf256_addmul_slice(&mut dst, &src, c);
        // Verify element-wise
        for i in 0..5 {
            assert_eq!(dst[i], (Gf256(src[i]) * c).0, "{context}");
        }
    }

    #[test]
    fn addmul_accumulates() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "addmul_accumulates", replay_ref);
        let src = vec![10u8, 20, 30];
        let c = Gf256(5);
        let mut dst = vec![1u8, 2, 3]; // nonzero initial
        let expected: Vec<u8> = dst
            .iter()
            .zip(src.iter())
            .map(|(&d, &s)| d ^ (Gf256(s) * c).0)
            .collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected, "{context}");
    }

    #[test]
    fn addmul_slice_large_inputs() {
        const LEN: usize = 64 + 7;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slice_large_inputs",
            replay_ref,
        );
        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let mut dst = vec![0u8; LEN];
        let expected: Vec<u8> = src.iter().map(|&s| (Gf256(s) * c).0).collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected, "{context}");
    }

    #[test]
    fn mul_slices2_matches_two_independent_mul_slice_calls() {
        const LEN_A: usize = 73;
        const LEN_B: usize = 131;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slices2_matches_two_independent_mul_slice_calls",
            replay_ref,
        );
        let c = Gf256(29);

        let mut a_fused: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut b_fused: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut a_seq = a_fused.clone();
        let mut b_seq = b_fused.clone();

        gf256_mul_slices2(&mut a_fused, &mut b_fused, c);
        gf256_mul_slice(&mut a_seq, c);
        gf256_mul_slice(&mut b_seq, c);

        assert_eq!(a_fused, a_seq, "{context}");
        assert_eq!(b_fused, b_seq, "{context}");
    }

    #[test]
    fn addmul_slices2_matches_two_independent_addmul_slice_calls() {
        const LEN_A: usize = 79;
        const LEN_B: usize = 149;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slices2_matches_two_independent_addmul_slice_calls",
            replay_ref,
        );
        let c = Gf256(71);

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_addmul_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b, c);
        gf256_addmul_slice(&mut expected_left, &src_a, c);
        gf256_addmul_slice(&mut expected_right, &src_b, c);

        assert_eq!(accum_left, expected_left, "{context}");
        assert_eq!(accum_right, expected_right, "{context}");
    }

    #[test]
    fn active_kernel_is_stable_within_process() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "active_kernel_is_stable_within_process",
            replay_ref,
        );
        let first = active_kernel();
        for _ in 0..16 {
            assert_eq!(active_kernel(), first, "{context}");
        }
    }

    // -- SIMD nibble decomposition verification --

    #[cfg(feature = "simd-intrinsics")]
    #[test]
    fn nibble_tables_exhaustive() {
        // Verify nibble decomposition for all 256×256 (c, x) pairs.
        let replay_ref = "replay:rq-u-gf256-nibble-table-v1";
        for c in 0u16..=255 {
            let gc = Gf256(c as u8);
            let nib = NibbleTables::for_scalar(gc);
            for x in 0u16..=255 {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    u64::from(c),
                    &format!("nibble_table,c={c},x={x}"),
                    replay_ref,
                );
                let expected = (gc * Gf256(x as u8)).0;
                let v = Simd::<u8, 16>::splat(x as u8);
                let result = nib.mul16(v);
                assert_eq!(
                    result[0], expected,
                    "nibble decomp mismatch: c={c}, x={x}, got={}, expected={expected}; {context}",
                    result[0],
                );
            }
        }
    }

    #[test]
    fn simd_vs_scalar_mul_equivalence() {
        // Compare SIMD and scalar mul paths at various sizes.
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    seed,
                    &format!("simd_vs_scalar_mul,len={len},c={c_val}"),
                    replay_ref,
                );
                let c = Gf256(c_val);
                let original: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut simd_dst = original.clone();
                let nib = NibbleTables::for_scalar(c);
                mul_with_table_wide(&mut simd_dst, &nib, table);

                let mut scalar_dst = original;
                mul_with_table_scalar(&mut scalar_dst, table);

                assert_eq!(
                    simd_dst, scalar_dst,
                    "mul mismatch: len={len}, c={c_val}; {context}"
                );
            }
        }
    }

    #[test]
    fn simd_vs_scalar_addmul_equivalence() {
        // Compare SIMD and scalar addmul paths at various sizes.
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    seed,
                    &format!("simd_vs_scalar_addmul,len={len},c={c_val}"),
                    replay_ref,
                );
                let c = Gf256(c_val);
                let src: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let dst_init: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(53)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut simd_dst = dst_init.clone();
                let nib = NibbleTables::for_scalar(c);
                addmul_with_table_wide(&mut simd_dst, &src, &nib, table);

                let mut scalar_dst = dst_init;
                addmul_with_table_scalar(&mut scalar_dst, &src, table);

                assert_eq!(
                    simd_dst, scalar_dst,
                    "addmul mismatch: len={len}, c={c_val}; {context}"
                );
            }
        }
    }

    #[test]
    fn dispatched_paths_match_scalar_reference() {
        const LEN: usize = 96;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "dispatched_paths_match_scalar_reference",
            replay_ref,
        );

        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let original: Vec<u8> = (0..LEN).map(|i| (255u16 - i as u16) as u8).collect();
        let c = Gf256(29);

        let mut add_dispatch = original.clone();
        let mut add_scalar = original.clone();
        gf256_add_slice(&mut add_dispatch, &src);
        gf256_add_slice_scalar(&mut add_scalar, &src);
        assert_eq!(add_dispatch, add_scalar, "{context}");

        let mut mul_dispatch = original.clone();
        let mut mul_scalar = original.clone();
        gf256_mul_slice(&mut mul_dispatch, c);
        gf256_mul_slice_scalar(&mut mul_scalar, c);
        assert_eq!(mul_dispatch, mul_scalar, "{context}");

        let mut addmul_dispatch = original.clone();
        let mut addmul_scalar = original;
        gf256_addmul_slice(&mut addmul_dispatch, &src, c);
        gf256_addmul_slice_scalar(&mut addmul_scalar, &src, c);
        assert_eq!(addmul_dispatch, addmul_scalar, "{context}");
    }

    #[test]
    fn dual_policy_ratio_gate_behaves_as_expected() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v1";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_ratio_gate_behaves_as_expected",
            replay_ref,
        );
        assert!(lane_ratio_within(1024, 1024, 1), "{context}");
        assert!(lane_ratio_within(1024, 4096, 4), "{context}");
        assert!(!lane_ratio_within(1024, 4097, 4), "{context}");
        assert!(!lane_ratio_within(0, 1024, 8), "{context}");
    }

    #[test]
    fn dual_policy_window_gate_behaves_as_expected() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v1";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_window_gate_behaves_as_expected",
            replay_ref,
        );
        assert!(in_window(8192, 8192, 16384), "{context}");
        assert!(in_window(12000, 8192, 16384), "{context}");
        assert!(!in_window(4096, 8192, 16384), "{context}");
        assert!(!in_window(20000, 8192, 16384), "{context}");
        assert!(!in_window(12000, 20000, 10000), "{context}");
    }
}
