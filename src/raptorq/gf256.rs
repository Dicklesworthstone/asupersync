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
//!
//! # Profile Packs
//!
//! Dual-lane fused-kernel thresholds are selected from deterministic
//! architecture profile packs:
//! - `scalar-conservative-v1`
//! - `x86-avx2-balanced-v1`
//! - `aarch64-neon-balanced-v1`
//!
//! Runtime can request a specific pack via `ASUPERSYNC_GF256_PROFILE_PACK`.
//! Unsupported requests fail closed to the host default pack with an explicit
//! fallback reason surfaced in [`DualKernelPolicySnapshot`].

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
    __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
    _mm256_loadu_si256, _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16,
    _mm256_storeu_si256, _mm256_xor_si256,
};
#[cfg(all(feature = "simd-intrinsics", target_arch = "x86_64"))]
use core::arch::x86_64::{
    __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
    _mm256_loadu_si256, _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16,
    _mm256_storeu_si256, _mm256_xor_si256,
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
const GF256_PROFILE_PACK_SCHEMA_VERSION: &str = "raptorq-gf256-profile-pack-v1";
const GF256_PROFILE_PACK_MANIFEST_SCHEMA_VERSION: &str = "raptorq-gf256-profile-pack-manifest-v1";
const GF256_PROFILE_PACK_REPLAY_POINTER: &str = "replay:rq-e-gf256-profile-pack-v1";
const GF256_PROFILE_PACK_COMMAND_BUNDLE: &str =
    "rch exec -- cargo bench --bench raptorq_benchmark -- gf256_primitives";
const GF256_PROFILE_TUNING_CORPUS_ID: &str = "raptorq-gf256-profile-corpus-v1";

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

/// Public-facing dual-kernel policy mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualKernelMode {
    /// Heuristic mode using deterministic length/ratio windows.
    Auto,
    /// Force sequential scalarized dual-lane behavior.
    Sequential,
    /// Force fused dual-lane behavior.
    Fused,
}

/// Deterministic dual-kernel dispatch decision for a lane pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualKernelDecision {
    /// Execute via sequential dual-lane operations.
    Sequential,
    /// Execute via fused dual-lane operation.
    Fused,
}

impl DualKernelDecision {
    /// Returns true when the decision selects fused dual-lane execution.
    #[must_use]
    pub const fn is_fused(self) -> bool {
        matches!(self, Self::Fused)
    }
}

/// Snapshot of the active deterministic dual-kernel policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DualKernelPolicySnapshot {
    /// Version marker for the profile-pack snapshot schema.
    pub profile_schema_version: &'static str,
    /// Selected architecture profile pack.
    pub profile_pack: Gf256ProfilePackId,
    /// Architecture class used for deterministic profile selection.
    pub architecture_class: Gf256ArchitectureClass,
    /// Runtime-selected kernel kind.
    pub kernel: Gf256Kernel,
    /// Pinned tuning corpus identifier used by offline profile-pack exploration.
    pub tuning_corpus_id: &'static str,
    /// Selected offline-tuning candidate identifier for active profile pack.
    pub selected_tuning_candidate_id: &'static str,
    /// Deterministically rejected tuning candidate identifiers for active profile pack.
    pub rejected_tuning_candidate_ids: &'static [&'static str],
    /// Fallback reason when requested profile is unavailable on this host.
    pub fallback_reason: Option<Gf256ProfileFallbackReason>,
    /// Deterministically rejected profile-pack candidates for this host class.
    pub rejected_candidates: &'static [Gf256ProfilePackId],
    /// Stable replay pointer for policy-tuning provenance and forensics.
    pub replay_pointer: &'static str,
    /// Repro command bundle for profile-pack validation and rollback rehearsal.
    pub command_bundle: &'static str,
    /// Effective policy mode.
    pub mode: DualKernelMode,
    /// Inclusive minimum total lane bytes for fused dual-mul path in auto mode.
    pub mul_min_total: usize,
    /// Inclusive maximum total lane bytes for fused dual-mul path in auto mode.
    pub mul_max_total: usize,
    /// Inclusive minimum total lane bytes for fused dual-addmul path in auto mode.
    pub addmul_min_total: usize,
    /// Inclusive maximum total lane bytes for fused dual-addmul path in auto mode.
    pub addmul_max_total: usize,
    /// Maximum allowed lane length ratio (`max(len_a,len_b)/min(...)`) in auto mode.
    pub max_lane_ratio: usize,
}

/// Snapshot of deterministic profile-pack manifest plus active policy selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gf256ProfilePackManifestSnapshot {
    /// Version marker for serialized/structured manifest snapshots.
    pub schema_version: &'static str,
    /// Active runtime dual-kernel policy selection.
    pub active_policy: DualKernelPolicySnapshot,
    /// Active profile-pack metadata entry aligned with `active_policy.profile_pack`.
    pub active_profile_metadata: &'static Gf256ProfilePackMetadata,
    /// Active selected tuning candidate metadata, if catalog entry is available.
    pub active_selected_tuning_candidate: Option<&'static Gf256TuningCandidateMetadata>,
    /// Full deterministic profile-pack catalog used by runtime policy.
    pub profile_pack_catalog: &'static [Gf256ProfilePackMetadata],
    /// Full deterministic offline-tuning candidate catalog.
    pub tuning_candidate_catalog: &'static [Gf256TuningCandidateMetadata],
    /// Deterministic build-target metadata for reproducibility and forensics.
    pub environment_metadata: Gf256ProfileEnvironmentMetadata,
}

/// Deterministic environment metadata emitted with profile-pack manifests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gf256ProfileEnvironmentMetadata {
    /// Target architecture identifier from compile-time cfg.
    pub target_arch: &'static str,
    /// Target operating-system identifier from compile-time cfg.
    pub target_os: &'static str,
    /// Target ABI/environment identifier from compile-time cfg.
    pub target_env: &'static str,
    /// Target endianness identifier (`little` or `big`).
    pub target_endian: &'static str,
    /// Target pointer width in bits.
    pub target_pointer_width_bits: usize,
}

/// Architecture class used to map profile-pack defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gf256ArchitectureClass {
    /// No ISA acceleration available; conservative scalar profile.
    GenericScalar,
    /// AVX2-capable x86/x86_64 host class.
    X86Avx2,
    /// NEON-capable aarch64 host class.
    Aarch64Neon,
}

impl Gf256ArchitectureClass {
    /// Stable machine-readable identifier for structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GenericScalar => "generic-scalar",
            Self::X86Avx2 => "x86-avx2",
            Self::Aarch64Neon => "aarch64-neon",
        }
    }
}

/// Deterministic profile-pack identifier for dual-kernel policy windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gf256ProfilePackId {
    /// Conservative scalar profile (fused dual paths effectively disabled).
    ScalarConservativeV1,
    /// Balanced AVX2 profile tuned from benchmark evidence.
    X86Avx2BalancedV1,
    /// Balanced NEON profile tuned from benchmark evidence.
    Aarch64NeonBalancedV1,
}

impl Gf256ProfilePackId {
    /// Stable machine-readable identifier for structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScalarConservativeV1 => "scalar-conservative-v1",
            Self::X86Avx2BalancedV1 => "x86-avx2-balanced-v1",
            Self::Aarch64NeonBalancedV1 => "aarch64-neon-balanced-v1",
        }
    }
}

/// Reason why requested profile-pack selection fell back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gf256ProfileFallbackReason {
    /// Environment requested an unknown profile pack.
    UnknownRequestedProfile,
    /// Requested profile pack is not valid for detected host architecture.
    UnsupportedProfileForHost,
}

impl Gf256ProfileFallbackReason {
    /// Stable machine-readable identifier for structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownRequestedProfile => "unknown-requested-profile",
            Self::UnsupportedProfileForHost => "unsupported-profile-for-host",
        }
    }
}

/// Deterministic metadata for a runtime-eligible profile pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gf256ProfilePackMetadata {
    /// Version marker for serialized/structured profile-pack metadata.
    pub schema_version: &'static str,
    /// Stable profile identifier.
    pub profile_pack: Gf256ProfilePackId,
    /// Host architecture class this pack is tuned for.
    pub architecture_class: Gf256ArchitectureClass,
    /// Pinned corpus identifier used for deterministic offline tuning.
    pub tuning_corpus_id: &'static str,
    /// Selected candidate identifier emitted by offline tuner for this pack.
    pub selected_tuning_candidate_id: &'static str,
    /// Rejected candidate identifiers evaluated during offline tuning for this pack.
    pub rejected_tuning_candidate_ids: &'static [&'static str],
    /// Inclusive minimum total lane bytes for fused dual-mul path in auto mode.
    pub mul_min_total: usize,
    /// Inclusive maximum total lane bytes for fused dual-mul path in auto mode.
    pub mul_max_total: usize,
    /// Inclusive minimum total lane bytes for fused dual-addmul path in auto mode.
    pub addmul_min_total: usize,
    /// Inclusive maximum total lane bytes for fused dual-addmul path in auto mode.
    pub addmul_max_total: usize,
    /// Maximum allowed lane length ratio (`max(len_a,len_b)/min(...)`) in auto mode.
    pub max_lane_ratio: usize,
    /// Stable replay pointer used for traceability and deterministic replays.
    pub replay_pointer: &'static str,
    /// Repro command bundle for validating this profile pack.
    pub command_bundle: &'static str,
}

/// Deterministic metadata for a single offline tuning candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gf256TuningCandidateMetadata {
    /// Stable candidate identifier.
    pub candidate_id: &'static str,
    /// Target architecture class for this candidate.
    pub architecture_class: Gf256ArchitectureClass,
    /// Target profile pack for this candidate.
    pub profile_pack: Gf256ProfilePackId,
    /// Tile size explored by this candidate.
    pub tile_bytes: usize,
    /// Unroll factor explored by this candidate.
    pub unroll: usize,
    /// Prefetch distance explored by this candidate.
    pub prefetch_distance: usize,
    /// Fusion shape explored by this candidate.
    pub fusion_shape: &'static str,
}

const SCALAR_SELECTED_TUNING_CANDIDATE: &str = "scalar-t16-u1-pf0-fused-off-v1";
const X86_SELECTED_TUNING_CANDIDATE: &str = "x86-avx2-t32-u2-pf64-fused-balanced-v1";
const AARCH64_SELECTED_TUNING_CANDIDATE: &str = "aarch64-neon-t32-u2-pf32-fused-balanced-v1";

const SCALAR_REJECTED_TUNING_CANDIDATES: &[&str] = &["scalar-t8-u1-pf0-fused-off-v1"];
const X86_REJECTED_TUNING_CANDIDATES: &[&str] = &[
    "x86-avx2-t16-u2-pf32-fused-balanced-v1",
    "x86-avx2-t32-u4-pf64-split-balanced-v1",
];
const AARCH64_REJECTED_TUNING_CANDIDATES: &[&str] = &[
    "aarch64-neon-t16-u2-pf16-fused-balanced-v1",
    "aarch64-neon-t32-u4-pf32-split-balanced-v1",
];

const REJECTED_PROFILE_GENERIC_SCALAR: &[Gf256ProfilePackId] = &[
    Gf256ProfilePackId::X86Avx2BalancedV1,
    Gf256ProfilePackId::Aarch64NeonBalancedV1,
];
const REJECTED_PROFILE_X86_AVX2: &[Gf256ProfilePackId] =
    &[Gf256ProfilePackId::Aarch64NeonBalancedV1];
const REJECTED_PROFILE_AARCH64_NEON: &[Gf256ProfilePackId] =
    &[Gf256ProfilePackId::X86Avx2BalancedV1];

const GF256_PROFILE_PACK_CATALOG: [Gf256ProfilePackMetadata; 3] = [
    Gf256ProfilePackMetadata {
        schema_version: GF256_PROFILE_PACK_SCHEMA_VERSION,
        profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
        architecture_class: Gf256ArchitectureClass::GenericScalar,
        tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
        selected_tuning_candidate_id: SCALAR_SELECTED_TUNING_CANDIDATE,
        rejected_tuning_candidate_ids: SCALAR_REJECTED_TUNING_CANDIDATES,
        mul_min_total: usize::MAX,
        mul_max_total: 0,
        addmul_min_total: usize::MAX,
        addmul_max_total: 0,
        max_lane_ratio: 1,
        replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
        command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
    },
    Gf256ProfilePackMetadata {
        schema_version: GF256_PROFILE_PACK_SCHEMA_VERSION,
        profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
        architecture_class: Gf256ArchitectureClass::X86Avx2,
        tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
        selected_tuning_candidate_id: X86_SELECTED_TUNING_CANDIDATE,
        rejected_tuning_candidate_ids: X86_REJECTED_TUNING_CANDIDATES,
        // Conservative tuned windows from Track-E benchmark evidence.
        mul_min_total: 8 * 1024,
        mul_max_total: 24 * 1024,
        addmul_min_total: 8 * 1024,
        addmul_max_total: 16 * 1024,
        max_lane_ratio: 8,
        replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
        command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
    },
    Gf256ProfilePackMetadata {
        schema_version: GF256_PROFILE_PACK_SCHEMA_VERSION,
        profile_pack: Gf256ProfilePackId::Aarch64NeonBalancedV1,
        architecture_class: Gf256ArchitectureClass::Aarch64Neon,
        tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
        selected_tuning_candidate_id: AARCH64_SELECTED_TUNING_CANDIDATE,
        rejected_tuning_candidate_ids: AARCH64_REJECTED_TUNING_CANDIDATES,
        // Conservative tuned windows from Track-E benchmark evidence.
        mul_min_total: 8 * 1024,
        mul_max_total: 24 * 1024,
        addmul_min_total: 8 * 1024,
        addmul_max_total: 16 * 1024,
        max_lane_ratio: 8,
        replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
        command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
    },
];

/// Returns deterministic profile-pack metadata entries used for runtime dispatch policy.
#[must_use]
pub const fn gf256_profile_pack_catalog() -> &'static [Gf256ProfilePackMetadata] {
    &GF256_PROFILE_PACK_CATALOG
}

const GF256_TUNING_CANDIDATE_CATALOG: [Gf256TuningCandidateMetadata; 8] = [
    Gf256TuningCandidateMetadata {
        candidate_id: SCALAR_SELECTED_TUNING_CANDIDATE,
        architecture_class: Gf256ArchitectureClass::GenericScalar,
        profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
        tile_bytes: 16,
        unroll: 1,
        prefetch_distance: 0,
        fusion_shape: "fused-off",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: SCALAR_REJECTED_TUNING_CANDIDATES[0],
        architecture_class: Gf256ArchitectureClass::GenericScalar,
        profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
        tile_bytes: 8,
        unroll: 1,
        prefetch_distance: 0,
        fusion_shape: "fused-off",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: X86_SELECTED_TUNING_CANDIDATE,
        architecture_class: Gf256ArchitectureClass::X86Avx2,
        profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
        tile_bytes: 32,
        unroll: 2,
        prefetch_distance: 64,
        fusion_shape: "fused-balanced",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: X86_REJECTED_TUNING_CANDIDATES[0],
        architecture_class: Gf256ArchitectureClass::X86Avx2,
        profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
        tile_bytes: 16,
        unroll: 2,
        prefetch_distance: 32,
        fusion_shape: "fused-balanced",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: X86_REJECTED_TUNING_CANDIDATES[1],
        architecture_class: Gf256ArchitectureClass::X86Avx2,
        profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
        tile_bytes: 32,
        unroll: 4,
        prefetch_distance: 64,
        fusion_shape: "split-balanced",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: AARCH64_SELECTED_TUNING_CANDIDATE,
        architecture_class: Gf256ArchitectureClass::Aarch64Neon,
        profile_pack: Gf256ProfilePackId::Aarch64NeonBalancedV1,
        tile_bytes: 32,
        unroll: 2,
        prefetch_distance: 32,
        fusion_shape: "fused-balanced",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: AARCH64_REJECTED_TUNING_CANDIDATES[0],
        architecture_class: Gf256ArchitectureClass::Aarch64Neon,
        profile_pack: Gf256ProfilePackId::Aarch64NeonBalancedV1,
        tile_bytes: 16,
        unroll: 2,
        prefetch_distance: 16,
        fusion_shape: "fused-balanced",
    },
    Gf256TuningCandidateMetadata {
        candidate_id: AARCH64_REJECTED_TUNING_CANDIDATES[1],
        architecture_class: Gf256ArchitectureClass::Aarch64Neon,
        profile_pack: Gf256ProfilePackId::Aarch64NeonBalancedV1,
        tile_bytes: 32,
        unroll: 4,
        prefetch_distance: 32,
        fusion_shape: "split-balanced",
    },
];

/// Returns deterministic candidate catalog explored during offline profile tuning.
#[must_use]
pub const fn gf256_tuning_candidate_catalog() -> &'static [Gf256TuningCandidateMetadata] {
    &GF256_TUNING_CANDIDATE_CATALOG
}

fn tuning_candidate_metadata(candidate_id: &str) -> Option<&'static Gf256TuningCandidateMetadata> {
    GF256_TUNING_CANDIDATE_CATALOG
        .iter()
        .find(|metadata| metadata.candidate_id == candidate_id)
}

fn target_env_name() -> &'static str {
    match option_env!("CARGO_CFG_TARGET_ENV") {
        Some(env) if !env.is_empty() => env,
        _ => "unknown",
    }
}

fn target_endian_name() -> &'static str {
    match option_env!("CARGO_CFG_TARGET_ENDIAN") {
        Some("little") => "little",
        Some("big") => "big",
        Some(other) => other,
        None => {
            if cfg!(target_endian = "little") {
                "little"
            } else {
                "big"
            }
        }
    }
}

fn target_pointer_width_bits() -> usize {
    match option_env!("CARGO_CFG_TARGET_POINTER_WIDTH") {
        Some("16") => 16,
        Some("32") => 32,
        Some("64") => 64,
        Some("128") => 128,
        _ => usize::BITS as usize,
    }
}

fn profile_environment_metadata() -> Gf256ProfileEnvironmentMetadata {
    Gf256ProfileEnvironmentMetadata {
        target_arch: std::env::consts::ARCH,
        target_os: std::env::consts::OS,
        target_env: target_env_name(),
        target_endian: target_endian_name(),
        target_pointer_width_bits: target_pointer_width_bits(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfilePackRequest {
    Auto,
    ScalarConservativeV1,
    X86Avx2BalancedV1,
    Aarch64NeonBalancedV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProfilePackSelection {
    profile_pack: Gf256ProfilePackId,
    architecture_class: Gf256ArchitectureClass,
    fallback_reason: Option<Gf256ProfileFallbackReason>,
    rejected_candidates: &'static [Gf256ProfilePackId],
}

#[derive(Clone, Copy, Debug)]
struct DualKernelPolicy {
    profile_pack: Gf256ProfilePackId,
    architecture_class: Gf256ArchitectureClass,
    tuning_corpus_id: &'static str,
    selected_tuning_candidate_id: &'static str,
    rejected_tuning_candidate_ids: &'static [&'static str],
    fallback_reason: Option<Gf256ProfileFallbackReason>,
    rejected_candidates: &'static [Gf256ProfilePackId],
    replay_pointer: &'static str,
    command_bundle: &'static str,
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

fn parse_profile_pack_request(raw: &str) -> Option<ProfilePackRequest> {
    match raw {
        "auto" => Some(ProfilePackRequest::Auto),
        "scalar-conservative-v1" | "scalar" => Some(ProfilePackRequest::ScalarConservativeV1),
        "x86-avx2-balanced-v1" | "x86-avx2" => Some(ProfilePackRequest::X86Avx2BalancedV1),
        "aarch64-neon-balanced-v1" | "aarch64-neon" => {
            Some(ProfilePackRequest::Aarch64NeonBalancedV1)
        }
        _ => None,
    }
}

fn architecture_class_for_kernel(kernel: Gf256Kernel) -> Gf256ArchitectureClass {
    match kernel {
        Gf256Kernel::Scalar => Gf256ArchitectureClass::GenericScalar,
        #[cfg(all(
            feature = "simd-intrinsics",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        Gf256Kernel::X86Avx2 => Gf256ArchitectureClass::X86Avx2,
        #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
        Gf256Kernel::Aarch64Neon => Gf256ArchitectureClass::Aarch64Neon,
    }
}

fn default_profile_pack_for_arch(class: Gf256ArchitectureClass) -> Gf256ProfilePackId {
    match class {
        Gf256ArchitectureClass::GenericScalar => Gf256ProfilePackId::ScalarConservativeV1,
        Gf256ArchitectureClass::X86Avx2 => Gf256ProfilePackId::X86Avx2BalancedV1,
        Gf256ArchitectureClass::Aarch64Neon => Gf256ProfilePackId::Aarch64NeonBalancedV1,
    }
}

const fn rejected_profile_candidates_for_arch(
    class: Gf256ArchitectureClass,
) -> &'static [Gf256ProfilePackId] {
    match class {
        Gf256ArchitectureClass::GenericScalar => REJECTED_PROFILE_GENERIC_SCALAR,
        Gf256ArchitectureClass::X86Avx2 => REJECTED_PROFILE_X86_AVX2,
        Gf256ArchitectureClass::Aarch64Neon => REJECTED_PROFILE_AARCH64_NEON,
    }
}

fn profile_pack_metadata(profile_pack: Gf256ProfilePackId) -> &'static Gf256ProfilePackMetadata {
    GF256_PROFILE_PACK_CATALOG
        .iter()
        .find(|metadata| metadata.profile_pack == profile_pack)
        .unwrap_or(&GF256_PROFILE_PACK_CATALOG[0])
}

fn select_profile_pack(
    kernel: Gf256Kernel,
    requested: Option<ProfilePackRequest>,
) -> ProfilePackSelection {
    let architecture_class = architecture_class_for_kernel(kernel);
    let default_pack = default_profile_pack_for_arch(architecture_class);
    let mut fallback_reason = None;
    let rejected_candidates = rejected_profile_candidates_for_arch(architecture_class);

    let profile_pack = match requested.unwrap_or(ProfilePackRequest::Auto) {
        ProfilePackRequest::Auto => default_pack,
        ProfilePackRequest::ScalarConservativeV1 => Gf256ProfilePackId::ScalarConservativeV1,
        ProfilePackRequest::X86Avx2BalancedV1 => {
            if matches!(architecture_class, Gf256ArchitectureClass::X86Avx2) {
                Gf256ProfilePackId::X86Avx2BalancedV1
            } else {
                fallback_reason = Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost);
                default_pack
            }
        }
        ProfilePackRequest::Aarch64NeonBalancedV1 => {
            if matches!(architecture_class, Gf256ArchitectureClass::Aarch64Neon) {
                Gf256ProfilePackId::Aarch64NeonBalancedV1
            } else {
                fallback_reason = Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost);
                default_pack
            }
        }
    };

    ProfilePackSelection {
        profile_pack,
        architecture_class,
        fallback_reason,
        rejected_candidates,
    }
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

    let requested_profile_raw = std::env::var("ASUPERSYNC_GF256_PROFILE_PACK").ok();
    let requested_profile = requested_profile_raw
        .as_deref()
        .and_then(parse_profile_pack_request);
    let parse_fallback = requested_profile_raw.as_deref().and_then(|raw| {
        if parse_profile_pack_request(raw).is_some() {
            None
        } else {
            Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
        }
    });

    let selection = select_profile_pack(dispatch().kind, requested_profile);
    let metadata = profile_pack_metadata(selection.profile_pack);

    let mut policy = DualKernelPolicy {
        profile_pack: metadata.profile_pack,
        architecture_class: selection.architecture_class,
        tuning_corpus_id: metadata.tuning_corpus_id,
        selected_tuning_candidate_id: metadata.selected_tuning_candidate_id,
        rejected_tuning_candidate_ids: metadata.rejected_tuning_candidate_ids,
        fallback_reason: selection.fallback_reason.or(parse_fallback),
        rejected_candidates: selection.rejected_candidates,
        replay_pointer: metadata.replay_pointer,
        command_bundle: metadata.command_bundle,
        mode,
        mul_min_total: metadata.mul_min_total,
        mul_max_total: metadata.mul_max_total,
        addmul_min_total: metadata.addmul_min_total,
        addmul_max_total: metadata.addmul_max_total,
        max_lane_ratio: metadata.max_lane_ratio,
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

const fn to_public_mode(mode: DualKernelOverride) -> DualKernelMode {
    match mode {
        DualKernelOverride::Auto => DualKernelMode::Auto,
        DualKernelOverride::ForceSequential => DualKernelMode::Sequential,
        DualKernelOverride::ForceFused => DualKernelMode::Fused,
    }
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
fn dual_mul_decision_with_policy(
    policy: &DualKernelPolicy,
    len_a: usize,
    len_b: usize,
) -> DualKernelDecision {
    match policy.mode {
        DualKernelOverride::ForceSequential => DualKernelDecision::Sequential,
        DualKernelOverride::ForceFused => DualKernelDecision::Fused,
        DualKernelOverride::Auto => {
            let total = len_a.saturating_add(len_b);
            if in_window(total, policy.mul_min_total, policy.mul_max_total)
                && lane_ratio_within(len_a, len_b, policy.max_lane_ratio)
            {
                DualKernelDecision::Fused
            } else {
                DualKernelDecision::Sequential
            }
        }
    }
}

#[inline]
fn should_use_dual_mul_fused(len_a: usize, len_b: usize) -> bool {
    dual_mul_kernel_decision(len_a, len_b).is_fused()
}

#[inline]
fn dual_addmul_decision_with_policy(
    policy: &DualKernelPolicy,
    len_a: usize,
    len_b: usize,
) -> DualKernelDecision {
    match policy.mode {
        DualKernelOverride::ForceSequential => DualKernelDecision::Sequential,
        DualKernelOverride::ForceFused => DualKernelDecision::Fused,
        DualKernelOverride::Auto => {
            let total = len_a.saturating_add(len_b);
            if in_window(total, policy.addmul_min_total, policy.addmul_max_total)
                && lane_ratio_within(len_a, len_b, policy.max_lane_ratio)
            {
                DualKernelDecision::Fused
            } else {
                DualKernelDecision::Sequential
            }
        }
    }
}

/// Returns a deterministic snapshot of the active dual-lane fused-kernel policy.
#[must_use]
pub fn dual_kernel_policy_snapshot() -> DualKernelPolicySnapshot {
    let policy = dual_policy();
    DualKernelPolicySnapshot {
        profile_schema_version: GF256_PROFILE_PACK_SCHEMA_VERSION,
        profile_pack: policy.profile_pack,
        architecture_class: policy.architecture_class,
        kernel: dispatch().kind,
        tuning_corpus_id: policy.tuning_corpus_id,
        selected_tuning_candidate_id: policy.selected_tuning_candidate_id,
        rejected_tuning_candidate_ids: policy.rejected_tuning_candidate_ids,
        fallback_reason: policy.fallback_reason,
        rejected_candidates: policy.rejected_candidates,
        replay_pointer: policy.replay_pointer,
        command_bundle: policy.command_bundle,
        mode: to_public_mode(policy.mode),
        mul_min_total: policy.mul_min_total,
        mul_max_total: policy.mul_max_total,
        addmul_min_total: policy.addmul_min_total,
        addmul_max_total: policy.addmul_max_total,
        max_lane_ratio: policy.max_lane_ratio,
    }
}

/// Returns a deterministic snapshot of active profile-pack manifest and policy selection.
#[must_use]
pub fn gf256_profile_pack_manifest_snapshot() -> Gf256ProfilePackManifestSnapshot {
    let active_policy = dual_kernel_policy_snapshot();
    Gf256ProfilePackManifestSnapshot {
        schema_version: GF256_PROFILE_PACK_MANIFEST_SCHEMA_VERSION,
        active_profile_metadata: profile_pack_metadata(active_policy.profile_pack),
        active_selected_tuning_candidate: tuning_candidate_metadata(
            active_policy.selected_tuning_candidate_id,
        ),
        profile_pack_catalog: gf256_profile_pack_catalog(),
        tuning_candidate_catalog: gf256_tuning_candidate_catalog(),
        environment_metadata: profile_environment_metadata(),
        active_policy,
    }
}

/// Returns the deterministic dual-lane decision for dual-mul path lengths.
#[must_use]
pub fn dual_mul_kernel_decision(len_a: usize, len_b: usize) -> DualKernelDecision {
    dual_mul_decision_with_policy(dual_policy(), len_a, len_b)
}

/// Returns the deterministic dual-lane decision for dual-addmul path lengths.
#[must_use]
pub fn dual_addmul_kernel_decision(len_a: usize, len_b: usize) -> DualKernelDecision {
    dual_addmul_decision_with_policy(dual_policy(), len_a, len_b)
}

#[inline]
fn should_use_dual_addmul_fused(len_a: usize, len_b: usize) -> bool {
    dual_addmul_kernel_decision(len_a, len_b).is_fused()
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

/// XOR two independent source/destination pairs in one dispatch lookup.
///
/// Applies:
/// - `dst_a[i] ^= src_a[i]`
/// - `dst_b[i] ^= src_b[i]`
///
/// # Panics
///
/// Panics if `dst_a.len() != src_a.len()` or `dst_b.len() != src_b.len()`.
#[inline]
pub fn gf256_add_slices2(dst_a: &mut [u8], src_a: &[u8], dst_b: &mut [u8], src_b: &[u8]) {
    assert_eq!(dst_a.len(), src_a.len(), "slice length mismatch");
    assert_eq!(dst_b.len(), src_b.len(), "slice length mismatch");
    let add_slice = dispatch().add_slice;
    add_slice(dst_a, src_a);
    add_slice(dst_b, src_b);
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

/// Minimum slice length to amortize SIMD nibble-table setup in mul paths.
const MUL_TABLE_THRESHOLD: usize = 64;
/// Minimum slice length to amortize SIMD nibble-table setup in addmul paths.
const ADDMUL_TABLE_THRESHOLD: usize = 64;

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
    let dispatch = dispatch();
    if !should_use_dual_mul_fused(dst_a.len(), dst_b.len()) {
        (dispatch.mul_slice)(dst_a, c);
        (dispatch.mul_slice)(dst_b, c);
        return;
    }

    let table = mul_table_for(c);
    #[cfg(feature = "simd-intrinsics")]
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    if matches!(dispatch.kind, Gf256Kernel::X86Avx2) {
        // SAFETY: `dispatch()` only selects X86Avx2 when runtime feature
        // detection succeeds; pointers remain within provided slice bounds.
        unsafe {
            gf256_mul_slice_x86_avx2_impl_tables(dst_a, low_tbl_arr, high_tbl_arr, table);
            gf256_mul_slice_x86_avx2_impl_tables(dst_b, low_tbl_arr, high_tbl_arr, table);
        }
        return;
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    if matches!(dispatch.kind, Gf256Kernel::Aarch64Neon) {
        // SAFETY: `dispatch()` only selects Aarch64Neon when runtime feature
        // detection succeeds; pointers remain within provided slice bounds.
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
    let table = mul_table_for(c);
    if dst.len() >= MUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        mul_with_table_wide(dst, &nib, table);
    } else {
        mul_with_table_scalar(dst, table);
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
    let mut chunks = dst.chunks_exact_mut(8);
    for chunk in chunks.by_ref() {
        let mapped = [
            table[chunk[0] as usize],
            table[chunk[1] as usize],
            table[chunk[2] as usize],
            table[chunk[3] as usize],
            table[chunk[4] as usize],
            table[chunk[5] as usize],
            table[chunk[6] as usize],
            table[chunk[7] as usize],
        ];
        chunk.copy_from_slice(&mapped);
    }
    for d in chunks.into_remainder() {
        *d = table[*d as usize];
    }
}

/// Table-driven scalar inner loop for `gf256_mul_slice`.
///
/// Used by the production scalar path for short slices and by tests as the
/// scalar reference against the wide table kernel.
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
    let mut d_chunks = dst.chunks_exact_mut(8);
    let mut s_chunks = src.chunks_exact(8);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let d_word = u64::from_ne_bytes(d_chunk[..].try_into().unwrap());
        let s_word = u64::from_ne_bytes([
            table[s_chunk[0] as usize],
            table[s_chunk[1] as usize],
            table[s_chunk[2] as usize],
            table[s_chunk[3] as usize],
            table[s_chunk[4] as usize],
            table[s_chunk[5] as usize],
            table[s_chunk[6] as usize],
            table[s_chunk[7] as usize],
        ]);
        d_chunk.copy_from_slice(&(d_word ^ s_word).to_ne_bytes());
    }
    for (d, s) in d_chunks
        .into_remainder()
        .iter_mut()
        .zip(s_chunks.remainder())
    {
        *d ^= table[*s as usize];
    }
}

/// Table-driven scalar inner loop for `gf256_addmul_slice`.
///
/// Used by the production scalar path for short slices and by tests as the
/// scalar reference against the wide table kernel.
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
/// For slices >= `ADDMUL_TABLE_THRESHOLD` bytes the hot path uses wide table
/// kernels. Smaller slices use scalar table lookups.
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
    let dispatch = dispatch();
    if c == Gf256::ONE {
        (dispatch.add_slice)(dst_a, src_a);
        (dispatch.add_slice)(dst_b, src_b);
        return;
    }
    if !should_use_dual_addmul_fused(dst_a.len(), dst_b.len()) {
        (dispatch.addmul_slice)(dst_a, src_a, c);
        (dispatch.addmul_slice)(dst_b, src_b, c);
        return;
    }

    let table = mul_table_for(c);
    #[cfg(feature = "simd-intrinsics")]
    let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    if matches!(dispatch.kind, Gf256Kernel::X86Avx2) {
        // SAFETY: `dispatch()` only selects X86Avx2 when runtime feature
        // detection succeeds; both pairs are length-checked.
        unsafe {
            gf256_addmul_slice_x86_avx2_impl_tables(dst_a, src_a, low_tbl_arr, high_tbl_arr, table);
            gf256_addmul_slice_x86_avx2_impl_tables(dst_b, src_b, low_tbl_arr, high_tbl_arr, table);
        }
        return;
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    if matches!(dispatch.kind, Gf256Kernel::Aarch64Neon) {
        // SAFETY: `dispatch()` only selects Aarch64Neon when runtime feature
        // detection succeeds; both pairs are length-checked.
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
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice_scalar(dst, src);
        return;
    }
    let table = mul_table_for(c);
    if src.len() >= ADDMUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        addmul_with_table_wide(dst, src, &nib, table);
        return;
    }
    addmul_with_table_scalar(dst, src, table);
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
    fn add_slices2_matches_two_independent_add_slice_calls() {
        const LEN_A: usize = 83;
        const LEN_B: usize = 141;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "add_slices2_matches_two_independent_add_slice_calls",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_add_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b);
        gf256_add_slice(&mut expected_left, &src_a);
        gf256_add_slice(&mut expected_right, &src_b);

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

    #[test]
    fn dual_policy_snapshot_is_consistent_with_decision_helpers() {
        let snapshot = dual_kernel_policy_snapshot();
        let mode = snapshot.mode;
        assert!(
            matches!(
                mode,
                DualKernelMode::Auto | DualKernelMode::Sequential | DualKernelMode::Fused
            ),
            "snapshot mode should be a valid public dual-kernel mode",
        );

        for (len_a, len_b) in [(0, 0), (64, 64), (512, 4096), (4096, 4096), (16384, 2048)] {
            let mul_decision = dual_mul_kernel_decision(len_a, len_b);
            let addmul_decision = dual_addmul_kernel_decision(len_a, len_b);
            assert_eq!(
                mul_decision.is_fused(),
                should_use_dual_mul_fused(len_a, len_b),
                "public mul decision helper should match internal gate",
            );
            assert_eq!(
                addmul_decision.is_fused(),
                should_use_dual_addmul_fused(len_a, len_b),
                "public addmul decision helper should match internal gate",
            );
        }
    }

    fn expected_decision_from_snapshot(
        mode: DualKernelMode,
        min_total: usize,
        max_total: usize,
        max_lane_ratio: usize,
        len_a: usize,
        len_b: usize,
    ) -> bool {
        match mode {
            DualKernelMode::Sequential => false,
            DualKernelMode::Fused => true,
            DualKernelMode::Auto => {
                let total = len_a.saturating_add(len_b);
                in_window(total, min_total, max_total)
                    && lane_ratio_within(len_a, len_b, max_lane_ratio)
            }
        }
    }

    #[test]
    fn dual_policy_decision_matrix_matches_snapshot_contract() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v2";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_decision_matrix_matches_snapshot_contract",
            replay_ref,
        );
        let snapshot = dual_kernel_policy_snapshot();

        // Mirrors the benchmark policy-probe matrix used in benches/raptorq_benchmark.rs.
        let scenarios = [
            ("RQ-E-GF256-DUAL-001", 4096usize, 4096usize),
            ("RQ-E-GF256-DUAL-002", 7168usize, 1024usize),
            ("RQ-E-GF256-DUAL-003", 7424usize, 768usize),
            ("RQ-E-GF256-DUAL-004", 12288usize, 12288usize),
            ("RQ-E-GF256-DUAL-005", 15360usize, 15360usize),
            ("RQ-E-GF256-DUAL-006", 16384usize, 16384usize),
        ];

        for (scenario_id, len_a, len_b) in scenarios {
            let expected_mul = expected_decision_from_snapshot(
                snapshot.mode,
                snapshot.mul_min_total,
                snapshot.mul_max_total,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            let expected_addmul = expected_decision_from_snapshot(
                snapshot.mode,
                snapshot.addmul_min_total,
                snapshot.addmul_max_total,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            let mul_actual = dual_mul_kernel_decision(len_a, len_b).is_fused();
            let addmul_actual = dual_addmul_kernel_decision(len_a, len_b).is_fused();
            assert_eq!(
                mul_actual, expected_mul,
                "{context}; scenario_id={scenario_id}; mul mismatch for lane_a={len_a}, lane_b={len_b}"
            );
            assert_eq!(
                addmul_actual, expected_addmul,
                "{context}; scenario_id={scenario_id}; addmul mismatch for lane_a={len_a}, lane_b={len_b}"
            );
        }
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn gf256_debug_display_format() {
        let elem = Gf256(42);
        assert_eq!(format!("{elem:?}"), "GF(42)");
        assert_eq!(format!("{elem}"), "42");
        let zero = Gf256::ZERO;
        assert_eq!(format!("{zero:?}"), "GF(0)");
        assert_eq!(format!("{zero}"), "0");
    }

    #[test]
    fn gf256_default_is_zero() {
        let def = Gf256::default();
        assert_eq!(def, Gf256::ZERO);
        assert_eq!(def.0, 0);
    }

    #[test]
    fn gf256_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = Gf256(100);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Gf256(101));

        let mut set = HashSet::new();
        set.insert(Gf256(1));
        set.insert(Gf256(2));
        set.insert(Gf256(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn gf256_kernel_debug_clone_copy_eq() {
        let k = Gf256Kernel::Scalar;
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
        assert_eq!(copied, Gf256Kernel::Scalar);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Scalar"));
    }

    #[test]
    fn dual_kernel_mode_debug_clone_copy_eq() {
        for mode in [
            DualKernelMode::Auto,
            DualKernelMode::Sequential,
            DualKernelMode::Fused,
        ] {
            let copied = mode;
            let cloned = mode;
            assert_eq!(copied, cloned);
            let dbg = format!("{mode:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(DualKernelMode::Auto, DualKernelMode::Sequential);
        assert_ne!(DualKernelMode::Sequential, DualKernelMode::Fused);
    }

    #[test]
    fn dual_kernel_decision_debug_clone_copy_eq() {
        let seq = DualKernelDecision::Sequential;
        let fused = DualKernelDecision::Fused;
        assert_ne!(seq, fused);
        assert_eq!(seq, DualKernelDecision::Sequential);
        assert!(fused.is_fused());
        assert!(!seq.is_fused());
        let dbg = format!("{seq:?}");
        assert!(dbg.contains("Sequential"));
    }

    #[test]
    fn dual_kernel_policy_snapshot_debug_clone_copy_eq() {
        let snap = DualKernelPolicySnapshot {
            profile_schema_version: GF256_PROFILE_PACK_SCHEMA_VERSION,
            profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
            architecture_class: Gf256ArchitectureClass::GenericScalar,
            kernel: Gf256Kernel::Scalar,
            tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
            selected_tuning_candidate_id: SCALAR_SELECTED_TUNING_CANDIDATE,
            rejected_tuning_candidate_ids: SCALAR_REJECTED_TUNING_CANDIDATES,
            fallback_reason: None,
            rejected_candidates: &[],
            replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
            command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
            mode: DualKernelMode::Auto,
            mul_min_total: 8192,
            mul_max_total: 24576,
            addmul_min_total: 8192,
            addmul_max_total: 16384,
            max_lane_ratio: 8,
        };
        let copied = snap;
        let cloned = snap;
        assert_eq!(copied, cloned);
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("DualKernelPolicySnapshot"));
    }

    #[test]
    fn profile_pack_request_parser_handles_known_and_unknown_values() {
        assert_eq!(
            parse_profile_pack_request("auto"),
            Some(ProfilePackRequest::Auto)
        );
        assert_eq!(
            parse_profile_pack_request("scalar-conservative-v1"),
            Some(ProfilePackRequest::ScalarConservativeV1)
        );
        assert_eq!(
            parse_profile_pack_request("x86-avx2-balanced-v1"),
            Some(ProfilePackRequest::X86Avx2BalancedV1)
        );
        assert_eq!(
            parse_profile_pack_request("aarch64-neon-balanced-v1"),
            Some(ProfilePackRequest::Aarch64NeonBalancedV1)
        );
        assert_eq!(parse_profile_pack_request("unknown-pack"), None);
    }

    #[test]
    fn profile_pack_catalog_is_deterministic_and_versioned() {
        let catalog = gf256_profile_pack_catalog();
        assert_eq!(catalog.len(), 3);
        assert_eq!(
            catalog[0].profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            catalog[1].profile_pack,
            Gf256ProfilePackId::X86Avx2BalancedV1
        );
        assert_eq!(
            catalog[2].profile_pack,
            Gf256ProfilePackId::Aarch64NeonBalancedV1
        );
        for metadata in catalog {
            assert_eq!(metadata.schema_version, GF256_PROFILE_PACK_SCHEMA_VERSION);
            assert_eq!(metadata.replay_pointer, GF256_PROFILE_PACK_REPLAY_POINTER);
            assert_eq!(metadata.tuning_corpus_id, GF256_PROFILE_TUNING_CORPUS_ID);
            assert!(!metadata.selected_tuning_candidate_id.is_empty());
            for rejected_id in metadata.rejected_tuning_candidate_ids {
                assert_ne!(metadata.selected_tuning_candidate_id, *rejected_id);
                assert!(!rejected_id.is_empty());
            }
            assert!(!metadata.command_bundle.is_empty());
            assert!(metadata.command_bundle.contains("rch exec --"));
        }
    }

    #[test]
    fn tuning_candidate_catalog_is_deterministic_and_profile_aligned() {
        let catalog = gf256_tuning_candidate_catalog();
        assert_eq!(catalog.len(), 8);
        for candidate in catalog {
            assert!(!candidate.candidate_id.is_empty());
            assert!(candidate.tile_bytes > 0);
            assert!(candidate.unroll > 0);
            assert!(
                gf256_profile_pack_catalog()
                    .iter()
                    .any(|pack| pack.profile_pack == candidate.profile_pack),
                "candidate {} references unknown profile pack",
                candidate.candidate_id
            );
        }
    }

    #[test]
    fn profile_pack_selection_exposes_arch_rejected_candidates() {
        let selected = select_profile_pack(Gf256Kernel::Scalar, None);
        assert_eq!(
            selected.rejected_candidates,
            REJECTED_PROFILE_GENERIC_SCALAR
        );
    }

    #[test]
    fn profile_pack_selection_falls_back_when_host_does_not_support_request() {
        let selected = select_profile_pack(
            Gf256Kernel::Scalar,
            Some(ProfilePackRequest::X86Avx2BalancedV1),
        );
        assert_eq!(
            selected.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            selected.architecture_class,
            Gf256ArchitectureClass::GenericScalar
        );
        assert_eq!(
            selected.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
        );
        assert_eq!(
            selected.rejected_candidates,
            REJECTED_PROFILE_GENERIC_SCALAR
        );
    }

    #[test]
    fn dual_policy_snapshot_exposes_profile_pack_metadata() {
        let snapshot = dual_kernel_policy_snapshot();
        assert_eq!(
            snapshot.profile_schema_version,
            GF256_PROFILE_PACK_SCHEMA_VERSION
        );
        assert_eq!(
            snapshot.architecture_class,
            architecture_class_for_kernel(snapshot.kernel)
        );
        assert_eq!(snapshot.tuning_corpus_id, GF256_PROFILE_TUNING_CORPUS_ID);
        assert!(!snapshot.selected_tuning_candidate_id.is_empty());
        assert!(!snapshot.command_bundle.is_empty());
        assert_eq!(snapshot.replay_pointer, GF256_PROFILE_PACK_REPLAY_POINTER);
        assert!(!snapshot.profile_pack.as_str().is_empty());
        for rejected_id in snapshot.rejected_tuning_candidate_ids {
            assert_ne!(snapshot.selected_tuning_candidate_id, *rejected_id);
            assert!(!rejected_id.is_empty());
        }
        for rejected in snapshot.rejected_candidates {
            assert_ne!(*rejected, snapshot.profile_pack);
            assert!(!rejected.as_str().is_empty());
        }
        if let Some(reason) = snapshot.fallback_reason {
            assert!(!reason.as_str().is_empty());
        }
    }

    #[test]
    fn profile_pack_manifest_snapshot_debug_clone_copy_eq() {
        let manifest = gf256_profile_pack_manifest_snapshot();
        let copied = manifest;
        let cloned = manifest;
        assert_eq!(copied, cloned);
        let dbg = format!("{manifest:?}");
        assert!(dbg.contains("Gf256ProfilePackManifestSnapshot"));
    }

    #[test]
    fn profile_pack_manifest_snapshot_is_deterministic_and_self_consistent() {
        let manifest = gf256_profile_pack_manifest_snapshot();
        let policy = manifest.active_policy;
        assert_eq!(
            manifest.schema_version,
            GF256_PROFILE_PACK_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            policy.profile_schema_version,
            GF256_PROFILE_PACK_SCHEMA_VERSION
        );
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            policy.profile_pack
        );
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            policy.architecture_class
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .selected_tuning_candidate_id,
            policy.selected_tuning_candidate_id
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .rejected_tuning_candidate_ids,
            policy.rejected_tuning_candidate_ids
        );
        assert!(
            manifest
                .profile_pack_catalog
                .iter()
                .any(|metadata| metadata.profile_pack == policy.profile_pack)
        );
        let selected = manifest
            .active_selected_tuning_candidate
            .expect("selected tuning candidate must exist in deterministic catalog");
        assert_eq!(selected.candidate_id, policy.selected_tuning_candidate_id);
        assert_eq!(selected.profile_pack, policy.profile_pack);
        assert_eq!(
            manifest.environment_metadata.target_arch,
            std::env::consts::ARCH
        );
        assert_eq!(
            manifest.environment_metadata.target_os,
            std::env::consts::OS
        );
        assert!(!manifest.environment_metadata.target_env.is_empty());
        assert!(matches!(
            manifest.environment_metadata.target_endian,
            "little" | "big"
        ));
        assert!(matches!(
            manifest.environment_metadata.target_pointer_width_bits,
            16 | 32 | 64 | 128
        ));
        assert!(manifest.profile_pack_catalog.len() >= 3);
        assert!(manifest.tuning_candidate_catalog.len() >= 3);
    }

    #[test]
    fn dual_policy_decisions_are_symmetric_under_lane_swap() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v2";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_decisions_are_symmetric_under_lane_swap",
            replay_ref,
        );

        for (len_a, len_b) in [
            (1usize, 1usize),
            (1024usize, 1024usize),
            (7168usize, 1024usize),
            (7424usize, 768usize),
            (12288usize, 12288usize),
            (16384usize, 16384usize),
        ] {
            assert_eq!(
                dual_mul_kernel_decision(len_a, len_b),
                dual_mul_kernel_decision(len_b, len_a),
                "{context}; mul decision was not symmetric for lane_a={len_a}, lane_b={len_b}"
            );
            assert_eq!(
                dual_addmul_kernel_decision(len_a, len_b),
                dual_addmul_kernel_decision(len_b, len_a),
                "{context}; addmul decision was not symmetric for lane_a={len_a}, lane_b={len_b}"
            );
        }
    }
}
