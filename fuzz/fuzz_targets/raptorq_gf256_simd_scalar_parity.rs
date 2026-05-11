//! GF256 SIMD vs Scalar Differential Fuzzing
//!
//! **CRITICAL GAP ADDRESSED**: The existing `raptorq_gf256_slice_mismatch.rs`
//! fuzzer tests panic conditions but lacks differential testing between
//! SIMD (AVX2/NEON) and scalar implementations.
//!
//! **ORACLE**: Reference implementation comparison - the strongest available oracle.
//! For any given input, SIMD and scalar code paths MUST produce identical results.
//!
//! **STRUCTURE-AWARE**: Uses GF256 field properties and realistic slice size
//! distributions to maximize deep coverage vs random byte mutations.

#![no_main]

use asupersync::raptorq::gf256::{
    Gf256, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice, gf256_addmul_slices2,
    gf256_mul_slices2,
};
use libfuzzer_sys::fuzz_target;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

const MAX_SLICE_LEN: usize = 2048; // Realistic for RaptorQ symbols
const SCALAR_PROFILE: &str = "scalar-conservative-v1";
const PROFILE_PACK_ENV: &str = "ASUPERSYNC_GF256_PROFILE_PACK";
const DUAL_POLICY_ENV: &str = "ASUPERSYNC_GF256_DUAL_POLICY";

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn set_env_var(key: &str, value: &str) {
    // SAFETY: this fuzz target serializes its own GF256 environment overrides
    // with ENV_LOCK and does not spawn helper threads while the overrides are active.
    unsafe { std::env::set_var(key, value) };
}

fn remove_env_var(key: &str) {
    // SAFETY: this fuzz target serializes its own GF256 environment overrides
    // with ENV_LOCK and does not spawn helper threads while the overrides are active.
    unsafe { std::env::remove_var(key) };
}

/// Force scalar-only execution by overriding environment
fn with_forced_scalar<T>(f: impl FnOnce() -> T) -> T {
    let _lock = env_guard();
    set_env_var(PROFILE_PACK_ENV, SCALAR_PROFILE);
    set_env_var(DUAL_POLICY_ENV, "never");
    let result = f();
    remove_env_var(PROFILE_PACK_ENV);
    remove_env_var(DUAL_POLICY_ENV);
    result
}

/// Allow auto-detection (SIMD if available, scalar fallback)
fn with_auto_kernel<T>(f: impl FnOnce() -> T) -> T {
    let _lock = env_guard();
    remove_env_var(PROFILE_PACK_ENV);
    remove_env_var(DUAL_POLICY_ENV);
    f()
}

#[derive(Debug)]
struct GfOperation {
    op_type: u8,
    coef: u8,
    len_a: usize,
    len_b: usize,
    data: Vec<u8>,
}

impl GfOperation {
    fn from_fuzz_data(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let op_type = data[0] % 5; // 5 operations to test
        let coef = data[1];
        let len_a = ((data[2] as usize) % (MAX_SLICE_LEN + 1)).max(1);
        let len_b = ((data[3] as usize) % (MAX_SLICE_LEN + 1)).max(1);

        let needed_bytes = len_a.max(len_b) * 4; // Conservative estimate
        if data.len() < 4 + needed_bytes {
            return None;
        }

        Some(GfOperation {
            op_type,
            coef,
            len_a,
            len_b,
            data: data[4..].to_vec(),
        })
    }

    /// Execute operation with current kernel (SIMD or scalar)
    fn execute(&self) -> Result<Vec<Vec<u8>>, String> {
        match self.op_type {
            0 => self.test_gf256_add_slice(),
            1 => self.test_gf256_addmul_slice(),
            2 => self.test_gf256_add_slices2(),
            3 => self.test_gf256_addmul_slices2(),
            4 => self.test_gf256_mul_slices2(),
            _ => Err("Invalid operation type".to_string()),
        }
    }

    fn test_gf256_add_slice(&self) -> Result<Vec<Vec<u8>>, String> {
        if self.data.len() < self.len_a + self.len_b {
            return Err("Insufficient data".to_string());
        }

        let mut dst = self.data[..self.len_a].to_vec();
        let src = &self.data[self.len_a..self.len_a + self.len_b];

        // Only test when lengths match (mismatch = panic, not differential behavior)
        if dst.len() == src.len() {
            gf256_add_slice(&mut dst, src);
            Ok(vec![dst])
        } else {
            Err("Length mismatch".to_string())
        }
    }

    fn test_gf256_addmul_slice(&self) -> Result<Vec<Vec<u8>>, String> {
        if self.data.len() < self.len_a + self.len_b {
            return Err("Insufficient data".to_string());
        }

        let mut dst = self.data[..self.len_a].to_vec();
        let src = &self.data[self.len_a..self.len_a + self.len_b];

        if dst.len() == src.len() {
            gf256_addmul_slice(&mut dst, src, Gf256::new(self.coef));
            Ok(vec![dst])
        } else {
            Err("Length mismatch".to_string())
        }
    }

    fn test_gf256_add_slices2(&self) -> Result<Vec<Vec<u8>>, String> {
        let needed = self.len_a * 4;
        if self.data.len() < needed {
            return Err("Insufficient data".to_string());
        }

        let mut dst_a = self.data[..self.len_a].to_vec();
        let src_a = &self.data[self.len_a..2 * self.len_a];
        let mut dst_b = self.data[2 * self.len_a..3 * self.len_a].to_vec();
        let src_b = &self.data[3 * self.len_a..4 * self.len_a];

        gf256_add_slices2(&mut dst_a, src_a, &mut dst_b, src_b);
        Ok(vec![dst_a, dst_b])
    }

    fn test_gf256_addmul_slices2(&self) -> Result<Vec<Vec<u8>>, String> {
        let needed = self.len_a * 4;
        if self.data.len() < needed {
            return Err("Insufficient data".to_string());
        }

        let mut dst_a = self.data[..self.len_a].to_vec();
        let src_a = &self.data[self.len_a..2 * self.len_a];
        let mut dst_b = self.data[2 * self.len_a..3 * self.len_a].to_vec();
        let src_b = &self.data[3 * self.len_a..4 * self.len_a];

        gf256_addmul_slices2(&mut dst_a, src_a, &mut dst_b, src_b, Gf256::new(self.coef));
        Ok(vec![dst_a, dst_b])
    }

    fn test_gf256_mul_slices2(&self) -> Result<Vec<Vec<u8>>, String> {
        let needed = self.len_a * 2;
        if self.data.len() < needed {
            return Err("Insufficient data".to_string());
        }

        let mut dst_a = self.data[..self.len_a].to_vec();
        let mut dst_b = self.data[self.len_a..2 * self.len_a].to_vec();

        gf256_mul_slices2(&mut dst_a, &mut dst_b, Gf256::new(self.coef));
        Ok(vec![dst_a, dst_b])
    }
}

fuzz_target!(|data: &[u8]| {
    if !(8..=65_536).contains(&data.len()) {
        return;
    }

    let operation = match GfOperation::from_fuzz_data(data) {
        Some(op) => op,
        None => return,
    };

    // Execute with auto-kernel (SIMD if available)
    let auto_result = with_auto_kernel(|| operation.execute());

    // Execute with forced scalar
    let scalar_result = with_forced_scalar(|| operation.execute());

    // Both must succeed or both must fail
    match (auto_result, scalar_result) {
        (Ok(auto_output), Ok(scalar_output)) => {
            assert_eq!(
                auto_output, scalar_output,
                "GF256 SIMD/scalar parity violation: op_type={}, coef={}, len_a={}, len_b={}",
                operation.op_type, operation.coef, operation.len_a, operation.len_b
            );
        }
        (Err(_), Err(_)) => {
            // Both failed - acceptable if it's due to valid precondition violation
        }
        (Ok(auto), Err(scalar_err)) => {
            panic!(
                "SIMD succeeded but scalar failed: auto_result={:?}, scalar_error={}",
                auto, scalar_err
            );
        }
        (Err(auto_err), Ok(scalar)) => {
            panic!(
                "Scalar succeeded but SIMD failed: scalar_result={:?}, auto_error={}",
                scalar, auto_err
            );
        }
    }
});
