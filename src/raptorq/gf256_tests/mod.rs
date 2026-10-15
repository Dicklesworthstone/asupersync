//! GF(256) validation test modules.
//!
//! Provides comprehensive validation of GF(256) finite field operations
//! and kernel implementations.

pub(super) use crate::raptorq::gf256::{
    DualKernelMode, Gf256, active_kernel, dual_addmul_kernel_decision, dual_kernel_policy_snapshot,
    dual_mul_kernel_decision, gf256_add_slice, gf256_add_slices2, gf256_mul_slice,
    gf256_mul_slices2, gf256_profile_pack_manifest_snapshot,
};

#[cfg(test)]
mod gf256_validation_tests;

#[cfg(test)]
mod validation_tests;
