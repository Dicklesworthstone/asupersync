//! Ambient authority audit and hardening.
//!
//! Provides compile-time and runtime checks to prevent ambient authority
//! from bypassing the Cx capability system.
//!
//! # Meta-Audit Security
//!
//! The audit system implements the "audit-the-auditor" principle through
//! [`meta_audit`] to prevent capability escalation where the audit system
//! itself could be manipulated to hide violations or accumulate ambient
//! authority outside the Cx capability system.

pub mod ambient;
pub mod meta_audit;
