//! Obligation analysis: static leak checking and graded type experiments.
//!
//! This module provides two complementary approaches to obligation safety:
//!
//! 1. **Static leak checking** ([`leak_check`]): Abstract interpretation over
//!    a structured IR to detect code paths where obligations may leak.
//!
//! 2. **Graded types** ([`graded`]): A type-level encoding where obligations
//!    carry resource annotations, making leaks into compile warnings or
//!    runtime panics via `#[must_use]` and `Drop`.
//!
//! # Static Leak Checker
//!
//! The checker operates on a simple structured IR ([`Body`]) rather than Rust
//! source code directly. This allows testing the analysis logic independently
//! from the Rust parser/type system.
//!
//! ```
//! use asupersync::obligation::{Body, Instruction, LeakChecker, ObligationVar};
//! use asupersync::record::ObligationKind;
//!
//! let body = Body::new("send_message", vec![
//!     Instruction::Reserve { var: ObligationVar(0), kind: ObligationKind::SendPermit },
//!     // Oops: no commit or abort before scope exit
//! ]);
//!
//! let mut checker = LeakChecker::new();
//! let result = checker.check(&body);
//! assert!(!result.is_clean());
//! assert_eq!(result.leaks().len(), 1);
//! ```
//!
//! # Graded Types
//!
//! The graded surface makes obligation leaks a type-level concern:
//!
//! ```
//! use asupersync::obligation::graded::{GradedObligation, Resolution};
//! use asupersync::record::ObligationKind;
//!
//! let ob = GradedObligation::reserve(ObligationKind::SendPermit, "test");
//! ob.resolve(Resolution::Commit); // Must resolve before scope exit
//! ```

pub mod graded;
mod leak_check;

pub use leak_check::{
    Body, CheckResult, Diagnostic, DiagnosticKind, Instruction, LeakChecker, ObligationVar,
    VarState,
};
