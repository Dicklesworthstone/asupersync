//! Static obligation leak checking via abstract interpretation.
//!
//! Provides a prototype checker that detects code paths where obligations
//! (reserve/commit/abort) may leak — i.e., scope exits while an obligation
//! is still held and unresolved.
//!
//! # Architecture
//!
//! The checker operates on a simple structured IR ([`Body`]) rather than Rust
//! source code directly. This allows testing the analysis logic independently
//! from the Rust parser/type system.
//!
//! 1. **IR**: A sequence of [`Instruction`]s representing obligation operations
//! 2. **Abstract Domain**: [`VarState`] tracks whether each obligation variable
//!    is empty, held, may-hold (uncertain), or resolved
//! 3. **Checker**: Walks the IR, maintains abstract state, emits diagnostics
//!    at scope boundaries and function exits
//!
//! # Example
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

mod leak_check;

pub use leak_check::{
    Body, CheckResult, Diagnostic, DiagnosticKind, Instruction, LeakChecker, ObligationVar,
    VarState,
};
