//! Symbol authentication and security infrastructure.
//!
//! This module provides authentication primitives for the RaptorQ-based
//! distributed layer. It enables verification of symbol integrity and
//! authenticity during transmission across untrusted networks.
//!
//! # Design Principles
//!
//! 1. **Determinism-compatible**: All operations are deterministic for lab runtime
//! 2. **Interface-first**: Clean traits allow swapping implementations
//! 3. **No ambient keys**: Keys must be explicitly provided (capability security)
//! 4. **Fail-safe defaults**: Invalid/missing auth fails closed
//!
//! # Phase 0 Status
//!
//! The current implementation uses a deterministic keyed hash that is NOT
//! cryptographically secure. Production deployments MUST use a proper HMAC
//! implementation (e.g., HMAC-SHA256).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    SecurityContext                        │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │                      AuthKey                        │ │
//! │  │  • 256-bit key material                            │ │
//! │  │  • Deterministic derivation from seed/DetRng       │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! │                          │                               │
//! │                          ▼                               │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │                    Authenticator                    │ │
//! │  │  • sign(symbol) → AuthenticationTag                │ │
//! │  │  • verify(symbol, tag) → Result<(), AuthError>     │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! │                          │                               │
//! │                          ▼                               │
//! │  ┌─────────────────────────────────────────────────────┐ │
//! │  │               AuthenticatedSymbol                   │ │
//! │  │  • Symbol + AuthenticationTag bundle               │ │
//! │  │  • Verified on construction, unverified on receive │ │
//! │  └─────────────────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use asupersync::security::{AuthKey, SecurityContext, AuthenticatedSymbol};
//! use asupersync::types::Symbol;
//!
//! // Create a security context with a derived key
//! let key = AuthKey::from_seed(42);
//! let ctx = SecurityContext::new(key);
//!
//! // Sign a symbol
//! let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
//! let authenticated = ctx.sign_symbol(&symbol);
//!
//! // Verify on receive
//! let verified = ctx.verify_authenticated_symbol(&authenticated)?;
//! ```

pub mod authenticated;
pub mod context;
pub mod error;
pub mod key;
pub mod tag;

pub use authenticated::AuthenticatedSymbol;
pub use context::{AuthMode, SecurityContext};
pub use error::{AuthError, AuthErrorKind, AuthResult};
pub use key::{AuthKey, AUTH_KEY_SIZE};
pub use tag::AuthenticationTag;
