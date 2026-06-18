//! Channel bonding — fetch one object from N donors at once (multi-donor fountain).
//!
//! Each donor sprays a residue-disjoint slice of the *same* RaptorQ fountain for a
//! byte-identical object, so loss on one donor is repaired by symbols from another
//! and aggregate goodput scales with the number of donors. Correctness rests on a
//! single invariant: every donor and the receiver agree on the exact same object,
//! so a `(sbn, esi)` pair means the same bytes everywhere.
//!
//! Phase A (`z01bbr.1`) locks that invariant with types before any data-path code:
//!
//! * A1 ([`descriptor`]) — the shared [`BondTransferDescriptor`] + the donor
//!   byte-match (merkle) proof. **(this module)**
//! * A2 — ESI partition function + disjointness/coverage (`z01bbr.1.2`).
//! * A3 — `DonorAssignment` + security model + key distribution (`z01bbr.1.3`).
//! * A4 — bonded handshake version + capability negotiation (`z01bbr.1.4`).

pub mod descriptor;

pub use descriptor::{BondEntry, BondProofError, BondTransferDescriptor};
