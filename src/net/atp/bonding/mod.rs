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
//!   byte-match (merkle) proof.
//! * A2 ([`esi`]) — ESI partition function + disjointness/coverage.
//! * A3 ([`assignment`]) — [`DonorAssignment`] + security model + key distribution.
//! * A4 — bonded handshake version + capability negotiation (`z01bbr.1.4`).

pub mod assignment;
pub mod descriptor;
pub mod esi;
pub mod handshake;
pub mod receiver;

pub use assignment::{
    BONDING_ASSIGNMENT_VERSION, BondAuthKeyRef, BondedSymbolAuthVerdict, BondedSymbolRejectReason,
    DonorAssignment, DonorAssignmentError, EsiWindow, MAX_BONDING_DONORS, verify_bonded_symbol_tag,
};
pub use descriptor::{BondEntry, BondProofError, BondTransferDescriptor};
pub use esi::{
    DonorEsiStream, EsiPartition, EsiPartitionError, donor_esi_stream, esi_for_donor, owns_esi,
};
pub use handshake::{
    BONDING_HANDSHAKE_VERSION, BondTransport, BondingAgreement, BondingAssignmentMode,
    BondingHandshake, BondingHandshakeError,
};
pub use receiver::{
    BondedDonorIngressStats, BondedReceiverIngressStats, BondedReceiverSymbolSet,
    BondedSymbolDisposition, BondedSymbolKey,
};
