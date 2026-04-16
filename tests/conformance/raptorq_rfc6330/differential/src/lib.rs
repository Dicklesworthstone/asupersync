//! RaptorQ RFC 6330 differential testing scaffold.
//!
//! This crate provides the provenance and fixture-catalog layer for
//! cross-implementation differential testing. It intentionally focuses on the
//! durable metadata path first: which reference implementation was used, which
//! command generated a fixture, and which artifacts belong to each test case.

pub mod fixture_loader;
pub mod provenance;

pub use fixture_loader::{DifferentialFixtureLoader, FixtureCaseView};
pub use provenance::{
    CatalogSummary, DifferentialFixtureCatalog, DifferentialFixtureError, FixtureArtifact,
    FixtureProvenanceRecord, ReferenceImplementation, ReferenceLanguage,
};
