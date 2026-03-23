//! Session-contract surfaces for FABRIC.

pub mod conformance;
pub mod contract;
pub mod obligation;
pub mod projection;
pub mod synthesis;

pub use conformance::{
    ConformanceCheckRecord, ConformanceExpectation, ConformanceMonitor,
    ConformanceMonitorInitError, ConformanceObserved, ConformanceOracle, ConformanceRecoveryBranch,
    ConformanceRecoveryStage, ConformanceViolation, ConformanceViolationEvidence,
};
pub use contract::{
    CompensationPath, CutoffPath, EvidenceCheckpoint, GlobalSessionType, Label, MessageType,
    ProtocolContract, ProtocolContractValidationError, RoleName, SessionBranch, SessionPath,
    SessionType, TimeoutLaw, TimeoutOverride,
};
pub use obligation::{DerivedObligation, DerivedObligationClass, DerivedObligations};
pub use projection::{
    LocalSessionBranch, LocalSessionType, ProjectionError, is_dual, project, project_contract,
    project_pair,
};
pub use synthesis::SynthesizedHandlerPlaceholder;
