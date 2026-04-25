//! Symbol broadcast cancellation protocol.
//!
//! This module provides cancellation tokens, broadcast messages, and cleanup
//! coordination for symbol stream operations. Cancellation is a protocol:
//! it propagates correctly to stop generation, abort transmissions, clean up
//! partial symbol sets, and notify peers.
//!
//! [`progress_certificate`] provides martingale-based statistical certificates
//! that cancellation drain is making progress toward quiescence.

pub mod progress_certificate;
pub mod protocol_state_machines;
#[cfg(test)]
pub mod protocol_validator_test_suite;
pub mod symbol_cancel;

pub use progress_certificate::{
    CertificateVerdict, DrainPhase, EvidenceEntry, ProgressCertificate, ProgressConfig,
    ProgressObservation,
};
pub use protocol_state_machines::{
    CancelProtocolValidator, CancelStateMachine, ChannelContext, ChannelEvent, ChannelState,
    ChannelStateMachine, IoContext, IoEvent, IoState, IoStateMachine, ObligationContext,
    ObligationEvent, ObligationState, ObligationStateMachine, RegionContext, RegionEvent,
    RegionState, RegionStateMachine, TaskContext, TaskEvent, TaskState, TaskStateMachine,
    TimerContext, TimerEvent, TimerState, TimerStateMachine, TransitionResult, ValidationLevel,
};
#[cfg(test)]
pub use protocol_validator_test_suite::{
    BugInjectionConfig, BugInjectionStats, BugInjector, CancelProtocolTestSuite,
    FalsePositiveTestHarness, IntegrationTestConfig, IntegrationTestHarness,
    PerformanceMeasurement, PerformanceTestConfig, PerformanceTestHarness, PropertyTestHarness,
    ProtocolViolationType,
};
pub use symbol_cancel::{
    CancelBroadcastMetrics, CancelBroadcaster, CancelListener, CancelMessage, CancelSink,
    CleanupCoordinator, CleanupHandler, CleanupResult, CleanupStats, PeerId, SymbolCancelToken,
};
