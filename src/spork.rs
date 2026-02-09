//! SPORK: OTP-grade supervision, registry, and actor layer for Asupersync.
//!
//! This module provides a unified entry point for all Spork functionality.
//! The module layout mirrors the OTP mental model:
//!
//! | OTP Concept     | Spork Module           | Key Types                              |
//! |-----------------|------------------------|----------------------------------------|
//! | Application     | [`app`]                | `AppSpec`, `AppHandle`, `CompiledApp`  |
//! | Supervisor      | [`supervisor`]         | `SupervisorBuilder`, `ChildSpec`       |
//! | GenServer       | [`gen_server`]         | `GenServer`, `GenServerHandle`, `Reply`|
//! | Registry        | [`registry`]           | `NameRegistry`, `RegistryHandle`, `NameLease` |
//! | Monitor         | [`monitor`]            | `MonitorRef`, `DownReason`             |
//! | Link            | [`link`]               | `LinkRef`, `ExitPolicy`, `ExitSignal`  |
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::spork::prelude::*;
//!
//! // Build an application with a supervisor and children
//! let app = AppSpec::new("my_app")
//!     .child(
//!         ChildSpec::new("worker", MyWorkerStart)
//!             .restart_policy(SupervisionStrategy::Restart(
//!                 RestartConfig::default()
//!             ))
//!     )
//!     .start(&mut cx)
//!     .await?;
//!
//! app.stop(&mut cx).await?;
//! ```
//!
//! # Prelude
//!
//! The [`prelude`] re-exports the most commonly needed types so that a
//! single `use asupersync::spork::prelude::*` is sufficient for typical
//! supervised application development.
//!
//! # Bead
//!
//! bd-2td4e | Parent: bd-1f3nn

/// Application lifecycle: build, compile, start, stop.
///
/// Re-exports from [`crate::app`].
pub mod app {
    pub use crate::app::{
        AppCompileError, AppHandle, AppSpawnError, AppSpec, AppStartError, AppStopError,
        CompiledApp, StoppedApp,
    };
}

/// Supervision trees: strategies, child specs, builders.
///
/// Re-exports from [`crate::supervision`].
pub mod supervisor {
    pub use crate::supervision::{
        BackoffStrategy, ChildName, ChildSpec, ChildStart, CompiledSupervisor, EscalationPolicy,
        RestartConfig, RestartPolicy, StartTieBreak, StartedChild, SupervisionStrategy,
        SupervisorBuilder, SupervisorCompileError, SupervisorHandle, SupervisorSpawnError,
    };
}

/// Typed request-response actors (GenServer pattern).
///
/// Re-exports from [`crate::gen_server`].
pub mod gen_server {
    pub use crate::gen_server::{
        named_gen_server_start, CallError, CastError, CastOverflowPolicy, GenServer,
        GenServerHandle, GenServerRef, InfoError, NamedGenServerStart, Reply, ReplyOutcome,
        SystemMsg,
    };
}

/// Capability-scoped name registry and lease obligations.
///
/// Re-exports from [`crate::cx::registry`].
pub mod registry {
    pub use crate::cx::registry::{
        GrantedLease, NameCollisionOutcome, NameCollisionPolicy, NameLease, NameLeaseError,
        NameOwnershipKind, NameOwnershipNotification, NamePermit, NameRegistry, NameWatchRef,
        RegistryCap, RegistryEvent, RegistryHandle,
    };
}

/// Unidirectional down notifications.
///
/// Re-exports from [`crate::monitor`].
pub mod monitor {
    pub use crate::monitor::{DownNotification, DownReason, MonitorRef};
}

/// Bidirectional exit signal propagation.
///
/// Re-exports from [`crate::link`].
pub mod link {
    pub use crate::link::{ExitPolicy, ExitSignal, LinkRef};
}

/// Crash pack format and artifact writing.
///
/// Re-exports from [`crate::trace::crashpack`].
pub mod crash {
    pub use crate::trace::crashpack::{
        ArtifactId, CrashPack, CrashPackConfig, CrashPackManifest, CrashPackWriteError,
        CrashPackWriter, FailureInfo, FailureOutcome, FileCrashPackWriter, MemoryCrashPackWriter,
        ReplayCommand,
    };
}

/// The SPORK prelude: import this for typical supervised application development.
///
/// ```ignore
/// use asupersync::spork::prelude::*;
/// ```
///
/// This exports the minimal set of types needed to build, run, and debug
/// a supervised application. Advanced types (evidence ledgers, obligation
/// tokens, etc.) are available through the sub-modules.
///
/// # What's Included
///
/// - **App lifecycle**: `AppSpec`, `AppHandle`, `StoppedApp`
/// - **Supervision**: `SupervisorBuilder`, `ChildSpec`, `ChildStart`,
///   `SupervisionStrategy`, `RestartConfig`, `RestartPolicy`
/// - **GenServer**: `GenServer`, `GenServerHandle`, `Reply`, `SystemMsg`
/// - **Registry**: `NameRegistry`, `RegistryHandle`, `NameLease`
/// - **Monitoring**: `MonitorRef`, `DownReason`, `DownNotification`
/// - **Linking**: `ExitPolicy`, `ExitSignal`, `LinkRef`
/// - **Errors**: `AppStartError`, `CallError`, `CastError`
pub mod prelude {
    // -- Application lifecycle --
    pub use crate::app::{AppHandle, AppSpec, StoppedApp};

    // -- Supervision --
    pub use crate::supervision::{
        BackoffStrategy, ChildName, ChildSpec, ChildStart, RestartConfig, RestartPolicy,
        SupervisionStrategy, SupervisorBuilder,
    };

    // -- GenServer --
    pub use crate::gen_server::{
        named_gen_server_start, CallError, CastError, GenServer, GenServerHandle,
        NamedGenServerStart, Reply, SystemMsg,
    };

    // -- Registry --
    pub use crate::cx::{NameLease, NameRegistry, RegistryHandle};

    // -- Monitor --
    pub use crate::monitor::{DownNotification, DownReason, MonitorRef};

    // -- Link --
    pub use crate::link::{ExitPolicy, ExitSignal, LinkRef};

    // -- Errors --
    pub use crate::app::{AppCompileError, AppStartError};
    pub use crate::supervision::SupervisorCompileError;

    // -- Unified error --
    pub use super::error::SporkError;
}

// =============================================================================
// Unified Error Taxonomy (bd-2x5xc)
// =============================================================================

/// Unified SPORK error taxonomy.
///
/// Rather than requiring callers to memorize domain-specific error enums
/// (`AppStartError`, `CallError`, `SupervisorCompileError`, ...),
/// `SporkError` provides a single error type that covers all SPORK operations.
///
/// # Domains
///
/// | Domain         | Covers                                      |
/// |----------------|---------------------------------------------|
/// | `Lifecycle`    | `AppStartError`, `AppStopError`             |
/// | `Compile`      | `AppCompileError`, `SupervisorCompileError` |
/// | `Spawn`        | `AppSpawnError`, `SupervisorSpawnError`      |
/// | `Call`         | `GenServerHandle::call()` failures          |
/// | `Cast`         | `GenServerHandle::cast()` failures          |
/// | `Info`         | `GenServerHandle::info()` failures          |
///
/// # Severity
///
/// All variants carry a [`SporkSeverity`] classification that is monotone:
/// a failure that was classified as `Permanent` by its origin domain will
/// never be downgraded by wrapping it in `SporkError`.
///
/// # Example
///
/// ```ignore
/// use asupersync::spork::prelude::*;
///
/// let result: Result<(), SporkError> = app.start(&mut cx).await.map_err(SporkError::from);
/// match result {
///     Err(e) if e.is_permanent() => eprintln!("fatal: {e}"),
///     Err(e) => eprintln!("transient: {e}"),
///     Ok(()) => {},
/// }
/// ```
pub mod error {
    use crate::app::{AppCompileError, AppSpawnError, AppStartError, AppStopError};
    use crate::gen_server::{CallError, CastError, InfoError};
    use crate::supervision::{SupervisorCompileError, SupervisorSpawnError};

    /// Severity classification for SPORK errors.
    ///
    /// Monotone: wrapping an error in `SporkError` never downgrades severity.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SporkSeverity {
        /// The operation may succeed if retried (e.g., mailbox full).
        Transient,
        /// The operation failed and should not be retried in the same way
        /// (e.g., cycle in topology, server stopped).
        Permanent,
    }

    /// Unified error type for all SPORK operations.
    #[derive(Debug)]
    pub enum SporkError {
        /// Application start failed (compile or spawn phase).
        Start(AppStartError),
        /// Application stop failed.
        Stop(AppStopError),
        /// Supervisor topology compilation failed.
        Compile(AppCompileError),
        /// Supervisor spawn failed.
        Spawn(AppSpawnError),
        /// GenServer `call()` failed.
        Call(CallError),
        /// GenServer `cast()` failed.
        Cast(CastError),
        /// GenServer `info()` send failed.
        Info(InfoError),
    }

    impl SporkError {
        /// Classify the severity of this error.
        ///
        /// Severity is monotone: permanent errors remain permanent.
        #[must_use]
        pub fn severity(&self) -> SporkSeverity {
            match self {
                // Lifecycle errors are permanent (topology or region failures)
                Self::Start(_) | Self::Stop(_) | Self::Compile(_) | Self::Spawn(_) => {
                    SporkSeverity::Permanent
                }
                // Communication errors depend on the variant
                Self::Call(e) => match e {
                    CallError::ServerStopped | CallError::NoReply | CallError::Cancelled(_) => {
                        SporkSeverity::Permanent
                    }
                },
                Self::Cast(e) => match e {
                    CastError::Full => SporkSeverity::Transient,
                    CastError::ServerStopped | CastError::Cancelled(_) => SporkSeverity::Permanent,
                },
                Self::Info(e) => match e {
                    InfoError::Full => SporkSeverity::Transient,
                    InfoError::ServerStopped | InfoError::Cancelled(_) => SporkSeverity::Permanent,
                },
            }
        }

        /// Returns `true` if this error is permanent (should not retry).
        #[must_use]
        pub fn is_permanent(&self) -> bool {
            self.severity() == SporkSeverity::Permanent
        }

        /// Returns `true` if this error is transient (may succeed on retry).
        #[must_use]
        pub fn is_transient(&self) -> bool {
            self.severity() == SporkSeverity::Transient
        }

        /// Returns a short domain tag for this error (e.g., `"start"`, `"call"`).
        #[must_use]
        pub fn domain(&self) -> &'static str {
            match self {
                Self::Start(_) => "start",
                Self::Stop(_) => "stop",
                Self::Compile(_) => "compile",
                Self::Spawn(_) => "spawn",
                Self::Call(_) => "call",
                Self::Cast(_) => "cast",
                Self::Info(_) => "info",
            }
        }
    }

    impl std::fmt::Display for SporkError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Start(e) => write!(f, "spork start: {e}"),
                Self::Stop(e) => write!(f, "spork stop: {e}"),
                Self::Compile(e) => write!(f, "spork compile: {e}"),
                Self::Spawn(e) => write!(f, "spork spawn: {e}"),
                Self::Call(e) => write!(f, "spork call: {e}"),
                Self::Cast(e) => write!(f, "spork cast: {e}"),
                Self::Info(e) => write!(f, "spork info: {e}"),
            }
        }
    }

    impl std::error::Error for SporkError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Start(e) => Some(e),
                Self::Stop(e) => Some(e),
                Self::Compile(e) => Some(e),
                Self::Spawn(e) => Some(e),
                Self::Call(e) => Some(e),
                Self::Cast(e) => Some(e),
                Self::Info(e) => Some(e),
            }
        }
    }

    // -- From conversions (zero-cost wrapping) --

    impl From<AppStartError> for SporkError {
        fn from(e: AppStartError) -> Self {
            Self::Start(e)
        }
    }

    impl From<AppStopError> for SporkError {
        fn from(e: AppStopError) -> Self {
            Self::Stop(e)
        }
    }

    impl From<AppCompileError> for SporkError {
        fn from(e: AppCompileError) -> Self {
            Self::Compile(e)
        }
    }

    impl From<AppSpawnError> for SporkError {
        fn from(e: AppSpawnError) -> Self {
            Self::Spawn(e)
        }
    }

    impl From<SupervisorCompileError> for SporkError {
        fn from(e: SupervisorCompileError) -> Self {
            Self::Compile(AppCompileError::SupervisorCompile(e))
        }
    }

    impl From<SupervisorSpawnError> for SporkError {
        fn from(e: SupervisorSpawnError) -> Self {
            Self::Spawn(AppSpawnError::SpawnFailed(e))
        }
    }

    impl From<CallError> for SporkError {
        fn from(e: CallError) -> Self {
            Self::Call(e)
        }
    }

    impl From<CastError> for SporkError {
        fn from(e: CastError) -> Self {
            Self::Cast(e)
        }
    }

    impl From<InfoError> for SporkError {
        fn from(e: InfoError) -> Self {
            Self::Info(e)
        }
    }
}

#[cfg(test)]
#[allow(clippy::no_effect_underscore_binding)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn prelude_imports_compile() {
        init_test("prelude_imports_compile");

        // Verify all prelude types are accessible
        let _ = std::any::type_name::<prelude::AppSpec>();
        let _ = std::any::type_name::<prelude::AppHandle>();
        let _ = std::any::type_name::<prelude::StoppedApp>();
        let _ = std::any::type_name::<prelude::SupervisorBuilder>();
        let _ = std::any::type_name::<prelude::ChildSpec>();
        let _ = std::any::type_name::<prelude::RestartConfig>();
        let _ = std::any::type_name::<prelude::SupervisionStrategy>();
        let _ = std::any::type_name::<prelude::RestartPolicy>();
        let _ = std::any::type_name::<prelude::BackoffStrategy>();
        let _ = std::any::type_name::<prelude::NameRegistry>();
        let _ = std::any::type_name::<prelude::RegistryHandle>();
        let _ = std::any::type_name::<prelude::NameLease>();
        let _ = std::any::type_name::<prelude::MonitorRef>();
        let _ = std::any::type_name::<prelude::DownReason>();
        let _ = std::any::type_name::<prelude::DownNotification>();
        let _ = std::any::type_name::<prelude::ExitPolicy>();
        let _ = std::any::type_name::<prelude::LinkRef>();
        let _ = std::any::type_name::<prelude::CallError>();
        let _ = std::any::type_name::<prelude::CastError>();
        let _ = std::any::type_name::<prelude::AppStartError>();
        let _ = std::any::type_name::<prelude::AppCompileError>();
        let _ = std::any::type_name::<prelude::SupervisorCompileError>();

        crate::test_complete!("prelude_imports_compile");
    }

    #[test]
    fn submodule_types_accessible() {
        init_test("submodule_types_accessible");

        // App sub-module
        let _ = std::any::type_name::<app::CompiledApp>();
        let _ = std::any::type_name::<app::AppSpawnError>();
        let _ = std::any::type_name::<app::AppStopError>();

        // Supervisor sub-module
        let _ = std::any::type_name::<supervisor::CompiledSupervisor>();
        let _ = std::any::type_name::<supervisor::EscalationPolicy>();
        let _ = std::any::type_name::<supervisor::StartTieBreak>();
        let _ = std::any::type_name::<supervisor::SupervisorHandle>();
        let _ = std::any::type_name::<supervisor::StartedChild>();
        let _ = std::any::type_name::<supervisor::SupervisorSpawnError>();

        // GenServer sub-module
        let _ = std::any::type_name::<gen_server::CastOverflowPolicy>();
        let _ = std::any::type_name::<gen_server::InfoError>();
        let _ = std::any::type_name::<gen_server::ReplyOutcome>();

        // Registry sub-module
        let _ = std::any::type_name::<registry::NameRegistry>();
        let _ = std::any::type_name::<registry::RegistryHandle>();
        let _ = std::any::type_name::<registry::NameLease>();
        let _ = std::any::type_name::<registry::NameCollisionPolicy>();

        // Monitor sub-module
        let _ = std::any::type_name::<monitor::MonitorRef>();

        // Link sub-module
        let _ = std::any::type_name::<link::ExitPolicy>();

        // Crash sub-module
        let _ = std::any::type_name::<crash::CrashPack>();
        let _ = std::any::type_name::<crash::CrashPackConfig>();
        let _ = std::any::type_name::<crash::ReplayCommand>();

        crate::test_complete!("submodule_types_accessible");
    }

    #[test]
    fn supervision_strategy_constructible() {
        init_test("supervision_strategy_constructible");

        // Verify the prelude types can actually be used to construct values
        let _stop = prelude::SupervisionStrategy::Stop;
        let _restart = prelude::SupervisionStrategy::Restart(prelude::RestartConfig::default());
        let _escalate = prelude::SupervisionStrategy::Escalate;

        let _one_for_one = prelude::RestartPolicy::OneForOne;
        let _one_for_all = prelude::RestartPolicy::OneForAll;
        let _rest_for_one = prelude::RestartPolicy::RestForOne;

        let _none = prelude::BackoffStrategy::None;

        crate::test_complete!("supervision_strategy_constructible");
    }

    #[test]
    fn down_reason_constructible() {
        init_test("down_reason_constructible");

        let _normal = prelude::DownReason::Normal;
        let _error = prelude::DownReason::Error("oops".to_string());

        crate::test_complete!("down_reason_constructible");
    }

    #[test]
    fn exit_policy_constructible() {
        init_test("exit_policy_constructible");

        let _prop = prelude::ExitPolicy::Propagate;
        let _trap = prelude::ExitPolicy::Trap;
        let _ignore = prelude::ExitPolicy::Ignore;

        crate::test_complete!("exit_policy_constructible");
    }

    // =====================================================================
    // Unified Error Taxonomy tests (bd-2x5xc)
    // =====================================================================

    mod error_taxonomy {
        use crate::app::{AppCompileError, AppStartError, AppStopError};
        use crate::gen_server::{CallError, CastError, InfoError};
        use crate::spork::error::{SporkError, SporkSeverity};
        use crate::supervision::SupervisorCompileError;
        use crate::types::RegionId;
        use crate::util::arena::ArenaIndex;

        fn dummy_region_id() -> RegionId {
            RegionId::from_arena(ArenaIndex::new(0, 0))
        }

        fn init_test(name: &str) {
            crate::test_utils::init_test_logging();
            crate::test_phase!(name);
        }

        // -- From conversions --

        #[test]
        fn from_call_error() {
            init_test("from_call_error");
            let e: SporkError = CallError::ServerStopped.into();
            assert!(matches!(e, SporkError::Call(CallError::ServerStopped)));
            crate::test_complete!("from_call_error");
        }

        #[test]
        fn from_cast_error() {
            init_test("from_cast_error");
            let e: SporkError = CastError::Full.into();
            assert!(matches!(e, SporkError::Cast(CastError::Full)));
            crate::test_complete!("from_cast_error");
        }

        #[test]
        fn from_info_error() {
            init_test("from_info_error");
            let e: SporkError = InfoError::ServerStopped.into();
            assert!(matches!(e, SporkError::Info(InfoError::ServerStopped)));
            crate::test_complete!("from_info_error");
        }

        #[test]
        fn from_app_compile_error() {
            init_test("from_app_compile_error");
            let inner = AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("dup".into()),
            );
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Compile(_)));
            crate::test_complete!("from_app_compile_error");
        }

        #[test]
        fn from_supervisor_compile_error() {
            init_test("from_supervisor_compile_error");
            let inner = SupervisorCompileError::DuplicateChildName("x".into());
            let e: SporkError = inner.into();
            // Should wrap via AppCompileError::SupervisorCompile
            assert!(matches!(
                e,
                SporkError::Compile(AppCompileError::SupervisorCompile(_))
            ));
            crate::test_complete!("from_supervisor_compile_error");
        }

        #[test]
        fn from_app_start_error() {
            init_test("from_app_start_error");
            let inner = AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("a".into()),
            ));
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Start(_)));
            crate::test_complete!("from_app_start_error");
        }

        #[test]
        fn from_app_stop_error() {
            init_test("from_app_stop_error");
            let inner = AppStopError::RegionNotFound(dummy_region_id());
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Stop(_)));
            crate::test_complete!("from_app_stop_error");
        }

        // -- Severity classification --

        #[test]
        fn severity_permanent_lifecycle() {
            init_test("severity_permanent_lifecycle");
            let e = SporkError::Start(AppStartError::CompileFailed(
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                    "a".into(),
                )),
            ));
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            assert!(!e.is_transient());
            crate::test_complete!("severity_permanent_lifecycle");
        }

        #[test]
        fn severity_permanent_call() {
            init_test("severity_permanent_call");
            let e = SporkError::Call(CallError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            crate::test_complete!("severity_permanent_call");
        }

        #[test]
        fn severity_transient_cast_full() {
            init_test("severity_transient_cast_full");
            let e = SporkError::Cast(CastError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            assert!(!e.is_permanent());
            crate::test_complete!("severity_transient_cast_full");
        }

        #[test]
        fn severity_transient_info_full() {
            init_test("severity_transient_info_full");
            let e = SporkError::Info(InfoError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_info_full");
        }

        #[test]
        fn severity_permanent_cast_stopped() {
            init_test("severity_permanent_cast_stopped");
            let e = SporkError::Cast(CastError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            crate::test_complete!("severity_permanent_cast_stopped");
        }

        // -- Domain tags --

        #[test]
        fn domain_tags() {
            init_test("domain_tags");
            assert_eq!(
                SporkError::Start(AppStartError::CompileFailed(
                    AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                        "a".into()
                    ))
                ))
                .domain(),
                "start"
            );
            assert_eq!(
                SporkError::Stop(AppStopError::RegionNotFound(dummy_region_id())).domain(),
                "stop"
            );
            assert_eq!(
                SporkError::Compile(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName("a".into())
                ))
                .domain(),
                "compile"
            );
            assert_eq!(SporkError::Call(CallError::ServerStopped).domain(), "call");
            assert_eq!(SporkError::Cast(CastError::Full).domain(), "cast");
            assert_eq!(SporkError::Info(InfoError::ServerStopped).domain(), "info");
            crate::test_complete!("domain_tags");
        }

        // -- Display --

        #[test]
        fn display_format() {
            init_test("display_format");
            let e = SporkError::Call(CallError::ServerStopped);
            let s = format!("{e}");
            assert!(s.starts_with("spork call:"), "got: {s}");

            let e2 = SporkError::Cast(CastError::Full);
            let s2 = format!("{e2}");
            assert!(s2.starts_with("spork cast:"), "got: {s2}");
            crate::test_complete!("display_format");
        }

        // -- Error source chain --

        #[test]
        fn error_source_chain() {
            init_test("error_source_chain");
            let e = SporkError::Call(CallError::NoReply);
            let source = std::error::Error::source(&e);
            assert!(source.is_some(), "SporkError should have a source");
            crate::test_complete!("error_source_chain");
        }

        // -- SporkSeverity ordering --

        #[test]
        fn severity_ordering() {
            init_test("severity_ordering");
            assert!(SporkSeverity::Transient < SporkSeverity::Permanent);
            crate::test_complete!("severity_ordering");
        }
    }
}
