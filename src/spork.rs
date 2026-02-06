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
//! | Registry        | *(future)*             | *(bd-2hccu)*                           |
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
        BackoffStrategy, ChildSpec, ChildStart, CompiledSupervisor, EscalationPolicy,
        RestartConfig, RestartPolicy, StartTieBreak, StartedChild, SupervisionStrategy,
        SupervisorBuilder, SupervisorCompileError, SupervisorHandle, SupervisorSpawnError,
    };
}

/// Typed request-response actors (GenServer pattern).
///
/// Re-exports from [`crate::gen_server`].
pub mod gen_server {
    pub use crate::gen_server::{
        CallError, CastError, CastOverflowPolicy, GenServer, GenServerHandle, GenServerRef,
        InfoError, Reply, ReplyOutcome, SystemMsg,
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
/// - **Monitoring**: `MonitorRef`, `DownReason`, `DownNotification`
/// - **Linking**: `ExitPolicy`, `ExitSignal`, `LinkRef`
/// - **Errors**: `AppStartError`, `CallError`, `CastError`
pub mod prelude {
    // -- Application lifecycle --
    pub use crate::app::{AppHandle, AppSpec, StoppedApp};

    // -- Supervision --
    pub use crate::supervision::{
        BackoffStrategy, ChildSpec, ChildStart, RestartConfig, RestartPolicy, SupervisionStrategy,
        SupervisorBuilder,
    };

    // -- GenServer --
    pub use crate::gen_server::{
        CallError, CastError, GenServer, GenServerHandle, Reply, SystemMsg,
    };

    // -- Monitor --
    pub use crate::monitor::{DownNotification, DownReason, MonitorRef};

    // -- Link --
    pub use crate::link::{ExitPolicy, ExitSignal, LinkRef};

    // -- Errors --
    pub use crate::app::{AppCompileError, AppStartError};
    pub use crate::supervision::SupervisorCompileError;
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
}
