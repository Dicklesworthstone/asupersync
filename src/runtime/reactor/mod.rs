//! Reactor abstraction for I/O event multiplexing.
//!
//! This module provides the [`Reactor`] trait and associated types for platform-agnostic
//! I/O event notification. The reactor is the core of the async runtime's I/O system,
//! monitoring registered sources and notifying the runtime when they become ready.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Runtime                                  │
//! │  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
//! │  │    Tasks      │────│   Scheduler   │────│   IoDriver    │   │
//! │  └───────────────┘    └───────────────┘    └───────┬───────┘   │
//! │                                                     │           │
//! │  ┌──────────────────────────────────────────────────┼─────────┐ │
//! │  │                     Reactor                       │         │ │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────▼───────┐ │ │
//! │  │  │ Token Slab  │  │ Interest    │  │    Platform API     │ │ │
//! │  │  │ (waker map) │  │ Registry    │  │ (epoll/kqueue/IOCP) │ │ │
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │ │
//! │  └────────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`Reactor`] | Trait for I/O event notification backends |
//! | [`Interest`] | Bitflags for readable/writable/error events |
//! | [`Events`] | Container for poll results |
//! | [`Event`] | Single readiness notification |
//! | [`Token`] | Identifier linking registrations to events |
//! | [`Registration`] | RAII handle for registered sources |
//! | [`Source`] | Trait for I/O objects that can be registered |
//!
//! # Platform Backends
//!
//! | Platform | Backend | Module |
//! |----------|---------|--------|
//! | Linux/Android | epoll | `epoll.rs` |
//! | macOS/BSD | kqueue | `kqueue.rs` |
//! | Windows | IOCP | `windows.rs` |
//! | Browser/wasm32 | BrowserReactor | `browser.rs` |
//! | Testing | virtual | `lab.rs` |
//!
//! # Public Export Contract
//!
//! The live `runtime::reactor` export graph is intentionally cfg-gated:
//!
//! | Target / feature | Public symbols | Live source | Contract |
//! |------------------|----------------|-------------|----------|
//! | Linux/Android | `EpollReactor`, `IoUringReactor` | `epoll.rs`, `io_uring.rs` | `EpollReactor` is the always-available Linux/Android backend. `IoUringReactor` is exported on Linux/Android builds; it is real with the `io-uring` feature and intentionally returns `Unsupported` without that feature. |
//! | macOS/BSD | `KqueueReactor` | `kqueue.rs` | Live BSD-family backend only. |
//! | Windows | `IocpReactor` | `windows.rs` | Live Windows backend only. |
//! | wasm32 | `BrowserReactor` | `browser.rs` | Browser event-loop reactor. |
//! | Deterministic tests | `LabReactor` | `lab.rs` | Virtual reactor for replayable tests. |
//!
//! Historical source files such as `src/runtime/reactor/uring.rs` and
//! `src/runtime/reactor/macos.rs` are not part of the current public export graph.
//! They are legacy or duplicate cleanup targets, not the authoritative API
//! contract for `runtime::reactor`.
//!
//! # Usage Pattern
//!
//! ```ignore
//! use asupersync::runtime::reactor::{Reactor, Interest, Events, Token};
//!
//! // 1. Register a source
//! let token = Token::new(42);
//! reactor.register(&socket, token, Interest::READABLE)?;
//!
//! // 2. Poll for events
//! let mut events = Events::with_capacity(64);
//! loop {
//!     let n = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
//!
//!     for event in &events {
//!         match event.token {
//!             token if event.is_readable() => handle_read(token),
//!             token if event.is_writable() => handle_write(token),
//!             _ => {}
//!         }
//!     }
//!     events.clear();
//! }
//!
//! // 3. Deregister when done
//! reactor.deregister(token)?;
//! ```
//!
//! # Oneshot vs Edge Triggering
//!
//! The portable reactor contract defaults to oneshot delivery on the Unix
//! backends used by the runtime. After an event is delivered, callers re-arm
//! interest with `modify()` when they are ready for the next wakeup.
//!
//! The [`Interest::EDGE_TRIGGERED`] flag enables edge-triggered delivery when
//! the backend supports it. In edge-triggered mode, callers must fully drain
//! readable or writable state before waiting for the next event.
//!
//! # Cancel Safety
//!
//! The [`Registration`] type provides RAII deregistration. When a `Registration`
//! is dropped (e.g., due to task cancellation), it automatically deregisters from
//! the reactor. This prevents:
//!
//! - Dangling registrations for closed sources
//! - Spurious wakeups to cancelled tasks
//! - Resource leaks in the reactor's token slab

pub mod browser;
pub mod interest;
pub mod lab;
mod registration;
pub mod source;
pub mod token;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod epoll;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "io_uring.rs"]
pub mod uring;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub mod kqueue;

#[cfg(target_os = "windows")]
pub mod windows;

pub use browser::{BrowserReactor, BrowserReactorConfig};
pub use interest::Interest;
pub use lab::{FaultConfig, LabReactor};
#[allow(unused_imports)]
pub(crate) use registration::ReactorHandle;
pub use registration::Registration;
pub use source::{Source, SourceId, SourceWrapper, next_source_id};
pub use token::{SlabToken, TokenSlab};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use epoll::EpollReactor;

#[cfg(target_os = "windows")]
pub use windows::IocpReactor;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub use kqueue::KqueueReactor;

use std::io;
use std::sync::Arc;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use uring::IoUringReactor;

use smallvec::SmallVec;

/// Token identifying a registered source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token(pub usize);

impl Token {
    /// Creates a new token.
    #[must_use]
    pub const fn new(val: usize) -> Self {
        Self(val)
    }
}

/// I/O event from the reactor.
///
/// Represents a single readiness notification for a registered source.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::{Event, Interest, Token};
///
/// let event = Event::new(Token::new(1), Interest::READABLE | Interest::WRITABLE);
/// assert!(event.is_readable());
/// assert!(event.is_writable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Token identifying the registered source.
    pub token: Token,
    /// Readiness flags that triggered.
    pub ready: Interest,
}

impl Event {
    /// Creates a new event with specified token and readiness flags.
    #[must_use]
    pub const fn new(token: Token, ready: Interest) -> Self {
        Self { token, ready }
    }

    /// Creates a readable event.
    #[must_use]
    pub const fn readable(token: Token) -> Self {
        Self {
            token,
            ready: Interest::READABLE,
        }
    }

    /// Creates a writable event.
    #[must_use]
    pub const fn writable(token: Token) -> Self {
        Self {
            token,
            ready: Interest::WRITABLE,
        }
    }

    /// Creates an error event.
    #[must_use]
    pub const fn errored(token: Token) -> Self {
        Self {
            token,
            ready: Interest::ERROR,
        }
    }

    /// Creates a hangup event.
    #[must_use]
    pub const fn hangup(token: Token) -> Self {
        Self {
            token,
            ready: Interest::HUP,
        }
    }

    /// Returns true if the source is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.ready.is_readable()
    }

    /// Returns true if the source is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.ready.is_writable()
    }

    /// Returns true if an error was reported.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.ready.is_error()
    }

    /// Returns true if the source reported hangup.
    #[must_use]
    pub const fn is_hangup(&self) -> bool {
        self.ready.is_hup()
    }
}

/// Container for I/O events returned by poll().
///
/// Re-use across poll() calls to avoid allocation.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::Events;
///
/// let mut events = Events::with_capacity(64);
/// // ... poll ...
/// for event in &events {
///     println!("Token {:?} is ready: {:?}", event.token, event.ready);
/// }
/// events.clear();
/// ```
#[derive(Debug, Default)]
pub struct Events {
    inner: SmallVec<[Event; 16]>,
    capacity: usize,
}

impl Events {
    /// Creates a new events buffer with the given capacity.
    ///
    /// The capacity is an initial allocation hint for event storage.
    /// The buffer may grow if more events are pushed.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: SmallVec::with_capacity(capacity),
            capacity,
        }
    }

    /// Clears all events, maintaining capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Pushes an event.
    ///
    /// The container will grow if necessary. Capacity limits should be enforced
    /// by the reactor's poll batch size, not by dropping events here (which
    /// would be fatal for edge-triggered notifications).
    pub(crate) fn push(&mut self, event: Event) {
        self.inner.push(event);
        // Track the logical poll batch capacity requested by the caller, not
        // SmallVec's inline backing capacity. Grow only when retained events
        // exceed that logical capacity.
        self.capacity = self.capacity.max(self.inner.len());
    }

    /// Returns the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if no events are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the current storage capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Iterates over events.
    pub fn iter(&self) -> std::slice::Iter<'_, Event> {
        self.inner.iter()
    }
}

impl<'a> IntoIterator for &'a Events {
    type Item = &'a Event;
    type IntoIter = std::slice::Iter<'a, Event>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for Events {
    type Item = Event;
    type IntoIter = smallvec::IntoIter<[Event; 16]>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

/// Stable identity for the reactor backend selected at runtime construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoReactorBackend {
    /// No reactor backend is active.
    Unavailable,
    /// Linux/Android io_uring backend.
    IoUring,
    /// Linux/Android epoll backend.
    Epoll,
    /// BSD-family kqueue backend.
    Kqueue,
    /// Windows I/O completion-port backend.
    Iocp,
    /// Browser event-loop backend.
    Browser,
    /// Explicitly injected reactor whose concrete backend is not known here.
    Injected,
}

impl IoReactorBackend {
    /// Returns the bounded-cardinality identifier used by diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::IoUring => "io_uring",
            Self::Epoll => "epoll",
            Self::Kqueue => "kqueue",
            Self::Iocp => "iocp",
            Self::Browser => "browser",
            Self::Injected => "injected",
        }
    }
}

/// Advanced io_uring capability governed by the runtime policy spine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IoUringCapability {
    /// Classic fixed registered buffers.
    FixedBuffers = 0,
    /// Provided-buffer groups.
    ProvidedGroups = 1,
    /// Ring-mapped provided buffers.
    MappedBufferRing = 2,
    /// Multishot accept.
    MultishotAccept = 3,
    /// Multishot receive.
    MultishotRecv = 4,
    /// Submission-queue polling.
    SqPoll = 5,
}

impl IoUringCapability {
    /// Every capability in stable artifact order.
    pub const ALL: [Self; 6] = [
        Self::FixedBuffers,
        Self::ProvidedGroups,
        Self::MappedBufferRing,
        Self::MultishotAccept,
        Self::MultishotRecv,
        Self::SqPoll,
    ];

    /// Returns the stable capability identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::FixedBuffers => "URING-CAP-FIXED-BUFFERS",
            Self::ProvidedGroups => "URING-CAP-PROVIDED-GROUPS",
            Self::MappedBufferRing => "URING-CAP-MAPPED-BUFFER-RING",
            Self::MultishotAccept => "URING-CAP-MULTISHOT-ACCEPT",
            Self::MultishotRecv => "URING-CAP-MULTISHOT-RECV",
            Self::SqPoll => "URING-CAP-SQPOLL",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Result state for a bounded io_uring capability probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoUringSupportState {
    /// The bounded operation probe completed successfully.
    Supported,
    /// The bounded operation probe classified the capability as unavailable.
    Unsupported,
    /// No authoritative operation probe ran.
    NotProbed,
}

impl IoUringSupportState {
    /// Returns the stable diagnostic identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::NotProbed => "NOT_PROBED",
        }
    }
}

/// Deterministic result of one bounded capability probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoUringProbeOutcome {
    /// The bounded probe completed successfully.
    Supported,
    /// The required operation is not supported.
    Unsupported,
    /// Host policy or permissions rejected the probe.
    Permission,
    /// A bounded resource operation failed.
    Resource,
    /// The probe failed without a narrower classification.
    Error,
}

/// Typed request and force-off policy for advanced io_uring capabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct IoUringCapabilityPolicy {
    requested: u8,
    forced_off: u8,
}

impl IoUringCapabilityPolicy {
    /// Builds a policy with no advanced capabilities requested.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requested: 0,
            forced_off: 0,
        }
    }

    const fn bit(capability: IoUringCapability) -> u8 {
        1 << capability.index()
    }

    /// Sets whether one capability is requested.
    #[must_use]
    pub const fn with_requested(mut self, capability: IoUringCapability, requested: bool) -> Self {
        let bit = Self::bit(capability);
        if requested {
            self.requested |= bit;
        } else {
            self.requested &= !bit;
        }
        self
    }

    /// Sets deterministic force-off policy for one capability.
    #[must_use]
    pub const fn with_forced_off(
        mut self,
        capability: IoUringCapability,
        forced_off: bool,
    ) -> Self {
        let bit = Self::bit(capability);
        if forced_off {
            self.forced_off |= bit;
        } else {
            self.forced_off &= !bit;
        }
        self
    }

    /// Returns whether one capability is requested.
    #[must_use]
    pub const fn is_requested(self, capability: IoUringCapability) -> bool {
        self.requested & Self::bit(capability) != 0
    }

    /// Returns whether one capability is forced off.
    #[must_use]
    pub const fn is_forced_off(self, capability: IoUringCapability) -> bool {
        self.forced_off & Self::bit(capability) != 0
    }

    /// Resolves one deterministic injected probe outcome.
    #[must_use]
    pub const fn decide(
        self,
        capability: IoUringCapability,
        probe: Option<IoUringProbeOutcome>,
    ) -> IoUringCapabilityDecision {
        if !self.is_requested(capability) {
            return IoUringCapabilityDecision::not_requested(capability);
        }
        if self.is_forced_off(capability) {
            return IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::NotProbed,
                false,
                IoUringFallbackReason::ForcedOff,
            );
        }

        match probe {
            Some(IoUringProbeOutcome::Supported) => IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::Supported,
                true,
                IoUringFallbackReason::None,
            ),
            Some(IoUringProbeOutcome::Unsupported) => IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::Unsupported,
                false,
                IoUringFallbackReason::OperationUnsupported,
            ),
            Some(IoUringProbeOutcome::Permission) => IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::NotProbed,
                false,
                IoUringFallbackReason::Permission,
            ),
            Some(IoUringProbeOutcome::Resource) => IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::NotProbed,
                false,
                IoUringFallbackReason::Resource,
            ),
            Some(IoUringProbeOutcome::Error) | None => IoUringCapabilityDecision::new(
                capability,
                true,
                IoUringSupportState::NotProbed,
                false,
                IoUringFallbackReason::ProbeError,
            ),
        }
    }
}

/// Bounded reason explaining why an io_uring capability is inactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoUringFallbackReason {
    /// Requested, supported, and active.
    None,
    /// The capability was not requested.
    NotRequested,
    /// The build excludes the optional feature.
    FeatureDisabled,
    /// The target has no supported backend.
    TargetUnsupported,
    /// Typed injected policy disabled the capability.
    ForcedOff,
    /// Configured ring construction failed.
    RingCreate,
    /// Preferred and fallback reactor construction both failed.
    ReactorUnavailable,
    /// The required operation is unavailable.
    OperationUnsupported,
    /// Host policy or permissions rejected the mode.
    Permission,
    /// Bounded registration or allocation failed.
    Resource,
    /// The bounded probe failed without a narrower classification.
    ProbeError,
    /// A prerequisite capability is inactive.
    Dependency,
    /// Evidence classified the candidate as no-win.
    NoWin,
    /// An inconsistent or unknown tuple failed closed.
    Unknown,
}

impl IoUringFallbackReason {
    /// Returns the stable fallback identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::None => "URING-FB-NONE",
            Self::NotRequested => "URING-FB-NOT-REQUESTED",
            Self::FeatureDisabled => "URING-FB-FEATURE-DISABLED",
            Self::TargetUnsupported => "URING-FB-TARGET-UNSUPPORTED",
            Self::ForcedOff => "URING-FB-FORCED-OFF",
            Self::RingCreate => "URING-FB-RING-CREATE",
            Self::ReactorUnavailable => "URING-FB-REACTOR-UNAVAILABLE",
            Self::OperationUnsupported => "URING-FB-OP-UNSUPPORTED",
            Self::Permission => "URING-FB-PERMISSION",
            Self::Resource => "URING-FB-RESOURCE",
            Self::ProbeError => "URING-FB-PROBE-ERROR",
            Self::Dependency => "URING-FB-DEPENDENCY",
            Self::NoWin => "URING-FB-NO-WIN",
            Self::Unknown => "URING-FB-UNKNOWN",
        }
    }
}

/// Immutable, normalized decision for one io_uring capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IoUringCapabilityDecision {
    capability: IoUringCapability,
    requested: bool,
    supported: IoUringSupportState,
    active: bool,
    fallback_reason: IoUringFallbackReason,
}

impl IoUringCapabilityDecision {
    /// Builds a decision and fails inconsistent tuples closed to `URING-FB-UNKNOWN`.
    #[must_use]
    pub const fn new(
        capability: IoUringCapability,
        requested: bool,
        supported: IoUringSupportState,
        active: bool,
        fallback_reason: IoUringFallbackReason,
    ) -> Self {
        let valid = match fallback_reason {
            IoUringFallbackReason::None => {
                requested && matches!(supported, IoUringSupportState::Supported) && active
            }
            IoUringFallbackReason::NotRequested => {
                !requested && matches!(supported, IoUringSupportState::NotProbed) && !active
            }
            IoUringFallbackReason::TargetUnsupported
            | IoUringFallbackReason::OperationUnsupported => {
                requested && matches!(supported, IoUringSupportState::Unsupported) && !active
            }
            IoUringFallbackReason::NoWin => {
                requested && matches!(supported, IoUringSupportState::Supported) && !active
            }
            IoUringFallbackReason::FeatureDisabled
            | IoUringFallbackReason::ForcedOff
            | IoUringFallbackReason::RingCreate
            | IoUringFallbackReason::ReactorUnavailable
            | IoUringFallbackReason::Permission
            | IoUringFallbackReason::Resource
            | IoUringFallbackReason::ProbeError
            | IoUringFallbackReason::Dependency => {
                requested && matches!(supported, IoUringSupportState::NotProbed) && !active
            }
            IoUringFallbackReason::Unknown => !active,
        };

        Self {
            capability,
            requested,
            supported,
            active: if valid { active } else { false },
            fallback_reason: if valid {
                fallback_reason
            } else {
                IoUringFallbackReason::Unknown
            },
        }
    }

    /// Builds the default not-requested decision.
    #[must_use]
    pub const fn not_requested(capability: IoUringCapability) -> Self {
        Self::new(
            capability,
            false,
            IoUringSupportState::NotProbed,
            false,
            IoUringFallbackReason::NotRequested,
        )
    }

    /// Capability identity.
    #[must_use]
    pub const fn capability(self) -> IoUringCapability {
        self.capability
    }

    /// Whether policy requested the capability.
    #[must_use]
    pub const fn requested(self) -> bool {
        self.requested
    }

    /// Authoritative support state.
    #[must_use]
    pub const fn supported(self) -> IoUringSupportState {
        self.supported
    }

    /// Whether the capability is active.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }

    /// Stable inactive or success reason.
    #[must_use]
    pub const fn fallback_reason(self) -> IoUringFallbackReason {
        self.fallback_reason
    }
}

/// Immutable reactor-backend and io_uring capability snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoReactorCapabilitySnapshot {
    backend: IoReactorBackend,
    selection_fallback: Option<IoUringFallbackReason>,
    decisions: [IoUringCapabilityDecision; 6],
}

impl IoReactorCapabilitySnapshot {
    /// Resolves a complete deterministic snapshot from typed policy and probe outcomes.
    #[must_use]
    pub fn from_policy(
        backend: IoReactorBackend,
        selection_fallback: Option<IoUringFallbackReason>,
        policy: IoUringCapabilityPolicy,
        probes: [Option<IoUringProbeOutcome>; 6],
    ) -> Self {
        let decisions = IoUringCapability::ALL
            .map(|capability| policy.decide(capability, probes[capability.index()]));
        Self {
            backend,
            selection_fallback,
            decisions,
        }
    }

    fn unavailable(
        backend: IoReactorBackend,
        selection_fallback: Option<IoUringFallbackReason>,
        policy: IoUringCapabilityPolicy,
        reason: IoUringFallbackReason,
    ) -> Self {
        let decisions = IoUringCapability::ALL.map(|capability| {
            if !policy.is_requested(capability) {
                return IoUringCapabilityDecision::not_requested(capability);
            }
            if policy.is_forced_off(capability) {
                return policy.decide(capability, None);
            }

            let supported = if matches!(reason, IoUringFallbackReason::TargetUnsupported) {
                IoUringSupportState::Unsupported
            } else {
                IoUringSupportState::NotProbed
            };
            IoUringCapabilityDecision::new(capability, true, supported, false, reason)
        });
        Self {
            backend,
            selection_fallback,
            decisions,
        }
    }

    /// Builds a snapshot whose advanced capabilities are not requested.
    #[must_use]
    pub const fn not_requested(
        backend: IoReactorBackend,
        selection_fallback: Option<IoUringFallbackReason>,
    ) -> Self {
        Self {
            backend,
            selection_fallback,
            decisions: [
                IoUringCapabilityDecision::not_requested(IoUringCapability::FixedBuffers),
                IoUringCapabilityDecision::not_requested(IoUringCapability::ProvidedGroups),
                IoUringCapabilityDecision::not_requested(IoUringCapability::MappedBufferRing),
                IoUringCapabilityDecision::not_requested(IoUringCapability::MultishotAccept),
                IoUringCapabilityDecision::not_requested(IoUringCapability::MultishotRecv),
                IoUringCapabilityDecision::not_requested(IoUringCapability::SqPoll),
            ],
        }
    }

    /// Builds a snapshot for an explicitly injected reactor.
    #[must_use]
    pub const fn injected() -> Self {
        Self::not_requested(IoReactorBackend::Injected, None)
    }

    /// Builds the neutral receipt for a runtime configured without a reactor.
    #[must_use]
    pub const fn no_reactor() -> Self {
        Self::not_requested(IoReactorBackend::Unavailable, None)
    }

    /// Builds the terminal receipt for an exhausted platform reactor chain.
    #[must_use]
    pub(crate) fn reactor_unavailable(policy: IoUringCapabilityPolicy) -> Self {
        Self::unavailable(
            IoReactorBackend::Unavailable,
            Some(IoUringFallbackReason::ReactorUnavailable),
            policy,
            IoUringFallbackReason::ReactorUnavailable,
        )
    }

    /// Selected backend.
    #[must_use]
    pub const fn backend(self) -> IoReactorBackend {
        self.backend
    }

    /// Why platform selection fell back before choosing `backend`.
    #[must_use]
    pub const fn selection_fallback(self) -> Option<IoUringFallbackReason> {
        self.selection_fallback
    }

    /// Stable decision for one advanced capability.
    #[must_use]
    pub const fn decision(self, capability: IoUringCapability) -> IoUringCapabilityDecision {
        self.decisions[capability.index()]
    }

    /// All decisions in stable capability order.
    #[must_use]
    pub const fn decisions(self) -> [IoUringCapabilityDecision; 6] {
        self.decisions
    }
}

/// Platform-agnostic reactor for I/O event notification.
///
/// A reactor provides the core I/O multiplexing functionality for an async runtime.
/// It monitors registered I/O sources (sockets, files, pipes) for readiness events
/// and notifies the runtime when sources become readable, writable, or encounter errors.
///
/// # Platform Backends
///
/// | Platform | Backend | Module |
/// |----------|---------|--------|
/// | Linux | epoll | `epoll.rs` |
/// | macOS/BSD | kqueue | `kqueue.rs` |
/// | Windows | IOCP | `windows.rs` |
/// | Testing | virtual | `lab.rs` |
///
/// # Thread Safety
///
/// Reactor implementations must be thread-safe (`Send + Sync`). Typically the reactor
/// is shared across the runtime via `Arc<dyn Reactor>`. All methods use interior
/// mutability and are safe to call from multiple threads concurrently.
///
/// # Cancellation Safety
///
/// When a [`Registration`] is dropped, it automatically deregisters from the reactor.
/// This ensures cancel-safety: cancelled tasks don't leave dangling registrations that
/// could cause spurious wakeups or resource leaks.
///
/// # Oneshot vs Edge Triggering
///
/// The Unix reactor backends default to oneshot delivery so the runtime can use
/// a single explicit re-arm path through `modify()`.
///
/// Callers can request edge-triggered delivery with
/// [`Interest::EDGE_TRIGGERED`]. In edge-triggered mode, readable or writable
/// state must be fully drained before waiting for the next event.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::reactor::{Reactor, Interest, Events};
/// use std::time::Duration;
///
/// fn poll_loop(reactor: &dyn Reactor) -> io::Result<()> {
///     let mut events = Events::with_capacity(64);
///
///     loop {
///         // Block until events or timeout
///         let n = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
///
///         for event in &events {
///             if event.is_readable() {
///                 // Handle readable source
///             }
///             if event.is_writable() {
///                 // Handle writable source
///             }
///         }
///
///         events.clear();
///     }
/// }
/// ```
pub trait Reactor: Send + Sync {
    /// Returns the immutable backend and capability snapshot.
    ///
    /// Explicitly injected reactors default to the bounded `injected` identity.
    /// Platform factory wrappers override this with their construction receipt.
    #[must_use]
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        IoReactorCapabilitySnapshot::injected()
    }

    /// Registers interest in I/O events for a source.
    ///
    /// Creates a new registration for the given source, associating it with the
    /// provided token and interest flags. The token will be included in any events
    /// generated for this source.
    ///
    /// # Arguments
    ///
    /// * `source` - The I/O source to register (must implement [`Source`])
    /// * `token` - A unique token to identify this registration in events
    /// * `interest` - The events to monitor (readable, writable, error, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails:
    /// - `io::ErrorKind::AlreadyExists` - Source is already registered
    /// - `io::ErrorKind::InvalidInput` - Source fd/handle is invalid
    /// - `io::ErrorKind::OutOfMemory` - Too many registrations
    /// - Platform-specific errors from epoll_ctl/kevent/CreateIoCompletionPort
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_ADD)`
    /// - **macOS**: Calls `kevent()` with `EV_ADD`
    /// - **Windows**: Associates with IOCP
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()>;

    /// Modifies the interest set for an existing registration.
    ///
    /// Changes which events are monitored for a previously registered source.
    /// This is more efficient than deregistering and re-registering.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifying the registration
    /// * `interest` - The new interest flags to monitor
    ///
    /// # Errors
    ///
    /// Returns an error if modification fails:
    /// - `io::ErrorKind::NotFound` - Token not registered
    /// - `io::ErrorKind::InvalidInput` - Invalid interest flags
    /// - Platform-specific errors
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_MOD)`
    /// - **macOS**: Calls `kevent()` with `EV_ADD` (idempotent)
    /// - **Windows**: Re-posts completion notification
    fn modify(&self, token: Token, interest: Interest) -> io::Result<()>;

    /// Deregisters a previously registered source by token.
    ///
    /// Removes the source from the reactor's set of monitored sources.
    /// After deregistration, no more events will be generated for this source.
    ///
    /// This method is called automatically by [`Registration::drop()`].
    /// Direct calls are only needed for explicit deregistration with error handling.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifying the registration to remove
    ///
    /// # Errors
    ///
    /// Returns an error if deregistration fails:
    /// - `io::ErrorKind::NotFound` - Token not registered
    /// - Platform-specific errors
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_ctl(EPOLL_CTL_DEL)`
    /// - **macOS**: Calls `kevent()` with `EV_DELETE`
    /// - **Windows**: Disassociates from IOCP
    fn deregister(&self, token: Token) -> io::Result<()>;

    /// Polls for I/O events, blocking up to `timeout`.
    ///
    /// Waits for I/O events on registered sources and fills the events buffer
    /// with any that occur. This is the main driver method for an async runtime.
    ///
    /// # Arguments
    ///
    /// * `events` - Buffer to store received events (cleared before use)
    /// * `timeout` - Maximum time to wait:
    ///   - `None`: Block indefinitely until an event occurs
    ///   - `Some(Duration::ZERO)`: Non-blocking poll, return immediately
    ///   - `Some(d)`: Block up to duration `d`
    ///
    /// # Returns
    ///
    /// The number of events placed in `events`. Returns `Ok(0)` on timeout
    /// with no events.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails:
    /// - `io::ErrorKind::Interrupted` - Signal interrupted the wait
    /// - Platform-specific errors from epoll_wait/kevent/GetQueuedCompletionStatus
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Calls `epoll_wait()`
    /// - **macOS**: Calls `kevent()`
    /// - **Windows**: Calls `GetQueuedCompletionStatusEx()`
    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize>;

    /// Wakes the reactor from a blocking [`poll()`](Self::poll) call.
    ///
    /// This method signals the reactor to return from poll() early, even if
    /// no I/O events are pending. It's used when:
    /// - New tasks are spawned and need to be scheduled
    /// - Timers fire and need to be processed
    /// - The runtime is shutting down
    ///
    /// Must be safe to call from any thread, including threads not involved
    /// in the reactor's poll loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the wake signal cannot be sent:
    /// - Platform-specific errors from eventfd/pipe/PostQueuedCompletionStatus
    ///
    /// # Implementation Notes
    ///
    /// - **Linux**: Write to eventfd registered with the epoll
    /// - **macOS**: Write to a self-pipe or use EVFILT_USER
    /// - **Windows**: Call `PostQueuedCompletionStatus()`
    ///
    /// Implementations should coalesce multiple wake() calls into a single
    /// wakeup to avoid thundering herd issues.
    fn wake(&self) -> io::Result<()>;

    /// Returns the number of active registrations.
    ///
    /// Useful for diagnostics and capacity planning.
    fn registration_count(&self) -> usize;

    /// Returns `true` if no sources are currently registered.
    ///
    /// Equivalent to `self.registration_count() == 0`, but may be more efficient.
    fn is_empty(&self) -> bool {
        self.registration_count() == 0
    }
}

struct ObservedReactor {
    inner: Arc<dyn Reactor>,
    snapshot: IoReactorCapabilitySnapshot,
}

impl ObservedReactor {
    fn wrap(inner: Arc<dyn Reactor>, snapshot: IoReactorCapabilitySnapshot) -> Arc<dyn Reactor> {
        Arc::new(Self { inner, snapshot })
    }
}

impl Reactor for ObservedReactor {
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        self.snapshot
    }

    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.inner.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        self.inner.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        self.inner.wake()
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

/// Create the best available reactor for the current platform.
///
/// This is a convenience factory that selects the most capable backend
/// supported by the build and host environment.
///
/// # Selection Order
/// - **Linux/Android**: io_uring (if enabled and available), otherwise epoll
/// - **macOS/BSD**: kqueue
/// - **Windows**: IOCP
///
/// # Errors
/// Returns an error if no supported reactor backend can be created.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn create_reactor() -> io::Result<Arc<dyn Reactor>> {
    create_reactor_with_policy(IoUringCapabilityPolicy::default())
}

/// Creates the Linux/Android reactor with typed advanced-capability policy.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn create_reactor_with_policy(policy: IoUringCapabilityPolicy) -> io::Result<Arc<dyn Reactor>> {
    #[cfg(feature = "io-uring")]
    {
        if let Ok(reactor) = IoUringReactor::new() {
            let probes = reactor.capability_probes(policy);
            return Ok(ObservedReactor::wrap(
                Arc::new(reactor),
                IoReactorCapabilitySnapshot::from_policy(
                    IoReactorBackend::IoUring,
                    None,
                    policy,
                    probes,
                ),
            ));
        }

        Ok(ObservedReactor::wrap(
            Arc::new(EpollReactor::new()?),
            IoReactorCapabilitySnapshot::unavailable(
                IoReactorBackend::Epoll,
                Some(IoUringFallbackReason::RingCreate),
                policy,
                IoUringFallbackReason::RingCreate,
            ),
        ))
    }

    #[cfg(not(feature = "io-uring"))]
    Ok(ObservedReactor::wrap(
        Arc::new(EpollReactor::new()?),
        IoReactorCapabilitySnapshot::unavailable(
            IoReactorBackend::Epoll,
            Some(IoUringFallbackReason::FeatureDisabled),
            policy,
            IoUringFallbackReason::FeatureDisabled,
        ),
    ))
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
/// Creates the default reactor implementation for the current target.
pub fn create_reactor() -> io::Result<Arc<dyn Reactor>> {
    create_reactor_with_policy(IoUringCapabilityPolicy::default())
}

/// Creates the BSD-family reactor with typed advanced-capability policy.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn create_reactor_with_policy(policy: IoUringCapabilityPolicy) -> io::Result<Arc<dyn Reactor>> {
    Ok(ObservedReactor::wrap(
        Arc::new(KqueueReactor::new()?),
        IoReactorCapabilitySnapshot::unavailable(
            IoReactorBackend::Kqueue,
            None,
            policy,
            IoUringFallbackReason::TargetUnsupported,
        ),
    ))
}

#[cfg(target_os = "windows")]
/// Creates the default reactor implementation for the current target.
pub fn create_reactor() -> io::Result<Arc<dyn Reactor>> {
    create_reactor_with_policy(IoUringCapabilityPolicy::default())
}

/// Creates the Windows reactor with typed advanced-capability policy.
#[cfg(target_os = "windows")]
pub fn create_reactor_with_policy(policy: IoUringCapabilityPolicy) -> io::Result<Arc<dyn Reactor>> {
    Ok(ObservedReactor::wrap(
        Arc::new(IocpReactor::new()?),
        IoReactorCapabilitySnapshot::unavailable(
            IoReactorBackend::Iocp,
            None,
            policy,
            IoUringFallbackReason::TargetUnsupported,
        ),
    ))
}

#[cfg(target_arch = "wasm32")]
/// Creates the default reactor implementation for the current target.
pub fn create_reactor() -> io::Result<Arc<dyn Reactor>> {
    create_reactor_with_policy(IoUringCapabilityPolicy::default())
}

/// Creates the browser reactor with typed advanced-capability policy.
#[cfg(target_arch = "wasm32")]
pub fn create_reactor_with_policy(policy: IoUringCapabilityPolicy) -> io::Result<Arc<dyn Reactor>> {
    Ok(ObservedReactor::wrap(
        Arc::new(BrowserReactor::default()),
        IoReactorCapabilitySnapshot::unavailable(
            IoReactorBackend::Browser,
            None,
            policy,
            IoUringFallbackReason::TargetUnsupported,
        ),
    ))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "windows",
    target_arch = "wasm32"
)))]
/// Creates the default reactor implementation for the current target.
pub fn create_reactor() -> io::Result<Arc<dyn Reactor>> {
    create_reactor_with_policy(IoUringCapabilityPolicy::default())
}

/// Returns unsupported for targets without a reactor backend.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "windows",
    target_arch = "wasm32"
)))]
pub fn create_reactor_with_policy(
    _policy: IoUringCapabilityPolicy,
) -> io::Result<Arc<dyn Reactor>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no supported reactor backend for this platform",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "windows"
    ))]
    fn create_reactor_factory() {
        init_test("create_reactor_factory");
        let reactor = create_reactor().expect("failed to create reactor");
        let snapshot = reactor.capability_snapshot();
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        assert_ne!(snapshot.backend(), IoReactorBackend::Injected);
        for capability in IoUringCapability::ALL {
            assert_eq!(
                snapshot.decision(capability),
                IoUringCapabilityDecision::not_requested(capability)
            );
        }
        crate::test_complete!("create_reactor_factory");
    }

    #[test]
    fn io_uring_capability_ids_and_fallback_ids_are_stable() {
        assert_eq!(IoReactorBackend::Unavailable.as_str(), "unavailable");
        assert_eq!(
            IoUringCapability::ALL.map(IoUringCapability::id),
            [
                "URING-CAP-FIXED-BUFFERS",
                "URING-CAP-PROVIDED-GROUPS",
                "URING-CAP-MAPPED-BUFFER-RING",
                "URING-CAP-MULTISHOT-ACCEPT",
                "URING-CAP-MULTISHOT-RECV",
                "URING-CAP-SQPOLL",
            ]
        );
        assert_eq!(IoUringFallbackReason::None.id(), "URING-FB-NONE");
        assert_eq!(
            IoUringFallbackReason::NotRequested.id(),
            "URING-FB-NOT-REQUESTED"
        );
        assert_eq!(
            IoUringFallbackReason::FeatureDisabled.id(),
            "URING-FB-FEATURE-DISABLED"
        );
        assert_eq!(
            IoUringFallbackReason::TargetUnsupported.id(),
            "URING-FB-TARGET-UNSUPPORTED"
        );
        assert_eq!(IoUringFallbackReason::ForcedOff.id(), "URING-FB-FORCED-OFF");
        assert_eq!(
            IoUringFallbackReason::RingCreate.id(),
            "URING-FB-RING-CREATE"
        );
        assert_eq!(
            IoUringFallbackReason::ReactorUnavailable.id(),
            "URING-FB-REACTOR-UNAVAILABLE"
        );
        assert_eq!(
            IoUringFallbackReason::OperationUnsupported.id(),
            "URING-FB-OP-UNSUPPORTED"
        );
        assert_eq!(
            IoUringFallbackReason::Permission.id(),
            "URING-FB-PERMISSION"
        );
        assert_eq!(IoUringFallbackReason::Resource.id(), "URING-FB-RESOURCE");
        assert_eq!(
            IoUringFallbackReason::ProbeError.id(),
            "URING-FB-PROBE-ERROR"
        );
        assert_eq!(
            IoUringFallbackReason::Dependency.id(),
            "URING-FB-DEPENDENCY"
        );
        assert_eq!(IoUringFallbackReason::NoWin.id(), "URING-FB-NO-WIN");
        assert_eq!(IoUringFallbackReason::Unknown.id(), "URING-FB-UNKNOWN");
    }

    #[test]
    fn terminal_reactor_snapshot_preserves_policy_without_probing() {
        let policy = IoUringCapabilityPolicy::new()
            .with_requested(IoUringCapability::FixedBuffers, true)
            .with_requested(IoUringCapability::SqPoll, true)
            .with_forced_off(IoUringCapability::SqPoll, true);

        let snapshot = IoReactorCapabilitySnapshot::reactor_unavailable(policy);
        assert_eq!(snapshot.backend(), IoReactorBackend::Unavailable);
        assert_eq!(
            snapshot.selection_fallback(),
            Some(IoUringFallbackReason::ReactorUnavailable)
        );

        let requested = snapshot.decision(IoUringCapability::FixedBuffers);
        assert!(requested.requested());
        assert_eq!(requested.supported(), IoUringSupportState::NotProbed);
        assert!(!requested.active());
        assert_eq!(
            requested.fallback_reason(),
            IoUringFallbackReason::ReactorUnavailable
        );

        let forced_off = snapshot.decision(IoUringCapability::SqPoll);
        assert!(forced_off.requested());
        assert_eq!(forced_off.supported(), IoUringSupportState::NotProbed);
        assert!(!forced_off.active());
        assert_eq!(
            forced_off.fallback_reason(),
            IoUringFallbackReason::ForcedOff
        );

        let unrequested = snapshot.decision(IoUringCapability::MultishotAccept);
        assert!(!unrequested.requested());
        assert_eq!(unrequested.supported(), IoUringSupportState::NotProbed);
        assert!(!unrequested.active());
        assert_eq!(
            unrequested.fallback_reason(),
            IoUringFallbackReason::NotRequested
        );
    }

    #[test]
    fn io_uring_capability_decision_fails_inconsistent_tuples_closed() {
        let capability = IoUringCapability::FixedBuffers;
        let valid = IoUringCapabilityDecision::new(
            capability,
            true,
            IoUringSupportState::Supported,
            true,
            IoUringFallbackReason::None,
        );
        assert!(valid.active());
        assert_eq!(valid.fallback_reason(), IoUringFallbackReason::None);

        let invalid = IoUringCapabilityDecision::new(
            capability,
            false,
            IoUringSupportState::Supported,
            true,
            IoUringFallbackReason::None,
        );
        assert_eq!(invalid.capability(), capability);
        assert!(!invalid.requested());
        assert_eq!(invalid.supported(), IoUringSupportState::Supported);
        assert!(!invalid.active());
        assert_eq!(invalid.fallback_reason(), IoUringFallbackReason::Unknown);
    }

    #[test]
    fn io_uring_capability_policy_precedence_is_deterministic() {
        let requested = IoUringCapability::FixedBuffers;
        let unrequested = IoUringCapability::ProvidedGroups;
        let policy = IoUringCapabilityPolicy::new()
            .with_requested(requested, true)
            .with_forced_off(requested, true);

        let forced = policy.decide(requested, Some(IoUringProbeOutcome::Supported));
        assert!(forced.requested());
        assert_eq!(forced.supported(), IoUringSupportState::NotProbed);
        assert!(!forced.active());
        assert_eq!(forced.fallback_reason(), IoUringFallbackReason::ForcedOff);

        let skipped = policy.decide(unrequested, Some(IoUringProbeOutcome::Supported));
        assert_eq!(
            skipped,
            IoUringCapabilityDecision::not_requested(unrequested)
        );

        let active = IoUringCapabilityPolicy::new()
            .with_requested(requested, true)
            .decide(requested, Some(IoUringProbeOutcome::Supported));
        assert!(active.active());
        assert_eq!(active.fallback_reason(), IoUringFallbackReason::None);
    }

    // Event tests
    #[test]
    fn event_new() {
        init_test("event_new");
        let event = Event::new(Token::new(42), Interest::READABLE | Interest::WRITABLE);
        crate::assert_with_log!(event.token.0 == 42, "token id", 42usize, event.token.0);
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_new");
    }

    #[test]
    fn event_readable() {
        init_test("event_readable");
        let event = Event::readable(Token::new(1));
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_readable");
    }

    #[test]
    fn event_writable() {
        init_test("event_writable");
        let event = Event::writable(Token::new(2));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            event.is_writable(),
            "writable flag",
            true,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_writable");
    }

    #[test]
    fn event_errored() {
        init_test("event_errored");
        let event = Event::errored(Token::new(3));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(
            !event.is_hangup(),
            "hangup flag unset",
            false,
            event.is_hangup()
        );
        crate::test_complete!("event_errored");
    }

    #[test]
    fn event_hangup() {
        init_test("event_hangup");
        let event = Event::hangup(Token::new(4));
        crate::assert_with_log!(
            !event.is_readable(),
            "readable flag unset",
            false,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(
            !event.is_error(),
            "error flag unset",
            false,
            event.is_error()
        );
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_hangup");
    }

    #[test]
    fn event_combined_flags() {
        init_test("event_combined_flags");
        let event = Event::new(
            Token::new(5),
            Interest::READABLE | Interest::ERROR | Interest::HUP,
        );
        crate::assert_with_log!(
            event.is_readable(),
            "readable flag",
            true,
            event.is_readable()
        );
        crate::assert_with_log!(
            !event.is_writable(),
            "writable flag unset",
            false,
            event.is_writable()
        );
        crate::assert_with_log!(event.is_error(), "error flag", true, event.is_error());
        crate::assert_with_log!(event.is_hangup(), "hangup flag", true, event.is_hangup());
        crate::test_complete!("event_combined_flags");
    }

    // Events container tests
    #[test]
    fn events_with_capacity() {
        init_test("events_with_capacity");
        let events = Events::with_capacity(64);
        crate::assert_with_log!(
            events.capacity() == 64,
            "capacity",
            64usize,
            events.capacity()
        );
        crate::assert_with_log!(events.is_empty(), "len", 0usize, events.len());
        crate::assert_with_log!(events.is_empty(), "is_empty", true, events.is_empty());
        crate::test_complete!("events_with_capacity");
    }

    #[test]
    fn events_push_and_iterate() {
        init_test("events_push_and_iterate");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));
        events.push(Event::errored(Token::new(3)));

        crate::assert_with_log!(events.len() == 3, "len", 3usize, events.len());
        crate::assert_with_log!(!events.is_empty(), "not empty", false, events.is_empty());

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3],
            "tokens order",
            vec![1, 2, 3],
            tokens
        );
        crate::test_complete!("events_push_and_iterate");
    }

    #[test]
    fn events_clear() {
        init_test("events_clear");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));

        crate::assert_with_log!(events.len() == 2, "len before clear", 2usize, events.len());
        events.clear();
        crate::assert_with_log!(events.is_empty(), "len after clear", 0usize, events.len());
        crate::assert_with_log!(
            events.is_empty(),
            "empty after clear",
            true,
            events.is_empty()
        );
        // Capacity is maintained
        crate::assert_with_log!(
            events.capacity() == 10,
            "capacity maintained",
            10usize,
            events.capacity()
        );
        crate::test_complete!("events_clear");
    }

    #[test]
    fn events_grow_beyond_capacity() {
        init_test("events_grow_beyond_capacity");
        let mut events = Events::with_capacity(3);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::readable(Token::new(2)));
        events.push(Event::readable(Token::new(3)));
        // These should be retained (growing the vector)
        events.push(Event::readable(Token::new(4)));
        events.push(Event::readable(Token::new(5)));

        crate::assert_with_log!(events.len() == 5, "len grew", 5usize, events.len());

        // Capacity should track actual backing storage growth.
        crate::assert_with_log!(
            events.capacity() >= events.len(),
            "capacity tracks growth",
            true,
            events.capacity()
        );

        let tokens: Vec<usize> = events.iter().map(|e| e.token.0).collect();
        crate::assert_with_log!(
            tokens == vec![1, 2, 3, 4, 5],
            "all tokens retained",
            vec![1, 2, 3, 4, 5],
            tokens
        );
        crate::test_complete!("events_grow_beyond_capacity");
    }

    #[test]
    fn events_into_iter_ref() {
        init_test("events_into_iter_ref");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let mut count = 0;
        for event in &events {
            let ok = event.is_readable() || event.is_writable();
            crate::assert_with_log!(ok, "event readable or writable", true, ok);
            count += 1;
        }
        crate::assert_with_log!(count == 2, "iter count", 2usize, count);
        crate::test_complete!("events_into_iter_ref");
    }

    #[test]
    fn events_into_iter_owned() {
        init_test("events_into_iter_owned");
        let mut events = Events::with_capacity(10);
        events.push(Event::readable(Token::new(1)));
        events.push(Event::writable(Token::new(2)));

        let collected: Vec<Event> = events.into_iter().collect();
        crate::assert_with_log!(
            collected.len() == 2,
            "collected len",
            2usize,
            collected.len()
        );
        crate::assert_with_log!(
            collected[0].is_readable(),
            "first readable",
            true,
            collected[0].is_readable()
        );
        crate::assert_with_log!(
            collected[1].is_writable(),
            "second writable",
            true,
            collected[1].is_writable()
        );
        crate::test_complete!("events_into_iter_owned");
    }

    #[test]
    fn events_zero_capacity() {
        init_test("events_zero_capacity");
        let mut events = Events::with_capacity(0);
        crate::assert_with_log!(
            events.capacity() == 0,
            "capacity zero",
            0usize,
            events.capacity()
        );
        crate::assert_with_log!(events.is_empty(), "len zero", 0usize, events.len());

        // Should grow dynamically despite initial capacity of 0
        events.push(Event::readable(Token::new(1)));
        crate::assert_with_log!(events.len() == 1, "len grew", 1usize, events.len());
        crate::test_complete!("events_zero_capacity");
    }

    // Token tests
    #[test]
    fn token_new() {
        init_test("token_new");
        let token = Token::new(123);
        crate::assert_with_log!(token.0 == 123, "token id", 123usize, token.0);
        crate::test_complete!("token_new");
    }

    #[test]
    fn token_equality() {
        init_test("token_equality");
        let t1 = Token::new(1);
        let t2 = Token::new(1);
        let t3 = Token::new(2);

        crate::assert_with_log!(t1 == t2, "t1 == t2", t2, t1);
        crate::assert_with_log!(t1 != t3, "t1 != t3", true, t1 != t3);
        crate::test_complete!("token_equality");
    }

    #[test]
    fn token_ordering() {
        init_test("token_ordering");
        let t1 = Token::new(1);
        let t2 = Token::new(2);

        crate::assert_with_log!(t1 < t2, "t1 < t2", true, t1 < t2);
        crate::assert_with_log!(t2 > t1, "t2 > t1", true, t2 > t1);
        crate::test_complete!("token_ordering");
    }

    // ============================================================
    // Cross-reactor trait compliance tests
    //
    // Verify that all Reactor implementations satisfy the same
    // behavioral contract through the trait interface.
    // ============================================================

    /// Compile-time assertion that a reactor type is Send + Sync + Reactor.
    fn assert_reactor_trait_bounds<R: Reactor + Send + Sync>() {}

    #[test]
    fn reactor_trait_bounds_epoll() {
        init_test("reactor_trait_bounds_epoll");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_reactor_trait_bounds::<super::EpollReactor>();
        crate::test_complete!("reactor_trait_bounds_epoll");
    }

    #[test]
    fn reactor_trait_bounds_lab() {
        init_test("reactor_trait_bounds_lab");
        assert_reactor_trait_bounds::<super::LabReactor>();
        crate::test_complete!("reactor_trait_bounds_lab");
    }

    #[test]
    fn reactor_trait_bounds_browser() {
        init_test("reactor_trait_bounds_browser");
        assert_reactor_trait_bounds::<super::BrowserReactor>();
        crate::test_complete!("reactor_trait_bounds_browser");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn reactor_trait_bounds_io_uring() {
        init_test("reactor_trait_bounds_io_uring");
        assert_reactor_trait_bounds::<super::IoUringReactor>();
        crate::test_complete!("reactor_trait_bounds_io_uring");
    }

    /// Run a common compliance check against any Reactor implementation.
    /// Verifies: starts empty, registration_count, is_empty, wake succeeds.
    fn compliance_check_empty_state(reactor: &dyn Reactor, name: &str) {
        crate::assert_with_log!(
            reactor.is_empty(),
            &format!("{name} starts empty"),
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            &format!("{name} starts with zero registrations"),
            0usize,
            reactor.registration_count()
        );
    }

    fn compliance_check_wake(reactor: &dyn Reactor, name: &str) {
        let result = reactor.wake();
        crate::assert_with_log!(
            result.is_ok(),
            &format!("{name} wake succeeds"),
            true,
            result.is_ok()
        );
    }

    fn compliance_check_poll_nonblocking(reactor: &dyn Reactor, name: &str) {
        let mut events = Events::with_capacity(16);
        let result = reactor.poll(&mut events, Some(std::time::Duration::ZERO));
        crate::assert_with_log!(
            result.is_ok(),
            &format!("{name} non-blocking poll succeeds"),
            true,
            result.is_ok()
        );
        crate::assert_with_log!(
            events.is_empty(),
            &format!("{name} no events on empty reactor"),
            true,
            events.is_empty()
        );
    }

    fn compliance_check_deregister_unknown(reactor: &dyn Reactor, name: &str) {
        let result = reactor.deregister(Token::new(99999));
        crate::assert_with_log!(
            result.is_err(),
            &format!("{name} deregister unknown token fails"),
            true,
            result.is_err()
        );
        let kind = result.expect_err("checked above").kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            &format!("{name} deregister unknown token reports NotFound"),
            io::ErrorKind::NotFound,
            kind
        );
    }

    fn compliance_check_modify_unknown(reactor: &dyn Reactor, name: &str) {
        let result = reactor.modify(Token::new(99999), Interest::READABLE);
        crate::assert_with_log!(
            result.is_err(),
            &format!("{name} modify unknown token fails"),
            true,
            result.is_err()
        );
        let kind = result.expect_err("checked above").kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            &format!("{name} modify unknown token reports NotFound"),
            io::ErrorKind::NotFound,
            kind
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cross_reactor_compliance_epoll() {
        init_test("cross_reactor_compliance_epoll");
        let reactor = super::EpollReactor::new().expect("failed to create epoll reactor");
        let name = "EpollReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_epoll");
    }

    #[test]
    fn cross_reactor_compliance_lab() {
        init_test("cross_reactor_compliance_lab");
        let reactor = super::LabReactor::new();
        let name = "LabReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_lab");
    }

    #[test]
    fn cross_reactor_compliance_browser() {
        init_test("cross_reactor_compliance_browser");
        let reactor = super::BrowserReactor::default();
        let name = "BrowserReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_browser");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cross_reactor_compliance_io_uring() {
        init_test("cross_reactor_compliance_io_uring");
        let reactor = match super::IoUringReactor::new() {
            Ok(r) => r,
            Err(e) => {
                // io_uring may not be available on older kernels
                eprintln!("Skipping io_uring compliance test: {e}");
                return;
            }
        };
        let name = "IoUringReactor";

        compliance_check_empty_state(&reactor, name);
        compliance_check_wake(&reactor, name);
        compliance_check_poll_nonblocking(&reactor, name);
        compliance_check_deregister_unknown(&reactor, name);
        compliance_check_modify_unknown(&reactor, name);

        crate::test_complete!("cross_reactor_compliance_io_uring");
    }

    /// Verify that Reactor trait objects work correctly (dyn dispatch).
    #[test]
    fn reactor_as_trait_object() {
        init_test("reactor_as_trait_object");
        let lab = super::LabReactor::new();
        let reactor: &dyn Reactor = &lab;

        crate::assert_with_log!(
            reactor.is_empty(),
            "trait object is_empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "trait object registration_count",
            0usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            reactor.wake().is_ok(),
            "trait object wake",
            true,
            reactor.wake().is_ok()
        );

        crate::test_complete!("reactor_as_trait_object");
    }

    /// Verify that Arc<Reactor> works for shared reactor access.
    #[test]
    fn reactor_arc_shared_access() {
        init_test("reactor_arc_shared_access");
        let reactor = std::sync::Arc::new(super::LabReactor::new());
        let reactor_clone = std::sync::Arc::clone(&reactor);

        crate::assert_with_log!(
            reactor.is_empty(),
            "arc reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor_clone.is_empty(),
            "arc clone reactor empty",
            true,
            reactor_clone.is_empty()
        );

        // Wake from clone
        crate::assert_with_log!(
            reactor_clone.wake().is_ok(),
            "wake from arc clone",
            true,
            reactor_clone.wake().is_ok()
        );

        crate::test_complete!("reactor_arc_shared_access");
    }

    #[test]
    fn token_debug_clone_copy_hash_ord_eq() {
        use std::collections::HashSet;
        let t = Token::new(42);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("42"), "{dbg}");
        let copied: Token = t;
        let cloned = t;
        assert_eq!(copied, cloned);
        assert!(Token::new(1) < Token::new(2));

        let mut set = HashSet::new();
        set.insert(Token::new(1));
        set.insert(Token::new(2));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn event_debug_clone_copy_eq() {
        let e = Event::new(Token::new(1), Interest::READABLE);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Event"), "{dbg}");
        let copied: Event = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        assert_ne!(e, Event::new(Token::new(2), Interest::WRITABLE));
    }
}
