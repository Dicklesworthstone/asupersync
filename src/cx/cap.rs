//! Typed capability sets for `Cx`.
//!
//! The capability set is represented at the type level so that operations
//! requiring certain effects (spawn/time/random/io/remote) can be gated
//! at compile time.
//!
//! # Forging Prevention
//!
//! Capability marker traits are sealed to prevent external crates from
//! implementing them for arbitrary types. This ensures only the runtime's
//! `CapSet` types can grant access to gated APIs.
//!
//! # Trusted Roots
//!
//! - The runtime constructs full contexts internally (e.g., via `RuntimeState`).
//! - Test-only constructors (e.g., `Cx::for_testing*`) are permitted for harnesses.

mod sealed {
    pub trait Sealed {}
}

/// Type-level capability set.
///
/// Each boolean controls whether the capability is present:
/// - `SPAWN`: spawn tasks/regions
/// - `TIME`: timers, timeouts
/// - `RANDOM`: entropy and random values
/// - `IO`: async I/O capability
/// - `REMOTE`: remote task spawning
#[derive(Debug, Clone, Copy, Default)]
pub struct CapSet<
    const SPAWN: bool,
    const TIME: bool,
    const RANDOM: bool,
    const IO: bool,
    const REMOTE: bool,
>;

impl<
        const SPAWN: bool,
        const TIME: bool,
        const RANDOM: bool,
        const IO: bool,
        const REMOTE: bool,
    > sealed::Sealed for CapSet<SPAWN, TIME, RANDOM, IO, REMOTE>
{
}

/// Full capability set (default).
pub type All = CapSet<true, true, true, true, true>;

/// No capabilities.
pub type None = CapSet<false, false, false, false, false>;

/// Marker: spawn capability.
///
/// ```compile_fail
/// use asupersync::cx::HasSpawn;
///
/// struct FakeCaps;
/// impl HasSpawn for FakeCaps {}
/// ```
pub trait HasSpawn: sealed::Sealed {}
impl<const TIME: bool, const RANDOM: bool, const IO: bool, const REMOTE: bool> HasSpawn
    for CapSet<true, TIME, RANDOM, IO, REMOTE>
{
}

/// Marker: time capability.
pub trait HasTime: sealed::Sealed {}
impl<const SPAWN: bool, const RANDOM: bool, const IO: bool, const REMOTE: bool> HasTime
    for CapSet<SPAWN, true, RANDOM, IO, REMOTE>
{
}

/// Marker: random/entropy capability.
pub trait HasRandom: sealed::Sealed {}
impl<const SPAWN: bool, const TIME: bool, const IO: bool, const REMOTE: bool> HasRandom
    for CapSet<SPAWN, TIME, true, IO, REMOTE>
{
}

/// Marker: I/O capability.
pub trait HasIo: sealed::Sealed {}
impl<const SPAWN: bool, const TIME: bool, const RANDOM: bool, const REMOTE: bool> HasIo
    for CapSet<SPAWN, TIME, RANDOM, true, REMOTE>
{
}

/// Marker: remote capability.
pub trait HasRemote: sealed::Sealed {}
impl<const SPAWN: bool, const TIME: bool, const RANDOM: bool, const IO: bool> HasRemote
    for CapSet<SPAWN, TIME, RANDOM, IO, true>
{
}

/// Marker: subset relation between capability sets.
///
/// This encodes "A is a subset of B" at the type level.
/// Concrete impls are provided for common cases; the full
/// const-generic version requires `generic_const_exprs` (nightly).
///
/// ```compile_fail
/// use asupersync::cx::SubsetOf;
///
/// struct FakeCaps;
/// impl SubsetOf<FakeCaps> for FakeCaps {}
/// ```
pub trait SubsetOf<Super>: sealed::Sealed {}

// All is a superset of everything — allow narrowing from `All` to any `CapSet`.
impl<
        const SPAWN: bool,
        const TIME: bool,
        const RANDOM: bool,
        const IO: bool,
        const REMOTE: bool,
    > SubsetOf<All> for CapSet<SPAWN, TIME, RANDOM, IO, REMOTE>
{
}
