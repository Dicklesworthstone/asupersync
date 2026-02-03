//! Typed capability sets for `Cx`.
//!
//! The capability set is represented at the type level so that operations
//! requiring certain effects (spawn/time/random/io/remote) can be gated
//! at compile time.

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

/// Full capability set (default).
pub type All = CapSet<true, true, true, true, true>;

/// No capabilities.
pub type None = CapSet<false, false, false, false, false>;

/// Marker: spawn capability.
pub trait HasSpawn {}
impl<const TIME: bool, const RANDOM: bool, const IO: bool, const REMOTE: bool> HasSpawn
    for CapSet<true, TIME, RANDOM, IO, REMOTE>
{
}

/// Marker: time capability.
pub trait HasTime {}
impl<const SPAWN: bool, const RANDOM: bool, const IO: bool, const REMOTE: bool> HasTime
    for CapSet<SPAWN, true, RANDOM, IO, REMOTE>
{
}

/// Marker: random/entropy capability.
pub trait HasRandom {}
impl<const SPAWN: bool, const TIME: bool, const IO: bool, const REMOTE: bool> HasRandom
    for CapSet<SPAWN, TIME, true, IO, REMOTE>
{
}

/// Marker: I/O capability.
pub trait HasIo {}
impl<const SPAWN: bool, const TIME: bool, const RANDOM: bool, const REMOTE: bool> HasIo
    for CapSet<SPAWN, TIME, RANDOM, true, REMOTE>
{
}

/// Marker: remote capability.
pub trait HasRemote {}
impl<const SPAWN: bool, const TIME: bool, const RANDOM: bool, const IO: bool> HasRemote
    for CapSet<SPAWN, TIME, RANDOM, IO, true>
{
}

/// Marker: subset relation between capability sets.
///
/// This encodes "A is a subset of B" at the type level.
pub trait SubsetOf<Super> {}

struct Assert<const CHECK: bool>;
trait IsTrue {}
impl IsTrue for Assert<true> {}

impl<
        const SPAWN: bool,
        const TIME: bool,
        const RANDOM: bool,
        const IO: bool,
        const REMOTE: bool,
        const SPAWN_SUP: bool,
        const TIME_SUP: bool,
        const RANDOM_SUP: bool,
        const IO_SUP: bool,
        const REMOTE_SUP: bool,
    > SubsetOf<CapSet<SPAWN_SUP, TIME_SUP, RANDOM_SUP, IO_SUP, REMOTE_SUP>>
    for CapSet<SPAWN, TIME, RANDOM, IO, REMOTE>
where
    Assert<
        {
            (!SPAWN || SPAWN_SUP)
                && (!TIME || TIME_SUP)
                && (!RANDOM || RANDOM_SUP)
                && (!IO || IO_SUP)
                && (!REMOTE || REMOTE_SUP)
        },
    >: IsTrue,
{
}
