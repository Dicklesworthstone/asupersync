//! Runtime-driven SWIM over the existing UDP membership adapter.
//!
//! This is an explicit, bounded failure detector, not membership authority.
//! [`UdpSwimDriver::new_trusted_network`] preserves the existing unauthenticated
//! wire protocol. Its address allowlist is NOT cryptographic authentication.
//! Do not feed these observations directly into authoritative lease admission
//! or revocation; that remains the separate authenticated membership service.
//!
//! Run the owned future in an existing runtime task. One task services receive,
//! transmit, protocol maintenance, cancellation and graceful stop. No helper
//! task, DNS lookup, ambient clock or process-lifetime timer is created here.
//! Unsent datagrams retain their exact encoding across Pending and have a finite
//! age. A full outbox is an explicit failure, not unbounded allocation or success.

use super::{MembershipView, Swim, SwimConfig, SwimConfigError, UdpMembershipTransport, WireError};
use crate::cx::Cx;
use crate::remote::NodeId;
use crate::time::Sleep;
use crate::types::{CancelReason, Outcome, Time};
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

mod engine;
use engine::Engine;
mod observation;
pub use observation::{SwimDriverStatus, SwimObservation, SwimObserver};
use observation::ObservationState;

/// Independent finite bounds for one driver. All counts and durations are nonzero.
///
/// These are logical bounds, not allocator/RSS or wall-clock execution bounds.
/// The core's member/relay bound is tightened to `min(max_peers, max_members)`;
/// only configured identities (plus the local identity) are admitted from gossip.
/// Protocol work per tick is still proportional to the bounded member table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwimDriverConfig {
    /// Maximum configured peers, excluding the local node.
    pub max_peers: usize,
    /// Maximum encoded datagrams awaiting a socket send.
    pub max_queued_datagrams: usize,
    /// Maximum retained membership events; older events require reconciliation.
    pub retained_events: usize,
    /// Maximum received AND maximum transmitted datagrams in one task poll.
    pub io_batch: usize,
    /// Maintenance cadence, no greater than the direct-probe timeout.
    pub tick_ms: u64,
    /// Drop an unsent ordinary probe after this age, recording the local loss.
    pub max_datagram_age_ms: u64,
    /// Deadline for local acceptance of the graceful Leave fanout, not delivery.
    pub leave_timeout_ms: u64,
}

impl Default for SwimDriverConfig {
    fn default() -> Self {
        Self {
            max_peers: 1024,
            max_queued_datagrams: 4096,
            retained_events: 1024,
            io_batch: 32,
            tick_ms: 25,
            max_datagram_age_ms: 500,
            leave_timeout_ms: 500,
        }
    }
}

/// Bounded aggregate observations. A sent datagram is kernel acceptance, not ACK.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SwimDriverStats {
    /// Maintenance ticks actually delivered to the protocol.
    pub ticks: u64,
    /// Datagrams received, including rejected input.
    pub received_datagrams: u64,
    /// Fully decoded, allowlisted packets delivered to SWIM.
    pub accepted_packets: u64,
    /// Received ACK payloads (not a count of successful matching probes).
    pub received_acks: u64,
    /// Datagrams fully accepted by the socket.
    pub sent_datagrams: u64,
    /// Bytes fully accepted by the socket.
    pub sent_bytes: u64,
    /// Input from a source address not in the explicit topology.
    pub unknown_sources: u64,
    /// Input exceeding the configured datagram ceiling.
    pub oversized_datagrams: u64,
    /// Malformed, noncanonical or trailing-data input.
    pub malformed_datagrams: u64,
    /// Input naming an unauthorized subject, accuser or indirect target.
    pub unauthorized_packets: u64,
    /// Failed best-effort ordinary UDP sends; these packets were not sent.
    pub send_errors: u64,
    /// Transient receive errors treated as a lost datagram.
    pub receive_errors: u64,
    /// Unsent ordinary datagrams that exceeded their age bound.
    pub expired_datagrams: u64,
    /// Unsent datagrams discarded on Leave, cancellation, error or drop.
    pub discarded_datagrams: u64,
    /// Gossip rumors excluded by the existing MTU encoder.
    pub omitted_gossip: u64,
    /// Current encoded outbox occupancy.
    pub queued_datagrams: usize,
    /// Maximum encoded outbox occupancy observed.
    pub queue_high_water: usize,
}

/// Admission/runtime refusal. Sensitive packet bytes never appear in errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum SwimDriverError {
    /// The original SWIM configuration failed validation.
    Protocol(SwimConfigError),
    /// Invalid or unrepresentable driver bounds/topology.
    Configuration(&'static str),
    /// An explicit runtime timer is required; no fallback thread is created.
    MissingTimer,
    /// The future must be polled inside a context with a native I/O driver.
    MissingIoDriver,
    /// The supplied clock went backwards or cannot represent another deadline.
    Clock,
    /// An absolute membership cursor/revision cannot represent another update.
    ObservationExhausted,
    /// A full encoded outbox refused further protocol output.
    OutboxFull,
    /// Bounded outbox storage could not be reserved.
    Allocation,
    /// Local encoding of a protocol packet failed.
    Wire(WireError),
    /// Nontransient receive failure or a failed graceful Leave send.
    Io(io::Error),
    /// UDP must either accept the entire datagram or fail it.
    PartialDatagram,
    /// Graceful Leave still had unsent datagrams at its deadline.
    LeaveTimeout,
}

impl fmt::Display for SwimDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "SWIM configuration: {error}"),
            Self::Configuration(reason) => write!(f, "SWIM driver configuration: {reason}"),
            Self::MissingTimer => f.write_str("SWIM driver requires an explicit runtime timer"),
            Self::MissingIoDriver => f.write_str("SWIM driver requires an active runtime I/O context"),
            Self::Clock => f.write_str("SWIM driver clock regressed or exhausted"),
            Self::ObservationExhausted => f.write_str("SWIM observation sequence exhausted"),
            Self::OutboxFull => f.write_str("SWIM encoded outbox capacity exhausted"),
            Self::Allocation => f.write_str("SWIM bounded outbox allocation failed"),
            Self::Wire(error) => write!(f, "SWIM local encoding: {error}"),
            Self::Io(error) => write!(f, "SWIM driver I/O: {error}"),
            Self::PartialDatagram => f.write_str("SWIM socket reported a partial datagram send"),
            Self::LeaveTimeout => f.write_str("SWIM graceful Leave fanout timed out"),
        }
    }
}
impl std::error::Error for SwimDriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<WireError> for SwimDriverError {
    fn from(error: WireError) -> Self { Self::Wire(error) }
}

/// Terminal result after the owned transport was retired.
///
/// `Ok(())` means every graceful Leave datagram was accepted locally. It does
/// not mean peers received it, agreed on membership, or released any leases.
#[derive(Debug)]
pub struct SwimDriverReport {
    /// Actual driver completion, cancellation, or failure.
    pub outcome: Outcome<(), SwimDriverError>,
    /// Final bounded state/counters. No task, socket, or timer is retained.
    pub observation: SwimObservation,
}

/// Native driver for a fixed, explicitly configured topology.
///
/// Construction performs no I/O beyond querying the caller's bound socket.
/// Initial peers are SWIM seeds, not authenticated liveness evidence. Callers
/// should inspect accepted traffic and actual transitions, not call seeding
/// "convergence". Dead/Left identities retain the core's terminal semantics;
/// restarting/re-enrolling an identity is an external membership-authority job.
///
/// `run`/`run_until` consume the driver. Dropping either future closes its socket,
/// retires timer/cancel registrations, and publishes `Dropped`, not a fabricated
/// graceful departure. Observers retain only a bounded view, never the driver.
pub struct UdpSwimDriver {
    engine: Engine,
    transport: Option<UdpMembershipTransport>,
    observation: Arc<ObservationState>,
}

impl fmt::Debug for UdpSwimDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSwimDriver")
            .field("local", self.engine.swim.local())
            .field("peers", &self.engine.peers.len())
            .field("queued", &self.engine.outbox.len())
            .finish_non_exhaustive()
    }
}

impl UdpSwimDriver {
    /// Drive the legacy unauthenticated UDP protocol on a trusted network.
    ///
    /// Address filtering bounds identity growth and amplification; it does not
    /// prevent source spoofing or authenticate gossip. No peer addresses are
    /// learned from packets. IDs are limited to 255 UTF-8 bytes. The MTU must
    /// fit the largest indirect payload plus one largest membership rumor.
    /// The outbox must admit at least one Leave per configured peer.
    pub fn new_trusted_network(
        local: NodeId,
        mut protocol: SwimConfig,
        seed: u64,
        peers: BTreeMap<NodeId, SocketAddr>,
        transport: UdpMembershipTransport,
        config: SwimDriverConfig,
    ) -> Result<Self, SwimDriverError> {
        validate(&local, &protocol, &peers, &transport, config)?;
        protocol.max_members = protocol.max_members.min(config.max_peers);
        let mut swim = Swim::new(local, protocol, seed);
        for peer in peers.keys() { swim.add_peer(0, peer.clone()); }
        let observation = Arc::new(ObservationState::new(config.retained_events));
        let mut engine = Engine::new(swim, peers, transport.mtu(), config);
        observation.publish(
            engine.swim.drain_events(), SwimDriverStatus::Prepared, engine.stats,
        )?;
        Ok(Self { engine, transport: Some(transport), observation })
    }

    /// Clone bounded observation access without retaining the native transport.
    #[must_use]
    pub fn observer(&self) -> SwimObserver {
        SwimObserver { shared: Arc::clone(&self.observation) }
    }

    /// Run until context cancellation or a typed failure. No task is spawned here.
    pub async fn run(self, cx: &Cx) -> SwimDriverReport {
        self.run_until(cx, std::future::pending()).await
    }

    /// Run until `stop` completes, then send a bounded graceful Leave fanout.
    ///
    /// Cancellation wins a simultaneous stop and does not attempt Leave. Socket
    /// readiness and protocol maintenance are polled independently: a blocked
    /// send cannot block reads or timeout processing. The socket currently shares
    /// one reactor interest slot, so the explicit maintenance timer also bounds
    /// retry latency if one direction replaces the other's readiness interest.
    /// Floods consume at most `io_batch` receives/sends per poll before yielding.
    /// The cadence is not an exact timer or WAN latency guarantee.
    ///
    /// Poll this future in an existing native runtime task with an I/O driver.
    /// The supplied context's timer supplies both deadlines and logical time.
    /// A mask-agnostic cancellation request is a request to stop this detector;
    /// `checkpoint` is called for acknowledgement subject to the context's mask.
    /// No arbitrary user tasks or foreign operations are truncated by this loop.
    pub async fn run_until<F>(mut self, cx: &Cx, stop: F) -> SwimDriverReport
    where
        F: Future<Output = ()>,
    {
        let outcome = self.run_inner(cx, stop).await;
        self.engine.discard_outbox();
        // Retire native registrations/socket before publishing terminal state.
        drop(self.transport.take());
        let status = match &outcome {
            Outcome::Ok(()) => SwimDriverStatus::Left,
            Outcome::Cancelled(_) => SwimDriverStatus::Cancelled,
            _ => SwimDriverStatus::Failed,
        };
        self.observation.finish(status, self.engine.stats);
        SwimDriverReport { outcome, observation: self.observer().snapshot() }
    }

    async fn run_inner<F>(&mut self, cx: &Cx, stop: F) -> Outcome<(), SwimDriverError>
    where
        F: Future<Output = ()>,
    {
        let Some(timer) = cx.timer_driver() else {
            return Outcome::Err(SwimDriverError::MissingTimer);
        };
        if Cx::current().and_then(|current| current.io_driver_handle()).is_none() {
            return Outcome::Err(SwimDriverError::MissingIoDriver);
        }
        let first = timer.now();
        let tick_nanos = self.engine.config.tick_ms * 1_000_000; // validated
        let Some(deadline) = first.as_nanos().checked_add(tick_nanos) else {
            return Outcome::Err(SwimDriverError::Clock);
        };
        let mut sleeper = Box::pin(Sleep::with_timer_driver(Time::from_nanos(deadline), timer.clone()));
        let mut stop = std::pin::pin!(stop);
        let mut cancelled = std::pin::pin!(cx.cancelled());
        let mut last = first;
        let mut first_tick = true;
        let observation = &self.observation;
        let engine = &mut self.engine;
        let transport = self.transport.as_mut().expect("owned transport before terminal");
        if let Err(error) = observation.publish(Vec::new(), SwimDriverStatus::Running, engine.stats) {
            return Outcome::Err(error);
        }
        poll_fn(|task| {
            if Cx::current().and_then(|current| current.io_driver_handle()).is_none() {
                return Poll::Ready(Outcome::Err(SwimDriverError::MissingIoDriver));
            }
            if cancelled.as_mut().poll(task).is_ready() {
                let _ = cx.checkpoint();
                return Poll::Ready(Outcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(CancelReason::shutdown),
                ));
            }
            let now = timer.now();
            if now < last { return Poll::Ready(Outcome::Err(SwimDriverError::Clock)); }
            last = now;
            let now_ms = now.as_nanos() / 1_000_000;
            if !engine.is_leaving() && stop.as_mut().poll(task).is_ready() {
                if let Err(error) = engine.begin_leave(now_ms) {
                    return Poll::Ready(Outcome::Err(error));
                }
            }
            let timer_due = sleeper.as_mut().poll(task).is_ready();
            let tick = std::mem::take(&mut first_tick) || timer_due;
            let turn = engine.turn(transport, task, now_ms, tick);
            let status = if engine.is_leaving() { SwimDriverStatus::Leaving } else { SwimDriverStatus::Running };
            if let Err(error) = observation.publish(engine.swim.drain_events(), status, engine.stats) {
                return Poll::Ready(Outcome::Err(error));
            }
            match turn {
                Err(error) => return Poll::Ready(Outcome::Err(error)),
                Ok(engine::Turn::Left) => return Poll::Ready(Outcome::Ok(())),
                Ok(engine::Turn::Yield) => task.waker().wake_by_ref(),
                Ok(engine::Turn::Park) => {}
            }
            if timer_due {
                let Some(deadline) = now.as_nanos().checked_add(tick_nanos) else {
                    return Poll::Ready(Outcome::Err(SwimDriverError::Clock));
                };
                sleeper = Box::pin(Sleep::with_timer_driver(Time::from_nanos(deadline), timer.clone()));
                // Arm before returning Pending; an already-due timer requests
                // one more bounded turn, never an inner unbounded catch-up loop.
                if sleeper.as_mut().poll(task).is_ready() { task.waker().wake_by_ref(); }
            }
            Poll::Pending
        }).await
    }
}

impl Drop for UdpSwimDriver {
    fn drop(&mut self) {
        self.engine.discard_outbox();
        drop(self.transport.take());
        self.observation.finish_if_active(SwimDriverStatus::Dropped, self.engine.stats);
    }
}

fn validate(
    local: &NodeId,
    protocol: &SwimConfig,
    peers: &BTreeMap<NodeId, SocketAddr>,
    transport: &UdpMembershipTransport,
    config: SwimDriverConfig,
) -> Result<(), SwimDriverError> {
    protocol.validate().map_err(SwimDriverError::Protocol)?;
    if transport.is_connected() {
        return Err(SwimDriverError::Configuration("transport must be an unconnected UDP socket"));
    }
    if config.max_peers == 0 || config.max_queued_datagrams == 0 || config.retained_events == 0
        || config.io_batch == 0 || config.tick_ms == 0 || config.max_datagram_age_ms == 0
        || config.leave_timeout_ms == 0
    {
        return Err(SwimDriverError::Configuration("all bounds must be nonzero"));
    }
    if peers.len() > config.max_peers || peers.len() > protocol.max_members
        || peers.len() > config.max_queued_datagrams
    {
        return Err(SwimDriverError::Configuration("topology exceeds member or Leave-outbox capacity"));
    }
    if config.tick_ms > protocol.probe_timeout_ms {
        return Err(SwimDriverError::Configuration("tick exceeds direct-probe timeout"));
    }
    const MAX_MS: u64 = u64::MAX / 1_000_000;
    if [config.tick_ms, config.max_datagram_age_ms, config.leave_timeout_ms].into_iter().any(|n| n > MAX_MS)
        || u64::try_from(protocol.awareness_max).ok()
            .and_then(|n| n.checked_add(1))
            .and_then(|n| protocol.probe_interval_ms.checked_mul(n))
            .is_none_or(|n| n > MAX_MS)
        || protocol.probe_interval_ms.checked_mul(u64::from(protocol.suspicion_mult))
            .and_then(|n| n.checked_mul(u64::from(protocol.suspicion_max_timeout_mult)))
            .and_then(|n| n.checked_mul(u64::try_from(peers.len()).ok()?.checked_add(1)?))
            .is_none_or(|n| n > MAX_MS)
    {
        return Err(SwimDriverError::Configuration("duration arithmetic exceeds supported clock range"));
    }
    let mut addresses = std::collections::BTreeSet::new();
    let local_addr = transport.local_addr().map_err(SwimDriverError::Io)?;
    let mut longest = local.as_str().len();
    for (id, address) in peers {
        longest = longest.max(id.as_str().len());
        if id == local || id.as_str().is_empty() || !addresses.insert(*address)
            || *address == local_addr || address.port() == 0 || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        {
            return Err(SwimDriverError::Configuration("invalid or duplicate peer identity/address"));
        }
    }
    if local.as_str().is_empty() || longest > 255 {
        return Err(SwimDriverError::Configuration("identities require 1..=255 UTF-8 bytes"));
    }
    let mtu = transport.mtu();
    if mtu < 27 + 3 * longest || mtu > 65_507
        || mtu.checked_mul(config.max_queued_datagrams).is_none()
    {
        return Err(SwimDriverError::Configuration("MTU must fit an indirect probe plus one rumor and UDP"));
    }
    Ok(())
}

// Only the maintained driver and its focused adversarial tests use this seam.
// No public transport alternative or mock-only execution path is introduced.
trait DatagramIo {
    fn poll_datagram(&mut self, task: &mut Context<'_>) -> Poll<io::Result<(SocketAddr, &[u8])>>;
    fn poll_send_datagram(&mut self, task: &mut Context<'_>, target: SocketAddr, bytes: &[u8]) -> Poll<io::Result<usize>>;
}
impl DatagramIo for UdpMembershipTransport {
    fn poll_datagram(&mut self, task: &mut Context<'_>) -> Poll<io::Result<(SocketAddr, &[u8])>> {
        self.poll_raw_recv(task)
    }
    fn poll_send_datagram(&mut self, task: &mut Context<'_>, target: SocketAddr, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_raw_send(task, target, bytes)
    }
}

#[cfg(test)]
mod tests;
