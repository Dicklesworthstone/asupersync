//! Bonded (N-donor) transfer SDK: a fluent [`BondedTransfer`] builder plus a
//! cancel-correct progress handle over the real bonded RaptorQ transport.
//!
//! This is the first genuinely working net-SDK transfer. Unlike the
//! single-source [`ActiveTransfer`](super::ActiveTransfer) handle (whose
//! in-process driver is still a fail-closed stub), [`BondedTransfer`] drives
//! the landed [`receive_bonded`](crate::net::atp::transport_rq::receive_bonded)
//! / [`donate_bonded`](crate::net::atp::transport_rq::donate_bonded) data path:
//! the receiver derives the agreed descriptor from its own byte-identical local
//! copy, binds a control listener, enrolls donors, and commits fail-closed;
//! each donor derives the same descriptor from its copy, enrolls, sprays its
//! residue-disjoint fountain slice, and serves feedback.
//!
//! # Shape
//!
//! The builder mirrors [`SessionOptions`](super::SessionOptions): two leg
//! constructors ([`BondedTransfer::receive`], [`BondedTransfer::donate`]) and
//! `#[must_use]` chainable setters whose defaults match the `atp` CLI's
//! `bond-recv` / `bond-donate` argument structs.
//!
//! # Cancel-correctness
//!
//! Both drivers thread `&Cx` straight into the transport, which already
//! `cx.checkpoint()?`s on every round and unwinds cleanly on cancellation. The
//! concurrent [`BondedReceiveHandle`] spawns the receiver as an owned child via
//! [`Cx::spawn`]; [`BondedReceiveHandle::cancel`] aborts that child's `Cx`, so
//! the transport observes the cancellation at its next checkpoint (or in
//! `poll_accept`, which checks the ambient `Cx`) and returns without a hang or
//! a leak — the child region drains to quiescence and nothing is committed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::atp::object::MetadataPolicy;
use crate::channel::mpsc;
use crate::cx::Cx;
use crate::net::TcpListener;
use crate::net::atp::bonding::{
    BondedDonorIngressStats, MAX_BONDING_DONORS, derive_bonded_descriptor,
};
use crate::net::atp::protocol::{
    AtpError, AtpOutcome, AuthError, DiskError, ManifestError, PlatformError, ProtocolError,
    RepairError, TransportError,
};
use crate::net::atp::transport_rq::{
    self, BondedDonateReport, BondedReceiveReport, DEFAULT_REPAIR_OVERHEAD, DEFAULT_SYMBOL_SIZE,
    DEFAULT_UDP_FANOUT, RqConfig, RqError,
};
use crate::net::atp::transport_tcp::DEFAULT_MAX_TRANSFER_BYTES;
use crate::runtime::{JoinError, TaskHandle};
use crate::security::{AUTH_KEY_SIZE, AuthKey, SecurityContext};
use crate::types::cancel::CancelReason;

use super::TransferPhase;

/// Default bonded control listen port, matching the CLI's `bond-recv --listen`
/// default of `0.0.0.0:8473`.
const DEFAULT_BONDED_CONTROL_PORT: u16 = 8473;

/// Default RaptorQ source-block ceiling, matching the CLI's `--max-block-size
/// auto` resolution (`AUTO_MAX_BLOCK_SIZE`).
const DEFAULT_BONDED_MAX_BLOCK_SIZE: u64 = 512 * 1024;

/// Default donor enrollment / progress wait, matching the CLI's
/// `--accept-timeout-secs` default (`DEFAULT_RECV_ACCEPT_TIMEOUT_SECS`).
const DEFAULT_BONDED_ACCEPT_TIMEOUT_SECS: u64 = 60;

/// Bound on the receiver's live-progress channel. Snapshots are best-effort
/// (`try_send`) so a slow reader can never stall the transfer; a generous
/// buffer keeps the handful of round-boundary snapshots from being dropped.
const BONDED_PROGRESS_CHANNEL_CAPACITY: usize = 64;

/// Which leg of a bonded transfer this builder drives.
#[derive(Debug, Clone)]
enum BondedLeg {
    /// The receiver derives the descriptor from its own byte-identical
    /// `local_source`, enrolls donors, and commits into `dest_dir`.
    Receive {
        /// Destination directory for the committed transfer.
        dest_dir: PathBuf,
        /// Local byte-identical copy the agreed descriptor is derived from.
        local_source: PathBuf,
    },
    /// One donor leg: derive the descriptor from `source` and spray into the
    /// receiver's `control_addr`.
    Donate {
        /// Local byte-identical source this donor holds.
        source: PathBuf,
        /// Receiver bonded control address (host:port, TCP).
        control_addr: SocketAddr,
    },
}

/// Fluent builder + driver for a bonded (N-donor) transfer.
///
/// Construct with [`BondedTransfer::receive`] or [`BondedTransfer::donate`],
/// chain setters, then drive with [`BondedTransfer::run`] (blocking) or, for a
/// receiver, [`BondedTransfer::spawn`] (owned child + live progress handle).
#[derive(Debug, Clone)]
pub struct BondedTransfer {
    leg: BondedLeg,
    expect_donors: u32,
    listen: SocketAddr,
    udp_bind: Option<String>,
    peer_id: String,
    symbol_size: Option<u16>,
    max_block_size: u64,
    repair_overhead: f64,
    max_bytes: u64,
    accept_timeout: Duration,
    auth_key_hex: Option<String>,
    allow_unauthenticated_lab: bool,
}

impl BondedTransfer {
    fn new(leg: BondedLeg) -> Self {
        Self {
            leg,
            expect_donors: 1,
            listen: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                DEFAULT_BONDED_CONTROL_PORT,
            ),
            udp_bind: None,
            peer_id: "atp-bond-receiver".to_string(),
            symbol_size: None,
            max_block_size: DEFAULT_BONDED_MAX_BLOCK_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            max_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            accept_timeout: Duration::from_secs(DEFAULT_BONDED_ACCEPT_TIMEOUT_SECS),
            auth_key_hex: None,
            allow_unauthenticated_lab: false,
        }
    }

    /// Start a bonded **receiver** leg.
    ///
    /// The receiver derives the agreed descriptor from `local_source` (a
    /// byte-identical local copy — the enrollment protocol never transmits the
    /// descriptor) and commits the transfer into `dest_dir`.
    #[must_use]
    pub fn receive(dest_dir: impl Into<PathBuf>, local_source: impl Into<PathBuf>) -> Self {
        Self::new(BondedLeg::Receive {
            dest_dir: dest_dir.into(),
            local_source: local_source.into(),
        })
    }

    /// Start a bonded **donor** leg that sprays `source` into the receiver's
    /// `control_addr`.
    #[must_use]
    pub fn donate(source: impl Into<PathBuf>, control_addr: SocketAddr) -> Self {
        Self::new(BondedLeg::Donate {
            source: source.into(),
            control_addr,
        })
    }

    /// Exact number of donors that must enroll before a receiver runs.
    #[must_use]
    pub const fn expect_donors(mut self, donors: u32) -> Self {
        self.expect_donors = donors;
        self
    }

    /// TCP control address a receiver listens on for donor enrollment.
    #[must_use]
    pub const fn listen(mut self, listen: SocketAddr) -> Self {
        self.listen = listen;
        self
    }

    /// IP the receiver's bonded UDP symbol sockets bind on (defaults to the
    /// `listen` IP).
    #[must_use]
    pub fn udp_bind(mut self, udp_bind: impl Into<String>) -> Self {
        self.udp_bind = Some(udp_bind.into());
        self
    }

    /// This receiver's advertised identity label.
    #[must_use]
    pub fn peer_id(mut self, peer_id: impl Into<String>) -> Self {
        self.peer_id = peer_id.into();
        self
    }

    /// Hex-encoded 32-byte shared RQ symbol-auth key. All donors and the
    /// receiver must share the same key.
    #[must_use]
    pub fn auth_key_hex(mut self, auth_key_hex: impl Into<String>) -> Self {
        self.auth_key_hex = Some(auth_key_hex.into());
        self
    }

    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[must_use]
    pub const fn allow_unauthenticated_lab(mut self, allow: bool) -> Self {
        self.allow_unauthenticated_lab = allow;
        self
    }

    /// RaptorQ symbol size in bytes. Must be identical on every donor and the
    /// receiver (it is part of the agreed descriptor). Defaults to
    /// [`DEFAULT_SYMBOL_SIZE`] when unset.
    #[must_use]
    pub const fn symbol_size(mut self, symbol_size: u16) -> Self {
        self.symbol_size = Some(symbol_size);
        self
    }

    /// Maximum RaptorQ source-block size in bytes. Must be identical on every
    /// donor and the receiver: it fixes per-block `K`.
    #[must_use]
    pub const fn max_block_size(mut self, max_block_size: u64) -> Self {
        self.max_block_size = max_block_size;
        self
    }

    /// Round-0 repair overhead factor (clamped to `>= 1.0`).
    #[must_use]
    pub const fn repair_overhead(mut self, repair_overhead: f64) -> Self {
        self.repair_overhead = repair_overhead;
        self
    }

    /// Maximum transfer size in bytes.
    #[must_use]
    pub const fn max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Donor enrollment accept + progress wait before failing closed.
    #[must_use]
    pub const fn accept_timeout(mut self, accept_timeout: Duration) -> Self {
        self.accept_timeout = accept_timeout;
        self
    }

    /// Resolve the effective symbol size (explicit wins, else the RQ default).
    fn effective_symbol_size(&self) -> u16 {
        self.symbol_size.unwrap_or(DEFAULT_SYMBOL_SIZE)
    }

    /// Build the transfer `RqConfig`, mirroring the CLI's `rq_config` posture
    /// for bonded transfers (portable content agreement is applied separately
    /// during descriptor derivation).
    fn build_config(&self) -> Result<RqConfig, RqError> {
        let symbol_size = self.effective_symbol_size();
        let max_block_size = usize::try_from(self.max_block_size)
            .unwrap_or(usize::MAX)
            .max(usize::from(symbol_size.max(1)));
        let config = RqConfig {
            symbol_size,
            udp_fanout: DEFAULT_UDP_FANOUT.max(1),
            max_block_size,
            repair_overhead: self.repair_overhead.max(1.0),
            max_transfer_bytes: self.max_bytes,
            metadata_policy: bonded_transfer_metadata_policy(),
            preserve_hardlinks: true,
            accept_timeout: self.accept_timeout,
            ..RqConfig::default()
        };
        self.apply_auth(config)
    }

    /// Resolve the symbol-auth posture into `explicit key` vs `trusted lab`.
    fn resolve_auth(&self) -> Result<SdkRqAuth, RqError> {
        let configured = self
            .auth_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty());
        if self.allow_unauthenticated_lab {
            if configured.is_some() {
                return Err(RqError::Authentication(
                    "allow_unauthenticated_lab conflicts with auth_key_hex".to_string(),
                ));
            }
            return Ok(SdkRqAuth::UnauthenticatedLab);
        }
        if let Some(key_hex) = configured {
            // Validate before storing the normalized (lowercase, 0x-stripped)
            // hex so the auth key id fingerprint is stable across peers.
            let _ = sdk_auth_key_from_hex(key_hex)?;
            let normalized = key_hex
                .strip_prefix("0x")
                .unwrap_or(key_hex)
                .to_ascii_lowercase();
            return Ok(SdkRqAuth::KeyHex(normalized));
        }
        Err(RqError::Authentication(
            "bonded RQ transport requires symbol authentication: call auth_key_hex(<64-hex>) \
             or allow_unauthenticated_lab(true) for loopback/lab only"
                .to_string(),
        ))
    }

    /// Apply the resolved auth posture onto a config.
    fn apply_auth(&self, config: RqConfig) -> Result<RqConfig, RqError> {
        match self.resolve_auth()? {
            SdkRqAuth::KeyHex(key_hex) => {
                let key = sdk_auth_key_from_hex(&key_hex)?;
                Ok(config.with_symbol_auth(SecurityContext::new(key)))
            }
            SdkRqAuth::UnauthenticatedLab => {
                Ok(config.allow_unauthenticated_for_trusted_transport())
            }
        }
    }

    /// Derive the non-secret shared-key id carried in the descriptor (a
    /// truncated SHA-256 fingerprint of the raw key bytes, matching the CLI's
    /// `bond_auth_key_id`).
    fn resolved_auth_key_id(&self) -> Result<Option<String>, RqError> {
        match self.resolve_auth()? {
            SdkRqAuth::UnauthenticatedLab => Ok(None),
            SdkRqAuth::KeyHex(key_hex) => {
                let mut bytes = [0u8; AUTH_KEY_SIZE];
                hex::decode_to_slice(&key_hex, &mut bytes).map_err(|err| {
                    RqError::Authentication(format!("decode RQ auth key hex: {err}"))
                })?;
                let digest: [u8; 32] = Sha256::digest(bytes).into();
                Ok(Some(format!(
                    "rq-auth-sha256:{}",
                    hex::encode(&digest[..8])
                )))
            }
        }
    }

    /// Drive this bonded leg to completion, blocking until the transfer commits
    /// (or fails). Use [`BondedTransfer::spawn`] instead when you need live
    /// per-donor progress from a receiver.
    ///
    /// Threads `cx` straight into the transport, so a cancellation of `cx`
    /// unwinds the transfer cleanly (nothing is committed).
    pub async fn run(self, cx: &Cx) -> AtpOutcome<BondedReport> {
        match &self.leg {
            BondedLeg::Receive { .. } => match self.run_receive(cx, None, None).await {
                Ok(report) => AtpOutcome::Ok(BondedReport::Receive(report)),
                Err(err) => rq_error_to_atp_outcome(cx, err),
            },
            BondedLeg::Donate { .. } => match self.run_donate(cx).await {
                Ok(report) => AtpOutcome::Ok(BondedReport::Donate(report)),
                Err(err) => rq_error_to_atp_outcome(cx, err),
            },
        }
    }

    /// Spawn a **receiver** leg as an owned child task and return a handle for
    /// live progress and cancel-correct control.
    ///
    /// The receiver is spawned into `cx`'s own region via [`Cx::spawn`], so it
    /// is drained/cancelled with that region. The returned handle exposes the
    /// bound control address, a live [`BondedTransferProgress`] stream, a
    /// cancel that aborts the child's `Cx`, and the terminal report.
    ///
    /// This spawn-with-returnable-handle path deliberately takes `&Cx` (not a
    /// `&Scope`): `Cx::spawn` is the codebase's idiomatic owned-child spawn and
    /// is what threads the cancel-correct child `Cx` into the transport. Calling
    /// this on a donor leg is a usage error.
    #[must_use = "dropping the handle leaves the receiver running unobserved"]
    pub fn spawn(self, cx: &Cx) -> AtpOutcome<BondedReceiveHandle> {
        if !matches!(self.leg, BondedLeg::Receive { .. }) {
            cx.trace("BondedTransfer::spawn is receiver-only; use run() for a donor leg");
            return AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }
        let (progress_tx, progress_rx) = mpsc::channel(BONDED_PROGRESS_CHANNEL_CAPACITY);
        let (bound_tx, bound_rx) = mpsc::channel(1);
        let spawn_result = cx.spawn(move |child| async move {
            self.run_receive(&child, Some(progress_tx), Some(bound_tx))
                .await
        });
        match spawn_result {
            Ok(task) => AtpOutcome::Ok(BondedReceiveHandle {
                progress_rx,
                bound_rx,
                task,
                cx: cx.clone(),
            }),
            Err(_) => AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError)),
        }
    }

    /// The receiver-leg body: derive the agreed descriptor from the local copy,
    /// create the destination, bind the control listener (reporting the bound
    /// address to `on_bound`), then drive the landed bonded receive loop with
    /// an optional live-progress sink.
    async fn run_receive(
        &self,
        cx: &Cx,
        progress: Option<mpsc::Sender<BondedTransferProgress>>,
        on_bound: Option<mpsc::Sender<SocketAddr>>,
    ) -> Result<BondedReceiveReport, RqError> {
        let BondedLeg::Receive {
            dest_dir,
            local_source,
        } = &self.leg
        else {
            return Err(RqError::Source(
                "run_receive called on a non-receiver bonded leg".to_string(),
            ));
        };
        validate_expected_donors(self.expect_donors)?;
        let config = self.build_config()?;
        let auth_key_id = self.resolved_auth_key_id()?;
        let symbol_size = config.symbol_size;
        let max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX);

        let descriptor = derive_bonded_descriptor(
            cx,
            local_source,
            symbol_size,
            max_block_size,
            self.max_bytes,
            auth_key_id,
        )
        .await?;

        crate::fs::create_dir_all(dest_dir).await.map_err(|err| {
            RqError::Source(format!("create bonded dest {}: {err}", dest_dir.display()))
        })?;

        let listener = TcpListener::bind(self.listen).await?;
        let bound = listener.local_addr()?;
        if let Some(sink) = on_bound {
            // Best-effort: the caller may already have the address or may drop
            // the receiver before binding matters.
            let _ = sink.try_send(bound);
        }
        let udp_bind_ip = self
            .udp_bind
            .clone()
            .unwrap_or_else(|| self.listen.ip().to_string());

        transport_rq::receive_bonded(
            cx,
            &descriptor,
            dest_dir,
            &listener,
            &udp_bind_ip,
            self.expect_donors,
            config,
            &self.peer_id,
            progress,
        )
        .await
    }

    /// The donor-leg body: derive the agreed descriptor from the local source,
    /// then enroll + spray + serve feedback until the receiver commits.
    async fn run_donate(&self, cx: &Cx) -> Result<BondedDonateReport, RqError> {
        let BondedLeg::Donate {
            source,
            control_addr,
        } = &self.leg
        else {
            return Err(RqError::Source(
                "run_donate called on a non-donor bonded leg".to_string(),
            ));
        };
        let config = self.build_config()?;
        let auth_key_id = self.resolved_auth_key_id()?;
        let symbol_size = config.symbol_size;
        let max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX);

        let descriptor = derive_bonded_descriptor(
            cx,
            source,
            symbol_size,
            max_block_size,
            self.max_bytes,
            auth_key_id,
        )
        .await?;
        let source_root = bonded_source_root(source)?;
        transport_rq::donate_bonded(cx, &descriptor, *control_addr, &source_root, config).await
    }
}

/// Resolved symbol-auth posture for the SDK (no ambient env is read).
enum SdkRqAuth {
    /// Explicit normalized (lowercase, `0x`-stripped) 64-hex key.
    KeyHex(String),
    /// Deliberately unauthenticated loopback/lab link.
    UnauthenticatedLab,
}

/// Terminal report from a bonded transfer driven by [`BondedTransfer::run`].
#[derive(Debug, Clone)]
pub enum BondedReport {
    /// A committed receiver leg.
    Receive(BondedReceiveReport),
    /// A completed donor leg.
    Donate(BondedDonateReport),
}

/// A live receiver-side progress snapshot, emitted at each round boundary and
/// once more on completion. Everything here is derivable at the receiver's
/// round boundary.
#[derive(Debug, Clone)]
pub struct BondedTransferProgress {
    /// Transfer identifier from the bonded descriptor.
    pub transfer_id: String,
    /// Symbols accepted into the decode pipeline so far (post-dedup).
    pub symbols_accepted: u64,
    /// Total bytes in the transfer.
    pub bytes_total: u64,
    /// Tracked source blocks in the transfer.
    pub blocks_total: u32,
    /// Tracked source blocks whose owning entry has not yet decoded.
    pub blocks_remaining: u32,
    /// Aggregate fountain feedback rounds used so far.
    pub feedback_rounds: u32,
    /// Repair symbols whose windows were reallocated from dead donors.
    pub reallocated_repair_windows: u64,
    /// Donor control connections enrolled for this transfer.
    pub enrolled_donors: u32,
    /// Per-donor ingress counters (only donors that delivered a datagram).
    pub donor_ingress: Vec<(u32, BondedDonorIngressStats)>,
    /// Current transfer phase: `DataTransfer` while blocks are pending, then a
    /// terminal `Completed` (success) or `Failed` (decoded but verification
    /// failed) snapshot. Cancellation and other terminal errors are observed as
    /// the progress stream closes; the authoritative outcome is the receiver
    /// handle's join result.
    pub phase: TransferPhase,
}

impl BondedTransferProgress {
    /// Block-completion progress percentage (0.0 to 100.0).
    #[must_use]
    pub fn progress_percent(&self) -> f64 {
        if self.blocks_total == 0 {
            return if self.is_complete() { 100.0 } else { 0.0 };
        }
        let done = self.blocks_total.saturating_sub(self.blocks_remaining);
        (f64::from(done) / f64::from(self.blocks_total)) * 100.0
    }

    /// Whether this snapshot is a terminal phase.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(
            self.phase,
            TransferPhase::Completed | TransferPhase::Failed | TransferPhase::Cancelled
        )
    }
}

/// A handle to a spawned bonded **receiver** leg (see [`BondedTransfer::spawn`]).
///
/// The receiver runs as an owned child of the spawning `Cx`'s region. This
/// handle observes its bound control address, its live progress stream, and its
/// terminal report, and can cancel it (cancel-correctly) at any time.
pub struct BondedReceiveHandle {
    progress_rx: mpsc::Receiver<BondedTransferProgress>,
    bound_rx: mpsc::Receiver<SocketAddr>,
    task: TaskHandle<Result<BondedReceiveReport, RqError>>,
    cx: Cx,
}

impl BondedReceiveHandle {
    /// Await the bound control address donors dial back.
    ///
    /// Returns `None` if the receiver ended (e.g. failed to derive its
    /// descriptor) before it bound the control listener.
    pub async fn control_addr(&mut self) -> Option<SocketAddr> {
        self.bound_rx.recv(&self.cx).await.ok()
    }

    /// Await the next live progress snapshot. Returns `None` once the receiver
    /// task has finished and closed the progress channel.
    pub async fn next_progress(&mut self) -> Option<BondedTransferProgress> {
        self.progress_rx.recv(&self.cx).await.ok()
    }

    /// Request cancellation of the receiver.
    ///
    /// Aborts the spawned child's `Cx`; the transport unwinds at its next
    /// checkpoint and commits nothing. This only requests cancellation —
    /// [`BondedReceiveHandle::wait_for_completion`] resolves the clean unwind.
    pub async fn cancel(&self) -> AtpOutcome<()> {
        self.task.abort();
        AtpOutcome::Ok(())
    }

    /// Wait for the receiver to finish and return its terminal report.
    pub async fn wait_for_completion(self) -> AtpOutcome<BondedReceiveReport> {
        let Self { mut task, cx, .. } = self;
        match task.join(&cx).await {
            Ok(Ok(report)) => AtpOutcome::Ok(report),
            Ok(Err(err)) => rq_error_to_atp_outcome(&cx, err),
            Err(JoinError::Cancelled(reason)) => AtpOutcome::Cancelled(reason),
            Err(JoinError::Panicked(payload)) => AtpOutcome::Panicked(payload),
            Err(JoinError::PolledAfterCompletion) => {
                AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError))
            }
        }
    }
}

/// Metadata policy for the bonded transfer config, matching the CLI's
/// `selected_cli_metadata_policy` (timestamps preserved). Descriptor identity
/// uses the stricter [`MetadataPolicy::portable`] capture inside
/// [`derive_bonded_descriptor`].
fn bonded_transfer_metadata_policy() -> MetadataPolicy {
    MetadataPolicy {
        preserve_timestamps: true,
        ..MetadataPolicy::default()
    }
}

/// Resolve the root directory whose relative entry paths back the descriptor
/// (a directory source is its own root; a single file resolves against its
/// parent). Mirrors the CLI's `bond_source_root`.
fn bonded_source_root(source: &Path) -> Result<PathBuf, RqError> {
    if source.is_dir() {
        return Ok(source.to_path_buf());
    }
    source.parent().map(Path::to_path_buf).ok_or_else(|| {
        RqError::Source(format!(
            "bonded donor source {} has no parent directory",
            source.display()
        ))
    })
}

/// Validate an expected donor count against the bonding ceiling.
fn validate_expected_donors(expected: u32) -> Result<(), RqError> {
    if expected == 0 {
        return Err(RqError::Source(
            "bonded receive needs at least one expected donor".to_string(),
        ));
    }
    if expected > MAX_BONDING_DONORS {
        return Err(RqError::Source(format!(
            "expect_donors {expected} exceeds the bonding ceiling of {MAX_BONDING_DONORS} donors"
        )));
    }
    Ok(())
}

/// Decode + validate a 32-byte hex RQ auth key, mirroring the CLI's
/// `auth_key_from_hex` (leading `0x` tolerated).
fn sdk_auth_key_from_hex(key_hex: &str) -> Result<AuthKey, RqError> {
    let trimmed = key_hex.trim();
    let key_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if key_hex.len() != AUTH_KEY_SIZE * 2 {
        return Err(RqError::Authentication(format!(
            "RQ auth key must be exactly {} hex characters for a {AUTH_KEY_SIZE}-byte key",
            AUTH_KEY_SIZE * 2
        )));
    }
    if !key_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(RqError::Authentication(
            "RQ auth key must contain only hexadecimal characters".to_string(),
        ));
    }
    let mut bytes = [0u8; AUTH_KEY_SIZE];
    hex::decode_to_slice(key_hex, &mut bytes)
        .map_err(|err| RqError::Authentication(format!("decode RQ auth key hex: {err}")))?;
    AuthKey::from_bytes(bytes)
        .map_err(|err| RqError::Authentication(format!("RQ auth key rejected: {err}")))
}

/// Map a transport [`RqError`] into the SDK's [`AtpOutcome`] taxonomy, routing
/// cancellation (explicit or the `poll_accept` interrupt) to the cancel
/// channel and preserving the original message via a `cx` trace.
fn rq_error_to_atp_outcome<T>(cx: &Cx, err: RqError) -> AtpOutcome<T> {
    cx.trace(&format!("atp bonded sdk error: {err}"));
    match err {
        RqError::Cancelled => {
            AtpOutcome::Cancelled(CancelReason::user("bonded transfer cancelled"))
        }
        RqError::Io(io) => match io.kind() {
            std::io::ErrorKind::Interrupted => {
                AtpOutcome::Cancelled(CancelReason::user("bonded transfer cancelled"))
            }
            std::io::ErrorKind::TimedOut => {
                AtpOutcome::Err(AtpError::Transport(TransportError::ConnectionTimeout))
            }
            _ => AtpOutcome::Err(AtpError::Transport(TransportError::ConnectionReset)),
        },
        RqError::HandshakeRejected(_) => {
            AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
        }
        RqError::Unexpected { .. } | RqError::Frame(_) | RqError::Control(_) => {
            AtpOutcome::Err(AtpError::Protocol(ProtocolError::MalformedFrame))
        }
        RqError::Authentication(_) => AtpOutcome::Err(AtpError::Auth(AuthError::InvalidSignature)),
        RqError::Integrity(_) => AtpOutcome::Err(AtpError::Manifest(ManifestError::HashMismatch)),
        RqError::Source(_) => AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
        RqError::TooLarge { .. } => AtpOutcome::Err(AtpError::Disk(DiskError::QuotaExceeded)),
        RqError::Coding(_) | RqError::NoConvergence { .. } => {
            AtpOutcome::Err(AtpError::Repair(RepairError::DecodeFailure))
        }
    }
}

#[cfg(test)]
#[path = "bonded_inline_tests.rs"]
mod tests;
