//! Transfer Actor implementation for ATP session management.
//!
//! Defines TransferActor and ownership topology for transfer sessions,
//! providing the actor model foundation for the data-aware transfer brain.

use crate::atp::object::ObjectId;
use crate::atp::transfer_brain::{
    ChunkId, ScheduledChunk, SystemPressure, TransferBrain, TransferBrainConfig,
};
use crate::channel::{mpsc, oneshot};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind, Result};
use crate::time::{Sleep, wall_now};
use crate::types::{RegionId, TaskId, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};
#[cfg(feature = "tracing-integration")]
use tracing::{debug, error, info, warn};

// Provide no-op tracing macros when tracing is disabled
#[cfg(not(feature = "tracing-integration"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! error {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! warn {
    ($($arg:tt)*) => {};
}

/// Configuration for transfer actor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferActorConfig {
    /// Transfer brain configuration
    pub brain_config: TransferBrainConfig,
    /// Maximum concurrent transfer sessions
    pub max_concurrent_sessions: usize,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Pressure monitoring interval
    pub pressure_monitor_interval: Duration,
    /// Resource monitoring enabled
    pub enable_resource_monitoring: bool,
}

impl Default for TransferActorConfig {
    fn default() -> Self {
        Self {
            brain_config: TransferBrainConfig::default(),
            max_concurrent_sessions: 64,
            session_timeout: Duration::from_secs(3600), // 1 hour
            pressure_monitor_interval: Duration::from_secs(1),
            enable_resource_monitoring: true,
        }
    }
}

/// Unique identifier for a transfer session
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    /// Object being transferred
    pub object_id: ObjectId,
    /// Session start timestamp
    pub started_at: SystemTime,
    /// Unique session counter
    pub session_counter: u64,
}

impl SessionId {
    /// Create a new session ID
    pub fn new(object_id: ObjectId, session_counter: u64) -> Self {
        Self {
            object_id,
            started_at: SystemTime::now(),
            session_counter,
        }
    }

    /// Get string representation for logging
    pub fn as_string(&self) -> String {
        format!("sess-{}-{}", self.object_id, self.session_counter)
    }
}

/// State of a transfer session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is initializing
    Initializing,
    /// Session is actively transferring data
    Active,
    /// Session is paused due to pressure or backpressure
    Paused,
    /// Session is completing final operations
    Completing,
    /// Session completed successfully
    Completed,
    /// Session failed with error
    Failed,
    /// Session was cancelled
    Cancelled,
}

/// A transfer session managed by the transfer actor
#[derive(Debug)]
pub struct TransferSession {
    /// Session identifier
    pub session_id: SessionId,
    /// Current session state
    pub state: SessionState,
    /// Object being transferred
    pub object_id: ObjectId,
    /// Session-specific transfer brain
    pub brain: TransferBrain,
    /// Region that owns this session
    pub region_id: RegionId,
    /// Task handling this session
    pub task_id: TaskId,
    /// Session start time
    pub started_at: SystemTime,
    /// Last activity timestamp
    pub last_activity: SystemTime,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Total chunks completed
    pub chunks_completed: usize,
    /// Current error (if any)
    pub error: Option<Error>,
    /// Session trace ID
    pub trace_id: TraceId,
}

impl TransferSession {
    /// Create a new transfer session
    pub fn new(
        session_id: SessionId,
        object_id: ObjectId,
        region_id: RegionId,
        task_id: TaskId,
        brain_config: TransferBrainConfig,
        trace_id: TraceId,
    ) -> Self {
        Self {
            session_id,
            state: SessionState::Initializing,
            object_id,
            brain: TransferBrain::new(brain_config),
            region_id,
            task_id,
            started_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            bytes_transferred: 0,
            chunks_completed: 0,
            error: None,
            trace_id,
        }
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            SessionState::Active | SessionState::Initializing
        )
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed().unwrap_or(Duration::ZERO) > timeout
    }

    /// Update session activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }

    /// Transition session to new state
    pub fn transition_to(&mut self, new_state: SessionState) {
        if self.state != new_state {
            debug!(
                "Session {} transitioning from {:?} to {:?}",
                self.session_id.as_string(),
                self.state,
                new_state
            );
            self.state = new_state;
            self.update_activity();
        }
    }

    /// Set session error and transition to failed state
    pub fn fail_with_error(&mut self, error: Error) {
        self.error = Some(error);
        self.transition_to(SessionState::Failed);
    }
}

/// Message types for transfer actor communication
#[derive(Debug)]
pub enum TransferMessage {
    /// Start a new transfer session
    StartSession {
        object_id: ObjectId,
        region_id: RegionId,
        task_id: TaskId,
        trace_id: TraceId,
        response_tx: oneshot::Sender<Result<SessionId>>,
    },

    /// Schedule a chunk for transfer
    ScheduleChunk {
        session_id: SessionId,
        chunk: ScheduledChunk,
        response_tx: oneshot::Sender<Result<()>>,
    },

    /// Complete a chunk transfer
    CompleteChunk {
        session_id: SessionId,
        chunk_id: ChunkId,
        success: bool,
        bytes_transferred: u64,
        response_tx: oneshot::Sender<Result<()>>,
    },

    /// Update system pressure
    UpdatePressure { pressure: SystemPressure },

    /// Pause a transfer session
    PauseSession {
        session_id: SessionId,
        response_tx: oneshot::Sender<Result<()>>,
    },

    /// Resume a paused session
    ResumeSession {
        session_id: SessionId,
        response_tx: oneshot::Sender<Result<()>>,
    },

    /// Cancel a transfer session
    CancelSession {
        session_id: SessionId,
        response_tx: oneshot::Sender<Result<()>>,
    },

    /// Get session status
    GetSessionStatus {
        session_id: SessionId,
        response_tx: oneshot::Sender<Result<TransferSessionStatus>>,
    },

    /// Get all sessions status
    GetAllSessions {
        response_tx: oneshot::Sender<Result<Vec<TransferSessionStatus>>>,
    },

    /// Shutdown the transfer actor
    Shutdown,
}

/// Status information about a transfer session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSessionStatus {
    /// Session identifier
    pub session_id: SessionId,
    /// Current state
    pub state: SessionState,
    /// Object being transferred
    pub object_id: ObjectId,
    /// Session duration
    pub duration: Duration,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Chunks completed
    pub chunks_completed: usize,
    /// Current brain state
    pub brain_state: crate::atp::transfer_brain::SchedulingState,
    /// Current metrics
    pub metrics: crate::atp::transfer_brain::TransferMetrics,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Transfer actor for managing transfer sessions
pub struct TransferActor {
    /// Actor configuration
    config: TransferActorConfig,
    /// Active transfer sessions
    sessions: HashMap<SessionId, TransferSession>,
    /// Session counter for unique IDs
    session_counter: u64,
    /// Current system pressure
    current_pressure: SystemPressure,
    /// Message receiver
    message_rx: mpsc::Receiver<TransferMessage>,
    /// Message sender handle for cloning
    message_tx: mpsc::Sender<TransferMessage>,
}

impl TransferActor {
    /// Create a new transfer actor
    pub fn new(config: TransferActorConfig) -> (Self, TransferActorHandle) {
        let (message_tx, message_rx) = mpsc::channel(1000);

        let actor = Self {
            config: config.clone(),
            sessions: HashMap::new(),
            session_counter: 0,
            current_pressure: SystemPressure::default(),
            message_rx,
            message_tx: message_tx.clone(),
        };

        let handle = TransferActorHandle { message_tx };

        (actor, handle)
    }

    /// Run the transfer actor event loop
    pub async fn run(mut self, cx: &Cx) -> Result<()> {
        info!("Transfer actor starting");

        let maintenance_interval = self.config.session_timeout / 10;
        let mut last_maintenance = SystemTime::now();

        loop {
            // Check for cancellation
            if cx.is_cancel_requested() {
                info!("Transfer actor cancelled, shutting down");
                break;
            }

            // Try to receive a message (non-blocking)
            match self.message_rx.try_recv() {
                Ok(msg) => {
                    let shutdown = matches!(msg, TransferMessage::Shutdown);
                    if self.handle_message(cx, msg).await.is_err() {
                        error!("Error handling transfer actor message");
                    }

                    // Check if it's shutdown
                    if shutdown {
                        break;
                    }
                }
                Err(_) => {
                    // No message available, check if maintenance is needed
                    if last_maintenance.elapsed().unwrap_or(Duration::ZERO) > maintenance_interval {
                        self.cleanup_timed_out_sessions().await;
                        last_maintenance = SystemTime::now();
                    }

                    // Small delay to avoid busy spinning
                    Sleep::after(wall_now(), Duration::from_millis(10)).await;
                }
            }
        }

        info!("Transfer actor shut down");
        Ok(())
    }

    async fn handle_message(&mut self, cx: &Cx, message: TransferMessage) -> Result<()> {
        match message {
            TransferMessage::StartSession {
                object_id,
                region_id,
                task_id,
                trace_id,
                response_tx,
            } => {
                let result = self
                    .start_session(object_id, region_id, task_id, trace_id)
                    .await;
                if response_tx.send(cx, result).is_err() {
                    debug!("Failed to send start session response");
                }
            }

            TransferMessage::ScheduleChunk {
                session_id,
                chunk,
                response_tx,
            } => {
                let result = self.schedule_chunk(session_id, chunk).await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::CompleteChunk {
                session_id,
                chunk_id,
                success,
                bytes_transferred,
                response_tx,
            } => {
                let result = self
                    .complete_chunk(session_id, chunk_id, success, bytes_transferred)
                    .await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::UpdatePressure { pressure } => {
                self.update_pressure(pressure).await;
            }

            TransferMessage::PauseSession {
                session_id,
                response_tx,
            } => {
                let result = self.pause_session(session_id).await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::ResumeSession {
                session_id,
                response_tx,
            } => {
                let result = self.resume_session(session_id).await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::CancelSession {
                session_id,
                response_tx,
            } => {
                let result = self.cancel_session(session_id).await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::GetSessionStatus {
                session_id,
                response_tx,
            } => {
                let result = self.get_session_status(session_id).await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::GetAllSessions { response_tx } => {
                let result = self.get_all_sessions().await;
                let _ = response_tx.send(cx, result);
            }

            TransferMessage::Shutdown => {
                info!("Transfer actor received shutdown message");
                // Gracefully shut down all sessions
                for session in self.sessions.values_mut() {
                    if session.is_active() {
                        session.transition_to(SessionState::Cancelled);
                    }
                }
            }
        }

        Ok(())
    }

    async fn start_session(
        &mut self,
        object_id: ObjectId,
        region_id: RegionId,
        task_id: TaskId,
        trace_id: TraceId,
    ) -> Result<SessionId> {
        if self.sessions.len() >= self.config.max_concurrent_sessions {
            return Err(Error::new(ErrorKind::AdmissionDenied));
        }

        self.session_counter += 1;
        let session_id = SessionId::new(object_id.clone(), self.session_counter);

        let session = TransferSession::new(
            session_id.clone(),
            object_id,
            region_id,
            task_id,
            self.config.brain_config.clone(),
            trace_id,
        );

        info!("Started transfer session {}", session_id.as_string());
        self.sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    async fn schedule_chunk(&mut self, session_id: SessionId, chunk: ScheduledChunk) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        if !session.is_active() {
            return Err(Error::new(ErrorKind::RegionClosed));
        }

        session.brain.schedule_chunk(chunk)?;
        session.update_activity();

        if session.state == SessionState::Initializing {
            session.transition_to(SessionState::Active);
        }

        Ok(())
    }

    async fn complete_chunk(
        &mut self,
        session_id: SessionId,
        chunk_id: ChunkId,
        success: bool,
        bytes_transferred: u64,
    ) -> Result<()> {
        let pressure = self.current_pressure.clone();
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        let actual_resources =
            measured_completion_resources(session, &pressure, &chunk_id, bytes_transferred);

        session
            .brain
            .complete_chunk(&chunk_id, success, actual_resources)?;
        session.update_activity();

        if success {
            session.bytes_transferred += bytes_transferred;
            session.chunks_completed += 1;
        }

        debug!(
            "Completed chunk {} in session {} (success: {}, bytes: {})",
            chunk_id.as_string(),
            session_id.as_string(),
            success,
            bytes_transferred
        );

        Ok(())
    }

    async fn update_pressure(&mut self, pressure: SystemPressure) {
        self.current_pressure = pressure.clone();

        // Update pressure in all active sessions
        for session in self.sessions.values_mut() {
            if session.is_active() {
                session.brain.update_pressure(pressure.clone());
            }
        }

        // Pause sessions if pressure is too high
        if pressure.cpu_utilization > 0.95 || pressure.disk_pressure > 0.9 {
            for session in self.sessions.values_mut() {
                if session.state == SessionState::Active {
                    session.transition_to(SessionState::Paused);
                }
            }
        }
    }

    async fn pause_session(&mut self, session_id: SessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        if session.state == SessionState::Active {
            session.transition_to(SessionState::Paused);
            info!("Paused session {}", session_id.as_string());
        }

        Ok(())
    }

    async fn resume_session(&mut self, session_id: SessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        if session.state == SessionState::Paused {
            session.transition_to(SessionState::Active);
            info!("Resumed session {}", session_id.as_string());
        }

        Ok(())
    }

    async fn cancel_session(&mut self, session_id: SessionId) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            session.transition_to(SessionState::Cancelled);
            info!("Cancelled session {}", session_id.as_string());
        }

        Ok(())
    }

    async fn get_session_status(&self, session_id: SessionId) -> Result<TransferSessionStatus> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        Ok(TransferSessionStatus {
            session_id: session.session_id.clone(),
            state: session.state,
            object_id: session.object_id.clone(),
            duration: session.started_at.elapsed().unwrap_or(Duration::ZERO),
            bytes_transferred: session.bytes_transferred,
            chunks_completed: session.chunks_completed,
            brain_state: session.brain.scheduling_state(),
            metrics: session.brain.metrics().clone(),
            error_message: session.error.as_ref().map(|e| format!("{:?}", e)),
        })
    }

    async fn get_all_sessions(&self) -> Result<Vec<TransferSessionStatus>> {
        let mut statuses = Vec::new();

        for session in self.sessions.values() {
            statuses.push(TransferSessionStatus {
                session_id: session.session_id.clone(),
                state: session.state,
                object_id: session.object_id.clone(),
                duration: session.started_at.elapsed().unwrap_or(Duration::ZERO),
                bytes_transferred: session.bytes_transferred,
                chunks_completed: session.chunks_completed,
                brain_state: session.brain.scheduling_state(),
                metrics: session.brain.metrics().clone(),
                error_message: session.error.as_ref().map(|e| format!("{:?}", e)),
            });
        }

        Ok(statuses)
    }

    async fn cleanup_timed_out_sessions(&mut self) {
        let timeout = self.config.session_timeout;
        let mut to_remove = Vec::new();

        for (session_id, session) in &mut self.sessions {
            if session.is_timed_out(timeout) {
                session.transition_to(SessionState::Failed);
                to_remove.push(session_id.clone());
            }
        }

        for session_id in to_remove {
            self.sessions.remove(&session_id);
            warn!("Cleaned up timed out session {}", session_id.as_string());
        }
    }

    pub async fn run_pressure_monitor(&self, cx: &Cx) -> Result<()> {
        let tx = self.message_tx.clone();
        let interval = self.config.pressure_monitor_interval;
        let mut sampler = SystemPressureSampler::new();

        loop {
            if cx.is_cancel_requested() {
                return Ok(());
            }

            Sleep::after(wall_now(), interval).await;
            let pressure = sampler.sample();
            tx.send(cx, TransferMessage::UpdatePressure { pressure })
                .await
                .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;
        }
    }
}

/// Handle for communicating with the transfer actor
#[derive(Clone)]
pub struct TransferActorHandle {
    message_tx: mpsc::Sender<TransferMessage>,
}

impl TransferActorHandle {
    /// Start a new transfer session
    pub async fn start_session(
        &self,
        cx: &Cx,
        object_id: ObjectId,
        region_id: RegionId,
        task_id: TaskId,
        trace_id: TraceId,
    ) -> Result<SessionId> {
        let (response_tx, response_rx) = oneshot::channel();

        self.message_tx
            .send(
                cx,
                TransferMessage::StartSession {
                    object_id,
                    region_id,
                    task_id,
                    trace_id,
                    response_tx,
                },
            )
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        let mut response_rx = response_rx;
        response_rx
            .recv(cx)
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Schedule a chunk for transfer
    pub async fn schedule_chunk(
        &self,
        cx: &Cx,
        session_id: SessionId,
        chunk: ScheduledChunk,
    ) -> Result<()> {
        let (response_tx, mut response_rx) = oneshot::channel();

        self.message_tx
            .send(
                cx,
                TransferMessage::ScheduleChunk {
                    session_id,
                    chunk,
                    response_tx,
                },
            )
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv(cx)
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Complete a chunk transfer
    pub async fn complete_chunk(
        &self,
        cx: &Cx,
        session_id: SessionId,
        chunk_id: ChunkId,
        success: bool,
        bytes_transferred: u64,
    ) -> Result<()> {
        let (response_tx, mut response_rx) = oneshot::channel();

        self.message_tx
            .send(
                cx,
                TransferMessage::CompleteChunk {
                    session_id,
                    chunk_id,
                    success,
                    bytes_transferred,
                    response_tx,
                },
            )
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv(cx)
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Get session status
    pub async fn get_session_status(
        &self,
        cx: &Cx,
        session_id: SessionId,
    ) -> Result<TransferSessionStatus> {
        let (response_tx, mut response_rx) = oneshot::channel();

        self.message_tx
            .send(
                cx,
                TransferMessage::GetSessionStatus {
                    session_id,
                    response_tx,
                },
            )
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv(cx)
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Shutdown the transfer actor
    pub async fn shutdown(&self, cx: &Cx) -> Result<()> {
        self.message_tx
            .send(cx, TransferMessage::Shutdown)
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;
        Ok(())
    }
}
fn measured_completion_resources(
    session: &TransferSession,
    pressure: &SystemPressure,
    chunk_id: &ChunkId,
    bytes_transferred: u64,
) -> crate::atp::transfer_brain::ResourceUsage {
    let duration = session
        .last_activity
        .elapsed()
        .unwrap_or(Duration::ZERO)
        .max(Duration::from_millis(1));
    let duration_secs = duration.as_secs_f64().max(0.001);
    let cpu_seconds = pressure.cpu_utilization.clamp(0.0, 1.0) * duration_secs;
    let disk_bytes = chunk_id.size.max(bytes_transferred as usize) as f64
        * pressure.disk_pressure.clamp(0.0, 1.0).max(0.01);

    crate::atp::transfer_brain::ResourceUsage {
        cpu: cpu_seconds,
        disk_io: disk_bytes,
        network: bytes_transferred as f64,
        memory: chunk_id.size as f64,
        duration,
    }
}

#[derive(Debug, Clone)]
struct SystemPressureSampler {
    previous_cpu: Option<CpuSnapshot>,
    previous_disk: Option<DiskSnapshot>,
    previous_network: Option<NetworkSnapshot>,
    peak_network_bytes_per_second: f64,
}

impl SystemPressureSampler {
    fn new() -> Self {
        Self {
            previous_cpu: read_cpu_snapshot(),
            previous_disk: read_disk_snapshot(),
            previous_network: read_network_snapshot(),
            peak_network_bytes_per_second: 0.0,
        }
    }

    fn sample(&mut self) -> SystemPressure {
        let cpu_snapshot = read_cpu_snapshot();
        let cpu_utilization = cpu_snapshot
            .as_ref()
            .and_then(|current| {
                self.previous_cpu
                    .as_ref()
                    .map(|previous| current.utilization_since(previous))
            })
            .unwrap_or(0.0);
        self.previous_cpu = cpu_snapshot;

        let disk_snapshot = read_disk_snapshot();
        let disk_pressure = disk_snapshot
            .as_ref()
            .and_then(|current| {
                self.previous_disk
                    .as_ref()
                    .map(|previous| current.pressure_since(previous))
            })
            .unwrap_or(0.0);
        self.previous_disk = disk_snapshot;

        let network_snapshot = read_network_snapshot();
        let network_pressure = network_snapshot
            .as_ref()
            .and_then(|current| {
                self.previous_network.as_ref().map(|previous| {
                    current.pressure_since(previous, &mut self.peak_network_bytes_per_second)
                })
            })
            .unwrap_or(0.0);
        self.previous_network = network_snapshot;

        SystemPressure {
            cpu_utilization,
            disk_pressure,
            network_pressure,
            memory_pressure: read_memory_pressure().unwrap_or(0.0),
            measured_at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CpuSnapshot {
    idle: u64,
    total: u64,
}

impl CpuSnapshot {
    fn utilization_since(self, previous: &Self) -> f64 {
        let total_delta = self.total.saturating_sub(previous.total);
        if total_delta == 0 {
            return 0.0;
        }

        let idle_delta = self.idle.saturating_sub(previous.idle);
        ((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Copy)]
struct DiskSnapshot {
    weighted_io_millis: u64,
    sampled_at: Instant,
}

impl DiskSnapshot {
    fn pressure_since(self, previous: &Self) -> f64 {
        let elapsed_millis = self
            .sampled_at
            .saturating_duration_since(previous.sampled_at)
            .as_millis()
            .max(1) as f64;
        let io_delta = self
            .weighted_io_millis
            .saturating_sub(previous.weighted_io_millis) as f64;

        (io_delta / elapsed_millis).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Copy)]
struct NetworkSnapshot {
    bytes: u64,
    sampled_at: Instant,
}

impl NetworkSnapshot {
    fn pressure_since(self, previous: &Self, peak_bytes_per_second: &mut f64) -> f64 {
        let elapsed_secs = self
            .sampled_at
            .saturating_duration_since(previous.sampled_at)
            .as_secs_f64()
            .max(0.001);
        let byte_delta = self.bytes.saturating_sub(previous.bytes) as f64;
        let bytes_per_second = byte_delta / elapsed_secs;
        *peak_bytes_per_second = (*peak_bytes_per_second).max(bytes_per_second);

        if *peak_bytes_per_second <= f64::EPSILON {
            0.0
        } else {
            (bytes_per_second / *peak_bytes_per_second).clamp(0.0, 1.0)
        }
    }
}

fn read_cpu_snapshot() -> Option<CpuSnapshot> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let cpu_line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let mut values = cpu_line
        .split_whitespace()
        .skip(1)
        .filter_map(|field| field.parse::<u64>().ok());
    let user = values.next()?;
    let nice = values.next()?;
    let system = values.next()?;
    let idle = values.next()?;
    let iowait = values.next().unwrap_or(0);
    let irq = values.next().unwrap_or(0);
    let softirq = values.next().unwrap_or(0);
    let steal = values.next().unwrap_or(0);
    let idle_all = idle.saturating_add(iowait);
    let total = user
        .saturating_add(nice)
        .saturating_add(system)
        .saturating_add(idle)
        .saturating_add(iowait)
        .saturating_add(irq)
        .saturating_add(softirq)
        .saturating_add(steal);

    Some(CpuSnapshot {
        idle: idle_all,
        total,
    })
}

fn read_memory_pressure() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kib = None;
    let mut available_kib = None;

    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kib = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kib = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok());
        }
    }

    let total_kib = total_kib?;
    if total_kib == 0 {
        return None;
    }
    let available_kib = available_kib?;
    Some((1.0 - (available_kib as f64 / total_kib as f64)).clamp(0.0, 1.0))
}

fn read_disk_snapshot() -> Option<DiskSnapshot> {
    let diskstats = std::fs::read_to_string("/proc/diskstats").ok()?;
    let weighted_io_millis = diskstats
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let device = *fields.get(2)?;
            if device.starts_with("loop") || device.starts_with("ram") {
                return None;
            }
            fields.get(13)?.parse::<u64>().ok()
        })
        .fold(0_u64, u64::saturating_add);

    Some(DiskSnapshot {
        weighted_io_millis,
        sampled_at: Instant::now(),
    })
}

fn read_network_snapshot() -> Option<NetworkSnapshot> {
    let netdev = std::fs::read_to_string("/proc/net/dev").ok()?;
    let bytes = netdev
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (interface, counters) = line.split_once(':')?;
            if interface.trim() == "lo" {
                return None;
            }
            let mut fields = counters.split_whitespace();
            let rx_bytes = fields.next()?.parse::<u64>().ok()?;
            let tx_bytes = fields.nth(7)?.parse::<u64>().ok()?;
            Some(rx_bytes.saturating_add(tx_bytes))
        })
        .fold(0_u64, u64::saturating_add);

    Some(NetworkSnapshot {
        bytes,
        sampled_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;

    #[test]
    fn test_transfer_actor_creation() {
        let config = TransferActorConfig::default();
        let (actor, _handle) = TransferActor::new(config);

        assert_eq!(actor.session_counter, 0);
        assert!(actor.sessions.is_empty());
    }

    #[test]
    fn test_session_state_transition() {
        let object_id = ObjectId::content(ContentId::from_bytes(b"test-object"));
        let session_id = SessionId::new(object_id.clone(), 1);
        let mut session = TransferSession::new(
            session_id,
            object_id,
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(2, 0),
            TransferBrainConfig::default(),
            TraceId::from_raw(3),
        );

        assert_eq!(session.state, SessionState::Initializing);
        session.transition_to(SessionState::Active);
        assert_eq!(session.state, SessionState::Active);
    }
}
