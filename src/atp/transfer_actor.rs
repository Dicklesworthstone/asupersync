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
use crate::time::Sleep;
use crate::types::{RegionId, TaskId, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

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

        let handle = TransferActorHandle { message_tx, config };

        (actor, handle)
    }

    /// Run the transfer actor event loop
    pub async fn run(mut self, cx: &Cx) -> Result<()> {
        info!("Transfer actor starting");

        let maintenance_interval = self.config.session_timeout / 10;
        let mut last_maintenance = SystemTime::now();

        loop {
            // Check for cancellation
            if cx.is_cancelled() {
                info!("Transfer actor cancelled, shutting down");
                break;
            }

            // Try to receive a message (non-blocking)
            match self.message_rx.try_recv() {
                Ok(msg) => {
                    if let Err(e) = self.handle_message(msg).await {
                        error!("Error handling message: {:?}", e);
                    }

                    // Check if it's shutdown
                    if matches!(msg, TransferMessage::Shutdown) {
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
                    Sleep::new(SystemTime::now() + Duration::from_millis(10)).await;
                }
            }
        }

        info!("Transfer actor shut down");
        Ok(())
    }

    async fn handle_message(&mut self, message: TransferMessage) -> Result<()> {
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
                if let Err(_) = response_tx.send(result) {
                    debug!("Failed to send start session response");
                }
            }

            TransferMessage::ScheduleChunk {
                session_id,
                chunk,
                response_tx,
            } => {
                let result = self.schedule_chunk(session_id, chunk).await;
                let _ = response_tx.send(result);
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
                let _ = response_tx.send(result);
            }

            TransferMessage::UpdatePressure { pressure } => {
                self.update_pressure(pressure).await;
            }

            TransferMessage::PauseSession {
                session_id,
                response_tx,
            } => {
                let result = self.pause_session(session_id).await;
                let _ = response_tx.send(result);
            }

            TransferMessage::ResumeSession {
                session_id,
                response_tx,
            } => {
                let result = self.resume_session(session_id).await;
                let _ = response_tx.send(result);
            }

            TransferMessage::CancelSession {
                session_id,
                response_tx,
            } => {
                let result = self.cancel_session(session_id).await;
                let _ = response_tx.send(result);
            }

            TransferMessage::GetSessionStatus {
                session_id,
                response_tx,
            } => {
                let result = self.get_session_status(session_id).await;
                let _ = response_tx.send(result);
            }

            TransferMessage::GetAllSessions { response_tx } => {
                let result = self.get_all_sessions().await;
                let _ = response_tx.send(result);
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
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::new(ErrorKind::ObjectMismatch))?;

        let actual_resources = crate::atp::transfer_brain::ResourceUsage {
            cpu: 0.1, // TODO: Measure actual CPU usage
            disk_io: 0.05,
            network: bytes_transferred as f64,
            memory: chunk_id.size as f64,
            duration: Duration::from_millis(100), // TODO: Measure actual duration
        };

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

    async fn start_pressure_monitor(&self) -> tokio::task::JoinHandle<()> {
        let tx = self.message_tx.clone();
        let interval = self.config.pressure_monitor_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // TODO: Implement actual system pressure monitoring
                let pressure = SystemPressure {
                    cpu_utilization: 0.3, // Placeholder
                    disk_pressure: 0.2,
                    network_pressure: 0.1,
                    memory_pressure: 0.4,
                    measured_at: SystemTime::now(),
                };

                let _ = tx.send(TransferMessage::UpdatePressure { pressure });
            }
        })
    }
}

/// Handle for communicating with the transfer actor
#[derive(Clone)]
pub struct TransferActorHandle {
    message_tx: mpsc::Sender<TransferMessage>,
    config: TransferActorConfig,
}

impl TransferActorHandle {
    /// Start a new transfer session
    pub async fn start_session(
        &self,
        object_id: ObjectId,
        region_id: RegionId,
        task_id: TaskId,
        trace_id: TraceId,
    ) -> Result<SessionId> {
        let (response_tx, response_rx) = oneshot::channel();

        self.message_tx
            .send(TransferMessage::StartSession {
                object_id,
                region_id,
                task_id,
                trace_id,
                response_tx,
            })
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .await
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Schedule a chunk for transfer
    pub async fn schedule_chunk(&self, session_id: SessionId, chunk: ScheduledChunk) -> Result<()> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();

        self.message_tx
            .send(TransferMessage::ScheduleChunk {
                session_id,
                chunk,
                response_tx,
            })
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Complete a chunk transfer
    pub async fn complete_chunk(
        &self,
        session_id: SessionId,
        chunk_id: ChunkId,
        success: bool,
        bytes_transferred: u64,
    ) -> Result<()> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();

        self.message_tx
            .send(TransferMessage::CompleteChunk {
                session_id,
                chunk_id,
                success,
                bytes_transferred,
                response_tx,
            })
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Get session status
    pub async fn get_session_status(&self, session_id: SessionId) -> Result<TransferSessionStatus> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();

        self.message_tx
            .send(TransferMessage::GetSessionStatus {
                session_id,
                response_tx,
            })
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;

        response_rx
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::ChannelClosed))?
    }

    /// Shutdown the transfer actor
    pub fn shutdown(&self) -> Result<()> {
        self.message_tx
            .send(TransferMessage::Shutdown)
            .map_err(|_| Error::new(ErrorKind::ChannelClosed))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::transfer_brain::{ScheduledChunk, TransferPriority};
    // TODO: Reimplement tests with asupersync async primitives

    // TODO: Reimplement with asupersync async primitives
    /*
    #[test]
    fn test_transfer_actor_creation() {
        let config = TransferActorConfig::default();
        let (actor, handle) = TransferActor::new(config);

        // Should be able to create handle
        // TODO: Fix assertion for asupersync channels
    }

    #[test]
    fn test_session_lifecycle() {
        let config = TransferActorConfig {
            enable_resource_monitoring: false, // Disable for test
            ..TransferActorConfig::default()
        };
        let (mut actor, handle) = TransferActor::new(config);

        // Start actor in background
        let cx = crate::cx::Cx::root();
        tokio::spawn(async move {
            let _ = actor.run(&cx).await;
        });

        // Start a session
        let object_id = ObjectId::from("test-object");
        let region_id = RegionId::new();
        let task_id = TaskId::new();
        let trace_id = TraceId::new();

        let session_id = timeout(Duration::from_secs(1),
            handle.start_session(object_id.clone(), region_id, task_id, trace_id))
            .await.unwrap().unwrap();

        // Get session status
        let status = timeout(Duration::from_secs(1),
            handle.get_session_status(session_id.clone()))
            .await.unwrap().unwrap();

        assert_eq!(status.object_id, object_id);
        assert_eq!(status.state, SessionState::Initializing);

        // handle.shutdown().unwrap();
    }
    */
}
