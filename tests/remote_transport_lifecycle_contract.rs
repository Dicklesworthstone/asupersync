#![cfg(feature = "test-internals")]
//! Production-transport-backed proof for the RemoteRuntime lifecycle contract.

use asupersync::channel::oneshot;
use asupersync::distributed::{ComputationRegistryFingerprint, ComputationSchemaRegistry};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::remote::{
    ComputationName, IdempotencyKey, LeaseRenewal, MessageEnvelope, NodeId,
    RemoteComputationRegistry, RemoteError, RemoteInput, RemoteMessage, RemoteOutcome,
    RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion, RemoteRuntime, RemoteTaskId,
    RemoteTaskState, RemoteTransport, SpawnRejectReason, SpawnRequest, spawn_remote,
};
#[cfg(feature = "tls")]
use asupersync::remote::{
    NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeBuildError,
    NativeRemoteRuntimeConfig, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationClientError, RemoteComputationListenerError, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceError, RemoteComputationServiceHandle,
    RemoteComputationServiceReport, RemoteComputationSessionStart, RemoteServiceRejectionCode,
    RemoteServiceSessionCommand, RemoteServiceSessionError, RemoteServiceSessionEvent,
    RemoteServiceWireLimits, RemoteServiceWireOutcome, RemoteServiceWireRequest,
    RemoteServiceWireResponse, call_tls_computation_once, serve_tls_computation_once,
};
#[cfg(all(feature = "remote-service", unix))]
use asupersync::remote::{
    RemoteComputationServiceBootstrap, RemoteComputationServiceBootstrapError,
};
#[cfg(all(feature = "remote-service", unix))]
use asupersync::runtime::Runtime;
#[cfg(feature = "tls")]
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "tls")]
use asupersync::server::ShutdownPhase;
#[cfg(feature = "tls")]
use asupersync::service::{Discover, DnsDiscoveryConfig, DnsServiceDiscovery, StaticList};
#[cfg(feature = "tls")]
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::trace::TraceBufferHandle;
use asupersync::trace::distributed::LogicalTime;
#[cfg(feature = "tls")]
use asupersync::types::CancelKind;
use asupersync::types::CancelReason;
#[cfg(feature = "tls")]
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::{Budget, Cx};
use futures_lite::future::block_on;
use parking_lot::Mutex;
#[cfg(feature = "tls")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "tls")]
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const BEAD_ID: &str = "asupersync-5d9s85";
const ORIGIN_NODE: &str = "origin-prod-loopback";
const REMOTE_NODE: &str = "remote-prod-loopback";
const TRANSPORT_KIND: &str = "asupersync_tcp_loopback";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const RUNNER_PATH: &str = "scripts/run_remote_transport_lifecycle_evidence.sh";
#[cfg(feature = "tls")]
const REMOTE_CANCEL_REASON_TEST_MAX_DEPTH: usize = 64;
#[cfg(feature = "tls")]
const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
#[cfg(feature = "tls")]
const TEST_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum WireCommand {
    Spawn {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        computation: String,
        input_len: usize,
        lease_ms: u64,
        idempotency_key: String,
        sender_lamport: u64,
    },
    Cancel {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        reason: String,
        sender_lamport: u64,
    },
    LeaseProbe {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        lease_ms: u64,
        sender_lamport: u64,
    },
}

impl WireCommand {
    fn remote_task_id(&self) -> u64 {
        match self {
            Self::Spawn { remote_task_id, .. }
            | Self::Cancel { remote_task_id, .. }
            | Self::LeaseProbe { remote_task_id, .. } => *remote_task_id,
        }
    }

    fn idempotency_key(&self) -> &str {
        match self {
            Self::Spawn {
                idempotency_key, ..
            } => idempotency_key,
            Self::Cancel { .. } | Self::LeaseProbe { .. } => "none",
        }
    }

    fn command_name(&self) -> &'static str {
        match self {
            Self::Spawn { .. } => "spawn",
            Self::Cancel { .. } => "cancel",
            Self::LeaseProbe { .. } => "lease_probe",
        }
    }

    fn from_remote_message(
        destination: &NodeId,
        envelope: &MessageEnvelope<RemoteMessage>,
    ) -> Result<Self, RemoteError> {
        let sender_lamport = lamport_raw(&envelope.sender_time);
        let destination_node = destination.as_str().to_owned();
        match &envelope.payload {
            RemoteMessage::SpawnRequest(request) => Ok(Self::Spawn {
                remote_task_id: request.remote_task_id.raw(),
                origin_node: request.origin_node.as_str().to_owned(),
                destination_node,
                computation: request.computation.as_str().to_owned(),
                input_len: request.input.len(),
                lease_ms: millis_u64(request.lease),
                idempotency_key: request.idempotency_key.to_string(),
                sender_lamport,
            }),
            RemoteMessage::CancelRequest(request) => Ok(Self::Cancel {
                remote_task_id: request.remote_task_id.raw(),
                origin_node: request.origin_node.as_str().to_owned(),
                destination_node,
                reason: compact(&request.reason.to_string()),
                sender_lamport,
            }),
            RemoteMessage::LeaseRenewal(renewal) => Ok(Self::LeaseProbe {
                remote_task_id: renewal.remote_task_id.raw(),
                origin_node: envelope.sender.as_str().to_owned(),
                destination_node,
                lease_ms: millis_u64(renewal.new_lease),
                sender_lamport,
            }),
            RemoteMessage::SpawnAck(_) | RemoteMessage::ResultDelivery(_) => {
                Err(RemoteError::TransportError(
                    "origin runtime cannot send remote-to-origin protocol messages".to_owned(),
                ))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
enum WireReply {
    AckAccepted {
        remote_task_id: u64,
        assigned_node: String,
    },
    AckRejected {
        remote_task_id: u64,
        reason: String,
    },
    LeaseRenewed {
        remote_task_id: u64,
        current_state: String,
    },
    ResultSuccess {
        remote_task_id: u64,
        payload: Vec<u8>,
    },
    ResultCancelled {
        remote_task_id: u64,
        reason: String,
    },
    LeaseExpired {
        remote_task_id: u64,
    },
    CachedResult {
        remote_task_id: u64,
        idempotency_key: String,
        payload: Vec<u8>,
    },
}

impl WireReply {
    fn remote_task_id(&self) -> u64 {
        match self {
            Self::AckAccepted { remote_task_id, .. }
            | Self::AckRejected { remote_task_id, .. }
            | Self::LeaseRenewed { remote_task_id, .. }
            | Self::ResultSuccess { remote_task_id, .. }
            | Self::ResultCancelled { remote_task_id, .. }
            | Self::LeaseExpired { remote_task_id }
            | Self::CachedResult { remote_task_id, .. } => *remote_task_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointMode {
    CompleteAfterAck,
    HoldUntilCancel,
    CancelBeforeAck,
    RejectSpawn,
    LeaseRenewalThenSuccess,
    LeaseExpiry,
    DelayedAck,
    MalformedReply,
    CloseWithoutReply,
    DuplicateIdempotency,
}

#[derive(Debug, Default)]
struct EndpointState {
    commands: Mutex<Vec<WireCommand>>,
    executions: Mutex<BTreeMap<String, usize>>,
    cache: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

impl EndpointState {
    fn record_command(&self, command: WireCommand) {
        self.commands.lock().push(command);
    }

    fn command_count(&self) -> usize {
        self.commands.lock().len()
    }

    fn execution_count(&self, key: &str) -> usize {
        self.executions.lock().get(key).copied().unwrap_or(0)
    }

    fn mark_execution(&self, key: &str) {
        let mut executions = self.executions.lock();
        let entry = executions.entry(key.to_owned()).or_insert(0);
        *entry += 1;
    }
}

struct TestEndpoint {
    addr: SocketAddr,
    state: Arc<EndpointState>,
    join: thread::JoinHandle<io::Result<()>>,
}

impl TestEndpoint {
    fn launch(mode: EndpointMode, expected_connections: usize) -> Self {
        let listener = block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("test TCP listener should bind loopback");
        let addr = listener
            .local_addr()
            .expect("test TCP listener should expose local address");
        let state = Arc::new(EndpointState::default());
        let server_state = Arc::clone(&state);
        let join = thread::spawn(move || {
            block_on(serve_endpoint(
                listener,
                server_state,
                mode,
                expected_connections,
            ))
        });

        Self { addr, state, join }
    }

    fn finish(self) -> Arc<EndpointState> {
        let state = Arc::clone(&self.state);
        self.join
            .join()
            .expect("remote endpoint thread should not panic")
            .expect("remote endpoint should serve expected connections");
        state
    }
}

async fn serve_endpoint(
    listener: TcpListener,
    state: Arc<EndpointState>,
    mode: EndpointMode,
    expected_connections: usize,
) -> io::Result<()> {
    for _ in 0..expected_connections {
        let (mut stream, _) = listener.accept().await?;
        let command_bytes = read_raw_frame(&mut stream).await?;
        let command: WireCommand = serde_json::from_slice(&command_bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        state.record_command(command.clone());

        match mode {
            EndpointMode::CloseWithoutReply => continue,
            EndpointMode::MalformedReply => {
                write_raw_frame(&mut stream, b"{not-json").await?;
                continue;
            }
            EndpointMode::DelayedAck => thread::sleep(Duration::from_millis(25)),
            EndpointMode::CompleteAfterAck
            | EndpointMode::HoldUntilCancel
            | EndpointMode::CancelBeforeAck
            | EndpointMode::RejectSpawn
            | EndpointMode::LeaseRenewalThenSuccess
            | EndpointMode::LeaseExpiry
            | EndpointMode::DuplicateIdempotency => {}
        }

        let replies = endpoint_replies(&state, mode, &command);
        write_json_frame(&mut stream, &replies).await?;
    }
    Ok(())
}

fn endpoint_replies(
    state: &EndpointState,
    mode: EndpointMode,
    command: &WireCommand,
) -> Vec<WireReply> {
    let task_id = command.remote_task_id();
    match command {
        WireCommand::Spawn {
            idempotency_key,
            computation,
            input_len,
            ..
        } => match mode {
            EndpointMode::CancelBeforeAck => Vec::new(),
            EndpointMode::RejectSpawn => vec![WireReply::AckRejected {
                remote_task_id: task_id,
                reason: "unknown_computation".to_owned(),
            }],
            EndpointMode::LeaseRenewalThenSuccess => {
                state.mark_execution(idempotency_key);
                vec![
                    ack(task_id),
                    WireReply::LeaseRenewed {
                        remote_task_id: task_id,
                        current_state: "Running".to_owned(),
                    },
                    success(task_id, b"lease-renewed-ok"),
                ]
            }
            EndpointMode::LeaseExpiry => {
                state.mark_execution(idempotency_key);
                vec![
                    ack(task_id),
                    WireReply::LeaseExpired {
                        remote_task_id: task_id,
                    },
                ]
            }
            EndpointMode::DuplicateIdempotency => {
                let fingerprint = format!("{computation}:{input_len}");
                let mut cache = state.cache.lock();
                if let Some((cached_fingerprint, payload)) = cache.get(idempotency_key) {
                    assert_eq!(
                        cached_fingerprint, &fingerprint,
                        "idempotency key reused with different request fingerprint"
                    );
                    vec![WireReply::CachedResult {
                        remote_task_id: task_id,
                        idempotency_key: idempotency_key.clone(),
                        payload: payload.clone(),
                    }]
                } else {
                    let payload = b"idempotent-result".to_vec();
                    cache.insert(idempotency_key.clone(), (fingerprint, payload.clone()));
                    drop(cache);
                    state.mark_execution(idempotency_key);
                    vec![
                        ack(task_id),
                        WireReply::ResultSuccess {
                            remote_task_id: task_id,
                            payload,
                        },
                    ]
                }
            }
            EndpointMode::CompleteAfterAck | EndpointMode::DelayedAck => {
                state.mark_execution(idempotency_key);
                vec![ack(task_id), success(task_id, b"spawn-result-ok")]
            }
            EndpointMode::HoldUntilCancel
            | EndpointMode::MalformedReply
            | EndpointMode::CloseWithoutReply => {
                state.mark_execution(idempotency_key);
                vec![ack(task_id)]
            }
        },
        WireCommand::Cancel { reason, .. } => vec![WireReply::ResultCancelled {
            remote_task_id: task_id,
            reason: reason.clone(),
        }],
        WireCommand::LeaseProbe { .. } => vec![WireReply::LeaseRenewed {
            remote_task_id: task_id,
            current_state: "Running".to_owned(),
        }],
    }
}

fn ack(remote_task_id: u64) -> WireReply {
    WireReply::AckAccepted {
        remote_task_id,
        assigned_node: REMOTE_NODE.to_owned(),
    }
}

fn success(remote_task_id: u64, payload: &[u8]) -> WireReply {
    WireReply::ResultSuccess {
        remote_task_id,
        payload: payload.to_vec(),
    }
}

#[derive(Debug)]
struct TcpLoopbackRemoteRuntime {
    endpoint: SocketAddr,
    pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
    states: Mutex<BTreeMap<RemoteTaskId, RemoteTaskState>>,
    commands: Mutex<Vec<WireCommand>>,
    replies: Mutex<Vec<WireReply>>,
}

impl TcpLoopbackRemoteRuntime {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            pending: Mutex::new(BTreeMap::new()),
            states: Mutex::new(BTreeMap::new()),
            commands: Mutex::new(Vec::new()),
            replies: Mutex::new(Vec::new()),
        }
    }

    fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    fn state_count(&self) -> usize {
        self.states.lock().len()
    }

    fn trace_event_count(&self, trace: &TraceBufferHandle) -> usize {
        trace.snapshot().len() + self.commands.lock().len() + self.replies.lock().len()
    }

    fn last_command(&self) -> Option<WireCommand> {
        self.commands.lock().last().cloned()
    }

    fn saw_lease_renewal(&self, remote_task_id: RemoteTaskId) -> bool {
        self.replies.lock().iter().any(|reply| {
            matches!(
                reply,
                WireReply::LeaseRenewed {
                    remote_task_id: observed,
                    ..
                } if *observed == remote_task_id.raw()
            )
        })
    }

    fn deliver(&self, task_id: RemoteTaskId, result: Result<RemoteOutcome, RemoteError>) {
        if let Some(tx) = self.pending.lock().remove(&task_id) {
            let _ = tx.send_blocking(result);
        }
    }

    fn apply_reply(&self, reply: &WireReply) {
        let task_id = RemoteTaskId::from_raw(reply.remote_task_id());
        match reply {
            WireReply::AckAccepted { .. } | WireReply::LeaseRenewed { .. } => {
                self.states.lock().insert(task_id, RemoteTaskState::Running);
            }
            WireReply::AckRejected { reason, .. } => {
                self.states.lock().insert(task_id, RemoteTaskState::Failed);
                self.deliver(
                    task_id,
                    Err(RemoteError::SpawnRejected(reject_reason(reason))),
                );
            }
            WireReply::ResultSuccess { payload, .. } | WireReply::CachedResult { payload, .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::Completed);
                self.deliver(task_id, Ok(RemoteOutcome::Success(payload.clone())));
            }
            WireReply::ResultCancelled { reason, .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::Cancelled);
                assert!(
                    !reason.is_empty(),
                    "wire cancellation replies should carry diagnostic reason text"
                );
                self.deliver(
                    task_id,
                    Ok(RemoteOutcome::Cancelled(CancelReason::user(
                        "remote transport cancelled",
                    ))),
                );
            }
            WireReply::LeaseExpired { .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::LeaseExpired);
                self.deliver(task_id, Err(RemoteError::LeaseExpired));
            }
        }
    }
}

impl RemoteRuntime for TcpLoopbackRemoteRuntime {
    fn send_message(
        &self,
        destination: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        let command = WireCommand::from_remote_message(destination, &envelope)?;
        let replies = send_wire_command(self.endpoint, &command)?;
        self.commands.lock().push(command);
        self.replies.lock().extend(replies.iter().cloned());
        for reply in &replies {
            self.apply_reply(reply);
        }
        Ok(())
    }

    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        self.pending.lock().insert(task_id, tx);
        self.states.lock().insert(task_id, RemoteTaskState::Pending);
    }

    fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
        self.states.lock().get(&task_id).copied()
    }

    fn clear_task_state(&self, task_id: RemoteTaskId) {
        self.pending.lock().remove(&task_id);
        self.states.lock().remove(&task_id);
    }

    fn unregister_task(&self, task_id: RemoteTaskId) {
        self.pending.lock().remove(&task_id);
        self.states.lock().remove(&task_id);
    }
}

#[derive(Debug)]
struct WireTransport {
    endpoint: SocketAddr,
    inbound: Vec<MessageEnvelope<RemoteMessage>>,
}

impl WireTransport {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            inbound: Vec::new(),
        }
    }
}

impl RemoteTransport for WireTransport {
    fn send(
        &mut self,
        to: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        let command = WireCommand::from_remote_message(to, &envelope)?;
        let replies = send_wire_command(self.endpoint, &command)?;
        for reply in replies {
            if let Some(message) = reply_to_remote_message(&reply) {
                let sender = NodeId::new(REMOTE_NODE);
                let sender_time =
                    LogicalTime::Lamport(asupersync::trace::distributed::LamportTime::from_raw(
                        command.remote_task_id() + 100,
                    ));
                self.inbound
                    .push(MessageEnvelope::new(sender, sender_time, message));
            }
        }
        Ok(())
    }

    fn try_recv(&mut self) -> Option<MessageEnvelope<RemoteMessage>> {
        if self.inbound.is_empty() {
            None
        } else {
            Some(self.inbound.remove(0))
        }
    }
}

fn reply_to_remote_message(reply: &WireReply) -> Option<RemoteMessage> {
    match reply {
        WireReply::AckAccepted {
            remote_task_id,
            assigned_node,
        } => Some(RemoteMessage::SpawnAck(asupersync::remote::SpawnAck {
            remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
            status: asupersync::remote::SpawnAckStatus::Accepted,
            assigned_node: NodeId::new(assigned_node.clone()),
        })),
        WireReply::AckRejected {
            remote_task_id,
            reason,
        } => Some(RemoteMessage::SpawnAck(asupersync::remote::SpawnAck {
            remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
            status: asupersync::remote::SpawnAckStatus::Rejected(reject_reason(reason)),
            assigned_node: NodeId::new(REMOTE_NODE),
        })),
        WireReply::LeaseRenewed {
            remote_task_id,
            current_state,
        } => Some(RemoteMessage::LeaseRenewal(
            asupersync::remote::LeaseRenewal {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                new_lease: Duration::from_millis(50),
                current_state: parse_state(current_state),
                node: NodeId::new(REMOTE_NODE),
            },
        )),
        WireReply::ResultSuccess {
            remote_task_id,
            payload,
        } => Some(RemoteMessage::ResultDelivery(
            asupersync::remote::ResultDelivery {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                outcome: RemoteOutcome::Success(payload.clone()),
                execution_time: Duration::from_millis(1),
            },
        )),
        WireReply::ResultCancelled {
            remote_task_id,
            reason,
        } => Some(RemoteMessage::ResultDelivery(
            asupersync::remote::ResultDelivery {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                outcome: {
                    assert!(
                        !reason.is_empty(),
                        "wire cancellation replies should carry diagnostic reason text"
                    );
                    RemoteOutcome::Cancelled(CancelReason::user("remote transport cancelled"))
                },
                execution_time: Duration::from_millis(1),
            },
        )),
        WireReply::LeaseExpired { .. } | WireReply::CachedResult { .. } => None,
    }
}

fn send_wire_command(
    endpoint: SocketAddr,
    command: &WireCommand,
) -> Result<Vec<WireReply>, RemoteError> {
    block_on(async {
        let mut stream = TcpStream::connect(endpoint).await.map_err(map_io)?;
        write_json_frame(&mut stream, command)
            .await
            .map_err(map_io)?;
        stream.shutdown(Shutdown::Write).map_err(map_io)?;
        let response = read_raw_frame(&mut stream).await.map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                RemoteError::TransportError("receive EOF before response frame".to_owned())
            } else {
                map_io(error)
            }
        })?;
        serde_json::from_slice(&response)
            .map_err(|err| RemoteError::SerializationError(err.to_string()))
    })
}

async fn write_json_frame<S: AsyncWrite + Unpin, T: Serialize + Sync>(
    stream: &mut S,
    value: &T,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_raw_frame(stream, &encoded).await
}

async fn write_raw_frame<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await
}

async fn read_raw_frame<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0_u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "remote transport frame exceeded test maximum",
        ));
    }
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn map_io(error: io::Error) -> RemoteError {
    RemoteError::TransportError(format!(
        "{:?}:{}",
        error.kind(),
        compact(&error.to_string())
    ))
}

fn reject_reason(reason: &str) -> SpawnRejectReason {
    match reason {
        "unknown_computation" => SpawnRejectReason::UnknownComputation,
        "capacity_exceeded" => SpawnRejectReason::CapacityExceeded,
        "node_shutting_down" => SpawnRejectReason::NodeShuttingDown,
        "idempotency_conflict" => SpawnRejectReason::IdempotencyConflict,
        other => SpawnRejectReason::InvalidInput(other.to_owned()),
    }
}

fn parse_state(state: &str) -> RemoteTaskState {
    match state {
        "Running" => RemoteTaskState::Running,
        "Completed" => RemoteTaskState::Completed,
        "Cancelled" => RemoteTaskState::Cancelled,
        "LeaseExpired" => RemoteTaskState::LeaseExpired,
        "Failed" => RemoteTaskState::Failed,
        _ => RemoteTaskState::Pending,
    }
}

fn runtime_context(endpoint: SocketAddr) -> (Arc<TcpLoopbackRemoteRuntime>, Cx, TraceBufferHandle) {
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_default_lease(Duration::from_millis(50))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let trace = TraceBufferHandle::new(128);
    cx.set_trace_buffer(trace.clone());
    (runtime, cx, trace)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerAdmissionProbe {
    hello: RemotePeerHello,
    computation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerAdmissionReply {
    accepted: bool,
    diagnostic: String,
}

async fn serve_peer_admission_endpoint(
    listener: TcpListener,
    policy: RemotePeerAdmissionPolicy,
    dispatch_count: Arc<AtomicUsize>,
    expected_connections: usize,
) -> io::Result<()> {
    for _ in 0..expected_connections {
        let (mut stream, _) = listener.accept().await?;
        let probe: PeerAdmissionProbe = serde_json::from_slice(&read_raw_frame(&mut stream).await?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let decision = policy.admit(&probe.hello).and_then(|session| {
            session.authorize_computation(&ComputationName::new(&probe.computation))
        });
        let reply = match decision {
            Ok(()) => {
                dispatch_count.fetch_add(1, Ordering::SeqCst);
                PeerAdmissionReply {
                    accepted: true,
                    diagnostic: format!("dispatched named computation {}", probe.computation),
                }
            }
            Err(error) => PeerAdmissionReply {
                accepted: false,
                diagnostic: error.to_string(),
            },
        };
        write_json_frame(&mut stream, &reply).await?;
    }
    Ok(())
}

fn send_peer_admission_probe(
    endpoint: SocketAddr,
    hello: RemotePeerHello,
    computation: &str,
) -> PeerAdmissionReply {
    block_on(async {
        let mut stream = TcpStream::connect(endpoint)
            .await
            .expect("peer admission probe should connect");
        write_json_frame(
            &mut stream,
            &PeerAdmissionProbe {
                hello,
                computation: computation.to_owned(),
            },
        )
        .await
        .expect("peer admission probe should write");
        stream
            .shutdown(Shutdown::Write)
            .expect("peer admission probe should half-close");
        let response = read_raw_frame(&mut stream)
            .await
            .expect("peer admission probe should receive a response");
        serde_json::from_slice(&response).expect("peer admission response should decode")
    })
}

#[cfg(feature = "tls")]
fn call_tls_remote_service(
    endpoint: SocketAddr,
    connector: &TlsConnector,
    request: &RemoteServiceWireRequest,
) -> RemoteServiceWireResponse {
    call_tls_remote_service_result(endpoint, connector, request)
        .expect("TLS remote service exchange should complete")
}

#[cfg(feature = "tls")]
fn call_tls_remote_service_result(
    endpoint: SocketAddr,
    connector: &TlsConnector,
    request: &RemoteServiceWireRequest,
) -> Result<RemoteServiceWireResponse, RemoteComputationServiceError> {
    block_on(async {
        let stream = TcpStream::connect(endpoint)
            .await
            .expect("TLS remote service client should connect");
        let mut stream = connector
            .connect("localhost", stream)
            .await
            .expect("TLS remote service client should authenticate server");
        assert!(
            stream.peer_leaf_certificate_der().is_some(),
            "client should retain the authenticated server certificate"
        );
        call_tls_computation_once(
            &Cx::for_testing(),
            &mut stream,
            request,
            RemoteServiceWireLimits::default(),
        )
        .await
    })
}

#[cfg(feature = "tls")]
fn send_tls_malformed_remote_service_frame(
    endpoint: SocketAddr,
    connector: &TlsConnector,
    frame: &[u8],
) {
    block_on(async {
        let stream = TcpStream::connect(endpoint)
            .await
            .expect("malformed-frame client should connect");
        let mut stream = connector
            .connect("localhost", stream)
            .await
            .expect("malformed-frame client should authenticate server");
        write_raw_frame(&mut stream, frame)
            .await
            .expect("malformed-frame client should write bounded frame");
        stream
            .flush()
            .await
            .expect("malformed-frame client should flush TLS bytes");
    });
}

#[cfg(feature = "tls")]
fn send_tls_oversized_remote_service_prefix(endpoint: SocketAddr, connector: &TlsConnector) {
    block_on(async {
        let stream = TcpStream::connect(endpoint)
            .await
            .expect("oversized-frame client should connect");
        let mut stream = connector
            .connect("localhost", stream)
            .await
            .expect("oversized-frame client should authenticate server");
        let oversized = u32::try_from(RemoteServiceWireLimits::default().max_frame_bytes() + 1)
            .expect("default remote service frame cap should fit u32");
        stream
            .write_all(&oversized.to_be_bytes())
            .await
            .expect("oversized-frame client should write length prefix");
        stream
            .flush()
            .await
            .expect("oversized-frame client should flush TLS bytes");
    });
}

#[cfg(feature = "tls")]
fn remote_service_wire_request(
    hello: RemotePeerHello,
    computation: &str,
    remote_task_id: u64,
) -> RemoteServiceWireRequest {
    remote_service_wire_request_with(
        hello,
        computation,
        remote_task_id,
        u128::from(remote_task_id),
        b"executed-over-mtls",
    )
}

#[cfg(feature = "tls")]
fn remote_service_wire_request_with(
    hello: RemotePeerHello,
    computation: &str,
    remote_task_id: u64,
    idempotency_key: u128,
    input: &[u8],
) -> RemoteServiceWireRequest {
    remote_service_wire_request_with_lease(
        hello,
        computation,
        remote_task_id,
        idempotency_key,
        input,
        Duration::from_secs(30),
    )
}

#[cfg(feature = "tls")]
fn remote_service_wire_request_with_lease(
    hello: RemotePeerHello,
    computation: &str,
    remote_task_id: u64,
    idempotency_key: u128,
    input: &[u8],
    lease: Duration,
) -> RemoteServiceWireRequest {
    let cx = Cx::for_testing();
    RemoteServiceWireRequest::from_spawn_request(
        hello.clone(),
        &SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(remote_task_id),
            computation: ComputationName::new(computation),
            input: RemoteInput::new(input.to_vec()),
            lease,
            idempotency_key: IdempotencyKey::from_raw(idempotency_key),
            budget: None,
            origin_node: hello.peer_node().clone(),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        },
    )
    .expect("wire request identity should agree with its peer hello")
}

#[cfg(feature = "tls")]
fn assert_remote_json_golden<T>(golden: &str)
where
    T: DeserializeOwned + Serialize + fmt::Debug + PartialEq,
{
    let decoded: T = serde_json::from_str(golden).expect("wire golden should deserialize");
    let encoded = serde_json::to_string(&decoded).expect("wire golden should reserialize");
    assert_eq!(encoded, golden, "wire JSON changed without a version bump");
    let decoded_again: T =
        serde_json::from_str(&encoded).expect("canonical wire JSON should deserialize");
    assert_eq!(decoded_again, decoded);
}

#[cfg(feature = "tls")]
fn assert_remote_unknown_field_rejected<T>(value: serde_json::Value, field: &str)
where
    T: DeserializeOwned + fmt::Debug,
{
    let error = serde_json::from_value::<T>(value)
        .expect_err("same-version remote wire envelope must reject unknown fields");
    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains(field)
            && (diagnostic.contains("unknown field") || diagnostic.contains("expected")),
        "diagnostic: {diagnostic}"
    );
}

#[cfg(feature = "tls")]
#[test]
fn remote_service_v1_v2_v3_wire_json_is_golden_and_strict() {
    const FINGERPRINT_JSON: &str =
        "[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]";
    const REQUEST_TAIL: &str = concat!(
        ",\"registry_fingerprint\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,",
        "7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]},",
        "\"remote_task_id\":7,\"computation\":\"proof.echo\",\"input\":[1,2,3],",
        "\"lease_secs\":5,\"lease_subsec_nanos\":6,",
        "\"idempotency_key_high\":1,\"idempotency_key_low\":2,",
        "\"budget\":{\"deadline_nanos\":9,\"poll_quota\":10,\"cost_quota\":11,\"priority\":12},",
        "\"origin_region\":{\"kind\":\"RegionId\",\"index\":13,\"generation\":14},",
        "\"origin_task\":{\"kind\":\"TaskId\",\"index\":15,\"generation\":16}}"
    );

    let fingerprint = ComputationRegistryFingerprint::from_bytes([7; 32]);
    for version in [
        RemoteProtocolVersion::V1,
        RemoteProtocolVersion::V2,
        RemoteProtocolVersion::V3,
    ] {
        let hello = RemotePeerHello::new(NodeId::new("wire-peer"), version, fingerprint);
        let hello_golden = format!(
            "{{\"peer_node\":\"wire-peer\",\"protocol_version\":{{\"major\":{},\"minor\":0}},\"registry_fingerprint\":{FINGERPRINT_JSON}}}",
            version.major()
        );
        assert_eq!(
            serde_json::to_string(&hello).expect("peer hello should serialize"),
            hello_golden,
            "peer hello JSON changed without a version bump"
        );
        assert_remote_json_golden::<RemotePeerHello>(&hello_golden);

        let request = RemoteServiceWireRequest::from_spawn_request(
            hello,
            &SpawnRequest {
                remote_task_id: RemoteTaskId::from_raw(7),
                computation: ComputationName::new("proof.echo"),
                input: RemoteInput::new(vec![1, 2, 3]),
                lease: Duration::new(5, 6),
                idempotency_key: IdempotencyKey::from_raw((u128::from(1_u64) << 64) | 2),
                budget: Some(Budget {
                    deadline: Some(Time::from_nanos(9)),
                    poll_quota: 10,
                    cost_quota: Some(11),
                    priority: 12,
                }),
                origin_node: NodeId::new("wire-peer"),
                origin_region: RegionId::new_for_test(13, 14),
                origin_task: TaskId::new_for_test(15, 16),
            },
        )
        .expect("golden request identity should match its peer hello");
        let request_golden = format!(
            "{{\"hello\":{{\"peer_node\":\"wire-peer\",\"protocol_version\":{{\"major\":{},\"minor\":0}}{REQUEST_TAIL}",
            version.major()
        );
        assert_eq!(
            serde_json::to_string(&request).expect("wire request should serialize"),
            request_golden,
            "wire request JSON changed without a version bump"
        );
        assert_remote_json_golden::<RemoteServiceWireRequest>(&request_golden);
    }

    for golden in [
        "{\"outcome\":\"success\",\"value\":[4,5]}",
        "{\"outcome\":\"failed\",\"value\":\"application failure\"}",
        concat!(
            "{\"outcome\":\"cancelled\",\"value\":{\"kind\":\"User\",",
            "\"origin_region\":{\"kind\":\"RegionId\",\"index\":1,\"generation\":2},",
            "\"origin_task\":null,\"timestamp\":17,\"message\":null,\"cause\":null,",
            "\"truncated\":false,\"truncated_at_depth\":null}}"
        ),
        "{\"outcome\":\"panicked\",\"value\":\"panic boundary\"}",
    ] {
        assert_remote_json_golden::<RemoteServiceWireOutcome>(golden);
    }
    for (kind, golden) in [
        (CancelKind::User, "\"User\""),
        (CancelKind::Timeout, "\"Timeout\""),
        (CancelKind::Deadline, "\"Deadline\""),
        (CancelKind::PollQuota, "\"PollQuota\""),
        (CancelKind::CostBudget, "\"CostBudget\""),
        (CancelKind::FailFast, "\"FailFast\""),
        (CancelKind::RaceLost, "\"RaceLost\""),
        (CancelKind::ParentCancelled, "\"ParentCancelled\""),
        (CancelKind::ResourceUnavailable, "\"ResourceUnavailable\""),
        (CancelKind::Shutdown, "\"Shutdown\""),
        (CancelKind::LinkedExit, "\"LinkedExit\""),
    ] {
        assert_eq!(
            serde_json::to_string(&kind).expect("cancellation kind should serialize"),
            golden,
            "cancellation kind spelling changed without a protocol version bump"
        );
    }
    for golden in [
        concat!(
            "{\"response\":\"outcome\",\"remote_task_id\":7,",
            "\"outcome\":{\"outcome\":\"success\",\"value\":[4,5]}}"
        ),
        concat!(
            "{\"response\":\"rejected\",\"remote_task_id\":7,",
            "\"code\":\"malformed_request\",\"diagnostic\":\"strict refusal\"}"
        ),
    ] {
        assert_remote_json_golden::<RemoteServiceWireResponse>(golden);
    }
    for (code, golden) in [
        (
            RemoteServiceRejectionCode::AdmissionDenied,
            "\"admission_denied\"",
        ),
        (
            RemoteServiceRejectionCode::ExecutableRegistryDrift,
            "\"executable_registry_drift\"",
        ),
        (
            RemoteServiceRejectionCode::ComputationDenied,
            "\"computation_denied\"",
        ),
        (
            RemoteServiceRejectionCode::MalformedRequest,
            "\"malformed_request\"",
        ),
        (
            RemoteServiceRejectionCode::ExecutionFailed,
            "\"execution_failed\"",
        ),
        (
            RemoteServiceRejectionCode::LifecycleUnavailable,
            "\"lifecycle_unavailable\"",
        ),
        (
            RemoteServiceRejectionCode::OperationInFlight,
            "\"operation_in_flight\"",
        ),
        (
            RemoteServiceRejectionCode::IdempotencyConflict,
            "\"idempotency_conflict\"",
        ),
        (
            RemoteServiceRejectionCode::IdempotencyCapacity,
            "\"idempotency_capacity\"",
        ),
    ] {
        assert_eq!(
            serde_json::to_string(&code).expect("rejection code should serialize"),
            golden,
            "rejection-code spelling changed without a protocol version bump"
        );
    }
    for golden in [
        concat!(
            "{\"command\":\"cancel\",\"remote_task_id\":7,\"reason\":{\"kind\":\"User\",",
            "\"origin_region\":{\"kind\":\"RegionId\",\"index\":1,\"generation\":2},",
            "\"origin_task\":null,\"timestamp\":17,\"message\":null,\"cause\":null,",
            "\"truncated\":false,\"truncated_at_depth\":null}}"
        ),
        concat!(
            "{\"command\":\"renew_lease\",\"remote_task_id\":7,\"renewal_id\":8,",
            "\"lease_secs\":9,\"lease_subsec_nanos\":10}"
        ),
    ] {
        assert_remote_json_golden::<RemoteServiceSessionCommand>(golden);
    }
    for golden in [
        "{\"event\":\"accepted\",\"remote_task_id\":7}",
        concat!(
            "{\"event\":\"lease_renewed\",\"remote_task_id\":7,\"renewal_id\":8,",
            "\"lease_secs\":9,\"lease_subsec_nanos\":10}"
        ),
        concat!(
            "{\"event\":\"command_rejected\",\"remote_task_id\":7,\"renewal_id\":8,",
            "\"diagnostic\":\"strict refusal\"}"
        ),
        concat!(
            "{\"event\":\"terminal\",\"response\":{\"response\":\"outcome\",",
            "\"remote_task_id\":7,\"outcome\":{\"outcome\":\"success\",\"value\":[4,5]}}}"
        ),
    ] {
        assert_remote_json_golden::<RemoteServiceSessionEvent>(golden);
    }

    let hello = RemotePeerHello::new(
        NodeId::new("wire-peer"),
        RemoteProtocolVersion::V3,
        fingerprint,
    );
    let request = remote_service_wire_request(hello, "proof.echo", 7);
    let mut request_value = serde_json::to_value(&request).expect("request should serialize");
    request_value
        .as_object_mut()
        .expect("request should be a JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(request_value, "future_field");

    let mut nested_hello = serde_json::to_value(&request).expect("request should serialize");
    nested_hello["hello"]
        .as_object_mut()
        .expect("hello should be a JSON object")
        .insert("capabilities".to_owned(), serde_json::json!([]));
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(nested_hello, "capabilities");

    let mut nested_version = serde_json::to_value(&request).expect("request should serialize");
    nested_version["hello"]["protocol_version"]
        .as_object_mut()
        .expect("protocol version should be a JSON object")
        .insert("patch".to_owned(), serde_json::json!(1));
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(nested_version, "patch");

    let mut nested_budget = serde_json::to_value(&request).expect("request should serialize");
    nested_budget["budget"] = serde_json::json!({
        "deadline_nanos": 9,
        "poll_quota": 10,
        "cost_quota": 11,
        "priority": 12,
        "ambient_priority": 255
    });
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(
        nested_budget,
        "ambient_priority",
    );

    let mut nested_region_id = serde_json::to_value(&request).expect("request should serialize");
    nested_region_id["origin_region"]
        .as_object_mut()
        .expect("origin region should be a JSON object")
        .insert("epoch".to_owned(), serde_json::json!(1));
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(nested_region_id, "epoch");

    let mut nested_task_id = serde_json::to_value(&request).expect("request should serialize");
    nested_task_id["origin_task"]
        .as_object_mut()
        .expect("origin task should be a JSON object")
        .insert("epoch".to_owned(), serde_json::json!(1));
    assert_remote_unknown_field_rejected::<RemoteServiceWireRequest>(nested_task_id, "epoch");

    let cancellation = CancelReason::with_origin(
        CancelKind::User,
        RegionId::new_for_test(1, 2),
        Time::from_nanos(17),
    );
    let mut general_cancellation =
        serde_json::to_value(&cancellation).expect("general cancel reason should serialize");
    general_cancellation
        .as_object_mut()
        .expect("general cancel reason should be a JSON object")
        .insert("application_metadata".to_owned(), serde_json::json!(true));
    assert_eq!(
        serde_json::from_value::<CancelReason>(general_cancellation)
            .expect("general CancelReason serde should retain additive-field compatibility"),
        cancellation
    );

    let general_region = RegionId::new_for_test(21, 22);
    let mut general_region_value =
        serde_json::to_value(general_region).expect("general region ID should serialize");
    general_region_value
        .as_object_mut()
        .expect("general region ID should be a JSON object")
        .insert("application_metadata".to_owned(), serde_json::json!(true));
    assert_eq!(
        serde_json::from_value::<RegionId>(general_region_value)
            .expect("general RegionId serde should retain additive-field compatibility"),
        general_region
    );

    let general_task = TaskId::new_for_test(23, 24);
    let mut general_task_value =
        serde_json::to_value(general_task).expect("general task ID should serialize");
    general_task_value
        .as_object_mut()
        .expect("general task ID should be a JSON object")
        .insert("application_metadata".to_owned(), serde_json::json!(true));
    assert_eq!(
        serde_json::from_value::<TaskId>(general_task_value)
            .expect("general TaskId serde should retain additive-field compatibility"),
        general_task
    );

    let mut cancelled_outcome =
        serde_json::to_value(RemoteServiceWireOutcome::Cancelled(cancellation.clone()))
            .expect("cancelled outcome should serialize");
    cancelled_outcome["value"]
        .as_object_mut()
        .expect("cancelled reason should be a JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert_remote_unknown_field_rejected::<RemoteServiceWireOutcome>(
        cancelled_outcome,
        "future_field",
    );

    let mut parent_cancellation = cancellation.clone();
    parent_cancellation.cause = Some(Box::new(cancellation.clone()));
    let mut nested_cause =
        serde_json::to_value(RemoteServiceWireOutcome::Cancelled(parent_cancellation))
            .expect("nested cancellation outcome should serialize");
    nested_cause["value"]["cause"]
        .as_object_mut()
        .expect("nested cancellation cause should be a JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert_remote_unknown_field_rejected::<RemoteServiceWireOutcome>(nested_cause, "future_field");

    let cancellation_value =
        serde_json::to_value(&cancellation).expect("cancel reason should serialize");
    for (field, needle) in [
        ("kind", "\"kind\":\"User\""),
        (
            "origin_region",
            "\"origin_region\":{\"kind\":\"RegionId\",\"index\":1,\"generation\":2}",
        ),
        ("origin_task", "\"origin_task\":null"),
        ("timestamp", "\"timestamp\":17"),
        ("message", "\"message\":null"),
        ("cause", "\"cause\":null"),
        ("truncated", "\"truncated\":false"),
        ("truncated_at_depth", "\"truncated_at_depth\":null"),
    ] {
        let mut missing = cancellation_value.clone();
        missing
            .as_object_mut()
            .expect("cancel reason should be a JSON object")
            .remove(field);
        let missing_error = serde_json::from_value::<RemoteServiceWireOutcome>(
            serde_json::json!({"outcome": "cancelled", "value": missing}),
        )
        .expect_err("strict remote cancellation reason must reject missing fields");
        assert!(
            missing_error
                .to_string()
                .contains(&format!("missing field `{field}`")),
            "field {field:?} diagnostic: {missing_error}"
        );

        let duplicate = format!("{needle},{needle}");
        let cancellation_json =
            serde_json::to_string(&RemoteServiceWireOutcome::Cancelled(cancellation.clone()))
                .expect("cancelled outcome should serialize");
        let duplicate_json = cancellation_json.replacen(needle, &duplicate, 1);
        assert_ne!(
            duplicate_json, cancellation_json,
            "duplicate fixture must find field {field:?}"
        );
        let duplicate_error = serde_json::from_str::<RemoteServiceWireOutcome>(&duplicate_json)
            .expect_err("strict remote cancellation reason must reject duplicate fields");
        assert!(
            duplicate_error
                .to_string()
                .contains(&format!("duplicate field `{field}`")),
            "field {field:?} diagnostic: {duplicate_error}"
        );
    }

    let reason_with_depth = |depth: usize| {
        let mut reason = cancellation_value.clone();
        for _ in 1..depth {
            let mut parent = cancellation_value.clone();
            parent["cause"] = reason;
            reason = parent;
        }
        reason
    };
    let max_depth = reason_with_depth(REMOTE_CANCEL_REASON_TEST_MAX_DEPTH);
    serde_json::from_value::<RemoteServiceWireOutcome>(serde_json::json!({
        "outcome": "cancelled",
        "value": max_depth
    }))
    .expect("a cancellation chain at the exact remote depth limit should deserialize");

    let over_depth = reason_with_depth(REMOTE_CANCEL_REASON_TEST_MAX_DEPTH + 1);
    let deep_error = serde_json::from_value::<RemoteServiceWireOutcome>(serde_json::json!({
        "outcome": "cancelled",
        "value": over_depth
    }))
    .expect_err("strict remote cancellation reason must reject an over-depth cause chain");
    assert!(
        deep_error
            .to_string()
            .contains("remote cancellation cause-chain depth 65 exceeds maximum 64"),
        "diagnostic: {deep_error}"
    );
    serde_json::from_value::<RemoteServiceWireOutcome>(serde_json::json!({
        "outcome": "cancelled",
        "value": cancellation_value
    }))
    .expect("a valid cancellation must still parse after an over-depth refusal");

    let mut cancel_command = serde_json::json!({
        "command": "cancel",
        "remote_task_id": 7,
        "reason": serde_json::to_value(cancellation).expect("cancel reason should serialize")
    });
    cancel_command["reason"]
        .as_object_mut()
        .expect("cancel command reason should be a JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert_remote_unknown_field_rejected::<RemoteServiceSessionCommand>(
        cancel_command,
        "future_field",
    );

    assert_remote_unknown_field_rejected::<RemoteServiceWireOutcome>(
        serde_json::json!({
            "outcome": "success",
            "value": [4, 5],
            "future_field": true
        }),
        "future_field",
    );
    assert_remote_unknown_field_rejected::<RemoteServiceWireResponse>(
        serde_json::json!({
            "response": "rejected",
            "remote_task_id": 7,
            "code": "malformed_request",
            "diagnostic": "strict refusal",
            "future_field": true
        }),
        "future_field",
    );
    assert_remote_unknown_field_rejected::<RemoteServiceSessionCommand>(
        serde_json::json!({
            "command": "renew_lease",
            "remote_task_id": 7,
            "renewal_id": 8,
            "lease_secs": 9,
            "lease_subsec_nanos": 10,
            "future_field": true
        }),
        "future_field",
    );
    assert_remote_unknown_field_rejected::<RemoteServiceSessionEvent>(
        serde_json::json!({
            "event": "accepted",
            "remote_task_id": 7,
            "future_field": true
        }),
        "future_field",
    );
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_listener_enforces_lease_then_caches_cancelled_outcome() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let cleanup_complete = Arc::new(AtomicBool::new(false));
    let (park_tx, park_rx) = oneshot::channel::<()>();
    let park_receiver = Arc::new(Mutex::new(Some(park_rx)));
    let mut computations = RemoteComputationRegistry::new();
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let handler_cleanup_complete = Arc::clone(&cleanup_complete);
    let handler_park_receiver = Arc::clone(&park_receiver);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.lease", move |cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            let handler_cleanup_complete = Arc::clone(&handler_cleanup_complete);
            let mut receiver = handler_park_receiver
                .lock()
                .take()
                .expect("canonical leased request should execute exactly once");
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                let received = receiver.recv(&cx).await;
                handler_cleanup_complete.store(true, Ordering::SeqCst);
                received.map_err(|error| {
                    RemoteError::TransportError(format!(
                        "proof.lease parking operation ended: {error}"
                    ))
                })?;
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("listener proof.lease handler should register");

    let origin = NodeId::new("origin-lease-loopback");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V2,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.lease"])
        .expect("lease test certificate-bound grant should be valid");
    let hello = policy.hello_for(origin);
    let canonical = remote_service_wire_request_with_lease(
        hello.clone(),
        "proof.lease",
        7201,
        0x1ea5e,
        b"leased-input",
        Duration::from_millis(250),
    );
    let cached = remote_service_wire_request_with_lease(
        hello.clone(),
        "proof.lease",
        7202,
        0x1ea5e,
        b"leased-input",
        Duration::from_millis(250),
    );
    let zero_lease = remote_service_wire_request_with_lease(
        hello,
        "proof.lease",
        7203,
        0,
        b"must-not-dispatch",
        Duration::ZERO,
    );

    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("lease test mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("lease test mTLS connector should build");

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("lease test runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(4))
                .with_drain_timeout(Duration::from_secs(1)),
        ))
        .expect("lease test service should bind");
    let endpoint = service
        .local_addr()
        .expect("lease test service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_cleanup_complete = Arc::clone(&cleanup_complete);
    let connector = Arc::new(connector);

    let client = thread::spawn(move || {
        let cancelled = call_tls_remote_service(endpoint, &connector, &canonical);
        assert!(matches!(
            cancelled,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7201,
                outcome: RemoteServiceWireOutcome::Cancelled(ref reason),
            } if reason.kind == CancelKind::Deadline
                && reason.message.as_deref() == Some("remote computation lease expired")
        ));
        assert!(
            client_cleanup_complete.load(Ordering::SeqCst),
            "lease cancellation must drain handler cleanup before replying"
        );

        let replayed = call_tls_remote_service(endpoint, &connector, &cached);
        assert!(matches!(
            replayed,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7202,
                outcome: RemoteServiceWireOutcome::Cancelled(ref reason),
            } if reason.kind == CancelKind::Deadline
        ));

        let refused = call_tls_remote_service(endpoint, &connector, &zero_lease);
        assert!(matches!(
            refused,
            RemoteServiceWireResponse::Rejected {
                remote_task_id: 7203,
                code: RemoteServiceRejectionCode::MalformedRequest,
                ref diagnostic,
            } if diagnostic.contains("lease must be nonzero")
        ));
        assert!(client_operator.begin_drain());
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a lease test service context");
            service.run(&cx).await
        })
        .expect("lease test service should drain cleanly");
    client.join().expect("lease test client should not panic");
    drop(park_tx);

    assert_eq!(report.accepted_connections(), 3);
    assert_eq!(report.completed_connections(), 3);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.interrupted_connections(), 0);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert!(cleanup_complete.load(Ordering::SeqCst));
    assert_eq!(operator.active_connections(), 0);
    assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);

    ProofLogRow::pass(
        "structured_remote_service_request_lease",
        0,
        "none",
        "mtls_v2_expire_drain_cache_then_zero_lease_refusal",
        3,
        "one_dispatch_one_cleanup_two_cancelled_views_zero_live",
        "one_dispatch_one_cleanup_two_cancelled_views_zero_live",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_v3_session_renews_then_cancels_and_drains_one_child() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let cleanup_complete = Arc::new(AtomicBool::new(false));
    let observed_remote_budget = Arc::new(Mutex::new(None));
    let (park_tx, park_rx) = oneshot::channel::<()>();
    let park_receiver = Arc::new(Mutex::new(Some(park_rx)));
    let mut computations = RemoteComputationRegistry::new();
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let handler_cleanup_complete = Arc::clone(&cleanup_complete);
    let handler_observed_remote_budget = Arc::clone(&observed_remote_budget);
    let handler_park_receiver = Arc::clone(&park_receiver);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.v3-lifecycle", move |cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            let handler_cleanup_complete = Arc::clone(&handler_cleanup_complete);
            let handler_observed_remote_budget = Arc::clone(&handler_observed_remote_budget);
            let mut receiver = handler_park_receiver
                .lock()
                .take()
                .expect("V3 lifecycle request should execute exactly once");
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                handler_observed_remote_budget.lock().replace(cx.budget());
                let received = receiver.recv(&cx).await;
                handler_cleanup_complete.store(true, Ordering::SeqCst);
                received.map_err(|error| {
                    RemoteError::TransportError(format!(
                        "proof.v3-lifecycle parking operation ended: {error}"
                    ))
                })?;
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("V3 lifecycle handler should register");

    let origin = NodeId::new("origin-v3-loopback");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.v3-lifecycle"])
        .expect("V3 certificate-bound grant should be valid");
    let hello = policy.hello_for(origin);
    let request_cx = Cx::for_testing();
    let requested_budget = Budget::INFINITE.with_poll_quota(10_000);
    let request = RemoteServiceWireRequest::from_spawn_request(
        hello.clone(),
        &SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(7301),
            computation: ComputationName::new("proof.v3-lifecycle"),
            input: RemoteInput::new(b"v3-lifecycle-input".to_vec()),
            lease: Duration::from_secs(1),
            idempotency_key: IdempotencyKey::from_raw(0x7301),
            budget: Some(requested_budget),
            origin_node: hello.peer_node().clone(),
            origin_region: request_cx.region_id(),
            origin_task: request_cx.task_id(),
        },
    )
    .expect("V3 budgeted request identity should agree with its peer hello");

    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("V3 mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("V3 mTLS connector should build");

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("V3 service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(2))
                .with_drain_timeout(Duration::from_secs(1)),
        ))
        .expect("V3 structured service should bind");
    let endpoint = service
        .local_addr()
        .expect("V3 structured service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_dispatch_count = Arc::clone(&dispatch_count);
    let client_cleanup_complete = Arc::clone(&cleanup_complete);
    let session_client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .expect("V3 native client should accept its static configuration");

    let client = thread::spawn(move || {
        let start = block_on(session_client.start_session(&Cx::for_testing(), &request))
            .expect("V3 native client should connect and receive an accepted event");
        let mut session = match start {
            RemoteComputationSessionStart::Running(session) => session,
            RemoteComputationSessionStart::Terminal(response) => {
                panic!("V3 request unexpectedly terminated at admission: {response:?}")
            }
            _ => panic!("V3 start returned an unknown future variant"),
        };

        let dispatch_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while client_dispatch_count.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < dispatch_deadline,
                "V3 accepted request should reach its handler"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let renewed = block_on(session.renew_lease(&Cx::for_testing(), Duration::from_secs(2)))
            .expect("V3 lease renewal should be acknowledged");
        assert!(matches!(
            renewed,
            RemoteServiceSessionEvent::LeaseRenewed {
                remote_task_id: 7301,
                renewal_id: 1,
                lease_secs: 2,
                lease_subsec_nanos: 0,
            }
        ));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !client_cleanup_complete.load(Ordering::SeqCst),
            "V3 renewal must keep the child live beyond its original lease"
        );

        let reason = CancelReason::user("V3 explicit user cancel");
        let cancelled = block_on(session.cancel(&Cx::for_testing(), reason.clone()))
            .expect("V3 cancel should return a drained terminal response");
        assert!(matches!(
            cancelled,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7301,
                outcome: RemoteServiceWireOutcome::Cancelled(ref actual),
            } if actual == &reason
        ));
        assert!(
            client_cleanup_complete.load(Ordering::SeqCst),
            "V3 terminal cancellation must follow handler cleanup"
        );
        assert!(client_operator.begin_drain());
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a V3 service context");
            service.run(&cx).await
        })
        .expect("V3 service should drain cleanly");
    client.join().expect("V3 lifecycle client should not panic");
    drop(park_tx);

    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.interrupted_connections(), 0);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert!(cleanup_complete.load(Ordering::SeqCst));
    let observed_budget = observed_remote_budget
        .lock()
        .as_ref()
        .copied()
        .expect("V3 handler should observe its request budget");
    assert!(
        observed_budget.poll_quota <= requested_budget.poll_quota,
        "V3 child must not loosen the explicit remote budget ceiling"
    );
    assert_eq!(operator.active_connections(), 0);
    assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);

    ProofLogRow::pass(
        "structured_remote_service_v3_session",
        0,
        "none",
        "mtls_same_connection_renew_then_user_cancel",
        1,
        "one_dispatch_renewed_past_original_deadline_cancelled_after_cleanup",
        "one_dispatch_renewed_past_original_deadline_cancelled_after_cleanup",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_v3_wait_receives_terminal_after_expiry_cleanup_drains() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let cleanup_complete = Arc::new(AtomicBool::new(false));
    let (_park_tx, park_rx) = oneshot::channel::<()>();
    let park_receiver = Arc::new(Mutex::new(Some(park_rx)));
    let mut computations = RemoteComputationRegistry::new();
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let handler_cleanup_complete = Arc::clone(&cleanup_complete);
    let handler_park_receiver = Arc::clone(&park_receiver);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.v3-expiry-drain", move |cx, _invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            let handler_cleanup_complete = Arc::clone(&handler_cleanup_complete);
            let mut receiver = handler_park_receiver
                .lock()
                .take()
                .expect("V3 expiry handler should execute exactly once");
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                let received = receiver.recv(&cx).await;
                thread::sleep(Duration::from_millis(40));
                handler_cleanup_complete.store(true, Ordering::SeqCst);
                received.map_err(|error| {
                    RemoteError::TransportError(format!(
                        "proof.v3-expiry-drain parking operation ended: {error}"
                    ))
                })?;
                Ok(RemoteOutcome::Success(Vec::new()))
            }
        })
        .expect("V3 expiry handler should register");

    let origin = NodeId::new("origin-v3-expiry-drain");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.v3-expiry-drain"])
        .expect("V3 expiry grant should be valid");
    let request = remote_service_wire_request_with_lease(
        policy.hello_for(origin),
        "proof.v3-expiry-drain",
        7306,
        0x7306,
        b"expiry-drain-input",
        Duration::from_millis(100),
    );
    let (acceptor, connector) = remote_client_test_mtls_pair();

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("V3 expiry service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(1))
                .with_drain_timeout(Duration::from_secs(1)),
        ))
        .expect("V3 expiry service should bind");
    let endpoint = service
        .local_addr()
        .expect("V3 expiry service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_cleanup_complete = Arc::clone(&cleanup_complete);
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .expect("V3 expiry client should build");

    let client_thread = thread::spawn(move || {
        let start = block_on(client.start_session(&Cx::for_testing(), &request))
            .expect("V3 expiry request should be accepted");
        let session = match start {
            RemoteComputationSessionStart::Running(session) => session,
            RemoteComputationSessionStart::Terminal(response) => {
                panic!("V3 expiry request terminated at admission: {response:?}")
            }
            _ => panic!("V3 expiry start returned an unknown future variant"),
        };
        let terminal = block_on(session.wait(&Cx::for_testing()))
            .expect("V3 client should wait through server expiry cleanup");
        assert!(matches!(
            terminal,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7306,
                outcome: RemoteServiceWireOutcome::Cancelled(_),
            }
        ));
        assert!(
            client_cleanup_complete.load(Ordering::SeqCst),
            "V3 expiry terminal must follow child cleanup"
        );
        assert!(client_operator.begin_drain());
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a V3 expiry context");
            service.run(&cx).await
        })
        .expect("V3 expiry service should drain cleanly");
    client_thread
        .join()
        .expect("V3 expiry client should not panic");

    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert!(cleanup_complete.load(Ordering::SeqCst));
    assert_eq!(operator.active_connections(), 0);
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_v3_start_decodes_admission_rejection_as_terminal() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let computations = RemoteComputationRegistry::new();
    let policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    let request = remote_service_wire_request_with_lease(
        policy.hello_for(NodeId::new("ungranted-v3-peer")),
        "proof.denied",
        7302,
        0x7302,
        b"must-not-dispatch",
        Duration::from_secs(5),
    );

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("V3 admission service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new().with_max_connections(Some(1)),
        ))
        .expect("V3 admission service should bind");
    let endpoint = service
        .local_addr()
        .expect("V3 admission service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .expect("V3 admission client should build");

    let client_thread = thread::spawn(move || {
        let start = block_on(client.start_session(&Cx::for_testing(), &request))
            .expect("V3 admission refusal should decode as a session event");
        match start {
            RemoteComputationSessionStart::Terminal(RemoteServiceWireResponse::Rejected {
                remote_task_id: 7302,
                code: RemoteServiceRejectionCode::AdmissionDenied,
                ..
            }) => {}
            RemoteComputationSessionStart::Terminal(other) => {
                panic!("unexpected V3 admission terminal response: {other:?}")
            }
            RemoteComputationSessionStart::Running(_) => {
                panic!("ungranted V3 peer must not start a handler")
            }
            _ => panic!("V3 admission returned an unknown future variant"),
        }
        assert!(client_operator.begin_drain());
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a V3 admission context");
            service.run(&cx).await
        })
        .expect("V3 admission service should drain cleanly");
    client_thread
        .join()
        .expect("V3 admission client should not panic");

    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(operator.active_connections(), 0);
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_v3_disconnect_cancels_drains_and_replays_without_redispatch() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let cleanup_complete = Arc::new(AtomicBool::new(false));
    let (_park_tx, park_rx) = oneshot::channel::<()>();
    let park_receiver = Arc::new(Mutex::new(Some(park_rx)));
    let mut computations = RemoteComputationRegistry::new();
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let handler_cleanup_complete = Arc::clone(&cleanup_complete);
    let handler_park_receiver = Arc::clone(&park_receiver);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.v3-disconnect", move |cx, _invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            let handler_cleanup_complete = Arc::clone(&handler_cleanup_complete);
            let mut receiver = handler_park_receiver
                .lock()
                .take()
                .expect("V3 disconnect handler should execute exactly once");
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                let received = receiver.recv(&cx).await;
                handler_cleanup_complete.store(true, Ordering::SeqCst);
                received.map_err(|error| {
                    RemoteError::TransportError(format!(
                        "proof.v3-disconnect parking operation ended: {error}"
                    ))
                })?;
                Ok(RemoteOutcome::Success(Vec::new()))
            }
        })
        .expect("V3 disconnect handler should register");

    let origin = NodeId::new("origin-v3-disconnect");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.v3-disconnect"])
        .expect("V3 disconnect grant should be valid");
    let hello = policy.hello_for(origin);
    let first_request = remote_service_wire_request_with_lease(
        hello.clone(),
        "proof.v3-disconnect",
        7303,
        0x7303,
        b"disconnect-input",
        Duration::from_secs(10),
    );
    let replay_request = remote_service_wire_request_with_lease(
        hello,
        "proof.v3-disconnect",
        7304,
        0x7303,
        b"disconnect-input",
        Duration::from_secs(10),
    );
    let (acceptor, connector) = remote_client_test_mtls_pair();

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("V3 disconnect service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(2))
                .with_drain_timeout(Duration::from_secs(1)),
        ))
        .expect("V3 disconnect service should bind");
    let endpoint = service
        .local_addr()
        .expect("V3 disconnect service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_cleanup_complete = Arc::clone(&cleanup_complete);
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .expect("V3 disconnect client should build");

    let client_thread = thread::spawn(move || {
        let first = block_on(client.start_session(&Cx::for_testing(), &first_request))
            .expect("first V3 disconnect request should be accepted");
        let session = match first {
            RemoteComputationSessionStart::Running(session) => session,
            RemoteComputationSessionStart::Terminal(response) => {
                panic!("first V3 disconnect request terminated early: {response:?}")
            }
            _ => panic!("first V3 disconnect start returned an unknown future variant"),
        };
        drop(session);

        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !client_cleanup_complete.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < cleanup_deadline,
                "transport loss should cancel and drain the V3 child"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let replay = block_on(client.start_session(&Cx::for_testing(), &replay_request))
            .expect("V3 disconnect retry should decode its cached terminal event");
        match replay {
            RemoteComputationSessionStart::Terminal(RemoteServiceWireResponse::Outcome {
                remote_task_id: 7304,
                outcome: RemoteServiceWireOutcome::Cancelled(_),
            }) => {}
            RemoteComputationSessionStart::Terminal(other) => {
                panic!("unexpected V3 disconnect replay response: {other:?}")
            }
            RemoteComputationSessionStart::Running(_) => {
                panic!("cached V3 disconnect retry must not redispatch")
            }
            _ => panic!("V3 disconnect replay returned an unknown future variant"),
        }
        assert!(client_operator.begin_drain());
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a V3 disconnect context");
            service.run(&cx).await
        })
        .expect("V3 disconnect service should drain cleanly");
    client_thread
        .join()
        .expect("V3 disconnect client should not panic");

    assert_eq!(report.accepted_connections(), 2);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert!(cleanup_complete.load(Ordering::SeqCst));
    assert_eq!(operator.active_connections(), 0);
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_v3_session_cancellation_wakes_stalled_wait() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("V3 cancellation fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("V3 cancellation fixture should expose its address");
    let request = remote_client_test_request(RemoteProtocolVersion::V3, 7305, 0x7305);
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("V3 cancellation fixture should accept one connection");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("V3 cancellation fixture should authenticate the client");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("V3 cancellation fixture should receive a complete request");
            let received: RemoteServiceWireRequest = serde_json::from_slice(&encoded)
                .expect("V3 cancellation fixture request should decode");
            let accepted = RemoteServiceSessionEvent::Accepted {
                remote_task_id: received.remote_task_id().raw(),
            };
            let encoded = serde_json::to_vec(&accepted)
                .expect("V3 cancellation accepted event should encode");
            write_raw_frame(&mut stream, &encoded)
                .await
                .expect("V3 cancellation accepted event should flush");
            accepted_tx
                .send(())
                .expect("V3 cancellation fixture should publish acceptance");
            release_rx
                .recv()
                .expect("V3 cancellation fixture should receive cleanup release");
        });
    });

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .expect("V3 cancellation client should build");
    let start = block_on(client.start_session(&Cx::for_testing(), &request))
        .expect("V3 cancellation session should start");
    let session = match start {
        RemoteComputationSessionStart::Running(session) => session,
        RemoteComputationSessionStart::Terminal(response) => {
            panic!("V3 cancellation fixture terminated early: {response:?}")
        }
        _ => panic!("V3 cancellation start returned an unknown future variant"),
    };
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("V3 cancellation fixture should confirm acceptance");

    let cx = Cx::for_testing();
    let client_cx = cx.clone();
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let client_thread = thread::spawn(move || {
        let result = block_on(session.wait(&client_cx));
        result_tx
            .send(result)
            .expect("V3 cancellation client should publish its result");
    });
    cx.set_cancel_requested(true);
    let result = result_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("caller cancellation should wake a stalled V3 wait");
    assert!(matches!(result, Err(RemoteServiceSessionError::Cancelled)));

    release_tx
        .send(())
        .expect("V3 cancellation fixture should release its server stream");
    client_thread
        .join()
        .expect("V3 cancellation client should not panic");
    server
        .join()
        .expect("V3 cancellation fixture should not panic");
}

#[cfg(feature = "tls")]
fn spawn_native_route_service(
    label: &'static str,
    acceptor: TlsAcceptor,
    policy: RemotePeerAdmissionPolicy,
    computations: RemoteComputationRegistry,
) -> (
    SocketAddr,
    RemoteComputationServiceHandle,
    thread::JoinHandle<RemoteComputationServiceReport>,
) {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let service_thread = thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .unwrap_or_else(|error| panic!("{label} route service runtime should build: {error}"));
        let service = runtime
            .block_on(RemoteComputationService::bind(
                "127.0.0.1:0",
                acceptor,
                policy,
                computations,
                RemoteComputationServiceConfig::new()
                    .with_max_connections(Some(2))
                    .with_drain_timeout(Duration::from_secs(1)),
            ))
            .unwrap_or_else(|error| panic!("{label} route service should bind: {error}"));
        let endpoint = service.local_addr().unwrap_or_else(|error| {
            panic!("{label} route service should expose its address: {error}")
        });
        ready_tx
            .send((endpoint, service.handle()))
            .unwrap_or_else(|_| panic!("{label} route service should publish readiness"));
        runtime
            .block_on(async move {
                let cx = Cx::current()
                    .unwrap_or_else(|| panic!("{label} route service should install a context"));
                service.run(&cx).await
            })
            .unwrap_or_else(|error| panic!("{label} route service should drain cleanly: {error}"))
    });
    let (endpoint, operator) = ready_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("{label} route service did not become ready: {error}"));
    (endpoint, operator, service_thread)
}

#[cfg(feature = "tls")]
#[test]
fn native_remote_runtime_atomically_rotates_validated_routes() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let origin = NodeId::new("origin-native-runtime-route-rotation");
    let destination = NodeId::new("destination-native-runtime-route-rotation");

    let (started_a_tx, started_a_rx) = std::sync::mpsc::sync_channel(1);
    let (release_a_tx, release_a_rx) = oneshot::channel();
    let release_a_rx = Arc::new(Mutex::new(Some(release_a_rx)));
    let build_service =
        |prefix: &'static [u8],
         started_tx: Option<std::sync::mpsc::SyncSender<()>>,
         stall_receiver: Option<Arc<Mutex<Option<oneshot::Receiver<()>>>>>| {
            let dispatch_count = Arc::new(AtomicUsize::new(0));
            let handler_dispatch_count = Arc::clone(&dispatch_count);
            let mut computations = RemoteComputationRegistry::new();
            computations
                .register::<Vec<u8>, Vec<u8>, _, _>("proof.native-route", move |cx, invocation| {
                    let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
                    let started_tx = started_tx.clone();
                    let stall_receiver = stall_receiver.clone();
                    async move {
                        handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                        if let Some(started_tx) = started_tx {
                            started_tx
                                .send(())
                                .expect("route A handler should publish its start");
                        }
                        if let Some(stall_receiver) = stall_receiver {
                            let mut receiver = stall_receiver
                                .lock()
                                .take()
                                .expect("route A handler should dispatch once");
                            receiver.recv(&cx).await.map_err(|error| {
                                RemoteError::TransportError(format!(
                                    "route A release channel failed: {error}"
                                ))
                            })?;
                        }
                        let input = invocation.into_request().input.into_data();
                        let mut output = Vec::with_capacity(prefix.len() + input.len());
                        output.extend_from_slice(prefix);
                        output.extend_from_slice(&input);
                        Ok(RemoteOutcome::Success(output))
                    }
                })
                .expect("route-rotation handler should register");
            let mut peer_pins = CertificatePinSet::new();
            peer_pins.add(
                CertificatePin::compute_spki_sha256(&peer_certificate)
                    .expect("fixture certificate should produce an SPKI pin"),
            );
            let mut policy = RemotePeerAdmissionPolicy::new(
                RemoteProtocolVersion::V3,
                computations.schema_registry().clone(),
            );
            policy
                .grant_tls_peer(origin.clone(), peer_pins, ["proof.native-route"])
                .expect("route-rotation certificate-bound grant should be valid");
            (policy, computations, dispatch_count)
        };
    let (policy_a, computations_a, dispatch_count_a) =
        build_service(b"A:", Some(started_a_tx), Some(Arc::clone(&release_a_rx)));
    let (policy_b, computations_b, dispatch_count_b) = build_service(b"B:", None, None);
    let fingerprint = computations_a.schema_registry().fingerprint();
    assert_eq!(fingerprint, computations_b.schema_registry().fingerprint());
    let hello = policy_a.hello_for(origin.clone());

    let build_acceptor = || {
        let mut client_auth_roots = RootCertStore::empty();
        client_auth_roots
            .add(&peer_certificate)
            .expect("route service should trust the fixture client certificate");
        TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
            .client_auth(ClientAuth::Required(client_auth_roots))
            .build()
            .expect("route service mTLS acceptor should build")
    };
    let server_pins = CertificatePinSet::new().with_pin(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("route client should derive the fixture server SPKI pin"),
    );
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain.clone(), private_key.clone())
        .with_certificate_pins(server_pins)
        .build()
        .expect("route-rotation mTLS connector should build");
    let (endpoint_a, operator_a, service_a) =
        spawn_native_route_service("A", build_acceptor(), policy_a, computations_a);
    let (endpoint_b, operator_b, service_b) =
        spawn_native_route_service("B", build_acceptor(), policy_b, computations_b);
    let build_client = |endpoint| {
        RemoteComputationClient::new(
            endpoint,
            "localhost",
            connector.clone(),
            RemoteComputationClientConfig::new()
                .with_max_attempts(1)
                .with_attempt_timeout(Duration::from_secs(2)),
        )
        .expect("route-rotation client should validate")
    };
    fn fixed_discovery_time() -> asupersync::types::Time {
        asupersync::types::Time::from_nanos(0)
    }

    let resolved_endpoints = Arc::new(Mutex::new(HashSet::from([endpoint_a])));
    let resolver_endpoints = Arc::clone(&resolved_endpoints);
    let discovery = DnsServiceDiscovery::new(
        DnsDiscoveryConfig::new("native-route.test", 7443)
            .poll_interval(Duration::ZERO)
            .with_time_getter(fixed_discovery_time)
            .with_resolver(move |hostname, port| {
                assert_eq!(hostname, "native-route.test");
                assert_eq!(port, 7443);
                Ok(resolver_endpoints.lock().clone())
            }),
    );
    assert_eq!(
        discovery
            .poll_discover()
            .expect("initial deterministic DNS poll should succeed")
            .len(),
        1
    );
    assert_eq!(discovery.endpoints(), vec![endpoint_a]);
    let client_a = build_client(endpoint_a)
        .with_discovered_endpoints(&discovery)
        .expect("initial discovered endpoint snapshot should validate");
    let initial_route =
        NativeRemoteRoute::new(destination.clone(), hello.clone(), client_a.clone());

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("route-rotation driver runtime should build");
    let native = Arc::new(
        NativeRemoteRuntime::new(runtime.handle(), origin.clone(), [initial_route.clone()])
            .expect("initial native route should validate"),
    );
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(origin.clone())
        .with_runtime(native.clone());
    let cx = runtime
        .request_cx_with_budget(Budget::INFINITE)
        .with_remote_cap(cap);

    assert_eq!(native.route_generation(), 0);
    assert_eq!(
        native
            .route(&destination)
            .expect("initial borrowed route should exist")
            .client()
            .endpoint(),
        endpoint_a
    );
    let mut first = spawn_remote(
        &cx,
        destination.clone(),
        ComputationName::new("proof.native-route"),
        RemoteInput::new(b"first".to_vec()),
    )
    .expect("initial route should publish");
    started_a_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("route A handler should start before replacement");
    let running_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while first.state() != RemoteTaskState::Running {
        assert!(
            std::time::Instant::now() < running_deadline,
            "route A operation should publish Running before replacement"
        );
        thread::yield_now();
    }
    assert_eq!(native.active_operations(), 1);
    assert_eq!(dispatch_count_a.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch_count_b.load(Ordering::SeqCst), 0);

    *resolved_endpoints.lock() = HashSet::from([endpoint_b]);
    discovery.invalidate();
    assert_eq!(
        discovery
            .poll_discover()
            .expect("replacement deterministic DNS poll should succeed")
            .len(),
        2
    );
    assert_eq!(discovery.endpoints(), vec![endpoint_b]);
    let route_b = initial_route
        .with_discovered_endpoints(&discovery)
        .expect("discovered replacement route should preserve client policy");
    assert_eq!(route_b.destination(), &destination);
    assert_eq!(route_b.hello(), &hello);
    assert_eq!(route_b.client().server_name(), client_a.server_name());
    assert_eq!(route_b.client().config(), client_a.config());
    assert_eq!(route_b.client().bootstrap_endpoints(), &[endpoint_b]);
    let client_b = route_b.client().clone();
    assert_eq!(
        native
            .replace_routes([route_b.clone()])
            .expect("valid discovered replacement should publish atomically"),
        1
    );
    assert_eq!(native.route_generation(), 1);
    assert_eq!(
        native
            .route(&destination)
            .expect("borrowed compatibility route should remain initial")
            .client()
            .endpoint(),
        endpoint_a
    );
    assert_eq!(
        native
            .effective_route(&destination)
            .expect("effective replacement route should exist")
            .client()
            .endpoint(),
        endpoint_b
    );

    struct SnapshotDiscovery(Vec<SocketAddr>);

    impl Discover for SnapshotDiscovery {
        type Key = SocketAddr;
        type Error = std::convert::Infallible;

        fn poll_discover(
            &self,
        ) -> Result<Vec<asupersync::service::Change<Self::Key>>, Self::Error> {
            Ok(Vec::new())
        }

        fn endpoints(&self) -> Vec<Self::Key> {
            self.0.clone()
        }
    }

    let empty_refresh = route_b
        .with_discovered_endpoints(&SnapshotDiscovery(Vec::new()))
        .expect_err("empty discovered endpoint snapshot must fail before publication");
    assert!(matches!(
        empty_refresh,
        RemoteComputationClientError::InvalidConfig(
            "remote client bootstrap endpoints must be nonempty"
        )
    ));
    let duplicate_refresh = route_b
        .with_discovered_endpoints(&SnapshotDiscovery(vec![endpoint_b, endpoint_b]))
        .expect_err("duplicate discovered endpoint snapshot must fail before publication");
    assert!(matches!(
        duplicate_refresh,
        RemoteComputationClientError::InvalidConfig(
            "remote client bootstrap endpoints must be unique"
        )
    ));
    assert_eq!(native.route_generation(), 1);
    assert_eq!(
        native
            .effective_route(&destination)
            .expect("invalid discovery snapshots must retain the last-known-good route")
            .client()
            .endpoint(),
        endpoint_b
    );

    let wrong_protocol = native
        .replace_routes([NativeRemoteRoute::new(
            destination.clone(),
            RemotePeerHello::new(origin.clone(), RemoteProtocolVersion::V2, fingerprint),
            client_b.clone(),
        )])
        .expect_err("non-V3 replacement must fail closed");
    assert_eq!(
        wrong_protocol,
        NativeRemoteRuntimeBuildError::WrongProtocol {
            destination: destination.clone(),
            presented: RemoteProtocolVersion::V2,
        }
    );
    let wrong_origin = NodeId::new("wrong-native-route-origin");
    let origin_mismatch = native
        .replace_routes([NativeRemoteRoute::new(
            destination.clone(),
            RemotePeerHello::new(wrong_origin.clone(), RemoteProtocolVersion::V3, fingerprint),
            client_b.clone(),
        )])
        .expect_err("origin-mismatched replacement must fail closed");
    assert_eq!(
        origin_mismatch,
        NativeRemoteRuntimeBuildError::OriginIdentityMismatch {
            destination: destination.clone(),
            expected: origin.clone(),
            presented: wrong_origin,
        }
    );
    let duplicate = native
        .replace_routes([
            NativeRemoteRoute::new(destination.clone(), hello.clone(), client_b.clone()),
            NativeRemoteRoute::new(destination.clone(), hello.clone(), client_b.clone()),
        ])
        .expect_err("duplicate replacement must fail closed");
    assert_eq!(
        duplicate,
        NativeRemoteRuntimeBuildError::DuplicateDestination(destination.clone())
    );
    assert_eq!(native.route_generation(), 1);
    assert_eq!(
        native
            .effective_route(&destination)
            .expect("invalid updates must retain the last-known-good route")
            .client()
            .endpoint(),
        endpoint_b
    );

    let mut second = spawn_remote(
        &cx,
        destination.clone(),
        ComputationName::new("proof.native-route"),
        RemoteInput::new(b"second".to_vec()),
    )
    .expect("replacement route should publish");
    let second_outcome = runtime
        .block_on(second.join(&cx))
        .expect("replacement route should return a terminal outcome");
    assert!(matches!(
        second_outcome,
        RemoteOutcome::Success(ref payload) if payload == b"B:second"
    ));
    assert_eq!(dispatch_count_a.load(Ordering::SeqCst), 1);
    assert_eq!(dispatch_count_b.load(Ordering::SeqCst), 1);
    assert_eq!(first.state(), RemoteTaskState::Running);
    assert_eq!(native.active_operations(), 1);

    assert_eq!(
        native
            .replace_routes(std::iter::empty())
            .expect("empty snapshot should remove every route"),
        2
    );
    assert!(native.effective_route(&destination).is_none());
    let unreachable = spawn_remote(
        &cx,
        destination.clone(),
        ComputationName::new("proof.native-route"),
        RemoteInput::new(b"must-not-dispatch".to_vec()),
    )
    .expect_err("removed route must refuse new work before publication");
    assert_eq!(
        unreachable,
        RemoteError::NodeUnreachable(destination.as_str().to_owned())
    );
    assert_eq!(dispatch_count_b.load(Ordering::SeqCst), 1);
    release_a_tx
        .send(&cx, ())
        .expect("route A operation should be released after route removal");
    let first_outcome = runtime
        .block_on(first.join(&cx))
        .expect("in-flight route A operation should survive replacement and removal");
    assert!(matches!(
        first_outcome,
        RemoteOutcome::Success(ref payload) if payload == b"A:first"
    ));
    assert_eq!(native.active_operations(), 0);
    assert!(runtime.block_on(native.close(&cx)));
    drop(cx);
    drop(native);
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));

    assert!(operator_a.begin_drain());
    let report_a = service_a.join().expect("route service A should not panic");
    assert_eq!(report_a.accepted_connections(), 1);
    assert_eq!(report_a.completed_connections(), 1);
    assert_eq!(operator_a.active_connections(), 0);
    assert!(operator_b.begin_drain());
    let report_b = service_b.join().expect("route service B should not panic");
    assert_eq!(report_b.accepted_connections(), 1);
    assert_eq!(report_b.completed_connections(), 1);
    assert_eq!(operator_b.active_connections(), 0);
}

#[cfg(feature = "tls")]
#[test]
fn native_remote_runtime_drives_spawn_capacity_cancel_and_quiescent_close() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let cleanup_complete = Arc::new(AtomicBool::new(false));
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (park_tx, park_rx) = oneshot::channel::<()>();
    let park_receiver = Arc::new(Mutex::new(Some(park_rx)));
    let mut computations = RemoteComputationRegistry::new();
    let echo_dispatch_count = Arc::clone(&dispatch_count);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.native-echo", move |_cx, invocation| {
            let echo_dispatch_count = Arc::clone(&echo_dispatch_count);
            async move {
                echo_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("native runtime echo handler should register");
    let parked_dispatch_count = Arc::clone(&dispatch_count);
    let parked_cleanup_complete = Arc::clone(&cleanup_complete);
    let parked_receiver = Arc::clone(&park_receiver);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.native-park", move |cx, invocation| {
            let parked_dispatch_count = Arc::clone(&parked_dispatch_count);
            let parked_cleanup_complete = Arc::clone(&parked_cleanup_complete);
            let started_tx = started_tx.clone();
            let mut receiver = parked_receiver
                .lock()
                .take()
                .expect("native runtime parked handler should dispatch once");
            async move {
                parked_dispatch_count.fetch_add(1, Ordering::SeqCst);
                started_tx
                    .send(())
                    .expect("native runtime handler should publish its start");
                let received = receiver.recv(&cx).await;
                parked_cleanup_complete.store(true, Ordering::SeqCst);
                match received {
                    Ok(()) => Ok(RemoteOutcome::Success(
                        invocation.into_request().input.into_data(),
                    )),
                    Err(_) => Ok(RemoteOutcome::Cancelled(
                        cx.cancel_reason()
                            .unwrap_or_else(CancelReason::parent_cancelled),
                    )),
                }
            }
        })
        .expect("native runtime parked handler should register");

    let origin = NodeId::new("origin-native-runtime-loopback");
    let destination = NodeId::new("destination-native-runtime-loopback");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(
            origin.clone(),
            peer_pins,
            ["proof.native-echo", "proof.native-park"],
        )
        .expect("native runtime certificate-bound grant should be valid");
    let hello = policy.hello_for(origin.clone());

    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("native runtime mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("native runtime mTLS connector should build");

    let service_runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime service runtime should build");
    let service = service_runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(4))
                .with_drain_timeout(Duration::from_secs(1)),
        ))
        .expect("native runtime service should bind");
    let endpoint = service
        .local_addr()
        .expect("native runtime service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_dispatch_count = Arc::clone(&dispatch_count);
    let client_cleanup_complete = Arc::clone(&cleanup_complete);

    let client_thread = thread::spawn(move || {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("native remote driver runtime should build");
        let client = RemoteComputationClient::new(
            endpoint,
            "localhost",
            connector,
            RemoteComputationClientConfig::new()
                .with_max_attempts(1)
                .with_attempt_timeout(Duration::from_secs(2)),
        )
        .expect("native remote computation client should build");
        let native = Arc::new(
            NativeRemoteRuntime::with_config(
                runtime.handle(),
                origin.clone(),
                [NativeRemoteRoute::new(destination.clone(), hello, client)],
                NativeRemoteRuntimeConfig::new()
                    .with_max_in_flight(1)
                    .with_drain_timeout(Duration::from_secs(2)),
            )
            .expect("native remote runtime should validate its V3 route"),
        );
        let cap = asupersync::remote::RemoteCap::new()
            .with_local_node(origin)
            .with_default_lease(Duration::from_secs(5))
            .with_runtime(native.clone());
        let cx = runtime
            .request_cx_with_budget(Budget::INFINITE)
            .with_remote_cap(cap);

        let mut echo = spawn_remote(
            &cx,
            destination.clone(),
            ComputationName::new("proof.native-echo"),
            RemoteInput::new(b"native-runtime-echo".to_vec()),
        )
        .expect("native runtime should publish the echo driver");
        let echo_outcome = runtime
            .block_on(echo.join(&cx))
            .expect("native runtime echo should complete");
        assert!(matches!(
            echo_outcome,
            RemoteOutcome::Success(ref payload) if payload == b"native-runtime-echo"
        ));

        let mut parked = spawn_remote(
            &cx,
            destination.clone(),
            ComputationName::new("proof.native-park"),
            RemoteInput::new(b"native-runtime-park".to_vec()),
        )
        .expect("native runtime should publish the parked driver");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("native runtime parked handler should start");
        let running_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while parked.state() != RemoteTaskState::Running {
            assert!(
                std::time::Instant::now() < running_deadline,
                "native runtime should publish Running after the accepted event"
            );
            std::thread::yield_now();
        }
        assert_eq!(parked.state(), RemoteTaskState::Running);
        assert_eq!(native.active_operations(), 1);

        let capacity_error = spawn_remote(
            &cx,
            destination,
            ComputationName::new("proof.native-echo"),
            RemoteInput::new(b"must-not-dispatch".to_vec()),
        )
        .expect_err("native runtime should enforce its one-operation cap");
        assert_eq!(
            capacity_error,
            RemoteError::SpawnRejected(SpawnRejectReason::CapacityExceeded)
        );
        assert_eq!(client_dispatch_count.load(Ordering::SeqCst), 2);

        assert!(
            runtime.block_on(native.close(&cx)),
            "graceful V3 cancellation should quiesce without force-close"
        );
        assert_eq!(native.active_operations(), 0);
        assert!(client_cleanup_complete.load(Ordering::SeqCst));
        let parked_outcome = runtime
            .block_on(parked.join(&cx))
            .expect("native runtime shutdown should publish a cancelled outcome");
        assert!(matches!(parked_outcome, RemoteOutcome::Cancelled(_)));
        assert!(native.observe_task_state(parked.remote_task_id()).is_none());
        assert!(client_operator.begin_drain());

        drop(cx);
        drop(native);
        // Joined handles remain in scope: consuming their terminal result must
        // release the adapter's strong RuntimeHandle reference automatically.
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    });

    let report = service_runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a native service context");
            service.run(&cx).await
        })
        .expect("native remote service should drain cleanly");
    client_thread
        .join()
        .expect("native remote driver client should not panic");
    drop(park_tx);

    assert_eq!(report.accepted_connections(), 2);
    assert_eq!(report.completed_connections(), 2);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.interrupted_connections(), 0);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 2);
    assert!(cleanup_complete.load(Ordering::SeqCst));
    assert_eq!(operator.active_connections(), 0);
}

#[cfg(all(feature = "remote-service", unix))]
struct RemoteServiceChildGuard {
    child: Option<std::process::Child>,
}

#[cfg(all(feature = "remote-service", unix))]
impl RemoteServiceChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("remote service child should still be owned")
            .id()
    }

    fn wait_timeout(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self
                .child
                .as_mut()
                .expect("remote service child should still be owned")
                .try_wait()
            {
                Ok(Some(status)) => {
                    self.child.take();
                    return status;
                }
                Ok(None) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "remote service child did not exit within {timeout:?}"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("remote service child wait failed: {error}"),
            }
        }
    }
}

#[cfg(all(feature = "remote-service", unix))]
impl Drop for RemoteServiceChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(all(feature = "remote-service", unix))]
fn recv_remote_service_event(
    lines: &std::sync::mpsc::Receiver<Result<String, String>>,
    expected_event: &str,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "remote service never emitted event '{expected_event}'"
        );
        let line = lines
            .recv_timeout(remaining)
            .unwrap_or_else(|error| {
                panic!("remote service output ended before '{expected_event}': {error}")
            })
            .unwrap_or_else(|error| panic!("remote service stdout read failed: {error}"));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|error| {
            panic!("remote service emitted invalid JSON '{line}': {error}")
        });
        if value.get("event").and_then(serde_json::Value::as_str) == Some(expected_event) {
            return value;
        }
    }
}

#[cfg(all(feature = "remote-service", unix))]
fn run_remote_service_cli_session(
    runtime: &Runtime,
    client: &RemoteComputationClient,
    request: &RemoteServiceWireRequest,
) -> Result<RemoteServiceWireResponse, String> {
    runtime.block_on(async {
        let cx = Cx::current().expect("remote CLI client should have a root context");
        let started = client
            .start_session(&cx, request)
            .await
            .map_err(|error| error.to_string())?;
        match started {
            RemoteComputationSessionStart::Running(session) => {
                session.wait(&cx).await.map_err(|error| error.to_string())
            }
            RemoteComputationSessionStart::Terminal(response) => Ok(response),
            _ => Err("remote CLI returned an unknown session-start variant".to_string()),
        }
    })
}

#[cfg(all(feature = "remote-service", unix))]
#[test]
fn remote_service_cli_hosts_mtls_v3_and_drains_cross_process() {
    use asupersync::remote::RemoteComputationSessionStart;
    use std::io::BufRead;
    use std::process::Stdio;

    const AUTHORIZED_NODE: &str = "remote-cli-authorized";
    const ECHO_COMPUTATION: &str = "asupersync.remote.echo.v1";

    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let spki_pin = CertificatePin::compute_spki_sha256(&peer_certificate)
        .expect("TLS fixture should produce an SPKI pin")
        .to_base64();

    let temp = tempfile::tempdir().expect("remote service fixture directory should exist");
    let certificate_path = temp.path().join("service.crt");
    let private_key_path = temp.path().join("service.key");
    let ca_path = temp.path().join("client-ca.crt");
    let config_path = temp.path().join("remote-service.toml");
    fs::write(&certificate_path, TEST_CERT_PEM).expect("service certificate should be written");
    fs::write(&private_key_path, TEST_KEY_PEM).expect("service key should be written");
    fs::write(&ca_path, TEST_CERT_PEM).expect("client CA should be written");
    fs::write(
        &config_path,
        format!(
            "schema_version = 2\nprotocol = \"3.0\"\nlisten = \"127.0.0.1:0\"\nlisten_scope = \"loopback_only\"\nserver_certificate_chain = \"{}\"\nserver_private_key = \"{}\"\nclient_ca_bundle = \"{}\"\nmax_frame_bytes = 65536\nmax_connections = 1\ntls_handshake_timeout_ms = 200\ninitial_frame_timeout_ms = 2000\ndrain_timeout_ms = 5000\nidempotency_retention_ms = 30000\nmax_idempotency_records_per_peer = 32\n\n[[peers]]\nnode_id = \"{AUTHORIZED_NODE}\"\nspki_sha256 = [\"{spki_pin}\"]\ncomputations = [\"{ECHO_COMPUTATION}\"]\n",
            certificate_path.display(),
            private_key_path.display(),
            ca_path.display(),
        ),
    )
    .expect("remote service config should be written");

    let mut child = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            config_path
                .to_str()
                .expect("temporary config path should be UTF-8"),
            "remote",
            "serve",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("remote service child should start");
    let stdout = child
        .stdout
        .take()
        .expect("remote service stdout should be piped");
    let stderr = child
        .stderr
        .take()
        .expect("remote service stderr should be piped");
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.map_err(|error| error.to_string());
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let stderr_reader = thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut captured = String::new();
        std::io::Read::read_to_string(&mut reader, &mut captured)
            .expect("remote service stderr should be readable");
        captured
    });
    let mut child = RemoteServiceChildGuard::new(child);

    let ready =
        recv_remote_service_event(&line_rx, "remote_service_ready", Duration::from_secs(10));
    assert_eq!(ready["schema_version"], 2);
    assert_eq!(ready["protocol"], "3.0");
    assert_eq!(ready["listen_scope"], "loopback_only");
    assert_eq!(ready["authorized_peers"], 1);
    assert_eq!(
        ready["idempotency_scope"],
        "authenticated_peer_process_local"
    );
    let endpoint: SocketAddr = ready["listen"]
        .as_str()
        .expect("ready event should contain its listener address")
        .parse()
        .expect("ready listener address should parse");

    // Promote the native client from an in-process test helper to a second
    // packaged process. The closed primary proves ordered pre-delivery
    // failover; the exact echo receipt proves the live secondary completed the
    // mutually authenticated V3 session.
    let refused_endpoint = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("remote probe refused-primary fixture should bind");
        listener
            .local_addr()
            .expect("remote probe refused-primary address should be available")
    };
    let probe_config_path = temp.path().join("remote-probe.toml");
    fs::write(
        &probe_config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{refused_endpoint}\", \"{endpoint}\"]\nserver_name = \"localhost\"\nserver_ca_bundle = \"{}\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"{spki_pin}\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 3000\ncompletion_timeout_ms = 3000\nmax_attempts = 2\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 3000\nfull_jitter = false\ntcp_nodelay = true\n",
            ca_path.display(),
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("remote probe config should be written");
    let probe = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            probe_config_path
                .to_str()
                .expect("temporary probe config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            "packaged-mtls-v3-probe",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("remote probe child should run");
    assert!(
        probe.status.success(),
        "remote probe child failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(
        probe.stderr.is_empty(),
        "successful remote probe stderr was not empty: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let probe_output: serde_json::Value = serde_json::from_slice(&probe.stdout)
        .expect("remote probe should emit one JSON success record");
    assert_eq!(probe_output["event"], "remote_probe_completed");
    assert_eq!(probe_output["protocol"], "3.0");
    assert_eq!(probe_output["computation"], ECHO_COMPUTATION);
    assert_eq!(probe_output["origin_node"], AUTHORIZED_NODE);
    assert_eq!(probe_output["echoed_bytes"], 22);
    assert_eq!(
        probe_output["echoed_sha256"],
        "daa3990b665cc49e78df9e07da3f5a9c010992eeb5d533fea04764bf5d81d2d5"
    );
    assert_eq!(
        probe_output["bootstrap_endpoints"],
        serde_json::json!([refused_endpoint.to_string(), endpoint.to_string()])
    );

    // An authenticated primary with the wrong enforcing server pin is not a
    // pre-delivery transient: the client must fail closed on that endpoint and
    // never try the later bootstrap address.
    let secondary_observer = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("remote probe no-fallthrough observer should bind");
    secondary_observer
        .set_nonblocking(true)
        .expect("remote probe no-fallthrough observer should be nonblocking");
    let secondary_endpoint = secondary_observer
        .local_addr()
        .expect("remote probe no-fallthrough address should be available");
    let wrong_pin_config_path = temp.path().join("remote-probe-wrong-pin.toml");
    fs::write(
        &wrong_pin_config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{endpoint}\", \"{secondary_endpoint}\"]\nserver_name = \"localhost\"\nserver_ca_bundle = \"{}\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 3000\ncompletion_timeout_ms = 3000\nmax_attempts = 2\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 3000\nfull_jitter = false\ntcp_nodelay = true\n",
            ca_path.display(),
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("wrong-pin remote probe config should be written");
    let wrong_pin_probe = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            wrong_pin_config_path
                .to_str()
                .expect("temporary wrong-pin config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            "must-not-fall-through",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("wrong-pin remote probe child should run");
    assert!(!wrong_pin_probe.status.success());
    assert!(wrong_pin_probe.stdout.is_empty());
    let wrong_pin_error: serde_json::Value = serde_json::from_slice(&wrong_pin_probe.stderr)
        .expect("wrong-pin remote probe should emit one structured error");
    assert_eq!(wrong_pin_error["type"], "remote_probe_tls_failed");
    assert_eq!(wrong_pin_error["context"]["attempts"], 1);
    match secondary_observer.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("wrong-pin probe must not dial a later bootstrap endpoint"),
        Err(error) => panic!("remote probe no-fallthrough observer failed: {error}"),
    }

    let hostname_secondary_observer = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("remote probe hostname no-fallthrough observer should bind");
    hostname_secondary_observer
        .set_nonblocking(true)
        .expect("remote probe hostname observer should be nonblocking");
    let hostname_secondary_endpoint = hostname_secondary_observer
        .local_addr()
        .expect("remote probe hostname observer address should be available");
    let wrong_hostname_config_path = temp.path().join("remote-probe-wrong-hostname.toml");
    fs::write(
        &wrong_hostname_config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{endpoint}\", \"{hostname_secondary_endpoint}\"]\nserver_name = \"wrong.example.test\"\nserver_ca_bundle = \"{}\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"{spki_pin}\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 3000\ncompletion_timeout_ms = 3000\nmax_attempts = 2\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 3000\nfull_jitter = false\ntcp_nodelay = true\n",
            ca_path.display(),
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("wrong-hostname remote probe config should be written");
    let wrong_hostname_probe = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            wrong_hostname_config_path
                .to_str()
                .expect("temporary wrong-hostname config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            "must-not-fall-through-hostname",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("wrong-hostname remote probe child should run");
    assert!(!wrong_hostname_probe.status.success());
    assert!(wrong_hostname_probe.stdout.is_empty());
    let wrong_hostname_error: serde_json::Value =
        serde_json::from_slice(&wrong_hostname_probe.stderr)
            .expect("wrong-hostname remote probe should emit one structured error");
    assert_eq!(wrong_hostname_error["type"], "remote_probe_tls_failed");
    assert_eq!(wrong_hostname_error["context"]["attempts"], 1);
    match hostname_secondary_observer.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("wrong-hostname probe must not dial a later bootstrap endpoint"),
        Err(error) => panic!("remote probe hostname observer failed: {error}"),
    }

    let config_only_observer = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("remote probe config-only observer should bind");
    config_only_observer
        .set_nonblocking(true)
        .expect("remote probe config-only observer should be nonblocking");
    let config_only_endpoint = config_only_observer
        .local_addr()
        .expect("remote probe config-only observer address should be available");
    let unreadable_tls_config_path = temp.path().join("remote-probe-missing-ca.toml");
    fs::write(
        &unreadable_tls_config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{config_only_endpoint}\"]\nserver_name = \"localhost\"\nserver_ca_bundle = \"missing-server-ca.crt\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"{spki_pin}\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 3000\ncompletion_timeout_ms = 3000\nmax_attempts = 1\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 3000\nfull_jitter = false\ntcp_nodelay = true\n",
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("missing-CA remote probe config should be written");
    let unreadable_tls_probe = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            unreadable_tls_config_path
                .to_str()
                .expect("temporary missing-CA config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            "must-not-dial-with-missing-ca",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("missing-CA remote probe child should run");
    assert!(!unreadable_tls_probe.status.success());
    assert!(unreadable_tls_probe.stdout.is_empty());
    let unreadable_tls_error: serde_json::Value =
        serde_json::from_slice(&unreadable_tls_probe.stderr)
            .expect("missing-CA remote probe should emit one structured error");
    assert_eq!(unreadable_tls_error["type"], "remote_probe_config_invalid");
    match config_only_observer.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("unreadable TLS material must fail before any endpoint dial"),
        Err(error) => panic!("remote probe config-only observer failed: {error}"),
    }

    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("remote CLI mTLS connector should build");
    let stalled_connector = connector.clone();
    let final_stalled_connector = connector.clone();
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(3)),
    )
    .expect("remote CLI client should validate");
    let mut schemas = ComputationSchemaRegistry::new();
    schemas
        .register_typed::<Vec<u8>, Vec<u8>>(ECHO_COMPUTATION)
        .expect("remote CLI echo schema should register");
    let fingerprint = schemas.fingerprint();
    let unauthorized_request = remote_service_wire_request_with(
        RemotePeerHello::new(
            NodeId::new("remote-cli-unauthorized"),
            RemoteProtocolVersion::V3,
            fingerprint,
        ),
        ECHO_COMPUTATION,
        8801,
        0x8801,
        b"must-not-dispatch",
    );
    let authorized_hello = RemotePeerHello::new(
        NodeId::new(AUTHORIZED_NODE),
        RemoteProtocolVersion::V3,
        fingerprint,
    );
    let client_runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("remote CLI client runtime should build");
    client_runtime.block_on(async {
        let cx = Cx::current().expect("remote CLI client should have a root context");
        let unauthorized = client
            .start_session(&cx, &unauthorized_request)
            .await
            .expect("unauthorized request should receive a typed refusal");
        match unauthorized {
            RemoteComputationSessionStart::Terminal(RemoteServiceWireResponse::Rejected {
                code: RemoteServiceRejectionCode::AdmissionDenied,
                ..
            }) => {}
            RemoteComputationSessionStart::Terminal(other) => {
                panic!("unexpected unauthorized response: {other:?}")
            }
            RemoteComputationSessionStart::Running(_) => {
                panic!("unauthorized peer must not start a remote computation")
            }
            _ => panic!("unauthorized request returned an unknown session-start variant"),
        }
    });

    let assert_echo = |task_id: u64, expected_payload: &[u8]| {
        let request = remote_service_wire_request_with(
            authorized_hello.clone(),
            ECHO_COMPUTATION,
            task_id,
            u128::from(task_id),
            expected_payload,
        );
        let response = run_remote_service_cli_session(&client_runtime, &client, &request)
            .unwrap_or_else(|error| panic!("authorized echo {task_id} failed: {error}"));
        assert!(matches!(
            response,
            RemoteServiceWireResponse::Outcome {
                remote_task_id,
                outcome: RemoteServiceWireOutcome::Success(ref actual_payload),
            } if remote_task_id == task_id && actual_payload.as_slice() == expected_payload
        ));
    };
    assert_echo(8802, b"cross-process-native-echo");

    // With a one-connection cap, a raw TCP peer occupies the only slot until
    // the configured TLS handshake deadline closes it. EOF is the causal
    // recovery signal; the next authorized exchange then proves the slot was
    // returned rather than merely timing out the test.
    let mut raw_stall = std::net::TcpStream::connect(endpoint)
        .expect("raw stalled peer should complete its TCP handshake");
    raw_stall
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("raw stalled peer should set a bounded read");
    let mut raw_byte = [0_u8; 1];
    match std::io::Read::read(&mut raw_stall, &mut raw_byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(read) => panic!("raw stalled peer unexpectedly received {read} TLS bytes"),
        Err(error) => panic!("TLS handshake deadline did not close raw stalled peer: {error}"),
    }
    drop(raw_stall);
    assert_echo(8803, b"capacity-after-handshake-timeout");

    // A fully authenticated peer that sends no first frame is separately
    // bounded. Completing the TLS handshake proves this connection is the one
    // admitted slot; EOF proves the initial-frame deadline released it.
    let mut framed_stall = client_runtime.block_on(async {
        let stream = TcpStream::connect(endpoint)
            .await
            .expect("authenticated stalled peer should connect");
        stalled_connector
            .connect("localhost", stream)
            .await
            .expect("authenticated stalled peer should complete mutual TLS")
    });
    let stalled_read = client_runtime.block_on(async {
        let cx = Cx::current().expect("remote CLI client should have a root context");
        let mut byte = [0_u8; 1];
        asupersync::time::timeout(
            cx.now(),
            Duration::from_secs(3),
            framed_stall.read(&mut byte),
        )
        .await
        .expect("initial-frame deadline should close the silent peer within three seconds")
    });
    match stalled_read {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(read) => panic!("silent authenticated peer unexpectedly received {read} bytes"),
        Err(error) => panic!("initial-frame deadline did not close silent peer: {error}"),
    }
    drop(framed_stall);
    assert_echo(8804, b"capacity-after-initial-frame-timeout");

    // Hold one authenticated session before its first frame so the two-signal
    // path is exercised against live owned work. Listener refusal after the
    // first signal is the causal drain boundary; the second signal then forces
    // the still-live connection task closed before its two-second frame timer.
    let final_stall = client_runtime.block_on(async {
        let stream = TcpStream::connect(endpoint)
            .await
            .expect("final stalled peer should connect");
        final_stalled_connector
            .connect("localhost", stream)
            .await
            .expect("final stalled peer should complete mutual TLS")
    });

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(
            i32::try_from(child.id()).expect("remote service child PID should fit i32"),
        ),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("first SIGTERM should begin remote service drain");
    let admission_close_deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        match std::net::TcpStream::connect_timeout(&endpoint, Duration::from_millis(25)) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => break,
            Ok(stream) => drop(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) => panic!("unexpected admission-close probe failure: {error}"),
        }
        assert!(
            std::time::Instant::now() < admission_close_deadline,
            "first SIGTERM did not close remote service admission"
        );
        thread::yield_now();
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(
            i32::try_from(child.id()).expect("remote service child PID should fit i32"),
        ),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("second SIGTERM should force-close remote service work");
    let status = child.wait_timeout(Duration::from_secs(10));
    assert!(
        status.success(),
        "remote service child exited with {status}"
    );
    drop(final_stall);
    assert!(client_runtime.shutdown_timeout(Duration::from_secs(2)));
    let terminal =
        recv_remote_service_event(&line_rx, "remote_service_stopped", Duration::from_secs(2));
    stdout_reader
        .join()
        .expect("remote service stdout reader should not panic");
    let stderr = stderr_reader
        .join()
        .expect("remote service stderr reader should not panic");
    assert!(
        stderr.is_empty(),
        "remote service stderr was not empty: {stderr}"
    );

    assert_eq!(terminal["phase"], "Stopped");
    assert_eq!(terminal["active_connections"], 0);
    assert_eq!(terminal["signals_received"], 2);
    assert_eq!(terminal["drain_requested"], true);
    assert_eq!(terminal["force_close_requested"], true);
    assert!(
        terminal["accepted_connections"].as_u64().unwrap_or(0) >= 7,
        "every causal connection should be reflected in terminal accounting: {terminal}"
    );
    assert_eq!(terminal["completed_connections"], 5);
    assert!(
        terminal["failed_connections"].as_u64().unwrap_or(0) >= 4,
        "TLS identity refusals and both admission deadlines should be connection failures: {terminal}"
    );
    assert!(
        terminal["interrupted_connections"].as_u64().unwrap_or(0) >= 1,
        "second-signal force-close should interrupt the live stalled peer: {terminal}"
    );
    assert_eq!(terminal["panicked_connections"], 0);
    assert!(
        terminal["force_closed_connections"].as_u64().unwrap_or(0) >= 1,
        "second-signal force-close should be retained in shutdown stats: {terminal}"
    );
}

#[cfg(all(feature = "remote-service", unix))]
#[test]
fn remote_probe_cli_bounds_accepted_session_and_closes_transport() {
    use std::process::Stdio;

    const AUTHORIZED_NODE: &str = "remote-probe-timeout-origin";
    const ECHO_COMPUTATION: &str = "asupersync.remote.echo.v1";

    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let spki_pin = CertificatePin::compute_spki_sha256(&peer_certificate)
        .expect("TLS fixture should produce an SPKI pin")
        .to_base64();

    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(&peer_certificate)
        .expect("accepted-stall server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain, private_key)
        .client_auth(ClientAuth::Required(client_roots))
        .build()
        .expect("accepted-stall mTLS acceptor should build");
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("accepted-stall listener should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("accepted-stall listener should expose its address");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accepted-stall listener should accept the probe");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("accepted-stall listener should authenticate the probe");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("accepted-stall listener should receive the probe request");
            let request: RemoteServiceWireRequest = serde_json::from_slice(&encoded)
                .expect("accepted-stall probe request should decode");
            assert_eq!(request.hello().peer_node().as_str(), AUTHORIZED_NODE);
            assert_eq!(
                request.hello().protocol_version(),
                RemoteProtocolVersion::V3
            );
            let accepted = RemoteServiceSessionEvent::Accepted {
                remote_task_id: request.remote_task_id().raw(),
            };
            let encoded =
                serde_json::to_vec(&accepted).expect("accepted-stall event should encode");
            write_raw_frame(&mut stream, &encoded)
                .await
                .expect("accepted-stall event should write");
            stream
                .flush()
                .await
                .expect("accepted-stall event should flush");
            accepted_tx
                .send(())
                .expect("accepted-stall server should publish acceptance");

            assert!(
                read_raw_frame(&mut stream).await.is_err(),
                "completion timeout must close the accepted transport"
            );
            closed_tx
                .send(())
                .expect("accepted-stall server should publish transport close");
        });
    });

    let temp = tempfile::tempdir().expect("remote probe timeout fixture should exist");
    let certificate_path = temp.path().join("client.crt");
    let private_key_path = temp.path().join("client.key");
    let ca_path = temp.path().join("server-ca.crt");
    let config_path = temp.path().join("remote-probe-timeout.toml");
    fs::write(&certificate_path, TEST_CERT_PEM).expect("client certificate should be written");
    fs::write(&private_key_path, TEST_KEY_PEM).expect("client key should be written");
    fs::write(&ca_path, TEST_CERT_PEM).expect("server CA should be written");
    fs::write(
        &config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{endpoint}\"]\nserver_name = \"localhost\"\nserver_ca_bundle = \"{}\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"{spki_pin}\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 2000\ncompletion_timeout_ms = 100\nmax_attempts = 1\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 10000\nfull_jitter = false\ntcp_nodelay = true\n",
            ca_path.display(),
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("accepted-stall probe config should be written");
    let mut child = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            config_path
                .to_str()
                .expect("temporary timeout config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            ECHO_COMPUTATION,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("accepted-stall probe child should start");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("accepted-stall probe exceeded its completion deadline");
            }
            Err(error) => panic!("accepted-stall probe wait failed: {error}"),
        }
    };
    assert!(!status.success());
    accepted_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("accepted-stall probe must reach the post-accept phase");
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("accepted-stall probe must close its transport after timeout");
    let mut stdout = String::new();
    std::io::Read::read_to_string(
        child
            .stdout
            .as_mut()
            .expect("accepted-stall probe stdout should be piped"),
        &mut stdout,
    )
    .expect("accepted-stall probe stdout should be readable");
    let mut stderr = String::new();
    std::io::Read::read_to_string(
        child
            .stderr
            .as_mut()
            .expect("accepted-stall probe stderr should be piped"),
        &mut stderr,
    )
    .expect("accepted-stall probe stderr should be readable");
    assert!(stdout.is_empty());
    let error: serde_json::Value =
        serde_json::from_str(&stderr).expect("accepted-stall probe should emit structured error");
    assert_eq!(error["type"], "remote_probe_delivery_ambiguous");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("will not be replayed")
    );
    server
        .join()
        .expect("accepted-stall server should not panic");
}

#[cfg(all(feature = "remote-service", unix))]
#[test]
fn remote_probe_cli_does_not_replay_when_peer_drops_before_accepted() {
    use std::process::Stdio;

    const AUTHORIZED_NODE: &str = "remote-probe-pre-accepted-origin";
    const PAYLOAD: &str = "published-before-accepted";

    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let spki_pin = CertificatePin::compute_spki_sha256(&peer_certificate)
        .expect("TLS fixture should produce an SPKI pin")
        .to_base64();

    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(&peer_certificate)
        .expect("pre-accepted server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain, private_key)
        .client_auth(ClientAuth::Required(client_roots))
        .build()
        .expect("pre-accepted mTLS acceptor should build");
    let primary = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("pre-accepted primary listener should bind loopback");
    let primary_endpoint = primary
        .local_addr()
        .expect("pre-accepted primary listener should expose its address");
    let secondary = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("pre-accepted secondary observer should bind loopback");
    let secondary_endpoint = secondary
        .local_addr()
        .expect("pre-accepted secondary observer should expose its address");
    secondary
        .set_nonblocking(true)
        .expect("pre-accepted secondary observer should be nonblocking");
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = primary
                .accept()
                .await
                .expect("pre-accepted primary should accept the probe");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("pre-accepted primary should authenticate the probe");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("pre-accepted primary should receive the published request");
            let request_json: serde_json::Value = serde_json::from_slice(&encoded)
                .expect("pre-accepted probe request JSON should decode");
            assert_eq!(
                request_json["input"],
                serde_json::to_value(PAYLOAD.as_bytes())
                    .expect("pre-accepted expected payload should encode")
            );
            let request: RemoteServiceWireRequest = serde_json::from_value(request_json)
                .expect("pre-accepted probe request should decode");
            assert_eq!(request.hello().peer_node().as_str(), AUTHORIZED_NODE);
            assert_eq!(
                request.hello().protocol_version(),
                RemoteProtocolVersion::V3
            );
        });
    });

    let temp = tempfile::tempdir().expect("pre-accepted probe fixture should exist");
    let certificate_path = temp.path().join("client.crt");
    let private_key_path = temp.path().join("client.key");
    let ca_path = temp.path().join("server-ca.crt");
    let config_path = temp.path().join("remote-probe-pre-accepted.toml");
    fs::write(&certificate_path, TEST_CERT_PEM).expect("client certificate should be written");
    fs::write(&private_key_path, TEST_KEY_PEM).expect("client key should be written");
    fs::write(&ca_path, TEST_CERT_PEM).expect("server CA should be written");
    fs::write(
        &config_path,
        format!(
            "schema_version = 1\nprotocol = \"3.0\"\nbootstrap_endpoints = [\"{primary_endpoint}\", \"{secondary_endpoint}\"]\nserver_name = \"localhost\"\nserver_ca_bundle = \"{}\"\nclient_certificate_chain = \"{}\"\nclient_private_key = \"{}\"\nserver_spki_sha256 = [\"{spki_pin}\"]\norigin_node = \"{AUTHORIZED_NODE}\"\nmax_frame_bytes = 65536\nconnect_timeout_ms = 200\ntls_handshake_timeout_ms = 1000\nattempt_timeout_ms = 2000\ncompletion_timeout_ms = 1000\nmax_attempts = 2\ninitial_backoff_ms = 1\nmax_backoff_ms = 10\nlease_ms = 10000\nfull_jitter = false\ntcp_nodelay = true\n",
            ca_path.display(),
            certificate_path.display(),
            private_key_path.display(),
        ),
    )
    .expect("pre-accepted probe config should be written");
    let output = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args([
            "--format",
            "stream-json",
            "--config",
            config_path
                .to_str()
                .expect("temporary pre-accepted config path should be UTF-8"),
            "remote",
            "probe",
            "--payload",
            PAYLOAD,
        ])
        .stdin(Stdio::null())
        .output()
        .expect("pre-accepted probe child should run");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("probe error should be UTF-8");
    let error: serde_json::Value =
        serde_json::from_str(&stderr).expect("pre-accepted probe should emit structured error");
    assert_eq!(error["type"], "remote_probe_delivery_ambiguous");
    assert_eq!(error["context"]["attempts"], 1);
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("will not be replayed")
    );
    server
        .join()
        .expect("pre-accepted primary server should not panic");
    match secondary.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("ambiguous pre-accepted delivery must not dial the secondary endpoint"),
        Err(error) => panic!("unexpected secondary observer failure: {error}"),
    }
}

#[cfg(feature = "tls")]
#[test]
fn native_remote_runtime_drain_wakes_pending_tls_admission() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("pending-admission fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("pending-admission fixture should expose its address");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let server = thread::spawn(move || {
        let (stream, _) = listener
            .accept()
            .expect("pending-admission fixture should accept one connection");
        accepted_tx
            .send(())
            .expect("pending-admission fixture should publish its accepted socket");
        release_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("pending-admission fixture should receive cleanup release");
        drop(stream);
    });

    let (_, connector) = remote_client_test_mtls_pair();
    let origin = NodeId::new("origin-native-runtime-pending");
    let destination = NodeId::new("destination-native-runtime-pending");
    let mut schemas = ComputationSchemaRegistry::new();
    schemas
        .register_typed::<Vec<u8>, Vec<u8>>("proof.pending-admission")
        .expect("pending-admission computation schema should register");
    let hello = RemotePeerHello::new(
        origin.clone(),
        RemoteProtocolVersion::V3,
        schemas.fingerprint(),
    );

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("pending-admission driver runtime should build");
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(30)),
    )
    .expect("pending-admission client should build");
    let native = Arc::new(
        NativeRemoteRuntime::with_config(
            runtime.handle(),
            origin.clone(),
            [NativeRemoteRoute::new(destination.clone(), hello, client)],
            NativeRemoteRuntimeConfig::new().with_drain_timeout(Duration::from_millis(250)),
        )
        .expect("pending-admission native runtime should validate its route"),
    );
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(origin)
        .with_runtime(native.clone());
    let cx = runtime
        .request_cx_with_budget(Budget::INFINITE)
        .with_remote_cap(cap);
    let mut handle = spawn_remote(
        &cx,
        destination,
        ComputationName::new("proof.pending-admission"),
        RemoteInput::new(b"pending-admission".to_vec()),
    )
    .expect("pending-admission driver should publish");
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("pending-admission client should connect before TLS stalls");
    assert_eq!(handle.state(), RemoteTaskState::Pending);
    assert_eq!(native.active_operations(), 1);

    assert!(
        runtime.block_on(native.close(&cx)),
        "drain should wake pending TLS admission without reaching force-close"
    );
    assert_eq!(native.active_operations(), 0);
    let terminal = runtime
        .block_on(handle.join(&cx))
        .expect_err("pending TLS admission should terminate as cancelled");
    assert!(
        matches!(terminal, RemoteError::Cancelled(_)),
        "pending-admission cancellation classified as {terminal:?}"
    );

    release_tx
        .send(())
        .expect("pending-admission fixture should release its accepted socket");
    server
        .join()
        .expect("pending-admission fixture should not panic");
    drop(cx);
    drop(native);
    // The joined handle remains in scope and must no longer retain the runtime.
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[cfg(feature = "tls")]
#[test]
fn native_remote_runtime_cancel_preempts_stalled_renewal() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("stalled-renewal fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("stalled-renewal fixture should expose its address");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (renewal_tx, renewal_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("stalled-renewal fixture should accept one connection");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("stalled-renewal fixture should authenticate the client");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("stalled-renewal fixture should receive the spawn request");
            let request: RemoteServiceWireRequest = serde_json::from_slice(&encoded)
                .expect("stalled-renewal spawn request should decode");
            let accepted = RemoteServiceSessionEvent::Accepted {
                remote_task_id: request.remote_task_id().raw(),
            };
            let encoded = serde_json::to_vec(&accepted)
                .expect("stalled-renewal accepted event should encode");
            write_raw_frame(&mut stream, &encoded)
                .await
                .expect("stalled-renewal accepted event should flush");
            accepted_tx
                .send(())
                .expect("stalled-renewal fixture should publish acceptance");

            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("stalled-renewal fixture should receive the renewal command");
            let command: asupersync::remote::RemoteServiceSessionCommand =
                serde_json::from_slice(&encoded).expect("stalled-renewal command should decode");
            assert!(matches!(
                command,
                asupersync::remote::RemoteServiceSessionCommand::RenewLease { .. }
            ));
            renewal_tx
                .send(())
                .expect("stalled-renewal fixture should publish command receipt");

            assert!(
                read_raw_frame(&mut stream).await.is_err(),
                "cancellation should drop the transport without waiting for a renewal reply"
            );
            closed_tx
                .send(())
                .expect("stalled-renewal fixture should publish transport close");
        });
    });

    let origin = NodeId::new("origin-native-runtime-renewal");
    let destination = NodeId::new("destination-native-runtime-renewal");
    let mut schemas = ComputationSchemaRegistry::new();
    schemas
        .register_typed::<Vec<u8>, Vec<u8>>("proof.stalled-renewal")
        .expect("stalled-renewal computation schema should register");
    let hello = RemotePeerHello::new(
        origin.clone(),
        RemoteProtocolVersion::V3,
        schemas.fingerprint(),
    );
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("stalled-renewal driver runtime should build");
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(2)),
    )
    .expect("stalled-renewal client should build");
    let native = Arc::new(
        NativeRemoteRuntime::new(
            runtime.handle(),
            origin.clone(),
            [NativeRemoteRoute::new(destination.clone(), hello, client)],
        )
        .expect("stalled-renewal native runtime should validate its route"),
    );
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(origin.clone())
        .with_runtime(native.clone());
    let cx = runtime
        .request_cx_with_budget(Budget::INFINITE)
        .with_remote_cap(cap);
    let mut handle = spawn_remote(
        &cx,
        destination.clone(),
        ComputationName::new("proof.stalled-renewal"),
        RemoteInput::new(b"stalled-renewal".to_vec()),
    )
    .expect("stalled-renewal driver should publish");
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("stalled-renewal session should be accepted");
    let running_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while handle.state() != RemoteTaskState::Running {
        assert!(
            std::time::Instant::now() < running_deadline,
            "stalled-renewal handle should observe the accepted event"
        );
        std::thread::yield_now();
    }
    native
        .send_message(
            &destination,
            MessageEnvelope::new(
                origin.clone(),
                cx.logical_tick(),
                RemoteMessage::LeaseRenewal(LeaseRenewal {
                    remote_task_id: handle.remote_task_id(),
                    new_lease: Duration::from_secs(30),
                    current_state: RemoteTaskState::Running,
                    node: origin,
                }),
            ),
        )
        .expect("stalled-renewal command should publish");
    renewal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("stalled-renewal fixture should receive the renewal command");

    handle.abort(&cx);
    let terminal = runtime
        .block_on(async {
            asupersync::time::timeout(cx.now(), Duration::from_secs(1), handle.join(&cx))
                .await
                .expect("cancel should preempt a stalled renewal within the proof bound")
        })
        .expect_err("stalled renewal should terminate as cancelled");
    assert!(
        matches!(terminal, RemoteError::Cancelled(_)),
        "stalled-renewal cancellation classified as {terminal:?}"
    );
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("stalled-renewal cancellation should close the transport");
    server
        .join()
        .expect("stalled-renewal fixture should not panic");
    assert_eq!(native.active_operations(), 0);
    assert!(runtime.block_on(native.close(&cx)));
    drop(cx);
    drop(native);
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[cfg(feature = "tls")]
fn remote_client_test_mtls_pair() -> (TlsAcceptor, TlsConnector) {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("mTLS connector should build");
    (acceptor, connector)
}

#[cfg(all(feature = "remote-service", unix))]
fn write_configured_remote_service_file(
    path: &Path,
    listen: SocketAddr,
    certificate_path: &Path,
    private_key_path: &Path,
    ca_path: &Path,
    peer_node: &str,
    spki_pin: &str,
    computations: &[&str],
) {
    let computations = computations
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        path,
        format!(
            "schema_version = 2\nprotocol = \"3.0\"\nlisten = \"{listen}\"\nlisten_scope = \"loopback_only\"\nserver_certificate_chain = \"{}\"\nserver_private_key = \"{}\"\nclient_ca_bundle = \"{}\"\nmax_frame_bytes = 65536\nmax_connections = 8\ntls_handshake_timeout_ms = 1000\ninitial_frame_timeout_ms = 2000\ndrain_timeout_ms = 2000\nidempotency_retention_ms = 30000\nmax_idempotency_records_per_peer = 32\n\n[[peers]]\nnode_id = \"{peer_node}\"\nspki_sha256 = [\"{spki_pin}\"]\ncomputations = [{computations}]\n",
            certificate_path.display(),
            private_key_path.display(),
            ca_path.display(),
        ),
    )
    .expect("configured remote service file should be written");
}

#[cfg(all(feature = "remote-service", unix))]
#[test]
fn configured_remote_service_hosts_application_registry_over_mtls_and_drains() {
    const PEER_NODE: &str = "configured-application-peer";
    const ALPHA: &str = "app.alpha_prefix";
    const DENIED: &str = "app.middle_denied";
    const ZETA: &str = "app.zeta_reverse";

    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate");
    let spki_pin = CertificatePin::compute_spki_sha256(peer_certificate)
        .expect("TLS fixture should produce an SPKI pin")
        .to_base64();
    let temp = tempfile::tempdir().expect("configured service fixture directory should exist");
    let certificate_path = temp.path().join("service.crt");
    let private_key_path = temp.path().join("service.key");
    let ca_path = temp.path().join("client-ca.crt");
    fs::write(&certificate_path, TEST_CERT_PEM).expect("service certificate should be written");
    fs::write(&private_key_path, TEST_KEY_PEM).expect("service key should be written");
    fs::write(&ca_path, TEST_CERT_PEM).expect("client CA should be written");

    let alpha_dispatches = Arc::new(AtomicUsize::new(0));
    let denied_dispatches = Arc::new(AtomicUsize::new(0));
    let zeta_dispatches = Arc::new(AtomicUsize::new(0));
    let mut computations = RemoteComputationRegistry::new();
    let zeta_handler_dispatches = Arc::clone(&zeta_dispatches);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>(ZETA, move |_cx, invocation| {
            let zeta_handler_dispatches = Arc::clone(&zeta_handler_dispatches);
            async move {
                zeta_handler_dispatches.fetch_add(1, Ordering::SeqCst);
                let mut output = invocation.into_request().input.into_data();
                output.reverse();
                Ok(RemoteOutcome::Success(output))
            }
        })
        .expect("zeta application handler should register");
    let alpha_handler_dispatches = Arc::clone(&alpha_dispatches);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>(ALPHA, move |_cx, invocation| {
            let alpha_handler_dispatches = Arc::clone(&alpha_handler_dispatches);
            async move {
                alpha_handler_dispatches.fetch_add(1, Ordering::SeqCst);
                let input = invocation.into_request().input.into_data();
                let mut output = b"alpha:".to_vec();
                output.extend_from_slice(&input);
                Ok(RemoteOutcome::Success(output))
            }
        })
        .expect("alpha application handler should register");
    let denied_handler_dispatches = Arc::clone(&denied_dispatches);
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>(DENIED, move |_cx, invocation| {
            denied_handler_dispatches.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("denied application handler should register");
    let registry_fingerprint = computations.schema_registry().fingerprint();

    let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("missing-handler proof should occupy a loopback address");
    let occupied_address = occupied_listener
        .local_addr()
        .expect("occupied listener should expose its address");
    let missing_config_path = temp.path().join("remote-service-missing-handler.toml");
    write_configured_remote_service_file(
        &missing_config_path,
        occupied_address,
        &certificate_path,
        &private_key_path,
        &ca_path,
        PEER_NODE,
        &spki_pin,
        &[ALPHA, "app.absent", ZETA],
    );
    let missing = RemoteComputationServiceBootstrap::from_toml_file(
        &missing_config_path,
        computations.clone(),
    )
    .expect_err("configured missing handler must fail before listener bind");
    match missing {
        RemoteComputationServiceBootstrapError::UnknownComputation {
            peer, computation, ..
        } => {
            assert_eq!(peer, NodeId::new(PEER_NODE));
            assert_eq!(computation, "app.absent");
        }
        other => panic!("unexpected missing-handler refusal: {other}"),
    }
    assert_eq!(
        occupied_listener
            .local_addr()
            .expect("validation must not disturb the occupied listener"),
        occupied_address
    );
    drop(occupied_listener);

    let config_path = temp.path().join("remote-service-application.toml");
    write_configured_remote_service_file(
        &config_path,
        "127.0.0.1:0"
            .parse()
            .expect("loopback service address should parse"),
        &certificate_path,
        &private_key_path,
        &ca_path,
        PEER_NODE,
        &spki_pin,
        &[ALPHA, ZETA],
    );
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let service_thread = thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("configured application service runtime should build");
        let bootstrap =
            RemoteComputationServiceBootstrap::from_toml_file(config_path, computations)
                .expect("configured application bootstrap should validate");
        let (service, identity) = runtime
            .block_on(bootstrap.bind())
            .expect("configured application service should bind");
        let endpoint = service
            .local_addr()
            .expect("configured application service should expose its bound address");
        let operator = service.handle();
        ready_tx
            .send((endpoint, identity, operator.clone()))
            .expect("configured application service should publish readiness");
        let report = runtime
            .block_on(async move {
                let cx = Cx::current()
                    .expect("configured service runtime should install a root context");
                service.run(&cx).await
            })
            .expect("configured application service should drain cleanly");
        assert!(
            runtime.shutdown_timeout(Duration::from_secs(2)),
            "configured application service runtime should reach quiescence"
        );
        report
    });
    let (endpoint, identity, operator) = ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("configured application service should become ready");
    assert_eq!(identity.registry_fingerprint(), registry_fingerprint);
    assert_eq!(
        identity.computations(),
        &[ALPHA.to_owned(), DENIED.to_owned(), ZETA.to_owned()]
    );
    assert_eq!(identity.authorized_peers(), 1);
    assert_eq!(identity.config_schema_version(), 2);
    assert_eq!(identity.protocol_version(), RemoteProtocolVersion::V3);
    assert_eq!(identity.listen_scope().as_str(), "loopback_only");

    let (_, connector) = remote_client_test_mtls_pair();
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(3)),
    )
    .expect("configured application client should validate");
    let hello = RemotePeerHello::new(
        NodeId::new(PEER_NODE),
        RemoteProtocolVersion::V3,
        registry_fingerprint,
    );
    let client_runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("configured application client runtime should build");
    let alpha = run_remote_service_cli_session(
        &client_runtime,
        &client,
        &remote_service_wire_request_with(hello.clone(), ALPHA, 8_901, 0x8_901, b"payload"),
    )
    .expect("alpha application handler should complete");
    assert!(matches!(
        alpha,
        RemoteServiceWireResponse::Outcome {
            remote_task_id: 8_901,
            outcome: RemoteServiceWireOutcome::Success(ref payload),
        } if payload == b"alpha:payload"
    ));
    let zeta = run_remote_service_cli_session(
        &client_runtime,
        &client,
        &remote_service_wire_request_with(hello.clone(), ZETA, 8_902, 0x8_902, b"stressed"),
    )
    .expect("zeta application handler should complete");
    assert!(matches!(
        zeta,
        RemoteServiceWireResponse::Outcome {
            remote_task_id: 8_902,
            outcome: RemoteServiceWireOutcome::Success(ref payload),
        } if payload == b"desserts"
    ));
    let denied = run_remote_service_cli_session(
        &client_runtime,
        &client,
        &remote_service_wire_request_with(hello, DENIED, 8_903, 0x8_903, b"must-not-run"),
    )
    .expect("ungranted application handler should receive a typed refusal");
    assert!(matches!(
        denied,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 8_903,
            code: RemoteServiceRejectionCode::ComputationDenied,
            ref diagnostic,
        } if diagnostic.contains("not capability-authorized")
    ));
    assert_eq!(alpha_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(zeta_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(denied_dispatches.load(Ordering::SeqCst), 0);

    let connection_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while operator.active_connections() != 0 {
        assert!(
            std::time::Instant::now() < connection_deadline,
            "terminal client receipts should be followed by connection-task cleanup"
        );
        thread::yield_now();
    }
    assert!(operator.begin_drain());
    let report = service_thread
        .join()
        .expect("configured application service thread should not panic");
    assert_eq!(report.accepted_connections(), 3);
    assert_eq!(report.completed_connections(), 3);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.interrupted_connections(), 0);
    assert_eq!(report.panicked_connections(), 0);
    assert_eq!(report.shutdown().drained, 0);
    assert_eq!(report.shutdown().force_closed, 0);
    assert_eq!(operator.active_connections(), 0);
    assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);
    assert_eq!(
        denied_dispatches.load(Ordering::SeqCst),
        0,
        "ungranted handler must remain undispatched through runtime quiescence"
    );
}

#[cfg(all(feature = "remote-service", unix))]
#[test]
fn configured_remote_service_config_fails_closed_before_bind() {
    const PEER_NODE: &str = "configured-validation-peer";
    const COMPUTATION: &str = "app.validation";

    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate");
    let spki_pin = CertificatePin::compute_spki_sha256(peer_certificate)
        .expect("TLS fixture should produce an SPKI pin")
        .to_base64();
    let temp = tempfile::tempdir().expect("configured validation directory should exist");
    let certificate_path = temp.path().join("service.crt");
    let private_key_path = temp.path().join("service.key");
    let ca_path = temp.path().join("client-ca.crt");
    fs::write(&certificate_path, TEST_CERT_PEM).expect("service certificate should be written");
    fs::write(&private_key_path, TEST_KEY_PEM).expect("service key should be written");
    fs::write(&ca_path, TEST_CERT_PEM).expect("client CA should be written");
    let baseline_path = temp.path().join("baseline.toml");
    write_configured_remote_service_file(
        &baseline_path,
        "127.0.0.1:0"
            .parse()
            .expect("validation address should parse"),
        &certificate_path,
        &private_key_path,
        &ca_path,
        PEER_NODE,
        &spki_pin,
        &[COMPUTATION],
    );
    let baseline = fs::read_to_string(&baseline_path)
        .expect("configured validation baseline should be readable");
    let mut computations = RemoteComputationRegistry::new();
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>(COMPUTATION, |_cx, invocation| async move {
            Ok(RemoteOutcome::Success(
                invocation.into_request().input.into_data(),
            ))
        })
        .expect("validation computation should register");

    let cases = [
        (
            "legacy-schema.toml",
            baseline.replace("schema_version = 2", "schema_version = 1"),
            "unsupported schema_version 1; expected 2",
        ),
        (
            "unsupported-protocol.toml",
            baseline.replace("protocol = \"3.0\"", "protocol = \"2.0\""),
            "unsupported protocol '2.0'; expected '3.0'",
        ),
        (
            "hostname-listen.toml",
            baseline.replace("listen = \"127.0.0.1:0\"", "listen = \"localhost:7443\""),
            "listen must be a literal socket address",
        ),
        (
            "empty-listen.toml",
            baseline.replace("listen = \"127.0.0.1:0\"", "listen = \"\""),
            "listen must not be empty",
        ),
        (
            "loopback-wildcard.toml",
            baseline.replace("listen = \"127.0.0.1:0\"", "listen = \"0.0.0.0:7443\""),
            "loopback_only refuses non-loopback",
        ),
        (
            "network-loopback.toml",
            baseline.replace(
                "listen_scope = \"loopback_only\"",
                "listen_scope = \"network\"",
            ),
            "network refuses loopback",
        ),
        (
            "zero-capacity.toml",
            baseline.replace("max_connections = 8", "max_connections = 0"),
            "max_connections must be nonzero",
        ),
        (
            "missing-scope.toml",
            baseline.replace("listen_scope = \"loopback_only\"\n", ""),
            "missing field `listen_scope`",
        ),
        (
            "unknown-scope.toml",
            baseline.replace(
                "listen_scope = \"loopback_only\"",
                "listen_scope = \"automatic\"",
            ),
            "unknown variant `automatic`",
        ),
        (
            "unknown-field.toml",
            baseline.replace(
                "max_connections = 8",
                "max_connections = 8\nambient_authority = true",
            ),
            "unknown field `ambient_authority`",
        ),
        (
            "duplicate-computation.toml",
            baseline.replace(
                "computations = [\"app.validation\"]",
                "computations = [\"app.validation\", \"app.validation\"]",
            ),
            "repeats computation 'app.validation'",
        ),
        (
            "duplicate-peer.toml",
            format!(
                "{baseline}\n[[peers]]\nnode_id = \"{PEER_NODE}\"\nspki_sha256 = [\"{spki_pin}\"]\ncomputations = [\"{COMPUTATION}\"]\n"
            ),
            "duplicate peer node_id 'configured-validation-peer'",
        ),
        (
            "invalid-spki.toml",
            baseline.replace(&spki_pin, "not-base64"),
            "invalid SPKI pin",
        ),
    ];
    for (name, raw, expected) in cases {
        let path = temp.path().join(name);
        fs::write(&path, raw).expect("invalid configured-service fixture should be written");
        let error = RemoteComputationServiceBootstrap::from_toml_file(&path, computations.clone())
            .expect_err("invalid configured service must fail before bind");
        assert!(
            error.to_string().contains(expected),
            "{name} diagnostic was: {error}"
        );
    }

    let duplicate_pin_path = temp.path().join("duplicate-pin-compatible.toml");
    let duplicate_pin = baseline.replace(
        &format!("spki_sha256 = [\"{spki_pin}\"]"),
        &format!("spki_sha256 = [\"{spki_pin}\", \"{spki_pin}\"]"),
    );
    fs::write(&duplicate_pin_path, duplicate_pin)
        .expect("duplicate-pin compatibility fixture should be written");
    RemoteComputationServiceBootstrap::from_toml_file(&duplicate_pin_path, computations.clone())
        .expect("schema v2 duplicate pins must retain prior deduplicating behavior");

    let network_path = temp.path().join("explicit-network.toml");
    let network = baseline
        .replace("listen = \"127.0.0.1:0\"", "listen = \"0.0.0.0:0\"")
        .replace(
            "listen_scope = \"loopback_only\"",
            "listen_scope = \"network\"",
        );
    fs::write(&network_path, network).expect("explicit network fixture should be written");
    let network = RemoteComputationServiceBootstrap::from_toml_file(&network_path, computations)
        .expect("explicit network scope with a wildcard address should prepare");
    assert_eq!(network.identity().listen_scope().as_str(), "network");
    assert_eq!(
        network.configured_listen(),
        "0.0.0.0:0"
            .parse()
            .expect("network validation address should parse")
    );
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_listener_rejects_zero_initial_frame_timeout() {
    let (acceptor, _) = remote_client_test_mtls_pair();
    let computations = RemoteComputationRegistry::new();
    let policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("remote listener validation runtime should build");
    let result = runtime.block_on(RemoteComputationService::bind(
        "127.0.0.1:0",
        acceptor,
        policy,
        computations,
        RemoteComputationServiceConfig::new().with_initial_frame_timeout(Duration::ZERO),
    ));

    assert!(matches!(
        result,
        Err(RemoteComputationListenerError::InvalidInitialFrameTimeout)
    ));
}

#[cfg(feature = "tls")]
fn remote_client_test_request(
    protocol: RemoteProtocolVersion,
    task_id: u64,
    idempotency_key: u128,
) -> RemoteServiceWireRequest {
    let mut schemas = ComputationSchemaRegistry::new();
    schemas
        .register_typed::<Vec<u8>, Vec<u8>>("proof.echo")
        .expect("client test computation schema should register");
    let policy = RemotePeerAdmissionPolicy::new(protocol, schemas);
    remote_service_wire_request_with(
        policy.hello_for(NodeId::new("native-client-peer")),
        "proof.echo",
        task_id,
        idempotency_key,
        b"native-client-payload",
    )
}

#[cfg(feature = "tls")]
fn run_remote_client_call(
    client: &RemoteComputationClient,
    request: &RemoteServiceWireRequest,
) -> Result<RemoteServiceWireResponse, RemoteComputationClientError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("native remote client runtime should build");
    runtime.block_on(async {
        let cx = Cx::current().expect("runtime block_on should install an ambient context");
        client.call(&cx, request).await
    })
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_validates_policy_and_observes_preflight_cancellation() {
    let (_, connector) = remote_client_test_mtls_pair();
    let endpoint: SocketAddr = "127.0.0.1:9"
        .parse()
        .expect("discard endpoint should parse");

    for invalid in [
        RemoteComputationClientConfig::new().with_wire_limits(RemoteServiceWireLimits::new(0)),
        RemoteComputationClientConfig::new().with_connect_timeout(Duration::ZERO),
        RemoteComputationClientConfig::new().with_attempt_timeout(Duration::ZERO),
        RemoteComputationClientConfig::new().with_max_attempts(0),
        RemoteComputationClientConfig::new()
            .with_backoff(Duration::from_millis(2), Duration::from_millis(1)),
    ] {
        assert!(matches!(
            RemoteComputationClient::new(endpoint, "localhost", connector.clone(), invalid),
            Err(RemoteComputationClientError::InvalidConfig(_))
        ));
    }
    assert!(matches!(
        RemoteComputationClient::new(
            endpoint,
            "invalid server name",
            connector.clone(),
            RemoteComputationClientConfig::new(),
        ),
        Err(RemoteComputationClientError::InvalidServerName(_))
    ));
    assert!(matches!(
        RemoteComputationClient::from_bootstrap_endpoints(
            [],
            "localhost",
            connector.clone(),
            RemoteComputationClientConfig::new(),
        ),
        Err(RemoteComputationClientError::InvalidConfig(_))
    ));
    assert!(matches!(
        RemoteComputationClient::from_bootstrap_endpoints(
            [endpoint, endpoint],
            "localhost",
            connector.clone(),
            RemoteComputationClientConfig::new(),
        ),
        Err(RemoteComputationClientError::InvalidConfig(_))
    ));

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new(),
    )
    .expect("valid native client policy should build");
    let request = remote_client_test_request(RemoteProtocolVersion::V2, 7201, 0x7201);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let cancelled = block_on(client.call(&cx, &request))
        .expect_err("cancelled context must refuse before a connection attempt");
    assert!(matches!(
        cancelled,
        RemoteComputationClientError::Cancelled { attempts: 0 }
    ));

    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("closed-port fixture should reserve a unique loopback endpoint");
    let closed_endpoint = closed_listener
        .local_addr()
        .expect("closed-port fixture should expose its address");
    drop(closed_listener);
    let second_closed_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("second closed-port fixture should reserve a loopback endpoint");
    let second_closed_endpoint = second_closed_listener
        .local_addr()
        .expect("second closed-port fixture should expose its address");
    drop(second_closed_listener);
    let retry_client = RemoteComputationClient::from_bootstrap_endpoints(
        [closed_endpoint, second_closed_endpoint],
        "localhost",
        remote_client_test_mtls_pair().1,
        RemoteComputationClientConfig::new()
            .with_max_attempts(3)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("closed-port retry client should build");
    assert_eq!(retry_client.endpoint(), closed_endpoint);
    assert_eq!(
        retry_client.bootstrap_endpoints(),
        &[closed_endpoint, second_closed_endpoint]
    );
    let connect_error = run_remote_client_call(&retry_client, &request)
        .expect_err("closed loopback endpoint should exhaust finite pre-delivery retries");
    assert!(matches!(
        connect_error,
        RemoteComputationClientError::Connect { attempts: 3, .. }
    ));

    ProofLogRow::pass(
        "remote_native_client_preflight",
        0,
        "caller_cancelled_then_closed_port",
        "policy_validation_and_finite_pre_delivery_retry",
        3,
        "cancelled_zero_then_connect_three",
        "cancelled_zero_then_connect_three",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_fails_over_static_bootstrap_before_delivery() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let mut computations = RemoteComputationRegistry::new();
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.bootstrap", move |_cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                let mut output = b"bootstrap:".to_vec();
                output.extend_from_slice(&invocation.into_request().input.into_data());
                Ok(RemoteOutcome::Success(output))
            }
        })
        .expect("bootstrap handler should register");

    let origin = NodeId::new("origin-static-bootstrap-call");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.bootstrap"])
        .expect("bootstrap certificate-bound grant should be valid");
    let request = remote_service_wire_request_with(
        policy.hello_for(origin),
        "proof.bootstrap",
        7210,
        0x7210,
        b"payload",
    );
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener =
        block_on(TcpListener::bind("127.0.0.1:0")).expect("bootstrap service should bind loopback");
    let live_endpoint = listener
        .local_addr()
        .expect("bootstrap service should expose its address");
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("bootstrap service should accept one connection");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("bootstrap service should authenticate the client");
            serve_tls_computation_once(
                &Cx::for_testing(),
                &mut stream,
                &policy,
                &computations,
                RemoteServiceWireLimits::default(),
            )
            .await
            .expect("bootstrap service should flush one response")
        })
    });

    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bootstrap test should reserve a closed primary endpoint");
    let closed_endpoint = closed_listener
        .local_addr()
        .expect("closed primary endpoint should expose its address");
    drop(closed_listener);
    let client = RemoteComputationClient::from_bootstrap_endpoints(
        [closed_endpoint, live_endpoint],
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(2)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("ordered bootstrap client should validate");
    let response = run_remote_client_call(&client, &request)
        .expect("second bootstrap endpoint should complete the request");
    assert!(
        matches!(
            response,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7210,
                outcome: RemoteServiceWireOutcome::Success(ref payload),
            } if payload == b"bootstrap:payload"
        ),
        "unexpected bootstrap response: {response:?}"
    );
    let server_response = server.join().expect("bootstrap service should not panic");
    assert!(
        matches!(
            server_response,
            RemoteServiceWireResponse::Outcome {
                remote_task_id: 7210,
                outcome: RemoteServiceWireOutcome::Success(ref payload),
            } if payload == b"bootstrap:payload"
        ),
        "unexpected server-side bootstrap response: {server_response:?}"
    );
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

    ProofLogRow::pass(
        "remote_native_client_static_bootstrap",
        7210,
        "primary_refused_then_secondary_authenticated",
        "pre_delivery_endpoint_failover",
        2,
        "one_handler_dispatch",
        "one_handler_dispatch",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn native_remote_runtime_uses_static_bootstrap_failover_for_v3() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let mut computations = RemoteComputationRegistry::new();
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.bootstrap-v3", move |_cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("V3 bootstrap handler should register");

    let origin = NodeId::new("origin-static-bootstrap-v3");
    let destination = NodeId::new("destination-static-bootstrap-v3");
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.bootstrap-v3"])
        .expect("V3 bootstrap certificate-bound grant should be valid");
    let hello = policy.hello_for(origin.clone());
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let (live_endpoint, operator, service) =
        spawn_native_route_service("bootstrap-v3", acceptor, policy, computations);

    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("V3 bootstrap test should reserve a closed primary endpoint");
    let closed_endpoint = closed_listener
        .local_addr()
        .expect("V3 closed primary endpoint should expose its address");
    drop(closed_listener);
    let client = RemoteComputationClient::from_bootstrap_endpoints(
        [closed_endpoint, live_endpoint],
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(2)
            .with_attempt_timeout(Duration::from_secs(2))
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("V3 ordered bootstrap client should validate");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("V3 bootstrap driver runtime should build");
    let native = Arc::new(
        NativeRemoteRuntime::new(
            runtime.handle(),
            origin.clone(),
            [NativeRemoteRoute::new(destination.clone(), hello, client)],
        )
        .expect("V3 bootstrap route should validate"),
    );
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(origin)
        .with_default_lease(Duration::from_secs(5))
        .with_runtime(native.clone());
    let cx = runtime
        .request_cx_with_budget(Budget::INFINITE)
        .with_remote_cap(cap);
    let mut task = spawn_remote(
        &cx,
        destination,
        ComputationName::new("proof.bootstrap-v3"),
        RemoteInput::new(b"native-bootstrap-v3".to_vec()),
    )
    .expect("V3 bootstrap task should publish");
    let outcome = runtime
        .block_on(task.join(&cx))
        .expect("V3 bootstrap task should reach a terminal outcome");
    assert!(matches!(
        outcome,
        RemoteOutcome::Success(ref payload) if payload == b"native-bootstrap-v3"
    ));
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(native.active_operations(), 0);
    assert!(runtime.block_on(native.close(&cx)));
    drop(cx);
    drop(native);
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));

    assert!(operator.begin_drain());
    let report = service
        .join()
        .expect("V3 bootstrap service should not panic");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(operator.active_connections(), 0);

    ProofLogRow::pass(
        "native_remote_runtime_static_bootstrap",
        task.remote_task_id().raw(),
        "primary_refused_then_secondary_v3_authenticated",
        "native_runtime_pre_delivery_endpoint_failover",
        2,
        "one_handler_dispatch_and_quiescent_close",
        "one_handler_dispatch_and_quiescent_close",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_pin_mismatch_does_not_fall_through() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");
    let (acceptor, _) = remote_client_test_mtls_pair();
    let primary = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("pin-mismatch primary should bind loopback");
    let primary_endpoint = primary
        .local_addr()
        .expect("pin-mismatch primary should expose its address");
    let primary_server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = primary
                .accept()
                .await
                .expect("pin-mismatch primary should accept one connection");
            let _ = acceptor.accept(stream).await;
        });
    });

    let secondary = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("pin-mismatch secondary probe should bind loopback");
    let secondary_endpoint = secondary
        .local_addr()
        .expect("pin-mismatch secondary should expose its address");
    secondary
        .set_nonblocking(true)
        .expect("pin-mismatch secondary probe should be nonblocking");
    let wrong_pin = CertificatePin::spki_sha256(vec![0xA5; 32])
        .expect("fixed-size wrong SPKI pin should validate structurally");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .with_certificate_pins(CertificatePinSet::new().with_pin(wrong_pin))
        .build()
        .expect("pin-mismatch connector should build");
    let seed_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("pin-mismatch rebind should reserve a seed endpoint");
    let seed_endpoint = seed_listener
        .local_addr()
        .expect("pin-mismatch seed endpoint should expose its address");
    drop(seed_listener);
    let seed_client = RemoteComputationClient::new(
        seed_endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(2)
            .with_attempt_timeout(Duration::from_secs(2))
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("pin-mismatch seed client should validate");
    let discovery = StaticList::new(vec![primary_endpoint, secondary_endpoint]);
    assert_eq!(
        discovery
            .poll_discover()
            .expect("static pin-mismatch discovery poll should succeed")
            .len(),
        2
    );
    let client = seed_client
        .with_discovered_endpoints(&discovery)
        .expect("pin-mismatch discovered bootstrap set should validate");
    assert_eq!(
        client.bootstrap_endpoints(),
        &[primary_endpoint, secondary_endpoint]
    );
    let request = remote_client_test_request(RemoteProtocolVersion::V1, 7211, 0x7211);
    let error = run_remote_client_call(&client, &request)
        .expect_err("enforced pin mismatch must fail closed before request delivery");
    assert!(matches!(
        error,
        RemoteComputationClientError::Tls {
            attempts: 1,
            source: asupersync::tls::TlsError::PinMismatch { .. },
        }
    ));
    primary_server
        .join()
        .expect("pin-mismatch primary should not panic");
    assert!(matches!(
        secondary.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));

    ProofLogRow::pass(
        "remote_native_client_pin_mismatch",
        7211,
        "authenticated_primary_wrong_pin",
        "fail_closed_without_secondary_dial",
        1,
        "typed_tls_error_secondary_unused",
        "typed_tls_error_secondary_unused",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_cancellation_prevents_later_bootstrap_dial() {
    let primary = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("cancellation primary should bind loopback");
    let primary_endpoint = primary
        .local_addr()
        .expect("cancellation primary should expose its address");
    let secondary = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("cancellation secondary probe should bind loopback");
    let secondary_endpoint = secondary
        .local_addr()
        .expect("cancellation secondary should expose its address");
    secondary
        .set_nonblocking(true)
        .expect("cancellation secondary probe should be nonblocking");
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let primary_server = thread::spawn(move || {
        let (_stream, _) = primary
            .accept()
            .expect("cancellation primary should accept one TCP connection");
        accepted_tx
            .send(())
            .expect("cancellation primary should publish connection acceptance");
        release_rx
            .recv()
            .expect("cancellation primary should receive fixture release");
    });

    let client = RemoteComputationClient::from_bootstrap_endpoints(
        [primary_endpoint, secondary_endpoint],
        "localhost",
        remote_client_test_mtls_pair().1,
        RemoteComputationClientConfig::new()
            .with_max_attempts(2)
            .with_attempt_timeout(Duration::from_secs(5))
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("cancellation bootstrap client should validate");
    let request = remote_client_test_request(RemoteProtocolVersion::V1, 7212, 0x7212);
    let cx = Cx::for_testing();
    let client_cx = cx.clone();
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let client_thread = thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("cancellation bootstrap runtime should build");
        result_tx
            .send(runtime.block_on(client.call(&client_cx, &request)))
            .expect("cancellation bootstrap client should publish its result");
    });
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cancellation primary should observe the first dial");
    cx.set_cancel_requested(true);
    let error = result_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("cancellation should wake the first TLS attempt")
        .expect_err("cancelled first attempt must not dial the secondary");
    assert!(matches!(
        error,
        RemoteComputationClientError::CancelledDuringAttempt { attempts: 1 }
    ));
    assert!(matches!(
        secondary.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    release_tx
        .send(())
        .expect("cancellation primary should receive fixture release");
    primary_server
        .join()
        .expect("cancellation primary should not panic");
    client_thread
        .join()
        .expect("cancellation bootstrap client should not panic");

    ProofLogRow::pass(
        "remote_native_client_bootstrap_cancellation",
        7212,
        "cancel_during_primary_tls_handshake",
        "no_later_endpoint_dial",
        1,
        "typed_cancel_secondary_unused",
        "typed_cancel_secondary_unused",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_v1_does_not_replay_ambiguous_delivery() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("V1 ambiguity fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("V1 ambiguity fixture should expose its address");
    let request = remote_client_test_request(RemoteProtocolVersion::V1, 7202, 0x7202);
    let expected_request = request.clone();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let server_connections = Arc::clone(&accepted_connections);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("V1 ambiguity fixture should accept one connection");
            server_connections.fetch_add(1, Ordering::SeqCst);
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("V1 ambiguity fixture should authenticate the client");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("V1 ambiguity fixture should receive a complete request");
            let received: RemoteServiceWireRequest =
                serde_json::from_slice(&encoded).expect("V1 ambiguity request should decode");
            assert_eq!(received, expected_request);
        });
    });

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(3)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("V1 ambiguity client should build");
    let error = run_remote_client_call(&client, &request)
        .expect_err("V1 must surface post-delivery transport loss without replay");
    assert!(matches!(
        error,
        RemoteComputationClientError::AmbiguousExchange { attempts: 1, .. }
    ));
    server
        .join()
        .expect("V1 ambiguity fixture should not panic");
    assert_eq!(
        accepted_connections.load(Ordering::SeqCst),
        1,
        "V1 ambiguous delivery must never be replayed"
    );

    ProofLogRow::pass(
        "remote_native_client_v1_ambiguity",
        0,
        "complete_request_then_eof",
        "v1_no_ambiguous_replay",
        1,
        "typed_ambiguous_exchange",
        "typed_ambiguous_exchange",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_cancellation_wakes_stalled_exchange() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("cancellation fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("cancellation fixture should expose its address");
    let request = remote_client_test_request(RemoteProtocolVersion::V2, 7205, 0x7205);
    let (request_seen_tx, request_seen_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("cancellation fixture should accept one connection");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("cancellation fixture should authenticate the client");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("cancellation fixture should receive a complete request");
            let _: RemoteServiceWireRequest = serde_json::from_slice(&encoded)
                .expect("cancellation fixture request should decode");
            request_seen_tx
                .send(())
                .expect("cancellation fixture should publish request delivery");
            release_rx
                .recv()
                .expect("cancellation fixture should receive cleanup release");
        });
    });

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_attempt_timeout(Duration::from_secs(10))
            .with_max_attempts(3),
    )
    .expect("cancellation client should build");
    let cx = Cx::for_testing();
    let client_cx = cx.clone();
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let client_thread = thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("cancellation client runtime should build");
        let result = runtime.block_on(client.call(&client_cx, &request));
        result_tx
            .send(result)
            .expect("cancellation client should publish its result");
    });
    request_seen_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cancellation fixture should observe request delivery");
    cx.set_cancel_requested(true);
    let result_delivery = result_rx.recv_timeout(Duration::from_secs(1));
    release_tx
        .send(())
        .expect("cancellation fixture should release the server stream");
    server
        .join()
        .expect("cancellation fixture should not panic");
    client_thread
        .join()
        .expect("cancellation client should not panic");
    let error = result_delivery
        .expect("cancellation should wake the stalled exchange before server release")
        .expect_err("stalled exchange should terminate through caller cancellation");
    assert!(matches!(
        error,
        RemoteComputationClientError::CancelledDuringAttempt { attempts: 1 }
    ));

    ProofLogRow::pass(
        "remote_native_client_inflight_cancellation",
        7205,
        "complete_request_then_stall",
        "caller_cancel_wakes_exchange",
        1,
        "typed_ambiguous_cancel_one_attempt",
        "typed_ambiguous_cancel_one_attempt",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_attempt_timeout_fails_closed_without_replay() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("attempt-timeout fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("attempt-timeout fixture should expose its address");
    let request = remote_client_test_request(RemoteProtocolVersion::V2, 7206, 0x7206);
    let (request_seen_tx, request_seen_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    let server = thread::spawn(move || {
        block_on(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("attempt-timeout fixture should accept one connection");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("attempt-timeout fixture should authenticate the client");
            let encoded = read_raw_frame(&mut stream)
                .await
                .expect("attempt-timeout fixture should receive a complete request");
            let _: RemoteServiceWireRequest = serde_json::from_slice(&encoded)
                .expect("attempt-timeout fixture request should decode");
            request_seen_tx
                .send(())
                .expect("attempt-timeout fixture should publish request delivery");
            release_rx
                .recv()
                .expect("attempt-timeout fixture should receive cleanup release");
        });
    });

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_attempt_timeout(Duration::from_millis(100))
            .with_max_attempts(3)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("attempt-timeout client should build");
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let client_thread = thread::spawn(move || {
        result_tx
            .send(run_remote_client_call(&client, &request))
            .expect("attempt-timeout client should publish its result");
    });
    request_seen_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("attempt-timeout fixture should observe request delivery");
    let result_delivery = result_rx.recv_timeout(Duration::from_secs(2));
    release_tx
        .send(())
        .expect("attempt-timeout fixture should release the server stream");
    server
        .join()
        .expect("attempt-timeout fixture should not panic");
    client_thread
        .join()
        .expect("attempt-timeout client should not panic");
    let error = result_delivery
        .expect("attempt timeout should bound a stalled response")
        .expect_err("stalled response must terminate through attempt timeout");
    assert!(matches!(
        error,
        RemoteComputationClientError::AttemptTimeout {
            attempts: 1,
            timeout,
        } if timeout == Duration::from_millis(100)
    ));

    ProofLogRow::pass(
        "remote_native_client_attempt_timeout",
        7206,
        "complete_request_then_stall",
        "bounded_attempt_no_ambiguous_replay",
        1,
        "typed_timeout_one_attempt",
        "typed_timeout_one_attempt",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_native_client_v2_fails_closed_on_in_flight_and_wrong_task_response() {
    let (acceptor, connector) = remote_client_test_mtls_pair();
    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("V2 fail-closed fixture should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("V2 fail-closed fixture should expose its address");
    let in_flight_request = remote_client_test_request(RemoteProtocolVersion::V2, 7203, 0x7203);
    let mismatch_request = remote_client_test_request(RemoteProtocolVersion::V2, 7204, 0x7204);
    let server = thread::spawn(move || {
        block_on(async move {
            let mut requests = Vec::new();
            for attempt in 0..2 {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("V2 fail-closed fixture should accept both calls");
                let mut stream = acceptor
                    .accept(stream)
                    .await
                    .expect("V2 fail-closed fixture should authenticate the client");
                let encoded = read_raw_frame(&mut stream)
                    .await
                    .expect("V2 fail-closed fixture should receive a complete request");
                let received: RemoteServiceWireRequest =
                    serde_json::from_slice(&encoded).expect("V2 fail-closed request should decode");
                let remote_task_id = received.remote_task_id().raw();
                requests.push(received);
                let response = if attempt == 0 {
                    RemoteServiceWireResponse::Rejected {
                        remote_task_id,
                        code: RemoteServiceRejectionCode::OperationInFlight,
                        diagnostic: "planted in-flight fail-closed boundary".to_owned(),
                    }
                } else {
                    RemoteServiceWireResponse::Outcome {
                        remote_task_id: remote_task_id + 99,
                        outcome: RemoteServiceWireOutcome::Success(b"wrong-task".to_vec()),
                    }
                };
                write_json_frame(&mut stream, &response)
                    .await
                    .expect("V2 fail-closed fixture should write a typed response");
                stream
                    .flush()
                    .await
                    .expect("V2 fail-closed fixture should flush its typed response");
            }
            requests
        })
    });

    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(2)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("V2 fail-closed client should build");
    let response = run_remote_client_call(&client, &in_flight_request)
        .expect("typed in-flight refusal should remain a typed response");
    assert!(matches!(
        response,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 7203,
            code: RemoteServiceRejectionCode::OperationInFlight,
            ..
        }
    ));
    let mismatch = run_remote_client_call(&client, &mismatch_request)
        .expect_err("wrong-task response must fail correlation validation");
    assert!(matches!(
        mismatch,
        RemoteComputationClientError::ResponseTaskMismatch {
            attempts: 1,
            expected: 7204,
            actual: 7303,
        }
    ));
    let requests = server
        .join()
        .expect("V2 fail-closed fixture should not panic");
    assert_eq!(requests, vec![in_flight_request, mismatch_request]);

    ProofLogRow::pass(
        "remote_native_client_v2_fail_closed",
        0,
        "typed_in_flight_then_wrong_task",
        "no_fresh_connection_replay_then_correlation_check",
        2,
        "in_flight_and_typed_mismatch",
        "in_flight_and_typed_mismatch",
    )
    .emit();
}

fn spawn_test_handle(cx: &Cx) -> asupersync::remote::RemoteHandle {
    spawn_remote(
        cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::new(b"proof-input".to_vec()),
    )
    .expect("spawn_remote should hand request to attached runtime")
}

#[derive(Debug)]
struct ProofLogRow {
    scenario_id: &'static str,
    origin_node: String,
    remote_node: String,
    transport_kind: &'static str,
    remote_task_id: String,
    lease_id: String,
    idempotency_key: String,
    command: String,
    trace_event_count: usize,
    obligation_count_before: usize,
    obligation_count_after: usize,
    expected_state: String,
    actual_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl ProofLogRow {
    fn pass(
        scenario_id: &'static str,
        remote_task_id: impl fmt::Display,
        idempotency_key: impl Into<String>,
        command: impl Into<String>,
        trace_event_count: usize,
        expected_state: impl Into<String>,
        actual_state: impl Into<String>,
    ) -> Self {
        let task_id = remote_task_id.to_string();
        Self {
            scenario_id,
            origin_node: ORIGIN_NODE.to_owned(),
            remote_node: REMOTE_NODE.to_owned(),
            transport_kind: TRANSPORT_KIND,
            remote_task_id: task_id.clone(),
            lease_id: format!("lease-{task_id}"),
            idempotency_key: idempotency_key.into(),
            command: command.into(),
            trace_event_count,
            obligation_count_before: 0,
            obligation_count_after: 0,
            expected_state: expected_state.into(),
            actual_state: actual_state.into(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn emit(&self) {
        assert_eq!(self.verdict, "pass");
        assert!(
            self.trace_event_count > 0 || self.scenario_id.contains("capability_denied"),
            "trace_event_count must be populated for transport-backed scenarios"
        );
        assert_eq!(
            self.obligation_count_before, self.obligation_count_after,
            "remote transport proof should not leak obligations"
        );
        assert_eq!(
            self.expected_state, self.actual_state,
            "expected state should match actual state in proof log"
        );
        println!(
            "REMOTE_TRANSPORT_LIFECYCLE bead_id={} scenario_id={} origin_node={} remote_node={} transport_kind={} remote_task_id={} lease_id={} idempotency_key={} command={} trace_event_count={} obligation_count_before={} obligation_count_after={} expected_state={} actual_state={} verdict={} first_failure={}",
            BEAD_ID,
            self.scenario_id,
            compact(&self.origin_node),
            compact(&self.remote_node),
            self.transport_kind,
            compact(&self.remote_task_id),
            compact(&self.lease_id),
            compact(&self.idempotency_key),
            compact(&self.command),
            self.trace_event_count,
            self.obligation_count_before,
            self.obligation_count_after,
            compact(&self.expected_state),
            compact(&self.actual_state),
            self.verdict,
            compact(&self.first_failure),
        );
    }
}

fn compact(value: &str) -> String {
    let compacted = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .replace('=', ":");
    if compacted.is_empty() {
        String::new()
    } else {
        compacted
    }
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn lamport_raw(time: &LogicalTime) -> u64 {
    match time {
        LogicalTime::Lamport(value) => value.raw(),
        LogicalTime::Vector(_) | LogicalTime::Hybrid(_) => 0,
    }
}

fn command_metadata(runtime: &TcpLoopbackRemoteRuntime) -> (String, String, u64) {
    let command = runtime
        .last_command()
        .expect("runtime should record at least one command");
    (
        command.command_name().to_owned(),
        command.idempotency_key().to_owned(),
        match &command {
            WireCommand::Spawn { sender_lamport, .. }
            | WireCommand::Cancel { sender_lamport, .. }
            | WireCommand::LeaseProbe { sender_lamport, .. } => *sender_lamport,
        },
    )
}

fn assert_runtime_drained(runtime: &TcpLoopbackRemoteRuntime) {
    assert_eq!(runtime.pending_count(), 0, "pending remote result senders");
    assert_eq!(runtime.state_count(), 0, "tracked remote task states");
}

#[test]
fn remote_transport_wire_codec_preserves_protocol_fields() {
    let command = WireCommand::Spawn {
        remote_task_id: 42,
        origin_node: ORIGIN_NODE.to_owned(),
        destination_node: REMOTE_NODE.to_owned(),
        computation: "proof.echo".to_owned(),
        input_len: 11,
        lease_ms: 50,
        idempotency_key: "IK-0000000000000000000000000000002a".to_owned(),
        sender_lamport: 7,
    };

    let encoded = serde_json::to_vec(&command).expect("wire command should serialize");
    let decoded: WireCommand =
        serde_json::from_slice(&encoded).expect("wire command should deserialize");
    assert_eq!(decoded, command);
    assert_eq!(decoded.remote_task_id(), 42);
    assert_eq!(
        decoded.idempotency_key(),
        "IK-0000000000000000000000000000002a"
    );

    ProofLogRow::pass(
        "wire_codec_protocol_fields",
        42,
        decoded.idempotency_key(),
        decoded.command_name(),
        1,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_peer_admission_negotiates_registry_and_gates_dispatch_over_tcp() {
    let mut registry = ComputationSchemaRegistry::new();
    registry
        .register_typed::<Vec<u8>, Vec<u8>>("proof.echo")
        .expect("proof.echo schema should register");
    registry
        .register_typed::<Vec<u8>, u64>("proof.hash")
        .expect("proof.hash schema should register");

    let mut reverse_order_registry = ComputationSchemaRegistry::new();
    reverse_order_registry
        .register_typed::<Vec<u8>, u64>("proof.hash")
        .expect("proof.hash schema should register in reverse order");
    reverse_order_registry
        .register_typed::<Vec<u8>, Vec<u8>>("proof.echo")
        .expect("proof.echo schema should register in reverse order");
    assert_eq!(
        registry.fingerprint(),
        reverse_order_registry.fingerprint(),
        "complete registry identity must not depend on registration order"
    );

    let origin = NodeId::new(ORIGIN_NODE);
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.clone());
    policy
        .grant_peer(origin.clone(), ["proof.echo"])
        .expect("explicit proof.echo grant should be valid");
    let compatible_hello = policy.hello_for(origin.clone());

    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("peer admission endpoint should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("peer admission endpoint should expose its address");
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let server_dispatch_count = Arc::clone(&dispatch_count);
    let server = thread::spawn(move || {
        block_on(serve_peer_admission_endpoint(
            listener,
            policy,
            server_dispatch_count,
            5,
        ))
    });

    let accepted = send_peer_admission_probe(endpoint, compatible_hello.clone(), "proof.echo");
    assert!(accepted.accepted, "diagnostic: {}", accepted.diagnostic);
    assert!(accepted.diagnostic.contains("dispatched named computation"));

    let unauthorized_computation =
        send_peer_admission_probe(endpoint, compatible_hello.clone(), "proof.hash");
    assert!(!unauthorized_computation.accepted);
    assert!(
        unauthorized_computation
            .diagnostic
            .contains("not capability-authorized"),
        "diagnostic: {}",
        unauthorized_computation.diagnostic
    );

    let unauthorized_peer = send_peer_admission_probe(
        endpoint,
        RemotePeerHello::new(
            NodeId::new("untrusted-origin"),
            compatible_hello.protocol_version(),
            compatible_hello.registry_fingerprint(),
        ),
        "proof.echo",
    );
    assert!(!unauthorized_peer.accepted);
    assert!(
        unauthorized_peer
            .diagnostic
            .contains("peer is not capability-authorized"),
        "diagnostic: {}",
        unauthorized_peer.diagnostic
    );

    let version_mismatch = send_peer_admission_probe(
        endpoint,
        RemotePeerHello::new(
            origin.clone(),
            RemoteProtocolVersion::new(2, 0),
            compatible_hello.registry_fingerprint(),
        ),
        "proof.echo",
    );
    assert!(!version_mismatch.accepted);
    assert!(
        version_mismatch
            .diagnostic
            .contains("protocol version mismatch"),
        "diagnostic: {}",
        version_mismatch.diagnostic
    );

    let mut incompatible_registry = registry;
    incompatible_registry
        .register_typed::<u64, u64>("proof.extra")
        .expect("extra schema should register");
    let registry_mismatch = send_peer_admission_probe(
        endpoint,
        RemotePeerHello::new(
            origin,
            RemoteProtocolVersion::V1,
            incompatible_registry.fingerprint(),
        ),
        "proof.echo",
    );
    assert!(!registry_mismatch.accepted);
    assert!(
        registry_mismatch
            .diagnostic
            .contains("computation registry mismatch"),
        "diagnostic: {}",
        registry_mismatch.diagnostic
    );

    server
        .join()
        .expect("peer admission endpoint should not panic")
        .expect("peer admission endpoint should serve all probes");
    assert_eq!(
        dispatch_count.load(Ordering::SeqCst),
        1,
        "only the compatible, explicitly granted request may reach dispatch"
    );

    ProofLogRow::pass(
        "peer_admission_registry_and_capability_gate",
        0,
        "none",
        "peer_hello_then_named_dispatch",
        5,
        "one_authorized_dispatch",
        "one_authorized_dispatch",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_service_executes_only_certificate_bound_authorized_computation() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let unauthorized_handler_count = Arc::new(AtomicUsize::new(0));
    let denied_handler_count = Arc::clone(&unauthorized_handler_count);
    let oversized_handler_count = Arc::new(AtomicUsize::new(0));
    let large_handler_count = Arc::clone(&oversized_handler_count);
    let mut computations = RemoteComputationRegistry::new();
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.echo", move |_cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            async move {
                assert_eq!(invocation.peer_node().as_str(), ORIGIN_NODE);
                assert_eq!(invocation.request().computation.as_str(), "proof.echo");
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("proof.echo executable handler should register");
    computations
        .register::<Vec<u8>, u64, _, _>("proof.hash", move |_cx, _invocation| {
            let denied_handler_count = Arc::clone(&denied_handler_count);
            async move {
                denied_handler_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(42_u64.to_be_bytes().to_vec()))
            }
        })
        .expect("proof.hash executable handler should register");
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.large", move |_cx, _invocation| {
            let large_handler_count = Arc::clone(&large_handler_count);
            async move {
                large_handler_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(vec![
                    b'x';
                    RemoteServiceWireLimits::default()
                        .max_frame_bytes()
                ]))
            }
        })
        .expect("proof.large executable handler should register");
    assert_eq!(computations.len(), 3);
    let origin = NodeId::new(ORIGIN_NODE);
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(
            origin.clone(),
            peer_pins.clone(),
            ["proof.echo", "proof.large"],
        )
        .expect("certificate-bound service grants should be valid");
    let hello = policy.hello_for(origin.clone());

    let mut drift_registry = ComputationSchemaRegistry::new();
    drift_registry
        .register_typed::<Vec<u8>, Vec<u8>>("proof.echo")
        .expect("drift policy proof.echo schema should register");
    let mut drift_policy =
        RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, drift_registry);
    drift_policy
        .grant_tls_peer(origin.clone(), peer_pins, ["proof.echo"])
        .expect("drift policy certificate-bound grant should be valid");
    let drift_hello = drift_policy.hello_for(origin.clone());

    let unbound_error = policy
        .admit(&hello)
        .expect_err("asserted NodeId must not bypass a certificate-bound grant");
    assert!(
        unbound_error
            .to_string()
            .contains("requires certificate-bound TLS admission"),
        "diagnostic: {unbound_error}"
    );

    let mut mismatched_pins = CertificatePinSet::new();
    mismatched_pins.add(
        CertificatePin::spki_sha256(vec![0_u8; 32])
            .expect("32-byte mismatch pin should be valid configuration"),
    );
    let mut mismatched_policy = policy.clone();
    let capability_denial_policy = policy.clone();
    let oversized_response_policy = policy.clone();
    let malformed_frame_policy = policy.clone();
    let oversized_frame_policy = policy.clone();
    let unknown_request_field_policy = policy.clone();
    let unknown_hello_field_policy = policy.clone();
    let unknown_version_field_policy = policy.clone();
    let unknown_budget_field_policy = policy.clone();
    let future_version_policy = policy.clone();
    mismatched_policy
        .grant_tls_peer(origin, mismatched_pins, ["proof.echo"])
        .expect("mismatched certificate grant should be valid configuration");

    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("mTLS connector should build");

    let listener = block_on(TcpListener::bind("127.0.0.1:0"))
        .expect("mTLS peer admission endpoint should bind loopback");
    let endpoint = listener
        .local_addr()
        .expect("mTLS peer admission endpoint should expose its address");
    let server = thread::spawn(move || {
        block_on(async move {
            let mut framing_errors = Vec::new();
            for (connection_index, admission_policy) in [
                policy,
                capability_denial_policy,
                mismatched_policy,
                drift_policy,
                oversized_response_policy,
                malformed_frame_policy,
                oversized_frame_policy,
                unknown_request_field_policy,
                unknown_hello_field_policy,
                unknown_version_field_policy,
                unknown_budget_field_policy,
                future_version_policy,
            ]
            .into_iter()
            .enumerate()
            {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("mTLS peer admission endpoint should accept TCP");
                let mut stream = acceptor
                    .accept(stream)
                    .await
                    .expect("mTLS endpoint should authenticate the client certificate");
                assert!(
                    stream.peer_leaf_certificate_der().is_some(),
                    "server should retain the authenticated client certificate"
                );
                let result = serve_tls_computation_once(
                    &Cx::for_testing(),
                    &mut stream,
                    &admission_policy,
                    &computations,
                    RemoteServiceWireLimits::default(),
                )
                .await;
                if connection_index < 4 || connection_index == 11 {
                    result.expect("mTLS endpoint should flush one typed service response");
                } else {
                    framing_errors.push(
                        result
                            .expect_err("malformed or oversized frame must fail closed")
                            .to_string(),
                    );
                }
            }
            framing_errors
        })
    });

    let accepted_request = remote_service_wire_request(hello.clone(), "proof.echo", 7001);
    let accepted = call_tls_remote_service(endpoint, &connector, &accepted_request);
    assert!(matches!(
        accepted,
        RemoteServiceWireResponse::Outcome {
            remote_task_id: 7001,
            outcome: RemoteServiceWireOutcome::Success(ref payload),
        } if payload == b"executed-over-mtls"
    ));

    let unauthorized_request = remote_service_wire_request(hello.clone(), "proof.hash", 7002);
    let unauthorized_computation =
        call_tls_remote_service(endpoint, &connector, &unauthorized_request);
    assert!(matches!(
        unauthorized_computation,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 7002,
            code: RemoteServiceRejectionCode::ComputationDenied,
            ref diagnostic,
        } if diagnostic.contains("not capability-authorized")
    ));

    let mismatched_request = remote_service_wire_request(hello.clone(), "proof.echo", 7003);
    let certificate_mismatch = call_tls_remote_service(endpoint, &connector, &mismatched_request);
    assert!(matches!(
        certificate_mismatch,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 7003,
            code: RemoteServiceRejectionCode::AdmissionDenied,
            ref diagnostic,
        } if diagnostic.contains("TLS peer certificate was rejected")
    ));

    let drift_request = remote_service_wire_request(drift_hello, "proof.echo", 7004);
    let executable_registry_drift = call_tls_remote_service(endpoint, &connector, &drift_request);
    assert!(matches!(
        executable_registry_drift,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 7004,
            code: RemoteServiceRejectionCode::ExecutableRegistryDrift,
            ref diagnostic,
        } if diagnostic.contains("differs from executable registry")
    ));

    let oversized_response_request =
        remote_service_wire_request(hello.clone(), "proof.large", 7005);
    let oversized_response_error =
        call_tls_remote_service_result(endpoint, &connector, &oversized_response_request)
            .expect_err("oversized encoded response must close without a partial frame");
    assert!(
        matches!(
            oversized_response_error,
            RemoteComputationServiceError::UnexpectedEof
                | RemoteComputationServiceError::Transport(_)
        ),
        "diagnostic: {oversized_response_error}"
    );

    send_tls_malformed_remote_service_frame(endpoint, &connector, b"{not-json");
    send_tls_oversized_remote_service_prefix(endpoint, &connector);

    let strict_request = remote_service_wire_request(hello.clone(), "proof.echo", 7006);
    let mut unknown_request_field =
        serde_json::to_value(&strict_request).expect("strict request should serialize");
    unknown_request_field
        .as_object_mut()
        .expect("strict request should be a JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    let unknown_request_bytes =
        serde_json::to_vec(&unknown_request_field).expect("mutated request should serialize");
    send_tls_malformed_remote_service_frame(endpoint, &connector, &unknown_request_bytes);

    let mut unknown_hello_field =
        serde_json::to_value(&strict_request).expect("strict request should serialize");
    unknown_hello_field["hello"]
        .as_object_mut()
        .expect("strict hello should be a JSON object")
        .insert("capabilities".to_owned(), serde_json::json!([]));
    let unknown_hello_bytes =
        serde_json::to_vec(&unknown_hello_field).expect("mutated hello should serialize");
    send_tls_malformed_remote_service_frame(endpoint, &connector, &unknown_hello_bytes);

    let mut unknown_version_field =
        serde_json::to_value(&strict_request).expect("strict request should serialize");
    unknown_version_field["hello"]["protocol_version"]
        .as_object_mut()
        .expect("strict protocol version should be a JSON object")
        .insert("patch".to_owned(), serde_json::json!(1));
    let unknown_version_bytes =
        serde_json::to_vec(&unknown_version_field).expect("mutated version should serialize");
    send_tls_malformed_remote_service_frame(endpoint, &connector, &unknown_version_bytes);

    let mut unknown_budget_field =
        serde_json::to_value(&strict_request).expect("strict request should serialize");
    unknown_budget_field["budget"] = serde_json::json!({
        "deadline_nanos": 9,
        "poll_quota": 10,
        "cost_quota": 11,
        "priority": 12,
        "ambient_priority": 255
    });
    let unknown_budget_bytes =
        serde_json::to_vec(&unknown_budget_field).expect("mutated budget should serialize");
    send_tls_malformed_remote_service_frame(endpoint, &connector, &unknown_budget_bytes);

    let future_request = remote_service_wire_request(
        RemotePeerHello::new(
            NodeId::new(ORIGIN_NODE),
            RemoteProtocolVersion::new(4, 0),
            hello.registry_fingerprint(),
        ),
        "proof.echo",
        7007,
    );
    let future_version = call_tls_remote_service(endpoint, &connector, &future_request);
    assert!(matches!(
        future_version,
        RemoteServiceWireResponse::Rejected {
            remote_task_id: 7007,
            code: RemoteServiceRejectionCode::AdmissionDenied,
            ref diagnostic,
        } if diagnostic.contains("protocol version mismatch")
    ));

    let framing_errors = server
        .join()
        .expect("mTLS peer admission endpoint should not panic");
    assert_eq!(framing_errors.len(), 7);
    assert!(
        framing_errors[0].contains("encoded frame exceeds"),
        "diagnostic: {}",
        framing_errors[0]
    );
    assert!(
        framing_errors[1].contains("serialization error"),
        "diagnostic: {}",
        framing_errors[1]
    );
    assert!(
        framing_errors[2].contains("frame length exceeds max_frame_length"),
        "diagnostic: {}",
        framing_errors[2]
    );
    assert!(
        framing_errors[3].contains("unknown field `future_field`"),
        "diagnostic: {}",
        framing_errors[3]
    );
    assert!(
        framing_errors[4].contains("unknown field `capabilities`"),
        "diagnostic: {}",
        framing_errors[4]
    );
    assert!(
        framing_errors[5].contains("unknown field `patch`"),
        "diagnostic: {}",
        framing_errors[5]
    );
    assert!(
        framing_errors[6].contains("unknown field `ambient_priority`"),
        "diagnostic: {}",
        framing_errors[6]
    );
    assert_eq!(
        dispatch_count.load(Ordering::SeqCst),
        1,
        "only the connection with a matching authenticated certificate may dispatch"
    );
    assert_eq!(
        unauthorized_handler_count.load(Ordering::SeqCst),
        0,
        "registered but ungranted computation must be refused before handler invocation"
    );
    assert_eq!(
        oversized_handler_count.load(Ordering::SeqCst),
        1,
        "authorized oversized output should execute once but never allocate an oversized frame"
    );

    ProofLogRow::pass(
        "peer_admission_mtls_certificate_binding",
        0,
        "none",
        "mtls_wire_request_then_typed_outcome",
        12,
        "one_certificate_bound_dispatch",
        "one_certificate_bound_dispatch",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_listener_v2_deduplicates_by_peer_and_drains_without_orphans() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_dispatch_count = Arc::clone(&dispatch_count);
    let wait_dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_wait_dispatch_count = Arc::clone(&wait_dispatch_count);
    let failure_dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_failure_dispatch_count = Arc::clone(&failure_dispatch_count);
    let oversized_dispatch_count = Arc::new(AtomicUsize::new(0));
    let handler_oversized_dispatch_count = Arc::clone(&oversized_dispatch_count);
    let (wait_release_tx, wait_release_rx) = oneshot::channel::<()>();
    let wait_receiver = Arc::new(Mutex::new(Some(wait_release_rx)));
    let handler_wait_receiver = Arc::clone(&wait_receiver);
    let mut computations = RemoteComputationRegistry::new();
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.echo", move |_cx, invocation| {
            let handler_dispatch_count = Arc::clone(&handler_dispatch_count);
            async move {
                handler_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("listener proof.echo handler should register");
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.wait", move |cx, invocation| {
            let handler_wait_dispatch_count = Arc::clone(&handler_wait_dispatch_count);
            let mut receiver = handler_wait_receiver
                .lock()
                .take()
                .expect("proof.wait canonical request should execute exactly once");
            async move {
                handler_wait_dispatch_count.fetch_add(1, Ordering::SeqCst);
                receiver.recv(&cx).await.map_err(|error| {
                    RemoteError::TransportError(format!("proof.wait release failed: {error}"))
                })?;
                Ok(RemoteOutcome::Success(
                    invocation.into_request().input.into_data(),
                ))
            }
        })
        .expect("listener proof.wait handler should register");
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.fail", move |_cx, _invocation| {
            let handler_failure_dispatch_count = Arc::clone(&handler_failure_dispatch_count);
            async move {
                handler_failure_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Err(RemoteError::TransportError(
                    "planted execution refusal".to_owned(),
                ))
            }
        })
        .expect("listener proof.fail handler should register");
    computations
        .register::<Vec<u8>, Vec<u8>, _, _>("proof.large", move |_cx, _invocation| {
            let handler_oversized_dispatch_count = Arc::clone(&handler_oversized_dispatch_count);
            async move {
                handler_oversized_dispatch_count.fetch_add(1, Ordering::SeqCst);
                Ok(RemoteOutcome::Success(vec![
                    b'x';
                    RemoteServiceWireLimits::default()
                        .max_frame_bytes()
                ]))
            }
        })
        .expect("listener proof.large handler should register");

    let origin = NodeId::new(ORIGIN_NODE);
    let mut peer_pins = CertificatePinSet::new();
    peer_pins.add(
        CertificatePin::compute_spki_sha256(&peer_certificate)
            .expect("fixture certificate should produce an SPKI pin"),
    );
    let peer_two = NodeId::new("origin-prod-loopback-two");
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V2,
        computations.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(
            origin.clone(),
            peer_pins.clone(),
            ["proof.echo", "proof.wait", "proof.fail", "proof.large"],
        )
        .expect("listener certificate-bound grant should be valid");
    policy
        .grant_tls_peer(peer_two.clone(), peer_pins, ["proof.echo"])
        .expect("second listener certificate-bound grant should be valid");
    let hello = policy.hello_for(origin);
    let peer_two_hello = policy.hello_for(peer_two);
    let canonical_echo = remote_service_wire_request_with(
        hello.clone(),
        "proof.echo",
        7101,
        0xbeef,
        b"canonical-echo",
    );
    let duplicate_echo = remote_service_wire_request_with(
        hello.clone(),
        "proof.echo",
        7102,
        0xbeef,
        b"canonical-echo",
    );
    let conflicting_echo = remote_service_wire_request_with(
        hello.clone(),
        "proof.echo",
        7103,
        0xbeef,
        b"conflicting-input",
    );
    let peer_two_echo = remote_service_wire_request_with(
        peer_two_hello,
        "proof.echo",
        7104,
        0xbeef,
        b"peer-two-input",
    );
    let canonical_wait =
        remote_service_wire_request_with(hello.clone(), "proof.wait", 7111, 0xcafe, b"wait-result");
    let in_flight_wait =
        remote_service_wire_request_with(hello.clone(), "proof.wait", 7112, 0xcafe, b"wait-result");
    let cached_wait =
        remote_service_wire_request_with(hello.clone(), "proof.wait", 7113, 0xcafe, b"wait-result");
    let canonical_failure = remote_service_wire_request_with(
        hello.clone(),
        "proof.fail",
        7121,
        0xdead,
        b"failure-input",
    );
    let cached_failure = remote_service_wire_request_with(
        hello.clone(),
        "proof.fail",
        7122,
        0xdead,
        b"failure-input",
    );
    let canonical_oversized = remote_service_wire_request_with(
        hello.clone(),
        "proof.large",
        7123,
        0xbad,
        b"oversized-input",
    );
    let cached_oversized_retry = remote_service_wire_request_with(
        hello.clone(),
        "proof.large",
        7124,
        0xbad,
        b"oversized-input",
    );
    let capacity_request = remote_service_wire_request_with(
        hello.clone(),
        "proof.echo",
        7131,
        0xf00d,
        b"capacity-input",
    );
    let cached_echo_at_capacity =
        remote_service_wire_request_with(hello, "proof.echo", 7132, 0xbeef, b"canonical-echo");

    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain.clone(), private_key.clone())
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("structured mTLS acceptor should build");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&peer_certificate)
        .identity(certificate_chain, private_key)
        .build()
        .expect("structured mTLS connector should build");

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("structured remote service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(8))
                .with_max_idempotency_records_per_peer(4)
                .with_drain_timeout(Duration::from_millis(25)),
        ))
        .expect("structured remote service should bind");
    let endpoint = service
        .local_addr()
        .expect("structured remote service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let client_wait_dispatch_count = Arc::clone(&wait_dispatch_count);
    let connector = Arc::new(connector);

    let client = thread::spawn(move || {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let accepted = call_tls_remote_service(endpoint, &connector, &canonical_echo);
            assert!(matches!(
                accepted,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7101,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"canonical-echo"
            ));

            let duplicate = call_tls_remote_service(endpoint, &connector, &duplicate_echo);
            assert!(matches!(
                duplicate,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7102,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"canonical-echo"
            ));
            let conflict = call_tls_remote_service(endpoint, &connector, &conflicting_echo);
            assert!(matches!(
                conflict,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7103,
                    code: RemoteServiceRejectionCode::IdempotencyConflict,
                    ..
                }
            ));
            let peer_two = call_tls_remote_service(endpoint, &connector, &peer_two_echo);
            assert!(matches!(
                peer_two,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7104,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"peer-two-input"
            ));

            let canonical_wait_connector = Arc::clone(&connector);
            let canonical_wait_thread = thread::spawn(move || {
                call_tls_remote_service(endpoint, &canonical_wait_connector, &canonical_wait)
            });
            let wait_deadline = std::time::Instant::now() + Duration::from_secs(2);
            while client_wait_dispatch_count.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::time::Instant::now() < wait_deadline,
                    "canonical proof.wait request should reach its handler"
                );
                thread::sleep(Duration::from_millis(1));
            }
            let in_flight = call_tls_remote_service(endpoint, &connector, &in_flight_wait);
            assert!(matches!(
                in_flight,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7112,
                    code: RemoteServiceRejectionCode::OperationInFlight,
                    ..
                }
            ));
            wait_release_tx
                .send_blocking(())
                .expect("proof.wait canonical handler should still own its receiver");
            let canonical_wait_response = canonical_wait_thread
                .join()
                .expect("canonical proof.wait client should not panic");
            assert!(matches!(
                canonical_wait_response,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7111,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"wait-result"
            ));
            let replayed_wait = call_tls_remote_service(endpoint, &connector, &cached_wait);
            assert!(matches!(
                replayed_wait,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7113,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"wait-result"
            ));

            let canonical_failure_response =
                call_tls_remote_service(endpoint, &connector, &canonical_failure);
            let canonical_failure_diagnostic = match canonical_failure_response {
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7121,
                    code: RemoteServiceRejectionCode::ExecutionFailed,
                    diagnostic,
                } => diagnostic,
                other => panic!("unexpected canonical failure response: {other:?}"),
            };
            let cached_failure_response =
                call_tls_remote_service(endpoint, &connector, &cached_failure);
            assert!(matches!(
                cached_failure_response,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7122,
                    code: RemoteServiceRejectionCode::ExecutionFailed,
                    ref diagnostic,
                } if diagnostic == &canonical_failure_diagnostic
            ));

            let canonical_oversized_response =
                call_tls_remote_service(endpoint, &connector, &canonical_oversized);
            let oversized_diagnostic = match canonical_oversized_response {
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7123,
                    code: RemoteServiceRejectionCode::ExecutionFailed,
                    diagnostic,
                } => diagnostic,
                other => panic!("unexpected oversized terminal fallback: {other:?}"),
            };
            let cached_oversized =
                call_tls_remote_service(endpoint, &connector, &cached_oversized_retry);
            assert!(matches!(
                cached_oversized,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7124,
                    code: RemoteServiceRejectionCode::ExecutionFailed,
                    ref diagnostic,
                } if diagnostic == &oversized_diagnostic
            ));

            let capacity = call_tls_remote_service(endpoint, &connector, &capacity_request);
            assert!(matches!(
                capacity,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7131,
                    code: RemoteServiceRejectionCode::IdempotencyCapacity,
                    ..
                }
            ));
            let replay_at_capacity =
                call_tls_remote_service(endpoint, &connector, &cached_echo_at_capacity);
            assert!(matches!(
                replay_at_capacity,
                RemoteServiceWireResponse::Outcome {
                    remote_task_id: 7132,
                    outcome: RemoteServiceWireOutcome::Success(ref payload),
                } if payload == b"canonical-echo"
            ));

            block_on(async {
                let stream = TcpStream::connect(endpoint)
                    .await
                    .expect("stalled service client should connect");
                let mut stream = connector
                    .connect("localhost", stream)
                    .await
                    .expect("stalled service client should complete mutual TLS");
                stream
                    .write_all(&100_u32.to_be_bytes())
                    .await
                    .expect("stalled service client should write a bounded prefix");
                stream
                    .write_all(b"{")
                    .await
                    .expect("stalled service client should write a partial frame");
                stream
                    .flush()
                    .await
                    .expect("stalled service client should flush its partial frame");

                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while client_operator.active_connections() == 0 {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "stalled connection should become service-owned"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(client_operator.begin_drain());
                thread::sleep(Duration::from_millis(100));
                drop(stream);
            });
        }));
        if attempt.is_err() {
            client_operator.force_close();
        }
        attempt.expect("structured remote service client should complete");
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a service context");
            service.run(&cx).await
        })
        .expect("structured remote service should drain cleanly");
    client
        .join()
        .expect("structured remote service client should not panic");

    assert_eq!(report.accepted_connections(), 14);
    assert_eq!(report.capacity_rejections(), 0);
    assert_eq!(report.completed_connections(), 13);
    assert_eq!(report.interrupted_connections(), 1);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.panicked_connections(), 0);
    assert_eq!(report.first_connection_failure(), None);
    assert_eq!(report.shutdown().drained, 0);
    assert_eq!(report.shutdown().force_closed, 1);
    assert_eq!(operator.active_connections(), 0);
    assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 2);
    assert_eq!(wait_dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(failure_dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(oversized_dispatch_count.load(Ordering::SeqCst), 1);

    ProofLogRow::pass(
        "structured_remote_service_v2_idempotency_and_drain",
        0,
        "none",
        "mtls_v2_peer_dedup_then_force_close_stalled_frame",
        14,
        "thirteen_completed_zero_failed_one_interrupted_five_dispatches_zero_live",
        "thirteen_completed_zero_failed_one_interrupted_five_dispatches_zero_live",
    )
    .emit();
}

#[cfg(feature = "tls")]
#[test]
fn remote_tls_listener_parent_cancellation_interrupts_stalled_handshake() {
    let certificates = Certificate::from_pem(TEST_CERT_PEM).expect("TLS fixture should parse");
    let peer_certificate = certificates
        .first()
        .expect("TLS fixture should contain a leaf certificate")
        .clone();
    let certificate_chain =
        CertificateChain::from_pem(TEST_CERT_PEM).expect("TLS certificate chain should parse");
    let private_key = PrivateKey::from_pem(TEST_KEY_PEM).expect("TLS private key should parse");

    let computations = RemoteComputationRegistry::new();
    let policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1,
        computations.schema_registry().clone(),
    );
    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots
        .add(&peer_certificate)
        .expect("server should trust the fixture client certificate");
    let acceptor = TlsAcceptorBuilder::new(certificate_chain, private_key)
        .client_auth(ClientAuth::Required(client_auth_roots))
        .build()
        .expect("structured mTLS acceptor should build");

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("structured remote service runtime should build");
    let service = runtime
        .block_on(RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            computations,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(8))
                .with_drain_timeout(Duration::from_millis(25)),
        ))
        .expect("structured remote service should bind");
    let endpoint = service
        .local_addr()
        .expect("structured remote service should expose its address");
    let operator = service.handle();
    let client_operator = operator.clone();
    let (parent_cx_tx, parent_cx_rx) = std::sync::mpsc::sync_channel::<Cx>(1);

    let client = thread::spawn(move || {
        let stream = block_on(TcpStream::connect(endpoint))
            .expect("stalled handshake client should connect");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while client_operator.active_connections() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "stalled handshake should become service-owned"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let parent_cx = parent_cx_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("service should publish its parent context to the canceller");
        parent_cx.cancel_fast(CancelKind::User);
        thread::sleep(Duration::from_millis(100));
        drop(stream);
    });

    let report = runtime
        .block_on(async move {
            let cx = Cx::current().expect("runtime should install a service context");
            parent_cx_tx
                .send(cx.clone())
                .expect("canceller should remain available");
            service.run(&cx).await
        })
        .expect("parent cancellation should quiesce the remote service");
    client
        .join()
        .expect("parent-cancellation client should not panic");

    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.capacity_rejections(), 0);
    assert_eq!(report.completed_connections(), 0);
    assert_eq!(report.interrupted_connections(), 1);
    assert_eq!(report.failed_connections(), 0);
    assert_eq!(report.panicked_connections(), 0);
    assert_eq!(report.first_connection_failure(), None);
    assert_eq!(
        report.shutdown().drained + report.shutdown().force_closed,
        1
    );
    assert_eq!(operator.active_connections(), 0);
    assert_eq!(operator.shutdown_signal().phase(), ShutdownPhase::Stopped);

    ProofLogRow::pass(
        "structured_remote_service_parent_cancellation",
        0,
        "none",
        "parent_cancel_during_tls_handshake",
        1,
        "one_interrupted_zero_live_stopped",
        "one_interrupted_zero_live_stopped",
    )
    .emit();
}

#[test]
fn remote_transport_trait_receives_ack_result_and_logical_time() {
    let endpoint = TestEndpoint::launch(EndpointMode::CompleteAfterAck, 1);
    let mut transport = WireTransport::new(endpoint.addr);
    let task_id = RemoteTaskId::from_raw(77);
    let envelope = MessageEnvelope::new(
        NodeId::new(ORIGIN_NODE),
        LogicalTime::Lamport(asupersync::trace::distributed::LamportTime::from_raw(5)),
        RemoteMessage::SpawnRequest(asupersync::remote::SpawnRequest {
            remote_task_id: task_id,
            computation: ComputationName::new("proof.echo"),
            input: RemoteInput::new(b"transport-trait".to_vec()),
            lease: Duration::from_millis(50),
            idempotency_key: asupersync::remote::IdempotencyKey::from_raw(0x77),
            budget: None,
            origin_node: NodeId::new(ORIGIN_NODE),
            origin_region: Cx::for_testing().region_id(),
            origin_task: Cx::for_testing().task_id(),
        }),
    );

    transport
        .send(&NodeId::new(REMOTE_NODE), envelope)
        .expect("RemoteTransport send should cross TCP loopback");
    let first = transport.try_recv().expect("spawn ack should be queued");
    let second = transport
        .try_recv()
        .expect("result delivery should be queued");
    assert!(matches!(first.payload, RemoteMessage::SpawnAck(_)));
    assert!(matches!(second.payload, RemoteMessage::ResultDelivery(_)));
    assert!(transport.try_recv().is_none());
    let endpoint_state = endpoint.finish();
    assert_eq!(endpoint_state.command_count(), 1);

    ProofLogRow::pass(
        "remote_transport_trait_ack_result_logical_time",
        task_id.raw(),
        "IK-00000000000000000000000000000077",
        "spawn",
        3,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_transport_spawn_result_cancel_and_lease_matrix_emits_required_logs() {
    let endpoint = TestEndpoint::launch(EndpointMode::CompleteAfterAck, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("remote result should arrive");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, sender_lamport) = command_metadata(&runtime);
    assert!(sender_lamport > 0);
    endpoint.finish();
    ProofLogRow::pass(
        "spawn_ack_result_delivery",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::HoldUntilCancel, 2);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    assert_eq!(handle.state(), RemoteTaskState::Running);
    let outcome = block_on(handle.close(&cx)).expect("close should receive cancel outcome");
    assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
    assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    assert_runtime_drained(&runtime);
    let (_, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "cancel_while_running_drains_result",
        task_id.raw(),
        key,
        "spawn_then_cancel",
        runtime.trace_event_count(&trace),
        "Cancelled",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::CancelBeforeAck, 2);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    assert_eq!(handle.state(), RemoteTaskState::Pending);
    let outcome = block_on(handle.close(&cx)).expect("close should settle pending cancel");
    assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
    assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    assert_runtime_drained(&runtime);
    let (_, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "cancel_before_ack_drains_result",
        task_id.raw(),
        key,
        "spawn_without_ack_then_cancel",
        runtime.trace_event_count(&trace),
        "Cancelled",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::RejectSpawn, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let error = block_on(handle.join(&cx)).expect_err("rejected spawn should fail join");
    assert!(matches!(
        error,
        RemoteError::SpawnRejected(SpawnRejectReason::UnknownComputation)
    ));
    assert_eq!(handle.state(), RemoteTaskState::Failed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "spawn_rejected_cleans_origin_state",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Failed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::LeaseRenewalThenSuccess, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("lease-renewed task should complete");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert!(runtime.saw_lease_renewal(task_id));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "lease_renewal_then_result",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::LeaseExpiry, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let error = block_on(handle.join(&cx)).expect_err("lost renewal should expire lease");
    assert_eq!(error, RemoteError::LeaseExpired);
    assert_eq!(handle.state(), RemoteTaskState::LeaseExpired);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "lost_renewal_lease_expiry_cleanup",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "LeaseExpired",
        handle.state().to_string(),
    )
    .emit();
}

#[test]
fn remote_transport_failure_injection_cleans_origin_state() {
    let unused_addr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("unused probe bind");
        listener.local_addr().expect("unused probe address")
    };
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(unused_addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("connection refusal should fail spawn");
    assert!(matches!(error, RemoteError::TransportError(_)));
    assert_runtime_drained(&runtime);
    ProofLogRow::pass(
        "send_failure_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::CloseWithoutReply, 1);
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint.addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("EOF before ack should fail spawn");
    assert!(matches!(error, RemoteError::TransportError(_)));
    assert_runtime_drained(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "receive_eof_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::MalformedReply, 1);
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint.addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("malformed reply should fail spawn");
    assert!(matches!(error, RemoteError::SerializationError(_)));
    assert_runtime_drained(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "malformed_envelope_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::DelayedAck, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("delayed ack should still complete");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "delayed_ack_preserves_result_delivery",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();
}

#[test]
fn remote_transport_idempotency_replay_uses_cached_result() {
    let endpoint = TestEndpoint::launch(EndpointMode::DuplicateIdempotency, 2);
    let command = WireCommand::Spawn {
        remote_task_id: 9001,
        origin_node: ORIGIN_NODE.to_owned(),
        destination_node: REMOTE_NODE.to_owned(),
        computation: "proof.idempotent".to_owned(),
        input_len: 17,
        lease_ms: 50,
        idempotency_key: "IK-00000000000000000000000000009001".to_owned(),
        sender_lamport: 11,
    };

    let first = send_wire_command(endpoint.addr, &command).expect("first spawn should execute");
    let second =
        send_wire_command(endpoint.addr, &command).expect("duplicate spawn should be cached");
    assert!(matches!(
        first.as_slice(),
        [
            WireReply::AckAccepted { .. },
            WireReply::ResultSuccess { .. }
        ]
    ));
    assert!(matches!(
        second.as_slice(),
        [WireReply::CachedResult { .. }]
    ));
    let cached_payload = match &second[0] {
        WireReply::CachedResult { payload, .. } => payload,
        other => panic!("expected cached result, got {other:?}"),
    };
    assert_eq!(cached_payload, b"idempotent-result");
    let endpoint_state = endpoint.finish();
    assert_eq!(
        endpoint_state.execution_count("IK-00000000000000000000000000009001"),
        1,
        "duplicate idempotency key should not execute computation twice"
    );

    ProofLogRow::pass(
        "duplicate_idempotency_replay_cached_result",
        9001,
        command.idempotency_key(),
        "spawn_duplicate",
        4,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_transport_capability_denial_and_phase0_fallback_are_explicit() {
    let cx = Cx::for_testing();
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("missing RemoteCap should deny remote spawn");
    assert_eq!(error, RemoteError::NoCapability);
    ProofLogRow::pass(
        "capability_denied_without_remote_cap",
        0,
        "none",
        "spawn",
        0,
        "Failed",
        "Failed",
    )
    .emit();

    let cx = Cx::for_testing().with_remote_cap(asupersync::remote::RemoteCap::new());
    let mut handle = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect("phase0 fallback should create a terminal handle");
    let error = handle
        .try_join()
        .expect_err("phase0 fallback should report deterministic error");
    assert!(matches!(error, RemoteError::NodeUnreachable(_)));
    ProofLogRow::pass(
        "phase0_fallback_without_runtime_is_explicit",
        handle.remote_task_id().raw(),
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();
}

#[test]
fn remote_transport_runner_rejects_full_rch_fallback_marker_set() {
    let runner = fs::read_to_string(RUNNER_PATH).expect("read runner script");

    assert!(
        runner
            .matches(r#"grep -Eiq "${RCH_LOCAL_FALLBACK_PATTERN}""#)
            .count()
            >= 1,
        "runner must use the shared local fallback matcher at its rch gate"
    );

    for token in [
        "RCH_LOCAL_FALLBACK_PATTERN=",
        "[RCH\\] local",
        "falling back to local",
        "local fallback",
        "fallback to local",
        "executing locally",
    ] {
        assert!(
            runner.contains(token),
            "runner missing local fallback marker: {token}"
        );
    }
}

#[test]
fn remote_transport_runner_dry_run_records_rch_plan() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_root = tempfile::tempdir().expect("temp output root");
    let output_root_path = output_root.path().to_string_lossy().into_owned();
    let output = Command::new("bash")
        .current_dir(repo_root)
        .arg(RUNNER_PATH)
        .arg("--dry-run")
        .arg("--run-id")
        .arg("dry-run-smoke")
        .arg("--output-root")
        .arg(&output_root_path)
        .output()
        .expect("run remote transport lifecycle dry-run");

    assert!(
        output.status.success(),
        "dry-run runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run_dir = output_root.path().join("run_dry-run-smoke");
    let report_path = run_dir.join("run_report.json");
    let log_path = run_dir.join("run.log");
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&report_path)
            .unwrap_or_else(|_| panic!("missing {}", report_path.display())),
    )
    .expect("valid dry-run report json");
    let log =
        fs::read_to_string(&log_path).unwrap_or_else(|_| panic!("missing {}", log_path.display()));
    let runner = fs::read_to_string(repo_root.join(RUNNER_PATH)).expect("read runner script");
    let artifact: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            repo_root.join("artifacts/wave2/remote_transport_lifecycle_evidence.json"),
        )
        .expect("read remote transport lifecycle artifact"),
    )
    .expect("valid artifact json");

    assert_eq!(report["dry_run"].as_bool(), Some(true));
    assert_eq!(report["validation_passed"].as_bool(), Some(true));
    assert_eq!(
        report["missing_scenarios"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(log.contains("REMOTE_TRANSPORT_LIFECYCLE_DRY_RUN"));
    assert!(log.contains("rch exec -- env CARGO_INCREMENTAL=0"));
    for marker in [
        "RCH_BIN=\"${RCH_BIN:-$HOME/.local/bin/rch}\"",
        "RCH_COMMAND=(\"${RCH_BIN}\" exec -- \"${TEST_COMMAND[@]}\")",
        "falling back to local",
        "REMOTE_TRANSPORT_LIFECYCLE_DRY_RUN",
        "--dry-run",
    ] {
        assert!(runner.contains(marker), "runner missing marker: {marker}");
    }
    let validation_commands = artifact["validation_commands"]
        .as_array()
        .expect("validation_commands array");
    let cargo_commands = validation_commands
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|command| command.contains("cargo "))
        .collect::<Vec<_>>();
    assert!(
        !cargo_commands.is_empty(),
        "artifact must include Cargo validation commands"
    );
    assert!(
        cargo_commands
            .iter()
            .all(|command| command.contains("rch exec -- env ")
                && command.contains("CARGO_TARGET_DIR=")),
        "Cargo validation commands must route through rch exec -- env CARGO_TARGET_DIR=..."
    );
    assert!(
        validation_commands
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter(|command| command.contains("rustfmt "))
            .all(|command| command.contains("rch exec --")),
        "rustfmt validation commands must be rch-routed"
    );
}
