#![cfg(feature = "test-internals")]
//! Production-transport-backed proof for the RemoteRuntime lifecycle contract.

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::distributed::ComputationSchemaRegistry;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::remote::{
    ComputationName, IdempotencyKey, MessageEnvelope, NodeId, RemoteComputationRegistry,
    RemoteError, RemoteInput, RemoteMessage, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemotePeerHello, RemoteProtocolVersion, RemoteRuntime, RemoteTaskId, RemoteTaskState,
    RemoteTransport, SpawnRejectReason, SpawnRequest, spawn_remote,
};
#[cfg(feature = "tls")]
use asupersync::remote::{
    RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationClientError,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceError,
    RemoteServiceRejectionCode, RemoteServiceWireLimits, RemoteServiceWireOutcome,
    RemoteServiceWireRequest, RemoteServiceWireResponse, call_tls_computation_once,
    serve_tls_computation_once,
};
#[cfg(feature = "tls")]
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "tls")]
use asupersync::server::ShutdownPhase;
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
use futures_lite::future::block_on;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    let retry_client = RemoteComputationClient::new(
        closed_endpoint,
        "localhost",
        remote_client_test_mtls_pair().1,
        RemoteComputationClientConfig::new()
            .with_max_attempts(3)
            .with_backoff(Duration::ZERO, Duration::ZERO)
            .with_full_jitter(false),
    )
    .expect("closed-port retry client should build");
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
                if connection_index < 4 {
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

    let oversized_response_request = remote_service_wire_request(hello, "proof.large", 7005);
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

    let framing_errors = server
        .join()
        .expect("mTLS peer admission endpoint should not panic");
    assert_eq!(framing_errors.len(), 3);
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
        7,
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
    let ambiguous_oversized_retry = remote_service_wire_request_with(
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

            let oversized_error =
                call_tls_remote_service_result(endpoint, &connector, &canonical_oversized)
                    .expect_err(
                        "oversized V2 terminal response must not be committed before encoding",
                    );
            assert!(matches!(
                oversized_error,
                RemoteComputationServiceError::UnexpectedEof
                    | RemoteComputationServiceError::Transport(_)
            ));
            let ambiguous_oversized =
                call_tls_remote_service(endpoint, &connector, &ambiguous_oversized_retry);
            assert!(matches!(
                ambiguous_oversized,
                RemoteServiceWireResponse::Rejected {
                    remote_task_id: 7124,
                    code: RemoteServiceRejectionCode::OperationInFlight,
                    ..
                }
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
    assert_eq!(report.completed_connections(), 12);
    assert_eq!(report.interrupted_connections(), 1);
    assert_eq!(report.failed_connections(), 1);
    assert_eq!(report.panicked_connections(), 0);
    assert!(
        report
            .first_connection_failure()
            .is_some_and(|failure| failure.contains("encoded frame exceeds"))
    );
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
        "twelve_completed_one_failed_one_interrupted_five_dispatches_zero_live",
        "twelve_completed_one_failed_one_interrupted_five_dispatches_zero_live",
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
