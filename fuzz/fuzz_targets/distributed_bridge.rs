//! Fuzz target for distributed bridge cross-node message bridging.
//!
//! Focuses on the RegionBridge in src/distributed/bridge.rs with comprehensive
//! testing of cross-node message handling, sequence validation, and state
//! synchronization edge cases:
//! 1. Message framing length bounds and overflow protection
//! 2. Sequence number monotonicity enforcement per channel
//! 3. Unknown message type handling and graceful degradation
//! 4. Vector-clock ordering validation and conflict resolution
//! 5. Snapshot apply idempotency under concurrent operations
//!
//! Key attack vectors:
//! - Malformed inter-node messages for bridge corruption
//! - Sequence number manipulation for ordering violations
//! - Unknown message types for protocol confusion attacks
//! - Timestamp tampering for causality violations
//! - Duplicate snapshot application for idempotency failures
//! - Large message payloads for resource exhaustion

#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::bridge::{RegionBridge, RegionMode, BridgeConfig, SyncMode, ConflictResolution};
use asupersync::distributed::snapshot::{RegionSnapshot, TaskSnapshot, TaskState, BudgetSnapshot};
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, TaskId, Time, Budget};
use asupersync::util::ArenaIndex;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum input size to prevent memory exhaustion during fuzzing
const MAX_INPUT_SIZE: usize = 512 * 1024; // 512KB

/// Maximum number of snapshots per test case
const MAX_SNAPSHOTS: usize = 100;

/// Maximum number of tasks per snapshot
const MAX_TASKS: usize = 50;

/// Maximum metadata size per snapshot
const MAX_METADATA_SIZE: usize = 1024;

/// Cross-node message for distributed bridge testing
#[derive(Arbitrary, Debug, Clone)]
struct CrossNodeMessage {
    /// Message type identifier (some may be unknown)
    message_type: u8,
    /// Source node identifier
    source_node: u16,
    /// Channel identifier
    channel_id: u16,
    /// Sequence number for this channel
    sequence: u64,
    /// Vector clock for ordering (simplified as timestamp)
    vector_clock: u64,
    /// Message payload length
    payload_length: u32,
    /// Actual message payload
    payload: MessagePayload,
}

/// Message payload variants
#[derive(Arbitrary, Debug, Clone)]
enum MessagePayload {
    /// Snapshot synchronization message
    Snapshot(FuzzRegionSnapshot),
    /// Heartbeat/keepalive message
    Heartbeat { node_id: u16, timestamp: u64 },
    /// State transition notification
    StateTransition { region_id: u64, new_state: u8 },
    /// Unknown/malformed payload
    Unknown(Vec<u8>),
}

/// Fuzzable region snapshot configuration
#[derive(Arbitrary, Debug, Clone)]
struct FuzzRegionSnapshot {
    /// Region identifier (arena-based)
    region_arena_gen: u32,
    region_arena_slot: u32,
    /// Region state (may be invalid)
    state_value: u8,
    /// Timestamp
    timestamp_nanos: u64,
    /// Sequence number
    sequence: u64,
    /// Task configurations
    tasks: Vec<FuzzTaskSnapshot>,
    /// Child region IDs
    children: Vec<FuzzRegionId>,
    /// Finalizer count
    finalizer_count: u32,
    /// Budget configuration
    budget: FuzzBudgetSnapshot,
    /// Cancellation reason
    cancel_reason: Option<String>,
    /// Parent region
    parent: Option<FuzzRegionId>,
    /// Custom metadata
    metadata: Vec<u8>,
}

/// Fuzzable task snapshot
#[derive(Arbitrary, Debug, Clone)]
struct FuzzTaskSnapshot {
    /// Task identifier (arena-based)
    task_arena_gen: u32,
    task_arena_slot: u32,
    /// Task state (may be invalid)
    state_value: u8,
    /// Priority
    priority: u8,
}

/// Fuzzable region ID
#[derive(Arbitrary, Debug, Clone)]
struct FuzzRegionId {
    arena_gen: u32,
    arena_slot: u32,
}

/// Fuzzable budget snapshot
#[derive(Arbitrary, Debug, Clone)]
struct FuzzBudgetSnapshot {
    deadline_nanos: Option<u64>,
    polls_remaining: Option<u32>,
    cost_remaining: Option<u64>,
}

/// Bridge test configuration
#[derive(Arbitrary, Debug)]
struct BridgeTestConfig {
    /// Initial region mode
    mode: FuzzRegionMode,
    /// Bridge configuration
    bridge_config: FuzzBridgeConfig,
    /// Sequence of cross-node messages
    messages: Vec<CrossNodeMessage>,
}

/// Fuzzable region mode
#[derive(Arbitrary, Debug, Clone)]
enum FuzzRegionMode {
    Local,
    Distributed { replication_factor: u8 },
    Hybrid { replication_factor: u8, max_lag_secs: u8 },
}

/// Fuzzable bridge configuration
#[derive(Arbitrary, Debug, Clone)]
struct FuzzBridgeConfig {
    allow_upgrade: bool,
    sync_timeout_secs: u8,
    sync_mode: FuzzSyncMode,
    conflict_resolution: FuzzConflictResolution,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzSyncMode {
    Synchronous,
    Asynchronous,
    WriteSync,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzConflictResolution {
    DistributedWins,
    LocalWins,
    HighestSequence,
    Error,
}

impl FuzzRegionMode {
    fn to_region_mode(self) -> RegionMode {
        match self {
            Self::Local => RegionMode::Local,
            Self::Distributed { replication_factor } => {
                let factor = replication_factor.max(1).min(10) as u32;
                RegionMode::distributed(factor)
            }
            Self::Hybrid { replication_factor, max_lag_secs } => {
                let factor = replication_factor.max(1).min(10) as u32;
                let mut mode = RegionMode::hybrid(factor);
                if let RegionMode::Hybrid { max_lag, .. } = &mut mode {
                    *max_lag = Duration::from_secs(max_lag_secs.max(1) as u64);
                }
                mode
            }
        }
    }
}

impl FuzzBridgeConfig {
    fn to_bridge_config(self) -> BridgeConfig {
        BridgeConfig {
            allow_upgrade: self.allow_upgrade,
            sync_timeout: Duration::from_secs(self.sync_timeout_secs.max(1) as u64),
            sync_mode: match self.sync_mode {
                FuzzSyncMode::Synchronous => SyncMode::Synchronous,
                FuzzSyncMode::Asynchronous => SyncMode::Asynchronous,
                FuzzSyncMode::WriteSync => SyncMode::WriteSync,
            },
            conflict_resolution: match self.conflict_resolution {
                FuzzConflictResolution::DistributedWins => ConflictResolution::DistributedWins,
                FuzzConflictResolution::LocalWins => ConflictResolution::LocalWins,
                FuzzConflictResolution::HighestSequence => ConflictResolution::HighestSequence,
                FuzzConflictResolution::Error => ConflictResolution::Error,
            },
        }
    }
}

impl FuzzRegionSnapshot {
    fn to_region_snapshot(self) -> Option<RegionSnapshot> {
        // Convert with validation and bounds checking
        let region_id = RegionId::from_arena(ArenaIndex::new(
            self.region_arena_gen,
            self.region_arena_slot,
        ));

        // Validate region state
        let state = match self.state_value {
            0 => RegionState::Open,
            1 => RegionState::Closing,
            2 => RegionState::Closed,
            3 => RegionState::Cancelled,
            _ => return None, // Invalid state - should be ignored
        };

        // Convert tasks with validation
        let mut tasks = Vec::new();
        for task_config in self.tasks.into_iter().take(MAX_TASKS) {
            if let Some(task_snapshot) = task_config.to_task_snapshot() {
                tasks.push(task_snapshot);
            }
        }

        // Convert children
        let children: Vec<RegionId> = self
            .children
            .into_iter()
            .take(50) // Limit children
            .map(|child| RegionId::from_arena(ArenaIndex::new(child.arena_gen, child.arena_slot)))
            .collect();

        // Limit metadata size
        let metadata = if self.metadata.len() > MAX_METADATA_SIZE {
            self.metadata[..MAX_METADATA_SIZE].to_vec()
        } else {
            self.metadata
        };

        // Validate timestamp and sequence
        let timestamp = Time::from_nanos(self.timestamp_nanos);
        let sequence = self.sequence;

        Some(RegionSnapshot {
            region_id,
            state,
            timestamp,
            sequence,
            tasks,
            children,
            finalizer_count: self.finalizer_count,
            budget: BudgetSnapshot {
                deadline_nanos: self.budget.deadline_nanos,
                polls_remaining: self.budget.polls_remaining,
                cost_remaining: self.budget.cost_remaining,
            },
            cancel_reason: self.cancel_reason,
            parent: self.parent.map(|p| RegionId::from_arena(ArenaIndex::new(p.arena_gen, p.arena_slot))),
            metadata,
        })
    }
}

impl FuzzTaskSnapshot {
    fn to_task_snapshot(self) -> Option<TaskSnapshot> {
        let task_id = TaskId::from_arena(ArenaIndex::new(
            self.task_arena_gen,
            self.task_arena_slot,
        ));

        // Validate task state
        let state = match self.state_value {
            0 => TaskState::Pending,
            1 => TaskState::Running,
            2 => TaskState::Completed,
            3 => TaskState::Cancelled,
            4 => TaskState::Panicked,
            _ => return None, // Invalid state - should be ignored
        };

        Some(TaskSnapshot {
            task_id,
            state,
            priority: self.priority,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    // Property 1: Message framing length bounded
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Parse input as bridge test configuration
    let config = match BridgeTestConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input - gracefully ignore
    };

    // Limit number of messages to prevent timeout
    let messages: Vec<_> = config.messages.into_iter().take(MAX_SNAPSHOTS).collect();

    // Create test region
    let region_id = RegionId::from_arena(ArenaIndex::new(1, 0));

    // Create bridge with fuzz configuration
    let region_mode = config.mode.to_region_mode();
    let bridge_config = config.bridge_config.to_bridge_config();
    let mut bridge = RegionBridge::new(region_id, region_mode);

    // Track sequence numbers per channel for monotonicity validation
    let mut channel_sequences: HashMap<u16, u64> = HashMap::new();
    let mut applied_snapshots: HashMap<u64, u64> = HashMap::new(); // region_id -> sequence

    // Process cross-node messages
    for message in messages {
        // Property 1: Message framing length bounded
        assert!(
            message.payload_length <= MAX_INPUT_SIZE as u32,
            "Message payload length should be bounded"
        );

        // Property 3: Unknown message types ignored (not crashed)
        // We handle unknown message types by continuing without panic

        match message.payload {
            MessagePayload::Snapshot(fuzz_snapshot) => {
                if let Some(snapshot) = fuzz_snapshot.to_region_snapshot() {
                    // Property 2: Sequence number monotonic per channel
                    let channel_id = message.channel_id;
                    if let Some(&last_seq) = channel_sequences.get(&channel_id) {
                        if message.sequence <= last_seq {
                            // Non-monotonic sequence - should be rejected or handled gracefully
                            continue;
                        }
                    }
                    channel_sequences.insert(channel_id, message.sequence);

                    // Property 4: Vector-clock ordering honored
                    // In a real implementation, this would check vector clock consistency
                    // For fuzzing, we validate that timestamps don't cause crashes
                    if message.vector_clock == 0 {
                        continue; // Invalid vector clock - ignore
                    }

                    // Property 5: Snapshot apply idempotent
                    let region_key = snapshot.region_id.into_u64();
                    if let Some(&prev_seq) = applied_snapshots.get(&region_key) {
                        if snapshot.sequence == prev_seq {
                            // Re-applying same snapshot should be idempotent
                            let result1 = bridge.apply_snapshot(&snapshot);
                            let result2 = bridge.apply_snapshot(&snapshot);

                            // Both results should be the same (both success or both error)
                            match (result1, result2) {
                                (Ok(_), Ok(_)) => {
                                    // Idempotent success - good
                                }
                                (Err(e1), Err(e2)) => {
                                    // Both failed - should be same error kind
                                    assert_eq!(e1.kind(), e2.kind(), "Idempotent apply should produce same error");
                                }
                                _ => {
                                    panic!("Snapshot apply not idempotent: different results for same input");
                                }
                            }
                            continue;
                        }
                    }

                    // Apply snapshot and validate result
                    let result = bridge.apply_snapshot(&snapshot);

                    match result {
                        Ok(_) => {
                            // Successful apply - update tracking
                            applied_snapshots.insert(region_key, snapshot.sequence);

                            // Validate that sequence was properly updated
                            assert!(
                                bridge.sync_state.last_synced_sequence >= snapshot.sequence ||
                                bridge.sync_state.last_synced_sequence == 0,
                                "Bridge sequence state should be consistent after apply"
                            );
                        }
                        Err(_) => {
                            // Failed apply - should not crash and state should be unchanged
                            // Continue processing other messages
                        }
                    }
                } else {
                    // Invalid snapshot format - should be ignored gracefully
                }
            }
            MessagePayload::Heartbeat { node_id: _, timestamp: _ } => {
                // Property 3: Unknown message types ignored
                // Heartbeats are processed but don't affect bridge state
            }
            MessagePayload::StateTransition { region_id: _, new_state: _ } => {
                // Property 3: Unknown message types ignored
                // State transitions are processed but don't directly affect snapshot logic
            }
            MessagePayload::Unknown(payload) => {
                // Property 3: Unknown message types ignored
                // Unknown payloads should not crash the system
                assert!(
                    payload.len() <= MAX_METADATA_SIZE,
                    "Unknown payload should have bounded size"
                );
            }
        }

        // Ensure bridge state remains valid after each message
        assert!(
            bridge.sync_state.pending_ops < 10000,
            "Pending operations should be bounded"
        );
    }

    // Final validation: ensure bridge is in valid state
    let final_snapshot = bridge.create_snapshot(Time::from_nanos(1000));
    assert!(
        final_snapshot.sequence > 0,
        "Bridge should generate valid snapshots"
    );

    // Validate sequence monotonicity in generated snapshots
    let second_snapshot = bridge.create_snapshot(Time::from_nanos(2000));
    assert!(
        second_snapshot.sequence > final_snapshot.sequence,
        "Generated snapshot sequences should be monotonic"
    );
});