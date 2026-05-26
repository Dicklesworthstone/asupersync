# Byzantine Consensus Implementation

This module provides a Practical Byzantine Fault Tolerance (PBFT) consensus algorithm implementation for the asupersync distributed runtime.

## Overview

PBFT is a Byzantine fault-tolerant consensus algorithm that provides safety and liveness guarantees in partially synchronous networks with up to f Byzantine faults in a system of 3f+1 replicas.

## Components

### Core Types (`types.rs`)
- `ReplicaId`: Unique identifier for each replica
- `ViewNumber`: View number for leader election
- `SequenceNumber`: Request ordering within views
- `MessageDigest`: Cryptographic digest for message verification
- `ConsensusRequest`: Client request for consensus
- `ConsensusBatch`: Batch of requests for efficiency

### PBFT Protocol (`pbft.rs`)
- `PbftConfig`: Configuration for fault tolerance and timeouts
- `PbftNode`: Individual replica state machine
- `PbftConsensus`: High-level consensus interface
- `PbftTransport`: Abstract transport for message delivery

### Message Types
- `PrePrepare`: Primary proposes request ordering
- `Prepare`: Replicas agree on ordering
- `Commit`: Replicas commit to execution
- `ViewChange`: Request new primary election
- `NewView`: Establish new view with new primary

## Protocol Flow

1. **Normal Case Operation:**
   - Client sends request to primary replica
   - Primary creates batch and sends PrePrepare message
   - Replicas validate and send Prepare messages
   - After 2f+1 Prepare messages, replicas send Commit
   - After 2f+1 Commit messages, replicas execute requests

2. **View Change:**
   - Triggered when primary is suspected of being faulty
   - Replicas stop accepting messages from current primary
   - New primary selected based on view number

## Safety Properties

- **Agreement:** All non-faulty replicas agree on request ordering
- **Validity:** Only client requests are ordered and executed
- **Integrity:** Requests are executed exactly once in the agreed order

## Liveness Properties

- **Termination:** All client requests eventually get executed
- **Requires:** Partial synchrony (bounded message delays after some time)

## Usage Example

```rust
use asupersync::distributed::consensus::{
    PbftConfig, PbftConsensus, ReplicaId, ConsensusRequest
};

// Create configuration for 4 replicas tolerating 1 Byzantine fault
let config = PbftConfig::new(4, 1)?;

// Create consensus node
let replica_id = ReplicaId::new("replica-0".to_string());
let consensus = PbftConsensus::new(replica_id, config, transport)?;

// Submit request
let request = ConsensusRequest::new(
    "client-1".to_string(),
    Time::from_millis(1000),
    b"operation data".to_vec(),
);

let response = consensus.submit(&cx, request).await?;
```

## Implementation Notes

- Current implementation provides basic PBFT protocol
- View change is simplified (not fully implemented)
- Message authentication uses SHA-256 digests
- Transport is abstract to allow different network backends
- Designed to integrate with asupersync's structured concurrency

## Future Enhancements

- Complete view change implementation
- Digital signature support for message authentication
- Garbage collection for old log entries
- Checkpoint protocol for log compaction
- Dynamic reconfiguration support