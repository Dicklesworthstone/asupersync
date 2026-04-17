#!/usr/bin/env python3
"""
Create simple binary seed files for distributed snapshot fuzzing.
Creates seeds based on the binary format specification.
"""

import struct
import os

def create_seed_files():
    seeds_dir = "/data/projects/asupersync/fuzz/seeds/distributed_snapshot"

    # Seed 1: Valid empty snapshot
    empty_snapshot = create_empty_snapshot()
    write_seed(seeds_dir, "empty_snapshot.bin", empty_snapshot)

    # Seed 2: Valid snapshot with one task
    simple_snapshot = create_simple_snapshot()
    write_seed(seeds_dir, "simple_snapshot.bin", simple_snapshot)

    # Seed 3: Boundary values
    boundary_snapshot = create_boundary_snapshot()
    write_seed(seeds_dir, "boundary_snapshot.bin", boundary_snapshot)

    # Seed 4: Invalid magic
    invalid_magic = bytearray(empty_snapshot)
    invalid_magic[0:4] = b"BADM"
    write_seed(seeds_dir, "invalid_magic.bin", invalid_magic)

    # Seed 5: Truncated after magic
    truncated = empty_snapshot[:5]
    write_seed(seeds_dir, "truncated_after_magic.bin", truncated)

def create_empty_snapshot():
    """Create a valid empty snapshot binary."""
    data = bytearray()

    # Magic (4 bytes)
    data.extend(b"SNAP")

    # Version (1 byte)
    data.append(1)

    # Region ID (8 bytes: index=1, generation=0)
    data.extend(struct.pack("<II", 1, 0))

    # State (1 byte: Open=0)
    data.append(0)

    # Timestamp (8 bytes: 0)
    data.extend(struct.pack("<Q", 0))

    # Sequence (8 bytes: 0)
    data.extend(struct.pack("<Q", 0))

    # Task count (4 bytes: 0)
    data.extend(struct.pack("<I", 0))

    # Children count (4 bytes: 0)
    data.extend(struct.pack("<I", 0))

    # Finalizer count (4 bytes: 0)
    data.extend(struct.pack("<I", 0))

    # Budget: deadline_nanos (1 byte presence + 0 means None)
    data.append(0)

    # Budget: polls_remaining (1 byte presence + 0 means None)
    data.append(0)

    # Budget: cost_remaining (1 byte presence + 0 means None)
    data.append(0)

    # Cancel reason (1 byte presence + 0 means None)
    data.append(0)

    # Parent (1 byte presence + 0 means None)
    data.append(0)

    # Metadata length (4 bytes: 0)
    data.extend(struct.pack("<I", 0))

    return bytes(data)

def create_simple_snapshot():
    """Create a snapshot with one task."""
    data = bytearray()

    # Header same as empty
    data.extend(b"SNAP")
    data.append(1)
    data.extend(struct.pack("<II", 42, 1))
    data.append(0)  # State: Open
    data.extend(struct.pack("<Q", 1234567890))  # Timestamp
    data.extend(struct.pack("<Q", 100))  # Sequence

    # Task count: 1
    data.extend(struct.pack("<I", 1))

    # Task 1: ID (index=10, generation=0), state=Running(1), priority=1
    data.extend(struct.pack("<II", 10, 0))  # Task ID
    data.append(1)  # State: Running
    data.append(1)  # Priority

    # Children count: 0
    data.extend(struct.pack("<I", 0))

    # Finalizer count: 5
    data.extend(struct.pack("<I", 5))

    # Budget: all None
    data.extend(b"\x00\x00\x00")

    # Cancel reason: None
    data.append(0)

    # Parent: None
    data.append(0)

    # Metadata: empty
    data.extend(struct.pack("<I", 0))

    return bytes(data)

def create_boundary_snapshot():
    """Create a snapshot with boundary values."""
    data = bytearray()

    # Header
    data.extend(b"SNAP")
    data.append(1)
    data.extend(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF))  # Max region ID
    data.append(3)  # State: Cancelled
    data.extend(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # Max timestamp
    data.extend(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # Max sequence

    # Task count: 1
    data.extend(struct.pack("<I", 1))

    # Task with max values
    data.extend(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF))  # Max task ID
    data.append(4)  # State: Panicked
    data.append(255)  # Max priority

    # Children count: 0
    data.extend(struct.pack("<I", 0))

    # Finalizer count: max
    data.extend(struct.pack("<I", 0xFFFFFFFF))

    # Budget: deadline with max value
    data.append(1)  # Has deadline
    data.extend(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))

    # Budget: polls with max value
    data.append(1)  # Has polls
    data.extend(struct.pack("<I", 0xFFFFFFFF))

    # Budget: cost with 0
    data.append(1)  # Has cost
    data.extend(struct.pack("<Q", 0))

    # Cancel reason: Some("Boundary test")
    data.append(1)  # Has cancel reason
    reason = b"Boundary test"
    data.extend(struct.pack("<I", len(reason)))
    data.extend(reason)

    # Parent: Some(max region ID)
    data.append(1)  # Has parent
    data.extend(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF))

    # Metadata: some bytes
    metadata = b"\x00\xFF\x55\xAA"
    data.extend(struct.pack("<I", len(metadata)))
    data.extend(metadata)

    return bytes(data)

def write_seed(dir_path, filename, data):
    """Write seed data to file."""
    filepath = os.path.join(dir_path, filename)
    with open(filepath, 'wb') as f:
        f.write(data)
    print(f"Created seed: {filepath} ({len(data)} bytes)")

if __name__ == "__main__":
    create_seed_files()