#!/usr/bin/env python3
"""
Generate seed files for distributed snapshot fuzzing.
Creates binary snapshot seeds using a Rust helper program.
"""

import subprocess
import os
import tempfile

# Rust code to generate snapshot seeds
rust_seed_generator = '''
use asupersync::distributed::snapshot::{RegionSnapshot, TaskSnapshot, TaskState, BudgetSnapshot};
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;

fn main() {
    let seeds_dir = std::env::args().nth(1).expect("Need seeds directory path");

    // Seed 1: Empty snapshot
    let empty = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(1, 0)));
    write_seed(&seeds_dir, "empty_snapshot", &empty);

    // Seed 2: Simple snapshot with one task
    let mut simple = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(42, 1)));
    simple.state = RegionState::Open;
    simple.timestamp = Time::from_nanos(1234567890);
    simple.sequence = 100;
    simple.finalizer_count = 5;
    simple.tasks.push(TaskSnapshot {
        task_id: TaskId::from_arena(ArenaIndex::new(10, 0)),
        state: TaskState::Running,
        priority: 1,
    });
    write_seed(&seeds_dir, "simple_snapshot", &simple);

    // Seed 3: Complex snapshot with multiple tasks and children
    let mut complex = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(100, 5)));
    complex.state = RegionState::Closing;
    complex.timestamp = Time::from_nanos(9876543210);
    complex.sequence = u64::MAX;
    complex.finalizer_count = u32::MAX;

    // Add multiple tasks in different states
    complex.tasks.push(TaskSnapshot {
        task_id: TaskId::from_arena(ArenaIndex::new(1, 0)),
        state: TaskState::Pending,
        priority: 0,
    });
    complex.tasks.push(TaskSnapshot {
        task_id: TaskId::from_arena(ArenaIndex::new(2, 1)),
        state: TaskState::Completed,
        priority: 255,
    });
    complex.tasks.push(TaskSnapshot {
        task_id: TaskId::from_arena(ArenaIndex::new(u32::MAX, u32::MAX)),
        state: TaskState::Cancelled,
        priority: 128,
    });

    // Add child regions
    complex.children.push(RegionId::from_arena(ArenaIndex::new(50, 2)));
    complex.children.push(RegionId::from_arena(ArenaIndex::new(51, 3)));

    // Set budget with all optional fields
    complex.budget = BudgetSnapshot {
        deadline_nanos: Some(u64::MAX),
        polls_remaining: Some(1000),
        cost_remaining: Some(0),
    };

    // Set cancel reason and parent
    complex.cancel_reason = Some("Test cancellation reason".to_string());
    complex.parent = Some(RegionId::from_arena(ArenaIndex::new(99, 4)));

    // Add metadata
    complex.metadata = vec![0xFF, 0x00, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF];

    write_seed(&seeds_dir, "complex_snapshot", &complex);

    // Seed 4: Boundary values snapshot
    let mut boundary = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(0, 0)));
    boundary.state = RegionState::Cancelled;
    boundary.timestamp = Time::from_nanos(0);
    boundary.sequence = 0;
    boundary.finalizer_count = 0;

    // Add task with boundary values
    boundary.tasks.push(TaskSnapshot {
        task_id: TaskId::from_arena(ArenaIndex::new(0, 0)),
        state: TaskState::Panicked,
        priority: 0,
    });

    write_seed(&seeds_dir, "boundary_snapshot", &boundary);

    // Seed 5: UTF-8 edge cases snapshot
    let mut utf8_test = RegionSnapshot::empty(RegionId::from_arena(ArenaIndex::new(123, 456)));
    utf8_test.cancel_reason = Some("Unicode test: 你好世界🌍🚀".to_string());
    utf8_test.metadata = "Special chars: ñáéíóú".as_bytes().to_vec();

    write_seed(&seeds_dir, "utf8_snapshot", &utf8_test);
}

fn write_seed(dir: &str, name: &str, snapshot: &RegionSnapshot) {
    let bytes = snapshot.to_bytes();
    let path = format!("{}/{}.bin", dir, name);
    std::fs::write(&path, bytes).expect(&format!("Failed to write {}", path));
    println!("Generated seed: {} ({} bytes)", path, bytes.len());
}
'''

def generate_seeds():
    """Generate snapshot seed files using Rust code."""

    # Create temporary Rust file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rs', delete=False) as f:
        f.write(rust_seed_generator)
        rust_file = f.name

    try:
        # Seeds directory
        seeds_dir = "/data/projects/asupersync/fuzz/seeds/distributed_snapshot"

        # Compile and run the Rust seed generator
        print("Compiling seed generator...")
        compile_result = subprocess.run([
            "rustc", "--edition", "2024",
            "-L", "/data/projects/asupersync/target/debug/deps",
            "--extern", "asupersync=/data/projects/asupersync/target/debug/libasupersync.rlib",
            "-o", "/tmp/snapshot_seed_gen",
            rust_file
        ], capture_output=True, text=True)

        if compile_result.returncode != 0:
            print(f"Compilation failed: {compile_result.stderr}")
            return False

        print("Generating seeds...")
        run_result = subprocess.run([
            "/tmp/snapshot_seed_gen", seeds_dir
        ], capture_output=True, text=True)

        if run_result.returncode != 0:
            print(f"Seed generation failed: {run_result.stderr}")
            return False

        print(run_result.stdout)
        print("Seed generation completed successfully!")
        return True

    finally:
        # Clean up
        if os.path.exists(rust_file):
            os.unlink(rust_file)
        if os.path.exists("/tmp/snapshot_seed_gen"):
            os.unlink("/tmp/snapshot_seed_gen")

if __name__ == "__main__":
    generate_seeds()