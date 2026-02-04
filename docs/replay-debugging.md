# Deterministic Replay Debugging

This guide explains how to use asupersync's deterministic replay debugging to diagnose async bugs. This capability is unique to asupersync's design and transforms debugging concurrent code from "add print statements and pray" to "record once, replay anywhere."

## Conceptual Overview

### What is Deterministic Replay?

Deterministic replay captures every decision point during program execution and allows you to replay that exact execution later. For concurrent programs, this includes:

- **Scheduling decisions**: Which task runs when
- **Time advancement**: Virtual time progression
- **RNG values**: Randomness consumed by the runtime
- **I/O results**: What data was read/written
- **Chaos injections**: Any fault injection events

When you replay a trace, the runtime makes the same decisions in the same order, producing identical behavior.

### Why Asupersync Uniquely Enables This

Traditional async runtimes use wall-clock time and non-deterministic scheduling. A bug that manifests in production may never reproduce locally.

Asupersync's Lab runtime is designed for determinism:

1. **Virtual time** - No wall-clock dependency; time only advances when you advance it
2. **Seeded scheduling** - Same seed produces same task ordering
3. **Trace recording** - All non-determinism sources are captured
4. **Capability isolation** - Effects flow through `Cx`, making them interceptable

This means: Same seed + same inputs = same execution, every time.

### Determinism Contract (Replay Preconditions)

Deterministic replay only works when the environment is fully controlled. The contract:

- **Same runtime + trace schema**: replays must use a compatible build and trace version.
- **Same Lab config**: seed, scheduler mode, and recording options must match the original run.
- **No ambient nondeterminism**: wall-clock, OS RNG, and global mutable state are forbidden inputs.
- **All effects through `Cx`**: I/O, timers, randomness, and cancellation must be intercepted.
- **Verify certificates when present**: if a trace includes proof/cert data, verify it before replay.

If any precondition is violated, replay should fail fast with explicit diagnostics rather than “best-effort.”

---

## Schedule Exploration (Seed Sweep + DPOR)

Asupersync ships a deterministic **schedule explorer** in `src/lab/explorer.rs` to
systematically vary task interleavings and discover concurrency bugs.

Two modes are available:
- **Seed sweep** (`ScheduleExplorer`): run many seeds, classify runs by Foata fingerprints, and track equivalence classes.
- **DPOR-guided** (`DporExplorer`): detect races, generate backtrack points, and explore alternative schedules with sleep-set pruning.

### When to Use

- Use **seed sweep** for quick coverage with minimal configuration.
- Use **DPOR-guided** when you need systematic exploration of race alternatives and coverage metrics.

### Example: Seed Sweep

```rust
use asupersync::lab::explorer::{ExplorerConfig, ScheduleExplorer};

let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 50));
let report = explorer.explore(|runtime| {
    // setup tasks, then run
    runtime.run_until_quiescent();
});

assert!(!report.has_violations());
println!("Unique classes: {}", report.unique_classes);
```

### Example: DPOR-Guided Exploration

```rust
use asupersync::lab::explorer::{DporExplorer, ExplorerConfig};

let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 25));
let report = explorer.explore(|runtime| {
    runtime.run_until_quiescent();
});

let coverage = explorer.dpor_coverage();
println!("Total races: {}", coverage.total_races);
println!("Backtrack points: {}", coverage.total_backtrack_points);
```

### Coverage Signals

DPOR coverage metrics include:
- `total_races` and `total_hb_races`
- `total_backtrack_points`, `pruned_backtrack_points`, and `sleep_pruned`
- `estimated_class_trend` for saturation signals

These metrics are deterministic and can be logged alongside the replay artifacts
described below.

## Deterministic Seed Registry + Artifact Schema (bd-30pc)

This section standardizes how seeds are chosen, propagated, logged, and stored in
repro artifacts. The goal is: **given a test_id + seed + inputs, anyone can
reproduce the exact run without guessing**.

### Seed Taxonomy

We use one **primary test seed** and derive all secondary seeds deterministically.

**Primary**
- `test_seed` (u64): The root seed for a test/E2E run.

**Derived (stable)**
- `schedule_seed`: scheduling RNG
- `entropy_seed`: capability RNG (Cx::random_*)
- `fault_seed`: chaos/fault injection
- `fuzz_seed`: property/fuzz generators

**Derivation rule (canonical):**
```
derived = H(test_seed || purpose_tag || scope_id)
```
Where `H` is a stable 64-bit hash (e.g., SplitMix64 or xxhash64) and
`purpose_tag` is a short ASCII tag (`"schedule"`, `"entropy"`, `"fault"`, `"fuzz"`).

### Seed Selection + Propagation (Required)

1. **Explicit seed wins**: if a test specifies a seed, use it.
2. **Environment override**: `ASUPERSYNC_SEED` (preferred) or `CI_SEED`.
3. **Fallback**: a constant seed (e.g., `0x_1234_5678_9abc_def0`) for local runs.

**Logging requirement** (unit + integration + E2E):
- Always log `test_id`, `test_seed`, and all derived seeds used.
- Emit these fields at test start **and** on failure.

### Artifact Schema (Repro Manifest)

Artifacts are emitted **only on failure** unless explicitly enabled. The
artifact root is controlled by `ASUPERSYNC_TEST_ARTIFACTS_DIR` so CI and
local runs can write to stable, deterministic locations.

**Directory layout (current harness):**
```
$ASUPERSYNC_TEST_ARTIFACTS_DIR/
  {test_id}/
    repro_manifest.json
    event_log.txt
    failed_assertions.json
    trace.async          # optional (if captured)
    inputs.bin           # optional (failing input payload)
  {test_id}_summary.json  # summary for the latest run
```

**Notes:**
- The `test_id` directory is sanitized (non-alphanumeric → `_`).
- The seed is stored in `repro_manifest.json` (future work may add a seed-hash
  subdirectory when bd-30pc lands).

**`repro_manifest.json` schema (minimum, current):**
```json
{
  "schema_version": 1,
  "seed": 42,
  "scenario_id": "cancel_request_drain_finalize",
  "entropy_seed": 123,
  "config_hash": "sha256:...",
  "trace_fingerprint": "sha256:...",
  "input_digest": "sha256:...",
  "oracle_violations": ["loser_drain"],
  "passed": false,
  "subsystem": "cancel",
  "invariant": "request_drain_finalize",
  "trace_file": "trace.async",
  "input_file": "inputs.bin",
  "env_snapshot": [["ASUPERSYNC_SEED","42"]],
  "phases_executed": ["setup","run","assertions"],
  "failure_reason": "cancelled completions count mismatch"
}
```

### Replay Workflow (Required)

1. Load `repro_manifest.json`.
2. Verify `schema_version`, `config_hash`, and `trace_schema`.
3. Re-run with `ASUPERSYNC_SEED` and same inputs (or load `trace.async` directly).
4. If divergence happens, emit a **divergence artifact** with the first mismatched event.

### Failure Triage + Repro Pipeline (bd-1ex7)

This is the standard failure triage pipeline used across unit, integration,
and E2E tests. It defines the minimum information needed to reproduce any
failure without guesswork.

**Failure summary (required):**
- Emit a structured log entry with `test_id`, `seed`, `subsystem`, `invariant`,
  and a human-readable `reason`.
- Use `TestContext::log_failure` so failures show up as:
  `TEST FAILURE — reproduce with seed 0x{SEED}` plus structured fields.

**Artifacts (required on failure when `ASUPERSYNC_TEST_ARTIFACTS_DIR` is set):**
- `event_log.txt` (high-signal event timeline)
- `failed_assertions.json` (all failed assertions)
- `repro_manifest.json` (canonical repro manifest)
- `trace.async` (if replay recording enabled)
- `inputs.bin` (if the failure depends on input bytes)

**Fast local repro workflow:**
1. Read `seed` + `test_id` from `repro_manifest.json` or the failure summary.
2. Re-run locally:
   `ASUPERSYNC_SEED=<seed> ASUPERSYNC_TEST_ARTIFACTS_DIR=target/test-artifacts cargo test <test_id> -- --nocapture`
3. Inspect trace artifacts (if present):
   `cargo run --bin asupersync trace info <trace.async>`
4. If two traces differ, use:
   `cargo run --bin asupersync trace diff <trace_a> <trace_b>`

### Deterministic Logging Rules (Reference)

- Avoid wall-clock timestamps; use lab time or event indices.
- All logs must include `test_id`, `seed`, `subsystem`, `phase`, and `outcome`.
- For multi-phase protocols, log phase transitions explicitly.

### When to Use Replay Debugging

| Scenario | Use Replay? |
|----------|------------|
| Intermittent test failure | **Yes** - Record the failing run, replay to investigate |
| Race condition | **Yes** - Replay lets you step through the race |
| Cancellation misbehavior | **Yes** - Trace cancellation propagation step by step |
| Timer interaction bugs | **Yes** - See exact firing order |
| Performance investigation | Maybe - Traces add overhead; use for correctness first |
| Production debugging | **Yes** - If you captured a trace before the bug |

---

## Getting Started

### Recording a Test Execution

Enable replay recording when creating the Lab runtime:

```rust
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::{RecorderConfig, TraceRecorder};

// Enable recording with default config
let config = LabConfig::new(42)
    .with_default_replay_recording();

let mut runtime = LabRuntime::new(config);

// Run your test
runtime.spawn_root(my_async_task);
runtime.run_until_quiescent();
```

For more control over what gets recorded:

```rust
use asupersync::trace::RecorderConfig;

// Custom recorder configuration
let recorder_config = RecorderConfig::enabled()
    .with_capacity(10_000)      // Pre-allocate for 10k events
    .with_rng(true)             // Record RNG values (verbose but complete)
    .with_wakers(false);        // Skip waker events (reduces noise)

let config = LabConfig::new(42)
    .with_replay_recording(recorder_config);
```

### Saving the Trace

After execution, extract and save the trace:

```rust
use asupersync::trace::file::TraceWriter;

// Get the trace from the runtime
let trace = runtime.take_replay_trace()
    .expect("replay recording was enabled");

// Save to file
let mut writer = TraceWriter::create("failing_test.trace")?;
writer.write_trace(&trace)?;
writer.finish()?;

println!("Saved {} events to failing_test.trace", trace.len());
```

### Loading and Replaying

Load a saved trace and create a replayer:

```rust
use asupersync::trace::file::TraceReader;
use asupersync::trace::replayer::{TraceReplayer, ReplayMode};

// Load the trace
let trace = TraceReader::open("failing_test.trace")?.read_all()?;

println!("Loaded trace with seed: {}", trace.metadata.seed);
println!("Event count: {}", trace.len());

// Create a replayer
let mut replayer = TraceReplayer::new(trace);
```

### Basic Debugging Workflow

The typical workflow:

1. **Record**: Run your test with recording enabled
2. **Save**: If it fails, save the trace
3. **Load**: Load the trace in a debugging session
4. **Step**: Walk through events to find the bug
5. **Fix**: Make your change
6. **Verify**: Replay the trace to confirm the fix

```rust
// Step through the trace
replayer.set_mode(ReplayMode::Step);

while let Some(event) = replayer.next() {
    println!("[{}] {:?}", replayer.current_index(), event);

    // Your analysis here...
}

if replayer.is_completed() {
    println!("Replay complete");
}
```

---

## Advanced Usage

### Stepping Through Execution

Use `ReplayMode::Step` to stop after each event:

```rust
replayer.set_mode(ReplayMode::Step);

while let Some(event) = replayer.next() {
    // Examine the event
    match event {
        ReplayEvent::TaskScheduled { task, at_tick } => {
            println!("Tick {}: Task {:?} scheduled", at_tick, task);
        }
        ReplayEvent::TaskCompleted { task, outcome } => {
            println!("Task {:?} completed with outcome {}", task, outcome);
        }
        ReplayEvent::ChaosInjection { kind, task, data } => {
            println!("Chaos: kind={} task={:?} data={}", kind, task, data);
        }
        _ => {}
    }

    // Optionally wait for user input
    // readline().unwrap();
}
```

### Setting Breakpoints

Run until a specific point:

```rust
use asupersync::trace::replayer::Breakpoint;

// Run until tick 500
replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(500)));
while let Some(event) = replayer.next() {
    if replayer.at_breakpoint() {
        println!("Hit breakpoint at event {}", replayer.current_index());
        break;
    }
}

// Run until a specific task is scheduled
let target_task = CompactTaskId::from_raw(42);
replayer.set_mode(ReplayMode::RunTo(Breakpoint::Task(target_task)));

// Run until event index 1000
replayer.set_mode(ReplayMode::RunTo(Breakpoint::EventIndex(1000)));
```

### Inspecting State at Each Step

Combine replay with state inspection:

```rust
// Track state as you replay
let mut task_states: HashMap<CompactTaskId, &'static str> = HashMap::new();
let mut scheduled_count = 0;
let mut completed_count = 0;

while let Some(event) = replayer.next() {
    match event {
        ReplayEvent::TaskScheduled { task, .. } => {
            task_states.insert(*task, "scheduled");
            scheduled_count += 1;
        }
        ReplayEvent::TaskYielded { task } => {
            task_states.insert(*task, "yielded");
        }
        ReplayEvent::TaskCompleted { task, .. } => {
            task_states.insert(*task, "completed");
            completed_count += 1;
        }
        _ => {}
    }

    // Print summary at intervals
    if replayer.current_index() % 100 == 0 {
        println!("Progress: {} scheduled, {} completed",
                 scheduled_count, completed_count);
    }
}
```

### Handling Divergence Errors

If you modify code and replay, the execution may diverge:

```rust
use asupersync::trace::replayer::ReplayError;

match replayer.verify_event(&actual_event) {
    Ok(()) => {
        // Execution matches trace
    }
    Err(ReplayError::Divergence(div)) => {
        eprintln!("Divergence at event {}!", div.index);
        eprintln!("Expected: {:?}", div.expected);
        eprintln!("Actual:   {:?}", div.actual);
        eprintln!("Context:  {}", div.context);

        // This tells you where your fix changed behavior
    }
    Err(ReplayError::UnexpectedEnd { index }) => {
        eprintln!("Trace ended at event {}, but execution continued", index);
    }
    Err(e) => {
        eprintln!("Replay error: {}", e);
    }
}
```

### Divergence Diagnostics Protocol (spec)

When a replay diverges, the diagnostics should pinpoint **where** and **why**
with minimal noise. The engine should emit a structured report that includes:

- First divergence index (event number).
- Expected vs actual event (compact form, redacted payloads if large).
- Schedule certificate prefix hash (determinism witness).
- Trace equivalence fingerprint at the divergence point.
- Minimal context window (last N events + next M expected events).
- Involved task/region IDs and scheduler lane.

#### Certificate-based divergence (recommended)

The runtime already maintains a schedule certificate (hash of scheduling
decisions). A replay should recompute this certificate and compare at every
step. If the certificate diverges before the event stream diverges, report that
earlier certificate mismatch to avoid chasing the wrong symptom.

Conceptual report:

```
DivergenceReport = {
  index: u64,
  expected: EventSummary,
  actual: EventSummary,
  schedule_cert_expected: Hash,
  schedule_cert_actual: Hash,
  trace_fingerprint: Hash,
  lane: DispatchLane,
  task_id: TaskId,
  region_id: RegionId,
  context: [EventSummary; N]
}
```

#### Minimal context payloads

To keep diagnostics lightweight:
- Event summaries include IDs, kinds, and hashes, but avoid large buffers.
- Context window is capped (e.g., last 16 events).
- Divergence payloads are deterministic and stable across replays.

#### Replay workflow with diagnostics

1. Recompute schedule certificate hash per step.
2. Compare expected vs actual event, plus certificate hashes.
3. On first mismatch, emit `DivergenceReport` and stop.
4. If replay finishes but certificates differ, emit a certificate-only mismatch.

---

## Real-World Examples

### Example 1: Race Condition

**Problem**: A test occasionally fails with "message received out of order."

```rust
#[test]
fn test_message_ordering() {
    // This test fails ~10% of the time
    let config = LabConfig::from_time()  // Random seed for variety
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);

    // ... test code that spawns sender and receiver ...

    runtime.run_until_quiescent();

    // On failure, save the trace
    if !messages_in_order(&received) {
        let trace = runtime.take_replay_trace().unwrap();
        TraceWriter::create("race_failure.trace")
            .unwrap()
            .write_trace(&trace)
            .unwrap()
            .finish()
            .unwrap();

        panic!("Messages out of order! Trace saved to race_failure.trace");
    }
}
```

**Debugging**:

```rust
fn analyze_race() {
    let trace = TraceReader::open("race_failure.trace")
        .unwrap()
        .read_all()
        .unwrap();

    let mut replayer = TraceReplayer::new(trace);
    replayer.set_mode(ReplayMode::Step);

    // Find the interleaving
    let mut sender_events = vec![];
    let mut receiver_events = vec![];

    while let Some(event) = replayer.next() {
        if let ReplayEvent::TaskScheduled { task, at_tick } = event {
            // Assuming task IDs: sender=1, receiver=2
            if task.as_raw() == 1 {
                sender_events.push(*at_tick);
            } else if task.as_raw() == 2 {
                receiver_events.push(*at_tick);
            }
        }
    }

    println!("Sender scheduled at ticks: {:?}", sender_events);
    println!("Receiver scheduled at ticks: {:?}", receiver_events);
    // Now you can see the exact interleaving that caused the bug
}
```

### Example 2: Cancellation Bug

**Problem**: A task doesn't clean up properly when cancelled.

```rust
#[test]
fn test_cancellation_cleanup() {
    let config = LabConfig::new(42)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);

    // Spawn a task and cancel it mid-operation
    let handle = runtime.spawn_root(async |cx| {
        let _permit = resource.acquire(cx).await?;
        // Long operation that gets cancelled
        cx.sleep(Duration::from_secs(10)).await;
        // Cleanup code that should run
        permit.release();
        Outcome::ok(())
    });

    runtime.step_n(100);
    runtime.cancel(handle);
    runtime.run_until_quiescent();

    // Bug: permit wasn't released!
    if resource.permits_held() > 0 {
        let trace = runtime.take_replay_trace().unwrap();
        save_trace(&trace, "cancel_bug.trace");
        panic!("Resource leak after cancellation");
    }
}
```

**Debugging**:

```rust
fn analyze_cancellation() {
    let trace = TraceReader::open("cancel_bug.trace")
        .unwrap()
        .read_all()
        .unwrap();

    let mut replayer = TraceReplayer::new(trace);

    // Find cancellation events
    while let Some(event) = replayer.next() {
        match event {
            ReplayEvent::ChaosInjection { kind, task, .. }
                if *kind == chaos_kind::CANCEL => {
                println!("Cancel injected for task {:?} at event {}",
                         task, replayer.current_index());
            }
            ReplayEvent::TaskCompleted { task, outcome } => {
                println!("Task {:?} completed with outcome {} at event {}",
                         task, outcome, replayer.current_index());
                // Check if outcome indicates proper cancellation handling
            }
            _ => {}
        }
    }

    // The trace shows the task was cancelled but never got to run
    // its cleanup code because sleep() didn't checkpoint properly
}
```

### Example 3: Timer Interaction

**Problem**: Timers fire in unexpected order.

```rust
#[test]
fn test_timer_ordering() {
    let config = LabConfig::new(42)
        .with_default_replay_recording();
    let mut runtime = LabRuntime::new(config);

    runtime.spawn_root(async |cx| {
        // These should complete in order
        let t1 = cx.sleep(Duration::from_millis(100));
        let t2 = cx.sleep(Duration::from_millis(200));
        let t3 = cx.sleep(Duration::from_millis(300));

        let mut order = vec![];

        join!(
            async { t1.await; order.push(1); },
            async { t2.await; order.push(2); },
            async { t3.await; order.push(3); },
        );

        assert_eq!(order, vec![1, 2, 3], "Timers fired out of order!");
        Outcome::ok(())
    });

    runtime.run_until_quiescent();
}
```

**Debugging**:

```rust
fn analyze_timers() {
    let trace = TraceReader::open("timer_bug.trace")
        .unwrap()
        .read_all()
        .unwrap();

    let mut replayer = TraceReplayer::new(trace);

    // Track timer lifecycle
    let mut timers: HashMap<u64, (u128, Option<u128>)> = HashMap::new();

    while let Some(event) = replayer.next() {
        match event {
            ReplayEvent::TimerCreated { timer_id, deadline_nanos } => {
                timers.insert(*timer_id, (*deadline_nanos, None));
                println!("Timer {} created, deadline={}ns", timer_id, deadline_nanos);
            }
            ReplayEvent::TimerFired { timer_id } => {
                if let Some((deadline, fired)) = timers.get_mut(timer_id) {
                    *fired = Some(replayer.current_index() as u128);
                    println!("Timer {} fired at event {} (deadline was {}ns)",
                             timer_id, replayer.current_index(), deadline);
                }
            }
            ReplayEvent::TimeAdvanced { from_nanos, to_nanos } => {
                println!("Time advanced: {}ns -> {}ns", from_nanos, to_nanos);
            }
            _ => {}
        }
    }

    // Analyze firing order vs deadline order
    let mut by_deadline: Vec<_> = timers.iter().collect();
    by_deadline.sort_by_key(|(_, (deadline, _))| *deadline);

    println!("\nTimer analysis:");
    for (id, (deadline, fired)) in by_deadline {
        println!("  Timer {}: deadline={}ns, fired_at_event={:?}",
                 id, deadline, fired);
    }
}
```

---

## Best Practices

### Keep Traces Small

Large traces are slow to save and load. Filter what you record:

```rust
// For normal testing, skip verbose events
let config = RecorderConfig::enabled()
    .with_rng(false)      // Skip RNG values unless debugging randomness
    .with_wakers(false);  // Skip waker events unless debugging wake patterns
```

### Version Control Trace Files

Save trace files for known regressions:

```
tests/
  traces/
    issue_123_race_condition.trace
    issue_456_cancellation_leak.trace
```

Then add regression tests:

```rust
#[test]
fn regression_issue_123() {
    let trace = TraceReader::open("tests/traces/issue_123_race_condition.trace")
        .unwrap()
        .read_all()
        .unwrap();

    // Replay with the fixed code
    let mut replayer = TraceReplayer::new(trace);

    // Verify the fix - execution should now diverge at the bug point
    // in a good way (the fix prevents the race)
}
```

### Combine with Tracing

For richer context, enable the tracing integration:

```rust
// Before running, enable tracing subscriber
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::TRACE)
    .init();

// The replay events will correlate with tracing spans
// Use the task IDs to cross-reference
```

---

## Troubleshooting

### "Trace file not found"

Ensure you saved the trace before the runtime was dropped:

```rust
// Wrong: runtime dropped, trace lost
{
    let mut runtime = LabRuntime::new(config);
    runtime.run_until_quiescent();
} // trace gone!

// Right: extract trace before drop
{
    let mut runtime = LabRuntime::new(config);
    runtime.run_until_quiescent();
    let trace = runtime.take_replay_trace();  // Extract first
}
```

### "Version mismatch"

The trace file version doesn't match the current code:

```rust
// The trace was recorded with an older/newer schema version
Err(ReplayError::VersionMismatch { expected: 1, found: 2 })

// Solution: Re-record the trace with the current version
// Or use the git revision that matches the trace
```

### "Divergence at event 0"

The trace's seed doesn't match:

```rust
// Make sure you're using the same seed
let trace = TraceReader::open("test.trace")?.read_all()?;
let config = LabConfig::new(trace.metadata.seed);  // Use trace's seed
```

### "Events seem wrong"

Verify the trace was recorded correctly:

```rust
// Dump raw events to inspect
for (i, event) in trace.events.iter().enumerate().take(50) {
    println!("[{:4}] {:?}", i, event);
}
```

### Large trace files

Traces grow linearly with execution length. For long-running tests:

```rust
// Limit trace size
let config = RecorderConfig::enabled()
    .with_capacity(100_000);  // Cap at 100k events

// Or record only the interesting part
runtime.step_n(900_000);  // Skip to near the bug
runtime.enable_recording();  // Start recording
runtime.step_n(1000);  // Capture just the problematic section
```

---

## API Reference

### RecorderConfig

```rust
pub struct RecorderConfig {
    pub enabled: bool,           // Master switch
    pub initial_capacity: usize, // Pre-allocated event buffer
    pub record_rng: bool,        // Include RNG values
    pub record_wakers: bool,     // Include waker events
}

impl RecorderConfig {
    pub fn enabled() -> Self;           // Recording on, all features
    pub fn disabled() -> Self;          // Recording off
    pub fn with_capacity(self, n: usize) -> Self;
    pub fn with_rng(self, b: bool) -> Self;
    pub fn with_wakers(self, b: bool) -> Self;
}
```

### TraceReplayer

```rust
pub struct TraceReplayer {
    // ...
}

impl TraceReplayer {
    pub fn new(trace: ReplayTrace) -> Self;
    pub fn metadata(&self) -> &TraceMetadata;
    pub fn event_count(&self) -> usize;
    pub fn current_index(&self) -> usize;
    pub fn is_completed(&self) -> bool;
    pub fn at_breakpoint(&self) -> bool;

    pub fn set_mode(&mut self, mode: ReplayMode);
    pub fn mode(&self) -> &ReplayMode;

    pub fn peek(&self) -> Option<&ReplayEvent>;
    pub fn next(&mut self) -> Option<&ReplayEvent>;
    pub fn reset(&mut self);
    pub fn seek(&mut self, index: usize) -> Result<(), ReplayError>;

    pub fn verify_event(&self, actual: &ReplayEvent) -> Result<(), ReplayError>;
}
```

### ReplayMode and Breakpoint

```rust
pub enum ReplayMode {
    Run,                    // Run to completion
    Step,                   // Stop after each event
    RunTo(Breakpoint),      // Run until breakpoint hit
}

pub enum Breakpoint {
    Tick(u64),              // Stop at specific tick/step
    Task(CompactTaskId),    // Stop when task scheduled
    EventIndex(usize),      // Stop at event index
}
```

### TraceWriter / TraceReader

```rust
// Writing
let mut writer = TraceWriter::create("trace.bin")?;
writer.write_trace(&trace)?;
writer.finish()?;

// Reading
let reader = TraceReader::open("trace.bin")?;
let metadata = reader.metadata();
let trace = reader.read_all()?;

// Streaming read (large traces)
for event in reader.events() {
    let event = event?;
    // process event
}
```

### ReplayEvent Variants

```rust
pub enum ReplayEvent {
    // Task lifecycle
    TaskScheduled { task: CompactTaskId, at_tick: u64 },
    TaskYielded { task: CompactTaskId },
    TaskCompleted { task: CompactTaskId, outcome: u8 },
    TaskSpawned { task: CompactTaskId, region: CompactRegionId, at_tick: u64 },

    // Time
    TimeAdvanced { from_nanos: u128, to_nanos: u128 },
    TimerCreated { timer_id: u64, deadline_nanos: u128 },
    TimerFired { timer_id: u64 },
    TimerCancelled { timer_id: u64 },

    // I/O
    IoReady { token: u64, readiness: u8 },
    IoResult { token: u64, bytes: i64 },
    IoError { token: u64, error_kind: u8 },

    // RNG
    RngSeed { seed: u64 },
    RngValue { value: u64 },

    // Chaos
    ChaosInjection { kind: u8, task: Option<CompactTaskId>, data: u64 },

    // Wakers
    WakerWake { task: CompactTaskId },
    WakerBatchWake { count: u32 },
}
```

---

## See Also

- [Lab Runtime Configuration](../README.md#lab-runtime-configuration) - How to configure the Lab runtime
- [Troubleshooting](../README.md#troubleshooting) - Common issues and solutions
- [Formal Semantics](../asupersync_v4_formal_semantics.md) - The math behind determinism
