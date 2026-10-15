#!/usr/bin/env python3
"""Apply the remaining GH#83 correction to its reviewed source, never a ref.

The Parker prerequisite is already on main. Preserve it and reject source drift.
The existing reactor-handoff workflow compiles/tests the resulting complete tree
before exporting Git objects; this script neither commits nor pushes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "src/runtime/io_driver.rs": "58f70151290ad75cb8fc641c820333f7c58181cc",
    "src/runtime/scheduler/three_lane.rs": "0c6939fbe7788963668d3660491cb649b8f46445",
    "src/runtime/scheduler/worker.rs": "8a5fa95d03882c02f5ffbeb79be415cd8ff253d7",
}
PATCH = r'''diff --git a/src/runtime/io_driver.rs b/src/runtime/io_driver.rs
--- a/src/runtime/io_driver.rs
+++ b/src/runtime/io_driver.rs
@@ -693,2 +693,12 @@
 impl IoDriverHandle {
+    /// Whether this handle's poll election currently has an owner.
+    ///
+    /// This is a readiness hint, not a reservation. Followers sample it only
+    /// after publishing their Parker waiter; the paired handoff fence makes
+    /// either that sample or the leader's waiter scan observe the other side.
+    #[inline]
+    pub(crate) fn is_polling(&self) -> bool {
+        self.is_polling.load(Ordering::Acquire)
+    }
+
     /// Creates a handle, reusing the dispatcher of this reactor allocation
 diff --git a/src/runtime/scheduler/three_lane.rs b/src/runtime/scheduler/three_lane.rs
--- a/src/runtime/scheduler/three_lane.rs
+++ b/src/runtime/scheduler/three_lane.rs
@@ -211,2 +211,3 @@
 const IDLE_IO_POLL_MAX_TIMEOUT: Duration = Duration::from_millis(250);
+const IO_POLL_ERROR_RETRY_NANOS: u64 = 1_000_000;
 #[cfg(any(test, feature = "test-internals"))]
@@ -350,2 +351,4 @@
     Follower,
+    /// This worker's poll failed; no other leader is implied.
+    PollError,
     /// No I/O progress from this worker (leader quick miss or no I/O driver).
@@ -371,3 +374,4 @@
     /// This thread is the woken task's runtime's idle reactor leader. It
-    /// dispatches right after the turn, so no other worker needs waking.
+    /// keeps the task wake, then promotes a reactor follower before polling
+    /// the selected task. The handoff does not re-arm the reactor.
     RunHere,
@@ -549,3 +553,14 @@
+
+/// Do not let a stale due entry turn a persistent reactor error into a spin.
+/// Future deadlines earlier than the retry cap still retain their wake time.
+#[inline]
+fn poll_error_retry_nanos(next_deadline: Option<Time>, now: Time) -> u64 {
+    next_deadline
+        .filter(|deadline| *deadline > now)
+        .map_or(IO_POLL_ERROR_RETRY_NANOS, |deadline| {
+            deadline.duration_since(now).min(IO_POLL_ERROR_RETRY_NANOS)
+        })
+}
 
 #[inline]
 fn record_backoff_deadline_selection(
@@ -1060,3 +1075,30 @@
+
+    /// Hand reactor responsibility to one idle peer before executing a task.
+    /// No busy-worker fallback permit, reactor wake, or host callback: unlike
+    /// a queue wake, a handoff exists only to give a parked peer a poll turn.
+    #[inline]
+    fn promote_follower(&self) -> bool {
+        let count = self.parkers.len();
+        if count < 2 {
+            return false;
+        }
+
+        // Paired with Parker's waiter-publication fence. The old poll flag
+        // was released before this scan; a late follower either participates
+        // in the scan or observes that release in park[_timeout]_unless.
+        std::sync::atomic::fence(Ordering::SeqCst);
+        let start = self.next_wake.fetch_add(1, Ordering::Relaxed);
+        let mut slot = self.mask.map_or_else(|| start % count, |mask| start & mask);
+        for _ in 0..count {
+            if self.parkers[slot].unpark_if_waiting() {
+                return true;
+            }
+            // Normalize before incrementing, also covering cursor wrap for
+            // non-power-of-two worker counts.
+            slot = if slot + 1 == count { 0 } else { slot + 1 };
+        }
+        false
+    }
 
     #[inline]
     fn wake_one_parker_prefer_waiter(&self) -> bool {
@@ -5517,8 +5559,9 @@
             Ok(None) | Err(_) if kept_a_wake => IoPhaseOutcome::Progress,
-            Ok(None) | Err(_) => {
+            Ok(None) => {
                 // Another thread is already polling (we are a follower).
                 // Do not busy loop. Proceed to backoff/park logic.
                 IoPhaseOutcome::Follower
             }
+            Err(_) => IoPhaseOutcome::PollError,
         }
     }
@@ -5633,3 +5676,6 @@
         let lifo_was_enabled = std::mem::replace(&mut self.lifo_enabled, true);
+        // Also carried by a promoted follower while the reactor is free:
+        // its next dispatch can select owner-local work before re-election.
+        let mut left_reactor = false;
 
         'dispatch: loop {
@@ -5650,3 +5696,9 @@
             if let Some(task) = self.next_task() {
                 self.reset_empty_backoff();
+                if std::mem::take(&mut left_reactor) {
+                    // The selected task can spend arbitrarily long in poll.
+                    // Keeping its first wake locally must not strand I/O or
+                    // shared timers behind that task (GH #83).
+                    self.coordinator.promote_follower();
+                }
                 self.execute(task);
@@ -5667,2 +5719,6 @@
             let io_phase = self.drive_io_phase(return_when_idle);
+            // Include a successful zero-timeout miss: runnable work can race
+            // the idle probe. Only a follower knows another poller owns I/O.
+            left_reactor = self.io_driver.is_some()
+                && !matches!(io_phase, IoPhaseOutcome::Follower);
             if matches!(io_phase, IoPhaseOutcome::Progress) {
@@ -5739,7 +5795,6 @@
                         }
-                        // Park with timeout based on next timer deadline.
-                        // If we are the IO leader, we shouldn't even be here (we'd block in epoll).
-                        // If we are a follower, we just park until a deadline or woken.
+                        // Followers keep only their owner-local deadline;
+                        // the current reactor leader drives shared deadlines.
                         let timer_deadline = self
                             .timer_driver
                             .as_ref()
@@ -5759,4 +5814,85 @@
                             global_deadline,
                         );
 
+                        if matches!(io_phase, IoPhaseOutcome::NoProgress)
+                            && self.io_driver.is_some()
+                        {
+                            // Work that forced a quick poll can disappear
+                            // while it runs. Re-elect instead of parking with
+                            // no poller, but retain the exhausted-backoff
+                            // kernel wait for a due/stale deadline signal.
+                            let now = self.current_scheduler_time();
+                            if next_deadline.is_some_and(|deadline| deadline <= now) {
+                                record_backoff_timeout_park(
+                                    &mut self.preemption_metrics,
+                                    io_phase,
+                                    STALE_DUE_DEADLINE_PARK_NANOS,
+                                );
+                                self.parker.park_timeout(Duration::from_nanos(
+                                    STALE_DUE_DEADLINE_PARK_NANOS,
+                                ));
+                                // Keep the spent spin/yield budget until work
+                                // actually dispatches or this signal clears.
+                            } else {
+                                self.reset_empty_backoff();
+                            }
+                            break;
+                        }
+
+                        if matches!(io_phase, IoPhaseOutcome::Follower) {
+                            let io = self.io_driver.as_ref().expect("follower has an I/O driver");
+                            if let Some(deadline) = next_deadline {
+                                let now = self.current_scheduler_time();
+                                let nanos = if deadline > now {
+                                    deadline.duration_since(now)
+                                } else {
+                                    STALE_DUE_DEADLINE_PARK_NANOS
+                                };
+                                record_backoff_timeout_park(
+                                    &mut self.preemption_metrics,
+                                    io_phase,
+                                    nanos,
+                                );
+                                self.parker.park_timeout_unless(
+                                    Duration::from_nanos(nanos),
+                                    || !io.is_polling(),
+                                );
+                            } else {
+                                record_backoff_indefinite_park(
+                                    &mut self.preemption_metrics,
+                                    io_phase,
+                                );
+                                self.parker.park_unless(|| !io.is_polling());
+                            }
+                            // The next selection may find owner-local work
+                            // before this follower gets to reactor election.
+                            // Carry the handoff forward so that work cannot
+                            // strand another idle peer behind its task poll.
+                            // An existing poller already owns responsibility;
+                            // it will hand off when it leaves its own turn.
+                            left_reactor = !io.is_polling();
+                            // A handoff may carry no runnable task at all.
+                            // Re-enter timer processing and reactor election,
+                            // not the inner queue-only backoff loop.
+                            self.reset_empty_backoff();
+                            break;
+                        }
+
+                        if matches!(io_phase, IoPhaseOutcome::PollError) {
+                            // A persistent poll failure must neither park
+                            // forever as a follower nor spin on is_polling.
+                            // Honor a nearer future deadline; a stale due
+                            // entry still gets a finite error cooldown.
+                            let now = self.current_scheduler_time();
+                            let nanos = poll_error_retry_nanos(next_deadline, now);
+                            record_backoff_timeout_park(
+                                &mut self.preemption_metrics,
+                                io_phase,
+                                nanos,
+                            );
+                            self.parker.park_timeout(Duration::from_nanos(nanos));
+                            self.reset_empty_backoff();
+                            break;
+                        }
+
                         if let Some(next_deadline) = next_deadline {
@@ -5858,3 +5994,6 @@
+        }
+        if left_reactor {
+            self.coordinator.promote_follower();
         }
         // The loop can stop between an execution and the next dispatch. A
         // task still in this worker's LIFO slot then goes to the global lane,
@@ -7841,5 +7980,11 @@
             // Never wait for I/O or its polling leader while runnable work
             // remains. Driver locks are released before readiness wakes tasks.
-            let _ = io.try_turn_with(Some(Duration::ZERO), |_, _| {});
+            if !matches!(io.try_turn_with(Some(Duration::ZERO), |_, _| {}), Ok(None)) {
+                // A peer can enter follower parking during this brief turn,
+                // even when it returns no events. Pass the released reactor
+                // on before the next task poll; no idle-loop flag exists on
+                // the single-step root-pump path (GH #83).
+                self.coordinator.promote_follower();
+            }
         }
     }
@@ -9759,3 +9904,7 @@
+
+#[cfg(all(test, not(target_arch = "wasm32")))]
+#[path = "reactor_handoff_tests.rs"]
+mod reactor_handoff_tests;
 
 #[cfg(test)]
 #[path = "three_lane_tests.rs"]
'''.replace('\n diff --git ', '\ndiff --git ')


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate without applying")
    args = parser.parse_args()
    for relative, expected in PINS.items():
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"Not a regular source file: {relative}")
        actual = blob_sha(path.read_bytes())
        if actual != expected:
            raise SystemExit(f"Refusing source drift: {relative}: expected {expected}, got {actual}")
    tests = ROOT / "src/runtime/scheduler/reactor_handoff_tests.rs"
    if not tests.is_file() or "a_busy_reactor_turn_promotes_a_follower" not in tests.read_text():
        raise SystemExit("The current GH#83 regressions must accompany this candidate")
    command = ["git", "apply", "--whitespace=error"]
    subprocess.run(command + ["--check", "-"], input=PATCH.encode(), cwd=ROOT, check=True)
    if not args.check:
        subprocess.run(command + ["-"], input=PATCH.encode(), cwd=ROOT, check=True)
    print("GH#83 source pins and patch check passed" + ("; applied locally" if not args.check else ""))


if __name__ == "__main__":
    main()
