//! ATP-NR10 CLI-to-daemon user journey e2e harness.
//!
//! Runs the real `asupersync` binary as both the daemon (`atp serve`) and the
//! CLI (`atp send`) over loopback, so it needs the `cli` feature that builds
//! that binary (`[[test]]` entry in Cargo.toml).
#![cfg(feature = "cli")]

#[path = "atp/cli_journey/push_artifact_harness.rs"]
mod push_artifact_harness;

// Stopping the real `atp serve` daemon with SIGINT/SIGTERM (br-asupersync-ylvfod).
#[cfg(unix)]
#[path = "atp/cli_journey/serve_signal_shutdown.rs"]
mod serve_signal_shutdown;

// Persistent local directory reconciliation uses the native Linux/glibc profile.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "atp/cli_journey/local_sync.rs"]
mod local_sync;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "atp/cli_journey/local_mirror.rs"]
mod local_mirror;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "atp/cli_journey/local_watch.rs"]
mod local_watch;
