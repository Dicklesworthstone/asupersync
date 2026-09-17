//! Explicit foreground launcher for the mTLS ATP live-transfer profile.
//!
//! Build with `--features atp-cli`. This separate command does not change or
//! enable the legacy `atpd start` listener, configuration, or PID-file protocol.
//! Unix filesystems are required by its no-clobber committing inbox backend.

#![forbid(unsafe_code)]

#[cfg(all(
    feature = "atp-cli",
    feature = "tls",
    unix,
    not(target_arch = "wasm32")
))]
#[path = "atpd_live/mod.rs"]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(all(
        feature = "atp-cli",
        feature = "tls",
        unix,
        not(target_arch = "wasm32")
    ))]
    {
        match app::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("atpd-live: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(all(
        feature = "atp-cli",
        feature = "tls",
        unix,
        not(target_arch = "wasm32")
    )))]
    {
        eprintln!("atpd-live requires a native Unix target and --features atp-cli");
        std::process::ExitCode::FAILURE
    }
}
