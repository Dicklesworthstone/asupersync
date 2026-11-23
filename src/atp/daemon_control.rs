//! Secure ATP Daemon Control Implementation
//!
//! Provides capability-checked daemon lifecycle management with proper privilege
//! validation, safe process control, and prevention of privilege escalation.
//!
//! # Security Model
//!
//! - All daemon operations require explicit capability authorization
//! - Process control uses safe, non-privileged system interfaces
//! - Owned children retain their OS handle until reaped
//! - Externally discovered PIDs require a fresh executable identity check
//! - State validation prevents privilege escalation through daemon manipulation
//! - Audit logging for all control operations
//!
//! External PID files are discovery hints, not process handles. Executable and
//! start-time checks reject stale targets and different executables, but cannot
//! eliminate a PID-reuse race between inspection and signaling on every platform.
//! A PID file must still be protected from replacement by another process using
//! the same daemon executable.

use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::types::RegionId;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::{Duration, Instant};
#[cfg(unix)]
use sysinfo::Signal as SysSignal;
use sysinfo::{Pid, ProcessesToUpdate, System};

/// Daemon control capability required for process management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonControlCapability {
    /// Can check daemon status (read-only).
    Status,
    /// Can start daemon processes.
    Start,
    /// Can stop daemon processes gracefully.
    Stop,
    /// Can force-kill daemon processes (emergency only).
    ForceKill,
    /// Can restart daemon processes (combines Stop + Start).
    Restart,
}

/// Daemon process identification and state.
#[derive(Debug, Clone, PartialEq)]
pub struct DaemonProcessInfo {
    /// Process ID if daemon is running.
    pub pid: Option<u32>,
    /// Command line used to start the process.
    pub command: String,
    /// Working directory of the daemon.
    pub working_dir: PathBuf,
    /// User running the daemon.
    pub user: String,
    /// CPU usage percentage (0.0-100.0).
    pub cpu_usage: f32,
    /// Memory usage in bytes.
    pub memory_usage: u64,
    /// Process start time.
    pub start_time: Option<Instant>,
}

/// Result of daemon control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonControlResult {
    /// Operation completed successfully.
    Success {
        /// Previous state of the daemon.
        previous_state: DaemonState,
        /// New state after operation.
        new_state: DaemonState,
        /// Duration the operation took.
        duration: Duration,
    },
    /// Operation failed with details.
    Failed {
        /// The operation that failed.
        operation: DaemonControlCapability,
        /// Error details.
        error: String,
        /// Current daemon state (may be unknown).
        current_state: DaemonState,
    },
    /// Operation was denied due to insufficient privileges.
    PermissionDenied {
        /// Required capability.
        required_capability: DaemonControlCapability,
        /// Current privilege level.
        current_privileges: Vec<DaemonControlCapability>,
    },
}

/// Current state of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    /// Daemon is not running.
    Stopped,
    /// Daemon is starting up.
    Starting,
    /// Daemon is running normally.
    Running,
    /// Daemon is shutting down gracefully.
    Stopping,
    /// Daemon state is unknown or indeterminate.
    Unknown,
    /// Daemon has crashed or failed.
    Failed,
}

/// Secure daemon controller with capability-based access control.
#[derive(Debug)]
pub struct SecureDaemonController {
    /// Region ID that owns this controller instance.
    region_id: RegionId,
    /// Capabilities granted to this controller.
    capabilities: Vec<DaemonControlCapability>,
    /// Path to daemon executable.
    daemon_path: PathBuf,
    /// Path to daemon configuration.
    config_path: PathBuf,
    /// Caller-selected configuration directory, also used for the PID claim
    /// and child working directory when the configuration file is a symlink.
    config_dir: PathBuf,
    /// Path to daemon PID file.
    pid_file: PathBuf,
    /// Process system interface.
    system: System,
    /// Retain the spawned child until it is reaped. On Unix, dropping the
    /// controller transfers a live child to the process module's shared reaper.
    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
    child: Option<crate::process::Child>,
    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
    child_state: DaemonState,
}

impl SecureDaemonController {
    /// Creates a new secure daemon controller with specified capabilities.
    ///
    /// # Security
    ///
    /// The controller is region-scoped and can only perform operations explicitly
    /// granted via the capabilities list. Each operation validates authorization.
    pub fn new(
        region_id: RegionId,
        capabilities: Vec<DaemonControlCapability>,
        daemon_path: PathBuf,
        config_path: PathBuf,
    ) -> Result<Self, Error> {
        // Validate daemon executable exists and is executable
        if !daemon_path.exists() {
            return Err(Error::new(ErrorKind::ConfigError).with_message(format!(
                "Daemon executable not found: {}",
                daemon_path.display()
            )));
        }

        if !Self::is_executable(&daemon_path)? {
            return Err(Error::new(ErrorKind::AdmissionDenied)
                .with_message("Daemon executable lacks execute permissions"));
        }

        // Validate config file exists if specified
        if !config_path.exists() {
            return Err(Error::new(ErrorKind::ConfigError).with_message(format!(
                "Daemon config not found: {}",
                config_path.display()
            )));
        }

        // Resolve the caller's directory independently from the configuration
        // target. A symlinked config must not relocate the daemon's PID claim
        // or its working directory to the shared target's directory.
        let config_dir = fs::canonicalize(
            config_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )
        .map_err(|e| {
            Error::new(ErrorKind::ConfigError)
                .with_message(format!("Cannot resolve configuration directory: {e}"))
        })?;

        // The child runs beside the caller's configuration. Resolve these
        // paths before changing its working directory.
        let daemon_path = fs::canonicalize(&daemon_path).map_err(|e| {
            Error::new(ErrorKind::ConfigError)
                .with_message(format!("Cannot resolve daemon executable: {e}"))
        })?;
        let config_path = fs::canonicalize(&config_path).map_err(|e| {
            Error::new(ErrorKind::ConfigError)
                .with_message(format!("Cannot resolve daemon configuration: {e}"))
        })?;

        let pid_file = config_dir.join("daemon.pid");

        let system = System::new_all().map_err(|e| {
            Error::new(ErrorKind::Internal)
                .with_message(format!("Failed to initialize system info: {e}"))
        })?;

        Ok(Self {
            region_id,
            capabilities,
            daemon_path,
            config_path,
            config_dir,
            pid_file,
            system,
            #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
            child: None,
            #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
            child_state: DaemonState::Stopped,
        })
    }

    /// Checks the current status of the daemon.
    ///
    /// # Security
    /// Requires Status capability.
    pub fn status(&mut self, cx: &Cx) -> Result<DaemonProcessInfo, Error> {
        self.status_with_policy(cx, false)
    }

    /// Checks daemon status without treating an inconclusive PID claim or
    /// executable lookup as a stopped daemon.
    ///
    /// A missing PID file or an exited process is stopped. An unreadable or
    /// malformed claim, or a live external process whose executable cannot be
    /// identified, returns an error. A process with an identifiable different
    /// executable is not this daemon. Owned children remain authoritative even
    /// when optional system metadata is unavailable.
    ///
    /// # Security
    /// Requires Status capability, like [`Self::status`].
    pub fn status_strict(&mut self, cx: &Cx) -> Result<DaemonProcessInfo, Error> {
        self.status_with_policy(cx, true)
    }

    fn status_with_policy(&mut self, cx: &Cx, strict: bool) -> Result<DaemonProcessInfo, Error> {
        self.require_capability(DaemonControlCapability::Status)?;
        self.validate_operation_authorized(cx, DaemonControlCapability::Status)?;

        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        self.reap_owned_child()?;

        // Refresh system information
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        // Prefer the owned process handle over the replaceable PID file.
        let owned_pid = self.owned_pid();
        let pid = match owned_pid {
            Some(pid) => Some(pid),
            None if strict => self.read_pid_claim()?,
            None => self.read_pid_claim().ok().flatten(),
        };

        if let Some(pid) = pid {
            // Verify process is still running and is our daemon
            if let Some(process) = self.system.process(Pid::from_u32(pid)) {
                let is_daemon = if owned_pid == Some(pid) {
                    true
                } else if strict {
                    self.process_matches_daemon(process)?
                } else {
                    self.is_our_daemon_process(process)
                };
                if is_daemon {
                    return Ok(DaemonProcessInfo {
                        pid: Some(pid),
                        command: process
                            .cmd()
                            .iter()
                            .map(|s| s.to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                            .join(" "),
                        working_dir: process
                            .cwd()
                            .map_or_else(platform_fallback_work_dir, Path::to_path_buf),
                        user: format!(
                            "{:?}",
                            process
                                .user_id()
                                .map_or_else(|| "0".to_string(), |uid| uid.to_string())
                        ),
                        cpu_usage: process.cpu_usage(),
                        memory_usage: process.memory(),
                        start_time: Some(Instant::now()), // Approximate start time
                    });
                }
            }
            if owned_pid == Some(pid) {
                // The owned child handle proves liveness until try_wait reaps
                // it. A missing sysinfo snapshot must not report it stopped.
                return Ok(DaemonProcessInfo {
                    pid: Some(pid),
                    command: self.daemon_path.display().to_string(),
                    working_dir: self.config_dir.clone(),
                    user: "unknown".to_owned(),
                    cpu_usage: 0.0,
                    memory_usage: 0,
                    start_time: None,
                });
            }
        }

        // The daemon owns its PID claim. A read-only status probe must not
        // unlink a claim that another daemon may have replaced in the meantime.
        // Return stopped state
        Ok(DaemonProcessInfo {
            pid: None,
            command: "Not running".to_string(),
            working_dir: self.config_dir.clone(),
            user: "none".to_string(),
            cpu_usage: 0.0,
            memory_usage: 0,
            start_time: None,
        })
    }

    /// Starts the daemon process.
    ///
    /// `Running` confirms that the child survived its initial startup check
    /// and published its PID claim. It does not prove that every transfer
    /// listener has finished binding; use a service-specific readiness check.
    /// This synchronous method may wait up to ten seconds
    /// for the PID claim. The explicit process-less slim profile cannot start
    /// a daemon unless the `process` feature is also enabled.
    ///
    /// # Security
    /// Requires Start capability. Uses safe process spawning without privilege escalation.
    pub fn start(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        self.require_capability(DaemonControlCapability::Start)?;
        self.validate_operation_authorized(cx, DaemonControlCapability::Start)?;
        self.start_authorized(cx)
    }

    fn start_authorized(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        cx.checkpoint()?;

        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        {
            self.start_process(cx)
        }
        #[cfg(all(feature = "slim-runtime-profile", not(feature = "process")))]
        {
            Ok(DaemonControlResult::Failed {
                operation: DaemonControlCapability::Start,
                error: "Daemon startup requires the process feature in the slim runtime profile"
                    .to_owned(),
                current_state: self.get_daemon_state(),
            })
        }
    }

    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
    fn start_process(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        let start_time = Instant::now();
        let previous_state = self.get_daemon_state();

        // Check if daemon is already running
        if previous_state == DaemonState::Running {
            return Ok(DaemonControlResult::Success {
                previous_state,
                new_state: DaemonState::Running,
                duration: start_time.elapsed(),
            });
        }
        if !matches!(previous_state, DaemonState::Stopped | DaemonState::Failed) {
            return Ok(DaemonControlResult::Failed {
                operation: DaemonControlCapability::Start,
                error: "The previous daemon child has not completed its lifecycle".to_owned(),
                current_state: previous_state,
            });
        }

        // Use the actual atpd CLI. The daemon, not this controller, claims the
        // PID path exclusively and removes its own claim on a clean exit.
        let mut cmd = crate::process::Command::new(&self.daemon_path);
        cmd.arg("--config")
            .arg(&self.config_path)
            .arg("--pid-file")
            .arg(&self.pid_file)
            .arg("--foreground")
            .arg("start")
            .stdout(crate::process::Stdio::Null)
            .stderr(crate::process::Stdio::Null)
            .stdin(crate::process::Stdio::Null);

        // SECURITY: Drop all unnecessary privileges and use safe working directory
        cmd.current_dir(&self.config_dir);

        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                return Ok(DaemonControlResult::Failed {
                    operation: DaemonControlCapability::Start,
                    error: format!("Failed to start daemon: {error}"),
                    current_state: self.get_daemon_state(),
                });
            }
        };
        let pid = child.id().expect("a newly spawned child has a process id");
        self.child = Some(child);
        self.child_state = DaemonState::Starting;

        loop {
            match self.reap_owned_child() {
                Ok(Some(status)) => {
                    return Ok(DaemonControlResult::Failed {
                        operation: DaemonControlCapability::Start,
                        error: format!("Daemon exited during startup ({status})"),
                        current_state: DaemonState::Failed,
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    let current_state = self.terminate_startup_child();
                    return Ok(DaemonControlResult::Failed {
                        operation: DaemonControlCapability::Start,
                        error: format!("Cannot observe daemon startup: {error}"),
                        current_state,
                    });
                }
            }

            if let Err(error) = cx.checkpoint() {
                self.terminate_startup_child();
                return Err(error);
            }

            // Retain the old minimum observation window, but wait for the
            // child's own PID publication instead of manufacturing a claim.
            if start_time.elapsed() >= Duration::from_millis(100)
                && self.read_pid_file().ok() == Some(pid)
            {
                self.child_state = DaemonState::Running;
                return Ok(DaemonControlResult::Success {
                    previous_state,
                    new_state: DaemonState::Running,
                    duration: start_time.elapsed(),
                });
            }
            if start_time.elapsed() >= Duration::from_secs(10) {
                let current_state = self.terminate_startup_child();
                return Ok(DaemonControlResult::Failed {
                    operation: DaemonControlCapability::Start,
                    error: "Daemon did not publish its PID claim within ten seconds".to_owned(),
                    current_state,
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Stops the daemon process gracefully.
    ///
    /// # Security
    /// Requires Stop capability. Uses SIGTERM for graceful shutdown with timeout.
    pub fn stop(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        self.require_capability(DaemonControlCapability::Stop)?;
        self.validate_operation_authorized(cx, DaemonControlCapability::Stop)?;
        cx.checkpoint()?;
        self.stop_process(DaemonControlCapability::Stop, Signal::Term, false)
    }

    /// Stops the daemon after strict discovery of one process instance.
    ///
    /// Unlike [`Self::stop`], an unreadable or malformed PID claim, or an
    /// unobservable external executable, is an error rather than evidence of
    /// a stopped daemon. The discovered PID and start time are checked again
    /// before signaling; a later PID-file replacement cannot redirect the
    /// operation. Owned children are controlled through their retained handle.
    ///
    /// # Security
    /// Requires Stop capability. Status capability is not additionally required.
    pub fn stop_strict(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        self.require_capability(DaemonControlCapability::Stop)?;
        self.validate_operation_authorized(cx, DaemonControlCapability::Stop)?;
        cx.checkpoint()?;
        self.stop_process(DaemonControlCapability::Stop, Signal::Term, true)
    }

    fn stop_process(
        &mut self,
        operation: DaemonControlCapability,
        signal: Signal,
        strict: bool,
    ) -> Result<DaemonControlResult, Error> {
        let start_time = Instant::now();
        let (previous_state, pid, expected_start_time) = if strict {
            let (previous_state, target) = self.strict_stop_target()?;
            let Some(target) = target else {
                return Ok(DaemonControlResult::Success {
                    previous_state,
                    new_state: DaemonState::Stopped,
                    duration: start_time.elapsed(),
                });
            };
            (previous_state, target.pid, target.start_time)
        } else {
            let owned_at_entry = self.owned_pid();
            let previous_state = self.get_daemon_state();

            if (owned_at_entry.is_some() && self.owned_pid().is_none())
                || (matches!(signal, Signal::Term) && previous_state == DaemonState::Stopped)
            {
                // A child reaped during the state check was the operation's
                // target. Do not fall through to a replacement PID claim.
                return Ok(DaemonControlResult::Success {
                    previous_state,
                    new_state: DaemonState::Stopped,
                    duration: start_time.elapsed(),
                });
            }

            // The owned handle remains authoritative if the PID file is
            // removed or replaced. Never redirect an in-progress control
            // operation to a newly published PID.
            let pid = match self.owned_pid().map_or_else(|| self.read_pid_file(), Ok) {
                Ok(pid) => pid,
                Err(error) => {
                    return Ok(DaemonControlResult::Failed {
                        operation,
                        error: format!("Cannot identify the daemon to stop: {error}"),
                        current_state: previous_state,
                    });
                }
            };
            (previous_state, pid, None)
        };

        let target = match self.send_signal_to_process(pid, signal, expected_start_time) {
            Ok(target) => target,
            Err(error) => {
                return Ok(DaemonControlResult::Failed {
                    operation,
                    error: format!("Failed to signal daemon: {error}"),
                    current_state: self.get_daemon_state(),
                });
            }
        };
        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        if self.owned_pid() == Some(pid) {
            self.child_state = DaemonState::Stopping;
        }

        let timeout = match signal {
            Signal::Term => Duration::from_secs(10),
            Signal::Kill => Duration::from_secs(5),
        };
        let signalled_at = Instant::now();
        loop {
            match self.target_has_exited(target) {
                Ok(true) => {
                    // Only the daemon removes its own PID claim. In
                    // particular, do not unlink a successor's claim here.
                    return Ok(DaemonControlResult::Success {
                        previous_state,
                        new_state: DaemonState::Stopped,
                        duration: start_time.elapsed(),
                    });
                }
                Ok(false) => {}
                Err(error) => {
                    return Ok(DaemonControlResult::Failed {
                        operation,
                        error: format!("Cannot confirm daemon exit: {error}"),
                        current_state: DaemonState::Unknown,
                    });
                }
            }
            if signalled_at.elapsed() >= timeout {
                return Ok(DaemonControlResult::Failed {
                    operation,
                    error: format!("Daemon did not exit within {timeout:?} after {signal:?}"),
                    current_state: DaemonState::Stopping,
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Force-kills the daemon process (emergency use only).
    ///
    /// # Security
    /// Requires ForceKill capability. Should only be used when graceful stop fails.
    /// Success requires confirmed process exit; a sent signal alone is not
    /// reported as `Stopped`. An abrupt exit can leave the daemon's stale PID
    /// claim, which the next daemon start may replace.
    pub fn force_kill(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        self.require_capability(DaemonControlCapability::ForceKill)?;
        self.validate_operation_authorized(cx, DaemonControlCapability::ForceKill)?;
        cx.checkpoint()?;
        self.stop_process(DaemonControlCapability::ForceKill, Signal::Kill, false)
    }

    /// Restarts the daemon (stop + start).
    ///
    /// # Security
    /// Requires Restart capability (or both Stop + Start capabilities).
    pub fn restart(&mut self, cx: &Cx) -> Result<DaemonControlResult, Error> {
        // Check for explicit restart capability or both stop + start
        if !self
            .capabilities
            .contains(&DaemonControlCapability::Restart)
        {
            self.require_capability(DaemonControlCapability::Stop)?;
            self.require_capability(DaemonControlCapability::Start)?;
        }

        self.validate_operation_authorized(cx, DaemonControlCapability::Restart)?;
        cx.checkpoint()?;

        let start_time = Instant::now();
        let owned_at_entry = self.owned_pid();
        let previous_state = self.get_daemon_state();
        let owned_child_exited = owned_at_entry.is_some() && self.owned_pid().is_none();

        // Authorization applies to the combined action, not to two nested
        // public calls that would require extra Start and Stop grants.
        // If that observation reaped our old child, it must not redirect the
        // stop phase to another daemon that has replaced its PID claim.
        if previous_state != DaemonState::Stopped && !owned_child_exited {
            let stop_result =
                self.stop_process(DaemonControlCapability::Stop, Signal::Term, false)?;
            if !matches!(
                stop_result,
                DaemonControlResult::Success {
                    new_state: DaemonState::Stopped,
                    ..
                }
            ) {
                return Ok(stop_result);
            }
        }

        // Then start
        let start_result = self.start_authorized(cx)?;

        // Return result with original previous state and final duration
        match start_result {
            DaemonControlResult::Success { new_state, .. } => Ok(DaemonControlResult::Success {
                previous_state,
                new_state,
                duration: start_time.elapsed(),
            }),
            other => Ok(other),
        }
    }

    // --- Private implementation ---

    fn require_capability(&self, cap: DaemonControlCapability) -> Result<(), Error> {
        if self.capabilities.contains(&cap) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                "Operation requires {:?} capability, but only have: {:?}",
                cap, self.capabilities
            )))
        }
    }

    fn validate_operation_authorized(
        &self,
        cx: &Cx,
        _operation: DaemonControlCapability,
    ) -> Result<(), Error> {
        // Validate the operation is authorized by the region's capability context
        // This ensures the operation is running in the proper security context
        if cx.budget().remaining_cost() == Some(0) {
            return Err(Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                "Daemon control operation for region {:?} not authorized by capability context",
                self.region_id
            )));
        }

        // Additional validation could check cx.current_region() == self.region_id
        // when that API is available
        Ok(())
    }

    fn get_daemon_state(&mut self) -> DaemonState {
        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        {
            if self.reap_owned_child().is_err() {
                return DaemonState::Unknown;
            }
            // A live child still belongs to this controller even if someone
            // removes its PID file. Do not start a duplicate in that case.
            if self.child.is_some() {
                return self.child_state;
            }
        }
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        if let Ok(pid) = self.read_pid_file() {
            if let Some(process) = self.system.process(Pid::from_u32(pid)) {
                if self.is_our_daemon_process(process) {
                    return DaemonState::Running;
                }
            }
        }
        DaemonState::Stopped
    }

    fn owned_pid(&self) -> Option<u32> {
        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        {
            self.child.as_ref().and_then(crate::process::Child::id)
        }
        #[cfg(all(feature = "slim-runtime-profile", not(feature = "process")))]
        {
            None
        }
    }

    fn strict_stop_target(&mut self) -> Result<(DaemonState, Option<ControlTarget>), Error> {
        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        {
            let owned_at_entry = self.owned_pid();
            self.reap_owned_child()?;
            if let Some(pid) = self.owned_pid() {
                return Ok((
                    self.child_state,
                    Some(ControlTarget {
                        pid,
                        start_time: None,
                    }),
                ));
            }
            if owned_at_entry.is_some() {
                // The owned instance already exited. A replacement claim
                // belongs to a different lifecycle and must be left alone.
                return Ok((DaemonState::Stopped, None));
            }
        }

        let Some(pid) = self.read_pid_claim()? else {
            return Ok((DaemonState::Stopped, None));
        };
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        let Some(process) = self.system.process(Pid::from_u32(pid)) else {
            return Ok((DaemonState::Stopped, None));
        };
        if !self.process_matches_daemon(process)? {
            return Ok((DaemonState::Stopped, None));
        }
        Ok((
            DaemonState::Running,
            Some(ControlTarget {
                pid,
                start_time: Some(process.start_time()),
            }),
        ))
    }

    fn target_has_exited(&mut self, target: ControlTarget) -> Result<bool, Error> {
        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        if self.owned_pid() == Some(target.pid) {
            return self.reap_owned_child().map(|status| status.is_some());
        }
        let Some(start_time) = target.start_time else {
            // An owned handle was already reaped. Its old PID is no longer
            // ours to inspect or signal, even if the OS has reused it.
            return Ok(true);
        };
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        Ok(self
            .system
            .process(Pid::from_u32(target.pid))
            .is_none_or(|process| {
                process.status() == sysinfo::ProcessStatus::Zombie
                    || process.start_time() != start_time
            }))
    }

    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
    fn reap_owned_child(&mut self) -> Result<Option<crate::process::ExitStatus>, Error> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child.try_wait().map_err(|error| {
            Error::new(ErrorKind::Internal)
                .with_message(format!("Cannot query the owned daemon child: {error}"))
        })?;
        if status.is_some() {
            // Child::try_wait consumes its OS handle once it reaps. Never
            // poll that completed handle again, or signal its reusable PID.
            self.child = None;
            self.child_state = DaemonState::Stopped;
        }
        Ok(status)
    }

    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
    fn terminate_startup_child(&mut self) -> DaemonState {
        let Some(child) = self.child.as_mut() else {
            return DaemonState::Failed;
        };
        let state = match child.kill() {
            Ok(()) => DaemonState::Stopping,
            Err(_) => DaemonState::Unknown,
        };
        self.child_state = state;
        // Do not wait unboundedly after a failed start. Retain the child if it
        // has not exited yet; on Unix, controller drop transfers it to the reaper.
        let _ = self.reap_owned_child();
        if self.child.is_some() {
            state
        } else {
            DaemonState::Failed
        }
    }

    fn read_pid_file(&self) -> Result<u32, Error> {
        self.read_pid_claim()?.ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput).with_message("Daemon PID file does not exist")
        })
    }

    fn read_pid_claim(&self) -> Result<Option<u32>, Error> {
        let contents = match fs::read_to_string(&self.pid_file) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::new(ErrorKind::InvalidInput)
                    .with_message(format!("Failed to read PID file: {error}")));
            }
        };

        let pid = contents.trim().parse::<u32>().map_err(|e| {
            Error::new(ErrorKind::InvalidInput).with_message(format!("Invalid PID in file: {}", e))
        })?;
        validate_daemon_pid(pid)?;
        Ok(Some(pid))
    }

    fn is_our_daemon_process(&self, process: &sysinfo::Process) -> bool {
        self.process_matches_daemon(process).unwrap_or(false)
    }

    fn process_matches_daemon(&self, process: &sysinfo::Process) -> Result<bool, Error> {
        // argv[0] and a matching basename are both forgeable. If the platform
        // cannot expose the executable path, refuse external control.
        if process.status() == sysinfo::ProcessStatus::Zombie {
            return Ok(false);
        }
        let executable = process
            .exe()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message("Cannot identify the executable of the live daemon PID")
            })?;
        if executable == self.daemon_path {
            return Ok(true);
        }
        let executable = fs::canonicalize(executable).map_err(|error| {
            Error::new(ErrorKind::Internal)
                .with_message(format!("Cannot resolve the live PID's executable: {error}"))
        })?;
        Ok(executable == self.daemon_path)
    }

    fn send_signal_to_process(
        &mut self,
        pid: u32,
        signal: Signal,
        expected_start_time: Option<u64>,
    ) -> Result<ControlTarget, Error> {
        validate_daemon_pid(pid)?;

        #[cfg(any(not(feature = "slim-runtime-profile"), feature = "process"))]
        if let Some(child) = self.child.as_mut()
            && child.id() == Some(pid)
        {
            let result = match signal {
                Signal::Kill => Some(child.kill()),
                #[cfg(unix)]
                Signal::Term => Some(child.signal(libc::SIGTERM)),
                #[cfg(not(unix))]
                Signal::Term => None,
            };
            if let Some(result) = result {
                result.map_err(|error| {
                    Error::new(ErrorKind::Internal)
                        .with_message(format!("Failed to signal the owned daemon child: {error}"))
                })?;
                return Ok(ControlTarget {
                    pid,
                    start_time: None,
                });
            }
        }

        let mut system = System::new_all().map_err(|e| {
            Error::new(ErrorKind::Internal)
                .with_message(format!("Failed to query system processes: {e}"))
        })?;
        system.refresh_processes(ProcessesToUpdate::All, true);
        let process = system.process(Pid::from_u32(pid)).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput)
                .with_message(format!("Daemon pid {pid} no longer exists"))
        })?;
        if expected_start_time.is_some_and(|expected| process.start_time() != expected) {
            return Err(Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                "Refusing to signal pid {pid}: process identity changed after discovery"
            )));
        }
        if !self.process_matches_daemon(process)? {
            return Err(Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                "Refusing to signal pid {pid}: executable identity does not match the daemon"
            )));
        }
        let target = ControlTarget {
            pid,
            start_time: Some(process.start_time()),
        };

        #[cfg(unix)]
        {
            let signal = match signal {
                Signal::Term => SysSignal::Term,
                Signal::Kill => SysSignal::Kill,
            };
            match process.kill_with(signal) {
                Some(true) => Ok(target),
                Some(false) => Err(Error::new(ErrorKind::Internal)
                    .with_message(format!("Failed to send {:?} to pid {}", signal, pid))),
                None => Err(Error::new(ErrorKind::Internal).with_message(format!(
                    "Signal {:?} is unsupported or pid {} no longer exists",
                    signal, pid
                ))),
            }
        }

        #[cfg(windows)]
        {
            let mut command = Command::new("taskkill.exe");
            command.arg("/PID").arg(pid.to_string()).arg("/T");
            if matches!(signal, Signal::Kill) {
                command.arg("/F");
            }

            let output = command.output().map_err(|e| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("Failed to invoke taskkill for pid {}: {}", pid, e))
            })?;

            if output.status.success() {
                Ok(target)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(Error::new(ErrorKind::Internal)
                    .with_message(format!("taskkill failed for pid {}: {}", pid, stderr)))
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (signal, target);
            Err(Error::new(ErrorKind::Internal).with_message(format!(
                "Process signalling is unsupported on this platform for pid {}",
                pid
            )))
        }
    }

    fn is_executable(path: &Path) -> Result<bool, Error> {
        let metadata = fs::metadata(path).map_err(|e| {
            Error::new(ErrorKind::InvalidInput).with_message(format!("Cannot access file: {}", e))
        })?;
        if !metadata.is_file() {
            return Ok(false);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            Ok(metadata.permissions().mode() & 0o111 != 0)
        }

        #[cfg(windows)]
        {
            Ok(path_has_windows_executable_extension(
                path,
                std::env::var_os("PATHEXT").as_deref(),
            ))
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(true)
        }
    }
}

/// A control operation follows one process instance, never a changing PID file.
#[derive(Clone, Copy)]
struct ControlTarget {
    pid: u32,
    /// Absent only for an owned child whose handle pins its identity until reap.
    start_time: Option<u64>,
}

fn validate_daemon_pid(pid: u32) -> Result<(), Error> {
    if pid <= 1 {
        return Err(Error::new(ErrorKind::InvalidInput)
            .with_message(format!("PID {pid} cannot identify a daemon process")));
    }
    #[cfg(unix)]
    if i32::try_from(pid).is_err() {
        return Err(Error::new(ErrorKind::InvalidInput)
            .with_message(format!("PID {pid} exceeds the native process id range")));
    }
    Ok(())
}

fn platform_fallback_work_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir())
}

#[cfg(any(windows, test))]
fn path_has_windows_executable_extension(path: &Path, pathext: Option<&std::ffi::OsStr>) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    let extension = extension.trim_start_matches('.');
    let default_pathext = ".COM;.EXE;.BAT;.CMD;.PS1";
    let pathext = pathext
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default_pathext);

    pathext
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            entry
                .trim_start_matches('.')
                .eq_ignore_ascii_case(extension)
        })
}

/// Signal types for process control.
#[derive(Debug, Clone, Copy)]
enum Signal {
    /// SIGTERM - graceful shutdown.
    Term,
    /// SIGKILL - force kill.
    Kill,
}

/// Factory function to create a secure daemon controller with standard ATP daemon configuration.
///
/// Uses the current executable as the daemon. This factory is intended for
/// callers running inside `atpd`; embedding applications should select the
/// daemon binary with [`create_atp_daemon_controller_with_executable`].
///
/// # Security
///
/// Returns a controller with minimal required capabilities for the specified use case.
/// Callers should request only the minimum capabilities needed for their operation.
pub fn create_atp_daemon_controller(
    region_id: RegionId,
    capabilities: Vec<DaemonControlCapability>,
    config_dir: &Path,
) -> Result<SecureDaemonController, Error> {
    let daemon_path = std::env::current_exe().map_err(|e| {
        Error::new(ErrorKind::ConfigError)
            .with_message(format!("Cannot determine daemon executable path: {}", e))
    })?;

    create_atp_daemon_controller_with_executable(region_id, capabilities, config_dir, &daemon_path)
}

/// Creates an ATP controller for an explicitly selected daemon executable.
///
/// Reads `config.toml` from `config_dir`. The executable and configuration are
/// validated and resolved by [`SecureDaemonController::new`], and the supplied
/// capabilities are preserved. Construction does not start the daemon.
pub fn create_atp_daemon_controller_with_executable(
    region_id: RegionId,
    capabilities: Vec<DaemonControlCapability>,
    config_dir: &Path,
    daemon_path: &Path,
) -> Result<SecureDaemonController, Error> {
    SecureDaemonController::new(
        region_id,
        capabilities,
        daemon_path.to_path_buf(),
        config_dir.join("config.toml"),
    )
}

#[cfg(test)]
#[path = "daemon_control_inline_tests.rs"]
mod tests;
