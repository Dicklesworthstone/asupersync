#![cfg(any(feature = "postgres", feature = "mysql"))]
#![allow(clippy::all)]
//! Real-DB end-to-end reconnection tests for [`AsyncDbPool`]
//! [br-asupersync-na35bj].
//!
//! Methodology: per `/testing-perfect-e2e-integration-tests-with-logging-and-no-mocks`,
//! these tests use REAL PostgreSQL (`postgres:16-alpine`) and REAL MariaDB
//! (`mariadb:11`) containers brought up via `docker run`, REAL TCP sockets
//! through asupersync's `PgConnection` / `MySqlConnection`, and REAL kernel-
//! level fault injection via `sudo iptables -j REJECT --reject-with tcp-reset`
//! on the assigned ephemeral port. There are no mocks, no in-process fakes,
//! and no stubbed `connect()` paths.
//!
//! Suites:
//!
//! * `pg_e2e_happy_pool_get_real_connection` — proves the pool can take a
//!   real connection out and return it on drop, with stats reflecting the
//!   round trip.
//! * `pg_e2e_backoff_under_iptables_block_then_recover` — under an active
//!   iptables REJECT rule the pool's `get_with_retry` must (a) fail with
//!   `Connect`/`Timeout` after exhausting attempts, (b) elapse no less than
//!   the cumulative inter-attempt backoff (jitter disabled for determinism),
//!   then (c) recover once the rule is removed.
//! * `pg_e2e_close_rejects_subsequent_gets` — `Pool::close()` causes every
//!   later `get` to return `DbPoolError::Closed`, exercising the close-drain
//!   contract.
//! * MySQL counterparts of the happy/backoff/recover tests.
//!
//! Out of scope (intentionally; would need additional primitives the pool
//! does not currently expose):
//!
//! * In-flight transaction rollback under fault (needs explicit transaction
//!   API on `AsyncPooledConnection`).
//! * Explicit circuit breaker threshold assertions (the pool exposes a retry
//!   policy with attempt cap + exponential backoff, not a discrete
//!   open/half-open breaker primitive). The retry-attempt cap is the
//!   functional analogue and is exercised by the backoff test.
//!
//! All tests gracefully skip — never fail — when docker, sudo iptables, or the
//! relevant feature flag is unavailable, so they remain safe to run on any
//! laptop and in CI without docker capability.

use std::process::Command;
use std::time::{Duration, Instant};

use asupersync::combinator::RetryPolicy;
use asupersync::cx::Cx;
use asupersync::database::pool::{AsyncConnectionManager, AsyncDbPool, DbPoolConfig, DbPoolError};
use asupersync::types::Outcome;
use futures_lite::future::block_on;

// ─── Structured JSON-line logging (one event per println) ───────────────────────

fn jlog(suite: &str, phase: &str, event: &str, data: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    println!(
        r#"{{"ts":{ts},"suite":"{suite}","phase":"{phase}","event":"{event}","data":{data}}}"#
    );
}

// ─── Capability gates ──────────────────────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn sudo_iptables_available() -> bool {
    Command::new("sudo")
        .args(["-n", "iptables", "-L", "-n"])
        .output()
        .is_ok_and(|o| o.status.success())
}

// ─── Docker container management ───────────────────────────────────────────────

struct Container {
    name: String,
    port: u16,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output();
    }
}

#[allow(dead_code)] // used by feature-gated suites
fn start_postgres() -> Option<Container> {
    let name = format!(
        "asupersync-na35bj-pg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() % 1_000_000)
            .unwrap_or_default()
    );
    let _ = Command::new("docker").args(["rm", "-f", &name]).output();
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-e",
            "POSTGRES_PASSWORD=testpass",
            "-e",
            "POSTGRES_USER=testuser",
            "-e",
            "POSTGRES_DB=testdb",
            "-p",
            "127.0.0.1::5432",
            "postgres:16-alpine",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "docker run postgres failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let port = read_port(&name, 5432)?;
    if !wait_postgres_ready(&name) {
        return None;
    }
    Some(Container { name, port })
}

#[allow(dead_code)] // used by feature-gated suites
fn start_mysql() -> Option<Container> {
    let name = format!(
        "asupersync-na35bj-mysql-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() % 1_000_000)
            .unwrap_or_default()
    );
    let _ = Command::new("docker").args(["rm", "-f", &name]).output();
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-e",
            "MYSQL_ROOT_PASSWORD=testpass",
            "-e",
            "MYSQL_DATABASE=testdb",
            "-e",
            "MYSQL_USER=testuser",
            "-e",
            "MYSQL_PASSWORD=testpass",
            "-p",
            "127.0.0.1::3306",
            "mariadb:11",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "docker run mysql failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let port = read_port(&name, 3306)?;
    if !wait_mysql_ready(&name) {
        return None;
    }
    Some(Container { name, port })
}

fn read_port(name: &str, internal: u16) -> Option<u16> {
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(500));
        let out = Command::new("docker")
            .args(["port", name, &internal.to_string()])
            .output()
            .ok()?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = s.lines().next() {
                if let Some(host_port) = line.rsplit(':').next() {
                    if let Ok(p) = host_port.trim().parse::<u16>() {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

fn wait_postgres_ready(name: &str) -> bool {
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(500));
        let r = Command::new("docker")
            .args(["exec", name, "pg_isready", "-U", "testuser", "-d", "testdb"])
            .output();
        if r.is_ok_and(|o| o.status.success()) {
            std::thread::sleep(Duration::from_millis(300));
            return true;
        }
    }
    false
}

fn wait_mysql_ready(name: &str) -> bool {
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        let r = Command::new("docker")
            .args([
                "exec",
                name,
                "mysqladmin",
                "-u",
                "testuser",
                "-ptestpass",
                "-h",
                "127.0.0.1",
                "ping",
            ])
            .output();
        if r.is_ok_and(|o| o.status.success()) {
            std::thread::sleep(Duration::from_millis(300));
            return true;
        }
    }
    false
}

// ─── Real iptables fault injection (RAII) ──────────────────────────────────────

struct IptablesBlock {
    port: u16,
    armed: bool,
}

impl IptablesBlock {
    fn arm(port: u16) -> Self {
        let r = Command::new("sudo")
            .args([
                "-n",
                "iptables",
                "-I",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-d",
                "127.0.0.1",
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            ])
            .output();
        let armed = r.is_ok_and(|o| o.status.success());
        Self { port, armed }
    }

    fn disarm(&mut self) {
        if !self.armed {
            return;
        }
        let _ = Command::new("sudo")
            .args([
                "-n",
                "iptables",
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &self.port.to_string(),
                "-d",
                "127.0.0.1",
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            ])
            .output();
        self.armed = false;
    }
}

impl Drop for IptablesBlock {
    fn drop(&mut self) {
        self.disarm();
    }
}

// ─── PostgreSQL real-DB E2E ────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
mod pg {
    use super::*;
    use asupersync::database::postgres::{PgConnection, PgError};

    struct PgRealManager {
        url: String,
    }

    impl AsyncConnectionManager for PgRealManager {
        type Connection = PgConnection;
        type Error = PgError;

        async fn connect(&self, cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            PgConnection::connect(cx, &self.url).await
        }

        async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
            // Cheap optimistic validity: rely on protocol-level errors at the
            // next real query rather than spending a round-trip on Sync ping.
            // Connection validity under fault is exercised separately by the
            // backoff test which forces the connect path.
            true
        }
    }

    fn url(port: u16) -> String {
        format!("postgres://testuser:testpass@127.0.0.1:{port}/testdb")
    }

    #[test]
    fn pg_e2e_happy_pool_get_real_connection() {
        let suite = "pg_happy";
        if !docker_available() {
            jlog(suite, "skip", "no_docker", "{}");
            return;
        }
        let Some(c) = start_postgres() else {
            jlog(suite, "skip", "postgres_failed_to_start", "{}");
            return;
        };
        jlog(
            suite,
            "setup",
            "container_ready",
            &format!(r#"{{"port":{}}}"#, c.port),
        );

        let manager = PgRealManager { url: url(c.port) };
        let pool = AsyncDbPool::new(
            manager,
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(8)),
        );
        let cx = Cx::for_testing();

        let started = Instant::now();
        let result = block_on(pool.get(&cx));
        let elapsed = started.elapsed();
        jlog(
            suite,
            "act",
            "get_returned",
            &format!(
                r#"{{"ok":{},"elapsed_ms":{}}}"#,
                result.is_ok(),
                elapsed.as_millis()
            ),
        );

        let pooled = result.expect("real postgres connect should succeed");
        let stats = pool.stats();
        assert_eq!(stats.total, 1, "exactly one connection created");
        assert_eq!(stats.active, 1, "connection is checked out");
        drop(pooled);

        let stats = pool.stats();
        assert_eq!(stats.idle, 1, "connection returned to pool on drop");
        assert_eq!(stats.active, 0);
        jlog(suite, "assert", "pool_stats_ok", "{}");
    }

    #[test]
    fn pg_e2e_backoff_under_iptables_block_then_recover() {
        let suite = "pg_backoff_recover";
        if !docker_available() {
            jlog(suite, "skip", "no_docker", "{}");
            return;
        }
        if !sudo_iptables_available() {
            jlog(suite, "skip", "no_sudo_iptables", "{}");
            return;
        }
        let Some(c) = start_postgres() else {
            jlog(suite, "skip", "postgres_failed_to_start", "{}");
            return;
        };
        jlog(
            suite,
            "setup",
            "container_ready",
            &format!(r#"{{"port":{}}}"#, c.port),
        );

        // Baseline: prove the path works before any fault injection.
        let pool = AsyncDbPool::new(
            PgRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(8)),
        );
        let cx = Cx::for_testing();
        block_on(pool.get(&cx))
            .expect("baseline real-DB connect must succeed before any fault is injected");
        jlog(suite, "baseline", "connect_ok", "{}");

        // Arm the network fault.
        let mut block = IptablesBlock::arm(c.port);
        if !block.armed {
            jlog(suite, "skip", "iptables_arm_failed", "{}");
            return;
        }
        jlog(
            suite,
            "fault",
            "iptables_armed",
            &format!(r#"{{"port":{}}}"#, c.port),
        );

        // Fresh pool with tight timeout + deterministic backoff.
        let pool = AsyncDbPool::new(
            PgRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(2_000)),
        );
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(80), 4).no_jitter();

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();
        jlog(
            suite,
            "act",
            "blocked_retry_returned",
            &format!(
                r#"{{"is_err":{},"elapsed_ms":{}}}"#,
                result.is_err(),
                elapsed.as_millis()
            ),
        );

        // Backoff invariant: TCP REJECT --reject-with tcp-reset returns
        // ECONNREFUSED almost immediately, so the dominant time is spent
        // sleeping between retry attempts. With 4 attempts and 80ms fixed
        // delay we expect at least 3 inter-attempt sleeps; 160ms is a
        // conservative lower bound that proves backoff actually engaged
        // rather than spinning.
        match result {
            Err(DbPoolError::Connect(_)) | Err(DbPoolError::Timeout) => {
                assert!(
                    elapsed >= Duration::from_millis(160),
                    "expected ≥160ms cumulative backoff, observed {elapsed:?}"
                );
            }
            Err(other) => panic!("unexpected error from blocked get_with_retry: {other:?}"),
            Ok(_) => panic!("expected failure under iptables REJECT block"),
        }

        // Recovery: drop the rule, fresh get must succeed.
        block.disarm();
        std::thread::sleep(Duration::from_millis(200));
        let pool = AsyncDbPool::new(
            PgRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(5)),
        );
        block_on(pool.get(&cx)).expect("post-unblock connect must succeed");
        jlog(suite, "recovery", "connect_ok_after_unblock", "{}");
    }

    #[test]
    fn pg_e2e_close_rejects_subsequent_gets() {
        let suite = "pg_close_rejects";
        if !docker_available() {
            jlog(suite, "skip", "no_docker", "{}");
            return;
        }
        let Some(c) = start_postgres() else {
            jlog(suite, "skip", "postgres_failed_to_start", "{}");
            return;
        };

        let pool = AsyncDbPool::new(
            PgRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(8)),
        );
        let cx = Cx::for_testing();
        let conn = block_on(pool.get(&cx)).expect("real-DB connect ok");
        drop(conn);

        pool.close();
        match block_on(pool.get(&cx)) {
            Err(DbPoolError::Closed) => {}
            other => panic!("post-close get must return Closed, got {other:?}"),
        }
        jlog(suite, "assert", "post_close_rejected", "{}");
    }
}

// ─── MySQL real-DB E2E ─────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
mod mysql {
    use super::*;
    use asupersync::database::mysql::{MySqlConnection, MySqlError};

    struct MySqlRealManager {
        url: String,
    }

    impl AsyncConnectionManager for MySqlRealManager {
        type Connection = MySqlConnection;
        type Error = MySqlError;

        async fn connect(&self, cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            MySqlConnection::connect(cx, &self.url).await
        }

        async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
            true
        }
    }

    fn url(port: u16) -> String {
        format!("mysql://testuser:testpass@127.0.0.1:{port}/testdb")
    }

    #[test]
    fn mysql_e2e_happy_pool_get_real_connection() {
        let suite = "mysql_happy";
        if !docker_available() {
            jlog(suite, "skip", "no_docker", "{}");
            return;
        }
        let Some(c) = start_mysql() else {
            jlog(suite, "skip", "mysql_failed_to_start", "{}");
            return;
        };
        jlog(
            suite,
            "setup",
            "container_ready",
            &format!(r#"{{"port":{}}}"#, c.port),
        );

        let pool = AsyncDbPool::new(
            MySqlRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(8)),
        );
        let cx = Cx::for_testing();
        let pooled = block_on(pool.get(&cx)).expect("real mysql connect should succeed");
        let stats = pool.stats();
        assert_eq!(stats.total, 1);
        drop(pooled);
        assert_eq!(pool.stats().idle, 1);
        jlog(suite, "assert", "pool_stats_ok", "{}");
    }

    #[test]
    fn mysql_e2e_backoff_under_iptables_block_then_recover() {
        let suite = "mysql_backoff_recover";
        if !docker_available() {
            jlog(suite, "skip", "no_docker", "{}");
            return;
        }
        if !sudo_iptables_available() {
            jlog(suite, "skip", "no_sudo_iptables", "{}");
            return;
        }
        let Some(c) = start_mysql() else {
            jlog(suite, "skip", "mysql_failed_to_start", "{}");
            return;
        };

        let pool = AsyncDbPool::new(
            MySqlRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(8)),
        );
        let cx = Cx::for_testing();
        block_on(pool.get(&cx)).expect("baseline mysql connect must succeed");
        jlog(suite, "baseline", "connect_ok", "{}");

        let mut block = IptablesBlock::arm(c.port);
        if !block.armed {
            jlog(suite, "skip", "iptables_arm_failed", "{}");
            return;
        }

        let pool = AsyncDbPool::new(
            MySqlRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(2_000)),
        );
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(80), 4).no_jitter();

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();
        jlog(
            suite,
            "act",
            "blocked_retry_returned",
            &format!(
                r#"{{"is_err":{},"elapsed_ms":{}}}"#,
                result.is_err(),
                elapsed.as_millis()
            ),
        );

        match result {
            Err(DbPoolError::Connect(_)) | Err(DbPoolError::Timeout) => {
                assert!(
                    elapsed >= Duration::from_millis(160),
                    "expected ≥160ms cumulative backoff, observed {elapsed:?}"
                );
            }
            Err(other) => panic!("unexpected error from blocked get_with_retry: {other:?}"),
            Ok(_) => panic!("expected failure under iptables REJECT block"),
        }

        block.disarm();
        std::thread::sleep(Duration::from_millis(200));
        let pool = AsyncDbPool::new(
            MySqlRealManager { url: url(c.port) },
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(5)),
        );
        block_on(pool.get(&cx)).expect("post-unblock connect must succeed");
        jlog(suite, "recovery", "connect_ok_after_unblock", "{}");
    }
}
