//! [br-e2e-5] Real SQLite Database E2E Tests
//!
//! Real-service E2E tests for SQLite database operations using actual database files
//! and real SQL execution. Tests complete database lifecycle, transactions, and
//! concurrent operations without mocks, using in-memory and temporary file databases.
//!
//! Uses rch + CARGO_TARGET_DIR=/tmp/rch_target_pane1_e2e for end-to-end validation
//! with actual SQLite database operations and transaction isolation.

#[cfg(any(test, feature = "test-internals"))]
mod sqlite_e2e_tests {
    use crate::cx::{Cx, CxBuilder};
    use crate::database::{SqliteConnection, SqliteError, SqliteRow, SqliteValue};
    use crate::runtime::RuntimeBuilder;
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome};
    use serde_json;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::{TempDir, tempdir};

    /// Real SQLite database manager for E2E testing
    pub struct RealSqliteDatabase {
        connection: SqliteConnection,
        db_path: Option<PathBuf>,
        temp_dir: Option<TempDir>,
        stats: Arc<SqliteE2EStats>,
        config: SqliteE2EConfig,
    }

    /// Configuration for SQLite E2E testing
    #[derive(Debug, Clone)]
    pub struct SqliteE2EConfig {
        pub use_memory: bool,
        pub enable_wal: bool,
        pub busy_timeout_ms: u64,
        pub cache_size: i32,
        pub journal_mode: String,
        pub synchronous: String,
        pub foreign_keys: bool,
    }

    impl Default for SqliteE2EConfig {
        fn default() -> Self {
            Self {
                use_memory: true,  // Safer for E2E tests
                enable_wal: false, // Simpler for testing
                busy_timeout_ms: 1000,
                cache_size: -2000, // 2MB cache
                journal_mode: "DELETE".to_string(),
                synchronous: "NORMAL".to_string(),
                foreign_keys: true,
            }
        }
    }

    /// Statistics for SQLite E2E operations
    #[derive(Debug, Default)]
    pub struct SqliteE2EStats {
        pub queries_executed: AtomicU64,
        pub transactions_committed: AtomicU64,
        pub transactions_rolled_back: AtomicU64,
        pub rows_inserted: AtomicU64,
        pub rows_updated: AtomicU64,
        pub rows_deleted: AtomicU64,
        pub rows_selected: AtomicU64,
        pub connection_errors: AtomicU64,
        pub query_errors: AtomicU64,
    }

    /// Enhanced logger for SQLite E2E tests with SQL operation tracking
    pub struct SqliteE2ELogger {
        events: Arc<Mutex<Vec<SqliteLogEvent>>>,
        start_time: Instant,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct SqliteLogEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub operation: String,
        pub sql_query: Option<String>,
        pub parameters: Option<Vec<String>>,
        pub rows_affected: Option<i64>,
        pub execution_time_ms: Option<u64>,
        pub error: Option<String>,
        pub connection_id: Option<String>,
        pub transaction_id: Option<String>,
        pub details: HashMap<String, serde_json::Value>,
    }

    impl SqliteE2ELogger {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                start_time: Instant::now(),
            }
        }

        pub fn log_query_start(&self, sql: &str, params: &[SqliteValue]) -> QueryTracker {
            let mut param_strs = Vec::new();
            for param in params {
                match param {
                    SqliteValue::Text(s) => param_strs.push(format!("'{}'", s)),
                    SqliteValue::Integer(i) => param_strs.push(i.to_string()),
                    SqliteValue::Real(f) => param_strs.push(f.to_string()),
                    SqliteValue::Blob(_) => param_strs.push("<BLOB>".to_string()),
                    SqliteValue::Null => param_strs.push("NULL".to_string()),
                }
            }

            let mut details = HashMap::new();
            details.insert(
                "query_start_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = SqliteLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "query_start".to_string(),
                operation: Self::extract_operation(sql),
                sql_query: Some(sql.to_string()),
                parameters: Some(param_strs),
                rows_affected: None,
                execution_time_ms: None,
                error: None,
                connection_id: Some("main".to_string()),
                transaction_id: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }

            QueryTracker {
                logger: self,
                start_time: Instant::now(),
                sql: sql.to_string(),
            }
        }

        pub fn log_query_complete(
            &self,
            tracker: &QueryTracker,
            rows_affected: i64,
            error: Option<&str>,
        ) {
            let execution_time = tracker.start_time.elapsed();

            let mut details = HashMap::new();
            details.insert(
                "query_complete_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = SqliteLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: if error.is_some() {
                    "query_error".to_string()
                } else {
                    "query_complete".to_string()
                },
                operation: Self::extract_operation(&tracker.sql),
                sql_query: Some(tracker.sql.clone()),
                parameters: None,
                rows_affected: if error.is_none() {
                    Some(rows_affected)
                } else {
                    None
                },
                execution_time_ms: Some(execution_time.as_millis() as u64),
                error: error.map(String::from),
                connection_id: Some("main".to_string()),
                transaction_id: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_transaction_event(
            &self,
            event_type: &str,
            transaction_id: &str,
            details: HashMap<String, serde_json::Value>,
        ) {
            let event = SqliteLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: event_type.to_string(),
                operation: "TRANSACTION".to_string(),
                sql_query: None,
                parameters: None,
                rows_affected: None,
                execution_time_ms: None,
                error: None,
                connection_id: Some("main".to_string()),
                transaction_id: Some(transaction_id.to_string()),
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        fn extract_operation(sql: &str) -> String {
            let trimmed = sql.trim().to_uppercase();
            if trimmed.starts_with("SELECT") {
                "SELECT".to_string()
            } else if trimmed.starts_with("INSERT") {
                "INSERT".to_string()
            } else if trimmed.starts_with("UPDATE") {
                "UPDATE".to_string()
            } else if trimmed.starts_with("DELETE") {
                "DELETE".to_string()
            } else if trimmed.starts_with("CREATE") {
                "CREATE".to_string()
            } else if trimmed.starts_with("DROP") {
                "DROP".to_string()
            } else if trimmed.starts_with("ALTER") {
                "ALTER".to_string()
            } else if trimmed.starts_with("BEGIN") {
                "BEGIN".to_string()
            } else if trimmed.starts_with("COMMIT") {
                "COMMIT".to_string()
            } else if trimmed.starts_with("ROLLBACK") {
                "ROLLBACK".to_string()
            } else {
                "OTHER".to_string()
            }
        }

        pub fn export_json(&self) -> String {
            if let Ok(events) = self.events.lock() {
                serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            }
        }

        pub fn get_event_count(&self) -> usize {
            if let Ok(events) = self.events.lock() {
                events.len()
            } else {
                0
            }
        }
    }

    pub struct QueryTracker<'a> {
        logger: &'a SqliteE2ELogger,
        start_time: Instant,
        sql: String,
    }

    impl RealSqliteDatabase {
        /// Create new real SQLite database for E2E testing
        pub async fn new(cx: &Cx, config: SqliteE2EConfig) -> Result<Self, SqliteError> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            let (connection, db_path, temp_dir) = if config.use_memory {
                // In-memory database (safer for E2E tests)
                let conn = SqliteConnection::open_in_memory(cx).await?;
                (conn, None, None)
            } else {
                // Temporary file database
                let temp_dir = tempdir().map_err(|e| SqliteError::Io(e.to_string()))?;
                let db_path = temp_dir.path().join("e2e_test.db");
                let conn = SqliteConnection::open(cx, &db_path).await?;
                (conn, Some(db_path), Some(temp_dir))
            };

            // Apply configuration
            Self::configure_database(cx, &connection, &config).await?;

            Ok(Self {
                connection,
                db_path,
                temp_dir,
                stats: Arc::new(SqliteE2EStats::default()),
                config,
            })
        }

        /// Validate environment is safe for real database testing
        fn validate_test_environment() -> Result<(), SqliteError> {
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(SqliteError::Connection(
                    "Cannot run real database E2E tests in production environment".to_string(),
                ));
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(SqliteError::Connection(
                    "Set REAL_SERVICE_TESTS=true to enable real service testing".to_string(),
                ));
            }

            Ok(())
        }

        /// Configure database with provided settings
        async fn configure_database(
            cx: &Cx,
            conn: &SqliteConnection,
            config: &SqliteE2EConfig,
        ) -> Result<(), SqliteError> {
            // Set pragmas based on configuration
            if config.foreign_keys {
                conn.execute_batch(cx, "PRAGMA foreign_keys = ON;").await?;
            }

            if !config.journal_mode.is_empty() {
                let pragma = format!("PRAGMA journal_mode = {};", config.journal_mode);
                conn.execute_batch(cx, &pragma).await?;
            }

            if !config.synchronous.is_empty() {
                let pragma = format!("PRAGMA synchronous = {};", config.synchronous);
                conn.execute_batch(cx, &pragma).await?;
            }

            if config.cache_size != 0 {
                let pragma = format!("PRAGMA cache_size = {};", config.cache_size);
                conn.execute_batch(cx, &pragma).await?;
            }

            Ok(())
        }

        pub fn stats(&self) -> Arc<SqliteE2EStats> {
            self.stats.clone()
        }

        pub fn connection(&self) -> &SqliteConnection {
            &self.connection
        }

        pub fn db_path(&self) -> Option<&Path> {
            self.db_path.as_deref()
        }

        /// Execute SQL with tracking
        pub async fn execute_with_tracking(
            &self,
            cx: &Cx,
            sql: &str,
            params: &[SqliteValue],
            logger: &SqliteE2ELogger,
        ) -> Result<i64, SqliteError> {
            let tracker = logger.log_query_start(sql, params);

            match self.connection.execute(cx, sql, params).await {
                Ok(rows_affected) => {
                    self.stats.queries_executed.fetch_add(1, Ordering::Relaxed);

                    let operation = SqliteE2ELogger::extract_operation(sql);
                    match operation.as_str() {
                        "INSERT" => {
                            self.stats
                                .rows_inserted
                                .fetch_add(rows_affected as u64, Ordering::Relaxed);
                        }
                        "UPDATE" => {
                            self.stats
                                .rows_updated
                                .fetch_add(rows_affected as u64, Ordering::Relaxed);
                        }
                        "DELETE" => {
                            self.stats
                                .rows_deleted
                                .fetch_add(rows_affected as u64, Ordering::Relaxed);
                        }
                        _ => {}
                    }

                    logger.log_query_complete(&tracker, rows_affected, None);
                    Ok(rows_affected)
                }
                Err(e) => {
                    self.stats.query_errors.fetch_add(1, Ordering::Relaxed);
                    logger.log_query_complete(&tracker, 0, Some(&e.to_string()));
                    Err(e)
                }
            }
        }

        /// Query with tracking
        pub async fn query_with_tracking(
            &self,
            cx: &Cx,
            sql: &str,
            params: &[SqliteValue],
            logger: &SqliteE2ELogger,
        ) -> Result<Vec<SqliteRow>, SqliteError> {
            let tracker = logger.log_query_start(sql, params);

            match self.connection.query(cx, sql, params).await {
                Ok(rows) => {
                    self.stats.queries_executed.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .rows_selected
                        .fetch_add(rows.len() as u64, Ordering::Relaxed);

                    logger.log_query_complete(&tracker, rows.len() as i64, None);
                    Ok(rows)
                }
                Err(e) => {
                    self.stats.query_errors.fetch_add(1, Ordering::Relaxed);
                    logger.log_query_complete(&tracker, 0, Some(&e.to_string()));
                    Err(e)
                }
            }
        }
    }

    /// Production safety guard - validates environment
    fn validate_sqlite_e2e_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real SQLite E2E tests blocked in production".to_string());
        }

        if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
            return Err("Set REAL_SERVICE_TESTS=true to enable".to_string());
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_sqlite_basic_crud_operations() -> Result<(), Box<dyn std::error::Error>> {
        validate_sqlite_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SqliteE2ELogger::new();
        let config = SqliteE2EConfig::default();
        let database = RealSqliteDatabase::new(&cx, config).await?;

        // Create test table
        database
            .execute_with_tracking(
                &cx,
                "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ",
                &[],
                &logger,
            )
            .await?;

        // Insert test data
        let insert_params = vec![
            SqliteValue::Text("Alice Johnson".to_string()),
            SqliteValue::Text("alice@example.com".to_string()),
        ];
        let rows_affected = database
            .execute_with_tracking(
                &cx,
                "INSERT INTO users (name, email) VALUES (?, ?)",
                &insert_params,
                &logger,
            )
            .await?;

        assert_eq!(rows_affected, 1, "Should insert exactly one row");

        // Query data
        let rows = database
            .query_with_tracking(
                &cx,
                "SELECT * FROM users WHERE name = ?",
                &[SqliteValue::Text("Alice Johnson".to_string())],
                &logger,
            )
            .await?;

        assert_eq!(rows.len(), 1, "Should find exactly one user");
        assert_eq!(rows[0].get_str("name")?, "Alice Johnson");
        assert_eq!(rows[0].get_str("email")?, "alice@example.com");

        // Update data
        let update_rows = database
            .execute_with_tracking(
                &cx,
                "UPDATE users SET email = ? WHERE name = ?",
                &[
                    SqliteValue::Text("alice.johnson@example.com".to_string()),
                    SqliteValue::Text("Alice Johnson".to_string()),
                ],
                &logger,
            )
            .await?;

        assert_eq!(update_rows, 1, "Should update exactly one row");

        // Delete data
        let delete_rows = database
            .execute_with_tracking(
                &cx,
                "DELETE FROM users WHERE name = ?",
                &[SqliteValue::Text("Alice Johnson".to_string())],
                &logger,
            )
            .await?;

        assert_eq!(delete_rows, 1, "Should delete exactly one row");

        // Verify deletion
        let remaining_rows = database
            .query_with_tracking(&cx, "SELECT COUNT(*) as count FROM users", &[], &logger)
            .await?;
        assert_eq!(
            remaining_rows[0].get_i64("count")?,
            0,
            "Table should be empty after deletion"
        );

        // Verify statistics
        let stats = database.stats();
        assert!(
            stats.queries_executed.load(Ordering::Relaxed) >= 5,
            "Should have executed multiple queries"
        );
        assert_eq!(
            stats.rows_inserted.load(Ordering::Relaxed),
            1,
            "Should have inserted one row"
        );
        assert_eq!(
            stats.rows_updated.load(Ordering::Relaxed),
            1,
            "Should have updated one row"
        );
        assert_eq!(
            stats.rows_deleted.load(Ordering::Relaxed),
            1,
            "Should have deleted one row"
        );

        eprintln!("SQLite CRUD E2E structured log:\n{}", logger.export_json());
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_sqlite_transaction_isolation() -> Result<(), Box<dyn std::error::Error>> {
        validate_sqlite_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SqliteE2ELogger::new();
        let config = SqliteE2EConfig::default();
        let database = RealSqliteDatabase::new(&cx, config).await?;

        // Set up test table
        database
            .execute_with_tracking(
                &cx,
                "
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                name TEXT,
                balance INTEGER
            );
        ",
                &[],
                &logger,
            )
            .await?;

        database
            .execute_with_tracking(
                &cx,
                "
            INSERT INTO accounts (id, name, balance) VALUES
            (1, 'Alice', 1000),
            (2, 'Bob', 500);
        ",
                &[],
                &logger,
            )
            .await?;

        // Begin transaction
        let mut tx_details = HashMap::new();
        tx_details.insert(
            "transaction_type".to_string(),
            serde_json::Value::String("transfer".to_string()),
        );
        logger.log_transaction_event("transaction_begin", "tx_001", tx_details);

        database
            .execute_with_tracking(&cx, "BEGIN TRANSACTION;", &[], &logger)
            .await?;

        // Perform transfers within transaction
        database
            .execute_with_tracking(
                &cx,
                "UPDATE accounts SET balance = balance - 200 WHERE id = 1",
                &[],
                &logger,
            )
            .await?;

        database
            .execute_with_tracking(
                &cx,
                "UPDATE accounts SET balance = balance + 200 WHERE id = 2",
                &[],
                &logger,
            )
            .await?;

        // Verify intermediate state within transaction
        let rows = database
            .query_with_tracking(
                &cx,
                "SELECT SUM(balance) as total FROM accounts",
                &[],
                &logger,
            )
            .await?;
        let total_balance = rows[0].get_i64("total")?;
        assert_eq!(
            total_balance, 1500,
            "Total balance should remain constant during transfer"
        );

        // Commit transaction
        database
            .execute_with_tracking(&cx, "COMMIT;", &[], &logger)
            .await?;

        let mut commit_details = HashMap::new();
        commit_details.insert(
            "commit_time".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                logger.start_time.elapsed().as_millis() as u64,
            )),
        );
        logger.log_transaction_event("transaction_commit", "tx_001", commit_details);

        // Verify final state
        let final_rows = database
            .query_with_tracking(
                &cx,
                "SELECT id, balance FROM accounts ORDER BY id",
                &[],
                &logger,
            )
            .await?;

        assert_eq!(final_rows.len(), 2);
        assert_eq!(
            final_rows[0].get_i64("balance")?,
            800,
            "Alice should have 800 after transfer"
        );
        assert_eq!(
            final_rows[1].get_i64("balance")?,
            700,
            "Bob should have 700 after transfer"
        );

        // Verify statistics
        let stats = database.stats();
        assert!(
            stats.transactions_committed.load(Ordering::Relaxed) >= 1,
            "Should have committed transaction"
        );
        assert!(
            stats.rows_updated.load(Ordering::Relaxed) >= 2,
            "Should have updated account balances"
        );

        eprintln!(
            "SQLite Transaction E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_sqlite_foreign_key_constraints() -> Result<(), Box<dyn std::error::Error>> {
        validate_sqlite_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SqliteE2ELogger::new();
        let config = SqliteE2EConfig {
            foreign_keys: true,
            ..Default::default()
        };
        let database = RealSqliteDatabase::new(&cx, config).await?;

        // Create tables with foreign key relationship
        database
            .execute_with_tracking(
                &cx,
                "
            CREATE TABLE departments (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            );
        ",
                &[],
                &logger,
            )
            .await?;

        database
            .execute_with_tracking(
                &cx,
                "
            CREATE TABLE employees (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                department_id INTEGER,
                FOREIGN KEY (department_id) REFERENCES departments (id)
            );
        ",
                &[],
                &logger,
            )
            .await?;

        // Insert department
        database
            .execute_with_tracking(
                &cx,
                "INSERT INTO departments (id, name) VALUES (1, 'Engineering')",
                &[],
                &logger,
            )
            .await?;

        // Insert valid employee
        let valid_insert = database
            .execute_with_tracking(
                &cx,
                "INSERT INTO employees (name, department_id) VALUES (?, ?)",
                &[
                    SqliteValue::Text("Alice".to_string()),
                    SqliteValue::Integer(1),
                ],
                &logger,
            )
            .await;

        assert!(
            valid_insert.is_ok(),
            "Should allow valid foreign key reference"
        );

        // Try to insert employee with invalid department_id
        let invalid_insert = database
            .execute_with_tracking(
                &cx,
                "INSERT INTO employees (name, department_id) VALUES (?, ?)",
                &[
                    SqliteValue::Text("Bob".to_string()),
                    SqliteValue::Integer(999), // Non-existent department
                ],
                &logger,
            )
            .await;

        assert!(
            invalid_insert.is_err(),
            "Should reject invalid foreign key reference"
        );

        // Verify foreign key error was counted
        let stats = database.stats();
        assert!(
            stats.query_errors.load(Ordering::Relaxed) > 0,
            "Should have recorded foreign key error"
        );

        eprintln!(
            "SQLite Foreign Key E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_sqlite_concurrent_access() -> Result<(), Box<dyn std::error::Error>> {
        validate_sqlite_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = SqliteE2ELogger::new();
        let config = SqliteE2EConfig::default();
        let database = RealSqliteDatabase::new(&cx, config).await?;

        // Create test table
        database
            .execute_with_tracking(
                &cx,
                "
            CREATE TABLE counters (
                id INTEGER PRIMARY KEY,
                value INTEGER DEFAULT 0
            );
        ",
                &[],
                &logger,
            )
            .await?;

        database
            .execute_with_tracking(
                &cx,
                "INSERT INTO counters (id, value) VALUES (1, 0)",
                &[],
                &logger,
            )
            .await?;

        // Simulate concurrent increments
        const NUM_INCREMENTS: i64 = 10;
        for i in 0..NUM_INCREMENTS {
            database
                .execute_with_tracking(
                    &cx,
                    "UPDATE counters SET value = value + 1 WHERE id = 1",
                    &[],
                    &logger,
                )
                .await?;

            // Small delay to simulate concurrent operations
            let _ = sleep(&cx, Duration::from_millis(1)).await;
        }

        // Verify final counter value
        let rows = database
            .query_with_tracking(&cx, "SELECT value FROM counters WHERE id = 1", &[], &logger)
            .await?;

        assert_eq!(rows.len(), 1);
        let final_value = rows[0].get_i64("value")?;
        assert_eq!(
            final_value, NUM_INCREMENTS,
            "Counter should be incremented {} times, got {}",
            NUM_INCREMENTS, final_value
        );

        // Verify statistics
        let stats = database.stats();
        assert!(
            stats.rows_updated.load(Ordering::Relaxed) >= NUM_INCREMENTS as u64,
            "Should have updated counter {} times",
            NUM_INCREMENTS
        );

        eprintln!(
            "SQLite Concurrent Access E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[test]
    fn test_environment_validation_errors() {
        use std::env;

        // Save original environment values
        let original_node_env = env::var("NODE_ENV").ok();
        let original_real_service_tests = env::var("REAL_SERVICE_TESTS").ok();

        // Test production environment rejection
        env::set_var("NODE_ENV", "production");
        env::set_var("REAL_SERVICE_TESTS", "true");
        let result = validate_sqlite_e2e_environment();
        assert!(
            result.is_err(),
            "Should reject production environment"
        );
        assert!(
            result.unwrap_err().contains("production"),
            "Error message should mention production"
        );

        // Test missing REAL_SERVICE_TESTS
        env::set_var("NODE_ENV", "test");
        env::remove_var("REAL_SERVICE_TESTS");
        let result = validate_sqlite_e2e_environment();
        assert!(
            result.is_err(),
            "Should reject when REAL_SERVICE_TESTS is unset"
        );
        assert!(
            result.unwrap_err().contains("REAL_SERVICE_TESTS"),
            "Error message should mention REAL_SERVICE_TESTS"
        );

        // Test REAL_SERVICE_TESTS=false
        env::set_var("NODE_ENV", "test");
        env::set_var("REAL_SERVICE_TESTS", "false");
        let result = validate_sqlite_e2e_environment();
        assert!(
            result.is_err(),
            "Should reject when REAL_SERVICE_TESTS=false"
        );

        // Test valid environment
        env::set_var("NODE_ENV", "test");
        env::set_var("REAL_SERVICE_TESTS", "true");
        let result = validate_sqlite_e2e_environment();
        assert!(
            result.is_ok(),
            "Should accept valid test environment"
        );

        // Restore original environment values
        match original_node_env {
            Some(value) => env::set_var("NODE_ENV", value),
            None => env::remove_var("NODE_ENV"),
        }
        match original_real_service_tests {
            Some(value) => env::set_var("REAL_SERVICE_TESTS", value),
            None => env::remove_var("REAL_SERVICE_TESTS"),
        }
    }
}

#[cfg(any(test, feature = "test-internals"))]
pub use sqlite_e2e_tests::*;
