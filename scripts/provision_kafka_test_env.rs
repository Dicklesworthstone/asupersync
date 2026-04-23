#!/usr/bin/env cargo +nightly -Zscript
//! Kafka test environment provisioning and validation.
//!
//! Usage:
//!   cargo +nightly -Zscript provision_kafka_test_env.rs --check
//!   cargo +nightly -Zscript provision_kafka_test_env.rs --setup-docker

use std::process::{Command, Stdio};
use std::collections::HashMap;
use serde_json::{json, Value};

#[derive(Debug)]
struct KafkaTestEnvironment {
    docker_available: bool,
    kafka_running: bool,
    bootstrap_servers: Vec<String>,
    safety_validated: bool,
    environment_issues: Vec<String>,
}

impl KafkaTestEnvironment {
    fn check() -> Self {
        let mut env = Self {
            docker_available: false,
            kafka_running: false,
            bootstrap_servers: Vec::new(),
            safety_validated: false,
            environment_issues: Vec::new(),
        };

        // Check Docker availability
        env.docker_available = Self::check_docker();
        if !env.docker_available {
            env.environment_issues.push("Docker not available or not running".to_string());
        }

        // Production safety checks
        env.safety_validated = Self::validate_safety_guards(&mut env.environment_issues);

        // Check for running Kafka
        if env.docker_available {
            env.kafka_running = Self::check_kafka_container();
            if env.kafka_running {
                env.bootstrap_servers = Self::detect_kafka_bootstrap_servers();
            }
        }

        env
    }

    fn check_docker() -> bool {
        Command::new("docker")
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn validate_safety_guards(issues: &mut Vec<String>) -> bool {
        let mut valid = true;

        // Check NODE_ENV
        if let Ok(node_env) = std::env::var("NODE_ENV") {
            if node_env == "production" {
                issues.push("BLOCKED: NODE_ENV=production (safety guard)".to_string());
                valid = false;
            }
        }

        // Check for production-like hostnames in KAFKA_BOOTSTRAP_SERVERS
        if let Ok(servers) = std::env::var("KAFKA_BOOTSTRAP_SERVERS") {
            let prod_indicators = ["prod", "production", "live", "prd"];
            for server in servers.split(',') {
                for indicator in &prod_indicators {
                    if server.to_lowercase().contains(indicator) {
                        issues.push(format!("BLOCKED: Production-like hostname detected: {}", server));
                        valid = false;
                    }
                }
            }
        }

        valid
    }

    fn check_kafka_container() -> bool {
        let output = Command::new("docker")
            .args(["ps", "--filter", "name=kafka", "--filter", "status=running", "--format", "{{.Names}}"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                !stdout.trim().is_empty()
            }
            Err(_) => false,
        }
    }

    fn detect_kafka_bootstrap_servers() -> Vec<String> {
        // Try common test ports
        let test_ports = ["29092", "19092", "9092"];
        let mut servers = Vec::new();

        for port in &test_ports {
            let server = format!("localhost:{}", port);
            if Self::test_kafka_connectivity(&server) {
                servers.push(server);
                break; // Use first working port
            }
        }

        // Fallback to environment variable
        if servers.is_empty() {
            if let Ok(env_servers) = std::env::var("KAFKA_BOOTSTRAP_SERVERS") {
                servers = env_servers.split(',').map(str::to_string).collect();
            }
        }

        servers
    }

    fn test_kafka_connectivity(server: &str) -> bool {
        // Simple TCP connection test
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        if let Ok(addr) = server.to_socket_addrs() {
            if let Some(addr) = addr.into_iter().next() {
                return TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).is_ok();
            }
        }
        false
    }

    fn setup_docker_kafka() -> Result<(), String> {
        println!("Setting up Docker-based Kafka test environment...");

        // Check if docker-compose is available
        let compose_available = Command::new("docker-compose")
            .args(["--version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if !compose_available {
            return Err("docker-compose not available. Please install Docker Compose.".to_string());
        }

        // Create docker-compose.yml for Kafka testing
        let compose_content = r#"
version: '3.8'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    hostname: zookeeper
    container_name: test-zookeeper
    ports:
      - "22181:2181"
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    healthcheck:
      test: ["CMD", "zookeeper-shell", "localhost:2181", "ls", "/"]
      interval: 10s
      timeout: 5s
      retries: 5

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    hostname: kafka
    container_name: test-kafka
    depends_on:
      zookeeper:
        condition: service_healthy
    ports:
      - "29092:29092"
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: 'zookeeper:2181'
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: 'true'
      KAFKA_NUM_PARTITIONS: 3
    healthcheck:
      test: ["CMD-SHELL", "kafka-topics --bootstrap-server localhost:9092 --list"]
      interval: 10s
      timeout: 5s
      retries: 5
"#;

        std::fs::write("docker-compose-kafka-test.yml", compose_content)
            .map_err(|e| format!("Failed to write docker-compose file: {}", e))?;

        // Start Kafka
        println!("Starting Kafka containers...");
        let output = Command::new("docker-compose")
            .args(["-f", "docker-compose-kafka-test.yml", "up", "-d"])
            .output()
            .map_err(|e| format!("Failed to start docker-compose: {}", e))?;

        if !output.status.success() {
            return Err(format!("Docker-compose failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        // Wait for Kafka to be healthy
        println!("Waiting for Kafka to be ready...");
        for attempt in 1..=30 {
            std::thread::sleep(std::time::Duration::from_secs(2));

            let health_check = Command::new("docker")
                .args(["exec", "test-kafka", "kafka-topics", "--bootstrap-server", "localhost:9092", "--list"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if health_check.map(|s| s.success()).unwrap_or(false) {
                println!("Kafka is ready after {} attempts", attempt);
                return Ok(());
            }

            if attempt % 5 == 0 {
                println!("Still waiting for Kafka... (attempt {})", attempt);
            }
        }

        Err("Kafka failed to become ready within 60 seconds".to_string())
    }

    fn stop_docker_kafka() -> Result<(), String> {
        if std::path::Path::new("docker-compose-kafka-test.yml").exists() {
            println!("Stopping Kafka test containers...");
            let output = Command::new("docker-compose")
                .args(["-f", "docker-compose-kafka-test.yml", "down", "-v"])
                .output()
                .map_err(|e| format!("Failed to stop docker-compose: {}", e))?;

            if !output.status.success() {
                return Err(format!("Failed to stop containers: {}", String::from_utf8_lossy(&output.stderr)));
            }

            // Clean up compose file
            std::fs::remove_file("docker-compose-kafka-test.yml")
                .map_err(|e| format!("Failed to clean up compose file: {}", e))?;
        }

        Ok(())
    }

    fn print_status(&self) {
        let status = json!({
            "kafka_test_environment": {
                "docker_available": self.docker_available,
                "kafka_running": self.kafka_running,
                "bootstrap_servers": self.bootstrap_servers,
                "safety_validated": self.safety_validated,
                "environment_issues": self.environment_issues,
                "ready_for_testing": self.is_ready_for_testing()
            }
        });

        println!("{}", serde_json::to_string_pretty(&status).unwrap());
    }

    fn is_ready_for_testing(&self) -> bool {
        self.safety_validated && self.kafka_running && !self.bootstrap_servers.is_empty()
    }

    fn print_test_instructions(&self) {
        if self.is_ready_for_testing() {
            println!("\n✅ Kafka test environment is ready!");
            println!("\nTo run real broker integration tests:");
            println!("  export REAL_KAFKA_TESTS=true");

            if !self.bootstrap_servers.is_empty() {
                println!("  export KAFKA_BOOTSTRAP_SERVERS={}", self.bootstrap_servers.join(","));
            }

            println!("  cargo test kafka_real_broker --features kafka -- --nocapture");
            println!("\nTo run with structured logging:");
            println!("  REAL_KAFKA_TESTS=true cargo test kafka_real_broker 2>&1 | grep '{{' | jq");
        } else {
            println!("\n❌ Kafka test environment is not ready");

            if !self.safety_validated {
                println!("\n🚨 Safety validation failed:");
                for issue in &self.environment_issues {
                    println!("  - {}", issue);
                }
            }

            if !self.kafka_running {
                println!("\n🔧 To set up Kafka for testing:");
                println!("  cargo +nightly -Zscript provision_kafka_test_env.rs --setup-docker");
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("--check") => {
            let env = KafkaTestEnvironment::check();
            env.print_status();
            env.print_test_instructions();

            if !env.is_ready_for_testing() {
                std::process::exit(1);
            }
        }
        Some("--setup-docker") => {
            let env = KafkaTestEnvironment::check();

            if !env.safety_validated {
                println!("❌ Safety validation failed. Cannot proceed.");
                env.print_status();
                std::process::exit(1);
            }

            if !env.docker_available {
                println!("❌ Docker not available. Please install Docker first.");
                std::process::exit(1);
            }

            match KafkaTestEnvironment::setup_docker_kafka() {
                Ok(()) => {
                    println!("✅ Kafka test environment set up successfully!");

                    // Re-check environment after setup
                    let updated_env = KafkaTestEnvironment::check();
                    updated_env.print_test_instructions();
                }
                Err(e) => {
                    println!("❌ Failed to set up Kafka: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("--stop-docker") => {
            match KafkaTestEnvironment::stop_docker_kafka() {
                Ok(()) => println!("✅ Kafka test environment stopped"),
                Err(e) => {
                    println!("❌ Failed to stop Kafka: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("Kafka Test Environment Provisioning");
            println!();
            println!("Usage:");
            println!("  --check        Check current test environment status");
            println!("  --setup-docker Set up Docker-based Kafka for testing");
            println!("  --stop-docker  Stop and clean up Docker Kafka");
            println!();
            println!("Example workflow:");
            println!("  1. cargo +nightly -Zscript provision_kafka_test_env.rs --setup-docker");
            println!("  2. export REAL_KAFKA_TESTS=true");
            println!("  3. cargo test kafka_real_broker --features kafka");
            println!("  4. cargo +nightly -Zscript provision_kafka_test_env.rs --stop-docker");
        }
    }
}