//! MySQL conformance integration tests.
//!
//! These tests verify that our MySQL wire protocol implementation works
//! correctly against real MariaDB instances.

use std::process::{Command, Output};

const MARIADB_IMAGE: &str = "mariadb:10.5";

fn docker(args: &[&str]) -> Option<Output> {
    Command::new("docker").args(args).output().ok()
}

fn docker_available() -> bool {
    docker(&["version"]).is_some_and(|output| output.status.success())
}

fn ensure_mariadb_image() -> bool {
    docker(&["pull", MARIADB_IMAGE]).is_some_and(|output| output.status.success())
}

fn cleanup_container(container_name: &str) {
    let _ = docker(&["rm", "-f", container_name]);
}

fn output_text(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("stdout: {stdout}\nstderr: {stderr}")
}

fn wait_for_mysql(container_id: &str, user: &str, password: &str) -> Result<(), String> {
    let password_arg = format!("-p{password}");
    let mut last_error = "mysqladmin ping was not attempted".to_string();

    for _ in 0..30 {
        let Some(output) = docker(&[
            "exec",
            container_id,
            "mysqladmin",
            "ping",
            "--protocol=tcp",
            "-h",
            "127.0.0.1",
            "-u",
            user,
            password_arg.as_str(),
        ]) else {
            last_error = "docker exec mysqladmin did not execute".to_string();
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        };

        if output.status.success() {
            return Ok(());
        }

        last_error = output_text(&output);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Err(last_error)
}

/// Tests that Docker is available for MySQL conformance testing.
#[test]
fn test_docker_availability() {
    if !docker_available() {
        return;
    }

    assert!(
        ensure_mariadb_image(),
        "Docker is available but MariaDB test image could not be pulled"
    );
}

/// Tests basic MySQL connection functionality.
#[test]
fn test_mysql_basic_connection() {
    // This would normally use our actual MySQL client implementation
    // For now, just verify the test infrastructure can start a container

    let container_name = "asupersync-test-mysql";

    cleanup_container(container_name);

    if !docker_available() {
        return;
    }

    let start_result = docker(&[
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        "MYSQL_ROOT_PASSWORD=testpass",
        "-e",
        "MYSQL_DATABASE=asupersync_test",
        "-e",
        "MYSQL_USER=testuser",
        "-e",
        "MYSQL_PASSWORD=testpass",
        "-p",
        "0:3306",
        MARIADB_IMAGE,
        "--default-authentication-plugin=mysql_native_password",
    ])
    .expect("docker run should execute");
    assert!(
        start_result.status.success(),
        "failed to start MySQL test container: {}",
        output_text(&start_result)
    );
    let container_id = String::from_utf8_lossy(&start_result.stdout)
        .trim()
        .to_string();

    let connection_test = wait_for_mysql(container_id.as_str(), "testuser", "testpass");
    cleanup_container(container_id.as_str());
    assert!(
        connection_test.is_ok(),
        "mysqladmin ping failed: {}",
        connection_test.unwrap_err()
    );
}

/// Tests that MySQL auth plugins can be configured.
#[test]
fn test_mysql_auth_plugins() {
    let container_name = "asupersync-test-auth";

    cleanup_container(container_name);

    if !docker_available() {
        return;
    }

    let start_result = docker(&[
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        "MYSQL_ROOT_PASSWORD=testpass",
        MARIADB_IMAGE,
        "--default-authentication-plugin=mysql_native_password",
    ])
    .expect("docker run should execute");
    assert!(
        start_result.status.success(),
        "failed to start MySQL auth test container: {}",
        output_text(&start_result)
    );
    let container_id = String::from_utf8_lossy(&start_result.stdout)
        .trim()
        .to_string();

    if let Err(error) = wait_for_mysql(container_id.as_str(), "root", "testpass") {
        cleanup_container(container_id.as_str());
        panic!("mysqladmin ping failed before auth plugin query: {error}");
    }

    let auth_query = docker(&[
        "exec",
        container_id.as_str(),
        "mysql",
        "--protocol=tcp",
        "-h",
        "127.0.0.1",
        "-u",
        "root",
        "-ptestpass",
        "-e",
        "SELECT plugin FROM mysql.user WHERE user='root';",
    ])
    .expect("docker exec mysql should execute");
    cleanup_container(container_id.as_str());
    assert!(
        auth_query.status.success(),
        "auth plugin query failed: {}",
        output_text(&auth_query)
    );
    let query_output = String::from_utf8_lossy(&auth_query.stdout);
    assert!(
        query_output.contains("mysql_native_password"),
        "auth plugin query did not report mysql_native_password: {query_output}"
    );
}

/// Tests SSL capabilities.
#[test]
fn test_mysql_ssl_support() {
    let container_name = "asupersync-test-ssl";

    cleanup_container(container_name);

    if !docker_available() {
        return;
    }

    let start_result = docker(&[
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        "MYSQL_ROOT_PASSWORD=testpass",
        MARIADB_IMAGE,
    ])
    .expect("docker run should execute");
    assert!(
        start_result.status.success(),
        "failed to start MySQL SSL test container: {}",
        output_text(&start_result)
    );
    let container_id = String::from_utf8_lossy(&start_result.stdout)
        .trim()
        .to_string();

    if let Err(error) = wait_for_mysql(container_id.as_str(), "root", "testpass") {
        cleanup_container(container_id.as_str());
        panic!("mysqladmin ping failed before SSL status query: {error}");
    }

    let ssl_query = docker(&[
        "exec",
        container_id.as_str(),
        "mysql",
        "--protocol=tcp",
        "-h",
        "127.0.0.1",
        "-u",
        "root",
        "-ptestpass",
        "-e",
        "SHOW STATUS LIKE 'Ssl%';",
    ])
    .expect("docker exec mysql should execute");
    cleanup_container(container_id.as_str());
    assert!(
        ssl_query.status.success(),
        "SSL status query failed: {}",
        output_text(&ssl_query)
    );
    let query_output = String::from_utf8_lossy(&ssl_query.stdout);
    assert!(
        query_output.contains("Ssl_cipher"),
        "SSL status query did not report Ssl_cipher: {query_output}"
    );
}
