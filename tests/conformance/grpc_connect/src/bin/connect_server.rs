//! Connect-compatible gRPC test server
//!
//! This binary provides a standalone gRPC server that implements the Connect
//! protocol for conformance testing. It can be used as a reference server
//! or target for external conformance test suites.

use anyhow::{Context, Result};
use asupersync::cx::Cx;
use asupersync::grpc::{Server, ServerBuilder};
use clap::{Arg, Command};
use grpc_conformance_suite::service::create_conformance_test_service;
use std::net::SocketAddr;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "grpc_conformance_suite=info,asupersync=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let matches = Command::new("grpc-connect-server")
        .version("0.1.0")
        .about("Connect-compatible gRPC test server for conformance testing")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Server bind address")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Server port")
                .default_value("8080"),
        )
        .arg(
            Arg::new("max-message-size")
                .long("max-message-size")
                .value_name("BYTES")
                .help("Maximum message size")
                .default_value("4194304"), // 4MB
        )
        .arg(
            Arg::new("enable-compression")
                .long("enable-compression")
                .help("Enable gzip compression")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enable-tls")
                .long("enable-tls")
                .help("Enable TLS/SSL")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("connect-protocol")
                .long("connect-protocol")
                .help("Enable Connect protocol support")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("reflection")
                .long("reflection")
                .help("Enable gRPC reflection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("health-check")
                .long("health-check")
                .help("Enable health check service")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let address = matches.get_one::<String>("address").unwrap();
    let port: u16 = matches.get_one::<String>("port")
        .unwrap()
        .parse()
        .context("Invalid port number")?;

    let bind_addr: SocketAddr = format!("{}:{}", address, port)
        .parse()
        .context("Invalid bind address")?;

    let max_message_size: usize = matches.get_one::<String>("max-message-size")
        .unwrap()
        .parse()
        .context("Invalid max message size")?;

    let enable_compression = matches.get_flag("enable-compression");
    let enable_tls = matches.get_flag("enable-tls");
    let connect_protocol = matches.get_flag("connect-protocol");
    let enable_reflection = matches.get_flag("reflection");
    let enable_health = matches.get_flag("health-check");

    info!("Starting Connect-compatible gRPC test server");
    info!("Bind address: {}", bind_addr);
    info!("Max message size: {} bytes", max_message_size);
    info!("Compression: {}", enable_compression);
    info!("TLS: {}", enable_tls);
    info!("Connect protocol: {}", connect_protocol);
    info!("Reflection: {}", enable_reflection);
    info!("Health check: {}", enable_health);

    // Create the conformance test service
    let test_service = create_conformance_test_service();

    // Build the server
    let mut server_builder = ServerBuilder::new()
        .max_message_size(max_message_size)
        .compression_enabled(enable_compression)
        .add_service(test_service);

    // Add optional services
    if enable_reflection {
        info!("Adding gRPC reflection service");
        // TODO: Add reflection service when available
        warn!("gRPC reflection service not yet implemented");
    }

    if enable_health {
        info!("Adding health check service");
        let health_service = asupersync::grpc::HealthService::new();
        server_builder = server_builder.add_service(health_service);
    }

    // Add Connect protocol support
    if connect_protocol {
        info!("Enabling Connect protocol support");
        // TODO: Add Connect-specific middleware/handlers
        warn!("Connect protocol support not yet fully implemented");
    }

    // Add TLS if requested
    if enable_tls {
        info!("Enabling TLS support");
        // TODO: Add TLS configuration when available
        warn!("TLS support not yet implemented - serving plaintext");
    }

    let server = server_builder.build();

    // Set up graceful shutdown
    let cx = Cx::root();
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Received Ctrl+C, initiating graceful shutdown");
    };

    info!("🚀 gRPC Connect test server listening on {}", bind_addr);
    info!("Available services:");
    info!("  - conformance.TestService (UnaryCall, ServerStreamingCall, ClientStreamingCall, BidirectionalStreamingCall, ErrorTestCall)");

    if enable_health {
        info!("  - grpc.health.v1.Health (Check, Watch)");
    }

    info!("Press Ctrl+C to shutdown");

    // Start the server
    tokio::select! {
        result = server.serve(&cx, bind_addr) => {
            match result {
                Ok(_) => info!("Server shutdown cleanly"),
                Err(e) => {
                    eprintln!("Server error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
        }
    }

    info!("Server stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let app = Command::new("test")
            .arg(
                Arg::new("address")
                    .long("address")
                    .default_value("127.0.0.1"),
            )
            .arg(
                Arg::new("port")
                    .long("port")
                    .default_value("8080"),
            );

        let matches = app.try_get_matches_from(&["test"]).unwrap();
        assert_eq!(matches.get_one::<String>("address").unwrap(), "127.0.0.1");
        assert_eq!(matches.get_one::<String>("port").unwrap(), "8080");
    }

    #[test]
    fn test_bind_address_parsing() {
        let addr: Result<SocketAddr, _> = "127.0.0.1:8080".parse();
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().port(), 8080);
    }
}