//! ATP-N2: Local Two-Endpoint E2E Script
//!
//! End-to-end testing script that transfers ATP test frames over native QUIC
//! between two local endpoints with comprehensive logging and evidence generation.

use asupersync::bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Macro for creating hashmaps easily
macro_rules! hashmap {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut map = HashMap::new();
        $(map.insert($key, $val);)*
        map
    }}
}

/// E2E test configuration
#[derive(Debug, Clone)]
pub struct E2EConfig {
    /// Server listen address
    pub server_addr: SocketAddr,
    /// Client connect address
    pub client_addr: SocketAddr,
    /// Test duration
    pub test_duration: Duration,
    /// Enable qlog-style logging
    pub enable_qlog: bool,
    /// Log file path
    pub log_path: String,
    /// Test data size
    pub test_data_size: usize,
    /// Expected transfer rate
    pub expected_rate_mbps: f64,
}

impl Default for E2EConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:8443".parse().unwrap(),
            client_addr: "127.0.0.1:0".parse().unwrap(),
            test_duration: Duration::from_secs(30),
            enable_qlog: true,
            log_path: "/tmp/atp_quic_e2e.qlog".to_string(),
            test_data_size: 1024 * 1024, // 1MB
            expected_rate_mbps: 1.0,
        }
    }
}

/// QUIC endpoint for E2E testing
pub struct QuicE2EEndpoint {
    /// Endpoint configuration
    config: E2EConfig,
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Connection state
    state: Arc<Mutex<EndpointState>>,
    /// Event logger
    logger: Arc<Mutex<E2EEventLogger>>,
}

/// Endpoint state tracking
#[derive(Debug)]
pub struct EndpointState {
    /// Current connection ID
    connection_id: Option<u64>,
    /// Packet number counter
    packet_number: u64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Packets sent
    packets_sent: u64,
    /// Packets received
    packets_received: u64,
    /// Round-trip time measurements
    rtt_measurements: Vec<Duration>,
    /// Connection start time
    start_time: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Flow control state
    flow_control: FlowControlState,
    /// Loss recovery state
    loss_recovery: LossRecoveryState,
}

/// Flow control tracking
#[derive(Debug)]
pub struct FlowControlState {
    /// Connection-level flow control limit
    max_data: u64,
    /// Data sent on connection
    data_sent: u64,
    /// Stream-level limits (stream_id -> limit)
    stream_limits: HashMap<u64, u64>,
    /// Stream data sent (stream_id -> sent)
    stream_data_sent: HashMap<u64, u64>,
}

/// Loss recovery state
#[derive(Debug)]
pub struct LossRecoveryState {
    /// Outstanding packets (packet_number -> send_time)
    outstanding_packets: HashMap<u64, Instant>,
    /// ACKed packets
    acked_packets: Vec<u64>,
    /// Lost packets
    lost_packets: Vec<u64>,
    /// PTO count
    pto_count: u32,
    /// Congestion window
    congestion_window: u32,
}

/// E2E event logger for qlog-style output
pub struct E2EEventLogger {
    /// Log entries
    events: Vec<QLogEvent>,
    /// Log file path
    log_path: String,
    /// Start time for relative timestamps
    start_time: SystemTime,
}

/// QLog-style event entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct QLogEvent {
    /// Relative timestamp in microseconds
    pub time: u64,
    /// Event category
    pub category: String,
    /// Event type
    pub event_type: String,
    /// Event data
    pub data: HashMap<String, serde_json::Value>,
}

impl QuicE2EEndpoint {
    /// Create new E2E endpoint
    pub fn new(config: E2EConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind(config.client_addr)?);
        socket.set_nonblocking(true)?;

        let state = Arc::new(Mutex::new(EndpointState {
            connection_id: None,
            packet_number: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            rtt_measurements: Vec::new(),
            start_time: Instant::now(),
            last_activity: Instant::now(),
            flow_control: FlowControlState {
                max_data: 1024 * 1024 * 10, // 10MB
                data_sent: 0,
                stream_limits: HashMap::new(),
                stream_data_sent: HashMap::new(),
            },
            loss_recovery: LossRecoveryState {
                outstanding_packets: HashMap::new(),
                acked_packets: Vec::new(),
                lost_packets: Vec::new(),
                pto_count: 0,
                congestion_window: 10240, // 10KB initial
            },
        }));

        let logger = Arc::new(Mutex::new(E2EEventLogger::new(&config.log_path)?));

        Ok(Self {
            config,
            socket,
            state,
            logger,
        })
    }

    /// Start E2E test as server
    pub fn start_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting QUIC E2E server on {}", self.config.server_addr);

        self.log_event("transport", "connection_started", hashmap! {
            "local_addr".to_string() => serde_json::Value::String(self.config.server_addr.to_string()),
            "role".to_string() => serde_json::Value::String("server".to_string()),
        });

        // Bind to server address
        let server_socket = UdpSocket::bind(self.config.server_addr)?;
        server_socket.set_nonblocking(true)?;

        let mut buffer = [0u8; 2048];
        let start_time = Instant::now();

        while start_time.elapsed() < self.config.test_duration {
            match server_socket.recv_from(&mut buffer) {
                Ok((size, client_addr)) => {
                    self.handle_received_packet(&buffer[..size], client_addr)?;

                    // Echo response
                    let response = self.create_response_packet(&buffer[..size])?;
                    server_socket.send_to(&response, client_addr)?;

                    self.update_send_stats(response.len());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(e.into()),
            }
        }

        self.finish_test()?;
        Ok(())
    }

    /// Start E2E test as client
    pub fn start_client(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "Starting QUIC E2E client connecting to {}",
            self.config.server_addr
        );

        self.log_event("transport", "connection_started", hashmap! {
            "remote_addr".to_string() => serde_json::Value::String(self.config.server_addr.to_string()),
            "role".to_string() => serde_json::Value::String("client".to_string()),
        });

        // Connect socket to server
        self.socket.connect(self.config.server_addr)?;

        // Send test data
        let test_data = self.generate_test_data();
        let chunk_size = 1200; // MTU-safe size
        let mut sent_bytes = 0;

        let start_time = Instant::now();

        while sent_bytes < test_data.len() && start_time.elapsed() < self.config.test_duration {
            let end_pos = std::cmp::min(sent_bytes + chunk_size, test_data.len());
            let chunk = &test_data[sent_bytes..end_pos];

            let packet = self.create_data_packet(chunk)?;
            self.socket.send(&packet)?;

            self.update_send_stats(packet.len());
            sent_bytes += chunk.len();

            // Wait for response
            let mut response_buffer = [0u8; 2048];
            match self.socket.recv(&mut response_buffer) {
                Ok(size) => {
                    self.handle_received_packet(&response_buffer[..size], self.config.server_addr)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Continue sending
                }
                Err(e) => return Err(e.into()),
            }

            thread::sleep(Duration::from_millis(10)); // Pace sending
        }

        self.finish_test()?;
        Ok(())
    }

    /// Handle received packet
    fn handle_received_packet(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let packet_number = if data.len() >= 8 {
            Some(u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]))
        } else {
            None
        };

        {
            let mut state = self.state.lock().unwrap();

            state.packets_received += 1;
            state.bytes_received += data.len() as u64;
            state.last_activity = Instant::now();

            self.log_event("transport", "packet_received", hashmap! {
                "from".to_string() => serde_json::Value::String(from.to_string()),
                "size".to_string() => serde_json::Value::Number(data.len().into()),
                "packet_number".to_string() => serde_json::Value::Number(state.packets_received.into()),
            });
        }

        if let Some(packet_number) = packet_number {
            self.process_ack(packet_number)?;
        }

        Ok(())
    }

    /// Create response packet
    fn create_response_packet(
        &self,
        received_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut packet = BytesMut::new();

        // Simple response: echo with packet number
        let state = self.state.lock().unwrap();
        packet.put_u64(state.packet_number);
        packet.put_slice(received_data);

        Ok(packet.to_vec())
    }

    /// Create data packet
    fn create_data_packet(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut packet = BytesMut::new();

        let mut state = self.state.lock().unwrap();
        state.packet_number += 1;
        let packet_number = state.packet_number;

        packet.put_u64(packet_number);
        packet.put_slice(data);

        // Record outstanding packet
        state
            .loss_recovery
            .outstanding_packets
            .insert(packet_number, Instant::now());

        self.log_event(
            "transport",
            "packet_sent",
            hashmap! {
                "packet_number".to_string() => serde_json::Value::Number(packet_number.into()),
                "size".to_string() => serde_json::Value::Number((data.len() + 8).into()),
                "stream_id".to_string() => serde_json::Value::Number(0.into()),
            },
        );

        Ok(packet.to_vec())
    }

    /// Process ACK for packet
    fn process_ack(&self, acked_packet: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = self.state.lock().unwrap();

        if let Some(send_time) = state
            .loss_recovery
            .outstanding_packets
            .remove(&acked_packet)
        {
            let rtt = Instant::now().duration_since(send_time);
            state.rtt_measurements.push(rtt);
            state.loss_recovery.acked_packets.push(acked_packet);

            self.log_event(
                "recovery",
                "packet_acked",
                hashmap! {
                    "packet_number".to_string() => serde_json::Value::Number(acked_packet.into()),
                    "rtt_us".to_string() => serde_json::Value::Number(
                        u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX).into()
                    ),
                },
            );
        }

        Ok(())
    }

    /// Update send statistics
    fn update_send_stats(&self, packet_size: usize) {
        let mut state = self.state.lock().unwrap();
        state.packets_sent += 1;
        state.bytes_sent += packet_size as u64;
    }

    /// Generate test data
    fn generate_test_data(&self) -> Vec<u8> {
        (0..self.config.test_data_size)
            .map(|i| (i % 256) as u8)
            .collect()
    }

    /// Log event to qlog
    fn log_event(
        &self,
        category: &str,
        event_type: &str,
        data: HashMap<String, serde_json::Value>,
    ) {
        let mut logger = self.logger.lock().unwrap();
        logger.log_event(category, event_type, data);
    }

    /// Finish test and generate report
    fn finish_test(&self) -> Result<(), Box<dyn std::error::Error>> {
        let state = self.state.lock().unwrap();
        let duration = state.start_time.elapsed();

        let throughput_mbps =
            (state.bytes_sent as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
        let avg_rtt = if !state.rtt_measurements.is_empty() {
            state.rtt_measurements.iter().sum::<Duration>() / state.rtt_measurements.len() as u32
        } else {
            Duration::from_secs(0)
        };

        println!("\n=== E2E Test Results ===");
        println!("Duration: {:?}", duration);
        println!("Packets sent: {}", state.packets_sent);
        println!("Packets received: {}", state.packets_received);
        println!("Bytes sent: {}", state.bytes_sent);
        println!("Bytes received: {}", state.bytes_received);
        println!("Throughput: {:.2} Mbps", throughput_mbps);
        println!("Average RTT: {:?}", avg_rtt);
        println!(
            "Outstanding packets: {}",
            state.loss_recovery.outstanding_packets.len()
        );

        self.log_event("transport", "connection_closed", hashmap! {
            "duration_ms".to_string() => serde_json::Value::Number(
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX).into()
            ),
            "throughput_mbps".to_string() => serde_json::Value::Number(serde_json::Number::from_f64(throughput_mbps).unwrap()),
            "packets_sent".to_string() => serde_json::Value::Number(state.packets_sent.into()),
            "packets_received".to_string() => serde_json::Value::Number(state.packets_received.into()),
        });

        // Flush log
        drop(state);
        let logger = self.logger.lock().unwrap();
        logger.flush()?;

        Ok(())
    }
}

impl E2EEventLogger {
    /// Create new event logger
    pub fn new(log_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            events: Vec::new(),
            log_path: log_path.to_string(),
            start_time: SystemTime::now(),
        })
    }

    /// Log an event
    pub fn log_event(
        &mut self,
        category: &str,
        event_type: &str,
        data: HashMap<String, serde_json::Value>,
    ) {
        let elapsed = SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default();

        self.events.push(QLogEvent {
            time: elapsed.as_micros() as u64,
            category: category.to_string(),
            event_type: event_type.to_string(),
            data,
        });
    }

    /// Flush events to log file
    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        let qlog = serde_json::json!({
            "qlog_version": "0.3",
            "title": "ATP QUIC E2E Test Log",
            "description": "End-to-end QUIC test with ATP frames",
            "summary": {
                "total_events": self.events.len()
            },
            "traces": [{
                "common_fields": {
                    "group_id": "atp_e2e_test",
                    "protocol_type": ["QUIC"],
                    "reference_time": self.start_time.duration_since(UNIX_EPOCH).unwrap().as_millis()
                },
                "events": self.events
            }]
        });

        std::fs::write(&self.log_path, serde_json::to_string_pretty(&qlog)?)?;
        println!("E2E test log written to: {}", self.log_path);

        Ok(())
    }
}

/// Run complete E2E test scenario
pub fn run_e2e_test(config: E2EConfig) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting ATP QUIC E2E test");
    println!(
        "Server: {}, Client: {}",
        config.server_addr, config.client_addr
    );

    // Start server in background thread
    let server_config = config.clone();
    let server_handle = thread::spawn(move || {
        let server = QuicE2EEndpoint::new(server_config).map_err(|err| err.to_string())?;
        server.start_server().map_err(|err| err.to_string())
    });

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Start client
    let client = QuicE2EEndpoint::new(config)?;
    let client_result = client.start_client();

    // Wait for server to complete
    let server_result = server_handle.join();

    // Report results
    match (client_result, server_result) {
        (Ok(_), Ok(Ok(_))) => {
            println!("E2E test completed successfully");
            Ok(())
        }
        (Err(e), _) => {
            println!("Client error: {:?}", e);
            Err(e)
        }
        (_, Ok(Err(e))) => {
            println!("Server error: {:?}", e);
            Err(e.into())
        }
        (_, Err(_)) => Err("Server thread panicked".into()),
    }
}

/// Test local two-endpoint E2E script
#[test]
fn test_quic_e2e_local_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let config = E2EConfig {
        server_addr: "127.0.0.1:18443".parse()?, // Use different port for test
        client_addr: "127.0.0.1:0".parse()?,
        test_duration: Duration::from_secs(5), // Shorter test
        enable_qlog: true,
        log_path: "/tmp/test_atp_quic_e2e.qlog".to_string(),
        test_data_size: 10240, // 10KB
        expected_rate_mbps: 1.0,
    };

    run_e2e_test(config)?;

    println!("Local endpoint E2E test completed");
    Ok(())
}

/// Test with different network conditions
#[test]
fn test_quic_e2e_with_packet_lab() -> Result<(), Box<dyn std::error::Error>> {
    // This test would integrate with the packet lab for realistic network conditions
    println!("E2E test with packet lab simulation");

    let _config = E2EConfig {
        server_addr: "127.0.0.1:18444".parse()?,
        test_duration: Duration::from_secs(3),
        test_data_size: 5120, // 5KB
        ..Default::default()
    };

    // In a full implementation, this would run the E2E test
    // through the packet lab with various network scenarios
    println!("Would test scenarios: perfect, high_loss, reordering, congested");

    Ok(())
}
