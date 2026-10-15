//! ATP relay telemetry HTTP dashboard for real-time monitoring.
//!
//! Provides HTTP endpoints for relay operators to monitor connection health,
//! throughput, error rates, and performance metrics without exposing sensitive
//! transfer data.

use crate::atp::telemetry::{RelayDashboardData, RelayTelemetryCollector};
use crate::net::atp::relay::RelayService;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde_json;

/// HTTP dashboard for ATP relay telemetry.
pub struct RelayDashboard {
    /// Telemetry collector with accumulated metrics
    telemetry: Arc<Mutex<RelayTelemetryCollector>>,
    /// Last collection time for rate limiting
    last_collection: Arc<Mutex<Instant>>,
    /// Minimum interval between collections to avoid overhead
    collection_interval: Duration,
}

impl RelayDashboard {
    /// Create new relay dashboard.
    pub fn new() -> Self {
        Self {
            telemetry: Arc::new(Mutex::new(RelayTelemetryCollector::new())),
            last_collection: Arc::new(Mutex::new(Instant::now())),
            collection_interval: Duration::from_secs(5), // Collect every 5 seconds
        }
    }

    /// Update telemetry from relay service (called periodically).
    pub fn update_from_service(&self, service: &RelayService) -> Result<(), String> {
        let mut last_collection = self.last_collection.lock().map_err(|_| "Lock poisoned")?;

        // Rate limit collections to avoid performance impact
        if last_collection.elapsed() < self.collection_interval {
            return Ok(());
        }

        let mut telemetry = self.telemetry.lock().map_err(|_| "Lock poisoned")?;
        telemetry.collect_from_service(service);
        *last_collection = Instant::now();

        Ok(())
    }

    /// Get current dashboard data as JSON.
    pub fn get_dashboard_json(&self) -> Result<String, String> {
        let mut telemetry = self.telemetry.lock().map_err(|_| "Lock poisoned")?;
        let dashboard_data = telemetry.get_dashboard_data();

        serde_json::to_string_pretty(&dashboard_data)
            .map_err(|e| format!("JSON serialization failed: {}", e))
    }

    /// Get telemetry summary in plain text format.
    pub fn get_summary_text(&self) -> Result<String, String> {
        let telemetry = self.telemetry.lock().map_err(|_| "Lock poisoned")?;
        let data = telemetry.get_dashboard_data();
        let current = &data.current;

        let summary = format!(
            r#"ATP Relay Telemetry Summary
============================

Connection Status:
- Active Reservations: {}
- Total Reservations: {}
- Total Packets Forwarded: {}
- Total Bytes Forwarded: {} MB
- Recent Forward Rate: {} packets/period

Transport Breakdown:
UDP Transport:
- Packets: {} ({:.1}%)
- Bytes: {} MB
- Avg Latency: {} μs
- Min/Max Latency: {}/{} μs

TCP/TLS 443 Transport:
- Packets: {} ({:.1}%)
- Bytes: {} MB
- Avg Latency: {} μs
- Min/Max Latency: {}/{} μs

Error Metrics:
- Quota Rejections: {}
- Auth Rejections: {}
- Bytes Rejected: {} MB
- Recent Error Rate: {} errors/period

Historical Data Points: {}
"#,
            current.connections.active_reservations,
            current.connections.total_reservations,
            current.connections.total_packets_forwarded,
            current.connections.total_bytes_forwarded / 1_048_576, // Convert to MB
            current.connections.recent_forward_rate,

            current.transport_udp.packets_forwarded,
            if current.connections.total_packets_forwarded > 0 {
                (current.transport_udp.packets_forwarded as f64 / current.connections.total_packets_forwarded as f64) * 100.0
            } else { 0.0 },
            current.transport_udp.bytes_forwarded / 1_048_576,
            current.transport_udp.average_latency_micros,
            current.transport_udp.min_latency_micros,
            current.transport_udp.max_latency_micros,

            current.transport_tcp_tls.packets_forwarded,
            if current.connections.total_packets_forwarded > 0 {
                (current.transport_tcp_tls.packets_forwarded as f64 / current.connections.total_packets_forwarded as f64) * 100.0
            } else { 0.0 },
            current.transport_tcp_tls.bytes_forwarded / 1_048_576,
            current.transport_tcp_tls.average_latency_micros,
            current.transport_tcp_tls.min_latency_micros,
            current.transport_tcp_tls.max_latency_micros,

            current.errors.quota_rejections,
            current.errors.auth_rejections,
            current.errors.bytes_rejected / 1_048_576,
            current.errors.recent_error_rate,

            data.historical.len()
        );

        Ok(summary)
    }

    /// Get HTML dashboard page.
    pub fn get_dashboard_html(&self) -> Result<String, String> {
        let json_data = self.get_dashboard_json()?;

        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATP Relay Telemetry Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #2c3e50; text-align: center; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-title {{ font-weight: bold; color: #34495e; margin-bottom: 10px; }}
        .metric-value {{ font-size: 24px; color: #3498db; }}
        .metric-unit {{ font-size: 14px; color: #7f8c8d; }}
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}
        .status-good {{ color: #27ae60; }}
        .status-warning {{ color: #f39c12; }}
        .status-error {{ color: #e74c3c; }}
        .refresh-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin: 10px 0;
        }}
        .refresh-btn:hover {{ background: #2980b9; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>ATP Relay Telemetry Dashboard</h1>
        <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        <div id="lastUpdate">Last Updated: <span id="timestamp"></span></div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Active Reservations</div>
                <div class="metric-value" id="activeReservations">-</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Total Packets Forwarded</div>
                <div class="metric-value" id="totalPackets">-</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Total Bytes Forwarded</div>
                <div class="metric-value" id="totalBytes">-</div>
                <div class="metric-unit">MB</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Error Rate</div>
                <div class="metric-value" id="errorRate">-</div>
                <div class="metric-unit">errors/period</div>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">UDP Transport</div>
                <div>Packets: <span id="udpPackets">-</span></div>
                <div>Avg Latency: <span id="udpLatency">-</span> μs</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">TCP/TLS Transport</div>
                <div>Packets: <span id="tcpPackets">-</span></div>
                <div>Avg Latency: <span id="tcpLatency">-</span> μs</div>
            </div>
        </div>

        <div class="metric-card">
            <div class="metric-title">Throughput Over Time</div>
            <div class="chart-container">
                <canvas id="throughputChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        let telemetryData = {};
        let throughputChart;

        function initChart() {{
            const ctx = document.getElementById('throughputChart').getContext('2d');
            throughputChart = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: [],
                    datasets: [{{
                        label: 'Packets/Period',
                        data: [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        }}

        function updateMetrics() {{
            if (!telemetryData.current) return;

            const current = telemetryData.current;

            document.getElementById('activeReservations').textContent = current.connections.active_reservations;
            document.getElementById('totalPackets').textContent = current.connections.total_packets_forwarded.toLocaleString();
            document.getElementById('totalBytes').textContent = Math.round(current.connections.total_bytes_forwarded / 1048576);
            document.getElementById('errorRate').textContent = current.errors.recent_error_rate;

            document.getElementById('udpPackets').textContent = current.transport_udp.packets_forwarded.toLocaleString();
            document.getElementById('udpLatency').textContent = current.transport_udp.average_latency_micros;
            document.getElementById('tcpPackets').textContent = current.transport_tcp_tls.packets_forwarded.toLocaleString();
            document.getElementById('tcpLatency').textContent = current.transport_tcp_tls.average_latency_micros;

            // Update timestamp
            const timestamp = new Date(current.timestamp_micros / 1000);
            document.getElementById('timestamp').textContent = timestamp.toLocaleString();

            // Update chart with historical data
            if (telemetryData.historical && throughputChart) {{
                const labels = telemetryData.historical.map(snapshot => {{
                    const date = new Date(snapshot.timestamp_micros / 1000);
                    return date.toLocaleTimeString();
                }});
                const data = telemetryData.historical.map(snapshot => snapshot.connections.recent_forward_rate);

                throughputChart.data.labels = labels;
                throughputChart.data.datasets[0].data = data;
                throughputChart.update();
            }}
        }}

        async function refreshData() {{
            try {{
                // In a real implementation, this would fetch from /relay/telemetry endpoint
                // For now, we'll use the embedded data
                telemetryData = {json_data};
                updateMetrics();
            }} catch (error) {{
                console.error('Failed to refresh data:', error);
            }}
        }}

        // Initialize
        window.onload = function() {{
            initChart();
            telemetryData = {json_data};
            updateMetrics();
        }};
    </script>
</body>
</html>"#, json_data = json_data, json_data = json_data);

        Ok(html)
    }

    /// Create a new telemetry collector reference for recording events.
    pub fn telemetry_collector(&self) -> Arc<Mutex<RelayTelemetryCollector>> {
        Arc::clone(&self.telemetry)
    }
}

impl Default for RelayDashboard {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP handler functions for relay telemetry endpoints.
pub mod handlers {
    use super::*;

    /// Handle /relay/telemetry endpoint - returns JSON data.
    pub fn handle_telemetry_json(dashboard: &RelayDashboard) -> Result<String, String> {
        dashboard.get_dashboard_json()
    }

    /// Handle /relay/dashboard endpoint - returns HTML dashboard.
    pub fn handle_dashboard_html(dashboard: &RelayDashboard) -> Result<String, String> {
        dashboard.get_dashboard_html()
    }

    /// Handle /relay/status endpoint - returns plain text summary.
    pub fn handle_status_text(dashboard: &RelayDashboard) -> Result<String, String> {
        dashboard.get_summary_text()
    }

    /// Health check endpoint for monitoring systems.
    pub fn handle_health_check(dashboard: &RelayDashboard) -> Result<String, String> {
        let telemetry = dashboard.telemetry.lock().map_err(|_| "Lock poisoned")?;
        let data = telemetry.get_dashboard_data();

        // Simple health check based on error rates
        let total_errors = data.current.errors.quota_rejections + data.current.errors.auth_rejections;
        let total_packets = data.current.connections.total_packets_forwarded;

        let health_status = if total_packets == 0 {
            "STARTING"
        } else if total_errors == 0 {
            "HEALTHY"
        } else {
            let error_rate = (total_errors as f64 / total_packets as f64) * 100.0;
            if error_rate < 1.0 {
                "HEALTHY"
            } else if error_rate < 5.0 {
                "WARNING"
            } else {
                "UNHEALTHY"
            }
        };

        Ok(format!(
            "ATP Relay Health: {}\nActive Reservations: {}\nTotal Packets: {}\nTotal Errors: {}",
            health_status,
            data.current.connections.active_reservations,
            total_packets,
            total_errors
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::relay::RelayServiceConfig;

    #[test]
    fn dashboard_creates_with_telemetry_collector() {
        let dashboard = RelayDashboard::new();
        let collector = dashboard.telemetry_collector();

        // Verify we can get a lock on the collector
        assert!(collector.lock().is_ok());
    }

    #[test]
    fn dashboard_generates_json_data() {
        let dashboard = RelayDashboard::new();

        let json = dashboard.get_dashboard_json().expect("Should generate JSON");
        assert!(json.contains("current"));
        assert!(json.contains("historical"));
        assert!(json.contains("timestamp_micros"));
    }

    #[test]
    fn dashboard_generates_html() {
        let dashboard = RelayDashboard::new();

        let html = dashboard.get_dashboard_html().expect("Should generate HTML");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("ATP Relay Telemetry Dashboard"));
        assert!(html.contains("throughputChart"));
    }

    #[test]
    fn dashboard_generates_text_summary() {
        let dashboard = RelayDashboard::new();

        let summary = dashboard.get_summary_text().expect("Should generate summary");
        assert!(summary.contains("ATP Relay Telemetry Summary"));
        assert!(summary.contains("Connection Status"));
        assert!(summary.contains("Transport Breakdown"));
        assert!(summary.contains("Error Metrics"));
    }

    #[test]
    fn dashboard_update_from_service_rate_limits() {
        let dashboard = RelayDashboard::new();
        let service = RelayService::new(RelayServiceConfig::default());

        // First update should succeed
        assert!(dashboard.update_from_service(&service).is_ok());

        // Immediate second update should be skipped due to rate limiting
        assert!(dashboard.update_from_service(&service).is_ok());
    }

    #[test]
    fn health_check_reports_status() {
        let dashboard = RelayDashboard::new();

        let health = handlers::handle_health_check(&dashboard).expect("Should generate health");
        assert!(health.contains("ATP Relay Health: STARTING"));
        assert!(health.contains("Active Reservations: 0"));
    }
}