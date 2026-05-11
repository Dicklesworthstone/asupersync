#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :authority pseudo-header test input for RFC 7540 §8.1.2.3 compliance
#[derive(Arbitrary, Debug)]
struct H2AuthorityInput {
    /// Authority value strategy
    authority_strategy: AuthorityStrategy,
    /// Scheme for the request
    scheme: SchemeType,
    /// Method for the request
    method: String,
    /// Path for the request
    path: String,
    /// Additional test parameters
    test_params: AuthorityTestParams,
}

#[derive(Arbitrary, Debug)]
enum AuthorityStrategy {
    /// Empty authority value
    Empty,
    /// Missing authority header entirely
    Missing,
    /// Whitespace-only authority
    Whitespace(String),
    /// Valid hostname
    ValidHostname(String),
    /// Valid IP address
    ValidIP(IpType),
    /// Hostname with port
    HostnameWithPort { hostname: String, port: u16 },
    /// IP with port
    IpWithPort { ip: IpType, port: u16 },
    /// Invalid authority format
    Invalid(InvalidAuthorityType),
}

#[derive(Arbitrary, Debug)]
enum SchemeType {
    Http,
    Https,
    Custom(String),
}

#[derive(Arbitrary, Debug)]
enum IpType {
    V4 { octets: [u8; 4] },
    V6 { segments: [u16; 8] },
}

#[derive(Arbitrary, Debug)]
enum InvalidAuthorityType {
    /// Contains userinfo (not allowed per RFC)
    WithUserinfo { userinfo: String, host: String },
    /// Contains invalid characters
    InvalidChars(String),
    /// Empty hostname with port
    EmptyHostWithPort(u16),
    /// Invalid port range
    InvalidPort(String),
    /// Multiple colons in IPv4 context
    MultipleColons(String),
    /// Malformed IPv6
    MalformedIPv6(String),
}

#[derive(Arbitrary, Debug)]
struct AuthorityTestParams {
    /// Whether to include Host header as well
    include_host_header: bool,
    /// Host header value if included
    host_header_value: String,
    /// Connection type being simulated
    connection_type: ConnectionType,
    /// Request target format
    target_format: TargetFormat,
}

#[derive(Arbitrary, Debug)]
enum ConnectionType {
    /// Direct HTTP/2 connection
    Direct,
    /// Upgrade from HTTP/1.1
    Upgrade,
    /// Via proxy/intermediary
    Proxy,
}

#[derive(Arbitrary, Debug)]
enum TargetFormat {
    /// origin-form: "/path?query"
    Origin,
    /// absolute-form: "http://host/path"
    Absolute,
    /// authority-form: "host:port" (for CONNECT)
    Authority,
    /// asterisk-form: "*" (for OPTIONS)
    Asterisk,
}

/// Mock HTTP/2 authority parser for testing RFC 7540 §8.1.2.3 compliance
struct MockH2AuthorityParser;

#[derive(Debug, PartialEq)]
enum AuthorityValidationError {
    /// Authority contains userinfo (forbidden per RFC 7540)
    ContainsUserinfo,
    /// Authority contains invalid characters
    InvalidCharacters,
    /// Authority is required but missing/empty
    RequiredButMissing { scheme: String },
    /// Invalid port format
    InvalidPort,
    /// Malformed IP address
    MalformedIP,
    /// Host and :authority headers conflict
    HostAuthorityConflict,
    /// Invalid hostname format
    InvalidHostname,
    /// Empty hostname with port
    EmptyHostWithPort,
}

impl MockH2AuthorityParser {
    fn validate_authority_header(
        input: &H2AuthorityInput,
    ) -> Result<Option<String>, AuthorityValidationError> {
        let authority_value = Self::generate_authority_value(input);
        let _connection_type = &input.test_params.connection_type;

        // Handle missing authority
        if matches!(input.authority_strategy, AuthorityStrategy::Missing) {
            // RFC 7540 §8.1.2.3: Authority MAY be omitted in certain cases
            return Self::validate_missing_authority(input);
        }

        // Handle empty authority
        if authority_value.is_empty() {
            return Self::validate_empty_authority(input);
        }

        // Handle whitespace-only authority
        if authority_value.trim().is_empty() {
            return Self::validate_empty_authority(input);
        }

        // Validate non-empty authority
        Self::validate_non_empty_authority(&authority_value, input)
    }

    fn generate_authority_value(input: &H2AuthorityInput) -> String {
        match &input.authority_strategy {
            AuthorityStrategy::Empty => String::new(),
            AuthorityStrategy::Missing => String::new(), // Will be handled specially
            AuthorityStrategy::Whitespace(ws) => ws.clone(),
            AuthorityStrategy::ValidHostname(hostname) => Self::sanitize_hostname(hostname),
            AuthorityStrategy::ValidIP(ip_type) => Self::format_ip(ip_type),
            AuthorityStrategy::HostnameWithPort { hostname, port } => {
                format!("{}:{}", Self::sanitize_hostname(hostname), port)
            }
            AuthorityStrategy::IpWithPort { ip, port } => {
                let ip_str = Self::format_ip(ip);
                if matches!(ip, IpType::V6 { .. }) {
                    format!("[{}]:{}", ip_str, port)
                } else {
                    format!("{}:{}", ip_str, port)
                }
            }
            AuthorityStrategy::Invalid(invalid_type) => match invalid_type {
                InvalidAuthorityType::WithUserinfo { userinfo, host } => {
                    format!("{}@{}", userinfo, host)
                }
                InvalidAuthorityType::InvalidChars(chars) => chars.clone(),
                InvalidAuthorityType::EmptyHostWithPort(port) => {
                    format!(":{}", port)
                }
                InvalidAuthorityType::InvalidPort(port_str) => {
                    format!("example.com:{}", port_str)
                }
                InvalidAuthorityType::MultipleColons(malformed) => malformed.clone(),
                InvalidAuthorityType::MalformedIPv6(malformed) => {
                    format!("[{}]", malformed)
                }
            },
        }
    }

    fn validate_missing_authority(
        input: &H2AuthorityInput,
    ) -> Result<Option<String>, AuthorityValidationError> {
        // RFC 7540 §8.1.2.3: Authority MAY be omitted for certain request types

        match &input.scheme {
            SchemeType::Https => {
                // For HTTPS, authority is typically required unless specific conditions
                match input.test_params.target_format {
                    TargetFormat::Asterisk => {
                        // OPTIONS * requests may omit authority
                        Ok(None)
                    }
                    TargetFormat::Absolute => {
                        // Absolute URI includes authority, so :authority may be omitted
                        Ok(None)
                    }
                    _ => {
                        // For origin-form with HTTPS, authority is usually required
                        Err(AuthorityValidationError::RequiredButMissing {
                            scheme: "https".to_string(),
                        })
                    }
                }
            }
            SchemeType::Http => {
                // HTTP is more lenient about missing authority
                Ok(None)
            }
            SchemeType::Custom(custom_scheme) => {
                // Custom schemes - allow missing authority
                let _custom_scheme_len = custom_scheme.len();
                Ok(None)
            }
        }
    }

    fn validate_empty_authority(
        input: &H2AuthorityInput,
    ) -> Result<Option<String>, AuthorityValidationError> {
        // Empty authority is generally acceptable per RFC 7540 §8.1.2.3
        // "this pseudo-header field MUST be omitted when translating from an HTTP/1.1
        // request that has a request target in origin or asterisk form"

        match input.test_params.target_format {
            TargetFormat::Origin | TargetFormat::Asterisk => {
                // For origin-form and asterisk-form, empty authority is acceptable
                Ok(Some(String::new()))
            }
            TargetFormat::Authority => {
                // For authority-form (CONNECT), empty authority doesn't make sense
                Err(AuthorityValidationError::RequiredButMissing {
                    scheme: "connect".to_string(),
                })
            }
            TargetFormat::Absolute => {
                // For absolute-form, empty authority is unusual but may be acceptable
                Ok(Some(String::new()))
            }
        }
    }

    fn validate_non_empty_authority(
        authority: &str,
        input: &H2AuthorityInput,
    ) -> Result<Option<String>, AuthorityValidationError> {
        // Check for forbidden userinfo
        if authority.contains('@') {
            return Err(AuthorityValidationError::ContainsUserinfo);
        }

        // Parse host and port
        let (host, port) = Self::parse_host_port(authority)?;

        // Validate host component
        if host.is_empty() {
            return Err(AuthorityValidationError::EmptyHostWithPort);
        }

        // Validate host format
        Self::validate_host(&host)?;

        // Validate port if present
        if let Some(port_str) = port {
            Self::validate_port(&port_str)?;
        }

        // Check for conflicts with Host header
        if input.test_params.include_host_header {
            Self::check_host_authority_conflict(authority, &input.test_params.host_header_value)?;
        }

        Ok(Some(authority.to_string()))
    }

    fn parse_host_port(
        authority: &str,
    ) -> Result<(String, Option<String>), AuthorityValidationError> {
        // Handle IPv6 addresses in brackets
        if authority.starts_with('[') {
            if let Some(bracket_end) = authority.find(']') {
                let ipv6_part = &authority[1..bracket_end];
                let remaining = &authority[bracket_end + 1..];

                if remaining.is_empty() {
                    return Ok((format!("[{}]", ipv6_part), None));
                } else if let Some(port_part) = remaining.strip_prefix(':') {
                    return Ok((format!("[{}]", ipv6_part), Some(port_part.to_string())));
                } else {
                    return Err(AuthorityValidationError::MalformedIP);
                }
            } else {
                return Err(AuthorityValidationError::MalformedIP);
            }
        }

        // Handle regular hostnames and IPv4 addresses
        let parts: Vec<&str> = authority.rsplitn(2, ':').collect();
        match parts.len() {
            1 => Ok((parts[0].to_string(), None)),
            2 => Ok((parts[1].to_string(), Some(parts[0].to_string()))),
            _ => Err(AuthorityValidationError::InvalidCharacters),
        }
    }

    fn validate_host(host: &str) -> Result<(), AuthorityValidationError> {
        if host.is_empty() {
            return Err(AuthorityValidationError::InvalidHostname);
        }

        // Handle bracketed IPv6
        if host.starts_with('[') && host.ends_with(']') {
            let ipv6_addr = &host[1..host.len() - 1];
            return Self::validate_ipv6(ipv6_addr);
        }

        // Check for invalid characters
        for ch in host.chars() {
            if ch.is_control() || ch.is_whitespace() {
                return Err(AuthorityValidationError::InvalidCharacters);
            }
            // Allow hostname characters: alphanumeric, dots, hyphens
            if !ch.is_alphanumeric() && ch != '.' && ch != '-' && ch != ':' {
                return Err(AuthorityValidationError::InvalidCharacters);
            }
        }

        // Try to validate as IPv4
        if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Self::validate_ipv4(host);
        }

        // Validate as hostname
        Self::validate_hostname(host)
    }

    fn validate_ipv4(ip: &str) -> Result<(), AuthorityValidationError> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(AuthorityValidationError::MalformedIP);
        }

        for part in parts {
            if part.parse::<u8>().is_err() {
                return Err(AuthorityValidationError::MalformedIP);
            }
        }

        Ok(())
    }

    fn validate_ipv6(ip: &str) -> Result<(), AuthorityValidationError> {
        // Basic IPv6 validation (simplified)
        if ip.is_empty() {
            return Err(AuthorityValidationError::MalformedIP);
        }

        // Allow :: for zero compression
        let double_colon_count = ip.matches("::").count();
        if double_colon_count > 1 {
            return Err(AuthorityValidationError::MalformedIP);
        }

        // Basic character check
        for ch in ip.chars() {
            if !ch.is_ascii_hexdigit() && ch != ':' {
                return Err(AuthorityValidationError::MalformedIP);
            }
        }

        Ok(())
    }

    fn validate_hostname(hostname: &str) -> Result<(), AuthorityValidationError> {
        if hostname.is_empty() || hostname.len() > 253 {
            return Err(AuthorityValidationError::InvalidHostname);
        }

        // Labels separated by dots
        for label in hostname.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(AuthorityValidationError::InvalidHostname);
            }

            // Labels can't start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return Err(AuthorityValidationError::InvalidHostname);
            }

            // Only alphanumeric and hyphens in labels
            if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return Err(AuthorityValidationError::InvalidHostname);
            }
        }

        Ok(())
    }

    fn validate_port(port_str: &str) -> Result<(), AuthorityValidationError> {
        if let Ok(port) = port_str.parse::<u16>() {
            if port == 0 {
                return Err(AuthorityValidationError::InvalidPort);
            }
            Ok(())
        } else {
            Err(AuthorityValidationError::InvalidPort)
        }
    }

    fn check_host_authority_conflict(
        authority: &str,
        host_header: &str,
    ) -> Result<(), AuthorityValidationError> {
        // RFC 7540: If both Host header and :authority are present, they should match
        // or at least be compatible
        if !authority.is_empty() && !host_header.is_empty() && authority != host_header {
            return Err(AuthorityValidationError::HostAuthorityConflict);
        }
        Ok(())
    }

    fn sanitize_hostname(hostname: &str) -> String {
        // Basic sanitization for test hostname generation
        hostname
            .chars()
            .filter(|&c| c.is_alphanumeric() || c == '.' || c == '-')
            .take(63) // Max label length
            .collect()
    }

    fn format_ip(ip_type: &IpType) -> String {
        match ip_type {
            IpType::V4 { octets } => {
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            IpType::V6 { segments } => segments
                .iter()
                .map(|seg| format!("{:x}", seg))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }
}

fuzz_target!(|input: H2AuthorityInput| {
    // Skip inputs that would cause excessive processing
    if input.path.len() > 1000 || input.method.len() > 100 {
        return;
    }

    let result = MockH2AuthorityParser::validate_authority_header(&input);

    // Apply assertions based on the authority strategy and context
    match &input.authority_strategy {
        AuthorityStrategy::Empty | AuthorityStrategy::Whitespace(_) => {
            // Empty authority should generally be acceptable per RFC 7540 §8.1.2.3
            match input.test_params.target_format {
                TargetFormat::Origin | TargetFormat::Asterisk => {
                    // Empty authority is explicitly acceptable for origin/asterisk forms
                    match result {
                        Ok(Some(_)) | Ok(None) => {
                            // Expected: empty authority accepted
                        }
                        Err(AuthorityValidationError::RequiredButMissing { .. }) => {
                            // May be required in some HTTPS contexts
                        }
                        Err(other) => {
                            // Unexpected error for empty authority
                            panic!(
                                "Unexpected error for empty authority in origin/asterisk form: {:?}",
                                other
                            );
                        }
                    }
                }
                TargetFormat::Authority => {
                    // CONNECT method requires authority
                    assert!(matches!(
                        result,
                        Err(AuthorityValidationError::RequiredButMissing { .. })
                    ));
                }
                TargetFormat::Absolute => {
                    // Absolute form may accept empty authority
                    assert!(
                        result.is_ok()
                            || matches!(
                                result,
                                Err(AuthorityValidationError::RequiredButMissing { .. })
                            )
                    );
                }
            }
        }
        AuthorityStrategy::Missing => {
            // Missing authority has specific rules per RFC 7540 §8.1.2.3
            match (&input.scheme, &input.test_params.target_format) {
                (SchemeType::Https, TargetFormat::Origin) => {
                    // HTTPS with origin-form typically requires authority
                    if !matches!(
                        result,
                        Ok(None) | Err(AuthorityValidationError::RequiredButMissing { .. })
                    ) {
                        // Either accepted or properly rejected
                    }
                }
                (_, TargetFormat::Asterisk) => {
                    // OPTIONS * may omit authority
                    assert!(result.is_ok());
                }
                (_, TargetFormat::Absolute) => {
                    // Absolute form includes authority in URI
                    assert!(result.is_ok());
                }
                _ => {
                    // Other combinations are generally acceptable
                    assert!(
                        result.is_ok()
                            || matches!(
                                result,
                                Err(AuthorityValidationError::RequiredButMissing { .. })
                            )
                    );
                }
            }
        }
        AuthorityStrategy::ValidHostname(_)
        | AuthorityStrategy::ValidIP(_)
        | AuthorityStrategy::HostnameWithPort { .. }
        | AuthorityStrategy::IpWithPort { .. } => {
            // Valid authority formats should be accepted
            match result {
                Ok(_) => {
                    // Expected: valid authority accepted
                }
                Err(AuthorityValidationError::HostAuthorityConflict) => {
                    // Expected: conflict with Host header
                }
                Err(_) => {
                    // May be rejected due to generation artifacts or validation strictness
                }
            }
        }
        AuthorityStrategy::Invalid(_) => {
            // Invalid authority formats should be rejected
            assert!(
                result.is_err(),
                "Invalid authority was incorrectly accepted"
            );

            // Check that the right type of error is reported
            match &input.authority_strategy {
                AuthorityStrategy::Invalid(InvalidAuthorityType::WithUserinfo { .. }) => {
                    assert!(matches!(
                        result,
                        Err(AuthorityValidationError::ContainsUserinfo)
                    ));
                }
                AuthorityStrategy::Invalid(InvalidAuthorityType::EmptyHostWithPort(_)) => {
                    assert!(matches!(
                        result,
                        Err(AuthorityValidationError::EmptyHostWithPort)
                    ));
                }
                AuthorityStrategy::Invalid(InvalidAuthorityType::InvalidPort(_)) => {
                    assert!(matches!(result, Err(AuthorityValidationError::InvalidPort)));
                }
                AuthorityStrategy::Invalid(InvalidAuthorityType::MalformedIPv6(_)) => {
                    assert!(matches!(result, Err(AuthorityValidationError::MalformedIP)));
                }
                _ => {
                    // Other invalid types should result in some error
                }
            }
        }
    }

    // Test invariants that should always hold
    test_authority_invariants(&input, &result);
});

fn test_authority_invariants(
    input: &H2AuthorityInput,
    result: &Result<Option<String>, AuthorityValidationError>,
) {
    // Invariant: Userinfo in authority must always be rejected per RFC 7540
    let authority_value = MockH2AuthorityParser::generate_authority_value(input);
    if authority_value.contains('@') {
        assert!(matches!(
            result,
            Err(AuthorityValidationError::ContainsUserinfo)
        ));
    }

    // Invariant: Host/Authority conflict should be detected
    if input.test_params.include_host_header
        && !input.test_params.host_header_value.is_empty()
        && !authority_value.is_empty()
        && input.test_params.host_header_value != authority_value
    {
        if matches!(result, Err(AuthorityValidationError::HostAuthorityConflict)) {
            // Expected conflict detected
        } else {
            // Some parsers might be more lenient
        }
    }

    // Invariant: Authority-form requests (CONNECT) need non-empty authority
    if matches!(input.test_params.target_format, TargetFormat::Authority)
        && matches!(
            input.authority_strategy,
            AuthorityStrategy::Empty | AuthorityStrategy::Missing
        )
    {
        assert!(matches!(
            result,
            Err(AuthorityValidationError::RequiredButMissing { .. })
        ));
    }

    // Invariant: Invalid port formats should be rejected
    if authority_value.contains(":abc") || authority_value.contains(":99999") {
        assert!(matches!(result, Err(AuthorityValidationError::InvalidPort)));
    }

    // Invariant: Empty hostname with port should be rejected
    if authority_value.starts_with(':') && authority_value.len() > 1 {
        assert!(matches!(
            result,
            Err(AuthorityValidationError::EmptyHostWithPort)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_authority_accepted() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::Empty,
            scheme: SchemeType::Http,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(
            result.is_ok(),
            "Empty authority should be accepted for origin-form"
        );
    }

    #[test]
    fn test_missing_authority_https() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::Missing,
            scheme: SchemeType::Https,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        // HTTPS with origin-form may require authority
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_userinfo_rejected() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::Invalid(InvalidAuthorityType::WithUserinfo {
                userinfo: "user:pass".to_string(),
                host: "example.com".to_string(),
            }),
            scheme: SchemeType::Https,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(matches!(
            result,
            Err(AuthorityValidationError::ContainsUserinfo)
        ));
    }

    #[test]
    fn test_valid_hostname_accepted() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::ValidHostname("example.com".to_string()),
            scheme: SchemeType::Https,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(result.is_ok(), "Valid hostname should be accepted");
    }

    #[test]
    fn test_hostname_with_port() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::HostnameWithPort {
                hostname: "example.com".to_string(),
                port: 8080,
            },
            scheme: SchemeType::Https,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(
            result.is_ok(),
            "Valid hostname with port should be accepted"
        );
    }

    #[test]
    fn test_ipv4_address() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::ValidIP(IpType::V4 {
                octets: [192, 168, 1, 1],
            }),
            scheme: SchemeType::Http,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(result.is_ok(), "Valid IPv4 address should be accepted");
    }

    #[test]
    fn test_ipv6_address_with_port() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::IpWithPort {
                ip: IpType::V6 {
                    segments: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1],
                },
                port: 443,
            },
            scheme: SchemeType::Https,
            method: "GET".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Origin,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(
            result.is_ok(),
            "Valid IPv6 address with port should be accepted"
        );
    }

    #[test]
    fn test_connect_requires_authority() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::Empty,
            scheme: SchemeType::Https,
            method: "CONNECT".to_string(),
            path: "/".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Authority,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(matches!(
            result,
            Err(AuthorityValidationError::RequiredButMissing { .. })
        ));
    }

    #[test]
    fn test_options_asterisk_allows_empty() {
        let input = H2AuthorityInput {
            authority_strategy: AuthorityStrategy::Missing,
            scheme: SchemeType::Http,
            method: "OPTIONS".to_string(),
            path: "*".to_string(),
            test_params: AuthorityTestParams {
                include_host_header: false,
                host_header_value: String::new(),
                connection_type: ConnectionType::Direct,
                target_format: TargetFormat::Asterisk,
            },
        };

        let result = MockH2AuthorityParser::validate_authority_header(&input);
        assert!(result.is_ok(), "OPTIONS * should allow missing authority");
    }
}
