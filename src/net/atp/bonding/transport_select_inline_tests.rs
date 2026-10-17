    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn direct_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4711)
    }

    fn tailnet_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 101, 102, 103)), 4711)
    }

    // --- z01bbr.4.3: CGNAT classification -----------------------------------

    #[test]
    fn is_cgnat_ipv4_accepts_the_full_100_64_0_0_slash_10_range() {
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(is_cgnat_ipv4(Ipv4Addr::new(100, 96, 12, 34)));
    }

    #[test]
    fn is_cgnat_ipv4_rejects_addresses_just_outside_the_boundaries() {
        // One below the low boundary (100.63.255.255) and one above the high
        // boundary (100.128.0.0).
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
        // Ordinary public / private addresses are rejected.
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_cgnat_ipv4(Ipv4Addr::new(100, 200, 0, 1)));
    }

    // --- z01bbr.4.3: status --json parsing ----------------------------------

    #[test]
    fn parse_tailscale_status_ipv4_extracts_self_cgnat_ip_and_magic_dns() {
        // Realistic (trimmed) `tailscale status --json` snippet.
        let json = r#"{
            "Version": "1.62.0",
            "BackendState": "Running",
            "Self": {
                "ID": "n123",
                "HostName": "workstation",
                "DNSName": "workstation.tail9f00.ts.net.",
                "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1234"],
                "Online": true
            },
            "Peer": {}
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("self cgnat ip present");
        assert_eq!(ipv4, Ipv4Addr::new(100, 101, 102, 103));
        // Trailing dot stripped.
        assert_eq!(magic_dns.as_deref(), Some("workstation.tail9f00.ts.net"));
    }

    #[test]
    fn parse_tailscale_status_ipv4_skips_non_cgnat_ipv4_and_ipv6() {
        // First IPv4 is NOT in CGNAT; the CGNAT one appears later in the list.
        let json = r#"{
            "Self": {
                "DNSName": "host.example.ts.net.",
                "TailscaleIPs": ["192.0.2.9", "fd7a:115c::1", "100.64.0.5"]
            }
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("later cgnat ip found");
        assert_eq!(ipv4, Ipv4Addr::new(100, 64, 0, 5));
        assert_eq!(magic_dns.as_deref(), Some("host.example.ts.net"));
    }

    #[test]
    fn parse_tailscale_status_ipv4_returns_none_without_a_cgnat_address() {
        let json = r#"{ "Self": { "TailscaleIPs": ["192.0.2.9", "fd7a::1"] } }"#;
        assert!(parse_tailscale_status_ipv4(json).is_none());
    }

    #[test]
    fn parse_tailscale_status_ipv4_returns_none_on_malformed_or_empty_json() {
        assert!(parse_tailscale_status_ipv4("not json at all").is_none());
        assert!(parse_tailscale_status_ipv4("").is_none());
        assert!(parse_tailscale_status_ipv4("{}").is_none());
        assert!(parse_tailscale_status_ipv4(r#"{ "Self": {} }"#).is_none());
    }

    #[test]
    fn parse_tailscale_status_ipv4_omits_empty_dns_name() {
        let json = r#"{
            "Self": { "DNSName": "", "TailscaleIPs": ["100.100.100.100"] }
        }"#;
        let (ipv4, magic_dns) = parse_tailscale_status_ipv4(json).expect("cgnat ip");
        assert_eq!(ipv4, Ipv4Addr::new(100, 100, 100, 100));
        assert_eq!(magic_dns, None);
    }

    // --- z01bbr.4.3: `tailscale ip -4` fallback parsing ----------------------

    #[test]
    fn parse_tailscale_ip_line_takes_the_first_cgnat_line() {
        let stdout = "100.115.92.1\nfd7a:115c:a1e0::1\n";
        assert_eq!(
            parse_tailscale_ip_line(stdout),
            Some(Ipv4Addr::new(100, 115, 92, 1))
        );
    }

    #[test]
    fn parse_tailscale_ip_line_skips_blanks_and_non_cgnat_lines() {
        let stdout = "\n   \n192.0.2.4\n100.72.0.9\n";
        assert_eq!(
            parse_tailscale_ip_line(stdout),
            Some(Ipv4Addr::new(100, 72, 0, 9))
        );
    }

    #[test]
    fn parse_tailscale_ip_line_returns_none_when_no_cgnat_line() {
        assert!(parse_tailscale_ip_line("").is_none());
        assert!(parse_tailscale_ip_line("not an ip\n").is_none());
        assert!(parse_tailscale_ip_line("192.0.2.4\n").is_none());
    }

    // --- z01bbr.4.4: per-donor path selection decision matrix ---------------

    #[test]
    fn select_auto_both_on_tailnet_picks_tailscale() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Auto, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_auto_donor_not_on_tailnet_picks_direct() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Auto, &endpoints, false).expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_direct_pref_picks_direct_even_when_tailnet_available() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Direct, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailscale_pref_falls_back_to_direct_when_donor_not_on_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, false)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailscale_pref_uses_tailscale_when_both_on_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, true)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_ssh_pref_picks_ssh_dialing_direct() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Ssh, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Ssh);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_ssh_pref_without_direct_tunnels_over_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: Some(tailnet_addr()),
        };
        let choice =
            select_donor_path(TransportPreference::Ssh, &endpoints, false).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Ssh);
        assert_eq!(choice.dial, tailnet_addr());
    }

    #[test]
    fn select_returns_none_when_no_endpoint_exists() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: None,
        };
        assert!(select_donor_path(TransportPreference::Auto, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Direct, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Tailscale, &endpoints, true).is_none());
        assert!(select_donor_path(TransportPreference::Ssh, &endpoints, true).is_none());
    }

    #[test]
    fn select_direct_only_endpoint_ignores_tailnet_preference() {
        let endpoints = ReceiverEndpoints {
            direct: Some(direct_addr()),
            tailnet: None,
        };
        // Even asking for Tailscale, with no tailnet endpoint we get direct.
        let choice = select_donor_path(TransportPreference::Tailscale, &endpoints, true)
            .expect("usable path");
        assert_eq!(choice.transport, BondTransport::DirectIp);
        assert_eq!(choice.dial, direct_addr());
    }

    #[test]
    fn select_tailnet_only_endpoint_is_last_resort_when_donor_shares_tailnet() {
        let endpoints = ReceiverEndpoints {
            direct: None,
            tailnet: Some(tailnet_addr()),
        };
        // Direct pref but only a tailnet endpoint: still usable via the shared
        // tailnet, so we return it rather than None.
        let choice =
            select_donor_path(TransportPreference::Direct, &endpoints, true).expect("usable path");
        assert_eq!(choice.transport, BondTransport::Tailscale);
        assert_eq!(choice.dial, tailnet_addr());
        // But if the donor is not on the tailnet, that endpoint is unusable.
        assert!(select_donor_path(TransportPreference::Direct, &endpoints, false).is_none());
    }
