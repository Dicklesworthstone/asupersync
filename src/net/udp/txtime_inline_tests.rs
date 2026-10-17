    use super::*;

    #[test]
    fn txtime_config_flags_match_linux_net_tstamp() {
        let config = UdpTxTimeConfig::new(UdpTxTimeClock::Tai);
        assert_eq!(config.flags(), 0);
        assert_eq!(config.with_deadline_mode(true).flags(), 1);
        assert_eq!(config.with_report_errors(true).flags(), 2);
        let both = config.with_deadline_mode(true).with_report_errors(true);
        assert_eq!(both.flags(), 3);
        assert!(both.deadline_mode() && both.report_errors());
        assert_eq!(both.clock(), UdpTxTimeClock::Tai);
        assert_eq!(UdpTxTimeClock::Tai.clockid(), libc::CLOCK_TAI);
    }

    fn report(origin: u8, code: u8, data: u32, info: u32) -> UdpErrorReport {
        UdpErrorReport {
            errno: libc::ECANCELED,
            origin: UdpErrorOrigin::from_raw(origin),
            ee_type: 0,
            ee_code: code,
            ee_info: info,
            ee_data: data,
            offender: None,
            destination: None,
            len: 0,
            truncated: false,
        }
    }

    #[test]
    fn txtime_report_decodes_split_launch_time_and_code() {
        let launch = 0x0123_4567_89ab_cdef_u64;
        let missed = report(6, 2, (launch >> 32) as u32, launch as u32);
        assert_eq!(missed.origin, UdpErrorOrigin::TxTime);
        assert_eq!(
            missed.txtime_error(),
            Some(UdpTxTimeError {
                kind: UdpTxTimeErrorKind::Missed,
                launch_time_ns: launch,
            })
        );
        let invalid = report(6, 1, 0, 0);
        assert_eq!(
            invalid.txtime_error().map(|e| e.kind),
            Some(UdpTxTimeErrorKind::InvalidParam)
        );
        assert_eq!(
            report(6, 9, 0, 0).txtime_error().map(|e| e.kind),
            Some(UdpTxTimeErrorKind::Other(9))
        );
        // ICMP reports are not launch-time reports.
        assert_eq!(report(2, 3, 0, 0).txtime_error(), None);
        assert_eq!(missed.error().raw_os_error(), Some(libc::ECANCELED));
    }

    #[test]
    fn error_origin_maps_linux_errqueue_values() {
        assert_eq!(UdpErrorOrigin::from_raw(0), UdpErrorOrigin::None);
        assert_eq!(UdpErrorOrigin::from_raw(1), UdpErrorOrigin::Local);
        assert_eq!(UdpErrorOrigin::from_raw(2), UdpErrorOrigin::Icmp);
        assert_eq!(UdpErrorOrigin::from_raw(3), UdpErrorOrigin::Icmp6);
        assert_eq!(UdpErrorOrigin::from_raw(4), UdpErrorOrigin::Timestamping);
        assert_eq!(UdpErrorOrigin::from_raw(5), UdpErrorOrigin::Zerocopy);
        assert_eq!(UdpErrorOrigin::from_raw(6), UdpErrorOrigin::TxTime);
        assert_eq!(UdpErrorOrigin::from_raw(42), UdpErrorOrigin::Other(42));
    }

    #[test]
    fn offender_conversion_ignores_unspecified_family() {
        // Local errors (launch-time reports) carry a zeroed AF_UNSPEC offender.
        let mut v4 = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9_u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(
            sockaddr_in_to_std(&v4),
            Some("127.0.0.1:9".parse().unwrap())
        );
        v4.sin_family = 0;
        assert_eq!(sockaddr_in_to_std(&v4), None);

        let mut v6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 9_u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };
        assert_eq!(sockaddr_in6_to_std(&v6), Some("[::1]:9".parse().unwrap()));
        v6.sin6_family = 0;
        assert_eq!(sockaddr_in6_to_std(&v6), None);
    }

    #[test]
    fn recverr_state_tracking_and_clone() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = UdpSocket::from_std(std_sock).unwrap();
        assert!(!socket.recverr());
        socket.set_recverr(true).unwrap();
        assert!(socket.recverr());
        let cloned = socket.try_clone().unwrap();
        assert!(cloned.recverr());
        socket.set_recverr(false).unwrap();
        assert!(!socket.recverr());
    }
