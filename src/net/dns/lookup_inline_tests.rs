    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn happy_eyeballs_interleaves() {
        init_test("happy_eyeballs_interleaves");
        let v6 = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];
        let v4 = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        let he = HappyEyeballs::new(v6, v4);
        let addrs: Vec<_> = he.collect();

        // Should interleave: v6, v4, v6, v4
        let len = addrs.len();
        crate::assert_with_log!(len == 4, "len", 4, len);
        crate::assert_with_log!(addrs[0].is_ipv6(), "addr0 v6", true, addrs[0]);
        crate::assert_with_log!(addrs[1].is_ipv4(), "addr1 v4", true, addrs[1]);
        crate::assert_with_log!(addrs[2].is_ipv6(), "addr2 v6", true, addrs[2]);
        crate::assert_with_log!(addrs[3].is_ipv4(), "addr3 v4", true, addrs[3]);
        crate::test_complete!("happy_eyeballs_interleaves");
    }

    #[test]
    fn happy_eyeballs_uneven() {
        init_test("happy_eyeballs_uneven");
        let v6 = vec!["2001:db8::1".parse().unwrap()];
        let v4 = vec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ];

        let he = HappyEyeballs::new(v6, v4);
        let addrs: Vec<_> = he.collect();

        let len = addrs.len();
        crate::assert_with_log!(len == 4, "len", 4, len);
        // v6, v4, v4, v4 (v6 exhausted after first)
        crate::assert_with_log!(addrs[0].is_ipv6(), "addr0 v6", true, addrs[0]);
        crate::assert_with_log!(addrs[1].is_ipv4(), "addr1 v4", true, addrs[1]);
        crate::assert_with_log!(addrs[2].is_ipv4(), "addr2 v4", true, addrs[2]);
        crate::assert_with_log!(addrs[3].is_ipv4(), "addr3 v4", true, addrs[3]);
        crate::test_complete!("happy_eyeballs_uneven");
    }

    #[test]
    fn lookup_ip_accessors() {
        init_test("lookup_ip_accessors");
        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            Duration::from_secs(300),
        );

        let len = lookup.len();
        crate::assert_with_log!(len == 2, "len", 2, len);
        let empty = lookup.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);
        let v4_count = lookup.ipv4_addrs().count();
        crate::assert_with_log!(v4_count == 1, "ipv4 count", 1, v4_count);
        let v6_count = lookup.ipv6_addrs().count();
        crate::assert_with_log!(v6_count == 1, "ipv6 count", 1, v6_count);
        crate::test_complete!("lookup_ip_accessors");
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn lookup_ip_empty() {
        init_test("lookup_ip_empty");
        let lookup = LookupIp::new(vec![], Duration::from_secs(60));
        assert!(lookup.is_empty());
        assert_eq!(lookup.len(), 0);
        assert!(lookup.first().is_none());
        assert_eq!(lookup.ipv4_addrs().count(), 0);
        assert_eq!(lookup.ipv6_addrs().count(), 0);
        crate::test_complete!("lookup_ip_empty");
    }

    #[test]
    fn lookup_ip_debug_clone() {
        init_test("lookup_ip_debug_clone");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(30));
        let dbg = format!("{lookup:?}");
        assert!(dbg.contains("LookupIp"), "{dbg}");
        let cloned = lookup;
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.ttl(), Duration::from_secs(30));
        crate::test_complete!("lookup_ip_debug_clone");
    }

    #[test]
    fn lookup_ip_first() {
        init_test("lookup_ip_first");
        let lookup = LookupIp::new(
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            Duration::from_secs(60),
        );
        assert_eq!(lookup.first(), Some("1.2.3.4".parse().unwrap()));
        crate::test_complete!("lookup_ip_first");
    }

    #[test]
    fn lookup_ip_iter() {
        init_test("lookup_ip_iter");
        let lookup = LookupIp::new(
            vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
            Duration::from_secs(10),
        );
        let count = lookup.iter().count();
        assert_eq!(count, 2);
        crate::test_complete!("lookup_ip_iter");
    }

    #[test]
    fn lookup_ip_into_iter_owned() {
        init_test("lookup_ip_into_iter_owned");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(5));
        assert_eq!(lookup.into_iter().count(), 1);
        crate::test_complete!("lookup_ip_into_iter_owned");
    }

    #[test]
    fn lookup_ip_into_iter_ref() {
        init_test("lookup_ip_into_iter_ref");
        let lookup = LookupIp::new(vec!["10.0.0.1".parse().unwrap()], Duration::from_secs(5));
        assert_eq!((&lookup).into_iter().count(), 1);
        crate::test_complete!("lookup_ip_into_iter_ref");
    }

    #[test]
    fn lookup_ip_ipv4_only() {
        init_test("lookup_ip_ipv4_only");
        let lookup = LookupIp::new(
            vec![
                "10.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ],
            Duration::from_secs(60),
        );
        let v4: Vec<_> = lookup.ipv4_addrs().collect();
        assert_eq!(v4.len(), 2);
        assert_eq!(v4[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        crate::test_complete!("lookup_ip_ipv4_only");
    }

    #[test]
    fn lookup_ip_ipv6_only() {
        init_test("lookup_ip_ipv6_only");
        let lookup = LookupIp::new(
            vec!["10.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            Duration::from_secs(60),
        );
        assert_eq!(lookup.ipv6_addrs().count(), 1);
        crate::test_complete!("lookup_ip_ipv6_only");
    }

    #[test]
    fn happy_eyeballs_empty() {
        init_test("happy_eyeballs_empty");
        let mut he = HappyEyeballs::new(vec![], vec![]);
        assert!(he.is_empty());
        assert_eq!(he.remaining(), 0);
        assert!(he.next().is_none());
        crate::test_complete!("happy_eyeballs_empty");
    }

    #[test]
    fn happy_eyeballs_from_lookup() {
        init_test("happy_eyeballs_from_lookup");
        let lookup = LookupIp::new(
            vec!["10.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            Duration::from_secs(60),
        );
        let he = HappyEyeballs::from_lookup(&lookup);
        assert!(!he.is_empty());
        assert_eq!(he.remaining(), 2);
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        // v6 first due to prefer_v6
        assert!(addrs[0].is_ipv6());
        assert!(addrs[1].is_ipv4());
        crate::test_complete!("happy_eyeballs_from_lookup");
    }

    #[test]
    fn happy_eyeballs_from_lookup_ignores_cross_family_interleaving() {
        init_test("happy_eyeballs_from_lookup_ignores_cross_family_interleaving");
        let v6_a: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_b: IpAddr = "2001:db8::2".parse().unwrap();
        let v6_c: IpAddr = "2001:db8::3".parse().unwrap();
        let v4_a: IpAddr = "192.0.2.1".parse().unwrap();
        let v4_b: IpAddr = "192.0.2.2".parse().unwrap();
        let v4_c: IpAddr = "192.0.2.3".parse().unwrap();

        let interleaved = LookupIp::new(
            vec![v4_a, v6_a, v4_b, v6_b, v6_c, v4_c],
            Duration::from_secs(60),
        );
        let partitioned = LookupIp::new(
            vec![v6_a, v6_b, v6_c, v4_a, v4_b, v4_c],
            Duration::from_secs(60),
        );

        let from_interleaved: Vec<_> = HappyEyeballs::from_lookup(&interleaved).collect();
        let from_partitioned: Vec<_> = HappyEyeballs::from_lookup(&partitioned).collect();

        assert_eq!(from_interleaved, from_partitioned);
        assert_eq!(from_interleaved, vec![v6_a, v4_a, v6_b, v4_b, v6_c, v4_c]);
        crate::test_complete!("happy_eyeballs_from_lookup_ignores_cross_family_interleaving");
    }

    #[test]
    fn happy_eyeballs_v4_only() {
        init_test("happy_eyeballs_v4_only");
        let he = HappyEyeballs::new(
            vec![],
            vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        );
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(std::net::IpAddr::is_ipv4));
        crate::test_complete!("happy_eyeballs_v4_only");
    }

    #[test]
    fn happy_eyeballs_v6_only() {
        init_test("happy_eyeballs_v6_only");
        let he = HappyEyeballs::new(vec!["::1".parse().unwrap(), "::2".parse().unwrap()], vec![]);
        let addrs: Vec<_> = he.collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().all(std::net::IpAddr::is_ipv6));
        crate::test_complete!("happy_eyeballs_v6_only");
    }

    #[test]
    fn happy_eyeballs_debug_clone() {
        init_test("happy_eyeballs_debug_clone");
        let he = HappyEyeballs::new(vec!["::1".parse().unwrap()], vec![]);
        let dbg = format!("{he:?}");
        assert!(dbg.contains("HappyEyeballs"), "{dbg}");
        let cloned = he;
        assert_eq!(cloned.remaining(), 1);
        crate::test_complete!("happy_eyeballs_debug_clone");
    }

    #[test]
    fn happy_eyeballs_remaining_saturates_for_invalid_internal_indices() {
        init_test("happy_eyeballs_remaining_saturates_for_invalid_internal_indices");
        let he = HappyEyeballs {
            v6: vec![],
            v4: vec![],
            v6_idx: 3,
            v4_idx: 7,
            prefer_v6: true,
        };
        assert_eq!(he.remaining(), 0);
        crate::test_complete!("happy_eyeballs_remaining_saturates_for_invalid_internal_indices");
    }

    #[test]
    fn lookup_srv_debug_clone() {
        init_test("lookup_srv_debug_clone");
        let srv = LookupSrv::new(vec![SrvRecord {
            priority: 10,
            weight: 50,
            port: 443,
            target: "srv.example.com".to_string(),
        }]);
        let dbg = format!("{srv:?}");
        assert!(dbg.contains("LookupSrv"), "{dbg}");
        let cloned = srv;
        assert_eq!(cloned.records().count(), 1);
        crate::test_complete!("lookup_srv_debug_clone");
    }

    #[test]
    fn srv_record_debug_clone() {
        init_test("srv_record_debug_clone");
        let rec = SrvRecord {
            priority: 5,
            weight: 100,
            port: 8080,
            target: "host.example".to_string(),
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("SrvRecord"), "{dbg}");
        let cloned = rec;
        assert_eq!(cloned.priority, 5);
        assert_eq!(cloned.port, 8080);
        crate::test_complete!("srv_record_debug_clone");
    }

    #[test]
    fn mx_record_debug_clone() {
        init_test("mx_record_debug_clone");
        let rec = MxRecord {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("MxRecord"), "{dbg}");
        let cloned = rec;
        assert_eq!(cloned.preference, 10);
        crate::test_complete!("mx_record_debug_clone");
    }

    #[test]
    fn lookup_txt_debug_clone() {
        init_test("lookup_txt_debug_clone");
        let txt = LookupTxt::new(vec!["v=spf1 include:example.com".to_string()]);
        let dbg = format!("{txt:?}");
        assert!(dbg.contains("LookupTxt"), "{dbg}");
        let cloned = txt;
        let records: Vec<_> = cloned.records().collect();
        assert_eq!(records.len(), 1);
        assert!(records[0].contains("spf1"));
        crate::test_complete!("lookup_txt_debug_clone");
    }

    #[test]
    fn lookup_txt_empty() {
        init_test("lookup_txt_empty");
        let txt = LookupTxt::new(vec![]);
        assert_eq!(txt.records().count(), 0);
        crate::test_complete!("lookup_txt_empty");
    }

    #[test]
    fn lookup_mx_new_sorts_by_preference() {
        init_test("lookup_mx_new_sorts_by_preference");
        let lookup = LookupMx::new(vec![
            MxRecord {
                preference: 20,
                exchange: "mx2.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx1.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx0.example".to_string(),
            },
        ]);
        let records: Vec<_> = lookup.records().collect();

        let first_pref = records[0].preference;
        let second_pref = records[1].preference;
        let third_pref = records[2].preference;
        crate::assert_with_log!(first_pref == 10, "first preference", 10, first_pref);
        crate::assert_with_log!(second_pref == 10, "second preference", 10, second_pref);
        crate::assert_with_log!(third_pref == 20, "third preference", 20, third_pref);

        let first_exchange = records[0].exchange.as_str();
        let second_exchange = records[1].exchange.as_str();
        crate::assert_with_log!(
            first_exchange == "mx0.example",
            "first exchange",
            "mx0.example",
            first_exchange
        );
        crate::assert_with_log!(
            second_exchange == "mx1.example",
            "second exchange",
            "mx1.example",
            second_exchange
        );
        crate::test_complete!("lookup_mx_new_sorts_by_preference");
    }

    #[test]
    fn lookup_mx_sorting_is_permutation_invariant() {
        init_test("lookup_mx_sorting_is_permutation_invariant");
        let records = vec![
            MxRecord {
                preference: 20,
                exchange: "mx-b.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx-c.example".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx-a.example".to_string(),
            },
            MxRecord {
                preference: 30,
                exchange: "mx-d.example".to_string(),
            },
        ];

        let reversed = records.iter().cloned().rev().collect::<Vec<_>>();
        let rotated = vec![
            records[2].clone(),
            records[0].clone(),
            records[3].clone(),
            records[1].clone(),
        ];

        let sorted = |records: Vec<MxRecord>| {
            LookupMx::new(records)
                .records()
                .map(|record| (record.preference, record.exchange.as_str().to_owned()))
                .collect::<Vec<_>>()
        };

        let expected = sorted(records);
        assert_eq!(sorted(reversed), expected);
        assert_eq!(sorted(rotated), expected);
        crate::test_complete!("lookup_mx_sorting_is_permutation_invariant");
    }
