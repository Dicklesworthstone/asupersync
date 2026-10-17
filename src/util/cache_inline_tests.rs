    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use core::mem;

    #[test]
    fn alignment_is_cache_line() {
        assert_eq!(mem::align_of::<CachePadded<u8>>(), CACHE_LINE_SIZE);
        assert_eq!(mem::align_of::<CachePadded<u64>>(), CACHE_LINE_SIZE);
        assert_eq!(mem::align_of::<CachePadded<[u8; 128]>>(), CACHE_LINE_SIZE);
    }

    #[test]
    fn size_is_multiple_of_cache_line() {
        assert_eq!(mem::size_of::<CachePadded<u8>>() % CACHE_LINE_SIZE, 0);
        assert_eq!(mem::size_of::<CachePadded<u64>>() % CACHE_LINE_SIZE, 0);
    }

    #[test]
    fn deref_works() {
        let padded = CachePadded::new(42u64);
        assert_eq!(*padded, 42);
    }

    #[test]
    fn deref_mut_works() {
        let mut padded = CachePadded::new(0u64);
        *padded = 99;
        assert_eq!(*padded, 99);
    }

    #[test]
    fn into_inner() {
        let padded = CachePadded::new(String::from("hello"));
        let s = padded.into_inner();
        assert_eq!(s, "hello");
    }

    #[test]
    fn default_works() {
        let padded: CachePadded<u64> = CachePadded::default();
        assert_eq!(*padded, 0);
    }

    #[test]
    fn cache_padded_debug_clone_copy() {
        let p = CachePadded::new(42u64);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("42"), "{dbg}");

        let copied: CachePadded<u64> = p;
        let cloned = p;
        assert_eq!(*copied, 42);
        assert_eq!(*cloned, 42);
    }

    #[test]
    fn two_padded_values_dont_share_cache_line() {
        let a = CachePadded::new(1u64);
        let b = CachePadded::new(2u64);
        let a_addr = core::ptr::addr_of!(*a) as usize;
        let b_addr = core::ptr::addr_of!(*b) as usize;
        // They must be at least CACHE_LINE_SIZE apart
        let diff = a_addr.abs_diff(b_addr);
        assert!(
            diff >= CACHE_LINE_SIZE,
            "values are only {diff} bytes apart, need >= {CACHE_LINE_SIZE}"
        );
    }
