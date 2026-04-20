#![no_main]

use arbitrary::Arbitrary;
use asupersync::util::DetRng;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    buffer_len: u8,
    bound: u16,
    values: Vec<u16>,
}

fuzz_target!(|input: FuzzInput| {
    if input.values.len() > 64 {
        return;
    }

    assert_stream_matches_model(input.seed);
    assert_zero_seed_normalization();
    assert_next_u32_matches_u64_projection(input.seed);
    assert_next_bool_matches_u64_lsb(input.seed);
    assert_fill_bytes_matches_stream(input.seed, usize::from(input.buffer_len));

    if input.bound > 0 {
        assert_next_usize_matches_model(input.seed, usize::from(input.bound));
    }

    assert_shuffle_is_deterministic_and_permuting(input.seed, &input.values);
});

fn assert_stream_matches_model(seed: u64) {
    let mut rng = DetRng::new(seed);
    let mut state = normalized_seed(seed);
    for _ in 0..8 {
        let expected = model_next_u64(&mut state);
        assert_eq!(rng.next_u64(), expected);
    }
}

fn assert_zero_seed_normalization() {
    let mut zero = DetRng::new(0);
    let mut one = DetRng::new(1);
    for _ in 0..4 {
        assert_eq!(zero.next_u64(), one.next_u64());
    }
}

fn assert_next_u32_matches_u64_projection(seed: u64) {
    let mut rng_u32 = DetRng::new(seed);
    let mut rng_u64 = DetRng::new(seed);
    let expected = (rng_u64.next_u64() >> 32) as u32;
    assert_eq!(rng_u32.next_u32(), expected);
}

fn assert_next_bool_matches_u64_lsb(seed: u64) {
    let mut rng_bool = DetRng::new(seed);
    let mut rng_u64 = DetRng::new(seed);
    let expected = rng_u64.next_u64() & 1 == 1;
    assert_eq!(rng_bool.next_bool(), expected);
}

fn assert_fill_bytes_matches_stream(seed: u64, buffer_len: usize) {
    let mut rng = DetRng::new(seed);
    let mut actual = vec![0u8; buffer_len];
    rng.fill_bytes(&mut actual);

    let mut expected = Vec::with_capacity(buffer_len);
    let mut state = normalized_seed(seed);
    while expected.len() < buffer_len {
        expected.extend_from_slice(&model_next_u64(&mut state).to_le_bytes());
    }
    expected.truncate(buffer_len);

    assert_eq!(actual, expected);
}

fn assert_next_usize_matches_model(seed: u64, bound: usize) {
    let mut rng = DetRng::new(seed);
    let mut state = normalized_seed(seed);
    let expected = model_next_usize(&mut state, bound);
    let actual = rng.next_usize(bound);
    assert_eq!(actual, expected);
    assert!(actual < bound);
}

fn assert_shuffle_is_deterministic_and_permuting(seed: u64, values: &[u16]) {
    let mut shuffled_a = values.to_vec();
    let mut shuffled_b = values.to_vec();
    let mut rng_a = DetRng::new(seed);
    let mut rng_b = DetRng::new(seed);
    rng_a.shuffle(&mut shuffled_a);
    rng_b.shuffle(&mut shuffled_b);
    assert_eq!(shuffled_a, shuffled_b);

    let mut expected = values.to_vec();
    let mut state = normalized_seed(seed);
    for i in (1..expected.len()).rev() {
        let j = model_next_usize(&mut state, i + 1);
        expected.swap(i, j);
    }
    assert_eq!(shuffled_a, expected);

    let mut original = values.to_vec();
    let mut shuffled = shuffled_a;
    original.sort_unstable();
    shuffled.sort_unstable();
    assert_eq!(shuffled, original);
}

fn normalized_seed(seed: u64) -> u64 {
    if seed == 0 { 1 } else { seed }
}

fn model_next_u64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn model_next_usize(state: &mut u64, bound: usize) -> usize {
    let bound_u64 = bound as u64;
    let threshold = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let value = model_next_u64(state);
        if value < threshold {
            return (value % bound_u64) as usize;
        }
    }
}
