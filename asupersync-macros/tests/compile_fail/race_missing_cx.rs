use asupersync_macros::race;

fn main() {
    // race! requires a cx argument before the branch block.
    let _ = race!({ fut_a(), fut_b() });
}
