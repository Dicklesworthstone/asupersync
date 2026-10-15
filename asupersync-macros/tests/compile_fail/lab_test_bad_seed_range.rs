use asupersync_macros::lab_test;

#[lab_test(seeds = 4..4)]
fn bad_seed_range(lab: &mut asupersync::lab::LabRuntime) {
    let _ = lab.now();
}

fn main() {}
