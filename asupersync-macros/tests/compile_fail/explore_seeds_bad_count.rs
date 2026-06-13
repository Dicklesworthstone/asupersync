use asupersync_macros::explore_seeds;

#[explore_seeds(count = 0)]
fn bad_count(lab: &mut asupersync::lab::LabRuntime) {
    let _ = lab.now();
}

fn main() {}
