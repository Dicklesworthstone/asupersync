use asupersync_macros::race;

fn main() {
    // race! requires at least two branches to actually race.
    let _ = race!(cx, { fut_a() });
}
