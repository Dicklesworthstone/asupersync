use asupersync_macros::spawn;

fn main() {
    let _ = spawn!("worker", "not a future");
}
