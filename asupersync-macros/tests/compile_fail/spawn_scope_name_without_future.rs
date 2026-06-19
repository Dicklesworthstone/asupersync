use asupersync_macros::spawn;

fn main() {
    let _ = spawn!(scope, "worker");
}
