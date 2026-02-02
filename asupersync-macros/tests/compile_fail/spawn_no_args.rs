use asupersync_macros::spawn;

fn main() {
    // spawn! requires at least a future expression
    let _ = spawn!();
}
