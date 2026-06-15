use asupersync_macros::select;

fn main() {
    // select! requires at least one branch.
    let _ = select!(cx, {});
}
