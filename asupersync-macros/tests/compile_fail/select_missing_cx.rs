use asupersync_macros::select;

fn main() {
    // select! requires a cx argument before the branch block.
    let _ = select!({ a = fut_a() => a, b = fut_b() => b });
}
