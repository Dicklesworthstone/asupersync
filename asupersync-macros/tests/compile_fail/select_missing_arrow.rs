use asupersync_macros::select;

fn main() {
    // Each select branch needs `binding = future => handler`; the `=>` is missing.
    let _ = select!(cx, { a = fut_a() a });
}
