#[cfg(feature = "proc-macros")]
mod demo {
    use asupersync::proc_macros::join;

    pub async fn demo() {
        let (a, b): (Result<i32, &'static str>, Result<i32, &'static str>) =
            join!(async { Ok(1) }, async { Err("boom") });

        let _ = match (a, b) {
            (Ok(x), Ok(y)) => Ok(x + y),
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
    }
}

#[cfg(feature = "proc-macros")]
fn main() {
    let _ = demo::demo();
}

#[cfg(not(feature = "proc-macros"))]
fn main() {}
