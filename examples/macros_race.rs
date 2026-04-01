#![allow(missing_docs)]
#![allow(clippy::trivially_copy_pass_by_ref, clippy::unused_self)]

#[cfg(feature = "proc-macros")]
mod demo {
    use asupersync::race;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
    type NamedFuture<T> = (&'static str, BoxFuture<T>);

    #[derive(Clone, Copy)]
    struct RaceCx;

    impl RaceCx {
        async fn race<T>(&self, mut futures: Vec<BoxFuture<T>>) -> T
        where
            T: Send + 'static,
        {
            futures.remove(0).await
        }

        async fn race_named<T>(&self, mut futures: Vec<NamedFuture<T>>) -> T
        where
            T: Send + 'static,
        {
            let (_, fut) = futures.remove(0);
            fut.await
        }

        async fn race_timeout<T>(&self, _timeout: Duration, futures: Vec<BoxFuture<T>>) -> T
        where
            T: Send + 'static,
        {
            self.race(futures).await
        }

        async fn race_timeout_named<T>(&self, _timeout: Duration, futures: Vec<NamedFuture<T>>) -> T
        where
            T: Send + 'static,
        {
            self.race_named(futures).await
        }
    }

    pub async fn demo() {
        let cx = RaceCx;

        let _ = race!(cx, { async { 1 }, async { 2 } });
        let _ = race!(cx, { "fast" => async { 10 }, "slow" => async { 20 } });
        let _ = race!(cx, timeout: Duration::from_secs(1), { async { 3 }, async { 4 } });
        let _ = race!(cx, timeout: Duration::from_secs(1), {
            "fast" => async { 30 },
            "slow" => async { 40 },
        });
    }
}

#[cfg(feature = "proc-macros")]
fn main() {
    std::mem::drop(demo::demo());
}

#[cfg(not(feature = "proc-macros"))]
fn main() {}
