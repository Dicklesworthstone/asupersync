#[cfg(feature = "proc-macros")]
mod demo {
    use asupersync::proc_macros::race;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    #[derive(Clone, Copy)]
    struct RaceCx;

    impl RaceCx {
        async fn race<T>(&self, mut futures: Vec<Pin<Box<dyn Future<Output = T>>>>) -> T {
            futures.remove(0).await
        }

        async fn race_named<T>(
            &self,
            mut futures: Vec<(&'static str, Pin<Box<dyn Future<Output = T>>>)>,
        ) -> T {
            let (_, fut) = futures.remove(0);
            fut.await
        }

        async fn race_timeout<T>(
            &self,
            _timeout: Duration,
            futures: Vec<Pin<Box<dyn Future<Output = T>>>>,
        ) -> T {
            self.race(futures).await
        }

        async fn race_timeout_named<T>(
            &self,
            _timeout: Duration,
            futures: Vec<(&'static str, Pin<Box<dyn Future<Output = T>>>)>,
        ) -> T {
            self.race_named(futures).await
        }
    }

    pub async fn demo() {
        let cx = RaceCx;

        let _ = race!(cx, { async { 1 }, async { 2 } });
        let _ = race!(cx, { "fast" => async { 10 }, "slow" => async { 20 } });
        let _ = race!(cx, timeout: Duration::from_secs(1), { async { 3 }, async { 4 } });
    }
}

#[cfg(feature = "proc-macros")]
fn main() {
    let _ = demo::demo();
}

#[cfg(not(feature = "proc-macros"))]
fn main() {}
