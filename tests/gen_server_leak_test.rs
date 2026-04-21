#![allow(clippy::all)]
//! Regression coverage for gen-server obligation leak handling.

//! Regression test for GenServer resource leaks

use asupersync::cx::Cx;
use asupersync::gen_server::*;
use asupersync::lab::LabConfig;
use asupersync::lab::LabRuntime;
use asupersync::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::time::Duration;

#[derive(Debug)]
struct TestServer;

impl GenServer for TestServer {
    type Call = ();
    type Cast = ();
    type Info = ();
    type Reply = ();

    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn handle_call(
        &mut self,
        _cx: &Cx,
        _msg: Self::Call,
        reply: Reply<Self::Reply>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let _ = reply.send(());
        Box::pin(async {})
    }

    fn handle_cast(
        &mut self,
        _cx: &Cx,
        _msg: Self::Cast,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // Block the actor loop so the mailbox fills up
            asupersync::time::sleep(
                asupersync::types::Time::from_secs(100),
                Duration::from_secs(100),
            )
            .await;
        })
    }
}

#[test]
fn test_call_future_dropped_mid_flight_prevents_obligation_leak() {
    let config = LabConfig::new(0)
        .panic_on_leak(true)
        .futurelock_max_idle_steps(0);
    let mut runtime = LabRuntime::new(config);
    let budget = Budget::INFINITE;
    let region = runtime.state.create_root_region(budget);
    let cx = Cx::for_testing();

    let (server_ref, _stored_task) = cx
        .scope()
        .spawn_gen_server(
            &mut runtime.state,
            &cx,
            TestServer,
            1, // Small mailbox capacity to easily fill it
        )
        .expect("spawn_gen_server");

    let task_id = server_ref.task_id();
    runtime.scheduler.lock().schedule(task_id, 0);

    let (task, _) = runtime
        .state
        .create_task(region, budget, async move {
            let cx = Cx::for_testing();

            // Fill the mailbox
            let _ = server_ref.try_cast(());
            let _ = server_ref.try_cast(());

            // This call will block on the full mailbox.
            let call_fut = server_ref.call(&cx, ());

            // We poll it once then drop it
            let mut pinned = Box::pin(call_fut);
            let mut std_cx = Context::from_waker(std::task::Waker::noop());
            let _ = std::future::Future::poll(pinned.as_mut(), &mut std_cx);

            drop(pinned); // Drops the mid-flight send future! Should NOT panic if obligation is managed properly.

            server_ref.abort();
        })
        .unwrap();

    runtime.scheduler.lock().schedule(task, 0);
    runtime.run_until_quiescent();
}
