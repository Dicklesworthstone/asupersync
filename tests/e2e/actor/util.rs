//! Shared helpers for Actor E2E tests.

use asupersync::actor::{Actor, ActorHandle, ActorId, ActorRef};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// Initialize actor test with logging.
pub fn init_actor_test(test_name: &str) {
    crate::common::init_test_logging();
    crate::test_phase!(test_name);
}

/// A simple counter actor for testing.
pub struct CounterActor {
    /// Current count value.
    pub count: u64,
    /// Event log for test assertions.
    pub events: Arc<Mutex<Vec<String>>>,
}

impl CounterActor {
    /// Create a new counter actor with the given event log.
    pub fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self { count: 0, events }
    }

    fn log(&self, msg: &str) {
        self.events.lock().unwrap().push(msg.to_string());
    }
}

/// Messages for the counter actor.
#[derive(Debug, Clone)]
pub enum CounterMessage {
    /// Increment the counter by the given amount.
    Increment(u64),
    /// Reset the counter to zero.
    Reset,
    /// Get the current count (reply via the provided channel).
    GetCount,
}

impl Actor for CounterActor {
    type Message = CounterMessage;

    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log("started");
        })
    }

    fn handle(
        &mut self,
        _cx: &Cx,
        msg: Self::Message,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match msg {
                CounterMessage::Increment(n) => {
                    self.count += n;
                    self.log(&format!("increment:{n}->{}", self.count));
                }
                CounterMessage::Reset => {
                    self.count = 0;
                    self.log("reset");
                }
                CounterMessage::GetCount => {
                    self.log(&format!("get:{}", self.count));
                }
            }
        })
    }

    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log(&format!("stopped:count={}", self.count));
        })
    }
}

/// An echo actor that records all received messages.
pub struct EchoActor {
    /// All messages received by this actor.
    pub received: Vec<String>,
    /// Event log for test assertions.
    pub events: Arc<Mutex<Vec<String>>>,
}

impl EchoActor {
    /// Create a new echo actor with the given event log.
    pub fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            received: Vec::new(),
            events,
        }
    }

    fn log(&self, msg: &str) {
        self.events.lock().unwrap().push(msg.to_string());
    }
}

impl Actor for EchoActor {
    type Message = String;

    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log("echo:started");
        })
    }

    fn handle(
        &mut self,
        _cx: &Cx,
        msg: Self::Message,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.received.push(msg.clone());
            self.log(&format!("echo:recv:{msg}"));
        })
    }

    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log(&format!("echo:stopped:count={}", self.received.len()));
        })
    }
}

/// A failing actor for supervision testing.
pub struct FailingActor {
    /// Number of messages to process before panicking.
    pub fail_after: u32,
    /// Messages processed so far.
    pub count: u32,
    /// Event log for test assertions.
    pub events: Arc<Mutex<Vec<String>>>,
}

impl FailingActor {
    /// Create a new failing actor that panics after processing `fail_after` messages.
    pub fn new(fail_after: u32, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            fail_after,
            count: 0,
            events,
        }
    }

    fn log(&self, msg: &str) {
        self.events.lock().unwrap().push(msg.to_string());
    }
}

impl Actor for FailingActor {
    type Message = ();

    fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log("failing:started");
        })
    }

    fn handle(
        &mut self,
        _cx: &Cx,
        _msg: Self::Message,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.count += 1;
            self.log(&format!("failing:msg:{}", self.count));
            if self.count >= self.fail_after {
                self.log("failing:panic!");
                panic!(
                    "Intentional test failure after {} messages",
                    self.fail_after
                );
            }
        })
    }

    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            self.log(&format!("failing:stopped:count={}", self.count));
        })
    }
}

/// Create a lab runtime with default test configuration.
pub fn test_lab_runtime(seed: u64) -> LabRuntime {
    LabRuntime::new(LabConfig::new(seed).max_steps(50_000))
}

/// Run a lab test and return the collected events.
pub fn run_lab_test<F>(seed: u64, events: &Arc<Mutex<Vec<String>>>, setup: F) -> Vec<String>
where
    F: FnOnce(&mut LabRuntime, Arc<Mutex<Vec<String>>>),
{
    let mut runtime = test_lab_runtime(seed);
    setup(&mut runtime, Arc::clone(events));
    runtime.run_until_quiescent();
    events.lock().unwrap().clone()
}
