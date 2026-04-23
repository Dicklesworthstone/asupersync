/*!
Utility modules for the lab runtime.

Shared utilities used by lab oracle modules and testing infrastructure.
*/

pub mod stack_trace;

pub use stack_trace::{
    capture_stack_trace, capture_stack_trace_default, capture_stack_trace_depth,
    capture_stack_trace_minimal, StackTraceConfig,
};