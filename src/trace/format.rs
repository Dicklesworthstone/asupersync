//! Formatting utilities for trace output.
//!
//! Provides human-readable and machine-readable formatting for traces.

use super::buffer::TraceBuffer;
use std::io::{self, Write};

/// Formats a trace buffer as human-readable text.
pub fn format_trace(buffer: &TraceBuffer, w: &mut impl Write) -> io::Result<()> {
    writeln!(w, "=== Trace ({} events) ===", buffer.len())?;
    for event in buffer.iter() {
        writeln!(w, "{event}")?;
    }
    writeln!(w, "=== End Trace ===")?;
    Ok(())
}

/// Formats a trace buffer as a string.
#[must_use]
pub fn trace_to_string(buffer: &TraceBuffer) -> String {
    let mut s = Vec::new();
    format_trace(buffer, &mut s).expect("writing to Vec should not fail");
    String::from_utf8(s).expect("trace should be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use crate::types::Time;

    #[test]
    fn format_empty_trace() {
        let buffer = TraceBuffer::new(10);
        let output = trace_to_string(&buffer);
        assert!(output.contains("0 events"));
    }

    #[test]
    fn format_with_events() {
        let mut buffer = TraceBuffer::new(10);
        buffer.push(TraceEvent::new(
            1,
            Time::from_millis(100),
            TraceEventKind::UserTrace,
            TraceData::Message("test".to_string()),
        ));
        let output = trace_to_string(&buffer);
        assert!(output.contains("1 events"));
        assert!(output.contains("test"));
    }
}
