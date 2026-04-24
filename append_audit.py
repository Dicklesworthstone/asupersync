import json
import sys

audits = [
    {
        "file": "src/net/tcp/virtual_tcp.rs",
        "lines": 600,
        "batch": "session-789b18c4",
        "date": "2026-04-23",
        "agent": "Gemini",
        "verdict": "FIXED",
        "bugs": 3,
        "notes": "Fixed massive cancel-safety violation across poll_read, poll_write, and poll_accept where dropped futures would bypass the central async runtime cancellation invariants."
    },
    {
        "file": "src/net/udp.rs",
        "lines": 900,
        "batch": "session-789b18c4",
        "date": "2026-04-23",
        "agent": "Gemini",
        "verdict": "SOUND",
        "bugs": 0,
        "notes": "Checked UDP poll_recv and poll_recv_from; all properly intercept Cx cancellation."
    }
]

with open('audit_index.jsonl', 'a') as f:
    for audit in audits:
        f.write(json.dumps(audit) + '\n')
