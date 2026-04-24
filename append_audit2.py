import json

audits = [
    {
        "file": "src/net/websocket/server.rs",
        "lines": 725,
        "batch": "session-789b18c4",
        "date": "2026-04-23",
        "agent": "Gemini",
        "verdict": "FIXED",
        "bugs": 2,
        "notes": "Fixed cancellation bug in ServerWebSocket recv where flush_write_buf Interrupted error bypassed the close handshake. Fixed ping to take Cx parameter and properly handle cancellation by initiating close handshake, aligning with send semantics."
    },
    {
        "file": "src/net/worker_channel.rs",
        "lines": 2815,
        "batch": "session-789b18c4",
        "date": "2026-04-23",
        "agent": "Gemini",
        "verdict": "SOUND",
        "bugs": 0,
        "notes": "Reviewed message port coordinator and cancellation envelope validation. Confirmed seq_no bounds and JobState transition machine reject invalid snapshots without desyncing the main/worker channel."
    }
]

with open('audit_index.jsonl', 'a') as f:
    for audit in audits:
        f.write(json.dumps(audit) + '\n')
