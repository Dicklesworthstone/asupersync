# Scored Candidates

| Candidate | LOC Saved | Confidence | Risk | Score | Decision |
|---|---:|---:|---:|---:|---|
| Extract `unsupported_result()` in the non-Windows IOCP stub | 3 | 5 | 1 | 15.0 | Landed |

Notes:
- The previous code duplicated both the message literal and the error
  constructor at every site.
