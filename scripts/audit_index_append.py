#!/usr/bin/env python3
"""Validate and append one audit_index.jsonl row without rewriting the file."""

import argparse
import datetime as dt
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


REQUIRED_KEYS = ("file", "lines", "batch", "date", "agent", "verdict", "bugs", "notes")
VALID_VERDICTS = {"SOUND", "FIXED"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate one audit_index NDJSON row and append it as a single line. "
            "Existing bytes are never rewritten."
        )
    )
    parser.add_argument("--index", default="audit_index.jsonl", help="NDJSON target path")
    parser.add_argument("--row-json", help="Complete JSON object for the row")
    parser.add_argument("--row-file", help="File containing one JSON object row")
    parser.add_argument("--file", dest="file_path", help="Audited path relative to repo root")
    parser.add_argument("--lines", type=int, help="Line count at audit time")
    parser.add_argument("--batch", help="Batch id, bead id, or stable campaign id")
    parser.add_argument("--date", help="ISO date, YYYY-MM-DD")
    parser.add_argument("--agent", help="Auditing agent name")
    parser.add_argument("--verdict", choices=sorted(VALID_VERDICTS), help="Audit verdict")
    parser.add_argument("--bugs", type=int, help="Bug count found during the audit")
    parser.add_argument("--notes", default=None, help="Short audit note")
    parser.add_argument("--dry-run", action="store_true", help="Print canonical row without appending")
    parser.add_argument("--create", action="store_true", help="Create the target file if it is absent")
    parser.add_argument("--self-test", action="store_true", help="Run helper unit tests")
    parser.add_argument("--self-test-dir", help="Directory for retained self-test artifacts")
    return parser.parse_args()


def reject(message: str) -> None:
    raise ValueError(message)


def has_control_or_newline(value: str) -> bool:
    return any(ord(char) < 0x20 for char in value)


def validate_string(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        reject(f"{name} must be a string")
    if not allow_empty and value == "":
        reject(f"{name} must not be empty")
    if has_control_or_newline(value):
        reject(f"{name} must not contain control characters or newlines")
    return value


def validate_relative_file(value: Any) -> str:
    path = validate_string("file", value)
    if path.startswith("/") or path.startswith("\\"):
        reject("file must be relative to the repository root")
    if "\\" in path:
        reject("file must use forward slash separators")
    parts = path.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        reject("file must be a normalized relative path")
    return path


def validate_non_negative_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        reject(f"{name} must be an integer")
    if value < 0:
        reject(f"{name} must be non-negative")
    return value


def validate_date(value: Any) -> str:
    date = validate_string("date", value)
    try:
        parsed = dt.date.fromisoformat(date)
    except ValueError as error:
        raise ValueError("date must be YYYY-MM-DD") from error
    if parsed.isoformat() != date:
        reject("date must be canonical YYYY-MM-DD")
    return date


def validate_batch(value: Any) -> int | str:
    if isinstance(value, bool):
        reject("batch must be an integer or string")
    if isinstance(value, int):
        return value
    batch = validate_string("batch", value)
    return batch


def validate_row(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject("row must be a JSON object")
    missing = [key for key in REQUIRED_KEYS if key not in value]
    if missing:
        reject(f"row is missing required keys: {', '.join(missing)}")
    unknown = [key for key in value if key not in REQUIRED_KEYS]
    if unknown:
        reject(f"row contains unknown keys: {', '.join(sorted(unknown))}")

    verdict = validate_string("verdict", value["verdict"])
    if verdict not in VALID_VERDICTS:
        reject("verdict must be SOUND or FIXED")
    bugs = validate_non_negative_int("bugs", value["bugs"])
    if verdict == "SOUND" and bugs != 0:
        reject("SOUND rows must have bugs=0")
    if verdict == "FIXED" and bugs == 0:
        reject("FIXED rows must have bugs>0")

    return {
        "file": validate_relative_file(value["file"]),
        "lines": validate_non_negative_int("lines", value["lines"]),
        "batch": validate_batch(value["batch"]),
        "date": validate_date(value["date"]),
        "agent": validate_string("agent", value["agent"]),
        "verdict": verdict,
        "bugs": bugs,
        "notes": validate_string("notes", value["notes"], allow_empty=True),
    }


def canonical_json(row: dict[str, Any]) -> str:
    ordered = {key: row[key] for key in REQUIRED_KEYS}
    return json.dumps(ordered, ensure_ascii=True, separators=(",", ":"))


def load_row_from_args(args: argparse.Namespace) -> dict[str, Any]:
    sources = [args.row_json is not None, args.row_file is not None]
    field_values = [
        args.file_path,
        args.lines,
        args.batch,
        args.date,
        args.agent,
        args.verdict,
        args.bugs,
        args.notes,
    ]
    sources.append(any(value is not None for value in field_values))
    if sum(1 for source in sources if source) != 1:
        reject("provide exactly one row source: --row-json, --row-file, or field flags")

    if args.row_json is not None:
        return validate_row(json.loads(args.row_json))
    if args.row_file is not None:
        row_text = Path(args.row_file).read_text(encoding="utf-8")
        return validate_row(json.loads(row_text))

    row = {
        "file": args.file_path,
        "lines": args.lines,
        "batch": args.batch,
        "date": args.date,
        "agent": args.agent,
        "verdict": args.verdict,
        "bugs": args.bugs,
        "notes": args.notes,
    }
    return validate_row(row)


def target_is_appendable(path: Path, *, create: bool) -> None:
    if not path.exists():
        if create:
            return
        reject(f"{path} does not exist; pass --create only for intentional new sidecars")
    if not path.is_file():
        reject(f"{path} is not a regular file")
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size == 0:
            return
        handle.seek(size - 1)
        if handle.read(1) != b"\n":
            reject(f"{path} is nonempty but does not end with a newline")


def append_line(path: Path, line: str, *, create: bool) -> None:
    target_is_appendable(path, create=create)
    flags = os.O_WRONLY | os.O_APPEND
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o644)
    try:
        payload = f"{line}\n".encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
    finally:
        os.close(fd)


def valid_sample(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "file": "src/example.rs",
        "lines": 12,
        "batch": "self-test",
        "date": "2026-05-22",
        "agent": "CyanHare",
        "verdict": "SOUND",
        "bugs": 0,
        "notes": "",
    }
    row.update(overrides)
    return row


def assert_rejected(row: dict[str, Any], expected: str) -> None:
    try:
        validate_row(row)
    except ValueError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!s}") from error
        return
    raise AssertionError(f"row unexpectedly accepted: {row!r}")


def self_test(base_dir: Path | None = None) -> Path:
    row = validate_row(valid_sample())
    if canonical_json(row) != (
        '{"file":"src/example.rs","lines":12,"batch":"self-test",'
        '"date":"2026-05-22","agent":"CyanHare","verdict":"SOUND","bugs":0,"notes":""}'
    ):
        raise AssertionError("canonical JSON shape changed")

    assert_rejected(valid_sample(verdict="SOUND", bugs=1), "SOUND rows")
    assert_rejected(valid_sample(verdict="FIXED", bugs=0), "FIXED rows")
    assert_rejected(valid_sample(file="/tmp/example.rs"), "relative")
    assert_rejected(valid_sample(file="src/../example.rs"), "normalized")
    assert_rejected(valid_sample(file="src\\example.rs"), "forward slash")
    assert_rejected(valid_sample(notes="line one\nline two"), "control")
    bad = valid_sample(extra=True)
    assert_rejected(bad, "unknown")

    temp = base_dir if base_dir is not None else Path(tempfile.mkdtemp(prefix="audit-index-append-test-"))
    temp.mkdir(parents=True, exist_ok=True)
    target = temp / "audit_index.jsonl"
    original = b'{"legacy":true}\n'
    target.write_bytes(original)
    append_line(target, canonical_json(validate_row(valid_sample())), create=False)
    after_first = target.read_bytes()
    if not after_first.startswith(original):
        raise AssertionError("append changed existing prefix")
    append_line(
        target,
        canonical_json(validate_row(valid_sample(file="src/second.rs", batch=378))),
        create=False,
    )
    rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    if rows[-2]["file"] != "src/example.rs" or rows[-1]["file"] != "src/second.rs":
        raise AssertionError("two-row append order was not preserved")
    if rows[-1]["batch"] != 378:
        raise AssertionError("integer batch ids must remain integers")

    missing = temp / "sidecar.jsonl"
    append_line(missing, canonical_json(validate_row(valid_sample(file="src/new.rs"))), create=True)
    if len(missing.read_text(encoding="utf-8").splitlines()) != 1:
        raise AssertionError("--create append did not write exactly one row")

    no_newline = temp / "bad.jsonl"
    no_newline.write_text('{"legacy":true}', encoding="utf-8")
    try:
        append_line(no_newline, canonical_json(validate_row(valid_sample())), create=False)
    except ValueError as error:
        if "does not end with a newline" not in str(error):
            raise AssertionError("wrong no-newline rejection") from error
    else:
        raise AssertionError("non-newline target unexpectedly accepted")
    return temp


def main() -> int:
    args = parse_args()
    if args.self_test:
        artifact_dir = self_test(Path(args.self_test_dir) if args.self_test_dir else None)
        print(f"audit_index_append self-test passed artifact_dir={artifact_dir}")
        return 0

    try:
        row = load_row_from_args(args)
        line = canonical_json(row)
        if args.dry_run:
            print(line)
        else:
            append_line(Path(args.index), line, create=args.create)
            print(line)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"audit_index_append: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
