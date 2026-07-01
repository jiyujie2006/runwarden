#!/usr/bin/env python3
"""Validate red-team JSONL corpora: schema, id uniqueness, expected enum."""
from __future__ import annotations

import glob
import json
import sys

VALID_EXPECTED = {"input_blocked", "tool_denied", "requires_review", "allowed_benign"}
REQUIRED = ["id", "category", "expected", "prompt"]


def main(paths: list[str]) -> int:
    errors: list[str] = []
    seen_ids: set[str] = set()
    total = 0
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{path}:{line_no} invalid JSON: {exc}")
                    continue
                for key in REQUIRED:
                    if key not in record:
                        errors.append(f"{path}:{line_no} missing {key}")
                if record.get("expected") not in VALID_EXPECTED:
                    errors.append(f"{path}:{line_no} invalid expected={record.get('expected')}")
                if not str(record.get("prompt", "")).strip():
                    errors.append(f"{path}:{line_no} empty prompt")
                rid = record.get("id")
                if rid in seen_ids:
                    errors.append(f"{path}:{line_no} duplicate id={rid}")
                seen_ids.add(rid)
    print(f"validated {total} records across {len(paths)} files")
    if errors:
        for error in errors:
            print(f"  FAIL {error}", file=sys.stderr)
        return 1
    print("all corpora valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or sorted(glob.glob("redteam/corpora/*.jsonl"))))
