#!/usr/bin/env python3
"""Print a strict, case-oriented summary of an Autobahn JSON report."""

from __future__ import annotations

import collections
import json
import pathlib
import sys


PASS = "OK"
INFORMATIONAL = "INFORMATIONAL"


def load_detail(report_dir: pathlib.Path, report_file: str) -> dict:
    path = (report_dir / report_file).resolve()
    try:
        path.relative_to(report_dir.resolve())
    except ValueError:
        return {}
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
            return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} REPORT/index.json", file=sys.stderr)
        return 2

    index_path = pathlib.Path(sys.argv[1])
    try:
        with index_path.open(encoding="utf-8") as stream:
            index = json.load(stream)
    except (OSError, ValueError) as error:
        print(f"cannot read Autobahn report {index_path}: {error}", file=sys.stderr)
        return 2

    behavior_counts: collections.Counter[str] = collections.Counter()
    close_counts: collections.Counter[str] = collections.Counter()
    failures: list[tuple[str, str, str, str, str]] = []
    total = 0

    for agent, cases in sorted(index.items()):
        for case_id, result in sorted(cases.items(), key=lambda item: tuple(
                int(part) for part in item[0].split("."))):
            total += 1
            behavior = str(result.get("behavior", "MISSING"))
            close = str(result.get("behaviorClose", "MISSING"))
            behavior_counts[behavior] += 1
            close_counts[close] += 1
            if behavior not in {PASS, INFORMATIONAL} or close not in {PASS, INFORMATIONAL}:
                detail = load_detail(index_path.parent, str(result.get("reportfile", "")))
                summary = str(detail.get("result", "no result detail"))
                close_summary = str(detail.get("resultClose", "no close detail"))
                failures.append((str(agent), case_id, behavior, close, f"{summary}; {close_summary}"))

    print(f"Autobahn cases: {total}")
    print("Behavior: " + ", ".join(
        f"{name}={count}" for name, count in sorted(behavior_counts.items())))
    print("Close behavior: " + ", ".join(
        f"{name}={count}" for name, count in sorted(close_counts.items())))

    if failures:
        print(f"Strict failures: {len(failures)}")
        for agent, case_id, behavior, close, detail in failures:
            print(f"  {agent} case {case_id}: behavior={behavior}, close={close}: {detail}")
        return 1

    print("Strict failures: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
