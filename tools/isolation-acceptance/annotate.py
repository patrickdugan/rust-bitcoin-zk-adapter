#!/usr/bin/env python3
"""Emit one GitHub notice annotation per log with its PASS/FAIL/INFO lines.

Annotations are readable through the public check-run API, unlike job logs,
so they carry the outcome summary. Exit status 1 if any line says FAIL.
"""
import re
import sys

failed = False
for path in sys.argv[1:]:
    try:
        lines = open(path, encoding="utf8", errors="replace").read().splitlines()
    except OSError as exc:
        print(f"::warning title={path}::unreadable: {exc}")
        failed = True
        continue
    keep = [l.rstrip() for l in lines
            if re.search(r"\b(PASS|FAIL|INFO)\b|policy_sha256=|exit=|transitions|passed$|"
                         r"Maximum resident|Elapsed|peak|rust-bitcoin-raito-sidecar|Cargo.lock", l)]
    failed |= any(re.search(r"\bFAIL\b", l) for l in keep)
    text = "\n".join(keep)[:60000] or "(no outcome lines)"
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::notice title={path.rsplit('/', 1)[-1]}::{text}")
sys.exit(1 if failed else 0)
