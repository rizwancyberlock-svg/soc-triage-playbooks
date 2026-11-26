#!/usr/bin/env python3
"""Export every ```kql block in the playbooks as a YAML file the Sentinel KQL validator can read.

Usage: python tools/export_kql.py playbooks .kql-snippets
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

BLOCK = re.compile(r"^[ \t]*```kql[ \t]*\n(.*?)^[ \t]*```", re.S | re.M)


def main() -> int:
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.yaml"):
        old.unlink()
    n = 0
    for path in sorted(src.rglob("*.md")):
        for i, m in enumerate(BLOCK.finditer(path.read_text(encoding="utf-8")), 1):
            lines = m.group(1).splitlines()
            indent = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
            body = "\n".join("  " + l[indent:] for l in lines)
            (out / f"{path.stem}-{i}.yaml").write_text(f"name: {path.stem} snippet {i}\nquery: |\n{body}\n", encoding="utf-8", newline="\n")
            n += 1
    print(f"exported {n} KQL snippets to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
