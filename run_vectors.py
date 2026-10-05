#!/usr/bin/env python3
"""Runs checker.py against the published acceptance-record vectors and
reports agreement/disagreement per vector, vs. the pinned `expect`
block already present in the vectors file (written by the vector
author from the condition table, per that file's own README -- not
read back from any checker). This script does not import or read any
checker other than this repo's own checker.py.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

EXPECTED_SHA256 = "c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0"


def main(argv):
    vectors_path = Path(argv[1] if len(argv) > 1 else "vectors.json")
    data = vectors_path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != EXPECTED_SHA256:
        print(f"ABORT: {vectors_path} sha256 {actual_sha} != expected {EXPECTED_SHA256}")
        return 2

    doc = json.loads(data)
    vectors = doc["vectors"]

    import checker

    agreements = []
    disagreements = []
    for vec in vectors:
        vid = vec["id"]
        case = vec["case"]
        expect = vec["expect"]
        got = checker.check_acceptance(case)

        got_conditions = set(got.get("conditions") or [])
        expect_conditions = set(expect.get("conditions") or [])

        match = (
            got["result"] == expect["result"]
            and got.get("disposition") == expect.get("disposition")
            and got_conditions == expect_conditions
        )
        record = {
            "id": vid,
            "what": vec.get("what"),
            "expect": {
                "result": expect["result"],
                "disposition": expect.get("disposition"),
                "conditions": sorted(expect_conditions),
            },
            "got": {
                "result": got["result"],
                "disposition": got.get("disposition"),
                "conditions": sorted(got_conditions),
                "exit_code": got["exit_code"],
                "policy_refusal": got.get("policy_refusal"),
            },
        }
        if match:
            agreements.append(record)
        else:
            disagreements.append(record)

    print(f"{len(agreements)}/{len(vectors)} agree, {len(disagreements)} disagree\n")

    print("=== AGREEMENTS ===")
    for r in agreements:
        print(f"  {r['id']}: {r['expect']['result']} (conditions={r['expect']['conditions']})  -- {r['what']}")

    print("\n=== DISAGREEMENTS ===")
    for r in disagreements:
        print(f"  {r['id']} -- {r['what']}")
        print(f"    expected: result={r['expect']['result']!r} disposition={r['expect']['disposition']!r} conditions={r['expect']['conditions']}")
        print(f"    got:      result={r['got']['result']!r} disposition={r['got']['disposition']!r} conditions={r['got']['conditions']} exit_code={r['got']['exit_code']} policy_refusal={r['got']['policy_refusal']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
