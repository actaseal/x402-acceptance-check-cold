#!/usr/bin/env python3
"""Runs checker.py against the published acceptance-record vectors and
reports agreement/disagreement per vector, vs. the pinned `expect`
block already present in the vectors file (written by the vector
author from the condition table, per that file's own README -- not
read back from any checker). This script does not import or read any
checker other than this repo's own checker.py.

By default, fetches the vectors file from its public source at a
pinned commit (stdlib urllib, no vendored copy in this repo) and
verifies its sha256 before running -- aborts on any mismatch, network
failure, or missing file, rather than silently falling back to
anything else. Pass a local path as the first argument to use an
already-downloaded copy instead (still sha256-checked).
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

EXPECTED_SHA256 = "464ee7933a17c3ab52db32b93ac21f555a026781f4a8a132b91977eb4fb02882"

# Pinned to commit 37fdb85 of the public source repo
# (babyblueviper1/preaction-governance-conformance; the 46-vector
# corpus -- vectors.json itself last changed at 536681b), not vendored
# here and not pointed at a moving branch -- the fetched bytes are
# still sha256-verified against EXPECTED_SHA256 regardless, so this URL
# is a convenience, not the source of trust.
VECTORS_URL = (
    "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/"
    "37fdb856d8fef1c410e69bbd81070da67dd945d8/examples/acceptance-record-cold/vectors.json"
)


def _load_vectors(argv) -> bytes:
    if len(argv) > 1:
        return Path(argv[1]).read_bytes()
    print(f"Fetching vectors from {VECTORS_URL}", file=sys.stderr)
    with urllib.request.urlopen(VECTORS_URL, timeout=30) as resp:
        return resp.read()


def main(argv):
    try:
        data = _load_vectors(argv)
    except Exception as exc:
        print(f"ABORT: could not load vectors file: {exc}")
        return 2

    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != EXPECTED_SHA256:
        print(f"ABORT: vectors sha256 {actual_sha} != expected {EXPECTED_SHA256}")
        return 2

    doc = json.loads(data)
    vectors = doc["vectors"]

    import checker

    rows = []
    for vec in vectors:
        case = vec["case"]
        expect = vec["expect"]
        got = checker.check_acceptance(case)

        got_conditions = set(got.get("conditions") or [])
        expect_conditions = set(expect.get("conditions") or [])
        expect_has_disposition = "disposition" in expect

        match = got["result"] == expect["result"] and got_conditions == expect_conditions
        if expect_has_disposition:
            match = match and got.get("disposition") == expect.get("disposition")

        rows.append(
            {
                "id": vec["id"],
                "what": vec.get("what") or "",
                "agree": match,
                "expect_result": expect["result"],
                "expect_disposition": expect.get("disposition") if expect_has_disposition else "(unspecified)",
                "expect_conditions": sorted(expect_conditions),
                "got_result": got["result"],
                "got_disposition": got.get("disposition"),
                "got_conditions": sorted(got_conditions),
            }
        )

    agreements = [r for r in rows if r["agree"]]
    disagreements = [r for r in rows if not r["agree"]]

    print(f"\n{len(agreements)}/{len(vectors)} agree, {len(disagreements)} disagree\n")

    print(f"{'id':<42} {'agree':<6} {'our result':<18} {'vector result':<18} conditions (ours | vector)")
    print("-" * 120)
    for r in rows:
        mark = "yes" if r["agree"] else "NO"
        print(
            f"{r['id']:<42} {mark:<6} {r['got_result']:<18} {r['expect_result']:<18} "
            f"{r['got_conditions']} | {r['expect_conditions']}"
        )

    print("\n=== DISAGREEMENTS (detail) ===")
    for r in disagreements:
        print(f"\n  {r['id']} -- {r['what']}")
        print(f"    vector expects: result={r['expect_result']!r} disposition={r['expect_disposition']!r} conditions={r['expect_conditions']}")
        print(f"    we compute:     result={r['got_result']!r} disposition={r['got_disposition']!r} conditions={r['got_conditions']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
