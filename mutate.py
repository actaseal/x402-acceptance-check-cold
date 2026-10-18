#!/usr/bin/env python3
"""Mutation test of checker.py against the acceptance-record vectors.

Each mutation removes or loosens one rule in checker.py (in memory; the
file on disk is never changed). A mutation the vectors catch is KILLED;
one that still agrees with every vector SURVIVED, which means no vector
pins that rule.

  python3 mutate.py            # the 50 vectors at upstream 6e487f0
  python3 mutate.py --pr16     # the 54 vectors proposed in upstream PR #16
  python3 mutate.py FILE       # a local vectors file (no hash check)

Downloads are sha256-checked and abort on mismatch. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

SOURCES = {
    "default": (
        "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/"
        "6e487f0e2253e1d5fcfbf0fd5048018f55119279/examples/acceptance-record-cold/vectors.json",
        "bc0fd4f5c5a0dc29cb4f9cf5fe9bb0d66ee88f91f9e03a74e64f4eb51707f1dd",
    ),
    "--pr16": (
        "https://raw.githubusercontent.com/actaseal/preaction-governance-conformance/"
        "7bf9f6bc6b2829387f04b8d71538df2973b71ad0/examples/acceptance-record-cold/vectors.json",
        "3bbc5a6963cc534131cecf925ab6eec20f61741874b8bae77bbfa73ff894d905",
    ),
}


def load(argv):
    arg = argv[1] if len(argv) > 1 else "default"
    if arg in SOURCES:
        url, want = SOURCES[arg]
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read()
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            sys.exit(f"ABORT: vectors sha256 {got} != {want}")
        return data, url
    with open(arg, "rb") as f:
        return f.read(), arg


def agrees(mod, v):
    got, exp = mod.check_acceptance(v["case"]), v["expect"]
    return (
        got["result"] == exp["result"]
        and set(got.get("conditions") or []) == set(exp["conditions"])
        and all(got.get(k) == x for k, x in exp.items() if k not in ("result", "conditions"))
    )


def run(src, V):
    mod = types.ModuleType("checker_mut")
    mod.__file__ = os.path.join(ROOT, "checker.py")
    exec(compile(src, "checker_mut", "exec"), mod.__dict__)
    return [i for i, v in V.items() if not agrees(mod, v)]


M=[
("equal-instant counts as precedes","elif accepted_at < outcome_at:","elif accepted_at <= outcome_at:"),
("timestamp fraction 1-9 digits",r'\.[0-9]{3}Z")',r'\.[0-9]{1,9}Z")'),
("no canonical base64url re-encode check",'    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:\n        raise ValueError("non-canonical base64url: non-zero trailing bits")\n',''),
("no len%4==1 check","or len(s) % 4 == 1:",":"),
("unusable first key: skip and try next",'            if len(raw) != 32 or is_small_order(raw) or is_mixed_order(raw):\n                return None','            if len(raw) != 32 or is_small_order(raw) or is_mixed_order(raw):\n                continue'),
("last duplicate kid decides","    for key in keys:","    for key in reversed(keys):"),
("kty/crv not checked",' and key.get("kty") == "OKP" and key.get("crv") == "Ed25519"',''),
("completeness: truthy, not JSON true",'case.get("trust_material_complete") is True','bool(case.get("trust_material_complete"))'),
("sha256 hex: uppercase allowed",'re.compile(r"[0-9a-f]{64}")','re.compile(r"[0-9a-fA-F]{64}")'),
("signer-is-issuer (i) same key bytes dropped","        if issuer_pubkey is not None and issuer_pubkey == pubkey:\n            signer_is_issuer = True","        if False:\n            signer_is_issuer = True"),
("signer-is-issuer (ii) dropped","        if confirming_party is not None and confirming_party == issuer:\n            signer_is_issuer = True","        if False:\n            signer_is_issuer = True"),
("signer-is-issuer (iii) dropped","        if kid in (delegation.get(issuer) or []):\n            signer_is_issuer = True","        if False:\n            signer_is_issuer = True"),
("issuer check by kid string, not key bytes","issuer_pubkey is not None and issuer_pubkey == pubkey","issuer_kid == kid"),
("JCS ensure_ascii=True","ensure_ascii=False).encode","ensure_ascii=True).encode"),
("record digest computed even when ill-typed","    elif record_well_typed:\n","    else:\n"),
("unknown reports no disposition",'            disposition=reported_disposition,\n            conditions={"acceptance_authority_unresolved"}','            disposition=None,\n            conditions={"acceptance_authority_unresolved"}'),
("alg not checked",'protected.get("alg") != "EdDSA" or not isinstance(kid, str)','not isinstance(kid, str)'),
("confirming_party trimmed",'return v if isinstance(v, str) and v else None','return v if isinstance(v, str) and v.strip() else None'),
("version: absent accepted",'if payload.get("acceptance_version") != ACCEPTANCE_VERSION:','if payload.get("acceptance_version", ACCEPTANCE_VERSION) != ACCEPTANCE_VERSION:'),
("small-order key accepted in trust material","or is_small_order(raw) or is_mixed_order(raw):\n                return None","or is_mixed_order(raw):\n                return None"),
("mixed-order key accepted in trust material","or is_small_order(raw) or is_mixed_order(raw):\n                return None","or is_small_order(raw):\n                return None"),
("checker's own small/mixed R checks removed (verify() still refuses)","            and not is_small_order(signature_bytes[:32])  # a small-order R is signature_invalid\n            and not is_mixed_order(signature_bytes[:32])  # so is a mixed-order R (sentence 9)\n",""),
("payload must be object: not checked","    if not isinstance(payload, dict):\n        return invalid()\n\n    # --- Malformed","    if not isinstance(payload, dict):\n        payload = {}\n\n    # --- Malformed"),
("non-dict accepted_record not normalised",'accepted_record = case.get("accepted_record") or {}','accepted_record = case.get("accepted_record")'),
("delegation entry: substring match if a string","        if kid in (delegation.get(issuer) or []):","        if kid in str(delegation.get(issuer) or ''):"),
("authority: kid matched as substring",'kid not in (delegation.get(confirming_party) or [])','kid not in str(delegation.get(confirming_party) or "")'),
("policy_refusal emitted as False when incomplete","policy_refusal=True if trust_material_complete else None","policy_refusal=trust_material_complete"),
("disposition: not_responded accepted as signed value","disposition_valid = disposition_raw in VALID_DISPOSITIONS","disposition_valid = disposition_raw in VALID_DISPOSITIONS or disposition_raw == 'not_responded'"),
]


def main(argv):
    data, where = load(argv)
    V = {v["id"]: v for v in json.loads(data)["vectors"]}
    src = open(os.path.join(ROOT, "checker.py")).read()
    print(f"vectors: {len(V)} from {where}")
    base = run(src, V)
    if base:
        sys.exit(f"ABORT: unmutated checker disagrees on {base}")
    print(f"unmutated checker: {len(V)}/{len(V)} agree\n")
    survivors = []
    for name, old, new in M:
        if src.count(old) != 1:
            sys.exit(f"ABORT: mutation pattern not found exactly once: {name}")
        try:
            bad = run(src.replace(old, new, 1), V)
        except Exception as e:
            bad = ["EXC " + repr(e)[:60]]
        print(("KILLED  " if bad else "SURVIVED"), name)
        if not bad:
            survivors.append(name)
    print(f"\nsurvivors: {len(survivors)} of {len(M)}")


if __name__ == "__main__":
    main(sys.argv)
