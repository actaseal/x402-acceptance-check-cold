"""Clean-room checker for the work-acceptance record, draft profile 1.4.1
(schema trilatic.acceptance-receipt/1.2), written from the README at
maximusrufus/work-acceptance-record@bc5a138 and its vectors only.
Standard library only, no network, no clock.

    python -I wa_check.py vectors/*.json          # prints the outcome object per file
"""
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops it

import wa_crypto as C  # noqa: E402
import wa_tsa as T  # noqa: E402

SCHEMA = "trilatic.acceptance-receipt/1.2"
CANONICALIZATION = "JCS-RFC8785"
SUITE = {"digest": "sha-256", "signature": "Ed25519"}
SHA256_OID = "2.16.840.1.101.3.4.2.1"
VOCABULARY = ("pass", "fail", "not-evaluated", "error")
REFUSED = {"refused": True, "reason": "unknown schema, canonicalization or suite"}


# ------------------------------------------------------------ RFC 8785
def es_number(x):
    """ECMAScript Number::toString of a double (RFC 8785 section 3.2.2.3)."""
    x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("not a JSON number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    text = repr(abs(x))
    mantissa, _, exp = text.partition("e")
    exp = int(exp) if exp else 0
    whole, _, frac = mantissa.partition(".")
    all_digits = whole + frac
    lead = len(all_digits) - len(all_digits.lstrip("0"))
    digits = all_digits.lstrip("0").rstrip("0")
    k = len(digits)
    n = len(whole) + exp - lead
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + body


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return es_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError(type(value))


def jcs_bytes(value):
    return jcs(value).encode("utf-8")


# ------------------------------------------------------------- helpers
_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?Z$")


def parse_iso(text):
    m = _ISO.match(text) if isinstance(text, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    frac = int((m.group(7) or "0").ljust(6, "0"))
    try:
        return datetime.datetime(y, mo, d, h, mi, s, frac, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _b64(value):
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def _imprint_matches(token, digest):
    return token is not None and token.imprint_oid == SHA256_OID and token.imprint == digest


def _find_key(keys_doc, key_id):
    for k in (keys_doc or {}).get("keys", []):
        if isinstance(k, dict) and k.get("key_id") == key_id and k.get("alg") == "Ed25519":
            return _b64(k.get("public_key_base64"))
    return None


# ----------------------------------------------------------- the check
def check(inputs):
    envelope = inputs.get("receipt")
    receipt = envelope.get("receipt") if isinstance(envelope, dict) else None
    if (not isinstance(receipt, dict) or receipt.get("schema") != SCHEMA
            or receipt.get("canonicalization") != CANONICALIZATION or receipt.get("suite") != SUITE):
        return dict(REFUSED)

    problems, warnings = set(), set()
    canonical = jcs_bytes(receipt)
    receipt_digest = hashlib.sha256(canonical).digest()

    # step 2: the signature, and whose key it is
    signature = envelope.get("signature") or {}
    key_id = receipt.get("key_id")
    parties = receipt.get("parties") or {}
    checker = parties.get("checker") or {}
    producer = parties.get("producer") or {}
    signature_valid = False
    pub = _find_key(inputs.get("keys"), key_id) if isinstance(key_id, str) else None
    if signature.get("key_id") != key_id or pub is None:
        problems.add("SIGNATURE_INVALID")
    elif not C.ed_key_ok(pub):
        problems.add("KEY_REJECTED")
    else:
        sig = _b64(signature.get("value"))
        signature_valid = sig is not None and C.ed_verify(pub, canonical, sig)
        if not signature_valid:
            problems.add("SIGNATURE_INVALID")
    if checker.get("key_id") != key_id:
        problems.add("CHECKER_NOT_SIGNER")

    # parties, independence
    producer_key_id = producer.get("key_id")
    key_collision = False
    if producer_key_id is not None:
        if producer_key_id == checker.get("key_id"):
            key_collision = True
        else:
            a = _find_key(inputs.get("keys"), producer_key_id)
            b = _find_key(inputs.get("keys"), checker.get("key_id"))
            key_collision = a is not None and a == b
    if key_collision:
        problems.add("KEY_COLLISION")
    undeclared = not producer.get("name") and not producer_key_id
    if undeclared:
        warnings.add("PRODUCER_UNDECLARED")
    same_party = bool(producer.get("name")) and producer.get("name") == checker.get("name")
    derived = "self-checked" if (undeclared or same_party or key_collision) else "independent"
    stated = receipt.get("independence")
    if stated == "self-checked":
        warnings.add("SELF_CHECKED")
    if stated != derived:
        problems.add("INDEPENDENCE_INCONSISTENT")

    # step 4: the criteria document
    criteria = receipt.get("criteria") or {}
    results = receipt.get("results") or []
    criteria_file = _b64(inputs.get("criteria_file_base64"))
    criteria_hash = "not_supplied"
    if criteria_file is not None:
        if hashlib.sha256(criteria_file).hexdigest() == criteria.get("sha256"):
            criteria_hash = "match"
            if not _results_match(criteria_file, results):
                problems.add("CRITERIA_RESULTS_MISMATCH")
        else:
            criteria_hash = "mismatch"
            problems.add("CRITERIA_HASH_MISMATCH")

    # steps 5 and 6: timestamps
    criteria_digest = bytes.fromhex(criteria["sha256"]) if _is_hex64(criteria.get("sha256")) else None
    criteria_token_raw = _b64(inputs.get("criteria_tsr_base64"))
    receipt_token_raw = _b64(inputs.get("receipt_tsr_base64"))
    criteria_token = T.parse_response(criteria_token_raw) if criteria_token_raw else None
    receipt_token = T.parse_response(receipt_token_raw) if receipt_token_raw else None

    receipt_timestamp = "none"
    if receipt_token_raw:
        receipt_timestamp = "imprint_match" if _imprint_matches(receipt_token, receipt_digest) else "imprint_mismatch"

    issued = parse_iso(receipt.get("issued_utc"))
    reference = issued
    if receipt_timestamp == "imprint_match" and issued is not None:
        reference = min(issued, receipt_token.gen_time)

    committed_at = parse_iso(criteria.get("committed_at"))
    commitment = committed_at
    if criteria_token_raw:
        if criteria_digest is not None and _imprint_matches(criteria_token, criteria_digest):
            if committed_at != criteria_token.gen_time:
                problems.add("CRITERIA_TIME_MISMATCH")
            commitment = criteria_token.gen_time + criteria_token.accuracy
        else:
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
            warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    else:
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    before = commitment is not None and reference is not None and commitment < reference
    if not before:
        problems.add("CRITERIA_COMMITTED_AFTER_CHECK")

    # step 7: the verdict
    recomputed = _verdict(results)
    if any(not isinstance(r, dict) or r.get("result") not in VOCABULARY for r in results):
        problems.add("RESULT_VOCABULARY")
    if receipt.get("verdict") != recomputed:
        problems.add("VERDICT_MISMATCH")

    outcome = {
        "criteria_committed_before_check": "yes" if before else "no",
        "criteria_hash": criteria_hash,
        "independence": stated,
        "problem_codes": sorted(problems),
        "receipt_timestamp": receipt_timestamp,
        "signature_valid": signature_valid,
        "verdict_recomputed": recomputed,
        "verdict_stated": receipt.get("verdict"),
        "warning_codes": sorted(warnings),
    }

    # step 9: the authority signature, reported separately
    anchors = T.decode_anchors(inputs.get("tsa_roots_base64"))
    tsa = {}
    if criteria_token_raw:
        tsa["criteria"] = T.tsa_signature(criteria_token, anchors)
    if receipt_token_raw:
        tsa["receipt"] = T.tsa_signature(receipt_token, anchors)
    if tsa:
        outcome["tsa_signature"] = tsa
    return outcome


def _is_hex64(text):
    return isinstance(text, str) and re.fullmatch(r"[0-9a-f]{64}", text) is not None


def _verdict(results):
    required = [r for r in results if isinstance(r, dict) and r.get("required") is True]
    values = [r.get("result") for r in required]
    if "fail" in values:
        return "fail"
    if any(v != "pass" for v in values):
        return "incomplete"
    return "pass"


def _results_match(criteria_file, results):
    try:
        doc = json.loads(criteria_file)
        want = {c["id"]: c["required"] for c in doc["criteria"]}
        have = {}
        for r in results:
            if r["id"] in have:
                return False
            have[r["id"]] = r["required"]
    except (ValueError, KeyError, TypeError):
        return False
    return want == have


def main(argv):
    status = 0
    for path in argv[1:]:
        with open(path, encoding="utf-8") as fh:
            vector = json.load(fh)
        print(path, json.dumps(check(vector["inputs"]), sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
