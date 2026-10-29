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
# 1.4.2 stated times: RFC 3339 UTC, YYYY-MM-DDTHH:MM:SS[.fff]Z, real calendar fields.
_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{3}))?Z$")
_B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


def parse_iso(text):
    m = _ISO.match(text) if isinstance(text, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    ms = int(m.group(7) or "0")
    try:
        return datetime.datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _b64(value):
    """Canonical base64 only (1.4.2): standard alphabet, '=' padding to a
    multiple of four, no whitespace, and re-encoding gives the input."""
    if not isinstance(value, str) or not _B64.match(value):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw).decode("ascii") == value else None


def _imprint_matches(token, digest):
    return token is not None and token.imprint_oid == SHA256_OID and token.imprint == digest


class _Keys:
    """The key list, read once. A key_id listed more than once is rejected,
    whichever entry comes first; an entry that is not canonical base64 is
    rejected; keys are compared as decoded bytes."""

    def __init__(self, keys_doc):
        self.count, self.raw = {}, {}
        for k in (keys_doc or {}).get("keys", []):
            kid = k.get("key_id")
            self.count[kid] = self.count.get(kid, 0) + 1
            if k.get("alg") == "Ed25519" and kid not in self.raw:
                self.raw[kid] = k.get("public_key_base64")

    def listed(self, kid):
        return self.count.get(kid, 0)

    def repeated(self):
        return any(n > 1 for n in self.count.values())

    def rejected(self, kid):
        """A stated key that is repeated or is not canonical base64."""
        if self.listed(kid) > 1:
            return True
        return kid in self.raw and _b64(self.raw[kid]) is None

    def key(self, kid):
        if self.listed(kid) != 1 or kid not in self.raw:
            return None
        return _b64(self.raw[kid])


# --------------------------------------------------------------- types
def _str_or_none(v):
    return v is None or isinstance(v, str)


def _types_ok(inputs, receipt, envelope):
    """1.4.2: a record or input of another type than the specification gives
    is refused as an unsupported schema, and never makes the checker fail."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("signature", {}), dict):
        return False
    sig = envelope.get("signature", {})
    if not _str_or_none(sig.get("key_id")) or not _str_or_none(sig.get("value")):
        return False
    for f in ("key_id", "issued_utc", "verdict", "independence"):
        if not _str_or_none(receipt.get(f)):
            return False
    parties = receipt.get("parties", {})
    if not isinstance(parties, dict):
        return False
    for role in ("producer", "checker"):
        p = parties.get(role, {})
        if not isinstance(p, dict) or not _str_or_none(p.get("name")) or not _str_or_none(p.get("key_id")):
            return False
    criteria = receipt.get("criteria", {})
    if not isinstance(criteria, dict) or not _str_or_none(criteria.get("sha256")) \
            or not _str_or_none(criteria.get("committed_at")):
        return False
    results = receipt.get("results", [])
    if not isinstance(results, list):
        return False
    for r in results:
        if not isinstance(r, dict) or not _str_or_none(r.get("id")):
            return False
    keys = inputs.get("keys", {})
    if keys is not None:
        if not isinstance(keys, dict) or not isinstance(keys.get("keys", []), list):
            return False
        for k in keys.get("keys", []):
            if not isinstance(k, dict) or not _str_or_none(k.get("key_id")) \
                    or not _str_or_none(k.get("public_key_base64")) or not _str_or_none(k.get("alg")):
                return False
    for f in ("criteria_file_base64", "criteria_tsr_base64", "receipt_tsr_base64"):
        if not _str_or_none(inputs.get(f)):
            return False
    roots = inputs.get("tsa_roots_base64")
    if roots is not None and (not isinstance(roots, list) or not all(isinstance(r, str) for r in roots)):
        return False
    return True


# ----------------------------------------------------------- the check
def check(inputs):
    envelope = inputs.get("receipt")
    receipt = envelope.get("receipt") if isinstance(envelope, dict) else None
    if (not isinstance(receipt, dict) or receipt.get("schema") != SCHEMA
            or receipt.get("canonicalization") != CANONICALIZATION or receipt.get("suite") != SUITE):
        return dict(REFUSED)
    if not _types_ok(inputs, receipt, envelope):
        return dict(REFUSED)

    problems, warnings = set(), set()
    canonical = jcs_bytes(receipt)
    receipt_digest = hashlib.sha256(canonical).digest()
    keys = _Keys(inputs.get("keys"))
    if keys.repeated():
        problems.add("KEY_REJECTED")

    # step 2: the signature, under the key the signed key_id names
    signature = envelope.get("signature") or {}
    key_id = receipt.get("key_id")
    parties = receipt.get("parties") or {}
    checker = parties.get("checker") or {}
    producer = parties.get("producer") or {}
    signature_valid = False
    if signature.get("key_id") != key_id or not isinstance(key_id, str) or keys.listed(key_id) == 0 \
            or key_id not in keys.raw:
        problems.add("SIGNATURE_INVALID")
    elif keys.rejected(key_id):
        problems.add("KEY_REJECTED")
    else:
        pub = keys.key(key_id)
        if not C.ed_key_ok(pub):
            problems.add("KEY_REJECTED")
        else:
            sig = _b64(signature.get("value"))
            signature_valid = sig is not None and C.ed_verify(pub, canonical, sig)
            if not signature_valid:
                problems.add("SIGNATURE_INVALID")
    if checker.get("key_id") != key_id:
        problems.add("CHECKER_NOT_SIGNER")

    # parties, independence: by key when a key_id is stated
    producer_key_id = producer.get("key_id")
    checker_key_id = checker.get("key_id")
    key_collision, key_rejected_party = False, False
    for kid in (producer_key_id, checker_key_id):
        if isinstance(kid, str) and kid and keys.rejected(kid):
            key_rejected_party = True
            problems.add("KEY_REJECTED")
    if producer_key_id is not None and not key_rejected_party:
        if producer_key_id == checker_key_id:
            key_collision = True
        else:
            a, b = keys.key(producer_key_id), keys.key(checker_key_id)
            key_collision = a is not None and a == b
    if key_collision:
        problems.add("KEY_COLLISION")
    undeclared = not producer.get("name") and not producer_key_id
    if undeclared:
        warnings.add("PRODUCER_UNDECLARED")
    same_party = bool(producer.get("name")) and producer.get("name") == checker.get("name")
    derived = "self-checked" if (undeclared or same_party or key_collision or key_rejected_party) else "independent"
    stated = receipt.get("independence")
    if stated == "self-checked":
        warnings.add("SELF_CHECKED")
    if stated != derived:
        problems.add("INDEPENDENCE_INCONSISTENT")
    if stated == "independent":
        for party in (producer, checker):
            kid = party.get("key_id")
            if kid is not None and (not kid or keys.listed(kid) != 1):
                problems.add("INDEPENDENCE_INCONSISTENT")

    # step 4: the criteria document (a non-canonical file matches nothing)
    criteria = receipt.get("criteria") or {}
    results = receipt.get("results") or []
    criteria_file_text = inputs.get("criteria_file_base64")
    criteria_hash = "not_supplied"
    if criteria_file_text is not None:
        criteria_file = _b64(criteria_file_text)
        if criteria_file is not None and hashlib.sha256(criteria_file).hexdigest() == criteria.get("sha256"):
            criteria_hash = "match"
            if not _results_match(criteria_file, results):
                problems.add("CRITERIA_RESULTS_MISMATCH")
        else:
            criteria_hash = "mismatch"
            problems.add("CRITERIA_HASH_MISMATCH")

    # steps 5 and 6: timestamps
    criteria_digest = bytes.fromhex(criteria["sha256"]) if _is_hex64(criteria.get("sha256")) else None
    criteria_tsr_text = inputs.get("criteria_tsr_base64")
    receipt_tsr_text = inputs.get("receipt_tsr_base64")
    criteria_token_raw = _b64(criteria_tsr_text) if criteria_tsr_text else None
    receipt_token_raw = _b64(receipt_tsr_text) if receipt_tsr_text else None
    criteria_token = T.parse_response(criteria_token_raw) if criteria_token_raw else None
    receipt_token = T.parse_response(receipt_token_raw) if receipt_token_raw else None

    receipt_timestamp = "none"
    if receipt_tsr_text:
        receipt_timestamp = "imprint_match" if _imprint_matches(receipt_token, receipt_digest) else "imprint_mismatch"

    issued = parse_iso(receipt.get("issued_utc"))
    unreadable = issued is None
    reference = issued
    if receipt_timestamp == "imprint_match" and issued is not None and receipt_token.gen_time is not None:
        reference = min(issued, receipt_token.gen_time.floor_ms())

    committed_text = criteria.get("committed_at")
    committed_at = parse_iso(committed_text)
    commitment = None
    usable_token = False
    if criteria_tsr_text:
        if criteria_digest is not None and _imprint_matches(criteria_token, criteria_digest):
            if criteria_token.gen_time is not None:
                usable_token = True
                gt = criteria_token.gen_time
                if committed_at is None or committed_at.replace(microsecond=0) != gt.floor_s():
                    problems.add("CRITERIA_TIME_MISMATCH")
                commitment = gt.ceil_ms() + criteria_token.accuracy
            else:
                warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
        else:
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
            warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    else:
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    if not usable_token:
        commitment = committed_at
        if committed_at is None and committed_text is not None:
            unreadable = True
    if unreadable:
        problems.add("RECEIPT_TIME_UNREADABLE")
        before = False
    else:
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
    if criteria_tsr_text:
        tsa["criteria"] = T.tsa_signature(criteria_token, anchors) if criteria_token_raw else _no_bytes(anchors)
    if receipt_tsr_text:
        tsa["receipt"] = T.tsa_signature(receipt_token, anchors) if receipt_token_raw else _no_bytes(anchors)
    if tsa:
        outcome["tsa_signature"] = tsa
    return outcome


def _no_bytes(anchors):
    """A token that is not canonical base64 decodes to no bytes: nothing to
    evaluate without anchors, a malformed token with them."""
    return "failed" if anchors else "not_evaluated"


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
