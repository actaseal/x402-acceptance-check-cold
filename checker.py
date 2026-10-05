"""Independent, from-scratch implementation of the x402-foundation
acceptance-record conditions (x402-foundation/tsc#4, 2026-10-04),
keyed per draft-krausz-verification-state-03 section 5.4.2 for the
confirming party's key handling (key_unresolved vs signature_invalid,
with a relying-party trust-material-completeness input).

Written from the specification only (the condition names and
semantics as given, plus the public spec prose at
x402run/pgc/examples/acceptance-record-cold/README.md -- itself a
description of the GitHub issue, not the checker's source). This file
does not import, read, or compare itself against
x402run/pgc/tools/acceptance_record_check.py or any other checker
implementation. Stdlib only; Ed25519 verification is this repo's own
ed25519_verify.py (RFC 8032, written independently, see that file's
docstring).

An "acceptance" is a flattened-JWS-shaped object:
    {"protected": "<base64url JSON header, {'alg':'EdDSA','kid':...}>",
     "payload":   "<base64url JSON payload>",
     "signature": "<base64url raw Ed25519 signature>"}
The JWS signing input (RFC 7515) is the ASCII bytes of
BASE64URL(protected) + "." + BASE64URL(payload) -- the encoded
strings themselves, not the decoded JSON.

Payload fields (as observed in the vector inputs, assumed required
unless noted): acceptance_version, accepted_at, accepted_record_sha256,
confirming_party, disposition, outcome_sha256, terms_sha256.

`accepted_record` (supplied separately by the relying party, per the
spec's A4 note -- its own signature is a different, upstream
verification step, not this one): issuer, issuer_kid, outcome_at,
outcome_sha256, record_id, terms_sha256.

`trust_material`: {"keys": [{"kty":"OKP","crv":"Ed25519","kid":...,
"x": "<base64url 32-byte public key>"}, ...]}.

`delegation`: {"<did>": ["<kid>", ...]} -- which signing kids a given
party identity is authorized to sign under.

`trust_material_complete`: bool, the relying party's own declaration
(see verify-state-03 5.4.2(b)) -- never read from the acceptance
itself.

Result tokens (this implementation's reading, documented inline at
each branch since parts of this are genuinely underdetermined by the
prose spec alone -- see REPORT.md for where a second reading is
possible):
    verified        -- key step passed, no malformed condition, authority resolves.  exit 0
    malformed       -- one or more malformed conditions (report-all).                exit 1
    key_unresolved  -- confirming party's kid is not in trust_material.              exit 2
    signature_invalid -- kid resolved, but the Ed25519 check failed.                 exit 2
    unknown         -- acceptance_authority_unresolved, and nothing else malformed.  exit 2
    no_record       -- no acceptance object was supplied at all.                     exit 2
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from ed25519_verify import Ed25519VerifyError, verify as ed25519_verify_raw

VALID_DISPOSITIONS = ("accepted", "rejected", "disputed")

MALFORMED_CONDITIONS = (
    "confirming_party_absent",
    "acceptance_signer_is_issuer",
    "acceptance_terms_digest_mismatch",
    "acceptance_outcome_digest_mismatch",
    "acceptance_precedes_outcome",
    "acceptance_record_digest_mismatch",
    "acceptance_member_invalid",
)


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _parse_iso8601(value: str) -> datetime:
    # Vectors use "...Z" suffix; datetime.fromisoformat before 3.11
    # doesn't accept a bare "Z", so normalize it to "+00:00" ourselves
    # rather than require a specific Python minor version.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _jcs_bytes(obj) -> bytes:
    """A JCS (RFC 8785) serialization sufficient for this spec's
    records: they are flat objects of string members only, no numbers
    or floats whose exact ECMAScript formatting JCS otherwise has
    strict rules for. Recursive key sorting + compact separators +
    non-ASCII left unescaped (ensure_ascii=False) matches JCS for this
    shape; this is NOT a general-purpose JCS implementation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _find_key(trust_material: dict, kid) -> bytes | None:
    if not isinstance(trust_material, dict):
        return None
    for key in trust_material.get("keys") or []:
        if not isinstance(key, dict):
            continue
        if key.get("kid") == kid and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
            x = key.get("x")
            if not isinstance(x, str):
                continue
            try:
                raw = _b64url_decode(x)
            except Exception:
                continue
            if len(raw) == 32:
                return raw
    return None


def _result(result: str, *, exit_code: int, disposition=None, conditions=None, policy_refusal=None) -> dict:
    out = {
        "result": result,
        "exit_code": exit_code,
        "disposition": disposition,
        "conditions": sorted(conditions) if conditions is not None else [],
    }
    if policy_refusal is not None:
        out["policy_refusal"] = policy_refusal
    return out


def check_acceptance(case: dict) -> dict:
    """`case` is the vector's "case" object: {"acceptance": ..|None,
    "accepted_record": ..., "delegation": ..., "trust_material": ...,
    "trust_material_complete": bool}. Returns a result dict per the
    module docstring's token table."""
    acceptance = case.get("acceptance")
    accepted_record = case.get("accepted_record") or {}
    delegation = case.get("delegation") or {}
    trust_material = case.get("trust_material") or {}
    trust_material_complete = bool(case.get("trust_material_complete", False))

    if acceptance is None:
        return _result("no_record", exit_code=2, disposition="not_responded")

    if not isinstance(acceptance, dict):
        return _result(
            "malformed", exit_code=1, disposition=None, conditions=["acceptance_member_invalid"]
        )

    protected_b64 = acceptance.get("protected")
    payload_b64 = acceptance.get("payload")
    signature_b64 = acceptance.get("signature")
    if not all(isinstance(v, str) for v in (protected_b64, payload_b64, signature_b64)):
        return _result(
            "malformed", exit_code=1, disposition=None, conditions=["acceptance_member_invalid"]
        )

    try:
        protected = json.loads(_b64url_decode(protected_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature_bytes = _b64url_decode(signature_b64)
    except Exception:
        return _result(
            "malformed", exit_code=1, disposition=None, conditions=["acceptance_member_invalid"]
        )

    if not isinstance(protected, dict) or not isinstance(payload, dict):
        return _result(
            "malformed", exit_code=1, disposition=None, conditions=["acceptance_member_invalid"]
        )

    kid = protected.get("kid")

    # --- Key step (draft-krausz-verification-state-03 5.4.2), first and
    # evaluation-stopping on key_unresolved or signature_invalid. ---
    pubkey = _find_key(trust_material, kid)
    if pubkey is None:
        return _result("key_unresolved", exit_code=2, disposition=None, policy_refusal=trust_material_complete)

    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    try:
        sig_ok = len(signature_bytes) == 64 and ed25519_verify_raw(pubkey, signing_input, signature_bytes)
    except Ed25519VerifyError:
        sig_ok = False
    if not sig_ok:
        return _result("signature_invalid", exit_code=2, disposition=None)

    # --- Malformed conditions (report-all), only reached once the
    # signature itself is confirmed genuine. ---
    conditions: set[str] = set()

    def _str_field(obj, name):
        v = obj.get(name) if isinstance(obj, dict) else None
        return v if isinstance(v, str) and v else None

    confirming_party = _str_field(payload, "confirming_party")
    if confirming_party is None:
        conditions.add("confirming_party_absent")

    disposition_raw = payload.get("disposition")
    disposition_valid = disposition_raw in VALID_DISPOSITIONS
    if not disposition_valid:
        # A2: a signed "not_responded" (or anything outside the three
        # real dispositions) is self-contradictory, reported as an
        # invalid member, not trusted as the record's disposition.
        conditions.add("acceptance_member_invalid")

    payload_terms = _str_field(payload, "terms_sha256")
    record_terms = _str_field(accepted_record, "terms_sha256")
    if payload_terms is None or record_terms is None:
        conditions.add("acceptance_member_invalid")
    elif payload_terms != record_terms:
        conditions.add("acceptance_terms_digest_mismatch")

    payload_outcome = _str_field(payload, "outcome_sha256")
    record_outcome = _str_field(accepted_record, "outcome_sha256")
    if payload_outcome is None or record_outcome is None:
        conditions.add("acceptance_member_invalid")
    elif payload_outcome != record_outcome:
        conditions.add("acceptance_outcome_digest_mismatch")

    accepted_at_raw = _str_field(payload, "accepted_at")
    outcome_at_raw = _str_field(accepted_record, "outcome_at")
    accepted_at = outcome_at = None
    if accepted_at_raw is None or outcome_at_raw is None:
        conditions.add("acceptance_member_invalid")
    else:
        try:
            accepted_at = _parse_iso8601(accepted_at_raw)
            outcome_at = _parse_iso8601(outcome_at_raw)
        except ValueError:
            conditions.add("acceptance_member_invalid")
    if accepted_at is not None and outcome_at is not None and accepted_at < outcome_at:
        # Strict: equal-instant is NOT "precedes" (spec: "An acceptance
        # at the outcome's own instant does not precede it").
        conditions.add("acceptance_precedes_outcome")

    payload_record_digest = _str_field(payload, "accepted_record_sha256")
    if payload_record_digest is None:
        conditions.add("acceptance_member_invalid")
    elif not isinstance(accepted_record, dict) or not accepted_record:
        conditions.add("acceptance_member_invalid")
    else:
        computed = hashlib.sha256(_jcs_bytes(accepted_record)).hexdigest()
        if computed != payload_record_digest:
            conditions.add("acceptance_record_digest_mismatch")

    issuer = _str_field(accepted_record, "issuer")
    issuer_kid = _str_field(accepted_record, "issuer_kid")
    if issuer is None or issuer_kid is None:
        conditions.add("acceptance_member_invalid")
    else:
        issuer_pubkey = _find_key(trust_material, issuer_kid)
        signer_is_issuer = False
        if issuer_pubkey is not None and issuer_pubkey == pubkey:
            signer_is_issuer = True  # (i) same key bytes under a possibly different kid
        if confirming_party is not None and confirming_party == issuer:
            signer_is_issuer = True  # (ii) confirming_party literally is the issuer
        if kid in (delegation.get(issuer) or []):
            signer_is_issuer = True  # (iii) delegation binds this signing kid to the issuer
        if signer_is_issuer:
            conditions.add("acceptance_signer_is_issuer")

    reported_disposition = disposition_raw if disposition_valid else None

    if conditions:
        return _result("malformed", exit_code=1, disposition=reported_disposition, conditions=conditions)

    # --- Authority step, only reached when nothing above is malformed,
    # so "unknown" is never stacked on a malformed finding. ---
    if confirming_party is None or kid not in (delegation.get(confirming_party) or []):
        return _result(
            "unknown",
            exit_code=2,
            disposition=reported_disposition,
            conditions={"acceptance_authority_unresolved"},
        )

    return _result("verified", exit_code=0, disposition=reported_disposition, conditions=set())
