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
                       Includes signature_invalid, as the ONLY condition: kid
                       resolved, but the Ed25519 check failed (key_step records it).
    key_unresolved  -- no usable, non-small-order key for the kid in trust_material. exit 2
    unknown         -- acceptance_authority_unresolved, and nothing else malformed.  exit 2
    no_record       -- no acceptance object was supplied at all.                     exit 2
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime

from ed25519_verify import (
    IDENTITY,
    Ed25519VerifyError,
    _decode_point,
    _point_equal,
    _point_mul,
    verify as ed25519_verify_raw,
)

ACCEPTANCE_VERSION = "acceptance-record-v0"
VALID_DISPOSITIONS = ("accepted", "rejected", "disputed")

MALFORMED_CONDITIONS = (
    "confirming_party_absent",
    "acceptance_signer_is_issuer",
    "acceptance_terms_digest_mismatch",
    "acceptance_outcome_digest_mismatch",
    "acceptance_precedes_outcome",
    "acceptance_record_digest_mismatch",
    "acceptance_member_invalid",
    "signature_invalid",
)


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def _b64url_decode(s: str) -> bytes:
    """Base64url without padding (RFC 7515 section 2), strictly. The
    stdlib decoder silently drops characters outside the alphabet and
    accepts '=' padding, so the alphabet and the length are checked
    here; ValueError otherwise."""
    if not _B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _sha256_hex(value) -> str | None:
    """`value` if it is a well-typed *_sha256 member (exactly 64 lowercase
    hex characters), else None."""
    return value if isinstance(value, str) and _SHA256_HEX.fullmatch(value) else None


_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


def _parse_timestamp(value) -> datetime | None:
    """The -03 5.3.2 form exactly: YYYY-MM-DDTHH:MM:SS.mmmZ, UTC, three
    fractional digits. Any other spelling -- RFC 3339 without the
    fraction, with an offset (even one naming the same instant), lower
    case, a space for the T -- is ill-typed and returns None, so
    ordering is only ever compared between two values of this form.
    Returned naive: every accepted value is UTC."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:  # right shape, not a real date/time (month 13, hour 24, ...)
        return None


def _jcs_bytes(obj) -> bytes:
    """A JCS (RFC 8785) serialization sufficient for this spec's
    records: they are flat objects of string members only, no numbers
    or floats whose exact ECMAScript formatting JCS otherwise has
    strict rules for. Recursive key sorting + compact separators +
    non-ASCII left unescaped (ensure_ascii=False) matches JCS for this
    shape; this is NOT a general-purpose JCS implementation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_small_order(raw: bytes) -> bool:
    """True if `raw` encodes one of the 8 points whose order divides 8
    (the identity among them). Under such a key, or such an R, one
    signature verifies for every message, so it binds nobody; RFC 8032
    does not require refusing them, this checker does. A string that is
    not a curve point at all is not "small order" -- verification
    rejects it separately."""
    try:
        point = _decode_point(raw)
    except ValueError:
        return False
    return _point_equal(_point_mul(8, point), IDENTITY)


def _find_key(trust_material: dict, kid) -> bytes | None:
    """The trust-material key for `kid`, or None if there is no usable
    one. The FIRST Ed25519 entry (kty OKP, crv Ed25519) carrying that
    kid decides: if it is unusable (bad base64url, not 32 bytes, small
    order) the kid is unresolved, and a later duplicate does not
    rescue it."""
    if not isinstance(trust_material, dict):
        return None
    keys = trust_material.get("keys")
    if not isinstance(keys, list):
        return None
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == kid and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
            x = key.get("x")
            if not isinstance(x, str):
                return None
            try:
                raw = _b64url_decode(x)
            except ValueError:
                return None
            if len(raw) != 32 or _is_small_order(raw):
                return None
            return raw
    return None


def _result(
    result: str, *, exit_code: int, disposition=None, conditions=None, policy_refusal=None, key_step=None
) -> dict:
    out = {
        "result": result,
        "exit_code": exit_code,
        "disposition": disposition,
        "conditions": sorted(conditions) if conditions is not None else [],
    }
    if policy_refusal is not None:
        out["policy_refusal"] = policy_refusal
    if key_step is not None:
        out["key_step"] = key_step
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
    # A declaration only as the JSON value true; "true", 1, etc. are not
    # one (-03 5.4.2: omitting the input is not a declaration either).
    trust_material_complete = case.get("trust_material_complete") is True

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

    # --- Envelope, before the key step: all three members are base64url
    # without padding, and the protected header decodes to a JSON object.
    # The payload's *content* is not looked at yet: the key step needs
    # only the header's kid, and the payload is not trusted until the
    # signature over it has been checked. ---
    invalid = lambda: _result(  # noqa: E731
        "malformed", exit_code=1, disposition=None, conditions=["acceptance_member_invalid"]
    )
    try:
        protected = json.loads(_b64url_decode(protected_b64))
        payload_bytes = _b64url_decode(payload_b64)
        signature_bytes = _b64url_decode(signature_b64)
    except (ValueError, RecursionError):  # ValueError covers JSONDecodeError, UnicodeDecodeError
        return invalid()

    if not isinstance(protected, dict):
        return invalid()

    kid = protected.get("kid")
    if protected.get("alg") != "EdDSA" or not isinstance(kid, str):
        # Found before the key step: with no usable kid there is nothing
        # to look up, so this is not key_unresolved.
        return invalid()

    # --- Key step (draft-krausz-verification-state-03 5.4.2), first and
    # evaluation-stopping on key_unresolved or signature_invalid. ---
    pubkey = _find_key(trust_material, kid)
    if pubkey is None:
        return _result(
            "key_unresolved",
            exit_code=2,
            disposition=None,
            policy_refusal=True if trust_material_complete else None,
            key_step="key_unresolved",
        )

    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    try:
        sig_ok = (
            len(signature_bytes) == 64
            and not _is_small_order(signature_bytes[:32])  # a small-order R is signature_invalid
            and ed25519_verify_raw(pubkey, signing_input, signature_bytes)
        )
    except Ed25519VerifyError:
        sig_ok = False
    if not sig_ok:
        # A confirmed finding, not "no check ran": it surfaces as
        # malformed with signature_invalid as the only condition.
        return _result(
            "malformed",
            exit_code=1,
            disposition=None,
            conditions=["signature_invalid"],
            key_step="signature_invalid",
        )

    # --- Payload, now that the signature over it is genuine. ---
    try:
        payload = json.loads(payload_bytes)
    except (ValueError, RecursionError):
        return invalid()
    if not isinstance(payload, dict):
        return invalid()

    # --- Malformed conditions (report-all). ---
    conditions: set[str] = set()

    def _str_field(obj, name):
        v = obj.get(name) if isinstance(obj, dict) else None
        return v if isinstance(v, str) and v else None

    # Required, and exactly this string: absent, not a string, or any
    # other value is malformed (not "unknown": a different version is
    # not a limit of the verifier, it is not this record format).
    if payload.get("acceptance_version") != ACCEPTANCE_VERSION:
        conditions.add("acceptance_member_invalid")

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

    # Type-check suppression: an ill-typed member raises
    # acceptance_member_invalid only, never the mismatch that depends on
    # it. A *_sha256 member is well-typed iff it is exactly 64 lowercase
    # hex characters (-03 5.3.2), not merely any non-empty string.
    payload_terms = _sha256_hex(payload.get("terms_sha256"))
    record_terms = _sha256_hex(accepted_record.get("terms_sha256") if isinstance(accepted_record, dict) else None)
    if payload_terms is None or record_terms is None:
        conditions.add("acceptance_member_invalid")
    elif payload_terms != record_terms:
        conditions.add("acceptance_terms_digest_mismatch")

    payload_outcome = _sha256_hex(payload.get("outcome_sha256"))
    record_outcome = _sha256_hex(accepted_record.get("outcome_sha256") if isinstance(accepted_record, dict) else None)
    if payload_outcome is None or record_outcome is None:
        conditions.add("acceptance_member_invalid")
    elif payload_outcome != record_outcome:
        conditions.add("acceptance_outcome_digest_mismatch")

    accepted_at = _parse_timestamp(payload.get("accepted_at"))
    outcome_at = _parse_timestamp(accepted_record.get("outcome_at") if isinstance(accepted_record, dict) else None)
    if accepted_at is None or outcome_at is None:
        conditions.add("acceptance_member_invalid")
    elif accepted_at < outcome_at:
        # Strict: equal-instant is NOT "precedes" (spec: "An acceptance
        # at the outcome's own instant does not precede it").
        conditions.add("acceptance_precedes_outcome")

    issuer = _str_field(accepted_record, "issuer")
    issuer_kid = _str_field(accepted_record, "issuer_kid")

    # The record digest depends on the supplied record being well-typed
    # throughout; if any member the checker reads from it is ill-typed
    # (raised above or below), that is the only finding, not a digest
    # mismatch over a record that is not one.
    record_well_typed = (
        isinstance(accepted_record, dict)
        and None not in (record_terms, record_outcome, outcome_at, issuer, issuer_kid)
    )
    payload_record_digest = _sha256_hex(payload.get("accepted_record_sha256"))
    if payload_record_digest is None:
        conditions.add("acceptance_member_invalid")
    elif record_well_typed:
        computed = hashlib.sha256(_jcs_bytes(accepted_record)).hexdigest()
        if computed != payload_record_digest:
            conditions.add("acceptance_record_digest_mismatch")

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
        # The disposition is reported only where a signed, well-formed
        # record exists to report it from (verified, unknown); it is null
        # on malformed, however parseable the member itself was.
        return _result("malformed", exit_code=1, disposition=None, conditions=conditions)

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
