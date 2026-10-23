"""RFC 3161 time-stamp responses: the signed TSTInfo (imprint, genTime,
accuracy) and the authority-signature outcome (profile 1.4.1, step 9).
Standard library only, no network, no clock: every date is compared
with the token's genTime."""
import base64
import datetime
import hashlib

import wa_crypto as C
import wa_der as D

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ESS_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_ESS_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_EKU = "2.5.29.37"
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"

HASH_BY_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
SIG_ALG = {  # signature algorithm OID -> (family, hash or None for "use the digestAlgorithm")
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    OID_RSA_ENCRYPTION: ("rsa", None),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    OID_EC_PUBLIC_KEY: ("ecdsa", None),
    OID_RSA_PSS: ("pss", None),
}


class Token:
    """What a time-stamp response says in its signed TSTInfo, plus the
    parts of the CMS wrapper needed for the authority signature."""

    def __init__(self):
        self.imprint_oid = None
        self.imprint = None
        self.gen_time = None
        self.accuracy = datetime.timedelta(0)
        self.signed_data = None  # parsed CMS pieces, or None


def parse_response(der):
    """DER TimeStampResp (or a bare ContentInfo) -> Token, or None when it
    holds no readable TSTInfo. Only the signed TSTInfo is read; the
    PKIStatusInfo is never consulted for an imprint or a time."""
    try:
        top = D.parse_exact(der)
        parts = top.children()
        content_info = None
        for p in parts:
            if p.tag == D.SEQUENCE and p.children() and p.children()[0].tag == D.OID:
                content_info = p
        if content_info is None:
            return None
        kids = content_info.children()
        if D.as_oid(kids[0]) != OID_SIGNED_DATA or kids[1].tag != 0xA0:
            return None
        signed = D.parse_exact(kids[1].content)
        sd = signed.children()
        encap = sd[2]
        if encap.tag != D.SEQUENCE:
            return None
        encap_kids = encap.children()
        econtent_type = D.as_oid(encap_kids[0])
        if len(encap_kids) < 2 or encap_kids[1].tag != 0xA0:
            return None
        octets = D.parse_exact(encap_kids[1].content)
        D.expect(octets, D.OCTET_STRING)
        tst = D.parse_exact(octets.content).children()
        token = Token()
        mi = tst[2].children()
        token.imprint_oid = D.as_oid(mi[0].children()[0])
        token.imprint = D.expect(mi[1], D.OCTET_STRING).content
        token.gen_time = D.as_time(tst[4])
        if len(tst) > 5 and tst[5].tag == D.SEQUENCE:
            token.accuracy = _accuracy(tst[5])
        cert_set, signer_infos = None, []
        for extra in sd[3:]:
            if extra.tag == 0xA0:
                cert_set = extra.children()
            elif extra.tag == D.SET:
                signer_infos = extra.children()
        token.signed_data = dict(
            econtent_type=econtent_type, econtent=octets.content,
            certs=cert_set or [], signer_infos=signer_infos)
        return token
    except (D.DerError, IndexError, ValueError, UnicodeDecodeError):
        return None


def _accuracy(seq):
    seconds, millis, micros = 0, 0, 0
    for k in seq.children():
        if k.tag == D.UNIVERSAL_INTEGER:
            seconds = D.as_int(k)
        elif k.tag == 0x80:
            millis = int.from_bytes(k.content, "big")
        elif k.tag == 0x81:
            micros = int.from_bytes(k.content, "big")
    return datetime.timedelta(seconds=seconds, milliseconds=millis, microseconds=micros)


# -------------------------------------------------------------- X.509
class Cert:
    def __init__(self, der):
        node = D.parse_exact(der)
        self.der = der
        top = node.children()
        tbs = top[0]
        self.tbs_der = tbs.raw
        self.sig_alg = top[1]
        bits = D.expect(top[2], D.BIT_STRING).content
        if not bits or bits[0] != 0:
            raise D.DerError("bad signature bit string")
        self.signature = bits[1:]
        f = tbs.children()
        i = 0
        if f[0].tag == 0xA0:
            i = 1
        self.serial = D.as_int(f[i])
        self.issuer = f[i + 2].raw
        validity = f[i + 3].children()
        self.not_before = D.as_time(validity[0])
        self.not_after = D.as_time(validity[1])
        self.subject = f[i + 4].raw
        self.spki = f[i + 5]
        self.ca = False
        self.eku = None
        self.has_basic_constraints = False
        for part in f[i + 6:]:
            if part.tag == 0xA3:
                for ext in D.parse_exact(part.content).children():
                    ek = ext.children()
                    oid = D.as_oid(ek[0])
                    value = ek[-1]
                    inner = D.parse_exact(D.expect(value, D.OCTET_STRING).content)
                    if oid == OID_BASIC_CONSTRAINTS:
                        self.has_basic_constraints = True
                        for c in inner.children():
                            if c.tag == 0x01:
                                self.ca = c.content != b"\x00"
                    elif oid == OID_EKU:
                        self.eku = [D.as_oid(o) for o in inner.children()]

    def public_key(self):
        """('rsa', (n, e)) | ('ec', (curve_oid, point_bytes)) | ('other', None)"""
        kids = self.spki.children()
        alg = kids[0].children()
        oid = D.as_oid(alg[0])
        bits = D.expect(kids[1], D.BIT_STRING).content[1:]
        if oid == OID_RSA_ENCRYPTION:
            seq = D.parse_exact(bits).children()
            return "rsa", (D.as_int(seq[0]), D.as_int(seq[1]))
        if oid == OID_EC_PUBLIC_KEY:
            return "ec", (D.as_oid(alg[1]), bits)
        return "other", None


def _digest(name, data):
    return hashlib.new(name, data).digest()


def _split_ecdsa(sig):
    seq = D.parse_exact(sig).children()
    return D.as_int(seq[0]), D.as_int(seq[1])


def verify_signature(key, alg_node, default_hash, message, signature):
    """Check `signature` over `message` with a certificate key.
    Returns True, False, or None when the algorithm is outside what the
    profile requires (RSA PKCS#1 v1.5, ECDSA P-256/P-384, optional PSS)."""
    kids = alg_node.children()
    oid = D.as_oid(kids[0])
    if oid not in SIG_ALG:
        return None
    family, hash_name = SIG_ALG[oid]
    kind, material = key
    try:
        if family == "pss":
            if kind != "rsa":
                return False
            params = _pss_params(kids[1] if len(kids) > 1 else None)
            if params is None:
                return None
            hash_name, mgf_hash, salt = params
            return C.rsa_pss_verify(*material, hash_name, mgf_hash, salt, _digest(hash_name, message), signature)
        hash_name = hash_name or default_hash
        if hash_name not in ("sha256", "sha384", "sha512"):
            return None
        if family == "rsa":
            if kind != "rsa":
                return False
            return C.rsa_pkcs1_verify(*material, hash_name, _digest(hash_name, message), signature)
        if kind != "ec":
            return False
        curve_oid, point = material
        if curve_oid not in C.CURVES:
            return None
        r, s = _split_ecdsa(signature)
        return C.ecdsa_verify(curve_oid, point, _digest(hash_name, message), r, s)
    except (D.DerError, IndexError, ValueError):
        return False


def _pss_params(node):
    hash_name, mgf_hash, salt = "sha1", "sha1", 20
    if node is None or node.tag != D.SEQUENCE:
        return None
    for p in node.children():
        inner = D.parse_exact(p.content)
        if p.tag == 0xA0:
            hash_name = HASH_BY_OID.get(D.as_oid(inner.children()[0]))
        elif p.tag == 0xA1:
            if D.as_oid(inner.children()[0]) != OID_MGF1:
                return None
            mgf_hash = HASH_BY_OID.get(D.as_oid(inner.children()[1].children()[0]))
        elif p.tag == 0xA2:
            salt = D.as_int(inner)
    if hash_name not in ("sha256", "sha384", "sha512") or mgf_hash not in ("sha256", "sha384", "sha512"):
        return None
    return hash_name, mgf_hash, salt


# ------------------------------------------------- authority signature
def tsa_signature(token, anchors):
    """One of verified / failed / untrusted / unsupported / no_signer /
    not_evaluated for a parsed token against relying-party anchors (DER
    certificates). Without anchors it is not_evaluated."""
    if not anchors:
        return "not_evaluated"
    if token is None or token.signed_data is None:
        return "failed"
    sd = token.signed_data
    try:
        anchor_certs = [Cert(a) for a in anchors]
    except (D.DerError, IndexError, ValueError):
        anchor_certs = []
    failed = False
    no_signer = False
    unsupported = False
    untrusted = False
    try:
        certs = []
        for c in sd["certs"]:
            try:
                certs.append(Cert(c.raw))
            except (D.DerError, IndexError, ValueError):
                continue
        if len(sd["signer_infos"]) != 1:
            return "failed" if sd["signer_infos"] else "no_signer"
        si = sd["signer_infos"][0].children()
        i = 1
        sid = si[i]
        i += 1
        digest_alg = D.as_oid(si[i].children()[0])
        i += 1
        signed_attrs = None
        if si[i].tag == 0xA0:
            signed_attrs = si[i]
            i += 1
        sig_alg = si[i]
        signature = D.expect(si[i + 1], D.OCTET_STRING).content
        hash_name = HASH_BY_OID.get(digest_alg)
        if signed_attrs is None or hash_name is None:
            return "failed"
        attrs = {}
        for a in signed_attrs.children():
            ak = a.children()
            attrs.setdefault(D.as_oid(ak[0]), []).append(ak[1].children())
        # checks that need no certificate
        md = attrs.get(OID_MESSAGE_DIGEST)
        if not md or len(md) != 1 or len(md[0]) != 1 or md[0][0].content != _digest(hash_name, sd["econtent"]):
            failed = True
        ct = attrs.get(OID_CONTENT_TYPE)
        if not ct or len(ct) != 1 or D.as_oid(ct[0][0]) != sd["econtent_type"] or sd["econtent_type"] != OID_TSTINFO:
            failed = True
        signer = _find_signer(sid, certs)
        if signer is None:
            no_signer = True
        else:
            if not _ess_binding_ok(attrs, signer):
                failed = True
            signed_bytes = b"\x31" + signed_attrs.raw[1:]
            result = verify_signature(signer.public_key(), sig_alg, hash_name, signed_bytes, signature)
            if result is None:
                unsupported = True
            elif not result:
                failed = True
            if signer.eku is None or OID_KP_TIMESTAMPING not in signer.eku:
                failed = True
            outcome = _check_chain(signer, certs, anchor_certs, token.gen_time)
            if outcome == "failed":
                failed = True
            elif outcome == "unsupported":
                unsupported = True
            elif outcome == "untrusted":
                untrusted = True
    except (D.DerError, IndexError, ValueError):
        return "failed"
    if failed:
        return "failed"
    if no_signer:
        return "no_signer"
    if unsupported:
        return "unsupported"
    if untrusted:
        return "untrusted"
    return "verified"


def _find_signer(sid, certs):
    if sid.tag == D.SEQUENCE:  # IssuerAndSerialNumber
        kids = sid.children()
        issuer, serial = kids[0].raw, D.as_int(kids[1])
        for c in certs:
            if c.issuer == issuer and c.serial == serial:
                return c
        return None
    if sid.tag == 0x80:  # SubjectKeyIdentifier [0]
        for c in certs:
            if _skid(c) == sid.content:
                return c
    return None


def _skid(cert):
    kind, material = cert.public_key()
    bits = cert.spki.children()[1].content[1:]
    return hashlib.sha1(bits).digest()


def _ess_binding_ok(attrs, signer):
    for oid, v2 in ((OID_ESS_SIGNING_CERT_V2, True), (OID_ESS_SIGNING_CERT, False)):
        found = attrs.get(oid)
        if not found:
            continue
        if len(found) != 1 or len(found[0]) != 1:
            return False
        seq = found[0][0].children()
        ess_cert_id = seq[0].children()[0].children()
        i = 0
        hash_name = "sha1"
        if v2 and ess_cert_id[0].tag == D.SEQUENCE:
            hash_name = HASH_BY_OID.get(D.as_oid(ess_cert_id[0].children()[0]))
            i = 1
        elif v2:
            hash_name = "sha256"
        if hash_name is None:
            return False
        return ess_cert_id[i].content == _digest(hash_name, signer.der)
    return False


def _check_chain(signer, token_certs, anchors, gen_time):
    """failed | unsupported | untrusted | verified for the path from the
    signer to a supplied anchor. The signer and every issuer other than
    the anchor must be valid at genTime; an issuer must be a CA."""
    cur = signer
    seen = []
    if not _valid_at(cur, gen_time):
        return "failed"
    while True:
        for anchor in anchors:
            if anchor.subject == cur.issuer:
                result = _signed_by(cur, anchor)
                if result is True:
                    return "verified"
                if result is None:
                    return "unsupported"
        issuer = None
        for c in token_certs:
            if c.subject == cur.issuer and c.der != cur.der and c.der not in seen:
                issuer = c
                break
        if issuer is None:
            return "untrusted"
        result = _signed_by(cur, issuer)
        if result is None:
            return "unsupported"
        if not result:
            return "failed"
        if not issuer.ca or not _valid_at(issuer, gen_time):
            return "failed"
        if issuer.subject == issuer.issuer:  # self-signed root carried in the token: not an anchor
            return "untrusted"
        seen.append(cur.der)
        cur = issuer


def _valid_at(cert, when):
    return cert.not_before <= when <= cert.not_after


def _signed_by(cert, issuer):
    kind = issuer.public_key()
    if kind[0] == "other":
        return None
    return verify_signature(kind, cert.sig_alg, None, cert.tbs_der, cert.signature)


def decode_anchors(values):
    out = []
    for v in values or []:
        try:
            out.append(base64.b64decode(v, validate=True))
        except ValueError:
            continue
    return out
