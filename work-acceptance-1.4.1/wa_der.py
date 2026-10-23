"""Minimal strict DER reader: enough for RFC 3161 responses, CMS SignedData
and X.509. Standard library only. Every malformed input raises DerError."""
import datetime

UNIVERSAL_INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
SEQUENCE = 0x30
SET = 0x31


class DerError(ValueError):
    pass


class Node:
    __slots__ = ("tag", "content", "raw")

    def __init__(self, tag, content, raw):
        self.tag = tag
        self.content = content
        self.raw = raw  # the full TLV bytes

    def children(self):
        return parse_all(self.content)


def _read(buf, pos):
    if pos + 2 > len(buf):
        raise DerError("truncated")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers unsupported")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise DerError("bad length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        if length < 0x80 or buf[pos] == 0:
            raise DerError("non-minimal length")
        pos += n
    end = pos + length
    if end > len(buf):
        raise DerError("length past end")
    return tag, pos, end


def parse_one(buf, pos=0):
    tag, start, end = _read(buf, pos)
    return Node(tag, bytes(buf[start:end]), bytes(buf[pos:end])), end


def parse_all(buf):
    out, pos = [], 0
    while pos < len(buf):
        node, pos = parse_one(buf, pos)
        out.append(node)
    return out


def parse_exact(buf):
    node, end = parse_one(buf, 0)
    if end != len(buf):
        raise DerError("trailing bytes")
    return node


def expect(node, tag):
    if node.tag != tag:
        raise DerError(f"expected tag {tag:#x}, got {node.tag:#x}")
    return node


def as_int(node):
    expect(node, UNIVERSAL_INTEGER)
    if not node.content:
        raise DerError("empty integer")
    return int.from_bytes(node.content, "big", signed=True)


def as_oid(node):
    expect(node, OID)
    c = node.content
    if not c:
        raise DerError("empty oid")
    arcs, val = [], 0
    for b in c:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(val)
            val = 0
    if c[-1] & 0x80:
        raise DerError("truncated oid")
    first = arcs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def encode_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + encode_len(len(content)) + content


def as_time(node):
    """UTCTime (0x17) or GeneralizedTime (0x18) -> aware UTC datetime
    (fractional seconds kept for GeneralizedTime)."""
    s = node.content.decode("ascii")
    if node.tag == 0x17:
        if len(s) != 13 or not s.endswith("Z"):
            raise DerError("bad UTCTime")
        yy = int(s[0:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        rest = s[2:-1]
        return datetime.datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                                 int(rest[6:8]), int(rest[8:10]), tzinfo=datetime.timezone.utc)
    if node.tag == 0x18:
        if not s.endswith("Z") or len(s) < 15:
            raise DerError("bad GeneralizedTime")
        body = s[:-1]
        frac = 0
        if len(body) > 14:
            if body[14] != "." or len(body) == 15 or not body[15:].isdigit():
                raise DerError("bad GeneralizedTime fraction")
            frac = int((body[15:] + "000000")[:6])
        return datetime.datetime(int(body[0:4]), int(body[4:6]), int(body[6:8]), int(body[8:10]),
                                 int(body[10:12]), int(body[12:14]), frac, tzinfo=datetime.timezone.utc)
    raise DerError("not a time")
