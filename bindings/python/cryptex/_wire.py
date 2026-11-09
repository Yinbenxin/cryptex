"""
Human-readable summaries of PSI messages, for DEBUG logs.

Only the message framing is parsed: type, counts and sizes, plus a short
hex preview of the first values. Every value on the wire is a blinded
point, a truncated pseudorandom tag or OT/VOLE material, meaningless
without keys that are never logged; items themselves never appear.
Parsing never raises: anything unexpected is summarized as raw bytes.
"""

import struct

# Values shown per array, and bytes shown per value.
PREVIEW_ITEMS = 2
PREVIEW_BYTES = 8

# Compressed point length per Curve value (RISTRETTO255, P256, SM2, FOURQ).
POINT_LEN = {0: 32, 1: 33, 2: 33, 3: 32}
# VOLE-PSI: base-OT points and IKNP rows.
_VOLE_POINT = 32
_BLOCK = 16


class _Short(Exception):
    pass


class _Reader:
    def __init__(self, msg):
        self.msg, self.off = msg, 1

    def take(self, n):
        if n < 0 or self.off + n > len(self.msg):
            raise _Short
        out = self.msg[self.off:self.off + n]
        self.off += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def array(self, count, width):
        """(count, width, preview) of `count` values of `width` bytes"""
        start = self.off
        self.take(count * width)
        return _preview(self.msg, start, count, width)

    def rest(self):
        return len(self.msg) - self.off


def _preview(msg, start, count, width):
    if count == 0 or width == 0:
        return ""
    shown = []
    for i in range(min(count, PREVIEW_ITEMS)):
        v = msg[start + i * width:start + (i + 1) * width]
        h = v[:PREVIEW_BYTES].hex()
        shown.append(f"#{i} {h}{'…' if width > PREVIEW_BYTES else ''}")
    more = f", … {count - PREVIEW_ITEMS} more" if count > PREVIEW_ITEMS else ""
    return f" (e.g. {'; '.join(shown)}{more})"


def _sizes(r):
    b = r.u32()
    sizes = [r.u64() for _ in range(b)]
    head = ", ".join(str(s) for s in sizes[:4])
    tail = ", …" if b > 4 else ""
    return f"{b} buckets, sizes [{head}{tail}] total {sum(sizes)}"


def _positions(r):
    k = r.u64()
    width = r.rest() // k if k else 4
    return k, r.array(k, width), width


def _ecdh(tag, r, p):
    if tag == 0x01:
        share = r.u8()
        n = r.u64()
        return (f"ECDH msg1 R→S [receiver's items, blinded H(x)^a]: {n} points × {p} B, "
                f"share_result={bool(share)}{r.array(n, p)}")
    if tag == 0x02:
        t = r.u8()
        n = r.u64()
        v = r.array(n, t)
        m = r.u64()
        w = r.array(m, p)
        return (f"ECDH msg2 S→R [receiver's items re-blinded, tags T(H(x)^ab)]: {n} tags × {t} B{v}; "
                f"[sender's items, blinded H(y)^b, shuffled]: {m} points × {p} B{w}")
    if tag == 0x03:
        k, prev, width = _positions(r)
        return (f"ECDH msg3 R→S [result for the sender]: {k} matching positions "
                f"× {width} B{prev}")
    return None


def _oprf(tag, r, p):
    if tag == 0x11:
        n = r.u64()
        return f"OPRF msg1 R→S [receiver's items, blinded H(x)^r]: {n} points × {p} B{r.array(n, p)}"
    if tag == 0x12:
        t = r.u8()
        n = r.u64()
        e = r.array(n, p)
        m = r.u64()
        f = r.array(m, t)
        return (f"OPRF msg2 S→R [receiver's items evaluated, H(x)^rk]: {n} points × {p} B{e}; "
                f"[sender's items, OPRF tags, sorted]: {m} tags × {t} B{f}")
    return None


def _vole(tag, r):
    if tag == 0x21:
        r.take(16)  # session seed
        share = r.u8()
        sizes = _sizes(r)
        r.take(_VOLE_POINT)
        return (f"VOLE setup 1/3 R→S [bucket sizes + base-OT point]: {sizes}, "
                f"share_result={bool(share)}")
    if tag == 0x22:
        r.take(16)
        sizes = _sizes(r)
        n = r.rest() // _VOLE_POINT
        return f"VOLE setup 2/3 S→R [bucket sizes + base-OT replies]: {sizes}, {n} points"
    if tag == 0x23:
        n = r.rest() // _BLOCK
        return f"VOLE setup 3/3 R→S [IKNP extension rows]: {n} rows × {_BLOCK} B"
    if tag == 0x24:
        it = r.u64()
        return f"VOLE Ferret iteration {it + 1} S→R [silent OT]: {r.rest()} B"
    if tag == 0x25:
        b = r.u32()
        r.take(16)  # OKVS seed
        rows = r.u64()
        return (f"VOLE bucket {b + 1} request R→S [receiver's items, OKVS-encoded and masked]: "
                f"{rows} rows × {_BLOCK} B{r.array(rows, _BLOCK)}")
    if tag == 0x26:
        b = r.u32()
        t = r.u8()
        m = r.u64()
        return (f"VOLE bucket {b + 1} reply S→R [sender's items, OPRF tags, shuffled]: "
                f"{m} tags × {t} B{r.array(m, t)}")
    if tag == 0x27:
        b = r.u32()
        k, prev, width = _positions(r)
        return (f"VOLE bucket {b + 1} result R→S [for the sender]: {k} matching positions "
                f"× {width} B{prev}")
    return None


def describe(protocol, curve, msg):
    """One-line summary of a PSI message (protocol: Protocol value)"""
    if not msg:
        return "empty"
    tag = msg[0]
    try:
        r = _Reader(msg)
        p = POINT_LEN.get(int(curve), 32)
        if protocol == 0:
            text = _ecdh(tag, r, p)
        elif protocol == 1:
            text = _vole(tag, r)
        elif protocol == 2:
            text = _oprf(tag, r, p)
        else:
            text = None
    except (_Short, ZeroDivisionError, struct.error):
        text = None
    if text is None:
        return f"unrecognized message type 0x{tag:02x}"
    return text


def describe_header(fields):
    """Summary of a session header tuple (see psi._HEADER)"""
    _, version, protocol, role, curve, bucket_hash, share, size, n = fields
    return (f"v{version} protocol={protocol} role={role} curve={curve} "
            f"bucket_hash={bucket_hash} share_result={bool(share)} "
            f"bucket_size={size or '-'} items={n}")
