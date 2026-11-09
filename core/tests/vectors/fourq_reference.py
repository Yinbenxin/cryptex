"""Independent, straightforward FourQ reference (not constant time).

Checks the curve constants and generates test vectors for the Rust
implementation in core/src/primitives/ec/fourq/. Run from this directory:

    python3 fourq_reference.py

FourQ (Costello, Longa, ASIACRYPT 2015): twisted Edwards curve
    -x^2 + y^2 = 1 + d x^2 y^2  over GF(p^2), p = 2^127 - 1, i^2 = -1,
with #E = 392 * N, N a 246-bit prime.

Hash-to-curve suite (cryptex-defined, no external interop):
    FourQ_XMD:SHA-256_ELL2_RO_
    expand_message_xmd with SHA-256, k = 128, L = 32 per GF(p) coefficient,
    Elligator 2 on the birationally equivalent Montgomery curve
    (RFC 9380 section 6.7.1) with Z = 2 + i (RFC 9380 appendix H.3 rule),
    rational map to the Edwards curve (RFC 9380 appendix D.1),
    then multiplication by the cofactor 392.
"""
import hashlib
import random

p = 2**127 - 1
# d = 4205857648805777768770 + 125317048443780598345676279555970305165 i
D = (4205857648805777768770, 125317048443780598345676279555970305165)
N = 0x0029CBC14E5E0A72F05397829CBC14E5DFBD004DFE0F79992FB2540EC7768CE7
COFACTOR = 392


# ---------------------------------------------------------------- GF(p^2)
def add(a, b): return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)
def sub(a, b): return ((a[0] - b[0]) % p, (a[1] - b[1]) % p)
def neg(a): return ((-a[0]) % p, (-a[1]) % p)
def mul(a, b): return ((a[0] * b[0] - a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)
def norm(a): return (a[0] * a[0] + a[1] * a[1]) % p
def inv(a):
    n = pow(norm(a), p - 2, p)
    return (a[0] * n % p, (-a[1]) * n % p)
def div(a, b): return mul(a, inv(b))
def sq(a): return mul(a, a)
def fpow(a, e):
    r = (1, 0)
    while e:
        if e & 1:
            r = mul(r, a)
        a = mul(a, a)
        e >>= 1
    return r
ONE, ZERO = (1, 0), (0, 0)


def is_square(a):
    """a is a square in GF(p^2) iff its norm is a square in GF(p)."""
    n = norm(a)
    return n == 0 or pow(n, (p - 1) // 2, p) == 1


def sqrt_fp(a):
    r = pow(a, (p + 1) // 4, p)
    return r if r * r % p == a % p else None


def sqrt(a):
    """Square root in GF(p^2) via GF(p) square roots (a different method from
    the Rust code, which uses Adj-Rodriguez-Henriquez algorithm 9)."""
    a0, a1 = a
    if a1 == 0:
        r = sqrt_fp(a0)
        if r is not None:
            return (r, 0)
        r = sqrt_fp((-a0) % p)
        return (0, r)
    s = sqrt_fp(norm(a))
    assert s is not None
    for c in ((a0 + s) * pow(2, p - 2, p) % p, (a0 - s) * pow(2, p - 2, p) % p):
        x0 = sqrt_fp(c)
        if x0 is not None and x0 != 0:
            x1 = a1 * pow(2 * x0, p - 2, p) % p
            assert sq((x0, x1)) == (a0 % p, a1 % p)
            return (x0, x1)
    raise AssertionError("no square root")


def sgn0(a):
    """RFC 9380 section 4.1, m = 2."""
    return (a[0] & 1) | ((a[0] == 0) & (a[1] & 1))


# ---------------------------------------------------------------- curve
def on_curve(P):
    x, y = P
    x2, y2 = sq(x), sq(y)
    return sub(y2, x2) == add(ONE, mul(D, mul(x2, y2)))


def padd(P, Q):
    (x1, y1), (x2, y2) = P, Q
    t = mul(D, mul(mul(x1, x2), mul(y1, y2)))
    x3 = div(add(mul(x1, y2), mul(y1, x2)), add(ONE, t))
    y3 = div(add(mul(y1, y2), mul(x1, x2)), sub(ONE, t))  # a = -1: y1y2 - a x1x2
    return (x3, y3)


IDENTITY = (ZERO, ONE)


def pmul(k, P):
    R = IDENTITY
    while k:
        if k & 1:
            R = padd(R, P)
        P = padd(P, P)
        k >>= 1
    return R


def pneg(P):
    return (neg(P[0]), P[1])


# ---------------------------------------------------------------- encoding
def encode(P):
    """32 bytes: y0 (16 LE) || y1 (16 LE), top bit = sgn0(x)."""
    x, y = P
    b = bytearray(y[0].to_bytes(16, "little") + y[1].to_bytes(16, "little"))
    b[31] |= sgn0(x) << 7
    return bytes(b)


# ---------------------------------------------------------------- hash to curve
def expand_xmd(msg, dst, n):
    H = lambda m: hashlib.sha256(m).digest()
    ell = -(-n // 32)
    dst_p = dst + bytes([len(dst)])
    b0 = H(b"\0" * 64 + msg + n.to_bytes(2, "big") + b"\0" + dst_p)
    bs = [H(b0 + b"\1" + dst_p)]
    for i in range(2, ell + 1):
        bs.append(H(bytes(x ^ y for x, y in zip(b0, bs[-1])) + bytes([i]) + dst_p))
    return b"".join(bs)[:n]


def hash_to_field(msg, dst, count):
    L = 32
    uni = expand_xmd(msg, dst, count * 2 * L)
    out = []
    for i in range(count):
        e = [int.from_bytes(uni[(2 * i + j) * L:(2 * i + j + 1) * L], "big") % p for j in range(2)]
        out.append(tuple(e))
    return out


# Montgomery form K t^2 = s^3 + J s^2 + s with a = (J+2)/K = -1, d = (J-2)/K.
J = div(mul((2, 0), sub(ONE, D)), add(ONE, D))
K = div((p - 4, 0), add(ONE, D))
assert div(add(J, (2, 0)), K) == (p - 1, 0)
assert div(sub(J, (2, 0)), K) == D


def find_z():
    """RFC 9380 appendix H.3 with F.gen() = i: candidates i, -i, i+1, ..."""
    ctr = 0
    while True:
        for z in (add((ctr, 0), (0, 1)), neg(add((ctr, 0), (0, 1)))):
            if not is_square(z):
                return z
        ctr += 1


Z = find_z()


def elligator2(u):
    """RFC 9380 section 6.7.1 (non-straight-line form)."""
    JK = div(J, K)
    tv = add(ONE, mul(Z, sq(u)))
    x1 = mul(neg(JK), inv(tv)) if tv != ZERO else ZERO
    if x1 == ZERO:
        x1 = neg(JK)
    g = lambda x: add(add(mul(sq(x), x), mul(JK, sq(x))), div(x, sq(K)))
    x2 = sub(neg(x1), JK)
    if is_square(g(x1)):
        x, y = x1, sqrt(g(x1))
        if sgn0(y) != 1:
            y = neg(y)
    else:
        x, y = x2, sqrt(g(x2))
        if sgn0(y) != 0:
            y = neg(y)
    s, t = mul(x, K), mul(y, K)
    # On the Montgomery curve.
    assert mul(K, sq(t)) == add(add(mul(sq(s), s), mul(J, sq(s))), s)
    return s, t


def to_edwards(s, t):
    """RFC 9380 appendix D.1."""
    if t == ZERO or add(s, ONE) == ZERO:
        return IDENTITY
    return (div(s, t), div(sub(s, ONE), add(s, ONE)))


SUITE = b"FourQ_XMD:SHA-256_ELL2_RO_"


def hash_to_curve(msg, dst):
    u0, u1 = hash_to_field(msg, dst, 2)
    q0 = to_edwards(*elligator2(u0))
    q1 = to_edwards(*elligator2(u1))
    assert on_curve(q0) and on_curve(q1)
    return pmul(COFACTOR, padd(q0, q1))


# ---------------------------------------------------------------- checks
def is_prime(n, rounds=40):
    if n < 4:
        return n in (2, 3)
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(1)
    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def checks():
    assert is_prime(p) and is_prime(N)
    assert N.bit_length() == 246
    # Completeness of the addition law: a = -1 square, d non-square.
    assert is_square((p - 1, 0)) and not is_square(D)
    # Random points have order dividing 392 N, and 392 P has order N.
    rng = random.Random(7)
    for _ in range(4):
        u = (rng.randrange(p), rng.randrange(p))
        P = to_edwards(*elligator2(u))
        assert on_curve(P)
        Q = pmul(COFACTOR, P)
        assert Q != IDENTITY and pmul(N, Q) == IDENTITY
    # Z per appendix H.3.
    assert Z == (2, 1), Z
    print("constants ok: p, N prime; d non-square; #E = 392 N; Z = 2 + i")


def hexes(a):
    return f"{a[0]:032x}", f"{a[1]:032x}"


if __name__ == "__main__":
    checks()
    print(f"J = {hexes(J)}")
    print(f"K = {hexes(K)}")
    dst = b"QUUX-V01-CS02-with-" + SUITE
    for msg in [b"", b"abc", b"abcdef0123456789", b"a512_" + b"a" * 507]:
        P = hash_to_curve(msg, dst)
        assert on_curve(P) and pmul(N, P) == IDENTITY
        label = msg.decode() if len(msg) < 40 else "a512_ + a*507"
        print(f"h2c {label!r}: {encode(P).hex()}")
    # Scalar multiplication on P = hash_to_curve("scalar"), already in the
    # order-N subgroup.
    P = hash_to_curve(b"scalar", dst)
    print(f"h2c 'scalar': {encode(P).hex()}")
    for c in [1, 2, 0x1234567890ABCDEF, N - 1]:
        print(f"mul c={c:#x}: {encode(pmul(c, P)).hex()}")
