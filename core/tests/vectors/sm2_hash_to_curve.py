"""Independent, straightforward (non constant-time) RFC 9380 reference."""
import hashlib, struct

# ---- SM3 (GB/T 32905-2016) ----
def _rotl(x, n): n %= 32; return ((x << n) | (x >> (32 - n))) & 0xffffffff
def sm3(msg):
    iv = [0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]
    l = len(msg) * 8
    msg = msg + b'\x80' + b'\x00' * ((56 - (len(msg) + 1) % 64) % 64) + struct.pack('>Q', l)
    v = iv
    for i in range(0, len(msg), 64):
        w = list(struct.unpack('>16I', msg[i:i+64]))
        p1 = lambda x: x ^ _rotl(x, 15) ^ _rotl(x, 23)
        for j in range(16, 68):
            w.append(p1(w[j-16] ^ w[j-9] ^ _rotl(w[j-3], 15)) ^ _rotl(w[j-13], 7) ^ w[j-6])
        w1 = [w[j] ^ w[j+4] for j in range(64)]
        a,b,c,d,e,f,g,h = v
        for j in range(64):
            t = 0x79cc4519 if j < 16 else 0x7a879d8a
            ss1 = _rotl((_rotl(a,12) + e + _rotl(t, j)) & 0xffffffff, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            ff = (a ^ b ^ c) if j < 16 else ((a & b) | (a & c) | (b & c))
            gg = (e ^ f ^ g) if j < 16 else ((e & f) | (~e & g))
            tt1 = (ff + d + ss2 + w1[j]) & 0xffffffff
            tt2 = (gg + h + ss1 + w[j]) & 0xffffffff
            d, c, b, a = c, _rotl(b, 9), a, tt1
            h, g, f, e = g, _rotl(f, 19), e, (tt2 ^ _rotl(tt2, 9) ^ _rotl(tt2, 17))
        v = [x ^ y for x, y in zip(v, [a,b,c,d,e,f,g,h])]
    return struct.pack('>8I', *v)

assert sm3(b'abc').hex() == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
assert sm3(b'abcd'*16).hex() == 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'

# ---- RFC 9380 ----
def expand_xmd(H, b_len, r_len, msg, dst, n):
    ell = -(-n // b_len)
    dst_p = dst + bytes([len(dst)])
    b0 = H(b'\x00' * r_len + msg + n.to_bytes(2, 'big') + b'\x00' + dst_p)
    bs = [H(b0 + b'\x01' + dst_p)]
    for i in range(2, ell + 1):
        bs.append(H(bytes(x ^ y for x, y in zip(b0, bs[-1])) + bytes([i]) + dst_p))
    return b''.join(bs)[:n]

def sqrt3mod4(x, p):
    r = pow(x, (p + 1) // 4, p)
    return r if r * r % p == x % p else None

def sswu(u, p, A, B, Z):
    # RFC 9380 §6.6.2, straight-line
    tv1 = pow((Z*Z*pow(u,4,p) + Z*u*u) % p, p - 2, p)
    x1 = (-B * pow(A, p-2, p)) * (1 + tv1) % p
    if tv1 == 0:
        x1 = B * pow(Z * A % p, p-2, p) % p
    gx1 = (x1**3 + A*x1 + B) % p
    x2 = Z * u * u * x1 % p
    gx2 = (x2**3 + A*x2 + B) % p
    y1 = sqrt3mod4(gx1, p)
    if y1 is not None:
        x, y = x1, y1
    else:
        x, y = x2, sqrt3mod4(gx2, p)
    if (u % 2) != (y % 2):
        y = (-y) % p
    return x, y

def add(P, Q, p):
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: raise ValueError('identity')
    lam = ((3*x1*x1 - 3) * pow(2*y1, p-2, p)) if P == Q else ((y2 - y1) * pow(x2 - x1, p-2, p))
    lam %= p
    x3 = (lam*lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p

def hash_to_curve(msg, dst, H, b_len, r_len, p, A, B, Z):
    uni = expand_xmd(H, b_len, r_len, msg, dst, 96)
    u0, u1 = (int.from_bytes(uni[i:i+48], 'big') % p for i in (0, 48))
    q0, q1 = sswu(u0, p, A, B, Z), sswu(u1, p, A, B, Z)
    return u0, u1, q0, q1, add(q0, q1, p)

# ---- validate the reference on P-256 (RFC 9380 J.1.1) ----
p256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
sha = lambda m: hashlib.sha256(m).digest()
dst = b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_'
_, _, _, _, P = hash_to_curve(b'abc', dst, sha, 32, 64, p256, p256 - 3, b256, p256 - 10)
assert P == (0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f,
             0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e), 'P-256 mismatch'
_, _, _, _, P = hash_to_curve(b'', dst, sha, 32, 64, p256, p256 - 3, b256, p256 - 10)
assert P[0] == 0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4
print('reference validated against RFC 9380 P-256 vectors')

# ---- SM2_XMD:SM3_SSWU_RO_ vectors ----
psm2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
bsm2 = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
dst = b'QUUX-V01-CS02-with-SM2_XMD:SM3_SSWU_RO_'
for msg in [b'', b'abc', b'abcdef0123456789', b'a512_' + b'a' * 507]:
    u0, u1, q0, q1, P = hash_to_curve(msg, dst, sm3, 32, 64, psm2, psm2 - 3, bsm2, psm2 - 9)
    for name, pt in (('Q0', q0), ('Q1', q1), ('P', P)):
        x, y = pt
        assert (y*y - x**3 + 3*x - bsm2) % psm2 == 0, name + ' not on curve'
    m = msg.decode() if len(msg) < 40 else f'a512_ + a*507'
    print(f'msg={m!r}\n  u0={u0:064x}\n  u1={u1:064x}\n  P.x={P[0]:064x}\n  P.y={P[1]:064x}')
