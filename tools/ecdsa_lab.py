"""Educational secp256k1 / ECDSA lab.

Purpose: teach WHY nonce reuse and weak randomness destroy ECDSA keys, using toy keys
generated inside this module only. This is standard, published cryptography education
(the same math is in every ECDSA textbook). It is not an attack tool: it cannot touch
real wallets or third-party keys — it only demonstrates the math on keys it creates itself.

Includes: keygen, ECDSA sign/verify, RFC 6979 deterministic nonces, and the classic
nonce-reuse private-key recovery demonstration.
"""

import hashlib
import hmac
import secrets

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def mod_inv(a, m=P):
    return pow(a, -1, m)


def point_add(p1, p2):
    """Add two points on secp256k1 (affine coordinates)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * mod_inv(2 * y1) % P
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point=G):
    """Scalar multiplication via double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def keygen():
    """Generate a toy keypair. d: secret scalar, P: public point."""
    d = secrets.randbelow(N)
    return d, point_mul(d)


def msg_hash(message):
    if isinstance(message, str):
        message = message.encode()
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % N


def rfc6979_nonce(d, message):
    """RFC 6979 deterministic nonce (HMAC-SHA256) — the fix for weak randomness."""
    if isinstance(message, str):
        message = message.encode()
    h1 = hashlib.sha256(message).digest()
    x = d.to_bytes(32, "big")
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def sign(d, message, k=None):
    """ECDSA sign. If k is None, uses RFC 6979 deterministic nonce."""
    z = msg_hash(message)
    if k is None:
        k = rfc6979_nonce(d, message)
    R = point_mul(k)
    r = R[0] % N
    if r == 0:
        raise ValueError("r == 0, pick another k")
    s = mod_inv(k, N) * (z + r * d) % N
    if s == 0:
        raise ValueError("s == 0, pick another k")
    return r, s, z


def verify(pub, message, r, s):
    """Verify an ECDSA signature."""
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = msg_hash(message)
    w = mod_inv(s, N)
    u1 = z * w % N
    u2 = r * w % N
    point = point_add(point_mul(u1), point_mul(u2, pub))
    if point is None:
        return False
    return point[0] % N == r


def recover_from_nonce_reuse(r, s1, s2, z1, z2):
    """Classic attack math: same r in two signatures reveals k, then d.

    k = (z1 - z2) / (s1 - s2) mod n
    d = (s1*k - z1) / r mod n
    """
    if r == 0:
        raise ValueError("r must be nonzero")
    ds = (s1 - s2) % N
    if ds == 0:
        raise ValueError("s1 == s2: signatures identical, cannot recover")
    k = (z1 - z2) * mod_inv(ds, N) % N
    d = (s1 * k - z1) * mod_inv(r, N) % N
    return k, d


def demo_nonce_reuse(message_a="tx one", message_b="tx two"):
    """Full demonstration on a freshly generated toy key.

    Returns evidence dict: original vs recovered private key, and verification
    that the recovered key reproduces the same public key.
    """
    d, pub = keygen()
    k = secrets.randbelow(N)  # deliberately REUSED across both signatures
    r1, s1, z1 = sign(d, message_a, k=k)
    r2, s2, z2 = sign(d, message_b, k=k)
    if r1 != r2:
        raise RuntimeError("demo error: r values differ (nonce was not reused)")
    k_rec, d_rec = recover_from_nonce_reuse(r1, s1, s2, z1, z2)
    pub_from_recovered = point_mul(d_rec)
    return {
        "scenario": "same nonce k used in two different signatures",
        "message_a": message_a,
        "message_b": message_b,
        "r": hex(r1),
        "s1": hex(s1),
        "s2": hex(s2),
        "recovered_k_matches": k_rec == k,
        "recovered_private_key": hex(d_rec),
        "original_private_key": hex(d),
        "private_key_recovered": d_rec == d,
        "public_key_matches": pub_from_recovered == pub,
        "lesson": "Ek hi nonce do signatures me use hua => private key turant recover ho gayi. "
                  "RFC 6979 deterministic nonces ya CSPRNG nonces isse bachate hain.",
    }


def rfc6979_stability_check(d, message, rounds=3):
    """Prove deterministic nonces are stable: same key+message => same k every time."""
    nonces = {rfc6979_nonce(d, message) for _ in range(rounds)}
    sigs = {sign(d, message)[:2] for _ in range(rounds)}
    return {"deterministic": len(nonces) == 1 and len(sigs) == 1,
            "distinct_nonces_seen": len(nonces),
            "distinct_signatures_seen": len(sigs),
            "lesson": "RFC 6979 se hamesha same (r, s) banta hai usi message ke liye — "
                      "randomness ki zaroorat hi nahi, isliye weak RNG ka risk khatam."}
