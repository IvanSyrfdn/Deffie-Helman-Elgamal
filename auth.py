"""Autentikasi tanpa library: SHA-256 dibuat sendiri, password bersalt, sesi lewat cookie."""
import os
import time

# ---------- SHA-256 dari nol (konstanta diturunkan dari akar bilangan prima) ----------
def _iroot(n, k):
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _first_primes(count):
    out, c = [], 2
    while len(out) < count:
        if all(c % p for p in out):
            out.append(c)
        c += 1
    return out


_P = _first_primes(64)
_K = [_iroot(p << 96, 3) & 0xFFFFFFFF for p in _P]
_H0 = [_iroot(p << 64, 2) & 0xFFFFFFFF for p in _P[:8]]
_M = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M


def sha256(data: bytes) -> bytes:
    h = _H0[:]
    bits = len(data) * 8
    data += b"\x80" + b"\x00" * ((55 - len(data)) % 64) + bits.to_bytes(8, "big")
    for i in range(0, len(data), 64):
        w = [int.from_bytes(data[i + j:i + j + 4], "big") for j in range(0, 64, 4)]
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & _M)
        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            t1 = (hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _K[t] + w[t]) & _M
            t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & _M
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _M, c, b, a, (t1 + t2) & _M
        h = [(x + y) & _M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def hash_password(password: str, salt: bytes, rounds=1000) -> bytes:
    """Hash bersalt yang diulang (versi sederhana, bukan PBKDF2)."""
    pw = password.encode("utf-8")
    h = sha256(salt + pw)
    for _ in range(rounds):
        h = sha256(h + salt + pw)
    return h


def _same(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


# ---------- Akun demo dan sesi ----------
DEMO = [("baak", "baak123", "baak", "BAAK"), ("dosen", "dosen123", "penerima", "Dosen wali")]
USERS, SESSIONS, FAILS = {}, {}, {}
for _name, _pw, _role, _label in DEMO:
    _salt = os.urandom(16)
    USERS[_name] = {"role": _role, "label": _label, "salt": _salt, "hash": hash_password(_pw, _salt)}


def login(username, password):
    now = time.time()
    u = USERS.get(username)
    count, until = FAILS.get(username, (0, 0))
    if u and until > now:
        raise ValueError(f"Terlalu banyak percobaan. Coba lagi dalam {int(until - now) + 1} detik.")
    digest = hash_password(password, u["salt"] if u else b"\x00" * 16)  # selalu dihitung agar waktu seragam
    if not (u and _same(digest, u["hash"])):
        if u:
            FAILS[username] = (count + 1, now + 30 if count + 1 >= 5 else 0)
        raise ValueError("Username atau password salah.")
    FAILS.pop(username, None)
    token = os.urandom(16).hex()
    SESSIONS[token] = {"token": token, "user": username, "role": u["role"], "label": u["label"]}
    return token, {"username": username, "role": u["role"], "label": u["label"]}
