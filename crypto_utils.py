"""Diffie-Hellman + ElGamal dibuat dari nol, tanpa library kriptografi.
Setiap proses mengembalikan daftar langkah (judul, baris-baris) untuk ditampilkan."""
import os

G = 4           # generator subgrup berorde q pada safe prime p = 2q + 1
MAX_DETAIL = 3  # jumlah blok yang dijabarkan langkahnya
_SMALL = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


# ---------- Matematika dasar ----------
def rand_bits(bits):
    return int.from_bytes(os.urandom((bits + 7) // 8), "big") >> ((-bits) % 8)


def rand_below(n):
    return int.from_bytes(os.urandom((n.bit_length() + 7) // 8 + 8), "big") % n


def mod_exp(base, exp, mod):
    """Square-and-multiply: base^exp mod mod."""
    result, b = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = (result * b) % mod
        b = (b * b) % mod
        exp >>= 1
    return result


def mod_inv(a, m):
    """Invers modular dengan algoritma Euclid yang diperluas."""
    old_r, r, old_s, s = a % m, m, 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("tidak punya invers")
    return old_s % m


def is_prime(n, rounds=30):
    """Miller-Rabin."""
    if n < 2:
        return False
    for sp in [2] + _SMALL:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = mod_exp(rand_below(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_safe_prime(bits):
    """Cari p = 2q + 1 dengan p dan q sama-sama prima."""
    while True:
        q = rand_bits(bits - 1) | (1 << (bits - 2)) | 1
        if is_prime(q) and is_prime(2 * q + 1):
            return 2 * q + 1


def block_size(p):
    """Byte per blok agar m (dengan byte penanda 0x01) selalu < p."""
    return (p.bit_length() - 2) // 8


# ---------- Pembuatan kunci ----------
def setup(bits):
    p = gen_safe_prime(bits)
    q = (p - 1) // 2
    a = rand_below(p - 3) + 2
    b = rand_below(p - 3) + 2
    x = rand_below(p - 3) + 2
    A, B, y = mod_exp(G, a, p), mod_exp(G, b, p), mod_exp(G, x, p)
    K1, K2 = mod_exp(B, a, p), mod_exp(A, b, p)
    steps = [
        ("Parameter publik", [
            f"Bilangan prima aman p = 2q + 1, dengan q = {q}",
            f"p = {p}",
            f"Generator g = {G} (berorde q pada mod p)"]),
        ("Diffie-Hellman", [
            f"BAAK memilih kunci privat a = {a}, lalu A = g^a mod p = {A}",
            f"Penerima memilih kunci privat b = {b}, lalu B = g^b mod p = {B}",
            "A dan B dikirim lewat jaringan, sedangkan a dan b dirahasiakan",
            f"BAAK menghitung K = B^a mod p = {K1}",
            f"Penerima menghitung K = A^b mod p = {K2}",
            "Hasil: K sama di kedua pihak" if K1 == K2 else "Hasil: K berbeda (gagal)"]),
        ("Kunci ElGamal penerima", [
            f"Kunci privat x = {x}",
            f"Kunci publik y = g^x mod p = {y}"]),
    ]
    return dict(p=p, K=K1, x=x, y=y), steps


# ---------- Enkripsi ----------
def encrypt(text, st):
    p, y, K = st["p"], st["y"], st["K"]
    data, bs = text.encode("utf-8"), block_size(p)
    chunks = [data[i:i + bs] for i in range(0, len(data), bs)]
    n = rand_below(2 ** 32) + 1
    steps = [("Persiapan", [
        f"Plaintext = {text!r} ({len(data)} byte)",
        f"Ukuran blok = {bs} byte, jadi ada {len(chunks)} blok (supaya m < p)",
        f"Nonce acak n = {n}, dikirim terbuka agar mask berbeda tiap pesan"])]
    out = []
    for i, ch in enumerate(chunks):
        m = int.from_bytes(b"\x01" + ch, "big")
        k = rand_below(p - 3) + 2
        c1, s = mod_exp(G, k, p), mod_exp(y, k, p)
        c2 = (m * s) % p
        mask = mod_exp(K, n + i + 1, p)
        c2o = (c2 * mask) % p
        out.append((c1, c2o))
        if i < MAX_DETAIL:
            steps.append((f"Blok {i + 1}", [
                f"Potongan plaintext = {ch!r}, hex = {ch.hex()}",
                f"Tambah byte penanda 0x01 di depan, m = {m}",
                f"Pilih k acak = {k}",
                f"ElGamal: c1 = g^k mod p = {c1}",
                f"ElGamal: s = y^k mod p = {s}",
                f"ElGamal: c2 = m x s mod p = {c2}",
                f"Lapisan DH: mask = K^(n+{i + 1}) mod p = {mask}",
                f"Lapisan DH: c2' = c2 x mask mod p = {c2o}",
                f"Hasil blok = (c1, c2') = ({c1}, {c2o})"]))
    if len(chunks) > MAX_DETAIL:
        steps.append(("Blok lainnya", [f"{len(chunks) - MAX_DETAIL} blok sisanya dihitung dengan cara yang sama"]))
    cipher = f"{n}|" + ";".join(f"{a},{b}" for a, b in out)
    steps.append(("Ciphertext akhir", [cipher]))
    return cipher, steps


# ---------- Dekripsi ----------
def decrypt(cipher, st):
    p, x, K = st["p"], st["x"], st["K"]
    try:
        n_s, body = cipher.strip().split("|", 1)
        n, pairs = int(n_s), []
        for blk in body.split(";"):
            c1, c2 = (int(v) for v in blk.split(","))
            if not (0 < c1 < p and 0 < c2 < p):
                raise ValueError
            pairs.append((c1, c2))
    except ValueError:
        raise ValueError("Format ciphertext tidak valid.")
    steps = [("Persiapan", [f"Nonce n = {n}, jumlah blok = {len(pairs)}"])]
    out = b""
    for i, (c1, c2o) in enumerate(pairs):
        mask = mod_exp(K, n + i + 1, p)
        mask_inv = mod_inv(mask, p)
        c2 = (c2o * mask_inv) % p
        s = mod_exp(c1, x, p)
        s_inv = mod_inv(s, p)
        m = (c2 * s_inv) % p
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if not raw or raw[0] != 1:
            raise ValueError("Ciphertext rusak atau sudah diubah.")
        out += raw[1:]
        if i < MAX_DETAIL:
            steps.append((f"Blok {i + 1}", [
                f"Terima (c1, c2') = ({c1}, {c2o})",
                f"Lapisan DH: mask = K^(n+{i + 1}) mod p = {mask}",
                f"Lapisan DH: invers mask (Euclid) = {mask_inv}",
                f"Lapisan DH: c2 = c2' x invers mask mod p = {c2}",
                f"ElGamal: s = c1^x mod p = {s}",
                f"ElGamal: invers s (Euclid) = {s_inv}",
                f"ElGamal: m = c2 x invers s mod p = {m}",
                f"Buang byte penanda 0x01, sisa = {raw[1:]!r}"]))
    if len(pairs) > MAX_DETAIL:
        steps.append(("Blok lainnya", [f"{len(pairs) - MAX_DETAIL} blok sisanya didekripsi dengan cara yang sama"]))
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Ciphertext rusak atau sudah diubah.")
    steps.append(("Plaintext akhir", ["Gabungkan semua byte lalu ubah ke teks UTF-8", text]))
    return text, steps
