"""Server web minimal memakai http.server bawaan Python (tanpa framework)."""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import auth
import crypto_utils as cu

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = {}   # kunci BAAK dan penerima (simulasi dalam satu proses)
INBOX = []   # ciphertext yang dikirim BAAK untuk penerima
COOKIE = "sid={}; HttpOnly; SameSite=Strict; Path=/"


def api_login(req, user):
    token, info = auth.login(str(req.get("username", "")).strip()[:50], str(req.get("password", ""))[:100])
    return info, {"Set-Cookie": COOKIE.format(token) + "; Max-Age=3600"}


def api_logout(req, user):
    auth.SESSIONS.pop(user["token"], None)
    return {}, {"Set-Cookie": COOKIE.format("") + "; Max-Age=0"}


def api_me(req, user):
    return {"username": user["user"], "role": user["role"], "label": user["label"]}


def api_inbox(req, user):
    return {"pesan": INBOX[::-1]}


def api_setup(req, user):
    bits = req.get("bits")
    if bits not in (16, 64, 256):
        raise ValueError("Ukuran bilangan prima tidak valid.")
    st, steps = cu.setup(bits)
    STATE.clear()
    STATE.update(st)
    INBOX.clear()  # pesan lama tidak bisa didekripsi dengan kunci baru
    return {"steps": steps}


def api_encrypt(req, user):
    if not STATE:
        raise ValueError("Buat kunci dulu di langkah 1.")
    text = str(req.get("text", "")).strip()
    if not text:
        raise ValueError("Isi data nilai/KRS terlebih dahulu.")
    cipher, steps = cu.encrypt(text, STATE)
    INBOX.append({"id": len(INBOX) + 1, "dari": user["label"], "waktu": time.strftime("%H:%M:%S"), "cipher": cipher})
    return {"cipher": cipher, "steps": steps}


def api_decrypt(req, user):
    if not STATE:
        raise ValueError("BAAK belum membuat kunci.")
    text, steps = cu.decrypt(str(req.get("cipher", "")), STATE)
    return {"text": text, "steps": steps}


# (metode, path) -> (fungsi, role yang boleh: None = publik, "*" = semua yang sudah login)
ROUTES = {
    ("POST", "/api/login"): (api_login, None),
    ("POST", "/api/logout"): (api_logout, "*"),
    ("GET", "/api/me"): (api_me, "*"),
    ("GET", "/api/inbox"): (api_inbox, "penerima"),
    ("POST", "/api/setup"): (api_setup, "baak"),
    ("POST", "/api/encrypt"): (api_encrypt, "baak"),
    ("POST", "/api/decrypt"): (api_decrypt, "penerima"),
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, ctype="application/json; charset=utf-8", headers=None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _session(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return auth.SESSIONS.get(v)
        return None

    def _dispatch(self, method):
        route = ROUTES.get((method, self.path))
        if not route:
            return self._send(404, {"error": "Tidak ditemukan"})
        fn, role = route
        user = self._session()
        if role and not user:
            return self._send(401, {"error": "Silakan login terlebih dahulu."})
        if role not in (None, "*") and user["role"] != role:
            return self._send(403, {"error": "Peran Anda tidak boleh mengakses fitur ini."})
        try:
            req = {}
            if method == "POST":
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if not isinstance(req, dict):
                    raise ValueError("Permintaan tidak valid.")
            res = fn(req, user)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        payload, headers = res if isinstance(res, tuple) else (res, {})
        self._send(200, payload, headers=headers)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Buka http://127.0.0.1:5000 di browser (Ctrl+C untuk berhenti)")
    HTTPServer(("127.0.0.1", 5000), Handler).serve_forever()