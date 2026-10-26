"""Server web minimal memakai http.server bawaan Python (tanpa framework)."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import crypto_utils as cu

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = {}  # simulasi: satu proses memegang kunci BAAK dan penerima


def api_setup(req):
    bits = req.get("bits")
    if bits not in (16, 64, 256):
        raise ValueError("Ukuran bilangan prima tidak valid.")
    st, steps = cu.setup(bits)
    STATE.clear()
    STATE.update(st)
    return {"steps": steps}


def api_encrypt(req):
    if not STATE:
        raise ValueError("Buat kunci dulu di langkah 1.")
    text = str(req.get("text", "")).strip()
    if not text:
        raise ValueError("Isi data nilai/KRS terlebih dahulu.")
    cipher, steps = cu.encrypt(text, STATE)
    return {"cipher": cipher, "steps": steps}


def api_decrypt(req):
    if not STATE:
        raise ValueError("Buat kunci dulu di langkah 1.")
    text, steps = cu.decrypt(str(req.get("cipher", "")), STATE)
    return {"text": text, "steps": steps}


ROUTES = {"/api/setup": api_setup, "/api/encrypt": api_encrypt, "/api/decrypt": api_decrypt}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, ctype="application/json; charset=utf-8"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "Tidak ditemukan"})

    def do_POST(self):
        handler = ROUTES.get(self.path)
        if not handler:
            return self._send(404, {"error": "Tidak ditemukan"})
        try:
            size = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(size) or b"{}")
            self._send(200, handler(req))
        except ValueError as e:
            self._send(400, {"error": str(e)})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Buka http://127.0.0.1:5000 di browser (Ctrl+C untuk berhenti)")
    HTTPServer(("127.0.0.1", 5000), Handler).serve_forever()
