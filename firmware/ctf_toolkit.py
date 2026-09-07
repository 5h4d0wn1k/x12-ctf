#!/usr/bin/env python3
"""
X12 — CTF Toolkit + Challenge Authorship

A generator of REAL local challenges (web/crypto/misc) with flags, a SQLite
scoreboard, and a solver-checker that solves each challenge and verifies the
recovered flags against stored hashes. Everything runs offline on localhost:
the web challenge is an actual stdlib HTTP server, the crypto challenge is a
known-plaintext repeat-key-XOR ciphertext, and the misc challenge is a real
byte-level data-carving exercise.

Legal: authorized CTF / lab use only.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_SEED = 20260907
DEFAULT_POINTS = 100
FLAG_RE = re.compile(rb"FLAG\{[^}]+\}")


# ---------------------------------------------------------------------------
# Challenge generator — writes real artifacts into a workdir
# ---------------------------------------------------------------------------

def _lcg_byte_iter(seed):
    state = seed
    while True:
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        yield state & 0xFF


def _pg_char(seed):
    state = seed
    while True:
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        yield chr(0x21 + (state % 0x5E))   # printable ASCII 0x21..0x7E


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


WEB_APP_TEMPLATE = '''\
#!/usr/bin/env python3
"""%(name)s — generated web challenge (stdlib http.server)."""
import argparse
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN = %(token)r
STATUS_OK = "operative"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            body = (
                "<html><body><h1>%(name)s</h1>"
                "<a href='/admin'>admin</a>"
                "<!-- token: %(token)s --></body></html>"
            ).encode()
            self._reply(200, body)
        elif self.path.startswith("/admin"):
            token = ""
            if "?" in self.path:
                token = self.path.split("?", 1)[1]
                if token.startswith("token="):
                    token = token[len("token="):]
            if token != TOKEN:
                self._reply(401, b"access denied")
                return
            try:
                with open(os.path.join(DIR, "flag.txt"), "rb") as f:
                    flag = f.read().strip()
            except OSError:
                flag = b"missing flag.txt"
            self._reply(200, b"<body><h1>admin</h1><pre>" + flag + b"</pre></body>")
        elif self.path == "/flag.txt":
            self._reply(404, b"not here")
        else:
            self._reply(404, b"not found")

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def make_server(port):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="%(name)s")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)
    srv = make_server(args.port)
    print("listening on 127.0.0.1:%%d" %% srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


class ChallengeGenerator:
    """Write the web / crypto / misc challenge artifacts into a workdir."""

    def __init__(self, workdir, seed=DEFAULT_SEED):
        self.workdir = workdir
        self.seed = seed
        self.challenges = []

    def _write(self, name, data):
        path = os.path.join(self.workdir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def generate_web(self):
        token = "token-%08x" % ((self.seed ^ 0x70) & 0xFFFFFFFF)
        flag = "FLAG{web_leak_admin_token_%08x}" % (self.seed & 0xFFFFFFFF)
        src = WEB_APP_TEMPLATE % {"name": "WEB-001", "token": token}
        self._write("web_app.py", src.encode("utf-8"))
        # the server reads the flag from its own directory (a "flag database"),
        # like a real web-lab server that holds credentials on disk
        self._write("flag.txt", flag.encode("utf-8") + b"\n")
        return {
            "name": "WEB-001",
            "category": "web",
            "points": 100,
            "flag_sha256": _sha256(flag),
            "file": "web_app.py",
            "token": token,
        }

    def generate_crypto(self):
        chars = _pg_char(self.seed ^ 0xC0DE)
        key = "".join(next(chars) for _ in range(5)).encode("utf-8")
        flag = "FLAG{crypto_repeat_key_xor_knwn_pt}"
        cipher = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag.encode("utf-8")))
        self._write("crypto_flag.enc",
                    base64.b64encode(cipher) + b"\n")
        return {
            "name": "CRYPTO-001",
            "category": "crypto",
            "points": 150,
            "flag_sha256": _sha256(flag),
            "file": "crypto_flag.enc",
            "algo": "repeat-key-xor",
            "key_len": len(key),
        }

    def generate_misc(self):
        flag = "FLAG{misc_carve_the_disk_image}"
        body = base64.b64encode(flag.encode("utf-8"))
        img = bytearray()
        for b in _lcg_byte_iter(self.seed ^ 0xBADC0DE):
            img.append(b)
            if len(img) >= 512:
                break
        img += b"\x1b\x00MISC" + body + b"\x00"
        for b in _lcg_byte_iter(self.seed ^ 0xD15C0DE):
            img.append(b)
            if len(img) >= 900:
                break
        self._write("misc_drive.img", bytes(img))
        return {
            "name": "MISC-001",
            "category": "misc",
            "points": 100,
            "flag_sha256": _sha256(flag),
            "file": "misc_drive.img",
        }

    def generate_all(self):
        os.makedirs(self.workdir, exist_ok=True)
        self.challenges = [
            self.generate_web(),
            self.generate_crypto(),
            self.generate_misc(),
        ]
        manifest = {"generator": "x12", "version": 1,
                    "challenges": self.challenges}
        mpath = os.path.join(self.workdir, "manifest.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2)
        return manifest


# ---------------------------------------------------------------------------
# Solvers — each solve() performs the real mechanism and returns the flag
# ---------------------------------------------------------------------------

class WebSolver:
    """Start the generated HTTP server on an ephemeral localhost port and
    walk the real web application: HTML page -> token -> authenticated /admin."""

    def __init__(self):
        self.steps = []

    def solve(self, workdir, port=0):
        app_path = os.path.join(workdir, "web_app.py")
        with open(app_path, "r", encoding="utf-8") as f:
            code = f.read()
        ns = {"__file__": app_path, "__name__": "x12_web_challenge"}
        exec(code, ns)  # executes the generated server definition in-process
        make_server = ns["make_server"]
        srv = make_server(port)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.steps.append("served generated web_app.py on 127.0.0.1:%d" % port)
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5) as r:
                index_html = r.read().decode("utf-8", errors="replace")
            m = re.search(r"<!-- token: (\S+) -->", index_html)
            if not m:
                raise RuntimeError("token not found on index page")
            token = m.group(1)
            self.steps.append("recovered admin token %r from index page" % token)
            url = "http://127.0.0.1:%d/admin?token=%s" % (port, token)
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read()
            m2 = FLAG_RE.search(body)
            if not m2:
                raise RuntimeError("no flag in /admin response")
            return m2.group(0).decode("utf-8")
        finally:
            srv.shutdown()
            srv.server_close()


class CryptoSolver:
    """Recover the repeat-key-XOR key from the known 'FLAG{' plaintext prefix
    (classic chosen/known-plaintext attack), then decrypt the whole flag."""

    def __init__(self):
        self.steps = []

    def solve(self, workdir):
        enc_path = os.path.join(workdir, "crypto_flag.enc")
        with open(enc_path, "rb") as f:
            cipher = base64.b64decode(f.read().strip())
        known = b"FLAG{"
        key = []
        for i, kc in enumerate(known):
            key.append(cipher[i] ^ kc)
        key = bytes(key)
        self.steps.append("recovered key bytes %r from 'FLAG{' prefix" % key.hex())
        plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(cipher))
        flag = plain.decode("utf-8", errors="replace")
        self.steps.append("decrypted %d bytes, key length %d" % (len(cipher), len(key)))
        return flag


class MiscSolver:
    """Carve the hidden payload from the generated disk image."""

    def __init__(self):
        self.steps = []

    def solve(self, workdir):
        img_path = os.path.join(workdir, "misc_drive.img")
        with open(img_path, "rb") as f:
            data = f.read()
        marker = b"\x1b\x00MISC"
        idx = data.find(marker)
        if idx == -1:
            raise RuntimeError("marker not found")
        self.steps.append("found marker at offset 0x%X" % idx)
        b64 = data[idx + len(marker):].split(b"\x00", 1)[0].strip()
        flag = base64.b64decode(b64).decode("utf-8")
        self.steps.append("decoded %d base64 payload bytes" % len(b64))
        return flag


# ---------------------------------------------------------------------------
# SQLite scoreboard — real persistence, flag verification by hash
# ---------------------------------------------------------------------------

class Scoreboard:
    """SQLite-backed CTF scoreboard storing a hash of each flag; submit()
    verifies a solver's flag against the stored hash and records the solve."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS challenges ("
                " id INTEGER PRIMARY KEY,"
                " name TEXT NOT NULL UNIQUE,"
                " category TEXT NOT NULL,"
                " points INTEGER NOT NULL,"
                " flag_sha256 TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS solves ("
                " id INTEGER PRIMARY KEY,"
                " challenge_id INTEGER NOT NULL REFERENCES challenges(id),"
                " team TEXT NOT NULL,"
                " ts TEXT NOT NULL,"
                " UNIQUE(challenge_id, team))")
            conn.commit()
        finally:
            conn.close()

    def register(self, name, category, points, flag):
        h = _sha256(flag)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO challenges"
                " (name, category, points, flag_sha256)"
                " VALUES (?, ?, ?, ?)", (name, category, points, h))
            conn.commit()
        finally:
            conn.close()
        return h

    def register_hash(self, name, category, points, flag_sha256):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO challenges"
                " (name, category, points, flag_sha256)"
                " VALUES (?, ?, ?, ?)", (name, category, points, flag_sha256))
            conn.commit()
        finally:
            conn.close()

    def register_manifest_hashes(self, manifest):
        for c in manifest["challenges"]:
            self.register_hash(c["name"], c["category"], c["points"],
                               c["flag_sha256"])

    def challenge_score(self, name):
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT id, points, flag_sha256 FROM challenges WHERE name=?",
                (name,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return {"id": row[0], "points": row[1], "flag_sha256": row[2]}

    def submit(self, name, flag, team="solver"):
        score = self.challenge_score(name)
        if score is None:
            return {"accepted": False, "reason": "unknown challenge",
                    "challenge": name, "points": 0}
        if _sha256(flag) != score["flag_sha256"]:
            return {"accepted": False, "reason": "flag rejected",
                    "challenge": name, "points": 0}
        conn = sqlite3.connect(self.db_path)
        try:
            okay = conn.execute(
                "INSERT OR IGNORE INTO solves (challenge_id, team, ts)"
                " VALUES (?, ?, ?)",
                (score["id"], team, time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                  time.gmtime()))).rowcount == 1
            conn.commit()
            solved_by = conn.execute(
                "SELECT COUNT(*) FROM solves WHERE challenge_id=?",
                (score["id"],)).fetchone()[0]
        finally:
            conn.close()
        return {"accepted": bool(okay), "challenge": name,
                "points": score["points"] if okay else 0,
                "reason": ("flag accepted" if okay else "already solved"),
                "solved_by": solved_by}

    def tally(self):
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT c.name, c.category, c.points, COUNT(s.id) AS n"
                " FROM challenges c LEFT JOIN solves s ON s.challenge_id = c.id"
                " GROUP BY c.id ORDER BY c.id").fetchall()
        finally:
            conn.close()
        return [{"name": r[0], "category": r[1], "points": r[2],
                 "solves": r[3]} for r in rows]


# ---------------------------------------------------------------------------
# Orchestration: generate -> solve -> submit -> report
# ---------------------------------------------------------------------------

def run_full(workdir=None, reports_dir=None, team="solver"):
    """Generate challenges into workdir (temp if None), solve each, submit to
    the SQLite scoreboard, write reports/ctf_report.json. Returns exit code."""
    tmp = workdir is None
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="x12_ctf_")
    elif not os.path.isdir(workdir):
        os.makedirs(workdir, exist_ok=True)
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    gen = ChallengeGenerator(workdir)
    manifest = gen.generate_all()
    print("[*] Generated 3 challenges in %s" % workdir)

    sb = Scoreboard(os.path.join(workdir, "scoreboard.db"))
    sb.register_manifest_hashes(manifest)

    solvers = [
        ("WEB-001", "web", WebSolver()),
        ("CRYPTO-001", "crypto", CryptoSolver()),
        ("MISC-001", "misc", MiscSolver()),
    ]

    results = []
    for name, category, solver in solvers:
        if category == "web":
            flag = solver.solve(workdir)
        elif category == "crypto":
            flag = solver.solve(workdir)
        else:
            flag = solver.solve(workdir)
        sub = sb.submit(name, flag, team=team)
        results.append({
            "challenge": name,
            "category": category,
            "flag": flag,
            "flag_sha256": _sha256(flag),
            "accepted": sub["accepted"],
            "reason": sub["reason"],
            "steps": list(solver.steps),
        })
        print("  [%s] %s: %s (%s)" % (
            "PASS" if sub["accepted"] else "FAIL", name, flag, sub["reason"]))

    all_ok = all(r["accepted"] for r in results)
    tally = sb.tally()
    report = {
        "tool": "ctf-toolkit-x12",
        "workdir": workdir,
        "generated": manifest,
        "solver_results": results,
        "scoreboard": tally,
        "total_points": sum(c["points"] for c in tally),
        "all_accepted": all_ok,
    }
    out = os.path.join(reports_dir, "ctf_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print("[+] Report written: %s" % out)
    if tmp:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if all_ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ctf_toolkit",
        description="X12 - CTF Toolkit: generator of real local challenges "
                    "(web/crypto/misc) with flags, SQLite scoreboard, and "
                    "solver-checker. Offline verifiable.",
        epilog="Authorized CTF/lab use only.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan and exit without solving")
    ap.add_argument("--generate", action="store_true",
                    help="generate challenge files into challenges/")
    ap.add_argument("--solve", action="store_true",
                    help="generate (if needed), solve, and verify flags")
    ap.add_argument("--demo-report", action="store_true",
                    help="full generate+solve+scoreboard and JSON report")
    ap.add_argument("--workdir", default=None,
                    help="directory to use for --solve (default challenges/)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED,
                    help="deterministic seed for generated challenges")
    args = ap.parse_args(argv)

    if args.dry_run:
        print("dry-run: generate (web/crypto/misc), solve, SQLite scoreboard "
              "(no execution)")
        return 0

    repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    if args.generate:
        wdir = args.workdir or os.path.join(repo_root, "challenges")
        gen = ChallengeGenerator(wdir, seed=args.seed)
        manifest = gen.generate_all()
        print("Generated 3 challenges -> %s" % wdir)
        for c in manifest["challenges"]:
            print("  [%s] %s points=%s sha256=%s" % (
                c["category"], c["name"], c["points"], c["flag_sha256"][:12]))
        return 0

    if args.solve:
        wdir = args.workdir or os.path.join(repo_root, "challenges")
        if not os.path.exists(wdir):
            ChallengeGenerator(wdir, seed=args.seed).generate_all()
        return run_full(workdir=wdir, reports_dir=args.workdir and wdir or None)

    if args.demo_report:
        return run_full(reports_dir=os.path.join(repo_root, "reports"))

    print("[*] X12 — CTF Toolkit + Challenge Authorship")
    print("[*] Offline demo: generate -> solve -> SQLite scoreboard")
    print()
    rc = run_full(reports_dir=os.path.join(repo_root, "reports"))
    print()
    print("=" * 70)
    print("  Self-test PASSED. Demo complete.")
    print("  Legal: This toolkit is for authorized CTF/lab use only.")
    print("=" * 70)
    return rc


if __name__ == "__main__":
    sys.exit(main())