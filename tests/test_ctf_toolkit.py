#!/usr/bin/env python3
"""Tests for X12 - CTF Toolkit (real generator / solvers / SQLite scoreboard)."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

FIRMWARE = os.path.join(os.path.dirname(__file__), os.pardir, "firmware")
ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
if FIRMWARE not in sys.path:
    sys.path.insert(0, FIRMWARE)

from ctf_toolkit import (                                  # noqa: E402
    ChallengeGenerator, WebSolver, CryptoSolver, MiscSolver,
    Scoreboard, _sha256, DEFAULT_SEED,
)


def make_workdir():
    return tempfile.mkdtemp(prefix="x12_test_")


class TestGenerator(unittest.TestCase):
    def setUp(self):
        self.wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(self.wd, ignore_errors=True))

    def test_generates_all_artifacts(self):
        gen = ChallengeGenerator(self.wd, seed=DEFAULT_SEED)
        manifest = gen.generate_all()
        self.assertIn("web_app.py", os.listdir(self.wd))
        self.assertIn("crypto_flag.enc", os.listdir(self.wd))
        self.assertIn("misc_drive.img", os.listdir(self.wd))
        self.assertEqual(len(manifest["challenges"]), 3)
        self.assertIn("manifest.json", os.listdir(self.wd))

    def test_manifest_has_no_plaintext_flags(self):
        gen = ChallengeGenerator(self.wd, seed=DEFAULT_SEED)
        manifest = gen.generate_all()
        raw = json.dumps(manifest)
        self.assertNotIn("FLAG{", raw)
        for c in manifest["challenges"]:
            self.assertEqual(len(c["flag_sha256"]), 64)

    def test_generated_web_file_is_runnable_source(self):
        gen = ChallengeGenerator(self.wd, seed=DEFAULT_SEED)
        gen.generate_all()
        with open(os.path.join(self.wd, "web_app.py")) as f:
            src = f.read()
        self.assertIn("BaseHTTPRequestHandler", src)
        self.assertIn("make_server", src)

    def test_deterministic_with_seed(self):
        wd2 = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd2, ignore_errors=True))
        m1 = ChallengeGenerator(self.wd, seed=42).generate_all()
        m2 = ChallengeGenerator(wd2, seed=42).generate_all()
        self.assertEqual([c["flag_sha256"] for c in m1["challenges"]],
                         [c["flag_sha256"] for c in m2["challenges"]])


class TestWebSolver(unittest.TestCase):
    def test_solves_via_real_http(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        ChallengeGenerator(wd, seed=DEFAULT_SEED).generate_all()
        solver = WebSolver()
        flag = solver.solve(wd)
        self.assertTrue(flag.startswith("FLAG{"))
        self.assertGreater(len(solver.steps), 0)

    def test_unknown_token_rejected(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        ChallengeGenerator(wd, seed=DEFAULT_SEED).generate_all()
        # wrong token must not return the flag through the live server
        with open(os.path.join(wd, "web_app.py")) as f:
            src = f.read()
        ns = {"__file__": os.path.join(wd, "web_app.py"),
              "__name__": "x12_web_challenge"}
        exec(src, ns)
        srv = ns["make_server"](0)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            import urllib.request
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/admin?token=wrong" % port, timeout=5).read()
                body = b""
            except Exception as exc:
                body = getattr(exc, "read", lambda: b"")() or str(exc).encode()
            self.assertNotIn(b"FLAG{", body)
        finally:
            srv.shutdown()
            srv.server_close()


class TestCryptoSolver(unittest.TestCase):
    def test_recovering_xor_key_yields_flag(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        ChallengeGenerator(wd, seed=DEFAULT_SEED).generate_all()
        solver = CryptoSolver()
        flag = solver.solve(wd)
        self.assertTrue(flag.startswith("FLAG{"))
        self.assertEqual(flag, "FLAG{crypto_repeat_key_xor_knwn_pt}")

    def test_ciphertext_is_real_xor(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        ChallengeGenerator(wd, seed=DEFAULT_SEED).generate_all()
        import base64
        with open(os.path.join(wd, "crypto_flag.enc")) as f:
            cipher = base64.b64decode(f.read().strip())
        plain = b"FLAG{crypto_repeat_key_xor_knwn_pt}"
        # key = plain xor cipher for the first 5 bytes; must decrypt the whole
        key = bytes(cipher[i] ^ plain[i] for i in range(5))
        self.assertGreater(min(key), 0x20)  # printable key, not all-null
        decoded = bytes(cipher[i] ^ key[i % 5] for i in range(len(cipher)))
        self.assertEqual(decoded, plain)


class TestMiscSolver(unittest.TestCase):
    def test_carves_flag_from_image(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        ChallengeGenerator(wd, seed=DEFAULT_SEED).generate_all()
        solver = MiscSolver()
        flag = solver.solve(wd)
        self.assertEqual(flag, "FLAG{misc_carve_the_disk_image}")
        self.assertGreater(len(solver.steps), 0)


class TestScoreboard(unittest.TestCase):
    def setUp(self):
        self.wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(self.wd, ignore_errors=True))
        self.db = os.path.join(self.wd, "scoreboard.db")

    def test_accepts_correct_flag(self):
        sb = Scoreboard(self.db)
        sb.register_hash("WEB-001", "web", 100, _sha256("FLAG{correct}"))
        res = sb.submit("WEB-001", "FLAG{correct}")
        self.assertTrue(res["accepted"])
        self.assertEqual(res["points"], 100)
        self.assertIn("scoreboard.db", os.listdir(self.wd))

    def test_rejects_wrong_flag(self):
        sb = Scoreboard(self.db)
        sb.register_hash("WEB-001", "web", 100, _sha256("FLAG{correct}"))
        res = sb.submit("WEB-001", "FLAG{wrong}")
        self.assertFalse(res["accepted"])

    def test_duplicate_solve_not_rewritten(self):
        sb = Scoreboard(self.db)
        sb.register_hash("MISC-001", "misc", 100, _sha256("FLAG{m}"))
        self.assertTrue(sb.submit("MISC-001", "FLAG{m}")["accepted"])
        res = sb.submit("MISC-001", "FLAG{m}")
        self.assertFalse(res["accepted"])
        self.assertEqual(res["reason"], "already solved")

    def test_unknown_challenge_rejected(self):
        sb = Scoreboard(self.db)
        res = sb.submit("GHOST", "FLAG{x}")
        self.assertFalse(res["accepted"])

    def test_tally_counts_solves(self):
        sb = Scoreboard(self.db)
        sb.register_hash("A", "web", 100, _sha256("FLAG{a}"))
        sb.register_hash("B", "crypto", 150, _sha256("FLAG{b}"))
        sb.submit("A", "FLAG{a}")
        rows = {r["name"]: r for r in sb.tally()}
        self.assertEqual(rows["A"]["solves"], 1)
        self.assertEqual(rows["B"]["solves"], 0)

    def test_challenge_score_lookup(self):
        sb = Scoreboard(self.db)
        sb.register_hash("WEB-001", "web", 100, _sha256("FLAG{x}"))
        score = sb.challenge_score("WEB-001")
        self.assertEqual(score["points"], 100)
        self.assertEqual(score["flag_sha256"], _sha256("FLAG{x}"))
        self.assertIsNone(sb.challenge_score("NOPE"))


class TestDemo(unittest.TestCase):
    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py")],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Self-test PASSED", r.stdout)
        self.assertEqual(r.stdout.count("flag accepted"), 3)


class TestCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py"), "--help"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("CTF", r.stdout)

    def test_dry_run(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py"), "--dry-run"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)

    def test_generate(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py"),
             "--generate", "--workdir", wd],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(wd, "manifest.json")))

    def test_solve_end_to_end(self):
        wd = make_workdir()
        self.addCleanup(lambda: shutil.rmtree(wd, ignore_errors=True))
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py"),
             "--solve", "--workdir", wd],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.count("flag accepted"), 3)
        db = os.path.join(wd, "scoreboard.db")
        self.assertTrue(os.path.exists(db))
        conn = sqlite3.connect(db)
        try:
            n = conn.execute("SELECT COUNT(*) FROM solves").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 3)

    def test_demo_report(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "ctf_toolkit.py"),
             "--demo-report"],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        report = os.path.join(ROOT, "reports", "ctf_report.json")
        self.assertTrue(os.path.exists(report))


class TestPyCompile(unittest.TestCase):
    def test_compile(self):
        r = subprocess.run(
            [sys.executable, "-m", "py_compile",
             os.path.join(FIRMWARE, "ctf_toolkit.py")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()