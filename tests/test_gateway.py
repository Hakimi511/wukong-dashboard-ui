from __future__ import annotations

import base64
import hashlib
import http.client
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
import sys
import secrets

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.server import GatewayConfig, handler_factory
from http.server import ThreadingHTTPServer


def test_password_hash(password: str) -> str:
    rounds = 200_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return f"pbkdf2_sha256${rounds}${encode(salt)}${encode(digest)}"


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.ui = root / "ui"
        self.dashboard = root / "dashboard_local"
        (self.ui).mkdir()
        (self.dashboard / "data").mkdir(parents=True)
        (self.dashboard / "reports").mkdir()
        (root / "output").mkdir()
        (root / "data" / "historical_longwave").mkdir(parents=True)
        (self.ui / "index.html").write_text("<h1>private ui</h1>", encoding="utf-8")
        (self.ui / "styles.css").write_text("body{}", encoding="utf-8")
        (self.dashboard / "data" / "factor_workbench.json").write_text('{"read_only":true}', encoding="utf-8")
        ledger = self.dashboard / "data" / "wukong_shadow.db"
        connection = sqlite3.connect(ledger)
        try:
            connection.execute("CREATE TABLE trade_ledger (trade_date TEXT, ticker TEXT, quantity INTEGER)")
            connection.execute("INSERT INTO trade_ledger VALUES ('2026-09-01', 'TEST.TICKER', 100)")
            connection.commit()
        finally:
            connection.close()
        (self.dashboard / "reports" / "report.pdf").write_bytes(b"%PDF-demo")
        (self.dashboard / "reports" / "report.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (root / "output" / "evidence.csv").write_text("a,b\n1,2\n", encoding="utf-8")
        (root / "output" / "deployment-secret.txt").write_text("must never be served", encoding="utf-8")
        (root / "data" / "historical_longwave" / "benchmark.csv").write_text("date,value\n2026-01-01,1\n", encoding="utf-8")
        self.test_password = secrets.token_urlsafe(24)
        self.reviewer_password = secrets.token_urlsafe(24)
        self.config = GatewayConfig(
            ui_root=self.ui,
            dashboard_root=self.dashboard,
            users={
                "liyilin": test_password_hash(self.test_password),
                "reviewer": test_password_hash(self.reviewer_password),
            },
            session_secret=secrets.token_bytes(32),
            secure_cookie=False,
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(self.config))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def request(self, method: str, path: str, body: str = "", headers: dict[str, str] | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        connection.close()
        return result

    def test_every_content_family_requires_login(self) -> None:
        for path in ("/", "/styles.css", "/api/production/factor_workbench.json", "/api/ledger/tables", "/reports/report.pdf", "/reports/report.png", "/output/evidence.csv", "/data/historical_longwave/benchmark.csv"):
            with self.subTest(path=path):
                status, headers, _ = self.request("GET", path)
                self.assertEqual(status, 303)
                self.assertTrue(headers["Location"].startswith("/login?next="))

    def test_login_sets_secure_session_and_allows_protected_files(self) -> None:
        form = urlencode({"username": "liyilin", "password": self.test_password})
        status, headers, _ = self.request("POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        session_cookie = cookie.split(";", 1)[0]
        for path in ("/", "/api/production/factor_workbench.json", "/api/ledger/tables", "/reports/report.pdf", "/reports/report.png", "/output/evidence.csv", "/data/historical_longwave/benchmark.csv"):
            with self.subTest(path=path):
                status, response_headers, body = self.request("GET", path, headers={"Cookie": session_cookie})
                self.assertEqual(status, 200)
                self.assertEqual(response_headers["Cache-Control"], "no-store, max-age=0")
                self.assertIn("noindex", response_headers["X-Robots-Tag"])
                self.assertTrue(body)

        status, _, body = self.request("GET", "/api/ledger/table/trade_ledger?limit=1", headers={"Cookie": session_cookie})
        self.assertEqual(status, 200)
        self.assertIn(b"TEST.TICKER", body)

    def test_each_configured_account_gets_its_own_session(self) -> None:
        form = urlencode({"username": "reviewer", "password": self.reviewer_password})
        status, headers, _ = self.request("POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 303)
        status, _, body = self.request("GET", "/", headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(status, 200)
        self.assertIn(b"private ui", body)

        self.config.users.pop("reviewer")
        status, headers, _ = self.request("GET", "/", headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(status, 303)

    def test_database_and_cross_origin_login_are_rejected(self) -> None:
        form = urlencode({"username": "liyilin", "password": self.test_password})
        status, _, _ = self.request("POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://wrong.example"})
        self.assertEqual(status, 403)
        status, headers, _ = self.request("POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 303)
        status, _, _ = self.request("GET", "/dashboard_local/data/wukong_shadow.db", headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(status, 404)
        status, _, _ = self.request("GET", "/output/deployment-secret.txt", headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
