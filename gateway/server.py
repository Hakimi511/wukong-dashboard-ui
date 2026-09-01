"""Small dependency-free, server-side authenticated read-only gateway.

The gateway deliberately keeps the source UI separate from the local data
root. It serves only approved file classes and refuses direct database files.
All non-login content is authenticated before route resolution.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import mimetypes
import os
import posixpath
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit


SESSION_TTL = 8 * 60 * 60
LOCKOUT_SECONDS = 15 * 60
MAX_LOGIN_BODY = 8 * 1024
ALLOWED_EXTENSIONS = {".html", ".css", ".js", ".json", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".txt"}
SENSITIVE_PATH_TOKENS = ("credential", "secret", "password", "token", "api_key", "apikey", "private_key", "id_rsa")
FORMAL_LEDGER_TABLES = frozenset({"data_snapshot", "ledger_meta", "nav_daily", "position_daily", "trade_ledger"})
MAX_LEDGER_PAGE_SIZE = 2_000


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds_text, salt_text, digest_text = encoded.split("$", 3)
        rounds = int(rounds_text)
        if algorithm != "pbkdf2_sha256" or rounds < 200_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError, UnicodeError):
        return False


@dataclass
class GatewayConfig:
    ui_root: Path
    dashboard_root: Path
    users: dict[str, str]
    session_secret: bytes
    public_origin: str | None = None
    secure_cookie: bool = True
    session_ttl: int = SESSION_TTL
    sessions: dict[str, tuple[str, float]] = field(default_factory=dict)
    attempts: defaultdict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    locked_until: dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.ui_root = self.ui_root.resolve()
        self.dashboard_root = self.dashboard_root.resolve()
        if not self.users or not self.session_secret:
            raise ValueError("at least one user and a session secret are required")
        if not all(isinstance(name, str) and isinstance(encoded, str) for name, encoded in self.users.items()):
            raise ValueError("every account must use string username and password-hash values")
        if any(not name.strip() or not encoded.strip() for name, encoded in self.users.items()):
            raise ValueError("every account needs a non-empty username and password hash")

    @property
    def project_root(self) -> Path:
        return self.dashboard_root.parent

    def login_allowed(self, client: str, now: float | None = None) -> bool:
        now = now or time.time()
        with self.lock:
            if self.locked_until.get(client, 0) > now:
                return False
            attempts = self.attempts[client]
            while attempts and attempts[0] <= now - LOCKOUT_SECONDS:
                attempts.popleft()
            return len(attempts) < 5

    def login_failure(self, client: str, now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            attempts = self.attempts[client]
            attempts.append(now)
            if len(attempts) >= 5:
                self.locked_until[client] = now + LOCKOUT_SECONDS

    def login_success(self, client: str) -> None:
        with self.lock:
            self.attempts.pop(client, None)
            self.locked_until.pop(client, None)

    def issue_session(self, username: str) -> str:
        session_id = secrets.token_urlsafe(32)
        expires = int(time.time() + self.session_ttl)
        payload = f"{session_id}.{expires}".encode("ascii")
        signature = hmac.new(self.session_secret, payload, hashlib.sha256).hexdigest()
        with self.lock:
            self.sessions[session_id] = (username, float(expires))
        return f"{session_id}.{expires}.{signature}"

    def valid_session(self, cookie_value: str | None) -> bool:
        if not cookie_value:
            return False
        parts = cookie_value.split(".")
        if len(parts) != 3:
            return False
        session_id, expires_text, signature = parts
        try:
            expires = int(expires_text)
        except ValueError:
            return False
        if expires < time.time():
            return False
        payload = f"{session_id}.{expires}".encode("ascii")
        expected = hmac.new(self.session_secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        with self.lock:
            session = self.sessions.get(session_id)
            if not session or session[0] not in self.users or session[1] < time.time():
                self.sessions.pop(session_id, None)
                return False
        return True

    def revoke_cookie(self, cookie_value: str | None) -> None:
        if cookie_value:
            session_id = cookie_value.split(".", 1)[0]
            with self.lock:
                self.sessions.pop(session_id, None)


def safe_relative_path(raw: str) -> str | None:
    decoded = raw.replace("\\", "/")
    if "\x00" in decoded:
        return None
    if any(part == ".." for part in decoded.split("/")):
        return None
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    if normalized.startswith("/../") or normalized == "/..":
        return None
    return normalized.lstrip("/")


def contained(root: Path, relative: str) -> Path | None:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


def is_database_path(path: Path) -> bool:
    return path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} or path.name.lower().endswith("shadow.db")


def is_sensitive_path(relative: str) -> bool:
    filename = Path(relative).name.lower()
    return filename.startswith(".env") or any(token in filename for token in SENSITIVE_PATH_TOKENS)


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    server_version = "WukongReadOnlyGateway/1.0"
    config: GatewayConfig

    def log_message(self, format: str, *args: object) -> None:
        # Do not log request bodies, cookies, query values, or credentials.
        print(f"{self.client_address[0]} - {format % args}")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _headers(self, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def _send_bytes(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self._headers(content_type)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self._headers()
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _cookie_value(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            name, _, value = item.strip().partition("=")
            if name == "wukong_session":
                return value
        return None

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if self.config.public_origin:
            return origin == self.config.public_origin
        if origin is None:
            return True
        host = self.headers.get("Host", "")
        return origin in {f"http://{host}", f"https://{host}"}

    def _login_page(self, error: str = "") -> bytes:
        message = f'<p class="error">{error}</p>' if error else ""
        page = ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>悟空后台登录</title><style>body{font-family:system-ui;background:#0b1118;color:#e6edf3;display:grid;place-items:center;min-height:100vh;margin:0}.box{width:min(360px,calc(100% - 40px));padding:26px;border:1px solid #2a3b50;border-radius:12px;background:#111b27}label{display:grid;gap:6px;margin:14px 0;color:#9fb0c1;font-size:13px}input{padding:10px;border:1px solid #344a61;border-radius:7px;background:#0b1118;color:#fff}button{width:100%;padding:10px;border:0;border-radius:7px;background:#3788d8;color:#fff;cursor:pointer}.error{color:#ff8f8f;font-size:13px}</style></head><body><main class=\"box\"><h1>悟空质量价值</h1><p>生产后台需要登录。数据为只读展示。</p>{message}<form method=\"post\" action=\"/login\"><label>账号<input name=\"username\" autocomplete=\"username\" required></label><label>密码<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label><button type=\"submit\">登录</button></form></main></body></html>").encode("utf-8")
        return page.replace(b"{message}", message.encode("utf-8"))

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path or "/"
        if path == "/healthz":
            self._send_bytes(200, b"ok\n")
            return
        if path == "/login":
            if method == "GET":
                self._send_bytes(200, self._login_page(), "text/html; charset=utf-8")
            elif method == "POST":
                self._login()
            else:
                self._send_bytes(405)
            return
        if path == "/logout":
            if method == "POST" or method == "GET":
                self.config.revoke_cookie(self._cookie_value())
                self._send_bytes(303, b"", extra={"Location": "/login", "Set-Cookie": self._expired_cookie()})
            else:
                self._send_bytes(405)
            return
        if not self.config.valid_session(self._cookie_value()):
            next_path = quote(path, safe="/._-~")
            self._redirect(f"/login?next={next_path}")
            return
        if method != "GET" and method != "HEAD":
            self._send_bytes(405)
            return
        if path == "/api/ledger/tables":
            self._serve_ledger_tables()
            return
        if path.startswith("/api/ledger/table/"):
            self._serve_ledger_rows(path[len("/api/ledger/table/"):])
            return
        target = self._route(path)
        if target is None or not target.is_file():
            self._send_bytes(404, b"not found\n")
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self._send_bytes(200, target.read_bytes(), f"{content_type}; charset=utf-8" if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"} else content_type)

    def _formal_ledger_connection(self) -> sqlite3.Connection | None:
        ledger = self.config.dashboard_root / "data" / "wukong_shadow.db"
        if not ledger.is_file():
            return None
        connection = sqlite3.connect(ledger.resolve().as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _send_json(self, payload: object, status: int = 200) -> None:
        def json_default(value: object) -> str | dict[str, str]:
            if isinstance(value, bytes):
                return {"base64": base64.b64encode(value).decode("ascii")}
            return str(value)

        body = json.dumps(payload, ensure_ascii=False, default=json_default, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _serve_ledger_tables(self) -> None:
        try:
            connection = self._formal_ledger_connection()
            if connection is None:
                self._send_bytes(404, b"formal ledger not found\n")
                return
            with connection:
                available = {
                    row[0]
                    for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
                }
                tables = []
                for name in sorted(FORMAL_LEDGER_TABLES & available):
                    quoted = name.replace('"', '""')
                    count = connection.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0]
                    columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")')]
                    tables.append({"name": name, "row_count": count, "columns": columns})
            self._send_json({"source": "formal_ledger", "read_only": True, "tables": tables})
        except sqlite3.Error:
            self._send_bytes(503, b"formal ledger temporarily unavailable\n")
        finally:
            if "connection" in locals() and connection is not None:
                connection.close()

    def _serve_ledger_rows(self, table: str) -> None:
        if table not in FORMAL_LEDGER_TABLES:
            self._send_bytes(404, b"not found\n")
            return
        query = parse_qs(urlsplit(self.path).query)
        try:
            limit = min(max(int(query.get("limit", ["500"])[0]), 1), MAX_LEDGER_PAGE_SIZE)
            offset = max(int(query.get("offset", ["0"])[0]), 0)
        except ValueError:
            self._send_bytes(400, b"limit and offset must be integers\n")
            return
        try:
            connection = self._formal_ledger_connection()
            if connection is None:
                self._send_bytes(404, b"formal ledger not found\n")
                return
            with connection:
                available = {
                    row[0]
                    for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
                }
                if table not in available:
                    self._send_bytes(404, b"not found\n")
                    return
                quoted = table.replace('"', '""')
                columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")')]
                rows = [dict(row) for row in connection.execute(f'SELECT * FROM "{quoted}" LIMIT ? OFFSET ?', (limit, offset))]
            self._send_json({
                "source": "formal_ledger",
                "read_only": True,
                "table": table,
                "columns": columns,
                "limit": limit,
                "offset": offset,
                "returned_rows": len(rows),
                "rows": rows,
            })
        except sqlite3.Error:
            self._send_bytes(503, b"formal ledger temporarily unavailable\n")
        finally:
            if "connection" in locals() and connection is not None:
                connection.close()

    def _login(self) -> None:
        if not self._origin_ok():
            self._send_bytes(403, b"origin rejected\n")
            return
        length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_LOGIN_BODY + 1)
        body = self.rfile.read(length)
        if length > MAX_LOGIN_BODY:
            self._send_bytes(413, b"request too large\n")
            return
        fields = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]
        client = self.client_address[0]
        if not self.config.login_allowed(client):
            self._send_bytes(429, b"too many attempts\n")
            return
        password_hash = self.config.users.get(username)
        valid = password_hash is not None and verify_password(password, password_hash)
        if not valid:
            self.config.login_failure(client)
            self._send_bytes(401, self._login_page("账号或密码不正确"), "text/html; charset=utf-8")
            return
        self.config.login_success(client)
        cookie = self._session_cookie(self.config.issue_session(username))
        self._send_bytes(303, b"", extra={"Location": "/", "Set-Cookie": cookie})

    def _session_cookie(self, value: str) -> str:
        secure = "; Secure" if self.config.secure_cookie else ""
        return f"wukong_session={value}; Path=/; Max-Age={self.config.session_ttl}; HttpOnly; SameSite=Strict{secure}"

    def _expired_cookie(self) -> str:
        secure = "; Secure" if self.config.secure_cookie else ""
        return f"wukong_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}"

    def _route(self, path: str) -> Path | None:
        relative = safe_relative_path(path)
        if relative is None:
            return None
        lower = relative.lower()
        if lower.endswith((".db", ".sqlite", ".sqlite3")):
            return None
        if is_sensitive_path(relative):
            return None
        if path == "/":
            return contained(self.config.ui_root, "index.html")
        if path.startswith("/api/production/"):
            data_relative = safe_relative_path(path[len("/api/production/"):])
            if not data_relative or Path(data_relative).suffix.lower() not in ALLOWED_EXTENSIONS:
                return None
            return contained(self.config.dashboard_root / "data", data_relative)
        if path.startswith("/dashboard_local/"):
            if Path(relative).suffix.lower() not in ALLOWED_EXTENSIONS:
                return None
            return contained(self.config.dashboard_root.parent, relative)
        if path.startswith("/reports/"):
            if Path(relative).suffix.lower() not in ALLOWED_EXTENSIONS:
                return None
            return contained(self.config.dashboard_root, relative)
        if path.startswith("/output/"):
            if Path(relative).suffix.lower() not in ALLOWED_EXTENSIONS:
                return None
            return contained(self.config.project_root, relative)
        if path.startswith("/data/historical_longwave/"):
            if Path(relative).suffix.lower() not in ALLOWED_EXTENSIONS:
                return None
            return contained(self.config.project_root, relative)
        if Path(relative).suffix.lower() not in ALLOWED_EXTENSIONS:
            return None
        return contained(self.config.ui_root, relative)


def handler_factory(config: GatewayConfig):
    class ConfiguredGatewayHandler(GatewayHandler):
        pass

    ConfiguredGatewayHandler.config = config
    return ConfiguredGatewayHandler


def load_users_from_environment() -> dict[str, str]:
    """Load individual accounts without ever putting hashes in source control.

    WUKONG_DASHBOARD_USERS_JSON is a deployment Secret containing a JSON object
    that maps each username to its PBKDF2 hash. The legacy two-variable form is
    kept only for a single owner account during an initial local setup.
    """
    encoded_users = os.environ.get("WUKONG_DASHBOARD_USERS_JSON", "").strip()
    if encoded_users:
        try:
            users = json.loads(encoded_users)
        except json.JSONDecodeError as exc:
            raise ValueError("WUKONG_DASHBOARD_USERS_JSON must be valid JSON") from exc
        if not isinstance(users, dict) or not all(isinstance(name, str) and isinstance(value, str) for name, value in users.items()):
            raise ValueError("WUKONG_DASHBOARD_USERS_JSON must map usernames to password hashes")
        return users

    username = os.environ.get("WUKONG_DASHBOARD_USERNAME", "liyilin")
    password_hash = os.environ.get("WUKONG_DASHBOARD_PASSWORD_HASH", "")
    return {username: password_hash}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wukong server-side authenticated read-only gateway")
    parser.add_argument("--ui-root", type=Path, default=Path(__file__).resolve().parents[1] / "public")
    parser.add_argument("--dashboard-root", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--origin", default=os.environ.get("WUKONG_DASHBOARD_ORIGIN"))
    parser.add_argument("--insecure-localhost", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = GatewayConfig(
        ui_root=args.ui_root,
        dashboard_root=args.dashboard_root,
        users=load_users_from_environment(),
        session_secret=os.environ.get("WUKONG_SESSION_SECRET", "").encode("utf-8"),
        public_origin=args.origin,
        secure_cookie=not args.insecure_localhost,
    )
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler_factory(config))
    print(f"Wukong gateway listening on {args.bind}:{args.port}; source data remains local and read-only")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
