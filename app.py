import os
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import sqlite3
import threading
from datetime import datetime
from functools import wraps
import secrets
import smtplib
import json
import html
from email.message import EmailMessage
import requests

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

# ✅ Risk Engine (risk_engine.py beside app.py)
from risk_engine import parse_auth_results, build_email_result

# -----------------------------
# Load .env (backend keys)
# -----------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()  # loads VT_API_KEY / GSB_API_KEY / ABUSEIPDB_API_KEY / IPINFO_TOKEN, etc.
except Exception:
    pass

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, send_file, Response
)

# -----------------------------
# Core (LOCKED modules stay imported)
# -----------------------------
from core.pass_strength_core import password_report
from core.file_scanner_core import scan_file_path
from core.crypto_core import encrypt_upload_to_file, decrypt_upload_to_file, peek_encrypted_metadata
from ai.ai_email_analyzer import analyze_email_ai
from core.gmail_core import (
    gmail_is_configured,
    gmail_get_auth_url,
    gmail_handle_callback,
    gmail_list_inbox,
    gmail_get_message,
    gmail_scan_message,
    gmail_disconnect,
    gmail_get_profile,
    gmail_set_star,
    gmail_archive,
    gmail_unarchive,
    gmail_trash,
    gmail_untrash,
    gmail_reply,
    gmail_forward,
)

# Advanced scan is optional; never break Gmail flow
try:
    from core.gmail_advscan import run_advanced_scan_layers
except Exception:
    run_advanced_scan_layers = None

# -----------------------------
# Enterprise Services (new intelligence layer)
# -----------------------------
try:
    from services.url_intel import analyze_url_intel
    from services.ip_intel import analyze_ip_intel
except Exception:
    analyze_url_intel = None
    analyze_ip_intel = None

# ✅ Production Email Header Analyzer
try:
    from core.header_core import analyze_headers as analyze_header_forensics
except Exception as e:
    print("Header analyzer import failed:", e)
    analyze_header_forensics = None

# -----------------------------
# Optional: Rate limiting (do not hard-fail if not installed)
# -----------------------------
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None

# -----------------------------
# Optional: Security logging
# -----------------------------
import logging
try:
    from logging.handlers import RotatingFileHandler
except Exception:
    RotatingFileHandler = None

# ✅ Quick File Scanner (upload-based)
import re
import uuid
import math
import hashlib
import mimetypes
import tempfile
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

TOKEN_PATH = BASE_DIR / "token.json"
FORCED_REDIRECT_URI = "http://127.0.0.1:5000/oauth2callback"

# -----------------------------
# Auth Database (SQLite)
# -----------------------------
AUTH_DB_PATH = BASE_DIR / "auth.db"


def _auth_init():
    try:
        con = sqlite3.connect(str(AUTH_DB_PATH))
        cur = con.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                reset_token TEXT,
                reset_token_expiry INTEGER,
                created_at INTEGER NOT NULL,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                is_locked INTEGER DEFAULT 0,
                failed_login_count INTEGER DEFAULT 0,
                last_login_ts INTEGER,
                last_password_change_ts INTEGER
            )
            """
        )

        for stmt in [
            "ALTER TABLE users ADD COLUMN reset_token TEXT",
            "ALTER TABLE users ADD COLUMN reset_token_expiry INTEGER",
            "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
            "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN is_locked INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN last_login_ts INTEGER",
            "ALTER TABLE users ADD COLUMN last_password_change_ts INTEGER",
        ]:
            try:
                cur.execute(stmt)
            except Exception:
                pass

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_name TEXT,
                email TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                status TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
            """
        )
        # Existing auth.db files may have an older login_activity schema.
        # Add missing columns safely so admin stats/activity do not fail.
        for stmt in [
            "ALTER TABLE login_activity ADD COLUMN user_id INTEGER",
            "ALTER TABLE login_activity ADD COLUMN user_name TEXT",
            "ALTER TABLE login_activity ADD COLUMN email TEXT",
            "ALTER TABLE login_activity ADD COLUMN action TEXT DEFAULT 'UNKNOWN'",
            "ALTER TABLE login_activity ADD COLUMN ip_address TEXT",
            "ALTER TABLE login_activity ADD COLUMN status TEXT DEFAULT 'UNKNOWN'",
            "ALTER TABLE login_activity ADD COLUMN ts INTEGER DEFAULT 0",
        ]:
            try:
                cur.execute(stmt)
            except Exception:
                pass

        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_login_activity_ts ON login_activity(ts)")
        except Exception:
            pass

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_email TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                details TEXT,
                ip_address TEXT,
                status TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
            """
        )
        # Existing auth.db files may also have an older admin audit schema.
        for stmt in [
            "ALTER TABLE admin_audit_log ADD COLUMN admin_email TEXT",
            "ALTER TABLE admin_audit_log ADD COLUMN action TEXT DEFAULT 'UNKNOWN'",
            "ALTER TABLE admin_audit_log ADD COLUMN target_type TEXT",
            "ALTER TABLE admin_audit_log ADD COLUMN target_id TEXT",
            "ALTER TABLE admin_audit_log ADD COLUMN details TEXT",
            "ALTER TABLE admin_audit_log ADD COLUMN ip_address TEXT",
            "ALTER TABLE admin_audit_log ADD COLUMN status TEXT DEFAULT 'UNKNOWN'",
            "ALTER TABLE admin_audit_log ADD COLUMN ts INTEGER DEFAULT 0",
        ]:
            try:
                cur.execute(stmt)
            except Exception:
                pass

        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(ts)")
        except Exception:
            pass

        con.commit()
        con.close()
    except Exception:
        pass


_auth_init()


def _auth_db():
    con = sqlite3.connect(str(AUTH_DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def _get_admin_emails():
    raw = []
    for key in ("PRIVGUARD_ADMIN_EMAILS", "ADMIN_EMAILS", "ADMIN_EMAIL"):
        value = (os.environ.get(key) or "").strip()
        if value:
            raw.extend([x.strip().lower() for x in value.split(",") if x.strip()])
    return set(raw)

def _metrics_db():
    con = sqlite3.connect(str(METRICS_DB_PATH))
    con.row_factory = sqlite3.Row
    return con

def _table_columns(con, table_name: str) -> set:
    try:
        rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(r["name"]) for r in rows}
    except Exception:
        return set()


def _pick_column(columns: set, candidates):
    for c in candidates:
        if c in columns:
            return c
    return None

def _ensure_user_role(email: str):
    email = (email or "").strip().lower()
    if not email:
        return
    role = "admin" if email in _get_admin_emails() else "user"
    try:
        con = _auth_db()
        cur = con.cursor()
        cur.execute("UPDATE users SET role=? WHERE lower(email)=lower(?)", (role, email))
        con.commit()
        con.close()
    except Exception:
        pass


def _client_ip():
    try:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
        return (request.remote_addr or "")[:64]
    except Exception:
        return ""


def _log_login_activity(user_id, user_name: str, email: str, action: str, status: str):
    try:
        con = _auth_db()
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO login_activity (user_id, user_name, email, action, ip_address, status, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(user_id) if user_id else None,
                (user_name or "")[:120],
                (email or "")[:255],
                (action or "UNKNOWN")[:80],
                _client_ip(),
                (status or "UNKNOWN")[:32],
                int(time.time()),
            ),
        )
        con.commit()
        con.close()
    except Exception:
        pass




def _log_admin_audit(action: str, status: str = "SUCCESS", target_type: str = "", target_id: str = "", details=None):
    try:
        con = _auth_db()
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO admin_audit_log (
                admin_email, action, target_type, target_id,
                details, ip_address, status, ts
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (session.get("admin_email") or session.get("user_email") or "")[:255],
                (action or "")[:120],
                (target_type or "")[:80],
                (str(target_id or ""))[:120],
                json.dumps(details or {}, ensure_ascii=False)[:4000],
                _client_ip(),
                (status or "SUCCESS")[:32],
                int(time.time()),
            ),
        )
        con.commit()
        con.close()
    except Exception:
        pass

def _is_valid_email(email: str) -> bool:
    if not email:
        return False
    return re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) is not None


def _password_strength_ok(password: str) -> bool:
    if not password or len(password) < 8:
        return False
    return True


def _generate_captcha(length: int = 5) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(chars) for _ in range(length))


def _generate_reset_token():
    return secrets.token_urlsafe(32)


def _verify_recaptcha(token: str, remote_ip: str = "") -> bool:
    secret = (os.environ.get("RECAPTCHA_SECRET_KEY") or "").strip()
    if not secret or not token:
        return False
    try:
        resp = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": secret,
                "response": token,
                "remoteip": remote_ip or "",
            },
            timeout=10,
        )
        data = resp.json() if resp.ok else {}
        return bool(data.get("success"))
    except Exception:
        return False


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth_page"))
        return fn(*args, **kwargs)
    return wrapper


def api_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def api_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401

        current_email = (session.get("user_email") or "").strip().lower()
        allowed_admins = _get_admin_emails()
        if not current_email or current_email not in allowed_admins:
            return jsonify({"error": "forbidden"}), 403

        return fn(*args, **kwargs)

    return wrapper


def api_private_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "unauthorized"}), 401

        if not session.get("is_admin"):
            return jsonify({"error": "admin access required"}), 403

        current_email = (session.get("user_email") or "").strip().lower()
        allowed_admins = _get_admin_emails()

        if allowed_admins and current_email not in allowed_admins:
            return jsonify({"error": "forbidden"}), 403

        session["admin_email"] = current_email
        return fn(*args, **kwargs)

    return wrapper
# -----------------------------
# Dashboard Metrics (SQLite)
# -----------------------------
METRICS_DB_PATH = BASE_DIR / "metrics.db"


def _metrics_init():
    try:
        con = sqlite3.connect(str(METRICS_DB_PATH))
        cur = con.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS scan_events (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts INTEGER NOT NULL,
                   module TEXT NOT NULL,
                   target TEXT,
                   score INTEGER NOT NULL,
                   label TEXT NOT NULL
               )"""
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_ts ON scan_events(ts)")
        con.commit()
        con.close()
    except Exception:
        pass


_metrics_init()


def _extract_score_label(obj: dict):
    try:
        if not isinstance(obj, dict):
            return None

        if isinstance(obj.get("report"), dict):
            rep = obj.get("report") or {}
            sc = rep.get("score")
            lb = rep.get("label")
        else:
            sc = obj.get("score")
            lb = obj.get("label")

        if sc is None and isinstance(obj.get("result"), dict):
            r = obj.get("result") or {}
            sc = r.get("score")
            lb = r.get("label")

        if sc is None:
            return None

        try:
            sc_i = int(float(sc))
        except Exception:
            return None

        sc_i = max(0, min(100, sc_i))
        lb_s = (lb or _score_to_label(sc_i)).upper()
        return sc_i, lb_s
    except Exception:
        return None


def _log_scan_event(module: str, target: str, score: int, label: str):
    try:
        s = int(score or 0)
    except Exception:
        s = 0
    s = max(0, min(100, s))
    lab = (label or "").upper().strip() or _score_to_label(s)

    try:
        ts = int(time.time())
        con = sqlite3.connect(str(METRICS_DB_PATH))
        cur = con.cursor()
        cur.execute(
            "INSERT INTO scan_events(ts, module, target, score, label) VALUES(?,?,?,?,?)",
            (ts, (module or "Unknown"), (target or ""), s, lab),
        )
        con.commit()
        con.close()
    except Exception:
        pass


def _today_epoch_range_local():
    now = datetime.now()
    start = datetime(now.year, now.month, now.day)
    end = start.replace(hour=23, minute=59, second=59, microsecond=999999)
    return int(start.timestamp()), int(end.timestamp()) + 1


app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)

# IMPORTANT:
# - If FLASK_SECRET_KEY exists in .env, that value is used.
# - If it does NOT exist, a new random key is generated on each run.
#   That makes every previous login session invalid after rerun/restart.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_PERMANENT"] = False

# Per-run boot ID so a session from an older server run is rejected immediately.
APP_BOOT_ID = secrets.token_hex(16)


@app.before_request
def _enforce_fresh_runtime_session():
    try:
        if session.get("user_id"):
            if session.get("boot_id") != APP_BOOT_ID:
                session.clear()
    except Exception:
        session.clear()


# -----------------------------
# Security logger (security.log)
# -----------------------------
sec_logger = logging.getLogger("privguard.security")
sec_logger.setLevel(logging.INFO)
sec_logger.propagate = False

if RotatingFileHandler is not None:
    try:
        SEC_LOG = BASE_DIR / "security.log"
        handler = RotatingFileHandler(
            str(SEC_LOG),
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        if not any(isinstance(h, RotatingFileHandler) for h in sec_logger.handlers):
            sec_logger.addHandler(handler)
    except Exception:
        pass


# -----------------------------
# Rate limiting (Flask-Limiter)
# -----------------------------
limiter = None
if Limiter is not None and get_remote_address is not None:
    try:
        limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])
    except Exception:
        limiter = None


def _limit(rule: str):
    def deco(fn):
        if limiter is None:
            return fn
        try:
            return limiter.limit(rule)(fn)
        except Exception:
            return fn
    return deco


def gmail_connected() -> bool:
    try:
        if not TOKEN_PATH.exists():
            return False
        gmail_get_profile()
        return True
    except Exception:
        return False


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _normalize_gmail_box(box: str) -> str:
    b = str(box or "inbox").strip().lower()
    aliases = {
        "inbox": "inbox",
        "flagged": "flagged",
        "starred": "flagged",
        "archive": "archived",
        "archived": "archived",
        "deleted": "deleted",
        "trash": "deleted",
        "bin": "deleted",
    }
    return aliases.get(b, "inbox")


def _gmail_box_candidates(box: str):
    b = _normalize_gmail_box(box)
    if b == "flagged":
        return ["flagged", "starred"]
    if b == "archived":
        return ["archived", "archive"]
    if b == "deleted":
        return ["deleted", "trash"]
    return ["inbox"]


def _message_has_label(msg: dict, label: str) -> bool:
    labels = msg.get("labelIds") or []
    if not isinstance(labels, list):
        return False
    target = str(label or "").upper()
    return target in [str(x).upper() for x in labels]


def _message_matches_box(msg: dict, box: str) -> bool:
    b = _normalize_gmail_box(box)
    if b == "flagged":
        return _message_has_label(msg, "STARRED")
    if b == "archived":
        return (not _message_has_label(msg, "INBOX")) and (not _message_has_label(msg, "TRASH"))
    if b == "deleted":
        return _message_has_label(msg, "TRASH")
    return _message_has_label(msg, "INBOX")


def _gmail_list_box_safe(max_results: int, box: str):
    requested_box = _normalize_gmail_box(box)
    last_error = None

    for candidate in _gmail_box_candidates(requested_box):
        try:
            result = gmail_list_inbox(max_results=max_results, box=candidate)
            payload = _as_dict(result)
            messages = payload.get("messages") or []
            if not isinstance(messages, list):
                messages = []

            if requested_box in {"flagged", "archived", "deleted"}:
                filtered = [m for m in messages if isinstance(m, dict) and _message_matches_box(m, requested_box)]
                payload["messages"] = filtered

            payload["box"] = requested_box
            payload["ok"] = True
            return payload
        except Exception as e:
            last_error = e
            continue

    raise last_error or RuntimeError("Inbox fetch failed")


def _json_ok(message: str, **extra):
    payload = {"ok": True, "message": message}
    payload.update(extra)
    return jsonify(payload)


def _json_err(message: str, status: int = 400, **extra):
    payload = {"error": message}
    payload.update(extra)
    return jsonify(payload), status

# ✅ UPDATED GLOBAL SCORE LABELS
# 0–10 SAFE
# 11–29 LOW
# 30–59 MEDIUM
# 60–100 HIGH
def _score_to_label(score: int) -> str:
    try:
        s = int(score or 0)
    except Exception:
        s = 0
    s = max(0, min(100, s))

    if s >= 60:
        return "HIGH"
    if s >= 30:
        return "MEDIUM"
    if s >= 11:
        return "LOW"
    return "SAFE"


def _non_technical_explain(msg: dict, email_result: dict) -> dict:
    """
    Gmail UX helper that uses email_result as the single source of truth.
    """
    score = int(email_result.get("overall_score") or 0)
    bullets = email_result.get("bullets") or []

    label_for_ux = _score_to_label(score)

    if label_for_ux == "HIGH":
        headline = "Phishing Attempt Detected!"
        explain = (
            "This email is high risk. It shows multiple scam indicators and may be attempting credential theft or malware delivery."
        )
        recs = [
            "Do not click any links.",
            "Do not open attachments.",
            "Flag it and consider deleting it.",
            "If you entered credentials, change your password immediately.",
            "Enable Two-Factor Authentication.",
        ]
    elif label_for_ux == "MEDIUM":
        headline = "Suspicious Email Detected"
        explain = (
            "This email is suspicious. Verify the sender and links before interacting."
        )
        recs = [
            "Verify the sender via another channel.",
            "Avoid unfamiliar links.",
            "Be cautious with attachments.",
            "Flag it if anything feels off.",
        ]
    elif label_for_ux == "LOW":
        headline = "Low Risk Email"
        explain = (
            "This email shows minor risk signals. It may be legitimate, but you should still proceed with caution."
        )
        recs = [
            "Read carefully before taking action.",
            "Avoid unexpected links or files.",
            "Verify the sender if the request feels unusual.",
        ]
    else:
        headline = "Looks Safe"
        explain = (
            "This email looks safe based on the checks we ran. Still be careful with unexpected links or files."
        )
        recs = [
            "Read normally.",
            "Only click links you expected.",
            "If unsure, confirm with the sender through another channel.",
        ]

    return {
        "headline": headline,
        "explain": explain,
        "recs": recs,
        "bullets": bullets[:8],
        "label": label_for_ux,
        "score": score,
    }


# -----------------------------
# Advanced Gmail Scan (background, cached)
# -----------------------------
ADV_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=4)
ADV_SCAN_LOCK = Lock()
ADV_SCAN_RESULTS = {}
ADV_SCAN_PENDING = set()
ADV_SCAN_TTL_S = 600


def _adv_cache_get(msg_id: str):
    now = time.time()
    with ADV_SCAN_LOCK:
        item = ADV_SCAN_RESULTS.get(msg_id)
        if not item:
            return None
        if (now - float(item.get("ts", 0))) > ADV_SCAN_TTL_S:
            ADV_SCAN_RESULTS.pop(msg_id, None)
            return None
        return item.get("result")


def _adv_cache_set(msg_id: str, result: dict):
    with ADV_SCAN_LOCK:
        ADV_SCAN_RESULTS[msg_id] = {"ts": time.time(), "result": result}


def _kickoff_adv_scan(msg_id: str, msg: dict, base_report: dict):
    if not msg_id or run_advanced_scan_layers is None:
        return
    if _adv_cache_get(msg_id) is not None:
        return
    with ADV_SCAN_LOCK:
        if msg_id in ADV_SCAN_PENDING:
            return
        ADV_SCAN_PENDING.add(msg_id)

    def _job():
        try:
            res = run_advanced_scan_layers(msg, base_report, timeout_s=3.0)
            _adv_cache_set(msg_id, res)
        except Exception:
            pass
        finally:
            with ADV_SCAN_LOCK:
                ADV_SCAN_PENDING.discard(msg_id)

    ADV_SCAN_EXECUTOR.submit(_job)


# ============================================================
# ✅ QUICK FILE SCANNER (UPLOAD)
# ============================================================

QFS_MAX_BYTES = 25 * 1024 * 1024
QFS_ALLOWED_EXT = {"exe", "pdf", "docx", "xlsx", "zip", "js", "dll", "bat", "scr", "rar", "png", "jpg"}
_QFS_DOUBLE_EXT_RE = re.compile(r"\.([a-z0-9]{1,8})\.([a-z0-9]{1,8})$", re.IGNORECASE)

_EICAR_ASCII = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def _qfs_safe_filename(original: str) -> str:
    name = (original or "").replace("\x00", "").strip()
    name = secure_filename(name) or "upload.bin"
    return name[:180]


def _qfs_get_ext(name: str) -> str:
    n = (name or "").lower()
    if "." not in n:
        return ""
    return n.rsplit(".", 1)[-1].strip()


def _qfs_has_double_extension(name: str) -> bool:
    n = (name or "").lower()
    m = _QFS_DOUBLE_EXT_RE.search(n)
    if not m:
        return False
    first, last = m.group(1), m.group(2)
    execish = {"exe", "dll", "scr", "bat", "js"}
    return (last in execish) and (first != last)


def _qfs_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _qfs_entropy(path: Path, max_bytes: int = 2_000_000) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return round(ent, 2)
    except Exception:
        return 0.0


def _qfs_sniff_mime(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head.startswith(b"%PDF-"):
            return "application/pdf"
        if head.startswith(b"MZ"):
            return "application/x-msdownload"
        if head.startswith(b"PK\x03\x04"):
            return "application/zip"
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if head.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if head.startswith(b"Rar!\x1a\x07\x00") or head.startswith(b"Rar!\x1a\x07\x01\x00"):
            return "application/x-rar-compressed"
        guess, _ = mimetypes.guess_type(str(path))
        return guess or "application/octet-stream"
    except Exception:
        return "application/octet-stream"


def _qfs_mime_matches_ext(mime: str, ext: str) -> bool:
    ext = (ext or "").lower()
    mime = (mime or "").lower()
    ok = {
        "pdf": {"application/pdf"},
        "png": {"image/png"},
        "jpg": {"image/jpeg"},
        "zip": {"application/zip", "application/x-zip-compressed"},
        "rar": {"application/x-rar-compressed", "application/vnd.rar"},
        "exe": {"application/x-msdownload", "application/octet-stream"},
        "dll": {"application/x-msdownload", "application/octet-stream"},
        "scr": {"application/x-msdownload", "application/octet-stream"},
        "bat": {"text/plain", "application/octet-stream"},
        "js": {"text/javascript", "application/javascript", "application/x-javascript", "text/plain"},
        "docx": {"application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        "xlsx": {"application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    }
    if ext not in ok:
        return True
    return mime in ok[ext]


def _qfs_detect_signatures(path: Path) -> list:
    found = []
    try:
        with open(path, "rb") as f:
            data = f.read()
        if _EICAR_ASCII in data:
            found.append("EICAR_TEST_STRING")
    except Exception:
        pass
    return found


def _qfs_risk_score(signatures: list, ext: str, mime_mismatch: bool, double_ext: bool, entropy: float):
    triggers = []
    if "EICAR_TEST_STRING" in signatures:
        triggers.append("Known malicious test signature detected (EICAR)")
        return 95, triggers

    score = 0
    if double_ext:
        score += 40
        triggers.append("Double extension detected")

    if mime_mismatch:
        score += 30
        triggers.append("MIME type does not match extension")

    if entropy >= 7.90:
        score += 25
        triggers.append(f"Very high entropy ({entropy}) - possible packing/encryption")
    elif entropy >= 7.50:
        score += 18
        triggers.append(f"High entropy ({entropy}) - possible packing/encryption")

    suspicious_ext = {".exe", ".dll", ".scr", ".bat"}
    if f".{ext}" in suspicious_ext:
        score += 12
        triggers.append(f"High-risk file type (.{ext})")

    score = max(0, min(100, int(score)))
    return score, triggers


def _qfs_verdict(score: int) -> str:
    s = max(0, min(100, int(score or 0)))
    if s >= 90:
        return "Malicious"
    if s >= 35:
        return "Suspicious"
    return "Safe"


def _qfs_recommendation(verdict: str) -> str:
    v = (verdict or "").lower()
    if v == "malicious":
        return "Do NOT open this file. Quarantine/delete it and scan your system with a trusted antivirus."
    if v == "suspicious":
        return "Do not run/execute this file until verified. If needed, open in an isolated sandbox environment."
    return "No known threats detected. Still verify file origin before opening."


@_limit("12 per minute")
@app.post("/api/file/scan")
def api_quick_file_scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    f = request.files["file"]
    orig_name = (getattr(f, "filename", "") or "").strip()
    if not orig_name:
        return jsonify({"error": "Missing filename."}), 400
    if "\x00" in orig_name:
        return jsonify({"error": "Invalid filename."}), 400

    safe_name = _qfs_safe_filename(orig_name)
    ext = _qfs_get_ext(safe_name)
    if not ext or ext not in QFS_ALLOWED_EXT:
        return jsonify({"error": "Unsupported file type."}), 400

    try:
        cl = request.content_length
        if cl is not None and int(cl) > (QFS_MAX_BYTES + 64 * 1024):
            return jsonify({"error": "File too large. Max is 25MB."}), 413
    except Exception:
        pass

    tmp_root = Path(tempfile.gettempdir()) / "scans"
    try:
        tmp_root.mkdir(parents=True, exist_ok=True)
    except Exception:
        return jsonify({"error": "Server storage error."}), 500

    tmp_path = tmp_root / f"{uuid.uuid4().hex}_{safe_name}"
    t0 = time.time()

    try:
        f.save(str(tmp_path))

        try:
            size_b = int(tmp_path.stat().st_size)
        except Exception:
            size_b = 0

        if size_b <= 0:
            return jsonify({"error": "Empty or unreadable file."}), 400
        if size_b > QFS_MAX_BYTES:
            return jsonify({"error": "File too large. Max is 25MB."}), 413

        sha256_hex = _qfs_sha256(tmp_path)
        entropy = _qfs_entropy(tmp_path)
        mime = _qfs_sniff_mime(tmp_path)

        double_ext = _qfs_has_double_extension(safe_name)
        mime_mismatch = not _qfs_mime_matches_ext(mime, ext)

        signatures = _qfs_detect_signatures(tmp_path)
        score, triggers = _qfs_risk_score(
            signatures=signatures,
            ext=ext,
            mime_mismatch=mime_mismatch,
            double_ext=double_ext,
            entropy=entropy,
        )

        verdict = _qfs_verdict(score)
        label = _score_to_label(score)

        signals = []
        for s in triggers:
            if s and s not in signals:
                signals.append(s)
        if signatures:
            for sig in signatures:
                line = f"Signature match: {sig}"
                if line not in signals:
                    signals.insert(0, line)

        scan_ms = int((time.time() - t0) * 1000)

        resp = {
            "file": {
                "name": safe_name,
                "size": size_b,
                "sha256": sha256_hex,
                "type": mime,
                "entropy": entropy,
            },
            "report": {
                "score": int(score),
                "label": label,
                "signals": signals,
                "detected_signatures": signatures,
                "verdict": verdict,
                "malware_family": "",
                "recommendation": _qfs_recommendation(verdict),
                "scan_time_ms": scan_ms,
            },
        }

        try:
            _log_scan_event("Quick File Scanner", safe_name, int(score), label)
        except Exception:
            pass

        return jsonify(resp)

    except Exception as e:
        sec_logger.info(f"quick_file_scan_error err={e.__class__.__name__}")
        return jsonify({"error": "Scan failed."}), 400
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


# -----------------------------
# Email Center (Composer / Sent / Drafts)
# -----------------------------
EMAIL_DB_PATH = Path(os.environ.get("PRIVGUARD_DB_PATH", str(BASE_DIR / "privguard.db")))
EMAIL_ATTACH_DIR = Path(os.environ.get("PRIVGUARD_EMAIL_ATTACH_DIR", str(BASE_DIR / "uploads" / "email_attachments")))
EMAIL_ATTACH_DIR.mkdir(parents=True, exist_ok=True)

EMAIL_ALLOWED_EXT = {"pdf", "docx", "png", "jpg", "jpeg", "gif", "webp", "zip"}
EMAIL_MAX_ATTACH_BYTES = 10 * 1024 * 1024
EMAIL_MAX_TOTAL_ATTACH_BYTES = 20 * 1024 * 1024
EMAIL_RATE_LIMIT_WINDOW_S = 3600
EMAIL_RATE_LIMIT_MAX_SENDS = 30
EMAIL_SEND_STATE = {}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "rb.gy", "tiny.one"
}
PRIVATE_EMAIL_DOMAINS = {"localhost", "local", "invalid", "example.com"}


def _email_db():
    con = sqlite3.connect(str(EMAIL_DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def _email_init():
    con = _email_db()
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender TEXT,
            recipient TEXT,
            cc TEXT,
            bcc TEXT,
            subject TEXT,
            body TEXT,
            body_text TEXT,
            attachments TEXT,
            status TEXT,
            folder TEXT,
            external_message_id TEXT,
            security_warnings TEXT,
            sent_at DATETIME,
            updated_at DATETIME
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_emails_user_folder ON emails(user_id, folder)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_emails_sent_at ON emails(sent_at)")
    con.commit()
    con.close()


_email_init()


def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _strip_html_to_text(value: str) -> str:
    if not value:
        return ""
    txt = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    txt = re.sub(r"</p\s*>", "\n\n", txt, flags=re.IGNORECASE)
    txt = re.sub(r"<[^>]+>", "", txt)
    return html.unescape(txt).strip()


def _extract_urls(text: str):
    if not text:
        return []
    return re.findall(r"https?://[^\s<>'\"()]+", text, flags=re.IGNORECASE)


def _split_emails(value):
    if isinstance(value, list):
        raw = value
    else:
        raw = re.split(r"[,\n;]+", str(value or ""))
    out = []
    seen = set()
    for item in raw:
        e = str(item or "").strip().lower()
        if not e:
            continue
        if e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out


def _validate_recipient_list(values):
    cleaned = _split_emails(values)
    bad = [e for e in cleaned if not _is_valid_email(e)]
    return cleaned, bad


def _domain_ok_for_recipient(email_addr: str) -> bool:
    try:
        domain = email_addr.split("@", 1)[1].lower().strip()
    except Exception:
        return False
    if domain in PRIVATE_EMAIL_DOMAINS:
        return False
    if "." not in domain:
        return False
    return True


def _email_security_warnings(message_html: str, recipients):
    warnings = []
    urls = _extract_urls(message_html or "")
    hosts = []

    for u in urls:
        try:
            p = urlparse(u)
            host = (p.hostname or "").lower()
            if host:
                hosts.append(host)

            if host in SHORTENER_HOSTS:
                warnings.append(f"Shortened link detected: {host}")

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""):
                warnings.append(f"Link uses raw IP address: {host}")

            lowered = u.lower()
            if any(k in lowered for k in ["login", "verify", "signin", "account", "password", "reset"]):
                warnings.append("Message contains a login or account verification link")
        except Exception:
            continue

    for host in hosts:
        if "xn--" in host:
            warnings.append(f"Possible lookalike domain detected: {host}")

    bad_domains = []
    for rcpt in recipients or []:
        if not _domain_ok_for_recipient(rcpt):
            bad_domains.append(rcpt)
    if bad_domains:
        warnings.append("One or more recipient domains look invalid")

    deduped = []
    seen = set()
    for w in warnings:
        k = w.lower().strip()
        if k and k not in seen:
            seen.add(k)
            deduped.append(w)
    return deduped[:8]


def _sanitize_attachment_name(name: str) -> str:
    n = secure_filename((name or "").strip()) or f"attachment_{uuid.uuid4().hex[:8]}"
    return n[:180]


def _attachment_ext_ok(name: str) -> bool:
    ext = (name.rsplit(".", 1)[-1].lower().strip() if "." in (name or "") else "")
    return ext in EMAIL_ALLOWED_EXT


def _smtp_settings():
    return {
        "host": (os.environ.get("SMTP_HOST") or "").strip(),
        "port": int(os.environ.get("SMTP_PORT") or "587"),
        "user": (os.environ.get("SMTP_USER") or "").strip(),
        "password": (os.environ.get("SMTP_PASSWORD") or "").strip(),
    }


def _smtp_ready():
    s = _smtp_settings()
    return bool(s["host"] and s["port"] and s["user"] and s["password"])


def _email_sender_address():
    s = _smtp_settings()
    smtp_user = (s.get("user") or "").strip().lower()
    if smtp_user and _is_valid_email(smtp_user):
        return smtp_user
    return (session.get("user_email") or "").strip().lower()


def _email_rate_limit_ok(user_id: int):
    now = time.time()
    arr = EMAIL_SEND_STATE.get(user_id, [])
    arr = [t for t in arr if (now - t) <= EMAIL_RATE_LIMIT_WINDOW_S]
    EMAIL_SEND_STATE[user_id] = arr
    return len(arr) < EMAIL_RATE_LIMIT_MAX_SENDS


def _email_rate_limit_mark(user_id: int):
    now = time.time()
    arr = EMAIL_SEND_STATE.get(user_id, [])
    arr.append(now)
    EMAIL_SEND_STATE[user_id] = arr[-EMAIL_RATE_LIMIT_MAX_SENDS:]


def _store_email_row(
    user_id: int,
    sender: str,
    to_list,
    cc_list,
    bcc_list,
    subject: str,
    body_html: str,
    attachments,
    status: str,
    folder: str,
    external_message_id: str = "",
    security_warnings=None,
    row_id: int = None,
):
    body_text = _strip_html_to_text(body_html)
    recipient = json.dumps(list(to_list or []))
    cc_json = json.dumps(list(cc_list or []))
    bcc_json = json.dumps(list(bcc_list or []))
    attachments_json = json.dumps(list(attachments or []))
    warnings_json = json.dumps(list(security_warnings or []))
    now = _now_iso()

    con = _email_db()
    cur = con.cursor()

    if row_id:
        cur.execute(
            """
            UPDATE emails
            SET sender=?, recipient=?, cc=?, bcc=?, subject=?, body=?, body_text=?,
                attachments=?, status=?, folder=?, external_message_id=?, security_warnings=?,
                updated_at=?
            WHERE id=? AND user_id=?
            """,
            (
                sender, recipient, cc_json, bcc_json, subject, body_html, body_text,
                attachments_json, status, folder, external_message_id, warnings_json,
                now, int(row_id), int(user_id)
            ),
        )
        con.commit()
        con.close()
        return int(row_id)

    cur.execute(
        """
        INSERT INTO emails (
            user_id, sender, recipient, cc, bcc, subject, body, body_text,
            attachments, status, folder, external_message_id, security_warnings,
            sent_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(user_id), sender, recipient, cc_json, bcc_json, subject, body_html, body_text,
            attachments_json, status, folder, external_message_id, warnings_json, now, now
        ),
    )
    new_id = cur.lastrowid
    con.commit()
    con.close()
    return int(new_id)


def _fetch_emails_for_user(user_id: int, folder: str, limit: int = 50):
    con = _email_db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, sender, recipient, cc, bcc, subject, body, body_text,
               attachments, status, folder, security_warnings, sent_at, updated_at
        FROM emails
        WHERE user_id=? AND folder=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(user_id), folder, int(limit)),
    )
    rows = cur.fetchall()
    con.close()

    out = []
    for r in rows:
        try:
            to_list = json.loads(r["recipient"] or "[]")
        except Exception:
            to_list = []
        try:
            cc_list = json.loads(r["cc"] or "[]")
        except Exception:
            cc_list = []
        try:
            bcc_list = json.loads(r["bcc"] or "[]")
        except Exception:
            bcc_list = []
        try:
            attachments = json.loads(r["attachments"] or "[]")
        except Exception:
            attachments = []
        try:
            warnings = json.loads(r["security_warnings"] or "[]")
        except Exception:
            warnings = []

        out.append({
            "id": int(r["id"]),
            "sender": r["sender"] or "",
            "to": to_list,
            "cc": cc_list,
            "bcc": bcc_list,
            "subject": r["subject"] or "",
            "body": r["body"] or "",
            "body_text": r["body_text"] or "",
            "attachments": attachments,
            "status": r["status"] or "",
            "folder": r["folder"] or "",
            "security_warnings": warnings,
            "sent_at": r["sent_at"] or "",
            "updated_at": r["updated_at"] or "",
        })
    return out


def _load_attachment_tokens(tokens):
    items = []
    total = 0
    for tok in (tokens or []):
        token = str(tok or "").strip()
        if not token:
            continue
        path = EMAIL_ATTACH_DIR / token
        meta_path = EMAIL_ATTACH_DIR / f"{token}.json"
        if not path.exists() or not meta_path.exists():
            raise ValueError("One or more attachments are missing.")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        size = int(meta.get("size") or 0)
        total += size
        if total > EMAIL_MAX_TOTAL_ATTACH_BYTES:
            raise ValueError("Total attachment size is too large.")

        items.append({
            "token": token,
            "path": path,
            "filename": meta.get("filename") or path.name,
            "mime": meta.get("mime") or "application/octet-stream",
            "size": size,
        })
    return items


def _smtp_send_email(sender: str, to_list, cc_list, bcc_list, subject: str, body_html: str, attachments):
    settings = _smtp_settings()
    if not _smtp_ready():
        raise RuntimeError(
            "SMTP is not configured. Add SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD to your .env file."
        )

    actual_sender = settings["user"].strip()
    if not actual_sender:
        raise RuntimeError("SMTP sender account is missing.")

    msg = EmailMessage()
    msg["From"] = actual_sender
    if sender and sender.lower().strip() != actual_sender.lower().strip():
        msg["Reply-To"] = sender
    msg["To"] = ", ".join(to_list or [])
    if cc_list:
        msg["Cc"] = ", ".join(cc_list or [])
    msg["Subject"] = subject or "(no subject)"
    msg.set_content(_strip_html_to_text(body_html) or "")

    safe_html = body_html or ""
    if "<html" not in safe_html.lower():
        safe_html = f"<html><body>{safe_html}</body></html>"
    msg.add_alternative(safe_html, subtype="html")

    for item in attachments or []:
        mime = (item.get("mime") or "application/octet-stream").lower()
        maintype, subtype = ("application", "octet-stream")
        if "/" in mime:
            maintype, subtype = mime.split("/", 1)
        with open(item["path"], "rb") as f:
            data = f.read()
        msg.add_attachment(
            data,
            maintype=maintype,
            subtype=subtype,
            filename=item.get("filename") or "attachment.bin"
        )

    recipients = list(to_list or []) + list(cc_list or []) + list(bcc_list or [])
    if not recipients:
        raise RuntimeError("No recipients provided.")

    with smtplib.SMTP(settings["host"], settings["port"], timeout=30) as server:
        server.starttls()
        server.login(settings["user"], settings["password"])
        server.send_message(msg, from_addr=actual_sender, to_addrs=recipients)

    return {"ok": True, "message_id": msg.get("Message-ID", ""), "actual_sender": actual_sender}


@app.get("/api/email-center/profile")
@api_login_required
def api_email_center_profile():
    sender_email = _email_sender_address()
    return jsonify({
        "ok": True,
        "email": sender_email,
        "name": session.get("user_name") or "",
    })


@app.get("/api/email-center/list")
@api_login_required
def api_email_center_list():
    folder = (request.args.get("folder") or "sent").strip().lower()
    limit = max(1, min(100, int(request.args.get("limit") or 50)))

    user_id = int(session.get("user_id"))
    if folder not in {"sent", "drafts", "inbox"}:
        folder = "sent"

    if folder == "inbox" and gmail_connected():
        try:
            max_results = max(1, min(50, limit))
            return jsonify({
                "ok": True,
                "folder": "inbox",
                "messages": gmail_list_inbox(max_results=max_results, box="inbox").get("messages", []),
                "source": "gmail"
            })
        except Exception:
            pass

    messages = _fetch_emails_for_user(user_id, folder, limit=limit)
    return jsonify({"ok": True, "folder": folder, "messages": messages, "source": "local"})


@app.get("/api/email-center/item/<int:item_id>")
@api_login_required
def api_email_center_item(item_id: int):
    user_id = int(session.get("user_id"))
    con = _email_db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, sender, recipient, cc, bcc, subject, body, body_text,
               attachments, status, folder, security_warnings, sent_at, updated_at
        FROM emails
        WHERE id=? AND user_id=?
        LIMIT 1
        """,
        (int(item_id), user_id),
    )
    row = cur.fetchone()
    con.close()

    if not row:
        return jsonify({"error": "Email not found."}), 404

    try:
        to_list = json.loads(row["recipient"] or "[]")
    except Exception:
        to_list = []
    try:
        cc_list = json.loads(row["cc"] or "[]")
    except Exception:
        cc_list = []
    try:
        bcc_list = json.loads(row["bcc"] or "[]")
    except Exception:
        bcc_list = []
    try:
        attachments = json.loads(row["attachments"] or "[]")
    except Exception:
        attachments = []
    try:
        warnings = json.loads(row["security_warnings"] or "[]")
    except Exception:
        warnings = []

    return jsonify({
        "ok": True,
        "item": {
            "id": int(row["id"]),
            "sender": row["sender"] or "",
            "to": to_list,
            "cc": cc_list,
            "bcc": bcc_list,
            "subject": row["subject"] or "",
            "body": row["body"] or "",
            "body_text": row["body_text"] or "",
            "attachments": attachments,
            "status": row["status"] or "",
            "folder": row["folder"] or "",
            "security_warnings": warnings,
            "sent_at": row["sent_at"] or "",
            "updated_at": row["updated_at"] or "",
        }
    })


@app.post("/api/email-center/upload-attachment")
@api_login_required
@_limit("20 per minute")
def api_email_center_upload_attachment():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    f = request.files["file"]
    original = (getattr(f, "filename", "") or "").strip()
    if not original:
        return jsonify({"error": "Missing filename."}), 400

    filename = _sanitize_attachment_name(original)
    if not _attachment_ext_ok(filename):
        return jsonify({"error": "Unsupported attachment type. Allowed: PDF, DOCX, images, ZIP."}), 400

    token = uuid.uuid4().hex
    tmp_path = EMAIL_ATTACH_DIR / token
    meta_path = EMAIL_ATTACH_DIR / f"{token}.json"

    try:
        f.save(str(tmp_path))
        size = int(tmp_path.stat().st_size)
        if size <= 0:
            raise ValueError("Empty file.")
        if size > EMAIL_MAX_ATTACH_BYTES:
            raise ValueError("Attachment exceeds 10MB limit.")

        mime = _qfs_sniff_mime(tmp_path)
        meta = {
            "filename": filename,
            "size": size,
            "mime": mime,
            "uploaded_at": _now_iso(),
            "user_id": int(session.get("user_id")),
        }
        with open(meta_path, "w", encoding="utf-8") as fp:
            json.dump(meta, fp)

        return jsonify({
            "ok": True,
            "attachment": {
                "token": token,
                "filename": filename,
                "size": size,
                "mime": mime,
            }
        })
    except Exception as e:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        try:
            if meta_path.exists():
                meta_path.unlink()
        except Exception:
            pass
        return jsonify({"error": str(e)}), 400


@app.post("/api/email-center/remove-attachment")
@api_login_required
def api_email_center_remove_attachment():
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Missing attachment token."}), 400

    path = EMAIL_ATTACH_DIR / token
    meta = EMAIL_ATTACH_DIR / f"{token}.json"
    try:
        if path.exists():
            path.unlink()
        if meta.exists():
            meta.unlink()
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"error": "Failed to remove attachment."}), 400


@app.post("/api/email-center/draft/save")
@api_login_required
@_limit("30 per minute")
def api_email_center_save_draft():
    data = request.get_json(force=True, silent=True) or {}

    user_id = int(session.get("user_id"))
    sender = (data.get("from") or _email_sender_address() or "").strip().lower()
    to_list, bad_to = _validate_recipient_list(data.get("to"))
    cc_list, bad_cc = _validate_recipient_list(data.get("cc"))
    bcc_list, bad_bcc = _validate_recipient_list(data.get("bcc"))
    subject = (data.get("subject") or "").strip()
    body = data.get("message") or ""
    draft_id = data.get("draft_id")
    attachment_tokens = data.get("attachment_tokens") or []

    if not sender or not _is_valid_email(sender):
        return jsonify({"error": "Invalid sender email."}), 400

    if bad_to or bad_cc or bad_bcc:
        return jsonify({"error": "One or more email addresses are invalid."}), 400

    try:
        attachment_items = _load_attachment_tokens(attachment_tokens)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    attachment_meta = [{
        "token": x["token"],
        "filename": x["filename"],
        "size": x["size"],
        "mime": x["mime"],
    } for x in attachment_items]

    warnings = _email_security_warnings(body, to_list + cc_list + bcc_list)

    row_id = _store_email_row(
        user_id=user_id,
        sender=sender,
        to_list=to_list,
        cc_list=cc_list,
        bcc_list=bcc_list,
        subject=subject,
        body_html=body,
        attachments=attachment_meta,
        status="DRAFT",
        folder="drafts",
        security_warnings=warnings,
        row_id=(int(draft_id) if str(draft_id or "").isdigit() else None),
    )

    return jsonify({
        "ok": True,
        "draft_id": row_id,
        "saved_at": _now_iso(),
        "security_warnings": warnings,
    })


@app.post("/api/email-center/send")
@api_login_required
@_limit("10 per minute")
def api_email_center_send():
    data = request.get_json(force=True, silent=True) or {}

    user_id = int(session.get("user_id"))
    sender = _email_sender_address()
    subject = (data.get("subject") or "").strip()
    body = data.get("message") or ""
    draft_id = data.get("draft_id")
    attachment_tokens = data.get("attachment_tokens") or []

    to_list, bad_to = _validate_recipient_list(data.get("to"))
    cc_list, bad_cc = _validate_recipient_list(data.get("cc"))
    bcc_list, bad_bcc = _validate_recipient_list(data.get("bcc"))

    if not session.get("user_id"):
        return jsonify({"error": "Authentication required."}), 401

    if not sender or not _is_valid_email(sender):
        return jsonify({"error": "Invalid sender email."}), 400

    if not to_list:
        return jsonify({"error": "At least one recipient is required."}), 400

    if bad_to or bad_cc or bad_bcc:
        return jsonify({"error": "One or more recipient emails are invalid."}), 400

    invalid_domains = [e for e in (to_list + cc_list + bcc_list) if not _domain_ok_for_recipient(e)]
    if invalid_domains:
        return jsonify({"error": "One or more recipient domains are invalid.", "invalid_recipients": invalid_domains}), 400

    if not _email_rate_limit_ok(user_id):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    try:
        attachment_items = _load_attachment_tokens(attachment_tokens)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    warnings = _email_security_warnings(body, to_list + cc_list + bcc_list)

    attachment_meta = [{
        "token": x["token"],
        "filename": x["filename"],
        "size": x["size"],
        "mime": x["mime"],
    } for x in attachment_items]

    try:
        smtp_result = _smtp_send_email(
            sender=sender,
            to_list=to_list,
            cc_list=cc_list,
            bcc_list=bcc_list,
            subject=subject,
            body_html=body,
            attachments=attachment_items,
        )
        _email_rate_limit_mark(user_id)

        stored_sender = smtp_result.get("actual_sender") or sender

        row_id = _store_email_row(
            user_id=user_id,
            sender=stored_sender,
            to_list=to_list,
            cc_list=cc_list,
            bcc_list=bcc_list,
            subject=subject,
            body_html=body,
            attachments=attachment_meta,
            status="SENT",
            folder="sent",
            external_message_id=smtp_result.get("message_id", ""),
            security_warnings=warnings,
            row_id=(int(draft_id) if str(draft_id or "").isdigit() else None),
        )

        try:
            _log_scan_event("Email Center", subject or "email_send", 5, "SAFE")
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "message": "Email sent successfully.",
            "email_id": row_id,
            "security_warnings": warnings,
        })

    except Exception as e:
        row_id = _store_email_row(
            user_id=user_id,
            sender=sender,
            to_list=to_list,
            cc_list=cc_list,
            bcc_list=bcc_list,
            subject=subject,
            body_html=body,
            attachments=attachment_meta,
            status="FAILED",
            folder="drafts",
            security_warnings=warnings,
            row_id=(int(draft_id) if str(draft_id or "").isdigit() else None),
        )
        sec_logger.info(f"email_send_failed user_id={user_id} err={e.__class__.__name__}")
        return jsonify({
            "error": f"Email sending failed: {e}",
            "draft_id": row_id,
            "security_warnings": warnings,
        }), 400


@app.get("/debug/login-activity")
def debug_login_activity():
    con = _auth_db()
    cur = con.cursor()

    try:
        cur.execute("SELECT * FROM login_activity ORDER BY rowid DESC LIMIT 20")
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        con.close()


# -----------------------------
# Auth Views / APIs
# -----------------------------
@app.get("/auth")
@app.get("/login")
@app.get("/signup")
@app.get("/register")
def auth_page():
    """Public web login/signup page.

    The public web area is separate from the private admin console.
    Admin access must start from /admin/login, not from the normal web login.
    """
    if session.get("user_id"):
        return redirect(url_for("tool_view", tool_name="dashboard"))
    return render_template("auth.html")


@app.get("/api/auth/captcha")
def api_auth_captcha():
    code = _generate_captcha(5)
    session["signup_captcha"] = code
    return jsonify({"ok": True, "captcha": code})


@app.post("/api/auth/captcha/verify")
def api_auth_captcha_verify():
    data = request.get_json(force=True, silent=True) or {}
    answer = (data.get("answer") or "").strip().upper()
    expected = (session.get("signup_captcha") or "").strip().upper()

    if not expected:
        return jsonify({"ok": False, "error": "CAPTCHA session expired."}), 400

    if answer != expected:
        return jsonify({"ok": False, "verified": False}), 400

    session["signup_captcha_verified"] = True
    return jsonify({"ok": True, "verified": True})


@app.post("/api/signup")
def api_signup():
    data = request.get_json(force=True, silent=True) or {}

    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    confirm_password = (data.get("confirm_password") or "").strip()
    accept_terms = bool(data.get("accept_terms", False))

    # Supports Google reCAPTCHA token, and still supports old local captcha fallback
    recaptcha_token = (data.get("recaptcha_token") or "").strip()
    captcha = (data.get("captcha") or "").strip().upper()

    errors = {}

    if not full_name:
        errors["full_name"] = "Full name is required."

    if not email:
        errors["email"] = "Email is required."
    elif not _is_valid_email(email):
        errors["email"] = "Enter a valid email address."

    if not password:
        errors["password"] = "Password is required."
    elif not _password_strength_ok(password):
        errors["password"] = "Password must be at least 8 characters."

    if confirm_password != password:
        errors["confirm_password"] = "Passwords do not match."

    if not accept_terms:
        errors["accept_terms"] = "You must accept the terms and privacy policy."

    recaptcha_secret = (os.environ.get("RECAPTCHA_SECRET_KEY") or "").strip()
    if recaptcha_secret:
        if not recaptcha_token:
            errors["captcha"] = "Please complete the CAPTCHA."
        else:
            ok = _verify_recaptcha(recaptcha_token, request.remote_addr or "")
            if not ok:
                errors["captcha"] = "Human verification failed."
    else:
        expected_captcha = (session.get("signup_captcha") or "").strip().upper()
        if not expected_captcha:
            errors["captcha"] = "CAPTCHA session expired. Refresh and try again."
        elif captcha != expected_captcha:
            errors["captcha"] = "CAPTCHA verification failed."

    if errors:
        return jsonify({"ok": False, "errors": errors}), 400

    try:
        con = _auth_db()
        cur = con.cursor()

        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()
        if existing:
            con.close()
            return jsonify({
                "ok": False,
                "errors": {"email": "An account with this email already exists."}
            }), 400

        password_hash = generate_password_hash(password)

        cur.execute(
            """
            INSERT INTO users (full_name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (full_name, email, password_hash, int(time.time()))
        )

        con.commit()
        con.close()

        session.pop("signup_captcha", None)
        session.pop("signup_captcha_verified", None)

        return jsonify({
            "ok": True,
            "message": "Account created successfully.",
            "user": {
                "full_name": full_name,
                "email": email
            }
        })
    except Exception:
        return jsonify({"ok": False, "error": "Signup failed."}), 500

@app.post("/api/login")
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    identifier = (data.get("name") or data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    errors = {}
    if not identifier:
        errors["name"] = "Email is required."
    if not password:
        errors["password"] = "Password is required."
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400

    try:
        con = _auth_db()
        cur = con.cursor()

        # detect whether role / security columns exist
        cur.execute("PRAGMA table_info(users)")
        cols = {str(r[1]).lower() for r in cur.fetchall()}

        has_role = "role" in cols
        has_is_active = "is_active" in cols
        has_is_locked = "is_locked" in cols
        has_failed_login_count = "failed_login_count" in cols
        has_last_login_ts = "last_login_ts" in cols

        select_role = "COALESCE(role, 'user') as role" if has_role else "'user' as role"
        select_is_active = "COALESCE(is_active, 1) as is_active" if has_is_active else "1 as is_active"
        select_is_locked = "COALESCE(is_locked, 0) as is_locked" if has_is_locked else "0 as is_locked"
        select_failed = (
            "COALESCE(failed_login_count, 0) as failed_login_count"
            if has_failed_login_count else
            "0 as failed_login_count"
        )

        cur.execute(
            f"""
            SELECT
                id,
                full_name,
                email,
                password_hash,
                {select_role},
                {select_is_active},
                {select_is_locked},
                {select_failed}
            FROM users
            WHERE lower(full_name)=lower(?) OR lower(email)=lower(?)
            LIMIT 1
            """,
            (identifier, identifier)
        )

        user = cur.fetchone()
        con.close()

        if not user:
            _log_login_activity(None, "", identifier, "LOGIN_ATTEMPT", "FAILED")
            return jsonify({"ok": False, "error": "Invalid credentials."}), 401

        if int(user["is_active"] or 0) != 1:
            _log_login_activity(user["id"], user["full_name"], user["email"], "LOGIN_ATTEMPT", "DISABLED")
            return jsonify({"ok": False, "error": "Account is disabled."}), 403

        if int(user["is_locked"] or 0) == 1:
            _log_login_activity(user["id"], user["full_name"], user["email"], "LOGIN_ATTEMPT", "LOCKED")
            return jsonify({"ok": False, "error": "Account is locked."}), 403

        if not check_password_hash(user["password_hash"], password):
            try:
                con = _auth_db()
                cur = con.cursor()

                if has_failed_login_count:
                    cur.execute(
                        "UPDATE users SET failed_login_count=COALESCE(failed_login_count,0)+1 WHERE id=?",
                        (user["id"],)
                    )
                    con.commit()

                    cur.execute(
                        "SELECT COALESCE(failed_login_count,0) AS failed_login_count FROM users WHERE id=?",
                        (user["id"],)
                    )
                    failed_row = cur.fetchone()
                    failed_count = int((failed_row["failed_login_count"] if failed_row else 0) or 0)

                    if has_is_locked and failed_count >= 5:
                        cur.execute("UPDATE users SET is_locked=1 WHERE id=?", (user["id"],))
                        con.commit()

                con.close()
            except Exception:
                try:
                    con.close()
                except Exception:
                    pass

            _log_login_activity(user["id"], user["full_name"], user["email"], "LOGIN_ATTEMPT", "FAILED")
            return jsonify({"ok": False, "error": "Invalid credentials."}), 401

        # Normal web login is intentionally not an admin login.
        # Users with admin role must use /admin/login to enter the private admin console.
        _ensure_user_role(user["email"])
        is_admin = False

        try:
            con = _auth_db()
            cur = con.cursor()

            updates = []
            params = []

            if has_failed_login_count:
                updates.append("failed_login_count=0")

            if has_last_login_ts:
                updates.append("last_login_ts=?")
                params.append(int(time.time()))

            if updates:
                params.append(user["id"])
                cur.execute(
                    f"UPDATE users SET {', '.join(updates)} WHERE id=?",
                    tuple(params)
                )
                con.commit()

            con.close()
        except Exception:
            try:
                con.close()
            except Exception:
                pass

        session.clear()
        session.permanent = False
        session["boot_id"] = APP_BOOT_ID
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        session["user_email"] = user["email"]
        session["is_admin"] = bool(is_admin)

        session.pop("admin_email", None)

        _log_login_activity(
            user["id"],
            user["full_name"],
            user["email"],
            "LOGIN_ATTEMPT",
            "SUCCESS"
        )
        return jsonify({
            "ok": True,
            "message": "Login successful.",
            "redirect_url": url_for("tool_view", tool_name="dashboard"),
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "is_admin": bool(is_admin)
            }
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"Login failed: {str(e)}"}), 500

@app.post("/api/forgot-password")
def api_forgot_password():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"ok": False, "error": "Email is required."}), 400

    try:
        con = _auth_db()
        cur = con.cursor()

        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            con.close()
            return jsonify({
                "ok": True,
                "message": "If the email exists, reset instructions have been generated."
            })

        token = _generate_reset_token()
        expiry = int(time.time()) + (15 * 60)

        cur.execute(
            """
            UPDATE users
            SET reset_token = ?, reset_token_expiry = ?
            WHERE email = ?
            """,
            (token, expiry, email)
        )

        con.commit()
        con.close()

        return jsonify({
            "ok": True,
            "message": "Reset token generated.",
            "reset_token": token
        })

    except Exception:
        return jsonify({"ok": False, "error": "Failed to process request."}), 500


@app.post("/api/reset-password")
def api_reset_password():
    data = request.get_json(force=True, silent=True) or {}

    token = (data.get("token") or "").strip()
    new_password = (data.get("new_password") or "").strip()
    confirm_password = (data.get("confirm_password") or "").strip()

    if not token:
        return jsonify({"ok": False, "error": "Reset token required."}), 400

    if not new_password:
        return jsonify({"ok": False, "error": "New password required."}), 400

    if len(new_password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400

    if new_password != confirm_password:
        return jsonify({"ok": False, "error": "Passwords do not match."}), 400

    try:
        con = _auth_db()
        cur = con.cursor()

        cur.execute(
            """
            SELECT id, reset_token_expiry
            FROM users
            WHERE reset_token = ?
            """,
            (token,)
        )

        user = cur.fetchone()

        if not user:
            con.close()
            return jsonify({"ok": False, "error": "Invalid token."}), 400

        expiry = user["reset_token_expiry"]
        if expiry is None or int(time.time()) > int(expiry):
            con.close()
            return jsonify({"ok": False, "error": "Token expired."}), 400

        new_hash = generate_password_hash(new_password)

        cur.execute(
            """
            UPDATE users
            SET password_hash = ?,
                reset_token = NULL,
                reset_token_expiry = NULL,
                last_password_change_ts = ?
            WHERE id = ?
            """,
            (new_hash, int(time.time()), user["id"])
        )

        con.commit()
        con.close()

        return jsonify({
            "ok": True,
            "message": "Password reset successful."
        })
    except Exception:
        return jsonify({"ok": False, "error": "Reset failed."}), 500


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/auth/me")
def api_auth_me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "user": {
            "id": session.get("user_id"),
            "full_name": session.get("user_name"),
            "email": session.get("user_email"),
            "is_admin": bool(session.get("is_admin"))
        }
    })


# -----------------------------
# Views / Dashboard
# -----------------------------
@app.get("/")
def home():
    """Public web entry point.

    http://127.0.0.1:5000 is always the normal web app.
    The admin console is only under /admin.
    """
    if session.get("user_id"):
        return redirect(url_for("tool_view", tool_name="dashboard"))
    return redirect(url_for("auth_page"))


@app.get("/dashboard")
@login_required
def dashboard_alias():
    """Short public dashboard route for normal web users."""
    return redirect(url_for("tool_view", tool_name="dashboard"))


@app.get("/tool/<tool_name>")
@login_required
def tool_view(tool_name: str):
    allowed = {
        "dashboard", "gmail", "crypto", "password", "phishing",
        "header", "iprep", "filescan", "settings", "help",
        "emailcenter", "admin"
    }
    if tool_name not in allowed:
        tool_name = "dashboard"
    if tool_name == "admin":
        if not session.get("is_admin"):
            return redirect(url_for("tool_view", tool_name="dashboard"))
        return redirect(url_for("admin_console"))
    return render_template("dashboard.html", tool=tool_name)


# -----------------------------
# Dashboard Metrics API
# -----------------------------
@app.get("/api/dashboard/metrics")
def api_dashboard_metrics():
    start_ts, end_ts = _today_epoch_range_local()
    try:
        con = sqlite3.connect(str(METRICS_DB_PATH))
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute(
            """SELECT
                   COUNT(*) as total,
                   SUM(CASE WHEN label='SAFE' THEN 1 ELSE 0 END) as safe,
                   SUM(CASE WHEN label='LOW' THEN 1 ELSE 0 END) as low,
                   SUM(CASE WHEN label='MEDIUM' THEN 1 ELSE 0 END) as medium,
                   SUM(CASE WHEN label='HIGH' THEN 1 ELSE 0 END) as high,
                   AVG(score) as avg_score
                 FROM scan_events
                 WHERE ts >= ? AND ts < ?""",
            (start_ts, end_ts),
        )
        row = cur.fetchone() or {}
        total = int(row["total"] or 0)
        safe = int(row["safe"] or 0)
        low = int(row["low"] or 0)
        medium = int(row["medium"] or 0)
        high = int(row["high"] or 0)
        avg_score = float(row["avg_score"] or 0.0)

        cur.execute(
            """SELECT ts, module, target, score, label
                 FROM scan_events
                 WHERE ts >= ? AND ts < ?
                 ORDER BY ts DESC
                 LIMIT 10""",
            (start_ts, end_ts),
        )
        recent = []
        for r in cur.fetchall():
            recent.append({
                "ts": int(r["ts"]),
                "module": r["module"],
                "target": r["target"],
                "score": int(r["score"]),
                "label": r["label"],
            })

        con.close()

        return jsonify({
            "ok": True,
            "range": {"start_ts": start_ts, "end_ts": end_ts},
            "today": {
                "total": total,
                "safe": safe,
                "low": low,
                "medium": medium,
                "high": high,
                "avg_score": round(avg_score, 1),
            },
            "recent": recent,
        })
    except Exception:
        return jsonify({"ok": False, "error": "Metrics unavailable."}), 500


# -----------------------------
# Admin Dashboard APIs
# -----------------------------
def _db_scalar(db_path: Path, query: str, params=()):
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute(query, params)
    row = cur.fetchone()
    con.close()
    return row[0] if row else 0


def _safe_int(value, default=0):
    try:
        return int(value or 0)
    except Exception:
        return default


@app.get("/api/admin/stats")
@api_admin_required
def api_admin_stats():
    start_ts, end_ts = _today_epoch_range_local()
    admin_emails = tuple(_get_admin_emails())

    total_users = _safe_int(_db_scalar(AUTH_DB_PATH, "SELECT COUNT(*) FROM users"))

    # Active Today = non-admin users whose last successful web login happened today.
    active_query = """
        SELECT COUNT(*) AS c
        FROM users
        WHERE COALESCE(last_login_ts, 0) >= ?
          AND COALESCE(last_login_ts, 0) < ?
          AND lower(COALESCE(role, 'user')) <> 'admin'
    """
    active_params = [start_ts, end_ts]
    if admin_emails:
        active_query += " AND lower(COALESCE(email, '')) NOT IN (" + ",".join(["?"] * len(admin_emails)) + ")"
        active_params.extend(admin_emails)

    active_today = _safe_int(_db_scalar(AUTH_DB_PATH, active_query, tuple(active_params)))

    total_scans = _safe_int(_db_scalar(METRICS_DB_PATH, "SELECT COUNT(*) FROM scan_events"))
    high_risk = _safe_int(_db_scalar(METRICS_DB_PATH, "SELECT COUNT(*) FROM scan_events WHERE score >= 60 OR upper(label)='HIGH'"))
    emails_sent = _safe_int(_db_scalar(EMAIL_DB_PATH, "SELECT COUNT(*) FROM emails WHERE lower(folder)='sent' OR upper(status)='SENT'"))

    return jsonify({
        "ok": True,
        "total_users": total_users,
        "active_today": active_today,
        "total_scans": total_scans,
        "high_risk": high_risk,
        "emails_sent": emails_sent,
    })


@app.get("/api/admin/users")
@api_admin_required
def api_admin_users():
    con = _auth_db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, full_name, email, created_at, COALESCE(role, 'user') AS role,
               COALESCE(last_login_ts, 0) AS last_login
        FROM users
        ORDER BY id DESC
        LIMIT 200
        """
    )
    rows = cur.fetchall()
    con.close()

    users = []
    for r in rows:
        users.append({
            "id": int(r["id"]),
            "name": r["full_name"] or "",
            "email": r["email"] or "",
            "role": (r["role"] or "user").lower(),
            "date_registered": int(r["created_at"] or 0),
            "last_login": int(r["last_login"] or 0) if r["last_login"] else None,
        })

    return jsonify({"ok": True, "users": users})


@app.get("/api/admin/activity")
@api_admin_required
def api_admin_activity():
    limit = max(1, min(200, _safe_int(request.args.get("limit"), 100)))
    con = _auth_db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT user_name, email, action, ip_address, status, ts
        FROM login_activity
        ORDER BY ts DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    con.close()

    activity = []
    for r in rows:
        activity.append({
            "user": r["user_name"] or r["email"] or "Unknown",
            "email": r["email"] or "",
            "action": r["action"] or "",
            "ip_address": r["ip_address"] or "",
            "timestamp": int(r["ts"] or 0),
            "status": r["status"] or "",
        })

    return jsonify({"ok": True, "activity": activity})


@app.get("/api/admin/threats")
@api_admin_required
def api_admin_threats():
    limit = max(1, min(200, _safe_int(request.args.get("limit"), 100)))
    risk = (request.args.get("risk") or "").strip().upper()

    con = sqlite3.connect(str(METRICS_DB_PATH))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    if risk in {"SAFE", "LOW", "MEDIUM", "HIGH"}:
        cur.execute(
            """
            SELECT id, ts, module, target, score, label
            FROM scan_events
            WHERE upper(label)=?
            ORDER BY ts DESC
            LIMIT ?
            """,
            (risk, limit),
        )
    else:
        cur.execute(
            """
            SELECT id, ts, module, target, score, label
            FROM scan_events
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        )

    rows = cur.fetchall()
    con.close()

    threats = []
    for r in rows:
        threats.append({
            "id": int(r["id"]),
            "timestamp": int(r["ts"] or 0),
            "module": r["module"] or "",
            "target": r["target"] or "",
            "score": int(r["score"] or 0),
            "label": (r["label"] or "SAFE").upper(),
            "details": f"{r['module'] or 'Scan'} → {(r['target'] or 'Unknown target')}",
        })

    return jsonify({"ok": True, "threats": threats})


@app.get("/api/admin/emails")
@api_admin_required
def api_admin_emails():
    limit = max(1, min(200, _safe_int(request.args.get("limit"), 100)))
    con = _email_db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT sender, recipient, subject, sent_at, status, folder
        FROM emails
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    con.close()

    emails = []
    for r in rows:
        try:
            recipients = json.loads(r["recipient"] or "[]")
        except Exception:
            recipients = []
        emails.append({
            "sender": r["sender"] or "",
            "recipient": ", ".join(recipients) if isinstance(recipients, list) else str(recipients or ""),
            "subject": r["subject"] or "",
            "timestamp": r["sent_at"] or "",
            "status": (r["status"] or r["folder"] or "").upper(),
        })

    return jsonify({"ok": True, "emails": emails})



# -----------------------------
# Private Admin Views
# -----------------------------
@app.get("/admin/login")
def admin_login_page():
    if session.get("user_id") and session.get("is_admin"):
        current_email = (session.get("user_email") or "").strip().lower()
        allowed_admins = _get_admin_emails()
        if (not allowed_admins) or current_email in allowed_admins:
            session["admin_email"] = current_email
            return redirect(url_for("admin_console"))
    return render_template("admin/login.html")


@app.post("/admin/login")
@_limit("10 per minute")
def admin_login_submit():
    data = request.get_json(silent=True) or request.form or {}
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    allowed_admins = _get_admin_emails()
    if allowed_admins and email not in allowed_admins:
        _log_login_activity(None, "", email, "ADMIN_LOGIN", "DENIED")
        _log_admin_audit("ADMIN_LOGIN", "DENIED", details={"email": email})
        return jsonify({"error": "Access denied."}), 403

    try:
        con = _auth_db()
        row = con.execute(
            """
            SELECT id, full_name, email, password_hash,
                   COALESCE(role, 'user') as role,
                   COALESCE(is_active, 1) as is_active,
                   COALESCE(is_locked, 0) as is_locked
            FROM users
            WHERE lower(email)=lower(?)
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        if not row:
            con.close()
            _log_login_activity(None, "", email, "ADMIN_LOGIN", "FAILED")
            _log_admin_audit("ADMIN_LOGIN", "FAILED", details={"email": email, "reason": "not_found"})
            return jsonify({"error": "Invalid admin credentials."}), 401

        if int(row["is_active"] or 1) != 1:
            con.close()
            _log_login_activity(row["id"], row["full_name"], row["email"], "ADMIN_LOGIN", "BLOCKED")
            _log_admin_audit("ADMIN_LOGIN", "FAILED", details={"email": email, "reason": "inactive"})
            return jsonify({"error": "Account disabled."}), 403

        if int(row["is_locked"] or 0) == 1:
            con.close()
            _log_login_activity(row["id"], row["full_name"], row["email"], "ADMIN_LOGIN", "LOCKED")
            _log_admin_audit("ADMIN_LOGIN", "FAILED", details={"email": email, "reason": "locked"})
            return jsonify({"error": "Account locked."}), 403

        if not check_password_hash(row["password_hash"], password):
            try:
                con.execute(
                    "UPDATE users SET failed_login_count=COALESCE(failed_login_count,0)+1 WHERE id=?",
                    (row["id"],)
                )
                con.commit()
            except Exception:
                pass
            con.close()
            _log_login_activity(row["id"], row["full_name"], row["email"], "ADMIN_LOGIN", "FAILED")
            _log_admin_audit("ADMIN_LOGIN", "FAILED", details={"email": email, "reason": "bad_password"})
            return jsonify({"error": "Invalid admin credentials."}), 401

        try:
            con.execute(
                "UPDATE users SET role='admin', failed_login_count=0, last_login_ts=? WHERE id=?",
                (int(time.time()), row["id"])
            )
            con.commit()
        except Exception:
            pass
        con.close()

        session.clear()
        session.permanent = False
        session["boot_id"] = APP_BOOT_ID
        session["user_id"] = row["id"]
        session["user_name"] = row["full_name"]
        session["user_email"] = row["email"]
        session["is_admin"] = True
        session["admin_email"] = row["email"]

        _log_login_activity(row["id"], row["full_name"], row["email"], "ADMIN_LOGIN", "SUCCESS")
        _log_admin_audit("ADMIN_LOGIN", "SUCCESS")

        return jsonify({"ok": True, "redirect_url": url_for("admin_console")})
    except Exception as e:
        _log_admin_audit("ADMIN_LOGIN", "FAILED", details={"email": email, "reason": str(e)})
        return jsonify({"error": f"Admin login failed: {e}"}), 500


@app.post("/admin/logout")
@api_private_admin_required
def admin_logout():
    _log_admin_audit("ADMIN_LOGOUT", "SUCCESS")
    session.clear()
    return jsonify({"ok": True, "redirect_url": url_for("admin_login_page")})


@app.get("/admin")
@api_private_admin_required
def admin_console():
    return render_template("admin/dashboard.html")


@app.get("/admin/users")
@api_private_admin_required
def admin_users_page():
    return render_template("admin/dashboard.html")


@app.get("/admin/activity")
@api_private_admin_required
def admin_activity_page():
    return render_template("admin/dashboard.html")


@app.get("/admin/threats")
@api_private_admin_required
def admin_threats_page():
    return render_template("admin/dashboard.html")


@app.get("/admin/system")
@api_private_admin_required
def admin_system_page():
    return render_template("admin/dashboard.html")


# -----------------------------
# Private Admin APIs
# -----------------------------
@app.get("/api/admin/private/stats")
@api_private_admin_required
def api_admin_private_stats():
    try:
        start_ts, end_ts = _today_epoch_range_local()
        admin_emails = tuple(_get_admin_emails())

        # ---------- AUTH DB ----------
        con = _auth_db()
        cur = con.cursor()

        cur.execute("SELECT COUNT(*) AS c FROM users")
        total_users = int((cur.fetchone()["c"]) or 0)

        # Active Today = non-admin users whose last successful web login happened today.
        # This avoids failures on older login_activity tables and exactly matches the dashboard meaning.
        active_query = """
            SELECT COUNT(*) AS c
            FROM users
            WHERE COALESCE(last_login_ts, 0) >= ?
              AND COALESCE(last_login_ts, 0) < ?
              AND lower(COALESCE(role, 'user')) <> 'admin'
        """
        active_params = [start_ts, end_ts]
        if admin_emails:
            active_query += " AND lower(COALESCE(email, '')) NOT IN (" + ",".join(["?"] * len(admin_emails)) + ")"
            active_params.extend(admin_emails)

        cur.execute(active_query, tuple(active_params))
        active_users_today = int((cur.fetchone()["c"]) or 0)
        con.close()

        # ---------- METRICS DB ----------
        mcon = _metrics_db()
        mcur = mcon.cursor()

        total_scans = 0
        high_risk_threats = 0

        metric_cols = _table_columns(mcon, "scan_events")
        if metric_cols:
            mcur.execute("SELECT COUNT(*) AS c FROM scan_events")
            total_scans = int((mcur.fetchone()["c"]) or 0)

            score_col = _pick_column(metric_cols, ["risk_score", "score", "threat_score"])
            label_col = _pick_column(metric_cols, ["risk_label", "label", "risk", "threat_label"])

            if score_col and label_col:
                mcur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM scan_events
                    WHERE COALESCE({score_col}, 0) >= 60
                       OR UPPER(COALESCE({label_col}, '')) IN ('HIGH', 'CRITICAL')
                    """
                )
                high_risk_threats = int((mcur.fetchone()["c"]) or 0)
            elif score_col:
                mcur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM scan_events
                    WHERE COALESCE({score_col}, 0) >= 60
                    """
                )
                high_risk_threats = int((mcur.fetchone()["c"]) or 0)
            elif label_col:
                mcur.execute(
                    f"""
                    SELECT COUNT(*) AS c
                    FROM scan_events
                    WHERE UPPER(COALESCE({label_col}, '')) IN ('HIGH', 'CRITICAL')
                    """
                )
                high_risk_threats = int((mcur.fetchone()["c"]) or 0)

        mcon.close()

        # ---------- EMAIL DB ----------
        econ = _email_db()
        ecur = econ.cursor()

        email_cols = _table_columns(econ, "emails")
        folder_col = _pick_column(email_cols, ["folder", "mailbox"])
        status_col = _pick_column(email_cols, ["status", "state"])

        emails_sent = 0
        if folder_col and status_col:
            ecur.execute(
                f"""
                SELECT COUNT(*) AS c
                FROM emails
                WHERE LOWER(COALESCE({folder_col}, '')) = 'sent'
                   OR LOWER(COALESCE({status_col}, '')) = 'sent'
                """
            )
            emails_sent = int((ecur.fetchone()["c"]) or 0)
        elif folder_col:
            ecur.execute(
                f"""
                SELECT COUNT(*) AS c
                FROM emails
                WHERE LOWER(COALESCE({folder_col}, '')) = 'sent'
                """
            )
            emails_sent = int((ecur.fetchone()["c"]) or 0)
        elif status_col:
            ecur.execute(
                f"""
                SELECT COUNT(*) AS c
                FROM emails
                WHERE LOWER(COALESCE({status_col}, '')) = 'sent'
                """
            )
            emails_sent = int((ecur.fetchone()["c"]) or 0)
        else:
            ecur.execute("SELECT COUNT(*) AS c FROM emails")
            emails_sent = int((ecur.fetchone()["c"]) or 0)

        econ.close()

        return jsonify({
            "ok": True,
            "stats": {
                "total_users": total_users,
                "active_users_today": active_users_today,
                "total_scans": total_scans,
                "high_risk_threats": high_risk_threats,
                "emails_sent": emails_sent
            },
            "admin": {
                "email": session.get("admin_email") or session.get("user_email") or ""
            }
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"Failed to load admin stats: {e}"
        }), 500

@app.get("/api/admin/private/users")
@api_private_admin_required
def api_admin_private_users():
    try:
        q = (request.args.get("q") or "").strip().lower()

        con = _auth_db()
        cur = con.cursor()

        if q:
            cur.execute(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    COALESCE(role, 'user') AS role,
                    COALESCE(is_active, 1) AS is_active,
                    COALESCE(is_locked, 0) AS is_locked,
                    COALESCE(failed_login_count, 0) AS failed_login_count,
                    last_login_ts
                FROM users
                WHERE lower(full_name) LIKE ? OR lower(email) LIKE ?
                ORDER BY id DESC
                """,
                (f"%{q}%", f"%{q}%")
            )
        else:
            cur.execute(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    COALESCE(role, 'user') AS role,
                    COALESCE(is_active, 1) AS is_active,
                    COALESCE(is_locked, 0) AS is_locked,
                    COALESCE(failed_login_count, 0) AS failed_login_count,
                    last_login_ts
                FROM users
                ORDER BY id DESC
                """
            )

        rows = cur.fetchall()
        con.close()

        users = []
        for r in rows:
            users.append({
                "id": r["id"],
                "full_name": r["full_name"],
                "email": r["email"],
                "role": r["role"],
                "is_active": int(r["is_active"] or 0),
                "is_locked": int(r["is_locked"] or 0),
                "failed_login_count": int(r["failed_login_count"] or 0),
                "last_login_ts": int(r["last_login_ts"] or 0) if r["last_login_ts"] else 0,
            })

        return jsonify({"ok": True, "users": users})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to load users: {e}"}), 500


@app.get("/api/admin/private/activity")
@api_private_admin_required
def api_admin_private_activity():
    try:
        con = _auth_db()
        cur = con.cursor()

        cols = _table_columns(con, "login_activity")
        if not cols:
            con.close()
            return jsonify({"ok": True, "activity": []})

        user_name_col = _pick_column(cols, ["user_name", "full_name", "name"])
        email_col = _pick_column(cols, ["email", "user_email"])
        action_col = _pick_column(cols, ["action", "event"])
        ip_col = _pick_column(cols, ["ip_address", "ip"])
        status_col = _pick_column(cols, ["status", "result"])
        ts_col = _pick_column(cols, ["ts", "created_at", "timestamp", "login_time"])

        query = f"""
            SELECT
                {f"COALESCE({user_name_col}, '')" if user_name_col else "''"} AS user_name,
                {f"COALESCE({email_col}, '')" if email_col else "''"} AS email,
                {f"COALESCE({action_col}, '')" if action_col else "''"} AS action,
                {f"COALESCE({ip_col}, '')" if ip_col else "''"} AS ip_address,
                {f"COALESCE({status_col}, '')" if status_col else "''"} AS status,
                {f"COALESCE({ts_col}, 0)" if ts_col else "0"} AS ts
            FROM login_activity
        """

        if ts_col:
            query += f" ORDER BY {ts_col} DESC"
        else:
            query += " ORDER BY rowid DESC"

        query += " LIMIT 200"

        cur.execute(query)
        rows = cur.fetchall()
        con.close()

        activity = [{
            "user_name": r["user_name"],
            "email": r["email"],
            "action": r["action"],
            "ip_address": r["ip_address"],
            "status": r["status"],
            "ts": r["ts"],
        } for r in rows]

        return jsonify({"ok": True, "activity": activity})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to load activity: {e}"}), 500


@app.get("/api/admin/private/threats")
@api_private_admin_required
def api_admin_private_threats():
    try:
        risk = (request.args.get("risk") or "").strip().upper()

        con = _metrics_db()
        cur = con.cursor()

        cols = _table_columns(con, "scan_events")
        if not cols:
            con.close()
            return jsonify({"ok": True, "threats": []})

        scan_col = _pick_column(cols, ["scan_type", "scan", "module", "tool_name"])
        target_col = _pick_column(cols, ["target", "subject", "input_value", "resource"])
        score_col = _pick_column(cols, ["risk_score", "score", "threat_score"])
        label_col = _pick_column(cols, ["risk_label", "label", "risk", "threat_label"])
        ts_col = _pick_column(cols, ["ts", "created_at", "timestamp", "logged_at"])

        select_scan = f"COALESCE({scan_col}, '') AS scan" if scan_col else "'' AS scan"
        select_target = f"COALESCE({target_col}, '') AS target" if target_col else "'' AS target"
        select_score = f"COALESCE({score_col}, 0) AS risk_score" if score_col else "0 AS risk_score"
        select_label = f"COALESCE({label_col}, '') AS risk_label" if label_col else "'' AS risk_label"
        select_ts = f"COALESCE({ts_col}, 0) AS ts" if ts_col else "0 AS ts"

        query = f"""
            SELECT
                {select_scan},
                {select_target},
                {select_score},
                {select_label},
                {select_ts}
            FROM scan_events
        """

        params = []
        if risk and label_col:
            query += f" WHERE UPPER(COALESCE({label_col}, '')) = ?"
            params.append(risk)

        if ts_col:
            query += f" ORDER BY {ts_col} DESC"
        else:
            query += " ORDER BY rowid DESC"

        query += " LIMIT 200"

        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        con.close()

        threats = [{
            "scan": r["scan"],
            "target": r["target"],
            "risk_score": r["risk_score"],
            "risk_label": r["risk_label"],
            "ts": r["ts"],
        } for r in rows]

        return jsonify({"ok": True, "threats": threats})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to load threats: {e}"}), 500

@app.get("/api/admin/private/audit")
@api_private_admin_required
def api_admin_private_audit():
    try:
        con = _auth_db()
        cur = con.cursor()

        cols = _table_columns(con, "admin_audit_log")
        if not cols:
            con.close()
            return jsonify({"ok": True, "audit": []})

        admin_email_col = _pick_column(cols, ["admin_email", "email"])
        action_col = _pick_column(cols, ["action", "event"])
        target_type_col = _pick_column(cols, ["target_type"])
        target_id_col = _pick_column(cols, ["target_id"])
        status_col = _pick_column(cols, ["status", "result"])
        ip_col = _pick_column(cols, ["ip_address", "ip"])
        ts_col = _pick_column(cols, ["ts", "created_at", "timestamp", "logged_at"])

        query = f"""
            SELECT
                {f"COALESCE({admin_email_col}, '')" if admin_email_col else "''"} AS admin_email,
                {f"COALESCE({action_col}, '')" if action_col else "''"} AS action,
                {f"COALESCE({target_type_col}, '')" if target_type_col else "''"} AS target_type,
                {f"COALESCE({target_id_col}, '')" if target_id_col else "''"} AS target_id,
                {f"COALESCE({status_col}, '')" if status_col else "''"} AS status,
                {f"COALESCE({ip_col}, '')" if ip_col else "''"} AS ip_address,
                {f"COALESCE({ts_col}, 0)" if ts_col else "0"} AS ts
            FROM admin_audit_log
        """

        if ts_col:
            query += f" ORDER BY {ts_col} DESC"
        else:
            query += " ORDER BY rowid DESC"

        query += " LIMIT 200"

        cur.execute(query)
        rows = cur.fetchall()
        con.close()

        audit = [{
            "admin_email": r["admin_email"],
            "action": r["action"],
            "target_type": r["target_type"],
            "target_id": r["target_id"],
            "status": r["status"],
            "ip_address": r["ip_address"],
            "ts": r["ts"],
        } for r in rows]

        return jsonify({"ok": True, "audit": audit})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to load audit log: {e}"}), 500

@app.get("/api/admin/private/system")
@api_private_admin_required
def api_admin_private_system():
    try:
        system = {
            "providers": {
                "gmail_oauth": bool(os.getenv("GOOGLE_CLIENT_ID")),
                "openai_key": bool(os.getenv("OPENAI_API_KEY")),
            },
            "files": {
                "auth_db": AUTH_DB_PATH.exists(),
                "metrics_db": METRICS_DB_PATH.exists(),
                "email_db": EMAIL_DB_PATH.exists(),
            },
            "runtime": {
                "boot_id": APP_BOOT_ID,
                "env": os.getenv("FLASK_ENV", "production"),
            }
        }
        return jsonify({"ok": True, "system": system})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to load system status: {e}"}), 500


@app.get("/api/admin/private/users/<int:user_id>")
@api_private_admin_required
def api_admin_get_user(user_id: int):
    try:
        con = _auth_db()
        row = con.execute(
            """
            SELECT id, full_name, email, COALESCE(role,'user') AS role,
                   COALESCE(is_active,1) AS is_active,
                   COALESCE(is_locked,0) AS is_locked,
                   COALESCE(failed_login_count,0) AS failed_login_count,
                   created_at, last_login_ts, last_password_change_ts
            FROM users
            WHERE id=?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        con.close()

        if not row:
            return jsonify({"error": "User not found."}), 404

        return jsonify({"ok": True, "user": dict(row)})
    except Exception:
        return jsonify({"error": "Failed to load user."}), 500


@app.post("/api/admin/private/users/<int:user_id>/role")
@api_private_admin_required
def api_admin_set_role(user_id: int):
    data = request.get_json(silent=True) or {}
    role = str(data.get("role") or "").strip().lower()

    if role not in {"user", "admin"}:
        return jsonify({"error": "Invalid role."}), 400

    try:
        con = _auth_db()
        row = con.execute(
            "SELECT id, email, COALESCE(role,'user') AS role FROM users WHERE id=? LIMIT 1",
            (user_id,),
        ).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        current_admin_email = (session.get("admin_email") or session.get("user_email") or "").strip().lower()
        target_email = (row["email"] or "").strip().lower()

        if target_email == current_admin_email and role != "admin":
            con.close()
            return jsonify({"error": "You cannot remove your own admin role."}), 400

        con.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        con.commit()
        con.close()

        _log_admin_audit("SET_ROLE", "SUCCESS", "user", str(user_id), {"email": target_email, "from": row["role"], "to": role})
        return jsonify({"ok": True, "message": f"Role updated to {role}."})
    except Exception as e:
        _log_admin_audit("SET_ROLE", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to update role."}), 500


@app.post("/api/admin/private/users/<int:user_id>/disable")
@api_private_admin_required
def api_admin_disable_user(user_id: int):
    try:
        con = _auth_db()
        row = con.execute("SELECT id, email FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        current_admin_email = (session.get("admin_email") or session.get("user_email") or "").strip().lower()
        target_email = (row["email"] or "").strip().lower()
        if target_email == current_admin_email:
            con.close()
            return jsonify({"error": "You cannot disable your own account."}), 400

        con.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
        con.commit()
        con.close()

        _log_admin_audit("DISABLE_USER", "SUCCESS", "user", str(user_id), {"email": target_email})
        return jsonify({"ok": True, "message": "User disabled."})
    except Exception as e:
        _log_admin_audit("DISABLE_USER", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to disable user."}), 500


@app.post("/api/admin/private/users/<int:user_id>/enable")
@api_private_admin_required
def api_admin_enable_user(user_id: int):
    try:
        con = _auth_db()
        row = con.execute("SELECT id, email FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        con.execute(
            """
            UPDATE users
            SET is_active=1,
                is_locked=0,
                failed_login_count=0
            WHERE id=?
            """,
            (user_id,),
        )
        con.commit()
        con.close()

        _log_admin_audit("ENABLE_USER", "SUCCESS", "user", str(user_id), {"email": row["email"]})
        return jsonify({"ok": True, "message": "User enabled."})
    except Exception as e:
        _log_admin_audit("ENABLE_USER", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to enable user."}), 500


@app.post("/api/admin/private/users/<int:user_id>/lock")
@api_private_admin_required
def api_admin_lock_user(user_id: int):
    try:
        con = _auth_db()
        row = con.execute("SELECT id, email FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        current_admin_email = (session.get("admin_email") or session.get("user_email") or "").strip().lower()
        target_email = (row["email"] or "").strip().lower()
        if target_email == current_admin_email:
            con.close()
            return jsonify({"error": "You cannot lock your own account."}), 400

        con.execute("UPDATE users SET is_locked=1 WHERE id=?", (user_id,))
        con.commit()
        con.close()

        _log_admin_audit("LOCK_USER", "SUCCESS", "user", str(user_id), {"email": target_email})
        return jsonify({"ok": True, "message": "User locked."})
    except Exception as e:
        _log_admin_audit("LOCK_USER", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to lock user."}), 500


@app.post("/api/admin/private/users/<int:user_id>/unlock")
@api_private_admin_required
def api_admin_unlock_user(user_id: int):
    try:
        con = _auth_db()
        row = con.execute("SELECT id, email FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        con.execute(
            """
            UPDATE users
            SET is_locked=0,
                failed_login_count=0
            WHERE id=?
            """,
            (user_id,),
        )
        con.commit()
        con.close()

        _log_admin_audit("UNLOCK_USER", "SUCCESS", "user", str(user_id), {"email": row["email"]})
        return jsonify({"ok": True, "message": "User unlocked."})
    except Exception as e:
        _log_admin_audit("UNLOCK_USER", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to unlock user."}), 500


@app.post("/api/admin/private/users/<int:user_id>/force-reset")
@api_private_admin_required
def api_admin_force_reset(user_id: int):
    try:
        con = _auth_db()
        row = con.execute("SELECT id, email FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()

        if not row:
            con.close()
            return jsonify({"error": "User not found."}), 404

        reset_token = _generate_reset_token()
        reset_expiry = int(time.time()) + (30 * 60)

        con.execute(
            """
            UPDATE users
            SET reset_token=?,
                reset_token_expiry=?
            WHERE id=?
            """,
            (reset_token, reset_expiry, user_id),
        )
        con.commit()
        con.close()

        _log_admin_audit("FORCE_PASSWORD_RESET", "SUCCESS", "user", str(user_id), {"email": row["email"]})
        return jsonify({
            "ok": True,
            "message": "Password reset token generated.",
            "reset_token": reset_token,
            "expires_in_minutes": 30,
        })
    except Exception as e:
        _log_admin_audit("FORCE_PASSWORD_RESET", "FAILED", "user", str(user_id), {"error": str(e)})
        return jsonify({"error": "Failed to generate reset token."}), 500

# -----------------------------
# Gmail APIs
# -----------------------------
@app.route("/api/gmail/status", methods=["GET"])
def gmail_status():
    try:
        token_path = BASE_DIR / "token.json"
        if not token_path.exists():
            return jsonify({"connected": False, "reason": "token.json missing"}), 200

        creds = Credentials.from_authorized_user_file(
            str(token_path),
            ["https://www.googleapis.com/auth/gmail.modify"]
        )

        if not creds:
            return jsonify({"connected": False, "reason": "no credentials loaded"}), 200

        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                token_path.write_text(creds.to_json(), encoding="utf-8")
            except Exception as e:
                return jsonify({"connected": False, "reason": f"refresh failed: {e}"}), 200

        if not creds.valid:
            return jsonify({"connected": False, "reason": "credentials invalid"}), 200

        return jsonify({"connected": True}), 200

    except Exception as e:
        return jsonify({"connected": False, "reason": str(e)}), 200
    
@app.route("/api/gmail/profile", methods=["GET"])
def gmail_profile():
    try:
        token_path = BASE_DIR / "token.json"
        if not token_path.exists():
            return jsonify({"error": "token.json missing"}), 401

        creds = Credentials.from_authorized_user_file(
            str(token_path),
            ["https://www.googleapis.com/auth/gmail.modify"]
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            token_path.write_text(creds.to_json(), encoding="utf-8")

        if not creds.valid:
            return jsonify({"error": "gmail credentials invalid"}), 401

        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()

        return jsonify({
            "ok": True,
            "profile": profile
        }), 200

    except Exception as e:
        return jsonify({"error": f"Gmail profile failed: {e}"}), 401

@app.route("/api/gmail/connect")
def gmail_connect():
    """Start Gmail OAuth using the Flask callback route."""
    try:
        if not gmail_is_configured():
            return jsonify({"error": "Gmail OAuth is not configured. Check credentials.json."}), 500

        # Use the same redirect URI handled by /oauth2callback.
        # Do not use InstalledAppFlow.run_local_server(port=0) here.
        try:
            auth_result = gmail_get_auth_url(FORCED_REDIRECT_URI)
        except TypeError:
            auth_result = gmail_get_auth_url()

        auth_url = ""
        state = ""

        if isinstance(auth_result, tuple):
            auth_url = auth_result[0] if len(auth_result) >= 1 else ""
            state = auth_result[1] if len(auth_result) >= 2 else ""
        elif isinstance(auth_result, dict):
            auth_url = auth_result.get("auth_url") or auth_result.get("url") or ""
            state = auth_result.get("state") or ""
        else:
            auth_url = str(auth_result or "")

        if not auth_url:
            return jsonify({"error": "Gmail OAuth URL could not be generated."}), 500

        if state:
            session["oauth_state"] = state

        return redirect(auth_url)

    except Exception as e:
        return jsonify({"error": f"Gmail connect failed: {e}"}), 500


@app.get("/oauth2callback")
def oauth2callback():
    args = dict(request.args)
    session["gmail_last_oauth_args"] = args

    if "error" in request.args:
        session["gmail_last_oauth_msg"] = f"Google error: {request.args.get('error')}"
        return render_template(
            "oauth_result.html",
            ok=False,
            message=session["gmail_last_oauth_msg"],
            details=args,
            next_url=url_for("tool_view", tool_name="gmail"),
        )

    expected_state = session.get("oauth_state", "")
    ok, msg = gmail_handle_callback(request.url, FORCED_REDIRECT_URI, expected_state)
    session["gmail_last_oauth_msg"] = msg

    return render_template(
        "oauth_result.html",
        ok=ok,
        message=msg,
        details=args,
        next_url=url_for("tool_view", tool_name="gmail"),
    )


@app.post("/api/gmail/disconnect")
def api_gmail_disconnect():
    gmail_disconnect()
    session.pop("oauth_state", None)
    session.pop("last_delete_id", None)
    session.pop("last_delete_ts", None)
    session.pop("gmail_last_oauth_msg", None)
    session.pop("gmail_last_oauth_args", None)
    return jsonify({"ok": True, "message": "Gmail disconnected."})


@app.get("/api/gmail/inbox")
def api_gmail_inbox():
    if not gmail_connected():
        return jsonify({"error": "Not connected (token.json missing)."}), 401

    box = _normalize_gmail_box(request.args.get("box") or "inbox")
    try:
        max_results = int(request.args.get("max", "100"))
    except ValueError:
        max_results = 100
    max_results = max(1, min(100, max_results))

    try:
        return jsonify(_gmail_list_box_safe(max_results=max_results, box=box))
    except Exception as e:
        return jsonify({"error": f"Inbox fetch failed: {e}", "box": box}), 400


def _safe_urlparse_host(u: str) -> str:
    try:
        p = urlparse(u if "://" in u else "http://" + u)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def _panel_level_from_score(score: int) -> str:
    s = max(0, min(100, int(score or 0)))
    if s >= 85:
        return "CRITICAL"
    if s >= 60:
        return "HIGH RISK"
    if s >= 30:
        return "MEDIUM RISK"
    if s >= 11:
        return "LOW RISK"
    return "SAFE"


def _status_from_auth(value: str) -> str:
    v = str(value or "").strip().upper()
    if v == "PASS":
        return "PASS"
    if v == "FAIL":
        return "FAIL"
    return "WARNING"


def _friendly_status_text(status: str) -> str:
    s = str(status or "").upper()
    if s == "PASS":
        return "PASS"
    if s == "FAIL":
        return "FAIL"
    return "WARNING"


def _extract_originating_ip(raw_headers: str) -> str:
    if not raw_headers:
        return ""
    patterns = [
        r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]",
        r"from\s+\S+\s+\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)",
        r"client-ip[:=]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
    ]
    for pat in patterns:
        m = re.search(pat, raw_headers, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _extract_return_path(raw_headers: str) -> str:
    if not raw_headers:
        return ""
    m = re.search(r"^Return-Path:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _extract_reply_to(raw_headers: str) -> str:
    if not raw_headers:
        return ""
    m = re.search(r"^Reply-To:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _extract_received_relays(raw_headers: str):
    if not raw_headers:
        return []
    matches = re.findall(r"^Received:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    clean = []
    for item in matches[:4]:
        t = " ".join(str(item).split())
        if t and t not in clean:
            clean.append(t[:180])
    return clean


def _simple_detail_text(score: int, indicators: list) -> str:
    if score >= 85:
        return (
            "This email looks very dangerous.\n"
            "It has strong warning signs often seen in scam emails.\n"
            "Do not click links, open files, or reply.\n"
            "Confirm it another way before taking action."
        )
    if score >= 60:
        return (
            "This email looks risky.\n"
            "Some safety checks failed and parts of it may be misleading.\n"
            "Avoid clicking anything for now.\n"
            "Confirm who sent it first."
        )
    if score >= 30:
        return (
            "This email has some warning signs.\n"
            "It may still be real, but caution is needed.\n"
            "Be careful with links, files, and requests for information.\n"
            "Verify the sender before interacting."
        )
    if score >= 11:
        return (
            "This email only shows a few minor concerns.\n"
            "It does not look highly dangerous.\n"
            "Still be careful with unexpected links or files."
        )
    return (
        "This email looks safe from the checks completed so far.\n"
        "No major danger signs were found."
    )


def _build_threat_panel(msg, raw_headers, auth, header_findings, url_findings, attachment_findings, base_score):
    score = 0
    breakdown = []

    def add_points(label: str, points: int, condition: bool):
        nonlocal score
        if condition:
            score += points
            breakdown.append({"label": label, "points": points})

    spf_status = _status_from_auth(auth.get("spf"))
    dkim_status = _status_from_auth(auth.get("dkim"))
    dmarc_status = _status_from_auth(auth.get("dmarc"))

    add_points("SPF failed", 20, spf_status == "FAIL")
    add_points("DKIM failed", 20, dkim_status == "FAIL")
    add_points("DMARC failed", 20, dmarc_status == "FAIL")
    add_points(
        "Header anomaly",
        10,
        bool(
            header_findings.get("mismatch_from_return_path")
            or header_findings.get("reply_to_mismatch")
            or header_findings.get("spoofing_indicators")
            or header_findings.get("display_name_spoof")
        ),
    )
    add_points("Suspicious URL", 15, bool(url_findings.get("domain_mismatch") or url_findings.get("login_pattern") or url_findings.get("long_url")))
    add_points("Suspicious attachment", 10, bool(attachment_findings.get("macro_enabled") or attachment_findings.get("executable") or attachment_findings.get("suspicious_types")))
    add_points("Young domain", 10, isinstance(url_findings.get("young_domain_days"), int) and url_findings.get("young_domain_days") <= 30)

    score = max(0, min(100, score))
    if base_score is not None:
        score = max(score, max(0, min(100, int(base_score or 0))))

    level = _panel_level_from_score(score)

    originating_ip = _extract_originating_ip(raw_headers)
    return_path = _extract_return_path(raw_headers)
    reply_to = _extract_reply_to(raw_headers)
    relays = _extract_received_relays(raw_headers)

    body_blob = ((msg.get("text") or "") + " " + (msg.get("snippet") or "")).lower()
    phishing_language = any(k in body_blob for k in [
        "urgent", "immediately", "verify your account", "reset your password",
        "click here", "limited time", "suspended", "confirm now"
    ])

    sender_ip_status = "WARNING" if originating_ip else "WARNING"
    sender_ip_explain = (
        f"We found a sending server address ({originating_ip}), but it was not confirmed as trusted yet."
        if originating_ip else
        "We could not clearly confirm the original sending server."
    )

    domain_reputation_status = "FAIL" if bool(url_findings.get("domain_mismatch")) else (
        "WARNING" if isinstance(url_findings.get("young_domain_days"), int) and url_findings.get("young_domain_days") <= 30 else "PASS"
    )
    domain_reputation_explain = (
        "The links in this email point to a different domain than the sender, which is a common phishing trick."
        if bool(url_findings.get("domain_mismatch")) else
        "The website linked in this email looks new, so extra care is needed."
        if isinstance(url_findings.get("young_domain_days"), int) and url_findings.get("young_domain_days") <= 30 else
        "No strong domain reputation issue was found."
    )

    header_status = "FAIL" if bool(header_findings.get("mismatch_from_return_path") or header_findings.get("reply_to_mismatch") or header_findings.get("spoofing_indicators")) else "PASS"
    header_explain = (
        "Some sender details do not match properly, which can happen in spoofed emails."
        if header_status == "FAIL" else
        "The main sender details look consistent."
    )

    url_status = "FAIL" if bool(url_findings.get("domain_mismatch") or url_findings.get("login_pattern")) else (
        "WARNING" if bool(url_findings.get("long_url") or url_findings.get("tracking_url")) else "PASS"
    )
    url_explain = (
        "This email contains a link that may lead to a risky or misleading website."
        if url_status == "FAIL" else
        "A link in this email needs caution before clicking."
        if url_status == "WARNING" else
        "No major link issue was detected."
    )

    attachment_status = "FAIL" if bool(attachment_findings.get("macro_enabled") or attachment_findings.get("executable")) else (
        "WARNING" if bool(attachment_findings.get("count")) else "PASS"
    )
    attachment_explain = (
        "This email has a file type that can be dangerous."
        if attachment_status == "FAIL" else
        "This email includes a file, so open it only if you fully trust the sender."
        if attachment_status == "WARNING" else
        "No attachment risk was detected."
    )

    language_status = "WARNING" if phishing_language else "PASS"
    language_explain = (
        "The message uses pressure or urgent language that can be used to trick people."
        if phishing_language else
        "The wording does not strongly match common phishing pressure tactics."
    )

    indicators = [
        {
            "group": "Authentication Checks",
            "name": "SPF Result",
            "status": spf_status,
            "explanation": "The sender is allowed to send on behalf of this domain." if spf_status == "PASS" else
                           "The sender could not prove it was allowed to send from this domain." if spf_status == "FAIL" else
                           "This sender check could not be confirmed.",
        },
        {
            "group": "Authentication Checks",
            "name": "DKIM Result",
            "status": dkim_status,
            "explanation": "The email signature looks valid." if dkim_status == "PASS" else
                           "The message signature could not be trusted." if dkim_status == "FAIL" else
                           "This message signature could not be confirmed.",
        },
        {
            "group": "Authentication Checks",
            "name": "DMARC Result",
            "status": dmarc_status,
            "explanation": "The domain identity checks are aligned." if dmarc_status == "PASS" else
                           "The domain identity checks did not match correctly." if dmarc_status == "FAIL" else
                           "The domain protection result is unclear.",
        },
        {
            "group": "Source Analysis",
            "name": "Sender IP Reputation",
            "status": sender_ip_status,
            "explanation": sender_ip_explain,
        },
        {
            "group": "Source Analysis",
            "name": "Domain Reputation",
            "status": domain_reputation_status,
            "explanation": domain_reputation_explain,
        },
        {
            "group": "Source Analysis",
            "name": "Header Analysis",
            "status": header_status,
            "explanation": header_explain,
        },
        {
            "group": "Content Inspection",
            "name": "Suspicious URLs",
            "status": url_status,
            "explanation": url_explain,
        },
        {
            "group": "Content Inspection",
            "name": "Attachments",
            "status": attachment_status,
            "explanation": attachment_explain,
        },
        {
            "group": "Content Inspection",
            "name": "Phishing Language Detection",
            "status": language_status,
            "explanation": language_explain,
        },
    ]

    ai_result = analyze_email_ai({
        "from": msg.get("from"),
        "spf": auth.get("spf"),
        "dkim": auth.get("dkim"),
        "dmarc": auth.get("dmarc"),
        "ip": originating_ip,
        "suspicious_urls": url_status in ("WARNING", "FAIL"),
        "attachment_risk": attachment_status in ("WARNING", "FAIL"),
        "header_anomaly": header_status in ("WARNING", "FAIL"),
        "phishing_language": phishing_language,
        "risk_score": score,
    })

    return {
        "score": score,
        "level": level,
        "simple_explanation": _simple_detail_text(score, indicators),
        "ai_meta": {
            "source": ai_result.get("source", "fallback"),
            "model": ai_result.get("model", "fallback"),
        },
        "indicators": indicators,
        "details": {
            "email_source_path": {
                "from": msg.get("from") or "-",
                "return_path": return_path or "-",
                "reply_to": reply_to or "-",
            },
            "originating_ip": originating_ip or "Not clearly identified",
            "relay_servers": relays,
            "spoofing_indicators": [
                "The sender and return address do not fully match." if header_findings.get("mismatch_from_return_path") else "",
                "The reply address is different from the visible sender." if header_findings.get("reply_to_mismatch") else "",
                "Some sender details look forged or misleading." if header_findings.get("spoofing_indicators") else "",
            ],
            "url_analysis": {
                "url_count": int(url_findings.get("count") or 0),
                "domain_age_days": url_findings.get("young_domain_days"),
                "domain_mismatch": bool(url_findings.get("domain_mismatch")),
                "redirect_indicators": bool(url_findings.get("tracking_url")),
                "known_phishing_databases": "Not checked in this panel",
            },
            "attachment_analysis": {
                "file_types": [a.get("filename") for a in (msg.get("attachments") or []) if isinstance(a, dict) and a.get("filename")],
                "malware_risk": _friendly_status_text(attachment_status),
                "suspicious_macros": bool(attachment_findings.get("macro_enabled")),
                "executable_content": bool(attachment_findings.get("executable")),
            },
            "scoring_breakdown": breakdown,
            "ai_threat_explanation": ai_result.get("text") or _simple_detail_text(score, indicators),
        },
    }


@app.get("/api/gmail/message/<msg_id>")
def api_gmail_message(msg_id: str):
    if not gmail_connected():
        return jsonify({"error": "Not connected"}), 401

    try:
        m = gmail_get_message(msg_id)
        rep = gmail_scan_message(m)
        rep = dict(rep or {})

        raw_headers = ""
        try:
            if isinstance(m.get("headers"), list):
                raw_headers = "\n".join(
                    f"{h.get('name','')}: {h.get('value','')}"
                    for h in m.get("headers", [])
                    if isinstance(h, dict)
                )
            elif isinstance(m.get("raw_headers"), str):
                raw_headers = m.get("raw_headers") or ""
            elif isinstance(m.get("headers_raw"), str):
                raw_headers = m.get("headers_raw") or ""
        except Exception:
            raw_headers = ""

        try:
            auth = parse_auth_results(raw_headers) if raw_headers else {}
        except Exception:
            auth = {}

        urls = rep.get("urls") or []
        if not isinstance(urls, list):
            urls = []

        from_domain = ""
        try:
            m_from = re.search(r"@([A-Za-z0-9\.\-]+\.[A-Za-z]{2,})", (m.get("from") or ""))
            from_domain = (m_from.group(1) or "").lower() if m_from else ""
        except Exception:
            from_domain = ""

        url_hosts = [_safe_urlparse_host(u) for u in urls]
        url_hosts = [h for h in url_hosts if h]

        domain_mismatch = False
        if from_domain and url_hosts:
            mism = [h for h in url_hosts if not (h == from_domain or h.endswith("." + from_domain))]
            if len(mism) >= 1:
                domain_mismatch = True

        long_url = any(len(str(u or "")) >= 120 for u in urls)
        tracking_url = any(
            any(k in (str(u or "").lower()) for k in ["utm_", "track", "redirect", "r=", "click"])
            for u in urls
        )

        body_blob = ((m.get("text") or "") + " " + (m.get("snippet") or "")).lower()
        login_pattern = any(
            any(k in (str(u or "").lower()) for k in ["login", "signin", "verify", "password", "account"])
            for u in urls
        ) or any(
            k in body_blob
            for k in ["verify your account", "reset your password", "confirm your password", "sign in"]
        )

        url_findings = {
            "count": len(urls),
            "domain_mismatch": bool(domain_mismatch),
            "login_pattern": bool(login_pattern),
            "long_url": bool(long_url),
            "tracking_url": bool(tracking_url),
            "young_domain_days": rep.get("domain_age_days"),
        }

        atts = m.get("attachments") or []
        if not isinstance(atts, list):
            atts = []

        suspicious_types = []
        macro_enabled = False
        executable = False
        archive_with_password = False

        for a in atts:
            fn = str((a or {}).get("filename") or "").lower()
            mt = str((a or {}).get("mimeType") or "").lower()

            if fn.endswith(".docm") or fn.endswith(".xlsm") or "macro" in mt:
                macro_enabled = True
            if fn.endswith(".exe") or fn.endswith(".scr") or fn.endswith(".bat") or fn.endswith(".dll"):
                executable = True
            if fn.endswith(".js") or fn.endswith(".vbs") or fn.endswith(".ps1"):
                suspicious_types.append(fn.rsplit(".", 1)[-1])

        attachment_findings = {
            "count": len(atts),
            "macro_enabled": bool(macro_enabled),
            "executable": bool(executable),
            "archive_with_password": bool(archive_with_password),
            "suspicious_types": suspicious_types[:6],
        }

        reasons = rep.get("reasons") or []
        reasons_l = " ".join([str(x or "") for x in reasons]).lower()

        mismatch_from_return_path = ("return-path mismatch" in reasons_l) or ("from/return-path mismatch" in reasons_l)
        spoofing_indicators = ("spoof" in reasons_l)

        header_findings = {
            "mismatch_from_return_path": bool(mismatch_from_return_path),
            "reply_to_mismatch": ("reply-to mismatch" in reasons_l),
            "spoofing_indicators": bool(spoofing_indicators),
            "display_name_spoof": ("display name" in reasons_l and "suspicious" in reasons_l),
        }

        email_result = build_email_result(
            auth=auth,
            header_findings=header_findings,
            url_findings=url_findings,
            attachment_findings=attachment_findings,
        )

        threat_panel = _build_threat_panel(
            msg=m,
            raw_headers=raw_headers,
            auth=auth,
            header_findings=header_findings,
            url_findings=url_findings,
            attachment_findings=attachment_findings,
            base_score=int(email_result.get("overall_score") or 0),
        )

        rep["auth"] = auth
        rep["score"] = int(threat_panel["score"])
        rep["label"] = str(threat_panel["level"]).upper()

        email_result["overall_score"] = int(threat_panel["score"])
        email_result["threat_level"] = str(threat_panel["level"]).upper()

        try:
            _log_scan_event("Gmail", (m.get("subject") or msg_id), rep["score"], _score_to_label(rep["score"]))
        except Exception:
            pass

        ux = _non_technical_explain(m, email_result)
        ux["headline"] = f"{threat_panel['level'].title()} Email"
        ux["explain"] = threat_panel["simple_explanation"]

        _kickoff_adv_scan(msg_id, m, rep)

        return jsonify({
            "message": m,
            "report": rep,
            "ux": ux,
            "email_result": email_result,
            "threat_panel": threat_panel,
        })

    except Exception as e:
        return jsonify({"error": f"Message scan failed: {e}"}), 400


@app.get("/api/gmail/adv/<msg_id>")
def api_gmail_adv(msg_id: str):
    if not gmail_connected():
        return jsonify({"error": "Not connected"}), 401
    try:
        res = _adv_cache_get(msg_id)
        if res is not None:
            return jsonify({"pending": False, "result": res})
        with ADV_SCAN_LOCK:
            pending = (msg_id in ADV_SCAN_PENDING)
        return jsonify({"pending": pending, "result": None})
    except Exception:
        return jsonify({"error": "Advanced scan unavailable."}), 400


@app.get("/api/gmail/html/<msg_id>")
def api_gmail_html(msg_id: str):
    if not gmail_connected():
        return jsonify({"error": "Not connected"}), 401
    try:
        m = gmail_get_message(msg_id)
        html_body = (m.get("html") or "").strip()
        if not html_body:
            return Response("<pre>No HTML body for this email.</pre>", mimetype="text/html")
        return Response(html_body, mimetype="text/html")
    except Exception:
        return Response("<pre>HTML render failed.</pre>", mimetype="text/html", status=400)


# -----------------------------
# Gmail Actions
# -----------------------------
@app.post("/api/gmail/star")
def api_gmail_star():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()
    starred = bool(data.get("starred", True))

    if not msg_id:
        return _json_err("Missing id", 400)

    try:
        raw = gmail_set_star(msg_id, starred)
        payload = _as_dict(raw)

        return _json_ok(
            "Email moved to flagged." if starred else "Email moved to inbox.",
            id=msg_id,
            starred=starred,
            box="flagged" if starred else "inbox",
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Flag action failed: {e}", 400)


@app.post("/api/gmail/archive")
def api_gmail_archive():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()

    if not msg_id:
        return _json_err("Missing id", 400)

    try:
        raw = gmail_archive(msg_id)
        payload = _as_dict(raw)

        return _json_ok(
            "Email archived successfully.",
            id=msg_id,
            archived=True,
            box="archived",
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Archive action failed: {e}", 400)


@app.post("/api/gmail/unarchive")
def api_gmail_unarchive():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()

    if not msg_id:
        return _json_err("Missing id", 400)

    try:
        raw = gmail_unarchive(msg_id)
        payload = _as_dict(raw)

        return _json_ok(
            "Email moved back to inbox.",
            id=msg_id,
            archived=False,
            box="inbox",
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Unarchive action failed: {e}", 400)


@app.post("/api/gmail/delete")
def api_gmail_delete():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()

    if not msg_id:
        return _json_err("Missing id", 400)

    try:
        raw = gmail_trash(msg_id)
        payload = _as_dict(raw)

        session["last_delete_id"] = msg_id
        session["last_delete_ts"] = int(time.time())

        return _json_ok(
            "Email deleted.",
            id=msg_id,
            deleted=True,
            box="deleted",
            undo_available=True,
            undo_seconds=30,
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Delete failed: {e}", 400)


@app.post("/api/gmail/undo_delete")
def api_gmail_undo_delete():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    msg_id = session.get("last_delete_id")
    ts = session.get("last_delete_ts", 0)

    if not msg_id:
        return _json_err("Nothing to undo", 400)

    if int(time.time()) - int(ts) > 30:
        session.pop("last_delete_id", None)
        session.pop("last_delete_ts", None)
        return _json_err("Undo window expired", 400)

    try:
        raw = gmail_untrash(msg_id)
        payload = _as_dict(raw)

        session.pop("last_delete_id", None)
        session.pop("last_delete_ts", None)

        return _json_ok(
            "Email restored to inbox.",
            id=msg_id,
            restored=True,
            box="inbox",
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Undo failed: {e}", 400)


@app.post("/api/gmail/reply")
def api_gmail_reply():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()
    body = (data.get("body") or "").strip()

    if not msg_id:
        return _json_err("Missing id", 400)
    if not body:
        return _json_err("Missing reply body", 400)

    try:
        raw = gmail_reply(msg_id, body)
        payload = _as_dict(raw)

        return _json_ok(
            "Reply sent successfully.",
            id=msg_id,
            replied=True,
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Reply failed: {e}", 400)


@app.post("/api/gmail/forward")
def api_gmail_forward():
    if not gmail_connected():
        return _json_err("Not connected", 401)

    data = request.get_json(force=True, silent=True) or {}
    msg_id = (data.get("id") or "").strip()
    to_email = (data.get("to") or "").strip()
    body = (data.get("body") or "").strip()

    if not msg_id:
        return _json_err("Missing id", 400)
    if not to_email:
        return _json_err("Missing recipient email", 400)
    if not _is_valid_email(to_email):
        return _json_err("Invalid recipient email", 400)

    try:
        raw = gmail_forward(msg_id, to_email, body)
        payload = _as_dict(raw)

        return _json_ok(
            "Forward sent successfully.",
            id=msg_id,
            forwarded=True,
            to=to_email,
            result=payload,
        )
    except Exception as e:
        return _json_err(f"Forward failed: {e}", 400)


# -----------------------------
# Other Tools APIs
# -----------------------------
@app.post("/api/password")
def api_password():
    data = request.get_json(force=True, silent=True) or {}
    pw = (data.get("password") or "").strip()
    res = password_report(pw)

    _m = _extract_score_label(res)
    if _m:
        _log_scan_event("Password", "password_check", _m[0], _m[1])

    return jsonify(res)


@_limit("10 per minute")
@app.post("/api/phishing")
def api_phishing():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    enable_online = bool(data.get("enable_online", True))
    enable_whois = bool(data.get("enable_whois", True))

    if not url:
        return jsonify({"error": "Enter a website URL to analyze."}), 400

    if analyze_url_intel is None:
        return jsonify({"error": "URL intelligence service not available. Ensure services/url_intel.py exists."}), 500

    try:
        try:
            res = analyze_url_intel(url, enable_online=enable_online, enable_whois=enable_whois)
        except TypeError:
            res = analyze_url_intel(url)

        if not isinstance(res, dict):
            return jsonify({"error": "Invalid phishing scan response."}), 500

        score = 0
        try:
            score = int(res.get("score") or res.get("risk_score") or 0)
        except Exception:
            score = 0
        score = max(0, min(100, score))

        ui_label = str(res.get("label") or res.get("classification") or "").upper()
        metric_label = "SAFE"
        if "HIGH" in ui_label:
            metric_label = "HIGH"
        elif "MEDIUM" in ui_label or "SUSPICIOUS" in ui_label:
            metric_label = "MEDIUM"
        elif "LOW" in ui_label:
            metric_label = "LOW"
        else:
            metric_label = _score_to_label(score)

        try:
            _log_scan_event("Phishing URL", res.get("url") or url, score, metric_label)
        except Exception:
            pass

        return jsonify(res)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        sec_logger.info(f"phishing_intel_error err={e.__class__.__name__}")
        return jsonify({"error": "Scan failed."}), 400


def _sanitize_iprep_response(ip: str, res: dict) -> dict:
    res = res or {}

    risk_score = 0
    try:
        risk_score = int(res.get("risk_score") or 0)
    except Exception:
        risk_score = 0
    risk_score = max(0, min(100, risk_score))

    verdict = (res.get("verdict") or res.get("classification") or _score_to_label(risk_score)).strip()
    scope = (res.get("scope") or "public").strip()

    sources = res.get("sources") or {}
    if not isinstance(sources, dict):
        sources = {}

    ab = sources.get("abuseipdb") or {}
    vt = sources.get("virustotal") or {}
    info = sources.get("ipinfo") or {}

    safe_sources = {
        "abuseipdb": {
            "abuseConfidenceScore": ab.get("abuseConfidenceScore"),
            "totalReports": ab.get("totalReports"),
            "lastReportedAt": ab.get("lastReportedAt"),
            "countryCode": ab.get("countryCode"),
            "usageType": ab.get("usageType"),
            "isp": ab.get("isp"),
            "error": ab.get("error"),
        },
        "virustotal": {
            "reputation": vt.get("reputation"),
            "last_analysis_stats": (vt.get("last_analysis_stats") if isinstance(vt.get("last_analysis_stats"), dict) else None),
            "error": vt.get("error"),
        },
        "ipinfo": {
            "countryCode": info.get("country") or info.get("countryCode"),
            "region": info.get("region"),
            "city": info.get("city"),
            "org": info.get("org") or info.get("isp"),
            "hostname": info.get("hostname"),
            "asn": info.get("asn"),
            "hosting_type": info.get("hosting_type") or info.get("hostingType") or info.get("hosting"),
            "error": info.get("error"),
        }
    }

    indicators = res.get("threat_indicators") or []
    if not isinstance(indicators, list):
        indicators = []

    degraded = bool(res.get("degraded", False))

    return {
        "ip": ip,
        "scope": scope,
        "risk_score": risk_score,
        "verdict": verdict,
        "sources": safe_sources,
        "threat_indicators": indicators[:12],
        "degraded": degraded,
    }


@_limit("12 per minute")
@app.post("/api/iprep")
def api_iprep():
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    enable_online = bool(data.get("enable_online", True))

    if not ip:
        return jsonify({"error": "Enter an IP address first."}), 400

    if analyze_ip_intel is None:
        return jsonify({"error": "IP intelligence service not available. Ensure services/ip_intel.py exists."}), 500

    try:
        res = analyze_ip_intel(ip, enable_online=enable_online, timeout_s=8.0)

        if not isinstance(res, dict):
            return jsonify({"error": "Invalid IP reputation response."}), 500

        if res.get("error"):
            return jsonify({"error": res.get("error")}), 400

        safe_res = _sanitize_iprep_response(ip, res)

        try:
            sc = int(safe_res.get("risk_score") or 0)
            lb = _score_to_label(sc)
            _log_scan_event("IP Reputation", ip, sc, lb)
        except Exception:
            pass

        return jsonify(safe_res)

    except Exception:
        sec_logger.info("ip_intel_error")
        return jsonify({"error": "Scan failed."}), 400


@app.post("/api/filescan")
def api_filescan():
    data = request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or "").strip().strip('"')
    use_vt = bool(data.get("use_vt", False))
    vt_key = (data.get("vt_api_key") or "").strip()
    vt_mode = (data.get("vt_mode") or "lookup_only").strip()
    quarantine_dir = (data.get("quarantine_dir") or "").strip()

    try:
        res = scan_file_path(
            path=path,
            use_vt=use_vt,
            vt_api_key=vt_key,
            vt_mode=vt_mode,
            quarantine_dir=quarantine_dir,
        )

        _m = _extract_score_label(res)
        if _m:
            _log_scan_event("File Scanner", os.path.basename(path) or path, _m[0], _m[1])

        return jsonify(res)
    except Exception:
        sec_logger.info("filescan_error")
        return jsonify({"error": "Scan failed."}), 400


@_limit("8 per minute")
@app.post("/api/header")
def api_header():
    data = request.get_json(force=True, silent=True) or {}
    raw = (data.get("headers") or "").strip()
    enable_online = bool(data.get("enable_online", True))

    if not raw:
        return jsonify({"error": "Paste raw email headers first."}), 400

    if analyze_header_forensics is None:
        return jsonify({"error": "Header analyzer service not available. Ensure header_core.py exists beside app.py."}), 500

    try:
        vt_key = (os.environ.get("VT_API_KEY") or "").strip()
        abuse_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
        ipinfo_key = (os.environ.get("IPINFO_TOKEN") or "").strip()

        try:
            res = analyze_header_forensics(
                raw,
                use_online=enable_online,
                vt_api_key=vt_key,
                abuseipdb_api_key=abuse_key,
                ipinfo_api_key=ipinfo_key,
            )
        except TypeError:
            try:
                res = analyze_header_forensics(raw, enable_online=enable_online)
            except TypeError:
                res = analyze_header_forensics(raw)

        if not isinstance(res, dict):
            return jsonify({"error": "Header analyzer returned an invalid response."}), 500

        hr = res.get("header_result") or {}
        try:
            score = int(hr.get("overall_score") or 0)
            label = _score_to_label(score)
            _log_scan_event("Email Header", "pasted_headers", score, label)
        except Exception:
            pass

        return jsonify(res)

    except Exception:
        sec_logger.info("header_forensics_error")
        return jsonify({"error": "Scan failed."}), 400


# -----------------------------
# Crypto APIs
# -----------------------------
def _uploaded_file_or_error(field_name: str = "file"):
    if field_name not in request.files:
        return None, (jsonify({"error": "No file uploaded."}), 400)
    f = request.files[field_name]
    filename = (getattr(f, "filename", "") or "").strip()
    if not filename:
        return None, (jsonify({"error": "Missing filename."}), 400)
    return f, None


@app.post("/api/crypto/peek")
def api_crypto_peek():
    print(">>> HIT /api/crypto/peek")
    f, err = _uploaded_file_or_error("file")
    if err:
        return err

    password = (request.form.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        if hasattr(f, "stream"):
            try:
                f.stream.seek(0)
            except Exception:
                pass
        meta = peek_encrypted_metadata(f, password)
        print(">>> PEEK OK")
        return jsonify(meta)
    except Exception as e:
        print("CRYPTO PEEK ERROR:", repr(e))
        return jsonify({"error": f"{e.__class__.__name__}: {e}"}), 400


@app.post("/api/crypto/encrypt")
def api_crypto_encrypt():
    print(">>> HIT /api/crypto/encrypt")
    try:
        f = request.files.get("file")
        if not f:
            print(">>> ENCRYPT FAIL: no file")
            return jsonify({"error": "No file received."}), 400

        password = (request.form.get("password") or "").strip()
        if not password:
            print(">>> ENCRYPT FAIL: no password")
            return jsonify({"error": "Password is required."}), 400

        label = (request.form.get("label") or "").strip()
        note = (request.form.get("note") or "").strip()
        encrypt_names = (request.form.get("encrypt_names") or "1").strip().lower() in {"1", "true", "yes", "on"}

        print(">>> ENCRYPT REQUEST:", {
            "filename": getattr(f, "filename", ""),
            "label": label,
            "encrypt_names": encrypt_names
        })

        out_path, out_name = encrypt_upload_to_file(
            f,
            password,
            encrypt_names=encrypt_names,
            label=label,
            note=note,
        )

        print(">>> ENCRYPT OK:", out_path, out_name)
        return send_file(out_path, as_attachment=True, download_name=out_name)
    except Exception as e:
        print("CRYPTO ENCRYPT ERROR:", repr(e))
        return jsonify({"error": f"{e.__class__.__name__}: {e}"}), 400


@app.post("/api/crypto/decrypt")
def api_crypto_decrypt():
    print(">>> HIT /api/crypto/decrypt")
    f, err = _uploaded_file_or_error("file")
    if err:
        return err

    password = (request.form.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        if hasattr(f, "stream"):
            try:
                f.stream.seek(0)
            except Exception:
                pass

        print(">>> DECRYPT REQUEST:", {"filename": getattr(f, "filename", "")})
        out_path, out_name = decrypt_upload_to_file(f, password)
        print(">>> DECRYPT OK:", out_path, out_name)
        return send_file(out_path, as_attachment=True, download_name=out_name)
    except Exception as e:
        print("CRYPTO DECRYPT ERROR:", repr(e))
        return jsonify({"error": f"{e.__class__.__name__}: {e}"}), 400


# ============================================================
# ✅ CRYPTO JOB ENGINE (NEW - reliable Encrypt flow)
# ============================================================

CRYPTO_JOBS_LOCK = threading.Lock()
CRYPTO_JOBS = {}  # job_id -> dict state

CRYPTO_TMP_DIR = BASE_DIR / "uploads" / "crypto_jobs"
try:
    CRYPTO_TMP_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def _crypto_job_set(job_id: str, **fields):
    try:
        with CRYPTO_JOBS_LOCK:
            job = CRYPTO_JOBS.get(job_id) or {}
            job.update(fields)
            CRYPTO_JOBS[job_id] = job
    except Exception:
        pass


def _crypto_job_get(job_id: str):
    try:
        with CRYPTO_JOBS_LOCK:
            return dict(CRYPTO_JOBS.get(job_id) or {})
    except Exception:
        return {}


def _crypto_job_cancelled(job_id: str) -> bool:
    try:
        with CRYPTO_JOBS_LOCK:
            return bool((CRYPTO_JOBS.get(job_id) or {}).get("cancelled", False))
    except Exception:
        return False


@app.post("/api/crypto/encrypt/start")
def api_crypto_encrypt_start():
    """
    Starts an encryption job. Frontend polls /api/crypto/job/<job_id>,
    then downloads via /api/crypto/download/<job_id>.
    """
    print(">>> HIT /api/crypto/encrypt/start")

    f, err = _uploaded_file_or_error("file")
    if err:
        return err

    password = (request.form.get("password") or "").strip()
    if not password:
        return jsonify({"error": "Password is required."}), 400

    label = (request.form.get("label") or "").strip()
    note = (request.form.get("note") or "").strip()
    encrypt_names = (request.form.get("encrypt_names") or "1").strip().lower() in {"1", "true", "yes", "on"}

    job_id = secrets.token_hex(12)
    in_path = CRYPTO_TMP_DIR / f"{job_id}_input.bin"

    try:
        f.save(str(in_path))
    except Exception as e:
        print(">>> START FAIL:", repr(e))
        return jsonify({"error": f"Upload save failed: {e}"}), 400

    _crypto_job_set(
        job_id,
        status="running",
        stage="Queued…",
        message="Preparing encryption…",
        progress=8,
        created_ts=int(time.time()),
        cancelled=False,
        error="",
        out_path="",
        out_name="",
        in_path=str(in_path),
    )

    def _worker():
        try:
            if _crypto_job_cancelled(job_id):
                _crypto_job_set(job_id, status="cancelled", stage="Cancelled", message="Cancelled.", progress=0)
                return

            _crypto_job_set(job_id, stage="Encrypting…", message="Encrypting file…", progress=35)

            # build a FileStorage wrapper so your existing crypto_core API works unchanged
            from werkzeug.datastructures import FileStorage

            with open(in_path, "rb") as fp:
                fs = FileStorage(stream=fp, filename=f.filename or "upload.bin")

                out_path, out_name = encrypt_upload_to_file(
                    fs,
                    password,
                    encrypt_names=encrypt_names,
                    label=label,
                    note=note,
                )

            if _crypto_job_cancelled(job_id):
                _crypto_job_set(job_id, status="cancelled", stage="Cancelled", message="Cancelled.", progress=0)
                return

            _crypto_job_set(job_id, stage="Finalizing…", message="Preparing download…", progress=90)

            _crypto_job_set(
                job_id,
                status="done",
                stage="Done",
                message="Ready to download.",
                progress=100,
                out_path=str(out_path),
                out_name=str(out_name),
            )

            print(">>> JOB DONE:", job_id, out_name)

        except Exception as e:
            print(">>> JOB ERROR:", job_id, repr(e))
            _crypto_job_set(
                job_id,
                status="error",
                stage="Error",
                message="Encryption failed.",
                progress=0,
                error=f"{e.__class__.__name__}: {e}",
            )
        finally:
            # cleanup input temp file
            try:
                if in_path.exists():
                    in_path.unlink()
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})


@app.get("/api/crypto/job/<job_id>")
def api_crypto_job_status(job_id: str):
    job = _crypto_job_get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404

    return jsonify({
        "job_id": job_id,
        "status": job.get("status", "unknown"),
        "stage": job.get("stage", "Idle"),
        "message": job.get("message", ""),
        "progress": int(job.get("progress") or 0),
        "error": job.get("error", ""),
    })


@app.post("/api/crypto/cancel/<job_id>")
def api_crypto_job_cancel(job_id: str):
    job = _crypto_job_get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404

    _crypto_job_set(
        job_id,
        cancelled=True,
        status="cancelled",
        stage="Cancelled",
        message="Cancelled.",
        progress=0,
    )
    print(">>> JOB CANCELLED:", job_id)
    return jsonify({"ok": True, "cancelled": True})


@app.get("/api/crypto/download/<job_id>")
def api_crypto_job_download(job_id: str):
    job = _crypto_job_get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404

    if job.get("status") != "done":
        return jsonify({"error": "File not ready yet."}), 400

    out_path = (job.get("out_path") or "").strip()
    out_name = (job.get("out_name") or "encrypted_file.enc").strip()

    if not out_path or not os.path.exists(out_path):
        return jsonify({"error": "Output file missing."}), 404

    print(">>> DOWNLOAD:", job_id, out_name)
    return send_file(out_path, as_attachment=True, download_name=out_name)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
