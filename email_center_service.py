import base64
import json
import os
import re
import sqlite3
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Tuple

DB_PATH = os.environ.get("PRIVGUARD_DB_PATH", "privguard.db")
ATTACH_DIR = Path(os.environ.get("PRIVGUARD_EMAIL_ATTACH_DIR", "uploads/email_attachments"))
ATTACH_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXT = {"pdf", "doc", "docx", "png", "jpg", "jpeg", "gif", "webp", "zip"}
MAX_ATTACH_SIZE = 10 * 1024 * 1024
RATE_LIMIT_WINDOW_MIN = 10
RATE_LIMIT_MAX_SEND = 12
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_email_tables() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                cc TEXT DEFAULT '',
                bcc TEXT DEFAULT '',
                subject TEXT DEFAULT '',
                body TEXT DEFAULT '',
                attachments TEXT DEFAULT '[]',
                status TEXT NOT NULL,
                sent_at DATETIME NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )
        conn.commit()


def parse_email_list(value) -> List[str]:
    if isinstance(value, list):
        raw = value
    else:
        raw = str(value or "").split(",")
    return [str(x).strip() for x in raw if str(x).strip()]


def validate_recipients(addresses: List[str]) -> List[str]:
    issues = []
    for addr in addresses:
        if not EMAIL_RE.match(addr):
            issues.append(f"Invalid email address: {addr}")
            continue
        domain = addr.split("@", 1)[1]
        if domain.startswith("-") or ".." in domain:
            issues.append(f"Invalid recipient domain: {addr}")
    return issues


def phishing_warnings(body_text: str, body_html: str) -> List[str]:
    warns = []
    urls = re.findall(r"https?://[^\s\"'<]+", body_html or "", flags=re.I)
    for url in urls:
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url):
            warns.append("Message contains a direct IP-based link")
        if re.search(r"bit\.ly|tinyurl|t\.co|rb\.gy|goo\.gl", url, flags=re.I):
            warns.append("Message contains a shortened link")
        if re.search(r"login|verify|account|password|reset", url, flags=re.I) and url.lower().startswith("http://"):
            warns.append("Message contains an insecure login-related link")
    if re.search(r"urgent|verify your account|reset your password|click here immediately", body_text or "", flags=re.I):
        warns.append("Message contains pressure language often seen in phishing emails")
    return sorted(set(warns))


def check_rate_limit(sender: str) -> Tuple[bool, str]:
    since = (datetime.utcnow() - timedelta(minutes=RATE_LIMIT_WINDOW_MIN)).isoformat(sep=" ", timespec="seconds")
    with db_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM email_activity WHERE sender=? AND action='send' AND created_at>=?",
            (sender, since),
        ).fetchone()
    count = int(row["cnt"] or 0)
    if count >= RATE_LIMIT_MAX_SEND:
        return False, f"Rate limit reached. Try again later."
    return True, ""


def _save_attachment(item: Dict) -> Dict:
    name = os.path.basename(str(item.get("name") or "attachment"))
    ext = (name.rsplit(".", 1)[-1] if "." in name else "").lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"Attachment type not allowed: {name}")
    data_b64 = str(item.get("data") or "")
    raw = base64.b64decode(data_b64) if data_b64 else b""
    if len(raw) > MAX_ATTACH_SIZE:
        raise ValueError(f"Attachment exceeds 10 MB limit: {name}")
    safe_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{name}"
    path = ATTACH_DIR / safe_name
    path.write_bytes(raw)
    return {
        "name": name,
        "content_type": item.get("content_type") or "application/octet-stream",
        "size": len(raw),
        "path": str(path),
    }


def process_attachments(items: List[Dict]) -> List[Dict]:
    out = []
    for item in items or []:
        out.append(_save_attachment(item))
    return out


def smtp_send_email(payload: Dict, attachments: List[Dict]) -> Tuple[bool, str]:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587") or "587")
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    if not host or not user or not password:
        return False, "SMTP is not configured"

    msg = EmailMessage()
    msg["From"] = payload["from"]
    msg["To"] = ", ".join(payload["to"])
    if payload["cc"]:
        msg["Cc"] = ", ".join(payload["cc"])
    msg["Subject"] = payload.get("subject", "")
    text = payload.get("message_text", "") or re.sub(r"<[^>]+>", "", payload.get("message", ""))
    html = payload.get("message", "") or f"<p>{text}</p>"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    for item in attachments:
        data = Path(item["path"]).read_bytes()
        maintype, subtype = (item["content_type"].split("/", 1) if "/" in item["content_type"] else ("application", "octet-stream"))
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=item["name"])

    recipients = payload["to"] + payload["cc"] + payload["bcc"]
    with smtplib.SMTP(host, port, timeout=30) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg, from_addr=payload["from"], to_addrs=recipients)
    return True, "sent"


def log_email(sender: str, recipient: str, cc: List[str], bcc: List[str], subject: str, body: str, attachments: List[Dict], status: str) -> int:
    sent_at = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO emails (sender, recipient, cc, bcc, subject, body, attachments, status, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sender,
                ", ".join(recipient) if isinstance(recipient, list) else recipient,
                ", ".join(cc),
                ", ".join(bcc),
                subject,
                body,
                json.dumps(attachments),
                status,
                sent_at,
            ),
        )
        conn.execute(
            "INSERT INTO email_activity (sender, action, created_at) VALUES (?, 'send', ?)",
            (sender, sent_at),
        )
        conn.commit()
        return int(cur.lastrowid)


def save_draft(sender: str, recipient: List[str], cc: List[str], bcc: List[str], subject: str, body: str) -> str:
    ts = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO emails (sender, recipient, cc, bcc, subject, body, attachments, status, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, '[]', 'draft', ?)
            """,
            (sender, ", ".join(recipient), ", ".join(cc), ", ".join(bcc), subject, body, ts),
        )
        conn.commit()
    return ts


def list_sent(limit: int = 30) -> List[Dict]:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, sender, recipient, subject, status, sent_at FROM emails WHERE status='sent' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_drafts(limit: int = 30) -> List[Dict]:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, sender, recipient, cc, bcc, subject, body, sent_at FROM emails WHERE status='draft' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def send_email(payload: Dict) -> Dict:
    sender = str(payload.get("from") or "").strip()
    to = parse_email_list(payload.get("to"))
    cc = parse_email_list(payload.get("cc"))
    bcc = parse_email_list(payload.get("bcc"))
    subject = str(payload.get("subject") or "").strip()
    body_html = str(payload.get("message") or "")
    body_text = str(payload.get("message_text") or re.sub(r"<[^>]+>", "", body_html)).strip()

    if not sender:
        raise ValueError("Sender is required")
    if not to:
        raise ValueError("At least one recipient is required")
    if not subject:
        raise ValueError("Subject is required")
    if not body_text:
        raise ValueError("Message body is required")

    issues = validate_recipients([sender] + to + cc + bcc)
    if issues:
        raise ValueError(issues[0])

    ok, msg = check_rate_limit(sender)
    if not ok:
        raise ValueError(msg)

    warns = phishing_warnings(body_text, body_html)
    attachments = process_attachments(payload.get("attachments") or [])
    sent_ok, status = smtp_send_email(
        {
            "from": sender,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "message": body_html,
            "message_text": body_text,
        },
        attachments,
    )
    if not sent_ok:
        raise ValueError(status)

    email_id = log_email(sender, to, cc, bcc, subject, body_html, attachments, "sent")
    return {"ok": True, "id": email_id, "warnings": warns}
