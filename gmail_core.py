from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional
import base64
import re
from email.message import EmailMessage
from email.utils import parseaddr
from urllib.parse import urlparse

import httplib2
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import BatchHttpRequest

APP_DIR = Path(__file__).resolve().parents[1]
TOKEN_PATH = APP_DIR / "token.json"
CREDS_PATH = APP_DIR / "credentials.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]

URL_RE = re.compile(r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)", re.IGNORECASE)

SUSPICIOUS_WORDS = [
    "verify", "urgent", "password", "account", "locked", "login", "reset", "click here",
    "confirm", "security alert", "unusual activity", "suspended", "limited", "payment",
    "invoice", "refund", "bank", "crypto", "wallet", "prize", "winner"
]

SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "mov", "cam", "live", "quest", "gq", "tk"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly"}

# IMPORTANT: these are NOT “guaranteed safe”, but they reduce false positives a lot.
KNOWN_SAFE_DOMAINS = {
    "google.com", "accounts.google.com", "mail.google.com",
    "linkedin.com", "coursera.org", "tryhackme.com", "cisco.com",
    "microsoft.com", "office.com", "live.com", "outlook.com",
    "amazon.com", "paypal.com",
}


def gmail_is_configured() -> bool:
    return CREDS_PATH.exists()


def gmail_disconnect():
    if TOKEN_PATH.exists():
        TOKEN_PATH.unlink()


def gmail_get_auth_url(redirect_uri: str) -> Tuple[str, str]:
    if not CREDS_PATH.exists():
        raise RuntimeError("credentials.json not found beside app.py")

    flow = Flow.from_client_secrets_file(
        str(CREDS_PATH),
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="consent",
    )
    return auth_url, state


def gmail_handle_callback(full_callback_url: str, redirect_uri: str, expected_state: str) -> Tuple[bool, str]:
    try:
        if not expected_state:
            return False, (
                "Missing OAuth state in session. "
                "Use ONLY http://127.0.0.1:5000 and run Flask without the reloader."
            )

        flow = Flow.from_client_secrets_file(
            str(CREDS_PATH),
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            state=expected_state,
        )
        flow.fetch_token(authorization_response=full_callback_url)

        creds = flow.credentials
        TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")
        return True, f"Token saved to: {TOKEN_PATH}"
    except Exception as e:
        return False, f"{e.__class__.__name__}: {e}"


def _load_creds() -> Credentials:
    if not TOKEN_PATH.exists():
        raise RuntimeError("token.json missing. Connect Gmail first.")
    return Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)


def _svc(timeout_seconds: int = 20):
    creds = _load_creds()
    http = AuthorizedHttp(creds, http=httplib2.Http(timeout=timeout_seconds))
    return build("gmail", "v1", http=http, cache_discovery=False)


def _hdr_map(payload: dict) -> Dict[str, str]:
    headers = payload.get("headers") or []
    return {h["name"].lower(): h["value"] for h in headers}


def _hdr_list(payload: dict, header_name: str) -> List[str]:
    """Return all header values that match header_name (case-insensitive)."""
    want = (header_name or "").lower()
    out: List[str] = []
    for h in (payload.get("headers") or []):
        try:
            if (h.get("name") or "").lower() == want:
                out.append(h.get("value") or "")
        except Exception:
            continue
    return out


def _decode_b64url(data: str) -> str:
    if not data:
        return ""
    pad = "=" * ((4 - len(data) % 4) % 4)
    raw = base64.urlsafe_b64decode((data + pad).encode("utf-8"))
    return raw.decode("utf-8", errors="replace")


def _pick_body(payload: dict) -> Dict[str, str]:
    result = {"text": "", "html": ""}
    if not payload:
        return result

    if payload.get("body", {}).get("data"):
        mt = (payload.get("mimeType") or "").lower()
        decoded = _decode_b64url(payload["body"]["data"])
        if "html" in mt:
            result["html"] = decoded
        else:
            result["text"] = decoded
        return result

    parts = payload.get("parts") or []

    def walk(ps):
        for p in ps:
            mt = (p.get("mimeType") or "").lower()
            body = p.get("body") or {}
            if body.get("data"):
                decoded = _decode_b64url(body["data"])
                if mt == "text/plain" and not result["text"]:
                    result["text"] = decoded
                elif mt == "text/html" and not result["html"]:
                    result["html"] = decoded
            if p.get("parts"):
                walk(p["parts"])

    walk(parts)
    return result


def _attachments(payload: dict) -> List[Dict[str, Any]]:
    out = []

    def walk(ps):
        for p in ps:
            filename = p.get("filename") or ""
            body = p.get("body") or {}
            att_id = body.get("attachmentId")
            size = body.get("size")
            mt = p.get("mimeType") or ""
            if filename and att_id:
                out.append({"filename": filename, "mimeType": mt, "size": size, "attachmentId": att_id})
            if p.get("parts"):
                walk(p["parts"])

    if payload.get("parts"):
        walk(payload["parts"])
    return out


def gmail_get_profile() -> Dict[str, Any]:
    svc = _svc()
    prof = svc.users().getProfile(userId="me").execute()
    return {
        "emailAddress": prof.get("emailAddress", ""),
        "messagesTotal": prof.get("messagesTotal", 0),
        "threadsTotal": prof.get("threadsTotal", 0),
        "historyId": prof.get("historyId", ""),
    }


def _list_message_ids(svc, max_results: int, box: str) -> List[str]:
    """
    Supported views:
    - inbox
    - flagged / starred
    - archived / archive
    - deleted / trash
    """
    box = (box or "inbox").lower().strip()

    if box in {"flagged", "starred"}:
        query = "is:starred -in:trash"
    elif box in {"archived", "archive"}:
        query = "-in:inbox -in:trash"
    elif box in {"deleted", "trash"}:
        query = "in:trash"
    else:
        query = "in:inbox -in:trash"

    resp = svc.users().messages().list(
        userId="me",
        q=query,
        maxResults=max_results
    ).execute()

    msgs = resp.get("messages") or []
    return [m.get("id") for m in msgs if m.get("id")]
def gmail_list_inbox(max_results: int = 100, box: str = "inbox") -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    ids = _list_message_ids(svc, max_results=max_results, box=box)

    if not ids:
        return {"box": box, "messages": []}

    out: List[Dict[str, Any]] = []
    warning: Optional[str] = None

    CHUNK = 25
    GMAIL_BATCH_URI = "https://gmail.googleapis.com/batch/gmail/v1"

    try:
        for start in range(0, len(ids), CHUNK):
            chunk_ids = ids[start:start + CHUNK]

            idx_map = {mid: len(out) + i for i, mid in enumerate(chunk_ids)}
            out.extend([{
                "id": mid,
                "from": "",
                "subject": "",
                "date": "",
                "snippet": "",
                "internalDate": "",
                "labelIds": [],
            } for mid in chunk_ids])

            def _cb(request_id, response, exception):
                if exception:
                    return
                payload = (response or {}).get("payload") or {}
                hdrs = {h["name"].lower(): h["value"] for h in (payload.get("headers") or [])}
                mid = (response or {}).get("id")
                idx = idx_map.get(mid)
                if idx is None:
                    return
                out[idx].update({
                    "from": hdrs.get("from", ""),
                    "subject": hdrs.get("subject", ""),
                    "date": hdrs.get("date", ""),
                    "snippet": (response or {}).get("snippet", ""),
                    "internalDate": (response or {}).get("internalDate", ""),
                    "labelIds": (response or {}).get("labelIds", []) or [],
                })

            batch = BatchHttpRequest(callback=_cb, batch_uri=GMAIL_BATCH_URI)
            for mid in chunk_ids:
                req = svc.users().messages().get(
                    userId="me",
                    id=mid,
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                )
                batch.add(req)

            batch.execute()

    except Exception as e:
        warning = f"{e.__class__.__name__}: {e}"

    return {"box": box, "messages": out, "warning": warning}

def gmail_get_message(msg_id: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=25)
    m = svc.users().messages().get(userId="me", id=msg_id, format="full").execute()

    payload = m.get("payload") or {}
    hdrs = _hdr_map(payload)
    bodies = _pick_body(payload)
    atts = _attachments(payload)
    label_ids = m.get("labelIds") or []

    auth_results = hdrs.get("authentication-results", "") or ""

    return {
        "id": msg_id,
        "threadId": m.get("threadId", ""),
        "labelIds": label_ids,
        "from": hdrs.get("from", ""),
        "to": hdrs.get("to", ""),
        "subject": hdrs.get("subject", ""),
        "date": hdrs.get("date", ""),
        "snippet": m.get("snippet", ""),
        "text": bodies["text"],
        "html": bodies["html"],
        "attachments": atts,
        "auth_results": auth_results,
        "return_path": hdrs.get("return-path", ""),
        "reply_to": hdrs.get("reply-to", ""),
        "received": _hdr_list(payload, "Received"),
    }


def _extract_urls(text: str) -> List[str]:
    urls = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).strip().rstrip(").,;!\"'")
        if u.lower().startswith("www."):
            u = "http://" + u
        urls.append(u)
    return list(dict.fromkeys(urls))


def _domain_from_url(u: str) -> str:
    try:
        p = urlparse(u if u.startswith("http") else "http://" + u)
        host = (p.hostname or "").lower()
        return host
    except Exception:
        return ""


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def _auth_pass(auth_results: str) -> Dict[str, bool]:
    a = (auth_results or "").lower()
    return {
        "spf": "spf=pass" in a,
        "dkim": "dkim=pass" in a,
        "dmarc": "dmarc=pass" in a,
    }


def _base_domain(host: str) -> str:
    # basic base-domain (not perfect, but good enough without extra libs)
    parts = (host or "").split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _url_risk(u: str, sender_domain: str) -> Tuple[int, List[str]]:
    host = _domain_from_url(u)
    reasons = []
    if not host:
        return 2, reasons

    pts = 0

    if _looks_like_ip(host):
        pts += 25
        reasons.append("Link uses an IP address instead of a normal domain.")

    if "xn--" in host:
        pts += 18
        reasons.append("Link domain uses unusual encoding (can be used for look-alike tricks).")

    tld = host.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        pts += 15
        reasons.append("Link uses a risky domain extension often abused by scammers.")

    if host in URL_SHORTENERS:
        pts += 14
        reasons.append("Link is shortened (hides the real destination).")

    # sender-domain mismatch: only add points if the mismatch looks meaningful
    if sender_domain:
        sd = sender_domain.lower()
        if _base_domain(host) != _base_domain(sd):
            # allow known safe domains (reduces false positives)
            if _base_domain(host) not in KNOWN_SAFE_DOMAINS and host not in KNOWN_SAFE_DOMAINS:
                pts += 10
                reasons.append("Link domain does not match the sender’s domain.")

    low = u.lower()
    if any(k in low for k in ["login", "verify", "password", "reset", "security", "account", "authenticate"]):
        pts += 8
        reasons.append("Link looks like a login/verification page.")

    if len(u) > 80:
        pts += 4
        reasons.append("Link is very long (often used to hide tracking or tricks).")

    if host.count(".") >= 4:
        pts += 4
        reasons.append("Link has many subdomains (sometimes used to mimic brands).")

    # reduce points for known safe domains
    bd = _base_domain(host)
    if host in KNOWN_SAFE_DOMAINS or bd in KNOWN_SAFE_DOMAINS:
        pts = max(0, pts - 12)

    return pts, reasons


def gmail_scan_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    from_header = msg.get("from", "") or ""
    _, from_addr = parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    combined = (msg.get("text") or "") + "\n" + (msg.get("html") or "")
    low = combined.lower()

    score = 0
    reasons: List[str] = []
    urls = _extract_urls(combined)
    attachments = msg.get("attachments") or []

    # Authentication trust bonus
    auth = _auth_pass(msg.get("auth_results", ""))
    trust_bonus = 0
    if auth["spf"] and auth["dkim"]:
        trust_bonus += 15
    if auth["dmarc"]:
        trust_bonus += 10

    # Suspicious wording
    hits = [w for w in SUSPICIOUS_WORDS if w in low]
    if hits:
        score += min(20, 3 * len(set(hits)))
        reasons.append("Email uses suspicious urgency or credential-related wording.")

    # Attachments
    if attachments:
        score += 6
        reasons.append("Email includes attachment(s).")

    # URL risk
    if urls:
        score += 5
        worst = 0
        worst_reasons = []
        for u in urls[:40]:
            pts, rs = _url_risk(u, from_domain)
            if pts > worst:
                worst = pts
                worst_reasons = rs

        score += min(40, worst)

        if worst >= 25:
            score += 10  # escalate malicious links

        reasons.append(f"Email contains {len(urls)} link(s).")

        for r in worst_reasons[:3]:
            if r not in reasons:
                reasons.append(r)

    # HTML phishing form detection
    if "<form" in low and ("password" in low or "login" in low):
        score += 25
        reasons.append("Email contains a fake login form.")

    # Apply trust reduction
    score = max(0, score - trust_bonus)

    # Clamp
    score = int(min(100, score))

    # Balanced thresholds
    if score >= 75:
        label = "HIGH"
    elif score >= 40:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "urls": urls[:30],
    }


# -------------------
# Gmail Actions
# -------------------
def gmail_set_star(msg_id: str, starred: bool) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    body = {"addLabelIds": ["STARRED"] if starred else [], "removeLabelIds": [] if starred else ["STARRED"]}
    res = svc.users().messages().modify(userId="me", id=msg_id, body=body).execute()
    return {"ok": True, "id": res.get("id"), "starred": starred}


def gmail_archive(msg_id: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    body = {"removeLabelIds": ["INBOX"], "addLabelIds": []}
    res = svc.users().messages().modify(userId="me", id=msg_id, body=body).execute()
    return {"ok": True, "id": res.get("id"), "archived": True}


def gmail_unarchive(msg_id: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    body = {"addLabelIds": ["INBOX"], "removeLabelIds": []}
    res = svc.users().messages().modify(userId="me", id=msg_id, body=body).execute()
    return {"ok": True, "id": res.get("id"), "archived": False}


def gmail_trash(msg_id: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    svc.users().messages().trash(userId="me", id=msg_id).execute()
    return {"ok": True, "id": msg_id, "trashed": True}


def gmail_untrash(msg_id: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=20)
    svc.users().messages().untrash(userId="me", id=msg_id).execute()
    return {"ok": True, "id": msg_id, "untrashed": True}


def gmail_reply(msg_id: str, body_text: str) -> Dict[str, Any]:
    svc = _svc(timeout_seconds=25)

    orig = svc.users().messages().get(
        userId="me", id=msg_id, format="metadata",
        metadataHeaders=["From", "Subject", "Message-Id", "References"]
    ).execute()

    payload = orig.get("payload") or {}
    hdrs = _hdr_map(payload)

    to_addr = hdrs.get("from", "")
    subj = hdrs.get("subject", "")
    msgid = hdrs.get("message-id", "")
    refs = hdrs.get("references", "")

    if not subj.lower().startswith("re:"):
        subj = "Re: " + subj

    em = EmailMessage()
    em["To"] = to_addr
    em["Subject"] = subj
    if msgid:
        em["In-Reply-To"] = msgid
        em["References"] = (refs + " " + msgid).strip() if refs else msgid

    em.set_content(body_text or "")
    raw = base64.urlsafe_b64encode(em.as_bytes()).decode("utf-8")

    sent = svc.users().messages().send(
        userId="me",
        body={"raw": raw, "threadId": orig.get("threadId")}
    ).execute()

    return {"ok": True, "id": sent.get("id"), "threadId": sent.get("threadId")}


def gmail_forward(msg_id: str, to_email: str, body_text: str) -> Dict[str, Any]:
    msg = gmail_get_message(msg_id)
    subj = msg.get("subject", "")
    if not subj.lower().startswith("fwd:"):
        subj = "Fwd: " + subj

    em = EmailMessage()
    em["To"] = to_email
    em["Subject"] = subj

    original = (msg.get("text") or msg.get("snippet") or "")
    combined = (body_text or "") + "\n\n---- Forwarded message ----\n" + original
    em.set_content(combined)

    svc = _svc(timeout_seconds=25)
    raw = base64.urlsafe_b64encode(em.as_bytes()).decode("utf-8")
    res = svc.users().messages().send(userId="me", body={"raw": raw}).execute()
    return {"ok": True, "id": res.get("id"), "threadId": res.get("threadId")}