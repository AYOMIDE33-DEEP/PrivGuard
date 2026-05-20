"""Advanced layered email scanner for PrivGuard Gmail tool.

Design goals:
- Do NOT change existing core scan behavior.
- Add extra layers as modular helpers.
- Keep external/network lookups time-bounded (<=3s each) and cacheable.

This module is intentionally self-contained so app.py can call it from a
background thread without blocking the UI request path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
import ipaddress
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DANGEROUS_EXTS = {".exe", ".js", ".scr", ".docm", ".xlsm"}

_BOGON_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

_URL_RE = re.compile(r"(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class _TTLCache:
    def __init__(self, ttl_seconds: int = 3600, max_items: int = 2048):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._lock = threading.Lock()
        self._d: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            ts, val = item
            if now - ts > self.ttl:
                self._d.pop(key, None)
                return None
            return val

    def set(self, key: str, val: Any) -> None:
        now = time.time()
        with self._lock:
            if len(self._d) >= self.max_items:
                items = sorted(self._d.items(), key=lambda kv: kv[1][0])
                for k, _ in items[: max(1, self.max_items // 10)]:
                    self._d.pop(k, None)
            self._d[key] = (now, val)


_DOMAIN_AGE_CACHE = _TTLCache(ttl_seconds=24 * 3600, max_items=4096)


def _base_domain(host: str) -> str:
    host = (host or "").strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _extract_urls(text: str) -> List[str]:
    out: List[str] = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).strip().rstrip(").,;!\"'")
        if u.lower().startswith("www."):
            u = "http://" + u
        out.append(u)
    seen = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _domain_from_url(u: str) -> str:
    try:
        p = urlparse(u if u.startswith("http") else ("http://" + u))
        return (p.hostname or "").lower()
    except Exception:
        return ""


def _auth_status(auth_results: str) -> Dict[str, str]:
    a = (auth_results or "").lower()

    def _pass(token: str) -> bool:
        return f"{token}=pass" in a

    return {
        "spf": "PASS" if _pass("spf") else "FAIL",
        "dkim": "PASS" if _pass("dkim") else "FAIL",
        "dmarc": "PASS" if _pass("dmarc") else "FAIL",
    }


def _parse_email_addr(header_val: str) -> str:
    _, addr = parseaddr(header_val or "")
    return (addr or "").strip().lower()


def _safe_ip(ip_s: str) -> Optional[ipaddress.IPv4Address]:
    try:
        ip = ipaddress.ip_address(ip_s)
        return ip if isinstance(ip, ipaddress.IPv4Address) else None
    except Exception:
        return None


def _is_bogon(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in _BOGON_NETS)


def _first_public_ip(received_headers: List[str]) -> Optional[str]:
    for h in received_headers or []:
        for ip_s in _IP_RE.findall(h or ""):
            ip = _safe_ip(ip_s)
            if not ip:
                continue
            if not _is_bogon(ip):
                return str(ip)
    return None


def _rdap_domain_age_days(domain: str, timeout_s: float = 3.0) -> Optional[int]:
    d = _base_domain(domain)
    if not d:
        return None

    cached = _DOMAIN_AGE_CACHE.get(d)
    if cached is not None:
        return cached

    url = f"https://rdap.org/domain/{d}"
    try:
        req = Request(url, headers={"User-Agent": "PrivGuard/1.0"})
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)

        events = data.get("events") or []
        created: Optional[str] = None
        for ev in events:
            if (ev.get("eventAction") or "").lower() in {"registration", "registered", "created"}:
                created = ev.get("eventDate")
                break
        if not created:
            _DOMAIN_AGE_CACHE.set(d, None)
            return None

        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except Exception:
            _DOMAIN_AGE_CACHE.set(d, None)
            return None

        now = datetime.now(timezone.utc)
        age_days = max(0, int((now - created_dt.astimezone(timezone.utc)).total_seconds() // 86400))
        _DOMAIN_AGE_CACHE.set(d, age_days)
        return age_days

    except Exception:
        _DOMAIN_AGE_CACHE.set(d, None)
        return None


@dataclass
class LayerResult:
    points: int
    lines: List[str]


def _layer1_fast_checks(msg: Dict[str, Any]) -> LayerResult:
    lines: List[str] = []
    pts = 0

    auth = _auth_status(msg.get("auth_results") or "")
    lines.append("Authentication Results:")
    lines.append(f"SPF: {auth['spf']}")
    lines.append(f"DKIM: {auth['dkim']}")
    lines.append(f"DMARC: {auth['dmarc']}")

    for k in ("spf", "dkim", "dmarc"):
        if auth[k] == "FAIL":
            pts += 10

    return LayerResult(points=pts, lines=lines)


def _layer2_header_analysis(msg: Dict[str, Any]) -> LayerResult:
    lines: List[str] = []
    pts = 0

    from_addr = _parse_email_addr(msg.get("from") or "")
    rp_addr = _parse_email_addr(msg.get("return_path") or "")
    rt_addr = _parse_email_addr(msg.get("reply_to") or "")

    lines.append("Header Analysis:")

    if from_addr and rp_addr and from_addr != rp_addr:
        pts += 15
        lines.append("From/Return-Path mismatch detected")
        lines.append(f"From: {from_addr}")
        lines.append(f"Return-Path: {rp_addr}")

    if rt_addr and from_addr and rt_addr != from_addr:
        pts += 10
        lines.append("Reply-To mismatch detected")
        lines.append(f"Reply-To: {rt_addr}")

    received = msg.get("received") or []
    ip = _first_public_ip(received)
    if ip:
        lines.append(f"Sending IP detected: {ip}")

    if len(lines) == 1:
        lines.append("No header anomalies detected")

    return LayerResult(points=pts, lines=lines)


def _layer3_url_analysis(msg: Dict[str, Any], timeout_s: float = 3.0) -> LayerResult:
    pts = 0
    lines: List[str] = ["URL Analysis:"]

    body = (msg.get("text") or "")
    if not body.strip():
        body = msg.get("snippet") or ""

    urls = _extract_urls(body)
    if not urls:
        lines.append("No URLs found")
        return LayerResult(points=0, lines=lines)

    long_urls = [u for u in urls if len(u) > 120]
    if long_urls:
        pts += 6
        lines.append(f"Long URL detected ({len(long_urls)} link(s))")

    ip_hosts = 0
    for u in urls[:40]:
        host = _domain_from_url(u)
        if host and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            ip_hosts += 1
    if ip_hosts:
        pts += 12
        lines.append(f"URL uses raw IP address ({ip_hosts} link(s))")

    sus_kw = 0
    for u in urls[:40]:
        low = u.lower()
        if any(k in low for k in ["login", "verify", "password", "reset", "security", "account"]):
            sus_kw += 1
    if sus_kw:
        pts += 5
        lines.append(f"Login/verification pattern detected ({sus_kw} link(s))")

    young_hits: List[Tuple[str, int]] = []
    checked = 0
    for u in urls:
        if checked >= 5:
            break
        host = _domain_from_url(u)
        bd = _base_domain(host)
        if not bd:
            continue
        checked += 1
        age = _rdap_domain_age_days(bd, timeout_s=timeout_s)
        if age is None:
            continue
        if age <= 14:
            young_hits.append((bd, age))

    if young_hits:
        pts += 18
        for d, age in young_hits[:2]:
            lines.append(f"Suspicious domain age: {age} days ({d})")

    return LayerResult(points=pts, lines=lines)


def _layer4_attachment_analysis(msg: Dict[str, Any]) -> LayerResult:
    pts = 0
    lines: List[str] = ["Attachment Analysis:"]

    atts = msg.get("attachments") or []
    if not atts:
        lines.append("No attachments found")
        return LayerResult(points=0, lines=lines)

    danger = []
    double_ext = []
    macro = []

    for a in atts:
        fn = (a.get("filename") or "").strip()
        low = fn.lower()
        parts = [p for p in low.split(".") if p]

        if len(parts) >= 3:
            last = "." + parts[-1]
            prev = "." + parts[-2]
            if last in DANGEROUS_EXTS and prev in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"}:
                double_ext.append(fn)

        ext = ("." + parts[-1]) if parts else ""
        if ext in DANGEROUS_EXTS:
            danger.append(fn)

        if ext in {".docm", ".xlsm"}:
            macro.append(fn)

    if danger:
        pts += 25
        lines.append("Dangerous attachment extension detected")
        for fn in danger[:3]:
            lines.append(f"File: {fn}")

    if macro:
        pts += 12
        lines.append("Macro-enabled document detected (.docm/.xlsm)")

    if double_ext:
        pts += 20
        lines.append("Double-extension trick detected")
        for fn in double_ext[:2]:
            lines.append(f"File: {fn}")

    if len(lines) == 1:
        lines.append("Attachments look normal")

    return LayerResult(points=pts, lines=lines)


def _layer5_risk_scoring(base_score: int, extra_points: int) -> Tuple[int, str]:
    score = int(max(0, min(100, (base_score or 0) + extra_points)))
    if score >= 75:
        label = "HIGH"
    elif score >= 40:
        label = "MEDIUM"
    else:
        label = "LOW"
    return score, label


def run_advanced_scan_layers(msg: Dict[str, Any], base_report: Dict[str, Any], timeout_s: float = 3.0) -> Dict[str, Any]:
    base_score = int((base_report or {}).get("score") or 0)

    l1 = _layer1_fast_checks(msg)
    l2 = _layer2_header_analysis(msg)
    l3 = _layer3_url_analysis(msg, timeout_s=timeout_s)
    l4 = _layer4_attachment_analysis(msg)

    extra_points = l1.points + l2.points + l3.points + l4.points
    final_score, final_label = _layer5_risk_scoring(base_score, extra_points)

    lines: List[str] = []
    lines.extend(l1.lines)
    lines.append("")
    lines.extend(l2.lines)
    lines.append("")
    lines.extend(l3.lines)
    lines.append("")
    lines.extend(l4.lines)
    lines.append("")
    lines.append(f"Overall Risk Score: {final_score}/100")
    lines.append(f"Threat Level: {final_label}")

    return {
        "lines": lines,
        "score": final_score,
        "label": final_label,
        "extra_points": extra_points,
    }
