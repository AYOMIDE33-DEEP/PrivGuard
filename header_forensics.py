from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from services.ip_intel import analyze_ip_intel

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
AUTH_TOKEN_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)

@dataclass
class Hop:
    raw: str
    ips: List[str]

@dataclass
class Finding:
    title: str
    severity: str
    detail: str

def _uniq(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _extract_ips(text: str) -> List[str]:
    return _uniq(IPV4_RE.findall(text or ""))

def _parse_received_chain(msg) -> List[Hop]:
    recvd = msg.get_all("Received", []) or []
    hops: List[Hop] = []
    for raw in recvd:
        r = str(raw).replace("\r", "").replace("\n", " ").strip()
        hops.append(Hop(raw=r, ips=_extract_ips(r)))
    return hops

def _extract_origin_ip(msg) -> Optional[str]:
    # Prefer explicit headers when present
    for k in ("X-Originating-IP", "X-Client-IP", "X-Forwarded-For"):
        v = msg.get(k)
        if v:
            ips = _extract_ips(v)
            if ips:
                return ips[0]
    hops = _parse_received_chain(msg)
    all_ips: List[str] = []
    for h in hops:
        all_ips.extend(h.ips)
    all_ips = _uniq(all_ips)
    return all_ips[-1] if all_ips else None

def _auth_results(msg) -> Dict[str, str]:
    ars = msg.get_all("Authentication-Results", []) or []
    joined = " | ".join(str(x) for x in ars)
    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    for k, v in AUTH_TOKEN_RE.findall(joined):
        k = k.lower().strip()
        if k in auth and auth[k] == "unknown":
            auth[k] = (v or "").lower().strip()
    return auth

def analyze_header_forensics(raw_headers: str) -> Dict[str, Any]:
    raw_headers = (raw_headers or "").strip()
    if not raw_headers:
        raise ValueError("Paste raw email headers first.")
    if len(raw_headers) > 200_000:
        raise ValueError("Headers too large.")

    msg = Parser(policy=policy.default).parsestr(raw_headers)

    from_name, from_addr = parseaddr(msg.get("From", "") or "")
    _, rp_addr = parseaddr(msg.get("Return-Path", "") or "")
    _, reply_to = parseaddr(msg.get("Reply-To", "") or "")

    hops = _parse_received_chain(msg)
    origin_ip = _extract_origin_ip(msg)

    findings: List[Finding] = []
    if from_addr and rp_addr and from_addr.lower() != rp_addr.lower():
        findings.append(Finding("From/Return-Path mismatch", "warn", f"From={from_addr} Return-Path={rp_addr}"))
    if reply_to and from_addr and reply_to.lower() != from_addr.lower():
        findings.append(Finding("Reply-To mismatch", "warn", f"Reply-To={reply_to} From={from_addr}"))

    auth = _auth_results(msg)
    if auth.get("spf") in ("fail", "softfail"):
        findings.append(Finding("SPF failure", "warn", f"SPF={auth.get('spf')}"))
    if auth.get("dkim") == "fail":
        findings.append(Finding("DKIM failure", "warn", "DKIM=fail"))
    if auth.get("dmarc") == "fail":
        findings.append(Finding("DMARC failure", "warn", "DMARC=fail"))

    ip_intel = None
    if origin_ip:
        try:
            ip_intel = analyze_ip_intel(origin_ip)
        except Exception:
            ip_intel = {"ip": origin_ip, "risk_score": 0, "classification": "UNKNOWN", "degraded": True}

    # Path visualization: top hop is most recent; origin is earliest
    path = []
    for i, h in enumerate(hops[:30]):
        path.append({
            "hop": i + 1,
            "ips": h.ips,
            "raw": h.raw[:700],
        })

    # IP risk roll-up (if present)
    ip_score = int((ip_intel or {}).get("risk_score", 0) or 0)
    if ip_score >= 80: threat = "HIGH RISK"
    elif ip_score >= 45: threat = "SUSPICIOUS"
    else: threat = "LOW"

    recommendation = (
        "Treat as malicious: quarantine and block sender infrastructure."
        if threat == "HIGH RISK" else
        "Verify sender authenticity; inspect links and attachments carefully."
        if threat == "SUSPICIOUS" else
        "No strong infrastructure indicators detected; continue content-level review."
    )

    return {
        "from": {"name": from_name, "addr": from_addr},
        "return_path": rp_addr,
        "reply_to": reply_to,
        "auth": auth,
        "origin_ip": origin_ip or "—",
        "ip_intel": ip_intel,
        "ip_risk": {"score": ip_score, "classification": threat},
        "received_path": path,
        "findings": [asdict(f) for f in findings],
        "recommendation": recommendation,
    }