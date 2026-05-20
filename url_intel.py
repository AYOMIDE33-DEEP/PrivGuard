from __future__ import annotations

import base64
import os
import re
import time
import ipaddress
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from services.http_client import HttpClient

try:
    import whois
except Exception:
    whois = None


SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "cam", "icu", "work",
    "gq", "tk", "ml", "cf", "fit", "rest", "buzz", "info"
}
TRACKING_KEYS_PREFIX = ("utm_",)
TRACKING_KEYS_EXACT = {"gclid", "fbclid", "msclkid", "igshid", "mc_cid", "mc_eid"}

HOST_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUNY_RE = re.compile(r"(^|\.)(xn--)", re.IGNORECASE)

SUSPICIOUS_KEYWORDS = {
    "verify", "login", "signin", "secure", "account", "bank",
    "banking", "update", "confirm", "password", "wallet",
    "billing", "support", "reset", "alert", "security", "otp"
}

FREE_HOSTING_HINTS = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "github.io",
    "pages.dev", "netlify.app", "vercel.app", "blogspot.com"
}

TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.ng", "org.ng", "gov.ng", "edu.ng",
    "com.au", "net.au", "org.au",
    "co.za", "org.za", "co.in", "com.br", "com.tr"
}

BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "gmail": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "gtbank": {"gtbank.com"},
    "accessbank": {"accessbankplc.com"},
    "uba": {"ubagroup.com"},
    "firstbank": {"firstbanknigeria.com"},
}


@dataclass
class Finding:
    title: str
    severity: str   # info|warn|fail|pass
    detail: str


def _strip_tracking(u: str) -> str:
    p = urlparse(u)
    q = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        lk = (k or "").lower()
        if lk.startswith(TRACKING_KEYS_PREFIX) or lk in TRACKING_KEYS_EXACT:
            continue
        q.append((k, v))
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a website URL to analyze.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "http://" + raw

    p = urlparse(raw)
    if not p.hostname:
        raise ValueError("Invalid URL. Hostname is missing.")

    if (p.scheme or "").lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    cleaned = _strip_tracking(raw)
    p2 = urlparse(cleaned)
    return urlunparse((
        (p2.scheme or "http").lower(),
        p2.netloc.lower(),
        p2.path or "/",
        "",
        p2.query or "",
        ""
    ))


def _vt_url_id(u: str) -> str:
    b = u.encode("utf-8")
    return base64.urlsafe_b64encode(b).decode("ascii").strip("=")


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    if HOST_IP_RE.fullmatch(host):
        try:
            ipaddress.ip_address(host)
            return True
        except Exception:
            return False
    return False


def _guess_etld1(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return last3
    if last3 in TWO_LEVEL_SUFFIXES and len(parts) >= 4:
        return ".".join(parts[-4:])
    return last2


def _count_subdomains(host: str) -> int:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return 0
    base = _guess_etld1(host)
    return max(0, len(parts) - len(base.split(".")))


def _extract_domain_age_days(host: str) -> Optional[int]:
    if whois is None:
        return None
    try:
        w = whois.whois(host)
        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if not creation_date:
            return None
        now = time.time()
        ts = creation_date.timestamp()
        days = int((now - ts) / 86400)
        if days < 0:
            return None
        return days
    except Exception:
        return None


def _extract_registrar(host: str) -> Optional[str]:
    if whois is None:
        return None
    try:
        w = whois.whois(host)
        reg = getattr(w, "registrar", None)
        return str(reg).strip() if reg else None
    except Exception:
        return None


def _vt_lookup(client: HttpClient, url: str, vt_key: str) -> Dict[str, Any]:
    if not vt_key:
        return {"ok": False, "skipped": True}

    url_id = _vt_url_id(url)
    r = client.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": vt_key},
    )
    if not r.ok:
        return {"ok": False, "error": r.error, "status": r.status}

    attrs = ((r.json or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "ok": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "reputation": int(attrs.get("reputation", 0) or 0),
        "raw": {"last_analysis_stats": stats},
    }


def _gsb_lookup(client: HttpClient, url: str, gsb_key: str) -> Dict[str, Any]:
    if not gsb_key:
        return {"ok": False, "skipped": True}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "PrivGuard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = client.post(endpoint, params={"key": gsb_key}, json=payload)
    if not r.ok:
        return {"ok": False, "error": r.error, "status": r.status}

    matches = (r.json or {}).get("matches") or []
    return {"ok": True, "matched": bool(matches), "matches": matches[:5]}


def _structural_analysis(url: str) -> Tuple[int, List[Finding], Dict[str, Any]]:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    findings: List[Finding] = []
    score = 0

    base_domain = _guess_etld1(host)
    subdomain_count = _count_subdomains(host)
    tld = (host.split(".")[-1] if "." in host else host)
    is_ip_host = _is_ip_host(host)
    is_punycode = bool(PUNY_RE.search(host))
    long_url = len(url) >= 90
    very_long_url = len(url) >= 140
    query_len = len(p.query or "")
    path_len = len(p.path or "")
    suspicious_tld = tld in SUSPICIOUS_TLDS
    free_hosting = any(host.endswith(x) for x in FREE_HOSTING_HINTS)

    full_blob = (host + (p.path or "") + "?" + (p.query or "")).lower()
    suspicious_keywords = sorted({k for k in SUSPICIOUS_KEYWORDS if k in full_blob})

    if is_ip_host:
        score += 20
        findings.append(Finding("IP-based URL", "fail", "The URL host is a raw IP address, which is common in phishing."))

    if is_punycode:
        score += 18
        findings.append(Finding("Punycode domain", "warn", "The hostname uses punycode and may be spoofing a known brand."))

    if suspicious_tld:
        score += 10
        findings.append(Finding("Suspicious TLD", "warn", f"TLD '.{tld}' is frequently abused."))

    if subdomain_count >= 3:
        score += 10
        findings.append(Finding("Excessive subdomains", "warn", f"The hostname contains {subdomain_count} subdomains."))

    if long_url:
        score += 6
        findings.append(Finding("Long URL", "warn", "The URL is unusually long."))
    if very_long_url:
        score += 4

    if query_len > 180:
        score += 4
        findings.append(Finding("Long encoded query", "warn", "Very long query strings often hide redirects or tracking."))

    if suspicious_keywords:
        score += min(12, 3 * len(suspicious_keywords))
        findings.append(Finding(
            "Suspicious URL Pattern Detected",
            "warn",
            f"Contains keywords: {', '.join(suspicious_keywords[:6])}"
        ))

    if free_hosting:
        score += 12
        findings.append(Finding("Free hosting pattern", "warn", "The domain appears hosted on a commonly abused free-hosting platform."))

    for brand, allowed_domains in BRANDS.items():
        if brand in full_blob and base_domain not in allowed_domains:
            score += 18
            findings.append(Finding(
                "Brand impersonation",
                "fail",
                f"The URL references '{brand}' but is hosted on '{base_domain}' instead of the legitimate domain."
            ))
            break

    extra = {
        "host": host,
        "base_domain": base_domain,
        "scheme": p.scheme,
        "path_len": path_len,
        "query_len": query_len,
        "subdomain_count": subdomain_count,
        "is_punycode": is_punycode,
        "is_ip_host": is_ip_host,
        "tld": tld,
        "suspicious_tld": suspicious_tld,
        "free_hosting": free_hosting,
        "suspicious_keywords": suspicious_keywords,
        "long_url": long_url or very_long_url,
    }

    return min(100, score), findings, extra


def _ui_label_from_score(score: int) -> str:
    s = max(0, min(100, int(score)))
    if s <= 20:
        return "SAFE"
    if s <= 40:
        return "LOW RISK"
    if s <= 70:
        return "MEDIUM RISK"
    return "HIGH RISK"


def analyze_url_intel(raw_url: str, enable_online: bool = True, enable_whois: bool = True) -> Dict[str, Any]:
    url = _normalize_url(raw_url)

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    gsb_key = os.environ.get("GSB_API_KEY", "").strip()

    client = HttpClient(timeout_s=8.0, retries=1)

    structural_score, findings, extra = _structural_analysis(url)

    host = extra["host"]
    domain_age_days = _extract_domain_age_days(host) if enable_whois else None
    registrar = _extract_registrar(host) if enable_whois else None

    if domain_age_days is not None and domain_age_days <= 30:
        structural_score = min(100, structural_score + 10)
        findings.append(Finding("Domain Age", "warn", f"{domain_age_days} days old (Very new domain)"))
    elif domain_age_days is not None and domain_age_days <= 90:
        structural_score = min(100, structural_score + 5)
        findings.append(Finding("Domain Age", "warn", f"{domain_age_days} days old"))

    if enable_online:
        vt = _vt_lookup(client, url, vt_key)
        gsb = _gsb_lookup(client, url, gsb_key)
    else:
        vt = {"ok": False, "skipped": True}
        gsb = {"ok": False, "skipped": True}

    score = 0

    # Google Safe Browsing
    if gsb.get("ok") and gsb.get("matched"):
        score += 50
        findings.append(Finding("Google Safe Browsing", "fail", "Flagged as unsafe."))
    elif gsb.get("skipped"):
        findings.append(Finding("Google Safe Browsing", "info", "Skipped (GSB_API_KEY not configured or online checks disabled)."))
    elif not gsb.get("ok"):
        findings.append(Finding("Google Safe Browsing", "warn", "Unavailable (timeout/limit/upstream error)."))
    else:
        findings.append(Finding("Google Safe Browsing", "pass", "Clean."))

    # VirusTotal
    if vt.get("ok"):
        mal = max(0, int(vt.get("malicious", 0)))
        sus = max(0, int(vt.get("suspicious", 0)))
        if mal > 0:
            score += min(40, 12 + mal * 2)
            findings.append(Finding("VirusTotal Detections", "fail", f"{mal} security vendors flagged"))
        elif sus > 0:
            score += min(18, 6 + sus * 2)
            findings.append(Finding("VirusTotal Suspicious", "warn", f"{sus} security vendors marked suspicious"))
        else:
            findings.append(Finding("VirusTotal", "pass", "No malicious engines flagged."))
    elif vt.get("skipped"):
        findings.append(Finding("VirusTotal", "info", "Skipped (VT_API_KEY not configured or online checks disabled)."))
    else:
        findings.append(Finding("VirusTotal", "warn", "Unavailable (timeout/limit/upstream error)."))

    # Structural / heuristics
    score += min(30, structural_score)

    score = max(0, min(100, int(round(score))))
    ui_label = _ui_label_from_score(score)

    summary_map = {
        "SAFE": "This website shows no strong indicators of phishing or scam activity.",
        "LOW RISK": "This website shows a few weak risk signals. Proceed with caution.",
        "MEDIUM RISK": "This website shows multiple suspicious indicators and should be verified carefully.",
        "HIGH RISK": "This website shows strong indicators of phishing or scam activity and should be avoided.",
    }

    threat_report: List[str] = []
    seen = set()
    for f in findings:
        line = f"{f.title}: {f.detail}"
        if line.lower() in seen:
            continue
        seen.add(line.lower())
        threat_report.append(line)
    threat_report = threat_report[:6]

    return {
        "ok": True,
        "url": url,
        "score": score,
        "label": ui_label,
        "summary": summary_map[ui_label],
        "details": {
            "google_safe_browsing": "flagged" if (gsb.get("ok") and gsb.get("matched")) else ("clean" if gsb.get("ok") else "disabled"),
            "virustotal_detections": int(vt.get("malicious", 0) or 0) if vt.get("ok") else 0,
            "virustotal_suspicious": int(vt.get("suspicious", 0) or 0) if vt.get("ok") else 0,
            "domain_age_days": domain_age_days,
            "registrar": registrar,
            "suspicious_patterns": bool(extra.get("suspicious_keywords") or extra.get("is_punycode") or extra.get("long_url") or extra.get("suspicious_tld") or extra.get("free_hosting")),
            "subdomains": int(extra.get("subdomain_count", 0) or 0),
            "punycode": bool(extra.get("is_punycode")),
            "suspicious_tld": bool(extra.get("suspicious_tld")),
            "ip_based_url": bool(extra.get("is_ip_host")),
            "free_hosting": bool(extra.get("free_hosting")),
        },
        "intel": {
            "virustotal": {
                "enabled": bool(vt_key) and enable_online,
                "status": "ok" if vt.get("ok") else ("skipped" if vt.get("skipped") else "error"),
                "malicious": vt.get("malicious"),
                "suspicious": vt.get("suspicious"),
                "harmless": vt.get("harmless"),
                "reputation": vt.get("reputation"),
            },
            "google_safe_browsing": {
                "enabled": bool(gsb_key) and enable_online,
                "status": "flagged" if (gsb.get("ok") and gsb.get("matched")) else ("clean" if gsb.get("ok") else ("skipped" if gsb.get("skipped") else "error")),
                "matched": bool(gsb.get("matched")),
            },
            "domain": {
                "base_domain": extra.get("base_domain"),
                "domain_age_days": domain_age_days,
                "registrar": registrar,
                "tld": extra.get("tld"),
            },
        },
        "findings": [asdict(f) for f in findings],
        "threat_report": threat_report,
        "provider_status": {
            "virustotal": "Connected" if vt_key else "Not Configured",
            "google_safe_browsing": "Connected" if gsb_key else "Not Configured",
        },
        "degraded": (
            enable_online and (
                (not vt.get("ok") and not vt.get("skipped")) or
                (not gsb.get("ok") and not gsb.get("skipped"))
            )
        ),
        # keep old keys too, so older UI still works
        "risk_score": score,
        "classification": ui_label,
        "components": {
            "structural_score": structural_score,
        },
        "indicators": extra,
    }