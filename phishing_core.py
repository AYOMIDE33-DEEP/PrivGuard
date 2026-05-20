import os
import re
import time
import base64
import ipaddress
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

try:
    import requests
except Exception:
    requests = None

try:
    import whois
except Exception:
    whois = None


SUSPICIOUS_TLDS = {
    "xyz", "top", "gq", "tk", "ml", "cf", "work", "click", "link",
    "zip", "cam", "icu", "info", "ru", "cn", "buzz", "fit", "rest"
}

SUSPICIOUS_KEYWORDS = {
    "verify", "login", "login-update", "account-security", "banking-alert",
    "secure", "signin", "confirm", "password", "wallet", "payment",
    "update", "billing", "support", "unlock", "otp", "reset"
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
    severity: str
    detail: str


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a website URL to analyze.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw = "http://" + raw

    p = urlparse(raw)
    if not p.hostname:
        raise ValueError("Invalid URL. Hostname is missing.")

    scheme = p.scheme.lower() if p.scheme else "http"
    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    host = (p.hostname or "").strip().lower().strip(".")
    netloc = host
    if p.port:
        netloc = f"{host}:{p.port}"

    normalized = urlunparse((
        scheme,
        netloc,
        p.path or "/",
        "",
        p.query or "",
        ""
    ))
    return normalized


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
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


def _contains_punycode(host: str) -> bool:
    return "xn--" in (host or "").lower()


def _extract_domain_age_days(host: str) -> Optional[int]:
    if whois is None:
        print("WHOIS ERROR: python-whois is not installed")
        return None

    try:
        w = whois.whois(host)
        creation_date = getattr(w, "creation_date", None)

        if isinstance(creation_date, list):
            creation_date = next((d for d in creation_date if d), None)

        if not creation_date:
            print(f"WHOIS ERROR: no creation_date returned for {host}")
            return None

        if not hasattr(creation_date, "timestamp"):
            print(f"WHOIS ERROR: invalid creation_date format for {host}: {creation_date}")
            return None

        now = time.time()
        ts = creation_date.timestamp()
        days = int((now - ts) / 86400)

        if days < 0:
            print(f"WHOIS ERROR: negative domain age for {host}")
            return None

        print(f"WHOIS OK: {host} -> {days} days")
        return days

    except Exception as e:
        print(f"WHOIS ERROR for {host}: {e}")
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


def _google_safe_browsing(url: str, api_key: str) -> Dict[str, Any]:
    if not requests or not api_key:
        return {"enabled": False, "status": "not_configured", "flagged": False, "matches": []}

    body = {
        "client": {"clientId": "privguard", "clientVersion": "1.0"},
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

    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=15,
        )

        if r.status_code != 200:
            return {
                "enabled": True,
                "status": "error",
                "flagged": False,
                "matches": [],
                "http_status": r.status_code,
                "error_body": r.text[:500],
            }

        j = r.json() or {}
        matches = j.get("matches") or []

        return {
            "enabled": True,
            "status": "flagged" if matches else "clean",
            "flagged": bool(matches),
            "matches": matches,
        }

    except Exception as e:
        return {
            "enabled": True,
            "status": "error",
            "flagged": False,
            "matches": [],
            "error_body": str(e),
        }


def _vt_scan_url(url: str, api_key: str) -> Dict[str, Any]:
    if not requests or not api_key:
        return {
            "enabled": False,
            "status": "not_configured",
            "malicious": None,
            "suspicious": None,
        }

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": api_key},
            data={"url": url},
            timeout=15,
        )

        if submit.status_code not in {200, 202}:
            return {"enabled": True, "status": "error", "malicious": None, "suspicious": None}

        sid = (((submit.json() or {}).get("data") or {}).get("id") or "").strip()

        if not sid:
            sid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        report = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{sid}",
            headers={"x-apikey": api_key},
            timeout=15,
        )

        if report.status_code != 200:
            return {"enabled": True, "status": "submitted", "malicious": None, "suspicious": None}

        attrs = (((report.json() or {}).get("data") or {}).get("attributes")) or {}
        stats = attrs.get("last_analysis_stats") or {}

        return {
            "enabled": True,
            "status": "ok",
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
        }

    except Exception:
        return {"enabled": True, "status": "error", "malicious": None, "suspicious": None}


def _label_from_score(score: int) -> str:
    if score <= 20:
        return "SAFE"
    if score <= 40:
        return "LOW RISK"
    if score <= 70:
        return "MEDIUM RISK"
    return "HIGH RISK"


def analyze_phishing_url(raw_url: str, enable_online: bool = True, enable_whois: bool = True) -> Dict[str, Any]:
    url = _normalize_url(raw_url)
    p = urlparse(url)
    host = (p.hostname or "").lower().strip(".")
    path_blob = ((p.path or "") + "?" + (p.query or "")).lower()
    full_blob = (host + path_blob).lower()

    findings: List[Finding] = []
    score = 0

    vt_key = (os.getenv("VT_API_KEY") or "").strip()
    gsb_key = (os.getenv("GSB_API_KEY") or "").strip()

    print("VT KEY:", vt_key[:12] if vt_key else "MISSING")
    print("GSB KEY:", gsb_key[:12] if gsb_key else "MISSING")

    base_domain = _guess_etld1(host)
    domain_lookup_target = base_domain

    domain_age_days = None
    registrar = None

    if enable_whois:
        domain_age_days = _extract_domain_age_days(domain_lookup_target)
        registrar = _extract_registrar(domain_lookup_target)

    gsb = _google_safe_browsing(url, gsb_key) if enable_online else {"enabled": False, "status": "disabled"}
    vt = _vt_scan_url(url, vt_key) if enable_online else {"enabled": False, "status": "disabled"}

    print("GSB RESPONSE:", gsb)

    return {
        "ok": True,
        "score": score,
        "label": _label_from_score(score),
        "details": {
            "google_safe_browsing": gsb.get("status"),
            "domain_age_days": domain_age_days,
            "domain_lookup_target": domain_lookup_target,
            "registrar": registrar,
        },
        "provider_status": {
            "virustotal": (
                "Connected" if vt.get("status") in {"ok", "submitted"}
                else "Error" if vt.get("status") == "error"
                else "Not Configured"
            ),
            "google_safe_browsing": (
                "Connected" if gsb.get("status") in {"clean", "flagged"}
                else "Error" if gsb.get("status") == "error"
                else "Not Configured"
            ),
        }
    }