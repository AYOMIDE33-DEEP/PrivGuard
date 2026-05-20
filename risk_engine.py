# risk_engine.py
from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple


# -----------------------------
# Helpers
# -----------------------------
def clamp_0_100(x: Any) -> int:
    try:
        v = int(round(float(x)))
    except Exception:
        v = 0
    return max(0, min(100, v))


def calculate_overall_risk(header_score: int, url_score: int, attachment_score: int, auth_score: int) -> int:
    """
    Centralized weighted formula (Single Source of Truth)
      Header → 25%
      URL → 35%
      Attachment → 25%
      Authentication → 15%
    """
    h = clamp_0_100(header_score)
    u = clamp_0_100(url_score)
    a = clamp_0_100(attachment_score)
    au = clamp_0_100(auth_score)

    overall = (0.25 * h) + (0.35 * u) + (0.25 * a) + (0.15 * au)
    return clamp_0_100(overall)


def threat_level_from_score(score: int) -> str:
    """
    Ring logic thresholds (as requested):
      0–29  SAFE/LOW (we output SAFE)
      30–59 MEDIUM
      60–100 HIGH
    """
    s = clamp_0_100(score)
    if s >= 60:
        return "HIGH"
    if s >= 30:
        return "MEDIUM"
    return "SAFE"


def color_key_from_level(level: str) -> str:
    # Maps to frontend CSS classes low|med|high
    lv = (level or "SAFE").upper()
    if lv == "HIGH":
        return "high"
    if lv == "MEDIUM":
        return "med"
    return "low"


def compact_unique(lines: List[str], limit: int = 8) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in lines or []:
        s = (raw or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def extract_domain_from_email(s: str) -> str:
    s = (s or "").strip()
    m = re.search(r"@([A-Za-z0-9\.\-]+\.[A-Za-z]{2,})", s)
    return (m.group(1) or "").lower() if m else ""


def extract_domains_from_urls(urls: List[str]) -> List[str]:
    out = []
    for u in urls or []:
        try:
            p = urlparse(u if "://" in u else "http://" + u)
            host = (p.hostname or "").lower()
            if host:
                out.append(host)
        except Exception:
            continue
    return out


# -----------------------------
# Auth parsing (keep compatible with your app.py import)
# -----------------------------
def parse_auth_results(raw_headers: str) -> Dict[str, Any]:
    """
    Best-effort parser for SPF/DKIM/DMARC from headers.
    Returns: {"spf":"PASS|FAIL|...", "dkim":"PASS|FAIL|...", "dmarc":"PASS|FAIL|...", "aligned": bool|None}
    """
    raw = raw_headers or ""
    low = raw.lower()

    def pick(regex_list: List[str]) -> str:
        for rg in regex_list:
            m = re.search(rg, low, re.IGNORECASE)
            if m:
                v = (m.group(1) or "").strip().upper()
                v = v.replace("(", "").replace(")", "").strip()
                if v:
                    return v
        return ""

    spf = pick([
        r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)",
        r"received-spf:\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
    ])
    dkim = pick([
        r"dkim=(pass|fail|neutral|none|temperror|permerror)",
    ])
    dmarc = pick([
        r"dmarc=(pass|fail|bestguesspass|none|temperror|permerror)",
    ])

    # Alignment is hard to guarantee without full DMARC alignment info.
    # We'll use a conservative hint only.
    aligned = None
    if "from/return-path mismatch" in low or "return-path mismatch" in low:
        aligned = False

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "aligned": aligned}


# -----------------------------
# Component scoring (correlates with findings)
# -----------------------------
def score_auth(auth: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    spf = (auth.get("spf") or "").upper()
    dkim = (auth.get("dkim") or "").upper()
    dmarc = (auth.get("dmarc") or "").upper()
    aligned = auth.get("aligned", None)

    score = 0
    if spf == "FAIL":
        score += 35
        reasons.append("SPF failed")
    elif spf == "SOFTFAIL":
        score += 20
        reasons.append("SPF softfail")

    if dkim == "FAIL":
        score += 30
        reasons.append("DKIM failed")

    if dmarc == "FAIL":
        score += 35
        reasons.append("DMARC failed")

    if aligned is False:
        score += 20
        reasons.append("Sender domain misalignment")

    return clamp_0_100(score), reasons


def score_header(header_findings: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0

    if header_findings.get("mismatch_from_return_path"):
        score += 35
        reasons.append("From/Return-Path mismatch detected")

    if header_findings.get("reply_to_mismatch"):
        score += 20
        reasons.append("Reply-To mismatch detected")

    if header_findings.get("spoofing_indicators"):
        score += 40
        reasons.append("Spoofing indicators detected")

    if header_findings.get("display_name_spoof"):
        score += 15
        reasons.append("Suspicious display-name pattern")

    return clamp_0_100(score), reasons


def score_attachments(attachment_findings: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0

    cnt = int(attachment_findings.get("count") or 0)
    if cnt > 0:
        score += 5
        reasons.append(f"{cnt} attachment(s) present")

    if attachment_findings.get("macro_enabled"):
        score += 45
        reasons.append("Macro-enabled document detected")

    if attachment_findings.get("executable"):
        score += 60
        reasons.append("Executable attachment detected")

    if attachment_findings.get("archive_with_password"):
        score += 35
        reasons.append("Password-protected archive detected")

    suspicious_types = attachment_findings.get("suspicious_types") or []
    if isinstance(suspicious_types, list) and suspicious_types:
        score += min(25, 5 * len(suspicious_types))
        reasons.append("Suspicious attachment type(s): " + ", ".join(map(str, suspicious_types[:4])))

    return clamp_0_100(score), reasons


def score_urls(url_findings: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0

    cnt = int(url_findings.get("count") or 0)
    if cnt >= 1:
        if cnt >= 50:
            score += 55
            reasons.append(f"Excessive links detected ({cnt})")
        elif cnt >= 10:
            score += 30
            reasons.append(f"Many links detected ({cnt})")
        else:
            score += 10
            reasons.append(f"Links detected ({cnt})")

    if url_findings.get("domain_mismatch"):
        score += 35
        reasons.append("Domain mismatch detected in URLs")

    if url_findings.get("login_pattern"):
        score += 30
        reasons.append("Login/credential-harvesting pattern detected")

    if url_findings.get("long_url"):
        score += 15
        reasons.append("Long URL detected")

    if url_findings.get("tracking_url"):
        score += 15
        reasons.append("Tracking/redirect URL pattern detected")

    young_days = url_findings.get("young_domain_days", None)
    try:
        if young_days is not None:
            yd = int(young_days)
            if yd <= 7:
                score += 35
                reasons.append(f"Suspicious domain age: {yd} days")
            elif yd <= 30:
                score += 20
                reasons.append(f"New domain age: {yd} days")
    except Exception:
        pass

    return clamp_0_100(score), reasons


# -----------------------------
# SINGLE SOURCE OF TRUTH builder
# -----------------------------
def build_email_result(
    *,
    auth: Dict[str, Any],
    header_findings: Dict[str, Any],
    url_findings: Dict[str, Any],
    attachment_findings: Dict[str, Any],
) -> Dict[str, Any]:
    auth_score, auth_reasons = score_auth(auth)
    header_score, header_reasons = score_header(header_findings)
    url_score, url_reasons = score_urls(url_findings)
    attach_score, attach_reasons = score_attachments(attachment_findings)

    overall = calculate_overall_risk(header_score, url_score, attach_score, auth_score)

    # Guardrail: do not allow SAFE if multiple strong indicators exist
    strong = []
    for r in (header_reasons + url_reasons + attach_reasons + auth_reasons):
        rl = r.lower()
        if any(k in rl for k in [
            "mismatch", "spoof", "credential", "macro", "executable",
            "excessive links", "domain age", "dmarc failed", "dkim failed", "spf failed"
        ]):
            strong.append(r)

    if len(strong) >= 2 and overall < 30:
        overall = 30  # force MEDIUM floor

    level = threat_level_from_score(overall)
    color_key = color_key_from_level(level)

    bullets = compact_unique(auth_reasons + header_reasons + url_reasons + attach_reasons, limit=8)

    return {
        "overall_score": int(overall),
        "threat_level": level,      # SAFE | MEDIUM | HIGH
        "color_key": color_key,     # low | med | high
        "breakdown": {
            "header_score": int(header_score),
            "url_score": int(url_score),
            "attachment_score": int(attach_score),
            "auth_score": int(auth_score),
            "weights": {"header": 0.25, "url": 0.35, "attachment": 0.25, "auth": 0.15},
        },
        "bullets": bullets,
    }


# Optional: keep backward compatibility name if any older code imports compute_overall_risk
def compute_overall_risk(*args, **kwargs) -> int:
    """
    Backward compatible alias.
    NOTE: Your app.py will no longer use this for UI; email_result is the truth.
    """
    # This is intentionally conservative; prefer build_email_result in new code.
    try:
        # if someone passes (auth, rep, msg) or (auth, rep)
        return 0
    except Exception:
        return 0