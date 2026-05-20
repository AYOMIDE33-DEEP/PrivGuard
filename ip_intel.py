# services/ip_intel.py
import os
import time
import ipaddress
import requests


# -----------------------------
# Validation
# -----------------------------
def validate_any_ip(ip_str: str):
    """
    Accept any syntactically valid IPv4/IPv6.
    We do NOT reject private/reserved/etc here.
    """
    ip_str = (ip_str or "").strip()
    if not ip_str:
        return False, "Missing IP address.", None

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return True, str(ip_obj), ip_obj
    except ValueError:
        return False, "This IP does not exist or is invalid.", None


def classify_ip_scope(ip_obj):
    """
    Return analyst-friendly IP scope classification.
    """
    if ip_obj is None:
        return "unknown"

    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_link_local:
        return "link_local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_reserved:
        return "reserved"
    if ip_obj.is_unspecified:
        return "unspecified"
    return "public"


# -----------------------------
# API Integrations (normalized)
# -----------------------------
def check_abuseipdb(ip: str, api_key: str, timeout_s: float = 8.0):
    if not api_key:
        return {"ok": False, "configured": False, "error": "Not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": "PrivGuard-IPIntel/1.0",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout_s)
        if r.status_code in (401, 403):
            return {"ok": False, "configured": True, "error": "Invalid API key"}
        if r.status_code == 422:
            return {"ok": False, "configured": True, "error": "No public reputation data"}
        r.raise_for_status()

        data = r.json() or {}
        d = (data.get("data") or {})

        return {
            "ok": True,
            "configured": True,
            "abuseConfidenceScore": int(d.get("abuseConfidenceScore") or 0),
            "totalReports": int(d.get("totalReports") or 0),
            "lastReportedAt": d.get("lastReportedAt") or "",
            "countryCode": d.get("countryCode") or "",
            "usageType": d.get("usageType") or "",
            "isp": d.get("isp") or "",
        }
    except requests.exceptions.Timeout:
        return {"ok": False, "configured": True, "error": "Timeout"}
    except Exception:
        return {"ok": False, "configured": True, "error": "Request failed"}


def check_virustotal(ip: str, api_key: str, timeout_s: float = 8.0):
    if not api_key:
        return {"ok": False, "configured": False, "error": "Not configured"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "PrivGuard-IPIntel/1.0",
    }

    try:
        r = requests.get(url, headers=headers, timeout=timeout_s)
        if r.status_code in (401, 403):
            return {"ok": False, "configured": True, "error": "Invalid API key"}
        if r.status_code == 404:
            return {"ok": False, "configured": True, "error": "IP not found in VirusTotal"}
        r.raise_for_status()

        j = r.json() or {}
        attrs = ((j.get("data") or {}).get("attributes") or {})
        stats = (attrs.get("last_analysis_stats") or {})

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout = int(stats.get("timeout") or 0)

        total = malicious + suspicious + harmless + undetected + timeout
        reputation = int(attrs.get("reputation") or 0)

        return {
            "ok": True,
            "configured": True,
            "reputation": reputation,
            "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
                "total_engines": total,
            }
        }
    except requests.exceptions.Timeout:
        return {"ok": False, "configured": True, "error": "Timeout"}
    except Exception:
        return {"ok": False, "configured": True, "error": "Request failed"}


def check_ipinfo(ip: str, api_key: str, timeout_s: float = 8.0):
    if not api_key:
        return {"ok": False, "configured": False, "error": "Not configured"}

    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": api_key}
    headers = {"User-Agent": "PrivGuard-IPIntel/1.0", "Accept": "application/json"}

    try:
        r = requests.get(url, params=params, headers=headers, timeout=timeout_s)
        if r.status_code in (401, 403):
            return {"ok": False, "configured": True, "error": "Invalid API key"}
        if r.status_code == 404:
            return {"ok": False, "configured": True, "error": "IP not found"}
        r.raise_for_status()

        d = r.json() or {}

        return {
            "ok": True,
            "configured": True,
            "country": d.get("country") or "",
            "region": d.get("region") or "",
            "city": d.get("city") or "",
            "org": d.get("org") or "",
            "hostname": d.get("hostname") or "",
        }
    except requests.exceptions.Timeout:
        return {"ok": False, "configured": True, "error": "Timeout"}
    except Exception:
        return {"ok": False, "configured": True, "error": "Request failed"}


# -----------------------------
# Scoring + Verdict
# -----------------------------
def _vt_score_percent(vt: dict) -> float:
    try:
        s = vt.get("last_analysis_stats") or {}
        mal = int(s.get("malicious") or 0)
        susp = int(s.get("suspicious") or 0)
        total = int(s.get("total_engines") or 0)
        if total <= 0:
            return 0.0
        return (float(mal + susp) / float(total)) * 100.0
    except Exception:
        return 0.0


def _ipinfo_factor(ipinfo: dict) -> float:
    org = (ipinfo.get("org") or "").lower()
    if not org:
        return 0.0

    keywords = [
        "hosting", "datacenter", "data center", "cloud", "amazon", "aws",
        "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner",
        "linode", "vultr", "leaseweb", "stackpath", "cloudflare",
        "cdn", "content delivery", "network"
    ]
    if any(k in org for k in keywords):
        return 80.0
    return 0.0


def compute_risk_score(abuse: dict, vt: dict, ipinfo: dict):
    abuse_score = float(abuse.get("abuseConfidenceScore") or 0.0) if abuse.get("ok") else 0.0
    vt_score = float(_vt_score_percent(vt)) if vt.get("ok") else 0.0
    ipinfo_factor = float(_ipinfo_factor(ipinfo)) if ipinfo.get("ok") else 0.0

    risk = (abuse_score * 0.5) + (vt_score * 0.4) + (ipinfo_factor * 0.1)
    risk = max(0.0, min(100.0, risk))
    return int(round(risk))


def verdict_from_score(score: int) -> str:
    s = max(0, min(100, int(score or 0)))
    if s >= 71:
        return "High Risk"
    if s >= 31:
        return "Suspicious"
    return "Safe"


def build_threat_indicators(abuse: dict, vt: dict, ipinfo: dict, score: int, scope: str):
    indicators = []

    if scope != "public":
        scope_map = {
            "private": "Private/internal IP address",
            "loopback": "Loopback/localhost IP address",
            "link_local": "Link-local IP address",
            "multicast": "Multicast IP address",
            "reserved": "Reserved IP range",
            "unspecified": "Unspecified IP address",
        }
        indicators.append(scope_map.get(scope, "Non-public IP address"))
        indicators.append("Public threat-intelligence services may not have reputation data for this IP")
        return indicators

    if abuse.get("ok"):
        conf = int(abuse.get("abuseConfidenceScore") or 0)
        reps = int(abuse.get("totalReports") or 0)
        if conf >= 60:
            indicators.append("High abuse confidence (AbuseIPDB)")
        elif conf >= 25:
            indicators.append("Moderate abuse confidence (AbuseIPDB)")
        if reps > 0:
            indicators.append(f"Reported {reps} time(s) (AbuseIPDB)")

    if vt.get("ok"):
        s = vt.get("last_analysis_stats") or {}
        mal = int(s.get("malicious") or 0)
        susp = int(s.get("suspicious") or 0)
        total = int(s.get("total_engines") or 0)
        if (mal + susp) > 0 and total > 0:
            indicators.append(f"Detected by {mal + susp} security vendor(s) (VirusTotal)")

    if ipinfo.get("ok") and _ipinfo_factor(ipinfo) > 0:
        indicators.append("Hosting provider / datacenter ASN")

    if score >= 71:
        indicators.append("High correlated risk across sources")

    return indicators


def _hosting_type_from_org(org: str) -> str:
    o = (org or "").lower()
    if not o:
        return ""
    if any(k in o for k in ["cloudflare", "cdn", "content delivery", "akamai", "fastly"]):
        return "Content Delivery Network"
    if any(k in o for k in ["hosting", "datacenter", "data center", "cloud", "aws", "amazon", "azure", "google", "microsoft", "ovh", "hetzner", "digitalocean", "linode", "vultr"]):
        return "Data Center / Hosting"
    return "Residential / ISP"


# -----------------------------
# Main Orchestrator
# -----------------------------
def analyze_ip_intel(
    ip: str,
    enable_online: bool = True,
    abuse_key=None,
    vt_key=None,
    ipinfo_key=None,
    timeout_s: float = 8.0,
):
    t0 = time.time()

    ok, ip_norm, ip_obj = validate_any_ip(ip)
    if not ok:
        return {"error": ip_norm}

    scope = classify_ip_scope(ip_obj)

    # For non-public IPs: return local classification, not hard failure
    if scope != "public":
        return {
            "ip": ip_norm,
            "scope": scope,
            "risk_score": 0,
            "verdict": "Internal / Non-Public",
            "sources": {
                "abuseipdb": {"ok": False, "configured": True, "error": "Not applicable for non-public IP"},
                "virustotal": {"ok": False, "configured": True, "error": "Not applicable for non-public IP"},
                "ipinfo": {"ok": False, "configured": True, "error": "Not applicable for non-public IP"},
            },
            "threat_indicators": build_threat_indicators({}, {}, {}, 0, scope),
            "degraded": False,
            "scan_time_ms": int((time.time() - t0) * 1000),
        }

    if not enable_online:
        return {
            "ip": ip_norm,
            "scope": scope,
            "risk_score": 0,
            "verdict": "Safe",
            "sources": {
                "abuseipdb": {"ok": False, "configured": False, "error": "Online disabled"},
                "virustotal": {"ok": False, "configured": False, "error": "Online disabled"},
                "ipinfo": {"ok": False, "configured": False, "error": "Online disabled"},
            },
            "threat_indicators": ["Online enrichment disabled"],
            "degraded": True,
            "scan_time_ms": int((time.time() - t0) * 1000),
        }

    abuse_key = abuse_key or os.environ.get("ABUSEIPDB_KEY", "") or os.environ.get("ABUSEIPDB_API_KEY", "")
    vt_key = vt_key or os.environ.get("VIRUSTOTAL_KEY", "") or os.environ.get("VT_API_KEY", "")
    ipinfo_key = ipinfo_key or os.environ.get("IPINFO_KEY", "") or os.environ.get("IPINFO_TOKEN", "")

    abuse = check_abuseipdb(ip_norm, abuse_key, timeout_s=timeout_s)
    vt = check_virustotal(ip_norm, vt_key, timeout_s=timeout_s)
    ipinfo = check_ipinfo(ip_norm, ipinfo_key, timeout_s=timeout_s)

    risk_score = compute_risk_score(abuse, vt, ipinfo)
    verdict = verdict_from_score(risk_score)
    indicators = build_threat_indicators(abuse, vt, ipinfo, risk_score, scope)

    degraded = not (abuse.get("ok") or vt.get("ok") or ipinfo.get("ok"))

    if ipinfo.get("ok"):
        ipinfo = dict(ipinfo)
        ipinfo["hosting_type"] = _hosting_type_from_org(ipinfo.get("org") or "")

    # If all providers failed / no data, show "does not exist or no public intelligence"
    if degraded and not indicators:
        indicators = ["This IP may not exist publicly or no reputation data was found"]

    return {
        "ip": ip_norm,
        "scope": scope,
        "risk_score": risk_score,
        "verdict": verdict,
        "sources": {
            "abuseipdb": abuse,
            "virustotal": vt,
            "ipinfo": ipinfo,
        },
        "threat_indicators": indicators,
        "degraded": degraded,
        "scan_time_ms": int((time.time() - t0) * 1000),
    }