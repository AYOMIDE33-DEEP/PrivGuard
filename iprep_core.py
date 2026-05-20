import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple

try:
    import requests
except Exception:
    requests = None

@dataclass
class Finding:
    title: str
    severity: str
    detail: str

def _parse_ip(raw: str) -> ipaddress._BaseAddress:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter an IP address.")
    if ":" in raw and raw.count(":") == 1 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d{1,5}", raw):
        raw = raw.split(":")[0]
    return ipaddress.ip_address(raw)

def _offline_checks(ip_obj: ipaddress._BaseAddress) -> List[Finding]:
    f: List[Finding] = []
    if ip_obj.is_loopback: f.append(Finding("Loopback address", "info", "Localhost/loopback (not public)."))
    if ip_obj.is_private: f.append(Finding("Private address", "info", "RFC1918/private range (not public)."))
    if ip_obj.is_link_local: f.append(Finding("Link-local address", "info", "Local network only."))
    if ip_obj.is_multicast: f.append(Finding("Multicast address", "info", "Multicast range."))
    if ip_obj.is_reserved: f.append(Finding("Reserved address", "info", "Reserved/special-use range."))
    if ip_obj.is_unspecified: f.append(Finding("Unspecified address", "warn", "Unspecified/invalid for real hosts."))

    if getattr(ip_obj, "is_global", False) is False:
        f.append(Finding("Not a global IP", "warn", "Not globally routable; reputation may be meaningless."))

    if not f:
        f.append(Finding("Public/global IP", "pass", "Looks like a globally routable IP address."))
    return f

def _abuseipdb_check(ip_str: str, api_key: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not api_key or requests is None:
        return None, None
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip_str, "maxAgeInDays": 90, "verbose": "true"}
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=12)
        if r.status_code != 200:
            return f"AbuseIPDB failed ({r.status_code})", None
        return "AbuseIPDB ok", (r.json().get("data", {}) or {})
    except Exception as e:
        return f"AbuseIPDB error: {e.__class__.__name__}", None

def _virustotal_ip_check(ip_str: str, api_key: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not api_key or requests is None:
        return None, None
    try:
        headers = {"x-apikey": api_key}
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_str}", headers=headers, timeout=12)
        if r.status_code != 200:
            return f"VirusTotal failed ({r.status_code})", None
        attrs = ((r.json().get("data", {}) or {}).get("attributes", {}) or {})
        return "VirusTotal ok", attrs
    except Exception as e:
        return f"VirusTotal error: {e.__class__.__name__}", None

def analyze_ip(raw: str, *, use_online: bool = False, vt_api_key: str = "", abuseipdb_api_key: str = "") -> dict:
    ip_obj = _parse_ip(raw)
    ip_str = str(ip_obj)

    findings = _offline_checks(ip_obj)
    score = 0
    extra: Dict[str, Any] = {"online": {}}

    non_global = not getattr(ip_obj, "is_global", False)
    verdict = "N/A" if non_global else "LOW"

    if use_online and not non_global:
        ab_status, ab_data = _abuseipdb_check(ip_str, abuseipdb_api_key.strip())
        if ab_status is None:
            findings.append(Finding("AbuseIPDB", "info", "Skipped (no ABUSEIPDB_API_KEY set)."))
        elif ab_data is None:
            findings.append(Finding("AbuseIPDB", "info", ab_status))
        else:
            extra["online"]["abuseipdb"] = ab_data
            conf = int(ab_data.get("abuseConfidenceScore", 0) or 0)
            reports = int(ab_data.get("totalReports", 0) or 0)
            last = ab_data.get("lastReportedAt") or "—"
            if conf >= 80:
                findings.append(Finding("AbuseIPDB: high abuse score", "fail", f"Score={conf}, reports={reports}, last={last}"))
                score += 55
            elif conf >= 40:
                findings.append(Finding("AbuseIPDB: suspicious", "warn", f"Score={conf}, reports={reports}, last={last}"))
                score += 25
            elif reports > 0:
                findings.append(Finding("AbuseIPDB: reports exist", "warn", f"Score={conf}, reports={reports}, last={last}"))
                score += 12
            else:
                findings.append(Finding("AbuseIPDB: no reports", "pass", "No abuse reports in last 90 days."))

        vt_status, vt_attrs = _virustotal_ip_check(ip_str, vt_api_key.strip())
        if vt_status is None:
            findings.append(Finding("VirusTotal", "info", "Skipped (no VT_API_KEY set)."))
        elif vt_attrs is None:
            findings.append(Finding("VirusTotal", "info", vt_status))
        else:
            extra["online"]["virustotal"] = vt_attrs
            stats = vt_attrs.get("last_analysis_stats") or {}
            mal = int(stats.get("malicious", 0) or 0)
            sus = int(stats.get("suspicious", 0) or 0)
            if mal >= 3:
                findings.append(Finding("VirusTotal: malicious detections", "fail", f"malicious={mal}, suspicious={sus}"))
                score += 45
            elif mal >= 1 or sus >= 2:
                findings.append(Finding("VirusTotal: suspicious", "warn", f"malicious={mal}, suspicious={sus}"))
                score += 20
            else:
                findings.append(Finding("VirusTotal: clean-ish", "pass", f"malicious={mal}, suspicious={sus}"))

    if not non_global:
        if score >= 70: verdict = "HIGH"
        elif score >= 35: verdict = "MEDIUM"
        else: verdict = "LOW"

    return {
        "ip": ip_str,
        "score": min(100, score),
        "verdict": verdict,
        "findings": [asdict(x) for x in findings],
        "extra": extra,
    }