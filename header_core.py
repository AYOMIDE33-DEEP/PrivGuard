import os
import re
import ipaddress
import socket
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from email import policy
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime
from datetime import timezone

try:
    import requests
except Exception:
    requests = None


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
FROM_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
BRACKET_HOST_RE = re.compile(r"\((.*?)\)")
MESSAGE_ID_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s(;\[]+)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s(;\[]+)", re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.IGNORECASE)
DKIM_DOMAIN_RE = re.compile(r"\bheader\.d=([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
SPF_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom=([A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str


def _clean(s: str) -> str:
    return (s or "").replace("\r", " ").replace("\n", " ").strip()


def _extract_ips(text: str) -> List[str]:
    ips = IPV4_RE.findall(text or "")
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except Exception:
        return False


def _extract_domain(value: str) -> str:
    m = FROM_DOMAIN_RE.search(value or "")
    return (m.group(1) or "").lower() if m else ""


def _extract_msgid_domain(value: str) -> str:
    m = MESSAGE_ID_DOMAIN_RE.search(value or "")
    return (m.group(1) or "").lower() if m else ""


def _safe_reverse_dns(ip: str) -> str:
    if not ip or not _is_public_ip(ip):
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _parse_received_chain(msg) -> List[Dict[str, Any]]:
    recvd = msg.get_all("Received", []) or []
    hops: List[Dict[str, Any]] = []

    # Email headers list newest first; reverse so hop 1 becomes earliest/source side
    for idx, raw in enumerate(reversed(recvd), start=1):
        r = _clean(str(raw))
        ips = _extract_ips(r)

        dt = None
        if ";" in r:
            try:
                dt = parsedate_to_datetime(r.rsplit(";", 1)[-1].strip())
                if dt and dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                dt = None

        host_from = ""
        host_by = ""
        transport = ""

        m_from = RECEIVED_FROM_RE.search(r)
        if m_from:
            host_from = (m_from.group(1) or "").strip()

        m_by = RECEIVED_BY_RE.search(r)
        if m_by:
            host_by = (m_by.group(1) or "").strip()

        m_with = RECEIVED_WITH_RE.search(r)
        if m_with:
            transport = (m_with.group(1) or "").strip()

        hops.append({
            "hop": idx,
            "raw": r,
            "ips": ips,
            "dt": dt.isoformat() if dt else None,
            "helo": host_from,
            "by": host_by,
            "transport": transport,
        })

    return hops


def _extract_auth(msg) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any]]:
    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    details = {"spf": "", "dkim": "", "dmarc": ""}
    meta = {
        "dkim_domain": "",
        "spf_mailfrom": "",
        "auth_results_raw": "",
    }

    ars = msg.get_all("Authentication-Results", []) or []
    joined = " | ".join(str(x) for x in ars)
    meta["auth_results_raw"] = joined

    for k, v in AUTH_RE.findall(joined):
        k = k.lower().strip()
        v = v.lower().strip()
        if k in auth and auth[k] == "unknown":
            auth[k] = v

    if joined:
        for k in auth.keys():
            m = re.search(rf"\b{k}\s*=\s*([a-zA-Z0-9_-]+)([^;|]+)?", joined, flags=re.IGNORECASE)
            if m:
                details[k] = (m.group(0) or "").strip()

        md = DKIM_DOMAIN_RE.search(joined)
        if md:
            meta["dkim_domain"] = (md.group(1) or "").lower()

        sm = SPF_MAILFROM_RE.search(joined)
        if sm:
            meta["spf_mailfrom"] = (sm.group(1) or "").lower()

    return auth, details, meta


def _guess_true_origin_ip(hops: List[Dict[str, Any]]) -> str:
    for hop in hops:
        for ip in hop.get("ips") or []:
            if _is_public_ip(ip):
                return ip
    # fallback to earliest found ip
    for hop in hops:
        for ip in hop.get("ips") or []:
            return ip
    return "—"


def _country_flag(country_code: str) -> str:
    cc = (country_code or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


def _abuseipdb(ip: str, api_key: str) -> Optional[dict]:
    if not requests or not api_key or not ip or ip == "—":
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            timeout=12,
        )
        if r.status_code != 200:
            return None
        return (r.json().get("data") or {})
    except Exception:
        return None


def _virustotal_ip(ip: str, api_key: str) -> Optional[dict]:
    if not requests or not api_key or not ip or ip == "—":
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=12,
        )
        if r.status_code != 200:
            return None
        return (((r.json().get("data") or {}).get("attributes")) or {})
    except Exception:
        return None


def _ipinfo(ip: str, api_key: str) -> Optional[dict]:
    if not requests or not api_key or not ip or ip == "—":
        return None
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=12,
        )
        if r.status_code != 200:
            return None
        return r.json() or {}
    except Exception:
        return None


def _normalize_reputation(ip: str, abuse: Optional[dict], vt: Optional[dict], ipi: Optional[dict]) -> Dict[str, Any]:
    vt_stats = (vt or {}).get("last_analysis_stats") or {}
    harmless = int(vt_stats.get("harmless", 0) or 0)
    malicious = int(vt_stats.get("malicious", 0) or 0)
    suspicious = int(vt_stats.get("suspicious", 0) or 0)

    abuse_conf = int((abuse or {}).get("abuseConfidenceScore", 0) or 0)
    abuse_reports = int((abuse or {}).get("totalReports", 0) or 0)

    country = (ipi or {}).get("country") or ""
    city = (ipi or {}).get("city") or ""
    org = (ipi or {}).get("org") or ""
    asn = ""
    if org.startswith("AS"):
        asn = org.split(" ", 1)[0]
    elif (ipi or {}).get("asn"):
        asn = str((ipi or {}).get("asn"))

    verdict = "Unknown"
    if malicious >= 3 or abuse_conf >= 60:
        verdict = "Malicious"
    elif malicious >= 1 or suspicious >= 1 or abuse_conf >= 20:
        verdict = "Suspicious"
    elif ip != "—":
        verdict = "Low Risk"

    return {
        "abuseipdb": {
            "enabled": abuse is not None,
            "abuse_confidence_score": abuse_conf if abuse else None,
            "total_reports": abuse_reports if abuse else None,
            "verdict": verdict if abuse else "Not Configured",
        },
        "virustotal": {
            "enabled": vt is not None,
            "malicious_detections": malicious if vt else None,
            "suspicious_detections": suspicious if vt else None,
            "harmless_votes": harmless if vt else None,
        },
        "ipinfo": {
            "enabled": ipi is not None,
            "country": country or None,
            "country_flag": _country_flag(country) if country else "",
            "city": city or None,
            "isp": org or None,
            "asn": asn or None,
            "hostname": (ipi or {}).get("hostname") or None,
        },
    }


def _build_server_path(hops: List[Dict[str, Any]], ipi: Optional[dict]) -> Tuple[List[Dict[str, Any]], List[str], int]:
    server_path = []
    relay_findings: List[str] = []
    relay_score = 0

    prev_dt = None
    country = (ipi or {}).get("country") or ""
    flag = _country_flag(country) if country else ""
    org = (ipi or {}).get("org") or ""

    for hop in hops:
        hop_ips = hop.get("ips") or []
        primary_ip = ""
        for ip in hop_ips:
            if _is_public_ip(ip):
                primary_ip = ip
                break
        if not primary_ip and hop_ips:
            primary_ip = hop_ips[0]

        hostname = _safe_reverse_dns(primary_ip) if primary_ip else ""
        raw = hop.get("raw") or ""

        # private ip exposure
        for ip in hop_ips:
            try:
                obj = ipaddress.ip_address(ip)
                if obj.is_private:
                    relay_score += 8
                    relay_findings.append(f"Private IP exposed in Received chain ({ip})")
                    break
            except Exception:
                continue

        delay_text = "—"
        cur_dt = hop.get("dt")
        if prev_dt and cur_dt:
            try:
                dt1 = parsedate_to_datetime(prev_dt) if isinstance(prev_dt, str) and "," in prev_dt else None
            except Exception:
                dt1 = None
        try:
            dt_cur = parsedate_to_datetime(cur_dt) if isinstance(cur_dt, str) and "," in cur_dt else None
        except Exception:
            dt_cur = None

        if prev_dt and isinstance(prev_dt, str) and cur_dt:
            try:
                from datetime import datetime as _dt
                p1 = _dt.fromisoformat(prev_dt)
                p2 = _dt.fromisoformat(cur_dt)
                sec = int((p2 - p1).total_seconds())
                delay_text = f"{sec}s"
                if sec < 0:
                    relay_score += 12
                    relay_findings.append("Received chain timestamps appear out of order")
            except Exception:
                delay_text = "—"

        server_path.append({
            "hop": hop.get("hop"),
            "ip": primary_ip or "—",
            "hostname": hostname or hop.get("helo") or "—",
            "country": country if primary_ip else "",
            "country_flag": flag if primary_ip else "",
            "isp": org if primary_ip else "",
            "delay": delay_text,
            "timestamp": hop.get("dt"),
            "suspicious": False,
            "raw": raw,
        })

        prev_dt = hop.get("dt")

    # mark suspicious hops
    for item in server_path:
        ip = item.get("ip") or ""
        if ip and ip != "—" and not _is_public_ip(ip):
            item["suspicious"] = True
        if item.get("hostname") == "—":
            item["suspicious"] = True

    return server_path, relay_findings, min(100, relay_score)


def calculate_header_risk(auth_score: int, relay_score: int, reputation_score: int, anomaly_score: int) -> int:
    score = (
        (0.35 * max(0, min(100, auth_score))) +
        (0.30 * max(0, min(100, reputation_score))) +
        (0.20 * max(0, min(100, relay_score))) +
        (0.15 * max(0, min(100, anomaly_score)))
    )
    return max(0, min(100, int(round(score))))


def _threat_level(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "SAFE"


def _provider_status() -> Dict[str, str]:
    return {
        "abuseipdb": "Connected" if os.getenv("ABUSEIPDB_API_KEY") else "Not Configured",
        "virustotal": "Connected" if os.getenv("VT_API_KEY") else "Not Configured",
        "ipinfo": "Connected" if os.getenv("IPINFO_TOKEN") else "Not Configured",
    }


def analyze_headers(
    raw_headers: str,
    *,
    use_online: bool = False,
    vt_api_key: str = "",
    abuseipdb_api_key: str = "",
    ipinfo_api_key: str = "",
) -> dict:
    if not (raw_headers or "").strip():
        return {"error": "Paste raw email headers first."}

    msg = Parser(policy=policy.default).parsestr(raw_headers)

    from_name, from_addr = parseaddr(msg.get("From", "") or "")
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    subject = msg.get("Subject", "") or ""
    message_id = msg.get("Message-ID", "") or ""
    date = msg.get("Date", "") or ""

    hops = _parse_received_chain(msg)
    origin_ip = _guess_true_origin_ip(hops)

    auth, auth_details, auth_meta = _extract_auth(msg)

    from_domain = _extract_domain(from_addr)
    return_path_domain = _extract_domain(return_path)
    reply_to_domain = _extract_domain(reply_to)
    dkim_domain = (auth_meta.get("dkim_domain") or "").lower()
    msgid_domain = _extract_msgid_domain(message_id)

    findings: List[Finding] = []
    auth_score = 0
    anomaly_score = 0

    # auth scoring
    if auth.get("spf") == "fail":
        auth_score += 35
        findings.append(Finding("fail", "SPF Failed", "Sender failed SPF validation."))
    elif auth.get("spf") == "softfail":
        auth_score += 22
        findings.append(Finding("warn", "SPF Softfail", "SPF softfail detected."))

    if auth.get("dkim") == "fail":
        auth_score += 30
        findings.append(Finding("fail", "DKIM Failed", "DKIM signature validation failed."))

    if auth.get("dmarc") == "fail":
        auth_score += 35
        findings.append(Finding("fail", "DMARC Failed", "DMARC alignment/validation failed."))

    # anomaly scoring
    if from_domain and return_path_domain and from_domain != return_path_domain:
        anomaly_score += 35
        findings.append(Finding("fail", "From/Return-Path Mismatch", "Header sender domain does not align with Return-Path."))

    if from_domain and reply_to_domain and reply_to_domain != from_domain:
        anomaly_score += 18
        findings.append(Finding("warn", "Reply-To Mismatch", "Reply-To domain differs from visible From domain."))

    if dkim_domain and from_domain and dkim_domain != from_domain:
        anomaly_score += 22
        findings.append(Finding("warn", "DKIM Domain Mismatch", "DKIM signing domain differs from From domain."))

    if msgid_domain and from_domain and msgid_domain != from_domain:
        anomaly_score += 12
        findings.append(Finding("warn", "Message-ID Domain Mismatch", "Message-ID domain differs from From domain."))

    if origin_ip == "—":
        anomaly_score += 15
        findings.append(Finding("warn", "Origin IP Missing", "No sending IP could be confidently extracted from Received headers."))
    elif not _is_public_ip(origin_ip):
        anomaly_score += 20
        findings.append(Finding("warn", "Non-Public Origin IP", "Earliest extracted IP is not publicly routable."))

    # provider keys: server-side env first, explicit args override if provided
    vt_key = (vt_api_key or os.getenv("VT_API_KEY") or "").strip()
    abuse_key = (abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY") or "").strip()
    ipinfo_key = (ipinfo_api_key or os.getenv("IPINFO_TOKEN") or "").strip()

    vt = None
    ab = None
    ipi = None
    degraded = False

    if use_online and origin_ip != "—" and _is_public_ip(origin_ip):
        vt = _virustotal_ip(origin_ip, vt_key)
        ab = _abuseipdb(origin_ip, abuse_key)
        ipi = _ipinfo(origin_ip, ipinfo_key)
        degraded = not all([vt_key or False, abuse_key or False, ipinfo_key or False])

    reputation = _normalize_reputation(origin_ip, ab, vt, ipi)

    reputation_score = 0
    if reputation["abuseipdb"]["abuse_confidence_score"] is not None:
        reputation_score += min(40, int(reputation["abuseipdb"]["abuse_confidence_score"] * 0.45))
    if reputation["abuseipdb"]["total_reports"] is not None and reputation["abuseipdb"]["total_reports"] >= 10:
        reputation_score += 10
    if reputation["virustotal"]["malicious_detections"] is not None:
        reputation_score += min(35, int(reputation["virustotal"]["malicious_detections"] * 4))
    if reputation["virustotal"]["suspicious_detections"] is not None:
        reputation_score += min(12, int(reputation["virustotal"]["suspicious_detections"] * 3))

    server_path, relay_findings, relay_score = _build_server_path(hops, ipi)
    for item in relay_findings[:3]:
        findings.append(Finding("warn", "Relay Anomaly", item))

    overall_score = calculate_header_risk(auth_score, relay_score, reputation_score, anomaly_score)
    threat_level = _threat_level(overall_score)

    # mark suspicious hops after scoring
    for hop in server_path:
        if hop["ip"] == origin_ip and threat_level == "HIGH":
            hop["suspicious"] = True

    # compact forensic bullets max 6
    bullets = []
    seen = set()
    for f in findings:
        line = f"{f.title}: {f.detail}"
        k = line.lower()
        if k in seen:
            continue
        seen.add(k)
        bullets.append(line)
        if len(bullets) >= 6:
            break

    if not bullets and threat_level == "SAFE":
        bullets.append("No major header anomalies detected.")

    header_result = {
        "sender_display_name": from_name or (from_addr.split("@")[0] if from_addr else "Unknown Sender"),
        "from_email": from_addr or "—",
        "return_path": return_path or "—",
        "reply_to": reply_to or "—",
        "subject": subject or "—",
        "message_id": message_id or "—",
        "date": date or "—",
        "true_origin_ip": origin_ip,
        "server_path": server_path,
        "auth_results": {
            "spf": auth.get("spf", "unknown"),
            "dkim": auth.get("dkim", "unknown"),
            "dmarc": auth.get("dmarc", "unknown"),
            "details": auth_details,
            "dkim_domain": dkim_domain or "",
            "from_domain": from_domain or "",
            "return_path_domain": return_path_domain or "",
        },
        "reputation": reputation,
        "forensic_findings": bullets,
        "overall_score": overall_score,
        "threat_level": threat_level,
        "provider_status": _provider_status(),
        "degraded": degraded,
    }

    # backward-compatible extras for existing route/UI if needed
    return {
        "from": {"name": from_name, "addr": from_addr},
        "return_path": return_path or "—",
        "reply_to": reply_to or "—",
        "subject": subject or "—",
        "message_id": message_id or "—",
        "date": date or "—",
        "origin_ip": origin_ip,
        "auth": auth,
        "auth_details": auth_details,
        "received_path": server_path,
        "findings": [asdict(f) for f in findings],
        "recommendation": "Investigate immediately." if threat_level == "HIGH" else ("Verify sender and routing." if threat_level == "MEDIUM" else "No urgent action required."),
        "ip_risk": {
            "score": overall_score,
            "classification": threat_level,
        },
        "header_result": header_result,
        "provider_status": _provider_status(),
        "degraded": degraded,
    }