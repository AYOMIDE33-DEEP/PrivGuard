import os
import re
import shutil
import hashlib
from pathlib import Path
from typing import Optional, List, Tuple, Any, Dict

try:
    import requests
except Exception:
    requests = None

DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx|xlsx|jpg|png|txt|rtf)\.(exe|scr|js|vbs|bat|cmd|ps1|msi|dll)$", re.IGNORECASE)

HIGH_RISK_EXT = {".exe",".scr",".js",".vbs",".bat",".cmd",".ps1",".msi",".dll",".jar"}
MED_RISK_EXT  = {".docm",".xlsm",".pptm",".lnk",".iso",".img",".hta",".wsf"}

SUSPICIOUS_STRINGS = [
    b"powershell", b"cmd.exe", b"wscript", b"cscript", b"rundll32", b"regsvr32",
    b"mshta", b"curl", b"wget", b"invoke-webrequest", b"base64", b"fromcharcode",
    b"eval(", b"createobject", b"shell.application",
]

def sha256_of_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def shannon_entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    freq = [0] * 256
    for b in sample:
        freq[b] += 1
    import math
    n = len(sample)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def risk_from_ext(path: str) -> Tuple[int, str]:
    ext = Path(path).suffix.lower()
    if ext in HIGH_RISK_EXT:
        return 18, f"High-risk executable extension ({ext})"
    if ext in MED_RISK_EXT:
        return 10, f"Medium-risk extension ({ext})"
    return 0, "Common/low-risk extension"

def compute_verdict(score: int) -> str:
    if score >= 75: return "INFECTED"
    if score >= 35: return "SUSPICIOUS"
    return "SAFE"

def scan_local(path: str) -> Tuple[int, List[str], str]:
    reasons: List[str] = []
    score = 0
    p = Path(path)
    name = p.name
    ext = p.suffix.lower()

    if DOUBLE_EXT_RE.search(name):
        score += 35
        reasons.append("Double extension (social-engineering tactic)")

    s, why = risk_from_ext(path)
    score += s
    if s:
        reasons.append(why)

    size = p.stat().st_size if p.exists() else 0
    if ext in HIGH_RISK_EXT and size < 60_000:
        score += 12
        reasons.append("Unusually small executable (dropper-like)")
    if ext in {".js",".vbs",".ps1",".bat",".cmd"} and size > 400_000:
        score += 10
        reasons.append("Very large script (obfuscation likely)")

    try:
        with open(path, "rb") as f:
            head = f.read(64 * 1024)
        ent = shannon_entropy(head)
        if ent >= 7.2 and ext in HIGH_RISK_EXT:
            score += 12
            reasons.append("High entropy binary (packed/obfuscated)")

        lower = head.lower()
        hits = sum(1 for s in SUSPICIOUS_STRINGS if s in lower)
        if hits:
            score += min(25, 6 * hits)
            reasons.append(f"Suspicious command strings (hits={hits})")
    except Exception:
        pass

    return min(100, score), reasons, ""

def vt_lookup(hash_hex: str, api_key: str, timeout: float = 15.0) -> Optional[dict]:
    if not requests or not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{hash_hex}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=timeout)
    if r.status_code == 200:
        data = r.json()
        attrs = ((data.get("data") or {}).get("attributes") or {})
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "reputation": attrs.get("reputation"),
        }
    if r.status_code == 404:
        return {"not_found": True}
    return {"error": f"VT status {r.status_code}"}

def maybe_quarantine(path: str, quarantine_dir: str) -> Optional[str]:
    if not quarantine_dir:
        return None
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        dst = os.path.join(quarantine_dir, os.path.basename(path))
        # avoid overwrite
        base, ext = os.path.splitext(dst)
        i = 1
        while os.path.exists(dst):
            dst = f"{base}_{i}{ext}"
            i += 1
        shutil.copy2(path, dst)
        return dst
    except Exception:
        return None

def scan_file_path(
    path: str,
    *,
    use_vt: bool = False,
    vt_api_key: str = "",
    vt_mode: str = "lookup_only",
    quarantine_dir: str = ""
) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {"error": "File not found. Provide a valid file path."}

    h = sha256_of_file(path)
    score, reasons, malware_name = scan_local(path)
    verdict = compute_verdict(score)

    vt = None
    if use_vt and vt_api_key:
        vt = vt_lookup(h, vt_api_key.strip())

    quarantined_to = None
    if verdict in ("INFECTED", "SUSPICIOUS") and quarantine_dir:
        quarantined_to = maybe_quarantine(path, quarantine_dir)

    return {
        "path": path,
        "sha256": h,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "vt": vt,
        "quarantined_to": quarantined_to,
    }