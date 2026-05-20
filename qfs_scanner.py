# services/qfs_scanner.py
from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

# -----------------------------
# Signatures (content-based)
# -----------------------------
EICAR_ASCII = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SIGNATURES: Dict[str, bytes] = {
    "EICAR-Test-String": EICAR_ASCII,
    # Add more patterns here as needed (keep bytes literals).
}

# -----------------------------
# Helpers: safe name checks
# -----------------------------
_DOUBLE_EXT_RE = re.compile(r"(?i)\.[a-z0-9]{1,6}\.[a-z0-9]{1,6}$")

SUSPICIOUS_EXTS = {
    "exe", "dll", "scr", "bat", "js", "vbs", "ps1", "cmd", "com", "jar"
}

EXT_TO_MAGIC_MIME = {
    # minimal "magic" set (no external deps)
    "pdf":  (b"%PDF-", "application/pdf"),
    "png":  (b"\x89PNG\r\n\x1a\n", "image/png"),
    "jpg":  (b"\xff\xd8\xff", "image/jpeg"),
    "jpeg": (b"\xff\xd8\xff", "image/jpeg"),
    "zip":  (b"PK\x03\x04", "application/zip"),
    "docx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xlsx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "rar":  (b"Rar!\x1a\x07\x00", "application/vnd.rar"),
}

@dataclass
class HeuristicFindings:
    double_extension: bool
    mime_mismatch: bool
    high_entropy: bool
    suspicious_extension: bool
    reasons: List[str]

# -----------------------------
# Core: hashing
# -----------------------------
def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# (Optional but useful in UI)
def md5_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# -----------------------------
# Core: entropy
# -----------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)

def entropy_of_file(path: str, max_bytes: int = 512 * 1024) -> float:
    # sample first N bytes to keep it fast
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    return shannon_entropy(data)

# -----------------------------
# Core: signature detection (content scan)
# -----------------------------
def detect_signatures(path: str, chunk_size: int = 1024 * 1024) -> List[str]:
    """
    Streaming scan:
    - reads in binary
    - searches patterns even if split across chunk boundary
    """
    patterns = list(SIGNATURES.items())
    if not patterns:
        return []

    # keep overlap equal to max pattern length - 1
    max_pat_len = max(len(pat) for _, pat in patterns)
    overlap = b""
    hits = set()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf = overlap + chunk
            for name, pat in patterns:
                if pat and pat in buf:
                    hits.add(name)
            overlap = buf[-(max_pat_len - 1):] if max_pat_len > 1 else b""

    return sorted(hits)

# -----------------------------
# Core: MIME guess (lightweight)
# -----------------------------
def guess_mime(path: str, filename: str) -> str:
    ext = (os.path.splitext(filename)[1] or "").lower().lstrip(".")
    # Try magic header match if possible
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except Exception:
        head = b""

    if ext in EXT_TO_MAGIC_MIME:
        magic, mime = EXT_TO_MAGIC_MIME[ext]
        if head.startswith(magic):
            return mime

    # fallback: python mimetypes
    mt, _ = mimetypes.guess_type(filename)
    return mt or "application/octet-stream"

def ext_from_name(filename: str) -> str:
    return (os.path.splitext(filename)[1] or "").lower().lstrip(".")

def has_double_extension(filename: str) -> bool:
    return bool(_DOUBLE_EXT_RE.search(filename or ""))

def mime_matches_extension(mime: str, ext: str) -> bool:
    """
    Simple, pragmatic mapping. MIME detection is inherently fuzzy without libmagic.
    """
    if not ext:
        return True

    ext = ext.lower()
    mime = (mime or "").lower()

    if ext in {"jpg", "jpeg"}:
        return "jpeg" in mime or "image/" in mime
    if ext == "png":
        return "png" in mime
    if ext == "pdf":
        return "pdf" in mime
    if ext in {"zip", "docx", "xlsx"}:
        return "zip" in mime or "officedocument" in mime or mime == "application/octet-stream"
    if ext == "rar":
        return "rar" in mime or mime == "application/octet-stream"
    if ext in {"exe", "dll", "scr", "bat", "js"}:
        # Many servers will label these as octet-stream; allow that
        return ("octet-stream" in mime) or ("text/" in mime and ext == "js")
    return True

# -----------------------------
# Core: heuristics
# -----------------------------
def run_heuristics(filename: str, mime: str, entropy: float) -> HeuristicFindings:
    ext = ext_from_name(filename)
    reasons: List[str] = []

    double_ext = has_double_extension(filename)
    if double_ext:
        reasons.append("Double extension detected (possible masquerading)")

    suspicious_ext = ext in SUSPICIOUS_EXTS
    if suspicious_ext:
        reasons.append(f"Suspicious extension (.{ext})")

    mismatch = not mime_matches_extension(mime, ext)
    if mismatch:
        reasons.append("MIME type does not match file extension")

    high_ent = entropy >= 7.8  # stronger than 7.5 for fewer false positives
    if high_ent:
        reasons.append(f"Very high entropy detected ({entropy})")

    return HeuristicFindings(
        double_extension=double_ext,
        mime_mismatch=mismatch,
        high_entropy=high_ent,
        suspicious_extension=suspicious_ext,
        reasons=reasons,
    )

# -----------------------------
# Core: risk scoring
# -----------------------------
def score_risk(signatures: List[str], heur: HeuristicFindings) -> Tuple[int, str]:
    """
    Returns (risk_score 0-100, verdict Safe/Suspicious/Malicious)
    Rules:
      - EICAR signature => 95+ and Malicious
      - Otherwise combine heuristics
    """
    # Signature dominance
    if "EICAR-Test-String" in signatures:
        return 95, "Malicious"

    score = 0

    # Heuristic weights (tuneable)
    if heur.double_extension:
        score += 30
    if heur.mime_mismatch:
        score += 25
    if heur.high_entropy:
        score += 25
    if heur.suspicious_extension:
        score += 15

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "Malicious"
    elif score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return score, verdict

# -----------------------------
# Orchestrator
# -----------------------------
def scan_quick_file(path: str, original_name: str) -> Dict:
    t0 = time.time()

    file_size = os.path.getsize(path)
    sha = sha256_file(path)
    md5 = md5_file(path)
    entropy = entropy_of_file(path)
    mime = guess_mime(path, original_name)
    ext = ext_from_name(original_name)

    sigs = detect_signatures(path)
    heur = run_heuristics(original_name, mime, entropy)
    risk_score, verdict = score_risk(sigs, heur)

    scan_ms = int((time.time() - t0) * 1000)

    # Required response fields + useful extras
    return {
        "sha256": sha,
        "file_name": original_name,
        "file_size": file_size,
        "detected_signatures": sigs,
        "risk_score": risk_score,
        "verdict": verdict,
        # extras (safe to include; UI can use them)
        "md5": md5,
        "mime": mime,
        "extension": ext,
        "entropy": entropy,
        "heuristics": heur.reasons,
        "scan_time_ms": scan_ms,
    }