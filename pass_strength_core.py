import re
import math

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein",
    "admin", "welcome", "iloveyou", "000000", "password1"
}

def estimate_entropy_bits(pw: str) -> float:
    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw): pool += 10
    if re.search(r"[^\w\s]", pw): pool += 33
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)

def password_report(pw: str, *, min_len: int = 12) -> dict:
    issues = []
    pwl = pw.lower().strip()

    if not pw:
        return {"score": 0, "entropy": 0.0, "label": "—", "issues": ["Type a password to test."]}

    if len(pw) < min_len:
        issues.append(f"Too short (min {min_len} characters).")

    if pwl in COMMON_PASSWORDS:
        issues.append("Very common password (blacklisted).")

    if not re.search(r"[a-z]", pw): issues.append("Add lowercase letters (a-z).")
    if not re.search(r"[A-Z]", pw): issues.append("Add uppercase letters (A-Z).")
    if not re.search(r"\d", pw): issues.append("Add digits (0-9).")
    if not re.search(r"[^\w\s]", pw): issues.append("Add symbols (e.g., !@#$%).")

    if re.search(r"(.)\1\1", pw):
        issues.append("Avoid repeated characters (e.g., 'aaa').")
    if re.search(r"(?:012|123|234|345|456|567|678|789)", pw):
        issues.append("Avoid obvious number sequences (e.g., 123).")
    if re.search(r"(password|admin|welcome|qwerty|letmein)", pwl):
        issues.append("Avoid common words/patterns (e.g., 'password').")

    entropy = estimate_entropy_bits(pw)

    score = 0
    score += min(40, max(0, (len(pw) - 8) * 4))
    score += min(30, entropy / 3)
    score += 10 if re.search(r"[a-z]", pw) else 0
    score += 10 if re.search(r"[A-Z]", pw) else 0
    score += 10 if re.search(r"\d", pw) else 0
    score += 10 if re.search(r"[^\w\s]", pw) else 0

    if issues:
        score -= 8 * min(6, len(issues))

    score = int(max(0, min(100, score)))

    if score >= 85:
        label = "Strong"
    elif score >= 70:
        label = "Good"
    elif score >= 45:
        label = "Weak"
    else:
        label = "Very weak"

    return {"score": score, "entropy": round(entropy, 1), "label": label, "issues": issues}