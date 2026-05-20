import os
from typing import Any, Dict


def _normalize(v: Any) -> str:
    return str(v or "").strip().upper()


def _simple_fallback(indicators: Dict[str, Any]) -> str:
    score = int(indicators.get("risk_score") or 0)
    concerns = []

    if _normalize(indicators.get("spf")) != "PASS":
        concerns.append("the sender could not be fully verified")
    if _normalize(indicators.get("dkim")) != "PASS":
        concerns.append("part of the message could not be confirmed as trusted")
    if _normalize(indicators.get("dmarc")) != "PASS":
        concerns.append("the sender identity checks were incomplete")
    if indicators.get("suspicious_urls"):
        concerns.append("the email contains a link that may be unsafe")
    if indicators.get("attachment_risk"):
        concerns.append("the email includes a file that should be treated carefully")
    if indicators.get("header_anomaly"):
        concerns.append("some sender details look unusual")

    if not concerns:
        return (
            "This email looks safe based on the main checks completed.\n"
            "No major warning signs were found.\n"
            "Still be careful with unexpected links or files."
        )

    first = concerns[:2]

    if score >= 60:
        return (
            "This email shows important warning signs.\n"
            f"The main concerns are that {', and '.join(first)}.\n"
            "Attackers often use this kind of pattern to trick people.\n"
            "Do not click links or open files until you confirm the sender."
        )

    if score >= 30:
        return (
            "This email shows some warning signs.\n"
            f"The main concerns are that {', and '.join(first)}.\n"
            "It may still be real, but caution is needed.\n"
            "Confirm the sender before clicking links or opening files."
        )

    return (
        "This email has a few minor concerns.\n"
        f"The main concern is that {first[0]}.\n"
        "It does not look highly dangerous, but you should still be careful."
    )


def analyze_email_ai(indicators: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return {
            "text": _simple_fallback(indicators),
            "source": "fallback",
            "model": "fallback",
        }

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        prompt = f"""
You explain email safety results to non-technical people.

Write 4 short lines maximum.
Use very simple English.
Do not use heavy technical terms.
Focus only on the biggest warning signs.
End with one clear safety action.

Facts:
SPF: {indicators.get('spf')}
DKIM: {indicators.get('dkim')}
DMARC: {indicators.get('dmarc')}
Suspicious URLs: {indicators.get('suspicious_urls')}
Attachment risk: {indicators.get('attachment_risk')}
Header anomaly: {indicators.get('header_anomaly')}
Risk score: {indicators.get('risk_score')}
"""
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": "You explain cybersecurity findings in simple everyday language."},
                {"role": "user", "content": prompt},
            ],
        )
        text = (response.choices[0].message.content or "").strip()
        if not text:
            raise ValueError("Empty AI response")

        lines = [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]
        cleaned = "\n".join(lines[:4])

        return {
            "text": cleaned or _simple_fallback(indicators),
            "source": "openai",
            "model": "gpt-4o-mini",
        }
    except Exception:
        return {
            "text": _simple_fallback(indicators),
            "source": "fallback",
            "model": "fallback",
        }