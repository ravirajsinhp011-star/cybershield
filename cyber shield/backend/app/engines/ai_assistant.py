import os
import json
import httpx
from typing import Dict, Any, Optional, List
from ..config import GEMINI_API_KEY

SYSTEM_INSTRUCTION = """You are AI CyberShield Assistant, an elite yet friendly cybersecurity safety expert built for the AI CyberShield platform.
Your mission is to help both technical and non-technical users understand digital threats (phishing, malicious URLs, scam SMS, fake QR codes).
Guidelines:
1. Explain threats in clear, concise, actionable language.
2. If scan context is provided (e.g., risk score, detected findings, URL, message), explain why those specific signals are risky and what the user should do right now.
3. Be reassuring, educational, and precise. Never recommend clicking untrusted links or sharing credentials.
4. Keep explanations under 200 words unless in-depth technical analysis is requested.
"""

def generate_offline_expert_response(user_message: str, scan_context: Optional[Dict[str, Any]] = None) -> str:
    """Provides high-quality heuristic cybersecurity responses when Gemini API key is offline or unavailable."""
    msg = user_message.lower().strip()

    # If asking about scan context
    if scan_context:
        score = scan_context.get("risk_score", 0)
        level = scan_context.get("risk_level", "UNKNOWN")
        target = scan_context.get("target", "Input")
        findings = scan_context.get("findings", [])

        indicators_text = ", ".join([f['indicator'] for f in findings[:3]]) if findings else "None"

        if level in ["HIGH", "CRITICAL"]:
            return (
                f"🚨 **Threat Breakdown for `{target}`**:\n\n"
                f"- **Assessed Risk Level:** {level} (Threat Score: {score}/100)\n"
                f"- **Key Warning Signals:** {indicators_text}.\n\n"
                f"**Why this is dangerous:**\n"
                f"This target demonstrates patterns common in social engineering and credential theft campaigns. "
                f"Attackers use deceptive domains, urgency triggers, or disguised redirects to trick victims into sharing private credentials or OTPs.\n\n"
                f"**Immediate Safety Action:**\n"
                f"1. Do **NOT** click or open this link.\n"
                f"2. Never provide bank account details, OTPs, or passwords.\n"
                f"3. Delete the message or report the URL to your organization's IT security team."
            )
        else:
            return (
                f"✅ **Safety Assessment for `{target}`**:\n\n"
                f"- **Assessed Risk Level:** {level} (Threat Score: {score}/100)\n"
                f"- **Signals:** No critical phishing patterns were detected.\n\n"
                f"**Safety Recommendation:**\n"
                f"Even with low risk scores, always practice basic cyber hygiene: check that the domain spelling is genuine in your address bar and never submit passwords over unverified channels."
            )

    # General Cyber Q&A queries
    if "phishing" in msg:
        return (
            "🎣 **What is Phishing?**\n\n"
            "Phishing is a social engineering attack where cybercriminals impersonate reputable organizations "
            "(like banks, Netflix, or tech support) via email, SMS, or fake websites to deceive individuals into "
            "revealing confidential information like login passwords, credit card numbers, or OTPs.\n\n"
            "**Key indicators:** False urgency, mismatched sender domains, generic greetings, and suspicious download links."
        )
    elif "quishing" in msg or "qr" in msg:
        return (
            "📷 **What is Quishing (QR Phishing)?**\n\n"
            "Quishing combines 'QR Code' and 'Phishing'. Scammers generate QR codes that encode malicious URLs "
            "or payment traps and paste them on parking meters, restaurant menus, or phishing emails.\n\n"
            "**How to stay safe:**\n"
            "- Always use CyberShield's QR Scanner to preview and evaluate the destination URL before browsing.\n"
            "- Never authorize UPI or banking pin prompts when scanning an unknown QR code."
        )
    elif "2fa" in msg or "mfa" in msg or "two factor" in msg:
        return (
            "🔐 **Two-Factor Authentication (2FA):**\n\n"
            "2FA adds a secondary layer of protection beyond your password. Even if an attacker steals your password "
            "through phishing, they cannot breach your account without the second factor (such as an Authenticator app code or security key).\n\n"
            "**Pro Tip:** Prefer App-based authenticators (like Google Authenticator) over SMS OTPs to resist SIM-swapping attacks."
        )
    elif "safe" in msg or "protect" in msg or "tips" in msg:
        return (
            "🛡️ **Top Cyber Safety Best Practices:**\n\n"
            "1. **Verify Before Clicking:** Inspect the domain name carefully for typosquatting (e.g., `paypa1.com` vs `paypal.com`).\n"
            "2. **Resist Urgency:** Scammers rely on panic ('Account blocked in 1 hour'). Take a deep breath and contact the official helpline.\n"
            "3. **Never Share OTPs:** Bank employees and support agents will never ask for your OTP or UPI PIN.\n"
            "4. **Enable 2FA:** Turn on multi-factor authentication on all email, banking, and social accounts."
        )
    else:
        return (
            "🛡️ **AI CyberShield Safety Assistant:**\n\n"
            "I'm here to safeguard your digital presence! You can ask me:\n"
            "- *'Why was my scanned link flagged as high risk?'*\n"
            "- *'What is Quishing and how does it work?'*\n"
            "- *'How can I identify a fake bank SMS?'*\n"
            "- *'What should I do if I accidentally clicked a phishing link?'*\n\n"
            "Scan any URL, message, or QR code above and I will break down the risk evidence for you!"
        )

async def ask_cyber_assistant(
    user_message: str,
    scan_context: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, str]]] = None
) -> Dict[str, str]:
    """Generates an AI response using Google Gemini API or intelligent offline fallback."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip() or GEMINI_API_KEY

    # If Gemini API Key is provided, call Gemini
    if api_key:
        try:
            # Build prompt with scan context
            context_str = ""
            if scan_context:
                context_str = f"\n[CURRENT SCAN CONTEXT]\nTarget: {scan_context.get('target')}\nRisk Score: {scan_context.get('risk_score')}/100\nRisk Level: {scan_context.get('risk_level')}\nFindings: {json.dumps(scan_context.get('findings', []))}\nRecommendations: {json.dumps(scan_context.get('recommendations', []))}\n"

            prompt = f"{SYSTEM_INSTRUCTION}\n{context_str}\nUser Question: {user_message}"

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
            payload = {
                "contents": [
                    {
                        "parts": [{"text": prompt}]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.4,
                    "maxOutputTokens": 400
                }
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        reply_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if reply_text:
                            return {"reply": reply_text, "source": "gemini"}
        except Exception as e:
            # Fall back to heuristic engine if API call fails
            pass

    # Offline / Heuristic fallback
    fallback_reply = generate_offline_expert_response(user_message, scan_context)
    return {"reply": fallback_reply, "source": "expert_rules"}
