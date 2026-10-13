import re
import joblib
from pathlib import Path
from typing import Dict, Any, List
from .risk_scorer import calculate_risk_level

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml_models" / "phishing_classifier.joblib"

# Pre-load ML model if available
ml_pipeline = None
if MODEL_PATH.exists():
    try:
        ml_pipeline = joblib.load(MODEL_PATH)
    except Exception:
        ml_pipeline = None

# Indicators
URGENCY_WORDS = [
    "urgent", "immediately", "within 24 hours", "account blocked", "suspended",
    "deactivated", "final notice", "action required", "disconnected tonight",
    "power disconnected", "card blocked", "legal action", "penalty"
]

FINANCIAL_LURES = [
    "won", "lottery", "cash prize", "reward points", "claim now", "free iphone",
    "earn rs", "daily income", "part time job", "refund approved", "airdrop",
    "giveaway", "bonus", "guaranteed profit"
]

CREDENTIAL_HARVESTING = [
    "verify otp", "send pin", "share otp", "password", "cvv", "16 digit card",
    "kyc update", "video kyc", "pan card", "aadhaar", "seed phrase", "secret phrase"
]

AUTHORITY_IMPERSONATION = [
    "income tax department", "sbi", "hdfc", "icici", "axis bank", "paytm",
    "electricity officer", "chase", "fedex", "netflix", "meta support", "amazon security"
]

URL_REGEX = re.compile(r"https?://[^\s]+")

def analyze_message(message_text: str) -> Dict[str, Any]:
    """Analyzes text message (SMS, Email, Chat) for phishing patterns and social engineering tactics."""
    text_lower = message_text.lower().strip()
    findings: List[Dict[str, str]] = []
    recommendations: List[str] = []
    risk_points = 0.0

    # 1. Check ML Model probability
    ml_confidence = 0.0
    if ml_pipeline is not None:
        try:
            proba = ml_pipeline.predict_proba([message_text])[0]
            # Class 1 is phishing
            ml_confidence = float(proba[1])
            if ml_confidence >= 0.6:
                risk_points += (ml_confidence * 45.0)
                findings.append({
                    "indicator": f"ML Phishing Classifier (Confidence: {int(ml_confidence*100)}%)",
                    "severity": "DANGER" if ml_confidence >= 0.8 else "WARNING",
                    "description": "Trained NLP model classified the linguistic structure and vocabulary as highly characteristic of phishing messages."
                })
        except Exception:
            pass

    # 2. Check Urgency / Intimidation tactics
    matched_urgency = [w for w in URGENCY_WORDS if w in text_lower]
    if matched_urgency:
        risk_points += min(30.0, len(matched_urgency) * 15.0)
        findings.append({
            "indicator": "High Urgency / Pressure Tactics Detected",
            "severity": "DANGER",
            "description": f"Detected urgency cues ({', '.join(matched_urgency)}). Scammers induce panic to prevent victims from verifying claims."
        })
        recommendations.append("Never rush into taking action under pressure. Legitimate banks and government agencies give reasonable notice.")

    # 3. Check Credential / OTP Harvesting
    matched_creds = [w for w in CREDENTIAL_HARVESTING if w in text_lower]
    if matched_creds:
        risk_points += min(35.0, len(matched_creds) * 20.0)
        findings.append({
            "indicator": "Sensitive Credential / OTP Solicitation",
            "severity": "DANGER",
            "description": f"Message requests sensitive data ({', '.join(matched_creds)}). Organizations never ask for passwords, PINs, or OTPs over text."
        })
        recommendations.append("DO NOT share OTPs, PINs, or password details. No genuine bank official will ask for them.")

    # 4. Check Financial Lures / Fake Prizes
    matched_lures = [w for w in FINANCIAL_LURES if w in text_lower]
    if matched_lures:
        risk_points += min(25.0, len(matched_lures) * 12.0)
        findings.append({
            "indicator": "Unsolicited Financial Lure / Prize Scheme",
            "severity": "WARNING",
            "description": f"Contains prize/money incentives ({', '.join(matched_lures)}). Standard lure for advance-fee scams."
        })
        recommendations.append("Be skeptical of unsolicited winnings or easy-money schemes. If it sounds too good to be true, it is a scam.")

    # 5. Check Authority Impersonation
    matched_auth = [w for w in AUTHORITY_IMPERSONATION if w in text_lower]
    if matched_auth:
        risk_points += 15.0
        findings.append({
            "indicator": "Known Brand / Organization Impersonation",
            "severity": "WARNING",
            "description": f"Claims to represent prominent organization: {', '.join(matched_auth)}. Verify via their official app or website."
        })

    # 6. Check Embedded Links
    found_urls = URL_REGEX.findall(message_text)
    if found_urls:
        risk_points += 20.0
        findings.append({
            "indicator": f"Embedded Hyperlink ({len(found_urls)} link(s) found)",
            "severity": "WARNING",
            "description": f"Message urges clicking external link(s): {', '.join(found_urls[:2])}. Avoid tapping links directly inside unknown messages."
        })
        recommendations.append("Do not tap links in unsolicited SMS or chat messages. Open the official website directly.")

    # Default safe recommendation
    if not recommendations:
        recommendations.append("Always verify sender authenticity before acting on unfamiliar communications.")

    tier = calculate_risk_level(risk_points)

    technical_details = {
        "ml_phishing_probability": round(ml_confidence, 3),
        "embedded_urls": found_urls,
        "matched_urgency_triggers": matched_urgency,
        "matched_credential_triggers": matched_creds,
        "matched_financial_triggers": matched_lures,
        "raw_points": risk_points
    }

    return {
        "scan_type": "message",
        "target": message_text[:120] + ("..." if len(message_text) > 120 else ""),
        "risk_score": tier["score"],
        "risk_level": tier["level"],
        "badge_color": tier["badge_color"],
        "summary": tier["summary"],
        "findings": findings,
        "recommendations": recommendations,
        "technical_details": technical_details
    }
