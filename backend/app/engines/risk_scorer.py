def calculate_risk_level(score: float):
    """
    Normalizes a numerical threat score into standard CyberShield risk tiers:
    0 - 25: LOW (Green)
    26 - 50: MEDIUM (Amber/Yellow)
    51 - 75: HIGH (Orange)
    76 - 100: CRITICAL (Red)
    """
    bounded_score = max(0.0, min(100.0, round(score, 1)))

    if bounded_score <= 25.0:
        return {
            "score": bounded_score,
            "level": "LOW",
            "badge_color": "#10b981",  # Emerald Green
            "badge_class": "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
            "summary": "Low risk signals detected. Target appears relatively safe, but standard browsing hygiene applies."
        }
    elif bounded_score <= 50.0:
        return {
            "score": bounded_score,
            "level": "MEDIUM",
            "badge_color": "#f59e0b",  # Amber
            "badge_class": "bg-amber-500/10 text-amber-400 border-amber-500/30",
            "summary": "Moderate risk indicators detected. Exercise caution before entering credentials or executing downloads."
        }
    elif bounded_score <= 75.0:
        return {
            "score": bounded_score,
            "level": "HIGH",
            "badge_color": "#f97316",  # Orange
            "badge_class": "bg-orange-500/10 text-orange-400 border-orange-500/30",
            "summary": "High risk detected. Strong phishing or deceptive patterns found. Do not enter credentials."
        }
    else:
        return {
            "score": bounded_score,
            "level": "CRITICAL",
            "badge_color": "#ef4444",  # Crimson Red
            "badge_class": "bg-rose-500/10 text-rose-400 border-rose-500/30",
            "summary": "CRITICAL THREAT: Severe malicious indicators confirmed. High probability of credential theft or scam."
        }
