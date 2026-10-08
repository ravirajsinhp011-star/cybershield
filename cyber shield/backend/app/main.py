from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import APP_NAME
from .database import engine, Base, SessionLocal
from .models.user import User
from .models.scan import ScanHistory
from .models.threat_rule import ThreatRule
from .core.security import hash_password
from .routers import auth, scan, assistant, analytics, user_portal, admin_portal

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=APP_NAME,
    description="AI-Powered Digital Threat Detection & Cyber Safety Platform with Role-Based Access Control",
    version="2.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Bootstrap default security configurations if empty
def seed_initial_data():
    db = SessionLocal()
    try:
        # 1. Administrator Account
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin_user = User(
                username="admin",
                email="security-admin@cybershield.ai",
                hashed_password=hash_password("admin123"),
                role="admin"
            )
            db.add(admin_user)
            db.commit()

        # 2. Default Enterprise Threat Rules
        if db.query(ThreatRule).count() == 0:
            sample_rules = [
                ThreatRule(rule_type="whitelist", pattern="internal-secure-portal.org", reason="Corporate Single Sign-On Gateway", created_by="admin"),
                ThreatRule(rule_type="blacklist", pattern="dark-scam-vault.xyz", reason="Known credential harvesting ring", created_by="admin"),
            ]
            db.add_all(sample_rules)
            db.commit()

        # 4. Seed initial sample scans for dashboard visualization
        if db.query(ScanHistory).count() == 0:
            sample_scans = [
                ScanHistory(scan_type="url", input_target="http://secure-login.paypal-update.xyz/verify", risk_score=95.0, risk_level="CRITICAL", findings_json="[]", recommendation="Do not visit or submit credentials."),
                ScanHistory(scan_type="message", input_target="URGENT: Your SBI account is blocked. Verify KYC at http://sbi-kyc.xyz", risk_score=92.0, risk_level="CRITICAL", findings_json="[]", recommendation="Never share OTPs or KYC credentials."),
                ScanHistory(scan_type="url", input_target="https://github.com/torvalds/linux", risk_score=5.0, risk_level="LOW", findings_json="[]", recommendation="Verified standard repository."),
                ScanHistory(scan_type="message", input_target="Hey, are we still meeting for lunch at 1 PM today?", risk_score=0.0, risk_level="LOW", findings_json="[]", recommendation="Standard benign conversational message."),
                ScanHistory(scan_type="url", input_target="http://tinyurl.com/fast-cash-bonus", risk_score=68.0, risk_level="HIGH", findings_json="[]", recommendation="Shortener hides untrusted destination."),
                ScanHistory(scan_type="qr", input_target="http://fake-electricity-bill-pay.click", risk_score=88.0, risk_level="CRITICAL", findings_json="[]", recommendation="Malicious Quishing payment lure."),
                ScanHistory(scan_type="url", input_target="https://en.wikipedia.org/wiki/Computer_security", risk_score=4.0, risk_level="LOW", findings_json="[]", recommendation="Trusted reference domain.")
            ]
            db.add_all(sample_scans)
            db.commit()
    finally:
        db.close()

seed_initial_data()

# Include API Routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(assistant.router)
app.include_router(analytics.router)
app.include_router(user_portal.router)
app.include_router(admin_portal.router)

# Static files and Frontend template paths
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
def serve_home():
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "AI CyberShield API is running. Visit /docs for Swagger specifications."}
