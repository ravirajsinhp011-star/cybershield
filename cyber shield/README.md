# AI CyberShield
### Enterprise Autonomous Threat Intelligence & Cyber Defense Platform

---

## 📌 Executive Summary
**AI CyberShield** is a next-generation cybersecurity intelligence and forensic analysis platform built to protect enterprise networks and digital citizens from sophisticated digital threats, including **Credential-Harvesting Phishing URLs**, **Social Engineering Fraud Messages**, and **Malicious QR Code Traps (Quishing)**.

### Core Architectural Lifecycle
$$\text{Input Ingestion} \longrightarrow \text{Multi-Signal Forensics} \longrightarrow \text{Risk Engine (0-100)} \longrightarrow \text{AI Explainer} \longrightarrow \text{Proactive Defense}$$

---

## 🛡️ Core Capabilities

1. **🌐 Deep URL Threat Analyzer:**
   - Multi-factor inspection engine combining Shannon Entropy analysis (algorithmic randomness / DGA detection), raw IP host identification, SSL/TLS protocol verification, brand typosquatting, high-risk TLD filtering, and sensitive path keyword matching.
2. **💬 NLP Phishing & Social Engineering Classifier:**
   - Machine learning classifier (TF-IDF + Scikit-Learn) integrated with heuristic rules detecting psychological coercion, artificial urgency, financial lures, and sensitive credential solicitation.
3. **📷 Quishing Security Scanner:**
   - Real-time client-side optical scanner and server-side OpenCV decoder. Decodes embedded targets and routes payloads through deep inspection pipelines.
4. **🤖 AI Cyber Intelligence Consultant:**
   - Powered by **Google Gemini API** with an embedded high-speed heuristic safety engine for contextual risk breakdowns and actionable defensive guidance.
5. **📊 Security Operations Center (SOC) Telemetry:**
   - Real-time threat distribution metrics, attack vector telemetry, and machine learning model validation (Precision, Recall, F1-Score, Confusion Matrix).
6. **👥 Enterprise Identity & Access Management (RBAC):**
   - Argon2id password hashing, signed JSON Web Tokens (JWT), role-separated user vaults, and SOC administrative controls.
7. **⚡ Dynamic Policy Enforcement Engine:**
   - Custom blacklist and whitelist policy enforcement with immediate threat blocking.

---

## 💻 Deployment & Execution

### 1. Requirements
- Python 3.10+ (Verified on Python 3.14)

### 2. Dependency Installation
```bash
pip install -r requirements.txt
```

### 3. Environment Configuration (Optional)
Edit `.env` to configure application parameters or connect a Google Gemini API key:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

### 4. Launch Application
```bash
python run.py
```
Or directly with Uvicorn:
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Navigate to:
- **Web Application Portal:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **API Swagger Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

**Default Administrator Account:**
- **Username:** `admin`
- **Password:** `admin123`

---

## 📁 Architecture Directory Structure

```text
cyber-shield/
├── backend/
│   ├── app/
│   │   ├── config.py             # Configuration & environment loader
│   │   ├── database.py           # Database engine & session manager
│   │   ├── main.py               # Application entrypoint & middleware
│   │   ├── core/
│   │   │   └── security.py       # Argon2id hashing & JWT authentication
│   │   ├── engines/
│   │   │   ├── url_engine.py     # URL threat heuristics & policy checks
│   │   │   ├── nlp_engine.py     # Phishing message classifier
│   │   │   ├── qr_engine.py      # QR decoder & pipeline router
│   │   │   ├── risk_scorer.py    # Normalized 0-100 risk calculation
│   │   │   └── ai_assistant.py   # AI intelligence & fallback explainer
│   │   ├── ml_models/
│   │   │   ├── train_models.py   # ML pipeline trainer
│   │   │   ├── phishing_classifier.joblib
│   │   │   └── model_metrics.json
│   │   ├── models/               # SQLAlchemy ORM models
│   │   ├── routers/              # API routers (auth, scan, assistant, analytics, user, admin)
│   │   └── schemas/              # Pydantic validation schemas
├── frontend/
│   ├── static/
│   │   ├── css/style.css         # Cyber defense aesthetic styling
│   │   └── js/app.js             # Client SPA controller & role manager
│   └── templates/
│       └── index.html            # Main web portal interface
├── run.py                        # Unified server launcher
├── requirements.txt
├── .env
└── README.md
```
