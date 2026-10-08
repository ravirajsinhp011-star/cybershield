import os
from pathlib import Path

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Read .env file manually if exists
env_file = BASE_DIR / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

APP_NAME = os.getenv("APP_NAME", "AI CyberShield")
APP_ENV = os.getenv("APP_ENV", "development")
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "127.0.0.1")

SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-secret-key-super-secure-change-in-prod-2026")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'cybershield.db'}")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
