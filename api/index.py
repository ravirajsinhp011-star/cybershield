import os
import sys
from pathlib import Path

# Add root folder to sys.path for backend imports
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Set VERCEL environment flag if not present
os.environ.setdefault("VERCEL", "1")

# Import the FastAPI application
from backend.app.main import app

# Vercel Serverless Function entrypoint
# The ASGI application 'app' is automatically detected and served by Vercel
