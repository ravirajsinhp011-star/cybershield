#!/usr/bin/env python3
"""
AI CYBERSHIELD — TEAM ALPHA
AI-Powered Digital Threat Detection & Cyber Safety Platform
Startup Launcher
"""
import sys
import uvicorn
from backend.app.config import HOST, PORT

def main():
    print("=" * 65)
    print("      AI CYBERSHIELD  |  TEAM ALPHA")
    print("      AI-Powered Digital Threat Detection & Cyber Safety")
    print("=" * 65)
    print(f"[*] Starting server at: http://{HOST}:{PORT}")
    print(f"[*] API Swagger Docs:   http://{HOST}:{PORT}/docs")
    print("[*] Press Ctrl+C to stop the server.")
    print("=" * 65)

    uvicorn.run(
        "backend.app.main:app",
        host=HOST,
        port=PORT,
        reload=True
    )

if __name__ == "__main__":
    main()
