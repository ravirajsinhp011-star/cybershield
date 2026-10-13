from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to analyze for threat signals")

class MessageScanRequest(BaseModel):
    message: str = Field(..., description="SMS, email, or message body to analyze for phishing")

class FindingDetail(BaseModel):
    indicator: str
    severity: str  # "INFO", "WARNING", "DANGER"
    description: str

class ScanResultResponse(BaseModel):
    scan_type: str
    target: str
    risk_score: float  # 0 to 100
    risk_level: str    # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    badge_color: str   # Hex color e.g. "#10b981", "#ef4444"
    summary: str
    findings: List[FindingDetail]
    recommendations: List[str]
    technical_details: Dict[str, Any] = {}
