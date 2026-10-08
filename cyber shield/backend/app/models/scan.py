from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
from ..database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    scan_type = Column(String(20), index=True, nullable=False)  # "url", "message", "qr"
    input_target = Column(Text, nullable=False)                 # Scanned URL or message text snippet
    risk_score = Column(Float, nullable=False)                  # 0 to 100
    risk_level = Column(String(20), nullable=False)             # LOW, MEDIUM, HIGH, CRITICAL
    findings_json = Column(Text, nullable=True)                 # JSON array of detected signals
    recommendation = Column(Text, nullable=True)                # Safety advice
    source_ip = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
