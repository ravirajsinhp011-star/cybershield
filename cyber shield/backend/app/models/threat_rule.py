from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from ..database import Base

class ThreatRule(Base):
    __tablename__ = "threat_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_type = Column(String(20), nullable=False)  # "blacklist" or "whitelist"
    pattern = Column(String(255), nullable=False, unique=True, index=True)  # Domain or keyword
    reason = Column(String(255), nullable=True)
    created_by = Column(String(50), default="admin")
    created_at = Column(DateTime, default=datetime.utcnow)
