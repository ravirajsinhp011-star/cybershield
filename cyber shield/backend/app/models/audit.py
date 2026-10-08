from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from ..database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=True)
    status = Column(String(20), default="SUCCESS")
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
