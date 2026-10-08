from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from ..database import Base

class UserBadge(Base):
    __tablename__ = "user_badges"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    badge_name = Column(String(100), nullable=False)
    badge_icon = Column(String(50), default="fa-shield-halved")
    description = Column(String(255), nullable=True)
    earned_at = Column(DateTime, default=datetime.utcnow)
