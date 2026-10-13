from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from ..database import get_db
from ..models.user import User
from ..models.scan import ScanHistory
from ..models.user_badge import UserBadge
from ..core.security import get_current_user

router = APIRouter(prefix="/api/user", tags=["User Portal"])

class BadgeClaimRequest(BaseModel):
    badge_name: str
    quiz_score: int

@router.get("/history")
def get_user_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns persistent personal scan records for the authenticated user."""
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    return [
        {
            "id": s.id,
            "scan_type": s.scan_type,
            "input_target": s.input_target,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "recommendation": s.recommendation,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else ""
        }
        for s in scans
    ]

@router.delete("/history/{scan_id}")
def delete_user_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Allows a user to remove a record from their personal scan vault."""
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found in your vault")
    db.delete(scan)
    db.commit()
    return {"success": True, "message": "Scan record deleted from personal vault."}

@router.get("/stats")
def get_user_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Calculates personal threat exposure statistics."""
    total_scans = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).count()
    threats_avoided = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id, ScanHistory.risk_level.in_(["HIGH", "CRITICAL"]))
        .count()
    )
    clean_scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id, ScanHistory.risk_level == "LOW")
        .count()
    )
    avg_score_query = (
        db.query(func.avg(ScanHistory.risk_score))
        .filter(ScanHistory.user_id == current_user.id)
        .scalar()
    )
    avg_score = round(float(avg_score_query), 1) if avg_score_query else 0.0

    return {
        "username": current_user.username,
        "email": current_user.email,
        "total_scans": total_scans,
        "threats_avoided": threats_avoided,
        "clean_scans": clean_scans,
        "avg_risk_score": avg_score
    }

@router.get("/badges")
def get_user_badges(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves security awareness badges earned by the user."""
    badges = db.query(UserBadge).filter(UserBadge.user_id == current_user.id).all()
    return [
        {
            "id": b.id,
            "badge_name": b.badge_name,
            "badge_icon": b.badge_icon,
            "description": b.description,
            "earned_at": b.earned_at.strftime("%Y-%m-%d %H:%M") if b.earned_at else ""
        }
        for b in badges
    ]

@router.post("/claim-badge")
def claim_quiz_badge(
    req: BadgeClaimRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Awards a badge if quiz threshold is met."""
    if req.quiz_score < 60:
        raise HTTPException(status_code=400, detail="Score must be at least 60 to claim this badge")

    existing = (
        db.query(UserBadge)
        .filter(UserBadge.user_id == current_user.id, UserBadge.badge_name == req.badge_name)
        .first()
    )
    if existing:
        return {"success": True, "already_earned": True, "badge_name": existing.badge_name}

    badge = UserBadge(
        user_id=current_user.id,
        badge_name=req.badge_name,
        badge_icon="fa-award",
        description=f"Demonstrated cyber awareness excellence with score {req.quiz_score}/100"
    )
    db.add(badge)
    db.commit()
    return {"success": True, "already_earned": False, "badge_name": badge.badge_name}
