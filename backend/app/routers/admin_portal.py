from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from ..database import get_db
from ..models.user import User
from ..models.scan import ScanHistory
from ..models.threat_rule import ThreatRule
from ..models.audit import AuditLog
from ..core.security import require_admin

router = APIRouter(prefix="/api/admin", tags=["Admin SOC Console"])

class RuleCreateRequest(BaseModel):
    rule_type: str = Field(..., pattern="^(blacklist|whitelist)$")
    pattern: str = Field(..., min_length=3, max_length=255)
    reason: Optional[str] = None

class RoleChangeRequest(BaseModel):
    new_role: str = Field(..., pattern="^(user|admin)$")

@router.get("/users")
def get_all_users(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Lists all registered platform users with their activity telemetry."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    user_list = []
    for u in users:
        scans_count = db.query(ScanHistory).filter(ScanHistory.user_id == u.id).count()
        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "total_scans": scans_count,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else ""
        })
    return user_list

@router.post("/users/{user_id}/toggle-status")
def toggle_user_status(user_id: int, current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Suspends or reactivates a user account."""
    if current_admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot toggle your own active admin account")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_active = not target.is_active
    db.commit()

    # Log audit event
    audit = AuditLog(
        user_id=current_admin.id,
        action="USER_STATUS_TOGGLED",
        status="SUCCESS",
        details=f"Admin {current_admin.username} changed user {target.username} active status to {target.is_active}."
    )
    db.add(audit)
    db.commit()

    return {"success": True, "user_id": target.id, "is_active": target.is_active}

@router.post("/users/{user_id}/change-role")
def change_user_role(user_id: int, req: RoleChangeRequest, current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Promotes or demotes user privileges."""
    if current_admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot alter your own role")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.role = req.new_role
    db.commit()

    audit = AuditLog(
        user_id=current_admin.id,
        action="USER_ROLE_CHANGED",
        status="SUCCESS",
        details=f"Admin {current_admin.username} updated {target.username} role to {target.role}."
    )
    db.add(audit)
    db.commit()

    return {"success": True, "user_id": target.id, "role": target.role}

@router.get("/rules")
def get_threat_rules(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Returns all custom blacklist and whitelist domain rules."""
    rules = db.query(ThreatRule).order_by(ThreatRule.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "rule_type": r.rule_type,
            "pattern": r.pattern,
            "reason": r.reason or "",
            "created_by": r.created_by,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else ""
        }
        for r in rules
    ]

@router.post("/rules")
def create_threat_rule(req: RuleCreateRequest, current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Adds a new custom blacklist or whitelist rule."""
    clean_pat = req.pattern.strip().lower()
    existing = db.query(ThreatRule).filter(ThreatRule.pattern == clean_pat).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Rule pattern '{clean_pat}' already exists")

    rule = ThreatRule(
        rule_type=req.rule_type,
        pattern=clean_pat,
        reason=req.reason or "Admin defined SOC rule",
        created_by=current_admin.username
    )
    db.add(rule)
    db.commit()

    audit = AuditLog(
        user_id=current_admin.id,
        action="THREAT_RULE_CREATED",
        status="SUCCESS",
        details=f"Admin created {rule.rule_type} for pattern '{rule.pattern}'."
    )
    db.add(audit)
    db.commit()

    return {"success": True, "rule_id": rule.id, "pattern": rule.pattern, "rule_type": rule.rule_type}

@router.delete("/rules/{rule_id}")
def delete_threat_rule(rule_id: int, current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Removes a custom threat rule."""
    rule = db.query(ThreatRule).filter(ThreatRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    pat = rule.pattern
    rule_type = rule.rule_type
    db.delete(rule)
    db.commit()

    audit = AuditLog(
        user_id=current_admin.id,
        action="THREAT_RULE_DELETED",
        status="SUCCESS",
        details=f"Admin deleted {rule_type} rule for '{pat}'."
    )
    db.add(audit)
    db.commit()

    return {"success": True, "message": f"Rule '{pat}' deleted."}

@router.get("/global-scans")
def get_global_scans(limit: int = 50, current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Retrieves system-wide scan history with associated user accounts."""
    scans = (
        db.query(ScanHistory, User.username)
        .outerjoin(User, ScanHistory.user_id == User.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": s.id,
            "scan_type": s.scan_type,
            "input_target": s.input_target,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "user": username or "Guest",
            "source_ip": s.source_ip or "127.0.0.1",
            "recommendation": s.recommendation,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else ""
        }
        for s, username in scans
    ]
