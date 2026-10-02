from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityIncident

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"]
)


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    incident = (
        db.query(SecurityIncident)
        .filter(SecurityIncident.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "id": incident.id,
        "ip": incident.ip,
        "attack": incident.attack,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "path": incident.path,
        "mitre_technique": incident.mitre_technique,
        "timestamp": incident.timestamp,
        "created_at": incident.created_at
    }