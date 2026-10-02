import json

from fastapi import (
    APIRouter,
    Depends,
    HTTPException
)
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import SecurityIncident
from app.services.ai_analyst import analyze_incident


router = APIRouter(
    prefix="/ai",
    tags=["AI Security Analyst"]
)


@router.post("/analyst/{incident_id}")
async def run_ai_analyst(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):

    incident = (
        db.query(SecurityIncident)
        .filter(
            SecurityIncident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    try:
        iocs = (
            json.loads(
                incident.iocs
            )
            if incident.iocs
            else {}
        )

    except json.JSONDecodeError:
        iocs = {}

    incident_data = {
        "incident_id": incident.id,
        "attack": incident.attack,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "incident_status": (
            incident.incident_status
            or "OPEN"
        ),
        "source_ip": incident.ip,
        "http_method": incident.method,
        "endpoint": incident.path,
        "http_status": incident.status,
        "timestamp": incident.timestamp,
        "mitre_technique": (
            incident.mitre_technique
        ),
        "mitre_name": incident.mitre_name,
        "iocs": iocs
    }

    result = await analyze_incident(
        incident_data
    )

    if not result.get("available"):
        raise HTTPException(
            status_code=503,
            detail=result.get(
                "error",
                "AI analyst unavailable"
            )
        )

    analysis = result.get(
        "analysis",
        ""
    )

    incident.ai_analysis = analysis

    db.commit()
    db.refresh(incident)

    return {
        "incident_id": incident.id,
        "available": True,
        "model": result.get("model"),
        "analysis": analysis
    }