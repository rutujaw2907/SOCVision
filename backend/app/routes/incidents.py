from datetime import datetime

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import SecurityIncident
from app.services.report_generator import (
    generate_incident_report,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


VALID_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
}


class IncidentStatusUpdate(BaseModel):
    status: str


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
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
            detail="Incident not found",
        )

    return {
        "id": incident.id,
        "ip": incident.ip,
        "attack": incident.attack,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "path": incident.path,
        "method": incident.method,
        "status": incident.status,
        "incident_status": (
            incident.incident_status
            or "OPEN"
        ),
        "mitre_technique": (
            incident.mitre_technique
        ),
        "mitre_name": incident.mitre_name,
        "iocs": incident.iocs,
        "timestamp": incident.timestamp,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    data: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    new_status = (
        data.status
        .upper()
        .strip()
    )

    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid incident status. "
                "Allowed statuses: "
                "OPEN, INVESTIGATING, "
                "CONTAINED, RESOLVED"
            ),
        )

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
            detail="Incident not found",
        )

    incident.incident_status = new_status
    incident.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident status updated",
        "id": incident.id,
        "incident_status": (
            incident.incident_status
        ),
        "updated_at": incident.updated_at,
    }


@router.get(
    "/{incident_id}/report"
)
def generate_incident_pdf(
    incident_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
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
            detail="Incident not found",
        )

    pdf_buffer = generate_incident_report(
        incident=incident,
        ai_analysis=incident.ai_analysis,
    )

    filename = (
        f"SOCVision_Incident_{incident.id}.pdf"
    )

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )