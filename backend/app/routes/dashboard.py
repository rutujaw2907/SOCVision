from fastapi import APIRouter, Depends
from app.auth import get_current_user
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityIncident

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


@router.get("/stats")
def dashboard_stats(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    incidents = db.query(SecurityIncident).all()

    total = len(incidents)

    critical = sum(i.severity == "Critical" for i in incidents)
    high = sum(i.severity == "High" for i in incidents)
    medium = sum(i.severity == "Medium" for i in incidents)
    low = sum(i.severity == "Low" for i in incidents)

    attack_types = {}

    for incident in incidents:
        attack = incident.attack or "Unknown"
        attack_types[attack] = attack_types.get(attack, 0) + 1

    attacker_ips = {}

    for incident in incidents:
        ip = incident.ip or "Unknown"
        attacker_ips[ip] = attacker_ips.get(ip, 0) + 1

    return {
        "total_incidents": total,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "attack_types": attack_types,
        "top_attacker_ips": dict(
            sorted(
                attacker_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        )
    }


@router.get("/recent")
def attack_timeline(
    db: Session = Depends(get_db)
):

    incidents = (
        db.query(SecurityIncident)
        .order_by(SecurityIncident.created_at.desc())
        .limit(10)
        .all()
    )

    return incidents


@router.get("/timeline")
def attack_timeline(
    db: Session = Depends(get_db)
):

    incidents = (
        db.query(SecurityIncident)
        .order_by(SecurityIncident.created_at.asc())
        .all()
    )

    timeline = []

    for incident in incidents:

        timeline.append({
            "timestamp": incident.timestamp,
            "attack": incident.attack,
            "severity": incident.severity,
            "ip": incident.ip,
            "path": incident.path,
            "mitre": incident.mitre_technique
        })

    return {
        "total_events": len(timeline),
        "events": timeline
    }