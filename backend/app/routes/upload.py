from pathlib import Path
import shutil
import json
from app.auth import get_current_user
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UploadedLog, SecurityIncident
from app.services.log_identifier import detect_log_type
from app.services.parser import parse_apache_log
from app.services.detector import detect_threats
from app.services.risk_engine import calculate_risk


router = APIRouter(
    prefix="/upload",
    tags=["Upload"]
)

UPLOAD_FOLDER = "uploads"
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)


@router.post("/")
async def upload_log(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):

    if not file.filename.lower().endswith((".log", ".txt")):
        raise HTTPException(
            status_code=400,
            detail="Only .log and .txt files are allowed."
        )

    destination = Path(UPLOAD_FOLDER) / file.filename

    with destination.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    log_type = detect_log_type(destination)

    uploaded = UploadedLog(
        filename=file.filename,
        log_type=log_type
    )

    db.add(uploaded)
    db.commit()
    db.refresh(uploaded)

    # Parse the uploaded log
    parsed_logs = parse_apache_log(str(destination))

    # Detect threats
    findings = detect_threats(parsed_logs)

    # Calculate overall risk
    risk = calculate_risk(findings)

    # Store every finding
    for finding in findings:

        mitre = finding.get("mitre", {})
        iocs = finding.get("iocs", {})

        incident = SecurityIncident(
            ip=finding.get("ip"),
            timestamp=finding.get("timestamp"),
            method=finding.get("method"),
            path=finding.get("path"),
            status=str(finding.get("status")),
            attack=finding.get("attack"),
            severity=finding.get("severity"),
            risk_score=risk["score"],
            mitre_technique=mitre.get("technique"),
            mitre_name=mitre.get("name"),
            iocs=json.dumps(iocs)
        )

        db.add(incident)

    db.commit()

    return {
    "message": "Log processed successfully",
    "filename": file.filename,
    "log_type": log_type,
    "total_logs": len(parsed_logs),
    "threats_found": len(findings),

    "risk_score": risk.get("score", 0),
    "risk_severity": risk.get("severity", "Low"),

    "threats": [
        {
            "attack": finding.get("attack", "Unknown"),
            "severity": finding.get("severity", "Low"),
            "risk_score": finding.get(
                "risk_score",
                risk.get("score", 0)
            ),
            "mitre_technique": (
                finding.get("mitre", {}).get("technique")
                if isinstance(finding.get("mitre"), dict)
                else finding.get("mitre_technique")
            ),
            "reason": finding.get("reason", ""),
            "ip": finding.get("ip")
        }
        for finding in findings
    ],

    "risk": risk
}