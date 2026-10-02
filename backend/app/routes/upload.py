from pathlib import Path
import shutil
import json

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import UploadedLog, SecurityIncident

from app.services.log_identifier import detect_log_type
from app.services.parser import parse_apache_log
from app.services.detector import detect_threats
from app.services.risk_engine import calculate_risk
from app.services.virustotal import check_ip as check_virustotal
from app.services.abuseipdb import check_ip as check_abuseipdb


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
    # ========================================================
    # 1. Validate file
    # ========================================================

    if not file.filename.lower().endswith(
        (".log", ".txt")
    ):
        raise HTTPException(
            status_code=400,
            detail="Only .log and .txt files are allowed."
        )

    # ========================================================
    # 2. Save uploaded file
    # ========================================================

    destination = Path(
        UPLOAD_FOLDER
    ) / file.filename

    with destination.open("wb") as buffer:
        shutil.copyfileobj(
            file.file,
            buffer
        )

    # ========================================================
    # 3. Identify log type
    # ========================================================

    log_type = detect_log_type(
        destination
    )

    # ========================================================
    # 4. Save uploaded log
    # ========================================================

    uploaded = UploadedLog(
        filename=file.filename,
        log_type=log_type
    )

    db.add(uploaded)
    db.commit()
    db.refresh(uploaded)

    # ========================================================
    # 5. Parse log
    # ========================================================

    parsed_logs = parse_apache_log(
        str(destination)
    )

    # ========================================================
    # 6. Detect threats
    # ========================================================

    findings = detect_threats(
        parsed_logs
    )

    # ========================================================
    # 7. Threat Intelligence
    #
    # Query each unique IP only once.
    # ========================================================

    threat_intelligence = []

    unique_ips = {
        finding.get("ip")
        for finding in findings
        if finding.get("ip")
    }

    for ip in unique_ips:

        virustotal_result = await check_virustotal(
            ip
        )

        abuseipdb_result = await check_abuseipdb(
            ip
        )

        threat_intelligence.append({
            "ip": ip,
            "virustotal": virustotal_result,
            "abuseipdb": abuseipdb_result
        })

    # ========================================================
    # 8. Calculate explainable risk
    # ========================================================

    risk = calculate_risk(
        findings,
        threat_intelligence
    )

    # ========================================================
    # 9. Save incidents
    # ========================================================

    for finding in findings:

        mitre = finding.get(
            "mitre",
            {}
        )

        iocs = finding.get(
            "iocs",
            {}
        )

        incident = SecurityIncident(
            ip=finding.get(
                "ip"
            ),
            timestamp=finding.get(
                "timestamp",
                finding.get("time")
            ),
            method=finding.get(
                "method"
            ),
            path=finding.get(
                "path"
            ),
            status=str(
                finding.get(
                    "status"
                )
            ),
            attack=finding.get(
                "attack"
            ),
            severity=finding.get(
                "severity"
            ),
            risk_score=risk.get(
                "score",
                0
            ),
            mitre_technique=(
                mitre.get("technique")
                if isinstance(
                    mitre,
                    dict
                )
                else finding.get(
                    "mitre_technique"
                )
            ),
            mitre_name=(
                mitre.get("name")
                if isinstance(
                    mitre,
                    dict
                )
                else None
            ),
            iocs=json.dumps(
                iocs
            )
        )

        db.add(
            incident
        )

    db.commit()

    # ========================================================
    # 10. Prepare frontend threat data
    # ========================================================

    threats = []

    for finding in findings:

        mitre = finding.get(
            "mitre",
            {}
        )

        threats.append({
            "attack": finding.get(
                "attack",
                "Unknown"
            ),
            "severity": finding.get(
                "severity",
                "Low"
            ),
            "confidence": finding.get(
                "confidence",
                0
            ),
            "risk_score": finding.get(
                "risk_score",
                risk.get(
                    "score",
                    0
                )
            ),
            "mitre_technique": (
                mitre.get("technique")
                if isinstance(
                    mitre,
                    dict
                )
                else finding.get(
                    "mitre_technique"
                )
            ),
            "reason": finding.get(
                "reason",
                ""
            ),
            "evidence": finding.get(
                "evidence",
                finding.get(
                    "reason",
                    ""
                )
            ),
            "ip": finding.get(
                "ip"
            )
        })

    # ========================================================
    # 11. Final response
    # ========================================================

    return {
        "message": "Log processed successfully",
        "filename": file.filename,
        "log_type": log_type,
        "total_logs": len(
            parsed_logs
        ),
        "threats_found": len(
            findings
        ),
        "risk_score": risk.get(
            "score",
            0
        ),
        "risk_severity": risk.get(
            "severity",
            "Low"
        ),
        "threats": threats,
        "threat_intelligence": (
            threat_intelligence
        ),
        "risk": risk
    }