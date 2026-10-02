from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from app.database import Base


class UploadedLog(Base):
    __tablename__ = "uploaded_logs"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    log_type = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    timestamp = Column(String)
    method = Column(String)
    path = Column(Text)
    status = Column(String)

    attack = Column(String, index=True)
    severity = Column(String, index=True)
    risk_score = Column(Integer)

    mitre_technique = Column(String)
    mitre_name = Column(String)

    iocs = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)