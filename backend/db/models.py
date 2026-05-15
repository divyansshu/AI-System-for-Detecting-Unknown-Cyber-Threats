from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime, timezone
from db.database import Base

class ThreatAlert(Base):
    __tablename__ = 'threat_alerts'

    # defining the columns
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    action = Column(String, index=True)
    threat_type = Column(String)
    caught_by = Column(String)
    anomaly_score = Column(Float)
