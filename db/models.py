from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from db.database import Base

class ThreatAlert(Base):
    __tablename__ = 'threat_alerts'

    # defining the columns
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String, index=True)
    threat_type = Column(String)
    caught_by = Column(String)
    anomaly_score = Column(Float)