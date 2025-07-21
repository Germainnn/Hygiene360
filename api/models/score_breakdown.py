from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from .base import Base

class ScoreBreakdown(Base):
    __tablename__ = 'score_breakdown'

    id = Column(Integer, primary_key=True)
    snapshot_id = Column(UUID(as_uuid=True), ForeignKey('security_snapshots.id'), nullable=False)
    component = Column(String)
    weight = Column(Float)
    achieved_score = Column(Float)
    max_score = Column(Float)
