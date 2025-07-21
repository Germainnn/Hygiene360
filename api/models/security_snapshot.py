from sqlalchemy import Column, String, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from .base import Base

class SecuritySnapshot(Base):
    __tablename__ = 'security_snapshots'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(String(36), ForeignKey('devices.id'), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)

    os_patch_status     = Column(JSONB)
    antivirus_summary   = Column(JSONB)
    firewall_summary    = Column(JSONB)

    edr_found           = Column(Boolean, default=False)
    dlp_found           = Column(Boolean, default=False)
    security_score      = Column(Float,   default=0.0)

    def to_dict(self):
        return {
            'id': str(self.id),
            'device_id': self.device_id,
            'collected_at': self.collected_at.isoformat(),
            'security_score': self.security_score
        }
