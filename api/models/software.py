from sqlalchemy import Column, String, DateTime, Integer, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
from .base import Base

class Software(Base):
    __tablename__ = 'software'

    id           = Column(Integer, primary_key=True)
    device_id    = Column(String(36), ForeignKey('devices.id'), nullable=False)
    snapshot_id  = Column(UUID(as_uuid=True),
                          ForeignKey('security_snapshots.id'),
                          nullable=False)

    name         = Column(String(255), nullable=False)
    version      = Column(String(100))
    publisher    = Column(String(255))
    install_date = Column(String(50))

    is_outdated  = Column(Boolean, default=False)
    is_vulnerable= Column(Boolean, default=False)
    risk_level   = Column(Integer, default=0)
    raw_data     = Column(JSONB)

    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'snapshot_id': str(self.snapshot_id),
            'name': self.name,
            'version': self.version,
            'publisher': self.publisher,
            'install_date': self.install_date,
            'is_outdated': self.is_outdated is True,
            'is_vulnerable': self.is_vulnerable is True,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
