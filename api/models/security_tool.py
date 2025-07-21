from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from .base import Base

class SecurityTool(Base):
    __tablename__ = 'security_tools'

    id           = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id  = Column(UUID(as_uuid=True),
                          ForeignKey('security_snapshots.id', ondelete='CASCADE'),
                          nullable=False)
    device_id    = Column(String(36),
                          ForeignKey('devices.id'),
                          nullable=False)
    tool_type    = Column(String(50))   # antivirus, edr, dlp
    tool_name    = Column(String(255))

    found        = Column(Boolean, default=False)
    installed    = Column(Boolean, default=False)
    running      = Column(Boolean, default=False)
    registry_found = Column(Boolean, default=False)
    start_mode   = Column(String(50))
    process_count = Column(Integer)

    raw_data     = Column(JSONB)

    def to_dict(self):
        return {
            'tool_type': self.tool_type,
            'tool_name': self.tool_name,
            'found': self.found,
            'installed': self.installed,
            'running': self.running,
            'registry_found': self.registry_found,
            'start_mode': self.start_mode,
            'process_count': self.process_count
        }
