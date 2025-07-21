"""
Device Model
Stores information about registered devices.
"""

from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float, func
from datetime import datetime
from .base import Base

class Device(Base):
    """
    Device model representing an endpoint
    """
    __tablename__ = 'devices'
    
    # Primary key
    id = Column(String(36), primary_key=True)  # UUID
    username = Column(String(255), nullable=True)
    # Device information
    hostname = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)
    platform_version = Column(String(100))
    platform_release = Column(String(100))
    architecture = Column(String(50))
    processor = Column(String(255))
    
    # Security posture
    security_score = Column(Float, default=0.0)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_compliant = Column(Boolean, default=False)
    
    # Patch status
    patches_missing = Column(Integer, default=0)
    os_up_to_date = Column(Boolean, default=False)
    
    # Security features
    antivirus_active = Column(Boolean, default=False)
    firewall_active = Column(Boolean, default=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    rescan_requested = Column(Boolean, default=False)
    
    def __init__(self, id, hostname, platform, platform_version=None, platform_release=None, 
                 architecture=None, processor=None):
        self.id = id
        self.hostname = hostname
        self.platform = platform
        self.platform_version = platform_version
        self.platform_release = platform_release
        self.architecture = architecture
        self.processor = processor
        
    def update_security_status(self, antivirus_active, firewall_active, 
                              os_up_to_date, patches_missing, security_score):
        """Update the security status of the device"""
        self.antivirus_active = antivirus_active
        self.firewall_active = firewall_active
        self.os_up_to_date = os_up_to_date
        self.patches_missing = patches_missing
        self.security_score = security_score
        self.last_seen = datetime.utcnow()
        self.is_compliant = security_score >= 70  # Simple compliance threshold
        
    def to_dict(self):
        """Convert device data to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'hostname': self.hostname,
            'platform': self.platform,
            'platform_version': self.platform_version,
            'platform_release': self.platform_release,
            'architecture': self.architecture,
            'processor': self.processor,
            'security_score': self.security_score,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_compliant': self.is_compliant,
            'patches_missing': self.patches_missing,
            'os_up_to_date': self.os_up_to_date,
            'antivirus_active': self.antivirus_active,
            'firewall_active': self.firewall_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 