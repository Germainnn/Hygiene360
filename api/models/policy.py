"""
Policy Model
Stores security policies for device compliance assessment.
"""

from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float, JSON
from datetime import datetime
from .base import Base
from models.base import db

def get_active_policy():
    return db.session.query(Policy).filter_by(is_active=True).first()

class Policy(Base):
    """
    Policy model for security policy configuration
    """
    __tablename__ = 'policies'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Policy information
    name = Column(String(255), nullable=False)
    description = Column(String(500))
    
    # Policy requirements
    min_security_score = Column(Float, default=70.0)
    require_os_up_to_date = Column(Boolean, default=True)
    require_antivirus = Column(Boolean, default=True)
    require_firewall = Column(Boolean, default=True)
    require_edr = Column(Boolean, default=False)
    require_dlp = Column(Boolean, default=False)
    max_missing_patches = Column(Integer, default=0)
    
    # Policy configuration
    os_score_weight = Column(Float, default=25.0)
    antivirus_score_weight = Column(Float, default=25.0)
    firewall_score_weight = Column(Float, default=20.0)
    security_tools_score_weight = Column(Float, default=30.0)
    software_penalty_per_vuln = Column(Float, default=5.0)
    max_software_penalty = Column(Float, default=20.0)
    
    # Custom scoring rules (JSON)
    custom_rules = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, name, description=None, min_security_score=70.0,
                require_os_up_to_date=True, require_antivirus=True, require_firewall=True,
                require_edr=False, require_dlp=False,
                max_missing_patches=0, custom_rules=None,
                software_penalty_per_vuln=5.0, max_software_penalty=20.0):
        
        self.name = name
        self.description = description
        self.min_security_score = min_security_score
        self.require_os_up_to_date = require_os_up_to_date
        self.require_antivirus = require_antivirus
        self.require_firewall = require_firewall
        self.require_edr = require_edr
        self.require_dlp = require_dlp
        self.max_missing_patches = max_missing_patches
        self.custom_rules = custom_rules or {}
        self.software_penalty_per_vuln = software_penalty_per_vuln
        self.max_software_penalty = max_software_penalty
    
    def check_compliance(self, security_data):
        """
        Check if a device is compliant with this policy
        
        Args:
            security_data (SecurityData): The security data to check against this policy
            
        Returns:
            dict: Compliance results with details
        """
        compliance = {
            'compliant': True,
            'security_score': security_data.security_score,
            'min_required_score': self.min_security_score,
            'details': {}
        }
        
        # Check minimum security score
        if security_data.security_score < self.min_security_score:
            compliance['compliant'] = False
            compliance['details']['security_score'] = {
                'compliant': False,
                'reason': f"Security score {security_data.security_score} is below minimum required {self.min_security_score}"
            }
        else:
            compliance['details']['security_score'] = {
                'compliant': True
            }
        
        # Check OS patch status
        if self.require_os_up_to_date and not security_data.os_up_to_date:
            compliance['compliant'] = False
            compliance['details']['os_up_to_date'] = {
                'compliant': False,
                'reason': "Operating system is not up to date"
            }
        else:
            compliance['details']['os_up_to_date'] = {
                'compliant': True
            }
        
        # Check missing patches
        if security_data.patches_missing > self.max_missing_patches:
            compliance['compliant'] = False
            compliance['details']['patches_missing'] = {
                'compliant': False,
                'reason': f"Missing {security_data.patches_missing} patches, maximum allowed is {self.max_missing_patches}"
            }
        else:
            compliance['details']['patches_missing'] = {
                'compliant': True
            }
        
        # Check antivirus
        if self.require_antivirus and not security_data.antivirus_active:
            compliance['compliant'] = False
            compliance['details']['antivirus'] = {
                'compliant': False,
                'reason': "Antivirus is not active"
            }
        else:
            compliance['details']['antivirus'] = {
                'compliant': True
            }
        
        # Check firewall
        if self.require_firewall and not security_data.firewall_active:
            compliance['compliant'] = False
            compliance['details']['firewall'] = {
                'compliant': False,
                'reason': "Firewall is not active"
            }
        else:
            compliance['details']['firewall'] = {
                'compliant': True
            }
        
        # Check EDR
        if self.require_edr and not security_data.edr_active:
            compliance['compliant'] = False
            compliance['details']['edr'] = {
                'compliant': False,
                'reason': "Endpoint Detection and Response is not active"
            }
        else:
            compliance['details']['edr'] = {
                'compliant': True
            }
        
        # Check DLP
        if self.require_dlp and not security_data.dlp_active:
            compliance['compliant'] = False
            compliance['details']['dlp'] = {
                'compliant': False,
                'reason': "Data Loss Prevention is not active"
            }
        else:
            compliance['details']['dlp'] = {
                'compliant': True
            }

        return compliance

    def to_dict(self):
        """Convert policy to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'min_security_score': self.min_security_score,
            'require_os_up_to_date': self.require_os_up_to_date,
            'require_antivirus': self.require_antivirus,
            'require_firewall': self.require_firewall,
            'require_edr': self.require_edr,
            'require_dlp': self.require_dlp,
            'max_missing_patches': self.max_missing_patches,
            'os_score_weight': self.os_score_weight,
            'antivirus_score_weight': self.antivirus_score_weight,
            'firewall_score_weight': self.firewall_score_weight,
            'security_tools_score_weight': self.security_tools_score_weight,
            'custom_rules': self.custom_rules,
            'is_active': self.is_active,
            'software_penalty_per_vuln': self.software_penalty_per_vuln,
            'max_software_penalty': self.max_software_penalty,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 