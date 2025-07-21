"""
Alert Model
Stores security alerts for endpoint devices.
"""

from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base
from models.base import db
from datetime import timedelta

class Alert(Base):
    """
    Alert model for security alerts
    """
    __tablename__ = 'alerts'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to device
    device_id = Column(String(36), ForeignKey('devices.id'), nullable=False)
    
    # Alert information
    title = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100), nullable=False)  # e.g., 'patch', 'antivirus', 'firewall', etc.
    severity = Column(Integer, nullable=False)  # 0-low, 1-medium, 2-high, 3-critical
    
    # Status
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    def __init__(
        self,
        device_id,
        title,
        description=None,
        category='general',
        severity=1,
        first_seen=None,
        last_seen=None,
        is_resolved=False,
        resolved_at=None
    ):
        self.device_id = device_id
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.first_seen = first_seen or datetime.utcnow()
        self.last_seen = last_seen or datetime.utcnow()
        self.is_resolved = is_resolved
        self.resolved_at = resolved_at

    
    def resolve(self):
        """Mark alert as resolved"""
        self.is_resolved = True
        self.resolved_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'severity': self.severity,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    @staticmethod
    def compute_severity_from_age(age: timedelta) -> int:
        """
        Compute alert severity based on duration
        """
        if age >= timedelta(days=14):
            return 3  # Critical
        elif age >= timedelta(days=7):
            return 2  # High
        elif age >= timedelta(days=3):
            return 1  # Medium
        else:
            return 0  # Low

    @classmethod
    def create_from_security_data(cls, device_id, security_data, policy=None):
        """
        Create or update alerts based on security data
        """
        new_alerts = []
        now = datetime.utcnow()

        def add_or_update_alert(title, description, category, initial_severity):
            existing_alert = Alert.query.filter_by(
                device_id=device_id,
                title=title,
                category=category
            ).order_by(Alert.created_at.desc()).first()

            if existing_alert and not existing_alert.is_resolved:
                # Update last_seen
                existing_alert.last_seen = now
                age = now - existing_alert.first_seen
                severity = Alert.compute_severity_from_age(age)
                if severity > existing_alert.severity:
                    existing_alert.severity = severity
            elif existing_alert and existing_alert.is_resolved:
                # Reopen the alert if problem persists
                new_alert = cls(
                    device_id=device_id,
                    title=title,
                    description=description,
                    category=category,
                    severity=initial_severity,
                    first_seen=now,
                    last_seen=now,
                    is_resolved=False,
                    resolved_at=None
                )
                new_alerts.append(new_alert)
            else:
                # New alert
                new_alert = cls(
                    device_id=device_id,
                    title=title,
                    description=description,
                    category=category,
                    severity=initial_severity,
                    first_seen=now,
                    last_seen=now
                )
                new_alerts.append(new_alert)

        # --- Alert conditions below ---
        if not security_data.os_up_to_date and policy:
            missing = security_data.patches_missing
            allowed = policy.max_missing_patches
            description = f"Device has {missing} missing patches; policy allows max {allowed}."

            # Assume severity starts at Medium or High depending on how far over the limit it is
            if missing > allowed + 5:
                initial_severity = 3
            elif missing > allowed:
                initial_severity = 2
            else:
                initial_severity = 1

            add_or_update_alert(
                "Operating System Not Up To Date",
                description,
                "patch",
                initial_severity
            )

        if not security_data.antivirus_active:
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="Antivirus Not Active",
                category="antivirus"
            ).order_by(Alert.created_at.desc()).first()
            
            age = now - existing.first_seen if existing and not existing.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "Antivirus Not Active",
                "Your antivirus software is not running or not installed.",
                "antivirus",
                severity
            )

        elif not security_data.antivirus_updated:
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="Antivirus Definitions Outdated",
                category="antivirus"
            ).order_by(Alert.created_at.desc()).first()
            
            age = now - existing.first_seen if existing and not existing.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "Antivirus Definitions Outdated",
                "Your antivirus definitions are not up to date.",
                "antivirus",
                severity
            )

        if not security_data.firewall_active:
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="Firewall Not Active",
                category="firewall"
            ).order_by(Alert.created_at.desc()).first()
            
            age = now - existing.first_seen if existing and not existing.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "Firewall Not Active",
                "Your firewall is not running or not configured properly.",
                "firewall",
                severity
            )

        # === Auto-resolve ANTIVIRUS alerts if policy no longer requires it ===
        if not getattr(policy, "require_antivirus", False):
            for title in ["Antivirus Not Active", "Antivirus Definitions Outdated"]:
                existing = Alert.query.filter_by(
                    device_id=device_id,
                    title=title,
                    category="antivirus",
                    is_resolved=False
                ).order_by(Alert.created_at.desc()).first()
                if existing:
                    existing.resolve()

        # === Auto-resolve FIREWALL alert if policy no longer requires it ===
        if not getattr(policy, "require_firewall", False):
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="Firewall Not Active",
                category="firewall",
                is_resolved=False
            ).order_by(Alert.created_at.desc()).first()
            if existing:
                existing.resolve()

        if getattr(policy, "require_edr", False) and not getattr(security_data, "edr_active", True):
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="EDR Not Active",
                category="edr"
            ).order_by(Alert.created_at.desc()).first()

            age = now - existing.first_seen if existing and not existing.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "EDR Not Active",
                "Endpoint Detection and Response tool is not found or not running.",
                "edr",
                severity
            )

        if getattr(policy, "require_dlp", False) and not getattr(security_data, "dlp_active", True):
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="DLP Not Active",
                category="dlp"
            ).order_by(Alert.created_at.desc()).first()

            age = now - existing.first_seen if existing and not existing.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "DLP Not Active",
                "Data Loss Prevention tool is not found or not running.",
                "dlp",
                severity
            )

        # === Auto-resolve EDR alert if policy no longer requires it ===
        if not getattr(policy, "require_edr", False):
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="EDR Not Active",
                category="edr",
                is_resolved=False
            ).order_by(Alert.created_at.desc()).first()

            if existing:
                existing.resolve()

        # === Auto-resolve DLP alert if policy no longer requires it ===
        if not getattr(policy, "require_dlp", False):
            existing = Alert.query.filter_by(
                device_id=device_id,
                title="DLP Not Active",
                category="dlp",
                is_resolved=False
            ).order_by(Alert.created_at.desc()).first()

            if existing:
                existing.resolve()

        min_score = getattr(policy, 'min_security_score', 70.0)

        if security_data.security_score < min_score:
            existing_score_alert = Alert.query.filter_by(
                device_id=device_id,
                title="Low Security Score",
                category="score"
            ).order_by(Alert.created_at.desc()).first()

            age = now - existing_score_alert.first_seen if existing_score_alert and not existing_score_alert.is_resolved else timedelta()
            severity = Alert.compute_severity_from_age(age)

            add_or_update_alert(
                "Low Security Score",
                f"Security score {security_data.security_score} is below policy threshold ({min_score}) for {age.days} day(s).",
                "score",
                severity
            )

        else:
            # Resolve the alert if one exists
            existing_score_alert = Alert.query.filter_by(
                device_id=device_id,
                title="Low Security Score",
                category="score",
                is_resolved=False
            ).first()

            if existing_score_alert:
                existing_score_alert.resolve()

        return new_alerts
