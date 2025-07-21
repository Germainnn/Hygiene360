from sqlalchemy import Column, String, DateTime, Integer, Boolean, Float, JSON, ForeignKey
from datetime import datetime
from .base import Base

class SecurityData(Base):
    __tablename__ = 'security_data'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(36), ForeignKey('devices.id'), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)

    os_patch_status = Column(JSON)
    os_up_to_date = Column(Boolean, default=False)
    patches_missing = Column(Integer, default=0)

    antivirus_status = Column(JSON)
    antivirus_active = Column(Boolean, default=False)
    antivirus_updated = Column(Boolean, default=False)

    firewall_status = Column(JSON)
    firewall_active = Column(Boolean, default=False)

    security_tools_status = Column(JSON)
    edr_active = Column(Boolean, default=False)
    dlp_active = Column(Boolean, default=False)

    security_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __init__(self, device_id, os_patch_status=None, antivirus_status=None,
                 firewall_status=None, security_tools_status=None, collected_at=None):
        self.device_id = device_id
        self.collected_at = collected_at or datetime.utcnow()

        # --- OS Patch Status ---
        if os_patch_status:
            self.os_patch_status = os_patch_status
            if isinstance(os_patch_status, dict):
                update_info = os_patch_status.get("update_status", os_patch_status)
                status = update_info.get("status")
                pending_updates = update_info.get("pending_updates")

                self.os_up_to_date = status == "up_to_date"
                try:
                    self.patches_missing = int(pending_updates)
                except (ValueError, TypeError):
                    self.patches_missing = 0

        # --- Antivirus Status ---
        if antivirus_status:
            self.antivirus_status = antivirus_status
            products = antivirus_status.get("products", [])

            self.antivirus_active = any(
                p.get("found") and p.get("running") for p in products if isinstance(p, dict)
            )

            # There’s no "updated" flag, so use 'protected' or fallback
            self.antivirus_updated = antivirus_status.get("protected", False)

        # --- Firewall Status ---
        if firewall_status:
            self.firewall_status = firewall_status
            if isinstance(firewall_status, dict):
                firewall_data = firewall_status.get("firewall_status", {})
                self.firewall_active = firewall_data.get("overall_status", False)

        # --- Security Tools ---
        if security_tools_status:
            self.security_tools_status = security_tools_status
            if isinstance(security_tools_status, dict):
                self.edr_active = security_tools_status.get("edr", {}).get("found", False)
                self.dlp_active = security_tools_status.get("dlp", {}).get("found", False)

        # --- Calculate Score ---
        self.calculate_security_score()

    def calculate_security_score(self):
        score = 0

        # OS (0–25)
        if self.os_up_to_date:
            score += 25
        elif self.patches_missing is not None:
            score += max(0, 25 - min(self.patches_missing * 5, 25))

        # Antivirus (0–25)
        if self.antivirus_active:
            score += 20
            if self.antivirus_updated:
                score += 5

        # Firewall (0–20)
        if self.firewall_active:
            score += 20

        # Security Tools (0–30)
        if self.edr_active:
            score += 15
        if self.dlp_active:
            score += 5

        self.security_score = score
        return score

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "os_up_to_date": self.os_up_to_date,
            "patches_missing": self.patches_missing,
            "antivirus_active": self.antivirus_active,
            "antivirus_updated": self.antivirus_updated,
            "firewall_active": self.firewall_active,
            "edr_active": self.edr_active,
            "dlp_active": self.dlp_active,
            "security_score": self.security_score,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
