-- Hygiene360 Updated Database Schema

-- Create database (run as admin if needed)
-- CREATE DATABASE hygiene360;
-- \c hygiene360

-- ========================
-- Devices Table
-- ========================
CREATE TABLE IF NOT EXISTS devices (
    id VARCHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    platform_version VARCHAR(100),
    platform_release VARCHAR(100),
    architecture VARCHAR(50),
    processor VARCHAR(255),
    security_score FLOAT DEFAULT 0.0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN DEFAULT FALSE,
    patches_missing INTEGER DEFAULT 0,
    os_up_to_date BOOLEAN DEFAULT FALSE,
    antivirus_active BOOLEAN DEFAULT FALSE,
    firewall_active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    rescan_requested = Column(Boolean, default=False)
);

-- ========================
-- Security Data Table (Live Posture)
-- ========================
CREATE TABLE IF NOT EXISTS security_data (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) REFERENCES devices(id) ON DELETE CASCADE,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    os_patch_status JSONB,
    os_up_to_date BOOLEAN DEFAULT FALSE,
    patches_missing INTEGER DEFAULT 0,
    antivirus_status JSONB,
    antivirus_active BOOLEAN DEFAULT FALSE,
    antivirus_updated BOOLEAN DEFAULT FALSE,
    firewall_status JSONB,
    firewall_active BOOLEAN DEFAULT FALSE,
    security_tools_status JSONB,
    edr_active BOOLEAN DEFAULT FALSE,
    dlp_active BOOLEAN DEFAULT FALSE,
    security_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
-- Software Table
-- ========================
CREATE TABLE IF NOT EXISTS software (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) REFERENCES devices(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    publisher VARCHAR(255),
    install_date VARCHAR(50),
    is_outdated BOOLEAN DEFAULT FALSE,
    is_vulnerable BOOLEAN DEFAULT FALSE,
    risk_level INTEGER DEFAULT 0,
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
-- Policies Table
-- ========================
CREATE TABLE IF NOT EXISTS policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(500),
    min_security_score FLOAT DEFAULT 70.0,
    require_os_up_to_date BOOLEAN DEFAULT TRUE,
    require_antivirus BOOLEAN DEFAULT TRUE,
    require_firewall BOOLEAN DEFAULT TRUE,
    require_edr BOOLEAN DEFAULT FALSE,
    require_dlp BOOLEAN DEFAULT FALSE,
    max_missing_patches INTEGER DEFAULT 0,
    os_score_weight FLOAT DEFAULT 25.0,
    antivirus_score_weight FLOAT DEFAULT 25.0,
    firewall_score_weight FLOAT DEFAULT 20.0,
    security_tools_score_weight FLOAT DEFAULT 30.0,
    software_penalty_per_vuln FLOAT DEFAULT 5.0,
    max_software_penalty FLOAT DEFAULT 20.0,
    custom_rules JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
-- Alerts Table
-- ========================
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) REFERENCES devices(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    severity INTEGER NOT NULL,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
-- Default Policy Insert
-- ========================
INSERT INTO policies (
    name, 
    description, 
    min_security_score,
    require_os_up_to_date,
    require_antivirus,
    require_firewall,
    require_edr,
    require_dlp,
    max_missing_patches,
    software_penalty_per_vuln,
    max_software_penalty
) VALUES (
    'Default Security Policy',
    'Default policy applied to all devices unless overridden.',
    70.0,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    0,
    5.0,
    20.0
);

-- ========================
-- Indexes
-- ========================
CREATE INDEX IF NOT EXISTS idx_device_id ON security_data(device_id);
CREATE INDEX IF NOT EXISTS idx_software_device_id ON software(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(is_resolved);
