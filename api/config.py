"""
Hygiene360 API Configuration
==========================
Configuration settings for the Hygiene360 API.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/hygiene360')

# Server Configuration
PORT = int(os.getenv('PORT', 5000))
DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

# Security
SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key-for-development-only')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default-jwt-secret-key-for-development-only')
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour

# Default policy configuration
DEFAULT_POLICY = {
    'name': 'Default Security Policy',
    'description': 'Default security policy for all devices',
    'min_security_score': 70.0,
    'require_os_up_to_date': True,
    'require_antivirus': True,
    'require_firewall': True,
    'require_edr': False,
    'require_dlp': False,
    'max_missing_patches': 0
} 