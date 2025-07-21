#!/usr/bin/env python3
"""
Hygiene360 Endpoint Security Agent
=================================
Collects security metrics from the endpoint and sends them to the central server.
"""

import os
import sys
import time
import json
import uuid
import platform
import logging
import schedule
import requests
from datetime import datetime
import socket
import threading
from flask import Flask, jsonify

# Importing agent modules
from .modules.os_patch import get_os_patch_status
from .modules.antivirus import get_antivirus_status_service_only
from .modules.firewall import get_firewall_status
from .modules.software import get_software_inventory
from .modules.security_tools import check_security_tools

# Flask setup
app = Flask(__name__)

# Configuration
API_URL = "http://localhost:5000/api"
DEVICE_ID = None
CONFIG_FILE = "agent_config.json"
LOG_FILE = "agent.log"

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Hygiene360Agent")

def generate_device_id():
    """Generate a unique device ID or retrieve existing one"""
    global DEVICE_ID
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                DEVICE_ID = config.get('device_id')
                logger.info(f"Retrieved existing device ID: {DEVICE_ID}")
                return DEVICE_ID
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
    
    # Generate new ID if none exists
    DEVICE_ID = str(uuid.uuid4())
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'device_id': DEVICE_ID}, f)
            logger.info(f"Generated new device ID: {DEVICE_ID}")
    except Exception as e:
        logger.error(f"Error saving config file: {e}")
    
    return DEVICE_ID

def collect_system_info():
    """Collect basic system information"""
    system_info = {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "device_id": DEVICE_ID,
        "timestamp": datetime.now().isoformat()
    }
    return system_info

def collect_security_data():
    """Collect all security-related data from the system"""
    logger.info("Starting security data collection")
    
    try:
        # Generate device ID if not exists
        if not DEVICE_ID:
            generate_device_id()
            
        # Collect all security metrics
        data = {
            "system_info": collect_system_info(),
            "os_patch_status": get_os_patch_status(),
            "antivirus_status": get_antivirus_status_service_only(),
            "firewall_status": get_firewall_status(),
            "software_inventory": get_software_inventory(),
            "security_tools": check_security_tools(),
        }
        
        logger.info("Data collection completed successfully")
        return data
    
    except Exception as e:
        logger.error(f"Error collecting security data: {e}")
        return None

def send_data_to_server(data):
    """Send collected data to the central server"""
    if not data:
        logger.error("No data to send")
        return False
    
    try:
        response = requests.post(
            f"{API_URL}/device-data",
            json=data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            logger.info("Data sent successfully to server")
            return True
        else:
            logger.error(f"Error sending data to server. Status code: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error connecting to server: {e}")
        return False

def run_assessment():
    """Run a complete security assessment and send data to server"""
    logger.info("Starting security assessment")
    data = collect_security_data()
    result = send_data_to_server(data)
    logger.info(f"Assessment completed with result: {result}")
    return result

def run_agent():
    """Run the agent in background mode"""
    logger.info("Starting Hygiene360 agent in background mode")
    
    # Generate or retrieve device ID
    generate_device_id()
    
    # Initial run
    run_assessment()
    
    # Schedule regular runs (every 6 hours)
    #schedule.every(6).hours.do(run_assessment)
    
    # Run the scheduler loop
    #logger.info("Entering scheduler loop")
    #while True:
        #schedule.run_pending()
        #time.sleep(60)

def poll_rescan_flag():
    """Agent checks for rescan request every 60 seconds."""
    while True:
        logger.info("Polling for rescan flag...")
        try:
            response = requests.get(f"{API_URL}/devices/{DEVICE_ID}/rescan-request")
            if response.status_code == 200:
                if response.json().get("rescan_requested"):
                    logger.info("Rescan requested by server. Running scan...")
                    run_assessment()

                    # Clear the rescan flag
                    requests.post(
                        f"{API_URL}/devices/{DEVICE_ID}/update-rescan-status",
                        json={"rescan_requested": False}
                    )
        except Exception as e:
            logger.error(f"Error polling rescan request: {e}")
        time.sleep(60)

# === Flask API Route ===
@app.route('/run-scan', methods=['POST'])
def run_scan():
    logger.info("Received manual scan trigger via API")
    success = run_assessment()
    return jsonify({"success": success})

def start_flask_api():
    app.run(host="127.0.0.1", port=6000)

if __name__ == "__main__":
    try:
        # Always launch Flask API in background
        generate_device_id()
        threading.Thread(target=start_flask_api, daemon=True).start()
        threading.Thread(target=poll_rescan_flag, daemon=True).start()

        if len(sys.argv) > 1:
            if sys.argv[1] == "--gui":
                from gui import main
                main()
            elif sys.argv[1] == "--scan":
                logger.info("Running one-time scan via --scan")
                result = run_assessment()
                logger.info(f"Scan completed. Success: {result}")
            else:
                logger.warning(f"Unknown argument: {sys.argv[1]}")
        else:
            run_agent()  # background scheduled scans

    except KeyboardInterrupt:
        logger.info("Agent terminated by user")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unhandled exception occurred")
        sys.exit(1)