import subprocess
import platform
import time
import json
import re
import logging

if platform.system() == "Windows":
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
else:
    CREATE_NO_WINDOW = 0

logger = logging.getLogger("Hygiene360Agent.antivirus")

# Define AV service display names for detection
KNOWN_AV_SERVICES = {
    "Avast Antivirus": "Avast Antivirus",
    "Avast Firewall": "Avast Firewall Service",
    "Avast Tools": "Avast Tools",
    "Windows Defender": "WinDefend",
    
    # McAfee entries
    "McAfee WebAdvisor": "McAfee WebAdvisor",
    "McAfee AP Service": "McAPExe",
    "McAfee CSP Service": "mccspsvc",
    "McAfee Core Service": "ModuleCoreService",
    "McAfee Trust Protection": "mfevtp",
    "McAfee Scan Host": "McComponentHostService",
    "McAfee Safe Connect": "SafeConnectService"
}

def get_service_status(service_display_name):
    """Check if a given Windows service (by display name) is running"""
    try:
        cmd = [
            "powershell.exe",
            "-Command",
            f"Get-Service | Where-Object {{ $_.DisplayName -eq '{service_display_name}' }} | Select-Object -ExpandProperty Status"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)

        if result.returncode != 0 or not result.stdout.strip():
            return {"found": False, "running": False}

        status = result.stdout.strip()
        return {
            "found": True,
            "running": status.lower() == "running",
            "status": status
        }

    except Exception as e:
        logger.error(f"Error checking service '{service_display_name}': {e}")
        return {"found": False, "running": False, "error": str(e)}

def get_all_known_av_status():
    """Check the status of known antivirus services by display name"""
    results = []
    for label, display_name in KNOWN_AV_SERVICES.items():
        status = get_service_status(display_name)
        status.update({"name": label})
        results.append(status)
    return results

def determine_protection_state(av_status_list):
    """Decide protection status based on service statuses"""
    for av in av_status_list:
        if av.get("found") and av.get("running"):
            return True, "Compliant"
    return False, "Outdated"

def get_antivirus_status_service_only():
    """Main entry point"""
    if platform.system() != "Windows":
        return {
            "os_type": platform.system(),
            "not_implemented": True
        }

    av_status_list = get_all_known_av_status()
    is_protected, compliance = determine_protection_state(av_status_list)

    return {
        "os_type": "Windows",
        "method": "service_only",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "products": av_status_list,
        "protected": is_protected,
        "status": compliance
    }

# Debug/Test
if __name__ == "__main__":
    result = get_antivirus_status_service_only()
    print(json.dumps(result, indent=4))
