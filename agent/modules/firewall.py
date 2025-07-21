"""
Firewall Status Module
Checks the status and configuration of the firewall.
"""

import logging
import platform
import subprocess
import re
import json
import time

if platform.system() == "Windows":
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
else:
    CREATE_NO_WINDOW = 0

logger = logging.getLogger("Hygiene360Agent.firewall")

def get_windows_firewall_status():
    """Get Windows Firewall status using PowerShell"""
    try:
        # 1. Get firewall profiles
        cmd = [
            "powershell.exe",
            "-Command",
            "Get-NetFirewallProfile | Format-List Name,Enabled"
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
        stdout, stderr = process.communicate()

        profiles = {}
        current_profile = None

        if process.returncode == 0 and stdout:
            output = stdout.decode('utf-8')
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue

                name_match = re.match(r"Name\s+:\s+(.+)", line)
                if name_match:
                    current_profile = name_match.group(1)
                    profiles[current_profile] = {"enabled": False}
                    continue

                if current_profile:
                    enabled_match = re.match(r"Enabled\s+:\s+(.+)", line)
                    if enabled_match:
                        profiles[current_profile]["enabled"] = enabled_match.group(1).lower() == "true"

        # 2. Get active rules count
        cmd = [
            "powershell.exe",
            "-Command",
            "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Measure-Object | Select-Object -ExpandProperty Count"
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
        stdout, _ = process.communicate()
        active_rules = int(stdout.decode('utf-8').strip()) if process.returncode == 0 else -1

        # 3. Get block rules count
        cmd = [
            "powershell.exe",
            "-Command",
            "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Block'} | Measure-Object | Select-Object -ExpandProperty Count"
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
        stdout, _ = process.communicate()
        block_rules = int(stdout.decode('utf-8').strip()) if process.returncode == 0 else -1

        return {
            "profiles": profiles,
            "active_rules_count": active_rules,
            "block_rules_count": block_rules,
            "overall_status": any(profile["enabled"] for profile in profiles.values())
        }

    except Exception as e:
        logger.error(f"Error getting Windows Firewall status: {e}")
        return {
            "error": str(e),
            "overall_status": False
        }

def get_firewall_status():
    """Get the status of the firewall on the system"""
    logger.info("Checking firewall status")
    os_type = platform.system()

    if os_type == "Windows":
        firewall_status = get_windows_firewall_status()
        return {
            "os_type": os_type,
            "firewall_status": firewall_status
        }
    else:
        return {
            "os_type": os_type,
            "not_implemented": True
        }

# 🔁 Testing
if __name__ == "__main__":
        result = get_firewall_status()
        print(json.dumps(result, indent=4))
