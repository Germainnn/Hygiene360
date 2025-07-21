"""
OS Patch Status Module
Safe for use across different Windows laptops without requiring external modules.
"""

import platform
import subprocess
import logging
import winreg
import json

if platform.system() == "Windows":
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
else:
    CREATE_NO_WINDOW = 0

logger = logging.getLogger("Hygiene360Agent.os_patch")

def get_last_installed_update():
    """Parse last installed update into structured key-value format"""
    try:
        cmd = [
            "powershell.exe",
            "-Command",
            "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-List"
        ]
        process = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)

        if process.returncode == 0 and process.stdout:
            raw_output = process.stdout.strip()
            update_info = {}

            for line in raw_output.splitlines():
                if ':' in line:
                    key, value = line.split(":", 1)
                    update_info[key.strip()] = value.strip()

            return update_info
        else:
            return {"status": "unknown"}
    except Exception as e:
        logger.error(f"Error getting last update info: {e}")
        return {"status": "error", "error": str(e)}


def get_windows_build_info():
    """Get Windows build and version details from registry"""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")

        current_build = winreg.QueryValueEx(key, "CurrentBuild")[0]
        build_lab = winreg.QueryValueEx(key, "BuildLab")[0]
        product_name = winreg.QueryValueEx(key, "ProductName")[0]

        try:
            ubr = winreg.QueryValueEx(key, "UBR")[0]  # Update Build Revision
        except:
            ubr = "unknown"

        return {
            "current_build": current_build,
            "update_build_revision": ubr,
            "build_lab": build_lab,
            "product_name": product_name
        }
    except Exception as e:
        logger.error(f"Error reading registry: {e}")
        return {"error": str(e)}

def check_pending_updates():
    """Check how many important Windows updates are pending (excludes drivers, firmware, optional)"""
    try:
        cmd = [
            "powershell.exe",
            "-Command",
            "$session = New-Object -ComObject Microsoft.Update.Session; " +
            "$searcher = $session.CreateUpdateSearcher(); " +
            "$updates = $searcher.Search('IsInstalled=0').Updates; " +
            "$important = 0; " +
            "foreach ($u in $updates) { if ($u.MsrcSeverity) { $important++ } }; " +
            "Write-Output $important"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if result.returncode == 0:
            return int(result.stdout.strip())
        else:
            return "unknown"
    except Exception as e:
        logger.error(f"Error checking important updates: {e}")
        return f"error: {e}"

def get_os_patch_status():
    """Collect OS patch and version status without external dependencies"""
    logger.info("Checking OS patch status")

    os_type = platform.system()

    if os_type == "Windows":
        last_update_info = get_last_installed_update()
        build_info = get_windows_build_info()
        pending_count = check_pending_updates()

        if isinstance(pending_count, int):
            status = "up_to_date" if pending_count == 0 else "updates_available"
        else:
            status = "partial_check"

        return {
            "os_type": os_type,
            "os_version": platform.version(),
            "os_release": platform.release(),
            "last_installed_update": last_update_info,
            "build_info": build_info,
            "pending_updates": pending_count,
            "status": status
        }
    elif os_type == "Linux":
        return {
            "os_type": os_type,
            "os_version": platform.version(),
            "os_release": platform.release(),
            "not_implemented": True
        }
    elif os_type == "Darwin":
        return {
            "os_type": os_type,
            "os_version": platform.version(),
            "os_release": platform.release(),
            "not_implemented": True
        }
    else:
        return {
            "os_type": os_type,
            "error": "Unsupported OS"
        }

if __name__ == "__main__":
    result = get_os_patch_status()
    print(json.dumps(result, indent=4))
