import logging
import platform
import winreg
import requests
import json
import time
import re
import os
from dotenv import load_dotenv
from datetime import datetime
from packaging import version

logger = logging.getLogger("Hygiene360Agent.software")

load_dotenv()

VULDB_API_KEY = os.getenv("VULDB_API_KEY")
VULDB_API_URL = "https://vuldb.com/?api"

SOFTWARE_MAPPING = {
    "google chrome": ("Google", "Chrome"),
    "adobe acrobat": ("Adobe", "Acrobat"),
    "microsoft office": ("Microsoft", "Office"),
    "microsoft word": ("Microsoft", "Word"),
    "microsoft excel": ("Microsoft", "Excel"),
    "microsoft powerpoint": ("Microsoft", "PowerPoint"),
    "microsoft outlook": ("Microsoft", "Outlook"),
    "microsoft edge": ("Microsoft", "Edge"),
}

COMMON_SOFTWARE_NAMES = list(SOFTWARE_MAPPING.keys())

def get_installed_software_windows():
    software_list = []
    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for reg_hive, reg_path in reg_paths:
        try:
            registry_key = winreg.OpenKey(reg_hive, reg_path)
            for i in range(0, winreg.QueryInfoKey(registry_key)[0]):
                try:
                    subkey_name = winreg.EnumKey(registry_key, i)
                    subkey = winreg.OpenKey(registry_key, subkey_name)
                    try:
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        software_info = {
                            "name": display_name,
                            "source": "registry",
                            "version": winreg.QueryValueEx(subkey, "DisplayVersion")[0] if "DisplayVersion" in [winreg.EnumValue(subkey, j)[0] for j in range(winreg.QueryInfoKey(subkey)[1])] else "unknown",
                            "publisher": winreg.QueryValueEx(subkey, "Publisher")[0] if "Publisher" in [winreg.EnumValue(subkey, j)[0] for j in range(winreg.QueryInfoKey(subkey)[1])] else "unknown",
                            "install_date": "unknown"
                        }
                        software_list.append(software_info)
                    except:
                        continue
                    finally:
                        winreg.CloseKey(subkey)
                except:
                    continue
            winreg.CloseKey(registry_key)
        except:
            continue
    return software_list


def simplify_name(name):
    name = name.lower()
    for key in SOFTWARE_MAPPING:
        if key in name:
            return SOFTWARE_MAPPING[key]
    return ("unknown", name.split(" ")[0])

def is_software_version_vulnerable(installed_version, vuln_titles):
    #print(f"🔎 Checking version: {installed_version} against titles: {vuln_titles}")
    try:
        # Validate the version string
        if not installed_version or not isinstance(installed_version, str):
            return None
        if installed_version.lower() == "unknown":
            return None

        installed = version.parse(installed_version)

        for title in vuln_titles:
            matches = re.findall(r"up to ([\d.]+)", title)
            for vuln_ver in matches:
                try:
                    if installed <= version.parse(vuln_ver):
                        return True
                except:
                    continue  # Ignore bad version strings in VulDB
        return False

    except Exception as e:
        print(f"Version check failed: {e}")
        return None

def filter_common_software(installed_software):
    filtered = []
    seen = set()
    for sw in installed_software:
        for keyword in COMMON_SOFTWARE_NAMES:
            if keyword in sw["name"].lower() and sw["name"].lower() not in seen:
                filtered.append(sw)
                seen.add(sw["name"].lower())
    return filtered

def check_vuldb_vulnerabilities(vendor, product):
    try:
        headers = {
            "X-VulDB-ApiKey": VULDB_API_KEY,
            "User-Agent": "Hygiene360/1.0"
        }

        # Advanced search using form data
        payload = {
            "advancedsearch": f"vendor:{vendor},product:{product}",
            "details": "0"
        }

        #print(f"🔍 Querying VulDB: vendor={vendor}, product={product}")
        response = requests.post(VULDB_API_URL, headers=headers, data=payload)

        if response.status_code == 200:
            data = response.json()
            result_list = data.get("result", [])

            # If no results, try fallback full-text search
            if not result_list:
                fallback_payload = {
                    "search": f"{vendor} {product}",
                    "details": "0"
                }
                response = requests.post(VULDB_API_URL, headers=headers, data=fallback_payload)
                if response.status_code == 200:
                    data = response.json()
                    result_list = data.get("result", [])

            return {
                "vulnerabilities_found": len(result_list),
                "titles": [entry["entry"]["title"] for entry in result_list[:3] if "entry" in entry and "title" in entry["entry"]]
            }

        else:
            return {"error": f"VulDB error {response.status_code}: {response.text}"}

    except Exception as e:
        return {"error": str(e)}

def get_software_inventory():
    logger.info("Collecting software inventory")
    os_type = platform.system()

    if os_type != "Windows":
        return {"os_type": os_type, "not_implemented": True}

    installed_software = get_installed_software_windows()
    common_software = filter_common_software(installed_software)

    results = []
    for sw in common_software:
        name = sw.get("name", "unknown")
        vendor, product = simplify_name(name)

        if vendor == "unknown":
            sw.update({
                "vuldb": {"note": "Vendor unknown, query skipped"},
                "vulnerable": None
            })
            results.append(sw)
            continue

        # VulDB API lookup
        vuln_info = check_vuldb_vulnerabilities(vendor, product)
        titles = vuln_info.get("titles", [])

        # Version string validation
        version_str = sw.get("version", "unknown")
        is_vulnerable = is_software_version_vulnerable(version_str, titles)

        # Combine results
        sw.update({
            "vuldb": vuln_info,
            "vulnerable": is_vulnerable,
            "version_checked": version_str  # optional debug info
        })
        results.append(sw)

        time.sleep(2)  # Delay to avoid API rate limiting

    return {
        "os_type": os_type,
        "common_software_count": len(results),
        "common_software": results,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    result = get_software_inventory()
    print(json.dumps(result, indent=4))
