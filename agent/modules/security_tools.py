import logging
import platform
import winreg
import wmi

logger = logging.getLogger("Hygiene360Agent.security_tools")

SECURITY_TOOLS = {
    "edr": {
        "name": "Endpoint Detection and Response",
        "tools": [
            {"name": "CrowdStrike Falcon", "service": "CSFalconService", "process": "CSFalconService.exe", "registry": r"SOFTWARE\CrowdStrike"},
            {"name": "Microsoft Defender for Endpoint", "service": "Sense", "process": "MsSense.exe", "registry": r"SOFTWARE\Microsoft\Windows Advanced Threat Protection"},
            {"name": "Carbon Black", "service": "CbDefense", "process": "CbDefense.exe", "registry": r"SOFTWARE\CarbonBlack"},
            {"name": "SentinelOne", "service": "SentinelAgent", "process": "SentinelAgent.exe", "registry": r"SOFTWARE\SentinelOne"},
            {"name": "Symantec EDR", "service": "SEDService", "process": "SEDService.exe", "registry": r"SOFTWARE\Symantec\Symantec Endpoint Protection"},
            {"name": "Sophos EDR", "service": "Sophos Endpoint Defense", "process": "SophosED.exe", "registry": r"SOFTWARE\Sophos"},
            {"name": "Elastic EDR", "service": "elastic-agent", "process": "elastic-agent.exe", "registry": r"SOFTWARE\Elastic"},
            {"name": "Mock EDR", "service": "TestEDR", "process": "testedr.exe", "registry": r"SOFTWARE\TestEDR"}
        ]
    },
    "dlp": {
        "name": "Data Loss Prevention",
        "tools": [
            {"name": "Symantec DLP", "service": "SymantecDLP", "process": "DLPAgentService.exe", "registry": r"SOFTWARE\Symantec\DLP"},
            {"name": "McAfee DLP", "service": "McAfeeDLPAgentService", "process": "DLPAgentService.exe", "registry": r"SOFTWARE\McAfee\DLP"},
            {"name": "Digital Guardian", "service": "DG", "process": "dgagent.exe", "registry": r"SOFTWARE\Digital Guardian"},
            {"name": "Forcepoint DLP", "service": "Forcepoint DLP", "process": "FDLPService.exe", "registry": r"SOFTWARE\Forcepoint"},
            {"name": "MyDLP", "service": "mydlp-agent", "process": "mydlpagent.exe", "registry": r"SOFTWARE\MyDLP"},
            {"name": "Mock DLP", "service": "TestDLP", "process": "testdlp.exe", "registry": r"SOFTWARE\TestDLP"}
        ]
    },
    "antivirus": {
        "name": "Antivirus",
        "tools": [
            {"name": "Windows Defender", "service": "WinDefend", "process": "MsMpEng.exe", "registry": r"SOFTWARE\Microsoft\Windows Defender"},
            {"name": "ClamAV", "service": "ClamWin Free Antivirus", "process": "clamd.exe", "registry": r"SOFTWARE\ClamWin"},
            {"name": "Avast Antivirus", "service": "AvastSvc", "process": "AvastUI.exe", "registry": r"SOFTWARE\AVAST Software"},
            {"name": "AVG Antivirus", "service": "AVG Antivirus", "process": "AVGUI.exe", "registry": r"SOFTWARE\AVG"},
            {"name": "Bitdefender", "service": "VSSERV", "process": "bdagent.exe", "registry": r"SOFTWARE\Bitdefender"},
            {"name": "McAfee VirusScan", "service": "McAfeeFramework", "process": "mcupdate.exe", "registry": r"SOFTWARE\McAfee"}
        ]
    }
}

def check_service_status(service_name):
    import pythoncom
    pythoncom.CoInitialize()
    try:
        w = wmi.WMI()
        services = w.Win32_Service(Name=service_name)
        if services:
            service = services[0]
            return {"exists": True, "running": service.State == "Running", "start_mode": service.StartMode}
        return {"exists": False}
    except Exception as e:
        logger.error(f"Error checking service {service_name}: {e}")
        return {"exists": False, "error": str(e)}
    finally:
        pythoncom.CoUninitialize()

def check_process_running(process_name):
    import pythoncom
    pythoncom.CoInitialize()
    try:
        w = wmi.WMI()
        processes = w.Win32_Process(Name=process_name)
        if processes:
            return {"running": True, "count": len(processes)}
        return {"running": False}
    except Exception as e:
        logger.error(f"Error checking process {process_name}: {e}")
        return {"running": False, "error": str(e)}
    finally:
        pythoncom.CoUninitialize()

def check_registry_exists(registry_path):
    try:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path)
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                return False
    except Exception as e:
        logger.error(f"Error checking registry {registry_path}: {e}")
        return False

def check_security_tools():
    os_type = platform.system()
    if os_type != "Windows":
        return {"os_type": os_type, "not_implemented": True}

    security_summary = {}
    for category, category_info in SECURITY_TOOLS.items():
        tools_status = []
        category_found = False

        for tool in category_info["tools"]:
            tool_status = {"name": tool["name"], "found": False, "details": {}}

            if tool.get("service"):
                service_status = check_service_status(tool["service"])
                tool_status["details"]["service"] = service_status
                if service_status.get("exists"):
                    tool_status["found"] = True

            if tool.get("process"):
                process_status = check_process_running(tool["process"])
                tool_status["details"]["process"] = process_status
                if process_status.get("running"):
                    tool_status["found"] = True

            if tool.get("registry"):
                registry_status = check_registry_exists(tool["registry"])
                tool_status["details"]["registry"] = registry_status
                if registry_status:
                    tool_status["found"] = True

            if tool_status["found"]:
                category_found = True
                registry_exists = tool_status["details"].get("registry", False)
                process_running = tool_status["details"].get("process", {}).get("running", False)

                if process_running and registry_exists:
                    tool_status["status"] = "Active"
                elif registry_exists:
                    tool_status["status"] = "Installed"
                else:
                    tool_status["status"] = "Inactive or Misconfigured"

            tools_status.append(tool_status)

        security_summary[category] = {
            "name": category_info["name"],
            "found": category_found,
            "tools": tools_status
        }

    score = sum(1 for c in security_summary.values() if c["found"])
    security_summary["overall_score"] = {
        "score": score,
        "max_score": len(SECURITY_TOOLS),
        "percentage": round((score / len(SECURITY_TOOLS)) * 100) if SECURITY_TOOLS else 0
    }

    return security_summary

if __name__ == "__main__":
    import json
    result = check_security_tools()
    print(json.dumps(result, indent=4))
