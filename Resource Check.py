import psutil
import subprocess
import time
import os
import csv
import json
from datetime import datetime

# CONFIGURATION
AGENT_PATH = r"C:\Users\wwjie\Downloads\Hygiene360\dist\Hygiene360Agent.exe"
AGENT_ARGS = ["--scan"]
LOG_CSV = "agent_performance_log.csv"
LOG_JSON = "agent_performance_log.json"

def monitor_process(proc):
    pid = proc.pid
    process = psutil.Process(pid)

    cpu_usage = []
    ram_usage = []
    start_time = time.time()

    # 🧠 Warm up CPU tracking to avoid inaccurate first reading
    process.cpu_percent(interval=None)
    time.sleep(3)

    try:
        while proc.poll() is None:
            cpu = process.cpu_percent(interval=3)
            ram = process.memory_info().rss / (1024 * 1024)  # MB
            cpu_usage.append(cpu)
            ram_usage.append(ram)
            print(f"CPU: {cpu:.2f}% | RAM: {ram:.2f} MB")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print("Process ended or access denied")

    end_time = time.time()

    return {
        "start_time": datetime.fromtimestamp(start_time).isoformat(),
        "end_time": datetime.fromtimestamp(end_time).isoformat(),
        "duration_sec": round(end_time - start_time, 2),
        "peak_cpu": round(max(cpu_usage, default=0.0), 2),
        "peak_ram": round(max(ram_usage, default=0.0), 2)
    }

def save_to_csv(data, filepath):
    fieldnames = data.keys()
    file_exists = os.path.exists(filepath)

    with open(filepath, mode='a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def save_to_json(data, filepath):
    with open(filepath, mode='a') as jsonfile:
        jsonfile.write(json.dumps(data, indent=2) + "\n")

def run():
    print(f"Launching agent: {AGENT_PATH} {' '.join(AGENT_ARGS)}")
    proc = subprocess.Popen([AGENT_PATH] + AGENT_ARGS)

    perf_data = monitor_process(proc)

    print("\n=== Performance Summary ===")
    for k, v in perf_data.items():
        print(f"{k}: {v}")

    save_to_csv(perf_data, LOG_CSV)
    save_to_json(perf_data, LOG_JSON)

if __name__ == "__main__":
    run()
