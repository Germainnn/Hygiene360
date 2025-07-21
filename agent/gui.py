import tkinter as tk
from tkinter import ttk, messagebox
import threading
from datetime import datetime
from PIL import Image, ImageTk
import os
import sys
import requests
import ttkbootstrap as tb
from ttkbootstrap.constants import *

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.agent import collect_security_data, send_data_to_server

API_URL = "http://localhost:5000/api"

DEFAULT_POLICY = {
    "name": "Default Policy",
    "os_score_weight": 25,
    "antivirus_score_weight": 25,
    "firewall_score_weight": 25,
    "security_tools_score_weight": 25,
    "require_os_up_to_date": True,
    "max_missing_patches": 0,
    "require_antivirus": True,
    "require_firewall": True,
    "require_edr": True,
    "require_dlp": True,
    "software_penalty_per_vuln": 5.0,
    "max_software_penalty": 20.0
}

def fetch_active_policy():
    try:
        response = requests.get(f"{API_URL}/policies")
        response.raise_for_status()
        policies = response.json().get('policies', [])
        for p in policies:
            if p.get('is_active'):
                return p
    except Exception as e:
        print(f"Failed to fetch active policy: {e}")
        print("🔁 Using default fallback policy.")
        return DEFAULT_POLICY

def calculate_score_local(security_data, software_list, policy):
    breakdown = []

    def bool_policy(key, default=True):
        return policy.get(key, default)

    os_score = 0
    os_weight = policy.get("os_score_weight", 25)
    if bool_policy("require_os_up_to_date"):
        if security_data.get("os_patch_status", {}).get("pending_updates", 1) == 0:
            os_score += 0.5
        if security_data.get("os_patch_status", {}).get("pending_updates", 9999) <= policy.get("max_missing_patches", 0):
            os_score += 0.5
        breakdown.append({
            "component": "OS",
            "weight": os_weight,
            "achieved": os_score * os_weight,
            "max": os_weight
        })

    av_weight = policy.get("antivirus_score_weight", 25)
    if bool_policy("require_antivirus"):
        av = 1.0 if security_data.get("antivirus_status", {}).get("protected", False) else 0.0
        breakdown.append({
            "component": "Antivirus",
            "weight": av_weight,
            "achieved": av * av_weight,
            "max": av_weight
        })

    fw_weight = policy.get("firewall_score_weight", 25)
    if bool_policy("require_firewall"):
        fw = 1.0 if security_data.get("firewall_status", {}).get("firewall_status", {}).get("overall_status", False) else 0.0
        breakdown.append({
            "component": "Firewall",
            "weight": fw_weight,
            "achieved": fw * fw_weight,
            "max": fw_weight
        })

    tools_weight = policy.get("security_tools_score_weight", 25)
    edr_tools = security_data.get("security_tools", {}).get("edr", {}).get("tools", [])
    dlp_tools = security_data.get("security_tools", {}).get("dlp", {}).get("tools", [])

    def tool_score(tools):
        for t in tools:
            installed = t.get("status", "").lower() in ["installed", "active"]
            running = t.get("details", {}).get("process", {}).get("running", False)
            if installed and running:
                return 1.0
            elif installed:
                return 0.5
        return 0.0

    tool_scores = []
    if bool_policy("require_edr", False):
        tool_scores.append(tool_score(edr_tools))
    if bool_policy("require_dlp", False):
        tool_scores.append(tool_score(dlp_tools))

    if tool_scores:
        avg_score = sum(tool_scores) / len(tool_scores)
        breakdown.append({
            "component": "Security Tools",
            "weight": tools_weight,
            "achieved": avg_score * tools_weight,
            "max": tools_weight
        })

    penalty = 0
    penalty_per_vuln = policy.get("software_penalty_per_vuln", 5.0)
    max_penalty = policy.get("max_software_penalty", 20.0)
    for sw in security_data.get("software_inventory", {}).get("common_software", []):
        if sw.get("vulnerable", False):
            penalty += penalty_per_vuln
    penalty = min(penalty, max_penalty)
    if penalty > 0:
        breakdown.append({
            "component": "Vulnerable Software",
            "weight": -max_penalty,
            "achieved": -penalty,
            "max": 0
        })

    total_achieved = sum(x["achieved"] for x in breakdown)
    total_weight = sum(x["weight"] for x in breakdown if x["weight"] > 0)

    if total_weight == 0:
        score = 0.0
    else:
        score = (total_achieved / total_weight) * 100.0

    return round(max(0, min(score, 100)), 2), breakdown

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # When frozen
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class Hygiene360GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hygiene360 Security Agent")
        self.root.geometry("1000x600")

        self.security_data = None
        self.last_scan_time = None

        self.icon_cache = {}

        # === Layout
        self.main_frame = tb.Frame(root)
        self.main_frame.pack(fill=BOTH, expand=True)

        self.sidebar = tb.Frame(self.main_frame, width=200, bootstyle="dark")
        self.sidebar.pack(side=LEFT, fill=Y)
        self.sidebar.pack_propagate(False)

        self.content_area = tb.Frame(self.main_frame)
        self.content_area.pack(side=LEFT, fill=BOTH, expand=True)

        self.frames = {
            "dashboard": tb.Frame(self.content_area, padding=10),
            "system": tb.Frame(self.content_area, padding=10),
            "security": tb.Frame(self.content_area, padding=10),
            "software": tb.Frame(self.content_area, padding=10),
            "logs": tb.Frame(self.content_area, padding=10),
        }

        self.setup_sidebar()
        self.setup_dashboard(self.frames["dashboard"])
        self.setup_system_tab(self.frames["system"])
        self.setup_security_tab(self.frames["security"])
        self.setup_software_tab(self.frames["software"])
        self.setup_log_tab(self.frames["logs"])

        # Button bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tb.Label(root, textvariable=self.status_var, bootstyle="secondary", anchor="w")
        self.status_bar.pack(fill=X)

        btn_frame = tb.Frame(root)
        btn_frame.pack(fill=X, pady=5)
        self.scan_button = tb.Button(btn_frame, text="Run Scan", bootstyle="primary", command=self.run_scan)
        self.scan_button.pack(side=LEFT, padx=10)
        #self.send_button = tb.Button(btn_frame, text="Send to Server", bootstyle="info", command=self.send_data)
        #self.send_button.pack(side=LEFT)

        self.show_frame("dashboard")

    def setup_sidebar(self):
        logo_path = resource_path("icons/logo.png")
        if os.path.exists(logo_path):
            img = Image.open(logo_path).resize((64, 64))
            logo_img = ImageTk.PhotoImage(img)
            lbl = tb.Label(self.sidebar, image=logo_img)
            lbl.image = logo_img  # prevent garbage collection
            lbl.pack(pady=(20, 10))

        nav = [
            ("Dashboard", "dashboard", "dashboard.png"),
            ("System Info", "system", "system.png"),
            ("Security", "security", "security.png"),
            ("Software", "software", "software.png"),
            ("Agent Logs", "logs", "logs.png"),
        ]

        for label, frame_key, icon_file in nav:
            icon = self.load_icon(f"icons/{icon_file}")
            btn = tb.Button(
                self.sidebar, text=label, image=icon, compound=LEFT,
                bootstyle="secondary", width=180, padding=(10, 20),
                command=lambda k=frame_key: self.show_frame(k)
            )
            btn.pack(fill=X, padx=10, pady=5)
            btn.image = icon
            btn.pack(pady=5, padx=10)

    def load_icon(self, path, size=(24, 24)):
        if path in self.icon_cache:
            return self.icon_cache[path]
        try:
            img = Image.open(resource_path(path)).resize(size)
        except FileNotFoundError:
            img = Image.new("RGBA", size, (100, 100, 100, 0))
        icon = ImageTk.PhotoImage(img)
        self.icon_cache[path] = icon
        return icon

    def show_frame(self, name):
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[name].pack(fill=BOTH, expand=True)

    def setup_dashboard(self,frame):
        frame.pack(fill=tk.BOTH, expand=True)
        self.last_scan_label = ttk.Label(frame, text="Last Scan: Never")
        self.last_scan_label.pack(pady=5)

        self.policy_name_var = tk.StringVar(value="Policy: Unknown")
        policy_label = ttk.Label(frame, textvariable=self.policy_name_var)
        policy_label.pack(anchor="e") 

        tick_img = Image.open(resource_path("icons/green_tick.png")).resize((64, 64))
        cross_img = Image.open(resource_path("icons/red_cross.png")).resize((64, 64))
        self.tick_icon = ImageTk.PhotoImage(tick_img)
        self.cross_icon = ImageTk.PhotoImage(cross_img)
        self.score_status_icon = ttk.Label(frame, image=None)
        self.score_status_icon.pack(pady=(0, 5))
        
        score_frame = ttk.LabelFrame(frame, text="Security Score")
        score_frame.pack(fill=tk.X, pady=5)


        self.score_var = tk.IntVar(value=0)
        self.score_progress = ttk.Progressbar(score_frame, length=250, maximum=100, variable=self.score_var)
        self.score_progress.pack(pady=5)
        self.score_text = ttk.Label(score_frame, text="0%")
        self.score_text.pack()
        self.score_detail_frame = ttk.Frame(score_frame)
        self.score_detail_frame.pack(pady=5)

        status_frame = ttk.LabelFrame(frame, text="Quick Status")
        status_frame.pack(fill=tk.X, pady=5)
        self.antivirus_status = ttk.Label(status_frame, text="Antivirus: Not scanned")
        self.antivirus_status.pack(anchor=tk.W)
        self.firewall_status = ttk.Label(status_frame, text="Firewall: Not scanned")
        self.firewall_status.pack(anchor=tk.W)
        self.updates_status = ttk.Label(status_frame, text="System Updates: Not scanned")
        self.updates_status.pack(anchor=tk.W)

    def setup_system_tab(self,frame):
        frame.pack(fill=tk.BOTH, expand=True)
        self.system_tree = ttk.Treeview(frame, columns=("Value",), show="tree headings")
        self.system_tree.heading("#0", text="Property")
        self.system_tree.heading("Value", text="Value")
        self.system_tree.column("Value", stretch=True)
        self.system_tree.pack(fill=tk.BOTH, expand=True)

    def setup_security_tab(self,frame):
        frame.pack(fill=tk.BOTH, expand=True)
        self.security_tree = ttk.Treeview(frame, columns=("Status",), show="tree headings")
        self.security_tree.heading("#0", text="Component")
        self.security_tree.heading("Status", text="Status")
        self.security_tree.pack(fill=tk.BOTH, expand=True)

    def setup_software_tab(self,frame):
        frame.pack(fill=tk.BOTH, expand=True)
        self.software_tree = ttk.Treeview(frame, columns=("Version", "Status"), show="tree headings")
        self.software_tree.heading("#0", text="Software")
        self.software_tree.heading("Version", text="Version")
        self.software_tree.heading("Status", text="Status")
        self.software_tree.pack(fill=tk.BOTH, expand=True)

    def setup_log_tab(self,frame):
        frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(frame, height=20, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        refresh_btn = ttk.Button(frame, text="Refresh Logs", command=self.load_logs)
        refresh_btn.pack(pady=5)

    def run_scan(self):
        def scan_thread():
            self.status_var.set("Scanning...")
            self.scan_button.state(['disabled'])
            try:
                data = collect_security_data()
                if not data or not isinstance(data, dict):
                    raise Exception("Invalid data")
                self.security_data = data
                self.last_scan_time = datetime.now()
                self.update_display()
                self.status_var.set("Scan completed")

                # ✅ Automatically send data after successful scan
                if send_data_to_server(self.security_data):
                    self.status_var.set("Scan and data sent successfully")
                else:
                    self.status_var.set("Scan complete, but failed to send data")

            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.status_var.set("Scan failed")
            finally:
                self.scan_button.state(['!disabled'])

        threading.Thread(target=scan_thread, daemon=True).start()

    def send_data(self):
        if not self.security_data:
            messagebox.showwarning("Warning", "No data to send. Please run a scan first.")
            return

        def send_thread():
            self.status_var.set("Sending data...")
            self.send_button.state(['disabled'])
            try:
                if send_data_to_server(self.security_data):
                    messagebox.showinfo("Success", "Data sent sucessfully")
                    self.status_var.set("Data sent sucessfully")
                else:
                    messagebox.showerror("Error", "Failed to send")
                    self.status_var.set("Send failed")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.status_var.set("Send error")
            finally:
                self.send_button.state(['!disabled'])

        threading.Thread(target=send_thread, daemon=True).start()

    def update_score_breakdown(self, breakdown):
        # Clear previous labels
        for widget in self.score_detail_frame.winfo_children():
            widget.destroy()

        for entry in breakdown:
            name = entry.get("component", "Unknown")
            achieved = entry.get("achieved", 0)
            max_score = entry.get("max", 0)
            weight = entry.get("weight", 0)

            if weight < 0:
                text = f"⚠️ {name}: Penalty {achieved:.1f}"
                color = "orange"
            else:
                icon = "✔️" if achieved == max_score else "❌"
                text = f"{icon} {name}: {achieved:.1f} / {max_score:.1f}"
                color = "green" if achieved == max_score else "red"

            lbl = tk.Label(self.score_detail_frame, text=text, fg=color, font=("Segoe UI", 9))
            lbl.pack(anchor="w")

    def update_display(self):
        if self.last_scan_time:
            self.last_scan_label.config(text=f"Last Scan: {self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Show quick status labels
        updates = self.security_data.get('os_patch_status', {})
        pending_updates = updates.get('pending_updates', 0)
        up_to_date = pending_updates == 0
        self.updates_status.config(text=f"System Updates: {'Up to date' if up_to_date else f'{pending_updates} pending'}")

        av_status = self.security_data.get('antivirus_status', {})
        av_enabled = av_status.get('protected', False)
        self.antivirus_status.config(text=f"Antivirus: {'Enabled' if av_enabled else 'Disabled'}")

        fw_status = self.security_data.get('firewall_status', {}).get('firewall_status', {})
        fw_enabled = fw_status.get('overall_status', False)
        self.firewall_status.config(text=f"Firewall: {'Enabled' if fw_enabled else 'Disabled'}")

        # Fill system info
        self.system_tree.delete(*self.system_tree.get_children())
        for key, val in self.security_data.get('system_info', {}).items():
            self.system_tree.insert("", "end", text=key, values=(val,))

        # Fill security tool status
        sec_tools = self.security_data.get('security_tools', {})
        self.security_tree.delete(*self.security_tree.get_children())
        for category in ['antivirus', 'edr', 'dlp']:
            tools = sec_tools.get(category, {}).get('tools', [])
            if tools:
                cat_node = self.security_tree.insert("", "end", text=category.upper())
                for t in tools:
                    self.security_tree.insert(cat_node, "end", text=t.get("name"), values=(t.get("status", "Unknown"),))

        # Fill software table
        self.software_tree.delete(*self.software_tree.get_children())
        for item in self.security_data.get('software_inventory', {}).get("common_software", []):
            self.software_tree.insert("", "end",
                                    text=item.get('name', 'Unknown'),
                                    values=(item.get('version', 'Unknown'),
                                            "Vulnerable" if item.get('vulnerable') else "Safe"))

        # ✅ Fetch policy and calculate real score
        policy = fetch_active_policy()
        if policy:
            self.policy_name_var.set(f"Policy: {policy.get('name', 'Unnamed')}")
            score, breakdown = calculate_score_local(
                self.security_data,
                self.security_data.get('software_inventory', {}).get('common_software', []),
                policy
            )
            self.score_var.set(score)
            self.score_text.config(text=f"{score}%")
            self.update_score_breakdown(breakdown)
            if score >= 80:
                self.score_status_icon.config(image=self.tick_icon)
                self.score_status_icon.image = self.tick_icon
            else:
                self.score_status_icon.config(image=self.cross_icon)
                self.score_status_icon.image = self.cross_icon
        else:
            self.score_var.set(0)
            self.score_text.config(text="N/A")
            messagebox.showwarning("Warning", "Failed to fetch active policy. Score not calculated.")

    def load_logs(self):
        try:
            with open("agent.log", "r") as f:
                lines = f.readlines()[-100:]
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, "".join(lines))
            self.log_text.see(tk.END)
        except FileNotFoundError:
            self.log_text.insert(tk.END, "Log file not found. Run a scan first.\\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"Error loading logs: {str(e)}\\n")

def main():
    print("🚀 GUI launching...")
    try:
        root = tb.Window(themename="superhero")
        app = Hygiene360GUI(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ Exception in GUI: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()