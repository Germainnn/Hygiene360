import threading
import os
import sys
import logging
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pystray
from PIL import Image
from agent.agent import start_flask_api,poll_rescan_flag,generate_device_id
from agent.gui import main as launch_gui 

_gui_thread = None

def exit_app(icon, item):
    icon.stop()
    os._exit(0)

def open_gui(icon, item):
    global _gui_thread
    if _gui_thread and _gui_thread.is_alive():
        return  # GUI already running

    def safe_start_gui():
        try:
            launch_gui()
        except Exception as e:
            logger.error("Error launching GUI: %s", str(e))
            logger.error(traceback.format_exc())

    _gui_thread = threading.Thread(target=safe_start_gui, daemon=True)
    _gui_thread.start()
        
logger = logging.getLogger("Hygiene360")
logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def run_tray():
    try:
        if hasattr(sys, '_MEIPASS'):
            # Running from PyInstaller bundle
            base_dir = sys._MEIPASS
        else:
            # Running from script
            base_dir = os.path.abspath(os.path.dirname(__file__))

        icon_path = os.path.join(base_dir, 'agent', 'Hygiene360.ico')
        print(f"🧭 Loading tray icon from: {icon_path}")
        image = Image.open(icon_path)
    except Exception as e:
        print(f"⚠️ Failed to load icon: {e}")
        image = Image.new("RGB", (64, 64), color=(255, 0, 0))

    menu = pystray.Menu(
        pystray.MenuItem('Open GUI', open_gui),
        pystray.MenuItem('Exit', exit_app)
    )

    icon = pystray.Icon("Hygiene360", image, "Hygiene360 Agent", menu)
    icon.run()

if __name__ == "__main__":
    generate_device_id()
    try:
        threading.Thread(target=start_flask_api, daemon=True).start()
        threading.Thread(target=poll_rescan_flag, daemon=True).start()
        run_tray()
    except Exception as e:
        logger.exception("Unhandled exception in tray launcher")