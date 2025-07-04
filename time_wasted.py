from PyQt5.QtWidgets import QMainWindow, QApplication, QLabel
from PyQt5.QtCore import QTimer
import os
import ida_diskio
import idaapi
import ida_netnode
import sip
import time
import json

NETNODE_NAME = "$ plugin time wasted"
NETNODE_DB_TIME_KEY = 0
NETNODE_DEBUG_TIME_KEY = 1

def find_ida_main_window():
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMainWindow) and 'IDA' in widget.windowTitle():
            return widget
    return None

def format_elapsed(seconds):
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{days:02}:{hours:02}:{minutes:02}:{secs:02}"

def PLUGIN_ENTRY():
    return IDAStatusBarTimerPlugin()

class IDAStatusBarTimerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Determine how much time you've wasted staring at dissassemblers"
    help = ""
    wanted_name = "Time Wasted"
    wanted_hotkey = ""

    def __init__(self):
        self.label = None
        self.timer = None
        self.netnode = None
        
        self.config = {
            "stop_re_count_when_debugging": False,
            "global": True,
            "global_debug": True,
            "per_idb": True,
            "per_idb_debug": True,
            "per_session": True,
            "per_session_debug": True
        }

        self.db_elapsed = 0
        self.debug_elapsed = 0
        self.global_debug_elapsed = 0
        self.last_check = time.time()
        self.debugging = False
        self.session_start = time.time()
        self.plugin_config_path = os.path.join(ida_diskio.get_user_idadir(), "time_wasted.config.json")
        self.plugin_data_path = os.path.join(ida_diskio.get_user_idadir(), "time_wasted.global_data.json")
        self.plugin_sessions = []
    
    def load_plugin_config(self):
        if not os.path.exists(self.plugin_config_path):
            self.save_plugin_config()
            return

        try:
            with open(self.plugin_config_path, "r") as f:
                self.config = json.load(f)
        except Exception as e:
            print(f"[time_wasted] Failed to load config, using defaults: {e}")
            self.save_plugin_config()

    def save_plugin_config(self):
        try:
            with open(self.plugin_config_path, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"[time_wasted] Failed to save config: {e}")    
                
    def load_plugin_data(self):
        if os.path.exists(self.plugin_data_path):
            try:
                with open(self.plugin_data_path, "r") as f:
                    self.plugin_sessions = json.load(f)
            except Exception:
                self.plugin_sessions = []
        else:
            self.plugin_sessions = []

    def save_plugin_data(self):
        try:
            # reload before saving to get sessions saved by other instances
            if os.path.exists(self.plugin_data_path):
                with open(self.plugin_data_path, "r") as f:
                    try:
                        existing_sessions = json.load(f)
                    except:
                        existing_sessions = []
            else:
                existing_sessions = []

            merged_sessions = existing_sessions + [s for s in self.plugin_sessions if s not in existing_sessions]
    
            with open(self.plugin_data_path, "w") as f:
                f.write(json.dumps(merged_sessions, indent=2))
                f.flush()
        except Exception as e:
            print("[time_wasted] Failed saving plugin time data:", e)

    def init(self):
        self.load_plugin_config()
        if self.config["global"]:
            self.load_plugin_data()
        self.global_elapsed = sum(session.get("duration_sec", 0) for session in self.plugin_sessions)
        self.global_debug_elapsed = sum(session.get("debug_duration_sec", 0) for session in self.plugin_sessions)

        self.session_start = time.time()
        main = find_ida_main_window()
        if not main:
            print("[time_wasted] Main window not found.")
            return idaapi.PLUGIN_SKIP
    
        if self.config["per_idb"]:
            self.netnode = idaapi.netnode(NETNODE_NAME, 0, 1)
            self.db_elapsed = self.netnode.altval(NETNODE_DB_TIME_KEY)
            self.debug_elapsed = self.netnode.altval(NETNODE_DEBUG_TIME_KEY)

        self.db_elapsed_start = self.db_elapsed
        self.debug_elapsed_start = self.debug_elapsed
    
        self.label = QLabel()
        self.last_check = time.time()
        self.debugging = idaapi.is_debugger_on()
    
        def update_label():
            now = time.time()
            delta = now - self.last_check
            self.last_check = now
    
            currently_debugging = idaapi.is_debugger_on()
    
            if currently_debugging:
                if not self.debugging:
                    self.debugging = True
                self.debug_elapsed += delta
                if not self.config["stop_re_count_when_debugging"]:
                    self.db_elapsed += delta
            else:
                if self.debugging:
                    self.debugging = False
                self.db_elapsed += delta
                
    
            if self.config["per_idb"]:
                self.netnode.altset(NETNODE_DB_TIME_KEY, int(self.db_elapsed))
                self.netnode.altset(NETNODE_DEBUG_TIME_KEY, int(self.debug_elapsed))
    
            session_reverse = self.db_elapsed - self.db_elapsed_start
            session_debug = self.debug_elapsed - self.debug_elapsed_start
            total_global = self.global_elapsed + int(time.time() - self.session_start)
            total_global_debug = self.global_debug_elapsed + int(session_debug)
    
            text = "Time wasted reversing"
            if self.config["global"]:
                text += f": {format_elapsed(total_global)}"
                if self.config["global_debug"]:
                    text += f" | debugging: {format_elapsed(total_global_debug)}"
            
            if self.config["per_idb"]:
                if self.config["global"]:
                    text += " ["
                else:
                    text += " "
                text += f"this idb: {format_elapsed(int(self.db_elapsed))}"
                if self.config["per_idb_debug"]:
                    text += " | "
                    if not (self.config["global"] and self.config["global_debug"]):
                        text += "debugging: "
                    text += f"{format_elapsed(int(self.debug_elapsed))}"
                if self.config["global"]:
                    text += "]"
            
            if self.config["per_session"]:
                if self.config["global"] or self.config["per_idb"]:
                    text += " ["
                text += f"this session: {format_elapsed(int(session_reverse))}"
                if self.config["per_session_debug"]:
                    text += " | "
                    if not (self.config["global"] and self.config["global_debug"]) and not (self.config["per_idb"] and self.config["per_idb_debug"]):
                        text += "debugging: "
                    text += f"{format_elapsed(int(session_debug))}"
                if self.config["global"] or self.config["per_idb"]:
                    text += " ]" 
                    
            self.label.setText(text)
    
        self.timer = QTimer()
        self.timer.timeout.connect(update_label)
        self.timer.start(1000)
        update_label()
    
        main.statusBar().addPermanentWidget(self.label)
        print(f"[time_wasted] Initialized ({self.config})")
    
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    
    def term(self):
        if self.config["global"]:
            session_end = time.time()
            self.plugin_sessions.append({
                "start": self.session_start,
                "end": session_end,
                "duration_sec": int(session_end - self.session_start),
                "debug_duration_sec": int(self.debug_elapsed - self.debug_elapsed_start)
            })
            self.save_plugin_data()

        if self.timer:
            self.timer.stop()
            self.timer.deleteLater()
        if self.label:
            self.label.deleteLater()

        if self.netnode and self.config["per_idb"]:
            self.netnode.altset(NETNODE_DB_TIME_KEY, int(self.db_elapsed))
            self.netnode.altset(NETNODE_DEBUG_TIME_KEY, int(self.debug_elapsed))